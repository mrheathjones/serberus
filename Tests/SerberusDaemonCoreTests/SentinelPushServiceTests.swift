import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// Records each `PromptContext` the service presents and lets a test await the
/// next presentation. This makes the actor's async push flow deterministic: a
/// test only sends a verdict once it has observed the prompt being presented
/// (which guarantees the pending entry + continuation already exist).
private actor PresentationRecorder {
    private var presented: [PromptContext] = []
    private var waiters: [CheckedContinuation<PromptContext, Never>] = []

    /// Every prompt ever delivered here, consumed or not.
    private(set) var total = 0

    func record(_ context: PromptContext) {
        total += 1
        if waiters.isEmpty {
            presented.append(context)
        } else {
            waiters.removeFirst().resume(returning: context)
        }
    }

    func next() async -> PromptContext {
        if !presented.isEmpty {
            return presented.removeFirst()
        }
        return await withCheckedContinuation { waiters.append($0) }
    }
}

@Suite("SentinelPushService")
struct SentinelPushServiceTests {
    private func context(timeout: Int = 60) -> PromptContext {
        PromptContext(
            user: "alice", processName: "brew", canonicalPath: "/opt/homebrew/bin/brew",
            teamID: nil, signingStatus: .unsigned, humanReadableRequest: "sudo brew install wget",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: timeout
        )
    }

    /// A service with a "connected Sentinel" whose deliveries feed `recorder`.
    private func connectedService(_ recorder: PresentationRecorder) async -> SentinelPushService {
        let service = SentinelPushService()
        await service.setDelivery({ ctx in Task { await recorder.record(ctx) } }, forUID: 501)
        return service
    }

    @Test("the continuation resumes when the Sentinel responds")
    func promptResolvesWhenAgentResponds() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let ctx = context()

        async let result = service.requestApproval(context: ctx, forUID: 501, timeout: 60)
        let presented = await recorder.next()
        #expect(presented.requestID == ctx.requestID)

        await service.receiveResponse(
            PromptResponse(requestID: ctx.requestID, verdict: .approved, justificationText: "deploy")
        )
        let response = await result
        #expect(response.verdict == .approved)
        #expect(response.justificationText == "deploy")
    }

    @Test("the watchdog denies via timeout when the Sentinel never replies")
    func promptDeniedOnTimeout() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let response = await service.requestApproval(context: context(), forUID: 501, timeout: 0.1)
        #expect(response.verdict == .timedOut)
    }

    @Test("concurrent prompts resolve independently without cross-wiring")
    func concurrentPromptsResolveIndependently() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let c1 = context()
        let c2 = context()

        async let r1 = service.requestApproval(context: c1, forUID: 501, timeout: 60)
        async let r2 = service.requestApproval(context: c2, forUID: 501, timeout: 60)

        // Prompts are serialized — one shown at a time. Approve the first
        // presented, deny the second, regardless of scheduling order.
        let first = await recorder.next()
        await service.receiveResponse(PromptResponse(requestID: first.requestID, verdict: .approved))
        let second = await recorder.next()
        await service.receiveResponse(PromptResponse(requestID: second.requestID, verdict: .denied))

        let (res1, res2) = await (r1, r2)
        let verdictByID = [res1.requestID: res1.verdict, res2.requestID: res2.verdict]
        #expect(first.requestID != second.requestID)
        #expect(verdictByID[first.requestID] == .approved)
        #expect(verdictByID[second.requestID] == .denied)
    }

    @Test("with no Sentinel connected, a prompt is denied immediately")
    func promptImmediatelyDeniedWhenNoSentinelPeer() async {
        let service = SentinelPushService() // no delivery installed
        let ctx = context()
        let response = await service.requestApproval(context: ctx, forUID: 501, timeout: 60)
        #expect(response.verdict == .denied)
        #expect(await service.pollVerdict(for: ctx.requestID) == .denied)
    }

    @Test("poll returns nil until the verdict arrives")
    func pollVerdictReturnsNilUntilResolved() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let ctx = context()

        async let result = service.requestApproval(context: ctx, forUID: 501, timeout: 60)
        _ = await recorder.next()
        #expect(await service.pollVerdict(for: ctx.requestID) == nil)

        await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .approved))
        _ = await result
    }

    @Test("poll returns the verdict once the Sentinel responds")
    func pollVerdictReturnsResultAfterResolve() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let ctx = context()

        async let result = service.requestApproval(context: ctx, forUID: 501, timeout: 60)
        _ = await recorder.next()
        await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .denied))
        _ = await result

        #expect(await service.pollVerdict(for: ctx.requestID) == .denied)
    }

    // MARK: Approval publication (grant-persistence ordering)

    @Test("an approved verdict is not pollable until it is published")
    func approvedVerdictNotPollableUntilPublished() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let ctx = context()

        async let result = service.requestApproval(context: ctx, forUID: 501, timeout: 60)
        _ = await recorder.next()
        await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .approved))
        let response = await result
        #expect(response.verdict == .approved)

        // Resolved but unpublished: PAM's poll must still read "pending" so
        // sudo cannot proceed before the grant insert lands.
        #expect(await service.pollVerdict(for: ctx.requestID) == nil)

        await service.publishVerdict(for: ctx.requestID, verdict: .approved)
        #expect(await service.pollVerdict(for: ctx.requestID) == .approved)
    }

    @Test("a failed grant persist publishes denied over an approved resolution")
    func publishDeniedOverridesApprovedResolution() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let ctx = context()

        async let result = service.requestApproval(context: ctx, forUID: 501, timeout: 60)
        _ = await recorder.next()
        await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .approved))
        _ = await result

        await service.publishVerdict(for: ctx.requestID, verdict: .denied)
        #expect(await service.pollVerdict(for: ctx.requestID) == .denied)

        // Idempotent: the first publication wins — a late approve cannot
        // flip the deny PAM already observed.
        await service.publishVerdict(for: ctx.requestID, verdict: .approved)
        #expect(await service.pollVerdict(for: ctx.requestID) == .denied)
    }

    @Test("denied and timed-out verdicts are pollable immediately at resolution")
    func nonApprovedVerdictsPublishImmediately() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)

        let deniedCtx = context()
        async let deniedResult = service.requestApproval(context: deniedCtx, forUID: 501, timeout: 60)
        _ = await recorder.next()
        await service.receiveResponse(PromptResponse(requestID: deniedCtx.requestID, verdict: .denied))
        _ = await deniedResult
        #expect(await service.pollVerdict(for: deniedCtx.requestID) == .denied)

        let timedOutCtx = context()
        let timedOut = await service.requestApproval(context: timedOutCtx, forUID: 501, timeout: 0.05)
        #expect(timedOut.verdict == .timedOut)
        #expect(await service.pollVerdict(for: timedOutCtx.requestID) == .timedOut)
    }

    @Test("publishVerdict is a no-op for unknown and still-unresolved prompts")
    func publishVerdictSafeForUnknownAndUnresolved() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)

        // Unknown requestID: nothing to publish, nothing crashes.
        await service.publishVerdict(for: UUID(), verdict: .approved)

        // In-flight (unresolved) prompt: publication must not conjure a
        // pollable verdict the user never gave.
        let ctx = context()
        async let result = service.requestApproval(context: ctx, forUID: 501, timeout: 60)
        _ = await recorder.next()
        await service.publishVerdict(for: ctx.requestID, verdict: .approved)
        #expect(await service.pollVerdict(for: ctx.requestID) == nil)

        await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .denied))
        _ = await result
        #expect(await service.pollVerdict(for: ctx.requestID) == .denied)
    }

    @Test("the watchdog never re-resolves an approved-but-unpublished prompt")
    func watchdogDoesNotDoubleResumeHeldApproval() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let ctx = context()

        // Short watchdog so its window elapses while the approval is still
        // resolved-but-unpublished (the grant insert "in flight"). The
        // cancellation at resolution also runs the watchdog body immediately
        // (its sleep aborts, then it checks the entry), so BOTH the cancelled
        // and the naturally-elapsed watchdog paths execute below.
        async let result = service.requestApproval(context: ctx, forUID: 501, timeout: 0.15)
        _ = await recorder.next()
        await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .approved))
        let response = await result
        #expect(response.verdict == .approved)

        // Give the watchdog every chance to fire against the held entry. It
        // must treat the prompt as resolved (no second continuation resume —
        // that would crash — and no timed-out overwrite of the held verdict).
        try? await Task.sleep(for: .milliseconds(250))
        #expect(await service.pollVerdict(for: ctx.requestID) == nil)

        await service.publishVerdict(for: ctx.requestID, verdict: .approved)
        #expect(await service.pollVerdict(for: ctx.requestID) == .approved)
    }

    // MARK: - Prompts reach only the requesting user's Sentinel

    @Test("a prompt for a user with no Sentinel is denied, not shown to another user")
    func otherUsersSentinelNeverSeesPrompt() async {
        let alice = PresentationRecorder()
        let service = SentinelPushService()
        await service.setDelivery({ ctx in Task { await alice.record(ctx) } }, forUID: 501)

        let response = await service.requestApproval(context: context(), forUID: 502, timeout: 60)
        #expect(response.verdict == .denied)
        #expect(await alice.total == 0)
    }

    @Test("with two users connected, each prompt goes only to its own user's Sentinel")
    func promptRoutedToRequestingUser() async {
        let alice = PresentationRecorder()
        let bob = PresentationRecorder()
        let service = SentinelPushService()
        await service.setDelivery({ ctx in Task { await alice.record(ctx) } }, forUID: 501)
        await service.setDelivery({ ctx in Task { await bob.record(ctx) } }, forUID: 502)

        let ctx = context()
        async let result = service.requestApproval(context: ctx, forUID: 502, timeout: 60)
        let shown = await bob.next()
        #expect(shown.requestID == ctx.requestID)
        await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .denied))
        #expect(await result.verdict == .denied)
        #expect(await alice.total == 0)
    }

    @Test("a prompt for an unknown user is denied")
    func unknownUserDenied() async {
        let recorder = PresentationRecorder()
        let service = await connectedService(recorder)
        let response = await service.requestApproval(context: context(), forUID: nil, timeout: 60)
        #expect(response.verdict == .denied)
        #expect(await recorder.total == 0)
    }
}

// MARK: - Per-user prompt budget + serialization

@Suite("SentinelPushService — per-user cap and serialization")
struct SentinelPushServicePerUserTests {
    private func context(user: String) -> PromptContext {
        PromptContext(
            user: user, processName: "brew", canonicalPath: "/opt/homebrew/bin/brew",
            teamID: nil, signingStatus: .unsigned, humanReadableRequest: "sudo brew install wget",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60
        )
    }

    /// Waits (bounded) until `uid` has `count` unresolved prompts registered.
    private func waitForUnresolved(_ service: SentinelPushService, uid: uid_t?, count: Int) async {
        for _ in 0..<500 {
            if await service.unresolvedCountForTesting(uid: uid) >= count { return }
            try? await Task.sleep(nanoseconds: 2_000_000)
        }
    }

    @Test("one user at their cap is denied, but another user's prompt is still presented")
    func perUserCapDoesNotStarveOthers() async {
        let alice = PresentationRecorder()
        let bob = PresentationRecorder()
        let service = SentinelPushService()
        await service.setDelivery({ ctx in Task { await alice.record(ctx) } }, forUID: 501)
        await service.setDelivery({ ctx in Task { await bob.record(ctx) } }, forUID: 502)

        let cap = SentinelPushService.maxConcurrentPromptsPerUser
        let flood = (0..<cap).map { _ in context(user: "alice") }
        let tasks = flood.map { ctx in
            Task { await service.requestApproval(context: ctx, forUID: 501, timeout: 30) }
        }
        await waitForUnresolved(service, uid: 501, count: cap)

        // Alice is at her cap: her next prompt fails closed immediately…
        let overflow = await service.requestApproval(context: context(user: "alice"), forUID: 501, timeout: 30)
        #expect(overflow.verdict == .denied)

        // …but Bob's prompt is NOT starved: it is presented to Bob right away,
        // even though Alice's first prompt is still open on her Sentinel.
        let bobContext = context(user: "bob")
        async let bobResult = service.requestApproval(context: bobContext, forUID: 502, timeout: 30)
        let presentedToBob = await bob.next()
        #expect(presentedToBob.requestID == bobContext.requestID)
        await service.receiveResponse(PromptResponse(requestID: bobContext.requestID, verdict: .denied))
        #expect(await bobResult.verdict == .denied)

        // Clean up Alice's flood.
        for ctx in flood {
            await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .denied))
        }
        for task in tasks { _ = await task.value }
    }

    @Test("prompts are serialized per user: Bob's is shown while Alice's is still open")
    func serializationIsPerUser() async {
        let alice = PresentationRecorder()
        let bob = PresentationRecorder()
        let service = SentinelPushService()
        await service.setDelivery({ ctx in Task { await alice.record(ctx) } }, forUID: 501)
        await service.setDelivery({ ctx in Task { await bob.record(ctx) } }, forUID: 502)

        let a1 = context(user: "alice")
        let a2 = context(user: "alice")
        let b1 = context(user: "bob")
        async let r1 = service.requestApproval(context: a1, forUID: 501, timeout: 30)
        let firstForAlice = await alice.next()
        async let r2 = service.requestApproval(context: a2, forUID: 501, timeout: 30)
        async let r3 = service.requestApproval(context: b1, forUID: 502, timeout: 30)

        // Bob sees his prompt while Alice's first is unresolved.
        #expect(await bob.next().requestID == b1.requestID)
        // Alice's second waits for her first (per-user FIFO).
        #expect(firstForAlice.requestID == a1.requestID)
        #expect(await alice.total == 1)

        await service.receiveResponse(PromptResponse(requestID: a1.requestID, verdict: .denied))
        #expect(await alice.next().requestID == a2.requestID)
        await service.receiveResponse(PromptResponse(requestID: a2.requestID, verdict: .denied))
        await service.receiveResponse(PromptResponse(requestID: b1.requestID, verdict: .denied))
        _ = await (r1, r2, r3)
    }

    @Test("the global ceiling still bounds the total across users")
    func globalCeiling() async {
        let service = SentinelPushService()
        let perUser = SentinelPushService.maxConcurrentPromptsPerUser
        let users = SentinelPushService.maxConcurrentPrompts / perUser
        var contexts: [PromptContext] = []
        var tasks: [Task<PromptResponse, Never>] = []
        for index in 0..<users {
            let uid = uid_t(600 + index)
            await service.setDelivery({ _ in }, forUID: uid)
            for _ in 0..<perUser {
                let ctx = context(user: "u\(index)")
                contexts.append(ctx)
                tasks.append(Task { await service.requestApproval(context: ctx, forUID: uid, timeout: 30) })
            }
        }
        await waitForUnresolved(service, uid: nil, count: SentinelPushService.maxConcurrentPrompts)

        // A fresh user (well under their own cap) hits the global ceiling.
        await service.setDelivery({ _ in }, forUID: 999)
        let refused = await service.requestApproval(context: context(user: "late"), forUID: 999, timeout: 30)
        #expect(refused.verdict == .denied)

        for ctx in contexts {
            await service.receiveResponse(PromptResponse(requestID: ctx.requestID, verdict: .denied))
        }
        for task in tasks { _ = await task.value }
    }
}
