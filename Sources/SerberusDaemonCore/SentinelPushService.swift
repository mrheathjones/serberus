import Foundation
import PrivMgrCore
import SerberusXPCShim

/// Carries a non-Sendable sentinel XPC peer connection into the ``SentinelPushService``
/// actor. The peer is the daemon's server-side handle to the Sentinel's connection;
/// the daemon sends `presentPrompt` on it and receives the verdict as the reply.
public final class SentinelPeer: @unchecked Sendable {
    let connection: xpc_connection_t
    public init(_ connection: xpc_connection_t) { self.connection = connection }
}

/// Bridges a `.prompt` decision to the Sentinel and back.
///
/// PAM cannot block for the ~60s a user takes to decide, so the daemon answers
/// the initial request with `prompt_pending` + a `requestID` and PAM polls. This
/// actor owns the in-flight prompt state:
///
/// - **Push** — when a prompt reaches the front of the queue, it delivers a
///   `presentPrompt` to the REQUESTING USER's Sentinel (keyed by the uid from
///   that Sentinel's kernel-stamped audit token) and routes the reply back
///   through ``receiveResponse(_:)``. A prompt is never shown to, or approved
///   by, another user's session.
/// - **Serialize** — only one prompt is shown at a time PER USER (each user has
///   their own Sentinel); that user's next prompt is presented when the current
///   one resolves. One user's open prompt never delays another user's.
/// - **Resolve** — via the Sentinel's reply, a timeout watchdog, or an immediate
///   deny when no Sentinel is connected.
/// - **Publish** — a deny or timeout becomes visible to PAM's poll the moment
///   it resolves. An APPROVAL does not: it is held back until the daemon's
///   resolution task confirms the approval's side effects (the timed-grant
///   insert) persisted and calls ``publishVerdict(for:verdict:)``. Otherwise
///   PAM could poll `approved` — and sudo proceed — before the grant existed,
///   and a failed insert would leave that one allow outside revocation and
///   the ESF exec gate.
/// - **Cache** — resolved verdicts linger (`verdictRetention`) so PAM's final
///   poll always sees the result before the entry is evicted.
///
/// The transport is injected as a ``Delivery`` closure so the queue/continuation
/// logic is unit-testable without a live XPC peer.
public actor SentinelPushService {
    /// Delivers a prompt to one user's Sentinel.
    public typealias Delivery = @Sendable (PromptContext) -> Void

    /// Per-user cap on simultaneously-unresolved prompts, so an unprivileged
    /// caller spamming `.prompt`-matched binaries cannot grow `pending` without
    /// bound — and, being per target uid, cannot exhaust the budget another
    /// user's prompts need. Each new prompt past the cap fails closed (deny).
    static let maxConcurrentPromptsPerUser = 8

    /// Global safety ceiling across all users (memory bound even with many
    /// users logged in at once).
    static let maxConcurrentPrompts = 64

    private struct PendingEntry {
        let context: PromptContext
        /// The user whose Sentinel must show and answer this prompt.
        let targetUID: uid_t
        var continuation: CheckedContinuation<PromptResponse, Never>?
        /// The verdict the prompt RESOLVED to (Sentinel reply, watchdog timeout,
        /// or immediate deny). Set exactly once; it is the idempotency guard
        /// that protects the continuation from a double resume.
        var resolution: PromptResponse?
        /// The verdict PAM may observe via ``pollVerdict(for:)``. Deny and
        /// timeout publish at resolution; an approval stays `nil` until
        /// ``publishVerdict(for:verdict:)`` confirms its grant persisted.
        var response: PromptResponse?
        var watchdog: Task<Void, Never>?
    }

    /// One delivery per user with a connected Sentinel.
    private var deliveries: [uid_t: Delivery] = [:]
    private var pending: [UUID: PendingEntry] = [:]
    private var queue: [UUID] = []
    /// The prompt each user's Sentinel is currently showing.
    private var presenting: [uid_t: UUID] = [:]
    private let now: @Sendable () -> Date
    private let verdictRetention: TimeInterval

    private static let replyQueue = DispatchQueue(
        label: "com.herojoneslabs.serberus.sentinelpush", qos: .userInitiated
    )

    public init(
        now: @escaping @Sendable () -> Date = { Date() },
        verdictRetention: TimeInterval = 90
    ) {
        self.now = now
        self.verdictRetention = verdictRetention
    }

    // MARK: Sentinel connection

    /// Registers (or clears, when `nil`) the Sentinel for user `uid`, installing a
    /// ``Delivery`` that pushes `presentPrompt` over XPC and routes the reply
    /// back through ``receiveResponse(_:)``. `uid` must come from the peer's
    /// audit token, never from the message.
    public func registerSentinel(_ peer: SentinelPeer?, uid: uid_t) {
        guard let peer else { setDelivery(nil, forUID: uid); return }
        setDelivery({ [weak self] context in
            let service = self
            SentinelPushService.push(context, to: peer.connection, on: SentinelPushService.replyQueue) { response in
                Task { await service?.receiveResponse(response) }
            }
        }, forUID: uid)
    }

    /// Installs (or clears) user `uid`'s delivery directly (production via
    /// ``registerSentinel(_:uid:)``; tests pass a recorder). A new delivery
    /// re-drives the queue, re-presenting a prompt of this user's that was left
    /// mid-flight on a now-dead peer (idempotency guards make a late reply from
    /// the old peer a no-op).
    public func setDelivery(_ delivery: Delivery?, forUID uid: uid_t) {
        deliveries[uid] = delivery
        guard delivery != nil else { return }
        // Re-present this user's in-flight prompt on the new peer.
        presenting[uid] = nil
        presentNextIfIdle()
    }

    /// Whether any user's Sentinel is connected.
    public var isSentinelConnected: Bool { !deliveries.isEmpty }

    // MARK: PAM-driven prompt lifecycle

    /// Suspends until user `uid`'s Sentinel answers or the timeout elapses,
    /// returning the resolved response. The verdict is also cached for
    /// ``pollVerdict(for:)``. Fails closed (immediate deny) when the user is
    /// unknown (`nil`), has no Sentinel connected, or the concurrent-prompt cap
    /// is exceeded.
    public func requestApproval(context: PromptContext, forUID uid: uid_t?,
                                timeout: TimeInterval) async -> PromptResponse {
        if let existing = pending[context.requestID]?.resolution {
            return existing
        }
        guard let uid, deliveries[uid] != nil else {
            return denyImmediately(context, targetUID: uid ?? 0)
        }
        var unresolvedTotal = 0
        var unresolvedForUser = 0
        for entry in pending.values where entry.resolution == nil {
            unresolvedTotal += 1
            if entry.targetUID == uid { unresolvedForUser += 1 }
        }
        guard unresolvedForUser < Self.maxConcurrentPromptsPerUser,
              unresolvedTotal < Self.maxConcurrentPrompts else {
            return denyImmediately(context, targetUID: uid)
        }
        return await withCheckedContinuation { continuation in
            let nanos = UInt64(max(0, timeout) * 1_000_000_000)
            let requestID = context.requestID
            let watchdog = Task { [weak self] in
                try? await Task.sleep(nanoseconds: nanos)
                await self?.timeoutIfUnresolved(requestID)
            }
            pending[requestID] = PendingEntry(
                context: context, targetUID: uid, continuation: continuation,
                resolution: nil, response: nil, watchdog: watchdog
            )
            queue.append(requestID)
            presentNextIfIdle()
        }
    }

    /// PAM poll: the PUBLISHED verdict, or `nil` while still awaiting the user
    /// (PAM keeps polling). `nil` for an unknown requestID is also "keep
    /// polling" — the entry is created moments after the `prompt_pending`
    /// reply. An approval that resolved but has not yet been published (its
    /// grant insert is still in flight) is deliberately `nil` here.
    public func pollVerdict(for requestID: UUID) -> PromptResponse.Verdict? {
        pending[requestID]?.response?.verdict
    }

    /// Records the Sentinel's reply (or a watchdog timeout). Idempotent: the first
    /// resolution wins and any later one is ignored.
    ///
    /// Deny and timeout are terminal the moment they resolve, so they publish
    /// for PAM's poll immediately. An APPROVAL is resolved (continuation
    /// resumed, watchdog cancelled, queue advanced) but NOT published — the
    /// resolution task publishes via ``publishVerdict(for:verdict:)`` only
    /// after the timed grant persisted, so sudo can never proceed on an
    /// approval the daemon then failed to record. If publication never comes
    /// (the resolution task died), PAM's wall deadline fails closed and the
    /// eviction scheduled here still bounds the entry's lifetime.
    public func receiveResponse(_ response: PromptResponse) {
        guard var entry = pending[response.requestID], entry.resolution == nil else { return }
        entry.resolution = response
        if response.verdict != .approved {
            entry.response = response
        }
        let continuation = entry.continuation
        entry.continuation = nil
        entry.watchdog?.cancel()
        entry.watchdog = nil
        pending[response.requestID] = entry
        continuation?.resume(returning: response)
        if presenting[entry.targetUID] == response.requestID { presenting[entry.targetUID] = nil }
        queue.removeAll { $0 == response.requestID }
        scheduleEviction(response.requestID)
        presentNextIfIdle()
    }

    /// Makes a resolved verdict visible to PAM's ``pollVerdict(for:)``. The
    /// prompt-resolution task calls this once an approval's side effects are
    /// settled: `.approved` when the timed grant persisted (or the rule
    /// carries no grant), `.denied` when the insert failed and the daemon
    /// fails closed. Idempotent and safe for unknown IDs: a no-op when the
    /// prompt is unknown, still unresolved, or already published (deny and
    /// timeout publish at resolution time).
    public func publishVerdict(for requestID: UUID, verdict: PromptResponse.Verdict) {
        guard var entry = pending[requestID],
              let resolution = entry.resolution,
              entry.response == nil else { return }
        entry.response = verdict == resolution.verdict
            ? resolution
            : PromptResponse(
                requestID: requestID, verdict: verdict,
                justificationText: resolution.justificationText
            )
        pending[requestID] = entry
    }

    /// Test seam: unresolved prompts, optionally for one target uid.
    func unresolvedCountForTesting(uid: uid_t? = nil) -> Int {
        pending.values.filter { $0.resolution == nil && (uid == nil || $0.targetUID == uid) }.count
    }

    // MARK: Internals

    private func denyImmediately(_ context: PromptContext, targetUID: uid_t) -> PromptResponse {
        let denied = PromptResponse(requestID: context.requestID, verdict: .denied)
        pending[context.requestID] = PendingEntry(
            context: context, targetUID: targetUID, continuation: nil, resolution: denied,
            response: denied, watchdog: nil
        )
        scheduleEviction(context.requestID)
        return denied
    }

    /// Presents, for EVERY user whose Sentinel is idle, that user's oldest
    /// unresolved prompt (FIFO per user).
    private func presentNextIfIdle() {
        queue.removeAll { pending[$0] == nil }
        var considered = Set<uid_t>()
        for requestID in queue {
            guard let entry = pending[requestID], entry.resolution == nil else { continue }
            let uid = entry.targetUID
            // Only the user's oldest unresolved prompt is a candidate.
            guard considered.insert(uid).inserted else { continue }
            guard presenting[uid] == nil else { continue }
            // Only the requesting user's own Sentinel may show this prompt. If it
            // has gone away, the prompt fails closed rather than going to anyone
            // else (receiveResponse re-drives presentation for the next one).
            guard let deliver = deliveries[uid] else {
                receiveResponse(PromptResponse(requestID: requestID, verdict: .denied))
                return
            }
            presenting[uid] = requestID
            deliver(entry.context)
        }
    }

    /// Guarded on `resolution`, not the published `response`: an approval that
    /// resolved but is awaiting publication must never be re-resolved as a
    /// timeout (the continuation already resumed; a second resolution would
    /// also flip the held verdict to a deny out from under the grant insert).
    private func timeoutIfUnresolved(_ requestID: UUID) {
        guard let entry = pending[requestID], entry.resolution == nil else { return }
        receiveResponse(PromptResponse(requestID: requestID, verdict: .timedOut))
    }

    private func scheduleEviction(_ requestID: UUID) {
        let nanos = UInt64(max(0, verdictRetention) * 1_000_000_000)
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: nanos)
            await self?.evict(requestID)
        }
    }

    private func evict(_ requestID: UUID) {
        pending[requestID] = nil
    }

    // MARK: XPC push

    private static func push(
        _ context: PromptContext,
        to peer: xpc_connection_t,
        on queue: DispatchQueue,
        onResponse: @escaping @Sendable (PromptResponse) -> Void
    ) {
        guard let data = try? SerberusXPCCoding.encode(context) else {
            onResponse(PromptResponse(requestID: context.requestID, verdict: .denied))
            return
        }
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, XPCMessageKey.interface, XPCInterface.sentinel.rawValue)
        xpc_dictionary_set_string(message, XPCMessageKey.method, SentinelXPCMethod.presentPrompt.rawValue)
        data.withUnsafeBytes { buffer in
            xpc_dictionary_set_data(message, XPCMessageKey.payload, buffer.baseAddress, buffer.count)
        }
        let requestID = context.requestID
        xpc_connection_send_message_with_reply(peer, message, queue) { reply in
            onResponse(decodeResponse(reply, requestID: requestID))
        }
    }

    /// Decodes the Sentinel's reply. Fails closed to a deny on any error, malformed
    /// payload, or — critically — a payload whose `requestID` is not the one the
    /// daemon pushed, so a reply can never resolve a *different* in-flight prompt.
    private static func decodeResponse(_ reply: xpc_object_t, requestID: UUID) -> PromptResponse {
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
            return PromptResponse(requestID: requestID, verdict: .denied)
        }
        var length = 0
        guard let pointer = xpc_dictionary_get_data(reply, XPCMessageKey.reply, &length), length > 0 else {
            return PromptResponse(requestID: requestID, verdict: .denied)
        }
        let data = Data(bytes: pointer, count: length)
        guard let response = try? SerberusXPCCoding.decode(PromptResponse.self, from: data),
              response.requestID == requestID else {
            return PromptResponse(requestID: requestID, verdict: .denied)
        }
        return response
    }
}
