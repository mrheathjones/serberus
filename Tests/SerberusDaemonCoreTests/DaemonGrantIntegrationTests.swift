import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// End-to-end: a timed-grant rule evaluated through the daemon's
/// `handlePAM` issues a grant that is persisted and survives a store reopen —
/// the "grants survive daemon restart" guarantee through the real daemon path.
@Suite("Daemon ↔ GrantStore integration", .serialized)
struct DaemonGrantIntegrationTests {
    private let brewHash = "aa" + String(repeating: "0", count: 62)

    private func config(mode: EnforcementMode = .enforce) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60, pamBypass: PAMBypass(),
            // These tests exercise the time-bound (expiring) grant path.
            timeBoundGrantsEnabled: true
        )
    }

    private func timedGrantProfile() -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "grant-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(maxGrantDurationSeconds: 900)
            )]
        )
    }

    private func makeController(
        grantStore: GrantMaintaining,
        paths: DaemonPaths
    ) -> DaemonController {
        DaemonController(
            paths: paths,
            machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:])),
            grantStore: grantStore,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil,
            decisionLogger: nil,
            pppc: StaticPPPCStatus(ready: true),
            authDB: NoopAuthorizationDBApplier(),
            // Never the production snapshot store (no /Library access in tests).
            lastKnownGood: InMemoryLastKnownGoodConfigStore(
                initial: CoordinatorFixtures.lastKnownGoodConfig()
            ),
            inspector: StaticBinaryIdentityInspector(identity: BinaryIdentity(
                canonicalPath: "", teamID: nil, sha256: brewHash, signingStatus: .unsigned
            )),
            deviceSerial: "TESTSERIAL",
            now: { CoordinatorFixtures.now }
        )
    }

    @Test("a timed-grant sudo decision persists a grant that survives reopen")
    func grantPersistsThroughDaemon() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let keyProvider = InMemoryKeyProvider.random()

        let store = try GrantStore(path: paths.grantDatabase.path, keyProvider: keyProvider)
        let controller = makeController(grantStore: store, paths: paths)
        await controller.loadPolicyForTesting(profiles: [timedGrantProfile()], config: config())

        let response = await controller.handlePAM(
            PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: ["hi"], tty: nil))
        )
        #expect(response.decision == .allow)
        #expect(response.grantID != nil)
        await store.close()

        // Reopen the database — the grant must still be active.
        let reopened = try GrantStore(path: paths.grantDatabase.path, keyProvider: keyProvider)
        let active = try await reopened.activeGrants(now: CoordinatorFixtures.now)
        #expect(active.count == 1)
        #expect(active.first?.grantID == response.grantID)
        #expect(active.first?.ruleID == "grant-echo")
        #expect(active.first?.binaryHash == brewHash)
        await reopened.close()
    }

    @Test("a cached grant satisfies a later prompt-rule request (cache hit)")
    func grantSatisfiesLaterRequest() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let store = try GrantStore(path: paths.grantDatabase.path, keyProvider: InMemoryKeyProvider.random())

        // Pre-seed a grant for a prompt rule, then verify the daemon allows.
        let promptProfile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(id: "prompt-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                         match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                         elevation: ElevationBehavior(type: .prompt))]
        )
        try await store.insert(Grant(
            user: "root", uid: 0, ruleID: "prompt-echo", profileKey: "rules_sudo_echo",
            teamID: "", binaryHash: brewHash, canonicalPath: "/bin/echo",
            grantedAt: CoordinatorFixtures.now, expiresAt: CoordinatorFixtures.now.addingTimeInterval(600),
            policyVersion: "1.0.0"
        ))

        let controller = makeController(grantStore: store, paths: paths)
        await controller.loadPolicyForTesting(profiles: [promptProfile], config: config())
        let response = await controller.handlePAM(
            PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: [], tty: nil))
        )
        // An active grant satisfies a prompt rule without re-prompting; the
        // daemon allows directly via the cache hit.
        #expect(response.decision == .allow)
        await store.close()
    }

    private func promptGrantProfile() -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "prompt-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(maxGrantDurationSeconds: 900),
                elevation: ElevationBehavior(type: .prompt)
            )]
        )
    }

    /// Polls the store until it holds `expected` active grants or the bounded
    /// retry budget is spent (the resolution runs in a detached task).
    private func activeGrants(in store: GrantStore, until expected: Int) async throws -> [Grant] {
        for _ in 0..<200 {
            let active = try await store.activeGrants(now: CoordinatorFixtures.now)
            if active.count >= expected { return active }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return try await store.activeGrants(now: CoordinatorFixtures.now)
    }

    /// Polls the push service until a verdict is published or the bounded
    /// retry budget is spent (an approval publishes from the detached
    /// resolution task only after the grant insert lands).
    private func publishedVerdict(
        from push: SentinelPushService, requestID: UUID
    ) async -> PromptResponse.Verdict? {
        for _ in 0..<200 {
            if let verdict = await push.pollVerdict(for: requestID) { return verdict }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return await push.pollVerdict(for: requestID)
    }

    @Test("an approved prompt persists the timed grant through the daemon")
    func promptApprovalPersistsGrant() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let store = try GrantStore(path: paths.grantDatabase.path, keyProvider: InMemoryKeyProvider.random())

        let controller = makeController(grantStore: store, paths: paths)
        await controller.loadPolicyForTesting(profiles: [promptGrantProfile()], config: config())

        // A connected Sentinel whose presentations feed the capture box.
        let capture = PromptCapture()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await capture.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let response = await controller.handlePAM(
            PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: [], tty: nil))
        )
        #expect(response.decision == .prompt)
        let requestID = try #require(response.promptRequestID)

        // The Sentinel shows the prompt; the user approves.
        let presented = await capture.next()
        #expect(presented.requestID == requestID)
        await push.receiveResponse(PromptResponse(requestID: requestID, verdict: .approved))

        // The detached resolution task persists the grant; poll until it lands.
        let active = try await activeGrants(in: store, until: 1)
        #expect(active.count == 1)
        #expect(active.first?.ruleID == "prompt-echo")
        #expect(active.first?.binaryHash == brewHash)
        #expect(active.first?.expiresAt == CoordinatorFixtures.now.addingTimeInterval(900))
        // The approval becomes pollable only AFTER the grant persisted — the
        // publication follows the insert from the same resolution task.
        #expect(await publishedVerdict(from: push, requestID: requestID) == .approved)
        await store.close()
    }

    @Test("a denied prompt persists no grant through the daemon")
    func promptDenialPersistsNothing() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let store = try GrantStore(path: paths.grantDatabase.path, keyProvider: InMemoryKeyProvider.random())

        let controller = makeController(grantStore: store, paths: paths)
        await controller.loadPolicyForTesting(profiles: [promptGrantProfile()], config: config())

        let capture = PromptCapture()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await capture.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let response = await controller.handlePAM(
            PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: [], tty: nil))
        )
        #expect(response.decision == .prompt)
        let requestID = try #require(response.promptRequestID)

        let presented = await capture.next()
        #expect(presented.requestID == requestID)
        await push.receiveResponse(PromptResponse(requestID: requestID, verdict: .denied))

        // The resolution task must NOT persist a grant for a denied prompt.
        for _ in 0..<20 {
            try? await Task.sleep(for: .milliseconds(10))
            let active = try await store.activeGrants(now: CoordinatorFixtures.now)
            #expect(active.isEmpty)
        }
        #expect(await push.pollVerdict(for: requestID) == .denied)
        await store.close()
    }

    @Test("the reload tick revokes a grant the continuous clock expired, though the wall clock was set back")
    func tickRevokesClockExpiredGrant() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let boot = MonotonicInstant(bootSessionID: "boot-a", nanoseconds: 10_000_000_000)
        let clock = MonotonicBox(boot)
        let store = try GrantStore(path: paths.grantDatabase.path, keyProvider: InMemoryKeyProvider.random(),
                                   monotonicNow: { clock.value })
        let controller = makeController(grantStore: store, paths: paths)
        await controller.loadPolicyForTesting(profiles: [timedGrantProfile()], config: config())

        let request = PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: ["hi"], tty: nil))
        let issued = await controller.handlePAM(request)
        let grantID = try #require(issued.grantID)
        #expect(await controller.activeGrants(forUser: "root").map(\.grantID) == [grantID])

        // 16 minutes pass on the continuous clock; the wall clock is held at issue time.
        clock.set(MonotonicInstant(bootSessionID: "boot-a", nanoseconds: boot.nanoseconds + 960_000_000_000))
        #expect(await controller.activeGrants(forUser: "root").isEmpty)
        await controller.revokeExpiredGrantsForTesting()
        let row = try #require(try await store.allGrants().first { $0.grantID == grantID })
        #expect(row.revokedAt != nil)
        await store.close()
    }

    @Test("under the kill switch a new JIT admin request is refused outright")
    func killSwitchRefusesJIT() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: NullGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        let off = SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: false, enforcementMode: .enforce, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60, pamBypass: PAMBypass()
        )
        await controller.loadPolicyForTesting(profiles: [], config: off)
        let result = await controller.requestAdminElevation(user: "root", justification: "need admin right now")
        #expect(result.outcome == .denied)
        #expect(result.message.contains("turned off"))
    }
}

/// A continuous clock a test sets by hand.
private final class MonotonicBox: @unchecked Sendable {
    private let lock = NSLock()
    private var current: MonotonicInstant?
    init(_ value: MonotonicInstant?) { current = value }
    var value: MonotonicInstant? { lock.lock(); defer { lock.unlock() }; return current }
    func set(_ value: MonotonicInstant?) { lock.lock(); current = value; lock.unlock() }
}

/// Records presentations so an integration test can wait for the prompt to be
/// shown before delivering the verdict (the push flow is async).
private actor PromptCapture {
    private var presented: [PromptContext] = []
    private var waiters: [CheckedContinuation<PromptContext, Never>] = []

    func record(_ context: PromptContext) {
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

/// Debug mode captures every sudo request's arguments, but only into the
/// root-only event lists, never into the decision log every user can read.
@Suite("Daemon debug-mode arguments stay out of the decision log", .serialized)
struct DaemonDebugArgumentsTests {
    @Test("a denied sudo request under debug mode: no argv in decisions-*.jsonl, full argv in recent-events")
    func debugArgvRootOnly() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        try FileManager.default.createDirectory(at: paths.logDirectory, withIntermediateDirectories: true)
        let events = RecentEventsWriter(logDirectory: paths.logDirectory, localURL: paths.recentEventsLocal,
                                        publicURL: paths.fleetEventsPublic)
        let controller = DaemonController(
            paths: paths, machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:])),
            grantStore: NullGrantStore(),
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil,
            decisionLogger: try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random()),
            recentEventsWriter: events,
            pppc: StaticPPPCStatus(ready: true), authDB: NoopAuthorizationDBApplier(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            inspector: StaticBinaryIdentityInspector(identity: BinaryIdentity(
                canonicalPath: "", teamID: nil, sha256: "bb" + String(repeating: "0", count: 62), signingStatus: .unsigned)),
            deviceSerial: "TESTSERIAL", now: { CoordinatorFixtures.now })
        let config = SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: .enforce, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60, pamBypass: PAMBypass())
        await controller.loadPolicyForTesting(profiles: [], config: config)
        await controller.setDebugModeForTesting(true)

        let response = await controller.handlePAM(
            PAMRequest(user: "root", kind: .sudo(command: "/usr/bin/jamf", argv: ["policy", "-event", "S3cretEvent"], tty: nil)))
        #expect(response.decision == .deny)

        let logged = ((try? FileManager.default.contentsOfDirectory(at: paths.logDirectory, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.lastPathComponent.hasPrefix("decisions-") && $0.pathExtension == "jsonl" }
            .compactMap { try? String(contentsOf: $0, encoding: .utf8) }.joined()
        #expect(logged.contains("/usr/bin/jamf"))
        #expect(!logged.contains("S3cretEvent"))
        #expect(!logged.contains("\"arguments\""))

        let targets = events.events(now: CoordinatorFixtures.now).map(\.target)
        #expect(targets == ["/usr/bin/jamf policy -event S3cretEvent"])
    }
}

/// Grants follow the policy: a grant whose rule is gone is revoked, and turning
/// time-bound grants back on bounds the indefinite ones.
@Suite("Grant lifetime follows the policy", .serialized)
struct GrantPolicyAlignmentTests {
    private let now = CoordinatorFixtures.now
    private let hash = "aa" + String(repeating: "0", count: 62)

    private func grant(profile: String = "rules_sudo_test", rule: String = "allow-brew",
                       expiresIn: TimeInterval? = nil) -> Grant {
        Grant(user: "alice", uid: 501, ruleID: rule, profileKey: profile, teamID: "", binaryHash: hash,
              canonicalPath: "/opt/homebrew/bin/brew", grantedAt: now.addingTimeInterval(-3600),
              expiresAt: expiresIn.map { now.addingTimeInterval($0) }, policyVersion: "1.0.0")
    }

    private func rule(_ id: String = "allow-brew", duration: Int = 0) -> Rule {
        Rule(id: id, type: .sudo, action: .allow, description: "t", priority: 10,
             match: MatchCriteria(commandPattern: "/opt/homebrew/bin/brew", matchType: .exact),
             conditions: RuleConditions(maxGrantDurationSeconds: duration))
    }

    private func key(_ profile: String = "rules_sudo_test", _ rule: String = "allow-brew")
        -> GrantPolicyAlignment.RuleKey { .init(profileKey: profile, ruleID: rule) }

    @Test("a grant whose profile or rule is gone is revoked; JIT grants are never touched")
    func orphansRevoked() {
        let kept = grant(expiresIn: 600)
        let otherProfile = grant(profile: "rules_sudo_old")
        let otherRule = grant(rule: "gone")
        let jit = Grant(user: "bob", uid: 502, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
                        teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
                        grantedAt: now, expiresAt: now.addingTimeInterval(600), policyVersion: "jit")
        let plan = GrantPolicyAlignment.plan(grants: [kept, otherProfile, otherRule, jit], rules: [key(): rule()],
                                             timeBoundGrantsEnabled: false, defaultGrantSeconds: 0)
        #expect(Set(plan.revoke) == [otherProfile.grantID, otherRule.grantID])
        #expect(plan.bound.isEmpty)
    }

    @Test("a rule that now evaluates every time loses its grants")
    func minusOneRevokes() {
        let g = grant(expiresIn: 600)
        let plan = GrantPolicyAlignment.plan(grants: [g], rules: [key(): rule(duration: -1)],
                                             timeBoundGrantsEnabled: true, defaultGrantSeconds: 1800)
        #expect(plan.revoke == [g.grantID])
    }

    @Test("time-bound on: indefinite grants get the rule's duration, else the default, else are revoked")
    func indefiniteBounded() {
        let byDefault = grant()
        let byRule = grant(rule: "own")
        let timed = grant(expiresIn: 60)
        let rules = [key(): rule(), key("rules_sudo_test", "own"): rule("own", duration: 600)]
        let plan = GrantPolicyAlignment.plan(grants: [byDefault, byRule, timed], rules: rules,
                                             timeBoundGrantsEnabled: true, defaultGrantSeconds: 1800)
        #expect(plan.bound == [byDefault.grantID: 1800, byRule.grantID: 600])
        #expect(plan.revoke.isEmpty)

        let noDefault = GrantPolicyAlignment.plan(grants: [byDefault, byRule], rules: rules,
                                                  timeBoundGrantsEnabled: true, defaultGrantSeconds: 0)
        #expect(noDefault.revoke == [byDefault.grantID])
        #expect(noDefault.bound == [byRule.grantID: 600])

        // Time-bound off: a grant with no expiry is revoked (only a time-bound
        // grant may skip a prompt); a timed one is left to expire.
        let off = GrantPolicyAlignment.plan(grants: [byDefault, timed], rules: rules, timeBoundGrantsEnabled: false,
                                            defaultGrantSeconds: 1800)
        #expect(off.revoke == [byDefault.grantID])
        #expect(off.bound.isEmpty)
    }

    @Test("bounding re-signs the row, which still verifies, with a same-boot continuous deadline")
    func storeBounds() async throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("bound-\(UUID().uuidString).sqlite").path
        defer { for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) } }
        let key = InMemoryKeyProvider.random()
        let instant = MonotonicInstant(bootSessionID: "boot-A", nanoseconds: 5_000_000_000)
        let store = try GrantStore(path: path, keyProvider: key, monotonicNow: { instant })
        let indefinite = grant()
        try await store.insert(indefinite)
        #expect(try await store.bound(grantID: indefinite.grantID, seconds: 1800, now: now) == 1)
        #expect(try await store.bound(grantID: indefinite.grantID, seconds: 1800, now: now) == 0) // no longer indefinite
        await store.close()

        let reopened = try GrantStore(path: path, keyProvider: key, monotonicNow: { instant })
        let row = try #require(try await reopened.allGrants().first)
        #expect(row.expiresAt == now.addingTimeInterval(1800))
        #expect(row.bootSessionID == "boot-A")
        #expect(row.continuousDeadlineNanos == 5_000_000_000 + 1800 * 1_000_000_000)
        #expect(await reopened.drainIntegrityViolations().isEmpty)
        #expect(try await reopened.activeGrants(now: now).count == 1)
        #expect(try await reopened.activeGrants(now: now.addingTimeInterval(1801)).isEmpty)
        await reopened.close()
    }

    private func config(timeBound: Bool, defaultMinutes: Int = 0) -> [String: any Sendable] {
        [
            "daemonEnabled": true, "enforcementMode": "enforce",
            "pamBypass": ["groups": ["admin"]] as [String: any Sendable],
            "timeBoundGrantsEnabled": timeBound, "defaultGrantDurationMinutes": defaultMinutes,
        ]
    }

    @Test("a reload revokes orphaned grants and, with time-bound off, grants with no expiry; when time-bound comes back, a grant with no expiry is bounded")
    func reloadAligns() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let store = try GrantStore(path: paths.grantDatabase.path, keyProvider: InMemoryKeyProvider.random(),
                                   monotonicNow: { nil })
        let live = grant()
        let orphan = grant(profile: "rules_sudo_removed")
        try await store.insert(live)
        try await store.insert(orphan)

        let rules: [String: any Sendable] = ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
        let source = MutablePreferencesSource(domains: [
            BundleConfig.configDomain: config(timeBound: false), BundleConfig.rulesDomain: rules,
        ])
        let controller = DaemonController(
            paths: paths, machServiceName: "test.unused", prefsReader: ManagedPreferencesReader(source: source),
            grantStore: store,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil, pppc: StaticPPPCStatus(ready: true), authDB: NoopAuthorizationDBApplier(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            deviceSerial: "TESTSERIAL", now: { CoordinatorFixtures.now })

        await controller.reloadPolicyIfChanged()
        var rows = try await store.allGrants()
        #expect(rows.first { $0.grantID == orphan.grantID }?.revokedAt != nil)
        // Time-bound off: a grant with no expiry would let its prompt rule skip
        // the prompt forever, so it is revoked too.
        #expect(rows.first { $0.grantID == live.grantID }?.revokedAt != nil)

        // A grant with no expiry left by an older version, then time-bound on:
        // it gets the org default instead of being revoked.
        let legacy = grant()
        try await store.insert(legacy)
        source.set([BundleConfig.configDomain: config(timeBound: true, defaultMinutes: 30),
                    BundleConfig.rulesDomain: rules])
        await controller.reloadPolicyIfChanged()
        rows = try await store.allGrants()
        #expect(rows.first { $0.grantID == legacy.grantID }?.expiresAt == now.addingTimeInterval(1800))
        #expect(rows.first { $0.grantID == legacy.grantID }?.revokedAt == nil)
        await store.close()
    }
}
