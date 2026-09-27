import EndpointSecurity
import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("ESFMonitor")
struct ESFMonitorTests {
    private static let now = CoordinatorFixtures.now

    private func grant(
        user: String,
        uid: uid_t,
        path: String,
        grantedAt: Date = now,
        expiresAt: Date?,
        revokedAt: Date? = nil
    ) -> Grant {
        Grant(
            user: user, uid: uid, ruleID: "r-\(path)", profileKey: "rules_sudo_test",
            teamID: "", binaryHash: "hash", canonicalPath: path,
            grantedAt: grantedAt, expiresAt: expiresAt, revokedAt: revokedAt,
            policyVersion: "1.0.0"
        )
    }

    // MARK: MonitoredSet

    @Test("monitored set is built from active grants only")
    func monitoredSetBuildsFromActiveGrants() {
        let now = Self.now
        let active = grant(user: "alice", uid: 501, path: "/bin/echo", expiresAt: now.addingTimeInterval(300))
        let expired = grant(user: "bob", uid: 502, path: "/bin/ls",
                            grantedAt: now.addingTimeInterval(-600), expiresAt: now.addingTimeInterval(-300))
        let revoked = grant(user: "carol", uid: 503, path: "/sbin/ping",
                            expiresAt: now.addingTimeInterval(300), revokedAt: now.addingTimeInterval(-1))

        let set = ESFMonitor.MonitoredSet(grants: [active, expired, revoked], now: now)
        #expect(set.contains("/bin/echo"))
        #expect(!set.contains("/bin/ls"))      // expired
        #expect(!set.contains("/sbin/ping"))   // revoked
    }

    // MARK: Exec decision

    @Test("the sudo-approved run itself is allowed: auid matches the grant even though euid is 0")
    func checkGrantAllowsMatchingAuditUser() {
        let now = Self.now
        let g = grant(user: "alice", uid: 501, path: "/bin/echo", expiresAt: now.addingTimeInterval(300))
        // sudo's child: euid 0, audit user 501 (alice logged in).
        #expect(ESFMonitor.isExecAllowed(path: "/bin/echo", auid: 501, euid: 0, grants: [g], now: now))
    }

    @Test("an expired grant denies an elevated exec from the grantee's session")
    func checkGrantDeniesExpiredGrant() {
        let now = Self.now
        let g = grant(user: "alice", uid: 501, path: "/bin/echo",
                      grantedAt: now.addingTimeInterval(-600), expiresAt: now.addingTimeInterval(-1))
        #expect(!ESFMonitor.isExecAllowed(path: "/bin/echo", auid: 501, euid: 0, grants: [g], now: now))
    }

    @Test("another login session elevating a granted path without its own grant is denied")
    func checkGrantDeniesWrongAuditUser() {
        let now = Self.now
        let g = grant(user: "alice", uid: 501, path: "/bin/echo", expiresAt: now.addingTimeInterval(300))
        #expect(!ESFMonitor.isExecAllowed(path: "/bin/echo", auid: 999, euid: 0, grants: [g], now: now))
    }

    @Test("the decision keys on auid, not euid: a grant for uid 0 does not cover a user's sudo run")
    func euidIsNotTheKey() {
        let now = Self.now
        let rootGrant = grant(user: "root", uid: 0, path: "/bin/echo", expiresAt: now.addingTimeInterval(300))
        #expect(!ESFMonitor.isExecAllowed(path: "/bin/echo", auid: 501, euid: 0, grants: [rootGrant], now: now))
    }

    @Test("a root exec outside any login session (auid unset: launchd, root-run jamf, MDM) is never blocked")
    func unsetAuditUserIsAllowed() {
        let now = Self.now
        let g = grant(user: "alice", uid: 501, path: "/usr/sbin/installer", expiresAt: now.addingTimeInterval(300))
        #expect(ESFMonitor.unsetAuditUserID == uid_t.max)   // AU_DEFAUDITID
        #expect(ESFMonitor.isExecAllowed(path: "/usr/sbin/installer", auid: ESFMonitor.unsetAuditUserID,
                                         euid: 0, grants: [g], now: now))
        #expect(ESFMonitor.isExecAllowed(path: "/usr/sbin/installer", auid: ESFMonitor.unsetAuditUserID,
                                         euid: 0, grants: [], now: now))
    }

    @Test("a non-elevated exec is never blocked, grant or not")
    func nonElevatedIsAllowed() {
        let now = Self.now
        let g = grant(user: "alice", uid: 501, path: "/bin/echo", expiresAt: now.addingTimeInterval(300))
        #expect(ESFMonitor.isExecAllowed(path: "/bin/echo", auid: 999, euid: 999, grants: [g], now: now))
    }

    @Test("the store-backed check fails closed only for an elevated login-session exec")
    func storeFailureFailsClosedOnlyWhenElevated() async {
        let monitor = ESFMonitor(grantStore: FailingGrantStore(), exemptionCheck: { _, _ in false },
                                 now: { Self.now })
        #expect(await monitor.isExecAllowed(path: "/bin/echo", auid: 501, euid: 0) == false)
        #expect(await monitor.isExecAllowed(path: "/bin/echo", auid: ESFMonitor.unsetAuditUserID, euid: 0))
        #expect(await monitor.isExecAllowed(path: "/bin/echo", auid: 501, euid: 501))
    }

    // MARK: Refresh + lifecycle

    @Test("refresh rebuilds the snapshot from the store")
    func refreshUpdatesSnapshot() async {
        let now = Self.now
        let store = StubGrantStore([
            grant(user: "alice", uid: 501, path: "/bin/echo", expiresAt: now.addingTimeInterval(300)),
        ])
        let monitor = ESFMonitor(grantStore: store, now: { now })

        await monitor.refreshMonitoredSet()
        #expect(monitor.monitoredSnapshot.contains("/bin/echo"))
        #expect(!monitor.monitoredSnapshot.contains("/usr/bin/true"))

        await store.setGrants([
            grant(user: "alice", uid: 501, path: "/bin/echo", expiresAt: now.addingTimeInterval(300)),
            grant(user: "bob", uid: 502, path: "/usr/bin/true", expiresAt: now.addingTimeInterval(300)),
        ])
        await monitor.refreshMonitoredSet()
        #expect(monitor.monitoredSnapshot.contains("/usr/bin/true"))
    }

    @Test("isActive is false before start()")
    func isActiveIsFalseBeforeStart() {
        let monitor = ESFMonitor(grantStore: StubGrantStore([]), now: { Self.now })
        #expect(!monitor.isActive)
    }

    // MARK: Monitored set = live grants only

    @Test("a path with NO active grant is not monitored (root-run jamf and silent sudo allows run)")
    func pathNotMonitoredWithoutGrant() async {
        let monitor = ESFMonitor(grantStore: StubGrantStore([]), now: { Self.now })
        await monitor.refreshMonitoredSet()
        #expect(!monitor.monitoredSnapshot.contains("/usr/sbin/installer"))
    }

    @Test("monitored set is exactly the active-grant paths")
    func monitoredSetIsGrantPaths() async {
        let now = Self.now
        let store = StubGrantStore([
            grant(user: "alice", uid: 501, path: "/opt/tool", expiresAt: now.addingTimeInterval(300)),
        ])
        let monitor = ESFMonitor(grantStore: store, now: { now })
        await monitor.refreshMonitoredSet()
        #expect(monitor.monitoredSnapshot.paths == ["/opt/tool"])
    }

    // MARK: Auth deadline budget (the kernel-deadline safety bound)

    @Test("a deadline already in the past yields a zero budget (respond/deny immediately)")
    func authorizationBudgetPastDeadlineIsZero() {
        #expect(ESFMonitor.authorizationBudget(deadline: 0) == .zero)
        #expect(ESFMonitor.authorizationBudget(deadline: 1) == .zero)
    }

    @Test("a far-future deadline is bounded (never unbounded), capped at 5s")
    func authorizationBudgetIsBoundedAndCapped() {
        // A deadline far out must still cap the budget so the store query can
        // never run unbounded against the kernel's auth deadline.
        let farDeadline = mach_absolute_time() &+ 1_000_000_000_000
        let budget = ESFMonitor.authorizationBudget(deadline: farDeadline)
        #expect(budget > .zero)
        #expect(budget <= .seconds(5))
    }

    @Test("an absurd/malformed deadline does not crash and stays bounded")
    func authorizationBudgetHandlesAbsurdDeadline() {
        let budget = ESFMonitor.authorizationBudget(deadline: UInt64.max)
        #expect(budget >= .zero)
        #expect(budget <= .seconds(5))
    }

    // MARK: Answering within the budget

    @Test("a lookup that blocks past the budget is answered DENY at the budget, not when it returns")
    func slowExemptionLookupAnswersAtTheBudget() async {
        // No grant covers the exec, so the exemption lookup runs — and blocks
        // for 2s, like mbr_check_membership against an unreachable directory
        // node. A thread block ignores cancellation entirely.
        let monitor = ESFMonitor(
            grantStore: StubGrantStore([]),
            exemptionCheck: { _, _ in Thread.sleep(forTimeInterval: 2); return true },
            now: { Self.now }
        )
        let started = ContinuousClock.now
        let answers = AnswerLog()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            ESFMonitor.respond(within: .milliseconds(200), decide: {
                await monitor.isExecAllowed(path: "/opt/tool", auid: 501, euid: 0)
            }, respond: { allowed in
                answers.record(allowed)
                continuation.resume()
            })
        }
        let elapsed = ContinuousClock.now - started
        #expect(answers.values == [false])   // fail closed at the deadline
        #expect(elapsed < .seconds(1))       // not the 2s the lookup takes
        // The late decision (allow, after 2s) is dropped: still exactly one answer.
        try? await Task.sleep(for: .milliseconds(2300))
        #expect(answers.values == [false])
    }

    @Test("a decision that lands inside the budget is the answer, exactly once")
    func fastDecisionIsTheAnswer() async {
        let answers = AnswerLog()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            ESFMonitor.respond(within: .milliseconds(300), decide: { true }, respond: { allowed in
                answers.record(allowed)
                continuation.resume()
            })
        }
        try? await Task.sleep(for: .milliseconds(500)) // let the timer fire, and lose
        #expect(answers.values == [true])
    }

    @Test("exemption verdicts are cached per audit user; a bypass change drops the cache")
    func exemptionIsCachedPerUID() async {
        let calls = CallCounter()
        let monitor = ESFMonitor(
            grantStore: StubGrantStore([]),
            exemptionCheck: { auid, bypass in calls.increment(); return bypass.users.contains("u\(auid)") },
            now: { Self.now }
        )
        #expect(await monitor.isExecAllowed(path: "/opt/tool", auid: 501, euid: 0) == false)
        #expect(await monitor.isExecAllowed(path: "/opt/tool", auid: 501, euid: 0) == false)
        #expect(calls.value == 1)                        // second exec served from the cache
        #expect(await monitor.isExecAllowed(path: "/opt/tool", auid: 502, euid: 0) == false)
        #expect(calls.value == 2)                        // per uid

        monitor.updateBypass(PAMBypass(users: ["u501"])) // a reload changes break-glass
        #expect(await monitor.isExecAllowed(path: "/opt/tool", auid: 501, euid: 0))
        #expect(calls.value == 3)
        monitor.updateBypass(PAMBypass(users: ["u501"])) // unchanged: cache kept
        #expect(await monitor.isExecAllowed(path: "/opt/tool", auid: 501, euid: 0))
        #expect(calls.value == 3)
    }
}

/// Collects `respond` answers from any thread.
private final class AnswerLog: @unchecked Sendable {
    private let lock = NSLock()
    private var _values: [Bool] = []
    var values: [Bool] { lock.lock(); defer { lock.unlock() }; return _values }
    func record(_ value: Bool) { lock.lock(); _values.append(value); lock.unlock() }
}

/// A thread-safe call counter.
private final class CallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return _value }
    func increment() { lock.lock(); _value += 1; lock.unlock() }
}

// MARK: - Break-glass / admin exemption

@Suite("ESFMonitor — break-glass and admin exemption")
struct ESFMonitorExemptionTests {
    private static let now = CoordinatorFixtures.now
    private static let path = "/usr/local/bin/tool"
    // A = granted user, B = break-glass (pamBypass) user, C = current admin, D = neither.
    private static let userA: uid_t = 601, userB: uid_t = 602, adminC: uid_t = 603, userD: uid_t = 604

    private static func grantForA() -> Grant {
        Grant(user: "usera", uid: userA, ruleID: "r", profileKey: "rules_sudo_test", teamID: "",
              binaryHash: "h", canonicalPath: path, grantedAt: now,
              expiresAt: now.addingTimeInterval(300), policyVersion: "1.0.0")
    }

    /// Exemption decided purely from the injected tables (no real accounts).
    private static let exemption: @Sendable (uid_t, PAMBypass) -> Bool = { auid, bypass in
        let names: [uid_t: String] = [userA: "usera", userB: "userb", adminC: "adminc", userD: "userd"]
        if let name = names[auid], bypass.users.contains(name) { return true }
        if bypass.groups.contains("breakglass"), auid == userB { return true }
        return auid == adminC // "admin" member
    }

    private func monitor(bypass: PAMBypass) -> ESFMonitor {
        ESFMonitor(grantStore: StubGrantStore([Self.grantForA()]), bypass: bypass,
                   exemptionCheck: Self.exemption, now: { Self.now })
    }

    @Test("A (granted) is allowed; B (bypass user) and C (admin) are allowed WITHOUT a grant; D is denied")
    func grantedBypassAdminAndOther() async {
        let esf = monitor(bypass: PAMBypass(users: ["userb"]))
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userA, euid: 0))
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userB, euid: 0))
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.adminC, euid: 0))
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userD, euid: 0) == false)
    }

    @Test("a bypass GROUP member is exempt; updateBypass takes effect on the next exec")
    func bypassGroupAndLiveUpdate() async {
        let esf = monitor(bypass: PAMBypass())
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userB, euid: 0) == false)
        esf.updateBypass(PAMBypass(groups: ["breakglass"]))
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userB, euid: 0))
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userD, euid: 0) == false)
    }

    @Test("pure decision: exemption only matters after the grant check fails")
    func pureDecision() {
        let grants = [Self.grantForA()]
        #expect(ESFMonitor.isExecAllowed(path: Self.path, auid: Self.userD, euid: 0, grants: grants,
                                         now: Self.now, isExempt: true))
        #expect(!ESFMonitor.isExecAllowed(path: Self.path, auid: Self.userD, euid: 0, grants: grants,
                                          now: Self.now, isExempt: false))
        #expect(ESFMonitor.isExecAllowed(path: Self.path, auid: Self.userA, euid: 0, grants: grants,
                                         now: Self.now, isExempt: false))
    }

    @Test("an exempt user is allowed even when the grant store is unreadable")
    func exemptSurvivesStoreFailure() async {
        let esf = ESFMonitor(grantStore: FailingGrantStore(), bypass: PAMBypass(users: ["userb"]),
                             exemptionCheck: Self.exemption, now: { Self.now })
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userB, euid: 0))
        #expect(await esf.isExecAllowed(path: Self.path, auid: Self.userD, euid: 0) == false)
    }

    @Test("production exemption: root is a member of admin; an unknown uid is never exempt")
    func productionExemption() {
        #expect(LocalAccounts.userName(uid: 0) == "root")
        #expect(LocalAccounts.isMember(uid: 0, ofGroup: "wheel") == true)
        #expect(ESFMonitor.isExemptUser(auid: 0, bypass: PAMBypass()))            // root ∈ admin
        #expect(!ESFMonitor.isExemptUser(auid: 4_000_000_000, bypass: PAMBypass(users: ["nobody-here"])))
        #expect(ESFMonitor.isExemptUser(auid: 0, bypass: PAMBypass(users: ["root"])))
    }
}

/// Configurable in-memory grant store for ESF tests.
private actor StubGrantStore: GrantMaintaining {
    private var grants: [Grant]
    init(_ grants: [Grant]) { self.grants = grants }
    func setGrants(_ grants: [Grant]) { self.grants = grants }

    func insert(_ grant: Grant) async throws { grants.append(grant) }
    func cleanupExpired(now: Date) async throws -> Int { 0 }
    func activeGrants(now: Date) async throws -> [Grant] { grants.filter { $0.isActive(at: now) } }
    func activeGrants(for user: String, now: Date) async throws -> [Grant] {
        grants.filter { $0.user == user && $0.isActive(at: now) }
    }
    func revokeAll(now: Date) async throws -> Int { 0 }
    func revoke(grantID: UUID, now: Date) async throws -> Int { 0 }
}

/// A grant store whose reads always fail (fail-closed path).
private actor FailingGrantStore: GrantMaintaining {
    struct Failure: Error {}
    func insert(_ grant: Grant) async throws { throw Failure() }
    func cleanupExpired(now: Date) async throws -> Int { throw Failure() }
    func activeGrants(now: Date) async throws -> [Grant] { throw Failure() }
    func activeGrants(for user: String, now: Date) async throws -> [Grant] { throw Failure() }
    func revokeAll(now: Date) async throws -> Int { throw Failure() }
    func revoke(grantID: UUID, now: Date) async throws -> Int { throw Failure() }
}

/// A build without the Endpoint Security entitlement: the exec gate is off,
/// said once, recorded in state.plist, and nothing else changes.
@Suite("Exec gate without the Endpoint Security entitlement", .serialized)
struct ExecGateStatusTests {
    @Test("a missing entitlement is recognized and described plainly")
    func notEntitledError() {
        let error = ESFMonitor.ESFError.clientCreationFailed(ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED)
        #expect(error.isNotEntitled)
        #expect(error.description.contains("no Endpoint Security entitlement"))
        #expect(!ESFMonitor.ESFError.clientCreationFailed(ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED).isNotEntitled)
        #expect(!ESFMonitor.ESFError.subscribeFailed(ES_RETURN_ERROR).isNotEntitled)
    }

    @Test("this unentitled test process cannot start the monitor, and it throws rather than crashing")
    func startThrowsHere() async {
        let monitor = ESFMonitor(grantStore: NullGrantStore(), bypass: PAMBypass(), now: { CoordinatorFixtures.now })
        await #expect(throws: ESFMonitor.ESFError.self) { try await monitor.start() }
    }

    @Test("state.plist carries the exec gate status beside the state, which stays as it was")
    func statePlist() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("state.plist")
        let controller = DaemonStateController(statePlist: url, integrityLogger: nil)
        await controller.transition(to: .healthy)
        await controller.setExecGate(.notEntitled)
        await controller.transition(to: .healthy)   // later writes keep it
        let plist = try #require(try PropertyListSerialization.propertyList(
            from: Data(contentsOf: url), format: nil) as? [String: Any])
        #expect(plist["state"] as? String == "healthy")
        #expect(plist["execGate"] as? String == "off_not_entitled")
        #expect((plist["execGateDetail"] as? String)?.contains("sudo, AuthorizationDB rights and JIT admin") == true)
        #expect(plist["degradedReason"] == nil)

        await controller.setExecGate(.active)
        let active = try #require(try PropertyListSerialization.propertyList(
            from: Data(contentsOf: url), format: nil) as? [String: Any])
        #expect(active["execGate"] as? String == "active")
        #expect(active["execGateDetail"] == nil)
    }
}
