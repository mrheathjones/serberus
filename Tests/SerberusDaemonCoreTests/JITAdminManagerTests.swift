import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

// MARK: - Fakes

private struct StoreFailure: Error {}

private actor MemGrantStore: GrantMaintaining, UnverifiedJITRowSource {
    private var grants: [Grant] = []
    /// Unverifiable JIT rows the fake reports (HMAC failure stand-ins).
    private var unverified: [UnverifiedJITRow] = []
    /// Row IDs retired through ``retireUnverifiedRow(rowID:)``.
    private(set) var retired: [Int64] = []

    func setUnverified(_ rows: [UnverifiedJITRow]) { unverified = rows }
    func unverifiedJITCandidates() async throws -> [UnverifiedJITRow] {
        unverified.filter { !retired.contains($0.rowID) }
    }
    func retireUnverifiedRow(rowID: Int64) async throws -> Bool {
        retired.append(rowID)
        return true
    }
    /// Simulates SQLITE_FULL / a NullGrantStore-style insert failure.
    var failInsert = false
    /// Simulates an unreadable store (every read throws).
    var failReads = false
    /// Simulates a revoke that throws.
    var failRevoke = false

    init(grants: [Grant] = []) { self.grants = grants }

    func setFailInsert(_ value: Bool) { failInsert = value }
    func setFailReads(_ value: Bool) { failReads = value }
    func setFailRevoke(_ value: Bool) { failRevoke = value }

    func insert(_ grant: Grant) async throws {
        if failInsert { throw StoreFailure() }
        grants.append(grant)
    }
    func cleanupExpired(now: Date) async throws -> Int { 0 }
    func activeGrants(now: Date) async throws -> [Grant] {
        if failReads { throw StoreFailure() }
        return grants.filter { $0.isActive(at: now) }
    }
    func activeGrants(for user: String, now: Date) async throws -> [Grant] {
        if failReads { throw StoreFailure() }
        return grants.filter { $0.user == user && $0.isActive(at: now) }
    }
    func allGrants() async throws -> [Grant] {
        if failReads { throw StoreFailure() }
        return grants
    }
    /// Test-side view that ignores `failReads`.
    func snapshot() -> [Grant] { grants }

    @discardableResult func revokeAll(now: Date) async throws -> Int {
        var count = 0
        grants = grants.map {
            guard $0.revokedAt == nil else { return $0 }
            count += 1
            return Self.revoked($0, at: now)
        }
        return count
    }
    @discardableResult func revoke(grantID: UUID, now: Date) async throws -> Int {
        if failRevoke { throw StoreFailure() }
        guard let index = grants.firstIndex(where: { $0.grantID == grantID && $0.revokedAt == nil }) else { return 0 }
        grants[index] = Self.revoked(grants[index], at: now)
        return 1
    }

    private static func revoked(_ grant: Grant, at now: Date) -> Grant {
        Grant(grantID: grant.grantID, user: grant.user, uid: grant.uid, ruleID: grant.ruleID,
              profileKey: grant.profileKey, teamID: grant.teamID, binaryHash: grant.binaryHash,
              canonicalPath: grant.canonicalPath, argvPattern: grant.argvPattern,
              grantedAt: grant.grantedAt, expiresAt: grant.expiresAt, revokedAt: now,
              policyVersion: grant.policyVersion)
    }
}

private actor FakeMembership: GroupMembershipControlling {
    private var members: Set<String> = []
    private var userGroups: [String: Set<String>] = [:]
    var failAdd = false
    /// With `failAdd`: the add LANDS and then the command reports failure (a
    /// timed-out `dseditgroup` killed after the mutation took effect).
    var addLandsDespiteFailure = false
    /// Simulates `dseditgroup -o checkmember` failing to DETERMINE membership
    /// (unreachable directory node / timeout) — distinct from a clean "not a
    /// member", which is a plain `false`.
    var failCheckMember = false
    /// Simulates a removal that does not land (e.g. a timed-out `dseditgroup`
    /// killed mid-mutation): the membership SURVIVES and the error is raised.
    var failRemove = false
    private(set) var addCount = 0
    private(set) var removeCount = 0
    /// Delay inside `groups(forUser:)` so two requests can interleave.
    var groupsDelay: Duration = .zero

    init(members: Set<String> = [], userGroups: [String: Set<String>] = [:]) {
        self.members = members
        self.userGroups = userGroups
    }

    private func key(_ user: String, _ group: String) -> String { "\(user)|\(group)" }

    /// Users whose record `dseditgroup` cannot find (exit 64): deleted,
    /// renamed, or on an unreachable directory node.
    private var missingRecords: Set<String> = []
    func setMissingRecord(_ user: String) { missingRecords.insert(user) }

    func isMember(user: String, group: String) async throws -> Bool {
        if failCheckMember {
            throw JITAdminError.commandTimedOut(path: "/usr/sbin/dseditgroup", seconds: 10)
        }
        if missingRecords.contains(user) { throw JITAdminError.userRecordNotFound(user: user) }
        return members.contains(key(user, group))
    }
    func groups(forUser user: String) async -> Set<String> {
        if groupsDelay > .zero { try? await Task.sleep(for: groupsDelay) }
        return userGroups[user] ?? []
    }
    func setGroupsDelay(_ delay: Duration) { groupsDelay = delay }
    /// Removes a member out-of-band (an admin edited the group by hand).
    func removeDirect(_ user: String, _ group: String) { members.remove(key(user, group)) }
    func addMember(user: String, group: String) async throws {
        addCount += 1
        if failAdd {
            if addLandsDespiteFailure { members.insert(key(user, group)) }
            throw JITAdminError.membershipCommandFailed(status: 1)
        }
        members.insert(key(user, group))
    }
    func removeMember(user: String, group: String) async throws {
        removeCount += 1
        if missingRecords.contains(user) { throw JITAdminError.membershipCommandFailed(status: 64) }
        if failRemove {
            // Throw WITHOUT removing: the whole point is that the user is still
            // in the group when the caller sees the error.
            throw JITAdminError.commandTimedOut(path: "/usr/sbin/dseditgroup", seconds: 10)
        }
        members.remove(key(user, group))
    }
    func setFailAdd(_ value: Bool, landed: Bool = false) {
        failAdd = value
        addLandsDespiteFailure = landed
    }
    func setFailCheckMember(_ value: Bool) { failCheckMember = value }
    func setFailRemove(_ value: Bool) { failRemove = value }
    func contains(_ user: String, _ group: String) -> Bool { members.contains(key(user, group)) }
}

// MARK: - Tests

@Suite("JITAdminManager — Serberus provider")
struct JITAdminManagerSerberusTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func make(policy: JITAdminPolicy, membership: FakeMembership,
                      store: MemGrantStore = MemGrantStore()) -> JITAdminManager {
        JITAdminManager(
            policyProvider: { policy }, membership: membership,
            grantStore: store, decisionLogger: nil, integrityLogger: nil, now: { self.now }
        )
    }

    @Test("eligible user is added to admin and gets a timed grant")
    func grantsEligible() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)
        let membership = FakeMembership(userGroups: ["alice": ["developers", "staff"]])
        let manager = make(policy: policy, membership: membership)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the build box")
        #expect(result.outcome == .granted)
        #expect(result.expiresAt == now.addingTimeInterval(900))
        #expect(await membership.contains("alice", "admin"))
        await manager.stop()
    }

    @Test("ineligible user is denied and not added")
    func deniesIneligible() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"])
        let membership = FakeMembership(userGroups: ["bob": ["staff"]])
        let manager = make(policy: policy, membership: membership)

        let result = await manager.requestElevation(user: "bob", uid: 502, justification: "please")
        #expect(result.outcome == .denied)
        #expect(!(await membership.contains("bob", "admin")))
    }

    @Test("missing justification is denied before any membership change")
    func deniesMissingJustification() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"],
                                    requireJustification: true, justificationMinLength: 10)
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let manager = make(policy: policy, membership: membership)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "too short")
        #expect(result.outcome == .denied)
        #expect(!(await membership.contains("alice", "admin")))
    }

    @Test("membership check FAILS to determine: denied, never promoted (a permanent admin must not be demotable)")
    func unknownMembershipFailsClosed() async {
        // `dseditgroup` opens an OpenDirectory session and can block on an
        // unreachable node. Bounding it (GroupMembership.swift) turned that hang
        // into an ANSWER — and reporting "not a member" here would be the WRONG
        // answer: `alice` may be a permanent admin, in which case Serberus would
        // promote her (a no-op), then strip her real admin rights at expiry.
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"])
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        await membership.setFailCheckMember(true)
        let store = MemGrantStore()
        let manager = make(policy: policy, membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "unknown membership")

        #expect(result.outcome == .denied)
        #expect(await membership.addCount == 0)              // never promoted
        #expect((try? await store.allGrants())?.isEmpty == true) // ⇒ no demotion is ever scheduled
    }

    @Test("a demotion whose group removal FAILS keeps the grant ACTIVE, so recovery can retry")
    func failedDemotionKeepsGrantActiveForRetry() async {
        // The trap: `demoteAll`/`reconcile`/`expire` all filter on
        // `revokedAt == nil`. Stamping revokedAt when the removal did NOT land
        // would hide a real, Serberus-created admin from every recovery path
        // forever — while the log claimed a clean demotion.
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let manager = make(policy: policy, membership: membership, store: store)

        let granted = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")
        #expect(granted.outcome == .granted)

        await membership.setFailRemove(true)
        let demoted = await manager.endElevation(user: "alice")

        #expect(demoted == false)                        // reported as the failure it is
        #expect(await membership.contains("alice", "admin")) // still admin — the removal did not land
        let grants = (try? await store.allGrants()) ?? []
        #expect(grants.count == 1)
        #expect(grants[0].revokedAt == nil) // ⇒ still visible to demoteAll/reconcile/expire

        // Recovery must actually work once the directory answers again.
        await membership.setFailRemove(false)
        #expect(await manager.demoteAll() == 1)
        #expect(!(await membership.contains("alice", "admin")))
        await manager.stop()
    }

    @Test("an already-permanent admin is a no-op — never scheduled for demotion")
    func alreadyAdminNoOp() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"])
        let membership = FakeMembership(members: ["alice|admin"], userGroups: ["alice": ["developers", "admin"]])
        let store = MemGrantStore()
        let manager = make(policy: policy, membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "already an admin here")
        #expect(result.outcome == .alreadyAdmin)
        // No grant was created, so nothing will ever demote the permanent admin.
        #expect((try? await store.allGrants())?.isEmpty == true)
        #expect(await membership.contains("alice", "admin"))
    }

    @Test("a second request while active returns the existing window")
    func idempotentActive() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let manager = make(policy: policy, membership: membership, store: store)

        _ = await manager.requestElevation(user: "alice", uid: 501, justification: "first request here")
        let second = await manager.requestElevation(user: "alice", uid: 501, justification: "second request here")
        #expect(second.outcome == .alreadyActive)
        #expect((try? await store.allGrants())?.count == 1)
        await manager.stop()
    }

    @Test("failed group add denies and leaves no ACTIVE grant")
    func failedAddDenies() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"])
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        await membership.setFailAdd(true)
        let store = MemGrantStore()
        let manager = make(policy: policy, membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "legitimate reason")
        #expect(result.outcome == .denied)
        // The grant is persisted BEFORE the add, so a row exists — but it was
        // retired when the add failed: nothing active, nothing to demote.
        #expect((try? await store.activeGrants(now: now))?.isEmpty == true)
    }

    @Test("ending early demotes the user and revokes the grant")
    func endEarly() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let manager = make(policy: policy, membership: membership, store: store)

        _ = await manager.requestElevation(user: "alice", uid: 501, justification: "temporary access here")
        let ended = await manager.endElevation(user: "alice")
        #expect(ended)
        #expect(!(await membership.contains("alice", "admin")))
        #expect((try? await store.activeGrants(now: now))?.isEmpty == true)
    }

    @Test("demoteAll strips every active JIT admin")
    func demoteAll() async {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)
        let membership = FakeMembership(userGroups: ["alice": ["developers"], "carol": ["developers"]])
        let manager = make(policy: policy, membership: membership)

        _ = await manager.requestElevation(user: "alice", uid: 501, justification: "reason enough here")
        _ = await manager.requestElevation(user: "carol", uid: 502, justification: "reason enough here")
        let count = await manager.demoteAll()
        #expect(count == 2)
        #expect(!(await membership.contains("alice", "admin")))
        #expect(!(await membership.contains("carol", "admin")))
    }
}

@Suite("JITAdminManager — reconcile + Jamf Connect")
struct JITAdminManagerReconcileTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    @Test("reconcile demotes a grant that expired while the daemon was down")
    func reconcileDemotesExpired() async {
        // Seed a grant that expired one hour ago, with the user still in admin.
        let store = MemGrantStore()
        let expired = Grant(user: "alice", uid: 501, ruleID: "jit-self-service",
                            profileKey: JITAdminGrant.profileKey, teamID: "", binaryHash: "",
                            canonicalPath: JITAdminGrant.canonicalPath,
                            grantedAt: now.addingTimeInterval(-7200),
                            expiresAt: now.addingTimeInterval(-3600), policyVersion: "jit")
        try? await store.insert(expired)
        let membership = FakeMembership(members: ["alice|admin"])
        let manager = JITAdminManager(
            policyProvider: { JITAdminPolicy(provider: .serberus, eligibleGroups: ["x"]) },
            membership: membership,
            grantStore: store, decisionLogger: nil, integrityLogger: nil, now: { self.now })

        await manager.reconcile()
        #expect(!(await membership.contains("alice", "admin")))
    }

    @Test("the daemon refuses jamfConnect — it runs in the user session, not root")
    func daemonRefusesJamfConnect() async {
        // JC elevation is launched by the Agent in the user's session; if a
        // caller routes it to the daemon it must be denied, and no group touched.
        let membership = FakeMembership()
        let manager = JITAdminManager(
            policyProvider: { JITAdminPolicy(provider: .jamfConnect) }, membership: membership,
            grantStore: MemGrantStore(), decisionLogger: nil, integrityLogger: nil, now: { self.now })

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "")
        #expect(result.outcome == .denied)
        #expect(!(await membership.contains("alice", "admin")))
    }

    @Test("disabled provider always denies")
    func disabledDenies() async {
        let manager = JITAdminManager(
            policyProvider: { .disabledDefault }, membership: FakeMembership(),
            grantStore: MemGrantStore(), decisionLogger: nil, integrityLogger: nil, now: { self.now })
        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "anything at all here")
        #expect(result.outcome == .denied)
    }
}

// MARK: - Grant-first ordering (no permanent admin on a failed insert)

@Suite("JITAdminManager — grant persisted before promotion")
struct JITAdminManagerGrantOrderingTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)
    private let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)

    private func make(membership: FakeMembership, store: GrantMaintaining,
                      degraded: Bool = false) -> JITAdminManager {
        JITAdminManager(
            policyProvider: { [policy] in policy }, membership: membership,
            grantStore: store, decisionLogger: nil, integrityLogger: nil,
            grantStoreDegraded: degraded, now: { self.now }
        )
    }

    @Test("a grant insert that THROWS denies the request and never touches the admin group")
    func insertFailureDenies() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        await store.setFailInsert(true)
        let manager = make(membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(result.outcome == .denied)
        #expect(await membership.addCount == 0)          // never promoted…
        #expect(!(await membership.contains("alice", "admin")))
        #expect(await store.snapshot().isEmpty)          // …and nothing to demote
    }

    @Test("NullGrantStore (grants_db_error): JIT is refused, no promotion")
    func nullGrantStoreRefuses() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let manager = make(membership: membership, store: NullGrantStore())

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(result.outcome == .denied)
        #expect(await membership.addCount == 0)
    }

    @Test("a degraded grant store refuses JIT up front, even if the store would accept writes")
    func degradedFlagRefuses() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let manager = make(membership: membership, store: store, degraded: true)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(result.outcome == .denied)
        #expect(await membership.addCount == 0)
        #expect(await store.snapshot().isEmpty)
    }

    @Test("an UNREADABLE store is not 'no active grant': denied, no promotion")
    func unreadableStoreDenies() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        await store.setFailReads(true)
        let manager = make(membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(result.outcome == .denied)
        #expect(await membership.addCount == 0)
        #expect(await store.snapshot().isEmpty)
    }

    @Test("addMember THROWS (add did not land): the persisted grant row is retired")
    func addFailureRetiresGrant() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        await membership.setFailAdd(true)
        let store = MemGrantStore()
        let manager = make(membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(result.outcome == .denied)
        #expect(!(await membership.contains("alice", "admin")))
        let rows = await store.snapshot()
        #expect(rows.count == 1)
        #expect(rows[0].revokedAt != nil)                // retired: no active grant left behind
        #expect((try? await store.activeGrants(now: now))?.isEmpty == true)
    }

    @Test("addMember THROWS but the add LANDED: rolled back by demotion, grant revoked only after removal")
    func addFailureThatLandedIsRolledBack() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        await membership.setFailAdd(true, landed: true)
        let store = MemGrantStore()
        let manager = make(membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(result.outcome == .denied)
        #expect(await membership.removeCount == 1)
        #expect(!(await membership.contains("alice", "admin"))) // not left a permanent admin
        #expect(await store.snapshot().first?.revokedAt != nil)
        await manager.stop()
    }

    @Test("rollback removal that FAILS keeps the grant ACTIVE so every recovery path still sees it")
    func failedRollbackKeepsGrantActive() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        await membership.setFailAdd(true, landed: true)
        await membership.setFailRemove(true)
        let store = MemGrantStore()
        let manager = make(membership: membership, store: store)

        _ = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(await membership.contains("alice", "admin"))
        #expect(await store.snapshot().first?.revokedAt == nil)  // visible to demoteAll/reconcile/--demote-jit
        await membership.setFailRemove(false)
        #expect(await manager.demoteAll() == 1)
        #expect(!(await membership.contains("alice", "admin")))
        await manager.stop()
    }

    @Test("a successful grant is persisted BEFORE the group add")
    func grantPersistedBeforeAdd() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let manager = make(membership: membership, store: store)

        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box")

        #expect(result.outcome == .granted)
        let rows = await store.snapshot()
        #expect(rows.count == 1)
        #expect(rows.first?.grantID == result.grantID)
        #expect(rows.first?.revokedAt == nil)
        await manager.stop()
    }
}

// MARK: - `serberusd --demote-jit` core

@Suite("JITDemotionSweep (serberusd --demote-jit)")
struct JITDemotionSweepTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func jitGrant(_ user: String, uid: uid_t = 501, expiresIn: TimeInterval,
                          revoked: Bool = false) -> Grant {
        Grant(user: user, uid: uid, ruleID: "jit-self-service",
              profileKey: JITAdminGrant.profileKey, teamID: "", binaryHash: "",
              canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: now.addingTimeInterval(-600),
              expiresAt: now.addingTimeInterval(expiresIn),
              revokedAt: revoked ? now.addingTimeInterval(-60) : nil,
              policyVersion: "jit")
    }

    @Test("demotes every UNREVOKED JIT holder (revoked rows never qualify), marks the grants revoked, exit 0")
    func demotesQualifyingUsers() async {
        let store = MemGrantStore(grants: [
            jitGrant("alice", expiresIn: 600),                        // live window
            jitGrant("bob", uid: 502, expiresIn: -600),               // expired, demotion never landed
            jitGrant("carol", uid: 503, expiresIn: 600, revoked: true), // revoked by a blanket revoke, still admin
            jitGrant("dave", uid: 504, expiresIn: -600, revoked: true), // cleanly demoted: ignored
        ])
        let membership = FakeMembership(members: ["alice|admin", "bob|admin", "carol|admin", "dave|admin"])

        let report = await DaemonMode.demoteJITAdmins(
            grantStore: store, membership: membership, integrityLogger: nil, now: now, echo: { _ in })

        #expect(report.succeeded)
        // A REVOKED row never qualifies, even while unexpired: carol ended JIT
        // early and was later made a real admin — she must not be demoted.
        #expect(report.demoted == ["alice", "bob"])
        #expect(!(await membership.contains("alice", "admin")))
        #expect(!(await membership.contains("bob", "admin")))
        #expect(await membership.contains("carol", "admin"))
        #expect(await membership.contains("dave", "admin")) // a revoked+expired grant never qualifies
        let rows = await store.snapshot()
        #expect(rows.allSatisfy { $0.revokedAt != nil })
        #expect(report.revokedGrantIDs.count == 2) // alice + bob (carol's row was already revoked)
    }

    @Test("a non-JIT grant is never touched")
    func ignoresNonJITGrants() async {
        let binary = Grant(user: "erin", uid: 505, ruleID: "allow-brew", profileKey: "rules_sudo",
                           teamID: "", binaryHash: "abc", canonicalPath: "/opt/homebrew/bin/brew",
                           grantedAt: now, expiresAt: now.addingTimeInterval(600), policyVersion: "1")
        let store = MemGrantStore(grants: [binary])
        let membership = FakeMembership(members: ["erin|admin"])

        let report = await DaemonMode.demoteJITAdmins(
            grantStore: store, membership: membership, integrityLogger: nil, now: now, echo: { _ in })

        #expect(report.succeeded)
        #expect(report.demoted.isEmpty)
        #expect(await membership.contains("erin", "admin"))
        #expect(await store.snapshot().first?.revokedAt == nil)
    }

    @Test("a user already out of admin: grant retired, success, no removal attempted")
    func alreadyNotAdmin() async {
        let store = MemGrantStore(grants: [jitGrant("alice", expiresIn: 600)])
        let membership = FakeMembership()

        let report = await DaemonMode.demoteJITAdmins(
            grantStore: store, membership: membership, integrityLogger: nil, now: now, echo: { _ in })

        #expect(report.succeeded)
        #expect(report.alreadyNotAdmin == ["alice"])
        #expect(await membership.removeCount == 0)
        #expect(await store.snapshot().first?.revokedAt != nil)
    }

    @Test("a failed removal fails the run (exit 1) but every user is still attempted; its grant stays active")
    func failureStillAttemptsEveryUser() async {
        let store = MemGrantStore(grants: [jitGrant("alice", expiresIn: 600), jitGrant("bob", uid: 502, expiresIn: 600)])
        let membership = FakeMembership(members: ["alice|admin", "bob|admin"])
        await membership.setFailRemove(true)

        let report = await DaemonMode.demoteJITAdmins(
            grantStore: store, membership: membership, integrityLogger: nil, now: now, echo: { _ in })

        #expect(!report.succeeded)
        #expect(Set(report.failures.keys) == ["alice", "bob"])
        #expect(await membership.removeCount == 2)            // both attempted
        #expect(await store.snapshot().allSatisfy { $0.revokedAt == nil }) // never marked revoked while still admin
    }

    @Test("an unreadable store fails with a clear message (exit 1)")
    func unreadableStoreFails() async {
        let store = MemGrantStore(grants: [jitGrant("alice", expiresIn: 600)])
        await store.setFailReads(true)
        let membership = FakeMembership(members: ["alice|admin"])
        let lines = LineCollector()

        let report = await DaemonMode.demoteJITAdmins(
            grantStore: store, membership: membership, integrityLogger: nil, now: now,
            echo: { line in lines.append(line) })

        #expect(!report.succeeded)
        #expect(report.failures["<store>"] != nil)
        #expect(lines.all.contains { $0.contains("grant store unreadable") })
        #expect(await membership.removeCount == 0)
    }

    @Test("each demotion is logged")
    func logsEachDemotion() async {
        let store = MemGrantStore(grants: [jitGrant("alice", expiresIn: 600), jitGrant("bob", uid: 502, expiresIn: -60)])
        let membership = FakeMembership(members: ["alice|admin", "bob|admin"])
        let lines = LineCollector()

        _ = await DaemonMode.demoteJITAdmins(
            grantStore: store, membership: membership, integrityLogger: nil, now: now,
            echo: { line in lines.append(line) })

        #expect(lines.all.contains { $0.contains("removed alice from admin") })
        #expect(lines.all.contains { $0.contains("removed bob from admin") })
    }
}

/// Thread-safe line sink for the sweep's `echo` closure.
private final class LineCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        lines.append(line)
    }
    var all: [String] {
        lock.lock(); defer { lock.unlock() }
        return lines
    }
}

// MARK: - JIT hygiene: membership-first demotion, in-flight guard, wall-clock expiry, unverifiable rows

/// A settable clock for wall-clock expiry tests.
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    init(_ start: Date) { current = start }
    func advance(_ seconds: TimeInterval) { lock.lock(); current += seconds; lock.unlock() }
    var now: Date { lock.lock(); defer { lock.unlock() }; return current }
}

@Suite("JITAdminManager — hygiene")
struct JITAdminManagerHygieneTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)
    private let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)

    private func jitGrant(_ user: String, expiresIn: TimeInterval) -> Grant {
        Grant(user: user, uid: 501, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: start.addingTimeInterval(-60), expiresAt: start.addingTimeInterval(expiresIn),
              policyVersion: "jit")
    }

    @Test("a user already removed from admin by hand: demotion SUCCEEDS and retires the row (no removal call)")
    func demotingANonMemberSucceeds() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let manager = JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                                      decisionLogger: nil, integrityLogger: nil, now: { start })
        #expect(await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box").outcome == .granted)
        await membership.removeDirect("alice", "admin")

        #expect(await manager.endElevation(user: "alice"))
        #expect(await membership.removeCount == 0)
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
        await manager.stop()
    }

    @Test("concurrent requests from the same user stack NO second grant or promotion")
    func concurrentRequestsSameUser() async {
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        await membership.setGroupsDelay(.milliseconds(100))
        let store = MemGrantStore()
        let manager = JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                                      decisionLogger: nil, integrityLogger: nil, now: { start })
        async let first = manager.requestElevation(user: "alice", uid: 501, justification: "first request here")
        async let second = manager.requestElevation(user: "alice", uid: 501, justification: "second request here")
        let outcomes = await [first.outcome, second.outcome]
        #expect(outcomes.filter { $0 == .granted }.count == 1)
        #expect(await membership.addCount == 1)
        #expect(await store.snapshot().count == 1)
        await manager.stop()
    }

    @Test("the reload-tick sweep demotes an unrevoked JIT grant past its wall-clock expiry")
    func expireOverdueDemotes() async {
        let clock = TestClock(start)
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let manager = JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                                      decisionLogger: nil, integrityLogger: nil, now: { clock.now })
        #expect(await manager.requestElevation(user: "alice", uid: 501, justification: "patching the box").outcome == .granted)

        #expect(await manager.expireOverdue() == 0)        // still inside the window
        #expect(await membership.contains("alice", "admin"))

        clock.advance(901)                                  // e.g. the Mac slept through expiry
        #expect(await manager.expireOverdue() == 1)
        #expect(!(await membership.contains("alice", "admin")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
        await manager.stop()
    }

    @Test("unverifiable JIT rows are DEMOTION candidates in the daemon (reconcile), then retired")
    func unverifiedRowsDemotedByReconcile() async {
        let membership = FakeMembership(members: ["mallory|admin"])
        let store = MemGrantStore()
        await store.setUnverified([
            UnverifiedJITRow(rowID: 7, grantID: nil, user: "mallory", reason: "HMAC verification failed"),
            UnverifiedJITRow(rowID: 8, grantID: nil, user: nil, reason: "row does not decode"),
        ])
        let manager = JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                                      decisionLogger: nil, integrityLogger: nil, now: { start })
        await manager.reconcile()
        #expect(!(await membership.contains("mallory", "admin")))
        #expect(await store.retired == [7])               // the unreadable-user row is left for a human
    }

    @Test("unverifiable rows: a non-member is retired without a removal; demoteAll and the tick handle them too")
    func unverifiedRowsOtherPaths() async {
        let membership = FakeMembership(members: ["eve|admin"])
        let store = MemGrantStore()
        await store.setUnverified([
            UnverifiedJITRow(rowID: 1, grantID: nil, user: "bob", reason: "HMAC verification failed"),
        ])
        let manager = JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                                      decisionLogger: nil, integrityLogger: nil, now: { start })
        #expect(await manager.expireOverdue() == 0)
        #expect(await membership.removeCount == 0)
        #expect(await store.retired == [1])

        await store.setUnverified([
            UnverifiedJITRow(rowID: 2, grantID: nil, user: "eve", reason: "HMAC verification failed"),
        ])
        #expect(await manager.demoteAll() == 1)
        #expect(!(await membership.contains("eve", "admin")))
    }

    @Test("teardown sweep: unverifiable JIT rows demote their users but are never written")
    func sweepUnverifiedCandidates() async {
        let membership = FakeMembership(members: ["mallory|admin", "alice|admin"])
        let store = MemGrantStore(grants: [jitGrant("alice", expiresIn: 600)])
        await store.setUnverified([
            UnverifiedJITRow(rowID: 3, grantID: nil, user: "mallory", reason: "HMAC verification failed"),
        ])
        let report = await DaemonMode.demoteJITAdmins(grantStore: store, membership: membership,
                                                      integrityLogger: nil, now: start, echo: { _ in })
        #expect(report.succeeded)
        #expect(report.demoted == ["alice", "mallory"])
        #expect(report.unverifiedCandidates == ["mallory"])
        #expect(await store.retired.isEmpty)
    }
}

@Suite("dseditgroup checkmember exit status")
struct CheckMemberStatusTests {
    @Test("0 = member, 67 = not a member, 64 = no user record, anything else throws")
    func statuses() throws {
        #expect(try DirectoryServicesGroupController.interpretCheckMember(status: 0))
        #expect(try !DirectoryServicesGroupController.interpretCheckMember(status: 67))
        #expect(throws: JITAdminError.userRecordNotFound(user: "gone")) {
            _ = try DirectoryServicesGroupController.interpretCheckMember(status: 64, user: "gone")
        }
        for status: Int32 in [1, 2, 70, 255] {
            #expect(throws: JITAdminError.membershipCommandFailed(status: status)) {
                _ = try DirectoryServicesGroupController.interpretCheckMember(status: status)
            }
        }
    }

    @Test("isMember surfaces exit 64 as userRecordNotFound, never as 'not a member'")
    func exit64Throws() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-dsedit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let tool = dir.appendingPathComponent("dseditgroup")
        try "#!/bin/sh\nexit 64\n".write(to: tool, atomically: true, encoding: .utf8)
        #expect(chmod(tool.path, 0o755) == 0)
        let controller = DirectoryServicesGroupController(dseditgroup: tool.path)
        await #expect(throws: JITAdminError.userRecordNotFound(user: "someone")) {
            _ = try await controller.isMember(user: "someone", group: "admin")
        }
    }
}

/// Scripted ``JITAccountResolving`` answer, recording what it was asked.
private final class ScriptedAccountResolver: JITAccountResolving, @unchecked Sendable {
    private let lock = NSLock()
    private let answer: JITAccountIdentity
    private var _asked: [(String, uid_t?)] = []
    init(_ answer: JITAccountIdentity) { self.answer = answer }
    var asked: [(String, uid_t?)] { lock.withLock { _asked } }
    func identify(user: String, uid: uid_t?) async -> JITAccountIdentity {
        lock.withLock { _asked.append((user, uid)) }
        return answer
    }
}

/// Scripted local directory node.
private struct ScriptedLocalNode: LocalDirectoryProbing {
    var byName: LocalNodeLookup = .absent
    var byUID: LocalNodeLookup = .absent
    var network: Bool? = false
    func userRecord(named name: String) async -> LocalNodeLookup { byName }
    func userRecord(uid: uid_t) async -> LocalNodeLookup { byUID }
    func networkDirectoryConfigured() async -> Bool? { network }
}

@Suite("JIT account identity: deleted, renamed, or unreachable")
struct JITAccountIdentityTests {
    private func resolver(name: AccountLookup = .notFound, uid: AccountLookup = .notFound,
                          node: ScriptedLocalNode = ScriptedLocalNode()) -> DirectoryJITAccountResolver {
        DirectoryJITAccountResolver(byName: { _ in name }, byUID: { _ in uid }, localNode: node)
    }

    @Test("gone only when name AND uid find nothing, the local node has neither, and no network directory is configured")
    func goneNeedsEverySource() async {
        #expect(await resolver().identify(user: "alice", uid: 501) == .gone)
        #expect(await resolver().identify(user: "alice", uid: nil) == .gone)
        // Any source that still knows the account, or cannot answer, keeps the row.
        for candidate in [
            resolver(name: .failed),
            resolver(uid: .failed),
            resolver(node: ScriptedLocalNode(byName: .present)),
            resolver(node: ScriptedLocalNode(byName: .failed)),
            resolver(node: ScriptedLocalNode(byUID: .present)),
            resolver(node: ScriptedLocalNode(byUID: .failed)),
            resolver(node: ScriptedLocalNode(network: true)),   // a network account on an unreachable node
            resolver(node: ScriptedLocalNode(network: nil)),
        ] {
            guard case .undetermined = await candidate.identify(user: "alice", uid: 501) else {
                Issue.record("an undecided account was treated as settled"); continue
            }
        }
    }

    @Test("the uid decides a rename; a name that still resolves is present")
    func renameAndPresent() async {
        #expect(await resolver(uid: .found("alice2")).identify(user: "alice", uid: 501) == .renamed(to: "alice2"))
        #expect(await resolver(uid: .found("alice")).identify(user: "alice", uid: 501) == .present)
        #expect(await resolver(name: .found("alice")).identify(user: "alice", uid: nil) == .present)
    }

    @Test("passwd lookups keep 'found nothing' apart from a found record")
    func passwdLookups() {
        #expect(LocalAccounts.lookupUser(named: "root") == .found("root"))
        #expect(LocalAccounts.lookupUser(uid: 0) == .found("root"))
        #expect(LocalAccounts.lookupUser(named: "serberus-no-such-user-\(UUID().uuidString.prefix(8))") == .notFound)
        #expect(LocalAccounts.lookupUser(uid: 3_999_999_999) == .notFound)
    }

    @Test("dscl output parsing: record-not-found and the search path")
    func dsclParsing() {
        typealias P = DSCLLocalDirectoryProbe
        #expect(P.isRecordNotFound(status: 56, output: "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"))
        #expect(!P.isRecordNotFound(status: 56, output: "<dscl_cmd> DS Error: -14140 (eDSNodeNotFound)"))
        #expect(!P.isRecordNotFound(status: 0, output: "eDSRecordNotFound"))
        #expect(P.searchPathHasNetworkNode("CSPSearchPath: /Local/Default\n") == false)
        #expect(P.searchPathHasNetworkNode("CSPSearchPath:\n /Local/Default\n /BSD/local\n") == false)
        #expect(P.searchPathHasNetworkNode("CSPSearchPath:\n /Local/Default\n /Active Directory/CORP/All Domains\n") == true)
        #expect(P.searchPathHasNetworkNode("") == nil)
    }

    @Test("the production local-node probe answers for real records")
    func liveProbe() async {
        let probe = DSCLLocalDirectoryProbe()
        #expect(await probe.userRecord(named: "root") == .present)
        #expect(await probe.userRecord(named: "serberus-no-such-user-\(UUID().uuidString.prefix(8))") == .absent)
        #expect(await probe.userRecord(named: "../Groups/admin") == .failed)   // never a different path
        #expect(await probe.userRecord(uid: 0) == .present)
        #expect(await probe.userRecord(uid: 3_999_999_999) == .absent)
        #expect(await probe.networkDirectoryConfigured() != nil)
    }
}

@Suite("JIT demotion when the user record is not found")
struct JITMissingRecordDemotionTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)

    private func expiredGrant(_ user: String, uid: uid_t = 777) -> Grant {
        Grant(user: user, uid: uid, ruleID: "jit-self-service",
              profileKey: JITAdminGrant.profileKey, teamID: "", binaryHash: "",
              canonicalPath: JITAdminGrant.canonicalPath, grantedAt: start.addingTimeInterval(-900),
              expiresAt: start.addingTimeInterval(-1), policyVersion: "jit")
    }

    private func manager(_ membership: FakeMembership, _ store: MemGrantStore,
                         _ resolver: JITAccountResolving) -> JITAdminManager {
        JITAdminManager(policyProvider: { .disabledDefault }, membership: membership, grantStore: store,
                        decisionLogger: nil, integrityLogger: nil, now: { start }, accountResolver: resolver)
    }

    @Test("an account confirmed gone retires its row (once)")
    func goneRetires() async {
        let membership = FakeMembership()
        await membership.setMissingRecord("deleted-user")
        let store = MemGrantStore(grants: [expiredGrant("deleted-user")])
        let resolver = ScriptedAccountResolver(.gone)
        let jit = manager(membership, store, resolver)
        #expect(await jit.expireOverdue() == 1)
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
        #expect(resolver.asked.first?.0 == "deleted-user")
        #expect(resolver.asked.first?.1 == 777)          // the row's uid is consulted
        #expect(await jit.expireOverdue() == 0)
    }

    @Test("an undecided account (outage, network account) keeps the row active and retried")
    func undeterminedKeepsRow() async {
        let membership = FakeMembership()
        await membership.setMissingRecord("netuser")
        let store = MemGrantStore(grants: [expiredGrant("netuser")])
        let jit = manager(membership, store, ScriptedAccountResolver(.undetermined("directory unreachable")))
        #expect(await jit.expireOverdue() == 0)
        #expect(await store.snapshot().allSatisfy { $0.revokedAt == nil })
        #expect(await jit.expireOverdue() == 0)          // still there to retry
        await jit.stop()
    }

    @Test("a renamed account is demoted under its new name, then the row retires")
    func renamedIsDemoted() async {
        let membership = FakeMembership(members: ["alice2|admin"])
        await membership.setMissingRecord("alice")
        let store = MemGrantStore(grants: [expiredGrant("alice", uid: 501)])
        let jit = manager(membership, store, ScriptedAccountResolver(.renamed(to: "alice2")))
        #expect(await jit.expireOverdue() == 1)
        #expect(!(await membership.contains("alice2", "admin")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
    }

    @Test("the teardown sweep applies the same rule")
    func sweepSameRule() async {
        let membership = FakeMembership(members: ["bob2|admin"])
        for user in ["gone", "unsure", "bob"] { await membership.setMissingRecord(user) }
        let resolver = ScriptedAccountResolver(.gone)
        let gone = await JITDemotionSweep.run(
            grantStore: MemGrantStore(grants: [expiredGrant("gone")]), membership: membership,
            accountResolver: resolver, now: start)
        #expect(gone.succeeded)
        #expect(gone.alreadyNotAdmin == ["gone"])
        #expect(gone.revokedGrantIDs.count == 1)

        let unsureStore = MemGrantStore(grants: [expiredGrant("unsure")])
        let unsure = await JITDemotionSweep.run(
            grantStore: unsureStore, membership: membership,
            accountResolver: ScriptedAccountResolver(.undetermined("outage")), now: start)
        #expect(!unsure.succeeded)
        #expect(unsure.failures["unsure"] != nil)
        #expect(await unsureStore.snapshot().allSatisfy { $0.revokedAt == nil })

        let renamedStore = MemGrantStore(grants: [expiredGrant("bob", uid: 502)])
        let renamed = await JITDemotionSweep.run(
            grantStore: renamedStore, membership: membership,
            accountResolver: ScriptedAccountResolver(.renamed(to: "bob2")), now: start)
        #expect(renamed.succeeded)
        #expect(renamed.demoted == ["bob2"])
        #expect(!(await membership.contains("bob2", "admin")))
        #expect(await renamedStore.snapshot().allSatisfy { $0.revokedAt != nil })
    }
}

/// Answers `true` for the first `allowed` calls, then `false`: a kill switch
/// that lands at a chosen point in the request.
private final class KillSwitchAfter: @unchecked Sendable {
    private let lock = NSLock()
    private var remaining: Int
    init(allowed: Int) { remaining = allowed }
    func permitted() -> Bool {
        lock.withLock {
            defer { remaining -= 1 }
            return remaining > 0
        }
    }
}

@Suite("JITAdminManager — kill switch during a request")
struct JITKillSwitchRaceTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)
    private let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)

    private func manager(_ membership: FakeMembership, _ store: MemGrantStore,
                         _ gate: KillSwitchAfter) -> JITAdminManager {
        let policy = self.policy
        return JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                               decisionLogger: nil, integrityLogger: nil, now: { self.now },
                               promotionPermitted: { gate.permitted() })
    }

    @Test("a kill switch that arrives before promotion refuses it; the row is retired unpromoted")
    func refusedBeforePromotion() async {
        let membership = FakeMembership(userGroups: ["carol": ["developers"]])
        let store = MemGrantStore()
        let result = await manager(membership, store, KillSwitchAfter(allowed: 0))
            .requestElevation(user: "carol", uid: 502, justification: "need admin now")
        #expect(result.outcome == .denied)
        #expect(await membership.addCount == 0)
        #expect(!(await membership.contains("carol", "admin")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
    }

    @Test("a kill switch that lands during the promotion undoes it at once")
    func undoneAfterPromotion() async {
        let membership = FakeMembership(userGroups: ["carol": ["developers"]])
        let store = MemGrantStore()
        let result = await manager(membership, store, KillSwitchAfter(allowed: 1))
            .requestElevation(user: "carol", uid: 502, justification: "need admin now")
        #expect(result.outcome == .denied)
        #expect(await membership.addCount == 1)
        #expect(!(await membership.contains("carol", "admin")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
    }

    @Test("no kill switch: granted as before")
    func grantedWhenPermitted() async {
        let membership = FakeMembership(userGroups: ["carol": ["developers"]])
        let jit = manager(membership, MemGrantStore(), KillSwitchAfter(allowed: 10))
        #expect(await jit.requestElevation(user: "carol", uid: 502, justification: "need admin now").outcome == .granted)
        #expect(await membership.contains("carol", "admin"))
        await jit.stop()
    }
}

@Suite("Clock set back while the daemon was not running")
struct ClockRollbackTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    @Test("set back only when more than the tolerance behind the mark")
    func threshold() {
        typealias G = ClockRollbackGuard
        #expect(!G.isSetBack(now: now, highWater: nil))
        #expect(!G.isSetBack(now: now, highWater: now.addingTimeInterval(G.toleranceSeconds)))
        #expect(G.isSetBack(now: now, highWater: now.addingTimeInterval(G.toleranceSeconds + 1)))
        #expect(!G.isSetBack(now: now, highWater: now.addingTimeInterval(-3600)))
    }

    @Test("every JIT admin demoted and every timed grant revoked; untimed grants and failed demotions kept")
    func revokesTimedGrants() async {
        func grant(_ user: String, jit: Bool, expires: Bool = true) -> Grant {
            Grant(user: user, uid: 501, ruleID: jit ? "jit-self-service" : "r",
                  profileKey: jit ? JITAdminGrant.profileKey : "rules_sudo_test", teamID: "", binaryHash: "",
                  canonicalPath: jit ? JITAdminGrant.canonicalPath : "/bin/echo",
                  grantedAt: now.addingTimeInterval(-60),
                  expiresAt: expires ? now.addingTimeInterval(900) : nil, policyVersion: "1")
        }
        let alice = grant("alice", jit: true)
        let stuck = grant("stuck", jit: true)
        let timed = grant("bob", jit: false)
        let untimed = grant("carol", jit: false, expires: false)
        let store = MemGrantStore(grants: [alice, stuck, timed, untimed])
        let membership = FakeMembership(members: ["alice|admin", "stuck|admin"])
        await membership.setMissingRecord("stuck")

        let outcome = await ClockRollbackGuard.revokeTimedGrants(
            grantStore: store, membership: membership,
            accountResolver: ScriptedAccountResolver(.undetermined("outage")), now: now)

        #expect(outcome.jit.demoted == ["alice"])
        #expect(!(await membership.contains("alice", "admin")))
        #expect(outcome.revokedGrants == 1)
        let rows = Dictionary(uniqueKeysWithValues: await store.snapshot().map { ($0.user, $0) })
        #expect(rows["alice"]?.revokedAt != nil)
        #expect(rows["bob"]?.revokedAt != nil)
        #expect(rows["carol"]?.revokedAt == nil)        // no expiry: not a timed grant
        #expect(rows["stuck"]?.revokedAt == nil)        // demotion not confirmed: left for the retry
        #expect(outcome.jit.failures["stuck"] != nil)
    }

    @Test("the high-water mark round-trips, and an untrustworthy file is ignored")
    func markFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-hwm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent(WallClockHighWaterMark.fileName)
        let mark = WallClockHighWaterMark(url: url)
        #expect(mark.read() == nil)
        try mark.write(now)
        #expect(mark.read() == now)
        var info = stat()
        #expect(stat(url.path, &info) == 0 && info.st_mode & 0o777 == 0o600)

        #expect(chmod(url.path, 0o666) == 0)
        #expect(mark.read() == nil)                     // group/other-writable
        #expect(WallClockHighWaterMark(url: url, requiredOwnerUID: getuid() &+ 1).read() == nil)

        let link = dir.appendingPathComponent("link.plist")
        try mark.write(now)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
        #expect(WallClockHighWaterMark(url: link).read() == nil)   // never followed
    }
}

@Suite("Lost grants key: keyless read view", .serialized)
struct LostGrantsKeyTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)

    private func grant(_ user: String, jit: Bool) -> Grant {
        Grant(user: user, uid: 501, ruleID: jit ? "jit-self-service" : "r",
              profileKey: jit ? JITAdminGrant.profileKey : "rules_sudo_test", teamID: "", binaryHash: "",
              canonicalPath: jit ? JITAdminGrant.canonicalPath : "/bin/echo",
              grantedAt: start.addingTimeInterval(-60), expiresAt: start.addingTimeInterval(900), policyVersion: "1")
    }

    /// A database written with a key that is then lost.
    private func seededPaths() async throws -> (DaemonPaths, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-lostkey-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let paths = DaemonPaths.ephemeral(in: dir)
        let store = try GrantStore(path: paths.grantDatabase.path, integrityKeys: [HMACSHA256.generateKey()],
                                   options: .standard)
        try await store.insert(grant("alice", jit: true))
        try await store.insert(grant("bob", jit: false))
        await store.close()
        return (paths, dir)
    }

    @Test("no database → no view; a database whose key is gone → a keyless view listing its JIT rows")
    func openView() async throws {
        let empty = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-nodb-\(UUID().uuidString)")
        #expect(DaemonController.openUnverifiedRowView(paths: DaemonPaths.ephemeral(in: empty)) == nil)

        let (paths, dir) = try await seededPaths()
        defer { try? FileManager.default.removeItem(at: dir) }
        let view = try #require(DaemonController.openUnverifiedRowView(paths: paths))
        let candidates = try await view.unverifiedJITCandidates()
        #expect(candidates.map(\.user) == ["alice"])   // JIT rows only
        // Still refusing to mint a key over these rows.
        #expect(!DaemonController.grantKeyCreationAllowed(account: BundleConfig.grantsHMACKeyAccount,
                                                          databasePath: paths.grantDatabase.path))
        await view.close()
    }

    @Test("on a NullGrantStore with the keyless view, every tick demotes the unverifiable JIT user — once")
    func tickDemotesOnce() async throws {
        let (paths, dir) = try await seededPaths()
        defer { try? FileManager.default.removeItem(at: dir) }
        let view = try #require(DaemonController.openUnverifiedRowView(paths: paths))
        let store = NullGrantStore(unverifiedRows: view)
        #expect(store.hasUnverifiedRowSource)
        let membership = FakeMembership(members: ["alice|admin"], userGroups: ["carol": ["developers"]])
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)
        let manager = JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                                      decisionLogger: nil, integrityLogger: nil, grantStoreDegraded: true,
                                      now: { start })

        #expect(await manager.expireOverdue() == 1)
        #expect(!(await membership.contains("alice", "admin")))

        // An admin re-adds alice on purpose: the next tick leaves her alone (the
        // row could not be stamped, but this process remembers it).
        try await membership.addMember(user: "alice", group: "admin")
        #expect(await manager.expireOverdue() == 0)
        #expect(await membership.contains("alice", "admin"))
        // The database was never written.
        #expect(try await view.unverifiedJITCandidates().count == 1)

        // Still degraded: timed grants and JIT stay refused.
        #expect(await manager.requestElevation(user: "carol", uid: 502, justification: "need admin now").outcome == .denied)
        await #expect(throws: (any Error).self) { _ = try await store.activeGrants(now: start) }
        await view.close()
    }
}

@Suite("JITAdminManager — continuous-clock expiry")
struct JITContinuousClockTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)
    private let issued = MonotonicInstant(bootSessionID: "boot-a", nanoseconds: 1_000_000_000_000)

    /// A JIT grant issued 60s before `start` for 15 minutes, stamped on the continuous clock.
    private func stampedGrant() -> Grant {
        Grant(user: "alice", uid: 501, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: start.addingTimeInterval(-60), expiresAt: start.addingTimeInterval(840), policyVersion: "jit")
            .stampingContinuousDeadline(at: issued)
    }

    /// Under the `serberus` provider, so only the clocks decide (any other
    /// provider ends the window whatever they say).
    private func manager(store: MemGrantStore, membership: FakeMembership, wall: Date,
                         monotonic: MonotonicInstant?) -> JITAdminManager {
        JITAdminManager(policyProvider: { JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"]) },
                        membership: membership, grantStore: store,
                        decisionLogger: nil, integrityLogger: nil, now: { wall }, monotonicNow: { monotonic })
    }

    private func after(_ seconds: UInt64, boot: String = "boot-a") -> MonotonicInstant {
        MonotonicInstant(bootSessionID: boot, nanoseconds: issued.nanoseconds + seconds * 1_000_000_000)
    }

    @Test("same boot: the window is over on the continuous clock, so a wall clock set back does not keep admin")
    func continuousClockDemotes() async {
        let membership = FakeMembership(members: ["alice|admin"])
        let store = MemGrantStore(grants: [stampedGrant()])
        // Wall clock set back to inside the window; 16 minutes really passed.
        let jit = manager(store: store, membership: membership, wall: start, monotonic: after(960))
        await jit.reconcile()   // restart path
        #expect(!(await membership.contains("alice", "admin")))

        let membership2 = FakeMembership(members: ["alice|admin"])
        let tick = manager(store: MemGrantStore(grants: [stampedGrant()]), membership: membership2,
                           wall: start, monotonic: after(960))
        #expect(await tick.expireOverdue() == 1)   // reload-tick path
        #expect(!(await membership2.contains("alice", "admin")))
    }

    @Test("same boot, still inside the window on both clocks: not demoted")
    func insideWindowStays() async {
        let membership = FakeMembership(members: ["alice|admin"])
        let jit = manager(store: MemGrantStore(grants: [stampedGrant()]), membership: membership,
                          wall: start, monotonic: after(300))
        #expect(await jit.expireOverdue() == 0)
        await jit.reconcile()
        #expect(await membership.contains("alice", "admin"))
        await jit.stop()
    }

    @Test("another boot: wall clock only — and a wall clock before the issue time is expiry")
    func otherBootUsesWallClock() async {
        let membership = FakeMembership(members: ["alice|admin"])
        let jit = manager(store: MemGrantStore(grants: [stampedGrant()]), membership: membership,
                          wall: start, monotonic: after(960, boot: "boot-b"))
        #expect(await jit.expireOverdue() == 0)   // wall clock says the window is open
        #expect(await membership.contains("alice", "admin"))
        await jit.stop()

        let setBack = manager(store: MemGrantStore(grants: [stampedGrant()]), membership: membership,
                              wall: start.addingTimeInterval(-3600), monotonic: after(1, boot: "boot-b"))
        #expect(await setBack.expireOverdue() == 1)
        #expect(!(await membership.contains("alice", "admin")))
    }
}

@Suite("serberusd command line")
struct DaemonCommandLineTests {
    @Test("no flags runs the service; each known one-shot parses")
    func known() {
        #expect(DaemonCommandLine.parse([]) == .service)
        #expect(DaemonCommandLine.parse(["-NSDocumentRevisionsDebugMode", "YES"]) == .service)
        #expect(DaemonCommandLine.parse(["-AppleLanguages", "(en)"]) == .service)
        #expect(DaemonCommandLine.parse(["--restore-authdb"]) == .restoreAuthDB)
        #expect(DaemonCommandLine.parse(["--remove-sudoers"]) == .removeSudoers)
        #expect(DaemonCommandLine.parse(["--demote-jit"]) == .demoteJIT)
    }

    @Test("an unknown or conflicting flag is a usage error (exit 2), never the service")
    func unknown() {
        guard case .usageError = DaemonCommandLine.parse(["--demote-jti"]) else {
            Issue.record("misspelled flag started the service"); return
        }
        guard case .usageError = DaemonCommandLine.parse(["--demote-jit", "--help"]) else {
            Issue.record("unknown flag alongside a known one accepted"); return
        }
        guard case .usageError = DaemonCommandLine.parse(["--demote-jit", "--remove-sudoers"]) else {
            Issue.record("two one-shots accepted"); return
        }
        #expect(DaemonCommandLine.usageExitCode == 2)
    }

    @Test("a single-dash option other than -NS… / -Apple… is a usage error, never the service")
    func singleDashOption() {
        for arguments in [["-demote-jit"], ["-x", "y"], ["-restore-authdb"], ["-NSFlag", "YES", "-x", "y"]] {
            guard case let .usageError(message) = DaemonCommandLine.parse(arguments) else {
                Issue.record("\(arguments) started the service"); continue
            }
            #expect(message.contains("unknown option"))
        }
    }

    @Test("a stray positional argument is a usage error too, never the service")
    func strayPositional() {
        for arguments in [["foo"], ["demote-jit"], ["--demote-jit", "extra"], ["-NSFlag", "YES", "extra"]] {
            guard case let .usageError(message) = DaemonCommandLine.parse(arguments) else {
                Issue.record("\(arguments) was accepted"); continue
            }
            #expect(message.contains("unexpected argument"))
        }
    }

    @Test("the LaunchDaemon plist starts serberusd with no arguments")
    func launchdPassesNoArguments() throws {
        let plist = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Support/com.herojoneslabs.serberus.daemon.plist")
        let parsed = try PropertyListSerialization.propertyList(from: Data(contentsOf: plist), format: nil)
        let arguments = try #require((parsed as? [String: Any])?["ProgramArguments"] as? [String])
        #expect(arguments.count == 1)   // argv[0] only
        #expect(DaemonCommandLine.parse(Array(arguments.dropFirst())) == .service)
    }
}

// MARK: - `serberusd --demote-jit` against a real SQLite store

@Suite("serberusd --demote-jit — keys, store, exit codes", .serialized)
struct DemoteJITOneShotTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)
    private let key = HMACSHA256.generateKey()

    private func tempPath() -> String {
        FileManager.default.temporaryDirectory.appendingPathComponent("serberus-demote-\(UUID().uuidString).sqlite").path
    }

    private func jitGrant(_ user: String) -> Grant {
        Grant(user: user, uid: 501, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: now.addingTimeInterval(-60), expiresAt: now.addingTimeInterval(600), policyVersion: "jit")
    }

    private func seed(_ path: String, _ grants: [Grant]) async throws {
        let store = try GrantStore(path: path, integrityKeys: [key], options: .standard)
        for grant in grants { try await store.insert(grant) }
        await store.close()
    }

    private func sqlite(_ path: String, _ sql: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        process.arguments = [path, sql]
        try process.run()
        process.waitUntilExit()
    }

    private func cleanup(_ path: String) {
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
    }

    @Test("not root → refused (exit 1), nothing touched")
    func notRoot() async {
        let membership = FakeMembership(members: ["alice|admin"])
        let outcome = await DaemonMode.demoteJITAdmins(databasePath: tempPath(), integrityKeys: [key],
                                                       membership: membership, integrityLogger: nil,
                                                       euid: 501, echo: { _ in }, errorEcho: { _ in })
        #expect(outcome == .notRoot)
        #expect(outcome.exitCode == 1)
        #expect(await membership.contains("alice", "admin"))
    }

    @Test("missing store → exit 3 'no grant store; nothing to demote' (information, not an error); NOT created")
    func missingStore() async {
        let path = tempPath()
        let out = ErrorLines()
        let err = ErrorLines()
        let outcome = await DaemonMode.demoteJITAdmins(databasePath: path, integrityKeys: [key],
                                                       membership: FakeMembership(), integrityLogger: nil,
                                                       euid: 0, echo: { out.append($0) }, errorEcho: { err.append($0) })
        #expect(outcome == .noStore(path: path))
        #expect(outcome.exitCode == 3)
        #expect(outcome.exitCode == DaemonMode.demoteJITNoStoreExitCode)
        #expect(!FileManager.default.fileExists(atPath: path))
        #expect(out.all.contains { $0.contains("no grant store") && $0.contains("nothing to demote") })
        #expect(err.all.isEmpty)   // not reported as an error
    }

    @Test("verifies with WHICHEVER key matches; demotes and re-signs with that key (exit 0)")
    func verifiesWithFallbackKey() async throws {
        let path = tempPath()
        defer { cleanup(path) }
        try await seed(path, [jitGrant("alice")])
        let membership = FakeMembership(members: ["alice|admin"])
        let outcome = await DaemonMode.demoteJITAdmins(databasePath: path,
                                                       integrityKeys: [HMACSHA256.generateKey(), key],
                                                       membership: membership, integrityLogger: nil,
                                                       euid: 0, now: now, echo: { _ in }, errorEcho: { _ in })
        guard case let .success(report) = outcome else { Issue.record("\(outcome)"); return }
        #expect(report.demoted == ["alice"])
        #expect(!(await membership.contains("alice", "admin")))
        // The revocation verifies under the ORIGINAL key.
        let reopened = try GrantStore(path: path, integrityKeys: [key], options: .existingNoQuarantine)
        let rows = try await reopened.allGrants()
        #expect(rows.count == 1 && rows[0].revokedAt != nil)
        await reopened.close()
    }

    @Test("no key verifies anything: JIT users still demoted, rows NOT stamped, exit 1 'unverifiable'")
    func unverifiableStore() async throws {
        let path = tempPath()
        defer { cleanup(path) }
        try await seed(path, [jitGrant("alice")])
        let membership = FakeMembership(members: ["alice|admin"])
        let lines = ErrorLines()
        let outcome = await DaemonMode.demoteJITAdmins(databasePath: path, integrityKeys: [],
                                                       membership: membership, integrityLogger: nil,
                                                       euid: 0, now: now, echo: { _ in },
                                                       errorEcho: { lines.append($0) })
        guard case let .unverifiable(report) = outcome else { Issue.record("\(outcome)"); return }
        #expect(outcome.exitCode == 1)
        #expect(report.unverifiedCandidates == ["alice"])
        #expect(!(await membership.contains("alice", "admin")))
        #expect(lines.all.contains { $0.contains("grant store unverifiable") && $0.contains("by hand") })
        // Never written: under the real key the row is still intact and unrevoked.
        let reopened = try GrantStore(path: path, integrityKeys: [key], options: .existingNoQuarantine)
        let rows = try await reopened.allGrants()
        #expect(rows.count == 1 && rows[0].revokedAt == nil)
        await reopened.close()
    }

    @Test("a tampered JIT row alongside a valid one: both users demoted, tampered row untouched, exit 0")
    func tamperedRowIsCandidate() async throws {
        let path = tempPath()
        defer { cleanup(path) }
        let tampered = jitGrant("bob")
        try await seed(path, [jitGrant("alice"), tampered])
        try sqlite(path, "UPDATE grants SET user='mallory' WHERE grantID='\(tampered.grantID.uuidString)'")
        let membership = FakeMembership(members: ["alice|admin", "mallory|admin"])
        let outcome = await DaemonMode.demoteJITAdmins(databasePath: path, integrityKeys: [key],
                                                       membership: membership, integrityLogger: nil,
                                                       euid: 0, now: now, echo: { _ in }, errorEcho: { _ in })
        guard case let .success(report) = outcome else { Issue.record("\(outcome)"); return }
        #expect(report.demoted == ["alice", "mallory"])
        #expect(!(await membership.contains("mallory", "admin")))
        let reopened = try GrantStore(path: path, integrityKeys: [key], options: .existingNoQuarantine)
        #expect(try await reopened.unverifiedJITCandidates().map(\.user) == ["mallory"]) // not quarantined
        await reopened.close()
    }
}

@Suite("GrantStore through GrantMaintaining", .serialized)
struct GrantStoreWitnessTests {
    @Test("allGrants() through the protocol returns EVERY row (expired + revoked), not the active-only default")
    func allGrantsWitness() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-witness-\(UUID().uuidString).sqlite").path
        defer { for s in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + s) } }
        let store = try GrantStore(path: path, integrityKeys: [HMACSHA256.generateKey()], options: .standard)
        let past = Date(timeIntervalSince1970: 1_000_000)
        let expiredJIT = Grant(user: "alice", uid: 501, ruleID: "jit-self-service",
                               profileKey: JITAdminGrant.profileKey, teamID: "", binaryHash: "",
                               canonicalPath: JITAdminGrant.canonicalPath, grantedAt: past,
                               expiresAt: past.addingTimeInterval(60), policyVersion: "jit")
        try await store.insert(expiredJIT)
        let existential: GrantMaintaining = store
        #expect(try await existential.allGrants().map(\.grantID) == [expiredJIT.grantID])

        // …so the teardown sweep sees (and demotes) an expired-but-undemoted JIT admin.
        let membership = FakeMembership(members: ["alice|admin"])
        let report = await DaemonMode.demoteJITAdmins(grantStore: store, membership: membership,
                                                      integrityLogger: nil, echo: { _ in })
        #expect(report.demoted == ["alice"])
        await store.close()
    }
}

@Suite("Grants HMAC key minting guard")
struct GrantKeyMintingTests {
    @Test("the grants key may be minted only while grants.sqlite has no rows; other accounts always")
    func guardRule() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-mint-\(UUID().uuidString).sqlite").path
        defer { for s in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + s) } }
        let grants = BundleConfig.grantsHMACKeyAccount
        #expect(DaemonController.grantKeyCreationAllowed(account: grants, databasePath: path))       // absent
        #expect(DaemonController.grantKeyCreationAllowed(account: BundleConfig.logHMACKeyAccount, databasePath: path))

        let store = try GrantStore(path: path, integrityKeys: [HMACSHA256.generateKey()], options: .standard)
        #expect(DaemonController.grantKeyCreationAllowed(account: grants, databasePath: path))       // empty table
        try await store.insert(Grant(user: "a", uid: 501, ruleID: "r", profileKey: "p", teamID: "",
                                     binaryHash: "", canonicalPath: "/x", grantedAt: Date(),
                                     expiresAt: nil, policyVersion: "1"))
        await store.close()
        #expect(!DaemonController.grantKeyCreationAllowed(account: grants, databasePath: path))      // rows exist
        #expect(DaemonController.grantKeyCreationAllowed(account: BundleConfig.logHMACKeyAccount, databasePath: path))
    }
}

private final class ErrorLines: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return lines }
}

// MARK: - Kill switch interleaved with an in-flight promotion

/// Group membership whose `addMember` and a chosen `isMember` call can be held
/// open by the test, so a demotion can be run in the middle of a promotion.
private actor SteppedMembership: GroupMembershipControlling {
    private var admins: Set<String> = []
    private let userGroups: [String: Set<String>]
    private var addWaiter: CheckedContinuation<Void, Never>?
    private var addStarted = false
    private var isMemberCalls = 0
    /// The 1-based `isMember` call to hold: its answer is taken when it is
    /// made, and returned only when the test releases it.
    private let holdIsMemberCall: Int?
    /// Whether the held call answers from the state at release instead.
    private let answerAfterRelease: Bool
    private var heldCheck: CheckedContinuation<Void, Never>?
    private var heldCheckReached = false
    private(set) var removed: [String] = []

    init(userGroups: [String: Set<String>], holdIsMemberCall: Int?, answerAfterRelease: Bool = false) {
        self.userGroups = userGroups
        self.holdIsMemberCall = holdIsMemberCall
        self.answerAfterRelease = answerAfterRelease
    }

    func isMember(user: String, group: String) async throws -> Bool {
        isMemberCalls += 1
        let answer = admins.contains(user)
        if isMemberCalls == holdIsMemberCall {
            heldCheckReached = true
            await withCheckedContinuation { heldCheck = $0 }
            if answerAfterRelease { return admins.contains(user) }
        }
        return answer
    }
    func groups(forUser user: String) async -> Set<String> { userGroups[user] ?? [] }
    func addMember(user: String, group: String) async throws {
        addStarted = true
        await withCheckedContinuation { addWaiter = $0 }
        admins.insert(user)
    }
    func removeMember(user: String, group: String) async throws {
        removed.append(user)
        admins.remove(user)
    }

    var isAddStarted: Bool { addStarted }
    var isHeldCheckReached: Bool { heldCheckReached }
    func releaseAdd() { addWaiter?.resume(); addWaiter = nil }
    func releaseHeldCheck() { heldCheck?.resume(); heldCheck = nil }
    func isAdmin(_ user: String) -> Bool { admins.contains(user) }
}

private final class Switch: @unchecked Sendable {
    private let lock = NSLock()
    private var on = true
    func turnOff() { lock.lock(); on = false; lock.unlock() }
    var permitted: Bool { lock.lock(); defer { lock.unlock() }; return on }
}

@Suite("JITAdminManager — kill switch interleaved with a promotion", .serialized)
struct JITKillSwitchInterleavingTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)
    private let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 900)

    private func poll(_ condition: @Sendable () async -> Bool) async -> Bool {
        for _ in 0..<500 {
            if await condition() { return true }
            try? await Task.sleep(for: .milliseconds(5))
        }
        return false
    }

    private func manager(_ membership: SteppedMembership, _ store: MemGrantStore, _ killSwitch: Switch) -> JITAdminManager {
        let policy = self.policy
        let now = self.now
        return JITAdminManager(policyProvider: { policy }, membership: membership, grantStore: store,
                               decisionLogger: nil, integrityLogger: nil, now: { now }, monotonicNow: { nil },
                               promotionPermitted: { killSwitch.permitted })
    }

    /// isMember calls: #1 the request's "already an admin?" check, #2 the kill
    /// switch's demotion pre-check, #3 its look again after retiring the row.
    @Test("demote-all checks before the add lands and is still running when the promotion's gate fails: the user ends up not in admin")
    func promotionWaitsForTheDemotion() async {
        let membership = SteppedMembership(userGroups: ["carol": ["developers"]], holdIsMemberCall: 3)
        let store = MemGrantStore()
        let killSwitch = Switch()
        let jit = manager(membership, store, killSwitch)

        let request = Task { await jit.requestElevation(user: "carol", uid: 502, justification: "need admin now") }
        #expect(await poll { await membership.isAddStarted })

        killSwitch.turnOff()
        let demoteAll = Task { await jit.demoteAll() }
        // The demotion saw "not a member", retired the row, and is looking
        // again, with the answer taken before the add landed.
        #expect(await poll { await membership.isHeldCheckReached })
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })

        // The add lands while that demotion is still in progress; the
        // promotion's gate fails and it must wait for the demotion, not give up.
        await membership.releaseAdd()
        try? await Task.sleep(for: .milliseconds(50))
        await membership.releaseHeldCheck()

        let result = await request.value
        _ = await demoteAll.value
        #expect(result.outcome == .denied)
        #expect(!(await membership.isAdmin("carol")))
        #expect(await membership.removed == ["carol"])
        // Every JIT row for carol is retired: the original and the replacement
        // row that carried the removal.
        let rows = await store.snapshot()
        #expect(rows.count == 2)
        #expect(rows.allSatisfy { $0.revokedAt != nil })
    }

    @Test("the demotion's second look, after retiring the row, finds the add that landed and removes it")
    func demotionSecondLookRemoves() async {
        let membership = SteppedMembership(userGroups: ["carol": ["developers"]], holdIsMemberCall: 3,
                                           answerAfterRelease: true)
        let store = MemGrantStore()
        let killSwitch = Switch()
        let jit = manager(membership, store, killSwitch)

        let request = Task { await jit.requestElevation(user: "carol", uid: 502, justification: "need admin now") }
        #expect(await poll { await membership.isAddStarted })
        killSwitch.turnOff()
        let demoteAll = Task { await jit.demoteAll() }
        #expect(await poll { await membership.isHeldCheckReached })
        await membership.releaseAdd()
        try? await Task.sleep(for: .milliseconds(50))
        await membership.releaseHeldCheck()   // answers "member": the add has landed

        #expect(await request.value.outcome == .denied)
        _ = await demoteAll.value
        #expect(!(await membership.isAdmin("carol")))
        #expect(await membership.removed == ["carol"])
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
    }

    @Test("a grant ended while its add was in flight does not leave the user an admin")
    func endedDuringAdd() async {
        let membership = SteppedMembership(userGroups: ["carol": ["developers"]], holdIsMemberCall: nil)
        let store = MemGrantStore()
        let jit = manager(membership, store, Switch())
        let request = Task { await jit.requestElevation(user: "carol", uid: 502, justification: "need admin now") }
        #expect(await poll { await membership.isAddStarted })
        // The user ends it before the add lands: the row is retired unremoved.
        #expect(await jit.endElevation(user: "carol"))
        await membership.releaseAdd()
        #expect(await request.value.outcome == .denied)
        #expect(!(await membership.isAdmin("carol")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
        await jit.stop()
    }
}

// MARK: - A retired account's leftovers in admin

private final class ScrubSpy: StaleAdminEntryScrubbing, @unchecked Sendable {
    private let lock = NSLock()
    private var calls: [(String, String?)] = []
    func scrub(name: String, generatedUID: String?) async -> [String] {
        lock.withLock { calls.append((name, generatedUID)) }
        return ["scrubbed \(name)"]
    }
    var scrubbed: [String] { lock.withLock { calls.map(\.0) } }
    var generatedUIDs: [String?] { lock.withLock { calls.map(\.1) } }
}

private final class RecordingRunner: CommandRunning, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [(String, [String])] = []
    let status: Int32
    init(status: Int32) { self.status = status }
    func run(path: String, arguments: [String]) async throws -> Int32 {
        lock.withLock { recorded.append((path, arguments)) }
        return status
    }
    var calls: [(String, [String])] { lock.withLock { recorded } }
}

@Suite("A retired JIT account leaves nothing in admin")
struct StaleAdminEntryScrubTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)
    private let guid = "11111111-2222-3333-4444-555555555555"

    private func expiredGrant(_ user: String, uid: uid_t = 777) -> Grant {
        Grant(user: user, uid: uid, ruleID: "jit-self-service",
              profileKey: JITAdminGrant.profileKey, teamID: "", binaryHash: "",
              canonicalPath: JITAdminGrant.canonicalPath, grantedAt: start.addingTimeInterval(-900),
              expiresAt: start.addingTimeInterval(-1), policyVersion: "jit", generatedUID: guid)
    }

    private func manager(_ membership: FakeMembership, _ store: MemGrantStore, _ resolver: JITAccountResolving,
                         _ spy: ScrubSpy) -> JITAdminManager {
        JITAdminManager(policyProvider: { .disabledDefault }, membership: membership, grantStore: store,
                        decisionLogger: nil, integrityLogger: nil, now: { start }, accountResolver: resolver,
                        adminGroupScrubber: spy)
    }

    @Test("the dscl commands: absolute path, local node, one value each; unsafe values are left out")
    func commands() async {
        #expect(DSCLStaleAdminEntryScrubber.dsclPath == "/usr/bin/dscl")
        #expect(DSCLStaleAdminEntryScrubber.commands(name: "bob", generatedUID: guid.lowercased()) == [
            [".", "-delete", "/Groups/admin", "GroupMembership", "bob"],
            [".", "-delete", "/Groups/admin", "GroupMembers", guid],
        ])
        #expect(DSCLStaleAdminEntryScrubber.commands(name: "", generatedUID: "not-a-uuid").isEmpty)
        #expect(DSCLStaleAdminEntryScrubber.commands(name: "-bob", generatedUID: nil).isEmpty)
        #expect(DSCLStaleAdminEntryScrubber.commands(name: "bo\nb", generatedUID: nil).isEmpty)

        let runner = RecordingRunner(status: 0)
        let lines = await DSCLStaleAdminEntryScrubber(runner: runner).scrub(name: "bob", generatedUID: guid)
        #expect(runner.calls.map(\.0) == ["/usr/bin/dscl", "/usr/bin/dscl"])
        #expect(runner.calls.map(\.1.last) == ["bob", guid])
        #expect(lines.count == 2)
        let absent = await DSCLStaleAdminEntryScrubber(runner: RecordingRunner(status: 56)).scrub(name: "bob", generatedUID: nil)
        #expect(absent.first?.contains("not removed") == true)
    }

    @Test("gone and uid-reused accounts are scrubbed from admin after the row retires")
    func goneAndReused() async {
        for answer in [JITAccountIdentity.gone, .uidReused(by: "newhire")] {
            let membership = FakeMembership()
            await membership.setMissingRecord("olduser")
            let store = MemGrantStore(grants: [expiredGrant("olduser")])
            let spy = ScrubSpy()
            #expect(await manager(membership, store, ScriptedAccountResolver(answer), spy).expireOverdue() == 1)
            #expect(spy.scrubbed == ["olduser"])
            #expect(spy.generatedUIDs == [guid])
            #expect(await membership.removeCount == 0)
        }
    }

    @Test("a renamed or present account is demoted normally and never scrubbed")
    func renamedNotScrubbed() async {
        let membership = FakeMembership(members: ["renamed|admin"])
        await membership.setMissingRecord("olduser")
        let spy = ScrubSpy()
        let store = MemGrantStore(grants: [expiredGrant("olduser")])
        #expect(await manager(membership, store, ScriptedAccountResolver(.renamed(to: "renamed")), spy).expireOverdue() == 1)
        #expect(spy.scrubbed.isEmpty)
        #expect(!(await membership.contains("renamed", "admin")))

        let present = FakeMembership(members: ["carol|admin"])
        let spy2 = ScrubSpy()
        _ = await manager(present, MemGrantStore(grants: [expiredGrant("carol")]),
                          ScriptedAccountResolver(.present), spy2).expireOverdue()
        #expect(spy2.scrubbed.isEmpty)
    }

    @Test("the teardown sweep scrubs a gone account too")
    func sweepScrubs() async {
        let membership = FakeMembership()
        await membership.setMissingRecord("olduser")
        let spy = ScrubSpy()
        let report = await JITDemotionSweep.run(
            grantStore: MemGrantStore(grants: [expiredGrant("olduser")]), membership: membership,
            accountResolver: ScriptedAccountResolver(.gone), adminGroupScrubber: spy, now: start)
        #expect(report.succeeded)
        #expect(spy.scrubbed == ["olduser"])
        #expect(spy.generatedUIDs == [guid])
    }
}

// MARK: - GeneratedUID on rows from before schema 3

@Suite("Older JIT rows get their GeneratedUID", .serialized)
struct GeneratedUIDStampTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)

    private func jitGrant(_ user: String, uid: uid_t, revoked: Bool = false) -> Grant {
        Grant(user: user, uid: uid, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: start, expiresAt: start.addingTimeInterval(900),
              revokedAt: revoked ? start : nil, policyVersion: "jit")
    }

    @Test("rows whose name and uid still match are stamped and re-signed; others are left as they were")
    func stamps() async throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("guid-\(UUID().uuidString).sqlite").path
        defer { for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) } }
        let key = InMemoryKeyProvider.random()
        let store = try GrantStore(path: path, keyProvider: key, monotonicNow: { nil })
        let same = jitGrant("alice", uid: 501)
        let moved = jitGrant("bob", uid: 502)
        let revoked = jitGrant("carol", uid: 503, revoked: true)
        let binary = Grant(user: "alice", uid: 501, ruleID: "r", profileKey: "rules_sudo_test", teamID: "",
                           binaryHash: "aa", canonicalPath: "/bin/echo", grantedAt: start, expiresAt: nil,
                           policyVersion: "1")
        for grant in [same, moved, revoked, binary] { try await store.insert(grant) }

        let stamped = try await store.stampGeneratedUIDs { user, uid in
            user == "alice" && uid == 501 ? "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" : nil
        }
        #expect(stamped == 1)
        #expect(try await store.stampGeneratedUIDs { _, _ in "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" } == 1) // bob now
        await store.close()

        // Reopened: every row still verifies, stamped or not.
        let reopened = try GrantStore(path: path, keyProvider: key, monotonicNow: { nil })
        let rows = try await reopened.allGrants()
        #expect(await reopened.drainIntegrityViolations().isEmpty)
        #expect(rows.count == 4)
        #expect(rows.first { $0.grantID == same.grantID }?.generatedUID == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        #expect(rows.first { $0.grantID == revoked.grantID }?.generatedUID == nil)
        #expect(rows.first { $0.grantID == binary.grantID }?.generatedUID == nil)
        #expect(try await reopened.unverifiedJITCandidates().isEmpty)
        await reopened.close()
    }

    @Test("the daemon's resolver answers only when the name and uid are the same account")
    func resolver() {
        let resolve = DaemonController.generatedUIDIfSameAccount
        #expect(resolve("root", 0) == nil)                       // system account: no usable GeneratedUID
        #expect(resolve("serberus-no-such-user-7f3a", 501) == nil)
        let me = NSUserName()
        if getuid() >= 501 {
            #expect(resolve(me, getuid()) != nil)
            #expect(resolve(me, getuid() + 1) == nil)             // same name, other uid: not stamped
        }
    }
}

// MARK: - Upgrade ends JIT sessions

private final class MemoryBuildMarker: DaemonBuildMarkerStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    init(_ value: String?) { self.value = value }
    func read() -> String? { lock.withLock { value } }
    func write(_ identity: String) throws { lock.withLock { value = identity } }
}

@Suite("Startup after an upgrade ends live JIT sessions", .serialized)
struct UpgradeEndsJITTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)

    private func liveGrant() -> Grant {
        Grant(user: "carol", uid: 502, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: start.addingTimeInterval(-60), expiresAt: start.addingTimeInterval(840), policyVersion: "jit")
    }

    private func run(
        recorded: String?,
        upgradeMarker: ((URL) throws -> Void)? = nil
    ) async throws -> (admin: Bool, marker: String?, revoked: Bool, upgradeMarkerLeft: Bool) {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        try upgradeMarker?(paths.upgradeMarker)
        let marker = MemoryBuildMarker(recorded)
        let store = MemGrantStore(grants: [liveGrant()])
        let membership = FakeMembership(members: ["carol|admin"])
        let controller = DaemonController(
            paths: paths, machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:])),
            grantStore: store,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil, pppc: StaticPPPCStatus(ready: true), authDB: NoopAuthorizationDBApplier(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            buildMarker: marker, buildIdentity: "1.0.0 sha256:new", now: { self.start })
        await controller.loadPolicyForTesting(profiles: [], config: SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil, daemonEnabled: true,
            enforcementMode: .enforce, sudoCacheSeconds: 0, promptTimeoutSeconds: 60, pamBypass: PAMBypass()))
        // The `serberus` provider, so only the upgrade decides whether the
        // session ends.
        let manager = JITAdminManager(policyProvider: { JITAdminPolicy(provider: .serberus, eligibleGroups: ["x"]) },
                                      membership: membership, grantStore: store,
                                      decisionLogger: nil, integrityLogger: nil, now: { self.start },
                                      monotonicNow: { nil })
        await controller.settleJITAdminsAtStartup(manager)
        await manager.stop()
        var info = stat()
        let left = lstat(paths.upgradeMarker.path, &info) == 0
        return (await membership.contains("carol", "admin"), marker.read(),
                await store.snapshot().allSatisfy { $0.revokedAt != nil }, left)
    }

    private static func writeMarker(_ url: URL, mode: Int = 0o600) throws {
        try Data("startedAt=2026-06-12T00:00:00Z\n".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }

    @Test("the same build with the installer's upgrade marker: the session is ended and the marker removed")
    func upgradeMarkerEndsSession() async throws {
        let result = try await run(recorded: "1.0.0 sha256:new") { try Self.writeMarker($0) }
        #expect(!result.admin)
        #expect(result.revoked)
        #expect(!result.upgradeMarkerLeft)
    }

    @Test("an untrusted upgrade marker is ignored, and removed")
    func untrustedUpgradeMarker() async throws {
        // Group/other-writable.
        let writable = try await run(recorded: "1.0.0 sha256:new") { try Self.writeMarker($0, mode: 0o666) }
        #expect(writable.admin)
        #expect(!writable.revoked)
        #expect(!writable.upgradeMarkerLeft)

        // A symlink, even to a well-formed marker.
        let linked = try await run(recorded: "1.0.0 sha256:new") { url in
            let target = url.deletingLastPathComponent().appendingPathComponent("elsewhere")
            try Self.writeMarker(target)
            try FileManager.default.createSymbolicLink(at: url, withDestinationURL: target)
        }
        #expect(linked.admin)
        #expect(!linked.upgradeMarkerLeft)

        // Too large.
        let large = try await run(recorded: "1.0.0 sha256:new") { url in
            try Data(repeating: 0x41, count: 8192).write(to: url)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        #expect(large.admin)
    }

    @Test("the upgrade marker's checks")
    func upgradeMarkerChecks() throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent(PreinstallUpgradeMarker.fileName)
        #expect(DaemonPaths.ephemeral(in: dir).upgradeMarker == url)
        #expect(DaemonPaths.production.upgradeMarker.path
                == "/Library/Application Support/Serberus/.upgrade-in-progress")
        let mine = PreinstallUpgradeMarker(url: url, requiredOwnerUID: getuid())
        #expect(mine.read() == .absent)
        try Self.writeMarker(url)
        #expect(mine.read() == .present)
        // Owned by someone other than the daemon's user.
        let rootOnly = PreinstallUpgradeMarker(url: url, requiredOwnerUID: getuid() == 0 ? 501 : 0)
        guard case .untrusted = rootOnly.read() else {
            Issue.record("a marker with the wrong owner was trusted")
            return
        }
        #expect(mine.remove())
        #expect(mine.read() == .absent)
        // A directory is never removed.
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        guard case .untrusted = mine.read() else {
            Issue.record("a directory was trusted as the marker")
            return
        }
        #expect(!mine.remove())
    }

    @Test("a different build: the live session is ended and the new build recorded")
    func differentBuild() async throws {
        let result = try await run(recorded: "0.9.0 sha256:old")
        #expect(!result.admin)
        #expect(result.revoked)
        #expect(result.marker == "1.0.0 sha256:new")
    }

    @Test("no record (a daemon from before the check): treated as an upgrade")
    func noRecord() async throws {
        let result = try await run(recorded: nil)
        #expect(!result.admin)
        #expect(result.marker == "1.0.0 sha256:new")
    }

    @Test("the same build (a restart): the session is re-armed, not ended")
    func sameBuild() async throws {
        let result = try await run(recorded: "1.0.0 sha256:new")
        #expect(result.admin)
        #expect(!result.revoked)
    }

    @Test("the build identity and its marker file")
    func identityAndMarker() throws {
        let identity = try #require(DaemonBuildIdentity.current(version: "9.9.9"))
        #expect(identity.hasPrefix("9.9.9 sha256:"))
        #expect(identity == DaemonBuildIdentity.current(version: "9.9.9"))
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let marker = DaemonBuildMarker(url: dir.appendingPathComponent(DaemonBuildMarker.fileName), requiredOwnerUID: getuid())
        #expect(marker.read() == nil)
        try marker.write(identity)
        #expect(marker.read() == identity)
        let mode = (try FileManager.default.attributesOfItem(atPath: marker.url.path)[.posixPermissions] as? NSNumber)?.intValue
        #expect(mode == 0o600)
        #expect(DaemonBuildIdentity.isUpgrade(recorded: nil, current: identity))
        #expect(!DaemonBuildIdentity.isUpgrade(recorded: identity, current: identity))
    }
}

// MARK: - A policy that turns Serberus JIT off ends open windows

/// The live JIT policy, changed by a test as a reload would change it.
private final class LiveJITPolicy: @unchecked Sendable {
    private let lock = NSLock()
    private var policy: JITAdminPolicy
    init(_ policy: JITAdminPolicy) { self.policy = policy }
    func set(_ policy: JITAdminPolicy) { lock.withLock { self.policy = policy } }
    var current: JITAdminPolicy { lock.withLock { policy } }
}

/// Records the sudo tickets demotions clear, as "uid/name".
private final class ClearedTickets: SudoTicketClearing, @unchecked Sendable {
    private let lock = NSLock()
    private var cleared: [String] = []
    func clearTicket(uid: uid_t, user: String?) -> Bool {
        lock.withLock { cleared.append("\(uid)/\(user ?? "")") }
        return true
    }
    func clearTicket(user: String) -> Bool {
        lock.withLock { cleared.append(user) }
        return true
    }
    func clearAllTickets() -> Int { 0 }
    var all: [String] { lock.withLock { cleared } }
}

@Suite("JITAdminManager — a provider other than serberus ends open windows", .serialized)
struct JITProviderOffTests {
    private let start = Date(timeIntervalSince1970: 1_781_222_400)
    private static let serberus = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"],
                                                 maxDurationSeconds: 900)
    /// The policies a reload can turn Serberus JIT off with: provider
    /// `disabled`, provider `jamf_connect`, and no JIT profile at all (read as
    /// ``JITAdminPolicy/disabledDefault``).
    static let offPolicies: [JITAdminPolicy] = [
        JITAdminPolicy(provider: .disabled, eligibleGroups: ["developers"], maxDurationSeconds: 900),
        JITAdminPolicy(provider: .jamfConnect),
        .disabledDefault,
    ]

    private func manager(_ policy: LiveJITPolicy, _ membership: FakeMembership, _ store: MemGrantStore,
                         tickets: SudoTicketClearing = NoopSudoTicketClearer(), logs: URL? = nil,
                         clock: TestClock? = nil) throws -> JITAdminManager {
        let start = self.start
        return JITAdminManager(
            policyProvider: { policy.current }, membership: membership, grantStore: store,
            decisionLogger: try logs.map { try DecisionLogger(directory: $0, keyProvider: InMemoryKeyProvider.random()) },
            integrityLogger: try logs.map { try IntegrityLogger(directory: $0) },
            now: { clock?.now ?? start }, monotonicNow: { nil }, ticketClearer: tickets)
    }

    /// alice's window: opened 60 seconds ago, 14 minutes left.
    private func openWindow() -> Grant {
        Grant(user: "alice", uid: 501, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: start.addingTimeInterval(-60), expiresAt: start.addingTimeInterval(840), policyVersion: "jit")
    }

    /// The JSON lines of the `prefix` log files in `directory`.
    private func logged(_ prefix: String, in directory: URL) -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.lastPathComponent.hasPrefix(prefix) && $0.pathExtension == "jsonl" }
            .compactMap { try? String(contentsOf: $0, encoding: .utf8) }
            .flatMap { $0.split(separator: "\n").map(String.init) }
    }

    @Test("the tick after the provider leaves serberus demotes the open window as an expiry would, and says why",
          arguments: offPolicies)
    func tickDemotes(off: JITAdminPolicy) async throws {
        let logs = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: logs) }
        let policy = LiveJITPolicy(Self.serberus)
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let tickets = ClearedTickets()
        let jit = try manager(policy, membership, store, tickets: tickets, logs: logs)
        #expect(await jit.requestElevation(user: "alice", uid: 501, justification: "patching the box").outcome == .granted)
        #expect(await jit.expireOverdue() == 0)                 // serberus: the window stays open

        policy.set(off)                                          // the reload adopts the new policy…
        #expect(await jit.expireOverdue() == 1)                 // …and the tick right after it ends the window
        #expect(!(await membership.contains("alice", "admin")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
        #expect(tickets.all == ["501/alice"])
        #expect(logged("decisions", in: logs).contains { $0.contains("jit_admin_demotion") })
        let integrity = logged("integrity", in: logs)
        #expect(integrity.contains {
            $0.contains("JIT admin demoted alice (JIT provider is now \(off.provider.rawValue), not serberus (reload tick))")
        })

        // Nothing is left to end: later ticks demote and log nothing.
        #expect(await jit.expireOverdue() == 0)
        #expect(logged("integrity", in: logs).count == integrity.count)
        await jit.stop()
    }

    @Test("a demotion that fails keeps the window's row, and the next tick tries again")
    func failedDemotionRetriedNextTick() async throws {
        let policy = LiveJITPolicy(Self.serberus)
        let membership = FakeMembership(userGroups: ["alice": ["developers"]])
        let store = MemGrantStore()
        let jit = try manager(policy, membership, store)
        #expect(await jit.requestElevation(user: "alice", uid: 501, justification: "patching the box").outcome == .granted)

        policy.set(.disabledDefault)
        await membership.setFailRemove(true)
        #expect(await jit.expireOverdue() == 0)
        #expect(await membership.contains("alice", "admin"))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt == nil })

        await membership.setFailRemove(false)
        #expect(await jit.expireOverdue() == 1)
        #expect(!(await membership.contains("alice", "admin")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
        await jit.stop()
    }

    @Test("at startup under a provider other than serberus, an open window is demoted instead of re-armed",
          arguments: offPolicies)
    func reconcileDemotes(off: JITAdminPolicy) async throws {
        let logs = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: logs) }
        let membership = FakeMembership(members: ["alice|admin"])
        let store = MemGrantStore(grants: [openWindow()])
        let tickets = ClearedTickets()
        let jit = try manager(LiveJITPolicy(off), membership, store, tickets: tickets, logs: logs)

        await jit.reconcile()
        #expect(!(await membership.contains("alice", "admin")))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt != nil })
        #expect(tickets.all == ["501/alice"])
        #expect(logged("integrity", in: logs).contains {
            $0.contains("JIT admin demoted alice (JIT provider is now \(off.provider.rawValue), not serberus (startup))")
        })
        await jit.stop()
    }

    @Test("under serberus nothing changes: a restart and the ticks keep the window, and its expiry still demotes it")
    func serberusUnchanged() async throws {
        let clock = TestClock(start)
        let membership = FakeMembership(members: ["alice|admin"])
        let store = MemGrantStore(grants: [openWindow()])
        let jit = try manager(LiveJITPolicy(Self.serberus), membership, store, clock: clock)

        await jit.reconcile()                                    // re-armed, not demoted
        #expect(await jit.expireOverdue() == 0)
        #expect(await membership.contains("alice", "admin"))
        #expect(await store.snapshot().allSatisfy { $0.revokedAt == nil })

        clock.advance(841)                                       // the window runs out
        #expect(await jit.expireOverdue() == 1)
        #expect(!(await membership.contains("alice", "admin")))
        await jit.stop()
    }
}
