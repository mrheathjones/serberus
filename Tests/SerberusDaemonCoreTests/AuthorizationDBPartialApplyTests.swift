import Darwin
import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// One failed AuthorizationDB read or write must never keep the rest of the
/// policy from landing: denies land first, the failure is reported,
/// and the daemon retries the reconcile on every reload tick. A restore-sweep
/// reset that fails is a leftover and keeps its records. Everything runs
/// against the in-memory `MockAuthorizationDB` (AuthorizationDBTests.swift) and
/// temporary directories; nothing touches the real AuthorizationDB.
enum PartialApplyFixtures {
    static func plist(_ dict: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    static func dict(_ data: Data?) -> [String: Any] {
        guard let data else { return [:] }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] ?? [:]
    }

    /// A plain admin gate: what a plain allow may be written over.
    static let adminGate = plist(["class": "user", "group": "admin"])
    /// A native definition a composition preserves as its fallback row.
    static let composable = plist(["class": "rule", "rule": ["authenticate-admin-nonshared"]])
    static let branch = AppIdentityBranch(teamID: "H7H8Q7M5CK", bundleID: "com.postmanlabs.mac")

    /// A right whose snapshot the store cannot write: its record's file name is
    /// longer than the file system allows, so the save fails as it does on a
    /// full disk, for this right alone.
    static let unsnapshottable = "com.example.unsnapshottable." + String(repeating: "x", count: 240)

    static func deny(_ name: String) -> AuthorizationDBManager.DesiredRight {
        .init(name: name, definition: AuthorizationDBManager.definitionPlist(for: .deny))
    }

    static func allow(_ name: String) -> AuthorizationDBManager.DesiredRight {
        .init(name: name, definition: AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin),
              requiresNativeAdminGate: true)
    }

    static func composition(_ right: String) -> AuthorizationDBManager.DesiredComposition {
        .init(right: right, branches: [branch])
    }

    static func denyProfile(_ right: String) -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_test", profilePriority: 50, rules: [
            Rule(id: "deny-pane", type: .authuri, action: .deny, description: "t", priority: 10,
                 match: MatchCriteria(authURI: right)),
        ])
    }

    static func manager(_ backend: AuthorizationDBBackend, _ store: AuthorizationDBSnapshotStore,
                        shipped: [String: Data] = [:], integrityLogger: IntegrityLogger? = nil) -> AuthorizationDBManager {
        AuthorizationDBManager(backend: backend, store: store, integrityLogger: integrityLogger, daemonVersion: "1.0.0",
                               now: { CoordinatorFixtures.now }, osMajor: 27,
                               authPluginVerifier: StubPluginVerifier(status: .installed),
                               shippedDefinitions: { shipped[$0] })
    }

    /// Runs `apply`, which must throw ``AuthorizationDBError/applyIncomplete(_:)``,
    /// and returns the result it carries (nil, with an issue recorded, otherwise).
    static func applyExpectingIncomplete(_ manager: AuthorizationDBManager,
                                         _ desired: [AuthorizationDBManager.DesiredRight],
                                         compositions: [AuthorizationDBManager.DesiredComposition] = []) async
        -> AuthorizationDBManager.ApplyResult? {
        do {
            _ = try await manager.apply(desired, compositions: compositions)
            Issue.record("apply succeeded; expected applyIncomplete")
        } catch let AuthorizationDBError.applyIncomplete(result) {
            return result
        } catch {
            Issue.record("apply threw \(error); expected applyIncomplete")
        }
        return nil
    }

    /// Every integrity event written under `directory`, one JSON line each.
    static func integrityLines(in directory: URL) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return names.filter { $0.hasPrefix("integrity-") && $0.hasSuffix(".jsonl") }.sorted().flatMap { name in
            ((try? String(contentsOf: directory.appendingPathComponent(name), encoding: .utf8)) ?? "")
                .split(separator: "\n").map(String.init)
        }
    }
}

// MARK: - The apply pass

@Suite("AuthorizationDB apply — one failure never stops the rest", .serialized)
struct AuthorizationDBPartialApplyTests {
    typealias F = PartialApplyFixtures
    static let composed = "com.example.composed"

    private func tempStore() throws -> (AuthorizationDBSnapshotStore, URL) {
        let dir = try CoordinatorFixtures.tempDirectory()
        return (AuthorizationDBSnapshotStore(directory: dir), dir)
    }

    @Test("a refused write: later denies, the allows and every composition still land, denies first; the right is reported, then lands on the retry")
    func refusedWriteDoesNotStopTheRest() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = MockAuthorizationDB(rights: [
            "com.example.a-deny": F.adminGate, "com.example.b-allow": F.adminGate,
            "com.example.z-deny": F.adminGate, Self.composed: F.composable,
        ])
        db.failWritesFor = ["com.example.a-deny"]
        let mgr = F.manager(db, store, shipped: ["com.example.b-allow": F.adminGate])
        let desired = [F.deny("com.example.a-deny"), F.allow("com.example.b-allow"), F.deny("com.example.z-deny")]

        let result = await F.applyExpectingIncomplete(mgr, desired, compositions: [F.composition(Self.composed)])
        #expect(result?.failed.keys.sorted() == ["com.example.a-deny"])
        #expect(result?.failed["com.example.a-deny"]?.contains("unwritable") == true)
        #expect(result.map { AuthorizationDBError.applyIncomplete($0).localizedDescription.contains("'com.example.a-deny'") } == true)
        // Left as it was, with its original recorded for the retry.
        #expect(db.current("com.example.a-deny") == F.adminGate)
        #expect(store.hasSnapshot(rightName: "com.example.a-deny"))
        // Everything after it still landed.
        #expect(F.dict(db.current("com.example.z-deny"))["class"] as? String == "deny")
        #expect(F.dict(db.current("com.example.b-allow"))["session-owner"] as? Bool == true)
        #expect(result?.composed == [Self.composed])
        #expect(F.dict(db.current(Self.composed))["k-of-n"] as? Int == 1)
        // Every deny is written before any other right, whatever the names.
        let deny = try #require(db.writes.firstIndex(of: "com.example.z-deny"))
        let allow = try #require(db.writes.firstIndex(of: "com.example.b-allow"))
        #expect(deny < allow)
        #expect(db.writes.last == Self.composed)

        // The retry lands it once the write goes through.
        db.failWritesFor = []
        let retried = try await mgr.apply(desired, compositions: [F.composition(Self.composed)])
        #expect(retried.failed.isEmpty)
        #expect(retried.modified == ["com.example.a-deny"])
        #expect(F.dict(db.current("com.example.a-deny"))["class"] as? String == "deny")
    }

    @Test("a right whose definition cannot be read is reported and never touched; the rest land")
    func unreadableRightIsSkipped() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = MockAuthorizationDB(rights: [
            "com.example.a-deny": F.adminGate, "com.example.z-deny": F.adminGate, Self.composed: F.composable,
        ])
        db.failReadsFor = ["com.example.a-deny"]
        let mgr = F.manager(db, store)

        let result = await F.applyExpectingIncomplete(
            mgr, [F.deny("com.example.a-deny"), F.deny("com.example.z-deny")], compositions: [F.composition(Self.composed)])
        #expect(result?.failed.keys.sorted() == ["com.example.a-deny"])
        #expect(result?.failed["com.example.a-deny"]?.contains("unreadable") == true)
        #expect(db.current("com.example.a-deny") == F.adminGate)
        #expect(!store.hasSnapshot(rightName: "com.example.a-deny"))
        #expect(F.dict(db.current("com.example.z-deny"))["class"] as? String == "deny")
        #expect(result?.composed == [Self.composed])
    }

    @Test("a snapshot the store cannot save: that right is neither written nor created; the rest land")
    func unsavableSnapshotLeavesRightUnwritten() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let existing = F.unsnapshottable
        let absent = F.unsnapshottable + "-absent"
        let db = MockAuthorizationDB(rights: [
            existing: F.adminGate, "com.example.z-deny": F.adminGate, Self.composed: F.composable,
        ])
        let mgr = F.manager(db, store)

        let result = await F.applyExpectingIncomplete(
            mgr, [F.deny(existing), F.deny(absent), F.deny("com.example.z-deny")],
            compositions: [F.composition(Self.composed)])
        #expect(result.map { Set($0.failed.keys) } == [existing, absent])
        // Nothing is modified without a record to restore it from.
        #expect(db.current(existing) == F.adminGate)
        #expect(!db.rightExists(absent))
        #expect(!db.writes.contains(existing) && !db.writes.contains(absent))
        #expect(F.dict(db.current("com.example.z-deny"))["class"] as? String == "deny")
        #expect(result?.composed == [Self.composed])
    }

    @Test("a replaced definition whose new snapshot cannot be saved is left alone until it can")
    func unsavableReSnapshotLeavesReplacementAlone() async throws {
        let (store, dir) = try tempStore()
        let right = "com.example.pane"
        let record = dir.appendingPathComponent("\(right).json")
        defer {
            _ = chflags(record.path, 0)
            try? FileManager.default.removeItem(at: dir)
        }
        let db = MockAuthorizationDB(rights: [right: F.adminGate, "com.example.z-deny": F.adminGate])
        let mgr = F.manager(db, store)
        _ = try await mgr.apply([F.deny(right)])

        // Someone else replaces the definition (it still passes the checks),
        // and the store can no longer rewrite the right's record.
        let replacement = F.plist(["class": "user", "group": "admin", "timeout": 30])
        db.seed(right, replacement)
        #expect(chflags(record.path, UInt32(UF_IMMUTABLE)) == 0)
        let desired = [F.deny(right), F.deny("com.example.z-deny")]
        let result = await F.applyExpectingIncomplete(mgr, desired)
        #expect(result?.failed.keys.sorted() == [right])
        #expect(db.current(right) == replacement)
        #expect(try store.load(rightName: right).originalDefinition == F.adminGate)
        #expect(F.dict(db.current("com.example.z-deny"))["class"] as? String == "deny")

        // Once it can be saved, the replacement is the new original and the deny lands.
        #expect(chflags(record.path, 0) == 0)
        let fixed = try await mgr.apply(desired)
        #expect(fixed.nativeChanged == [right])
        #expect(F.dict(db.current(right))["class"] as? String == "deny")
        #expect(try store.load(rightName: right).originalDefinition == replacement)
    }

    @Test("a deny that cannot be created is a failure; an allow that cannot be created stays non-fatal")
    func createFailures() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // The catch-all right governs every undefined name: a plain admin gate.
        let db = MockAuthorizationDB(rights: ["": F.adminGate])
        db.failWritesFor = ["com.example.new-deny", "com.example.new-allow"]
        let mgr = F.manager(db, store)

        let result = await F.applyExpectingIncomplete(mgr, [F.deny("com.example.new-deny")])
        #expect(result?.failed.keys.sorted() == ["com.example.new-deny"])
        #expect(!db.rightExists("com.example.new-deny"))
        #expect(!store.hasSnapshot(rightName: "com.example.new-deny"))

        let allowed = try await mgr.apply([F.allow("com.example.new-allow")])
        #expect(allowed.failed.isEmpty)
        #expect(allowed.skippedMissing == ["com.example.new-allow"])
        #expect(!db.rightExists("com.example.new-allow"))
    }

    @Test("a composition that fails does not stop the next one")
    func failedCompositionDoesNotStopTheNext() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let first = "com.example.composed-a"
        let second = "com.example.composed-b"
        let db = MockAuthorizationDB(rights: [first: F.composable, second: F.composable])
        db.failWritesFor = [first]   // its top-level cannot be rewritten
        let mgr = F.manager(db, store)

        let result = await F.applyExpectingIncomplete(
            mgr, [], compositions: [F.composition(first), F.composition(second)])
        #expect(result?.failed.keys.sorted() == [first])
        #expect(result?.composed == [second])
        #expect(F.dict(db.current(second))["k-of-n"] as? Int == 1)
        #expect(db.current(first) == F.composable)
    }

    @Test("while the reconcile keeps failing, a failure is written to the integrity log once, and again only when it changes")
    func repeatedFailureIsLoggedOnce() async throws {
        let (store, dir) = try tempStore()
        let logs = try CoordinatorFixtures.tempDirectory()
        defer {
            try? FileManager.default.removeItem(at: dir)
            try? FileManager.default.removeItem(at: logs)
        }
        let right = "com.example.pane"
        let db = MockAuthorizationDB(rights: [right: F.adminGate])
        db.failWritesFor = [right]
        let logger = try IntegrityLogger(directory: logs)
        let applier = AuthorizationDBApplier(manager: F.manager(db, store, integrityLogger: logger))
        let profiles = [F.denyProfile(right)]
        let failures = { F.integrityLines(in: logs).filter { $0.contains("could not be applied") }.count }

        for _ in 0..<3 {
            await #expect(throws: AuthorizationDBError.self) { try await applier.reconcile(profiles: profiles) }
        }
        #expect(failures() == 1)

        // The same right failing differently is new.
        db.failWritesFor = []
        db.failReadsFor = [right]
        await #expect(throws: AuthorizationDBError.self) { try await applier.reconcile(profiles: profiles) }
        #expect(failures() == 2)

        // After a pass that succeeded, a failure is logged afresh.
        db.failReadsFor = []
        try await applier.reconcile(profiles: profiles)
        db.seed(right, F.plist(["class": "user", "group": "admin", "timeout": 30]))
        db.failWritesFor = [right]
        await #expect(throws: AuthorizationDBError.self) { try await applier.reconcile(profiles: profiles) }
        #expect(failures() == 3)
    }

    @Test("StartupOutcome carries a failed reconcile and what the state came from; the kill switch's failed restore is not carried")
    func startupOutcomeCarriesFailure() async throws {
        let failed = await StartupCoordinator(
            prefsReader: CoordinatorFixtures.prefs(rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]),
            grantStore: MockGrantStore(), pppc: StaticPPPCStatus(ready: true), authDB: FailingAuthDB(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore(), now: { CoordinatorFixtures.now }
        ).run()
        #expect(failed.degradedReason == .authDBFailure)
        #expect(failed.authDBFailed)
        var inputs = try #require(failed.stateInputs)
        #expect(StartupCoordinator.resolveState(inputs).reason == .authDBFailure)
        inputs.authDBError = false
        #expect(StartupCoordinator.resolveState(inputs).state == .healthy)

        let killSwitch = await StartupCoordinator(
            prefsReader: CoordinatorFixtures.prefs(config: ["daemonEnabled": false]),
            grantStore: MockGrantStore(), pppc: StaticPPPCStatus(ready: true), authDB: FailingAuthDB(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore(), now: { CoordinatorFixtures.now }
        ).run()
        #expect(killSwitch.degradedReason == .authDBFailure)
        #expect(!killSwitch.authDBFailed)
    }
}

// MARK: - The restore sweep

@Suite("AuthorizationDB restore sweep — a failed reset is a leftover and keeps its records", .serialized)
struct AuthorizationDBSweepResetFailureTests {
    typealias F = PartialApplyFixtures

    @Test("a Serberus-written right the sweep cannot reset fails restoreAll and keeps its record")
    func unrecordedFailedResetIsLeftover() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        let right = "com.example.pane"
        // A deny projection with no snapshot left, only its projection record.
        let db = MockAuthorizationDB(rights: [right: AuthorizationDBManager.definitionPlist(for: .deny)])
        try store.saveProjectionDigest("digest", rightName: right)
        db.failWritesFor = [right]
        let mgr = F.manager(db, store)

        do {
            _ = try await mgr.restoreAll()
            Issue.record("restoreAll succeeded while Serberus's deny is still in place")
        } catch let AuthorizationDBError.restoreFailed(name, _) {
            #expect(name.contains(right))
        }
        #expect(F.dict(db.current(right))["class"] as? String == "deny")
        #expect(store.projectionDigest(rightName: right) == "digest")

        // Writable again: the next restore resets it and clears the record.
        db.failWritesFor = []
        _ = try await mgr.restoreAll()
        #expect(F.dict(db.current(right))["class"] as? String == "user")
        #expect(store.projectionDigest(rightName: right) == nil)
    }

    @Test("a recorded right that cannot be reset keeps its snapshot, so the next restore puts the original back")
    func recordedFailedResetKeepsSnapshot() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        let right = "com.example.pane"
        let db = MockAuthorizationDB(rights: [right: F.adminGate])
        let mgr = F.manager(db, store)
        _ = try await mgr.apply([F.deny(right)])

        db.failWritesFor = [right]
        await #expect(throws: AuthorizationDBError.self) { _ = try await mgr.restoreAll() }
        #expect(store.hasSnapshot(rightName: right))
        #expect(F.dict(db.current(right))["class"] as? String == "deny")

        db.failWritesFor = []
        let restored = try await mgr.restoreAll()
        #expect(restored.contains(right))
        #expect(db.current(right) == F.adminGate)   // the original, not a stand-in
        #expect(!store.hasSnapshot(rightName: right))
    }
}

// MARK: - The daemon's retry

@Suite("DaemonController — a failed AuthorizationDB reconcile is retried on its own", .serialized)
struct AuthDBReconcileRetryTests {
    typealias F = PartialApplyFixtures
    static let right = "com.example.pane"

    static func domains(cacheSeconds: Int = 0) -> [String: [String: any Sendable]] {
        var config = CoordinatorFixtures.enforceableConfig
        config["sudoCacheSeconds"] = cacheSeconds
        let rules = String(decoding: try! JSONEncoder().encode(F.denyProfile(right)), as: UTF8.self)
        return [BundleConfig.configDomain: config, BundleConfig.rulesDomain: ["rules_authuri_test": rules]]
    }

    /// The real applier, counting reconciles.
    final class CountingApplier: AuthorizationDBApplying, @unchecked Sendable {
        private let inner: AuthorizationDBApplying
        private let lock = NSLock()
        private var count = 0
        init(_ inner: AuthorizationDBApplying) { self.inner = inner }
        var reconciles: Int { lock.lock(); defer { lock.unlock() }; return count }
        func apply(profiles: [RuleProfile]) async throws { try await inner.apply(profiles: profiles) }
        func reconcile(profiles: [RuleProfile]) async throws {
            bump()
            try await inner.reconcile(profiles: profiles)
        }
        private func bump() { lock.lock(); count += 1; lock.unlock() }
    }

    /// A daemon whose in-memory AuthorizationDB refuses every write until the
    /// test says otherwise, with a real integrity log.
    struct Rig {
        let dir: URL
        let logs: URL
        let db: MockAuthorizationDB
        let authDB: CountingApplier
        let state: DaemonStateController
        let sudoers: DaemonSudoersReconcileTests.ReconcileSpyProvisioner
        let controller: DaemonController

        init(source: PreferencesSource, lastKnownGood: any LastKnownGoodConfigStoring) throws {
            let dir = try CoordinatorFixtures.tempDirectory()
            let paths = DaemonPaths.ephemeral(in: dir)
            try FileManager.default.createDirectory(at: paths.logDirectory, withIntermediateDirectories: true)
            let logger = try IntegrityLogger(directory: paths.logDirectory)
            let db = MockAuthorizationDB(rights: [AuthDBReconcileRetryTests.right: F.adminGate])
            db.failWrites = true
            let authDB = CountingApplier(AuthorizationDBApplier(manager: F.manager(
                db, AuthorizationDBSnapshotStore(directory: paths.authDBBackupDirectory), integrityLogger: logger)))
            let state = DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil)
            let sudoers = DaemonSudoersReconcileTests.ReconcileSpyProvisioner()
            self.dir = dir
            self.logs = paths.logDirectory
            self.db = db
            self.authDB = authDB
            self.state = state
            self.sudoers = sudoers
            self.controller = DaemonController(
                paths: paths, machServiceName: "test.unused", prefsReader: ManagedPreferencesReader(source: source),
                grantStore: NullGrantStore(), stateController: state, integrityLogger: logger, decisionLogger: nil,
                pppc: StaticPPPCStatus(ready: true), authDB: authDB, sudoers: sudoers, lastKnownGood: lastKnownGood,
                deviceSerial: "TESTSERIAL", now: { CoordinatorFixtures.now })
        }

        func events(containing text: String) -> Int {
            F.integrityLines(in: logs).filter { $0.contains(text) }.count
        }
    }

    @Test("a reload whose reconcile fails: degraded(authdb_failure) with the signature committed; each tick retries only the reconcile until it lands")
    func reloadFailureIsRetriedEachTick() async throws {
        let rig = try Rig(source: DictionaryPreferencesSource(domains: Self.domains()),
                          lastKnownGood: InMemoryLastKnownGoodConfigStore())
        defer { try? FileManager.default.removeItem(at: rig.dir) }

        // The policy's deny cannot be written.
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(await rig.state.current().state == .degraded)
        #expect(await rig.state.current().reason == .authDBFailure)
        #expect(rig.authDB.reconciles == 1)
        #expect(rig.sudoers.applyCount == 1)
        #expect(rig.events(containing: "policy reloaded") == 1)
        #expect(await rig.controller.authDBNotFullyAppliedForTesting())
        let cache = await rig.controller.sessionCacheForTesting()
        await cache.store(decision: .allow, key: SessionGrantCache.Key(user: "alice", ruleID: "r", binaryHash: "aa"),
                          ttlSeconds: 300, now: CoordinatorFixtures.now)

        // Nothing changed: only the reconcile runs again, and fails again.
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(rig.authDB.reconciles == 2)
        #expect(await rig.state.current().reason == .authDBFailure)
        #expect(rig.sudoers.applyCount == 1)
        #expect(rig.events(containing: "policy reloaded") == 1)
        #expect(await cache.count(now: CoordinatorFixtures.now) == 1)

        // The AuthorizationDB recovers: the retry lands the deny and clears authdb_failure.
        rig.db.failWrites = false
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(rig.authDB.reconciles == 3)
        #expect(F.dict(rig.db.current(Self.right))["class"] as? String == "deny")
        #expect(await rig.state.current().state == .healthy)
        #expect(await rig.state.current().reason == nil)
        #expect(await rig.controller.authDBNotFullyAppliedForTesting() == false)
        #expect(rig.events(containing: "retry succeeded") == 1)
        #expect(rig.sudoers.applyCount == 1)
        #expect(rig.events(containing: "policy reloaded") == 1)
        #expect(await cache.count(now: CoordinatorFixtures.now) == 1)

        // Fully applied: later ticks leave the AuthorizationDB alone.
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(rig.authDB.reconciles == 3)
    }

    @Test("a startup whose reconcile fails retries it on the next tick, without a full reload")
    func startupFailureIsRetriedNextTick() async throws {
        let source = DictionaryPreferencesSource(domains: Self.domains())
        let lastKnownGood = InMemoryLastKnownGoodConfigStore()
        let rig = try Rig(source: source, lastKnownGood: lastKnownGood)
        defer { try? FileManager.default.removeItem(at: rig.dir) }
        let outcome = await StartupCoordinator(
            prefsReader: ManagedPreferencesReader(source: source), grantStore: MockGrantStore(),
            pppc: StaticPPPCStatus(ready: true), authDB: rig.authDB, lastKnownGood: lastKnownGood,
            now: { CoordinatorFixtures.now }
        ).run()
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .authDBFailure)
        #expect(outcome.authDBFailed)
        await rig.controller.adoptStartupOutcomeForTesting(outcome)

        rig.db.failWrites = false
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(rig.authDB.reconciles == 2)   // startup's, then the retry
        #expect(rig.sudoers.applyCount == 0)  // no full reload pass
        #expect(F.dict(rig.db.current(Self.right))["class"] as? String == "deny")
        #expect(await rig.state.current().state == .healthy)
        #expect(await rig.controller.authDBNotFullyAppliedForTesting() == false)
    }

    @Test("a policy change while a retry is pending runs the full pass, which resets the retry from its own result")
    func policyChangeRunsTheFullPass() async throws {
        let source = MutablePreferencesSource(domains: Self.domains())
        let rig = try Rig(source: source, lastKnownGood: InMemoryLastKnownGoodConfigStore())
        defer { try? FileManager.default.removeItem(at: rig.dir) }
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(await rig.controller.authDBNotFullyAppliedForTesting())

        rig.db.failWrites = false
        source.set(Self.domains(cacheSeconds: 5))
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(rig.authDB.reconciles == 2)
        #expect(rig.sudoers.applyCount == 2)
        #expect(rig.events(containing: "policy reloaded") == 2)
        #expect(await rig.state.current().state == .healthy)
        #expect(await rig.controller.authDBNotFullyAppliedForTesting() == false)

        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(rig.authDB.reconciles == 2)
    }

    @Test("the kill switch ends a pending retry: later ticks never publish over kill_switch")
    func killSwitchEndsTheRetry() async throws {
        let source = MutablePreferencesSource(domains: Self.domains())
        let rig = try Rig(source: source,
                          lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()))
        defer { try? FileManager.default.removeItem(at: rig.dir) }
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(await rig.controller.authDBNotFullyAppliedForTesting())

        rig.db.failWrites = false
        source.set([BundleConfig.configDomain: ["daemonEnabled": false], BundleConfig.rulesDomain: Self.domains()[BundleConfig.rulesDomain]!])
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(await rig.state.current().state == .killSwitch)
        #expect(await rig.controller.authDBNotFullyAppliedForTesting() == false)

        let reconciles = rig.authDB.reconciles
        await rig.controller.runWatchdoggedReloadPassForTesting()
        #expect(rig.authDB.reconciles == reconciles)
        #expect(await rig.state.current().state == .killSwitch)
    }
}

// MARK: - A right a standard user pre-created

/// Any user can create a right macOS does not ship (`config.add.` is
/// class=allow), and authd then refuses to let root overwrite it (-60005)
/// while still letting root remove it. `MockAuthorizationDB.otherCreator`
/// models that.
@Suite("AuthorizationDB: a right created outside Serberus is replaced, not left refusing the deny", .serialized)
struct AuthorizationDBForeignReplaceTests {
    typealias F = PartialApplyFixtures
    static let right = "com.example.serberus-livetest"
    static let userAllow = F.plist(["class": "allow"])

    private func dirs() throws -> (AuthorizationDBSnapshotStore, URL, URL) {
        let dir = try CoordinatorFixtures.tempDirectory()
        let logs = try CoordinatorFixtures.tempDirectory()
        return (AuthorizationDBSnapshotStore(directory: dir), dir, logs)
    }

    @Test("a deny on a user-pre-created unshipped right lands: removed as root, then written; the event is logged")
    func denyReplacesUserCreatedRight() async throws {
        let (store, dir, logs) = try dirs()
        defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: logs) }
        let db = MockAuthorizationDB(rights: [:])
        db.seedByOtherCreator(Self.right, Self.userAllow)
        let manager = F.manager(db, store, integrityLogger: try IntegrityLogger(directory: logs))

        let result = try await manager.apply([F.deny(Self.right)])
        #expect(result.failed.isEmpty)
        #expect(result.modified == [Self.right])
        #expect(db.removes == [Self.right])
        #expect(F.dict(db.current(Self.right))["class"] as? String == "deny")
        let snapshot = try store.load(rightName: Self.right)
        #expect(snapshot.foreign)
        #expect(snapshot.originalDefinition == Self.userAllow)
        #expect(F.integrityLines(in: logs).contains { $0.contains("replaced right") && $0.contains("created outside Serberus") })

        // Steady state: nothing more is removed or written.
        let writes = db.writes.count
        let steady = try await manager.apply([F.deny(Self.right)])
        #expect(steady.unchanged == [Self.right])
        #expect(db.writes.count == writes)
        #expect(db.removes == [Self.right])
    }

    @Test("a refused write on a shipped right, one with a recorded non-foreign original, or a non-authd failure, is never removed")
    func shippedOrRecordedRightNotRemoved() async throws {
        do {
            let (store, dir, logs) = try dirs()
            defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: logs) }
            let db = MockAuthorizationDB(rights: [:])
            db.seedByOtherCreator(Self.right, Self.userAllow)
            let manager = F.manager(db, store, shipped: [Self.right: Self.userAllow])
            let result = try #require(await F.applyExpectingIncomplete(manager, [F.deny(Self.right)]))
            #expect(result.failed[Self.right] != nil)
            #expect(db.removes.isEmpty)
            #expect(db.current(Self.right) == Self.userAllow)
        }
        do {
            let (store, dir, logs) = try dirs()
            defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: logs) }
            let db = MockAuthorizationDB(rights: [:])
            db.seedByOtherCreator(Self.right, Self.userAllow)
            try store.save(AuthorizationDBSnapshot(rightName: Self.right, originalDefinition: Self.userAllow,
                                                   timestamp: CoordinatorFixtures.now, daemonVersion: "0.8"))
            let result = try #require(await F.applyExpectingIncomplete(F.manager(db, store), [F.deny(Self.right)]))
            #expect(result.failed[Self.right] != nil)
            #expect(db.removes.isEmpty)
            #expect(db.current(Self.right) == Self.userAllow)
        }
        do {
            // A write that fails for any reason other than authd's refusal
            // (-60005) never removes the right, foreign or not.
            let (store, dir, logs) = try dirs()
            defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: logs) }
            let db = MockAuthorizationDB(rights: [Self.right: Self.userAllow])
            db.failWritesFor = [Self.right]
            let result = try #require(await F.applyExpectingIncomplete(F.manager(db, store), [F.deny(Self.right)]))
            #expect(result.failed[Self.right] != nil)
            #expect(db.removes.isEmpty)
            #expect(db.current(Self.right) == Self.userAllow)
        }
    }

    @Test("restore after a replace puts back the user's original definition")
    func restoreAfterReplace() async throws {
        let (store, dir, logs) = try dirs()
        defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: logs) }
        let db = MockAuthorizationDB(rights: [:])
        db.seedByOtherCreator(Self.right, Self.userAllow)
        let manager = F.manager(db, store)
        _ = try await manager.apply([F.deny(Self.right)])
        #expect(F.dict(db.current(Self.right))["class"] as? String == "deny")

        let restored = try await manager.restoreAll()
        #expect(restored.contains(Self.right))
        #expect(db.current(Self.right) == Self.userAllow)
        #expect(!store.hasSnapshot(rightName: Self.right))
        #expect(db.removes == [Self.right])
    }

    @Test("re-created between remove and write: reported, not looped; the next pass retries and lands")
    func recreationRace() async throws {
        let (store, dir, logs) = try dirs()
        defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: logs) }
        let db = MockAuthorizationDB(rights: [:])
        db.seedByOtherCreator(Self.right, Self.userAllow)
        let recreated = F.plist(["class": "user", "group": "staff"])
        db.onRemove = { db, name in db.seedByOtherCreator(name, recreated) }
        let manager = F.manager(db, store)

        let result = try #require(await F.applyExpectingIncomplete(manager, [F.deny(Self.right)]))
        #expect(result.failed[Self.right] != nil)
        #expect(db.removes == [Self.right])              // one attempt in the pass
        #expect(db.current(Self.right) == recreated)

        db.onRemove = nil
        let retry = try await manager.apply([F.deny(Self.right)])
        #expect(retry.failed.isEmpty)
        #expect(db.removes == [Self.right, Self.right])
        #expect(F.dict(db.current(Self.right))["class"] as? String == "deny")
        // The re-created definition is the foreign original restore puts back.
        let snapshot = try store.load(rightName: Self.right)
        #expect(snapshot.foreign)
        #expect(snapshot.originalDefinition == recreated)
    }

    @Test("a user-created right carrying a copy of Serberus's marker still takes the deny; restore resets it to admin-auth")
    func markerCopyStillReplaced() async throws {
        let (store, dir, logs) = try dirs()
        defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: logs) }
        let db = MockAuthorizationDB(rights: [:])
        db.seedByOtherCreator(Self.right, F.plist(["class": "allow", "comment": AuthorizationDBManager.managedMarker]))
        let manager = F.manager(db, store)
        let result = try await manager.apply([F.deny(Self.right)])
        #expect(result.failed.isEmpty)
        #expect(result.originalUnrecoverable == [Self.right])
        #expect(F.dict(db.current(Self.right))["class"] as? String == "deny")

        _ = try await manager.restoreAll()
        let restoredClass = F.dict(db.current(Self.right))["class"] as? String
        #expect(restoredClass != "allow" && restoredClass != "deny")
    }
}
