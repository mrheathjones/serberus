import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// In-memory authdb backend simulating right definitions.
final class MockAuthorizationDB: AuthorizationDBBackend, @unchecked Sendable {
    private let lock = NSLock()
    private var rights: [String: Data]
    private(set) var writes: [String] = []
    private(set) var removes: [String] = []
    var failWrites = false
    /// Simulates macOS denying AuthorizationRightRemove (e.g. -60005).
    var failRemoves = false
    /// Rights whose writes fail, as `failWrites` makes every write fail.
    var failWritesFor: Set<String> = []
    /// Rights that exist but whose definition cannot be read.
    var failReadsFor: Set<String> = []

    init(rights: [String: Data]) {
        self.rights = rights
    }

    func rightExists(_ name: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return rights[name] != nil
    }

    func definition(of name: String) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let data = rights[name], !failReadsFor.contains(name) else {
            throw AuthorizationDBError.rightUnreadable(name: name, status: -1)
        }
        return data
    }

    /// macOS 26 authd stamps the WRITING process's code identity
    /// (`identifier` + `requirement`) onto a right it creates. Whether it
    /// also stamps an update is unknown, so both are modelled.
    var stampCreates = false
    var stampUpdates = false
    static let stampIdentifier = "com.herojoneslabs.serberus.daemon"
    static let stampRequirement = "identifier \"com.herojoneslabs.serberus.daemon\" and anchor apple generic and certificate leaf[subject.CN] = \"Apple Development: Test (TEST000000)\" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"

    /// Models authd (macOS 26.7.1): rights created by a non-root
    /// "other creator" (any user may create a right, `config.add.` is
    /// class=allow). authd refuses to let anyone else, root included,
    /// overwrite such a right (-60005) but lets root remove it.
    var otherCreator: Set<String> = []
    /// Called after a successful remove (outside the lock), to model a user
    /// re-creating the right between Serberus's remove and write.
    var onRemove: ((MockAuthorizationDB, String) -> Void)?

    /// Test setup: `name` exists with `data`, created by a non-root other
    /// creator.
    func seedByOtherCreator(_ name: String, _ data: Data) {
        lock.lock(); defer { lock.unlock() }
        rights[name] = data
        otherCreator.insert(name)
    }

    func setDefinition(_ data: Data, for name: String) throws {
        if failWrites || failWritesFor.contains(name) {
            throw AuthorizationDBError.rightUnwritable(name: name, status: -1)
        }
        lock.lock(); defer { lock.unlock() }
        if otherCreator.contains(name), rights[name] != nil {
            throw AuthorizationDBError.rightUnwritable(name: name, status: -60005)
        }
        var stored = data
        if (rights[name] == nil ? stampCreates : stampUpdates),
           var dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] {
            dict["identifier"] = Self.stampIdentifier
            dict["requirement"] = Self.stampRequirement
            stored = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        }
        rights[name] = stored
        writes.append(name)
    }

    func removeRight(_ name: String) throws {
        if failRemoves {
            throw AuthorizationDBError.rightUnwritable(name: name, status: -60005)
        }
        lock.lock()
        rights[name] = nil
        otherCreator.remove(name)
        removes.append(name)
        let hook = onRemove
        lock.unlock()
        hook?(self, name)
    }

    func current(_ name: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return rights[name]
    }

    /// Enumerable, like the production backend's read-only auth.db read.
    /// `enumerable = false` models a backend that cannot list rights.
    var enumerable = true
    func allRightNames() -> [String]? {
        lock.lock(); defer { lock.unlock() }
        return enumerable ? Array(rights.keys) : nil
    }

    /// Sets a right's definition without recording a write (test setup).
    func seed(_ name: String, _ data: Data) {
        lock.lock(); defer { lock.unlock() }
        rights[name] = data
    }
}

@Suite("AuthorizationDBManager", .serialized)
struct AuthorizationDBManagerTests {
    private func definition(_ rule: String) -> Data {
        try! PropertyListSerialization.data(
            fromPropertyList: ["rule": [rule], "class": "rule"] as [String: Any],
            format: .xml, options: 0
        )
    }

    /// A `class=user group=admin` rule, for a native definition to delegate to.
    private var adminRule: Data {
        try! PropertyListSerialization.data(
            fromPropertyList: ["class": "user", "group": "admin"] as [String: Any], format: .xml, options: 0)
    }

    private func tempStore() throws -> (AuthorizationDBSnapshotStore, URL) {
        let dir = try CoordinatorFixtures.tempDirectory()
        return (AuthorizationDBSnapshotStore(directory: dir), dir)
    }

    /// `shipped` models the rights macOS ships in authorization.plist; a
    /// right absent from it that Serberus has no record of is foreign.
    private func manager(backend: AuthorizationDBBackend, store: AuthorizationDBSnapshotStore,
                         shipped: [String: Data] = [:]) -> AuthorizationDBManager {
        AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil,
                               daemonVersion: "1.0.0", now: { CoordinatorFixtures.now }, shippedDefinitions: { shipped[$0] })
    }

    private func authuriProfile(key: String, right: String, action: RuleAction) -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: key, profilePriority: 50,
                    rules: [Rule(id: "r", type: .authuri, action: action, description: "d", priority: 1,
                                 match: MatchCriteria(authURI: right))])
    }

    @Test("reconcile restores a right dropped from the policy and applies the new one")
    func reconcileRestoresRemoved() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let originalA = definition("original-datetime")
        let originalB = definition("original-printing")
        let backend = MockAuthorizationDB(rights: [
            "system.preferences.datetime": originalA,
            "system.preferences.printing": originalB,
        ])
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store))

        // Control datetime (deny).
        try await applier.apply(profiles: [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .deny)])
        #expect(backend.current("system.preferences.datetime") != originalA)

        // Reconcile to a policy that controls printing instead.
        try await applier.reconcile(profiles: [authuriProfile(key: "rules_authuri_b", right: "system.preferences.printing", action: .deny)])
        #expect(backend.current("system.preferences.datetime") == originalA)   // dropped right restored
        #expect(backend.current("system.preferences.printing") != originalB)   // new right controlled
    }

    @Test("steady state: reconcile with the SAME desired set does not restore or re-write the right")
    func reconcileSteadyStateNoFlicker() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = definition("original-datetime")
        let backend = MockAuthorizationDB(rights: ["system.preferences.datetime": original])
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store))
        let profiles = [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .deny)]

        try await applier.apply(profiles: profiles)
        let applied = try #require(backend.current("system.preferences.datetime"))
        #expect(applied != original)

        // Record write/remove counts, then reconcile with the identical policy.
        let writesBefore = backend.writes.count
        let removesBefore = backend.removes.count
        try await applier.reconcile(profiles: profiles)

        // No further backend mutation for the still-desired right: it was neither
        // restored (removeRight/setDefinition-to-original) nor re-written.
        #expect(backend.writes.count == writesBefore)
        #expect(backend.removes.count == removesBefore)
        // Its definition stayed the applied value the whole time (never flickered
        // back to the original admin gate).
        #expect(backend.current("system.preferences.datetime") == applied)
        #expect(store.hasSnapshot(rightName: "system.preferences.datetime"))
    }

    @Test("add a new right: the existing controlled right is untouched; the new one is snapshotted + applied")
    func reconcileAddNewRight() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let originalA = definition("original-datetime")
        let originalB = definition("original-printing")
        let backend = MockAuthorizationDB(rights: [
            "system.preferences.datetime": originalA,
            "system.preferences.printing": originalB,
        ])
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store))

        try await applier.apply(profiles: [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .deny)])
        let appliedA = try #require(backend.current("system.preferences.datetime"))
        let writesBefore = backend.writes.count

        // Reconcile with {existing + a NEW right}.
        try await applier.reconcile(profiles: [
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
                Rule(id: "r1", type: .authuri, action: .deny, description: "d", priority: 1,
                     match: MatchCriteria(authURI: "system.preferences.datetime")),
                Rule(id: "r2", type: .authuri, action: .deny, description: "d", priority: 2,
                     match: MatchCriteria(authURI: "system.preferences.printing")),
            ]),
        ])

        // Existing right untouched (no restore, no rewrite): same value, one new write total (for the new right).
        #expect(backend.current("system.preferences.datetime") == appliedA)
        #expect(backend.writes.count == writesBefore + 1)
        #expect(backend.writes.last == "system.preferences.printing")
        // New right snapshotted + applied.
        #expect(store.hasSnapshot(rightName: "system.preferences.printing"))
        #expect(backend.current("system.preferences.printing") != originalB)
    }

    @Test("drop a right: the dropped right is restored; the kept right is untouched")
    func reconcileDropOneKeepOther() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let originalA = definition("original-datetime")
        let originalB = definition("original-printing")
        let backend = MockAuthorizationDB(rights: [
            "system.preferences.datetime": originalA,
            "system.preferences.printing": originalB,
        ])
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store))

        try await applier.apply(profiles: [
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
                Rule(id: "r1", type: .authuri, action: .deny, description: "d", priority: 1,
                     match: MatchCriteria(authURI: "system.preferences.datetime")),
                Rule(id: "r2", type: .authuri, action: .deny, description: "d", priority: 2,
                     match: MatchCriteria(authURI: "system.preferences.printing")),
            ]),
        ])
        let appliedA = try #require(backend.current("system.preferences.datetime"))
        let writesBefore = backend.writes.count

        // Reconcile with printing dropped.
        try await applier.reconcile(profiles: [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .deny)])

        // Dropped right restored to its original; snapshot cleared.
        #expect(backend.current("system.preferences.printing") == originalB)
        #expect(!store.hasSnapshot(rightName: "system.preferences.printing"))
        // Kept right untouched — and PROVEN untouched: it is never re-written
        // during the reconcile (the old restore-all path would restore it to the
        // original then re-apply, appearing in `writes`). Only the dropped
        // right's restore write should appear.
        #expect(backend.current("system.preferences.datetime") == appliedA)
        #expect(!backend.writes[writesBefore...].contains("system.preferences.datetime"))
        #expect(store.hasSnapshot(rightName: "system.preferences.datetime"))
    }

    @Test("change a right: a kept right whose projection changed is updated in place, not reverted-then-reapplied")
    func reconcileChangeInPlace() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = definition("original-datetime")
        let backend = MockAuthorizationDB(rights: ["system.preferences.datetime": original])
        // The rule the native definition delegates to: an admin gate, so a
        // plain allow may be written over it.
        backend.seed("original-datetime", adminRule)
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store,
                                                              shipped: ["system.preferences.datetime": original]))

        // First applied as allow (session-owner-or-admin).
        try await applier.apply(profiles: [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .allow)])
        #expect(AuthorizationDBManager.semanticallyEqual(
            backend.current("system.preferences.datetime")!,
            AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)))
        let removesBefore = backend.removes.count
        let writesBefore = backend.writes.count

        // Reconcile with the projection changed to deny.
        try await applier.reconcile(profiles: [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .deny)])

        // Updated in place to the new definition — never reverted to the original.
        #expect(AuthorizationDBManager.semanticallyEqual(
            backend.current("system.preferences.datetime")!,
            AuthorizationDBManager.definitionPlist(for: .deny)))
        #expect(backend.current("system.preferences.datetime") != original)
        #expect(backend.removes.count == removesBefore)   // never removed as part of a restore
        // The proof of "in place, not reverted-then-reapplied": the changed right
        // is written EXACTLY ONCE (the new deny). The old restore-all-then-apply
        // path wrote it twice — original (restore) then deny (re-apply) — so this
        // count distinguishes the differential behavior from the flicker bug.
        let datetimeWrites = backend.writes[writesBefore...].filter { $0 == "system.preferences.datetime" }.count
        #expect(datetimeWrites == 1)
        #expect(store.hasSnapshot(rightName: "system.preferences.datetime"))
    }

    @Test("restore-failure resilience: a failed drop-restore still applies the desired set and surfaces the error")
    func reconcileRestoreFailureStillApplies() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let originalA = definition("original-datetime")
        let originalB = definition("original-printing")
        let backend = MockAuthorizationDB(rights: [
            "system.preferences.datetime": originalA,
            "system.preferences.printing": originalB,
        ])
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store))

        try await applier.apply(profiles: [
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
                Rule(id: "r1", type: .authuri, action: .deny, description: "d", priority: 1,
                     match: MatchCriteria(authURI: "system.preferences.datetime")),
                Rule(id: "r2", type: .authuri, action: .deny, description: "d", priority: 2,
                     match: MatchCriteria(authURI: "system.preferences.printing")),
            ]),
        ])

        // Make the restore of the dropped right (printing) fail on write-back.
        backend.failWrites = true
        await #expect(throws: AuthorizationDBError.self) {
            // Drop printing; datetime stays desired. Restore of printing fails, but
            // datetime's desired definition must still be enforced (apply of a still-
            // desired unchanged right is a no-op, so no write is needed and no throw
            // from apply) and the restore error is surfaced.
            try await applier.reconcile(profiles: [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .deny)])
        }
        // datetime still controlled (its snapshot intact, definition unchanged).
        #expect(store.hasSnapshot(rightName: "system.preferences.datetime"))
        #expect(AuthorizationDBManager.semanticallyEqual(
            backend.current("system.preferences.datetime")!,
            AuthorizationDBManager.definitionPlist(for: .deny)))
    }

    @Test("controlledRightNames reports every snapshotted right")
    func controlledRightNamesReflectsSnapshots() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [
            "system.preferences.datetime": definition("a"),
            "system.preferences.printing": definition("b"),
        ])
        let mgr = manager(backend: backend, store: store)
        #expect(mgr.controlledRightNames().isEmpty)

        try await mgr.apply([
            .init(name: "system.preferences.datetime", definition: AuthorizationDBManager.definitionPlist(for: .deny)),
            .init(name: "system.preferences.printing", definition: AuthorizationDBManager.definitionPlist(for: .deny)),
        ])
        #expect(Set(mgr.controlledRightNames()) == ["system.preferences.datetime", "system.preferences.printing"])

        _ = try await mgr.restore(names: ["system.preferences.printing"])
        #expect(mgr.controlledRightNames() == ["system.preferences.datetime"])
    }

    @Test("reconcile to an empty policy restores every controlled right")
    func reconcileEmptyRestoresAll() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = definition("original-datetime")
        let backend = MockAuthorizationDB(rights: ["system.preferences.datetime": original])
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store))

        try await applier.apply(profiles: [authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .deny)])
        #expect(backend.current("system.preferences.datetime") != original)

        try await applier.reconcile(profiles: [])   // rules removed entirely
        #expect(backend.current("system.preferences.datetime") == original)
    }

    @Test("discovers authuri right names deterministically")
    func discovery() {
        let profiles = [
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_b", profilePriority: 50,
                        rules: [Rule(id: "r1", type: .authuri, action: .allow, description: "d", priority: 1,
                                     match: MatchCriteria(authURI: "system.keychain-modify"))]),
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50,
                        rules: [Rule(id: "r2", type: .authuri, action: .allow, description: "d", priority: 1,
                                     match: MatchCriteria(authURI: "system.preferences"))]),
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_sudo_x", profilePriority: 50,
                        rules: [Rule(id: "r3", type: .sudo, action: .allow, description: "d", priority: 1,
                                     match: MatchCriteria(commandPattern: "/bin/x", matchType: .exact))]),
        ]
        #expect(AuthorizationDBManager.discoverRightNames(in: profiles)
            == ["system.keychain-modify", "system.preferences"])
    }

    @Test("snapshots existing rights once, with a valid checksum")
    func snapshotOnce() async throws {
        let backend = MockAuthorizationDB(rights: ["system.keychain-modify": definition("authenticate-admin")])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = manager(backend: backend, store: store)

        let first = try await mgr.apply([.init(name: "system.keychain-modify")])
        #expect(first.snapshotted == ["system.keychain-modify"])
        #expect(store.hasSnapshot(rightName: "system.keychain-modify"))
        #expect(try store.load(rightName: "system.keychain-modify").isIntact)

        // Re-applying does not snapshot again.
        let second = try await mgr.apply([.init(name: "system.keychain-modify")])
        #expect(second.snapshotted.isEmpty)
        #expect(second.unchanged == ["system.keychain-modify"])
    }

    @Test("creates a right that does not exist, recording an absent tombstone")
    func createsMissingRight() async throws {
        let backend = MockAuthorizationDB(rights: [:])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let result = try await manager(backend: backend, store: store)
            .apply([.init(name: "system.invented-right", definition: definition("authenticate-session-owner-or-admin"))])
        #expect(result.created == ["system.invented-right"])
        #expect(result.skippedMissing.isEmpty)
        #expect(backend.writes == ["system.invented-right"])
        #expect(backend.rightExists("system.invented-right"))
        // The tombstone marks it as created (wasAbsent) so restore removes it.
        let snap = try store.load(rightName: "system.invented-right")
        #expect(snap.wasAbsent)
    }

    @Test("restore REMOVES a right Serberus created (does not rewrite it)")
    func restoreRemovesCreatedRight() async throws {
        let backend = MockAuthorizationDB(rights: [:])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = manager(backend: backend, store: store)

        try await mgr.apply([.init(name: "system.invented-right",
                                   definition: definition("authenticate-session-owner-or-admin"))])
        #expect(backend.rightExists("system.invented-right"))

        let restored = try await mgr.restoreAll()
        #expect(restored == ["system.invented-right"])
        #expect(backend.removes == ["system.invented-right"])
        #expect(!backend.rightExists("system.invented-right"))          // gone, not left behind
        #expect(!store.hasSnapshot(rightName: "system.invented-right")) // tombstone cleared
    }

    @Test("a missing right that is protected is never created")
    func protectedMissingNeverCreated() async throws {
        let backend = MockAuthorizationDB(rights: [:])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let result = try await manager(backend: backend, store: store)
            .apply([.init(name: "system.login.console", definition: definition("authenticate-admin"))])
        #expect(result.skippedProtected == ["system.login.console"])
        #expect(result.created.isEmpty)
        #expect(backend.writes.isEmpty)
        #expect(!backend.rightExists("system.login.console"))
    }

    @Test("restore neutralizes a created right macOS refuses to remove, without stranding others")
    func restoreCreatedRightRemovalDenied() async throws {
        let existing = definition("original-datetime")
        let backend = MockAuthorizationDB(rights: ["system.preferences.datetime": existing])
        backend.seed("original-datetime", adminRule)
        backend.failRemoves = true   // macOS denies AuthorizationRightRemove (-60005)
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = manager(backend: backend, store: store)

        try await mgr.apply([
            .init(name: "system.preferences.datetime", definition: definition("authenticate-session-owner-or-admin")),
            .init(name: "system.invented-right", definition: definition("authenticate-session-owner-or-admin")),
        ])
        #expect(backend.rightExists("system.invented-right"))

        // Restore must NOT throw even though the created right can't be removed,
        // and the existing right must still be rolled back (not stranded).
        let restored = try await mgr.restoreAll()
        #expect(Set(restored) == ["system.preferences.datetime", "system.invented-right"])
        #expect(backend.current("system.preferences.datetime") == existing)   // real right restored
        // Un-removable created right neutralized to admin-auth — never left as the
        // weaker session-owner gate, never removed.
        #expect(AuthorizationDBManager.semanticallyEqual(
            backend.current("system.invented-right")!,
            AuthorizationDBManager.definitionPlist(for: .requireAdmin)))
    }

    @Test("reconcile re-applies the current policy even when a created right can't be removed")
    func reconcileAppliesDespiteRemovalDenied() async throws {
        let existing = definition("original-datetime")
        let backend = MockAuthorizationDB(rights: ["system.preferences.datetime": existing])
        backend.seed("original-datetime", adminRule)
        // The wildcard authd answers the undefined right from: an admin gate.
        backend.seed("system.", definition("original-datetime"))
        backend.failRemoves = true
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let applier = AuthorizationDBApplier(manager: manager(backend: backend, store: store))

        let profiles = [
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
                Rule(id: "r1", type: .authuri, action: .allow, description: "d", priority: 1,
                     match: MatchCriteria(authURI: "system.preferences.datetime")),
                Rule(id: "r2", type: .authuri, action: .allow, description: "d", priority: 2,
                     match: MatchCriteria(authURI: "system.invented-right")),
            ]),
        ]
        try await applier.apply(profiles: profiles)          // modify existing + create missing
        #expect(backend.rightExists("system.invented-right"))

        // DROP the created (invented) right so reconcile's restore actually hits
        // the denied AuthorizationRightRemove path (with the full policy it would
        // stay desired and never be restored). Removal is refused, so the created
        // right is reset to the admin gate — and the STILL-DESIRED datetime right
        // must remain applied: a restore failure on the dropped right must never
        // strand the rights that stay in the policy.
        try await applier.reconcile(profiles: [
            authuriProfile(key: "rules_authuri_a", right: "system.preferences.datetime", action: .allow),
        ])
        let sessionOwner = AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)
        #expect(AuthorizationDBManager.semanticallyEqual(backend.current("system.preferences.datetime")!, sessionOwner))
        // Dropped created right could not be removed (macOS denied) → reset to the
        // admin default, never left at its prior allow gate; snapshot cleared.
        #expect(AuthorizationDBManager.semanticallyEqual(
            backend.current("system.invented-right")!,
            AuthorizationDBManager.definitionPlist(for: .requireAdmin)))
        #expect(!store.hasSnapshot(rightName: "system.invented-right"))
    }

    @Test("minimal diff: writes only when the definition differs")
    func minimalDiff() async throws {
        let original = definition("authenticate-admin")
        let backend = MockAuthorizationDB(rights: ["r": original])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = manager(backend: backend, store: store)

        // Desired equals current → no write.
        _ = try await mgr.apply([.init(name: "r", definition: original)])
        #expect(backend.writes.isEmpty)

        // Desired differs → one write.
        let changed = definition("serberus-evaluate")
        let result = try await mgr.apply([.init(name: "r", definition: changed)])
        #expect(result.modified == ["r"])
        #expect(backend.current("r") == changed)
    }

    @Test("restoreAll returns every modified right to its original and clears snapshots")
    func restore() async throws {
        let original = definition("authenticate-admin")
        let backend = MockAuthorizationDB(rights: ["r": original])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = manager(backend: backend, store: store)

        try await mgr.apply([.init(name: "r", definition: definition("serberus-evaluate"))])
        #expect(backend.current("r") != original)

        let restored = try await mgr.restoreAll()
        #expect(restored == ["r"])
        #expect(backend.current("r") == original)
        #expect(!store.hasSnapshot(rightName: "r"))
    }

    @Test("a tampered snapshot fails the checksum check on restore")
    func tamperedSnapshot() async throws {
        let backend = MockAuthorizationDB(rights: ["r": definition("admin")])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try await manager(backend: backend, store: store).apply([.init(name: "r")])

        // Corrupt the snapshot file's definition without fixing the checksum.
        let file = dir.appendingPathComponent("r.json")
        var json = try JSONSerialization.jsonObject(with: try Data(contentsOf: file)) as! [String: Any]
        json["originalDefinition"] = Data("tampered".utf8).base64EncodedString()
        try JSONSerialization.data(withJSONObject: json).write(to: file)

        #expect(throws: AuthorizationDBError.self) {
            _ = try store.load(rightName: "r")
        }
    }

    @Test("restore failure surfaces (drives degraded state)")
    func restoreFailure() async throws {
        let backend = MockAuthorizationDB(rights: ["r": definition("admin")])
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = manager(backend: backend, store: store)
        try await mgr.apply([.init(name: "r", definition: definition("changed"))])

        backend.failWrites = true
        await #expect(throws: AuthorizationDBError.self) {
            _ = try await mgr.restoreAll()
        }
    }
}

@Suite("AuthorizationDB authuri mapping")
struct AuthorizationDBMappingTests {
    private func authuriRule(_ uri: String, _ action: RuleAction, _ elevation: ElevationType = .silent) -> Rule {
        Rule(id: "\(uri)-\(action.rawValue)", type: .authuri, action: action, description: "d", priority: 1,
             match: MatchCriteria(authURI: uri), elevation: ElevationBehavior(type: elevation))
    }

    private func profile(_ key: String, _ priority: Int, _ rules: [Rule]) -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: key, profilePriority: priority, rules: rules)
    }

    private func ruleClass(of data: Data) -> String? {
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return (plist as? [String: Any])?["class"] as? String
    }

    private func ruleRefs(of data: Data) -> [String]? {
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return (plist as? [String: Any])?["rule"] as? [String]
    }

    private func boolValue(of data: Data, _ key: String) -> Bool? {
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return (plist as? [String: Any])?[key] as? Bool
    }

    @Test("allow → session-owner-or-admin (never strips auth); deny → class=deny; definitions serialize")
    func policyProjection() {
        // allow NEVER projects to class=allow — that would strip authentication.
        // It maps to session-owner-or-admin so a STANDARD user can self-serve.
        #expect(AuthorizationDBManager.policy(for: authuriRule("a", .allow, .silent)) == .requireSessionOwnerOrAdmin)
        #expect(AuthorizationDBManager.policy(for: authuriRule("a", .allow, .prompt)) == .requireSessionOwnerOrAdmin)
        #expect(AuthorizationDBManager.policy(for: authuriRule("a", .deny)) == .deny)

        #expect(ruleClass(of: AuthorizationDBManager.definitionPlist(for: .deny)) == "deny")
        // The allow projection is a self-contained class=user definition (NOT a
        // delegate to the built-in authenticate-session-owner-or-admin rule): the
        // session owner self-serves, and — the MDM/installer invariant — a
        // root/non-interactive caller (Jamf `installer`) passes via allow-root.
        let owner = AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)
        #expect(ruleClass(of: owner) == "user")
        #expect(boolValue(of: owner, "session-owner") == true)
        #expect(boolValue(of: owner, "allow-root") == true)
        // requireAdmin (the snapshot-loss reset target) is likewise root-passable.
        let admin = AuthorizationDBManager.definitionPlist(for: .requireAdmin)
        #expect(ruleClass(of: admin) == "user")
        #expect(boolValue(of: admin, "allow-root") == true)
    }

    @Test("protected rights are never modified (deny-list, fail closed)")
    func protectedRightsSkipped() async throws {
        #expect(AuthorizationDBManager.isProtected("system.login.console"))
        #expect(AuthorizationDBManager.isProtected("authenticate-admin"))
        #expect(AuthorizationDBManager.isProtected("config.modify.right"))
        #expect(!AuthorizationDBManager.isProtected("system.preferences"))
        // Install rights are NOT protected — rewriting them (so standard users
        // self-install) is a legitimate use case; the projection's allow-root
        // keeps a root/non-interactive Jamf install working.
        #expect(!AuthorizationDBManager.isProtected("system.install.software"))

        // desiredRights excludes the protected right, keeps the install right.
        let desired = AuthorizationDBManager.desiredRights(in: [
            profile("rules_authuri_a", 50, [
                authuriRule("system.login.console", .deny),
                authuriRule("system.install.software", .allow),
                authuriRule("system.preferences.datetime", .deny),
            ]),
        ])
        #expect(desired.map(\.name) == ["system.install.software", "system.preferences.datetime"])
        // The install right's rewrite carries allow-root so a root Jamf/MDM
        // installer is authorized without an (impossible) interactive prompt.
        let install = try #require(desired.first { $0.name == "system.install.software" })
        #expect(boolValue(of: try #require(install.definition), "allow-root") == true)

        // apply re-checks even if a protected right is passed directly (no write).
        let backend = MockAuthorizationDB(rights: ["system.login.console": Data("x".utf8)])
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = AuthorizationDBManager(backend: backend, store: AuthorizationDBSnapshotStore(directory: dir),
                                         integrityLogger: nil, daemonVersion: "1.0.0", now: { CoordinatorFixtures.now }, shippedDefinitions: { _ in nil })
        let result = try await mgr.apply([.init(name: "system.login.console",
                                                definition: AuthorizationDBManager.definitionPlist(for: .deny))])
        #expect(result.skippedProtected == ["system.login.console"])
        #expect(backend.writes.isEmpty)
    }

    @Test("semantic diff ignores system metadata — no rewrite churn on restart")
    func semanticDiffIgnoresMetadata() {
        let desired = AuthorizationDBManager.definitionPlist(for: .deny) // {class:deny}
        let currentWithMeta = try! PropertyListSerialization.data(
            fromPropertyList: ["class": "deny", "created": 1.0, "modified": 2.0, "version": 1] as [String: Any],
            format: .xml, options: 0
        )
        #expect(AuthorizationDBManager.semanticallyEqual(desired, currentWithMeta))
        #expect(!AuthorizationDBManager.semanticallyEqual(desired, AuthorizationDBManager.definitionPlist(for: .requireAdmin)))
    }

    @Test("semantic diff detects mechanism/shared/timeout changes — an evaluate-mechanisms rewrite is not skipped")
    func semanticDiffDetectsMechanismChanges() {
        func plist(mechanisms: [String], shared: Bool, timeout: Int, extra: [String: Any] = [:]) -> Data {
            var dict: [String: Any] = [
                "class": "evaluate-mechanisms",
                "mechanisms": mechanisms,
                "shared": shared,
                "timeout": timeout,
            ]
            dict.merge(extra) { _, new in new }
            return try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        }
        let base = plist(mechanisms: ["builtin:authenticate", "builtin:authenticate,privileged"], shared: false, timeout: 0)

        // A mechanism-array change (e.g. inserting the Sentinel plugin ahead of
        // the native password mechanisms) must be detected, not compared equal.
        let mechanismAdded = plist(
            mechanisms: ["SerberusAuth:audit", "builtin:authenticate", "builtin:authenticate,privileged"],
            shared: false, timeout: 0)
        #expect(!AuthorizationDBManager.semanticallyEqual(base, mechanismAdded))

        // `shared`/`timeout` are decision-bearing for evaluate-mechanisms (a
        // shared cache or nonzero timeout lets authd skip re-running the chain).
        let sharedChanged = plist(mechanisms: ["builtin:authenticate", "builtin:authenticate,privileged"], shared: true, timeout: 0)
        #expect(!AuthorizationDBManager.semanticallyEqual(base, sharedChanged))
        let timeoutChanged = plist(mechanisms: ["builtin:authenticate", "builtin:authenticate,privileged"], shared: false, timeout: 60)
        #expect(!AuthorizationDBManager.semanticallyEqual(base, timeoutChanged))

        // Non-decision metadata (tries/comment/version) is still ignored, same as
        // the existing class/rule/group churn tolerance above.
        let metadataChurn = plist(
            mechanisms: ["builtin:authenticate", "builtin:authenticate,privileged"], shared: false, timeout: 0,
            extra: ["tries": 3, "comment": "Serberus authURI prompt rule", "version": 1])
        #expect(AuthorizationDBManager.semanticallyEqual(base, metadataChurn))
    }

    @Test("restoreAll is best-effort: one corrupt snapshot does not strand the others")
    func restoreBestEffort() async throws {
        let originalA = try! PropertyListSerialization.data(
            fromPropertyList: ["class": "user", "group": "admin"] as [String: Any], format: .xml, options: 0)
        let backend = MockAuthorizationDB(rights: ["a": originalA, "b": Data("orig-b".utf8)])
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        let mgr = AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil,
                                         daemonVersion: "1.0.0", now: { CoordinatorFixtures.now }, shippedDefinitions: { _ in nil })

        try await mgr.apply([
            .init(name: "a", definition: AuthorizationDBManager.definitionPlist(for: .deny)),
            .init(name: "b", definition: AuthorizationDBManager.definitionPlist(for: .deny)),
        ])

        // Tamper with b's snapshot (checksum will fail).
        let bFile = dir.appendingPathComponent("b.json")
        var json = try JSONSerialization.jsonObject(with: try Data(contentsOf: bFile)) as! [String: Any]
        json["originalDefinition"] = Data("tampered".utf8).base64EncodedString()
        try JSONSerialization.data(withJSONObject: json).write(to: bFile)

        let restored = try await mgr.restoreAll()
        #expect(Set(restored) == ["a", "b"])
        #expect(backend.current("a") == originalA)                       // intact → original
        // corrupt snapshot → conservative admin-auth reset (class=user, root-passable), not deny
        #expect(ruleClass(of: backend.current("b")!) == "user")
        #expect(boolValue(of: backend.current("b")!, "allow-root") == true)
    }

    @Test("desiredRights covers only authuri rights, sorted")
    func desiredRightsCoversAuthuriOnly() {
        let profiles = [
            profile("rules_authuri_a", 50, [authuriRule("system.preferences.datetime", .deny)]),
            profile("rules_sudo_x", 50, [
                Rule(id: "s", type: .sudo, action: .allow, description: "d", priority: 1,
                     match: MatchCriteria(commandPattern: "/bin/x", matchType: .exact)),
            ]),
            profile("rules_authuri_b", 50, [authuriRule("system.keychain-modify", .allow, .prompt)]),
        ]
        let desired = AuthorizationDBManager.desiredRights(in: profiles)
        #expect(desired.map(\.name) == ["system.keychain-modify", "system.preferences.datetime"])
    }

    @Test("conflicting rules for one right resolve to the most restrictive (deny wins)")
    func mostRestrictiveWins() {
        let profiles = [
            profile("rules_authuri_a", 50, [authuriRule("system.preferences.datetime", .allow, .silent)]),
            profile("rules_authuri_b", 10, [authuriRule("system.preferences.datetime", .deny)]),
            profile("rules_authuri_c", 90, [authuriRule("system.preferences.datetime", .allow, .prompt)]),
        ]
        let desired = AuthorizationDBManager.desiredRights(in: profiles)
        let def = try! #require(desired.first { $0.name == "system.preferences.datetime" }?.definition)
        #expect(ruleClass(of: def) == "deny")
    }

    @Test("applier snapshots the original and injects the mapped definition")
    func applierInjectsMappedDefinition() async throws {
        let original = try! PropertyListSerialization.data(
            fromPropertyList: ["class": "user", "group": "admin"] as [String: Any], format: .xml, options: 0
        )
        let backend = MockAuthorizationDB(rights: ["system.preferences.datetime": original])
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        let manager = AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil,
                                             daemonVersion: "1.0.0", now: { CoordinatorFixtures.now }, shippedDefinitions: { _ in nil })

        try await AuthorizationDBApplier(manager: manager)
            .apply(profiles: [profile("rules_authuri_a", 50, [authuriRule("system.preferences.datetime", .deny)])])

        #expect(ruleClass(of: backend.current("system.preferences.datetime")!) == "deny")
        #expect(store.hasSnapshot(rightName: "system.preferences.datetime"))
        // Original is recoverable.
        #expect(try store.load(rightName: "system.preferences.datetime").originalDefinition == original)
    }

    @Test("applier with no authuri rules writes nothing")
    func applierNoopForSudoOnly() async throws {
        let backend = MockAuthorizationDB(rights: ["system.preferences": Data("x".utf8)])
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AuthorizationDBManager(
            backend: backend, store: AuthorizationDBSnapshotStore(directory: dir),
            integrityLogger: nil, daemonVersion: "1.0.0", now: { CoordinatorFixtures.now },
            shippedDefinitions: { _ in nil }
        )
        try await AuthorizationDBApplier(manager: manager).apply(profiles: [
            profile("rules_sudo_x", 50, [
                Rule(id: "s", type: .sudo, action: .allow, description: "d", priority: 1,
                     match: MatchCriteria(commandPattern: "/bin/x", matchType: .exact)),
            ]),
        ])
        #expect(backend.writes.isEmpty)
    }
}

@Suite("UpgradeValidator — 7 criteria")
struct UpgradeValidatorTests {
    @Test("all criteria passing permits the upgrade")
    func allPass() {
        #expect(UpgradeValidator().mayProceed(.allPassing))
        #expect(UpgradeValidator().failures(.allPassing).isEmpty)
    }

    @Test("any single failing criterion blocks the upgrade")
    func eachBlocks() {
        let validator = UpgradeValidator()
        var facts = UpgradeValidator.Facts.allPassing
        let keyPaths: [WritableKeyPath<UpgradeValidator.Facts, Bool>] = [
            \.daemonBinaryPresentAndExecutable,
            \.daemonSignatureValid,
            \.pamModulePresentAndCorrectMode,
            \.pamSignatureValid,
            \.launchDaemonPlistParses,
            \.launchDaemonPlistHasRequiredKeys,
            \.authDBBackupsValid,
        ]
        for keyPath in keyPaths {
            facts = .allPassing
            facts[keyPath: keyPath] = false
            #expect(!validator.mayProceed(facts))
            #expect(validator.failures(facts).count == 1)
        }
    }

    @Test("a fresh (all-false) facts set lists all seven failures")
    func allFail() {
        #expect(UpgradeValidator().failures(UpgradeValidator.Facts()).count == 7)
    }
}

@Suite("AuthorizationDB rules apply only in enforce mode")
struct AuthorizationDBModeGateTests {
    private let profiles = [
        RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [])
    ]

    @Test("enforce applies the rules")
    func enforceApplies() {
        let applied = AuthorizationDBApplier.profilesToApply(profiles, mode: .enforce, awaitingConfig: false)
        #expect(applied.map(\.profileKey) == ["rules_authuri_a"])
    }

    @Test("monitor and audit leave every right native", arguments: [EnforcementMode.monitor, .audit])
    func nonEnforcingModesApplyNothing(mode: EnforcementMode) {
        #expect(AuthorizationDBApplier.profilesToApply(profiles, mode: mode, awaitingConfig: false).isEmpty)
    }

    @Test("awaiting config applies nothing, whatever the mode", arguments: EnforcementMode.allCases)
    func awaitingConfigAppliesNothing(mode: EnforcementMode) {
        #expect(AuthorizationDBApplier.profilesToApply(profiles, mode: mode, awaitingConfig: true).isEmpty)
    }
}

@Suite("Plain allow rules never open root-equivalent rights")
struct RootEquivalentRightTests {
    private func profile(_ rules: [Rule]) -> [RuleProfile] {
        [RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: rules)]
    }

    private func rule(_ right: String, _ action: RuleAction, app: AppIdentityBranch? = nil) -> Rule {
        Rule(id: "r-\(right)-\(action)", type: .authuri, action: action, description: "d", priority: 1,
             match: MatchCriteria(authURI: right), appIdentity: app)
    }

    @Test("an allow on a root-equivalent right is dropped and reported", arguments: [
        "system.privilege.admin", "system.privilege.taskport.debug",
        "com.apple.ServiceManagement.daemons.modify", "system.preferences.accounts",
        "com.apple.system-extensions.admin", "com.apple.trust-settings.admin", "system.keychain.modify",
        "system.services.directory.configure", "system.preferences.sharing",
        "system.identity.write.credential", "com.apple.tcc.util.admin",
        "com.apple.backgroundtaskmanagement.manage-daemons", "com.apple.system-migration.launch",
        "system.admin", "com.apple.configurationprofiles.install",
        "system.services.systemconfiguration.network", "sys.openfile.readwrite.x",
    ])
    func allowDropped(right: String) {
        let profiles = profile([rule(right, .allow)])
        #expect(AuthorizationDBManager.desiredRights(in: profiles).isEmpty)
        #expect(AuthorizationDBManager.skippedRootEquivalentAllows(profiles) == [right])
    }

    @Test("a deny on a root-equivalent right still applies")
    func denyStillApplies() {
        let desired = AuthorizationDBManager.desiredRights(in: profile([rule("system.privilege.admin", .deny)]))
        #expect(desired.map(\.name) == ["system.privilege.admin"])
    }

    @Test("an allow on an ordinary right still applies")
    func ordinaryAllowApplies() {
        let profiles = profile([rule("system.preferences.datetime", .allow)])
        #expect(AuthorizationDBManager.desiredRights(in: profiles).map(\.name) == ["system.preferences.datetime"])
        #expect(AuthorizationDBManager.skippedRootEquivalentAllows(profiles).isEmpty)
    }

    @Test("one verified app can still be allowed an identity-scoped ServiceManagement right")
    func identityScopedStillComposes() {
        let app = AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer")
        let profiles = profile([rule("com.apple.ServiceManagement.daemons.modify", .allow, app: app)])
        // Composition machinery (per-app pins are disabled in production).
        #expect(AuthorizationDBManager.desiredCompositions(in: profiles, perAppPinsEnabled: true).map(\.right)
                == ["com.apple.ServiceManagement.daemons.modify"])
        #expect(AuthorizationDBManager.skippedRootEquivalentAllows(profiles).isEmpty)
    }
}

@Suite("Rule targets and deny targets the AuthorizationDB layer refuses")
struct AuthRightTargetGateTests {
    private func profile(_ rules: [Rule]) -> [RuleProfile] {
        [RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: rules)]
    }

    private func rule(_ right: String, _ action: RuleAction, app: AppIdentityBranch? = nil) -> Rule {
        Rule(id: "r-\(right)-\(action)", type: .authuri, action: action, description: "d", priority: 1,
             match: MatchCriteria(authURI: right), appIdentity: app)
    }

    @Test("the bare system.preferences right stays openable (it is not a wildcard); guarded children stay guarded")
    func systemPreferencesIsOpenable() {
        #expect(!AuthorizationDBManager.isRootEquivalent("system.preferences"))
        #expect(!AuthorizationDBManager.isRootEquivalent("system.preferences.datetime"))
        #expect(AuthorizationDBManager.isRootEquivalent("system.preferences.accounts"))
        #expect(AuthorizationDBManager.isRootEquivalent("system.preferences.sharing"))
        let open = profile([rule("system.preferences", .allow), rule("system.preferences.datetime", .allow)])
        #expect(Set(AuthorizationDBManager.desiredRights(in: open).map(\.name))
                == ["system.preferences", "system.preferences.datetime"])
    }

    @Test("rule-class names and trailing-dot wildcards are never targets", arguments: [
        "is-root", "is-admin", "entitled", "default", "authenticate-admin-nonshared", "use-login-window-ui",
        "system.privilege.", "system.preferences.", "sys.openfile.",
    ])
    func targetsRefused(right: String) {
        for action in RuleAction.allCases {
            let profiles = profile([rule(right, action)])
            #expect(AuthorizationDBManager.desiredRights(in: profiles).isEmpty, "\(right) \(action)")
            #expect(AuthorizationDBManager.skippedRules(profiles).map(\.right) == [right])
        }
    }

    @Test("a deny on a login/unlock right is refused; other actions are unaffected by that check", arguments: [
        "system.disk.unlock", "system.platformsso.login", "system.platformsso.register",
    ])
    func denyForbidden(right: String) {
        let profiles = profile([rule(right, .deny)])
        #expect(AuthorizationDBManager.desiredRights(in: profiles).isEmpty)
        #expect(AuthorizationDBManager.skippedRules(profiles).first?.reason.contains("lock users out") == true)
        #expect(AuthRightTargetPolicy.denyRejectionReason("system.login.screensaver") != nil)
        // `use-login-window-ui` is a RULE (no dot): refused for every action by the target gate.
        #expect(AuthRightTargetPolicy.targetRejectionReason("use-login-window-ui") != nil)
        #expect(AuthRightTargetPolicy.denyRejectionReason("system.preferences.datetime") == nil)
    }

    @Test("an identity-scoped DENY is never composed (it would be enforced as an allow) and is logged")
    func identityDenyDropped() {
        let app = AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer")
        let profiles = profile([rule("com.apple.ServiceManagement.daemons.modify", .deny, app: app)])
        #expect(AuthorizationDBManager.desiredCompositions(in: profiles).isEmpty)
        #expect(AuthorizationDBManager.desiredRights(in: profiles).isEmpty)
        #expect(AuthorizationDBManager.skippedByProjection(profiles).isEmpty)
        let skipped = AuthorizationDBManager.skippedRules(profiles)
        #expect(skipped.count == 1)
        #expect(skipped.first?.reason.contains("must be an allow rule") == true)
    }

    @Test("every skipped rule is reported: protected and root-equivalent allows included")
    func skippedRulesCoversEveryReason() {
        let profiles = profile([
            rule("system.login.console", .allow),
            rule("system.privilege.admin", .allow),
            rule("system.preferences.datetime", .allow),   // enforced: not reported
        ])
        #expect(Set(AuthorizationDBManager.skippedRules(profiles).map(\.right))
                == ["system.login.console", "system.privilege.admin"])
    }
}

@Suite("Serberus-written definitions are never snapshotted as the original", .serialized)
struct AuthorizationDBMarkerTests {
    private func plist(_ dict: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    private func dict(_ data: Data?) -> [String: Any] {
        guard let data else { return [:] }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] ?? [:]
    }

    private func manager(_ backend: MockAuthorizationDB, _ store: AuthorizationDBSnapshotStore) -> AuthorizationDBManager {
        AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil,
                               daemonVersion: "1.0.0", now: { CoordinatorFixtures.now }, shippedDefinitions: { _ in nil })
    }

    @Test("every projection carries the marker in its comment; the admin-auth stand-in does not")
    func projectionsCarryMarker() {
        for policy in [AuthorizationDBManager.AuthURIPolicy.deny, .requireSessionOwnerOrAdmin] {
            #expect(AuthorizationDBManager.carriesManagedMarker(AuthorizationDBManager.definitionPlist(for: policy)))
        }
        #expect(!AuthorizationDBManager.carriesManagedMarker(AuthorizationDBManager.definitionPlist(for: .requireAdmin)))
        #expect(!AuthorizationDBManager.carriesManagedMarker(plist(["class": "rule", "rule": ["authenticate-admin"], "comment": "native"])))
    }

    @Test("a lost snapshot: the live Serberus rewrite is NOT adopted as the original; restore resets to admin-auth, never deny")
    func lostSnapshotIsNotReadopted() async throws {
        let right = "system.preferences.datetime"
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        // The right already holds Serberus's deny projection, and there is
        // no snapshot (the store was lost).
        let backend = MockAuthorizationDB(rights: [right: AuthorizationDBManager.definitionPlist(for: .deny)])
        let mgr = manager(backend, store)

        let result = try await mgr.apply([.init(name: right, definition: AuthorizationDBManager.definitionPlist(for: .deny))])
        #expect(result.originalUnrecoverable == [right])
        #expect(result.snapshotted.isEmpty)
        #expect(!store.hasSnapshot(rightName: right))
        // Still controlled, so a drop/uninstall finds it…
        #expect(mgr.controlledRightNames() == [right])

        // …and restoring falls back to the admin-auth reset, never the deny.
        _ = try await mgr.restoreAll()
        let restored = dict(backend.current(right))
        #expect(restored["class"] as? String == "user")
        #expect(restored["group"] as? String == "admin")
        #expect(mgr.controlledRightNames().isEmpty)
    }

    @Test("the unrecoverable state is stable across re-applies (no snapshot is ever taken of the rewrite)")
    func lostSnapshotStableAcrossApplies() async throws {
        let right = "system.preferences.printing"
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        let backend = MockAuthorizationDB(rights: [right: AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)])
        let mgr = manager(backend, store)
        let desired = [AuthorizationDBManager.DesiredRight(name: right, definition: AuthorizationDBManager.definitionPlist(for: .deny))]
        _ = try await mgr.apply(desired)
        _ = try await mgr.apply(desired)
        #expect(!store.hasSnapshot(rightName: right))
        #expect(dict(backend.current(right))["class"] as? String == "deny")
    }

    @Test("a native definition is still snapshotted on first touch, and a pre-marker projection gains the marker")
    func nativeStillSnapshotted() async throws {
        let right = "system.preferences.datetime"
        let native = plist(["class": "rule", "rule": ["authenticate-admin-nonshared"], "comment": "native"])
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        let backend = MockAuthorizationDB(rights: [right: native])
        let mgr = manager(backend, store)
        let result = try await mgr.apply([.init(name: right, definition: AuthorizationDBManager.definitionPlist(for: .deny))])
        #expect(result.snapshotted == [right])
        #expect(try store.load(rightName: right).originalDefinition == native)

        // A deny written by an older daemon (no marker) is re-written once to
        // carry it, then left alone.
        let other = "system.preferences.printing"
        backend.seed(other, plist(["class": "deny"]))
        try store.save(AuthorizationDBSnapshot(rightName: other, originalDefinition: native,
                                               timestamp: CoordinatorFixtures.now, daemonVersion: "0.9"))
        let upgraded = try await mgr.apply([.init(name: other, definition: AuthorizationDBManager.definitionPlist(for: .deny))])
        #expect(upgraded.modified == [other])
        #expect(AuthorizationDBManager.carriesManagedMarker(backend.current(other)!))
        let steady = try await mgr.apply([.init(name: other, definition: AuthorizationDBManager.definitionPlist(for: .deny))])
        #expect(steady.unchanged == [other])
    }
}
