import Foundation
import SQLite3
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// The identity-scoped composer: a right becomes `k-of-n: 1` over
/// `[app branches…, native-default]`, never rewritten in place. Uses the
/// in-memory `MockAuthorizationDB` from `AuthorizationDBTests.swift`.
@Suite("AuthorizationDBManager — identity-scoped composition", .serialized)
struct AuthorizationDBCompositionTests {
    static let right = "com.apple.ServiceManagement.daemons.modify"
    static let bless = "com.apple.ServiceManagement.blesshelper"
    static let testSerial = "SYNTHSER01"
    static let postman = AppIdentityBranch(teamID: "H7H8Q7M5CK", bundleID: "com.postmanlabs.mac")
    static let composer = AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer")
    static let third = AppIdentityBranch(teamID: "ABCDEFGHIJ", bundleID: "com.example.third")

    private func native(_ rule: String = "authenticate-admin-nonshared") -> Data {
        try! PropertyListSerialization.data(
            fromPropertyList: ["class": "rule", "rule": [rule], "comment": "native", "version": 0] as [String: Any],
            format: .xml, options: 0)
    }

    private func dict(_ data: Data?) -> [String: Any] {
        guard let data else { return [:] }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] ?? [:]
    }

    private func tempStore() throws -> (AuthorizationDBSnapshotStore, URL) {
        let dir = try CoordinatorFixtures.tempDirectory()
        return (AuthorizationDBSnapshotStore(directory: dir), dir)
    }

    private func manager(_ backend: AuthorizationDBBackend, _ store: AuthorizationDBSnapshotStore,
                         osMajor: Int = 27,
                         registry: AuthURIIdentityScopeRegistry = .current,
                         sessionOwnerOnly: Bool = false,
                         plugin: AuthPluginInstallStatus = .installed,
                         shipped: [String: Data] = [:]) -> AuthorizationDBManager {
        // Pinned, never read from this Mac's real config profile or its real
        // /Library/Security/SecurityAgentPlugins.
        AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil, daemonVersion: "1.0.0",
                               now: { CoordinatorFixtures.now }, scopeRegistry: registry, osMajor: osMajor,
                               sessionOwnerOnly: { sessionOwnerOnly },
                               authPluginVerifier: StubPluginVerifier(status: plugin),
                               shippedDefinitions: { shipped[$0] })
    }

    /// No SHIPPED right is provisional any more, so the "composes anyway, just
    /// warns" behaviour is driven from a synthetic table.
    private var provisionalRegistry: AuthURIIdentityScopeRegistry {
        AuthURIIdentityScopeRegistry(entries: [
            AuthURIIdentityScopeEntry(match: .exact(Self.bless), state: .provisional, verifiedMacOSMajors: nil,
                                      allowedSerials: [Self.testSerial], notes: "under test"),
        ])
    }

    private func profile(_ branches: [AppIdentityBranch], right: String = AuthorizationDBCompositionTests.right,
                         plain: RuleAction? = nil, key: String = "rules_authuri_a") -> RuleProfile {
        var rules = branches.enumerated().map { index, branch in
            Rule(id: "app\(index)", type: .authuri, action: .allow, description: "", priority: 50,
                 match: MatchCriteria(authURI: right), appIdentity: branch)
        }
        if let plain {
            rules.append(Rule(id: "plain", type: .authuri, action: plain, description: "", priority: 50,
                              match: MatchCriteria(authURI: right)))
        }
        return RuleProfile(policyVersion: "1.0.0", profileKey: key, profilePriority: 50, rules: rules)
    }

    private func composition(_ branches: [AppIdentityBranch], right: String = AuthorizationDBCompositionTests.right) -> AuthorizationDBManager.DesiredComposition {
        AuthorizationDBManager.DesiredComposition(right: right, branches: branches)
    }

    // MARK: Composer

    @Test("first touch: native definition snapshotted and preserved as the fallback row; one row per app; top-level k-of-n 1 with apps first, native last")
    func composesRight() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let mgr = manager(backend, store)

        let result = try await mgr.apply([], compositions: [composition([Self.postman, Self.composer])])
        #expect(result.composed == [Self.right])
        #expect(result.snapshotted == [Self.right])
        #expect(result.compositionRejected.isEmpty)

        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: Self.right)
        let postmanRow = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)
        let composerRow = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.composer)

        // Native default captured LIVE (the mock's definition), not hardcoded.
        #expect(dict(backend.current(nativeRow))["rule"] as? [String] == ["authenticate-admin-nonshared"])
        #expect(try store.load(rightName: Self.right).originalDefinition == original)

        // Each app is THREE rows: identity (mechanism), auth (credential
        // cache), and a k-of-n 2 composite requiring both. One rule cannot do
        // both jobs — only evaluate-mechanisms runs a mechanism, and only
        // class=user credential-caches.
        let postmanIdentity = AuthURICompositionNaming.appIdentityRow(for: Self.right, branch: Self.postman)
        let postmanAuth = AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.postman)

        let composite = dict(backend.current(postmanRow))
        #expect(composite["class"] as? String == "rule")
        #expect(composite["k-of-n"] as? Int == 2)   // AND: identity AND authentication
        #expect(composite["rule"] as? [String] == [postmanIdentity, postmanAuth])

        let identity = dict(backend.current(postmanIdentity))
        #expect(identity["class"] as? String == "evaluate-mechanisms")
        #expect(identity["mechanisms"] as? [String] == [AppIdentityBranch.mechanismName])
        #expect(identity["requirement"] == nil)   // authd has no such key; the plugin enforces it
        #expect((identity["comment"] as? String)?.contains("com.postmanlabs.mac") == true)

        let auth = dict(backend.current(postmanAuth))
        #expect(auth["class"] as? String == "user")
        #expect(auth["session-owner"] as? Bool == true)
        #expect(auth["group"] as? String == "admin")   // default: session-owner-OR-admin
        #expect(auth["allow-root"] as? Bool == true)
        // A SHARED credential would go in the global pool where any caller can
        // satisfy from it; the timeout scopes reuse to one authorization,
        // which is what collapses an install's three evaluations into one prompt.
        #expect(auth["shared"] as? Bool == false)
        #expect(auth["timeout"] as? Int == AppIdentityBranch.credentialTimeoutSeconds)

        #expect(dict(backend.current(composerRow))["class"] as? String == "rule")

        // Top level: pure OR, apps first (sorted by slug), native LAST.
        let top = dict(backend.current(Self.right))
        #expect(top["class"] as? String == "rule")
        #expect(top["k-of-n"] as? Int == 1)
        #expect(top["rule"] as? [String] == [composerRow, postmanRow, nativeRow])
        // Every row the composition owns: the native fallback plus, per app,
        // the composite and its two halves.
        #expect(Set(store.ownedRows(rightName: Self.right)) == [
            nativeRow,
            postmanRow, postmanIdentity, postmanAuth,
            composerRow,
            AuthURICompositionNaming.appIdentityRow(for: Self.right, branch: Self.composer),
            AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.composer),
        ])
    }

    @Test("steady state: re-applying the same composition writes nothing")
    func idempotent() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let mgr = manager(backend, store)
        try await mgr.apply([], compositions: [composition([Self.postman])])
        let writes = backend.writes.count
        let again = try await mgr.apply([], compositions: [composition([Self.postman])])
        #expect(backend.writes.count == writes)
        #expect(again.branchRowsWritten.isEmpty)
        #expect(again.unchanged.contains(Self.right))
        #expect(again.composed == [Self.right])
    }

    @Test("N apps: adding a third app touches only its row and the top-level array")
    func addApp() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let mgr = manager(backend, store)
        try await mgr.apply([], compositions: [composition([Self.postman, Self.composer])])
        let postmanRow = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)
        let postmanBefore = backend.current(postmanRow)
        let writesBefore = backend.writes.count

        let result = try await mgr.apply([], compositions: [composition([Self.postman, Self.composer, Self.third])])
        let thirdRow = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.third)
        // The new app's three rows, and nothing belonging to the other two.
        #expect(Set(result.branchRowsWritten) == [
            thirdRow,
            AuthURICompositionNaming.appIdentityRow(for: Self.right, branch: Self.third),
            AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.third),
        ])
        #expect(backend.writes.count == writesBefore + 4)   // three new rows + the top-level array
        #expect(backend.current(postmanRow) == postmanBefore)
        // Only the COMPOSITE is referenced by the right itself.
        #expect((dict(backend.current(Self.right))["rule"] as? [String])?.contains(thirdRow) == true)
    }

    @Test("reconcile retires exactly the removed app's row and drops it from the array; every other branch untouched")
    func retireApp() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let applier = AuthorizationDBApplier(manager: manager(backend, store), perAppPinsEnabled: true)
        try await applier.apply(profiles: [profile([Self.postman, Self.composer])])

        let postmanRow = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)
        let composerRow = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.composer)
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: Self.right)
        let composerBefore = backend.current(composerRow)
        let nativeBefore = backend.current(nativeRow)

        try await applier.reconcile(profiles: [profile([Self.composer])])

        #expect(backend.current(postmanRow) == nil)                          // exactly that app's rows deleted
        #expect(Set(backend.removes) == [
            postmanRow,
            AuthURICompositionNaming.appIdentityRow(for: Self.right, branch: Self.postman),
            AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.postman),
        ])
        #expect(backend.current(composerRow) == composerBefore)               // other app untouched
        #expect(backend.current(nativeRow) == nativeBefore)                   // native-default untouched
        #expect(dict(backend.current(Self.right))["rule"] as? [String] == [composerRow, nativeRow])
        #expect(Set(store.ownedRows(rightName: Self.right)) == [
            composerRow,
            AuthURICompositionNaming.appIdentityRow(for: Self.right, branch: Self.composer),
            AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.composer),
            nativeRow,
        ])
        #expect(try store.load(rightName: Self.right).originalDefinition == original)   // snapshot preserved
    }

    @Test("retiring the LAST app restores the native definition and sweeps every owned row")
    func retireLastApp() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let applier = AuthorizationDBApplier(manager: manager(backend, store), perAppPinsEnabled: true)
        try await applier.apply(profiles: [profile([Self.postman])])
        try await applier.reconcile(profiles: [])

        #expect(backend.current(Self.right) == original)
        #expect(backend.current(AuthURICompositionNaming.nativeDefaultRow(for: Self.right)) == nil)
        #expect(backend.current(AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)) == nil)
        #expect(!store.hasSnapshot(rightName: Self.right))
        #expect(store.ownedRows(rightName: Self.right).isEmpty)
        #expect(store.rightsWithOwnedRows().isEmpty)
    }

    @Test("restoreAll (uninstall) puts the native definition back and removes the owned rows")
    func restoreAllSweeps() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let mgr = manager(backend, store)
        try await mgr.apply([], compositions: [composition([Self.postman, Self.composer])])
        #expect(mgr.controlledRightNames() == [Self.right])

        let restored = try await mgr.restoreAll()
        #expect(restored == [Self.right])
        #expect(backend.current(Self.right) == original)
        for row in [AuthURICompositionNaming.nativeDefaultRow(for: Self.right),
                    AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman),
                    AuthURICompositionNaming.appRow(for: Self.right, branch: Self.composer)] {
            #expect(backend.current(row) == nil)
        }
        #expect(mgr.controlledRightNames().isEmpty)
    }

    @Test("a lost snapshot still restores: the preserved native-default row is the fallback source")
    func restoreFromPreservedRow() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let mgr = manager(backend, store)
        try await mgr.apply([], compositions: [composition([Self.postman])])

        // Corrupt the snapshot file (sidecar stays).
        try Data("garbage".utf8).write(to: dir.appendingPathComponent("\(Self.right).json"))
        #expect(mgr.controlledRightNames() == [Self.right])

        _ = try await mgr.restoreAll()
        #expect(backend.current(Self.right) == original)   // NOT the admin reset — the preserved row
        #expect(backend.current(AuthURICompositionNaming.nativeDefaultRow(for: Self.right)) == nil)
    }

    @Test("a row macOS refuses to remove is neutralized to deny, never left able to grant")
    func unremovableRowNeutralized() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let applier = AuthorizationDBApplier(manager: manager(backend, store), perAppPinsEnabled: true)
        try await applier.apply(profiles: [profile([Self.postman, Self.composer])])
        backend.failRemoves = true
        try await applier.reconcile(profiles: [profile([Self.composer])])
        let postmanRow = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)
        #expect(dict(backend.current(postmanRow))["class"] as? String == "deny")
        #expect(!(dict(backend.current(Self.right))["rule"] as? [String] ?? []).contains(postmanRow))
    }

    // MARK: Drift validation

    @Test("drift: an admin flipping k-of-n away from 1 (or dropping it) is detected, logged, and repaired")
    func driftRepair() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let mgr = manager(backend, store)
        try await mgr.apply([], compositions: [composition([Self.postman, Self.composer])])
        var top = dict(backend.current(Self.right))

        // k-of-n: 2 → both branches must pass → an app that matches its own
        // branch still has to satisfy the admin gate: a silent lockout.
        top["k-of-n"] = 2
        try backend.setDefinition(try PropertyListSerialization.data(fromPropertyList: top, format: .xml, options: 0), for: Self.right)
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: Self.right)
        #expect(AuthorizationDBManager.compositionDrift(in: backend.current(Self.right)!, nativeRow: nativeRow)?.contains("k-of-n is 2") == true)

        let repaired = try await mgr.apply([], compositions: [composition([Self.postman, Self.composer])])
        #expect(repaired.compositionDriftRepaired == [Self.right])
        #expect(dict(backend.current(Self.right))["k-of-n"] as? Int == 1)

        // Missing k-of-n entirely = AND of every branch.
        top.removeValue(forKey: "k-of-n")
        try backend.setDefinition(try PropertyListSerialization.data(fromPropertyList: top, format: .xml, options: 0), for: Self.right)
        #expect(AuthorizationDBManager.compositionDrift(in: backend.current(Self.right)!, nativeRow: nativeRow)?.contains("missing") == true)
        let repairedAgain = try await mgr.apply([], compositions: [composition([Self.postman, Self.composer])])
        #expect(repairedAgain.compositionDriftRepaired == [Self.right])
        #expect(dict(backend.current(Self.right))["k-of-n"] as? Int == 1)

        // Native-default dropped from the array.
        top["k-of-n"] = 1
        top["rule"] = [AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)]
        try backend.setDefinition(try PropertyListSerialization.data(fromPropertyList: top, format: .xml, options: 0), for: Self.right)
        #expect(AuthorizationDBManager.compositionDrift(in: backend.current(Self.right)!, nativeRow: nativeRow)?.contains("native-default") == true)
        let repairedNative = try await mgr.apply([], compositions: [composition([Self.postman, Self.composer])])
        #expect(repairedNative.compositionDriftRepaired == [Self.right])
        #expect((dict(backend.current(Self.right))["rule"] as? [String])?.last == nativeRow)

        // A plain native definition is not drift.
        #expect(AuthorizationDBManager.compositionDrift(in: native(), nativeRow: nativeRow) == nil)
    }

    @Test("enableBiometrics drops the admin clause so only the session owner can satisfy the auth half")
    func biometricsFlagNarrowsThePrincipal() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        _ = try await manager(backend, store, sessionOwnerOnly: true)
            .apply([], compositions: [composition([Self.postman])])

        let auth = dict(backend.current(AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.postman)))
        // macOS offers Touch ID only when the CURRENT user alone can satisfy
        // the rule; an admin clause forces the name-and-password form.
        #expect(auth["session-owner"] as? Bool == true)
        #expect(auth["group"] == nil)
        #expect(auth["timeout"] as? Int == AppIdentityBranch.credentialTimeoutSeconds)
        #expect((auth["comment"] as? String)?.contains("authenticate-session-owner,") == true)

        // Everything else about the composition is unchanged.
        #expect(dict(backend.current(Self.right))["k-of-n"] as? Int == 1)
        #expect(dict(backend.current(AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)))["k-of-n"] as? Int == 2)
    }

    @Test("flipping the flag rewrites the auth half in place, leaving identity and native untouched")
    func biometricsFlagIsLiveNotStored() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let identityRow = AuthURICompositionNaming.appIdentityRow(for: Self.right, branch: Self.postman)
        let authRow = AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.postman)

        _ = try await manager(backend, store, sessionOwnerOnly: false).apply([], compositions: [composition([Self.postman])])
        #expect(dict(backend.current(authRow))["group"] as? String == "admin")
        let identityBefore = backend.current(identityRow)
        let nativeBefore = backend.current(AuthURICompositionNaming.nativeDefaultRow(for: Self.right))

        // An MDM push flips the key; the next compose must follow it.
        let result = try await manager(backend, store, sessionOwnerOnly: true).apply([], compositions: [composition([Self.postman])])
        #expect(dict(backend.current(authRow))["group"] == nil)
        #expect(result.branchRowsWritten == [authRow])          // ONLY the auth half rewritten
        #expect(backend.current(identityRow) == identityBefore)
        #expect(backend.current(AuthURICompositionNaming.nativeDefaultRow(for: Self.right)) == nativeBefore)
    }

    // MARK: Verification table (advisory)

    @Test("unknown and ineligible rights are composed as authored, with a verification warning")
    func unverifiedRightsStillCompose() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [
            "system.preferences.datetime": native(),
            "system.install.software": native(),
        ])
        let result = try await manager(backend, store).apply([], compositions: [
            composition([Self.postman], right: "system.preferences.datetime"),
            composition([Self.postman], right: "system.install.software"),
        ])
        #expect(result.composed == ["system.install.software", "system.preferences.datetime"])
        #expect(result.compositionRejected.isEmpty)
        #expect(result.verificationWarnings["system.preferences.datetime"]?.contains("not been verified") == true)
        #expect(result.verificationWarnings["system.install.software"]?.contains("confirmed ineligible") == true)
        #expect(dict(backend.current("system.preferences.datetime"))["k-of-n"] as? Int == 1)
    }

    @Test("a provisional right composes on ANY Mac (no serial gate) and is flagged as under test")
    func provisionalComposesEverywhere() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.bless: native()])
        let result = try await manager(backend, store, registry: provisionalRegistry)
            .apply([], compositions: [composition([Self.composer], right: Self.bless)])
        #expect(result.composed == [Self.bless])
        #expect(result.verificationWarnings[Self.bless] == AuthURIIdentityEligibility.provisional.label)
        #expect(dict(backend.current(Self.bless))["k-of-n"] as? Int == 1)
    }

    @Test("a newer-than-verified macOS is warned loudly but still composes")
    func osVersionWarning() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let result = try await manager(backend, store, osMajor: 28).apply([], compositions: [composition([Self.postman])])
        #expect(result.osVersionWarnings[Self.right]?.contains("macOS 28") == true)
        #expect(result.composed == [Self.right])
    }

    // MARK: Requirement compiler gate

    @Test("an invalid pin skips that branch only; nothing about it is written; the rest compose")
    func invalidRequirementSkipsBranch() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let bad = AppIdentityBranch(teamID: "bad", bundleID: "com.example.bad")
        let result = try await manager(backend, store).apply([], compositions: [composition([Self.postman, bad])])
        let badRow = AuthURICompositionNaming.appRow(for: Self.right, branch: bad)
        #expect(result.branchesRejected["\(Self.right)|\(badRow)"]?.contains("Team ID") == true)
        #expect(backend.current(badRow) == nil)
        #expect(result.composed == [Self.right])
        #expect((dict(backend.current(Self.right))["rule"] as? [String])?.contains(badRow) == false)
    }

    @Test("a right with no valid branch is left uncomposed")
    func noValidBranch() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let bad = AppIdentityBranch(teamID: "bad", bundleID: "com.example.bad")
        let result = try await manager(backend, store).apply([], compositions: [composition([bad])])
        #expect(result.composed.isEmpty)
        #expect(backend.current(Self.right) == original)
        #expect(backend.writes.isEmpty)
    }

    // MARK: Discovery / precedence

    @Test("desiredCompositions groups branches per right, dedupes pins, and yields to a plain projection")
    func discovery() {
        let profiles = [
            profile([Self.postman], key: "rules_authuri_a"),
            profile([Self.postman, Self.composer], key: "rules_authuri_b"),
        ]
        let compositions = AuthorizationDBManager.desiredCompositions(in: profiles, perAppPinsEnabled: true)
        #expect(compositions.count == 1)
        #expect(compositions.first?.branches.count == 2)
        // Plain projections skip identity-scoped rules entirely.
        #expect(AuthorizationDBManager.desiredRights(in: profiles).isEmpty)

        let mixed = [profile([Self.postman], plain: .deny)]
        #expect(AuthorizationDBManager.desiredCompositions(in: mixed, perAppPinsEnabled: true).isEmpty)
        #expect(AuthorizationDBManager.desiredRights(in: mixed).map(\.name) == [Self.right])
        #expect(AuthorizationDBManager.skippedByProjection(mixed, perAppPinsEnabled: true) == [Self.right])
    }

    @Test("a composed right later covered by a plain deny is projected and its rows swept")
    func projectionReplacesComposition() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let applier = AuthorizationDBApplier(manager: manager(backend, store), perAppPinsEnabled: true)
        try await applier.apply(profiles: [profile([Self.postman])])
        try await applier.reconcile(profiles: [profile([Self.postman], plain: .deny)])
        #expect(dict(backend.current(Self.right))["class"] as? String == "deny")
        #expect(backend.current(AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)) == nil)
        #expect(store.ownedRows(rightName: Self.right).isEmpty)
    }

    @Test("a right that does not exist is never composed (nothing to preserve)")
    func missingRightNotComposed() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [:])
        let result = try await manager(backend, store).apply([], compositions: [composition([Self.postman])])
        #expect(result.skippedMissing == [Self.right])
        #expect(backend.writes.isEmpty)
    }

    @Test("the semantic diff sees k-of-n and principal flags, not authd's creator requirement stamp")
    func semanticDiffCoversComposition() {
        func plist(_ d: [String: Any]) -> Data { try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) }
        let a = plist(["class": "rule", "k-of-n": 1, "rule": ["x"]])
        let b = plist(["class": "rule", "k-of-n": 2, "rule": ["x"]])
        #expect(!AuthorizationDBManager.semanticallyEqual(a, b))
        let c = plist(["class": "user", "requirement": "identifier \"a\"", "session-owner": true])
        let d = plist(["class": "user", "requirement": "identifier \"b\"", "session-owner": true])
        let e = plist(["class": "user", "requirement": "identifier \"a\"", "session-owner": false])
        // authd does not decide with `requirement`; macOS 26 stamps the writer's.
        #expect(AuthorizationDBManager.semanticallyEqual(c, d))
        #expect(AuthorizationDBManager.semanticallyEqual(c, plist(["class": "user", "session-owner": true])))
        #expect(!AuthorizationDBManager.semanticallyEqual(c, e))
        // The digest still covers it, so a planted row must match it too.
        #expect(AuthorizationDBManager.canonicalDigest(c) != AuthorizationDBManager.canonicalDigest(d))
        #expect(AuthorizationDBManager.semanticallyEqual(c, plist(["class": "user", "requirement": "identifier \"a\"", "session-owner": true, "comment": "meta", "created": 1.0])))
    }

    // MARK: Plugin install check

    @Test("plugin missing: nothing is composed, the right stays native, and the problem is surfaced")
    func pluginMissingLeavesRightNative() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let mgr = manager(backend, store, plugin: .unavailable(reason: "not installed"))

        let result = try await mgr.apply([], compositions: [composition([Self.postman])])
        #expect(result.authPluginUnavailable == "not installed")
        #expect(result.compositionSkippedPluginUnavailable == [Self.right])
        #expect(result.composed.isEmpty)
        #expect(backend.writes.isEmpty)
        #expect(backend.current(Self.right) == original)
        #expect(mgr.authPluginStatus() == .unavailable(reason: "not installed"))
    }

    @Test("plugin removed after composing: the right is put back to native and its rows swept")
    func pluginRemovedRestoresComposedRight() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        _ = try await manager(backend, store).apply([], compositions: [composition([Self.postman])])
        #expect(backend.current(Self.right) != original)

        let gone = manager(backend, store, plugin: .unavailable(reason: "bundle not root-owned"))
        let result = try await gone.apply([], compositions: [composition([Self.postman])])
        #expect(result.compositionSkippedPluginUnavailable == [Self.right])
        #expect(backend.current(Self.right) == original)
        #expect(backend.current(AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)) == nil)
        #expect(gone.controlledRightNames().isEmpty)
    }

    @Test("the production verifier refuses a missing bundle and a non-root-owned directory")
    func systemVerifierRefusesUntrustedBundles() throws {
        let missing = SystemAuthPluginBundleVerifier(bundlePath: "/nonexistent/SerberusAuth.bundle", teamID: "")
        guard case .unavailable = missing.verify() else { Issue.record("missing bundle accepted"); return }

        // A directory the test user owns stands in for a planted bundle.
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let planted = SystemAuthPluginBundleVerifier(bundlePath: dir.path, teamID: "")
        guard case let .unavailable(reason) = planted.verify() else { Issue.record("user-owned bundle accepted"); return }
        #expect(reason.contains("not root"))

        #expect(SystemAuthPluginBundleVerifier.requirement(teamID: "ABCDE12345")?
            .contains("identifier \"\(SystemAuthPluginBundleVerifier.bundleIdentifier)\"") == true)
        #expect(SystemAuthPluginBundleVerifier.requirement(teamID: "") == nil)
    }

    // MARK: Lost snapshot

    @Test("a lost snapshot on a composed right whose native row is also gone: reset to admin-auth, never composed around the rewrite")
    func lostSnapshotAndNativeRow() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let mgr = manager(backend, store)
        _ = try await mgr.apply([], compositions: [composition([Self.postman])])

        // Lose the snapshot, the sidecar, and the native-default row.
        try FileManager.default.removeItem(at: dir.appendingPathComponent("\(Self.right).json"))
        try store.removeOwnedRows(rightName: Self.right)
        try backend.removeRight(AuthURICompositionNaming.nativeDefaultRow(for: Self.right))

        let result = try await mgr.apply([], compositions: [composition([Self.postman])])
        #expect(result.originalUnrecoverable == [Self.right])
        #expect(result.compositionRejected[Self.right] != nil)
        #expect(!store.hasSnapshot(rightName: Self.right))
        let top = dict(backend.current(Self.right))
        #expect(top["class"] as? String == "user")      // admin-auth reset
        #expect(top["group"] as? String == "admin")
        #expect(backend.current(AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)) == nil)
        #expect(mgr.controlledRightNames() == [Self.right])
    }

    @Test("an identity-scoped deny is never composed")
    func identityDenyNotComposed() {
        let denyPin = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
            Rule(id: "deny-pin", type: .authuri, action: .deny, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.right), appIdentity: Self.postman),
        ])
        #expect(AuthorizationDBManager.desiredCompositions(in: [denyPin], perAppPinsEnabled: true).isEmpty)
        #expect(AuthorizationDBManager.desiredRights(in: [denyPin]).isEmpty)
    }
}

/// Fixed-outcome plugin install check.
struct StubPluginVerifier: AuthPluginBundleVerifying {
    let status: AuthPluginInstallStatus
    func verify() -> AuthPluginInstallStatus { status }
}

/// A plugin verifier whose verdict and fingerprint the test flips, counting
/// full verifications (to prove the fingerprint cache).
final class SwitchablePluginVerifier: AuthPluginBundleVerifying, @unchecked Sendable {
    private let lock = NSLock()
    private var _status: AuthPluginInstallStatus
    private var _fingerprint: String?
    private(set) var verifyCount = 0

    init(status: AuthPluginInstallStatus, fingerprint: String? = "fp-1") {
        _status = status
        _fingerprint = fingerprint
    }

    func set(_ status: AuthPluginInstallStatus, fingerprint: String?) {
        lock.lock(); defer { lock.unlock() }
        _status = status
        _fingerprint = fingerprint
    }

    func verify() -> AuthPluginInstallStatus {
        lock.lock(); defer { lock.unlock() }
        verifyCount += 1
        return _status
    }

    func fingerprint() -> String? {
        lock.lock(); defer { lock.unlock() }
        return _fingerprint
    }
}

/// Review fixes: forged native-default rows, the live-database restore sweep,
/// plugin re-checks, evaluate-mechanisms refusal, name validation.
@Suite("AuthorizationDBManager — hardening", .serialized)
struct AuthorizationDBHardeningTests {
    static let right = AuthorizationDBCompositionTests.right
    static let postman = AuthorizationDBCompositionTests.postman

    private func native() -> Data {
        plist(["class": "rule", "rule": ["authenticate-admin-nonshared"], "comment": "native", "version": 0])
    }

    private func plist(_ dict: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    private func dict(_ data: Data?) -> [String: Any] {
        guard let data else { return [:] }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] ?? [:]
    }

    private func tempStore() throws -> (AuthorizationDBSnapshotStore, URL) {
        let dir = try CoordinatorFixtures.tempDirectory()
        return (AuthorizationDBSnapshotStore(directory: dir), dir)
    }

    private func manager(_ backend: AuthorizationDBBackend, _ store: AuthorizationDBSnapshotStore,
                         verifier: AuthPluginBundleVerifying = StubPluginVerifier(status: .installed),
                         sessionOwnerOnly: @escaping @Sendable () -> Bool = { false },
                         shipped: [String: Data] = [:]) -> AuthorizationDBManager {
        AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil, daemonVersion: "1.0.0",
                               now: { CoordinatorFixtures.now }, osMajor: 27,
                               sessionOwnerOnly: sessionOwnerOnly, authPluginVerifier: verifier,
                               shippedDefinitions: { shipped[$0] })
    }

    private func composition() -> AuthorizationDBManager.DesiredComposition {
        AuthorizationDBManager.DesiredComposition(right: Self.right, branches: [Self.postman])
    }

    private func identityProfile() -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
            Rule(id: "app", type: .authuri, action: .allow, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.right), appIdentity: Self.postman),
        ])
    }

    private var classAllow: Data { plist(["class": "allow", "comment": "forged"]) }
    private var nativeRow: String { AuthURICompositionNaming.nativeDefaultRow(for: Self.right) }

    // MARK: Forged native-default rows (config.add. is class=allow)

    @Test("restore never trusts a native-default row nobody recorded: a forged class=allow row → admin-auth reset")
    func forgedRowNotTrustedOnRestore() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // A composed-looking right whose snapshot is gone and whose ownership
        // sidecar never named the row an attacker created.
        let top = plist(["class": "rule", "k-of-n": 1, "rule": [nativeRow],
                         "comment": "x \(AuthorizationDBManager.managedMarker)"])
        let backend = MockAuthorizationDB(rights: [Self.right: top, nativeRow: classAllow])
        try store.saveOwnedRows([], rightName: Self.right)   // controlled, but names nothing
        _ = try await manager(backend, store).restoreAll()
        #expect(dict(backend.current(Self.right))["class"] as? String == "user")
        #expect(dict(backend.current(Self.right))["group"] as? String == "admin")
        #expect(backend.current(nativeRow) == nil)   // swept as an owned row
    }

    @Test("a row whose digest no longer matches the recorded one is not trusted either")
    func tamperedRowNotTrusted() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let mgr = manager(backend, store)
        try await mgr.apply([], compositions: [composition()])
        #expect(store.ownedRowsRecord(rightName: Self.right)?.nativeDefaultSHA256 != nil)
        #expect(mgr.verifiedNativeDefault(for: Self.right) != nil)

        // Snapshot lost AND the row replaced (e.g. removed then re-created by a user).
        try FileManager.default.removeItem(at: dir.appendingPathComponent("\(Self.right).json"))
        backend.seed(nativeRow, classAllow)
        #expect(mgr.verifiedNativeDefault(for: Self.right) == nil)
        _ = try await mgr.restoreAll()
        #expect(dict(backend.current(Self.right))["class"] as? String == "user")   // admin reset, not allow
    }

    @Test("a legacy sidecar (bare array, no digest) is read, but its row is not trusted until recomposed")
    func legacySidecar() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try JSONEncoder().encode([nativeRow]).write(to: dir.appendingPathComponent("\(Self.right).branches"))
        #expect(store.ownedRows(rightName: Self.right) == [nativeRow])
        #expect(store.ownedRowsRecord(rightName: Self.right)?.nativeDefaultSHA256 == nil)
        let backend = MockAuthorizationDB(rights: [Self.right: native(), nativeRow: native()])
        #expect(manager(backend, store).verifiedNativeDefault(for: Self.right) == nil)
    }

    @Test("apply never re-adopts a forged row as the original; a pre-existing row is overwritten and then recorded")
    func adoptRefusesForgedRow() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let top = plist(["class": "rule", "k-of-n": 1, "rule": [nativeRow],
                         "comment": "x \(AuthorizationDBManager.managedMarker)"])
        let backend = MockAuthorizationDB(rights: [Self.right: top, nativeRow: classAllow])
        let result = try await manager(backend, store).apply([], compositions: [composition()])
        #expect(result.originalUnrecoverable == [Self.right])
        #expect(!result.snapshotted.contains(Self.right))
        #expect(dict(backend.current(Self.right))["class"] as? String == "user")   // admin reset, uncomposed

        // Fresh right where an attacker PRE-created the native-default row
        // with the right's own semantics plus an extra key: compose rewrites it.
        let (store2, dir2) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir2) }
        var forged = dict(native()); forged["entitled-group"] = true
        let backend2 = MockAuthorizationDB(rights: [Self.right: native(), nativeRow: plist(forged)])
        let mgr2 = manager(backend2, store2)
        let composed = try await mgr2.apply([], compositions: [composition()])
        #expect(composed.branchRowsWritten.contains(nativeRow))
        #expect(dict(backend2.current(nativeRow))["entitled-group"] == nil)
        #expect(mgr2.verifiedNativeDefault(for: Self.right) != nil)
    }

    @Test("canonical digest ignores authd metadata but covers every policy key")
    func canonicalDigest() {
        let a = plist(["class": "user", "group": "admin", "created": 1.0, "modified": 2.0, "version": 3, "comment": "x"])
        let b = plist(["class": "user", "group": "admin", "created": 9.0, "version": 0])
        let c = plist(["class": "user", "group": "admin", "entitled-group": true])
        #expect(AuthorizationDBManager.canonicalDigest(a) == AuthorizationDBManager.canonicalDigest(b))
        #expect(AuthorizationDBManager.canonicalDigest(a) != AuthorizationDBManager.canonicalDigest(c))
        #expect(AuthorizationDBManager.semanticallyEqual(a, c))   // why policyFields alone is not enough
    }

    // MARK: restoreAll sweeps the live database

    @Test("an EMPTY backup directory still restores: composed + projected rights are found live and reset, rows removed")
    func sweepWithEmptyBackupDirectory() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native(), "system.preferences.datetime": native()])
        let mgr = manager(backend, store)
        try await mgr.apply(AuthorizationDBManager.desiredRights(in: [RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_authuri_b", profilePriority: 50, rules: [
                Rule(id: "dt", type: .authuri, action: .deny, description: "", priority: 1,
                     match: MatchCriteria(authURI: "system.preferences.datetime")),
            ])]), compositions: [composition()])
        #expect(AuthorizationDBManager.referencesSerberusAuthMechanism(
            backend.current(AuthURICompositionNaming.appIdentityRow(for: Self.right, branch: Self.postman))!))

        // The backup directory is wiped (uninstaller ran twice, disk cleanup, …).
        try FileManager.default.removeItem(at: dir)
        #expect(mgr.controlledRightNames().isEmpty)

        let restored = try await mgr.restoreAll()
        #expect(Set(restored) == [Self.right, "system.preferences.datetime"])
        #expect(dict(backend.current(Self.right))["class"] as? String == "user")
        #expect(dict(backend.current("system.preferences.datetime"))["class"] as? String == "user")
        #expect(backend.allRightNames()!.allSatisfy { !AuthURICompositionNaming.isOwnedRow($0) })
        // Idempotent: a second run finds nothing more to do and does not throw.
        #expect(try await mgr.restoreAll().isEmpty)
    }

    @Test("restoreAll throws when a right still references SerberusAuth afterwards (--restore-authdb exits non-zero)")
    func leftoverSerberusAuthThrows() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let foreign = plist(["class": "evaluate-mechanisms", "mechanisms": ["SerberusAuth:identity"]])
        let backend = MockAuthorizationDB(rights: ["com.example.probe": foreign])
        backend.failWrites = true
        backend.failRemoves = true
        await #expect(throws: AuthorizationDBError.self) { _ = try await manager(backend, store).restoreAll() }

        // Writable: the same leftover is reset and restore succeeds.
        let ok = MockAuthorizationDB(rights: ["com.example.probe": foreign])
        let restored = try await manager(ok, store).restoreAll()
        #expect(restored == ["com.example.probe"])
        #expect(!AuthorizationDBManager.referencesSerberusAuthMechanism(ok.current("com.example.probe")!))
    }

    @Test("a backend that cannot enumerate falls back to the shipped plist + recorded names")
    func nonEnumerableFallback() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        backend.enumerable = false
        let mgr = manager(backend, store)
        try await mgr.apply([], compositions: [composition()])
        try FileManager.default.removeItem(at: dir)
        // Self.right ships in /System/Library/Security/authorization.plist on
        // every supported macOS, so the fallback still finds it.
        if AuthorizationDBManager.shippedRightNames().contains(Self.right) {
            _ = try await mgr.restoreAll()
            #expect(dict(backend.current(Self.right))["class"] as? String == "user")
            #expect(backend.current(nativeRow) == nil)
        }
    }

    // MARK: Plugin re-checks

    @Test("plugin status is cached by fingerprint: full verification only when the fingerprint changes")
    func pluginFingerprintCache() {
        let verifier = SwitchablePluginVerifier(status: .installed)
        let (store, _) = try! tempStore()
        let mgr = manager(MockAuthorizationDB(rights: [:]), store, verifier: verifier)
        #expect(mgr.authPluginStatus() == .installed)
        #expect(mgr.authPluginStatus() == .installed)
        #expect(verifier.verifyCount == 1)
        verifier.set(.unavailable(reason: "gone"), fingerprint: "fp-2")
        #expect(mgr.authPluginStatus() == .unavailable(reason: "gone"))
        #expect(verifier.verifyCount == 2)
        verifier.set(.installed, fingerprint: nil)   // no cheap check → always verify
        _ = mgr.authPluginStatus(); _ = mgr.authPluginStatus()
        #expect(verifier.verifyCount == 4)
    }

    @Test("plugin disappears: the health token changes, reconcile restores the composed right, the daemon reports degraded")
    func pluginDisappears() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let verifier = SwitchablePluginVerifier(status: .installed)
        let applier = AuthorizationDBApplier(manager: manager(backend, store, verifier: verifier), perAppPinsEnabled: true)
        try await applier.reconcile(profiles: [identityProfile()])
        #expect(AuthorizationDBManager.referencesOwnedRows(backend.current(Self.right)!))
        #expect(applier.authPluginProblem() == nil)
        let healthyToken = applier.authPluginHealthToken()
        #expect(applier.overlayAuthPluginHealth(state: .healthy, reason: nil) == (.healthy, nil))

        verifier.set(.unavailable(reason: "bundle missing"), fingerprint: "-")
        #expect(applier.authPluginHealthToken() != healthyToken)   // moves the daemon's policy signature
        try await applier.reconcile(profiles: [identityProfile()])
        #expect(backend.current(Self.right) == original)            // back to native
        #expect(applier.authPluginProblem() != nil)
        #expect(applier.overlayAuthPluginHealth(state: .healthy, reason: nil) == (.degraded, .authPluginUnavailable))
        // Never masks a more urgent state.
        #expect(applier.overlayAuthPluginHealth(state: .degraded, reason: .authDBFailure) == (.degraded, .authDBFailure))
        #expect(applier.overlayAuthPluginHealth(state: .pendingPPPC, reason: nil) == (.pendingPPPC, nil))

        // No identity-scoped rules any more: a missing plugin is not a problem.
        try await applier.reconcile(profiles: [])
        #expect(applier.authPluginProblem() == nil)

        // Plugin back + rules back: recomposed, problem clears.
        verifier.set(.installed, fingerprint: "fp-3")
        try await applier.reconcile(profiles: [identityProfile()])
        #expect(AuthorizationDBManager.referencesOwnedRows(backend.current(Self.right)!))
        #expect(applier.authPluginProblem() == nil)
    }

    @Test("the production verifier's fingerprint moves when the bundle changes")
    func productionFingerprint() throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let bundle = dir.appendingPathComponent("SerberusAuth.bundle")
        let verifier = SystemAuthPluginBundleVerifier(bundlePath: bundle.path, teamID: "")
        let absent = verifier.fingerprint()
        try FileManager.default.createDirectory(at: bundle.appendingPathComponent("Contents/MacOS"),
                                                withIntermediateDirectories: true)
        let present = verifier.fingerprint()
        #expect(absent != present)
        try Data("x".utf8).write(to: bundle.appendingPathComponent("Contents/MacOS/SerberusAuth"))
        #expect(verifier.fingerprint() != present)
    }

    // MARK: evaluate-mechanisms rights are never rewritten

    @Test("a right that is natively class=evaluate-mechanisms is neither projected nor composed")
    func evaluateMechanismsRefused() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let chain = plist(["class": "evaluate-mechanisms", "mechanisms": ["builtin:smartcard-sniffer,privileged"]])
        let backend = MockAuthorizationDB(rights: ["com.example.chain": chain, Self.right: chain])
        // Both are rights macOS ships (a foreign right takes a deny anyway).
        let mgr = manager(backend, store, shipped: ["com.example.chain": chain, Self.right: chain])
        let result = try await mgr.apply(
            [AuthorizationDBManager.DesiredRight(name: "com.example.chain",
                                                 definition: AuthorizationDBManager.definitionPlist(for: .deny))],
            compositions: [composition()])
        #expect(Set(result.skippedEvaluateMechanisms) == ["com.example.chain", Self.right])
        #expect(result.compositionRejected[Self.right] != nil)
        #expect(backend.current("com.example.chain") == chain)
        #expect(backend.current(Self.right) == chain)
        #expect(backend.writes.isEmpty)
        #expect(!store.hasSnapshot(rightName: "com.example.chain"))
    }

    @Test("an older daemon's projection of an evaluate-mechanisms right is put back")
    func evaluateMechanismsProjectionRestored() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let chain = plist(["class": "evaluate-mechanisms", "mechanisms": ["builtin:x"]])
        try store.save(AuthorizationDBSnapshot(rightName: "com.example.chain", originalDefinition: chain,
                                               timestamp: CoordinatorFixtures.now, daemonVersion: "0.9"))
        let backend = MockAuthorizationDB(rights: ["com.example.chain": AuthorizationDBManager.definitionPlist(for: .deny)])
        // A right macOS ships (on one it does not ship, the deny is kept).
        _ = try await manager(backend, store, shipped: ["com.example.chain": chain]).apply([AuthorizationDBManager.DesiredRight(
            name: "com.example.chain", definition: AuthorizationDBManager.definitionPlist(for: .deny))])
        #expect(backend.current("com.example.chain") == chain)
        #expect(!store.hasSnapshot(rightName: "com.example.chain"))
    }

    // MARK: Effective-config settings

    @Test("enableBiometrics comes from the adopted EFFECTIVE config, read per compose")
    func effectiveBiometrics() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let settings = AuthorizationDBEffectiveSettings(enableBiometrics: false)
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let applier = AuthorizationDBApplier(
            manager: manager(backend, store, sessionOwnerOnly: { settings.enableBiometrics }), settings: settings,
            perAppPinsEnabled: true)
        let authRow = AuthURICompositionNaming.appAuthRow(for: Self.right, branch: Self.postman)
        try await applier.reconcile(profiles: [identityProfile()])
        #expect(dict(backend.current(authRow))["group"] as? String == "admin")

        applier.adoptEffectiveConfig(SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil, daemonEnabled: true,
            enforcementMode: .enforce, sudoCacheSeconds: 0, promptTimeoutSeconds: 60,
            pamBypass: PAMBypass(groups: ["admin"]), enableBiometrics: true))
        try await applier.reconcile(profiles: [identityProfile()])
        #expect(dict(backend.current(authRow))["group"] == nil)   // session owner only
    }

    @Test("the settings seed prefers a usable delivered config, else the last-known-good snapshot")
    func settingsSeed() throws {
        let lkg = InMemoryLastKnownGoodConfigStore()
        let usable: [String: any Sendable] = ["enableBiometrics": true, "enforcementMode": "enforce",
                                              "pamBypass": ["groups": ["admin"]] as [String: any Sendable]]
        let delivered = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.configDomain: usable]))
        #expect(AuthorizationDBEffectiveSettings(reader: delivered, lastKnownGood: lkg).enableBiometrics)

        let absent = ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:]))
        #expect(!AuthorizationDBEffectiveSettings(reader: absent, lastKnownGood: lkg).enableBiometrics)
        try lkg.save(delivered.readConfig().value)
        #expect(AuthorizationDBEffectiveSettings(reader: absent, lastKnownGood: lkg).enableBiometrics)
    }

    // MARK: Name validation in the production backend

    @Test("the production backend refuses NUL / whitespace / non-ASCII names before any AuthorizationRight* call")
    func backendNameValidation() {
        let db = SecurityAuthorizationDB()
        for bad in ["com.apple.\u{0}x", "com.apple. x", "com.apple.é", ""] {
            #expect(throws: AuthorizationDBError.invalidRightName(bad)) { try SecurityAuthorizationDB.validateName(bad) }
            #expect(throws: AuthorizationDBError.invalidRightName(bad)) { try db.setDefinition(Data(), for: bad) }
            #expect(throws: AuthorizationDBError.invalidRightName(bad)) { try db.removeRight(bad) }
            // The empty name is the catch-all right authd answers undefined
            // rights from: it may be READ (it cannot be truncated into another
            // name), never written.
            guard !bad.isEmpty else { continue }
            #expect(throws: AuthorizationDBError.invalidRightName(bad)) { _ = try db.definition(of: bad) }
            #expect(!db.rightExists(bad))
        }
        #expect(throws: Never.self) { try SecurityAuthorizationDB.validateName("system.preferences.datetime") }
    }

    @Test("auth.db enumeration reads the rules table's names through a read-only connection")
    func readRuleNames() throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("auth.db").path
        var db: OpaquePointer?
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        #expect(sqlite3_exec(db, "CREATE TABLE rules (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, type INTEGER); INSERT INTO rules (name, type) VALUES ('system.preferences.datetime', 1), ('is-admin', 2);", nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)
        let names = SecurityAuthorizationDB.readRuleNames(databasePath: path)
        #expect(Set(names ?? []) == ["system.preferences.datetime", "is-admin"])
        #expect(SecurityAuthorizationDB.readRuleNames(databasePath: dir.appendingPathComponent("missing.db").path) == nil)
        // Opened read-only: no journal / no file created for a missing path.
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("missing.db").path))
    }
}

/// A plain allow is written only over a native admin gate, read from the
/// LIVE definition (rule chains resolved through the backend); mechanism
/// chains are found through rule references; restore falls back to Apple's
/// shipped default; the sweep keeps foreign chains and never overwrites a
/// protected right; every composition row is digest-verified; the plugin
/// verifier requires this Mac's CPU slice.
@Suite("AuthorizationDBManager — native gates, restore stand-ins, row digests", .serialized)
struct AuthorizationDBNativeGateTests {
    static let right = "com.example.pane"
    static let composed = AuthorizationDBCompositionTests.right
    static let postman = AuthorizationDBCompositionTests.postman

    private func plist(_ dict: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    private func dict(_ data: Data?) -> [String: Any] {
        guard let data else { return [:] }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] ?? [:]
    }

    /// The rule classes macOS ships, as the live database returns them.
    private var shippedRules: [String: Data] {
        [
            "authenticate-admin": plist(["class": "user", "group": "admin", "shared": true, "timeout": 0]),
            "authenticate-admin-nonshared": plist(["class": "user", "group": "admin", "timeout": 30]),
            "authenticate-session-owner": plist(["class": "user", "session-owner": true]),
            "entitled": plist(["class": "evaluate-mechanisms", "mechanisms": ["builtin:entitled,privileged"]]),
            "kcunlock": plist(["class": "evaluate-mechanisms", "extract-password": true,
                               "mechanisms": ["builtin:unlock-keychain", "builtin:kc-verify,privileged"]]),
        ]
    }

    private func backend(_ rights: [String: Data]) -> MockAuthorizationDB {
        MockAuthorizationDB(rights: shippedRules.merging(rights) { _, new in new })
    }

    private func tempStore() throws -> (AuthorizationDBSnapshotStore, URL) {
        let dir = try CoordinatorFixtures.tempDirectory()
        return (AuthorizationDBSnapshotStore(directory: dir), dir)
    }

    private func manager(_ backend: AuthorizationDBBackend, _ store: AuthorizationDBSnapshotStore,
                         shipped: [String: Data] = [:]) -> AuthorizationDBManager {
        AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil, daemonVersion: "1.0.0",
                               now: { CoordinatorFixtures.now }, osMajor: 27,
                               authPluginVerifier: StubPluginVerifier(status: .installed),
                               shippedDefinitions: { shipped[$0] })
    }

    private func profile(_ action: RuleAction, right: String = AuthorizationDBNativeGateTests.right) -> [RuleProfile] {
        [RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
            Rule(id: "r", type: .authuri, action: action, description: "", priority: 1,
                 match: MatchCriteria(authURI: right)),
        ])]
    }

    /// Applies a plain allow on `native` and returns the result + backend.
    private func applyAllow(over native: Data) async throws -> (AuthorizationDBManager.ApplyResult, MockAuthorizationDB,
                                                                  AuthorizationDBManager, URL) {
        let (store, dir) = try tempStore()
        let db = backend([Self.right: native])
        let mgr = manager(db, store, shipped: [Self.right: native])
        let result = try await mgr.apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
        return (result, db, mgr, dir)
    }

    // MARK: Live admin-gate check

    @Test("an allow on a right natively gated to the session owner alone is refused and left native")
    func sessionOwnerOnlyRefused() async throws {
        let native = plist(["class": "user", "session-owner": true, "shared": false])
        let (result, db, mgr, dir) = try await applyAllow(over: native)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(result.skippedNotAdminGated[Self.right]?.contains("session owner alone") == true)
        #expect(db.current(Self.right) == native)
        #expect(db.writes.isEmpty)
        #expect(mgr.controlledRightNames().isEmpty)
        // The integrity log names the rule and why.
        #expect(mgr.skippedRules(profile(.allow)).contains { $0.ruleID == "r" && $0.reason.contains("session owner alone") })
        // A deny on the same right is still enforced.
        #expect(!mgr.skippedRules(profile(.deny)).contains { $0.right == Self.right })
    }

    @Test("an allow on an entitlement-only right is refused")
    func entitledOnlyRefused() async throws {
        let native = plist(["class": "rule", "rule": "entitled", "allow-root": true])
        let (result, db, _, dir) = try await applyAllow(over: native)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(result.skippedNotAdminGated[Self.right] != nil)
        #expect(result.skippedEvaluateMechanisms.isEmpty)   // an entitlement check is not a mechanism chain
        #expect(db.current(Self.right) == native)
    }

    @Test("an allow on a natively admin-gated right is applied")
    func adminGatedApplied() async throws {
        let native = plist(["class": "rule", "rule": "authenticate-admin"])
        let (result, db, _, dir) = try await applyAllow(over: native)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(result.skippedNotAdminGated.isEmpty)
        #expect(result.modified == [Self.right])
        // The projection, with authenticate-admin's credential settings.
        var written = dict(db.current(Self.right))
        #expect(written["timeout"] as? Int == 0 && written["shared"] as? Bool == true)
        written["timeout"] = nil
        written["shared"] = false
        #expect(AuthorizationDBManager.semanticallyEqual(
            plist(written), AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)))
    }

    @Test("a right that reaches kcunlock through a rule reference is a mechanism chain: allow, deny and composition all refused")
    func kcunlockChainRefused() async throws {
        let native = plist(["class": "rule", "rule": "kcunlock"])
        for action in [RuleAction.allow, .deny] {
            let (store, dir) = try tempStore()
            defer { try? FileManager.default.removeItem(at: dir) }
            let db = backend([Self.right: native])
            let result = try await manager(db, store, shipped: [Self.right: native])
                .apply(AuthorizationDBManager.desiredRights(in: profile(action)))
            #expect(result.skippedEvaluateMechanisms == [Self.right], "\(action)")
            #expect(db.current(Self.right) == native)
        }
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = backend([Self.composed: native])
        let result = try await manager(db, store).apply([], compositions: [
            AuthorizationDBManager.DesiredComposition(right: Self.composed, branches: [Self.postman]),
        ])
        #expect(result.compositionRejected[Self.composed]?.contains("kcunlock") == true)
        #expect(db.current(Self.composed) == native)
        #expect(db.writes.isEmpty)
    }

    @Test("an allow on a right that is natively class=allow is refused as already open")
    func alreadyOpenRefused() async throws {
        let native = plist(["class": "allow"])
        let (result, db, _, dir) = try await applyAllow(over: native)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(result.skippedNotAdminGated[Self.right]?.contains("already open") == true)
        #expect(db.current(Self.right) == native)
    }

    /// The wildcards and default rule macOS ships for undefined names:
    /// `system.` → `default`, `""` → `default`, and `default` itself a plain
    /// admin gate with a shared five-minute credential.
    private var wildcards: [String: Data] {
        [
            "system.": plist(["class": "rule", "rule": ["default"]]),
            "": plist(["class": "rule", "rule": ["default"]]),
            "default": plist(["class": "user", "group": "admin", "shared": true, "timeout": 300,
                              "authenticate-user": true, "allow-root": false]),
        ]
    }

    @Test("an allow on a right this macOS does not define is created once and then left alone, pass after pass")
    func undefinedRightCreatedAndStable() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let name = "system.preferences.dateandtime.changetimezone"
        let db = backend(wildcards)
        let mgr = manager(db, store)
        let desired = AuthorizationDBManager.desiredRights(in: profile(.allow, right: name))

        let first = try await mgr.apply(desired)
        #expect(first.created == [name])
        #expect(first.skippedNotAdminGated.isEmpty)
        let created = try #require(db.current(name))
        // Checked against, and credential settings carried from, the
        // governing `system.` → `default` gate.
        #expect(dict(created)["session-owner"] as? Bool == true)
        #expect(dict(created)["timeout"] as? Int == 300)
        #expect(dict(created)["shared"] as? Bool == true)
        #expect(dict(created)["version"] == nil)
        #expect(mgr.skippedRules(profile(.allow, right: name)).isEmpty)

        for pass in 2...4 {
            let result = try await mgr.apply(desired)
            #expect(result.unchanged == [name], "pass \(pass): \(result)")
            #expect(result.skippedNotAdminGated.isEmpty, "pass \(pass)")
            #expect(result.created.isEmpty && result.modified.isEmpty, "pass \(pass)")
            #expect(db.current(name) == created, "pass \(pass)")
        }
        #expect(db.writes == [name])
        #expect(try store.load(rightName: name).wasAbsent)

        // Restore still removes it.
        _ = try await mgr.restoreAll()
        #expect(!db.rightExists(name))
    }

    @Test("an allow on an undefined right whose governing wildcard is not an admin gate is refused and never created")
    func undefinedRightUnderNonAdminWildcardRefused() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let name = "system.volume.external.example"
        var rights = wildcards
        rights["system.volume.external."] = plist(["class": "rule", "k-of-n": 1, "rule": ["on-console", "authenticate-admin"]])
        rights["on-console"] = plist(["class": "evaluate-mechanisms", "mechanisms": ["builtin:on-console"]])
        let db = backend(rights)
        let mgr = manager(db, store)
        let desired = AuthorizationDBManager.desiredRights(in: profile(.allow, right: name))
        for _ in 1...2 {
            let result = try await mgr.apply(desired)
            #expect(result.created.isEmpty)
            #expect(result.skippedNotAdminGated[name]?.contains("system.volume.external.") == true, "\(result)")
        }
        #expect(!db.rightExists(name))
        #expect(db.writes.isEmpty)
        #expect(!store.hasSnapshot(rightName: name))
        #expect(mgr.skippedRules(profile(.allow, right: name)).contains { $0.reason.contains("system.volume.external.") })
        // A deny on it is still created.
        let deny = try await mgr.apply(AuthorizationDBManager.desiredRights(in: profile(.deny, right: name)))
        #expect(deny.created == [name])
    }

    @Test("an allow on an undefined right that no wildcard governs is refused")
    func undefinedRightWithoutWildcardRefused() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = backend([:])
        let result = try await manager(db, store).apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
        #expect(result.created.isEmpty)
        #expect(result.skippedNotAdminGated[Self.right]?.contains("no wildcard") == true)
        #expect(!db.rightExists(Self.right))
    }

    @Test("wildcard candidates follow authd's lookup order")
    func wildcardOrder() {
        #expect(AuthRightNativeGate.wildcardCandidates(for: "system.preferences.dateandtime.changetimezone")
            == ["system.preferences.dateandtime.", "system.preferences.", "system.", ""])
        #expect(AuthRightNativeGate.wildcardCandidates(for: "a") == [""])
    }

    // MARK: A native definition that changed underneath

    @Test("a replaced native definition that still passes becomes the new original; restore puts it back, not the stale one")
    func nativeChangedStillAdminGated() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = plist(["class": "rule", "rule": "authenticate-admin"])
        let db = backend([Self.right: original])
        let mgr = manager(db, store, shipped: [Self.right: original])
        let desired = AuthorizationDBManager.desiredRights(in: profile(.allow))
        _ = try await mgr.apply(desired)

        // A macOS update replaces the right with another admin gate.
        let updated = plist(["class": "user", "group": "admin", "timeout": 900, "shared": false, "comment": "new"])
        db.seed(Self.right, updated)
        let result = try await mgr.apply(desired)
        #expect(result.nativeChanged == [Self.right])
        #expect(result.snapshotted == [Self.right])
        #expect(result.modified == [Self.right])
        #expect(dict(db.current(Self.right))["timeout"] as? Int == 900)
        #expect(try store.load(rightName: Self.right).originalDefinition == updated)

        // The next pass sees Serberus's own write: nothing changes.
        let steady = try await mgr.apply(desired)
        #expect(steady.unchanged == [Self.right] && steady.nativeChanged.isEmpty)

        _ = try await mgr.restoreAll()
        #expect(db.current(Self.right) == updated)
    }

    @Test("a replaced native definition that no longer passes is refused and left in place; restore does not reinstate the stale one")
    func nativeChangedNarrowed() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = plist(["class": "rule", "rule": "authenticate-admin"])
        let db = backend([Self.right: original])
        let mgr = manager(db, store, shipped: [Self.right: original])
        let desired = AuthorizationDBManager.desiredRights(in: profile(.allow))
        _ = try await mgr.apply(desired)

        let narrowed = plist(["class": "rule", "rule": "entitled"])
        db.seed(Self.right, narrowed)
        let result = try await mgr.apply(desired)
        #expect(result.nativeChanged == [Self.right])
        #expect(result.skippedNotAdminGated[Self.right]?.contains("changed underneath") == true)
        #expect(db.current(Self.right) == narrowed)
        #expect(mgr.controlledRightNames().isEmpty)

        let writes = db.writes.count
        _ = try await mgr.apply(desired)
        _ = try await mgr.restoreAll()
        #expect(db.current(Self.right) == narrowed)
        #expect(db.writes.count == writes)
    }

    @Test("a composed right replaced underneath is recomposed around the replacement, which restore then puts back")
    func composedNativeChanged() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = plist(["class": "rule", "rule": ["authenticate-admin-nonshared"]])
        let db = backend([Self.composed: original])
        let mgr = manager(db, store)
        let desired = [AuthorizationDBManager.DesiredComposition(right: Self.composed, branches: [Self.postman])]
        _ = try await mgr.apply([], compositions: desired)

        let replaced = plist(["class": "user", "group": "admin", "timeout": 60])
        db.seed(Self.composed, replaced)
        let result = try await mgr.apply([], compositions: desired)
        #expect(result.nativeChanged == [Self.composed])
        #expect(result.composed == [Self.composed])
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: Self.composed)
        #expect(AuthorizationDBManager.semanticallyEqual(db.current(nativeRow)!, replaced))

        _ = try await mgr.restoreAll()
        #expect(db.current(Self.composed) == replaced)
    }

    @Test("a projection edited in place, even outside the compared fields, is detected by its digest and rewritten")
    func projectionDriftRepaired() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let native = plist(["class": "rule", "rule": "authenticate-admin"])
        let db = backend([Self.right: native])
        let mgr = manager(db, store, shipped: [Self.right: native])
        let desired = AuthorizationDBManager.desiredRights(in: profile(.allow))
        _ = try await mgr.apply(desired)
        let written = try #require(db.current(Self.right))
        #expect(store.projectionDigest(rightName: Self.right) == AuthorizationDBManager.canonicalDigest(written))

        var edited = dict(written)
        edited["tries"] = 1
        db.seed(Self.right, plist(edited))
        let result = try await mgr.apply(desired)
        #expect(result.modified == [Self.right])
        #expect(result.nativeChanged.isEmpty)
        #expect(dict(db.current(Self.right))["tries"] as? Int == 10000)
    }

    @Test("an allow keeps the native credential timeout and sharing")
    func nativeTimeoutCarried() async throws {
        let native = plist(["class": "user", "group": "admin", "timeout": 900, "shared": false,
                            "authenticate-user": true, "allow-root": true, "session-owner": false])
        let (result, db, _, dir) = try await applyAllow(over: native)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(result.modified == [Self.right])
        #expect(dict(db.current(Self.right))["timeout"] as? Int == 900)
        #expect(dict(db.current(Self.right))["shared"] as? Bool == false)

        // Through a single rule reference too.
        let delegated = plist(["class": "rule", "rule": "authenticate-admin-nonshared"])
        let (_, db2, _, dir2) = try await applyAllow(over: delegated)
        defer { try? FileManager.default.removeItem(at: dir2) }
        #expect(dict(db2.current(Self.right))["timeout"] as? Int == 30)
        #expect(dict(db2.current(Self.right))["shared"] as? Bool == false)
    }

    @Test("an older daemon's allow over a right that is not an admin gate is put back")
    func earlierProjectionRestored() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let native = plist(["class": "user", "session-owner": true])
        try store.save(AuthorizationDBSnapshot(rightName: Self.right, originalDefinition: native,
                                               timestamp: CoordinatorFixtures.now, daemonVersion: "0.9"))
        let db = backend([Self.right: AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)])
        let result = try await manager(db, store).apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
        #expect(result.skippedNotAdminGated[Self.right] != nil)
        #expect(db.current(Self.right) == native)
        #expect(!store.hasSnapshot(rightName: Self.right))
    }

    // MARK: Restore stand-in: Apple's shipped default

    @Test("with no verified backup, restore writes Apple's shipped definition; an unshipped name gets the admin gate")
    func restoreUsesShippedDefault() async throws {
        let shipped = plist(["class": "rule", "k-of-n": 1, "rule": ["on-console", "authenticate-admin"]])
        for (name, expectShipped) in [("com.example.shipped", true), ("com.example.unshipped", false)] {
            let (store, dir) = try tempStore()
            defer { try? FileManager.default.removeItem(at: dir) }
            let db = backend([name: AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)])
            try store.saveOwnedRows([], rightName: name)   // controlled, snapshot lost
            _ = try await manager(db, store, shipped: ["com.example.shipped": shipped]).restoreAll()
            if expectShipped {
                #expect(db.current(name) == shipped)
            } else {
                #expect(dict(db.current(name))["group"] as? String == "admin")
                #expect(dict(db.current(name))["session-owner"] == nil)
            }
        }
    }

    @Test("the restore sweep also uses the shipped default for a Serberus-written right with no record")
    func sweepUsesShippedDefault() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let shipped = plist(["class": "rule", "rule": "entitled"])
        let db = backend([Self.right: AuthorizationDBManager.definitionPlist(for: .requireSessionOwnerOrAdmin)])
        let restored = try await manager(db, store, shipped: [Self.right: shipped]).restoreAll()
        #expect(restored == [Self.right])
        #expect(db.current(Self.right) == shipped)
    }

    // MARK: Any-of natives carry the most restrictive credential settings

    @Test("an allow over a k-of-n 1 [is-admin, authenticate-admin] native carries timeout 0, not unlimited")
    func anyOfNativeCarriesMinimumTimeout() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let native = plist(["class": "rule", "k-of-n": 1, "rule": ["is-admin", "authenticate-admin"]])
        let db = backend([Self.right: native,
                          "is-admin": plist(["class": "user", "group": "admin", "authenticate-user": false])])
        let result = try await manager(db, store, shipped: [Self.right: native])
            .apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
        #expect(result.modified == [Self.right])
        let written = dict(db.current(Self.right))
        #expect(written["timeout"] as? Int == 0)
        // is-admin sets no `shared`, so not every admin branch is shared.
        #expect(written["shared"] as? Bool == false)
        #expect(written["password-only"] == nil)
    }

    @Test("an allow carries password-only from the native admin gate")
    func passwordOnlyCarried() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let native = plist(["class": "rule", "rule": "authenticate-admin-nonshared-password"])
        let db = backend([Self.right: native,
                          "authenticate-admin-nonshared-password": plist(["class": "user", "group": "admin", "timeout": 30,
                                                                          "password-only": true])])
        _ = try await manager(db, store, shipped: [Self.right: native])
            .apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
        #expect(dict(db.current(Self.right))["password-only"] as? Bool == true)
        #expect(dict(db.current(Self.right))["timeout"] as? Int == 30)
    }

    // MARK: The admin-auth stand-in is recorded, not marked

    @Test("the admin-auth stand-in carries no marker, is recorded by digest, and is a terminal state")
    func standInRecordedNotMarked() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let standIn = AuthorizationDBManager.definitionPlist(for: .requireAdmin)
        #expect(!AuthorizationDBManager.carriesManagedMarker(standIn))
        #expect(dict(standIn)["comment"] as? String == AuthorizationDBManager.standInComment)

        // A right someone created with the public marker in its comment: the
        // sweep resets it to the stand-in, which it records.
        let forged = plist(["class": "allow", "comment": "x \(AuthorizationDBManager.managedMarker)"])
        let db = backend([Self.right: forged])
        let mgr = manager(db, store)
        _ = try await mgr.restoreAll()
        let after = try #require(db.current(Self.right))
        #expect(AuthorizationDBManager.semanticallyEqual(after, standIn))
        #expect(!AuthorizationDBManager.carriesManagedMarker(after))
        #expect(store.standInDigest(rightName: Self.right) == AuthorizationDBManager.canonicalDigest(after))
        #expect(mgr.isRecordedStandIn(after, right: Self.right))
        // Only the stand-in record is left: no snapshot, projection or ownership record.
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        #expect(files == ["\(Self.right).standin"])

        // A second restore leaves it alone.
        let writes = db.writes.count
        _ = try await mgr.restoreAll()
        #expect(db.writes.count == writes)

        // The record, not the comment, makes it Serberus's: an allow over it
        // is refused (its original is lost), where the same shape without a
        // record would be treated as the native definition.
        let result = try await mgr.apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
        #expect(result.skippedNotAdminGated[Self.right]?.contains("cannot be recovered") == true)
        #expect(db.current(Self.right) == after)
    }

    @Test("a stand-in an older daemon wrote with the marker is rewritten once without it")
    func legacyStandInLosesMarker() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        var legacy = dict(AuthorizationDBManager.definitionPlist(for: .requireAdmin))
        legacy["comment"] = "Serberus projection (admin-auth reset: original definition unrecoverable). \(AuthorizationDBManager.managedMarker)"
        let db = backend([Self.right: plist(legacy)])
        _ = try await manager(db, store).restoreAll()
        let after = try #require(db.current(Self.right))
        #expect(!AuthorizationDBManager.carriesManagedMarker(after))
        #expect(store.standInDigest(rightName: Self.right) != nil)
    }

    // MARK: Orphaned rows and rows that cannot be removed

    @Test("the restore sweep removes an orphaned native-default row that names no mechanism and carries no marker")
    func orphanNativeDefaultSwept() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let row = AuthURICompositionNaming.nativeDefaultRow(for: Self.composed)
        let db = backend([row: plist(["class": "rule", "rule": ["authenticate-admin-nonshared"]])])
        _ = try await manager(db, store).restoreAll()
        #expect(db.current(row) == nil)
    }

    @Test("a composition row that can be neither removed nor neutralized fails the restore")
    func stuckRowIsLeftover() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let row = AuthURICompositionNaming.nativeDefaultRow(for: Self.composed)
        let db = backend([row: plist(["class": "rule", "rule": ["authenticate-admin-nonshared"]])])
        db.failRemoves = true
        db.failWrites = true
        await #expect(throws: AuthorizationDBError.self) {
            _ = try await manager(db, store).restoreAll()
        }
        // Neutralizing to deny is enough when removal alone is refused.
        db.failWrites = false
        _ = try await manager(db, store).restoreAll()
        #expect(dict(db.current(row))["class"] as? String == "deny")
    }

    @Test("SerberusAuth mechanisms are recognised whatever their case")
    func mechanismPrefixCaseInsensitive() {
        for name in ["SerberusAuth:identity", "serberusauth:identity", "SERBERUSAUTH:identity"] {
            #expect(AuthorizationDBManager.referencesSerberusAuthMechanism(plist(["class": "evaluate-mechanisms",
                                                                                  "mechanisms": [name]])), "\(name)")
        }
        let stripped = AuthorizationDBManager.strippingSerberusAuth(from: plist([
            "class": "evaluate-mechanisms", "mechanisms": ["builtin:prelogin", "serberusAUTH:identity"]]))
        #expect(dict(stripped)["mechanisms"] as? [String] == ["builtin:prelogin"])
    }

    // MARK: Foreign rights (not shipped, not recorded, not Serberus's)

    @Test("a deny lands on a right a user pre-created as a mechanism chain; the original is recorded as foreign")
    func denyOverForeignChain() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let planted = plist(["class": "evaluate-mechanisms", "mechanisms": ["builtin:authenticate"]])
        let db = backend([Self.right: planted])
        let mgr = manager(db, store)
        #expect(!mgr.skippedRules(profile(.deny)).contains { $0.right == Self.right })
        let result = try await mgr.apply(AuthorizationDBManager.desiredRights(in: profile(.deny)))
        #expect(result.skippedEvaluateMechanisms.isEmpty)
        #expect(dict(db.current(Self.right))["class"] as? String == "deny")
        let snapshot = try store.load(rightName: Self.right)
        #expect(snapshot.foreign)
        #expect(snapshot.originalDefinition == planted)

        // Steady state, then restore puts the original back.
        let again = try await mgr.apply(AuthorizationDBManager.desiredRights(in: profile(.deny)))
        #expect(again.unchanged == [Self.right])
        _ = try await mgr.restoreAll()
        #expect(db.current(Self.right) == planted)
    }

    /// macOS's `authenticate` rule: a mechanism chain that takes the
    /// caller's own password.
    private var authenticate: Data {
        plist(["class": "evaluate-mechanisms", "mechanisms": ["builtin:authenticate"]])
    }

    /// A deny over `planted`, a chain a user created on a right macOS does
    /// not ship and passed off as Serberus's own: it lands, stays, and is
    /// never adopted as the original, so restore writes the admin-auth
    /// stand-in instead of putting the chain back.
    private func expectDenyLandsThenStandIn(over planted: Data) async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = backend([Self.right: planted, "authenticate": authenticate])
        let mgr = manager(db, store)
        #expect(!mgr.skippedRules(profile(.deny)).contains { $0.right == Self.right })
        let desired = AuthorizationDBManager.desiredRights(in: profile(.deny))
        let result = try await mgr.apply(desired)
        #expect(result.skippedEvaluateMechanisms.isEmpty)
        #expect(dict(db.current(Self.right))["class"] as? String == "deny")
        #expect(result.originalUnrecoverable == [Self.right])
        #expect(!store.hasSnapshot(rightName: Self.right))

        let again = try await mgr.apply(desired)
        #expect(again.unchanged == [Self.right])
        #expect(again.skippedEvaluateMechanisms.isEmpty)
        #expect(db.writes == [Self.right])

        _ = try await mgr.restoreAll()
        let after = try #require(db.current(Self.right))
        #expect(mgr.isRecordedStandIn(after, right: Self.right))
    }

    @Test("a deny lands on a user-created chain carrying Serberus's marker; restore writes the admin-auth stand-in, since a marked original is never trusted")
    func denyOverMarkedChain() async throws {
        try await expectDenyLandsThenStandIn(over: plist([
            "class": "rule", "rule": ["authenticate"], "comment": "x \(AuthorizationDBManager.managedMarker)",
        ]))
    }

    @Test("a deny lands on a user-created chain referencing a composition row; restore writes the admin-auth stand-in, since such an original is never trusted")
    func denyOverChainReferencingRow() async throws {
        try await expectDenyLandsThenStandIn(over: plist([
            "class": "rule", "k-of-n": 1,
            "rule": [AuthURICompositionNaming.nativeDefaultRow(for: Self.right), "authenticate"],
        ]))
    }

    @Test("a deny lands on a forged chain referencing another right's composition rows, and leaves those rows untouched")
    func denyOverForgedRowReference() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = backend([Self.composed: plist(["class": "rule", "rule": ["authenticate-admin-nonshared"]]),
                          "authenticate": authenticate])
        let mgr = manager(db, store)
        _ = try await mgr.apply([], compositions: [
            AuthorizationDBManager.DesiredComposition(right: Self.composed, branches: [Self.postman]),
        ])
        let composedRows = try #require(store.ownedRowsRecord(rightName: Self.composed)).rows
        let before = composedRows.map { db.current($0) }

        // The composed right's native-default row referenced directly, and
        // its auth row through a row named for the denied right.
        let ownRow = AuthURICompositionNaming.rowPrefix + Self.right + ".app.forged"
        db.seed(ownRow, plist(["class": "rule",
                               "rule": [AuthURICompositionNaming.appAuthRow(for: Self.composed, branch: Self.postman)]]))
        db.seed(Self.right, plist(["class": "rule", "k-of-n": 1, "rule": [
            AuthURICompositionNaming.nativeDefaultRow(for: Self.composed), ownRow, "authenticate",
        ]]))
        let writes = db.writes.count
        let result = try await mgr.apply(AuthorizationDBManager.desiredRights(in: profile(.deny)))
        #expect(result.skippedEvaluateMechanisms.isEmpty)
        #expect(dict(db.current(Self.right))["class"] as? String == "deny")
        // Only the row named for the denied right is removed.
        #expect(result.branchRowsRemoved == [ownRow])
        #expect(db.removes == [ownRow])
        #expect(Array(db.writes[writes...]) == [Self.right])
        #expect(composedRows.map { db.current($0) } == before)
        #expect(mgr.verifiedNativeDefault(for: Self.composed) != nil)
    }

    @Test("a deny on an undefined right macOS does not ship is created even when its governing wildcard runs a chain; a name macOS ships is still refused")
    func denyCreatedUnderChainWildcard() async throws {
        let chained = ["com.example.": plist(["class": "rule", "rule": ["authenticate"]]), "authenticate": authenticate]
        let desired = AuthorizationDBManager.desiredRights(in: profile(.deny))
        do {
            let (store, dir) = try tempStore()
            defer { try? FileManager.default.removeItem(at: dir) }
            let db = backend(chained)
            let mgr = manager(db, store)
            #expect(!mgr.skippedRules(profile(.deny)).contains { $0.right == Self.right })
            let first = try await mgr.apply(desired)
            #expect(first.created == [Self.right])
            #expect(first.skippedEvaluateMechanisms.isEmpty)
            #expect(dict(db.current(Self.right))["class"] as? String == "deny")

            // The next pass checks the same wildcard, and keeps the deny.
            let again = try await mgr.apply(desired)
            #expect(again.unchanged == [Self.right])
            #expect(again.skippedEvaluateMechanisms.isEmpty)
            #expect(db.writes == [Self.right])

            _ = try await mgr.restoreAll()
            #expect(!db.rightExists(Self.right))
        }
        do {
            let (store, dir) = try tempStore()
            defer { try? FileManager.default.removeItem(at: dir) }
            let db = backend(chained)
            let mgr = manager(db, store, shipped: [Self.right: plist(["class": "rule", "rule": ["authenticate"]])])
            #expect(mgr.skippedRules(profile(.deny)).contains { $0.right == Self.right && $0.reason.contains("mechanism chain") })
            let result = try await mgr.apply(desired)
            #expect(result.skippedEvaluateMechanisms == [Self.right])
            #expect(!db.rightExists(Self.right))
        }
    }

    @Test("a deny on a mechanism-chain right macOS ships is still refused")
    func denyOverShippedChainRefused() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let chain = plist(["class": "evaluate-mechanisms", "mechanisms": ["builtin:authenticate"]])
        let db = backend([Self.right: chain])
        let result = try await manager(db, store, shipped: [Self.right: chain])
            .apply(AuthorizationDBManager.desiredRights(in: profile(.deny)))
        #expect(result.skippedEvaluateMechanisms == [Self.right])
        #expect(db.current(Self.right) == chain)
    }

    @Test("a deny on a foreign class=allow right lands; an allow on a foreign right must also pass as undefined")
    func foreignAllowJudgedAsUndefined() async throws {
        // A user pre-creates an admin-looking definition where the wildcard
        // that would govern the name is session-owner only.
        let planted = plist(["class": "rule", "rule": "authenticate-admin"])
        let wildcard = plist(["class": "user", "session-owner": true])
        do {
            let (store, dir) = try tempStore()
            defer { try? FileManager.default.removeItem(at: dir) }
            let db = backend([Self.right: planted, "com.example.": wildcard])
            let result = try await manager(db, store).apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
            #expect(result.skippedNotAdminGated[Self.right]?.contains("undefined right") == true)
            #expect(db.current(Self.right) == planted)
        }
        do {
            // The same definition on a right macOS ships is an admin gate.
            let (store, dir) = try tempStore()
            defer { try? FileManager.default.removeItem(at: dir) }
            let db = backend([Self.right: planted, "com.example.": wildcard])
            let result = try await manager(db, store, shipped: [Self.right: planted])
                .apply(AuthorizationDBManager.desiredRights(in: profile(.allow)))
            #expect(result.modified == [Self.right])
        }
        do {
            let (store, dir) = try tempStore()
            defer { try? FileManager.default.removeItem(at: dir) }
            let open = plist(["class": "allow"])
            let db = backend([Self.right: open])
            _ = try await manager(db, store).apply(AuthorizationDBManager.desiredRights(in: profile(.deny)))
            #expect(dict(db.current(Self.right))["class"] as? String == "deny")
            #expect(try store.load(rightName: Self.right).foreign)
        }
    }

    @Test("shippedDefinition reads a right out of an authorization.plist")
    func shippedDefinitionReader() throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("authorization.plist").path
        try plist(["rights": ["system.preferences.location": ["class": "rule", "rule": ["on-console"]]],
                   "rules": [:] as [String: Any]]).write(to: URL(fileURLWithPath: path))
        let definition = AuthorizationDBManager.shippedDefinition(of: "system.preferences.location", plistPath: path)
        #expect(dict(definition)["rule"] as? [String] == ["on-console"])
        #expect(AuthorizationDBManager.shippedDefinition(of: "com.example.none", plistPath: path) == nil)
        #expect(AuthorizationDBManager.shippedDefinition(of: "x", plistPath: dir.appendingPathComponent("missing").path) == nil)
    }

    // MARK: Restore sweep: foreign chains and protected rights

    @Test("a foreign mechanism chain that names SerberusAuth keeps its other mechanisms")
    func foreignChainStripped() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let foreign = plist(["class": "evaluate-mechanisms", "comment": "an admin's own chain",
                             "mechanisms": ["builtin:prelogin", "SerberusAuth:identity", "loginwindow:login"]])
        let db = backend(["system.login.console": foreign, "com.example.chain": foreign])
        _ = try await manager(db, store).restoreAll()
        for name in ["system.login.console", "com.example.chain"] {
            let after = dict(db.current(name))
            #expect(after["mechanisms"] as? [String] == ["builtin:prelogin", "loginwindow:login"], "\(name)")
            #expect(after["class"] as? String == "evaluate-mechanisms")
            #expect(after["comment"] as? String == "an admin's own chain")
        }
    }

    @Test("a protected right Serberus wrote with no recoverable original is never overwritten; it is a leftover")
    func protectedNeverOverwritten() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let written = plist(["class": "user", "group": "admin",
                             "comment": "x \(AuthorizationDBManager.managedMarker)"])
        let db = backend(["system.login.screensaver": written])
        await #expect(throws: AuthorizationDBError.self) {
            _ = try await manager(db, store, shipped: ["system.login.screensaver": plist(["class": "rule", "rule": "x"])]).restoreAll()
        }
        #expect(db.current("system.login.screensaver") == written)
        #expect(db.writes.isEmpty)
    }

    @Test("a protected right someone else created that names SerberusAuth or carries the marker is reported, not a failed restore")
    func plantedProtectedRightsDoNotBlockRestore() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // Any user can create a NEW right (`config.add.` is class=allow).
        let planted = plist(["class": "evaluate-mechanisms", "mechanisms": ["SerberusAuth:identity"]])
        let marked = plist(["class": "user", "group": "admin", "comment": "x \(AuthorizationDBManager.managedMarker)"])
        let db = backend(["com.apple.security.planted": planted, "system.login.planted": marked])
        _ = try await manager(db, store).restoreAll()
        // Protected: still never overwritten.
        #expect(db.current("com.apple.security.planted") == planted)
        #expect(db.current("system.login.planted") == marked)
        #expect(db.writes.isEmpty)

        // The same shapes on a right macOS ships still fail the restore.
        await #expect(throws: AuthorizationDBError.self) {
            _ = try await manager(db, store, shipped: ["com.apple.security.planted": plist(["class": "rule", "rule": "x"])]).restoreAll()
        }
    }

    // MARK: Every composition row is verified by digest

    @Test("a pre-created app row that matches on the compared fields is still rewritten, and every row's digest is recorded")
    func preCreatedAppRowRewritten() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let native = plist(["class": "rule", "rule": ["authenticate-admin-nonshared"]])
        let db = backend([Self.composed: native])
        let mgr = manager(db, store)
        let composition = AuthorizationDBManager.DesiredComposition(right: Self.composed, branches: [Self.postman])
        let authRow = AuthURICompositionNaming.appAuthRow(for: Self.composed, branch: Self.postman)

        // What the composer will write for the auth row, plus a key the
        // compared field set ignores, created by someone else first.
        var forged = AppIdentityBranch.authBody(sessionOwnerOnly: false)
        forged["vpn-entitled-group"] = true
        db.seed(authRow, plist(forged))
        #expect(AuthorizationDBManager.semanticallyEqual(plist(forged), plist(AppIdentityBranch.authBody(sessionOwnerOnly: false))))

        let first = try await mgr.apply([], compositions: [composition])
        #expect(first.branchRowsWritten.contains(authRow))
        #expect(dict(db.current(authRow))["vpn-entitled-group"] == nil)
        let record = try #require(store.ownedRowsRecord(rightName: Self.composed))
        for row in record.rows {
            #expect(record.rowSHA256?[row] == AuthorizationDBManager.canonicalDigest(db.current(row)!), "\(row)")
        }

        // Steady state: nothing is rewritten.
        let second = try await mgr.apply([], compositions: [composition])
        #expect(second.branchRowsWritten.isEmpty)

        // Tampered after the fact (same compared fields, different digest): rewritten.
        var tampered = dict(db.current(authRow)); tampered["entitled-group"] = true
        db.seed(authRow, plist(tampered))
        let third = try await mgr.apply([], compositions: [composition])
        #expect(third.branchRowsWritten == [authRow])
        #expect(dict(db.current(authRow))["entitled-group"] == nil)
    }

    @Test("a sidecar from before per-row digests: app rows are rewritten once, then recorded")
    func legacySidecarRewritesOnce() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = backend([Self.composed: plist(["class": "rule", "rule": ["authenticate-admin-nonshared"]])])
        let mgr = manager(db, store)
        let composition = AuthorizationDBManager.DesiredComposition(right: Self.composed, branches: [Self.postman])
        _ = try await mgr.apply([], compositions: [composition])
        let record = try #require(store.ownedRowsRecord(rightName: Self.composed))
        try store.saveOwnedRows(record.rows, rightName: Self.composed, nativeDefaultSHA256: record.nativeDefaultSHA256)
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: Self.composed)
        let again = try await mgr.apply([], compositions: [composition])
        #expect(Set(again.branchRowsWritten) == Set(record.rows).subtracting([nativeRow]))
        #expect(try await mgr.apply([], compositions: [composition]).branchRowsWritten.isEmpty)
    }

    // MARK: Plugin: this Mac's CPU slice

    private func machO(_ bytes: [UInt8]) throws -> String {
        let dir = try CoordinatorFixtures.tempDirectory()
        let path = dir.appendingPathComponent("SerberusAuth").path
        try Data(bytes).write(to: URL(fileURLWithPath: path))
        return path
    }

    private func le(_ value: UInt32) -> [UInt8] { withUnsafeBytes(of: value.littleEndian, Array.init) }
    private func be(_ value: UInt32) -> [UInt8] { withUnsafeBytes(of: value.bigEndian, Array.init) }

    @Test("the plugin executable must carry a slice for this Mac's CPU")
    func hostArchitectureSlice() throws {
        let arm = UInt32(bitPattern: SystemAuthPluginBundleVerifier.cpuTypeARM64)
        let intel = UInt32(bitPattern: SystemAuthPluginBundleVerifier.cpuTypeX86_64)
        let thinARM = try machO(le(0xFEED_FACF) + le(arm) + le(0) + le(6) + [UInt8](repeating: 0, count: 16))
        let fatIntel = try machO(be(0xCAFE_BABE) + be(1) + be(intel) + be(3) + be(4096) + be(100) + be(12))
        let fatBoth = try machO(be(0xCAFE_BABE) + be(2) + be(intel) + be(3) + be(4096) + be(100) + be(12)
                                + be(arm) + be(0) + be(16384) + be(100) + be(14))
        let garbage = try machO(Array("#!/bin/sh\necho hi\n".utf8))
        let paths = [thinARM, fatIntel, fatBoth, garbage]
        defer { for path in paths { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) } }

        let check = SystemAuthPluginBundleVerifier.machOContainsArchitecture
        #expect(check(thinARM, SystemAuthPluginBundleVerifier.cpuTypeARM64) == true)
        #expect(check(thinARM, SystemAuthPluginBundleVerifier.cpuTypeX86_64) == false)
        #expect(check(fatIntel, SystemAuthPluginBundleVerifier.cpuTypeARM64) == false)
        #expect(check(fatIntel, SystemAuthPluginBundleVerifier.cpuTypeX86_64) == true)
        #expect(check(fatBoth, SystemAuthPluginBundleVerifier.cpuTypeARM64) == true)
        #expect(check(garbage, SystemAuthPluginBundleVerifier.cpuTypeARM64) == nil)
        #expect(check("/nonexistent/SerberusAuth", SystemAuthPluginBundleVerifier.cpuTypeARM64) == nil)
        // A real system binary carries this Mac's slice.
        #expect(check("/bin/ls", SystemAuthPluginBundleVerifier.hostCPUType()) == true)
    }
}

/// On macOS 26 authd stamps the writing process's `identifier` and
/// `requirement` onto the rights it creates (and possibly updates). The
/// read-back of every row Serberus writes then differs from what it wrote in
/// `requirement`, which must not fail the native-default check or force a
/// rewrite every pass.
@Suite("AuthorizationDBManager — macOS 26 creator stamp", .serialized)
struct AuthorizationDBCreatorStampTests {
    static let bless = "com.apple.ServiceManagement.blesshelper"
    static let daemonsModify = "com.apple.ServiceManagement.daemons.modify"
    static let composer = AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer")

    private func plist(_ dict: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    private func dict(_ data: Data?) -> [String: Any] {
        guard let data else { return [:] }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] ?? [:]
    }

    /// A class=user native definition, as blesshelper ships.
    private var blessNative: Data {
        plist(["allow-root": true, "authenticate-user": true, "class": "user", "group": "admin",
               "session-owner": false, "shared": false, "timeout": 30, "tries": 10000, "version": 1])
    }

    /// A class=rule k-of-n 1 native definition, as daemons.modify ships.
    private var daemonsModifyNative: Data {
        plist(["class": "rule", "k-of-n": 1, "rule": ["is-root", "entitled-admin-or-authenticate-admin-nonshared"],
               "version": 1])
    }

    private func stampingBackend(_ rights: [String: Data], updates: Bool) -> MockAuthorizationDB {
        let backend = MockAuthorizationDB(rights: rights)
        backend.stampCreates = true
        backend.stampUpdates = updates
        return backend
    }

    private func manager(_ backend: AuthorizationDBBackend, _ store: AuthorizationDBSnapshotStore) -> AuthorizationDBManager {
        AuthorizationDBManager(backend: backend, store: store, integrityLogger: nil, daemonVersion: "1.0.0",
                               now: { CoordinatorFixtures.now }, scopeRegistry: .current, osMajor: 26,
                               sessionOwnerOnly: { false },
                               authPluginVerifier: StubPluginVerifier(status: .installed),
                               shippedDefinitions: { _ in nil })
    }

    /// Composes `right` over one app branch on a stamping backend and checks
    /// the composition landed; returns the manager and backend for more checks.
    private func composeStamped(_ right: String, native: Data, updates: Bool,
                                store: AuthorizationDBSnapshotStore) async throws -> (AuthorizationDBManager, MockAuthorizationDB) {
        let backend = stampingBackend([right: native], updates: updates)
        let mgr = manager(backend, store)
        let composition = AuthorizationDBManager.DesiredComposition(right: right, branches: [Self.composer])
        let result = try await mgr.apply([], compositions: [composition])
        #expect(result.failed.isEmpty)
        #expect(result.composed == [right])
        #expect(result.compositionRejected.isEmpty)

        let appRow = AuthURICompositionNaming.appRow(for: right, branch: Self.composer)
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: right)
        let top = dict(backend.current(right))
        #expect(top["class"] as? String == "rule")
        #expect(top["k-of-n"] as? Int == 1)
        #expect(top["rule"] as? [String] == [appRow, nativeRow])
        // The stamp really is on what authd hands back.
        #expect(dict(backend.current(nativeRow))["requirement"] as? String == MockAuthorizationDB.stampRequirement)
        #expect(AuthorizationDBManager.semanticallyEqual(backend.current(nativeRow)!, native))
        return (mgr, backend)
    }

    @Test("a class=user right (blesshelper) composes when authd stamps the writer", arguments: [false, true])
    func composesClassUserRight(updates: Bool) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = try await composeStamped(Self.bless, native: blessNative, updates: updates,
                                     store: AuthorizationDBSnapshotStore(directory: dir))
    }

    @Test("a class=rule k-of-n 1 right (daemons.modify) composes when authd stamps the writer", arguments: [false, true])
    func composesClassRuleRight(updates: Bool) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = try await composeStamped(Self.daemonsModify, native: daemonsModifyNative, updates: updates,
                                     store: AuthorizationDBSnapshotStore(directory: dir))
    }

    @Test("a second pass over a stamped composition writes nothing", arguments: [false, true])
    func secondPassIsNoOp(updates: Bool) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let (mgr, backend) = try await composeStamped(Self.bless, native: blessNative, updates: updates,
                                                      store: AuthorizationDBSnapshotStore(directory: dir))
        let writes = backend.writes.count
        let again = try await mgr.apply([], compositions: [
            AuthorizationDBManager.DesiredComposition(right: Self.bless, branches: [Self.composer]),
        ])
        #expect(again.failed.isEmpty)
        #expect(again.branchRowsWritten.isEmpty)
        #expect(again.modified.isEmpty)
        #expect(again.unchanged.contains(Self.bless))
        #expect(backend.writes.count == writes)
    }

    @Test("restoreAll puts back the original of a stamped composition and sweeps its rows", arguments: [false, true])
    func restoreStampedComposition(updates: Bool) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = AuthorizationDBSnapshotStore(directory: dir)
        let (mgr, backend) = try await composeStamped(Self.daemonsModify, native: daemonsModifyNative, updates: updates,
                                                      store: store)
        let restored = try await mgr.restoreAll()
        #expect(restored == [Self.daemonsModify])
        var back = dict(backend.current(Self.daemonsModify))
        if updates {
            // authd stamps the restore write itself; everything else is the original.
            #expect(back["requirement"] as? String == MockAuthorizationDB.stampRequirement)
            back["identifier"] = nil
            back["requirement"] = nil
        }
        #expect(NSDictionary(dictionary: back).isEqual(to: dict(daemonsModifyNative)))
        for row in [AuthURICompositionNaming.nativeDefaultRow(for: Self.daemonsModify),
                    AuthURICompositionNaming.appRow(for: Self.daemonsModify, branch: Self.composer),
                    AuthURICompositionNaming.appIdentityRow(for: Self.daemonsModify, branch: Self.composer),
                    AuthURICompositionNaming.appAuthRow(for: Self.daemonsModify, branch: Self.composer)] {
            #expect(backend.current(row) == nil)
        }
        #expect(mgr.controlledRightNames().isEmpty)
    }

    @Test("a lost snapshot on a stamped composition restores from the verified native-default row", arguments: [false, true])
    func restoreStampedFromPreservedRow(updates: Bool) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let (mgr, backend) = try await composeStamped(Self.bless, native: blessNative, updates: updates,
                                                      store: AuthorizationDBSnapshotStore(directory: dir))
        try Data("garbage".utf8).write(to: dir.appendingPathComponent("\(Self.bless).json"))
        _ = try await mgr.restoreAll()
        let back = backend.current(Self.bless)!
        #expect(AuthorizationDBManager.semanticallyEqual(back, blessNative))
        #expect(dict(back)["group"] as? String == "admin")   // the preserved row, not the admin-auth reset
        #expect(dict(back)["comment"] == nil)
    }

    @Test("a plain projection over a right is not rewritten every pass once authd stamps it", arguments: [false, true])
    func stampedProjectionIsStable(updates: Bool) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        // A right Serberus creates is always stamped; a native one it updates may be.
        let backend = stampingBackend([Self.daemonsModify: daemonsModifyNative], updates: updates)
        let applier = AuthorizationDBApplier(manager: manager(backend, AuthorizationDBSnapshotStore(directory: dir)))
        let profile = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50, rules: [
            Rule(id: "deny", type: .authuri, action: .deny, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.daemonsModify)),
        ])
        try await applier.apply(profiles: [profile])
        #expect(dict(backend.current(Self.daemonsModify))["class"] as? String == "deny")
        let writes = backend.writes.count
        try await applier.apply(profiles: [profile])
        #expect(backend.writes.count == writes)
    }
}

// MARK: - Per-app pins disabled in production

extension AuthorizationDBCompositionTests {
    static let expectedSkipReason = "per-app (App Identity) rules are disabled in Serberus 0.9.0: the app's identity comes from a value the caller can forge; the right keeps its native definition"

    @Test("the production applier composes nothing for a pin, reports the skip reason, and does not degrade the daemon",
          arguments: [AuthPluginInstallStatus.installed, .unavailable(reason: "bundle missing")])
    func disabledProductionSkipsPin(plugin: AuthPluginInstallStatus) async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])
        let mgr = manager(backend, store, plugin: plugin)
        let applier = AuthorizationDBApplier(manager: mgr)   // production default switch
        let pins = [profile([Self.postman, Self.composer])]

        #expect(AuthorizationDBManager.desiredCompositions(in: pins).isEmpty)
        try await applier.reconcile(profiles: pins)
        try await applier.apply(profiles: pins)

        #expect(backend.current(Self.right) == original)        // right stays native
        #expect(backend.writes.isEmpty)
        #expect(!store.hasSnapshot(rightName: Self.right))
        #expect(store.rightsWithOwnedRows().isEmpty)
        #expect(mgr.controlledRightNames().isEmpty)
        // Every pin is reported, with the skip reason, once per rule.
        let skipped = mgr.skippedRules(pins)
        #expect(skipped.map(\.ruleID).sorted() == ["app0", "app1"])
        #expect(skipped.allSatisfy { $0.right == Self.right && $0.reason == Self.expectedSkipReason })
        // Not degraded, even with the plugin missing: nothing is desired.
        #expect(applier.authPluginProblem() == nil)
        #expect(applier.overlayAuthPluginHealth(state: .healthy, reason: nil) == (.healthy, nil))
    }

    @Test("a plain authuri rule next to a disabled pin is still projected as before")
    func disabledPlainRuleUnaffected() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let applier = AuthorizationDBApplier(manager: manager(backend, store))
        try await applier.reconcile(profiles: [profile([Self.postman], plain: .deny)])
        #expect(dict(backend.current(Self.right))["class"] as? String == "deny")
        #expect(!AuthorizationDBManager.referencesOwnedRows(backend.current(Self.right)!))
    }

    @Test("upgrade — a right composed by an older build is restored to native on the first reconcile, every owned row removed")
    func disabledUpgradeRestoresComposedRight() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = native()
        let backend = MockAuthorizationDB(rights: [Self.right: original])

        // Older build: the right was composed (machinery driven directly).
        let old = manager(backend, store)
        _ = try await old.apply([], compositions: [composition([Self.postman, Self.composer])])
        #expect(AuthorizationDBManager.referencesOwnedRows(backend.current(Self.right)!))
        let ownedBefore = store.ownedRows(rightName: Self.right)
        #expect(ownedBefore.count == 7)   // 3 rows per app + native-default

        // This build starts with the same pin profile still delivered.
        let applier = AuthorizationDBApplier(manager: manager(backend, store))
        try await applier.reconcile(profiles: [profile([Self.postman, Self.composer])])   // no applyIncomplete

        #expect(backend.current(Self.right) == original)
        for row in ownedBefore { #expect(backend.current(row) == nil, "\(row)") }
        #expect(!store.hasSnapshot(rightName: Self.right))
        #expect(store.rightsWithOwnedRows().isEmpty)
        #expect(applier.authPluginProblem() == nil)

        // And it stays native on the next reload.
        let writes = backend.writes.count
        try await applier.reconcile(profiles: [profile([Self.postman, Self.composer])])
        #expect(backend.writes.count == writes)
    }
}

extension AuthorizationDBCompositionTests {
    @Test("each skipped pin is logged once per reload with the skip reason; with the switch injected on it composes")
    func disabledSkipLogLines() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let backend = MockAuthorizationDB(rights: [Self.right: native()])
        let pins = [profile([Self.postman])]
        let lines = AuthorizationDBApplier(manager: manager(backend, store)).logSkippedRules(pins)
        #expect(lines == ["authdb: rule 'app0' on '\(Self.right)' skipped: \(Self.expectedSkipReason)"])
        #expect(AuthURIIdentityScope.disabledSkipReason == Self.expectedSkipReason)
        #expect(AuthURIIdentityScope.perAppPinsEnabled == false)

        let enabled = AuthorizationDBApplier(manager: manager(backend, store), perAppPinsEnabled: true)
        #expect(enabled.logSkippedRules(pins).isEmpty)
        try await enabled.reconcile(profiles: pins)
        #expect(AuthorizationDBManager.referencesOwnedRows(backend.current(Self.right)!))
    }
}
