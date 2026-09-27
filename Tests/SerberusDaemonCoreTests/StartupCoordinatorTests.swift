import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

// MARK: - Test doubles

/// In-memory grant maintainer with injectable failures.
actor MockGrantStore: GrantMaintaining {
    var grants: [Grant]
    var failReads: Bool
    private(set) var revokeAllCount = 0

    init(grants: [Grant] = [], failReads: Bool = false) {
        self.grants = grants
        self.failReads = failReads
    }

    func insert(_ grant: Grant) throws {
        grants.append(grant)
    }

    func cleanupExpired(now: Date) throws -> Int {
        if failReads { throw GrantStoreError.openFailed(path: "x", code: 14, message: "mock") }
        let before = grants.count
        grants.removeAll { grant in
            guard let expiry = grant.expiresAt else { return false }
            return expiry < now
        }
        return before - grants.count
    }

    func activeGrants(now: Date) throws -> [Grant] {
        if failReads { throw GrantStoreError.openFailed(path: "x", code: 14, message: "mock") }
        return grants.filter { $0.isActive(at: now) }
    }

    func activeGrants(for user: String, now: Date) throws -> [Grant] {
        try activeGrants(now: now).filter { $0.user == user }
    }

    func revokeAll(now: Date) throws -> Int {
        revokeAllCount += 1
        let count = grants.count
        grants.removeAll()
        return count
    }

    func revoke(grantID: UUID, now: Date) throws -> Int {
        let before = grants.count
        grants.removeAll { $0.grantID == grantID }
        return before - grants.count
    }
}

struct FailingAuthDB: AuthorizationDBApplying {
    func apply(profiles: [RuleProfile]) async throws {
        throw GrantStoreError.openFailed(path: "authdb", code: 1, message: "mock authdb failure")
    }
}

/// An ``AuthorizationDBApplying`` that records whether the daemon mutated the
/// authdb at all — the assertion that matters for the awaiting-config contract
/// ("do not merely label the state; actually skip the mutation").
actor CountingAuthDB: AuthorizationDBApplying {
    private(set) var applyCount = 0
    private(set) var reconcileCount = 0
    /// The profiles handed to the MOST RECENT reconcile — so a test can prove the
    /// awaiting-config path reconciles the EMPTY desired set (a restore) rather than
    /// applying the live policy.
    private(set) var lastReconcileProfiles: [RuleProfile] = []

    func apply(profiles: [RuleProfile]) async throws { applyCount += 1 }
    func reconcile(profiles: [RuleProfile]) async throws {
        reconcileCount += 1
        lastReconcileProfiles = profiles
    }
}

enum CoordinatorFixtures {
    static let now = Date(timeIntervalSince1970: 1_781_222_400)

    static func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-daemon-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// The default config domain is a *safely enforceable* one — `enforce` WITH a
    /// break-glass group — because that is what a real configured Mac has, and it
    /// is the only shape the daemon will adopt and enforce. A config domain
    /// without `pamBypass` is the enrollment-race/partial-profile shape and is
    /// deliberately NOT the default fixture.
    static let enforceableConfig: [String: any Sendable] = [
        "daemonEnabled": true,
        "enforcementMode": "enforce",
        "pamBypass": ["groups": ["admin"], "users": [String]()] as [String: any Sendable],
    ]

    static func prefs(
        config: [String: any Sendable] = enforceableConfig,
        rules: [String: any Sendable] = [:]
    ) -> ManagedPreferencesReader {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: config,
            BundleConfig.rulesDomain: rules,
        ]))
    }

    /// A reader whose config domain is entirely ABSENT (no delivered keys) — the
    /// state of a Mac during the Jamf enrollment race, and after an admin unscopes
    /// or removes the config profile.
    static func prefsWithoutConfig(rules: [String: any Sendable] = [:]) -> ManagedPreferencesReader {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.rulesDomain: rules,
        ]))
    }

    /// The config a previously-configured Mac has snapshotted: enforcing, with an
    /// intact break-glass population.
    static func lastKnownGoodConfig(
        mode: EnforcementMode = .enforce,
        bypassGroups: [String] = ["admin"],
        bypassUsers: [String] = []
    ) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60,
            pamBypass: PAMBypass(groups: bypassGroups, users: bypassUsers)
        )
    }

    static func validProfileJSON(key: String = "rules_sudo_test") -> String {
        let profile = RuleProfile(
            policyVersion: "1.0.0",
            profileKey: key,
            profilePriority: 50,
            rules: [Rule(
                id: "allow-brew", type: .sudo, action: .allow,
                description: "t", priority: 10,
                match: MatchCriteria(commandPattern: "/opt/homebrew/bin/brew", matchType: .exact)
            )]
        )
        return String(decoding: try! JSONEncoder().encode(profile), as: UTF8.self)
    }
}

// MARK: - State resolution

@Suite("StartupCoordinator — state resolution precedence")
struct StateResolutionTests {
    @Test("healthy when everything is in order with profiles loaded")
    func healthy() {
        let resolved = StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false,
            rulesError: false, fdaReady: true, hasProfiles: true
        )
        #expect(resolved.state == .healthy)
        #expect(resolved.reason == nil)
    }

    @Test("pending_profiles when no rules are present")
    func pendingProfiles() {
        let resolved = StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false,
            rulesError: false, fdaReady: true, hasProfiles: false
        )
        #expect(resolved.state == .pendingProfiles)
    }

    @Test("pending_pppc when FDA is missing, outranking pending_profiles")
    func pendingPPPC() {
        let resolved = StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false,
            rulesError: false, fdaReady: false, hasProfiles: false
        )
        #expect(resolved.state == .pendingPPPC)
    }

    @Test("degraded outranks pending states; config cause wins first")
    func degradedPrecedence() {
        let resolved = StartupCoordinator.resolveState(
            configInvalid: true, grantsError: true, authDBError: true,
            rulesError: true, fdaReady: false, hasProfiles: false
        )
        #expect(resolved.state == .degraded)
        #expect(resolved.reason == .configInvalid)
    }

    @Test("each degraded cause surfaces in priority order")
    func degradedCauses() {
        #expect(StartupCoordinator.resolveState(
            configInvalid: false, grantsError: true, authDBError: true, rulesError: true,
            fdaReady: true, hasProfiles: true).reason == .grantsDBError)
        #expect(StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: true, rulesError: true,
            fdaReady: true, hasProfiles: true).reason == .authDBFailure)
        #expect(StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false, rulesError: true,
            fdaReady: true, hasProfiles: true).reason == .ruleParseError)
    }
}

// MARK: - Full run

@Suite("StartupCoordinator — full sequence")
struct StartupRunTests {
    private func coordinator(
        prefs: ManagedPreferencesReader,
        grantStore: GrantMaintaining = MockGrantStore(),
        pppc: PPPCStatusChecking = StaticPPPCStatus(ready: true),
        authDB: AuthorizationDBApplying = NoopAuthorizationDBApplier(),
        // Never the production store: a unit test must not read or write
        // /Library/Application Support.
        lastKnownGood: any LastKnownGoodConfigStoring = InMemoryLastKnownGoodConfigStore()
    ) -> StartupCoordinator {
        StartupCoordinator(
            prefsReader: prefs, grantStore: grantStore, pppc: pppc, authDB: authDB,
            lastKnownGood: lastKnownGood,
            now: { CoordinatorFixtures.now }
        )
    }

    @Test("healthy end to end with a valid profile and FDA")
    func healthyRun() async {
        let prefs = CoordinatorFixtures.prefs(
            rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
        )
        let outcome = await coordinator(prefs: prefs).run()
        #expect(outcome.state == .healthy)
        #expect(outcome.profiles.map(\.profileKey) == ["rules_sudo_test"])
    }

    @Test("kill switch revokes grants and returns early")
    func killSwitch() async {
        let store = MockGrantStore(grants: [TestGrants.make()])
        let prefs = CoordinatorFixtures.prefs(config: ["daemonEnabled": false])
        let outcome = await coordinator(prefs: prefs, grantStore: store).run()
        #expect(outcome.state == .killSwitch)
        #expect(await store.revokeAllCount == 1)
        #expect(outcome.profiles.isEmpty)
    }

    @Test("kill switch at startup restores the authdb — IDENTICAL to the reload path")
    func killSwitchRestoresAuthDBAtStartup() async {
        // A kill switch delivered while the daemon was DOWN must not strand a
        // Serberus-gated authright (e.g. a deny on a Settings pane) across the next
        // boot. The startup kill-switch branch used to return BEFORE the authdb
        // reconcile; it now reconciles the authdb to the EMPTY desired set (a
        // restore) first, exactly like DaemonController.reloadPolicyIfChanged.
        let authDB = CountingAuthDB()
        let prefs = CoordinatorFixtures.prefs(config: ["daemonEnabled": false])
        let outcome = await coordinator(prefs: prefs, authDB: authDB).run()
        #expect(outcome.state == .killSwitch)
        #expect(outcome.profiles.isEmpty)
        #expect(await authDB.reconcileCount == 1)         // authdb restored…
        #expect(await authDB.lastReconcileProfiles.isEmpty) // …to EMPTY (a restore, never an apply)
        #expect(await authDB.applyCount == 0)
    }

    @Test("missing FDA yields pending_pppc but still loads policy")
    func missingFDA() async {
        let prefs = CoordinatorFixtures.prefs(
            rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
        )
        let outcome = await coordinator(prefs: prefs, pppc: StaticPPPCStatus(ready: false)).run()
        #expect(outcome.state == .pendingPPPC)
        #expect(outcome.profiles.count == 1)
    }

    @Test("grant DB read failure degrades to grants_db_error with empty grants")
    func grantsDBError() async {
        let prefs = CoordinatorFixtures.prefs(
            rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
        )
        let outcome = await coordinator(prefs: prefs, grantStore: MockGrantStore(failReads: true)).run()
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .grantsDBError)
        #expect(outcome.activeGrants.isEmpty)
    }

    @Test("authdb failure degrades to authdb_failure")
    func authDBFailure() async {
        let prefs = CoordinatorFixtures.prefs(
            rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
        )
        let outcome = await coordinator(prefs: prefs, authDB: FailingAuthDB()).run()
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .authDBFailure)
    }

    @Test("undecodable profile degrades to rule_parse_error")
    func ruleParseError() async {
        let prefs = CoordinatorFixtures.prefs(rules: ["rules_sudo_bad": "{not json"])
        let outcome = await coordinator(prefs: prefs).run()
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .ruleParseError)
    }

    @Test("no rules and FDA present yields pending_profiles")
    func pendingProfiles() async {
        let outcome = await coordinator(prefs: CoordinatorFixtures.prefs()).run()
        #expect(outcome.state == .pendingProfiles)
    }

    @Test("expired grants are removed during startup")
    func expiredCleanup() async {
        let store = MockGrantStore(grants: [
            TestGrants.make(expiresAt: CoordinatorFixtures.now.addingTimeInterval(-60)),
            TestGrants.make(user: "bob"),
        ])
        let prefs = CoordinatorFixtures.prefs(
            rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
        )
        let outcome = await coordinator(prefs: prefs, grantStore: store).run()
        #expect(outcome.activeGrants.count == 1)
        #expect(outcome.activeGrants.first?.user == "bob")
    }
}

// MARK: - Await-config bootstrap + last-known-good fallback

/// The Jamf enrollment race and its inverse, the tamper case.
///
/// During enrollment APNS may deliver the Core pkg BEFORE the config profile. An
/// absent config parses to `SerberusConfig`'s fail-safe defaults — `enforce` with
/// an EMPTY `pamBypass` — which with `pam_serberus` wired denies every `sudo` on
/// the Mac with no break-glass: a brick. So a Mac with no usable config anywhere
/// must enforce nothing and mutate nothing until one arrives.
///
/// The fail-open is scoped by the EXISTENCE of the last-known-good snapshot: once
/// a config has been adopted even once, an absent or unsafe profile falls back to
/// that snapshot (still enforcing, break-glass intact), so removing the profile
/// can never disable Serberus.
@Suite("Startup — awaiting config (enrollment race) and last-known-good fallback")
struct AwaitingConfigStartupTests {
    private func coordinator(
        prefs: ManagedPreferencesReader,
        authDB: AuthorizationDBApplying,
        lastKnownGood: any LastKnownGoodConfigStoring
    ) -> StartupCoordinator {
        StartupCoordinator(
            prefsReader: prefs,
            grantStore: MockGrantStore(),
            pppc: StaticPPPCStatus(ready: true),
            authDB: authDB,
            lastKnownGood: lastKnownGood,
            now: { CoordinatorFixtures.now }
        )
    }

    // MARK: Bootstrap — never configured

    @Test("no config and no snapshot: awaiting_config, monitor (nothing denied), authdb reconciled to EMPTY (restore)")
    func bootstrapAwaitsConfigAndEnforcesNothing() async {
        let authDB = CountingAuthDB()
        let lkg = InMemoryLastKnownGoodConfigStore()
        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefsWithoutConfig(),
            authDB: authDB,
            lastKnownGood: lkg
        ).run()

        #expect(outcome.state == .awaitingConfig)
        #expect(outcome.degradedReason == nil)
        #expect(outcome.awaitingConfig)
        // The effective mode is monitor: PAM passes straight through and NOTHING is
        // denied while the profile is in flight.
        #expect(outcome.config.enforcementMode == .monitor)
        // The daemon does NOT apply policy — but it DOES reconcile the authdb to the
        // EMPTY desired set (a restore), so a Mac mutated before its marker was
        // planted is cleaned up. On a fresh install this is a harmless no-op.
        #expect(await authDB.reconcileCount == 1)
        #expect(await authDB.lastReconcileProfiles.isEmpty) // restore, not apply
        #expect(await authDB.applyCount == 0)
        #expect(lkg.saveCount == 0) // nothing worth snapshotting
    }

    @Test("awaiting_config outranks pending_pppc and pending_profiles")
    func awaitingConfigOutranksPendingStates() async {
        let outcome = await StartupCoordinator(
            prefsReader: CoordinatorFixtures.prefsWithoutConfig(),
            grantStore: MockGrantStore(),
            pppc: StaticPPPCStatus(ready: false), // would be pending_pppc
            authDB: CountingAuthDB(),             // no rules → would be pending_profiles
            lastKnownGood: InMemoryLastKnownGoodConfigStore(),
            now: { CoordinatorFixtures.now }
        ).run()
        #expect(outcome.state == .awaitingConfig)
    }

    // MARK: Config arrives

    @Test("a present, enforceable config is adopted, snapshotted, and enforced")
    func adoptedConfigIsSnapshotted() async {
        let authDB = CountingAuthDB()
        let lkg = InMemoryLastKnownGoodConfigStore()
        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefs(
                rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
            ),
            authDB: authDB,
            lastKnownGood: lkg
        ).run()

        #expect(outcome.state == .healthy)
        #expect(!outcome.awaitingConfig)
        #expect(outcome.config.enforcementMode == .enforce)
        #expect(await authDB.reconcileCount == 1) // mutations resume
        // Snapshotted, break-glass and all — this is what a later profile removal
        // will fall back to.
        let snapshot = lkg.load()
        #expect(snapshot?.enforcementMode == .enforce)
        #expect(snapshot?.pamBypass.groups == ["admin"])
    }

    @Test("LKG save FAILURE still adopts and enforces the delivered config (source .managed)")
    func lkgSaveFailureStillEnforcesManaged() {
        struct BoomError: Error {}
        // The snapshot write throws (I/O error, directory not yet created). The
        // resolver must STILL adopt and enforce the delivered config — the save is
        // best-effort and re-attempted on later polls; a failed snapshot never
        // blocks enforcement, and it certainly never drops the Mac into pass-through.
        let lkg = InMemoryLastKnownGoodConfigStore(saveError: BoomError())
        let managed = CoordinatorFixtures.lastKnownGoodConfig() // enforce + admin break-glass (enforceable)
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: managed, configPresent: true, lastKnownGood: lkg
        )
        #expect(effective.source == .managed)               // adopted despite the failed snapshot
        #expect(effective.config.enforcementMode == .enforce)
        #expect(effective.config.pamBypass.groups == ["admin"])
        #expect(lkg.saveCount == 1)                          // it tried once…
        #expect(!lkg.exists())                              // …and the marker was NOT planted
    }

    @Test("a monitor/audit config needs no break-glass: adopted and snapshotted")
    func monitorConfigIsEnforceableWithoutBypass() async {
        let lkg = InMemoryLastKnownGoodConfigStore()
        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefs(config: ["daemonEnabled": true, "enforcementMode": "audit"]),
            authDB: CountingAuthDB(),
            lastKnownGood: lkg
        ).run()
        #expect(!outcome.awaitingConfig)
        #expect(outcome.config.enforcementMode == .audit)
        #expect(lkg.load()?.enforcementMode == .audit)
    }

    // MARK: Tamper / profile removal

    @Test("config removed but a snapshot exists: runs on the snapshot and KEEPS ENFORCING")
    func profileRemovalFallsBackToSnapshotAndStillEnforces() async {
        let authDB = CountingAuthDB()
        let lkg = InMemoryLastKnownGoodConfigStore(
            initial: CoordinatorFixtures.lastKnownGoodConfig(bypassGroups: ["admin"], bypassUsers: ["breakglass"])
        )
        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefsWithoutConfig(
                rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
            ),
            authDB: authDB,
            lastKnownGood: lkg
        ).run()

        // NOT awaiting config: a configured Mac can never fall back into pass-through.
        #expect(!outcome.awaitingConfig)
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .configMissing)
        // Still enforcing, with the break-glass population intact.
        #expect(outcome.config.enforcementMode == .enforce)
        #expect(outcome.config.pamBypass.groups == ["admin"])
        #expect(outcome.config.pamBypass.users == ["breakglass"])
        // And still mutating the system it is responsible for.
        #expect(await authDB.reconcileCount == 1)
    }

    // MARK: Partial profile (e.g. only sudoEnrollment landed)

    @Test("present but NOT enforceable (enforce + empty pamBypass) with no snapshot: awaiting_config, not a brick")
    func partialProfileWithoutSnapshotAwaitsConfig() async {
        let authDB = CountingAuthDB()
        // A standalone sudoEnrollment profile: the config domain HAS keys, so the
        // naive "is the domain present?" check would say configured — and the
        // fail-safe parse would then enforce with no break-glass.
        let prefs = CoordinatorFixtures.prefs(config: [
            "sudoEnrollment": ["group": "staff"] as [String: any Sendable],
        ])
        let outcome = await coordinator(
            prefs: prefs, authDB: authDB, lastKnownGood: InMemoryLastKnownGoodConfigStore()
        ).run()

        #expect(outcome.state == .awaitingConfig)
        #expect(outcome.awaitingConfig)
        #expect(outcome.config.enforcementMode == .monitor) // nothing denied
        // The partial profile's sudoEnrollment (group=staff) is STRIPPED: the
        // bootstrap config is canonically empty, so nothing is provisioned. The
        // authdb is reconciled to EMPTY (restore), never applied.
        #expect(outcome.config.sudoEnrollment.group == nil)
        #expect(await authDB.reconcileCount == 1)
        #expect(await authDB.lastReconcileProfiles.isEmpty)
    }

    @Test("present but NOT enforceable WITH a snapshot: falls back to the snapshot")
    func partialProfileWithSnapshotFallsBack() async {
        let lkg = InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig())
        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefs(config: [
                "sudoEnrollment": ["group": "staff"] as [String: any Sendable],
            ]),
            authDB: CountingAuthDB(),
            lastKnownGood: lkg
        ).run()

        #expect(!outcome.awaitingConfig)
        #expect(outcome.degradedReason == .configMissing)
        #expect(outcome.config.enforcementMode == .enforce)
        #expect(outcome.config.pamBypass.groups == ["admin"])
        // The unsafe delivered config must never overwrite the good snapshot.
        #expect(lkg.saveCount == 0)
    }

    @Test("a delivered kill switch WITH a pamBypass is honored but NOT snapshotted (would-enforce ≠ snapshot)")
    func killSwitchIsAdoptedButNotSnapshotted() async {
        let lkg = InMemoryLastKnownGoodConfigStore()
        // The dangerous shape the earlier snapshot guard got wrong: a kill switch
        // (daemonEnabled=false) that ALSO carries enforce + a non-empty pamBypass, so
        // it satisfies `isEnforceable`. Snapshotting it would let a later profile
        // removal fall back to a config that DISABLES Serberus — the exact boundary
        // "removing the profile can never disable Serberus" forbids. The snapshot
        // guard must be `isEnforceable && daemonEnabled`, so this is NOT written.
        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefs(config: [
                "daemonEnabled": false,
                "enforcementMode": "enforce",
                "pamBypass": ["groups": ["admin"], "users": [String]()] as [String: any Sendable],
            ]),
            authDB: CountingAuthDB(),
            lastKnownGood: lkg
        ).run()
        #expect(outcome.state == .killSwitch)
        #expect(!outcome.awaitingConfig)
        #expect(lkg.saveCount == 0)
    }

    @Test("kill-switch boundary: after adopting a kill switch, removing the profile does NOT leave Serberus disabled")
    func killSwitchIsNeverTheFallback() async {
        // A kill switch is adopted (state kill_switch) but never snapshotted, so the
        // store stays empty. When the profile is later REMOVED, there is no
        // kill-switch snapshot to fall back to: the Mac lands in awaiting_config
        // (bootstrap), NOT a persistently-disabled daemon.
        let lkg = InMemoryLastKnownGoodConfigStore()
        _ = await coordinator(
            prefs: CoordinatorFixtures.prefs(config: [
                "daemonEnabled": false,
                "enforcementMode": "enforce",
                "pamBypass": ["groups": ["admin"], "users": [String]()] as [String: any Sendable],
            ]),
            authDB: CountingAuthDB(),
            lastKnownGood: lkg
        ).run()
        #expect(lkg.saveCount == 0)
        #expect(!lkg.exists()) // no fallback was planted

        let afterRemoval = await coordinator(
            prefs: CoordinatorFixtures.prefsWithoutConfig(),
            authDB: CountingAuthDB(),
            lastKnownGood: lkg
        ).run()
        #expect(afterRemoval.state == .awaitingConfig) // never a stuck-disabled daemon
    }

    // MARK: Corrupt snapshot — file exists but will not load (fail closed, NOT bootstrap)

    @Test("snapshot FILE exists but does not load: fails CLOSED (enforce), never awaiting_config / pass-through")
    func corruptSnapshotFailsClosedNotAwaitingConfig() async {
        let authDB = CountingAuthDB()
        // A store whose file EXISTS (exists()==true) but is unusable: an initial
        // config that is not enforceable (enforce + empty bypass) — load() rejects
        // it and returns nil, exactly like a truncated / hollowed on-disk plist.
        let corrupt = InMemoryLastKnownGoodConfigStore(
            initial: SerberusConfig(
                jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
                daemonEnabled: true, enforcementMode: .enforce, sudoCacheSeconds: 0,
                promptTimeoutSeconds: 60, pamBypass: PAMBypass()
            )
        )
        #expect(corrupt.exists())        // the marker file is present…
        #expect(corrupt.load() == nil)   // …but it will not load

        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefsWithoutConfig(), // no delivered config
            authDB: authDB,
            lastKnownGood: corrupt
        ).run()

        // The daemon must key bootstrap-vs-configured on FILE EXISTENCE (like pam),
        // not on load success. A present-but-unusable snapshot => fail CLOSED, not
        // pass-through: pam selects LAST_KNOWN_GOOD here and its readers fail closed,
        // so a monitor/awaiting_config daemon would DIVERGE from pam and unlock sudo.
        #expect(!outcome.awaitingConfig)
        #expect(outcome.config.enforcementMode == .enforce) // enforcing, not monitor
        #expect(outcome.config.pamBypass.groups.isEmpty)    // no break-glass: accepted lockout
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .configMissing)
    }

    @Test("a broken DELIVERED config still reports config_invalid — the safety path does not mask it")
    func invalidDeliveredConfigIsNotMasked() async {
        let outcome = await coordinator(
            prefs: CoordinatorFixtures.prefs(config: ["enforcementMode": 42]), // wrong type → finding
            authDB: CountingAuthDB(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore()
        ).run()
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .configInvalid)
        // …but it is STILL not enforced: unusable config ⇒ no enforcement, no mutations.
        #expect(outcome.awaitingConfig)
        #expect(outcome.config.enforcementMode == .monitor)
    }

    // MARK: resolveState precedence

    @Test("resolveState: awaiting_config beats pending states; degraded causes still beat it")
    func resolveStatePrecedence() {
        #expect(StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false, rulesError: false,
            fdaReady: false, hasProfiles: false, awaitingConfig: true
        ).state == .awaitingConfig)

        let invalid = StartupCoordinator.resolveState(
            configInvalid: true, grantsError: false, authDBError: false, rulesError: false,
            fdaReady: true, hasProfiles: true, awaitingConfig: true
        )
        #expect(invalid.state == .degraded)
        #expect(invalid.reason == .configInvalid)

        let missing = StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false, rulesError: false,
            fdaReady: true, hasProfiles: true, configMissing: true
        )
        #expect(missing.state == .degraded)
        #expect(missing.reason == .configMissing)
    }
}

// MARK: - Unresolvable break-glass is unenforceable

/// An enforcing config whose `pamBypass` entries ALL fail to resolve has no
/// working break-glass, exactly like an empty one: it is not adopted, never
/// snapshotted, and reported as `degraded(bypass_unresolvable)`.
@Suite("EffectiveConfigResolver — unresolvable break-glass")
struct UnresolvableBypassResolverTests {
    private struct Table: BypassResolving {
        var users: Set<String> = []
        var groups: Set<String> = []
        func userResolves(_ name: String) -> Bool { users.contains(name) }
        func groupResolves(_ name: String) -> Bool { groups.contains(name) }
    }

    /// Enforcing, break-glass that resolves on the snapshot's Mac (`admin`).
    private static let resolver = Table(users: ["itadmin"], groups: ["admin"])

    private func delivered(users: [String] = [], groups: [String] = []) -> SerberusConfig {
        CoordinatorFixtures.lastKnownGoodConfig(bypassGroups: groups, bypassUsers: users)
    }

    @Test("all entries unresolvable + a snapshot: runs on the snapshot, never saves, reports each entry")
    func fallsBackToSnapshot() {
        let lkg = InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig())
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: delivered(users: ["itadmn"], groups: ["admn"]), configPresent: true,
            lastKnownGood: lkg, bypassResolver: Self.resolver
        )
        #expect(effective.source == .lastKnownGood)
        #expect(effective.config.pamBypass.groups == ["admin"])     // the working break-glass
        #expect(effective.bypassUnresolvable)
        #expect(effective.unresolvedBypassEntries == ["user itadmn", "group admn"])
        #expect(lkg.saveCount == 0)                                  // never snapshotted
        #expect(effective.notes.contains { $0.contains("NO pamBypass entry resolves") })
    }

    @Test("all entries unresolvable and no snapshot: awaiting config, exactly as an empty pamBypass")
    func noSnapshotAwaitsConfig() {
        let lkg = InMemoryLastKnownGoodConfigStore()
        let unresolvable = EffectiveConfigResolver.resolve(
            managedConfig: delivered(users: ["nobody-here"]), configPresent: true,
            lastKnownGood: lkg, bypassResolver: Self.resolver
        )
        let empty = EffectiveConfigResolver.resolve(
            managedConfig: delivered(), configPresent: true,
            lastKnownGood: InMemoryLastKnownGoodConfigStore(), bypassResolver: Self.resolver
        )
        #expect(unresolvable.source == .awaitingConfig)
        #expect(unresolvable.source == empty.source)
        #expect(unresolvable.config == empty.config)
        #expect(unresolvable.bypassUnresolvable)
        #expect(!lkg.exists())
    }

    @Test("a partial typo is adopted and saved, but the entry that does not resolve is still reported")
    func partialTypoIsLogged() {
        let lkg = InMemoryLastKnownGoodConfigStore()
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: delivered(users: ["itadmn"], groups: ["admin"]), configPresent: true,
            lastKnownGood: lkg, bypassResolver: Self.resolver
        )
        #expect(effective.source == .managed)
        #expect(!effective.bypassUnresolvable)
        #expect(effective.unresolvedBypassEntries == ["user itadmn"])
        #expect(lkg.saveCount == 1)
    }

    @Test("startup: degraded(bypass_unresolvable), enforcing the snapshot")
    func startupReportsIt() async {
        let outcome = await StartupCoordinator(
            prefsReader: CoordinatorFixtures.prefs(config: [
                "daemonEnabled": true, "enforcementMode": "enforce",
                "pamBypass": ["users": ["itadmn"], "groups": [String]()] as [String: any Sendable],
            ], rules: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]),
            grantStore: MockGrantStore(), pppc: StaticPPPCStatus(ready: true),
            authDB: NoopAuthorizationDBApplier(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            bypassResolver: Self.resolver, now: { CoordinatorFixtures.now }
        ).run()
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .bypassUnresolvable)
        #expect(outcome.bypassUnresolvable)
        #expect(outcome.config.pamBypass.groups == ["admin"])
        #expect(outcome.config.enforcementMode == .enforce)
        #expect(outcome.notes.contains { $0.contains("user itadmn does not resolve") })
    }

    @Test("an unusable snapshot file's reason reaches the fail-closed note")
    func unusableSnapshotReasonIsNoted() throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("last-known-good-config.plist")
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        try store.save(CoordinatorFixtures.lastKnownGoodConfig())
        #expect(chmod(url.path, 0o666) == 0)
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: delivered(), configPresent: false, lastKnownGood: store
        )
        #expect(effective.source == .failClosed)
        #expect(effective.reportsConfigMissing)          // degraded(config_missing)
        #expect(effective.notes.contains { $0.contains("group/other-writable") })
    }

    /// Resolves user names case-insensitively, the way the directory does, so a
    /// wrong-case entry "exists" but is not the account's own name.
    private struct CaseInsensitiveDirectory: BypassResolving {
        let accounts: [String]
        func userResolves(_ name: String) -> Bool { accounts.contains(name) }
        func groupResolves(_ name: String) -> Bool { name == "admin" }
        func mismatchedUserName(_ name: String) -> String? {
            accounts.first { $0.lowercased() == name.lowercased() && $0 != name }
        }
    }

    @Test("a user entry that resolves only under another case is unresolved, and says why")
    func caseMismatchIsUnresolved() {
        let directory = CaseInsensitiveDirectory(accounts: ["itadmin"])
        let lkg = InMemoryLastKnownGoodConfigStore()
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: delivered(users: ["ITAdmin"]), configPresent: true,
            lastKnownGood: lkg, bypassResolver: directory
        )
        #expect(effective.bypassUnresolvable)
        #expect(effective.source == .awaitingConfig)                // treated as an empty pamBypass
        #expect(lkg.saveCount == 0)
        #expect(effective.unresolvedBypassEntries
                == ["user ITAdmin (resolves to 'itadmin'; entries are matched exactly)"])
    }

    @Test("the production resolver requires the directory's exact spelling of a user entry")
    func productionResolverIsExact() {
        let resolver = LocalBypassResolver()
        #expect(resolver.userResolves("root"))
        #expect(resolver.mismatchedUserName("root") == nil)
        #expect(!LocalAccounts.namesMatchExactly("root", "ROOT"))
        // Directory lookups on macOS are case-insensitive; where this host's are,
        // the wrong-case spelling must still be refused and explained.
        if LocalAccounts.canonicalUserName("ROOT") == "root" {
            #expect(!resolver.userResolves("ROOT"))
            #expect(!LocalAccounts.userExists("ROOT"))
            #expect(resolver.mismatchedUserName("ROOT") == "root")
            let config = CoordinatorFixtures.lastKnownGoodConfig(bypassGroups: [], bypassUsers: ["ROOT"])
            #expect(BypassResolution.isUnresolvable(config, resolver: resolver))
        }
        // Groups are unchanged: resolved by any name the directory accepts.
        #expect(resolver.groupResolves("wheel"))
    }

    /// A directory where some groups exist but have no members.
    private struct EmptyGroupDirectory: BypassResolving {
        let populated: Set<String>
        let empty: Set<String>
        func userResolves(_ name: String) -> Bool { false }
        func groupResolves(_ name: String) -> Bool { populated.contains(name) }
        func groupIsEmpty(_ name: String) -> Bool { empty.contains(name) }
    }

    @Test("a group that exists but has no members is unresolved, and says why")
    func emptyGroupIsUnresolved() {
        let directory = EmptyGroupDirectory(populated: [], empty: ["breakglass"])
        let lkg = InMemoryLastKnownGoodConfigStore()
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: delivered(groups: ["breakglass", "brekglass"]), configPresent: true,
            lastKnownGood: lkg, bypassResolver: directory
        )
        #expect(effective.bypassUnresolvable)
        #expect(effective.source == .awaitingConfig)                // treated as an empty pamBypass
        #expect(lkg.saveCount == 0)
        #expect(effective.unresolvedBypassEntries
                == ["group breakglass (group breakglass has no members)", "group brekglass"])
    }

    /// Fixture directory: accounts `breakglass` and `itadmin` exist (exact
    /// names only); group `uuidonly` has a GroupMembers GeneratedUID naming an
    /// account; gid 613 is some account's primary group. The same fixture as
    /// the C tests (PAMConfigTests) and the shell tests (test-pam-lib.sh).
    private static let fixtureProbes = LocalAccounts.GroupProbes(
        userExists: { ["breakglass", "itadmin"].contains($0) },
        generatedUIDMember: { $0 == "uuidonly" },
        primaryGroupInUse: { $0 == 613 })

    private static let emptyDirectory = LocalAccounts.GroupProbes(
        userExists: { _ in false }, generatedUIDMember: { _ in false }, primaryGroupInUse: { _ in false })

    @Test("group members: a listed name that is an existing account, a GroupMembers UUID that is one, or a primary-gid account")
    func groupHasMembersDefinition() {
        let probes = Self.fixtureProbes
        func has(_ listed: [String], group: String = "fixture", gid: gid_t) -> Bool {
            LocalAccounts.groupHasMembers(group: group, listed: listed, gid: gid, probes: probes)
        }
        #expect(has(["breakglass"], gid: 610))
        #expect(has(["deleted-user", "itadmin"], gid: 610))
        #expect(!has([], gid: 611))
        #expect(!has([""], gid: 612))
        #expect(has([], gid: 613))
        #expect(has([], group: "uuidonly", gid: 614))
        // A deleted account's name left behind in the group is not a member.
        #expect(!has(["deleted-user"], gid: 615))
        // Names are exact: a case variant, or one with a space, is not the account.
        #expect(!has(["BreakGlass", " breakglass", "breakglass "], gid: 616))
    }

    @Test("GeneratedUIDs resolve through mbr_uuid_to_id to an existing account only")
    func generatedUIDsNameUsers() {
        // root's compatibility UUID maps to uid 0, which exists.
        #expect(LocalAccounts.generatedUIDNamesUser("FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"))
        // A group's compatibility UUID maps to a gid, not a user.
        #expect(!LocalAccounts.generatedUIDNamesUser("ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050"))
        #expect(!LocalAccounts.generatedUIDNamesUser("00000000-1111-2222-3333-444444444444"))
        #expect(!LocalAccounts.generatedUIDNamesUser("not-a-uuid"))
        #expect(!LocalAccounts.generatedUIDMemberExists(group: "serberus-no-such-group-7f3a"))
        #expect(!LocalAccounts.generatedUIDMemberExists(group: ""))
    }

    @Test("a group lookup is classified by the injected probes, whatever the host's members")
    func groupLookupWithInjectedProbes() {
        // admin exists on every Mac. With a directory in which no account
        // exists it has no members; with one in which its listed names do, it
        // has. Deterministic whatever the host's group actually holds.
        #expect(LocalAccounts.groupMembers("admin", probes: Self.emptyDirectory) == .empty)
        let everyone = LocalAccounts.GroupProbes(
            userExists: { _ in true }, generatedUIDMember: { _ in true }, primaryGroupInUse: { _ in true })
        #expect(LocalAccounts.groupMembers("admin", probes: everyone) == .hasMembers)
        #expect(LocalAccounts.groupMembers("serberus-no-such-group-7f3a", probes: everyone) == .notFound)
        #expect(LocalAccounts.groupMembers("", probes: everyone) == .notFound)
    }

    @Test("the production resolver finds real groups with members")
    func productionResolver() {
        let resolver = LocalBypassResolver()
        // admin lists root, which exists; staff is every local user's primary group.
        #expect(LocalAccounts.groupMembers("admin") == .hasMembers)
        #expect(LocalAccounts.primaryGroupInUse(20))
        #expect(LocalAccounts.groupMembers("serberus-no-such-group-7f3a") == .notFound)
        #expect(!resolver.groupResolves("serberus-no-such-group-7f3a"))
        #expect(!resolver.groupIsEmpty("serberus-no-such-group-7f3a"))
        // A gid above Int32.max never matches by primary group (nobody, nogroup).
        #expect(!LocalAccounts.primaryGroupInUse(gid_t(UInt32.max - 1)))
    }

    @Test("names with U+0000 or whitespace are compared byte for byte, never shortened or trimmed")
    func unusualNamesAreExact() {
        let resolver = LocalBypassResolver()
        for name in ["root\u{0}x", " root", "root ", "root\n"] {
            #expect(!resolver.userResolves(name))
        }
        // getgrnam_r would read "admin\0x" as "admin".
        #expect(LocalAccounts.groupMembers("admin\u{0}x") == .notFound)
        #expect(!resolver.groupResolves("admin\u{0}x"))
        #expect(!resolver.groupResolves(" admin"))
    }

    @Test("the ESF exemption matches a pamBypass user entry exactly, never by case")
    func esfExemptionIsExact() {
        // `_www` (uid 70) is a system account that is not in admin, so only the
        // bypass entry can make it exempt.
        guard LocalAccounts.userName(uid: 70) == "_www",
              LocalAccounts.isMember(uid: 70, ofGroup: JITAdmin.adminGroup) == false else { return }
        #expect(ESFMonitor.isExemptUser(auid: 70, bypass: PAMBypass(users: ["_www"])))
        #expect(!ESFMonitor.isExemptUser(auid: 70, bypass: PAMBypass(users: ["_WWW"])))
    }
}

// MARK: - Await-config on the live reload path

/// The reload loop must reach the SAME conclusions startup does — it runs the same
/// ``EffectiveConfigResolver`` — and must gate the two real mutations (authdb
/// reconcile, sudoers drop-in) on the result, not merely label the state.
@Suite("DaemonController reload — awaiting config gates every mutation", .serialized)
struct AwaitingConfigReloadTests {
    private func makeController(
        source: PreferencesSource,
        paths: DaemonPaths,
        authDB: AuthorizationDBApplying,
        sudoers: SudoersProvisioning,
        lastKnownGood: any LastKnownGoodConfigStoring
    ) -> DaemonController {
        DaemonController(
            paths: paths,
            machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: source),
            grantStore: NullGrantStore(),
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil,
            decisionLogger: nil,
            pppc: StaticPPPCStatus(ready: true),
            authDB: authDB,
            sudoers: sudoers,
            lastKnownGood: lastKnownGood,
            deviceSerial: "TESTSERIAL",
            now: { CoordinatorFixtures.now }
        )
    }

    @Test("bootstrap reload MUTATES TOWARD NATIVE: authdb reconciled to EMPTY, drop-in provisioned empty, state awaiting_config")
    func reloadWhileAwaitingConfigMutatesTowardNative() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let authDB = CountingAuthDB()
        let sudoers = DaemonSudoersReconcileTests.ReconcileSpyProvisioner()
        let stateController = DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil)
        let controller = DaemonController(
            paths: paths,
            machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:])),
            grantStore: NullGrantStore(),
            stateController: stateController,
            integrityLogger: nil,
            decisionLogger: nil,
            pppc: StaticPPPCStatus(ready: true),
            authDB: authDB,
            sudoers: sudoers,
            lastKnownGood: InMemoryLastKnownGoodConfigStore(),
            deviceSerial: "TESTSERIAL",
            now: { CoordinatorFixtures.now }
        )

        await controller.reloadPolicyIfChanged()

        // NOT "touch nothing": the daemon reconciles the authdb to the EMPTY desired
        // set (a RESTORE of any stranded rights) and REMOVES the coarse drop-in.
        // Awaiting-config forces monitor mode, and the drop-in is an ENFORCE-only
        // grant (a non-enforce mode must never leave an enrolled standard user with
        // ungated path-level sudo), so provisioning takes the active-remove path —
        // not apply-empty. This is what cleans up a Mac mutated before its snapshot
        // marker was planted; on a fresh install both are no-ops. It must never
        // APPLY the live policy here.
        #expect(await authDB.reconcileCount == 1)
        #expect(await authDB.lastReconcileProfiles.isEmpty) // restore, not apply
        #expect(await authDB.applyCount == 0)               // authdb is RESTORED, never APPLIED
        #expect(sudoers.applyCount == 0)                    // non-enforce ⇒ never applied
        #expect(sudoers.removeCount == 1)                   // drop-in actively removed
        #expect(await controller.currentDaemonState() == .awaitingConfig)
    }

    @Test("the config lands on a later tick: snapshot persisted, mutations applied, no longer awaiting")
    func configArrivingOnReloadResumesEnforcement() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let authDB = CountingAuthDB()
        let sudoers = DaemonSudoersReconcileTests.ReconcileSpyProvisioner()
        let lkg = InMemoryLastKnownGoodConfigStore()
        let source = MutablePreferencesSource()
        let controller = makeController(
            source: source, paths: paths, authDB: authDB, sudoers: sudoers, lastKnownGood: lkg
        )

        // Tick 1: the pkg is installed, the profile has not landed. Bootstrap
        // mutates TOWARD native — reconcile([]) restores the authdb, and the
        // coarse drop-in is REMOVED (awaiting-config forces monitor, and the
        // drop-in is enforce-only). The reconcile carries the EMPTY set (a
        // restore), not policy.
        await controller.reloadPolicyIfChanged()
        #expect(await controller.currentDaemonState() == .awaitingConfig)
        #expect(await authDB.reconcileCount == 1)
        #expect(await authDB.lastReconcileProfiles.isEmpty)
        #expect(sudoers.removeCount == 1)  // bootstrap removed the drop-in, never applied

        // Tick 2: APNS delivers the (enforce) profile. The policy is now APPLIED.
        source.set([BundleConfig.configDomain: CoordinatorFixtures.enforceableConfig])
        await controller.reloadPolicyIfChanged()

        #expect(await controller.currentDaemonState() != .awaitingConfig)
        #expect(await authDB.reconcileCount == 2)
        #expect(sudoers.applyCount == 1)  // only the enforce tick applied the drop-in
        #expect(lkg.load()?.pamBypass.groups == ["admin"]) // snapshotted for next time
    }

    @Test("profile removed at runtime: the snapshot keeps enforcing (degraded/config_missing), never pass-through")
    func profileRemovedAtRuntimeFallsBackToSnapshot() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let authDB = CountingAuthDB()
        let sudoers = DaemonSudoersReconcileTests.ReconcileSpyProvisioner()
        let lkg = InMemoryLastKnownGoodConfigStore()
        let source = MutablePreferencesSource()
        source.set([BundleConfig.configDomain: CoordinatorFixtures.enforceableConfig])
        let controller = makeController(
            source: source, paths: paths, authDB: authDB, sudoers: sudoers, lastKnownGood: lkg
        )

        await controller.reloadPolicyIfChanged() // configured + snapshotted
        #expect(lkg.exists())

        // The profile is unscoped / removed.
        source.set([:])
        await controller.reloadPolicyIfChanged()

        #expect(await controller.currentDaemonState() == .degraded)
        // Still enforcing from the snapshot, and still mutating: Serberus cannot be
        // switched off by taking its profile away.
        #expect(await authDB.reconcileCount == 2)
        #expect(sudoers.applyCount == 2)
    }

    @Test("bootstrap window: a PAM request while awaiting config re-resolves synchronously and is EVALUATED, not denied")
    func pamRequestInBootstrapWindowReResolvesAndEvaluates() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let source = MutablePreferencesSource()
        let controller = makeController(
            source: source,
            paths: paths,
            authDB: CountingAuthDB(),
            sudoers: DaemonSudoersReconcileTests.ReconcileSpyProvisioner(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore() // no snapshot → genuine bootstrap
        )

        // Tick 1: the pkg is installed, the profile has not landed → awaiting_config.
        await controller.reloadPolicyIfChanged()
        #expect(await controller.currentDaemonState() == .awaitingConfig)

        // The profile lands (config + an allowing echo rule), but the daemon's next
        // poll has NOT fired yet — it is still sitting in awaiting_config.
        let echoProfile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(id: "allow-echo", type: .sudo, action: .allow, description: "t", priority: 10,
                         match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact))]
        )
        let echoJSON = String(decoding: try JSONEncoder().encode(echoProfile), as: UTF8.self)
        source.set([
            BundleConfig.configDomain: CoordinatorFixtures.enforceableConfig,
            BundleConfig.rulesDomain: ["rules_sudo_echo": echoJSON],
        ])

        // pam re-reads the plist each auth, sees enforce + the new bypass, and sends
        // a NON-bypass user here. The daemon must NOT answer from its stale
        // awaiting-config state (which would defensively deny) — it must re-resolve
        // synchronously, adopt the config, and evaluate against the real rule.
        let response = await controller.handlePAM(
            PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: ["hi"], tty: nil))
        )

        #expect(response.decision == .allow)                       // evaluated, not denied
        #expect(await controller.currentDaemonState() != .awaitingConfig) // adopted the config
    }

    @Test("kill switch on reload clears loaded rules AND restores the authdb — matches startup")
    func reloadKillSwitchClearsRulesAndRestoresAuthDB() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let authDB = CountingAuthDB()
        let sudoers = DaemonSudoersReconcileTests.ReconcileSpyProvisioner()
        // The kill switch arrives ALONGSIDE a delivered rule set: without the fix,
        // the reload would leave `profiles` set to that rule (a decision surface
        // that differs from startup's empty `profiles`). It must be cleared.
        let source = DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: ["daemonEnabled": false],
            BundleConfig.rulesDomain: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()],
        ])
        let controller = makeController(
            source: source, paths: paths, authDB: authDB, sudoers: sudoers,
            // A configured Mac (snapshot exists) so the kill switch is genuinely
            // consulted, not the awaiting-config path.
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig())
        )

        await controller.reloadPolicyIfChanged()

        #expect(await controller.currentDaemonState() == .killSwitch)
        // The delivered rules are cleared, so the daemon evaluates NOTHING
        // under a kill switch regardless of arrival path — IDENTICAL to startup,
        // whose StartupOutcome carries profiles:[].
        #expect(await controller.profilesForTesting().isEmpty)
        // Authdb restored to EMPTY and the coarse drop-in removed — the same
        // teardown startup performs.
        #expect(await authDB.reconcileCount == 1)
        #expect(await authDB.lastReconcileProfiles.isEmpty)
        #expect(sudoers.removeCount == 1)
        #expect(sudoers.applyCount == 0) // never grows the drop-in under a kill switch
    }

    @Test("removing a kill-switch profile re-enables enforcement from the prior last-known-good")
    func removingKillSwitchReEnablesFromSnapshot() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let authDB = CountingAuthDB()
        let sudoers = DaemonSudoersReconcileTests.ReconcileSpyProvisioner()
        // A previously-configured Mac: the snapshot is enforce + admin break-glass.
        let lkg = InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig())
        let source = MutablePreferencesSource()

        // A kill switch is delivered on top.
        source.set([BundleConfig.configDomain: ["daemonEnabled": false]])
        let controller = makeController(
            source: source, paths: paths, authDB: authDB, sudoers: sudoers, lastKnownGood: lkg
        )
        await controller.reloadPolicyIfChanged()
        #expect(await controller.currentDaemonState() == .killSwitch)
        #expect(await controller.profilesForTesting().isEmpty)

        // The kill-switch profile is removed. With no delivered config but a
        // snapshot present, the daemon falls back to the last-known-good and
        // ENFORCES again (degraded/config_missing) — it does not stay disabled.
        source.set([:])
        await controller.reloadPolicyIfChanged()
        #expect(await controller.currentDaemonState() == .degraded)
        // Back to enforcing the snapshot's break-glass.
        #expect(sudoers.applyCount == 1) // the drop-in is (re)provisioned from the snapshot
    }

    @Test("retryLastKnownGoodSaveIfNeeded re-attempts and succeeds once the store recovers")
    func lkgSaveRetriedAfterStoreRecovers() async throws {
        struct BoomError: Error {}
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let lkg = InMemoryLastKnownGoodConfigStore(saveError: BoomError())
        let source = DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: CoordinatorFixtures.enforceableConfig,
        ])
        let controller = makeController(
            source: source, paths: paths, authDB: CountingAuthDB(),
            sudoers: DaemonSudoersReconcileTests.ReconcileSpyProvisioner(), lastKnownGood: lkg
        )

        // Tick 1: config present & enforceable, but every save throws. The daemon
        // still ADOPTS and enforces — the marker file is just not planted yet.
        await controller.reloadPolicyIfChanged()
        #expect(!lkg.exists())
        #expect(lkg.saveCount >= 1)
        #expect(await controller.currentDaemonState() != .awaitingConfig)

        // The store recovers (disk space freed, directory created).
        lkg.setSaveError(nil)

        // Tick 2: retryLastKnownGoodSaveIfNeeded runs every tick INDEPENDENTLY of the
        // change gate (the config is unchanged, so resolve() would not re-run) and
        // now plants the marker the configured-Mac contract depends on.
        await controller.reloadPolicyIfChanged()
        #expect(lkg.exists())
        #expect(lkg.load()?.pamBypass.groups == ["admin"])
    }

    @Test("genuine bootstrap (no config on re-resolve): a PAM request is defensively denied, still awaiting")
    func pamRequestStillBootstrapIsDefensivelyDenied() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let source = MutablePreferencesSource() // stays empty: no config ever lands
        let controller = makeController(
            source: source,
            paths: paths,
            authDB: CountingAuthDB(),
            sudoers: DaemonSudoersReconcileTests.ReconcileSpyProvisioner(),
            lastKnownGood: InMemoryLastKnownGoodConfigStore()
        )

        await controller.reloadPolicyIfChanged()
        #expect(await controller.currentDaemonState() == .awaitingConfig)

        // In real bootstrap pam PAM_IGNOREs and never reaches the daemon; if it does
        // reach us and there is STILL no usable config, we fail closed (deny), never
        // monitor-mode pass-through (which the daemon cannot emit anyway).
        let response = await controller.handlePAM(
            PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: [], tty: nil))
        )
        #expect(response.decision == .deny)
        #expect(await controller.currentDaemonState() == .awaitingConfig)
    }

    @Test("a snapshot deleted while it is being served re-resolves on the next tick (nothing else changed)")
    func deletedSnapshotReResolves() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let snapshot = dir.appendingPathComponent("last-known-good-config.plist")
        let lkg = LastKnownGoodConfigStore(url: snapshot, requiredOwnerUID: getuid())
        try lkg.save(CoordinatorFixtures.lastKnownGoodConfig())
        let controller = makeController(
            source: MutablePreferencesSource(),   // no profile: the snapshot is served
            paths: paths,
            authDB: CountingAuthDB(),
            sudoers: DaemonSudoersReconcileTests.ReconcileSpyProvisioner(),
            lastKnownGood: lkg
        )

        await controller.reloadPolicyIfChanged()
        #expect(await controller.currentDaemonState() != .awaitingConfig)

        try FileManager.default.removeItem(at: snapshot)
        await controller.reloadPolicyIfChanged()
        #expect(await controller.currentDaemonState() == .awaitingConfig)
    }
}

enum TestGrants {
    static func make(
        user: String = "alice",
        expiresAt: Date? = CoordinatorFixtures.now.addingTimeInterval(600)
    ) -> Grant {
        Grant(
            user: user, uid: 501, ruleID: "allow-brew", profileKey: "rules_sudo_test",
            teamID: "", binaryHash: "aa", canonicalPath: "/opt/homebrew/bin/brew",
            grantedAt: CoordinatorFixtures.now, expiresAt: expiresAt, policyVersion: "1.0.0"
        )
    }
}
