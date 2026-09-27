import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// Regression coverage for two reconcile-side properties of the IdP-group
/// enrollment sudo path:
///
/// - **Signature gating** — the policy signature is committed only AFTER the fallible sudoers
///   side-effect succeeds, so a failed *shrink* (de-enroll / kill-switch removal
///   that kept the prior-good file) leaves the signature STALE and is retried on
///   the next reload tick, rather than latching a removed user as authorized.
/// - **Serialization** — coarse-drop-in provisioning is serialized (latest-wins), so the
///   reentrant console-user watch and the 30s reload loop cannot land two
///   overlapping apply/remove calls (a stale write racing a fresher one).
@Suite("Daemon sudoers reconcile (signature gating + serialization)", .serialized)
struct DaemonSudoersReconcileTests {

    // MARK: - Test doubles

    /// A ``SudoersProvisioning`` whose apply/remove results are dialable and whose
    /// call counts are observable — so a *failed* side-effect can be simulated and
    /// the reload loop's retry behavior verified.
    final class ReconcileSpyProvisioner: SudoersProvisioning, @unchecked Sendable {
        private let lock = NSLock()
        private var _applyResult: Bool
        private var _removeResult: Bool
        private var _applyCount = 0
        private var _removeCount = 0
        private var _lastApplyEnrollment: SerberusConfig.SudoEnrollment?
        private var _lastApplyProfiles: [RuleProfile] = []

        init(applyResult: Bool = true, removeResult: Bool = true) {
            _applyResult = applyResult
            _removeResult = removeResult
        }

        var applyCount: Int { read { _applyCount } }
        var removeCount: Int { read { _removeCount } }
        /// The enrollment/profiles handed to the MOST RECENT apply — so a test can
        /// prove the awaiting-config path applies an EMPTY enrollment (which the real
        /// generator turns into a drop-in REMOVAL) rather than the live enrollment.
        var lastApplyEnrollment: SerberusConfig.SudoEnrollment? { read { _lastApplyEnrollment } }
        var lastApplyProfiles: [RuleProfile] { read { _lastApplyProfiles } }

        func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool {
            recordApply(profiles: profiles, enrollment: enrollment)
        }

        func remove() async -> Bool {
            recordRemove()
        }

        // Synchronous critical sections — NSLock is `noasync` under Swift 6, and
        // none of these mutations ever await (mirrors MockSudoersInstaller).
        private func recordApply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) -> Bool {
            lock.lock(); defer { lock.unlock() }
            _applyCount += 1
            _lastApplyProfiles = profiles
            _lastApplyEnrollment = enrollment
            return _applyResult
        }

        private func recordRemove() -> Bool {
            lock.lock(); defer { lock.unlock() }
            _removeCount += 1
            return _removeResult
        }

        private func read<T>(_ body: () -> T) -> T {
            lock.lock(); defer { lock.unlock() }
            return body()
        }
    }

    /// A ``SudoersProvisioning`` that records max in-flight concurrency across
    /// apply calls and holds the FIRST apply on a gate, so a second, reentrant
    /// provisioning pass can be launched while the first is suspended — proving
    /// the serialization never lets the two overlap.
    final class ConcurrencyProbeProvisioner: SudoersProvisioning, @unchecked Sendable {
        private let lock = NSLock()
        private var _inFlight = 0
        private var _maxConcurrent = 0
        private var _applyCount = 0
        let firstEntered = Gate()
        let release = Gate()

        var maxConcurrent: Int { read { _maxConcurrent } }
        var applyCount: Int { read { _applyCount } }

        func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool {
            let n = enter()
            if n == 1 {
                // The first pass announces it is in apply, then blocks until the
                // test releases it — a window in which a reentrant pass could,
                // absent serialization, start its own apply.
                await firstEntered.open()
                await release.wait()
            }
            leave()
            return true
        }

        func remove() async -> Bool { true }

        // Synchronous critical sections — see the note on ReconcileSpyProvisioner.
        private func enter() -> Int {
            lock.lock(); defer { lock.unlock() }
            _applyCount += 1
            _inFlight += 1
            _maxConcurrent = max(_maxConcurrent, _inFlight)
            return _applyCount
        }

        private func leave() {
            lock.lock(); defer { lock.unlock() }
            _inFlight -= 1
        }

        private func read<T>(_ body: () -> T) -> T {
            lock.lock(); defer { lock.unlock() }
            return body()
        }
    }

    /// A minimal one-shot gate for coordinating the concurrency probe.
    actor Gate {
        private var opened = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func wait() async {
            if opened { return }
            await withCheckedContinuation { waiters.append($0) }
        }
        func open() {
            guard !opened else { return }
            opened = true
            let resume = waiters
            waiters.removeAll()
            for continuation in resume { continuation.resume() }
        }
    }

    // MARK: - Fixtures

    private func makeController(
        sudoers: SudoersProvisioning,
        source: PreferencesSource,
        paths: DaemonPaths
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
            authDB: NoopAuthorizationDBApplier(),
            sudoers: sudoers,
            // A configured Mac (a snapshot exists), so provisioning is NOT gated
            // off by the awaiting-config contract — these tests are about signature gating and serialization.
            lastKnownGood: InMemoryLastKnownGoodConfigStore(
                initial: CoordinatorFixtures.lastKnownGoodConfig()
            ),
            deviceSerial: "TESTSERIAL",
            now: { CoordinatorFixtures.now }
        )
    }

    private func enabledConfig() -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: .enforce, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60, pamBypass: PAMBypass()
        )
    }

    /// A daemon-enabled config in a NON-enforcing mode WITH a real enrollment —
    /// the exact shape that used to hand an enrolled standard user ungated
    /// path-level sudo. `mode` is `.monitor` or `.audit`.
    private func nonEnforcingEnrolledConfig(_ mode: EnforcementMode) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60,
            pamBypass: PAMBypass(groups: ["admin"]),
            sudoEnrollment: SerberusConfig.SudoEnrollment(users: ["standarduser"])
        )
    }

    /// An enrolled sudo profile — in `.enforce` this WOULD be applied; the point
    /// of the monitor/audit tests is that it is NOT, despite being present.
    private func curatedSudoProfile() -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: "rules_sudo_jamf", profilePriority: 50,
                    rules: [Rule(id: "recon", type: .sudo, action: .allow, description: "jamf recon",
                                 priority: 50,
                                 match: MatchCriteria(commandPattern: "/usr/local/bin/jamf",
                                                      argPattern: "^recon$", matchType: .exact))])
    }

    // MARK: - Monitor/audit must NOT grant coarse sudo (observe-only)

    @Test("monitor mode REMOVES the coarse drop-in even with an enrolled user + sudo rule (never grants ungated sudo)")
    func monitorModeRemovesCoarseDropIn() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let spy = ReconcileSpyProvisioner()
        let controller = makeController(
            sudoers: spy, source: DictionaryPreferencesSource(domains: [:]),
            paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(profiles: [curatedSudoProfile()],
                                              config: nonEnforcingEnrolledConfig(.monitor))
        await controller.provisionSudoersForTesting()
        // The fine gate (pam_serberus) passes through in monitor, so the coarse
        // path-only drop-in must never be written — it would be ungated sudo.
        #expect(spy.applyCount == 0)
        #expect(spy.removeCount == 1)
    }

    @Test("audit mode also REMOVES the coarse drop-in (no ungated grant)")
    func auditModeRemovesCoarseDropIn() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let spy = ReconcileSpyProvisioner()
        let controller = makeController(
            sudoers: spy, source: DictionaryPreferencesSource(domains: [:]),
            paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(profiles: [curatedSudoProfile()],
                                              config: nonEnforcingEnrolledConfig(.audit))
        await controller.provisionSudoersForTesting()
        #expect(spy.applyCount == 0)
        #expect(spy.removeCount == 1)
    }

    @Test("enforce mode DOES provision the coarse drop-in (baseline — the gate only strips non-enforce)")
    func enforceModeProvisionsCoarseDropIn() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let spy = ReconcileSpyProvisioner()
        let controller = makeController(
            sudoers: spy, source: DictionaryPreferencesSource(domains: [:]),
            paths: DaemonPaths.ephemeral(in: dir))
        var enforce = nonEnforcingEnrolledConfig(.monitor)
        enforce = enforce.withEnforcementMode(.enforce)
        await controller.loadPolicyForTesting(profiles: [curatedSudoProfile()], config: enforce)
        await controller.provisionSudoersForTesting()
        #expect(spy.applyCount == 1)
        #expect(spy.removeCount == 0)
        #expect(spy.lastApplyEnrollment?.users == ["standarduser"])
    }

    @Test("switching enforce → monitor removes a previously-provisioned drop-in")
    func enforceToMonitorTransitionRemoves() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let spy = ReconcileSpyProvisioner()
        let controller = makeController(
            sudoers: spy, source: DictionaryPreferencesSource(domains: [:]),
            paths: DaemonPaths.ephemeral(in: dir))
        // Enforce first — drop-in applied.
        await controller.loadPolicyForTesting(
            profiles: [curatedSudoProfile()],
            config: nonEnforcingEnrolledConfig(.monitor).withEnforcementMode(.enforce))
        await controller.provisionSudoersForTesting()
        // Then the admin flips the profile to monitor — the drop-in must go.
        await controller.loadPolicyForTesting(profiles: [curatedSudoProfile()],
                                              config: nonEnforcingEnrolledConfig(.monitor))
        await controller.provisionSudoersForTesting()
        #expect(spy.applyCount == 1)   // only the enforce pass applied
        #expect(spy.removeCount == 1)  // the monitor pass removed
    }

    // MARK: - Failed shrink retried (signature stays stale on failure)

    @Test("a FAILED apply leaves the signature stale — the next reload tick retries it")
    func failedApplyIsRetried() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        // daemonEnabled defaults true → the reload takes the apply (grow/shrink) path.
        let source = DictionaryPreferencesSource(domains: [:])
        let spy = ReconcileSpyProvisioner(applyResult: false) // the write keeps failing
        let controller = makeController(sudoers: spy, source: source, paths: DaemonPaths.ephemeral(in: dir))

        // Two ticks over an UNCHANGED policy: because provisioning fails, the
        // signature is never committed, so the second tick re-enters and retries.
        await controller.reloadPolicyIfChanged()
        await controller.reloadPolicyIfChanged()
        #expect(spy.applyCount == 2) // retried, not latched
    }

    @Test("a SUCCESSFUL apply commits the signature — an unchanged policy is not re-applied")
    func successfulApplyIsNotRetried() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = DictionaryPreferencesSource(domains: [:])
        let spy = ReconcileSpyProvisioner(applyResult: true)
        let controller = makeController(sudoers: spy, source: source, paths: DaemonPaths.ephemeral(in: dir))

        await controller.reloadPolicyIfChanged() // enters, provisions, commits signature
        await controller.reloadPolicyIfChanged() // signature unchanged → no-op
        #expect(spy.applyCount == 1)
    }

    @Test("a FAILED kill-switch removal leaves the signature stale — the shrink is retried")
    func failedKillSwitchRemovalIsRetried() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        // daemonEnabled=false → the reload takes the kill-switch REMOVE path.
        let source = DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: ["daemonEnabled": false]
        ])
        let spy = ReconcileSpyProvisioner(removeResult: false) // the removal keeps failing
        let controller = makeController(sudoers: spy, source: source, paths: DaemonPaths.ephemeral(in: dir))

        await controller.reloadPolicyIfChanged()
        await controller.reloadPolicyIfChanged()
        // The drop-in must never outlive the fine gate; a failed removal is retried.
        #expect(spy.removeCount == 2)
    }

    @Test("a SUCCESSFUL kill-switch removal commits the signature — not re-attempted")
    func successfulKillSwitchRemovalIsNotRetried() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: ["daemonEnabled": false]
        ])
        let spy = ReconcileSpyProvisioner(removeResult: true)
        let controller = makeController(sudoers: spy, source: source, paths: DaemonPaths.ephemeral(in: dir))

        await controller.reloadPolicyIfChanged()
        await controller.reloadPolicyIfChanged()
        #expect(spy.removeCount == 1)
    }

    // MARK: - Serialization (no stale write from reentrant provisioning)

    @Test("reentrant provisioning is serialized — no two apply passes ever overlap")
    func reentrantProvisioningIsSerialized() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let probe = ConcurrencyProbeProvisioner()
        let controller = makeController(
            sudoers: probe,
            source: DictionaryPreferencesSource(domains: [:]),
            paths: DaemonPaths.ephemeral(in: dir))
        // daemonEnabled true + idpSource disabled → provisioning calls apply.
        await controller.loadPolicyForTesting(profiles: [], config: enabledConfig())

        // Pass 1 enters apply and blocks on the release gate.
        async let first: Bool = controller.provisionSudoersForTesting()
        await probe.firstEntered.wait()

        // Pass 2 arrives WHILE pass 1 is suspended in apply (the reentrancy the
        // console-user watch vs reload loop produces). If unserialized it would
        // start its own apply now; serialized, it must wait behind pass 1.
        async let second: Bool = controller.provisionSudoersForTesting()
        try? await Task.sleep(for: .milliseconds(150))
        #expect(probe.applyCount == 1) // pass 2 has NOT started its apply

        // Release pass 1; pass 2 then runs to completion after it.
        await probe.release.open()
        _ = await first
        _ = await second
        #expect(probe.applyCount == 2)    // both ran…
        #expect(probe.maxConcurrent == 1) // …but never concurrently (no stale overlap)
    }
}
