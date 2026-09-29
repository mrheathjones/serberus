import CryptoKit
import Darwin
import Foundation
import PrivMgrCore
import SystemConfiguration

/// Top-level daemon orchestrator: startup sequence and health monitoring.
///
/// Owns the startup sequence, the live XPC serving surface, and the health
/// monitor. It is the production ``DaemonQuerying`` implementation; XPC
/// callers reach it (after audit-token validation) through ``XPCMessageRouter``.
///
/// The orchestration here is deliberately thin — every non-trivial decision
/// lives in a separately unit-tested component (``StartupCoordinator``,
/// ``DaemonStateController``, ``HealthMonitor``, ``XPCMessageRouter``).
public actor DaemonController {
    private let paths: DaemonPaths
    private let machServiceName: String
    private let prefsReader: ManagedPreferencesReader
    private let grantStore: GrantMaintaining
    private let stateController: DaemonStateController
    private let integrityLogger: IntegrityLogger?
    private let decisionLogger: DecisionLogger?
    /// Fleet telemetry: rewrites `fleet-summary.plist` from the decision
    /// log + active grants on each reload tick (nil = telemetry disabled).
    private let fleetSummaryWriter: FleetSummaryWriter?
    /// Debug telemetry: writes the per-device recent denial/prompt event list
    /// locally always, and to the EA path only while `debugModeEnabled` is on.
    private let recentEventsWriter: RecentEventsWriter?
    /// Prunes `decisions-*.jsonl` past the retention window on the same tick, so
    /// the "today + yesterday" summary read stays cheap and disk stays bounded.
    private let logRotator: LogRotator
    private let pppc: PPPCStatusChecking
    private let authDB: AuthorizationDBApplying
    /// Provisions the coarse `/etc/sudoers.d/serberus` drop-in. Non-fatal by
    /// contract — a failure here never degrades daemon state.
    private let sudoers: SudoersProvisioning
    /// Verifies `/etc/pam.d/sudo_local` routes sudo through `pam_serberus`
    /// before the coarse drop-in is written (the drop-in must never outlive the
    /// PAM gate). Production: ``FilesystemPAMGateVerifier``.
    private let pamGate: PAMGateVerifying
    /// True when the last provisioning pass WANTED the drop-in (enforce) but
    /// withheld it because the PAM gate failed verification — reported as
    /// `degraded(pam_not_wired)`.
    private var pamGateBlocked = false
    /// Last PAM-gate verdict seen by provisioning, so the integrity event fires
    /// on a CHANGE rather than on every pass.
    private var lastPAMGateStatus: PAMGateStatus?
    /// Last-known-good config snapshot: written whenever a present + safely
    /// enforceable config is adopted, read back when the profile is absent or
    /// unsafe. See ``EffectiveConfigResolver``.
    private let lastKnownGood: any LastKnownGoodConfigStoring
    /// The persisted wall-clock high-water mark (``ClockRollbackGuard``).
    private let clockHighWater: WallClockHighWaterStoring
    /// Which daemon build ran last, and this one's identity
    /// (``DaemonBuildIdentity``). nil identity: upgrade detection is off.
    private let buildMarker: DaemonBuildMarkerStoring?
    private let buildIdentity: String?
    /// Removes a deleted JIT account's leftovers from `admin`.
    private let staleAdminScrubber: StaleAdminEntryScrubbing
    private let evaluator: PAMEvaluator
    private let deviceSerial: String
    private let version: DaemonVersion
    private let exitProcess: @Sendable (Int32) -> Void
    private let now: @Sendable () -> Date

    private var config: SerberusConfig
    private var profiles: [RuleProfile]
    private var promptsConfig = PromptsConfig()
    private var jitPolicy: JITAdminPolicy = .disabledDefault
    /// Short-lived sudo session cache: allow decisions whose TTL
    /// came from the matched rule's resolved `cacheSeconds`. Enforce-mode
    /// only; cleared on policy reload, kill switch, and grant revocation.
    private let sessionCache = SessionGrantCache()
    private var listener: XPCListenerService?
    private var healthMonitor: HealthMonitor?
    private var sentinelPushService: SentinelPushService?
    private var esfMonitor: ESFMonitor?
    private var jitManager: JITAdminManager?
    /// Local `admin` membership, checked live for the JIT managers and the
    /// `native` decision. Production: ``DirectoryServicesGroupController``.
    private let membership: GroupMembershipControlling
    /// Deletes sudo tickets when an elevation ends and when gating resumes.
    /// Production: ``SudoTimestampDirectory``; the default clears nothing.
    private let sudoTickets: SudoTicketClearing
    /// Follows Jamf Connect / Self Service+ elevations in the unified log; runs
    /// only while the JIT provider is `jamf_connect` and Serberus is on. nil
    /// disables it (unit tests that do not inject one).
    private let jamfConnectObserver: JamfConnectElevationObserving?
    /// Whether the last adopted config made pam_serberus gate sudo (enforce,
    /// on, configured). nil until the first config is adopted, so the first
    /// adoption counts as a transition too.
    private var sudoGatingActive: Bool?
    /// The in-flight wall-clock JIT expiry sweep (``JITAdminManager/expireOverdue()``)
    /// scheduled from the reload tick; at most one at a time.
    private var jitOverdueSweep: Task<Void, Never>?
    /// Resolves `pamBypass` entries each tick (break-glass resolvability). Production:
    /// ``LocalBypassResolver``; the default treats every entry as resolvable.
    private let bypassResolver: BypassResolving
    /// Result of the last break-glass resolvability check (delivered and served
    /// config, ``EffectiveConfig/bypassUnresolvable``), reported as
    /// `degraded(bypass_unresolvable)`.
    private var bypassUnresolvable = false
    /// Watches the managed config plist so an MDM change (notably a switch away
    /// from enforce) is adopted immediately instead of on the next 30s tick.
    private var managedConfigWatch: ManagedConfigWatch?
    /// Result of this reload pass's leaving-enforce drop-in removal, consumed by the
    /// pass's own provisioning (which would otherwise remove a second time).
    private var earlyDropInRemoval: Bool?
    /// Directory the managed-config watch observes (`/Library/Managed Preferences`
    /// in production; nil disables the watch, e.g. in unit tests).
    private let managedConfigWatchDirectory: String?
    /// Managed-preferences reload loop + last-seen policy fingerprint, so the
    /// daemon picks up MDM-delivered rule/config/JIT changes without a restart.
    private var policyReloadTask: Task<Void, Never>?
    private var lastPolicySignature = 0
    /// Seconds between managed-preferences change checks.
    private let policyReloadIntervalSeconds: UInt64
    /// Wall-clock budget for ONE reload pass before the watchdog declares it
    /// stalled and abandons it. Deliberately generous — the worst legitimate pass
    /// is on the order of 15s (`visudo` alone is allowed 10s, see
    /// ``SudoersManager``) — because a false stall costs a restart.
    private let reloadDeadlineSeconds: TimeInterval
    /// Consecutive stalled ticks tolerated before the daemon exits for a launchd
    /// restart. At the default 30s interval that is ~3 minutes of policy drift.
    private let maxConsecutiveReloadStalls: Int
    /// True from the moment a reload pass starts until it completes — INCLUDING a
    /// pass that completed late, after its deadline. The watchdog's leak guard:
    /// while set, no new pass starts, so a permanent wedge leaks exactly one
    /// abandoned task rather than one per tick.
    private var reloadPassOutstanding = false
    /// Stalled ticks since the last healthy pass. Reset by any completed pass.
    private var consecutiveReloadStalls = 0
    /// When the outstanding reload pass started (continuous clock). A tick that
    /// finds a pass still running counts as a stall only once the pass is older
    /// than ``reloadDeadlineSeconds``; a younger one is simply still working.
    private var reloadPassStartedAt: ContinuousClock.Instant?
    /// A managed-config change arrived while a pass was running. The pass may
    /// have read the config before the change landed, so one more pass runs as
    /// soon as it completes instead of the change waiting for the next tick.
    private var reloadRerunRequested = false
    /// A stall was reported. The next pass runs in full and publishes its
    /// state even when the policy signature did not move, so a
    /// `degraded(reload_stalled)` never outlives the stall.
    private var publishAfterStall = false
    /// The last AuthorizationDB reconcile outside the kill switch, at startup
    /// or on a reload, failed: some right or composition of the served policy
    /// is not applied. Each reload tick whose policy signature did not move
    /// re-runs only that reconcile (``retryAuthDBReconcile()``) until it
    /// succeeds. A pass that runs in full reconciles anyway and resets this
    /// from its own result.
    private var authDBNotFullyApplied = false
    /// The failure the AuthorizationDB was last logged with, so a retry that
    /// fails the same way every tick is logged at error level only once.
    private var lastAuthDBFailure: String?
    /// What the state was last resolved from, at startup or on a reload. A
    /// retry that succeeds re-resolves from it, without the AuthorizationDB
    /// failure.
    private var lastStateInputs = StartupCoordinator.StateInputs()
    /// The last-known-good snapshot problem last logged, so a snapshot that
    /// stops (or starts) passing its file checks is logged once per change.
    private var lastSnapshotProblem: String?
    /// Live `log show` polls currently running on behalf of Sentinel tailers
    /// (Authorizations view + Capture); capped by ``maxInFlightLogPolls``.
    private var inFlightLogPolls = 0
    /// Set once the stall escalation has asked launchd for a restart, so the
    /// request is made exactly once. In production ``exitProcess`` ends the
    /// process here; the flag makes the injected test seam deterministic.
    private var reloadRestartRequested = false
    /// The console-user names most recently enrolled via IdP-group enrollment
    /// (``IDPGroupResolver``). Tracked so a drop-out (logout / state-file change /
    /// tamper) is logged as an `idp-resolve.revoked` and so the coarse drop-in
    /// shrinks on the next rebuild. Only ever `[]` or `[consoleUser.name]`.
    private var lastResolvedIDPUsers: [String] = []
    /// True while this Mac has never held a usable config AND has no snapshot file
    /// (``DaemonState/awaitingConfig``). While set, the daemon enforces nothing
    /// (``config`` is the canonical EMPTY config, `monitor`) but still mutates TOWARD
    /// the native state — authdb reconciled to empty (restore) and the sudoers
    /// drop-in removed — so a Mac mutated before its snapshot marker was planted is
    /// cleaned up. Cleared the moment a usable config (or snapshot) is available.
    private var awaitingConfig = false
    /// Cached debug-telemetry gate, refreshed on each telemetry tick. While set,
    /// `handlePAM` captures the (redacted) argv into the logged denial/prompt so
    /// the debug event list can show the full attempted command — never when off.
    private var debugModeEnabled = false
    /// The (un)installer the app-management handlers use. Production uses the real
    /// types; a test injects a fake command runner. Internal so `@testable` tests
    /// can swap them.
    var softwareInstaller = SoftwareInstaller()
    var softwareUninstaller = SoftwareUninstaller()
    /// Live `State:/Users/ConsoleUser` subscription (IdP-group enrollment follows a login at once). Started
    /// in ``start()``, torn down in `deinit`. `nil` when unstarted / unavailable.
    private var consoleUserWatch: ConsoleUserWatch?
    /// Serial provisioning chain. Every coarse-drop-in apply/remove is
    /// appended here so passes never overlap (latest-wins): the reentrant
    /// console-user watch and the 30s reload loop can both call
    /// ``provisionSudoers()`` without a stale write landing after a fresher one.
    private var provisioningChain: Task<Bool, Never>?
    /// Wall-clock budget for the (off-actor) IdP state-file read. A read that
    /// exceeds this fails safe (no enrollment) rather than pinning provisioning.
    private static let idpReadTimeoutSeconds: TimeInterval = 4

    /// Live JIT policy for the manager's policy provider (read on each request,
    /// so a reloaded policy takes effect without recreating the manager).
    func liveJITPolicy() -> JITAdminPolicy { jitPolicy }

    /// Whether a JIT promotion may still go ahead: false under the kill switch.
    /// The manager asks this again right before promoting, because the kill
    /// switch can arrive while a request waits on the directory.
    func jitPromotionPermitted() -> Bool { config.daemonEnabled }

    public init(
        paths: DaemonPaths,
        machServiceName: String,
        prefsReader: ManagedPreferencesReader,
        grantStore: GrantMaintaining,
        stateController: DaemonStateController,
        integrityLogger: IntegrityLogger?,
        decisionLogger: DecisionLogger? = nil,
        fleetSummaryWriter: FleetSummaryWriter? = nil,
        recentEventsWriter: RecentEventsWriter? = nil,
        logRotator: LogRotator? = nil,
        pppc: PPPCStatusChecking,
        authDB: AuthorizationDBApplying,
        sudoers: SudoersProvisioning = NoopSudoersProvisioner(),
        pamGate: PAMGateVerifying = AssumeWiredPAMGate(),
        bypassResolver: BypassResolving = AssumeResolvableBypass(),
        membership: GroupMembershipControlling = DirectoryServicesGroupController(),
        sudoTickets: SudoTicketClearing = NoopSudoTicketClearer(),
        jamfConnectObserver: JamfConnectElevationObserving? = nil,
        managedConfigWatchDirectory: String? = nil,
        lastKnownGood: any LastKnownGoodConfigStoring = LastKnownGoodConfigStore(),
        clockHighWater: WallClockHighWaterStoring? = nil,
        buildMarker: DaemonBuildMarkerStoring? = nil,
        buildIdentity: String? = nil,
        staleAdminScrubber: StaleAdminEntryScrubbing = NoopStaleAdminEntryScrubber(),
        inspector: BinaryIdentityInspecting = BinaryIdentityInspector(),
        deviceSerial: String = "UNKNOWN",
        version: DaemonVersion = .current,
        exitProcess: @escaping @Sendable (Int32) -> Void = { exit($0) },
        policyReloadIntervalSeconds: UInt64 = 30,
        reloadDeadlineSeconds: TimeInterval = 60,
        maxConsecutiveReloadStalls: Int = 3,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.paths = paths
        self.machServiceName = machServiceName
        self.prefsReader = prefsReader
        self.grantStore = grantStore
        self.stateController = stateController
        self.integrityLogger = integrityLogger
        self.decisionLogger = decisionLogger
        self.fleetSummaryWriter = fleetSummaryWriter
        self.recentEventsWriter = recentEventsWriter
        self.logRotator = logRotator ?? LogRotator(directory: paths.logDirectory)
        self.pppc = pppc
        self.authDB = authDB
        self.sudoers = sudoers
        self.pamGate = pamGate
        self.bypassResolver = bypassResolver
        self.membership = membership
        self.sudoTickets = sudoTickets
        self.jamfConnectObserver = jamfConnectObserver
        self.managedConfigWatchDirectory = managedConfigWatchDirectory
        self.lastKnownGood = lastKnownGood
        self.clockHighWater = clockHighWater ?? WallClockHighWaterMark(
            url: paths.supportDirectory.appendingPathComponent(WallClockHighWaterMark.fileName))
        self.buildMarker = buildMarker
        self.buildIdentity = buildIdentity
        self.staleAdminScrubber = staleAdminScrubber
        self.evaluator = PAMEvaluator(inspector: inspector)
        self.deviceSerial = deviceSerial
        self.version = version
        self.exitProcess = exitProcess
        self.policyReloadIntervalSeconds = policyReloadIntervalSeconds
        self.reloadDeadlineSeconds = reloadDeadlineSeconds
        self.maxConsecutiveReloadStalls = maxConsecutiveReloadStalls
        self.now = now
        self.config = Self.makeFailSafeConfig()
        self.profiles = []
    }

    deinit {
        // Detach the SCDynamicStore dispatch queue so no callback fires against
        // a torn-down actor. Safe from the nonisolated deinit: `ConsoleUserWatch`
        // is `Sendable` and `stop()` only touches its own CF state.
        consoleUserWatch?.stop()
        managedConfigWatch?.stop()
    }

    // MARK: Startup

    /// Runs the full startup sequence and brings the daemon up.
    public func start() async {
        ensureDirectories()
        // Clear install staging / temp-app leftovers a previous instance
        // couldn't remove (nothing is in flight yet).
        softwareInstaller.sweepStaleStaging()
        await emitIntegrity(.daemonStart, "serberusd \(version.daemonVersion) starting")

        // Before anything reads a grant (the listener below serves PAM): undo
        // every timed grant if the wall clock was set back while the daemon was
        // not running, then give each live timed row a continuous-clock
        // deadline in this boot session.
        await enforceClockHighWaterMark()
        await restampContinuousDeadlines()
        await stampJITGeneratedUIDs()

        // The push service owns in-flight prompts; the listener needs it
        // to answer PAM polls and to register the Sentinel peer.
        let sentinelPushService = SentinelPushService(now: now)
        self.sentinelPushService = sentinelPushService

        // The XPC listener comes up early so PAM can reach the daemon
        // even while it is degraded or pending.
        let listener = XPCListenerService(
            machServiceName: machServiceName,
            router: XPCMessageRouter(daemon: self),
            sentinelPushService: sentinelPushService
        )
        listener.start()
        self.listener = listener

        // Preflight, then load config/grants/profiles, apply authdb, resolve state.
        let coordinator = StartupCoordinator(
            prefsReader: prefsReader,
            grantStore: grantStore,
            pppc: pppc,
            authDB: authDB,
            lastKnownGood: lastKnownGood,
            bypassResolver: bypassResolver,
            now: now
        )
        let outcome = await coordinator.run()
        bypassUnresolvable = outcome.bypassUnresolvable
        config = outcome.config
        (authDB as? AuthorizationDBEffectiveConfigReceiving)?.adoptEffectiveConfig(config)
        profiles = outcome.profiles
        awaitingConfig = outcome.awaitingConfig
        for note in outcome.notes {
            DaemonLog.integrity.notice("startup: \(note, privacy: .public)")
        }
        warnUnresolvableSudoPatterns()
        await alignGrantsWithPolicy(context: "startup")

        // Prompts domain (justification minimum). Read like every other
        // managed domain; invalid values fall back to spec defaults.
        let promptsResult = prefsReader.readPrompts()
        promptsConfig = promptsResult.value
        for finding in promptsResult.findings {
            DaemonLog.integrity.notice("prompts config: \(finding.localizedDescription, privacy: .public)")
        }

        // JIT local-admin policy + manager. Read like every other managed
        // domain; the manager reconciles any admin membership left over from a
        // window that outlived the previous daemon instance.
        let jitResult = prefsReader.readJITAdmin()
        jitPolicy = jitResult.value
        for finding in jitResult.findings {
            DaemonLog.integrity.notice("jit policy: \(finding.localizedDescription, privacy: .public)")
        }
        let manager = JITAdminManager(
            // Read the live policy so an MDM-delivered JIT change takes effect on
            // the next request without recreating the manager.
            policyProvider: { [weak self] in await self?.liveJITPolicy() ?? .disabledDefault },
            membership: membership,
            grantStore: grantStore,
            decisionLogger: decisionLogger,
            integrityLogger: integrityLogger,
            deviceSerial: deviceSerial,
            version: version,
            // NullGrantStore = the SQLite store could not be opened
            // (grants_db_error): JIT is refused outright, since a promotion
            // whose grant cannot be persisted can never be demoted.
            grantStoreDegraded: grantStore is NullGrantStore,
            now: now,
            promotionPermitted: { [weak self] in await self?.jitPromotionPermitted() ?? false },
            ticketClearer: sudoTickets,
            adminGroupScrubber: staleAdminScrubber
        )
        jitManager = manager
        await settleJITAdminsAtStartup(manager)
        noteSudoGatingPosture()
        await updateJamfConnectObserver()

        // Coarse sudoers drop-in: provision the curated allowlist for enrolled
        // standard users (or remove it under the kill switch). Non-fatal and
        // off the resolveState path — a failure keeps the prior-good file and
        // never degrades the daemon.
        //
        // Runs even while awaiting config (bootstrap). There, `config` is the
        // canonical EMPTY effective config (no enrollment), so provisioning REMOVES
        // any drop-in rather than writing one — the "mutate toward native" cleanup
        // for a Mac that was mutated before its snapshot marker was planted. On a
        // fresh install this is a no-op (no drop-in to remove).
        let initialProvisioned = await provisionSudoers()

        // Publish state, then start the health monitor. The PAM
        // gate is only known after provisioning ran, so it is overlaid here with
        // the same precedence the reload path's `resolveState` applies.
        var published = StartupCoordinator.overlayPAMGate(
            state: outcome.state, reason: outcome.degradedReason, pamNotWired: pamGateBlocked
        )
        if let plugin = authDB as? AuthPluginHealthReporting {
            published = plugin.overlayAuthPluginHealth(state: published.state, reason: published.reason)
        }
        await stateController.transition(
            to: published.state,
            reason: published.reason,
            enforcementMode: outcome.config.enforcementMode
        )

        // Bring up the ESF exec gate only when fully healthy. A failure
        // (missing FDA or the ESF entitlement) is logged, not fatal — the daemon
        // serves the sudo path without exec enforcement, and `esfMonitor` stays
        // nil so the health probe treats ESF as intentionally absent.
        if outcome.state == .healthy {
            let monitor = ESFMonitor(
                grantStore: grantStore,
                // Break-glass users/groups (and current admins) are exempt from
                // the exec backstop, exactly as the sudo front door exempts them.
                bypass: config.pamBypass,
                now: now
            )
            do {
                try await monitor.start()
                esfMonitor = monitor
                DaemonLog.integrity.notice("ESF subscription active")
                await stateController.setExecGate(.active)
            } catch let error as ESFMonitor.ESFError where error.isNotEntitled {
                // A build without the entitlement: said once, at notice level,
                // and never retried. Nothing else depends on the exec gate.
                DaemonLog.integrity.notice(
                    "exec gate off: this build has no Endpoint Security entitlement; sudo, AuthorizationDB and JIT admin enforcement are unaffected")
                await stateController.setExecGate(.notEntitled)
            } catch {
                DaemonLog.integrity.error(
                    "ESF subscription unavailable (serving without exec enforcement): \(String(describing: error), privacy: .public)"
                )
                await stateController.setExecGate(.unavailable(String(describing: error)))
            }
        } else {
            await stateController.setExecGate(.notStarted(
                "The exec gate starts only when the daemon is healthy at startup (it was \(outcome.state.rawValue))."))
        }

        if outcome.state != .killSwitch {
            await startHealthMonitor(listener: listener)
        }

        // Watch managed preferences for MDM-delivered policy changes and reload
        // without a restart (rules, config, JIT). Fingerprint the initial load so
        // the first tick only reloads on an actual change — but ONLY once the
        // initial drop-in provisioning actually took. If it failed, leave the
        // signature at its initial 0 so the first tick re-attempts provisioning
        // rather than latching a not-yet-realized state.
        //
        // Likewise a kill switch whose AuthorizationDB restore FAILED at startup
        // (degraded authdb_failure with daemonEnabled == false) leaves the
        // signature at 0, so the first tick re-runs the kill-switch teardown and
        // retries the restore instead of latching the stranded rights.
        let killSwitchRestoreFailed = !outcome.config.daemonEnabled
            && outcome.degradedReason == .authDBFailure
        if initialProvisioned && !killSwitchRestoreFailed {
            lastPolicySignature = await policySignature()
        }
        // Any other failed reconcile left part of the policy unapplied: the
        // reload ticks retry just the reconcile until it succeeds.
        adoptStartupAuthDBResult(outcome)
        startPolicyReloadLoop()

        // React to a managed-config change immediately (debounced) rather
        // than up to 30s later — a switch away from enforce removes the drop-in
        // in that same pass.
        startManagedConfigWatch()

        // IdP-group enrollment: re-provision the coarse drop-in the moment the
        // console session changes (login / logout / fast-user-switch), instead
        // of waiting up to `policyReloadIntervalSeconds` for the loop above to notice.
        // The loop remains the reliable backstop (its signature folds in the
        // resolved IdP-user set); this watch just shortens the latency.
        startConsoleUserWatch()

        // Publish an initial fleet-summary immediately so recon finds a file
        // before the first 30s reload tick would write one.
        await refreshFleetTelemetry()
    }

    /// Polls managed preferences and reloads policy when it changes. Change-gated
    /// so an unchanged policy costs only a cheap prefs read + hash — no authdb
    /// write, no state transition, no log churn.
    ///
    /// The reload pass runs under a watchdog (``runWatchdoggedReloadPass()``): this
    /// loop is a single `Task`, so an unbounded `await` anywhere beneath
    /// ``reloadPolicyIfChanged()`` would park it FOREVER — no error, no state
    /// change, enforcement of the stale policy continuing normally. That is silent
    /// policy drift.
    private func startPolicyReloadLoop() {
        policyReloadTask?.cancel()
        // Captured here rather than read back through `self` inside the task: we
        // are already on the actor, and the property is an immutable `let`.
        let interval = policyReloadIntervalSeconds
        policyReloadTask = Task { [weak self] in
            while !Task.isCancelled {
                // Continuous clock: a tick falls due across sleep, so the first
                // tick after wake runs promptly (JIT expiry backstop below).
                try? await Task.sleep(until: ContinuousClock.now.advanced(by: .seconds(Int64(interval))),
                                      clock: .continuous)
                guard let self else { return }
                await self.runWatchdoggedReloadPass()
                await self.scheduleJITOverdueSweep()
                await self.sweepJamfConnectWindows()
                await self.revokeExpiredGrants()
                await self.pruneSessionCache()
                await self.refreshFleetTelemetry()
                await self.advanceClockHighWaterMark()
            }
        }
    }

    // MARK: Wall-clock high-water mark

    /// Startup check against the persisted high-water mark. When the clock is
    /// more than ``ClockRollbackGuard/toleranceSeconds`` behind it, every timed
    /// grant is revoked and every JIT admin demoted, and the mark is reset to
    /// the current time so a corrected clock is not punished again. Otherwise
    /// the mark only moves forward.
    private func enforceClockHighWaterMark() async {
        let current = now()
        let mark = clockHighWater.read()
        guard ClockRollbackGuard.isSetBack(now: current, highWater: mark), let mark else {
            advanceClockHighWaterMark()
            return
        }
        let behind = Int(mark.timeIntervalSince(current))
        DaemonLog.integrity.fault(
            "wall clock is \(behind, privacy: .public)s behind the last time serberusd saw (\(ISO8601.string(from: mark), privacy: .public)); it was set back while the daemon was not running — revoking every timed grant and demoting every JIT admin"
        )
        await emitIntegrity(.grantRevocation,
                            "clock set back \(behind)s while serberusd was not running (last seen \(ISO8601.string(from: mark))); "
                            + "revoking every timed grant and demoting every JIT admin")
        let outcome = await ClockRollbackGuard.revokeTimedGrants(
            grantStore: grantStore, membership: membership, ticketClearer: sudoTickets,
            adminGroupScrubber: staleAdminScrubber, now: current,
            log: { line in DaemonLog.integrity.error("clock set back: \(line, privacy: .public)") }
        )
        let failures = outcome.jit.failures.map { "\($0.key): \($0.value)" } + outcome.failures
        await emitIntegrity(.grantRevocation,
                            "clock set back: revoked \(outcome.revokedGrants) timed grant(s), demoted "
                            + "\(outcome.jit.demoted.count) JIT admin(s)"
                            + (failures.isEmpty ? "" : "; FAILED: \(failures.joined(separator: "; ")) (JIT rows left active are retried)"))
        do {
            try clockHighWater.write(current)
        } catch {
            DaemonLog.integrity.error("clock high-water mark could not be reset: \(String(describing: error), privacy: .public)")
        }
    }

    /// Moves the persisted mark forward to the current time; never back. Run at
    /// startup, on every reload tick, and at shutdown.
    private func advanceClockHighWaterMark() {
        Self.advance(clockHighWater, to: now())
    }

    /// Records the mark at a clean shutdown (SIGTERM). Callable from the
    /// signal handler without waiting on the actor.
    public nonisolated func recordClockHighWaterMarkAtShutdown() {
        Self.advance(clockHighWater, to: now())
    }

    private static func advance(_ store: WallClockHighWaterStoring, to current: Date) {
        if let mark = store.read(), mark >= current { return }
        do {
            try store.write(current)
        } catch {
            DaemonLog.integrity.error("clock high-water mark could not be written: \(String(describing: error), privacy: .public)")
        }
    }

    /// What startup does with the JIT admins the previous daemon left.
    ///
    /// Under a kill switch, FORCE-demote every JIT temp admin — identical to
    /// the reload kill-switch path (`jitManager.demoteAll()`). The ordinary
    /// `reconcile()` only revokes memberships whose grant has expired, so a
    /// cold boot into a kill switch would otherwise leave a still-valid
    /// JIT-granted admin in place, diverging from the live kill-switch path.
    ///
    /// After an upgrade, live JIT sessions end instead of being re-armed: the
    /// old daemon may have been replaced before it could demote them (its
    /// bootout can outlast the installer's wait), and an upgrade ends JIT
    /// sessions by design. An upgrade is a change of daemon build or the
    /// preinstall's marker (``PreinstallUpgradeMarker``), which is removed
    /// here. Otherwise `reconcile()` re-arms what is left, or, when the JIT
    /// provider is no longer `serberus` (disabled, `jamf_connect`, or no JIT
    /// profile), ends it instead.
    func settleJITAdminsAtStartup(_ manager: JITAdminManager) async {
        if !config.daemonEnabled {
            _ = await manager.demoteAll()
        } else if upgradeDetected() {
            let ended = await manager.demoteAll(reason: "Serberus was upgraded")
            await emitIntegrity(.grantRevocation,
                                "startup after an upgrade: ended \(ended) live JIT admin session(s) instead of re-arming them")
        } else {
            await manager.reconcile()
        }
        recordBuildIdentity()
        removeUpgradeMarker()
    }

    /// Whether this start follows an upgrade: a change of daemon build
    /// (``DaemonBuildIdentity``), or the preinstall's marker.
    private func upgradeDetected() -> Bool {
        var upgraded = false
        if let buildIdentity, let buildMarker {
            let recorded = buildMarker.read()
            if DaemonBuildIdentity.isUpgrade(recorded: recorded, current: buildIdentity) {
                DaemonLog.integrity.notice(
                    "startup: daemon build changed (was \(recorded ?? "unrecorded", privacy: .public), now \(buildIdentity, privacy: .public)); live JIT admin sessions end")
                upgraded = true
            }
        }
        let marker = PreinstallUpgradeMarker(url: paths.upgradeMarker)
        switch marker.read() {
        case .absent:
            break
        case .present:
            DaemonLog.integrity.notice(
                "startup: the installer's upgrade marker is present (\(marker.url.path, privacy: .public)); live JIT admin sessions end")
            upgraded = true
        case let .untrusted(reason):
            DaemonLog.integrity.error(
                "startup: ignoring the upgrade marker at \(marker.url.path, privacy: .public): \(reason, privacy: .public)")
        }
        return upgraded
    }

    /// Removes the preinstall's upgrade marker once startup has handled it.
    private func removeUpgradeMarker() {
        let marker = PreinstallUpgradeMarker(url: paths.upgradeMarker)
        guard marker.read() != .absent else { return }
        if !marker.remove() {
            DaemonLog.integrity.error(
                "startup: the upgrade marker at \(marker.url.path, privacy: .public) could not be removed")
        }
    }

    /// Records this build as the one that ran last.
    private func recordBuildIdentity() {
        guard let buildIdentity, let buildMarker, buildMarker.read() != buildIdentity else { return }
        do {
            try buildMarker.write(buildIdentity)
        } catch {
            DaemonLog.integrity.error("daemon build marker could not be written: \(String(describing: error), privacy: .public)")
        }
    }

    /// Brings the stored grants in line with the served policy
    /// (``GrantPolicyAlignment``): revokes grants whose profile and rule are
    /// gone or whose rule now evaluates every time, and bounds (time-bound grants
    /// on) or revokes (off) any grant with no expiry. Run at startup and
    /// on every reload the daemon adopts. Not under the kill switch (which
    /// revokes everything anyway) or while awaiting config (nothing is served).
    private func alignGrantsWithPolicy(context: String) async {
        guard config.daemonEnabled, !awaitingConfig, !(grantStore is NullGrantStore) else { return }
        var rules: [GrantPolicyAlignment.RuleKey: Rule] = [:]
        for profile in profiles {
            for rule in profile.rules {
                rules[GrantPolicyAlignment.RuleKey(profileKey: profile.profileKey, ruleID: rule.id)] = rule
            }
        }
        let grants: [Grant]
        do {
            grants = try await grantStore.allGrants()
        } catch {
            DaemonLog.integrity.error(
                "\(context, privacy: .public): grants could not be read to align them with the policy: \(String(describing: error), privacy: .public)")
            return
        }
        let plan = GrantPolicyAlignment.plan(
            grants: grants, rules: rules,
            timeBoundGrantsEnabled: config.timeBoundGrantsEnabled,
            defaultGrantSeconds: config.defaultGrantDurationSeconds)
        guard !plan.isEmpty else { return }
        let current = now()
        var revoked = 0
        var bounded = 0
        var failures: [String] = []
        for grantID in plan.revoke {
            do { revoked += try await grantStore.revoke(grantID: grantID, now: current) } catch {
                failures.append("revoke \(grantID.uuidString): \(error)")
            }
        }
        for (grantID, seconds) in plan.bound.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            do { bounded += try await grantStore.bound(grantID: grantID, seconds: seconds, now: current) } catch {
                failures.append("bound \(grantID.uuidString): \(error)")
            }
        }
        await emitIntegrity(.grantRevocation,
                            "\(context): revoked \(revoked) grant(s) whose rule is no longer in the policy (or no longer "
                            + "issues grants, or had no expiry); gave \(bounded) grant(s) with no expiry one because time-bound grants are on"
                            + (failures.isEmpty ? "" : "; FAILED: \(failures.joined(separator: "; "))"))
        scheduleMonitoredSetRefresh()
    }

    /// Records the account's GeneratedUID on JIT rows from before schema 3
    /// whose name and uid still name the same account
    /// (``GrantStore/stampGeneratedUIDs(resolve:)``), so a uid later reused by
    /// a new account is not taken for a rename of the promoted one.
    private func stampJITGeneratedUIDs() async {
        do {
            let stamped = try await grantStore.stampGeneratedUIDs(resolve: Self.generatedUIDIfSameAccount)
            if stamped > 0 {
                DaemonLog.integrity.notice(
                    "startup: recorded the GeneratedUID on \(stamped, privacy: .public) JIT admin grant(s) written without one")
            }
        } catch {
            DaemonLog.integrity.error(
                "startup: GeneratedUIDs could not be recorded on older JIT grants: \(String(describing: error), privacy: .public)")
        }
    }

    /// The GeneratedUID of the account with `uid`, only when the account named
    /// exactly `user` has that uid (the row still names the same account).
    static let generatedUIDIfSameAccount: @Sendable (String, uid_t) -> String? = { user, uid in
        guard SudoTimestampDirectory.exactUID(user) == uid else { return nil }
        return LocalAccounts.generatedUID(uid: uid)
    }

    /// Gives every live timed row a continuous-clock deadline in this boot
    /// session (``GrantStore/restampContinuousDeadlines(now:)``).
    private func restampContinuousDeadlines() async {
        do {
            let stamped = try await grantStore.restampContinuousDeadlines(now: now())
            if stamped > 0 {
                DaemonLog.integrity.notice(
                    "startup: gave \(stamped, privacy: .public) grant(s) a continuous-clock deadline for this boot session")
            }
        } catch {
            DaemonLog.integrity.error(
                "startup: continuous-clock deadlines could not be stamped: \(String(describing: error), privacy: .public)")
        }
    }

    /// Wall-clock JIT expiry backstop, run on every reload tick: demotes any
    /// unrevoked JIT grant past its `expiresAt` (and any unverifiable JIT row).
    /// Unawaited so a slow directory service never delays the tick; at most one
    /// sweep runs at a time.
    private func scheduleJITOverdueSweep() {
        guard jitOverdueSweep == nil, let manager = jitManager else { return }
        jitOverdueSweep = Task { [weak self] in
            _ = await manager.expireOverdue()
            await self?.clearJITOverdueSweep()
        }
    }

    private func clearJITOverdueSweep() { jitOverdueSweep = nil }

    /// Reload-tick backstop for observed Jamf Connect windows: ends those that
    /// elapsed or whose user left `admin` (clearing the user's sudo ticket).
    private func sweepJamfConnectWindows() async {
        await jamfConnectObserver?.sweep()
    }

    /// Runs the Jamf Connect observer exactly while the JIT provider is
    /// `jamf_connect` and Serberus is on. Under the kill switch the daemon is
    /// off and pam passes sudo through anyway, so there is nothing to observe
    /// for; stopping ends every open window (and clears those tickets).
    private func updateJamfConnectObserver() async {
        guard let jamfConnectObserver else { return }
        if config.daemonEnabled && jitPolicy.provider == .jamfConnect {
            await jamfConnectObserver.start()
        } else {
            await jamfConnectObserver.stop()
        }
    }

    /// Whether the served config makes pam_serberus gate sudo: on, enforce, and
    /// configured (not bootstrap).
    private var sudoGatingEffective: Bool {
        config.daemonEnabled && config.enforcementMode == .enforce && !awaitingConfig
    }

    /// Clears EVERY sudo ticket when the daemon moves into enforce from any
    /// other state (monitor, audit, the kill switch, bootstrap, or a start), so
    /// no ticket obtained while sudo was ungated lets a user skip the gate.
    /// Called after each config adoption.
    private func noteSudoGatingPosture() {
        let gating = sudoGatingEffective
        defer { sudoGatingActive = gating }
        guard gating, sudoGatingActive != true else { return }
        let cleared = sudoTickets.clearAllTickets()
        DaemonLog.integrity.notice(
            "sudo gating active (enforce); cleared \(cleared, privacy: .public) sudo ticket(s) left from before")
    }

    /// Revokes every non-JIT grant whose window is over — on the wall clock,
    /// on the continuous clock, or because the clock was set back before it
    /// was issued — on every tick, so a grant can never be revived or kept
    /// alive by changing the date. JIT admin grants are the JIT manager's
    /// (``scheduleJITOverdueSweep()``).
    private func revokeExpiredGrants() async {
        guard let revoked = try? await grantStore.revokeExpired(now: now()), revoked > 0 else { return }
        DaemonLog.integrity.notice("revoked \(revoked, privacy: .public) expired grant(s) on the reload tick")
        scheduleMonitoredSetRefresh()
    }

    /// Test seam: one expired-grant revocation pass, as the reload tick runs it.
    func revokeExpiredGrantsForTesting() async {
        await revokeExpiredGrants()
    }

    /// Test seam: one JIT overdue-expiry sweep, awaited.
    func expireOverdueJITForTesting() async -> Int {
        await jitManager?.expireOverdue() ?? 0
    }

    // MARK: Managed-config watch

    /// Starts the debounced file-system watch on the managed config plist. A
    /// change triggers an immediate reload pass (the 30s loop stays the
    /// backstop). The watch copes with the folder not existing yet, or being
    /// replaced (see ``ManagedConfigWatch``). Disabled when no directory is
    /// configured (unit tests).
    private func startManagedConfigWatch() {
        guard managedConfigWatch == nil, let directory = managedConfigWatchDirectory else { return }
        let watch = ManagedConfigWatch(
            directory: directory,
            fileName: "\(BundleConfig.configDomain).plist"
        ) { [weak self] in
            // Off-actor (dispatch queue): only schedule work.
            Task { await self?.handleManagedConfigChange() }
        }
        watch.start()
        managedConfigWatch = watch
    }

    /// Runs a reload pass right away for a managed-config change. While a pass
    /// is already outstanding, the change is queued instead: that pass may have
    /// read the config before the change, so one more pass runs when it
    /// completes (``markReloadPassComplete()``). Never counted as a stall.
    private func handleManagedConfigChange() async {
        guard !reloadPassOutstanding else {
            reloadRerunRequested = true
            return
        }
        await runWatchdoggedReloadPass()
    }

    /// Test seam: deliver one managed-config change notification.
    func handleManagedConfigChangeForTesting() async {
        await handleManagedConfigChange()
    }

    /// Fleet telemetry maintenance, run on each reload tick: rewrite
    /// `fleet-summary.plist` from the decision log + active grants, then prune
    /// decision logs past the retention window. Both are best-effort and fully
    /// isolated from the enforcement path — a failure here never degrades the
    /// daemon and never blocks the loop.
    private func refreshFleetTelemetry() async {
        let clock = now()
        // Gather the cheap, actor-bound inputs here…
        let active = (try? await grantStore.activeGrants(now: clock))?.count ?? 0
        let retentionDays = prefsReader.readNotify().value.logRetentionDays
        // Debug telemetry gate: read fresh each tick (managed-only) so adding or
        // removing the `debugModeEnabled` profile takes effect within 30s without
        // a policy-signature change.
        let debugEnabled = prefsReader.readDebugMode()
        // Cache for handlePAM's argv-capture (a cheap on-actor bool read on the
        // hot path); up to one tick stale after the profile changes.
        debugModeEnabled = debugEnabled
        // App-management master gate, read fresh each tick (managed-only) so the
        // sandboxed Finder extension can SHOW/HIDE its right-click items within a
        // tick of the profile being added/removed. Advisory UX only.
        let appManagementEnabled = prefsReader.readAppManagementPolicy().enabled
        let writer = fleetSummaryWriter
        let eventsWriter = recentEventsWriter
        let rotator = logRotator
        // …then do the bounded file I/O OFF the actor, unawaited, so a large log
        // read can never add latency to `handlePAM`/XPC on the reload tick. The
        // summary and prune are order-independent (atomic write, last wins), so
        // overlapping ticks are harmless.
        Task.detached(priority: .utility) {
            writer?.write(activeGrants: active, now: clock)
            // Recent events: always collected locally; published to the EA path
            // only while debug mode is on, else the EA-path file is removed.
            eventsWriter?.write(debugEnabled: debugEnabled, now: clock)
            // Publish the app-management master gate for the Finder extension.
            Self.writeAppManagementState(enabled: appManagementEnabled)
            // Retention: keep N days (managed `logRetentionDays`, default 90); the
            // prune only touches `<prefix>-YYYY-MM-DD.jsonl[.hmac]` older than the
            // window, so today + yesterday (the summary read) always survive.
            _ = try? rotator.prune(retentionDays: retentionDays, now: clock)
        }
    }

    /// Writes the app-management master-gate marker (world-readable 0644) the
    /// sandboxed Finder extension reads to conditionally show/hide its items.
    /// Best-effort and advisory: the daemon still gates every action server-side,
    /// so a stale/missing marker never permits an action the policy forbids.
    private static func writeAppManagementState(enabled: Bool) {
        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: ["enabled": enabled], format: .binary, options: 0) else { return }
        let path = BundleConfig.appManagementStatePath
        guard (try? data.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil else { return }
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
    }

    // MARK: Reload watchdog

    /// Runs one ``reloadPolicyIfChanged()`` pass under a wall-clock deadline,
    /// ABANDONING it if it overruns so the loop's next tick still happens.
    ///
    /// This is defense-in-depth against a *class* of hang, not a fix for any one
    /// frame: a stall becomes loud (os_log + `degraded`) instead of silent,
    /// bounded (one leaked task, never one per tick), and self-recovering —
    /// immediately if the hang was transient, via a launchd restart if not.
    ///
    /// Note the awaits below release the actor, which is what lets a *later* tick
    /// observe ``reloadPassOutstanding`` and what keeps a daemon with a wedged
    /// pass serving `handlePAM`/XPC normally.
    private func runWatchdoggedReloadPass() async {
        // LEAK GUARD. A pass abandoned at its deadline may still be parked on the
        // never-resuming await; starting another every 30s would pile up tasks
        // (and racing writers) indefinitely. One outstanding pass, maximum.
        //
        // It is a STALL only once that pass is older than the deadline. A pass
        // the managed-config watch started a moment ago is simply still
        // working; the tick leaves it alone.
        if reloadPassOutstanding {
            let age = reloadPassStartedAt.map { ContinuousClock.now - $0 } ?? .zero
            if age >= Self.duration(seconds: reloadDeadlineSeconds) {
                await noteReloadStall("previous pass still outstanding")
            }
            return
        }
        reloadPassOutstanding = true
        reloadPassStartedAt = ContinuousClock.now
        let completed = await withAbandoningTimeout(seconds: reloadDeadlineSeconds) { [weak self] () -> Bool in
            await self?.reloadPolicyIfChanged()
            // Clears the guard even when this runs AFTER the deadline: a merely
            // slow pass then self-heals on the next tick, with no restart.
            await self?.markReloadPassComplete()
            return true
        }
        if completed == nil {
            // `reloadPassOutstanding` stays true on purpose — only the (possibly
            // late) worker above may clear it, because only it knows the pass
            // actually finished.
            await noteReloadStall("pass exceeded \(reloadDeadlineSeconds)s")
        } else {
            consecutiveReloadStalls = 0
        }
    }

    /// Marks the in-flight reload pass finished. Called from inside the watchdogged
    /// worker, so it also runs for a pass that completes late. Starts the
    /// queued pass for a managed-config change that arrived mid-pass.
    private func markReloadPassComplete() {
        reloadPassOutstanding = false
        reloadPassStartedAt = nil
        guard reloadRerunRequested else { return }
        reloadRerunRequested = false
        Task { [weak self] in await self?.runWatchdoggedReloadPass() }
    }

    /// `seconds` as a `Duration` (sub-second budgets are used by tests).
    private static func duration(seconds: TimeInterval) -> Duration {
        .nanoseconds(Int64(max(0, seconds) * 1_000_000_000))
    }

    /// Reports a stalled reload pass and escalates once the stall looks permanent.
    ///
    /// Reporting is `os_log` ONLY. ``emitIntegrity`` and
    /// ``DaemonStateController/transition(to:reason:enforcementMode:)`` both await
    /// the ``IntegrityLogger`` **actor**, which is itself a plausible wedge
    /// candidate — a watchdog that reported through the thing it watches would go
    /// silent in exactly the case it exists for. `Logger` is synchronous, takes no
    /// actor hop, and cannot hang.
    private func noteReloadStall(_ reason: String) async {
        consecutiveReloadStalls += 1
        // Whatever the stalled pass did or did not publish, the next pass must
        // publish again, or `degraded(reload_stalled)` would stick while every
        // later tick takes the unchanged-signature early return.
        publishAfterStall = true
        DaemonLog.integrity.critical(
            """
            policy reload STALLED (\(reason, privacy: .public)); \
            stall \(self.consecutiveReloadStalls, privacy: .public)/\
            \(self.maxConsecutiveReloadStalls, privacy: .public). Enforcement continues on the \
            last-known policy; policy UPDATES are NOT being applied.
            """
        )
        await markStalledDegradedBestEffort()
        guard consecutiveReloadStalls >= maxConsecutiveReloadStalls, !reloadRestartRequested else { return }
        reloadRestartRequested = true
        DaemonLog.integrity.critical(
            """
            exiting for launchd restart after \(self.consecutiveReloadStalls, privacy: .public) \
            consecutive policy-reload stalls
            """
        )
        // Same restart contract the health monitor uses: launchd brings the daemon
        // back and startup reconciles from scratch.
        exitProcess(1)
    }

    /// Best-effort `degraded` report for a stall. Itself raced against a short
    /// deadline: `transition` awaits the integrity logger, so if THAT is the wedge
    /// an unbounded call here would park the watchdog too.
    ///
    /// Worth attempting anyway — `transition` writes `state.plist` BEFORE its
    /// logger await, so the admin-visible state lands even when the logger is the
    /// thing that is stuck. Self-clears: the next healthy pass transitions to its
    /// resolved state normally.
    private func markStalledDegradedBestEffort() async {
        let stateController = self.stateController
        let enforcementMode = config.enforcementMode
        _ = await withAbandoningTimeout(seconds: 5) { () -> Bool in
            await stateController.transition(to: .degraded, reason: .reloadStalled,
                                             enforcementMode: enforcementMode)
            return true
        }
    }

    /// A stable fingerprint of the managed policy (rules + the config/JIT fields
    /// that affect enforcement), used to detect MDM-delivered changes. `async`
    /// because the IdP-group enrollment probe resolves the live IdP state
    /// off-actor with a timeout.
    private func policySignature() async -> Int {
        // Key order must be canonical: some encoded types (e.g. JITAdminPolicy) emit
        // their JSON keys in a non-deterministic order across calls within a single
        // process, which would otherwise make the signature — and thus the
        // reload/provision gate — spuriously unstable. `.sortedKeys` pins a stable
        // byte sequence so an unchanged policy always hashes identically.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var hasher = Hasher()
        // Hash every byte: `Data.hash(into:)` can cover only a leading slice
        // on older Foundation, so equal-length edits past it (serberus -> disabled) went unseen.
        if let rules = try? encoder.encode(prefsReader.readRuleProfiles().value) {
            rules.withUnsafeBytes { hasher.combine(bytes: $0) }
        }
        let config = prefsReader.readConfig().value
        hasher.combine(config.daemonEnabled)
        hasher.combine(config.enforcementMode)
        hasher.combine(config.sudoCacheSeconds)
        hasher.combine(config.promptTimeoutSeconds)
        // Every other enforcement-relevant config key, so an MDM change to ONLY
        // one of these is adopted (and re-snapshotted as last-known-good) —
        // previously a lone `timeBoundGrantsEnabled` flip was never picked up.
        hasher.combine(config.timeBoundGrantsEnabled)
        hasher.combine(config.defaultGrantDurationMinutes)
        hasher.combine(config.enableBiometrics)
        hasher.combine(config.commanderPublishEnabled)
        // PAM-gate verdict: a gate that becomes wired (or unwired) must re-run
        // provisioning on the next tick even though no policy changed — this is
        // what brings a withheld drop-in back once sudo_local is fixed.
        hasher.combine(pamGate.verify().isWired)
        // Presence + break-glass are the inputs to the awaiting-config /
        // last-known-good resolution, and NEITHER shows up in the fields above: an
        // absent profile parses to the same daemonEnabled/enforce/0/60 defaults an
        // enforcing profile carries, and differs ONLY in `pamBypass`. Without these,
        // the profile ARRIVING (or being removed) would not move the signature, and
        // a Mac stuck in awaitingConfig would never notice its config landed —
        // it would sit in pass-through until some unrelated key happened to change.
        hasher.combine(prefsReader.configIsPresent())
        // Whether the last-known-good snapshot exists (one `lstat` per tick):
        // pam keys "configured" on that file, so a snapshot deleted while it was
        // being served must re-resolve (to awaiting-config, removing the drop-in)
        // rather than leave the daemon enforcing while pam falls to bootstrap.
        hasher.combine(lastKnownGood.exists())
        hasher.combine(config.pamBypass.groups)
        hasher.combine(config.pamBypass.users)
        // Break-glass RESOLVABILITY (getpwnam/getgrnam, once per
        // tick) — of both the delivered config and the one being served — so a
        // bypass account that appears or disappears re-resolves the state even
        // though no policy key changed.
        hasher.combine(BypassResolution.isUnresolvable(config, resolver: bypassResolver))
        hasher.combine(BypassResolution.isUnresolvable(self.config, resolver: bypassResolver))
        // Enrollment feeds the coarse sudoers drop-in, so an enrollment-only MDM
        // change must trigger a reload (and a drop-in rebuild) even when no rule
        // changed.
        hasher.combine(config.sudoEnrollment.group)
        hasher.combine(config.sudoEnrollment.users)
        // IdP-group enrollment: fold in both the MDM-configured
        // enrollment inputs AND the *live* resolution, so a login/logout/state-
        // file change with unchanged MDM policy still trips the reload loop (else
        // the coarse drop-in would go stale until the next MDM push). The
        // SCDynamicStore watch gives immediacy; this keeps the 30s loop honest.
        let enrollment = config.sudoEnrollment
        hasher.combine(enrollment.idpSource)
        hasher.combine(enrollment.idpGroups)
        hasher.combine(enrollment.idpStatePath)
        hasher.combine(enrollment.idpGroupsKey)
        hasher.combine(enrollment.requireRootOwnedState)
        if enrollment.idpSource != .disabled {
            // Silent probe — the authoritative resolve in `provisionSudoers`
            // owns the `idp-resolve.*` audit trail; this must not churn logs on
            // every tick. Fold in the resolved console-user set (what actually
            // drives the drop-in) and the raw console-user name (so even a swap
            // between two non-enrolled users is observable, per the contract).
            let idp = await resolveIDP(enrollment: enrollment, silent: true)
            hasher.combine(idp.consoleUser?.name)
            hasher.combine(idp.outcome.resolvedUsers)
        }
        // Only the prompts field the daemon consumes — UI-only prompt fields
        // must not churn policy reloads.
        hasher.combine(prefsReader.readPrompts().value.justificationMinLength)
        if let jit = try? encoder.encode(prefsReader.readJITAdmin().value) {
            jit.withUnsafeBytes { hasher.combine(bytes: $0) }
        }
        // SerberusAuth plugin health (cheap lstat fingerprint; full signature
        // check only on change): the plugin disappearing or returning must
        // re-run the reconcile, which puts composed rights back to native.
        if let plugin = authDB as? AuthPluginHealthReporting {
            hasher.combine(plugin.authPluginHealthToken())
        }
        return hasher.finalize()
    }

    /// Drops expired session-cache entries; called on the reload loop's tick.
    private func pruneSessionCache() async {
        await sessionCache.pruneExpired(now: now())
    }

    /// Serialized entry point for coarse-drop-in provisioning. Chains behind
    /// any in-flight pass so no two apply/remove calls ever overlap; the
    /// last-submitted pass computes its enrollment fresh at its exclusive turn and
    /// writes last (latest-wins), so a stale write can never land after a fresher
    /// one — closing the reentrancy race between the console-user watch and the
    /// reload loop. Returns whether THIS pass left the on-disk drop-in matching
    /// intent (the success signal), so callers can gate the policy signature.
    @discardableResult
    private func provisionSudoers(forceRemove: Bool = false) async -> Bool {
        let previous = provisioningChain
        let task = Task { [weak self] () -> Bool in
            // Serialize: wait for the prior pass to fully finish (including its
            // `await sudoers.apply`) before touching the file.
            _ = await previous?.value
            guard let self else { return false }
            return await self.performProvisioning(forceRemove: forceRemove)
        }
        provisioningChain = task
        return await task.value
    }

    /// One coarse-drop-in provisioning pass. NEVER call directly — always through
    /// ``provisionSudoers()`` so passes are serialized. Recomputes enrollment
    /// from the live config at its exclusive turn, so a later (coalesced) pass
    /// always reflects the freshest inputs.
    ///
    /// Rebuilds the drop-in from the live config/profiles, or removes it under the
    /// kill switch. Non-fatal — the manager keeps the prior-good file on any
    /// failure and never affects daemon state — but returns a success signal.
    ///
    /// When IdP-group enrollment is enabled, the enrollment handed to the
    /// generator is *augmented* with the resolved console user; when it is
    /// disabled the call uses the MDM-configured enrollment unchanged.
    private func performProvisioning(forceRemove: Bool = false) async -> Bool {
        // Leaving-enforce fast path (``removeDropInIfLeavingEnforce()``): the delivered
        // config has left enforce but has not been adopted yet — remove now.
        if forceRemove {
            let removed = await sudoers.remove()
            lastResolvedIDPUsers = []
            pamGateBlocked = false
            return removed
        }
        // Two non-enforce paths below actively REMOVE the drop-in rather than
        // apply anything (kill switch, then monitor/audit — including the
        // awaiting-config bootstrap, whose effective config is a monitor one).
        // Both are ACTIVE removals, never an early skip: a skip would strand a
        // stale drop-in from a prior enforce pass, leaving an enrolled standard
        // user with ungated sudo while pam passes through. Do not replace
        // either removal with a bare guard.
        guard config.daemonEnabled else {
            let removed = await removeDropInOnce()
            // The drop-in is gone, so nobody is enrolled from the IdP path; drop
            // the tracking (remove() already logs the teardown).
            lastResolvedIDPUsers = []
            pamGateBlocked = false
            return removed
        }

        // The coarse `/etc/sudoers.d/serberus` drop-in is a GRANT — it is the
        // only thing that lets an enrolled STANDARD user reach the curated
        // command paths through sudo at all. It is PATH-ONLY (argPattern is the
        // daemon's fine gate, never expressible in sudoers), so it is only safe
        // to write when the fine gate is actually active. `pam_serberus`
        // consults the daemon (and can deny) ONLY in `.enforce`; in `.monitor`
        // and `.audit` it returns PAM_IGNORE and passes sudo straight through.
        // So provisioning the drop-in outside enforce would hand an enrolled
        // standard user UNGATED path-level sudo (every subcommand, no argPattern
        // check) — broader access than enforce and the opposite of "observe
        // only". Non-enforcing modes therefore REMOVE the drop-in so enrolled
        // users revert to native macOS behavior (a standard user cannot sudo).
        // This is an active removal, never an early skip: a skip would strand a
        // stale drop-in from a prior enforce pass (the ungated-sudo bug the
        // `daemonEnabled` path above was written to avoid).
        guard config.enforcementMode == .enforce else {
            let removed = await removeDropInOnce()
            lastResolvedIDPUsers = []
            pamGateBlocked = false
            return removed
        }

        // The drop-in must never outlive the PAM gate. If sudo_local does not
        // route sudo through pam_serberus (an install that aborted after the
        // daemon loaded, a hand-edited sudo_local, Touch ID above Serberus, a
        // swappable module, an include), the drop-in is plain sudoers —
        // enrolled standard users could run the curated binaries with ANY
        // arguments and no Serberus decision. Withhold it (actively remove,
        // never skip) and report `degraded(pam_not_wired)`; the gate verdict
        // is folded into the policy signature, so a later-wired gate brings
        // the drop-in back on the next reload tick.
        let gate = pamGate.verify()
        let previousGate = lastPAMGateStatus
        let gateChanged = gate != previousGate
        lastPAMGateStatus = gate
        if case let .notWired(reason) = gate {
            pamGateBlocked = true
            lastResolvedIDPUsers = []
            let removed = await sudoers.remove()
            if gateChanged {
                DaemonLog.integrity.error(
                    "PAM gate NOT wired (\(reason, privacy: .public)); coarse sudoers drop-in withheld — degraded(pam_not_wired)"
                )
                await emitIntegrity(.configurationError,
                                    "PAM gate not wired: \(reason); sudoers drop-in removed (pam_not_wired)")
            }
            return removed
        }
        pamGateBlocked = false
        if let previousGate, !previousGate.isWired {
            DaemonLog.integrity.notice("PAM gate now verified; coarse sudoers drop-in provisioning resumed")
            await emitIntegrity(.configurationError, "PAM gate verified again; sudoers drop-in provisioning resumed")
        }

        let enrollment = await enrollmentForProvisioning()
        return await sudoers.apply(profiles: profiles, enrollment: enrollment)
    }

    /// Removes the drop-in — unless this reload pass's leaving-enforce fast path already
    /// did, in which case its result stands (no second `remove()`).
    private func removeDropInOnce() async -> Bool {
        if let early = earlyDropInRemoval {
            earlyDropInRemoval = nil
            return early
        }
        return await sudoers.remove()
    }

    /// Produces the enrollment the sudoers generator is fed. With IdP-group enrollment off
    /// this is exactly `config.sudoEnrollment` (byte-identical to today). With it
    /// on, it resolves the verified console user + IdP claim and appends the
    /// resolved console-user name (if any) to the MDM-configured `users`, deduped
    /// and order-stable. Emits the `idp-resolve.*` audit trail and diffs against
    /// the previously-resolved set so a drop-out is logged as `.revoked`.
    ///
    /// # Trust containment (unchanged by this wiring)
    /// The only name this can add is the daemon-verified `ConsoleUser.name` the
    /// resolver returns; it is passed as an ordinary `users` entry into the
    /// UNCHANGED hardened `SudoersGenerator`, which re-validates every principal.
    private func enrollmentForProvisioning() async -> SerberusConfig.SudoEnrollment {
        let base = config.sudoEnrollment
        guard base.idpSource != .disabled else {
            // Feature off — the MDM-configured enrollment, unchanged.
            lastResolvedIDPUsers = []
            return base
        }

        let idp = await resolveIDP(enrollment: base, silent: false)
        // On a read timeout `resolveIDP` already logged `idp-resolve.refused.timeout`;
        // suppress the duplicate (stale) event line here.
        if !idp.timedOut { emitIDPResolveEvent(idp.outcome.event) }

        // A user enrolled last pass but not this one has effectively been
        // revoked (logout, state-file rewrite, ownership tamper). Log it loudly
        // — the drop-in itself shrinks below via the fresh resolved set.
        let resolved = idp.outcome.resolvedUsers
        for user in lastResolvedIDPUsers where !resolved.contains(user) {
            DaemonLog.integrity.notice(
                "idp-resolve.revoked user=\(user, privacy: .public) (no longer resolved; dropped from drop-in)"
            )
        }
        lastResolvedIDPUsers = resolved

        guard !resolved.isEmpty else { return base }

        // MDM-configured users first, then the resolved console user(s), deduped
        // (a console user already listed by MDM must not be emitted twice).
        var users = base.users
        var seen = Set(base.users)
        for user in resolved where seen.insert(user).inserted {
            users.append(user)
        }
        return SerberusConfig.SudoEnrollment(
            group: base.group,
            users: users,
            idpGroups: base.idpGroups,
            idpSource: base.idpSource,
            idpStatePath: base.idpStatePath,
            idpGroupsKey: base.idpGroupsKey,
            requireRootOwnedState: base.requireRootOwnedState
        )
    }

    /// One resolve pass: verified console user (`ConsoleUserResolver`) →
    /// file-verified claim (`JamfConnectStateSource`) → pure decision
    /// (`IDPGroupResolver`). Pure orchestration of the injected components; the
    /// trust boundaries live inside them. `silent` swaps the components' advisory
    /// `warn` sinks for no-ops so the change-detection probe in `policySignature`
    /// does not spam the integrity log every tick.
    private func resolveIDP(
        enrollment: SerberusConfig.SudoEnrollment,
        silent: Bool
    ) async -> (consoleUser: ConsoleUser?, outcome: IDPResolveOutcome, timedOut: Bool) {
        let noWarn: @Sendable (String) -> Void = { _ in }
        // Console-user resolution (SCDynamicStore + getpwuid) is fast and stays on
        // the actor; only the potentially-blocking state-file read is moved off.
        let consoleUser = ConsoleUserResolver(
            warn: silent ? noWarn : ConsoleUserResolver.defaultWarn
        ).resolve()
        let source = JamfConnectStateSource(warn: silent ? noWarn : JamfConnectStateSource.defaultWarn)
        let resolver = IDPGroupResolver(source: source)

        // Defense in depth against a hung read: run the resolver (whose source performs the
        // blocking `openat` walk) OFF this actor with a timeout, so a pathological
        // blocking read — a real hung mountpoint the `O_NOFOLLOW` walk cannot flag
        // as a symlink — can never pin `handlePAM` and brick machine-wide sudo.
        let resolved = await withDetachedTimeout(seconds: Self.idpReadTimeoutSeconds) {
            resolver.resolve(consoleUser: consoleUser, config: enrollment)
        }
        guard let outcome = resolved else {
            if !silent {
                DaemonLog.integrity.error(
                    "idp-resolve.refused.timeout (state read exceeded \(Int(Self.idpReadTimeoutSeconds))s; no enrollment)"
                )
            }
            // Fail-safe: no enrollment. `.staleOrMissingSource` keeps
            // `resolvedUsers` empty; `timedOut` tells the caller to suppress the
            // duplicate event line (the timeout was already logged above).
            return (
                consoleUser,
                IDPResolveOutcome(resolvedUsers: [], matchedGroups: [], event: .staleOrMissingSource),
                true
            )
        }
        return (consoleUser, outcome, false)
    }

    /// Emits the single `idp-resolve.*` audit line for a resolve outcome. Quiet,
    /// expected off-paths (disabled / no console user / no configured groups) are
    /// intentionally silent; the security-relevant transitions (granted, no-match,
    /// every refusal) are logged. `.revoked` is emitted separately from the diff
    /// in ``enrollmentForProvisioning()`` since it is not an `IDPResolveEvent`.
    private func emitIDPResolveEvent(_ event: IDPResolveEvent) {
        switch event {
        case .disabled, .noConsoleUser, .noConfiguredGroups:
            break
        case .staleOrMissingSource:
            DaemonLog.integrity.notice(
                "idp-resolve.stale (state file missing/unreadable/no groups key); no enrollment"
            )
        case let .refusedOwnership(uid, mode):
            DaemonLog.integrity.error(
                "idp-resolve.refused.ownership uid=\(uid, privacy: .public) mode=\(String(mode, radix: 8), privacy: .public); no enrollment"
            )
        case .refusedSymlink:
            DaemonLog.integrity.error(
                "idp-resolve.refused.symlink (state path resolved through a symlink / non-regular file); no enrollment"
            )
        case .strictReject:
            DaemonLog.integrity.error(
                "idp-resolve.refused.strict (requireRootOwnedState rejected a non-root-owned / owner-writable file); no enrollment"
            )
        case .noMatch:
            DaemonLog.integrity.notice(
                "idp-resolve.no-match (valid claim, no configured group intersected); no enrollment"
            )
        case let .granted(user, matched):
            DaemonLog.integrity.notice(
                "idp-resolve.granted user=\(user, privacy: .public) matched=\(matched.joined(separator: ","), privacy: .public)"
            )
        }
    }

    /// Subscribes to `State:/Users/ConsoleUser` so a console session change
    /// re-provisions the drop-in immediately. The SCDynamicStore callback lands
    /// on a private dispatch queue and does nothing but hop onto this actor —
    /// no actor state is read or written off-actor.
    private func startConsoleUserWatch() {
        guard consoleUserWatch == nil else { return }
        let watch = ConsoleUserWatch { [weak self] in
            // Off-actor (SC dispatch queue): only schedule work, never mutate.
            Task { await self?.handleConsoleUserChange() }
        }
        watch.start()
        consoleUserWatch = watch
    }

    /// Actor-isolated handler for a console-session change. Rebuilds only the
    /// coarse drop-in (a login/logout cannot change MDM rules/config/JIT, so a
    /// full `reloadPolicyIfChanged` is unwarranted). Inert when IdP-group enrollment is off.
    /// Deliberately does not touch `lastPolicySignature`: the 30s backstop stays
    /// free to catch any MDM delta that landed in the same window.
    private func handleConsoleUserChange() async {
        guard config.sudoEnrollment.idpSource != .disabled else { return }
        await provisionSudoers()
    }

    /// Re-attempts the last-known-good snapshot when a usable managed config is
    /// present but the snapshot FILE is missing — i.e. an earlier
    /// ``EffectiveConfigResolver`` save failed (I/O error, directory not yet
    /// created). Stateless and idempotent: it only ever writes when a config the
    /// resolver WOULD snapshot (present && daemonEnabled && enforceable) is live and
    /// the file is absent, so it never fights the resolver and never snapshots a
    /// kill switch or an unsafe/partial profile. Runs every reload tick so the
    /// configured-Mac marker pam depends on is planted as soon as I/O allows.
    ///
    /// Also refreshes an EXISTING snapshot that has gone stale relative to the
    /// live usable config (``LastKnownGoodConfigStoring/needsRefresh(for:)``) —
    /// e.g. a pass-through key such as `sudoDenyMessage` changed, which moves no
    /// parsed config field and so never trips the policy signature.
    private func retryLastKnownGoodSaveIfNeeded() {
        reportLastKnownGoodProblemIfChanged()
        guard prefsReader.configIsPresent() else { return }
        let cfg = prefsReader.readConfig().value
        // The resolver's own snapshot guard: a bypass none of whose entries
        // resolves is as unenforceable as an empty one, and is never saved.
        guard cfg.daemonEnabled, cfg.isEnforceable,
              !BypassResolution.isUnresolvable(cfg, resolver: bypassResolver) else { return }
        let missing = !lastKnownGood.exists()
        guard missing || lastKnownGood.needsRefresh(for: cfg) else { return }
        do {
            try lastKnownGood.save(cfg)
            DaemonLog.integrity.notice(
                "last-known-good snapshot \(missing ? "re-saved after an earlier save failure" : "refreshed (stale keys)", privacy: .public)"
            )
        } catch {
            DaemonLog.integrity.error(
                "last-known-good snapshot re-save still failing: \(String(describing: error), privacy: .public)"
            )
        }
    }

    /// Logs, once per change, an existing snapshot that fails pam's file checks
    /// (owner, mode, symlink) or does not parse. While the profile is present
    /// nothing reads the snapshot, but if the profile is removed both pam and
    /// the daemon would fail closed with no break-glass — so say so early.
    private func reportLastKnownGoodProblemIfChanged() {
        let problem = lastKnownGood.unusableReason()
        guard problem != lastSnapshotProblem else { return }
        lastSnapshotProblem = problem
        if let problem {
            DaemonLog.integrity.error(
                "last-known-good snapshot unusable (\(problem, privacy: .public)); without the managed profile, sudo would fail closed with no break-glass"
            )
        } else {
            DaemonLog.integrity.notice("last-known-good snapshot usable again")
        }
    }

    /// Re-reads managed preferences; on a change, adopts the new config/rules/JIT,
    /// reconciles the authdb (restoring rights removed from the policy), and
    /// re-resolves daemon state. No-op when nothing changed.
    func reloadPolicyIfChanged() async {
        // A mode change AWAY from enforce (monitor / audit / kill switch)
        // removes the coarse drop-in FIRST — before the signature probe (IdP
        // read, PAM-gate verify), the authdb reconcile, or anything else in this
        // pass — so the window in which pam passes sudo through while the
        // drop-in still grants path-level sudo is as short as possible.
        await removeDropInIfLeavingEnforce()
        defer { earlyDropInRemoval = nil }

        // The last-known-good FILE is a hard invariant for a configured Mac: pam
        // keys bootstrap-vs-configured on its EXISTENCE, so a Mac that adopted a
        // managed config but whose snapshot write failed earlier could later fall
        // into bootstrap pass-through for want of the marker. Re-attempt the save
        // every tick, INDEPENDENTLY of the change gate below (the config is stable,
        // so the signature would not move and resolve() would never re-run). Cheap:
        // one managed-prefs read, and a no-op the instant the file exists.
        retryLastKnownGoodSaveIfNeeded()

        let signature = await policySignature()
        // After a reported stall the pass runs even with an unchanged signature,
        // so the state is published again and `reload_stalled` clears.
        guard signature != lastPolicySignature || publishAfterStall else {
            // Nothing changed, but the last reconcile left part of the policy
            // unapplied: retry that step alone. Only on a watchdogged pass
            // (``runWatchdoggedReloadPass()`` holds `reloadPassOutstanding`),
            // never on the bootstrap re-resolve a PAM request runs.
            if authDBNotFullyApplied && reloadPassOutstanding {
                await retryAuthDBReconcile()
            }
            return
        }
        publishAfterStall = false
        // Do NOT advance `lastPolicySignature` yet: it is committed only
        // AFTER the fallible sudoers side-effect confirms the on-disk drop-in
        // matches intent. A failed *shrink* (de-enroll / kill-switch removal that
        // kept the prior-good file) therefore leaves the signature STALE so the
        // next 30s tick re-attempts it, instead of latching a removed user as
        // still-authorized on disk until an unrelated policy change.

        let configResult = prefsReader.readConfig()
        let configPresent = prefsReader.configIsPresent()
        let profilesResult = prefsReader.readRuleProfiles()

        // The SAME resolution startup runs (delivered / last-known-good / none) —
        // one function, so a live reload can never reach a conclusion startup
        // would not have. In particular: a profile REMOVED at runtime falls back
        // to the snapshot and keeps enforcing (with its break-glass), and it can
        // never drop a configured Mac into the pass-through bootstrap state.
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: configResult.value,
            configPresent: configPresent,
            lastKnownGood: lastKnownGood,
            bypassResolver: bypassResolver
        )
        config = effective.config
        (authDB as? AuthorizationDBEffectiveConfigReceiving)?.adoptEffectiveConfig(config)
        awaitingConfig = effective.isAwaitingConfig
        bypassUnresolvable = effective.bypassUnresolvable
        for entry in effective.unresolvedBypassEntries {
            DaemonLog.integrity.error("policy reload: pamBypass \(entry, privacy: .public) does not resolve on this Mac")
        }
        if bypassUnresolvable {
            DaemonLog.integrity.error(
                "policy reload: NO pamBypass entry resolves on this Mac — zero working break-glass; an enforcing profile in this state is not adopted (degraded(bypass_unresolvable))"
            )
        }
        profiles = profilesResult.value
        promptsConfig = prefsReader.readPrompts().value
        jitPolicy = prefsReader.readJITAdmin().value
        noteSudoGatingPosture()
        await updateJamfConnectObserver()
        for note in effective.notes {
            DaemonLog.integrity.notice("policy reload: \(note, privacy: .public)")
        }
        warnUnresolvableSudoPatterns()

        // The old policy's cached allows must never outlive the policy that
        // produced them (a reloaded deny rule wins immediately).
        await sessionCache.removeAll()
        // Nor may its grants: a grant whose rule is gone is revoked, and a
        // grant with no expiry is bounded (time-bound on) or revoked (off).
        await alignGrantsWithPolicy(context: "policy reload")

        // Kill switch delivered live: revoke grants, demote JIT admins, restore
        // the authdb, and stop enforcing.
        guard config.daemonEnabled else {
            // The rule set the daemon evaluates under a kill switch must be EMPTY,
            // regardless of how the kill switch arrived. Startup carries `profiles: []`
            // in its ``StartupOutcome``; the reload path had just set `profiles`
            // to the delivered rules above, so clear them here — otherwise a daemon
            // consulted under a kill switch would evaluate a DIFFERENT rule set on
            // the reload path than on the startup path (a divergent decision
            // surface). pam returns PAM_IGNORE under the kill switch and no longer
            // consults the daemon, but this keeps the daemon's own decision surface
            // empty and arrival-path-independent.
            profiles = []
            // No policy is served, so there is nothing left to apply: a failed
            // restore below is retried through the uncommitted signature.
            authDBNotFullyApplied = false
            // Coarse grant removed FIRST (ordering preserved), via the serialized
            // provisioning path so it cannot overlap/lose to an in-flight apply:
            // the sudoers drop-in must never outlive the fine gate, or an enrolled
            // standard user could run the curated commands through plain sudo with
            // no argv/deny/prompt policy. `performProvisioning` clears
            // `lastResolvedIDPUsers` on this (daemonEnabled == false) path.
            let removed = await provisionSudoers()
            if let jitManager { _ = await jitManager.demoteAll() }
            _ = try? await grantStore.revokeAll(now: now())
            // A failed restore strands Serberus-gated rights (e.g. a `deny` on a
            // Settings pane) under a kill switch. Record it — degraded
            // authdb_failure, not kill_switch — and do NOT commit the signature,
            // so the next tick re-runs this teardown and retries the restore.
            var authDBRestored = true
            do {
                try await authDB.reconcile(profiles: [])
            } catch {
                authDBRestored = false
                DaemonLog.integrity.error(
                    "kill switch: AuthorizationDB restore FAILED (will retry next tick): \(String(describing: error), privacy: .public)"
                )
                await emitIntegrity(.authDBRestore,
                                    "kill switch: AuthorizationDB restore failed (\(error)); retrying next reload tick")
            }
            if authDBRestored {
                await stateController.transition(to: .killSwitch, reason: nil,
                                                 enforcementMode: config.enforcementMode)
            } else {
                await stateController.transition(to: .degraded, reason: .authDBFailure,
                                                 enforcementMode: config.enforcementMode)
            }
            scheduleMonitoredSetRefresh()
            await emitIntegrity(.killSwitch, "daemon disabled via managed-preferences reload")
            // Commit the signature only if the drop-in removal AND the authdb
            // restore both landed; either failure is retried next tick.
            if removed && authDBRestored { lastPolicySignature = signature }
            return
        }

        // Awaiting config (bootstrap): enforce nothing, but MUTATE TOWARD the native
        // state — do not skip. `reconcile([])` RESTORES every Serberus-gated authdb
        // right, and `provisionSudoers()` against the empty effective config REMOVES
        // any curated drop-in. This is what cleans up a Mac that adopted a config,
        // mutated the system, then re-entered awaiting-config (e.g. its snapshot
        // save had failed): otherwise a deny-classed right or an enrolled standard
        // user's drop-in would be stranded while pam passes sudo through — ungated
        // elevation. What we avoid is APPLYING policy, never the restore/remove.
        var authDBError = false
        let provisioned: Bool
        do {
            try await authDB.reconcile(profiles: AuthorizationDBApplier.profilesToApply(
                profiles, mode: config.enforcementMode, awaitingConfig: effective.isAwaitingConfig))
            lastAuthDBFailure = nil
        } catch {
            authDBError = true
            lastAuthDBFailure = error.localizedDescription
            DaemonLog.integrity.error("reload authdb reconcile failed (retrying on each reload tick): \(String(describing: error), privacy: .public)")
        }
        // The signature is still committed below: a failed reconcile is
        // retried on its own (``retryAuthDBReconcile()``), not by re-running
        // this whole pass every tick.
        authDBNotFullyApplied = authDBError

        // Rebuild (or, under the empty bootstrap config, remove) the coarse sudoers
        // drop-in for the reloaded policy/enrollment. Non-fatal and gated out of
        // resolveState below — a sudoers failure keeps the prior-good file and never
        // degrades the daemon.
        provisioned = await provisionSudoers()

        lastStateInputs = StartupCoordinator.StateInputs(
            configInvalid: configPresent && !configResult.findings.isEmpty,
            grantsError: false,
            authDBError: authDBError,
            rulesError: !profilesResult.findings.isEmpty,
            fdaReady: pppc.fullDiskAccessReady(),
            hasProfiles: !profiles.isEmpty,
            awaitingConfig: effective.isAwaitingConfig,
            configMissing: effective.reportsConfigMissing,
            pamNotWired: pamGateBlocked,
            bypassUnresolvable: bypassUnresolvable
        )
        let resolved = StartupCoordinator.resolveState(lastStateInputs)
        let published = (authDB as? AuthPluginHealthReporting)?
            .overlayAuthPluginHealth(state: resolved.state, reason: resolved.reason) ?? resolved
        await stateController.transition(to: published.state, reason: published.reason,
                                         enforcementMode: config.enforcementMode)
        scheduleMonitoredSetRefresh()
        await emitIntegrity(.policyChange,
                            "policy reloaded from managed preferences (\(profiles.count) profile(s))")

        // Commit the signature only when the drop-in provisioning succeeded, so a
        // failed shrink/grow is re-attempted on the next tick.
        if provisioned { lastPolicySignature = signature }
    }

    /// Re-runs only the AuthorizationDB reconcile for the served policy and
    /// mode, on a reload tick whose policy signature did not move, while the
    /// last one failed (``authDBNotFullyApplied``). Nothing else in the pass
    /// re-runs: not the allow-cache clear, the grant alignment, the drop-in
    /// provisioning or the "policy reloaded" event.
    ///
    /// A failure keeps `degraded(authdb_failure)` and is logged at error level
    /// only when it differs from the last one. On success the state is
    /// re-resolved from the inputs of the pass that failed, with the PAM-gate
    /// and Full Disk Access verdicts read again: the precedence a reload
    /// applies, without the AuthorizationDB failure.
    private func retryAuthDBReconcile() async {
        guard config.daemonEnabled else {
            authDBNotFullyApplied = false
            return
        }
        do {
            try await authDB.reconcile(profiles: AuthorizationDBApplier.profilesToApply(
                profiles, mode: config.enforcementMode, awaitingConfig: awaitingConfig))
        } catch {
            let failure = error.localizedDescription
            if failure != lastAuthDBFailure {
                lastAuthDBFailure = failure
                DaemonLog.integrity.error(
                    "AuthorizationDB still not fully applied (retrying on each reload tick): \(failure, privacy: .public)")
            } else {
                DaemonLog.integrity.debug("AuthorizationDB retry failed as before: \(failure, privacy: .public)")
            }
            return
        }
        authDBNotFullyApplied = false
        lastAuthDBFailure = nil
        lastStateInputs.authDBError = false
        lastStateInputs.fdaReady = pppc.fullDiskAccessReady()
        lastStateInputs.pamNotWired = pamGateBlocked
        let resolved = StartupCoordinator.resolveState(lastStateInputs)
        let published = (authDB as? AuthPluginHealthReporting)?
            .overlayAuthPluginHealth(state: resolved.state, reason: resolved.reason) ?? resolved
        await stateController.transition(to: published.state, reason: published.reason,
                                         enforcementMode: config.enforcementMode)
        DaemonLog.integrity.notice("AuthorizationDB retry succeeded; the served policy is fully applied")
        await emitIntegrity(.authDBModification,
                            "AuthorizationDB retry succeeded: every right and composition of the served policy is applied (authdb_failure cleared)")
    }

    /// Carries a failed startup reconcile into the reload loop, which then
    /// retries it (``retryAuthDBReconcile()``). The kill switch's failed
    /// restore is not carried: startup withholds the policy signature for it.
    private func adoptStartupAuthDBResult(_ outcome: StartupOutcome) {
        authDBNotFullyApplied = outcome.authDBFailed
        if let inputs = outcome.stateInputs { lastStateInputs = inputs }
    }

    /// Leaving-enforce fast path: while the served config is `enforce` (the only mode in
    /// which the drop-in exists), a delivered config that is a kill switch or a
    /// non-enforce mode removes the drop-in immediately, through the serialized
    /// provisioning chain. Cheap (one managed-prefs read) and deliberately
    /// resolver-free: it never snapshots, and an ABSENT profile is not "leaving
    /// enforce" (the last-known-good keeps enforcing). The full pass that
    /// follows re-provisions from the adopted config as usual (idempotent).
    private func removeDropInIfLeavingEnforce() async {
        guard config.daemonEnabled, config.enforcementMode == .enforce, prefsReader.configIsPresent() else { return }
        let delivered = prefsReader.readConfig().value
        guard !delivered.daemonEnabled || delivered.enforcementMode != .enforce else { return }
        DaemonLog.integrity.notice(
            "policy reload: leaving enforce (\(delivered.daemonEnabled ? delivered.enforcementMode.rawValue : "kill switch", privacy: .public)); removing the coarse sudoers drop-in first"
        )
        earlyDropInRemoval = await provisionSudoers(forceRemove: true)
    }

    /// The redacted argv the debug event list shows as the full attempted
    /// command — ONLY while debug mode is on, `nil` otherwise. It is kept apart
    /// from the decision log (see ``recordDebugArguments(_:for:)``): that log is
    /// readable by every local user, so argv reaches it only when a rule opts
    /// in with `logArguments`. Secrets are still redacted.
    private func debugCapturedArgs(_ requestArgv: [String], program: String?) -> [String]? {
        guard debugModeEnabled, !requestArgv.isEmpty else { return nil }
        return ArgumentRedactor.redact(requestArgv, program: program)
    }

    /// Hands debug-captured arguments for a logged decision to the root-only
    /// recent-events list (`recent-events.json` and the EA copy), never to the
    /// decision log.
    private nonisolated static func recordDebugArguments(_ arguments: [String]?, for event: DecisionEvent,
                                                         in writer: RecentEventsWriter?) {
        guard event.arguments == nil, let arguments, let writer else { return }
        writer.debugArguments.record(eventID: event.eventID, arguments: arguments, at: event.timestamp)
    }

    /// Re-applies argument redaction to a logged decision WITH the program it
    /// belongs to. The event initializer only sees the argv (pam hands the
    /// command separately, so `argv[0]` is the first argument, not the tool), so
    /// the tool-specific rules (`security -w`, `curl -u`, …) need the event's
    /// `sudoCommand` supplied here. Idempotent over already-redacted argv.
    static func redactingArguments(_ outcome: PAMEvaluator.Outcome) -> PAMEvaluator.Outcome {
        guard let arguments = outcome.event.arguments else { return outcome }
        var event = outcome.event
        event.arguments = ArgumentRedactor.redact(arguments, program: event.sudoCommand)
        return PAMEvaluator.Outcome(
            response: outcome.response,
            event: event,
            issuedGrant: outcome.issuedGrant,
            promptDirective: outcome.promptDirective
        )
    }

    private func startHealthMonitor(listener: XPCListenerService) async {
        let probe = DaemonHealthProbe(
            listener: listener,
            grantStore: grantStore,
            sentinelPushService: sentinelPushService,
            esfMonitor: esfMonitor,
            now: now
        )
        let stateController = self.stateController
        let exitProcess = self.exitProcess
        let monitor = HealthMonitor(checks: probe) { failures in
            // A health-triggered restart is the spec's `xpc_failure` cause.
            await stateController.transition(to: .degraded, reason: .xpcFailure)
            DaemonLog.integrity.critical(
                "exiting for launchd restart: \(failures.joined(separator: ", "), privacy: .public)"
            )
            exitProcess(1)
        }
        await monitor.start()
        healthMonitor = monitor
    }

    private func ensureDirectories() {
        for directory in [paths.supportDirectory, paths.logDirectory, paths.authDBBackupDirectory] {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    private func emitIntegrity(_ kind: IntegrityEvent.Kind, _ detail: String) async {
        guard let integrityLogger else { return }
        let event = IntegrityEvent(timestamp: now(), kind: kind, detail: detail, daemonVersion: version.daemonVersion)
        try? await integrityLogger.log(event)
    }

    private var representativePolicyVersion: String? {
        profiles.map(\.policyVersion).max()
    }

    /// Emits a load-time diagnostic for any `sudo` rule whose literal-path
    /// `commandPattern` neither resolves through a symlink nor exists on disk —
    /// a rule that will silently match nothing and fail closed (the
    /// symlink-absent trap behind the `jamf` deny). Runs once per policy load,
    /// so it never fires per request and only re-emits when the policy changes.
    private func warnUnresolvableSudoPatterns() {
        for warning in PAMEvaluator.unresolvableSudoCommandPatterns(profiles, canonicalizer: PathCanonicalizer()) {
            DaemonLog.integrity.notice("policy load: \(warning, privacy: .public)")
        }
    }

    /// Test seam: injects loaded policy without running the platform-bound
    /// startup (which would start the XPC listener). Internal — reachable only
    /// via `@testable import`, never part of the public API.
    func loadPolicyForTesting(
        profiles: [RuleProfile],
        config: SerberusConfig,
        prompts: PromptsConfig = PromptsConfig()
    ) {
        self.profiles = profiles
        self.config = config
        self.promptsConfig = prompts
    }

    /// Test seam: the debug-mode flag, as a reload tick would read it.
    func setDebugModeForTesting(_ enabled: Bool) {
        debugModeEnabled = enabled
    }

    /// Test seam: the JIT policy, as a reload would adopt it.
    func loadJITPolicyForTesting(_ policy: JITAdminPolicy) async {
        jitPolicy = policy
        await updateJamfConnectObserver()
    }

    /// Test seam: installs the JIT manager as `start()` does, so requests and
    /// the reload tick's sweep (``expireOverdueJITForTesting()``) run through it.
    func setJITManagerForTesting(_ manager: JITAdminManager) {
        jitManager = manager
    }

    /// Test seam: adopts `config` and applies the gating-transition rule, as a
    /// reload does.
    func adoptConfigForTesting(_ config: SerberusConfig, awaitingConfig: Bool = false) {
        self.config = config
        self.awaitingConfig = awaitingConfig
        noteSudoGatingPosture()
    }

    /// Test seam: the sudo session cache, so tests can assert population,
    /// TTL behavior, and invalidation without a live clock.
    func sessionCacheForTesting() -> SessionGrantCache { sessionCache }

    /// Test seam: the currently-loaded rule profiles, so a test can prove the
    /// kill-switch path clears them to EMPTY on the reload path exactly as
    /// startup does. Internal — reachable only via `@testable import`.
    func profilesForTesting() -> [RuleProfile] { profiles }

    /// Test seam: drive one serialized coarse-drop-in provisioning pass
    /// through the same chained entry point the console-user watch uses, so the
    /// reentrancy/serialization guarantee can be exercised without a live
    /// `SCDynamicStore` console-user watch. Internal — reachable only via
    /// `@testable import`.
    @discardableResult
    func provisionSudoersForTesting() async -> Bool {
        await provisionSudoers()
    }

    /// Test seam: drive one watchdogged reload pass — the exact call the 30s loop
    /// makes — so the deadline, leak guard, and escalation can be exercised
    /// without waiting out a live timer. Internal — reachable only via
    /// `@testable import`.
    func runWatchdoggedReloadPassForTesting() async {
        await runWatchdoggedReloadPass()
    }

    /// Test seam: whether the AuthorizationDB reconcile is waiting for a retry.
    func authDBNotFullyAppliedForTesting() -> Bool { authDBNotFullyApplied }

    /// Test seam: what ``start()`` does with its ``StartupOutcome`` (adopt the
    /// config and policy, publish the state, commit the initial signature,
    /// carry a failed reconcile into the reload loop), without the
    /// platform-bound rest of startup.
    func adoptStartupOutcomeForTesting(_ outcome: StartupOutcome) async {
        config = outcome.config
        profiles = outcome.profiles
        awaitingConfig = outcome.awaitingConfig
        bypassUnresolvable = outcome.bypassUnresolvable
        await stateController.transition(to: outcome.state, reason: outcome.degradedReason,
                                         enforcementMode: outcome.config.enforcementMode)
        lastPolicySignature = await policySignature()
        adoptStartupAuthDBResult(outcome)
    }

    /// Test seam: the watchdog's leak guard, so a test can prove a LATE-completing
    /// pass clears it (transient self-heal) rather than latching the daemon out of
    /// all future reloads.
    func reloadPassOutstandingForTesting() -> Bool { reloadPassOutstanding }

    /// Test seam: injects the prompt push service without running `start()`, so
    /// the prompt round-trip in ``handlePAM(_:)`` can be exercised end-to-end.
    func setSentinelPushServiceForTesting(_ service: SentinelPushService) {
        self.sentinelPushService = service
    }

    /// Re-stamps a conditional prompt grant at approval time, preserving its
    /// policy duration so deliberation latency does not shorten the window.
    private static func restamp(_ grant: Grant, grantedAt: Date) -> Grant {
        let duration = (grant.expiresAt ?? grant.grantedAt).timeIntervalSince(grant.grantedAt)
        return Grant(
            grantID: grant.grantID,
            user: grant.user,
            uid: grant.uid,
            ruleID: grant.ruleID,
            profileKey: grant.profileKey,
            teamID: grant.teamID,
            binaryHash: grant.binaryHash,
            canonicalPath: grant.canonicalPath,
            argvPattern: grant.argvPattern,
            grantedAt: grantedAt,
            expiresAt: grant.expiresAt == nil ? nil : grantedAt.addingTimeInterval(duration),
            policyVersion: grant.policyVersion
        )
    }

    private static func makeFailSafeConfig() -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil,
            jamfAPIClientID: nil,
            jamfAPIClientSecret: nil,
            daemonEnabled: true,
            enforcementMode: .enforce,
            sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60,
            pamBypass: PAMBypass()
        )
    }
}

// MARK: - DaemonQuerying

extension DaemonController: DaemonQuerying {
    public func handlePAM(_ request: PAMRequest) async -> PAMResponse {
        let timestamp = now()

        // Bootstrap window (the up-to-one-poll gap between a config landing and the
        // daemon's next reload). pam re-reads the config plist on EVERY auth, so the
        // instant the profile lands pam sees `enforce` + the new pamBypass: a bypass
        // user gets PAM_IGNORE, but a NON-bypass user is sent here — to a daemon that
        // may still be sitting in awaitingConfig from before the profile landed.
        // Monitor mode fails CLOSED to a deny (PAMEvaluator), so answering now would
        // wrongly deny that user for up to the poll interval. Re-resolve synchronously
        // first: a cheap managed-prefs read that, if a usable config is now present,
        // adopts it (full reload) and clears awaitingConfig so we evaluate against the
        // real policy below. If it is STILL genuine bootstrap afterwards (which pam
        // would not have consulted the daemon for), fall back to a logged defensive
        // deny rather than a monitor-mode pass that cannot happen from here.
        if awaitingConfig {
            await reloadPolicyIfChanged()
            if awaitingConfig {
                DaemonLog.decisions.notice(
                    "PAM request while awaiting config (bootstrap); no usable config on re-resolve — defensive deny user=\(request.user, privacy: .public)"
                )
                return .deny
            }
        }

        // A JIT admin inside their window (Serberus grant or observed Jamf
        // Connect elevation) who is in `admin` right now gets sudo exactly as
        // native macOS gives it: pam steps aside and keeps sudo's own ticket.
        if let native = await nativeAdminResponse(for: request, at: timestamp) {
            return native
        }

        // Session-cache probe: a cached allow for this exact
        // user + canonical command + binary content + exact argv answers
        // without a second evaluation or prompt. Enforce-mode only — audit and
        // monitor replies must always reflect a live evaluation (or its
        // defensive deny). Argv is part of the match: a cached allow for one
        // argument vector must never answer a different one, which could match
        // a different rule (including a higher-priority deny).
        // The resolved identity is reused by the evaluator on a miss, so the
        // binary is canonicalized and hashed exactly once per request.
        let requestArgv: [String]
        let requestProgram: String?
        if case let .sudo(command, argv, _) = request.kind {
            requestArgv = argv
            requestProgram = command
        } else {
            requestArgv = []
            requestProgram = nil
        }
        let resolvedCommand = evaluator.resolveCommand(request)
        if config.enforcementMode == .enforce,
           let resolved = resolvedCommand,
           let hit = await sessionCache.lookup(
               user: request.user,
               canonicalPath: resolved.canonicalPath,
               binaryHash: resolved.identity.sha256,
               argv: requestArgv,
               now: timestamp
           ) {
            return await respondFromSessionCache(hit, request: request, resolved: resolved, timestamp: timestamp)
        }

        let activeGrants = (try? await grantStore.activeGrants(for: request.user, now: timestamp)) ?? []
        let environment = PAMEvaluator.Environment(
            profiles: profiles,
            config: config,
            prompts: promptsConfig,
            activeGrants: activeGrants,
            deviceSerial: deviceSerial,
            version: version,
            policyVersion: representativePolicyVersion,
            now: timestamp
        )
        let outcome = Self.redactingArguments(
            evaluator.evaluate(request, environment: environment, resolvedCommand: resolvedCommand)
        )

        // Persist a timed grant before returning allow, so it survives restart.
        if let grant = outcome.issuedGrant {
            do {
                try await grantStore.insert(grant)
                scheduleMonitoredSetRefresh()
            } catch {
                // Fail closed, consistent with the degraded `grants_db_error`
                // semantics ("deny all timed grants; allow silent"): an allow
                // carrying a grantID that was never persisted would escape
                // revocation and the ESF exec gate.
                DaemonLog.decisions.error(
                    "grant persistence failed for \(request.user, privacy: .public); denying (fail closed): \(error.localizedDescription, privacy: .public)"
                )
                var denied = outcome.event
                denied.outcome = DecisionEvent.outcome(for: .deny, mode: config.enforcementMode)
                denied.grantID = nil
                denied.grantDurationSeconds = 0
                if let decisionLogger { try? await decisionLogger.log(denied) }
                return .deny
            }
        }

        // Prompt path: the terminal outcome isn't known yet, so do NOT
        // write a decision-log event now — at request time a prompt classifies as
        // "denied", which would falsify the audit trail. Push to the Sentinel, tell
        // PAM to poll, and log the real verdict from the detached resolution task.
        if let directive = outcome.promptDirective {
            guard let sentinelPushService else {
                // No push service wired — a prompt cannot be satisfied; fail closed.
                DaemonLog.decisions.notice(
                    "PAM prompt unsatisfiable (no sentinel service) user=\(request.user, privacy: .public)"
                )
                return .deny
            }
            // Keep the daemon's wait strictly inside PAM's fixed poll window so a
            // late approval can never resolve (and persist a grant) after PAM has
            // already given up and denied the authentication. This matches the
            // clamp the evaluator applies to the Sentinel-facing countdown.
            let timeout = TimeInterval(min(config.promptTimeoutSeconds, PAMEvaluator.maxPromptWindowSeconds))
            let context = directive.context
            let grantTemplate = directive.grantOnApproval
            let cacheTTL = directive.cacheSeconds
            let cache = sessionCache
            let commandKey = resolvedCommand
            let baseEvent = outcome.event
            let mode = config.enforcementMode
            // Captured on-actor now (debug gate + redaction) so the detached
            // resolution task can stamp the full attempted command.
            let debugArgv = debugCapturedArgs(requestArgv, program: requestProgram)
            let eventsWriter = recentEventsWriter
            let store = grantStore
            let esf = esfMonitor
            let logger = decisionLogger
            let clock = now
            let user = request.user
            let promptArgv = requestArgv
            DaemonLog.decisions.notice(
                "PAM prompt raised user=\(user, privacy: .public) rule=\(baseEvent.ruleID ?? "none", privacy: .public)"
            )
            Task {
                let response = await sentinelPushService.requestApproval(
                    context: context, forUID: DaemonController.userID(named: user), timeout: timeout)
                let approved = response.verdict == .approved
                // Issue the timed grant only on approval, stamped at approval time
                // so deliberation latency does not eat into the grant window.
                var persistedGrantID: UUID?
                var grantPersistenceFailed = false
                if approved {
                    if let template = grantTemplate {
                        let grant = Self.restamp(template, grantedAt: clock())
                        do {
                            try await store.insert(grant)
                            persistedGrantID = grant.grantID
                            await esf?.refreshMonitoredSet()
                            // Only now — grant durable, exec gate refreshed —
                            // does the approval become visible to PAM's poll.
                            // The push service held the verdict back at
                            // resolution precisely so sudo cannot proceed on
                            // an allow whose grant was never recorded.
                            await sentinelPushService.publishVerdict(
                                for: context.requestID, verdict: .approved
                            )
                        } catch {
                            // Fail closed, mirroring the non-prompt insert-
                            // failure path: an approval whose grant never
                            // persisted would escape revocation and the ESF
                            // exec gate, so the daemon treats it as DENIED
                            // everywhere — including PAM's poll, which is
                            // published a deny because the approval was never
                            // made pollable. The true outcome (denied) is
                            // logged, no grantID is ever exposed, nothing is
                            // cached, and the ESF monitored set is refreshed
                            // so the unpersisted grant's path is policed as
                            // if the grant had been revoked.
                            grantPersistenceFailed = true
                            DaemonLog.decisions.error(
                                "prompt grant persistence failed for \(user, privacy: .public); recording denied (grant_persist_failed): \(error.localizedDescription, privacy: .public)"
                            )
                            await esf?.refreshMonitoredSet()
                            await sentinelPushService.publishVerdict(
                                for: context.requestID, verdict: .denied
                            )
                        }
                    } else {
                        // Approved with no grant to persist: nothing can fail
                        // after resolution, so publish immediately.
                        await sentinelPushService.publishVerdict(
                            for: context.requestID, verdict: .approved
                        )
                    }
                }
                // Non-approved verdicts were published by the push service at
                // resolution time; no publishVerdict call is needed (or would
                // have any effect) here.
                // The outcome the daemon stands behind: approval counts only if
                // its grant (when the rule carries one) actually persisted.
                let effectiveAllow = approved && !grantPersistenceFailed
                // Cache the approved allow for the rule's resolved TTL so an
                // identical request inside the window skips the re-prompt.
                // Skipped when grant persistence failed — a broken grants DB
                // must not hand out unrecorded repeat allows.
                if effectiveAllow, cacheTTL > 0,
                   let commandKey, !commandKey.identity.sha256.isEmpty {
                    await cache.store(
                        decision: .allow,
                        key: SessionGrantCache.Key(
                            user: user,
                            ruleID: baseEvent.ruleID ?? "unknown",
                            binaryHash: commandKey.identity.sha256,
                            argv: promptArgv
                        ),
                        canonicalPath: commandKey.canonicalPath,
                        ttlSeconds: cacheTTL,
                        now: clock()
                    )
                }
                // Record the resolved decision in the durable, signed audit trail.
                if let logger {
                    var resolved = baseEvent
                    resolved.eventID = UUID()
                    resolved.timestamp = clock()
                    // Mark this decision as prompt-driven so the fleet summary
                    // can tally prompt fatigue (the terminal verdict below is
                    // still the real outcome).
                    resolved.requiredPrompt = true
                    // The REAL outcome: an approval whose grant failed to
                    // persist is logged as denied, never as a phantom grant.
                    resolved.outcome = DecisionEvent.outcome(for: effectiveAllow ? .allow : .deny, mode: mode)
                    resolved.grantID = persistedGrantID
                    // Duration only for a grant that actually persisted — a
                    // failed insert must not log a phantom grant window.
                    resolved.grantDurationSeconds = persistedGrantID != nil ? baseEvent.grantDurationSeconds : 0
                    // The user's stated reason, redacted like every logged
                    // free-text field before it reaches the signed trail.
                    resolved.justification = response.justificationText.map(ArgumentRedactor.redact(text:))
                    // Debug mode: the full attempted command goes to the root-only
                    // event list, not onto the (world-readable) logged event.
                    DaemonController.recordDebugArguments(debugArgv, for: resolved, in: eventsWriter)
                    try? await logger.log(resolved)
                }
                let resolvedVerdict = grantPersistenceFailed ? "denied (grant_persist_failed)" : response.verdict.rawValue
                DaemonLog.decisions.notice(
                    "PAM prompt resolved \(resolvedVerdict, privacy: .public) user=\(user, privacy: .public)"
                )
            }
            return outcome.response
        }

        // Populate the session cache with an enforce-mode allow whose matched
        // rule resolved a nonzero TTL (per-rule `cacheSeconds`, else the
        // global `sudoCacheSeconds`; 0 = never). Deny is never cached — the
        // cache itself refuses deny as a second line of defense.
        if config.enforcementMode == .enforce,
           outcome.response.isAllow,
           outcome.response.cacheSeconds > 0,
           let resolved = resolvedCommand,
           !resolved.identity.sha256.isEmpty {
            await sessionCache.store(
                decision: .allow,
                key: SessionGrantCache.Key(
                    user: request.user,
                    ruleID: outcome.event.ruleID ?? "unknown",
                    binaryHash: resolved.identity.sha256,
                    argv: requestArgv
                ),
                canonicalPath: resolved.canonicalPath,
                ttlSeconds: outcome.response.cacheSeconds,
                now: timestamp
            )
        }

        // Non-prompt: the outcome is terminal now, so log it immediately. Under
        // debug mode, the (redacted) argv goes to the root-only event list so it
        // shows the full attempted command even for a no-matching-rule deny;
        // the logged event itself keeps no argv unless its rule opted in.
        if let decisionLogger {
            let event = outcome.event
            Self.recordDebugArguments(debugCapturedArgs(requestArgv, program: requestProgram),
                                      for: event, in: recentEventsWriter)
            try? await decisionLogger.log(event)
        }
        DaemonLog.decisions.notice(
            "PAM \(outcome.event.outcome.rawValue, privacy: .public) user=\(request.user, privacy: .public) rule=\(outcome.event.ruleID ?? "none", privacy: .public)"
        )
        return outcome.response
    }

    /// The `native` reply when ``NativeAdminGate`` qualifies `request` (a sudo
    /// request from a JIT admin inside a window of the live JIT provider, live
    /// in `admin`), logged as a native decision; nil otherwise. Never under the
    /// kill switch: the daemon is off then and pam passes sudo through without
    /// asking.
    private func nativeAdminResponse(for request: PAMRequest, at timestamp: Date) async -> PAMResponse? {
        guard config.daemonEnabled, case let .sudo(command, _, _) = request.kind,
              let uid = PAMEvaluator.uid(forUser: request.user) else { return nil }
        let grants = (try? await grantStore.activeGrants(for: request.user, now: timestamp)) ?? []
        let window = jitPolicy.provider == .jamfConnect
            ? await jamfConnectObserver?.activeWindow(for: request.user) : nil
        // The provider as it is after the awaits above: a policy that turned
        // Serberus JIT off ends `jit-native` now, not at the next tick's sweep.
        guard let source = await NativeAdminGate.evaluate(
            user: request.user, uid: uid, provider: jitPolicy.provider, activeGrants: grants,
            jamfConnectWindow: window, membership: membership
        ) else { return nil }

        let sourcePath: String
        if case let .jamfConnect(window) = source { sourcePath = window.processImagePath } else {
            sourcePath = JITAdmin.grantCanonicalPath
        }
        let event = DecisionEvent(
            timestamp: timestamp,
            outcome: DecisionEvent.outcome(for: .allow, mode: config.enforcementMode),
            enforcementMode: config.enforcementMode,
            authURI: nil,
            sudoCommand: command,
            arguments: nil,
            processPath: sourcePath,
            processTeamID: "",
            processHash: "",
            userName: request.user,
            userUID: Int(uid),
            ruleID: source.ruleID,
            profileKey: JITAdmin.grantProfileKey,
            grantID: source.grantID,
            justification: nil,
            grantDurationSeconds: 0,
            cacheHit: false,
            deviceSerial: deviceSerial,
            daemonVersion: version.daemonVersion,
            pamModuleVersion: version.pamModuleVersion,
            policyVersion: representativePolicyVersion ?? "unknown"
        )
        if let decisionLogger { try? await decisionLogger.log(event) }
        DaemonLog.decisions.notice(
            "PAM native (JIT admin, \(source.ruleID, privacy: .public)) user=\(request.user, privacy: .public)"
        )
        return .native(ruleID: source.ruleID, grantID: source.grantID)
    }

    /// Answers a PAM request from the sudo session cache. A cache hit is
    /// still a decision: it writes the signed decision-log entry (with
    /// `cacheHit` set) before replying, so the audit trail never skips an
    /// elevation the daemon allowed.
    private func respondFromSessionCache(
        _ hit: SessionGrantCache.CommandHit,
        request: PAMRequest,
        resolved: PAMEvaluator.ResolvedCommand,
        timestamp: Date
    ) async -> PAMResponse {
        let event = DecisionEvent(
            timestamp: timestamp,
            outcome: DecisionEvent.outcome(for: .allow, mode: config.enforcementMode),
            enforcementMode: config.enforcementMode,
            authURI: nil,
            sudoCommand: resolved.canonicalPath,
            // The matched rule is not re-resolved on a hit, so its
            // `logArguments` opt-in is unknown — never log argv here.
            arguments: nil,
            processPath: resolved.identity.canonicalPath,
            processTeamID: resolved.identity.teamID ?? "",
            processHash: resolved.identity.sha256,
            userName: request.user,
            userUID: PAMEvaluator.uid(forUser: request.user).map { Int($0) } ?? -1,
            ruleID: hit.ruleID,
            profileKey: nil,
            grantID: nil,
            justification: nil,
            grantDurationSeconds: 0,
            cacheHit: true,
            deviceSerial: deviceSerial,
            daemonVersion: version.daemonVersion,
            pamModuleVersion: version.pamModuleVersion,
            policyVersion: representativePolicyVersion ?? "unknown"
        )
        if let decisionLogger { try? await decisionLogger.log(event) }
        DaemonLog.decisions.notice(
            "PAM granted (session cache) user=\(request.user, privacy: .public) rule=\(hit.ruleID, privacy: .public)"
        )
        return PAMResponse(decision: .allow, cacheSeconds: 0, grantID: nil, ruleID: hit.ruleID)
    }

    public func currentDaemonState() async -> DaemonState {
        await stateController.current().state
    }

    public func activeGrants(forUser user: String?) async -> [Grant] {
        let timestamp = now()
        if let user {
            return (try? await grantStore.activeGrants(for: user, now: timestamp)) ?? []
        }
        return (try? await grantStore.activeGrants(now: timestamp)) ?? []
    }

    /// The daemon's current status as one snapshot. Diagnostics only: no XPC
    /// method serves it.
    func healthReport() async -> HealthReport {
        let current = await stateController.current()
        let grantCount = (try? await grantStore.activeGrants(now: now()))?.count ?? 0
        return HealthReport(
            state: current.state,
            degradedReason: current.reason,
            daemonVersion: version.daemonVersion,
            policyVersion: representativePolicyVersion,
            enforcementMode: config.enforcementMode,
            loadedProfileKeys: profiles.map(\.profileKey).sorted(),
            activeGrantCount: grantCount,
            generatedAt: now()
        )
    }

    public func userRules() async -> SentinelRulesSnapshot {
        SentinelRulesSnapshot(
            profiles: profiles,
            enforcementMode: config.enforcementMode,
            generatedAt: now()
        )
    }

    // MARK: JIT local-admin

    public func jitAdminInfo() async -> JITAdminInfo {
        JITAdminInfo(policy: jitPolicy)
    }

    public func requestAdminElevation(user: String, justification: String) async -> JITAdminResult {
        // Kill switch: nothing new is granted while Serberus is turned off.
        // The kill switch already demoted every JIT admin; a fresh request must
        // not put one straight back.
        // The Jamf Connect hand-off is not refused here: the Sentinel launches
        // Jamf Connect itself (``jitAdminInfo()`` keeps describing it under the
        // kill switch), and a misrouted request is refused by the manager.
        guard config.daemonEnabled || jitPolicy.provider == .jamfConnect else {
            return JITAdminResult(
                outcome: .denied,
                message: "Just-in-time admin is unavailable while Serberus is turned off on this Mac."
            )
        }
        guard let jitManager else {
            return JITAdminResult(outcome: .denied, message: "Just-in-time admin is unavailable.")
        }
        guard let uid = Self.userID(named: user) else {
            return JITAdminResult(outcome: .denied, message: "Couldn't identify your account.")
        }
        let result = await jitManager.requestElevation(user: user, uid: uid, justification: justification)
        scheduleMonitoredSetRefresh()
        return result
    }

    public func endAdminElevation(user: String) async -> Bool {
        guard let jitManager else { return false }
        let ended = await jitManager.endElevation(user: user)
        if ended { scheduleMonitoredSetRefresh() }
        return ended
    }

    /// Collects diagnostics a standard user cannot read, for Serberus Intel.
    ///
    /// Read-only: it runs `log show` with a **hard-coded** predicate and copies
    /// files. It touches no policy, no grants, and no authdb, so it cannot
    /// change what this Mac enforces — a diagnostics path must never be able to
    /// mutate the thing it is diagnosing.
    ///
    /// Runs off the actor: `log show` over a long window takes seconds to
    /// minutes, and blocking the daemon actor would stall every sudo decision
    /// on the Mac behind a log export.
    public func collectPrivilegedDiagnostics(
        request: IntelRequest,
        callerUID: uid_t
    ) async -> IntelCollectionOutcome {
        let collector = PrivilegedLogCollector(paths: paths)
        return await Task.detached(priority: .userInitiated) { () -> IntelCollectionOutcome in
            do {
                let handoff = try collector.collect(request: request, callerUID: callerUID)
                DaemonLog.integrity.notice(
                    "Intel: collected privileged diagnostics for uid \(callerUID, privacy: .public) — \(handoff.files.count, privacy: .public) file(s)"
                )
                return .collected(handoff)
            } catch {
                DaemonLog.integrity.error(
                    "Intel: privileged collection failed: \(String(describing: error), privacy: .public)"
                )
                return .failed(error.localizedDescription)
            }
        }.value
    }

    /// At most this many live `log show` polls in flight, across the
    /// Authorizations view and Capture pollers of every connected Sentinel.
    ///
    /// Each poll pins a cooperative-pool thread (and a root `log` child) for
    /// the life of the `log show` — bounded by `PrivilegedLogCollector.pollTimeout`,
    /// but unbounded in COUNT it would let a slow logd plus a few 2-second
    /// tailers exhaust the pool and stall PAM routing: a standard-user-
    /// triggerable denial of sudo. The tailers tolerate a "busy" failure (they
    /// report once and poll again; their lookback window exceeds the interval,
    /// so nothing is missed). The counter itself lives with the actor's other
    /// stored state (extensions cannot hold stored properties).
    static let maxInFlightLogPolls = 2

    /// Recent authorization-right attempts for the live Authorizations view.
    ///
    /// Off the actor for the same reason as ``collectPrivilegedDiagnostics`` —
    /// a `log show` must not block sudo decisions — though this window is
    /// seconds, not days.
    public func pollAuthorizations(
        request: AuthorizationPollRequest,
        callerUID: uid_t
    ) async -> AuthorizationPollOutcome {
        guard inFlightLogPolls < Self.maxInFlightLogPolls else {
            return .failed("log poll busy — \(Self.maxInFlightLogPolls) already in flight; retry")
        }
        inFlightLogPolls += 1
        defer { inFlightLogPolls -= 1 }
        let collector = PrivilegedLogCollector(paths: paths)
        return await Task.detached(priority: .userInitiated) { () -> AuthorizationPollOutcome in
            do {
                return .collected(try collector.pollAuthorizations(request: request, callerUID: callerUID))
            } catch {
                return .failed(error.localizedDescription)
            }
        }.value
    }

    /// Recent sudo attempts (sudo's own unified-log lines, scoped to the
    /// caller) for a Sentinel Capture session. Same off-actor discipline and
    /// the same in-flight cap as the authorization poll.
    public func pollSudoAttempts(
        request: SudoPollRequest,
        callerUID: uid_t
    ) async -> SudoPollOutcome {
        guard inFlightLogPolls < Self.maxInFlightLogPolls else {
            return .failed("log poll busy — \(Self.maxInFlightLogPolls) already in flight; retry")
        }
        inFlightLogPolls += 1
        defer { inFlightLogPolls -= 1 }
        let collector = PrivilegedLogCollector(paths: paths)
        return await Task.detached(priority: .userInitiated) { () -> SudoPollOutcome in
            do {
                return .collected(try collector.pollSudoAttempts(request: request, callerUID: callerUID))
            } catch {
                return .failed(error.localizedDescription)
            }
        }.value
    }

    // MARK: Install with Serberus

    public func installSoftware(
        request: InstallRequest,
        callerUID: uid_t,
        callerUser: String?
    ) async -> InstallResult {
        let policy = prefsReader.readAppManagementPolicy()
        let installer = softwareInstaller
        let push = sentinelPushService
        let user = callerUser ?? "user"
        // Install confirms reuse the same Sentinel prompt channel as sudo, clamped
        // to the same fixed window so a request can't hang the caller forever.
        let promptTimeout = TimeInterval(min(config.promptTimeoutSeconds, PAMEvaluator.maxPromptWindowSeconds))

        // The prompt is built only from what the installer verified on the
        // staged copy: the canonical path, the headline read from the bundle
        // (or the package file name), the signer and its Team ID — never the
        // client-supplied displayName or raw path.
        let confirm: @Sendable (InstallConfirmation) async -> Bool = { item in
            // No Sentinel connected ⇒ can't confirm ⇒ fail closed.
            guard let push else { return false }
            let version = item.version.map { " \($0)" } ?? ""
            // The request row also names the file the user chose (the prompt
            // shows no separate path row for this kind of request).
            let source = SoftwareInstaller.sanitizedForDisplay(item.canonicalPath, maxLength: 300)
            let context = PromptContext(
                user: user,
                processName: PromptContext.installProcessName,
                canonicalPath: item.canonicalPath,
                teamID: item.teamID,
                signingStatus: .valid,
                humanReadableRequest: "Install “\(item.headline)”\(version) from \(source)",
                requireJustification: false,
                justificationMinLength: 0,
                timeoutSeconds: Int(promptTimeout),
                ruleName: "Install with Serberus",
                ruleDescription: "Install “\(item.headline)”\(version) — verified \(item.authority) [\(item.teamID)]"
            )
            let response = await push.requestApproval(context: context, forUID: callerUID, timeout: promptTimeout)
            return response.verdict == .approved
        }

        let (result, audit) = await installer.installAudited(
            request, callerUID: callerUID, policy: policy,
            stageID: UUID().uuidString, confirm: confirm
        )

        // Record what was actually evaluated: the canonical path (or, when the
        // request never resolved, the sanitized raw request marked as such),
        // bundle ID, team.
        let target = audit.canonicalPath
            ?? "unresolved:\(SoftwareInstaller.sanitizedForDisplay(request.sourcePath, maxLength: 1024))"
        DaemonLog.decisions.notice(
            "install-with-serberus \(result.status.rawValue, privacy: .public) user=\(user, privacy: .public) path=\(target, privacy: .public) bundle=\(audit.bundleID.map { SoftwareInstaller.sanitizedForDisplay($0, maxLength: 128) } ?? "-", privacy: .public) team=\(audit.teamID ?? "-", privacy: .public)"
        )
        await logAppManagement(eventType: "software_install", targetPath: target, teamID: audit.teamID ?? "",
                               ruleID: "install-with-serberus", callerUID: callerUID, result: result)
        return result
    }

    public func uninstallSoftware(
        request: UninstallRequest,
        callerUID: uid_t,
        callerUser: String?
    ) async -> InstallResult {
        let policy = prefsReader.readAppManagementPolicy()
        let uninstaller = softwareUninstaller
        let push = sentinelPushService
        let user = callerUser ?? "user"
        let promptTimeout = TimeInterval(min(config.promptTimeoutSeconds, PAMEvaluator.maxPromptWindowSeconds))

        // The prompt is built only from what the uninstaller established on
        // the pinned bundle: its checked name, canonical path, bundle ID, and
        // the result of actually checking its signature — never the
        // client-supplied displayName or raw path, and never an unchecked
        // "valid".
        let confirm: @Sendable (UninstallConfirmation) async -> Bool = { item in
            guard let push else { return false }
            let identity: String
            switch (item.bundleID, item.teamID) {
            case let (bundleID?, teamID?): identity = " — \(bundleID) [\(teamID)]"
            case let (bundleID?, nil): identity = " — \(bundleID), publisher unverified"
            case let (nil, teamID?): identity = " — [\(teamID)]"
            case (nil, nil): identity = " — publisher unverified"
            }
            let context = PromptContext(
                user: user,
                processName: PromptContext.uninstallProcessName,
                canonicalPath: item.canonicalPath,
                teamID: item.teamID,
                signingStatus: item.signingStatus,
                humanReadableRequest: "Move “\(item.appName)” to the Trash",
                requireJustification: false,
                justificationMinLength: 0,
                timeoutSeconds: Int(promptTimeout),
                ruleName: "Uninstall with Serberus",
                ruleDescription: "Move “\(item.appName)”\(identity) from \((item.canonicalPath as NSString).deletingLastPathComponent) to the Trash (recoverable)"
            )
            let response = await push.requestApproval(context: context, forUID: callerUID, timeout: promptTimeout)
            return response.verdict == .approved
        }

        let (result, audit) = await uninstaller.uninstallAudited(request, callerUID: callerUID, policy: policy, confirm: confirm)
        // Record what was actually evaluated: the canonical path (or, when the
        // request never resolved, the sanitized raw request marked as such),
        // bundle ID, team.
        let target = audit.canonicalPath
            ?? "unresolved:\(SoftwareInstaller.sanitizedForDisplay(request.appPath, maxLength: 1024))"
        DaemonLog.decisions.notice(
            "uninstall-with-serberus \(result.status.rawValue, privacy: .public) user=\(user, privacy: .public) path=\(target, privacy: .public) bundle=\(audit.bundleID.map { SoftwareInstaller.sanitizedForDisplay($0, maxLength: 128) } ?? "-", privacy: .public) team=\(audit.teamID ?? "-", privacy: .public)"
        )
        await logAppManagement(eventType: "software_uninstall", targetPath: target, teamID: audit.teamID ?? "",
                               ruleID: "uninstall-with-serberus", callerUID: callerUID, result: result)
        return result
    }

    /// Records an install/uninstall attempt in the signed decision log (a root
    /// change to the system is at least as audit-worthy as a sudo decision).
    /// Best-effort.
    ///
    /// The decision log is readable by every local user, so a path inside a
    /// user's folder (the package or app they picked) is logged in the
    /// ``decisionLogPath(_:)`` form: its file name and a hash of the full path.
    /// The full path goes to the unified log line above only.
    private func logAppManagement(eventType: String, targetPath: String, teamID: String, ruleID: String,
                                  callerUID: uid_t, result: InstallResult) async {
        guard let decisionLogger else { return }
        let succeeded = result.status == .installed || result.status == .removed
        let event = DecisionEvent(
            timestamp: now(),
            eventType: eventType,
            outcome: succeeded ? .granted : .denied,
            enforcementMode: config.enforcementMode,
            authURI: nil,
            sudoCommand: nil,
            arguments: nil,
            processPath: Self.decisionLogPath(targetPath),
            processTeamID: teamID,
            processHash: "",
            userName: "uid:\(callerUID)",
            userUID: Int(callerUID),
            ruleID: ruleID,
            profileKey: nil,
            grantID: nil,
            justification: Self.scrubUserPaths(result.message),
            grantDurationSeconds: 0,
            cacheHit: false,
            deviceSerial: deviceSerial,
            daemonVersion: version.daemonVersion,
            pamModuleVersion: version.pamModuleVersion,
            policyVersion: representativePolicyVersion ?? "unknown"
        )
        try? await decisionLogger.log(event)
    }

    /// The form of an install/uninstall target the world-readable decision log
    /// keeps. A path in a location every user can already list (`/Applications`,
    /// `/Library`, …) is kept whole. Anything else, above all a path inside a
    /// user's home folder or an unresolved request, becomes
    /// `…/<file name> [sha256:<first 12 hex digits of the full path's hash>]`:
    /// enough to tell attempts apart and to match them with the root-only
    /// logs, without showing other users the folders it came from.
    static func decisionLogPath(_ path: String) -> String {
        let publicRoots = ["/Applications/", "/Library/", "/System/", "/usr/", "/opt/"]
        if !path.hasPrefix("unresolved:"), !path.contains("/../"),
           publicRoots.contains(where: { path.hasPrefix($0) }) {
            return path
        }
        let raw = path.hasPrefix("unresolved:") ? String(path.dropFirst("unresolved:".count)) : path
        let name = (raw as NSString).lastPathComponent
        let digest = SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined()
        let prefix = path.hasPrefix("unresolved:") ? "unresolved:" : ""
        return "\(prefix)…/\(name.isEmpty ? "?" : name) [sha256:\(digest.prefix(12))]"
    }

    /// `message` with any path under `/Users/` shortened by ``decisionLogPath(_:)``.
    static func scrubUserPaths(_ message: String) -> String {
        guard message.contains("/Users/"),
              let pattern = try? NSRegularExpression(pattern: #"/Users/[^\s"“”]+"#) else { return message }
        var result = message
        for match in pattern.matches(in: message, range: NSRange(message.startIndex..., in: message)).reversed() {
            guard let range = Range(match.range, in: result) else { continue }
            result.replaceSubrange(range, with: decisionLogPath(String(result[range])))
        }
        return result
    }

    /// Resolves a username to its uid via the password database (0 if unknown).
    /// The uid for `user`, or nil when no such user exists. Never falls back to
    /// 0: an unknown user must be denied, not treated as root.
    static func userID(named user: String) -> uid_t? {
        guard let passwd = getpwnam(user) else { return nil }
        return passwd.pointee.pw_uid
    }

    /// Rebuilds the ESF monitored set off the actor after a grant change, so the
    /// exec gate tracks issuance/revocation without delaying the caller's reply.
    private func scheduleMonitoredSetRefresh() {
        guard let esfMonitor else { return }
        esfMonitor.updateBypass(config.pamBypass)
        Task { await esfMonitor.refreshMonitoredSet() }
    }
}

// MARK: - Production wiring

public extension DaemonController {
    /// Builds the production daemon against the real `/Library` paths, the
    /// System Keychain HMAC keys, and the live managed-preference domains.
    /// Resilient by construction: a failure to open the grant store or the
    /// keychain degrades behavior rather than aborting startup.
    static func makeProduction() -> DaemonController {
        let paths = DaemonPaths.production
        let version = DaemonVersion.read(from: paths.versionPlist)

        // Create the support/log dirs BEFORE opening the grant store or loggers:
        // SQLite's OPEN_CREATE makes the file, not its parent dir, so a missing
        // dir would fail the open (SQLITE_CANTOPEN) and silently degrade. (start()
        // also ensures these, but the store is constructed here first.)
        for directory in [paths.supportDirectory, paths.logDirectory, paths.authDBBackupDirectory] {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        let integrityLogger = try? IntegrityLogger(directory: paths.logDirectory)

        let keyProvider = productionKeyProvider(paths: paths)

        // Surface WHY the grant store failed rather than swallowing it with `try?`
        // — a security daemon degrading to NullGrantStore must say so.
        let grantStore: GrantMaintaining
        do {
            grantStore = try GrantStore(path: paths.grantDatabase.path, keyProvider: keyProvider)
        } catch {
            DaemonLog.integrity.error(
                "grant store unavailable — running degraded (grants_db_error): \(String(describing: error), privacy: .public)"
            )
            grantStore = NullGrantStore(unverifiedRows: openUnverifiedRowView(paths: paths))
        }

        let decisionLogger = try? DecisionLogger(directory: paths.logDirectory, keyProvider: keyProvider)
        if decisionLogger == nil {
            DaemonLog.integrity.error("decision logger unavailable; the signed decision log will not be written")
        }

        // Fleet telemetry: reads the (unsigned, read-only) decision log
        // and writes the world-readable summary plist. No keychain dependency —
        // counting needs no signing key — so it runs even when the logger above
        // is unavailable.
        let fleetSummaryWriter = FleetSummaryWriter(
            logDirectory: paths.logDirectory,
            outputURL: paths.fleetSummaryPlist,
            daemonVersion: version.daemonVersion
        )
        let recentEventsWriter = RecentEventsWriter(
            logDirectory: paths.logDirectory,
            localURL: paths.recentEventsLocal,
            publicURL: paths.fleetEventsPublic
        )

        let stateController = DaemonStateController(
            statePlist: paths.statePlist,
            integrityLogger: integrityLogger,
            daemonVersion: version.daemonVersion
        )

        let lastKnownGood = LastKnownGoodConfigStore(passthroughSource: CFPreferencesSource())
        // enableBiometrics comes from the EFFECTIVE config (seeded here for the
        // startup apply, then adopted on every resolution), never a live read.
        let authDBSettings = AuthorizationDBEffectiveSettings(reader: ManagedPreferencesReader(),
                                                              lastKnownGood: lastKnownGood)
        let authDBManager = AuthorizationDBManager(
            backend: SecurityAuthorizationDB(),
            store: AuthorizationDBSnapshotStore(directory: paths.authDBBackupDirectory),
            integrityLogger: integrityLogger,
            daemonVersion: version.daemonVersion,
            sessionOwnerOnly: { authDBSettings.enableBiometrics }
        )

        let sudoersManager = SudoersManager(
            installer: SystemSudoersInstaller(),
            integrityLogger: integrityLogger,
            daemonVersion: version.daemonVersion
        )

        return DaemonController(
            paths: paths,
            machServiceName: BundleConfig.machService,
            prefsReader: ManagedPreferencesReader(),
            grantStore: grantStore,
            stateController: stateController,
            integrityLogger: integrityLogger,
            decisionLogger: decisionLogger,
            fleetSummaryWriter: fleetSummaryWriter,
            recentEventsWriter: recentEventsWriter,
            pppc: PPPCPreflight(),
            authDB: AuthorizationDBApplier(manager: authDBManager, settings: authDBSettings),
            sudoers: sudoersManager,
            pamGate: FilesystemPAMGateVerifier(),
            bypassResolver: LocalBypassResolver(),
            membership: DirectoryServicesGroupController(),
            sudoTickets: SudoTimestampDirectory(),
            jamfConnectObserver: JamfConnectElevationObserver(
                membership: DirectoryServicesGroupController(),
                ticketClearer: SudoTimestampDirectory(),
                decisionLogger: decisionLogger,
                deviceSerial: DeviceInfo.serialNumber(),
                version: version
            ),
            managedConfigWatchDirectory: "/Library/Managed Preferences",
            lastKnownGood: lastKnownGood,
            buildMarker: DaemonBuildMarker(url: paths.supportDirectory.appendingPathComponent(DaemonBuildMarker.fileName)),
            buildIdentity: DaemonBuildIdentity.current(version: version.daemonVersion),
            staleAdminScrubber: DSCLStaleAdminEntryScrubber(),
            inspector: BinaryIdentityInspector(),
            deviceSerial: DeviceInfo.serialNumber(),
            version: version
        )
    }
}

extension DaemonController {
    /// The HMAC-key source the production daemon (and its one-shot modes) use.
    ///
    /// The System Keychain is the production store. In dev (no provisioned
    /// keychain item / no login session) `SERBERUS_DEV_KEY_FALLBACK=1` permits a
    /// root-only on-disk fallback so grants + the signed decision log persist for
    /// local testing. Production leaves it unset, so a keychain failure fails
    /// closed (NullGrantStore → degraded) rather than silently downgrading to a
    /// less-private on-disk key.
    ///
    /// Neither store may MINT a new grants key while `grants.sqlite` holds rows:
    /// a fresh key would orphan every row (all HMACs fail) — quarantining live
    /// grants and hiding JIT admins from every demotion path. The daemon then
    /// fails closed to `NullGrantStore` / `degraded(grants_db_error)` instead.
    /// (The log key may still be minted; only the grants key guards data.)
    static func productionKeyProvider(paths: DaemonPaths) -> SigningKeyProvider {
        let databasePath = paths.grantDatabase.path
        let creation = KeyCreationPolicy.createIf { account in
            grantKeyCreationAllowed(account: account, databasePath: databasePath)
        }
        guard ProcessInfo.processInfo.environment["SERBERUS_DEV_KEY_FALLBACK"] == "1" else {
            return SystemKeychainKeyProvider(creation: creation)
        }
        return FallbackKeyProvider(
            primary: SystemKeychainKeyProvider(creation: creation),
            secondary: FileKeyProvider(directory: paths.supportDirectory, creation: creation),
            onFallback: { account, error in
                DaemonLog.integrity.error(
                    "System Keychain key '\(account, privacy: .public)' unavailable (\(String(describing: error), privacy: .public)); using DEV on-disk fallback key"
                )
            }
        )
    }
}

extension DaemonController {
    /// A keyless, existing-only view of `grants.sqlite` for a daemon whose
    /// store could not be opened — typically because the grants key is gone
    /// while rows remain (a new key is never minted then; see
    /// ``grantKeyCreationAllowed(account:databasePath:)``).
    ///
    /// Opened exactly as `serberusd --demote-jit` opens it
    /// (``GrantStore/OpenOptions/existingNoQuarantine``): never created, never
    /// migrated, and nothing is stamped. With no key no row verifies, so every
    /// unrevoked JIT row is an unverifiable-row demotion candidate, and the JIT
    /// manager demotes those users on every tick — the decided rule for JIT
    /// rows Serberus can no longer vouch for. Everything else stays degraded
    /// (`grants_db_error`): timed grants are denied and JIT is refused until the
    /// key is restored or the database is removed. Nil when the database does
    /// not exist or cannot be opened even this way.
    static func openUnverifiedRowView(paths: DaemonPaths) -> GrantStore? {
        let path = paths.grantDatabase.path
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        do {
            let view = try GrantStore(path: path, integrityKeys: [], options: .existingNoQuarantine)
            DaemonLog.integrity.error(
                "grants key unavailable: opened grants.sqlite read-only without a key; unverifiable JIT rows will be demoted every tick"
            )
            return view
        } catch {
            DaemonLog.integrity.error(
                "grants.sqlite could not be opened even read-only (\(String(describing: error), privacy: .public)); JIT admins cannot be enumerated — check the admin group by hand"
            )
            return nil
        }
    }

    /// Whether a key provider may mint `account` now. Only the grants key is
    /// guarded: it may be minted only while the grant database holds NO rows
    /// (absent file / empty table). An unreadable database counts as "has rows"
    /// — never mint on doubt.
    static func grantKeyCreationAllowed(account: String, databasePath: String) -> Bool {
        guard account == BundleConfig.grantsHMACKeyAccount else { return true }
        guard let rows = GrantStore.existingRowCount(atPath: databasePath) else {
            DaemonLog.integrity.error("grants key absent and grants.sqlite unreadable; refusing to mint a new key")
            return false
        }
        if rows > 0 {
            DaemonLog.integrity.error(
                "grants key absent while grants.sqlite holds \(rows, privacy: .public) row(s); refusing to mint a new key (grants_db_error)"
            )
            return false
        }
        return true
    }
}

// MARK: - Console-user watch

/// SCDynamicStore notification trampoline. Must be a free function so it carries
/// the C calling convention (`SCDynamicStoreCallBack`) and captures nothing; the
/// retained ``ConsoleUserWatch`` is recovered from the context `info` pointer and
/// its Sendable closure is the only thing invoked here — no actor state is
/// touched on the SC dispatch queue.
private func serberusConsoleUserChanged(
    _ store: SCDynamicStore,
    _ changedKeys: CFArray,
    _ info: UnsafeMutableRawPointer?
) {
    guard let info else { return }
    Unmanaged<ConsoleUserWatch>.fromOpaque(info).takeUnretainedValue().fire()
}

/// Owns a `State:/Users/ConsoleUser` SCDynamicStore subscription and forwards
/// each change to an injected Sendable closure.
///
/// The store delivers callbacks on a private dispatch queue; the closure merely
/// schedules actor-isolated work (see ``DaemonController/startConsoleUserWatch()``).
/// `@unchecked Sendable`: the only mutable field, `store`, is written solely on
/// `start()`/`stop()` from the owning actor and is never read on the callback
/// path — which touches only the immutable `onChange` via ``fire()``.
private final class ConsoleUserWatch: @unchecked Sendable {
    private let onChange: @Sendable () -> Void
    private let queue = DispatchQueue(label: "com.herojoneslabs.serberus.daemon.consoleuser-watch")
    private var store: SCDynamicStore?

    init(onChange: @escaping @Sendable () -> Void) {
        self.onChange = onChange
    }

    /// Invoked from the SCDynamicStore callback (off-actor).
    func fire() { onChange() }

    /// Creates the store, subscribes to the console-user key, and attaches the
    /// dispatch queue. A creation failure is logged and non-fatal: the daemon
    /// falls back to the 30s reload backstop.
    func start() {
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        guard let store = SCDynamicStoreCreate(
            nil,
            "com.herojoneslabs.serberus.daemon.consoleuser" as CFString,
            serberusConsoleUserChanged,
            &context
        ) else {
            DaemonLog.integrity.error(
                "console-user watch unavailable (SCDynamicStoreCreate failed); relying on the reload backstop"
            )
            return
        }
        let key = SCDynamicStoreKeyCreateConsoleUser(nil)
        SCDynamicStoreSetNotificationKeys(store, [key] as CFArray, nil)
        SCDynamicStoreSetDispatchQueue(store, queue)
        self.store = store
    }

    /// Detaches the dispatch queue (stopping delivery) and releases the store.
    func stop() {
        if let store {
            SCDynamicStoreSetDispatchQueue(store, nil)
        }
        store = nil
    }
}

// MARK: - Managed-config watch

/// Debounced `DispatchSource` file-system watch on the managed config plist.
///
/// MDM writes `/Library/Managed Preferences/<domain>.plist` atomically (a
/// rename into the directory), so the DIRECTORY is watched for `.write`
/// (entries added/removed/renamed); the file itself is also watched for an
/// in-place write, re-armed after every event (a replaced file is a new vnode).
///
/// The directory itself may not exist yet (a Mac that has never received a
/// profile) or may be deleted or replaced wholesale. Until it exists the
/// PARENT folder is watched instead; the moment it appears, the watch moves to
/// it. A directory watch that sees its folder deleted or renamed away re-opens
/// the path (falling back to the parent again when it is gone).
///
/// Every event is coalesced over ``debounce`` into ONE `onChange` call.
/// `@unchecked Sendable`: all mutable state is confined to `queue`.
final class ManagedConfigWatch: @unchecked Sendable {
    private let directory: String
    private let fileName: String
    private let onChange: @Sendable () -> Void
    private let debounce: DispatchTimeInterval
    private let queue = DispatchQueue(label: "com.herojoneslabs.serberus.daemon.managed-config-watch")
    private var directorySource: DispatchSourceFileSystemObject?
    private var parentSource: DispatchSourceFileSystemObject?
    private var fileSource: DispatchSourceFileSystemObject?
    private var pending: DispatchWorkItem?
    private var stopped = false

    init(directory: String, fileName: String, debounce: DispatchTimeInterval = .milliseconds(750),
         onChange: @escaping @Sendable () -> Void) {
        self.directory = directory
        self.fileName = fileName
        self.debounce = debounce
        self.onChange = onChange
    }

    func start() {
        queue.async { [self] in
            stopped = false
            armDirectorySource()
        }
    }

    func stop() {
        queue.async { [self] in
            stopped = true
            pending?.cancel()
            pending = nil
            directorySource?.cancel()
            directorySource = nil
            parentSource?.cancel()
            parentSource = nil
            fileSource?.cancel()
            fileSource = nil
        }
    }

    /// Test seam: whether the watch is on the directory itself (true) or still
    /// waiting on its parent (false). Read on `queue`.
    var isWatchingDirectory: Bool { queue.sync { directorySource != nil } }

    /// On `queue`. (Re)opens the watch on the directory; if it does not exist,
    /// watches the parent folder until it does.
    private func armDirectorySource() {
        guard !stopped else { return }
        directorySource?.cancel()
        directorySource = makeSource(path: directory, mask: [.write, .delete, .rename, .link]) { [weak self] events in
            self?.directoryEventFired(events)
        }
        if directorySource != nil {
            parentSource?.cancel()
            parentSource = nil
            armFileSource()
            return
        }
        fileSource?.cancel()
        fileSource = nil
        guard parentSource == nil else { return }
        let parent = (directory as NSString).deletingLastPathComponent
        parentSource = makeSource(path: parent, mask: [.write, .link, .rename]) { [weak self] _ in
            self?.parentEventFired()
        }
        DaemonLog.integrity.notice(
            "managed-config watch: \(self.directory, privacy: .public) not present; watching its parent until it appears"
        )
        if parentSource == nil {
            DaemonLog.integrity.error(
                "managed-config watch unavailable (\(self.directory, privacy: .public) and its parent not openable); relying on the reload backstop"
            )
        }
    }

    /// (Re)opens the watch on the plist itself. Absent file ⇒ no file source;
    /// the directory watch sees it arrive.
    private func armFileSource() {
        fileSource?.cancel()
        fileSource = makeSource(path: directory + "/" + fileName,
                                mask: [.write, .extend, .attrib, .delete, .rename]) { [weak self] _ in
            self?.eventFired()
        }
    }

    private func makeSource(path: String, mask: DispatchSource.FileSystemEvent,
                            handler: @escaping (DispatchSource.FileSystemEvent) -> Void) -> DispatchSourceFileSystemObject? {
        let fd = open(path, O_EVTONLY | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: mask, queue: queue)
        source.setEventHandler { [weak source] in handler(source?.data ?? []) }
        source.setCancelHandler { close(fd) }
        source.resume()
        return source
    }

    /// On `queue`. The directory was deleted or renamed away: re-open the path
    /// (the replacement, or the parent while there is none).
    private func directoryEventFired(_ events: DispatchSource.FileSystemEvent) {
        if !events.intersection([.delete, .rename]).isEmpty {
            armDirectorySource()
        }
        eventFired()
    }

    /// On `queue`. Something changed in the parent: the directory may exist now.
    private func parentEventFired() {
        guard directorySource == nil else { return }
        armDirectorySource()
        if directorySource != nil { eventFired() }
    }

    /// On `queue`. Re-arms the file watch and (re)starts the debounce.
    private func eventFired() {
        guard !stopped else { return }
        if directorySource != nil { armFileSource() }
        pending?.cancel()
        let onChange = self.onChange
        let item = DispatchWorkItem { onChange() }
        pending = item
        queue.asyncAfter(deadline: .now() + debounce, execute: item)
    }
}
