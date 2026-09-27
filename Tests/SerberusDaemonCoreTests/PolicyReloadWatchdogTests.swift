import Foundation
import PrivMgrCore
import Testing

@testable import SerberusDaemonCore

// MARK: - The deadline primitive

/// ``withAbandoningTimeout`` is the watchdog's foundation: it must return on its
/// deadline even when the work it bounds ignores cancellation entirely, because
/// that is precisely the failure it exists to survive. (The existing
/// `withTimeout` in `DaemonHealthProbe` cannot: `withTaskGroup` implicitly awaits
/// every child at scope exit, so a cancellation-deaf child hangs the timeout.)
@Suite("withAbandoningTimeout — async deadline that abandons the loser")
struct AbandoningTimeoutTests {

    @Test("a fast closure returns its value")
    func fastClosureReturnsValue() async {
        let result = await withAbandoningTimeout(seconds: 5) { 42 }
        #expect(result == 42)
    }

    @Test("a value of zero (not nil) is distinguishable from a timeout")
    func zeroValueIsNotTimeout() async {
        let result = await withAbandoningTimeout(seconds: 5) { 0 }
        #expect(result == 0) // a real 0, not the nil-means-timeout sentinel
    }

    @Test("an async closure that outlasts the budget returns nil without waiting it out")
    func slowClosureTimesOut() async {
        let started = Date()
        let result: Int? = await withAbandoningTimeout(seconds: 0.1) {
            try? await Task.sleep(for: .seconds(3))
            return 7
        }
        let elapsed = Date().timeIntervalSince(started)
        #expect(result == nil)
        #expect(elapsed < 1.5) // returned on the deadline, not on the work finishing
    }

    @Test("a NON-CANCELLABLE hang is abandoned, not waited out")
    func nonCancellableHangIsAbandoned() async {
        let started = Date()
        // A thread block (not `Task.sleep`) ignores cancellation outright — the
        // same shape as a task parked on a continuation that never resumes, which
        // is the real stall. This is the case a task-group timeout CANNOT escape.
        let result: Int? = await withAbandoningTimeout(seconds: 0.2) {
            blockCurrentThread(seconds: 2)
            return 7
        }
        let elapsed = Date().timeIntervalSince(started)
        #expect(result == nil)
        #expect(elapsed < 1.5) // returned on the deadline, not on the block clearing
    }

    @Test("a non-positive budget collapses to an immediate timeout")
    func nonPositiveBudgetTimesOutImmediately() async {
        let result: Int? = await withAbandoningTimeout(seconds: 0) {
            blockCurrentThread(seconds: 1)
            return 7
        }
        #expect(result == nil)
    }

    @Test("an abandoned closure still runs to completion (the late-completion contract)")
    func abandonedClosureStillCompletes() async {
        // The reload watchdog depends on this: the abandoned worker clears the
        // leak guard when it finally finishes, which is what lets a merely-slow
        // pass self-heal with no restart. If the primitive cancelled its loser,
        // that tail could be skipped.
        let finished = AsyncFlag()
        let result: Int? = await withAbandoningTimeout(seconds: 0.05) {
            try? await Task.sleep(for: .milliseconds(200))
            await finished.set()
            return 7
        }
        #expect(result == nil) // the caller already moved on
        await finished.waitUntilSet(timeout: 5)
        #expect(await finished.isSet) // ...but the work still ran to its end
    }
}

/// Blocks the calling thread outright, ignoring cancellation — a stand-in for the
/// real wedge (a task parked on a continuation that never resumes). Synchronous
/// because `Thread.sleep` is `noasync` under Swift 6.
func blockCurrentThread(seconds: TimeInterval) {
    Thread.sleep(forTimeInterval: seconds)
}

/// A one-shot flag for observing work that outlives the call that started it.
actor AsyncFlag {
    private(set) var isSet = false
    func set() { isSet = true }

    /// Polls until set, bounded — so a broken contract fails the test instead of
    /// hanging the suite.
    func waitUntilSet(timeout: TimeInterval) async {
        let deadline = Date().addingTimeInterval(timeout)
        while !isSet, Date() < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
    }
}

// MARK: - Reload watchdog

/// A provisioner whose `apply`/`remove` NEVER return — the wedge the watchdog
/// exists for. Modeled on ``WedgedGrantStore`` (`StateHealthRouterTests`): pair a
/// deliberately hung dependency with an injected short deadline so the suite
/// finishes in milliseconds with no flake window.
///
/// Sudoers provisioning is a realistic site: the unbounded `await previous?.value`
/// in `provisionSudoers`'s serialization chain is one await that could park.
final class HangingProvisioner: SudoersProvisioning, @unchecked Sendable {
    private let lock = NSLock()
    private var _applyCount = 0
    private var _removeCount = 0

    var applyCount: Int { read { _applyCount } }
    var removeCount: Int { read { _removeCount } }

    func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool {
        recordApply()
        try? await Task.sleep(for: .seconds(3600))
        return true
    }

    func remove() async -> Bool {
        recordRemove()
        try? await Task.sleep(for: .seconds(3600))
        return true
    }

    // Synchronous critical sections — NSLock is `noasync` under Swift 6
    // (mirrors ReconcileSpyProvisioner).
    private func recordApply() { lock.lock(); defer { lock.unlock() }; _applyCount += 1 }
    private func recordRemove() { lock.lock(); defer { lock.unlock() }; _removeCount += 1 }
    private func read<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }
}

/// An authdb applier whose `reconcile` NEVER returns.
///
/// Used for the leak-guard test SPECIFICALLY because `reconcile` runs EARLY in
/// `reloadPolicyIfChanged` and is NOT serialized. Wedging the sudoers provisioner
/// instead would make the test vacuous: `provisionSudoers` already chains every
/// pass behind the previous one, so a second pass would block on
/// `await previous?.value` and never reach `apply` — the assertion would hold with
/// the leak guard deleted. This wedge has no such backstop, so only the guard can
/// stop the second pass.
actor HangingAuthDB: AuthorizationDBApplying {
    private(set) var reconcileCount = 0
    private(set) var applyCount = 0

    func apply(profiles: [RuleProfile]) async throws { applyCount += 1 }
    func reconcile(profiles: [RuleProfile]) async throws {
        reconcileCount += 1
        try await Task.sleep(for: .seconds(3600))
    }
}

/// Timings for the two tests that must distinguish a SLOW pass from a HEALTHY
/// one against the same controller.
///
/// These need a wide margin in BOTH directions, unlike the wedge-based tests
/// (a never-returning wedge cannot accidentally look healthy, so those can use a
/// 0.1s deadline safely). Here a real reload pass takes single-digit
/// milliseconds, so `deadline` sits ~100x above it — a healthy pass being
/// misread as a stall on a loaded machine is a real flake with a tighter
/// budget (0.05s is too tight).
enum SlowPassTiming {
    /// Comfortably above a real pass (~ms), comfortably below ``slowDelay``.
    static let deadline: TimeInterval = 0.5
    /// Comfortably above ``deadline``, but short enough that a test can wait for
    /// the late completion.
    static let slowDelay: Duration = .milliseconds(1500)
}

/// A provisioner whose per-apply delay is dialable, so a test can sequence
/// stall / healthy / stall passes against one controller.
final class DialableProvisioner: SudoersProvisioning, @unchecked Sendable {
    private let lock = NSLock()
    private var _delay: Duration
    private var _applyCount = 0

    init(delay: Duration) { _delay = delay }
    var applyCount: Int { read { _applyCount } }
    func setDelay(_ delay: Duration) { lock.lock(); defer { lock.unlock() }; _delay = delay }

    func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool {
        try? await Task.sleep(for: recordApplyAndReadDelay())
        return true
    }

    func remove() async -> Bool { true }

    private func recordApplyAndReadDelay() -> Duration {
        lock.lock(); defer { lock.unlock() }
        _applyCount += 1
        return _delay
    }

    private func read<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }
}

/// Counts `exit()` requests without ending the test process.
final class ExitSpy: @unchecked Sendable {
    private let lock = NSLock()
    private var _codes: [Int32] = []

    var codes: [Int32] { lock.lock(); defer { lock.unlock() }; return _codes }
    /// Synchronous by construction — ``DaemonController``'s `exitProcess` seam is
    /// a sync closure, so the lock is never taken from an async context.
    var callback: @Sendable (Int32) -> Void {
        { [self] code in lock.lock(); defer { lock.unlock() }; _codes.append(code) }
    }
}

/// The failure this guards against: the reload loop is a single `Task`, so one
/// unbounded `await` beneath `reloadPolicyIfChanged()` parks it FOREVER — no
/// error, no state change, `sudo` still working — while the endpoint quietly
/// stops applying every policy the admin ships. These tests pin the four
/// properties that turn that into a survivable event: bounded, loud, leak-free,
/// self-recovering.
@Suite("DaemonController — policy-reload watchdog", .serialized)
struct PolicyReloadWatchdogTests {

    private func makeController(
        paths: DaemonPaths,
        stateController: DaemonStateController,
        sudoers: SudoersProvisioning = NoopSudoersProvisioner(),
        authDB: AuthorizationDBApplying = CountingAuthDB(),
        source: PreferencesSource = DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: CoordinatorFixtures.enforceableConfig,
        ]),
        exitProcess: @escaping @Sendable (Int32) -> Void = { _ in },
        // Defaults to the PRODUCTION deadline. Tests that need a stall pass an
        // explicit short one; tests that need a healthy pass must NOT, or a loaded
        // machine could overrun a tight budget and report a phantom stall.
        reloadDeadlineSeconds: TimeInterval = 60,
        maxConsecutiveReloadStalls: Int = 3,
        pamGate: PAMGateVerifying = AssumeWiredPAMGate()
    ) -> DaemonController {
        DaemonController(
            paths: paths,
            machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: source),
            grantStore: NullGrantStore(),
            stateController: stateController,
            integrityLogger: nil,
            decisionLogger: nil,
            pppc: StaticPPPCStatus(ready: true),
            authDB: authDB,
            sudoers: sudoers,
            pamGate: pamGate,
            lastKnownGood: InMemoryLastKnownGoodConfigStore(),
            deviceSerial: "TESTSERIAL",
            exitProcess: exitProcess,
            reloadDeadlineSeconds: reloadDeadlineSeconds,
            maxConsecutiveReloadStalls: maxConsecutiveReloadStalls,
            now: { CoordinatorFixtures.now }
        )
    }

    /// A config domain that differs from the last one only in a field the policy
    /// signature hashes (`sudoCacheSeconds`), so the next tick does REAL work
    /// instead of taking `reloadPolicyIfChanged`'s change-gated early return.
    private static func config(cacheSeconds: Int) -> [String: any Sendable] {
        var config = CoordinatorFixtures.enforceableConfig
        config["sudoCacheSeconds"] = cacheSeconds
        return config
    }

    @Test("a wedged pass is ABANDONED at the deadline — the tick returns instead of hanging forever")
    func wedgedPassIsAbandonedAtTheDeadline() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let controller = makeController(
            paths: paths,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            sudoers: HangingProvisioner(),
            reloadDeadlineSeconds: 0.1
        )

        let started = Date()
        await controller.runWatchdoggedReloadPassForTesting()
        let elapsed = Date().timeIntervalSince(started)

        // Without the watchdog this call never returns — that is the whole bug.
        #expect(elapsed < 2)
    }

    @Test("a stalled pass is reported LOUDLY: state degraded, reason reload_stalled")
    func stalledPassDegradesWithReloadStalledReason() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let stateController = DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil)
        let controller = makeController(
            paths: paths, stateController: stateController, sudoers: HangingProvisioner(),
            reloadDeadlineSeconds: 0.1
        )

        await controller.runWatchdoggedReloadPassForTesting()

        // Silent drift is the failure mode; being visibly degraded is the fix.
        let current = await stateController.current()
        #expect(current.state == .degraded)
        #expect(current.reason == .reloadStalled)
    }

    @Test("LEAK GUARD: ticks while a pass is still wedged start NO new pass")
    func leakGuardStartsNoSecondPassWhileWedged() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let authDB = HangingAuthDB()
        // The prefs CHANGE on every tick, so `reloadPolicyIfChanged`'s signature
        // gate can never be what stops the second pass — only the leak guard can.
        let source = MutablePreferencesSource(domains: [
            BundleConfig.configDomain: Self.config(cacheSeconds: 1),
        ])
        let controller = makeController(
            paths: paths,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            authDB: authDB,
            source: source,
            reloadDeadlineSeconds: 0.1
        )

        await controller.runWatchdoggedReloadPassForTesting()
        #expect(await authDB.reconcileCount == 1)

        // A permanent wedge must cost ONE abandoned task, not one every 30s
        // forever — that would pile up tasks and racing writers indefinitely.
        source.set([BundleConfig.configDomain: Self.config(cacheSeconds: 2)])
        await controller.runWatchdoggedReloadPassForTesting()
        source.set([BundleConfig.configDomain: Self.config(cacheSeconds: 3)])
        await controller.runWatchdoggedReloadPassForTesting()

        #expect(await authDB.reconcileCount == 1) // still exactly one pass in flight
        #expect(await controller.reloadPassOutstandingForTesting())
    }

    @Test("ESCALATION: N consecutive stalls exit(1) for a launchd restart, exactly once")
    func consecutiveStallsEscalateToRestartOnce() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let exitSpy = ExitSpy()
        let controller = makeController(
            paths: paths,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            sudoers: HangingProvisioner(),
            exitProcess: exitSpy.callback,
            reloadDeadlineSeconds: 0.1,
            maxConsecutiveReloadStalls: 2
        )

        await controller.runWatchdoggedReloadPassForTesting() // stall 1 (deadline)
        #expect(exitSpy.codes.isEmpty)                        // one stall is not yet a restart

        await controller.runWatchdoggedReloadPassForTesting() // stall 2 (leak guard) → threshold
        #expect(exitSpy.codes == [1])

        // In production exit(1) ends the process; the request must not repeat
        // against the injected seam.
        await controller.runWatchdoggedReloadPassForTesting()
        #expect(exitSpy.codes == [1])
    }

    @Test("the watchdog is INVISIBLE on the happy path: no degrade, no restart, no latched guard")
    func healthyPassNeverDegrades() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let exitSpy = ExitSpy()
        let stateController = DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil)
        let controller = makeController(
            paths: paths,
            stateController: stateController,
            exitProcess: exitSpy.callback,
            maxConsecutiveReloadStalls: 2
        )

        for _ in 0..<5 {
            await controller.runWatchdoggedReloadPassForTesting()
        }
        let current = await stateController.current()
        #expect(current.state != .degraded)
        #expect(current.reason == nil)
        #expect(exitSpy.codes.isEmpty)
        #expect(await controller.reloadPassOutstandingForTesting() == false)
    }

    @Test("a healthy pass RESETS the stall counter, so an isolated later stall never restarts")
    func healthyPassResetsStallCounter() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let exitSpy = ExitSpy()
        let sudoers = DialableProvisioner(delay: SlowPassTiming.slowDelay)
        // Every tick sees changed prefs, so each does REAL work rather than taking
        // the signature-gated early return.
        let source = MutablePreferencesSource(domains: [
            BundleConfig.configDomain: Self.config(cacheSeconds: 1),
        ])
        let controller = makeController(
            paths: paths,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            sudoers: sudoers,
            source: source,
            exitProcess: exitSpy.callback,
            reloadDeadlineSeconds: SlowPassTiming.deadline,
            // Only TWO CONSECUTIVE stalls restart. The sequence below is
            // stall / healthy / stall — so if the healthy pass failed to reset the
            // counter, the second stall would be #2 and would exit(1). That is the
            // discriminating assertion.
            maxConsecutiveReloadStalls: 2
        )

        // Tick 1: slow ⇒ stall #1.
        await controller.runWatchdoggedReloadPassForTesting()
        #expect(exitSpy.codes.isEmpty)
        await waitForGuardToClear(controller)

        // Tick 2: fast ⇒ healthy ⇒ counter must reset to 0.
        sudoers.setDelay(.zero)
        source.set([BundleConfig.configDomain: Self.config(cacheSeconds: 2)])
        await controller.runWatchdoggedReloadPassForTesting()

        // Tick 3: slow again ⇒ stall, but it is #1, not #2.
        sudoers.setDelay(SlowPassTiming.slowDelay)
        source.set([BundleConfig.configDomain: Self.config(cacheSeconds: 3)])
        await controller.runWatchdoggedReloadPassForTesting()

        #expect(exitSpy.codes.isEmpty) // fails if the healthy pass did not reset
    }

    /// Polls until the watchdog's leak guard clears, bounded — so a regression
    /// fails the test instead of hanging the suite.
    private func waitForGuardToClear(_ controller: DaemonController) async {
        let deadline = Date().addingTimeInterval(5)
        while await controller.reloadPassOutstandingForTesting(), Date() < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    @Test("TRANSIENT hang self-heals: a LATE-completing pass clears the guard, with no restart")
    func lateCompletingPassClearsTheGuardWithoutRestart() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let exitSpy = ExitSpy()
        let sudoers = DialableProvisioner(delay: SlowPassTiming.slowDelay)
        let source = MutablePreferencesSource(domains: [
            BundleConfig.configDomain: Self.config(cacheSeconds: 1),
        ])
        let controller = makeController(
            paths: paths,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            sudoers: sudoers,
            source: source,
            exitProcess: exitSpy.callback,
            reloadDeadlineSeconds: SlowPassTiming.deadline,
            maxConsecutiveReloadStalls: 2
        )

        // Overruns its deadline, so this tick reports a stall and abandons it...
        await controller.runWatchdoggedReloadPassForTesting()
        #expect(await controller.reloadPassOutstandingForTesting())
        #expect(sudoers.applyCount == 1)

        // ...but the pass was only SLOW, not wedged: it runs to completion on its
        // own and clears the guard from INSIDE the abandoned worker. If the
        // primitive cancelled its loser — or if the guard were only cleared on the
        // in-deadline path — this would latch true and the daemon would never
        // reload again, converting a one-off slow tick into a permanent outage.
        await waitForGuardToClear(controller)
        #expect(await controller.reloadPassOutstandingForTesting() == false)

        // Guard clear ⇒ the next tick runs a REAL pass (not a phantom stall
        // against the abandoned one), and the transient never cost a restart.
        sudoers.setDelay(.zero)
        source.set([BundleConfig.configDomain: Self.config(cacheSeconds: 2)])
        await controller.runWatchdoggedReloadPassForTesting()
        #expect(sudoers.applyCount == 2) // the pass genuinely re-ran
        #expect(exitSpy.codes.isEmpty)
    }

    @Test("a tick that finds a YOUNG pass still running is not a stall; only one older than the deadline is")
    func youngOutstandingPassIsNotAStall() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let exitSpy = ExitSpy()
        let stateController = DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil)
        let sudoers = DialableProvisioner(delay: .milliseconds(800))
        let controller = makeController(
            paths: paths, stateController: stateController, sudoers: sudoers,
            exitProcess: exitSpy.callback, reloadDeadlineSeconds: 5, maxConsecutiveReloadStalls: 1
        )
        // The managed-config watch starts a pass; a tick lands while it runs.
        let watchPass = Task { await controller.handleManagedConfigChangeForTesting() }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await controller.reloadPassOutstandingForTesting())
        await controller.runWatchdoggedReloadPassForTesting()
        #expect(exitSpy.codes.isEmpty)                         // one stall would have restarted
        #expect(await stateController.current().reason != .reloadStalled)
        await watchPass.value
        #expect(sudoers.applyCount == 1)                       // and the tick started no second pass
    }

    @Test("a managed-config change that lands mid-pass is not dropped: one more pass runs when it completes")
    func changeDuringPassQueuesARerun() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let sudoers = DialableProvisioner(delay: .milliseconds(400))
        let source = MutablePreferencesSource(domains: [
            BundleConfig.configDomain: Self.config(cacheSeconds: 1),
        ])
        let controller = makeController(
            paths: paths,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            sudoers: sudoers, source: source
        )
        let first = Task { await controller.handleManagedConfigChangeForTesting() }
        try await Task.sleep(for: .milliseconds(100))
        // MDM delivers a change while that pass is still provisioning.
        source.set([BundleConfig.configDomain: Self.config(cacheSeconds: 2)])
        await controller.handleManagedConfigChangeForTesting()  // queued, returns at once
        await first.value

        // No tick: the queued pass picks the change up by itself.
        let deadline = Date().addingTimeInterval(5)
        while sudoers.applyCount < 2, Date() < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(sudoers.applyCount == 2)
    }

    @Test("after a stall the next pass publishes again, so reload_stalled clears even with nothing changed")
    func stallIsClearedByTheNextPass() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let stateController = DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil)
        let gate = SlowPAMGate()
        let controller = makeController(
            paths: paths, stateController: stateController,
            reloadDeadlineSeconds: 0.2, maxConsecutiveReloadStalls: 5, pamGate: gate
        )
        // A normal pass commits the policy signature.
        await controller.runWatchdoggedReloadPassForTesting()
        #expect(await stateController.current().reason != .reloadStalled)

        // A pass that is slow only while computing the signature: it finds the
        // policy unchanged and publishes nothing — but it overran, so it stalled.
        gate.setDelay(0.6)
        await controller.runWatchdoggedReloadPassForTesting()
        let deadline = Date().addingTimeInterval(5)
        while await controller.reloadPassOutstandingForTesting(), Date() < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(await stateController.current().reason == .reloadStalled)

        // Nothing changed, yet the next pass must publish the real state.
        gate.setDelay(0)
        await controller.runWatchdoggedReloadPassForTesting()
        #expect(await stateController.current().reason != .reloadStalled)
    }
}

@Suite("ManagedConfigWatch — missing and replaced folder", .serialized)
struct ManagedConfigWatchFolderTests {
    /// Fire counter readable from the test.
    private final class Fires: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func add() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    private func waitFor(_ condition: () -> Bool, seconds: TimeInterval = 5) async throws {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition(), Date() < deadline { try await Task.sleep(for: .milliseconds(25)) }
    }

    @Test("watches the parent until the folder appears, then the folder; survives the folder being replaced")
    func parentThenFolder() async throws {
        let parent = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let folder = parent.appendingPathComponent("Managed Preferences", isDirectory: true)
        let plist = folder.appendingPathComponent("x.plist")
        let fires = Fires()
        let watch = ManagedConfigWatch(directory: folder.path, fileName: "x.plist", debounce: .milliseconds(50)) {
            fires.add()
        }
        watch.start()
        defer { watch.stop() }
        try await Task.sleep(for: .milliseconds(150))
        #expect(!watch.isWatchingDirectory)             // no folder yet: on the parent

        // The first profile arrives: the folder is created, then the plist.
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        try await waitFor { watch.isWatchingDirectory }
        #expect(watch.isWatchingDirectory)
        try Data("a".utf8).write(to: plist, options: .atomic)
        try await waitFor { fires.value >= 1 }
        #expect(fires.value >= 1)

        // The folder is replaced wholesale: the watch follows the new one.
        try FileManager.default.removeItem(at: folder)
        try await Task.sleep(for: .milliseconds(150))
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        try await waitFor { watch.isWatchingDirectory }
        try await Task.sleep(for: .milliseconds(150))
        let before = fires.value
        try Data("b".utf8).write(to: plist, options: .atomic)
        try await waitFor { fires.value > before }
        #expect(fires.value > before)
    }
}

/// A PAM gate whose `verify()` blocks for a dialable time (it is part of the
/// policy signature, so it slows the change check itself).
final class SlowPAMGate: PAMGateVerifying, @unchecked Sendable {
    private let lock = NSLock()
    private var delay: TimeInterval = 0
    func setDelay(_ seconds: TimeInterval) { lock.lock(); delay = seconds; lock.unlock() }
    func verify() -> PAMGateStatus {
        lock.lock(); let seconds = delay; lock.unlock()
        if seconds > 0 { Thread.sleep(forTimeInterval: seconds) }
        return .wired
    }
}

// MARK: - Bounded subprocess runner

/// `ProcessCommandRunner.run` fed the reload path through `JITAdminManager` with
/// NO timeout: a bare `waitUntilExit()` inside a continuation that then never
/// resumes — one of the unbounded awaits that can park the reload loop for good.
@Suite("ProcessCommandRunner — bounded run")
struct ProcessCommandRunnerTimeoutTests {

    @Test("a command that outruns its budget THROWS commandTimedOut (fails closed)")
    func overrunningCommandThrows() async {
        let runner = ProcessCommandRunner(timeout: 0.1)
        let started = Date()
        await #expect(throws: JITAdminError.self) {
            _ = try await runner.run(path: "/bin/sleep", arguments: ["30"])
        }
        // Killed at the deadline rather than waited out — an unbounded run would
        // have parked here for 30s (and, if wedged, forever).
        #expect(Date().timeIntervalSince(started) < 5)
    }

    @Test("a command that ignores SIGTERM is SIGKILLed after the grace period")
    func sigtermIgnoringCommandIsKilled() async throws {
        // The shell drops its pipes first so only the shell's own exit is
        // awaited; it ignores SIGTERM while its `sleep` child runs.
        let started = Date()
        let result = try await ProcessCommandRunner.execute(
            path: "/bin/sh", arguments: ["-c", "exec >/dev/null 2>&1; trap '' TERM; sleep 30"], timeout: 0.1)
        #expect(result.timedOut)
        #expect(result.status == SIGKILL)
        #expect(Date().timeIntervalSince(started) < 10)
    }

    @Test("a fast command still returns its real exit status")
    func fastCommandReturnsStatus() async throws {
        let runner = ProcessCommandRunner(timeout: 10)
        #expect(try await runner.run(path: "/usr/bin/true", arguments: []) == 0)
        #expect(try await runner.run(path: "/usr/bin/false", arguments: []) != 0)
    }

    /// A scratch directory removed by the caller.
    private func scratchDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-runner-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test("output far past a pipe buffer is drained while the tool runs, not after")
    func largeOutputDoesNotDeadlock() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        // 4 MiB of lines: 64 times a pipe buffer.
        let line = String(repeating: "x", count: 63) + "\n"
        let text = String(repeating: line, count: (4 << 20) / line.utf8.count)
        let file = dir.appendingPathComponent("big.txt")
        try Data(text.utf8).write(to: file)

        let started = Date()
        let result = try await ProcessCommandRunner.execute(
            path: "/bin/cat", arguments: [file.path], timeout: 60)
        #expect(!result.timedOut)
        #expect(!result.outputLimitExceeded)
        #expect(result.status == 0)
        #expect(result.stdout.utf8.count == text.utf8.count)
        #expect(result.stdout == text)
        #expect(Date().timeIntervalSince(started) < 10)
    }

    @Test("lsbom of a Bom with thousands of paths returns its full listing")
    func lsbomOfLargeBom() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let tree = dir.appendingPathComponent("root", isDirectory: true)
        let count = 5_000
        for folder in 0..<50 {
            let sub = tree.appendingPathComponent("folder-\(folder)", isDirectory: true)
            try FileManager.default.createDirectory(at: sub, withIntermediateDirectories: true)
            for index in 0..<(count / 50) {
                FileManager.default.createFile(
                    atPath: sub.appendingPathComponent("file-with-a-longish-name-\(index).txt").path,
                    contents: Data("\(index)".utf8))
            }
        }
        let bom = dir.appendingPathComponent("payload.bom")
        let made = try await ProcessCommandRunner.execute(
            path: "/usr/bin/mkbom", arguments: [tree.path, bom.path], timeout: 60)
        #expect(made.status == 0)

        let started = Date()
        let listing = try await ProcessCommandRunner.execute(
            path: "/usr/bin/lsbom", arguments: ["-s", bom.path], timeout: 60)
        #expect(!listing.timedOut)
        #expect(listing.status == 0)
        let paths = listing.stdout.split(separator: "\n")
        // Every file, every folder and the root.
        #expect(paths.count == count + 50 + 1)
        #expect(listing.stdout.utf8.count > 1 << 17)
        #expect(Date().timeIntervalSince(started) < 10)
    }

    @Test("output past the cap kills the tool and fails closed")
    func outputCapFailsClosed() async throws {
        let started = Date()
        // `yes` never stops on its own: only the cap ends it.
        let result = try await ProcessCommandRunner.execute(
            path: "/usr/bin/yes", arguments: [], timeout: 30, outputLimit: 1 << 20)
        #expect(result.outputLimitExceeded)
        #expect(!result.timedOut)
        #expect(result.status == ProcessCommandRunner.outputLimitExceededStatus)
        #expect(result.status != 0)
        #expect(result.stdout.utf8.count <= 1 << 20)
        #expect(Date().timeIntervalSince(started) < 10)
    }

    @Test("a tool that exits 0 after passing the cap still fails")
    func outputCapOverridesSuccess() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("two-mib.bin")
        try Data(repeating: 0x41, count: 2 << 20).write(to: file)
        let result = try await ProcessCommandRunner.execute(
            path: "/bin/cat", arguments: [file.path], timeout: 30, outputLimit: 1 << 20)
        #expect(result.outputLimitExceeded)
        #expect(result.status == ProcessCommandRunner.outputLimitExceededStatus)
    }

    @Test("stderr is drained concurrently too")
    func largeStderrDoesNotDeadlock() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("one-mib.bin")
        try Data(repeating: 0x42, count: 1 << 20).write(to: file)
        let result = try await ProcessCommandRunner.execute(
            path: "/bin/sh", arguments: ["-c", "/bin/cat \"$0\" >&2; echo done", file.path], timeout: 30)
        #expect(!result.timedOut)
        #expect(result.status == 0)
        #expect(result.stderr.utf8.count == 1 << 20)
        #expect(result.stdout == "done\n")
    }

    @Test("a descendant holding the pipes open does not hold the call open")
    func inheritedPipeDoesNotBlock() async throws {
        let started = Date()
        // The shell exits at once; its background sleep keeps stdout open.
        let result = try await ProcessCommandRunner.execute(
            path: "/bin/sh", arguments: ["-c", "echo hi; /bin/sleep 30 & exit 0"], timeout: 10)
        #expect(result.status == 0)
        #expect(result.stdout == "hi\n")
        #expect(Date().timeIntervalSince(started) < 8)
    }
}
