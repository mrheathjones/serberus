import Foundation
import PrivMgrCore

/// The five liveness probes the health monitor runs. launchd
/// already handles crashes and non-zero exits; these catch *alive-but-broken*
/// states an unhandled-exception model misses.
public protocol DaemonHealthChecks: Sendable {
    func xpcListenerIsActive() async -> Bool
    func ruleEngineIsResponsive() async -> Bool
    func grantDatabaseIsResponsive() async -> Bool
    func authDBManagerIsHealthy() async -> Bool
    func esfSubscriptionIsActive() async -> Bool
}

/// Periodically probes the daemon and, on any failure, drives a restart.
///
/// The failure-detection step (``evaluate()``) is pure and unit-tested. The
/// reaction is injected as `onUnhealthy` so tests observe it without the
/// process actually exiting; the production reaction writes `degraded` and
/// calls `exit(1)` so launchd restarts within `ThrottleInterval`.
public actor HealthMonitor {
    private let checks: DaemonHealthChecks
    private let checkInterval: Duration
    private let onUnhealthy: @Sendable ([String]) async -> Void
    private var task: Task<Void, Never>?

    public init(
        checks: DaemonHealthChecks,
        checkInterval: Duration = .seconds(30),
        onUnhealthy: @escaping @Sendable ([String]) async -> Void
    ) {
        self.checks = checks
        self.checkInterval = checkInterval
        self.onUnhealthy = onUnhealthy
    }

    /// Runs all five probes and returns the list of failures (empty = healthy).
    public func evaluate() async -> [String] {
        var failures: [String] = []
        if !(await checks.xpcListenerIsActive()) { failures.append("XPC listener not active") }
        if !(await checks.ruleEngineIsResponsive()) { failures.append("Rule engine unresponsive") }
        if !(await checks.grantDatabaseIsResponsive()) { failures.append("Grant database unresponsive") }
        if !(await checks.authDBManagerIsHealthy()) { failures.append("AuthorizationDB manager unhealthy") }
        if !(await checks.esfSubscriptionIsActive()) { failures.append("ESF subscription dropped") }
        return failures
    }

    /// Runs one probe cycle and reacts if unhealthy. Exposed for tests.
    public func runOnce() async {
        let failures = await evaluate()
        guard !failures.isEmpty else { return }
        DaemonLog.integrity.critical(
            "Health check failed [\(failures.joined(separator: ", "), privacy: .public)] — restarting"
        )
        await onUnhealthy(failures)
    }

    /// Starts the periodic probe loop. Call after `state=healthy` is written.
    public func start() {
        guard task == nil else { return }
        task = Task { [checkInterval] in
            while !Task.isCancelled {
                try? await Task.sleep(for: checkInterval)
                if Task.isCancelled { break }
                await runOnce()
            }
        }
    }

    /// Stops the loop cleanly (before a graceful `exit(0)`).
    public func stop() {
        task?.cancel()
        task = nil
    }
}
