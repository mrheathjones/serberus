import Foundation
import PrivMgrCore

/// Concrete liveness probes for the running daemon.
///
/// Held by ``HealthMonitor`` as a `Sendable` value: it references the listener
/// (a `Sendable` class) and the grant store (an actor), and races each async
/// probe against a short timeout so a deadlocked component reads as a failure
/// rather than hanging the monitor.
public struct DaemonHealthProbe: DaemonHealthChecks {
    private let listener: XPCListenerService
    private let grantStore: GrantMaintaining
    private let sentinelPushService: SentinelPushService?
    private let esfMonitor: ESFMonitor?
    private let probeTimeout: Duration
    private let now: @Sendable () -> Date

    public init(
        listener: XPCListenerService,
        grantStore: GrantMaintaining,
        sentinelPushService: SentinelPushService? = nil,
        esfMonitor: ESFMonitor? = nil,
        probeTimeout: Duration = .seconds(2),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.listener = listener
        self.grantStore = grantStore
        self.sentinelPushService = sentinelPushService
        self.esfMonitor = esfMonitor
        self.probeTimeout = probeTimeout
        self.now = now
    }

    /// Whether a Sentinel is currently connected for prompt delivery.
    ///
    /// Observational only — a missing Sentinel is normal (the user may be logged
    /// out or the LaunchAgent not yet running) and must **never** trigger a
    /// restart, so this is deliberately not part of ``DaemonHealthChecks``.
    public func sentinelIsConnected() async -> Bool {
        await sentinelPushService?.isSentinelConnected ?? false
    }

    public func xpcListenerIsActive() async -> Bool {
        listener.isActive()
    }

    public func ruleEngineIsResponsive() async -> Bool {
        // The engine is pure and stateless; a trivial evaluation completing
        // within the timeout proves the cooperative pool isn't wedged.
        let now = self.now
        return await withTimeout(probeTimeout, fallback: false) {
            let request = ElevationRequest(
                user: "_serberus_health", uid: 0,
                kind: .authURI("system.serberus.health-probe"),
                identity: BinaryIdentity(canonicalPath: "/", teamID: nil, sha256: "", signingStatus: .unsigned),
                timestamp: now()
            )
            _ = RuleEngine().evaluate(request: request, profiles: [], globalCacheSeconds: 0, activeGrants: [])
            return true
        }
    }

    public func grantDatabaseIsResponsive() async -> Bool {
        let store = grantStore
        let now = self.now
        return await withTimeout(probeTimeout, fallback: false) {
            // Liveness, not correctness: the store *answering* within the timeout
            // — even by throwing — proves its actor isn't wedged. A thrown error
            // is an intentional degraded state (e.g. the `NullGrantStore` used in
            // `degraded(grants_db_error)`); restarting cannot fix it and would
            // loop forever. Only a timeout (a deadlocked actor) is unhealthy, and
            // that path returns the `false` fallback.
            _ = try? await store.activeGrants(now: now())
            return true
        }
    }

    public func authDBManagerIsHealthy() async -> Bool {
        // No live AuthorizationDB probe: apply/reconcile failures already drive
        // the daemon to `degraded(authdb_failure)`, so this always reports healthy.
        true
    }

    public func esfSubscriptionIsActive() async -> Bool {
        // A *running* ESF client reports its live state. When ESF was never
        // started — daemon degraded, no Full Disk Access, or the entitlement
        // unavailable — the monitor is nil and this returns true: ESF is
        // intentionally absent, not "dropped," so it must not trigger a restart
        // loop (same liveness-not-correctness rule as the grant-DB probe).
        esfMonitor?.isActive ?? true
    }
}

/// Runs `operation`, returning `fallback` if it does not finish within
/// `duration`. The loser task is cancelled.
func withTimeout<T: Sendable>(
    _ duration: Duration,
    fallback: T,
    operation: @escaping @Sendable () async -> T
) async -> T {
    await withTaskGroup(of: T?.self) { group in
        group.addTask { await operation() }
        group.addTask {
            try? await Task.sleep(for: duration)
            return nil
        }
        defer { group.cancelAll() }
        for await result in group {
            if let result { return result }
            return fallback
        }
        return fallback
    }
}

/// Grant-store stand-in used when the real SQLite store cannot be opened.
///
/// Reads throw, so ``StartupCoordinator`` resolves `degraded(grants_db_error)`
/// — deny all timed grants, allow silent — exactly as the spec requires.
///
/// It can still carry a keyless, existing-only view of the database
/// (``unverifiedRows``) — the case where the grants key is gone but rows
/// remain. No row verifies without the key, so every JIT row there is an
/// unverifiable-row demotion candidate, and the JIT manager's sweep demotes
/// those users on every tick even though nothing else about the store works.
public struct NullGrantStore: GrantMaintaining, UnverifiedJITRowSource {
    /// Keyless view of the existing database, or nil when none could be opened.
    private let unverifiedRows: (any UnverifiedJITRowSource)?

    public init(unverifiedRows: (any UnverifiedJITRowSource)? = nil) {
        self.unverifiedRows = unverifiedRows
    }

    /// Whether a keyless view of the existing database is attached.
    public var hasUnverifiedRowSource: Bool { unverifiedRows != nil }

    public func unverifiedJITCandidates() async throws -> [UnverifiedJITRow] {
        try await unverifiedRows?.unverifiedJITCandidates() ?? []
    }

    public func retireUnverifiedRow(rowID: Int64) async throws -> Bool {
        try await unverifiedRows?.retireUnverifiedRow(rowID: rowID) ?? false
    }

    public func insert(_ grant: Grant) async throws {
        throw GrantStoreError.openFailed(path: "(unavailable)", code: 14, message: "grant store unavailable")
    }
    public func cleanupExpired(now: Date) async throws -> Int {
        throw GrantStoreError.openFailed(path: "(unavailable)", code: 14, message: "grant store unavailable")
    }
    public func activeGrants(now: Date) async throws -> [Grant] {
        throw GrantStoreError.openFailed(path: "(unavailable)", code: 14, message: "grant store unavailable")
    }
    public func activeGrants(for user: String, now: Date) async throws -> [Grant] {
        throw GrantStoreError.openFailed(path: "(unavailable)", code: 14, message: "grant store unavailable")
    }
    public func revokeAll(now: Date) async throws -> Int { 0 }
    public func revoke(grantID: UUID, now: Date) async throws -> Int { 0 }
}
