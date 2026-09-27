import Foundation
import PrivMgrCore

/// Applies AuthorizationDB modifications during startup (startup step 9 in
/// ``StartupCoordinator``).
///
/// Production uses ``AuthorizationDBApplier``, backed by
/// ``AuthorizationDBManager`` (dynamic right discovery, checksummed snapshots,
/// minimal-diff injection, rollback); tests inject
/// ``NoopAuthorizationDBApplier`` or a failing mock so the startup sequence and
/// its failure handling (`authdb_failure` → degraded) are fully exercisable.
public protocol AuthorizationDBApplying: Sendable {
    /// Injects the rights required by `profiles`, snapshotting originals.
    /// - Throws: on any failure, signalling `degraded(authdb_failure)`.
    func apply(profiles: [RuleProfile]) async throws

    /// Reconciles the live authdb to `profiles`: restores every right Serberus
    /// controls to its original, then applies the current desired set. Unlike
    /// ``apply(profiles:)`` this restores rights **removed** from the policy, so
    /// a live rule reload doesn't strand a stale deny/admin-gate. Used by the
    /// daemon's managed-preferences reload loop.
    func reconcile(profiles: [RuleProfile]) async throws
}

public extension AuthorizationDBApplying {
    /// Default: appliers with no restore capability (e.g. the noop) just apply.
    func reconcile(profiles: [RuleProfile]) async throws {
        try await apply(profiles: profiles)
    }
}

/// Performs no AuthorizationDB modification and never fails. Used by tests
/// that exercise the startup sequence without touching the real authdb.
public struct NoopAuthorizationDBApplier: AuthorizationDBApplying {
    public init() {}
    public func apply(profiles: [RuleProfile]) async throws {}
}

/// The grant-store operations the startup sequence and revocation paths need.
///
/// Defined as a protocol so ``StartupCoordinator`` can be unit-tested with a
/// mock that injects failures (to drive `grants_db_error`) without a real
/// SQLite database. ``GrantStore`` satisfies it directly.
public protocol GrantMaintaining: Sendable {
    func insert(_ grant: Grant) async throws
    @discardableResult func cleanupExpired(now: Date) async throws -> Int
    func activeGrants(now: Date) async throws -> [Grant]
    func activeGrants(for user: String, now: Date) async throws -> [Grant]
    /// Every grant, including revoked and expired — needed to reconcile
    /// membership Serberus mutated (e.g. JIT admin) across a daemon restart.
    func allGrants() async throws -> [Grant]
    @discardableResult func revokeAll(now: Date) async throws -> Int
    @discardableResult func revoke(grantID: UUID, now: Date) async throws -> Int
    /// Revokes every non-JIT grant whose window is over — on the wall clock,
    /// the continuous clock, or because the clock was set back before issue.
    /// Run on every daemon tick.
    @discardableResult func revokeExpired(now: Date) async throws -> Int
    /// Gives every live timed row without a continuous-clock deadline in this
    /// boot session one, shortening only. Run once at daemon start.
    @discardableResult func restampContinuousDeadlines(now: Date) async throws -> Int
    /// Gives one indefinite grant an expiry `seconds` from `now`
    /// (``GrantPolicyAlignment``). Returns the number of rows changed.
    @discardableResult func bound(grantID: UUID, seconds: Int, now: Date) async throws -> Int
    /// Records the GeneratedUID on JIT rows written without one, where the
    /// row's name and uid still name the same account. Run once at start.
    @discardableResult func stampGeneratedUIDs(resolve: @Sendable (String, uid_t) -> String?) async throws -> Int
}

public extension GrantMaintaining {
    /// Default for conformers that don't retain revoked/expired rows (the
    /// `NullGrantStore` and in-memory test fakes): falls back to active grants.
    /// The real ``GrantStore`` overrides this with a full-table read.
    func allGrants() async throws -> [Grant] {
        try await activeGrants(now: Date())
    }

    /// Default for conformers that hold no persistent rows (in-memory test
    /// fakes, the `NullGrantStore`): nothing to revoke.
    func revokeExpired(now: Date) async throws -> Int { 0 }

    /// Default for conformers that hold no persistent rows: nothing to stamp.
    func restampContinuousDeadlines(now: Date) async throws -> Int { 0 }

    /// Default for conformers that hold no persistent rows: nothing to stamp.
    func stampGeneratedUIDs(resolve: @Sendable (String, uid_t) -> String?) async throws -> Int { 0 }

    /// Default for conformers that cannot rewrite a row: the grant is revoked
    /// instead, which ends it no later than bounding would.
    func bound(grantID: UUID, seconds: Int, now: Date) async throws -> Int {
        try await revoke(grantID: grantID, now: now)
    }
}

extension GrantStore: GrantMaintaining {}
