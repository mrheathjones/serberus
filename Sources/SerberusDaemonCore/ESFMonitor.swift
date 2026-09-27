import Darwin
import EndpointSecurity
import Foundation
import os
import PrivMgrCore
import SerberusXPCShim

/// Endpoint Security exec gate.
///
/// Subscribes to `ES_EVENT_TYPE_AUTH_EXEC` and, for a monitored binary,
/// authorizes the execution against the live grant store — the defense-in-depth
/// complement to the sudo/PAM front door. Every other exec is allowed on a fast,
/// lock-free path so the system-wide exec latency this adds is a single set lookup.
///
/// ## What is gated (deliberately conservative)
///
/// The monitored set is the canonical paths of **currently active grants**
/// only (``refreshMonitoredSet()``). An exec of a monitored path is decided by
/// ``isExecAllowed(path:auid:euid:grants:now:)``:
///
/// - keyed on the **audit user id** (`audit_token_to_auid`) — the user who
///   logged in, which survives `sudo` — never the effective uid, which is 0
///   for every sudo child and for every root daemon alike;
/// - an exec with **no audit user** (`AU_DEFAUDITID`: launchd daemons, a
///   root-run `jamf` policy, MDM installs) is always allowed — it did not come
///   from a login session, so it is not a user elevation;
/// - a **non-elevated** exec (effective uid ≠ 0) is always allowed — the gate
///   backs up the sudo front door, it does not ban binaries;
/// - an elevated exec from a login session by a **break-glass** user (named in
///   `pamBypass.users`, or a member of a `pamBypass.groups` group) or by a
///   current member of `admin` is always allowed — the sudo front door lets
///   them through without Serberus, so the backstop must not deny them merely
///   because ANOTHER user holds a grant for the same path;
/// - any other elevated exec from a login session is allowed iff THAT audit
///   user holds an active grant for the exact path.
///
/// Paths the policy merely allows are NOT monitored. Gating every exact-match
/// allow path made an ungranted root exec of it fail — a root-run `jamf`
/// running `installer`, or the very sudo run the policy had just approved (a
/// silent allow issues no grant, and the grant's uid never equalled the exec's
/// euid 0).
///
/// ## Response deadline
///
/// A monitored exec is answered by a race: the decision runs on its own task,
/// and a Dispatch timer answers DENY at ~70% of the kernel's deadline if the
/// decision has not landed by then (``respond(within:decide:respond:)``). The
/// timer does not run on the Swift cooperative pool, and the break-glass/admin
/// lookup (`mbr_check_membership`, `getpwuid_r`, which can block on a slow or
/// unreachable directory node) runs on a Dispatch queue, never on the pool —
/// so a wedged lookup costs one late answer that is thrown away, never a missed
/// deadline (which would get the client killed). Exemption results are cached
/// per audit user for ``exemptionCacheTTL``.
///
/// Concurrency: an `@unchecked Sendable` class, not an actor, because the ES
/// handler block is invoked synchronously on an ES-owned queue and must respond
/// without an `await`. All shared mutable state is confined to two
/// `OSAllocatedUnfairLock`s — `monitored` (the path snapshot) and `state` (the
/// ES client pointer + liveness flag, held together so the async responder and
/// `stop()` can never use/delete the client concurrently).
///
/// > V1 limits: binding the target's code identity (cdhash/teamID) to the grant
/// > is future hardening — acceptable because sudo/PAM is the primary
/// > authorization gate. A user who `su`s to another account and then sudo's
/// > keeps their ORIGINAL audit user id, so they are matched against their
/// > own grants. Stable enforcement requires a persisting grant store (so
/// > grants survive restart) and, live, FDA + the ESF entitlement.
public final class ESFMonitor: @unchecked Sendable {
    /// Snapshot of canonical paths the gate evaluates. Everything not in here is
    /// allowed without querying the grant store (the hot path).
    public struct MonitoredSet: Sendable, Equatable {
        public let paths: Set<String>
        public init(paths: Set<String>) { self.paths = paths }

        /// Builds the set from the canonical paths of all grants active at `now`.
        public init(grants: [Grant], now: Date) {
            self.paths = Set(grants.compactMap { $0.isActive(at: now) ? $0.canonicalPath : nil })
        }

        public static let empty = MonitoredSet(paths: [])
        public func contains(_ path: String) -> Bool { paths.contains(path) }
    }

    public enum ESFError: Error, CustomStringConvertible {
        case clientCreationFailed(es_new_client_result_t)
        case subscribeFailed(es_return_t)

        /// Whether the build lacks the Endpoint Security entitlement (a
        /// production build may ship without it): a fixed property of the
        /// binary, not a fault to retry.
        public var isNotEntitled: Bool {
            if case let .clientCreationFailed(result) = self { return result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED }
            return false
        }

        public var description: String {
            switch self {
            case let .clientCreationFailed(result):
                switch result {
                case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                    return "this build has no Endpoint Security entitlement"
                case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                    return "Endpoint Security is not permitted (Full Disk Access not granted)"
                case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                    return "Endpoint Security needs root"
                case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
                    return "too many Endpoint Security clients"
                default:
                    return "Endpoint Security client creation failed (\(result.rawValue))"
                }
            case let .subscribeFailed(result):
                return "Endpoint Security subscription failed (\(result.rawValue))"
            }
        }
    }

    /// ES client pointer + liveness, guarded together so a response (post-await)
    /// can never touch a client that ``stop()`` is deleting.
    private struct ClientState {
        var client: OpaquePointer?
        var active: Bool
    }

    /// Carries the non-Sendable ES client pointer across `withLock`'s `@Sendable`
    /// body when seeding ``ClientState``.
    private struct ClientHandle: @unchecked Sendable {
        let pointer: OpaquePointer
    }

    private let grantStore: GrantMaintaining
    private let now: @Sendable () -> Date
    /// Live break-glass config (from the EFFECTIVE config), updated by the
    /// daemon on every policy reload.
    private let bypass: OSAllocatedUnfairLock<PAMBypass>
    /// Whether an audit user is exempt from the gate (break-glass or admin).
    /// Injectable so tests need no real accounts.
    private let exemptionCheck: @Sendable (uid_t, PAMBypass) -> Bool
    private let monitored = OSAllocatedUnfairLock<MonitoredSet>(initialState: .empty)
    private let state = OSAllocatedUnfairLock<ClientState>(uncheckedState: ClientState(client: nil, active: false))
    private var refreshTask: Task<Void, Never>?

    /// A cached exemption verdict for one audit user.
    private struct CachedExemption {
        let exempt: Bool
        let expires: ContinuousClock.Instant
    }

    /// Exemption verdicts by audit user, each good for ``exemptionCacheTTL``.
    /// Cleared whenever the break-glass config changes.
    private let exemptionCache = OSAllocatedUnfairLock<[uid_t: CachedExemption]>(initialState: [:])

    /// How long an exemption verdict is reused. Short, so a user leaving
    /// `admin` or a bypass group stops being exempt within seconds, but long
    /// enough that a burst of execs costs one directory lookup.
    static let exemptionCacheTTL: Duration = .seconds(5)

    /// Where the (possibly blocking) directory lookups run: a Dispatch queue,
    /// so they can never tie up the Swift cooperative pool the rest of the
    /// daemon — and the deadline race — depends on.
    private static let exemptionQueue = DispatchQueue(
        label: "com.herojoneslabs.serberus.daemon.esf-exemption", qos: .userInitiated, attributes: .concurrent
    )

    /// Where deadline timers fire. Separate from the cooperative pool for the
    /// same reason.
    private static let deadlineQueue = DispatchQueue(
        label: "com.herojoneslabs.serberus.daemon.esf-deadline", qos: .userInteractive
    )

    /// Background refresh cadence: a backstop so grant expiry eventually leaves
    /// the monitored snapshot even absent an explicit grant-change notification.
    private let refreshInterval: Duration

    public init(
        grantStore: GrantMaintaining,
        bypass: PAMBypass = PAMBypass(),
        refreshInterval: Duration = .seconds(30),
        exemptionCheck: @escaping @Sendable (uid_t, PAMBypass) -> Bool = ESFMonitor.isExemptUser,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.grantStore = grantStore
        self.bypass = OSAllocatedUnfairLock(initialState: bypass)
        self.exemptionCheck = exemptionCheck
        self.refreshInterval = refreshInterval
        self.now = now
    }

    deinit { stop() }

    /// Whether the ES client is subscribed and serving. Read by the health probe.
    /// Flips to `false` on ``stop()`` or when the kernel rejects a response
    /// (client revoked), so a silent client death trips a health-driven restart.
    public var isActive: Bool { state.withLock { $0.active } }

    /// Replaces the break-glass config (called on every policy reload). A
    /// changed config drops every cached exemption verdict.
    public func updateBypass(_ newValue: PAMBypass) {
        let changed = bypass.withLock { current -> Bool in
            defer { current = newValue }
            return current != newValue
        }
        if changed { exemptionCache.withLock { $0.removeAll() } }
    }

    /// Test seam: the current monitored snapshot.
    var monitoredSnapshot: MonitoredSet { monitored.withLock { $0 } }

    // MARK: Lifecycle

    /// Creates the ES client, seeds the monitored set, subscribes to `AUTH_EXEC`,
    /// and starts the backstop refresh loop. The set is seeded *before*
    /// subscribing so the first delivered exec is evaluated against a populated
    /// snapshot (no fail-open window).
    ///
    /// - Throws: ``ESFError`` if the client cannot be created (missing FDA or the
    ///   ESF entitlement) or the subscription fails. ``DaemonController`` logs and
    ///   continues without exec enforcement on throw.
    public func start() async throws {
        var newClient: OpaquePointer?
        let creation = es_new_client(&newClient) { [weak self] client, message in
            guard let self else {
                // Monitor gone: respond on the still-live in-callback client so the
                // exec is not stranded. (Best effort; the kernel auto-allows once a
                // client is fully torn down.)
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                return
            }
            self.handleExec(client: client, message: message)
        }
        guard creation == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            throw ESFError.clientCreationFailed(creation)
        }

        // Seed before subscribing — the kernel delivers no events until subscribe.
        await refreshMonitoredSet()

        // Publish the client BEFORE subscribing: the first message can arrive
        // the moment `es_subscribe` returns, and an async responder that finds
        // no active client releases the message unanswered, which the kernel
        // punishes by revoking the client at the deadline. Rolled back below if
        // the subscription fails. The pointer is wrapped so it can cross
        // withLock's @Sendable body.
        let handle = ClientHandle(pointer: newClient)
        state.withLock { $0.client = handle.pointer; $0.active = true }

        let events: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_EXEC]
        let subscribed = events.withUnsafeBufferPointer { buffer in
            es_subscribe(newClient, buffer.baseAddress!, UInt32(buffer.count))
        }
        guard subscribed == ES_RETURN_SUCCESS else {
            state.withLock { current in
                current.client = nil
                current.active = false
                es_delete_client(handle.pointer)
            }
            throw ESFError.subscribeFailed(subscribed)
        }

        startRefreshLoop()
    }

    /// Unsubscribes and tears down the ES client. Safe against in-flight async
    /// responders: deletion happens under `state`'s lock, so a responder either
    /// runs fully before deletion or sees a nil client afterward and no-ops.
    public func stop() {
        refreshTask?.cancel()
        refreshTask = nil
        state.withLock { current in
            if let client = current.client {
                es_unsubscribe_all(client)
                es_delete_client(client)
            }
            current.client = nil
            current.active = false
        }
    }

    // MARK: Monitored set

    /// Rebuilds the monitored snapshot from the grant store. Called on every
    /// grant issuance/revocation (by ``DaemonController``) and by the backstop
    /// loop. A store read failure leaves the previous snapshot in place.
    public func refreshMonitoredSet() async {
        let timestamp = now()
        guard let grants = try? await grantStore.activeGrants(now: timestamp) else { return }
        // Only paths with a LIVE grant are gated; everything else takes the
        // hot-path allow. (Policy-controlled paths are deliberately not added —
        // see the type doc.)
        let set = MonitoredSet(grants: grants, now: timestamp)
        monitored.withLock { $0 = set }
    }

    private func startRefreshLoop() {
        let interval = refreshInterval
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: interval)
                if Task.isCancelled { break }
                await self?.refreshMonitoredSet()
            }
        }
    }

    // MARK: Exec authorization

    /// `AU_DEFAUDITID` (`(uid_t)-1`): the audit user id of a process that no
    /// login session ever claimed — launchd daemons and everything they spawn.
    /// (The C macro is not importable into Swift.)
    static let unsetAuditUserID: uid_t = uid_t.max

    /// Pure decision used by the handler and unit tests, for an exec of a
    /// MONITORED path (one with at least one active grant):
    ///
    /// 1. No audit user (`auid == AU_DEFAUDITID`) → allow: not a login-session
    ///    process, so not a user elevation (root-run jamf, MDM, daemons).
    /// 2. Not elevated (`euid != 0`) → allow: the gate backs up sudo, it does
    ///    not ban a binary from ordinary use.
    /// 3. Otherwise allow iff the AUDIT user — who logged in, and whom sudo
    ///    does not change — holds a grant for this exact path that is active
    ///    at `now`. Grants are issued to the requesting user's uid, which is
    ///    the auid of their sudo child, never its euid (0).
    ///
    /// `isExempt` (break-glass or current `admin` member — see
    /// ``isExemptUser(auid:bypass:)``) short-circuits step 3 to allow; the
    /// exemption is consulted only after the grant check fails, so the common
    /// granted case never touches the directory.
    static func isExecAllowed(path: String, auid: uid_t, euid: uid_t, grants: [Grant], now: Date,
                              isExempt: @autoclosure () -> Bool = false) -> Bool {
        guard auid != unsetAuditUserID else { return true }
        guard euid == 0 else { return true }
        if grants.contains(where: { $0.canonicalPath == path && $0.uid == auid && $0.isActive(at: now) }) {
            return true
        }
        return isExempt()
    }

    /// Production exemption: the audit user is named in `pamBypass.users`, is a
    /// member of any `pamBypass.groups` group, or is currently a member of
    /// `admin` (group membership via `mbr_check_membership`, nested groups
    /// included — the same check `pam_serberus` applies to `pamBypass.groups`).
    /// An unresolvable uid is never exempt. A `pamBypass.users` entry matches
    /// only the uid's canonical record name, byte for byte: the same rule the
    /// daemon's resolvability check and `pam_serberus` apply.
    public static func isExemptUser(auid: uid_t, bypass: PAMBypass) -> Bool {
        if !bypass.users.isEmpty, let name = LocalAccounts.userName(uid: auid),
           bypass.users.contains(where: { LocalAccounts.namesMatchExactly($0, name) }) {
            return true
        }
        for group in bypass.groups where LocalAccounts.isMember(uid: auid, ofGroup: group) == true {
            return true
        }
        return LocalAccounts.isMember(uid: auid, ofGroup: JITAdmin.adminGroup) == true
    }

    /// Authorizes one exec against the live store. Fails closed (deny) when the
    /// store cannot be read AND the exec is an elevated one from a login
    /// session by a non-exempt user — the only case the pure decision could deny.
    ///
    /// Same decision as the pure ``isExecAllowed(path:auid:euid:grants:now:isExempt:)``;
    /// the exemption is looked up (cached, off the cooperative pool) only when
    /// no grant covers the exec. Unbounded on its own — the ES handler bounds it
    /// with ``respond(within:decide:respond:)``.
    func isExecAllowed(path: String, auid: uid_t, euid: uid_t) async -> Bool {
        if auid == Self.unsetAuditUserID || euid != 0 { return true }
        let timestamp = now()
        if let grants = try? await grantStore.activeGrants(now: timestamp),
           Self.isExecAllowed(path: path, auid: auid, euid: euid, grants: grants, now: timestamp) {
            return true
        }
        return await isExempt(auid: auid)
    }

    /// Whether `auid` is exempt (break-glass or current admin), from the cache
    /// when a verdict younger than ``exemptionCacheTTL`` exists, else looked up
    /// on ``exemptionQueue`` and cached.
    func isExempt(auid: uid_t) async -> Bool {
        let now = ContinuousClock.now
        if let cached = exemptionCache.withLock({ $0[auid] }), cached.expires > now {
            return cached.exempt
        }
        let currentBypass = bypass.withLock { $0 }
        let check = exemptionCheck
        let exempt = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            Self.exemptionQueue.async { continuation.resume(returning: check(auid, currentBypass)) }
        }
        // Only cache a verdict for the config it was computed under: a reload
        // that landed meanwhile has already cleared the cache.
        if bypass.withLock({ $0 }) == currentBypass {
            let entry = CachedExemption(exempt: exempt, expires: ContinuousClock.now.advanced(by: Self.exemptionCacheTTL))
            exemptionCache.withLock { $0[auid] = entry }
        }
        return exempt
    }

    // MARK: ES handler

    /// Carries the (non-`Sendable`) message pointer into the async authorization
    /// task. The message is balanced with `es_retain_message`/`es_release_message`.
    private struct MessageBox: @unchecked Sendable {
        let message: UnsafePointer<es_message_t>
    }

    private func handleExec(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        // `event.exec.target` and `process` are non-optional pointers in the ES
        // Swift import, valid for the message's lifetime.
        let path = Self.path(from: message.pointee.event.exec.target.pointee.executable.pointee.path)

        // Hot path: not under a grant → allow synchronously (client is live for
        // the duration of this callback).
        guard monitored.withLock({ $0 }).contains(path) else {
            respondInCallback(client: client, message: message, allow: true)
            return
        }

        // The exec'ing process (for a sudo run: sudo itself, euid 0). The
        // decision keys on its AUDIT user id, which sudo preserves.
        let token = message.pointee.process.pointee.audit_token
        let auid = audit_token_to_auid(token)
        let euid = serberus_audit_token_euid(token)
        // Not a login-session elevation → allow synchronously, no store query.
        if auid == Self.unsetAuditUserID || euid != 0 {
            respondInCallback(client: client, message: message, allow: true)
            return
        }
        // Answer within the kernel's per-message auth deadline, whatever the
        // decision does: the store query or the directory lookup behind the
        // exemption can block (an unreachable directory node), and a missed
        // deadline gets the client killed, disabling enforcement machine-wide.
        // The deadline timer answers DENY (fail closed — the path is under a
        // grant) and the late decision is discarded.
        let budget = Self.authorizationBudget(deadline: message.pointee.deadline)

        es_retain_message(message)
        let box = MessageBox(message: message)
        Self.respond(within: budget, decide: { [weak self] in
            await self?.isExecAllowed(path: path, auid: auid, euid: euid) ?? false
        }, respond: { [weak self] allowed in
            guard let self else {
                // Monitor deallocated (client torn down): release, do not respond
                // on a deleted client.
                es_release_message(box.message)
                return
            }
            self.respondAsync(message: box.message, allow: allowed)
        })
    }

    /// Races `decide` against a `budget` timer and calls `respond` EXACTLY
    /// once: with the decision if it lands first, else with `false` (deny) when
    /// the timer fires. The loser is abandoned, not awaited — the decision keeps
    /// running on its own task and its result is dropped — so the answer is
    /// bounded by `budget` however long `decide` blocks. The timer is a
    /// Dispatch timer, so a cooperative pool tied up elsewhere cannot delay it.
    static func respond(
        within budget: Duration,
        decide: @escaping @Sendable () async -> Bool,
        respond: @escaping @Sendable (Bool) -> Void
    ) {
        let answered = OSAllocatedUnfairLock(initialState: false)
        let claim: @Sendable () -> Bool = {
            answered.withLock { done in
                guard !done else { return false }
                done = true
                return true
            }
        }
        let components = budget.components
        let nanos = max(0, components.seconds) * 1_000_000_000 + max(0, components.attoseconds) / 1_000_000_000
        deadlineQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(clamping: nanos))) {
            if claim() { respond(false) }
        }
        Task.detached(priority: .userInitiated) {
            let allowed = await decide()
            if claim() { respond(allowed) }
        }
    }

    /// Synchronous response from within the ES callback (client guaranteed live).
    private func respondInCallback(client: OpaquePointer, message: UnsafePointer<es_message_t>, allow: Bool) {
        let result = es_respond_auth_result(client, message, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
        if result != ES_RESPOND_RESULT_SUCCESS { markClientLost(result) }
    }

    /// Response after a suspension: takes `state`'s lock so it can never race
    /// ``stop()``'s `es_delete_client`. Releases the retained message exactly once.
    private func respondAsync(message: UnsafePointer<es_message_t>, allow: Bool) {
        let box = MessageBox(message: message)  // cross withLock's @Sendable body
        let result: es_respond_result_t? = state.withLock { current in
            guard current.active, let client = current.client else { return nil }
            return es_respond_auth_result(
                client, box.message, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false
            )
        }
        es_release_message(message)
        if let result, result != ES_RESPOND_RESULT_SUCCESS { markClientLost(result) }
    }

    /// The kernel rejected a response (duplicate, or the client was revoked for a
    /// missed deadline). Flip inactive so the health probe trips a restart that
    /// re-establishes enforcement, and log it.
    private func markClientLost(_ result: es_respond_result_t) {
        state.withLock { $0.active = false }
        DaemonLog.integrity.critical(
            "ESF client lost (es_respond_auth_result=\(result.rawValue, privacy: .public)); enforcement will restart"
        )
    }

    /// Authorization budget from the message's Mach-absolute deadline: at most
    /// 70% of the time remaining (capped at 5s), `.zero` if already past.
    static func authorizationBudget(deadline: UInt64) -> Duration {
        var info = mach_timebase_info_data_t()
        guard mach_timebase_info(&info) == KERN_SUCCESS, info.denom != 0 else {
            return .milliseconds(500)
        }
        let nowAbs = mach_absolute_time()
        guard deadline > nowAbs else { return .zero }
        // Overflow-safe even for an absurd/malformed deadline: a crash here would
        // strand the exec and ultimately disable enforcement. Wrapping multiply
        // for the timebase, divide-before-multiply for the 70% margin, hard cap.
        let remainingNanos = (deadline - nowAbs) &* UInt64(info.numer) / UInt64(info.denom)
        let budgetNanos = min((remainingNanos / 10) &* 7, 5_000_000_000)
        return .nanoseconds(Int64(budgetNanos))
    }

    /// Decodes an `es_string_token_t` (length-delimited, not NUL-terminated).
    static func path(from token: es_string_token_t) -> String {
        guard token.length > 0, let base = token.data else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: base, count: token.length), as: UTF8.self)
    }
}
