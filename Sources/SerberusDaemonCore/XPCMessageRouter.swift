import Foundation
import PrivMgrCore

// MARK: - PAM request / response value types

/// A decoded PAM request (the flat dictionary contract).
public struct PAMRequest: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        /// `argv` excludes the command itself and is preserved as a list.
        case sudo(command: String, argv: [String], tty: String?)
        case authURI(String)
    }

    public let user: String
    public let kind: Kind

    public init(user: String, kind: Kind) {
        self.user = user
        self.kind = kind
    }
}

/// The daemon's answer to a PAM request.
public struct PAMResponse: Sendable, Equatable {
    public let decision: Decision
    public let cacheSeconds: Int
    public let grantID: UUID?
    public let ruleID: String?
    /// Set only when `decision == .prompt`: the round-trip ticket PAM polls
    /// with. The listener serializes this as the `prompt_pending` reply.
    public let promptRequestID: UUID?
    /// The requesting user is a JIT admin right now (an active Serberus JIT
    /// grant or an observed Jamf Connect elevation, AND live `admin`
    /// membership): the wire reply is `native`, and PAM steps aside so sudo
    /// behaves exactly as native macOS. ``decision`` is `.deny` underneath, so
    /// any code that does not know about `native` treats it as a deny.
    public let native: Bool

    public init(
        decision: Decision,
        cacheSeconds: Int,
        grantID: UUID?,
        ruleID: String?,
        promptRequestID: UUID? = nil,
        native: Bool = false
    ) {
        self.decision = decision
        self.cacheSeconds = cacheSeconds
        self.grantID = grantID
        self.ruleID = ruleID
        self.promptRequestID = promptRequestID
        self.native = native
    }

    /// PAM maps any non-allow decision to a hard deny.
    public var isAllow: Bool { !native && (decision == .allow || decision == .timedGrant) }

    public static let deny = PAMResponse(decision: .deny, cacheSeconds: 0, grantID: nil, ruleID: nil)

    /// The `native` reply (see ``native``).
    public static func native(ruleID: String, grantID: UUID? = nil) -> PAMResponse {
        PAMResponse(decision: .deny, cacheSeconds: 0, grantID: grantID, ruleID: ruleID, native: true)
    }
}

// MARK: - Daemon query surface

/// What the daemon exposes to validated XPC callers. ``DaemonController``
/// conforms; tests use a mock so the router is verifiable without XPC.
public protocol DaemonQuerying: Sendable {
    func handlePAM(_ request: PAMRequest) async -> PAMResponse
    func currentDaemonState() async -> DaemonState
    func activeGrants(forUser user: String?) async -> [Grant]
    /// The loaded rules as display summaries for the Sentinel popover. Profiles
    /// are device-scoped by MDM, so the whole loaded set applies to the
    /// console user; no per-user filtering happens here.
    func userRules() async -> SentinelRulesSnapshot
    /// JIT local-admin availability for the calling user's Sentinel.
    func jitAdminInfo() async -> JITAdminInfo
    /// Handle a user's JIT local-admin request.
    func requestAdminElevation(user: String, justification: String) async -> JITAdminResult
    /// End the user's active JIT local-admin window early.
    func endAdminElevation(user: String) async -> Bool
    /// Collect the diagnostics the console user cannot read for themselves, and
    /// hand them to `callerUID`. Read-only: it copies files and runs `log show`
    /// with a hard-coded predicate, and mutates no policy state.
    ///
    /// Returns a plain failure string rather than a typed error: the value is
    /// serialized straight into the XPC `error` key, and the router has no use
    /// for a richer type it would only stringify anyway.
    func collectPrivilegedDiagnostics(
        request: IntelRequest,
        callerUID: uid_t
    ) async -> IntelCollectionOutcome
    /// Return recent authorization-right attempts as NDJSON for the live view.
    /// Read-only, stateless, bounded.
    func pollAuthorizations(
        request: AuthorizationPollRequest,
        callerUID: uid_t
    ) async -> AuthorizationPollOutcome
    /// Return recent sudo attempts (sudo's own unified-log lines) as NDJSON for
    /// a Capture session. Read-only, stateless, bounded.
    func pollSudoAttempts(
        request: SudoPollRequest,
        callerUID: uid_t
    ) async -> SudoPollOutcome
    /// Install a user-chosen `.pkg`/`.app` as root, gated by the install-software
    /// rule and the notarized-Developer-ID trust check. `callerUID` is the
    /// kernel-stamped console user (never from the message; uid 0 is refused);
    /// `callerUser` is its name for the confirmation prompt.
    func installSoftware(
        request: InstallRequest,
        callerUID: uid_t,
        callerUser: String?
    ) async -> InstallResult
    /// Uninstall (move to Trash) a `/Applications` app as root, gated by the
    /// app-management rule + `allowUninstall`. Same caller contract as install.
    func uninstallSoftware(
        request: UninstallRequest,
        callerUID: uid_t,
        callerUser: String?
    ) async -> InstallResult
}

/// Outcome of an authorization poll. Not `Result` — its `Failure` must be an
/// `Error`, and only a message string crosses XPC.
public enum AuthorizationPollOutcome: Sendable, Equatable {
    case collected(AuthorizationPollResult)
    case failed(String)
}

/// Outcome of a sudo-attempts poll (same shape as ``AuthorizationPollOutcome``).
public enum SudoPollOutcome: Sendable, Equatable {
    case collected(SudoPollResult)
    case failed(String)
}

/// Outcome of a privileged collection. `Result` is not used because its
/// `Failure` must be an `Error`, and the only thing that crosses XPC here is a
/// message string.
public enum IntelCollectionOutcome: Sendable, Equatable {
    case collected(IntelHandoff)
    case failed(String)
}

// MARK: - Reply representation

/// A transport-neutral reply the listener serializes into an xpc dictionary.
/// Keeping it neutral lets the router be tested without constructing real
/// xpc objects.
public enum XPCReply: Sendable, Equatable {
    /// A Codable payload encoded under ``XPCMessageKey/reply``.
    case payload(Data)
    /// A boolean under ``XPCMessageKey/success``.
    case success(Bool)
    /// An error string under ``XPCMessageKey/error`` (rejected/failed request).
    case failure(String)
    /// PAM's flat response fields.
    case pam(PAMResponse)
    /// A `poll_prompt` whose verdict is not yet known: serialized as the
    /// `pending` decision so PAM keeps polling.
    case pamPromptUnresolved
    /// A `poll_prompt` that resolved WITHOUT approval: serialized as a deny
    /// plus a ``PAMXPCKey/verdict`` detail so the PAM module can tell the
    /// user "you declined" / "it timed out" instead of the misleading
    /// "not permitted by policy".
    case pamPromptDenied(timedOut: Bool)
}

// MARK: - Router

/// Dispatches a validated message to the daemon and produces a reply.
///
/// The peer's code identity is validated by the listener *before* the router
/// runs; the router additionally enforces that the validated interface
/// matches the requested method (an Intel peer cannot reach a Sentinel method).
public struct XPCMessageRouter: Sendable {
    private let daemon: DaemonQuerying

    public init(daemon: DaemonQuerying) {
        self.daemon = daemon
    }

    /// Routes a PAM request. The listener builds ``PAMRequest`` from the flat
    /// dictionary; the router returns the response fields.
    public func routePAM(_ request: PAMRequest) async -> XPCReply {
        .pam(await daemon.handlePAM(request))
    }

    /// Routes a Sentinel or Intel method.
    ///
    /// - Parameters:
    ///   - validatedInterface: the interface proven by code-identity validation.
    ///   - interface: the interface claimed in the message.
    ///   - method: the method name from the message.
    ///   - payload: optional Codable-encoded request payload.
    ///   - callerUser: the validated peer's username, for user-scoped queries.
    public func routeTyped(
        validatedInterface: XPCInterface,
        interface: String,
        method: String,
        payload: Data?,
        callerUser: String?,
        /// Kernel-stamped euid of the peer. Optional so existing call sites and
        /// tests are unaffected; the `.intel` route requires it, because the
        /// hand-off is chowned to it and a caller-supplied uid would let one
        /// user hand another's logs to themselves.
        callerUID: uid_t? = nil
    ) async -> XPCReply {
        guard let claimed = XPCInterface(rawValue: interface) else {
            return .failure("unknown interface '\(interface)'")
        }
        // A peer may use its own interface, plus ONE explicit cross-interface
        // allowance: the Sentinel (the unified user-facing app, which absorbed
        // the Serberus Intel diagnostics UI) may also reach the READ-ONLY
        // ``XPCInterface/intel`` methods (pollAuthorizations, privileged
        // diagnostics collection). The Sentinel is at least as trusted as Intel
        // — it drives elevation prompts and is pinned by bundle ID + Team ID +
        // Hardened Runtime + the designated requirement — and `.intel` grants no
        // policy mutation. NOT symmetric: Intel can never reach Sentinel methods.
        let sentinelUsingIntel = validatedInterface == .sentinel && claimed == .intel
        guard claimed == validatedInterface || sentinelUsingIntel else {
            return .failure("interface mismatch: validated \(validatedInterface.rawValue), claimed \(claimed.rawValue)")
        }

        switch claimed {
        case .pam:
            return .failure("PAM uses the flat dictionary contract, not typed methods")
        case .sentinel:
            return await routeSentinel(method: method, payload: payload, callerUser: callerUser, callerUID: callerUID)
        case .intel:
            return await routeIntel(method: method, payload: payload, callerUID: callerUID)
        }
    }

    /// Serberus Intel — read-only diagnostics collection.
    ///
    /// This interface exposes only read-only methods and cannot reach the
    /// sentinel surface: `routeTyped` has already refused any message whose
    /// claimed interface differs from the validated one.
    private func routeIntel(method: String, payload: Data?, callerUID: uid_t?) async -> XPCReply {
        guard let intelMethod = IntelXPCMethod(rawValue: method) else {
            return .failure("unknown intel method '\(method)'")
        }
        switch intelMethod {
        case .collectPrivilegedDiagnostics:
            guard let callerUID else {
                return .failure("collectPrivilegedDiagnostics requires a validated caller uid")
            }
            guard let payload,
                  let request = try? SerberusXPCCoding.decode(IntelRequest.self, from: payload) else {
                return .failure("collectPrivilegedDiagnostics requires an IntelRequest payload")
            }
            switch await daemon.collectPrivilegedDiagnostics(request: request, callerUID: callerUID) {
            case let .collected(handoff):
                return encode(handoff)
            case let .failed(message):
                return .failure(message)
            }
        case .pollAuthorizations:
            guard let callerUID else {
                return .failure("pollAuthorizations requires a validated caller uid")
            }
            guard let payload,
                  let request = try? SerberusXPCCoding.decode(AuthorizationPollRequest.self, from: payload) else {
                return .failure("pollAuthorizations requires an AuthorizationPollRequest payload")
            }
            switch await daemon.pollAuthorizations(request: request, callerUID: callerUID) {
            case let .collected(result):
                return encode(result)
            case let .failed(message):
                return .failure(message)
            }
        case .pollSudoAttempts:
            // Same gating as pollAuthorizations: the uid must be the
            // audit-token uid (never from the message), and the payload is the
            // typed request whose window the collector allowlists.
            guard let callerUID else {
                return .failure("pollSudoAttempts requires a validated caller uid")
            }
            guard let payload,
                  let request = try? SerberusXPCCoding.decode(SudoPollRequest.self, from: payload) else {
                return .failure("pollSudoAttempts requires a SudoPollRequest payload")
            }
            switch await daemon.pollSudoAttempts(request: request, callerUID: callerUID) {
            case let .collected(result):
                return encode(result)
            case let .failed(message):
                return .failure(message)
            }
        }
    }

    private func routeSentinel(method: String, payload: Data?, callerUser: String?, callerUID: uid_t?) async -> XPCReply {
        guard let agentMethod = SentinelXPCMethod(rawValue: method) else {
            return .failure("unknown sentinel method '\(method)'")
        }
        switch agentMethod {
        case .registerSentinel:
            // The listener owns the peer connection and registers it before the
            // router runs; reaching here means it was already retained.
            return .success(true)
        case .daemonState:
            return encode(await daemon.currentDaemonState())
        case .activeGrants:
            // The Sentinel only ever sees the logged-in user's grants.
            return encode(await daemon.activeGrants(forUser: callerUser))
        case .userRules:
            return encode(await daemon.userRules())
        case .presentPrompt:
            // Daemon → Sentinel direction; the Sentinel never invokes this inbound.
            return .failure("presentPrompt is daemon-initiated")
        case .jitAdminInfo:
            return encode(await daemon.jitAdminInfo())
        case .requestAdminElevation:
            // The elevation is always applied to the *validated* caller — the
            // justification is the only client-supplied field, so a peer can
            // never elevate a different user.
            guard let callerUser else {
                return .failure("requestAdminElevation requires a validated caller")
            }
            let justification = payload.flatMap { try? SerberusXPCCoding.decode(String.self, from: $0) } ?? ""
            return encode(await daemon.requestAdminElevation(user: callerUser, justification: justification))
        case .endAdminElevation:
            guard let callerUser else {
                return .failure("endAdminElevation requires a validated caller")
            }
            return .success(await daemon.endAdminElevation(user: callerUser))
        case .installSoftware:
            // The kernel-stamped uid is required (never message-supplied): the
            // installer refuses uid 0 and attributes the install to it.
            guard let callerUID else {
                return .failure("installSoftware requires a validated caller uid")
            }
            guard let payload,
                  let request = try? SerberusXPCCoding.decode(InstallRequest.self, from: payload) else {
                return .failure("installSoftware requires an InstallRequest payload")
            }
            return encode(await daemon.installSoftware(request: request, callerUID: callerUID, callerUser: callerUser))
        case .uninstallSoftware:
            guard let callerUID else {
                return .failure("uninstallSoftware requires a validated caller uid")
            }
            guard let payload,
                  let request = try? SerberusXPCCoding.decode(UninstallRequest.self, from: payload) else {
                return .failure("uninstallSoftware requires an UninstallRequest payload")
            }
            return encode(await daemon.uninstallSoftware(request: request, callerUID: callerUID, callerUser: callerUser))
        }
    }

    private func encode(_ value: some Encodable) -> XPCReply {
        do {
            return .payload(try SerberusXPCCoding.encode(value))
        } catch {
            return .failure("reply encoding failed: \(error.localizedDescription)")
        }
    }
}
