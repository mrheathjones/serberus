import Darwin
import Foundation
import PrivMgrCore
import SerberusXPCShim

/// The single low-level XPC Mach-service listener.
///
/// Every peer — PAM (raw dictionaries), Sentinel, Intel — connects here. Each
/// message is gated by **audit-token** validation (never PID, which is
/// TOCTOU-vulnerable): the peer's signing identifier selects the expected
/// caller, the full code-identity check runs against that caller's designated
/// requirement, and only then is the message dispatched. The validated
/// interface is passed to the router, which additionally refuses any method
/// that does not belong to the proven interface.
///
/// `@unchecked Sendable`: the class holds the immutable router/validator plus
/// the listener connection, which is only assigned during ``start()``. The
/// xpc objects it bridges are not Swift-Sendable, so peer connections and
/// messages are carried across the async boundary in explicit unchecked boxes.
public final class XPCListenerService: @unchecked Sendable {
    private let machServiceName: String
    private let router: XPCMessageRouter
    private let validator: XPCConnectionValidator
    private let sentinelPushService: SentinelPushService?
    private let queue: DispatchQueue
    private var listener: xpc_connection_t?

    public init(
        machServiceName: String,
        router: XPCMessageRouter,
        validator: XPCConnectionValidator = XPCConnectionValidator(),
        sentinelPushService: SentinelPushService? = nil
    ) {
        self.machServiceName = machServiceName
        self.router = router
        self.validator = validator
        self.sentinelPushService = sentinelPushService
        self.queue = DispatchQueue(label: "\(machServiceName).xpc", qos: .userInitiated)
    }

    /// True once the listener is created and resumed. Used by the health
    /// monitor's XPC-listener probe.
    public func isActive() -> Bool { listener != nil }

    /// Creates and resumes the Mach-service listener.
    public func start() {
        let listener = xpc_connection_create_mach_service(
            machServiceName,
            queue,
            UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
        )
        xpc_connection_set_event_handler(listener) { [weak self] event in
            self?.handleNewPeer(event)
        }
        xpc_connection_resume(listener)
        self.listener = listener
        DaemonLog.integrity.notice("XPC listener active on \(self.machServiceName, privacy: .public)")
    }

    /// Cancels the listener (graceful shutdown).
    public func stop() {
        if let listener { xpc_connection_cancel(listener) }
        listener = nil
    }

    // MARK: Peer + message handling

    private func handleNewPeer(_ event: xpc_object_t) {
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
        // The peer event already is a connection object — `xpc_connection_t`
        // and `xpc_object_t` are the same underlying `OS_xpc_object`.
        let peer: xpc_connection_t = event
        let box = ConnectionBox(peer)
        xpc_connection_set_event_handler(peer) { [weak self] message in
            self?.handleMessage(message, from: box)
        }
        xpc_connection_resume(peer)
    }

    private func handleMessage(_ message: xpc_object_t, from box: ConnectionBox) {
        let type = xpc_get_type(message)
        // Connection-level errors (invalid/interrupted) carry no request.
        guard type == XPC_TYPE_DICTIONARY else { return }

        let peer = box.connection

        // --- Audit-token validation (the security gate) ---
        var token = audit_token_t()
        guard serberus_xpc_connection_copy_audit_token(peer, &token) else {
            reject(message, peer: peer, reason: "audit token unavailable")
            return
        }
        let validatedInterface: XPCInterface
        if let bundleID = validator.bundleID(forAuditToken: token),
           let expected = ExpectedCaller.forBundleID(bundleID) {
            // Serberus-signed caller (Sentinel, Intel): full
            // Team-ID + Hardened-Runtime + entitlement + designated-requirement
            // check. `forBundleID` never yields `.pam` — the PAM interface is
            // reachable ONLY through the sudo-host branch below.
            do {
                let identity = try validator.identity(forAuditToken: token, expected: expected)
                try validator.validate(identity: identity, against: expected)
            } catch {
                reject(message, peer: peer, reason: error.localizedDescription)
                return
            }
            guard let interface = expected.interface else {
                reject(message, peer: peer, reason: "no interface for caller")
                return
            }
            validatedInterface = interface
        } else if Self.isPAMContract(message) {
            // Real curated sudo: `pam_serberus.so` runs INSIDE `/usr/bin/sudo`,
            // so the connection's audit token is sudo's — its identifier is
            // never a Serberus bundle ID (that path yields "unknown caller").
            // Authenticate the sudo HOST instead: euid 0 + `anchor apple` +
            // sudo identifier/path pin. Only the PAM flat-dict contract opens
            // this path, and `validatedInterface == .pam` guards below refuse
            // any sentinel/intel method arriving on the connection.
            do {
                let host = try validator.pamHostIdentity(
                    forAuditToken: token, euid: serberus_audit_token_euid(token)
                )
                try validator.validatePAMHost(host)
            } catch {
                reject(message, peer: peer, reason: error.localizedDescription)
                return
            }
            validatedInterface = .pam
        } else {
            reject(message, peer: peer, reason: "unknown caller")
            return
        }

        let callerUser = Self.username(forUID: serberus_audit_token_euid(token))
        let messageBox = MessageBox(message: message, peer: peer)

        // PAM prompt poll: a flat dict (type=poll_prompt + requestID) asking
        // for a pending prompt's verdict. Answered directly from the push
        // service — it owns the in-flight prompt state.
        if let requestID = Self.decodePollPrompt(message) {
            guard validatedInterface == .pam else {
                reject(message, peer: peer, reason: "non-PAM caller polled a prompt")
                return
            }
            let push = self.sentinelPushService
            Task {
                let verdict = await push?.pollVerdict(for: requestID)
                Self.send(Self.pollReply(for: verdict), box: messageBox)
            }
            return
        }

        // PAM uses the flat dictionary contract; everyone else interface+method.
        if let pamRequest = Self.decodePAMRequest(message) {
            guard validatedInterface == .pam else {
                reject(message, peer: peer, reason: "non-PAM caller sent a PAM request")
                return
            }
            let router = self.router
            Task {
                let reply = await router.routePAM(pamRequest)
                Self.send(reply, box: messageBox)
            }
            return
        }

        let interface = Self.string(message, XPCMessageKey.interface) ?? ""
        let method = Self.string(message, XPCMessageKey.method) ?? ""
        let payload = Self.data(message, XPCMessageKey.payload)

        // Sentinel registration retains the peer connection so the daemon can push
        // `presentPrompt`. The router has no access to the peer, so it is handled
        // here, after code-identity validation.
        if validatedInterface == .sentinel, method == SentinelXPCMethod.registerSentinel.rawValue {
            let push = self.sentinelPushService
            let sentinelPeer = SentinelPeer(peer)
            // The Sentinel's user, from the kernel-stamped audit token: prompts
            // are delivered only to the requesting user's own Sentinel.
            let sentinelUID = serberus_audit_token_euid(token)
            Task {
                await push?.registerSentinel(sentinelPeer, uid: sentinelUID)
                Self.send(.success(true), box: messageBox)
            }
            return
        }

        let router = self.router
        // Kernel-stamped, taken from the same audit token the validation above
        // used — never from the message body.
        let callerUID = serberus_audit_token_euid(token)
        Task {
            let reply = await router.routeTyped(
                validatedInterface: validatedInterface,
                interface: interface,
                method: method,
                payload: payload,
                callerUser: callerUser,
                callerUID: callerUID
            )
            Self.send(reply, box: messageBox)
        }
    }

    // MARK: Reply writing

    private func reject(_ message: xpc_object_t, peer: xpc_connection_t, reason: String) {
        DaemonLog.integrity.error("Rejected XPC peer: \(reason, privacy: .public)")
        Self.send(.failure("rejected: \(reason)"), box: MessageBox(message: message, peer: peer))
        xpc_connection_cancel(peer)
    }

    private static func send(_ reply: XPCReply, box: MessageBox) {
        guard let response = xpc_dictionary_create_reply(box.message) else { return }
        encode(reply, into: response)
        xpc_connection_send_message(box.connection, response)
    }

    /// Serializes a transport-neutral ``XPCReply`` into an xpc reply
    /// dictionary. Split out of ``send(_:box:)`` (internal, not private) so
    /// wire-encoding tests can assert the exact dictionary PAM receives
    /// without a live connection. Encoding behavior is part of the frozen
    /// wire contract (`serberus_xpc_keys.h`).
    static func encode(_ reply: XPCReply, into response: xpc_object_t) {
        switch reply {
        case let .payload(data):
            data.withUnsafeBytes { buffer in
                xpc_dictionary_set_data(response, XPCMessageKey.reply, buffer.baseAddress, buffer.count)
            }
        case let .success(ok):
            xpc_dictionary_set_bool(response, XPCMessageKey.success, ok)
        case let .failure(message):
            xpc_dictionary_set_string(response, XPCMessageKey.error, message)
        case let .pam(pam):
            if pam.native {
                // A JIT admin inside their window: PAM steps aside (PAM_IGNORE)
                // without marking the request gated. Nothing else is sent.
                xpc_dictionary_set_string(response, PAMXPCKey.decision, PAMXPCKey.decisionNative)
            } else if pam.decision == .prompt {
                // A `.prompt` rule fired: tell PAM to poll with the ticket.
                xpc_dictionary_set_string(response, PAMXPCKey.decision, PAMXPCKey.decisionPromptPending)
                if let requestID = pam.promptRequestID {
                    xpc_dictionary_set_string(response, PAMXPCKey.requestID, requestID.uuidString)
                }
            } else {
                xpc_dictionary_set_string(response, PAMXPCKey.decision,
                                          pam.isAllow ? PAMXPCKey.decisionAllow : PAMXPCKey.decisionDeny)
                xpc_dictionary_set_int64(response, PAMXPCKey.cacheSeconds, Int64(pam.cacheSeconds))
                if let grantID = pam.grantID {
                    xpc_dictionary_set_string(response, PAMXPCKey.grantID, grantID.uuidString)
                }
                if let ruleID = pam.ruleID {
                    xpc_dictionary_set_string(response, PAMXPCKey.ruleID, ruleID)
                }
            }
        case .pamPromptUnresolved:
            xpc_dictionary_set_string(response, PAMXPCKey.decision, PAMXPCKey.decisionPending)
        case let .pamPromptDenied(timedOut):
            // A deny in every field PAM already reads, plus the verdict
            // detail (older modules ignore the extra key).
            xpc_dictionary_set_string(response, PAMXPCKey.decision, PAMXPCKey.decisionDeny)
            xpc_dictionary_set_int64(response, PAMXPCKey.cacheSeconds, 0)
            xpc_dictionary_set_string(
                response, PAMXPCKey.verdict,
                timedOut ? PAMXPCKey.verdictTimedOut : PAMXPCKey.verdictDenied
            )
        }
    }

    // MARK: Decoding helpers

    /// Whether `message` is a PAM flat-dict contract message (`type` ∈ {sudo,
    /// authuri, poll_prompt}) — the exact set ``decodePAMRequest`` and
    /// ``decodePollPrompt`` accept. Gates the sudo-host acceptance path so it
    /// opens only for genuine PAM messages, never for a typed sentinel/intel call.
    static func isPAMContract(_ message: xpc_object_t) -> Bool {
        switch string(message, PAMXPCKey.type) {
        case PAMXPCKey.typeSudo, PAMXPCKey.typeAuthURI, PAMXPCKey.typePollPrompt:
            return true
        default:
            return false
        }
    }

    static func decodePAMRequest(_ message: xpc_object_t) -> PAMRequest? {
        guard let type = string(message, PAMXPCKey.type),
              let user = string(message, PAMXPCKey.user) else {
            return nil
        }
        switch type {
        case PAMXPCKey.typeSudo:
            guard let command = string(message, PAMXPCKey.command) else { return nil }
            return PAMRequest(user: user, kind: .sudo(
                command: command,
                argv: stringArray(message, PAMXPCKey.argv),
                tty: string(message, PAMXPCKey.tty)
            ))
        case PAMXPCKey.typeAuthURI:
            guard let uri = string(message, PAMXPCKey.authURI) else { return nil }
            return PAMRequest(user: user, kind: .authURI(uri))
        default:
            return nil
        }
    }

    /// Decodes a `poll_prompt` flat dictionary into its prompt ticket, or `nil`
    /// when the message is not a poll (forcing the caller down the normal paths).
    static func decodePollPrompt(_ message: xpc_object_t) -> UUID? {
        guard string(message, PAMXPCKey.type) == PAMXPCKey.typePollPrompt,
              let idString = string(message, PAMXPCKey.requestID),
              let id = UUID(uuidString: idString) else {
            return nil
        }
        return id
    }

    /// Maps a polled verdict to the PAM wire reply: allow/deny once resolved,
    /// `pending` (keep polling) while `nil`.
    static func pollReply(for verdict: PromptResponse.Verdict?) -> XPCReply {
        switch verdict {
        case .approved:
            return .pam(PAMResponse(decision: .allow, cacheSeconds: 0, grantID: nil, ruleID: nil))
        case .denied:
            return .pamPromptDenied(timedOut: false)
        case .timedOut:
            return .pamPromptDenied(timedOut: true)
        case nil:
            return .pamPromptUnresolved
        }
    }

    static func string(_ message: xpc_object_t, _ key: String) -> String? {
        guard let pointer = xpc_dictionary_get_string(message, key) else { return nil }
        return String(cString: pointer)
    }

    static func stringArray(_ message: xpc_object_t, _ key: String) -> [String] {
        guard let array = xpc_dictionary_get_array(message, key) else { return [] }
        let count = xpc_array_get_count(array)
        var values: [String] = []
        values.reserveCapacity(count)
        for index in 0..<count {
            if let pointer = xpc_array_get_string(array, index) {
                values.append(String(cString: pointer))
            }
        }
        return values
    }

    static func data(_ message: xpc_object_t, _ key: String) -> Data? {
        var length = 0
        guard let pointer = xpc_dictionary_get_data(message, key, &length), length > 0 else {
            return nil
        }
        return Data(bytes: pointer, count: length)
    }

    static func username(forUID uid: uid_t) -> String? {
        guard let entry = getpwuid(uid) else { return nil }
        return String(cString: entry.pointee.pw_name)
    }
}

/// Carries a non-Sendable xpc peer connection across the async boundary.
private final class ConnectionBox: @unchecked Sendable {
    let connection: xpc_connection_t
    init(_ connection: xpc_connection_t) { self.connection = connection }
}

/// Carries a non-Sendable request message + its peer into the reply Task.
private final class MessageBox: @unchecked Sendable {
    let message: xpc_object_t
    let connection: xpc_connection_t
    init(message: xpc_object_t, peer: xpc_connection_t) {
        self.message = message
        self.connection = peer
    }
}
