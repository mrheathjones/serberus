import Foundation
import PrivMgrCore
import SerberusXPCShim

/// Errors surfaced by ``SentinelXPCClient`` queries.
public enum SentinelXPCError: Error, Sendable {
    case notConnected
    case connectionError
    case daemonError(String)
    case malformedReply
}

/// The Sentinel's low-level XPC client to the daemon.
///
/// The daemon serves a single libxpc Mach service (NSXPC is unavailable — the C
/// PAM module shares it), so the Sentinel speaks the same raw dictionary contract.
/// On ``connect()`` it announces itself (`registerSentinel`) so the daemon retains
/// the peer for daemon-initiated `presentPrompt` pushes, then it can pull
/// ``daemonState()`` and ``activeGrants()`` for the menubar.
///
/// Incoming `presentPrompt` pushes are routed to ``setPromptHandler(_:)``; the
/// handler's ``PromptResponse`` is sent back as the XPC reply on the same
/// message, completing the round-trip the daemon awaits.
public actor SentinelXPCClient {
    /// Shows a prompt to the user and returns their verdict. Runs on the main
    /// actor (it drives UI).
    public typealias PromptHandler = @Sendable @MainActor (PromptContext) async -> PromptResponse

    private let machServiceName: String
    private let queue: DispatchQueue
    private var connection: xpc_connection_t?
    private var promptHandler: PromptHandler?

    public init(machServiceName: String = BundleConfig.machService) {
        self.machServiceName = machServiceName
        self.queue = DispatchQueue(label: "com.herojoneslabs.serberus.sentinel.xpc", qos: .userInitiated)
    }

    /// Installs the handler invoked when the daemon pushes a `presentPrompt`.
    public func setPromptHandler(_ handler: PromptHandler?) {
        self.promptHandler = handler
    }

    /// Creates and resumes the connection, then announces the Sentinel so the
    /// daemon retains this peer for prompt delivery. Idempotent.
    public func connect() {
        guard connection == nil else { return }
        // PRIVILEGED: resolve the name in the system (root) bootstrap, where only
        // a root-installed LaunchDaemon can advertise it — never this user's
        // session, where any LaunchAgent could squat on it and receive our
        // requests or push fake prompts.
        let conn = xpc_connection_create_mach_service(
            machServiceName, queue, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        // Pin the peer to the daemon's signature (identifier + Apple-issued
        // certificate + this app's own Team ID). libxpc checks it on every
        // message, so a non-daemon peer's replies and pushes arrive only as
        // XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT. Must be set before resume.
        guard xpc_connection_set_peer_code_signing_requirement(conn, Self.daemonPeerRequirement) == 0 else {
            // libxpc traps on releasing a never-resumed connection; resuming
            // sends nothing (it connects on first send), then cancel.
            xpc_connection_set_event_handler(conn) { _ in }
            xpc_connection_resume(conn)
            xpc_connection_cancel(conn)
            return   // stays disconnected: every request throws .notConnected
        }
        xpc_connection_set_event_handler(conn) { [weak self] event in
            let box = XPCObjectBox(event)
            guard let self else { return }
            Task { await self.handleIncoming(box) }
        }
        xpc_connection_resume(conn)
        self.connection = conn
        sendRegister(on: conn)
    }

    /// The code-signing requirement the daemon peer must satisfy: the daemon's
    /// identifier, an Apple-issued certificate, and this app's own Team ID.
    /// An unsigned / ad-hoc build has no team to pin, so it keeps the identifier
    /// + Apple anchor (same fallback as `pam_serberus`).
    static var daemonPeerRequirement: String {
        let team = BundleConfig.teamID
        guard !team.isEmpty else {
            return "identifier \"\(BundleConfig.daemonBundleID)\" and anchor apple generic"
        }
        return ExpectedCaller(bundleID: BundleConfig.daemonBundleID, teamID: team,
                              requiredEntitlement: nil).designatedRequirement
    }

    /// Cancels the connection.
    public func disconnect() {
        if let connection { xpc_connection_cancel(connection) }
        connection = nil
    }

    // MARK: Daemon queries

    public func daemonState() async throws -> DaemonState {
        let data = try await request(method: .daemonState)
        return try SerberusXPCCoding.decode(DaemonState.self, from: data)
    }

    public func activeGrants() async throws -> [Grant] {
        let data = try await request(method: .activeGrants)
        return try SerberusXPCCoding.decode([Grant].self, from: data)
    }

    /// The loaded rules as display summaries for the popover's rule list.
    public func userRules() async throws -> SentinelRulesSnapshot {
        let data = try await request(method: .userRules)
        return try SerberusXPCCoding.decode(SentinelRulesSnapshot.self, from: data)
    }

    // MARK: JIT local-admin

    /// Reads whether JIT local-admin elevation is available to this user.
    public func jitAdminInfo() async throws -> JITAdminInfo {
        let data = try await request(method: .jitAdminInfo)
        return try SerberusXPCCoding.decode(JITAdminInfo.self, from: data)
    }

    /// Requests JIT local-admin elevation with a justification.
    public func requestAdminElevation(justification: String) async throws -> JITAdminResult {
        let payload = try SerberusXPCCoding.encode(justification)
        let data = try await request(method: .requestAdminElevation, payload: payload)
        return try SerberusXPCCoding.decode(JITAdminResult.self, from: data)
    }

    /// Ends the caller's active JIT local-admin window early.
    public func endAdminElevation() async throws -> Bool {
        try await requestSuccess(method: .endAdminElevation)
    }

    /// Requests an "Install with Serberus" of a user-chosen `.pkg`/`.app`. The
    /// daemon gates it on the install-software rule, verifies notarized
    /// Developer-ID signing, prompts (via the same channel as sudo), and installs
    /// as root — returning the outcome for the app to display.
    public func installSoftware(_ request: InstallRequest) async throws -> InstallResult {
        let payload = try SerberusXPCCoding.encode(request)
        let data = try await self.request(method: .installSoftware, payload: payload)
        return try SerberusXPCCoding.decode(InstallResult.self, from: data)
    }

    /// Requests an "Uninstall with Serberus" — moving a `/Applications` app to the
    /// user's Trash (recoverable) as root, gated by the app-management rule.
    public func uninstallSoftware(_ request: UninstallRequest) async throws -> InstallResult {
        let payload = try SerberusXPCCoding.encode(request)
        let data = try await self.request(method: .uninstallSoftware, payload: payload)
        return try SerberusXPCCoding.decode(InstallResult.self, from: data)
    }

    // MARK: Incoming prompt push

    private func handleIncoming(_ box: XPCObjectBox) async {
        let message = box.object
        // Connection-level errors (invalid/interrupted) are not dictionaries.
        if xpc_get_type(message) == XPC_TYPE_ERROR {
            // The daemon went away (restart / crash). For a Mach-service peer the
            // connection transparently reconnects on the next send, but the *new*
            // daemon instance has no record of this Sentinel — so re-announce, or the
            // Sentinel silently stops receiving `presentPrompt` pushes until it is
            // relaunched. Invalidation (service removed) is terminal; nothing to do.
            if message === XPC_ERROR_CONNECTION_INTERRUPTED, let connection {
                sendRegister(on: connection)
            }
            return
        }
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { return }
        // Only the daemon-initiated presentPrompt arrives on this handler.
        guard Self.string(message, XPCMessageKey.method) == SentinelXPCMethod.presentPrompt.rawValue else {
            return
        }
        // Capture the connection the push arrived on *before* any suspension, so
        // a reconnect mid-prompt can't redirect this reply onto a new connection.
        let connection = self.connection

        guard let payload = Self.data(message, XPCMessageKey.payload),
              let context = try? SerberusXPCCoding.decode(PromptContext.self, from: payload) else {
            // Undecodable push (e.g. version skew): reply empty so the daemon
            // resolves immediately (its decoder fails an empty reply closed to
            // a deny) instead of waiting out its timeout watchdog.
            if let connection { Self.replyEmpty(to: message, on: connection) }
            return
        }

        let response: PromptResponse
        if let promptHandler {
            response = await promptHandler(context)
        } else {
            response = PromptResponse(requestID: context.requestID, verdict: .denied)
        }

        if let connection {
            Self.reply(response, to: message, on: connection)
        }
    }

    // MARK: XPC plumbing

    private func sendRegister(on conn: xpc_connection_t) {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, XPCMessageKey.interface, XPCInterface.sentinel.rawValue)
        xpc_dictionary_set_string(message, XPCMessageKey.method, SentinelXPCMethod.registerSentinel.rawValue)
        xpc_connection_send_message(conn, message)
    }

    private func request(method: SentinelXPCMethod, payload: Data? = nil) async throws -> Data {
        guard let connection else { throw SentinelXPCError.notConnected }
        let queue = self.queue
        return try await withCheckedThrowingContinuation { continuation in
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(message, XPCMessageKey.interface, XPCInterface.sentinel.rawValue)
            xpc_dictionary_set_string(message, XPCMessageKey.method, method.rawValue)
            if let payload {
                payload.withUnsafeBytes { buffer in
                    xpc_dictionary_set_data(message, XPCMessageKey.payload, buffer.baseAddress, buffer.count)
                }
            }
            xpc_connection_send_message_with_reply(connection, message, queue) { reply in
                guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
                    continuation.resume(throwing: SentinelXPCError.connectionError)
                    return
                }
                if let errorPointer = xpc_dictionary_get_string(reply, XPCMessageKey.error) {
                    continuation.resume(throwing: SentinelXPCError.daemonError(String(cString: errorPointer)))
                    return
                }
                var length = 0
                guard let pointer = xpc_dictionary_get_data(reply, XPCMessageKey.reply, &length), length > 0 else {
                    continuation.resume(throwing: SentinelXPCError.malformedReply)
                    return
                }
                continuation.resume(returning: Data(bytes: pointer, count: length))
            }
        }
    }

    /// A method whose reply is the boolean `success` field (not a payload).
    private func requestSuccess(method: SentinelXPCMethod, payload: Data? = nil) async throws -> Bool {
        guard let connection else { throw SentinelXPCError.notConnected }
        let queue = self.queue
        return try await withCheckedThrowingContinuation { continuation in
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(message, XPCMessageKey.interface, XPCInterface.sentinel.rawValue)
            xpc_dictionary_set_string(message, XPCMessageKey.method, method.rawValue)
            if let payload {
                payload.withUnsafeBytes { buffer in
                    xpc_dictionary_set_data(message, XPCMessageKey.payload, buffer.baseAddress, buffer.count)
                }
            }
            xpc_connection_send_message_with_reply(connection, message, queue) { reply in
                guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
                    continuation.resume(throwing: SentinelXPCError.connectionError)
                    return
                }
                if let errorPointer = xpc_dictionary_get_string(reply, XPCMessageKey.error) {
                    continuation.resume(throwing: SentinelXPCError.daemonError(String(cString: errorPointer)))
                    return
                }
                continuation.resume(returning: xpc_dictionary_get_bool(reply, XPCMessageKey.success))
            }
        }
    }

    private static func reply(_ response: PromptResponse, to message: xpc_object_t, on connection: xpc_connection_t) {
        guard let reply = xpc_dictionary_create_reply(message),
              let data = try? SerberusXPCCoding.encode(response) else {
            return
        }
        data.withUnsafeBytes { buffer in
            xpc_dictionary_set_data(reply, XPCMessageKey.reply, buffer.baseAddress, buffer.count)
        }
        xpc_connection_send_message(connection, reply)
    }

    /// Replies with no payload; the daemon's decoder maps an empty reply to a
    /// deny for the in-flight requestID, resolving it without a watchdog wait.
    private static func replyEmpty(to message: xpc_object_t, on connection: xpc_connection_t) {
        guard let reply = xpc_dictionary_create_reply(message) else { return }
        xpc_connection_send_message(connection, reply)
    }

    private static func string(_ message: xpc_object_t, _ key: String) -> String? {
        guard let pointer = xpc_dictionary_get_string(message, key) else { return nil }
        return String(cString: pointer)
    }

    private static func data(_ message: xpc_object_t, _ key: String) -> Data? {
        var length = 0
        guard let pointer = xpc_dictionary_get_data(message, key, &length), length > 0 else { return nil }
        return Data(bytes: pointer, count: length)
    }
}

/// Carries a non-Sendable xpc object from a libxpc event handler into the actor.
private final class XPCObjectBox: @unchecked Sendable {
    let object: xpc_object_t
    init(_ object: xpc_object_t) { self.object = object }
}
