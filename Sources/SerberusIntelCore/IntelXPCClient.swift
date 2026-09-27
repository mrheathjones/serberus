import Foundation
import os
import PrivMgrCore

/// Asks the daemon for the diagnostics this process cannot read itself.
///
/// Intel runs as an unprivileged console user and cannot open
/// `/var/db/diagnostics` (root:admin 0750), so the `pam_serberus` and Sentinel
/// lines — and the root-only grant database — are unreachable to it. The daemon
/// is already root and already validates its XPC peers by code requirement, so
/// it collects on the caller's behalf and hands back a directory chowned to
/// them.
///
/// This is a best-effort enhancement, never a dependency: if the daemon is
/// absent, down, or refuses, Intel still produces a bundle from the
/// world-readable JSONL. A diagnostics tool that fails when the thing it is
/// diagnosing is broken would be useless exactly when it is needed.
public actor IntelXPCClient {
    public enum ClientError: Error, LocalizedError, Equatable {
        case unavailable(String)
        case refused(String)

        public var errorDescription: String? {
            switch self {
            case let .unavailable(reason):
                return "The Serberus daemon did not respond: \(reason)"
            case let .refused(reason):
                return "The Serberus daemon refused the request: \(reason)"
            }
        }
    }

    private let machService: String
    /// Bound on the whole round trip. The daemon caps `log show` itself; this
    /// is the client's own guard so a wedged daemon cannot hang the UI.
    private let timeout: TimeInterval

    public init(machService: String = BundleConfig.machService, timeout: TimeInterval = 180) {
        self.machService = machService
        self.timeout = timeout
    }

    public func collect(request: IntelRequest) async throws -> IntelHandoff {
        let payload = try SerberusXPCCoding.encode(request)
        return try await call(
            method: .collectPrivilegedDiagnostics, payload: payload, decoding: IntelHandoff.self
        )
    }

    /// One live-Authorizations poll — recent authd NDJSON.
    ///
    /// A short deadline (not the 180s collect timeout): this runs on a ~2s loop,
    /// so a wedged daemon must surface fast rather than pile up polls.
    public func pollAuthorizations(request: AuthorizationPollRequest) async throws -> AuthorizationPollResult {
        let payload = try SerberusXPCCoding.encode(request)
        return try await call(
            method: .pollAuthorizations, payload: payload, decoding: AuthorizationPollResult.self, timeout: 10
        )
    }

    /// One sudo-attempts poll — recent `sudo` unified-log NDJSON, for a
    /// Capture session. Same short deadline as the authorization poll.
    public func pollSudoAttempts(request: SudoPollRequest) async throws -> SudoPollResult {
        let payload = try SerberusXPCCoding.encode(request)
        return try await call(
            method: .pollSudoAttempts, payload: payload, decoding: SudoPollResult.self, timeout: 10
        )
    }

    private func call<Reply: Decodable & Sendable>(
        method: IntelXPCMethod,
        payload: Data,
        decoding: Reply.Type,
        timeout: TimeInterval? = nil
    ) async throws -> Reply {
        let timeout = timeout ?? self.timeout
        let requirement = Self.daemonPeerRequirement
        return try await withCheckedThrowingContinuation { continuation in
            let queue = DispatchQueue(label: "com.herojoneslabs.serberus.intel.xpc")
            // PRIVILEGED: resolve the name in the system (root) bootstrap, where
            // only a root-installed LaunchDaemon can advertise it — never this
            // user's session, where any LaunchAgent could squat on it.
            let connection = xpc_connection_create_mach_service(
                machService, queue, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
            xpc_connection_set_event_handler(connection) { _ in }
            // Pin the peer to the daemon's signature; a non-daemon peer's reply
            // arrives only as XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT (-> the
            // `.unavailable` path below). Must be set before resume.
            let pinned = xpc_connection_set_peer_code_signing_requirement(connection, requirement) == 0
            // Resume even when pinning failed: libxpc traps on releasing a
            // never-resumed connection, and resuming sends nothing by itself.
            xpc_connection_resume(connection)

            // Resumes the continuation exactly once — the reply handler and the
            // timeout race, and resuming twice traps.
            let gate = XPCReplyGate(connection: connection, continuation: continuation)
            guard pinned else {
                gate.finish(.failure(ClientError.unavailable("daemon code-signing requirement rejected")))
                return
            }

            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(message, XPCMessageKey.interface, XPCInterface.intel.rawValue)
            xpc_dictionary_set_string(message, XPCMessageKey.method, method.rawValue)
            payload.withUnsafeBytes { buffer in
                xpc_dictionary_set_data(message, XPCMessageKey.payload, buffer.baseAddress, buffer.count)
            }

            queue.asyncAfter(deadline: .now() + timeout) {
                gate.finish(.failure(ClientError.unavailable("timed out after \(Int(timeout))s")))
            }

            xpc_connection_send_message_with_reply(connection, message, queue) { reply in
                if xpc_get_type(reply) == XPC_TYPE_ERROR {
                    // The common case on an endpoint where serberusd is not
                    // installed or not running.
                    gate.finish(.failure(ClientError.unavailable("connection error")))
                    return
                }
                if let error = xpc_dictionary_get_string(reply, XPCMessageKey.error) {
                    gate.finish(.failure(ClientError.refused(String(cString: error))))
                    return
                }
                var length = 0
                guard let bytes = xpc_dictionary_get_data(reply, XPCMessageKey.reply, &length) else {
                    gate.finish(.failure(ClientError.unavailable("reply carried no payload")))
                    return
                }
                let data = Data(bytes: bytes, count: length)
                do {
                    gate.finish(.success(try SerberusXPCCoding.decode(Reply.self, from: data)))
                } catch {
                    gate.finish(.failure(ClientError.unavailable("undecodable reply: \(error.localizedDescription)")))
                }
            }
        }
    }
}

extension IntelXPCClient {
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
}

/// Resumes one checked continuation exactly once, then cancels the connection.
///
/// A class (not a captured local function) so the `@Sendable` reply and timeout
/// closures share it without capturing non-Sendable state: the continuation
/// lives behind the lock and is taken out on first use, so a later call is a
/// no-op. `@unchecked` only for `connection` — libxpc objects are thread-safe
/// and `xpc_connection_cancel` may be called from any thread.
private final class XPCReplyGate<Reply: Sendable>: @unchecked Sendable {
    private let connection: xpc_connection_t
    private let continuation: OSAllocatedUnfairLock<CheckedContinuation<Reply, Error>?>

    init(connection: xpc_connection_t, continuation: CheckedContinuation<Reply, Error>) {
        self.connection = connection
        self.continuation = OSAllocatedUnfairLock(initialState: continuation)
    }

    func finish(_ result: Result<Reply, Error>) {
        let pending = continuation.withLock { stored -> CheckedContinuation<Reply, Error>? in
            defer { stored = nil }
            return stored
        }
        guard let pending else { return }
        xpc_connection_cancel(connection)
        pending.resume(with: result)
    }
}
