import Darwin
import Foundation
import OSLog
import PrivMgrCore
import SerberusXPCShim

/// The agent's inbound Mach-service listener for the Finder Sync extension.
///
/// The sandboxed `SerberusFinderExtension.appex` provides the TOP-LEVEL
/// "Install/Uninstall with Serberus" right-click items (with the Sentinel
/// icon). It is deliberately **not** a daemon principal, so it cannot call the
/// daemon; instead it forwards the selected path to THIS listener. The listener
/// authenticates the peer by **kernel-stamped audit token** (never PID, which is
/// TOCTOU-vulnerable) as EXACTLY the Finder extension — the agent's own Team
/// ID + bundle `…intel.finderext` + Hardened Runtime + non-ad-hoc +
/// designated requirement — then hands the request to the very same
/// install/uninstall path the `NSServices` entry points use. The agent stays the
/// sole `.sentinel` caller; the daemon still gates on the managed appmanagement
/// profile, canonicalizes + stages the path, verifies notarized Developer-ID
/// signing, and shows the audited confirmation before doing anything as root.
///
/// `@unchecked Sendable`: it holds an immutable validator + handler and the
/// listener connection (assigned only in ``start()``); the non-Sendable xpc peer
/// objects are only ever touched on the listener's serial queue.
final class FinderBridgeListener: @unchecked Sendable {
    /// The two verbs the extension may request. A raw-value enum so an unknown
    /// string is rejected rather than dispatched.
    enum Action: String, Sendable { case install, uninstall }

    private let validator = XPCConnectionValidator()
    private let queue = DispatchQueue(label: BundleConfig.finderBridgeMachService + ".xpc", qos: .userInitiated)
    private var listener: xpc_connection_t?
    /// Invoked on the main actor for each authenticated request (wired to the
    /// same `InstallService.install(path:)` / `uninstall(path:)` the Service uses).
    private let handler: @MainActor (Action, String) -> Void

    private static let log = Logger(subsystem: BundleConfig.logSubsystem, category: "finder-bridge")

    init(handler: @escaping @MainActor (Action, String) -> Void) { self.handler = handler }

    /// Creates and resumes the Mach-service listener. launchd advertises the name
    /// via the agent's LaunchAgent `MachServices`, so this checks in for it.
    func start() {
        let l = xpc_connection_create_mach_service(
            BundleConfig.finderBridgeMachService, queue, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
        xpc_connection_set_event_handler(l) { [weak self] event in self?.onPeer(event) }
        xpc_connection_resume(l)
        listener = l
        Self.log.notice("Finder-bridge listener active on \(BundleConfig.finderBridgeMachService, privacy: .public)")
    }

    private func onPeer(_ event: xpc_object_t) {
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
        // The peer event already IS the connection object.
        let peer: xpc_connection_t = event
        xpc_connection_set_event_handler(peer) { [weak self] message in self?.onMessage(message, peer) }
        xpc_connection_resume(peer)
    }

    private func onMessage(_ message: xpc_object_t, _ peer: xpc_connection_t) {
        // Connection-level errors (invalid/interrupted) carry no request.
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { return }

        // --- The security gate: authenticate the peer as EXACTLY the extension. ---
        var token = audit_token_t()
        guard serberus_xpc_connection_copy_audit_token(peer, &token) else {
            return reject(peer, "audit token unavailable")
        }
        // Pin the signing identifier BEFORE the full check (mirrors the daemon):
        // never use ExpectedCaller.forBundleID here — that is the daemon's table,
        // and the extension is deliberately absent from it.
        guard validator.bundleID(forAuditToken: token) == BundleConfig.finderExtensionBundleID else {
            return reject(peer, "not the Finder extension")
        }
        do {
            let identity = try validator.identity(forAuditToken: token, expected: .finderExtension)
            try validator.validate(identity: identity, against: .finderExtension)
        } catch {
            return reject(peer, error.localizedDescription)
        }

        // --- Decode { action, path }. ---
        guard let actionRaw = Self.string(message, FinderBridgeWire.actionKey),
              let action = Action(rawValue: actionRaw),
              let path = Self.string(message, FinderBridgeWire.pathKey), !path.isEmpty else {
            return reject(peer, "malformed request")
        }

        Self.log.notice("bridge \(actionRaw, privacy: .public): \((path as NSString).lastPathComponent, privacy: .public)")

        // Hand off to the SAME main-actor install/uninstall path the NSService
        // uses. Forwarding the raw path is safe defense-in-depth: the daemon
        // re-canonicalizes it, pins it (/Applications for uninstall), verifies
        // notarization, and shows the audited prompt before acting as root.
        let handler = self.handler
        Task { @MainActor in handler(action, path) }

        // Ack "accepted" so the extension knows the agent received it; the real
        // outcome reaches the user via the daemon's prompt + the agent's toast.
        if let reply = xpc_dictionary_create_reply(message) {
            xpc_dictionary_set_bool(reply, FinderBridgeWire.acceptedKey, true)
            xpc_connection_send_message(peer, reply)
        }
    }

    private func reject(_ peer: xpc_connection_t, _ reason: String) {
        Self.log.error("rejected Finder-bridge peer: \(reason, privacy: .public)")
        xpc_connection_cancel(peer)
    }

    private static func string(_ message: xpc_object_t, _ key: String) -> String? {
        guard let pointer = xpc_dictionary_get_string(message, key) else { return nil }
        return String(cString: pointer)
    }
}
