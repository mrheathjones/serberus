import Foundation
import Observation
import PrivMgrCore

/// Drives the menubar "Request Admin Access" affordance: fetches availability,
/// submits a justified request over XPC, and reflects the resulting window.
///
/// The active window is derived from the daemon's active grants (the menubar
/// already polls those), so this model only owns the request/end interaction
/// and the transient status message.
@MainActor
@Observable
public final class JITAdminViewModel {
    public enum Phase: Equatable {
        case unknown
        case unavailable
        case idle
        case requesting
        case active(expiresAt: Date)
        case message(String)
    }

    public private(set) var info: JITAdminInfo = .unavailable
    public private(set) var phase: Phase = .unknown
    /// Jamf Connect provider only: whether the configured binary is installed
    /// and signed by Jamf. Re-checked on every refresh and before every launch.
    public private(set) var jamfConnectAvailability: JamfConnectAvailability = .ready
    public var justification: String = ""

    /// Injected calls, so the view model is testable without a live daemon.
    /// `request`/`end` are the daemon XPC path (Serberus-native mode);
    /// `runJamfConnect` launches Jamf Connect in the user session (JC mode).
    public struct Actions: Sendable {
        public var loadInfo: @Sendable () async -> JITAdminInfo?
        public var request: @Sendable (String) async -> JITAdminResult?
        public var end: @Sendable () async -> Bool
        public var runJamfConnect: @Sendable (JamfConnectCommand) async -> Bool
        /// Checks the Jamf Connect binary (``JamfConnectVerifier``).
        public var checkJamfConnect: @Sendable (JamfConnectCommand) async -> JamfConnectAvailability

        public init(
            loadInfo: @escaping @Sendable () async -> JITAdminInfo?,
            request: @escaping @Sendable (String) async -> JITAdminResult?,
            end: @escaping @Sendable () async -> Bool,
            runJamfConnect: @escaping @Sendable (JamfConnectCommand) async -> Bool,
            checkJamfConnect: @escaping @Sendable (JamfConnectCommand) async -> JamfConnectAvailability = {
                JamfConnectVerifier().availability(of: $0)
            }
        ) {
            self.loadInfo = loadInfo
            self.request = request
            self.end = end
            self.runJamfConnect = runJamfConnect
            self.checkJamfConnect = checkJamfConnect
        }
    }

    private let actions: Actions

    public init(actions: Actions) {
        self.actions = actions
    }

    /// Whether the justification field should be shown and enforced.
    public var needsJustification: Bool { info.requireJustification }

    /// Whether the current justification satisfies the policy minimum.
    public var justificationSatisfied: Bool {
        guard info.requireJustification else { return true }
        return justification.trimmingCharacters(in: .whitespacesAndNewlines).count >= info.justificationMinLength
    }

    /// Why the Jamf Connect item is disabled ("Jamf Connect isn't installed."),
    /// or nil when it can be used or the provider is not Jamf Connect.
    public var unavailableReason: String? {
        guard info.provider == .jamfConnect else { return nil }
        return jamfConnectAvailability.unavailableReason
    }

    public var canSubmit: Bool {
        guard info.available else { return false }
        if case .requesting = phase { return false }
        if unavailableReason != nil { return false }
        return justificationSatisfied
    }

    /// Refreshes availability and reconciles the active-window phase against the
    /// caller's current grants (nil = no active JIT grant).
    public func refresh(activeExpiry: Date?) async {
        if let loaded = await actions.loadInfo() {
            info = loaded
        }
        guard info.available else { phase = .unavailable; return }
        if info.provider == .jamfConnect, let command = info.jamfConnectCommand {
            jamfConnectAvailability = await actions.checkJamfConnect(command)
        } else {
            jamfConnectAvailability = .ready
        }
        if let activeExpiry, activeExpiry > Date() {
            phase = .active(expiresAt: activeExpiry)
        } else if case .message = phase {
            // Keep a transient message visible until the next explicit action.
        } else if case .requesting = phase {
            // A request is in flight; don't stomp it.
        } else {
            phase = .idle
        }
    }

    /// Submits the elevation request.
    public func submit() async {
        // Jamf Connect mode: launch JC in the user session and let it take over.
        // Serberus captures nothing and tracks nothing.
        if info.provider == .jamfConnect, let command = info.jamfConnectCommand {
            // Checked again right before the launch: the binary may have been
            // removed or replaced since the menu was drawn.
            jamfConnectAvailability = await actions.checkJamfConnect(command)
            guard jamfConnectAvailability == .ready else { return }
            phase = .requesting
            let launched = await actions.runJamfConnect(command)
            phase = .message(launched
                ? "Admin elevation started in Jamf Connect."
                : "Couldn't start Jamf Connect elevation.")
            return
        }

        guard canSubmit else { return }
        phase = .requesting
        guard let result = await actions.request(justification) else {
            phase = .message("Couldn't reach the Serberus daemon.")
            return
        }
        switch result.outcome {
        case .granted, .alreadyActive:
            justification = ""
            if let expiresAt = result.expiresAt {
                phase = .active(expiresAt: expiresAt)
            } else {
                phase = .message(result.message)
            }
        case .delegated:
            justification = ""
            phase = .message(result.message)
        case .alreadyAdmin, .denied:
            phase = .message(result.message)
        }
    }

    /// Ends the active window early.
    public func end() async {
        guard await actions.end() else { return }
        phase = .idle
    }
}
