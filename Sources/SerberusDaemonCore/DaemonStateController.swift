import Foundation
import PrivMgrCore

/// Owns the daemon state machine and persists it to
/// `state.plist` on every transition, emitting an integrity event each time.
///
/// state.plist is the source of truth the Sentinel menubar, the CLI `status`
/// command, and future Extension Attributes read. It is written atomically so
/// a reader never sees a half-written file.
public actor DaemonStateController {
    private let statePlist: URL
    private let integrityLogger: IntegrityLogger?
    private let daemonVersion: String
    private let now: @Sendable () -> Date

    private var state: DaemonState
    private var degradedReason: DegradedReason?
    private var enforcementMode: EnforcementMode
    /// The exec gate's status (``ExecGateStatus``), once startup decided it.
    private var execGate: ExecGateStatus?

    public init(
        statePlist: URL,
        integrityLogger: IntegrityLogger?,
        daemonVersion: String = DaemonVersion.current.daemonVersion,
        initialState: DaemonState = .pendingProfiles,
        enforcementMode: EnforcementMode = .enforce,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.statePlist = statePlist
        self.integrityLogger = integrityLogger
        self.daemonVersion = daemonVersion
        self.state = initialState
        self.degradedReason = nil
        self.enforcementMode = enforcementMode
        self.now = now
    }

    /// Current state and degraded cause.
    public func current() -> (state: DaemonState, reason: DegradedReason?) {
        (state, degradedReason)
    }

    /// The enforcement mode last applied to the state file.
    public func currentEnforcementMode() -> EnforcementMode {
        enforcementMode
    }

    /// Transitions to `newState`, writes `state.plist`, and emits an
    /// integrity event. A transition to the same state still rewrites the
    /// file (e.g. to refresh the timestamp or degraded reason).
    public func transition(
        to newState: DaemonState,
        reason: DegradedReason? = nil,
        enforcementMode: EnforcementMode? = nil
    ) async {
        let previous = state
        state = newState
        degradedReason = (newState == .degraded) ? reason : nil
        if let enforcementMode {
            self.enforcementMode = enforcementMode
        }

        writeStateFile()

        let detail: String
        if let degradedReason {
            detail = "\(previous.rawValue) → \(newState.rawValue) (\(degradedReason.rawValue))"
        } else {
            detail = "\(previous.rawValue) → \(newState.rawValue)"
        }
        DaemonLog.integrity.notice("State transition: \(detail, privacy: .public)")

        if let integrityLogger {
            let event = IntegrityEvent(
                timestamp: now(),
                kind: .stateTransition,
                detail: detail,
                daemonVersion: daemonVersion
            )
            try? await integrityLogger.log(event)
        }
    }

    /// Records whether the Endpoint Security exec gate is running, and why
    /// not, in `state.plist` (`execGate`, and `execGateDetail` when off).
    /// Separate from the state: the daemon is fully in service without it.
    public func setExecGate(_ status: ExecGateStatus) {
        execGate = status
        writeStateFile()
    }

    /// The exec gate status last recorded.
    public func currentExecGate() -> ExecGateStatus? { execGate }

    private func writeStateFile() {
        var dict: [String: Any] = [
            "state": state.rawValue,
            "enforcementMode": enforcementMode.rawValue,
            "updatedAt": ISO8601.string(from: now()),
            "daemonVersion": daemonVersion,
        ]
        if let degradedReason {
            dict["degradedReason"] = degradedReason.rawValue
        }
        if let execGate {
            dict["execGate"] = execGate.value
            if let detail = execGate.detail { dict["execGateDetail"] = detail }
        }

        try? FileManager.default.createDirectory(
            at: statePlist.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: dict, format: .xml, options: 0
        ) else {
            DaemonLog.integrity.error("Failed to serialize state.plist")
            return
        }
        do {
            try data.write(to: statePlist, options: .atomic)
        } catch {
            DaemonLog.integrity.error("Failed to write state.plist: \(error.localizedDescription, privacy: .public)")
        }
    }
}

/// Whether the Endpoint Security exec gate (``ESFMonitor``) is running. The
/// gate is a backstop: sudo through `pam_serberus`, the AuthorizationDB rights
/// and JIT admin work the same without it.
public enum ExecGateStatus: Sendable, Equatable {
    /// Subscribed and enforcing.
    case active
    /// This build has no Endpoint Security entitlement. Permanent for the
    /// build; not retried and not a degraded state.
    case notEntitled
    /// Tried and failed for another reason (Full Disk Access, …).
    case unavailable(String)
    /// Not started: the daemon was not healthy at startup.
    case notStarted(String)

    /// `state.plist`'s `execGate` value.
    public var value: String {
        switch self {
        case .active: return "active"
        case .notEntitled: return "off_not_entitled"
        case .unavailable: return "unavailable"
        case .notStarted: return "not_started"
        }
    }

    /// `state.plist`'s `execGateDetail`, when there is one.
    public var detail: String? {
        switch self {
        case .active: return nil
        case .notEntitled:
            return "This build has no Endpoint Security entitlement, so the exec gate is off. "
                + "sudo, AuthorizationDB rights and JIT admin are enforced as usual."
        case let .unavailable(why): return why
        case let .notStarted(why): return why
        }
    }
}
