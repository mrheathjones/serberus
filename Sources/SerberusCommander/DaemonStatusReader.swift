import Foundation
import Observation
import PrivMgrCore

/// Reads the local daemon's `state.plist` (the same world-readable file the
/// CLI `status` command uses) so the sidebar footer shows the *actual* daemon
/// posture on this Mac instead of a hardcoded label. `nil` status means the
/// plist is absent — the daemon isn't installed (or hasn't started yet).
@MainActor
@Observable
final class DaemonStatusReader {

    struct Status: Equatable {
        var state: DaemonState
        var enforcementMode: String?
        var version: String?
        var updatedAt: Date?
        var stale: Bool
    }

    private(set) var status: Status?

    private let plistURL: URL
    /// Beyond this age the daemon's heartbeat is considered stale (mirrors the
    /// CLI's staleness reporting).
    private let stalenessThreshold: TimeInterval

    init(
        plistURL: URL = URL(fileURLWithPath: BundleConfig.statePlistPath),
        stalenessThreshold: TimeInterval = 180
    ) {
        self.plistURL = plistURL
        self.stalenessThreshold = stalenessThreshold
        refresh()
    }

    func refresh() {
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any],
              let rawState = dict["state"] as? String,
              let state = DaemonState(rawValue: rawState) else {
            status = nil
            return
        }
        var updatedAt: Date?
        if let stamp = dict["updatedAt"] as? String {
            updatedAt = ISO8601DateFormatter().date(from: stamp)
        } else if let date = dict["updatedAt"] as? Date {
            updatedAt = date
        }
        status = Status(
            state: state,
            enforcementMode: dict["enforcementMode"] as? String,
            version: dict["daemonVersion"] as? String,
            updatedAt: updatedAt,
            stale: updatedAt.map { Date().timeIntervalSince($0) > stalenessThreshold } ?? false
        )
    }

    // MARK: Footer presentation

    var tone: StatusTone {
        guard let status else { return .offline }
        if status.stale { return .pending }
        switch status.state {
        case .healthy: return .healthy
        case .awaitingConfig, .pendingPPPC, .pendingProfiles: return .pending
        case .degraded: return .degraded
        case .killSwitch: return .offline
        }
    }

    var headline: String {
        guard let status else { return "Daemon not installed" }
        if status.stale { return "Daemon stale" }
        switch status.state {
        case .healthy: return "Daemon healthy"
        case .awaitingConfig: return "Daemon awaiting configuration"
        case .pendingPPPC: return "Daemon pending (PPPC)"
        case .pendingProfiles: return "Daemon pending (profiles)"
        case .degraded: return "Daemon degraded"
        case .killSwitch: return "Daemon disabled"
        }
    }

    var detail: String {
        guard let status else { return "No state.plist on this Mac" }
        let mode = status.enforcementMode ?? "unknown"
        let version = status.version.map { "v\($0)" } ?? "version unknown"
        return "\(mode) · \(version)"
    }
}
