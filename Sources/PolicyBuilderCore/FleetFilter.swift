import Foundation

/// The Fleet Observer's device filters — check-in freshness, the daemon
/// **state** and enforcement **mode** the Serberus EAs publish — plus a
/// "only Macs with uploads waiting" switch. `nil` / `false` = no constraint.
/// One value type so the Dashboard, the menu bar and the Fleet Observer all
/// describe the same slice of the fleet (a menu-bar "Offline · 2" row hands
/// `FleetFilter(freshness: .offline)` to the screen).
public struct FleetFilter: Equatable, Hashable, Sendable {
    public var freshness: FleetDevice.Freshness?
    /// Lowercased daemon-state EA value ("healthy", "degraded", "not installed");
    /// ``FleetDevice/postureNotReported`` selects Macs whose State EA has no value.
    public var state: String?
    /// Lowercased enforcement-mode EA value ("enforce", "audit", "monitor");
    /// ``FleetDevice/postureNotReported`` selects Macs whose Mode EA has no value.
    public var mode: String?
    /// Only Macs with at least one upload still waiting for review.
    public var waitingUploadsOnly: Bool
    /// Only Macs whose telemetry EA reports at least one denial in the last 24h
    /// (the Dashboard's Denials card / top-denial rows land here). Fleet telemetry counts
    /// are per-device — this narrows the fleet to the Macs actually denying.
    public var denials24hOnly: Bool

    public init(freshness: FleetDevice.Freshness? = nil, state: String? = nil, mode: String? = nil,
                waitingUploadsOnly: Bool = false, denials24hOnly: Bool = false) {
        self.freshness = freshness
        self.state = state?.lowercased()
        self.mode = mode?.lowercased()
        self.waitingUploadsOnly = waitingUploadsOnly
        self.denials24hOnly = denials24hOnly
    }

    public static let all = FleetFilter()

    public var isActive: Bool {
        freshness != nil || state != nil || mode != nil || waitingUploadsOnly || denials24hOnly
    }

    /// How many constraints are set (for a "2 filters" pill).
    public var activeCount: Int {
        [freshness != nil, state != nil, mode != nil, waitingUploadsOnly, denials24hOnly].filter { $0 }.count
    }

    /// Whether `device` passes every set constraint. `freshness(of:)` is
    /// injected so the model's thresholds apply; `waitingUploads` is the
    /// device's uploads not yet reviewed (the ledger lives on the model).
    public func matches(_ device: FleetDevice,
                        freshness deviceFreshness: FleetDevice.Freshness,
                        waitingUploads: Int) -> Bool {
        if let freshness, deviceFreshness != freshness { return false }
        if let state, (device.daemonState ?? FleetDevice.postureNotReported) != state { return false }
        if let mode, (device.enforcementMode ?? FleetDevice.postureNotReported) != mode { return false }
        if waitingUploadsOnly, waitingUploads == 0 { return false }
        if denials24hOnly, (device.denials24h ?? 0) == 0 { return false }
        return true
    }

    /// Human summary of the active constraints ("Offline · State: healthy").
    public func summary(thresholds: FleetDevice.FreshnessThresholds = .default) -> String {
        var parts: [String] = []
        if let freshness { parts.append(freshness.label) }
        if let state { parts.append("State: \(state)") }
        if let mode { parts.append("Mode: \(mode)") }
        if waitingUploadsOnly { parts.append("Uploads waiting") }
        if denials24hOnly { parts.append("Denials · 24h") }
        return parts.joined(separator: " · ")
    }
}

/// A cross-screen deep link into the Fleet Observer, consumed by the screen
/// on appear / on change (same shape as ``PendingFocus`` for the library
/// tiers). Set through ``PolicyBuilderModel/openFleetObserver(_:)`` from the
/// Dashboard cards, the menu bar and the risk signals.
public enum FleetRoute: Equatable, Hashable, Sendable {
    /// The Devices tab with these filters applied (`.all` clears them).
    case devices(FleetFilter)
    /// The Uploads tab — narrowed to one device's uploads when an id is given.
    case uploads(deviceID: String?)

    public static let allDevices = FleetRoute.devices(.all)
    public static let allUploads = FleetRoute.uploads(deviceID: nil)
}
