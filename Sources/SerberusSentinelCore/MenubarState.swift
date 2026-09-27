import Foundation
import Observation
import PrivMgrCore

/// The four menubar status presentations. Template SF Symbols
/// adapt to light/dark automatically; Figma custom assets replace them as a
/// polish pass.
public enum MenubarIcon: String, Equatable, Sendable, CaseIterable {
    case healthy
    case pending
    case degraded
    case killSwitch
    /// The Sentinel cannot reach the daemon (not installed, not running, or the
    /// connection dropped) — distinct from any daemon-reported state.
    case offline

    /// Maps a daemon state to its menubar presentation. Both pending states
    /// collapse to the single "pending" indicator.
    public static func from(_ state: DaemonState) -> MenubarIcon {
        switch state {
        case .healthy: return .healthy
        // Awaiting config is a setup state, not a fault: the daemon is up and
        // waiting for its profile, and enforces nothing until it arrives.
        case .awaitingConfig, .pendingPPPC, .pendingProfiles: return .pending
        case .degraded: return .degraded
        case .killSwitch: return .killSwitch
        }
    }

    /// SF Symbol fallback (the menu bar renders the Serberus template mark).
    public var symbolName: String {
        switch self {
        case .healthy: return "shield.lefthalf.filled"
        case .pending: return "shield.lefthalf.filled.badge.checkmark"
        case .degraded: return "exclamationmark.shield.fill"
        case .killSwitch: return "xmark.shield.fill"
        case .offline: return "shield.slash"
        }
    }

    public var tooltip: String {
        switch self {
        case .healthy: return "Serberus — healthy"
        case .pending: return "Serberus — pending setup"
        case .degraded: return "Serberus — degraded"
        case .killSwitch: return "Serberus — disabled (kill switch)"
        case .offline: return "Serberus — daemon unreachable"
        }
    }
}

/// The status-item rendering states of the redesigned Sentinel sigil
/// (design: menu bar icon states). A pure presentation vocabulary layered on
/// top of the daemon state: prompt/blocked are Sentinel-local events the
/// daemon state machine knows nothing about.
public enum MenubarPresentation: Equatable, Sendable {
    /// Healthy and quiet — monochrome template glyph.
    case idle
    /// Daemon up, setup pending — amber, steady.
    case pending
    /// An audit prompt is on screen awaiting the user — amber, pulsing.
    case promptWaiting
    /// A prompted action was just denied (user or timeout) — red, steady,
    /// transient.
    case blocked
    /// Daemon enforcement is degraded — red, steady, persistent. Shares the
    /// blocked rendering but NOT its tooltip: "action blocked" for an ongoing
    /// enforcement fault would misdirect the user's report to IT.
    case degraded
    /// Daemon unreachable — gray, dashed ring (cached policy).
    case offline
    /// Kill switch — template glyph with a slash.
    case killSwitch
    /// A TIMED elevation grant is counting down — the icon itself is the
    /// passive indicator (green, gently pulsing). `expiresAt` is the soonest
    /// active grant's deadline; the icon reads it to intensify into an urgent
    /// state in the final minute. The exact numeric countdown is shown only in
    /// the dropdown, never on the icon. A grant with no expiry (time-bound
    /// grants off) never pulses: there is nothing counting down, so the icon
    /// stays at rest and the grant is listed in the dropdown only.
    case grantActive(expiresAt: Date?)

    public var tooltip: String {
        switch self {
        case .idle: return "Serberus — protected"
        case .pending: return "Serberus — pending setup"
        case .promptWaiting: return "Serberus — waiting for your decision"
        case .blocked: return "Serberus — action blocked"
        case .degraded: return "Serberus — degraded · enforcement issue"
        case .offline: return "Serberus — offline · cached policy"
        case .killSwitch: return "Serberus — disabled (kill switch)"
        case .grantActive: return "Serberus — elevated access active"
        }
    }
}

/// Menubar view state: the current daemon state plus the logged-in user's
/// active grants, both pushed/pulled from the daemon over XPC. `@Observable` so
/// SwiftUI re-renders the menubar when ``SentinelXPCClient`` updates it live.
@MainActor
@Observable
public final class MenubarStateModel {
    public private(set) var daemonState: DaemonState
    public private(set) var activeGrants: [Grant]
    /// Whether the last daemon query succeeded. `false` presents ``MenubarIcon/offline``
    /// regardless of the (stale) last-known daemon state.
    public private(set) var daemonReachable: Bool
    /// True while an audit prompt is on screen (drives the pulsing icon).
    public private(set) var promptActive = false
    /// Set when a prompt resolves to a denial: the icon flashes red until
    /// this instant. Cleared lazily by ``presentation`` reads after expiry.
    private var blockedFlashUntil: Date?
    /// How long the red "blocked" flash lingers after a denial.
    public static let blockedFlashDuration: TimeInterval = 4
    /// Once an active grant is within this window of expiry, the menu bar icon
    /// shifts into its urgent (final-minute) presentation. The exact remaining
    /// time still appears only in the dropdown.
    public static let grantUrgentWindow: TimeInterval = 60
    private let now: @Sendable () -> Date

    public init(
        daemonState: DaemonState = .pendingProfiles,
        activeGrants: [Grant] = [],
        daemonReachable: Bool = true,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.daemonState = daemonState
        self.activeGrants = activeGrants
        self.daemonReachable = daemonReachable
        self.now = now
    }

    public var icon: MenubarIcon {
        daemonReachable ? MenubarIcon.from(daemonState) : .offline
    }

    /// The status-item state, combining daemon state with Sentinel-local
    /// prompt activity. Kill switch always wins (enforcement is off and the
    /// user must be able to see that); an on-screen prompt outranks the
    /// transient blocked flash, which outranks the steady daemon states. An
    /// active timed grant lights the icon only when nothing more urgent is
    /// showing and the daemon is healthy and reachable, and only a grant with
    /// an expiry (a countdown) lights it — a fault or an
    /// unreachable daemon is the more important signal to keep on screen.
    public var presentation: MenubarPresentation {
        if icon == .killSwitch { return .killSwitch }
        if promptActive { return .promptWaiting }
        if let until = blockedFlashUntil, now() < until { return .blocked }
        switch icon {
        case .healthy:
            if let expiry = soonestGrantExpiry() { return .grantActive(expiresAt: expiry) }
            return .idle
        case .pending: return .pending
        case .degraded: return .degraded
        case .offline: return .offline
        case .killSwitch: return .killSwitch
        }
    }

    /// The soonest expiry among currently-active grants, ignoring grants with no
    /// expiry. `nil` when no active grant carries a deadline, which keeps the
    /// icon at rest.
    private func soonestGrantExpiry() -> Date? {
        activeGrants
            .filter { $0.isActive(at: now()) }
            .compactMap { $0.expiresAt }
            .min()
    }

    /// An audit prompt just appeared.
    public func promptDidBegin() {
        promptActive = true
    }

    /// The prompt resolved. A denial (user or timeout) flashes the icon red
    /// for ``blockedFlashDuration``.
    public func promptDidEnd(verdict: PromptResponse.Verdict) {
        promptActive = false
        if verdict == .denied || verdict == .timedOut {
            blockedFlashUntil = now().addingTimeInterval(Self.blockedFlashDuration)
        }
    }

    /// Clears an expired blocked flash (called on a delayed tick so the icon
    /// returns to idle without waiting for the next state poll).
    public func clearExpiredBlockedFlash() {
        if let until = blockedFlashUntil, now() >= until {
            blockedFlashUntil = nil
        }
    }

    /// A successful state pull: adopt it and mark the daemon reachable.
    public func update(state: DaemonState) {
        daemonState = state
        daemonReachable = true
    }

    /// A failed state pull: keep the last-known state but present offline.
    public func markUnreachable() {
        daemonReachable = false
    }

    public func update(grants: [Grant]) {
        activeGrants = grants
    }

    /// Active (unexpired, unrevoked) grants for display, soonest-expiring first.
    public func displayGrants() -> [Grant] {
        activeGrants
            .filter { $0.isActive(at: now()) }
            .sorted { ($0.expiresAt ?? .distantFuture) < ($1.expiresAt ?? .distantFuture) }
    }
}
