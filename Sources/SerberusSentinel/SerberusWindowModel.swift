import Observation
import SwiftUI

/// Which tab the Serberus window shows: My Activity, My Rules, or Intel (the
/// diagnostics collection).
enum SerberusTab: String, CaseIterable, Identifiable {
    case activity
    case rules
    case intel

    var id: String { rawValue }

    var title: String {
        switch self {
        case .activity: return "My Activity"
        case .rules: return "My Rules"
        case .intel: return "Intel"
        }
    }

    var symbol: String {
        switch self {
        case .activity: return "scroll"
        case .rules: return "checklist"
        case .intel: return "chart.bar.doc.horizontal"
        }
    }
}

/// Shared navigation state for the single "Serberus" window. The menubar popover
/// sets `tab` (and, for the Audited-today deep link, `activityTodayOnly`) then
/// opens the window; the window observes this same instance and shows the right
/// tab/filter.
@MainActor
@Observable
final class SerberusWindowModel {
    /// Shared instance for the single-window full app. The `@main` scene and the
    /// AppKit `NSApplicationDelegate` (which receives deep-link URLs and reopen
    /// events regardless of window state) reference the same object, so a
    /// deep link resolved in the delegate is reflected by the live window with
    /// no injection-ordering hazard.
    static let shared = SerberusWindowModel()

    var tab: SerberusTab = .activity
    /// When true the My Activity tab starts filtered to today (the deep link
    /// from the popover's "Audited today" counter).
    var activityTodayOnly: Bool = false

    /// Routes the popover's "Audited today" counter → My Activity, today-only.
    func openActivityToday() {
        activityTodayOnly = true
        tab = .activity
    }

    /// Routes the popover's "My rules" counter → the full My Rules list.
    func openRules() {
        tab = .rules
    }

    /// Routes the footer "Open Serberus" → the window's default tab.
    func openDefault() {
        activityTodayOnly = false
        tab = .activity
    }

    /// Applies a deep link handed off by the menubar agent.
    func apply(_ link: SentinelDeepLink) {
        switch link {
        case .rules: openRules()
        case .activityToday: openActivityToday()
        case .home: openDefault()
        }
    }
}
