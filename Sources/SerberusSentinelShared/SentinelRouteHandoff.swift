import Foundation

/// A deep-link target in the full Serberus Sentinel window. Compiled into both
/// GUI targets (the menubar **agent** writes one; the full **app** consumes it).
enum SentinelDeepLink: String {
    case home
    case rules
    case activityToday = "activity-today"
}

/// Cross-process hand-off for menubar-agent → full-app deep links.
///
/// The two apps are separate processes with separate bundle IDs, so the agent
/// cannot `openWindow` the full app's scene or share a navigation model with it.
/// Instead the agent writes the requested route to a single file in the shared
/// support directory, then launches (or reactivates) the full app; the full
/// app reads-and-clears it on launch and on reopen and points its window at the
/// right tab. A file (rather than a custom URL scheme) keeps both apps on the
/// standard generated Info.plist — no `CFBundleURLTypes` registration — and
/// delivers reliably whether the full app is cold, warm-with-window, or
/// warm-with-window-closed.
///
/// The path is hard-coded to the **agent's** bundle domain (not the writer's or
/// reader's own container) so both processes resolve the same file regardless
/// of their differing bundle IDs — matching `ElevationHistoryStore` and
/// `SentinelRulesStore`, which share the same directory.
enum SentinelRouteHandoff {
    /// `~/Library/Application Support/Serberus/pending-route`
    static func fileURL() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return base
            .appendingPathComponent("Serberus", isDirectory: true)
            .appendingPathComponent("pending-route")
    }

    /// Records the route the agent wants the full app to open. Best-effort: a
    /// failed write just means the full app opens its default tab.
    static func write(_ route: SentinelDeepLink) {
        guard let url = fileURL() else { return }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? route.rawValue.write(to: url, atomically: true, encoding: .utf8)
    }

    /// Reads and removes the pending route (single-shot). Returns `nil` when
    /// there is none (a plain launch, not a deep link).
    static func take() -> SentinelDeepLink? {
        guard let url = fileURL(), let raw = try? String(contentsOf: url, encoding: .utf8) else {
            return nil
        }
        try? FileManager.default.removeItem(at: url)
        return SentinelDeepLink(rawValue: raw.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
