import AppKit
import OSLog
import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// Identity constants for the full app's single window and its deep-link scheme.
enum FullAppWindow {
    /// Internal scene id (the user-facing title is "Serberus Sentinel").
    static let id = "serberus"
    static let title = "Serberus Sentinel"
}

/// Ensures the always-on menubar **agent** is running whenever the full app is.
///
/// Requirement: launching Serberus Sentinel.app must also start the menu bar
/// app if it is not already running. Normally the agent's LaunchAgent
/// (RunAtLoad + KeepAlive) keeps it up; this is the fallback for when the user
/// quit it from the gear menu, and for un-packaged dev runs.
enum SentinelAgent {
    static let bundleID = BundleConfig.sentinelBundleID
    /// Installed location of the menubar agent — hidden under Application
    /// Support so /Applications shows only the one user-facing full app.
    static let installedPath = "\(BundleConfig.supportDirectory)/Serberus Sentinel Agent.app"

    @MainActor static func ensureRunning() {
        guard NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty else {
            return
        }
        let workspace = NSWorkspace.shared
        // Prefer the known install path; fall back to a LaunchServices lookup
        // for dev / unpackaged runs where the agent lives elsewhere.
        let url = FileManager.default.fileExists(atPath: installedPath)
            ? URL(fileURLWithPath: installedPath)
            : workspace.urlForApplication(withBundleIdentifier: bundleID)
        guard let url else { return }
        let config = NSWorkspace.OpenConfiguration()
        config.activates = false        // don't steal focus from our own window
        config.addsToRecentItems = false
        workspace.openApplication(at: url, configuration: config, completionHandler: nil)
    }
}

/// AppKit delegate for the full windowed app. It owns the three behaviours that
/// must work regardless of SwiftUI scene state:
///  1. deep links handed off by the menubar agent (``SentinelRouteHandoff``),
///  2. reopen (Dock click / double-click) recreating the closed window,
///  3. ensuring the menubar agent is running on every launch/reopen.
///
/// The route hand-off is consumed here (on launch AND on reopen) rather than via
/// SwiftUI's `.onOpenURL`, because a warm launch with the window closed has no
/// live scene view for a URL to reach — the AppKit reopen callback always fires.
@MainActor
final class FullAppDelegate: NSObject, NSApplicationDelegate {
    /// Captured when the window first appears. `OpenWindowAction` stays callable
    /// app-wide even after the `Window` scene is destroyed on close, so this is
    /// how a closed window is recreated (there is no NSWindow left to front).
    private var openWindow: OpenWindowAction?
    /// The Intel model, for the quit guard: a Capture in progress is minutes
    /// of a user reproducing a workflow and must not vanish on ⌘Q silently.
    private weak var intel: IntelModel?

    func registerOpenWindow(_ action: OpenWindowAction) { openWindow = action }
    func registerIntel(_ model: IntelModel) { intel = model }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let intel, intel.captureInProgress else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = "A capture is in progress"
        alert.informativeText = "Quitting now discards everything recorded so far. Stop the capture and save or upload it first?"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Keep Capturing")
        alert.addButton(withTitle: "Quit and Discard")
        return alert.runModal() == .alertFirstButtonReturn ? .terminateCancel : .terminateNow
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Cold launch: apply the route BEFORE the auto-opened window renders so
        // it comes up on the requested tab; a plain launch (no pending route)
        // keeps the default tab.
        if let route = SentinelRouteHandoff.take() {
            SerberusWindowModel.shared.apply(route)
        }
        SentinelAgent.ensureRunning()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        // Warm launch (agent deep link, Dock click, double-click): pick up a
        // pending route, then front/recreate the window.
        if let route = SentinelRouteHandoff.take() {
            SerberusWindowModel.shared.apply(route)
        }
        showWindow()
        SentinelAgent.ensureRunning()
        return true
    }

    /// Fronts the window if SwiftUI still has it, else recreates it via the
    /// captured `openWindow` action, then activates the app.
    private func showWindow() {
        let existing = NSApplication.shared.windows.first { window in
            window.identifier?.rawValue == FullAppWindow.id || window.title == FullAppWindow.title
        }
        if let existing {
            existing.makeKeyAndOrderFront(nil)
        } else {
            openWindow?(id: FullAppWindow.id)
        }
        NSApplication.shared.activate(ignoringOtherApps: true)
    }
}

/// **Serberus Sentinel** (bundle `com.herojoneslabs.serberus.intel`) — the full,
/// user-facing app: a regular Dock app (its own App menu next to the Apple
/// logo) whose single window carries the My Activity, My Rules, and Intel tabs.
///
/// It is a **separate process** from the menubar agent
/// (`com.herojoneslabs.serberus.sentinel`): quitting this app leaves the agent
/// (and its always-on audit prompts) running, and launching this app starts the
/// agent if needed (``SentinelAgent``). It reuses the retired standalone-Intel
/// bundle identity so it remains a first-class read-only `.intel` XPC caller
/// (the Intel tab) with no daemon change; My Activity and My Rules read the
/// shared history/rules caches the agent maintains.
@main
struct SerberusSentinelApp: App {
    @State private var nav = SerberusWindowModel.shared
    // Constructed in init() AFTER the folder migration — both read their JSON at
    // construction, so they must not run before the rename.
    @State private var rules: SentinelRulesStore
    @State private var history: ElevationHistoryStore
    /// App-lifetime so a Capture (Rule Recorder) session survives tab switches
    /// and window close/reopen; the Intel tab only borrows it.
    @State private var intel = IntelModel()

    @NSApplicationDelegateAdaptor(FullAppDelegate.self) private var appDelegate

    init() {
        // Move any pre-rename per-user data into ~/Library/Application Support/Serberus
        // BEFORE the disk-reading stores are constructed below.
        AppSupportMigration.migrateUserSupportDirectory()
        _rules = State(initialValue: SentinelRulesStore())
        _history = State(initialValue: ElevationHistoryStore())
    }

    var body: some Scene {
        Window(FullAppWindow.title, id: FullAppWindow.id) {
            RootView(nav: nav, rules: rules, history: history, intel: intel, delegate: appDelegate)
        }
        .defaultSize(width: 820, height: 560)
    }
}

/// The window's root: hosts the tabbed main view, registers the SwiftUI
/// `openWindow` action with the AppKit delegate (for reopen), and keeps the
/// read-only caches fresh while the window is open.
private struct RootView: View {
    let nav: SerberusWindowModel
    let rules: SentinelRulesStore
    let history: ElevationHistoryStore
    let intel: IntelModel
    let delegate: FullAppDelegate
    @Environment(\.openWindow) private var openWindow

    /// How often the full app re-reads the shared caches the agent writes.
    /// Cheap (two small JSON files) and only reassigns on change, so an idle
    /// window neither spins nor scroll-jumps.
    private static let reloadInterval: Duration = .seconds(3)

    var body: some View {
        // GeometryReader is greedy — it claims ALL offered space and reports it,
        // forcing the tabbed content to the full window size. On macOS 27 a
        // plain `.frame(maxWidth: .infinity)` no longer stretches a Window's
        // content to the window: the content settled at its ideal width and
        // left-aligned in a wider window, so the Intel controls bar was laid out
        // narrower than the window (dead space to the right, leading padding
        // gone). Pinning to `proxy.size` fills the window on every macOS version.
        GeometryReader { proxy in
            SerberusMainView(nav: nav, rules: rules, history: history, intel: intel)
                .frame(width: proxy.size.width, height: proxy.size.height)
        }
        .onAppear {
            delegate.registerOpenWindow(openWindow)
            delegate.registerIntel(intel)
        }
        .task {
            while !Task.isCancelled {
                rules.reloadFromDisk()
                history.reloadFromDisk()
                try? await Task.sleep(for: Self.reloadInterval)
                guard !Task.isCancelled else { break }
            }
        }
    }
}
