import AppKit
import OSLog
import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// Helpers for reaching the **full** Serberus Sentinel app from the menubar
/// agent. The two are separate processes with separate bundle IDs, so the agent
/// can neither `openWindow` the full app's scene nor share a
/// `SerberusWindowModel` with it — navigation crosses the process boundary via a
/// file hand-off (``SentinelRouteHandoff``) plus a launch/reactivate of the full
/// app, which reads the pending route and points its window at the right tab.
enum SentinelFullApp {
    /// The full windowed app's bundle ID. It deliberately reuses the retired
    /// standalone-Intel identity (`BundleConfig.intelBundleID`) so it stays a
    /// first-class read-only `.intel` XPC caller with **no daemon change** —
    /// see ``ExpectedCaller/intelApp``.
    static let bundleID = BundleConfig.intelBundleID
    /// Installed location of the full app (visible in /Applications). Fallback
    /// for the rare case LaunchServices has not indexed it yet.
    static let installedPath = "/Applications/Serberus Sentinel.app"

    /// Records `route`, then launches or reactivates the full app so it opens
    /// (or switches to) the matching tab.
    @MainActor static func open(_ route: SentinelDeepLink) {
        SentinelRouteHandoff.write(route)
        let workspace = NSWorkspace.shared
        // Open by the EXPLICIT /Applications path, NOT the bundle ID: a
        // bundle-ID open lets LaunchServices resolve to a stale/duplicate copy
        // (an old app in Trash, a backup, the pre-rename stray folder), which is
        // exactly what kept surfacing the previous binary after an update. The
        // bundle-ID lookup is only a fallback for dev/unpackaged runs where the
        // app lives elsewhere.
        let url = FileManager.default.fileExists(atPath: installedPath)
            ? URL(fileURLWithPath: installedPath)
            : workspace.urlForApplication(withBundleIdentifier: bundleID)
        guard let url else { return }
        let config = NSWorkspace.OpenConfiguration()
        config.activates = true
        workspace.openApplication(at: url, configuration: config, completionHandler: nil)
    }
}

/// Entry points the dropdown content uses to reach the AppKit shell that hosts
/// it: dismissing the dropdown itself (before a deep link into the full app),
/// and — debug builds only — opening the playable prompt demo window.
enum SentinelPopover {
    /// The live status-item controller; set once at launch.
    @MainActor static weak var controller: StatusItemController?

    /// Closes the dropdown. A no-controller / not-presented call is a no-op.
    @MainActor static func dismiss() {
        controller?.dismiss()
    }

    #if DEBUG
    @MainActor static func openPromptDemo() {
        PromptDemoWindow.open()
    }
    #endif
}

#if DEBUG
/// Playable prompt demo (no daemon required). Debug builds only — in
/// production, prompts arrive exclusively from the daemon over XPC.
@MainActor
enum PromptDemoWindow {
    private static var window: NSWindow?

    static func open() {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate()
            return
        }
        let host = NSHostingController(rootView: PromptDemoView())
        let window = NSWindow(contentViewController: host)
        window.title = "Serberus — Prompt Demo"
        window.identifier = NSUserInterfaceItemIdentifier("prompt-demo")
        window.styleMask = [.titled, .closable, .miniaturizable]
        window.isReleasedWhenClosed = false
        window.center()
        Self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate()
    }
}
#endif

/// Live menubar presentation config the dropdown content observes: the managed
/// `menuBarTopRulesCount` is refreshed on every poll so a pushed change applies
/// while the dropdown is open, without a relaunch.
@MainActor
@Observable
final class MenubarConfig {
    var topRulesCount = 3
}

/// The dropdown's root: reads the observable config in `body` so the content
/// re-renders when a poll changes it, and applies the popover chrome (rounded
/// clip + hairline) that the former MenuBarExtra host window used to draw.
private struct MenubarRoot: View {
    let model: MenubarStateModel
    let rules: SentinelRulesStore
    let history: ElevationHistoryStore
    let jit: JITAdminViewModel
    let config: MenubarConfig
    let refresh: () async -> Void

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.popover, style: .continuous)
        MenubarContentView(model: model, rules: rules, history: history, jit: jit,
                           topRulesCount: config.topRulesCount, refresh: refresh)
            .clipShape(shape)
            .overlay(shape.strokeBorder(Theme.stroke2, lineWidth: 1))
    }
}

/// Serberus Sentinel **Agent** (bundle `com.herojoneslabs.serberus.sentinel`) —
/// the always-on menubar LaunchAgent (LSUIElement, no Dock icon). It owns the
/// security-critical surface: it registers with the daemon, presents the audit
/// prompts pushed to it, and keeps the status icon honest with a light state
/// poll. It records every prompt it presents into the per-user history and
/// caches the rule list — both to the shared support directory the full
/// Serberus Sentinel.app reads for its "My Activity" and "My Rules" tabs.
///
/// It performs no policy evaluation and never talks to the Commander app or Jamf.
/// The tabbed window lives in a **separate** app process
/// (`SentinelFullApp`); this app has no window of its own (except a DEBUG prompt
/// demo).
///
/// A plain AppKit app, deliberately NOT a SwiftUI `App`/`MenuBarExtra` scene:
/// the status item and its dropdown are owned by ``StatusItemController`` (see
/// its doc for why — the private MenuBarExtra host window animated its own
/// frame on built-in displays and could not be told not to).
@main
@MainActor
final class SerberusSentinelAgentApp: NSObject, NSApplicationDelegate {
    /// Starts offline/pending: the menubar claims nothing until the first
    /// successful daemon pull proves otherwise.
    private let menubar = MenubarStateModel(daemonState: .pendingProfiles, daemonReachable: false)
    private let xpc: SentinelXPCClient
    private let promptController = PromptWindowController()
    // Constructed in init() AFTER the folder migration — both stores read their
    // JSON at construction, so they must not run before the rename.
    private let history: ElevationHistoryStore
    private let rules: SentinelRulesStore
    private let toasts = ToastPresenter()
    /// The "Install with Serberus" Finder Service handler (registered at launch).
    private let installService = InstallService()
    private let config = MenubarConfig()
    private let jit: JITAdminViewModel
    private var statusItem: StatusItemController?
    private var monitorTask: Task<Void, Never>?

    override init() {
        // Move any pre-rename per-user data into ~/Library/Application Support/Serberus
        // BEFORE the disk-reading stores are constructed below.
        AppSupportMigration.migrateUserSupportDirectory()
        history = ElevationHistoryStore()
        rules = SentinelRulesStore()
        let client = SentinelXPCClient()
        xpc = client
        jit = JITAdminViewModel(actions: .init(
            loadInfo: { try? await client.jitAdminInfo() },
            request: { try? await client.requestAdminElevation(justification: $0) },
            end: { (try? await client.endAdminElevation()) ?? false },
            runJamfConnect: { await JamfConnectLauncher().run($0) }
        ))
        super.init()
    }

    static func main() {
        let app = NSApplication.shared
        let delegate = SerberusSentinelAgentApp()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)   // no Dock icon; belt-and-suspenders with LSUIElement
        app.run()
    }

    private static let log = Logger(subsystem: BundleConfig.logSubsystem, category: "menubar")

    /// Seconds between daemon state pulls. There is no daemon→Sentinel state push
    /// (the sentinel XPC interface is pull-only by design), so a light poll keeps
    /// the icon honest; the dropdown additionally refreshes on open.
    private static let refreshInterval: Duration = .seconds(15)

    func applicationDidFinishLaunching(_ notification: Notification) {
        let controller = StatusItemController(menubar: menubar) { [unowned self] in
            MenubarRoot(model: menubar, rules: rules, history: history, jit: jit, config: config) {
                await self.refreshMenubar()
            }
        }
        statusItem = controller
        SentinelPopover.controller = controller
        // The status item is on screen from here, so this is where the daemon
        // connection is established.
        monitorTask = Task { await connectAndMonitor() }
    }

    /// Connects to the daemon, routes pushed prompts to the window controller
    /// (recording each resolution into the local history and showing the
    /// result toast), then keeps the menubar honest with a light state poll
    /// for the app's lifetime.
    private func connectAndMonitor() async {
        let controller = promptController
        let menubar = menubar
        let history = history
        let toasts = toasts
        await xpc.setPromptHandler { context in
            menubar.promptDidBegin()
            let response = await controller.present(context: context)
            menubar.promptDidEnd(verdict: response.verdict)
            history.record(context: context, response: response)
            // For an APPROVED install, the daemon now copies + commits the app
            // (seconds for a big one). Bridge that "approved → installed" gap with
            // a persistent "Installing…" progress bar instead of the transient
            // "Approved & logged" then a dead pause; the install-result toast then
            // replaces it. The file name comes from the item the user picked, so
            // it is cleaned exactly as the daemon cleans names (no control, bidi
            // or other invisible format characters) before it is shown.
            if response.verdict == .approved, context.processName == PromptContext.installProcessName {
                toasts.show(.installing(name: InstallPresentation.displayName(forPath: context.canonicalPath)))
            } else {
                // The audit-recipient label is org-configurable (managed
                // `auditRecipientLabel`); read fresh so a pushed profile change
                // applies to the very next toast.
                let recipient = ManagedPreferencesReader().readPrompts().value.auditRecipientLabel
                toasts.show(ToastPresenter.kind(for: response, recipient: recipient))
            }
            // Return the icon to idle once the blocked flash expires.
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(MenubarStateModel.blockedFlashDuration + 0.1))
                menubar.clearExpiredBlockedFlash()
            }
            return response
        }
        await xpc.connect()
        registerInstallService()
        await refreshMenubar()
        while !Task.isCancelled {
            try? await Task.sleep(for: Self.refreshInterval)
            await refreshMenubar()
        }
    }

    /// Registers the "Install with Serberus" Finder Service on the running agent
    /// so the right-click item appears (dynamic registration works regardless of
    /// the agent's on-disk location), and wires it to the daemon + toasts.
    private func registerInstallService() {
        let xpc = xpc
        let toasts = toasts
        installService.perform = { request in
            (try? await xpc.installSoftware(request)) ?? InstallResult(status: .failed, message: "Couldn't reach Serberus.")
        }
        installService.performUninstall = { request in
            (try? await xpc.uninstallSoftware(request)) ?? InstallResult(status: .failed, message: "Couldn't reach Serberus.")
        }
        installService.presentProgress = { name in toasts.show(.working(name: name)) }
        installService.present = { result, name in
            // Clear a stuck "Verifying…"/"Installing…" progress toast, but ONLY if
            // one is still showing — a cancelled/denied install already had its
            // "Denied by you" toast shown by the prompt handler, which this must
            // not clobber (kind(for:) returns nil for .cancelled).
            toasts.hideIfProgress()
            if let kind = ToastPresenter.kind(for: result, name: name) { toasts.show(kind) }
        }
        installService.presentUninstall = { result, name in
            if let kind = ToastPresenter.kind(forUninstall: result, name: name) { toasts.show(kind) }
        }
        NSApp.servicesProvider = installService
        NSUpdateDynamicServices()

        // Finder Sync extension bridge: the sandboxed appex provides the
        // TOP-LEVEL "Install/Uninstall with Serberus" right-click items (with the
        // Sentinel icon) and forwards the selected path here. The listener
        // authenticates the appex by audit token, then routes into the SAME
        // install/uninstall path as the NSService above. Retained on
        // installService; the handler holds it weakly to avoid a cycle.
        let service = installService
        let bridge = FinderBridgeListener { [weak service] action, path in
            switch action {
            case .install:   service?.install(path: path)
            case .uninstall: service?.uninstall(path: path)
            }
        }
        bridge.start()
        installService.finderBridge = bridge
    }

    /// Pulls daemon state, the user's active grants, and the rule list into
    /// the menubar model. A failed state pull flips the icon to offline
    /// instead of lying with the last-known state; the rule list falls back
    /// to its on-disk cache.
    private func refreshMenubar() async {
        // The full app can Clear the shared history; pick that up so the
        // dropdown's "Audited today" counter and top-rules never resurrect it.
        history.reloadFromDisk()
        do {
            menubar.update(state: try await xpc.daemonState())
        } catch {
            if menubar.daemonReachable {
                Self.log.warning("daemon state pull failed: \(String(describing: error), privacy: .public)")
            }
            menubar.markUnreachable()
        }
        if let grants = try? await xpc.activeGrants() {
            menubar.update(grants: grants)
        }
        if let snapshot = try? await xpc.userRules() {
            rules.adopt(snapshot)
        } else {
            rules.markOffline()
        }
        // Managed menubar presentation config (world-readable; no privilege).
        config.topRulesCount = ManagedPreferencesReader().readPrompts().value.menuBarTopRulesCount
        // Reconcile the JIT affordance against the caller's active admin grant.
        let jitExpiry = menubar.activeGrants
            .first { JITAdminGrant.isJITGrant($0) && $0.isActive(at: Date()) }?
            .expiresAt
        await jit.refresh(activeExpiry: jitExpiry)
    }
}
