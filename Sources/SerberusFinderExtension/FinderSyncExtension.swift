import Cocoa
import FinderSync
import OSLog
import PrivMgrCore
import SerberusXPCShim

/// The Serberus Finder Sync extension: the TOP-LEVEL "Install with Serberus" /
/// "Uninstall with Serberus" right-click items (with the Sentinel icon) that a
/// plain `NSService` cannot provide — a service is confined to the categorized
/// "Services" submenu with no custom icon, whereas a Finder Sync extension's
/// contextual-menu items appear inline, BeyondTrust-style.
///
/// It is SANDBOXED (the OS refuses a non-sandboxed FinderSync) and is **not** a
/// daemon principal. On click it forwards the selected path to the agent's
/// audit-token-authenticated bridge (`FinderBridgeListener`), which routes it
/// through the exact same gated path as the NSService. Every privilege check —
/// the managed appmanagement profile, notarized-Developer-ID verification, the
/// `/Applications` pin, and the audited confirmation prompt — stays in the root
/// daemon. This extension only marshals a path string; it reads no file bytes
/// and holds no authority of its own.
@objc(FinderSyncExtension)
final class FinderSyncExtension: FIFinderSync {
    private let controller = FIFinderSyncController.default()
    private let bridgeQueue = DispatchQueue(
        label: BundleConfig.finderBridgeMachService + ".client", qos: .userInitiated)
    private static let log = Logger(subsystem: BundleConfig.logSubsystem, category: "finder-ext")

    override init() {
        super.init()
        refreshMonitoredDirectories()
        // A .dmg (or USB/network share) mounts as a SEPARATE volume under
        // /Volumes/…; monitoring only "/" does not deliver menu(for:) for items
        // on those mounts (rdar://34362783), so re-monitor whenever a volume
        // mounts/unmounts — otherwise a .pkg/.app inside a .dmg only gets the
        // NSService submenu fallback, not the top-level items.
        let nc = NSWorkspace.shared.notificationCenter
        nc.addObserver(self, selector: #selector(volumesChanged),
                       name: NSWorkspace.didMountNotification, object: nil)
        nc.addObserver(self, selector: #selector(volumesChanged),
                       name: NSWorkspace.didUnmountNotification, object: nil)
    }

    deinit { NSWorkspace.shared.notificationCenter.removeObserver(self) }

    @objc private func volumesChanged() { refreshMonitoredDirectories() }

    /// Monitors the root volume PLUS every currently-mounted volume, so the
    /// top-level items are offered for a `.pkg`/`.app` ANYWHERE — Downloads,
    /// Desktop, /Applications, a mounted `.dmg`, external/USB media. FinderSync
    /// delivers `menu(for:)` only for items under a monitored directory, and a
    /// bare "/" does not cover separate mounts. We use ONLY the contextual menu
    /// (no badges/observing), so monitoring many volumes stays cheap.
    private func refreshMonitoredDirectories() {
        var urls: Set<URL> = [URL(fileURLWithPath: "/")]
        if let mounts = FileManager.default.mountedVolumeURLs(
            includingResourceValuesForKeys: nil, options: [.skipHiddenVolumes]) {
            urls.formUnion(mounts)
        }
        controller.directoryURLs = urls
    }

    override func menu(for menuKind: FIMenuKind) -> NSMenu {
        let menu = NSMenu(title: "")
        guard menuKind == .contextualMenuForItems else { return menu }
        // Hide the items entirely where the app-management master gate is OFF (the
        // daemon publishes it to a tiny world-readable marker). Fail-OPEN: only
        // hide on an EXPLICIT "disabled" — an absent/unreadable marker still shows
        // the items, and the daemon gates every action regardless.
        guard !Self.appManagementDisabled() else { return menu }
        // The selection MUST be read synchronously inside menu(for:) — reading it
        // later (e.g. from the action) is fine too, but deferring the menu build
        // past this callback yields an empty selection.
        let selection = controller.selectedItemURLs() ?? []
        if selection.contains(where: Self.isInstallable) {
            menu.addItem(item(title: "Install with Serberus", action: #selector(installClicked)))
        }
        if selection.contains(where: Self.isUninstallable) {
            menu.addItem(item(title: "Uninstall with Serberus", action: #selector(uninstallClicked)))
        }
        return menu
    }

    private func item(title: String, action: Selector) -> NSMenuItem {
        let menuItem = NSMenuItem(title: title, action: action, keyEquivalent: "")
        menuItem.target = self
        menuItem.image = BridgeGlyph.image(pointSize: 16)   // the Sentinel sigil (what users know as Serberus)
        return menuItem
    }

    /// Reads the daemon's app-management master-gate marker. Returns `true` ONLY
    /// when the marker exists and explicitly says disabled — fail-open otherwise,
    /// so a missing daemon/marker never hides a legitimately-enabled machine's
    /// items (the daemon still gates every action server-side regardless). Read
    /// synchronously each `menu(for:)`; the marker is a few bytes.
    private static func appManagementDisabled() -> Bool {
        guard let data = FileManager.default.contents(atPath: BundleConfig.appManagementStatePath),
              let obj = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = obj as? [String: Any],
              let enabled = dict["enabled"] as? Bool else { return false }
        return enabled == false
    }

    /// A flat `.pkg` (a file, not a bundle-style package folder) or any
    /// `.app` may be installed (a bundle-style `.mpkg` isn't supported). The
    /// daemon enforces the same rule; this just hides the item where it
    /// can't succeed.
    private static func isInstallable(_ url: URL) -> Bool {
        switch url.pathExtension.lowercased() {
        case "app": return true
        case "pkg": return (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) != true
        default: return false
        }
    }

    /// Only a `.app` directly in `/Applications` or `/Applications/Utilities`,
    /// reached without any symlink, may be uninstalled — the same rule the
    /// daemon enforces (it re-pins this; this is just so the item is offered
    /// only where it can succeed).
    private static func isUninstallable(_ url: URL) -> Bool {
        guard url.isFileURL, url.pathExtension.lowercased() == "app" else { return false }
        let path = url.standardizedFileURL.path
        guard path == url.resolvingSymlinksInPath().path else { return false }   // not canonical
        let parent = (path as NSString).deletingLastPathComponent
        let apps = BundleConfig.applicationsDirectory
        return parent == apps || parent == apps + "/Utilities"
    }

    @objc private func installClicked() {
        forward(action: FinderBridgeWire.install,
                urls: (controller.selectedItemURLs() ?? []).filter(Self.isInstallable))
    }

    @objc private func uninstallClicked() {
        forward(action: FinderBridgeWire.uninstall,
                urls: (controller.selectedItemURLs() ?? []).filter(Self.isUninstallable))
    }

    /// The code-signing requirement the bridge peer must satisfy: the Sentinel
    /// agent's identifier, an Apple-issued certificate, and this extension's own
    /// Team ID (an unsigned / ad-hoc build keeps the identifier + Apple anchor).
    static var agentPeerRequirement: String {
        let team = BundleConfig.teamID
        guard !team.isEmpty else {
            return "identifier \"\(BundleConfig.sentinelBundleID)\" and anchor apple generic"
        }
        return ExpectedCaller(bundleID: BundleConfig.sentinelBundleID, teamID: team,
                              requiredEntitlement: nil).designatedRequirement
    }

    /// Sends each selected path to the agent's bridge. Fire-and-forget from the
    /// user's view: the real outcome surfaces as the daemon's audited prompt and
    /// the agent's toast. The connection is retained by each reply handler until
    /// its reply (or a connection error) lands, then released.
    private func forward(action: String, urls: [URL]) {
        guard !urls.isEmpty else { return }
        let paths = urls.map(\.path)   // snapshot before the async hop
        // NOT privileged: the bridge is the Sentinel AGENT's service, advertised
        // in this user's launchd session (the daemon's system-domain name is
        // never contacted from here). Pin the peer to the agent's signature
        // instead, so another process registered under the bridge name can't
        // harvest the selected paths. Must be set before resume.
        let conn = xpc_connection_create_mach_service(
            BundleConfig.finderBridgeMachService, bridgeQueue, 0)
        xpc_connection_set_event_handler(conn) { _ in }   // required; connection-level events ignored
        let pinned = xpc_connection_set_peer_code_signing_requirement(conn, Self.agentPeerRequirement) == 0
        // Resume even when pinning failed: libxpc traps on releasing a
        // never-resumed connection, and resuming sends nothing by itself.
        xpc_connection_resume(conn)
        guard pinned else {
            xpc_connection_cancel(conn)
            Self.log.error("forward \(action, privacy: .public): agent code-signing requirement rejected")
            return
        }
        Self.log.notice("forward \(action, privacy: .public): \(paths.count, privacy: .public) item(s)")
        for path in paths {
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(message, FinderBridgeWire.actionKey, action)
            xpc_dictionary_set_string(message, FinderBridgeWire.pathKey, path)
            xpc_connection_send_message_with_reply(conn, message, bridgeQueue) { _ in
                _ = conn   // keep the connection alive until the reply/error arrives
            }
        }
    }
}
