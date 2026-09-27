import AppKit
import OSLog
import PrivMgrCore
import SerberusSentinelCore

/// The "Install with Serberus" Finder Service handler (declared in the agent's
/// Info.plist `NSServices`, method `installWithSerberus`). When the user
/// right-clicks a `.pkg`/`.app` and picks the item, macOS calls this on the
/// running agent; it hands each selected file to the daemon over the trusted
/// `.sentinel` XPC channel (the daemon gates, verifies, prompts, installs) and
/// shows the outcome as a toast.
///
/// The agent is the correct caller: it is the `.sentinel` peer (entitlement +
/// bundle + Team ID + Hardened Runtime + designated requirement), it is always
/// running, and it already owns the elevation-prompt UI the daemon reuses for
/// the install confirmation.
@MainActor
final class InstallService: NSObject {
    /// Brokers one install to the daemon (wired to `SentinelXPCClient.installSoftware`).
    var perform: (@Sendable (InstallRequest) async -> InstallResult)?
    /// Brokers one uninstall to the daemon (wired to `SentinelXPCClient.uninstallSoftware`).
    var performUninstall: (@Sendable (UninstallRequest) async -> InstallResult)?
    /// Shows an install outcome to the user (wired to the toast presenter).
    var present: ((InstallResult, String) -> Void)?
    /// Shows an uninstall outcome to the user.
    var presentUninstall: ((InstallResult, String) -> Void)?
    /// Shows an immediate "working" indicator the instant an install is requested,
    /// so the user gets feedback during the verification gap before the prompt.
    var presentProgress: ((String) -> Void)?
    /// Retains the Finder-extension bridge listener (top-level right-click items)
    /// for the app's lifetime. Its handler routes back into `install(path:)` /
    /// `uninstall(path:)`, so both front doors share one code path.
    var finderBridge: FinderBridgeListener?

    /// Keys ("verb|canonical path") of requests currently in flight, so a rapid
    /// duplicate (a double-click, or the Finder extension resending — possibly
    /// through a different spelling of the same path) is coalesced into ONE
    /// prompt instead of two. `@MainActor`-isolated, so access is race-free with
    /// no lock. Covers BOTH front doors (NSService + Finder-extension bridge),
    /// which both funnel through `install(path:)` / `uninstall(path:)`.
    private var inFlight: Set<String> = []

    /// The de-duplication key for `path`: standardized and symlink-resolved, so
    /// `/tmp/x.pkg` and `/private/tmp/x.pkg` coalesce. Display/dedupe only — the
    /// daemon canonicalizes independently.
    static func dedupeKey(verb: String, path: String) -> String {
        let canonical = ((path as NSString).standardizingPath as NSString).resolvingSymlinksInPath
        return "\(verb)|\(canonical)"
    }

    /// Reserves `key` if not already in flight; logs + returns `false` for a
    /// coalesced duplicate. The caller clears it when the request resolves.
    private func begin(_ key: String) -> Bool {
        guard !inFlight.contains(key) else {
            Self.log.notice("coalesced duplicate request: \(key, privacy: .public)")
            return false
        }
        inFlight.insert(key)
        return true
    }

    private static let log = Logger(subsystem: BundleConfig.logSubsystem, category: "install-service")

    /// NSServices entry point. Signature is fixed by the Services API; the
    /// Info.plist `NSMessage` names it. Reads file URLs from the pasteboard and
    /// installs each — returning immediately (the install runs async and reports
    /// via a toast) so Finder is never blocked.
    @objc func installWithSerberus(_ pboard: NSPasteboard, userData: String?,
                                   error: AutoreleasingUnsafeMutablePointer<NSString>?) {
        guard let urls = pboard.readObjects(forClasses: [NSURL.self],
                                            options: [.urlReadingFileURLsOnly: true]) as? [URL],
              !urls.isEmpty else {
            error?.pointee = "No file selected to install." as NSString
            return
        }
        for url in urls { install(path: url.path) }
    }

    /// Brokers one install by path — the shared core of the NSService entry point
    /// and the Finder-extension bridge. Returns immediately; the install runs
    /// async on the daemon (which gates, verifies, prompts, installs as root) and
    /// reports via a toast, so Finder is never blocked.
    func install(path: String) {
        let key = Self.dedupeKey(verb: "install", path: path)
        guard begin(key) else { return }
        // Shown in toasts: cleaned like every name the daemon shows.
        let name = InstallPresentation.displayName(forPath: path)
        presentProgress?(name)   // instant feedback — the prompt can be seconds away
        let request = InstallRequest(sourcePath: path, displayName: (path as NSString).lastPathComponent)
        let perform = perform
        let present = present
        Task { @MainActor in
            defer { self.inFlight.remove(key) }
            Self.log.notice("install requested: \(name, privacy: .public)")
            let result = await perform?(request)
                ?? InstallResult(status: .failed, message: "Serberus is unavailable.")
            Self.log.notice("install result \(result.status.rawValue, privacy: .public): \(name, privacy: .public)")
            present?(result, name)
        }
    }

    /// NSServices entry point for "Uninstall with Serberus" (Info.plist `NSMessage`
    /// `uninstallWithSerberus`). Moves each selected `/Applications` app to the
    /// user's Trash via the daemon (gated + confirmed), reporting via a toast.
    @objc func uninstallWithSerberus(_ pboard: NSPasteboard, userData: String?,
                                     error: AutoreleasingUnsafeMutablePointer<NSString>?) {
        guard let urls = pboard.readObjects(forClasses: [NSURL.self],
                                            options: [.urlReadingFileURLsOnly: true]) as? [URL],
              !urls.isEmpty else {
            error?.pointee = "No app selected to uninstall." as NSString
            return
        }
        for url in urls { uninstall(path: url.path) }
    }

    /// Brokers one uninstall by path — the shared core of the NSService entry
    /// point and the Finder-extension bridge. The daemon gates + confirms, then
    /// moves the `/Applications` app to the user's Trash; the outcome is a toast.
    func uninstall(path: String) {
        let key = Self.dedupeKey(verb: "uninstall", path: path)
        guard begin(key) else { return }
        let name = InstallPresentation.displayName(forPath: path)
        let request = UninstallRequest(appPath: path, displayName: (path as NSString).lastPathComponent)
        let performUninstall = performUninstall
        let presentUninstall = presentUninstall
        Task { @MainActor in
            defer { self.inFlight.remove(key) }
            Self.log.notice("uninstall requested: \(name, privacy: .public)")
            let result = await performUninstall?(request)
                ?? InstallResult(status: .failed, message: "Serberus is unavailable.")
            Self.log.notice("uninstall result \(result.status.rawValue, privacy: .public): \(name, privacy: .public)")
            presentUninstall?(result, name)
        }
    }
}
