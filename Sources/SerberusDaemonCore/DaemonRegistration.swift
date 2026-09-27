import Foundation
import PrivMgrCore
import ServiceManagement

/// Registers the daemon with launchd via `SMAppService`.
///
/// Two install models exist for V1:
/// * **PKG (production):** the installer drops the LaunchDaemon plist
///   in `/Library/LaunchDaemons` and runs `launchctl bootstrap system …`.
/// * **App-bundled (`SMAppService`):** an app ships the daemon plist under
///   `Contents/Library/LaunchDaemons/<plistName>` and registers it here.
///
/// This wrapper covers the second path and the status query the Commander app
/// surfaces. It is intentionally thin — registration is a platform action,
/// not policy.
public enum DaemonRegistration {
    /// The bundled LaunchDaemon plist filename (without a path).
    public static let plistName = "\(BundleConfig.daemonBundleID).plist"

    /// Registers the bundled daemon with launchd.
    /// - Throws: the `SMAppService` error on failure.
    public static func register() throws {
        try SMAppService.daemon(plistName: plistName).register()
    }

    /// Unregisters the bundled daemon (uninstall path).
    public static func unregister() throws {
        try SMAppService.daemon(plistName: plistName).unregister()
    }

    /// Current registration status, for the Commander app's diagnostics view.
    public static func status() -> SMAppService.Status {
        SMAppService.daemon(plistName: plistName).status
    }
}
