import Foundation
import PrivMgrCore

/// Filesystem locations the daemon reads and writes. Injectable so tests run
/// against temp directories instead of the real `/Library` paths.
public struct DaemonPaths: Sendable {
    public let supportDirectory: URL
    public let logDirectory: URL
    public let statePlist: URL
    public let fleetSummaryPlist: URL
    public let recentEventsLocal: URL
    public let fleetEventsPublic: URL
    public let versionPlist: URL
    public let grantDatabase: URL
    public let authDBBackupDirectory: URL
    /// The marker the production preinstall writes on an upgrade
    /// (``PreinstallUpgradeMarker``). Defaults to
    /// `<supportDirectory>/.upgrade-in-progress`, the path the preinstall uses.
    public let upgradeMarker: URL

    public init(
        supportDirectory: URL,
        logDirectory: URL,
        statePlist: URL,
        fleetSummaryPlist: URL,
        recentEventsLocal: URL,
        fleetEventsPublic: URL,
        versionPlist: URL,
        grantDatabase: URL,
        authDBBackupDirectory: URL,
        upgradeMarker: URL? = nil
    ) {
        self.supportDirectory = supportDirectory
        self.logDirectory = logDirectory
        self.statePlist = statePlist
        self.fleetSummaryPlist = fleetSummaryPlist
        self.recentEventsLocal = recentEventsLocal
        self.fleetEventsPublic = fleetEventsPublic
        self.versionPlist = versionPlist
        self.grantDatabase = grantDatabase
        self.authDBBackupDirectory = authDBBackupDirectory
        self.upgradeMarker = upgradeMarker
            ?? supportDirectory.appendingPathComponent(PreinstallUpgradeMarker.fileName)
    }

    /// The production install layout.
    public static let production = DaemonPaths(
        supportDirectory: URL(fileURLWithPath: BundleConfig.supportDirectory, isDirectory: true),
        logDirectory: URL(fileURLWithPath: BundleConfig.logDirectory, isDirectory: true),
        statePlist: URL(fileURLWithPath: BundleConfig.statePlistPath),
        fleetSummaryPlist: URL(fileURLWithPath: BundleConfig.fleetSummaryPlistPath),
        recentEventsLocal: URL(fileURLWithPath: BundleConfig.recentEventsLocalPath),
        fleetEventsPublic: URL(fileURLWithPath: BundleConfig.fleetEventsPublicPath),
        versionPlist: URL(fileURLWithPath: BundleConfig.versionPlistPath),
        grantDatabase: URL(fileURLWithPath: BundleConfig.grantDatabasePath),
        authDBBackupDirectory: URL(fileURLWithPath: BundleConfig.authDBBackupDirectory, isDirectory: true)
    )

    /// A throwaway layout rooted at `directory`, for tests and dry runs.
    public static func ephemeral(in directory: URL) -> DaemonPaths {
        DaemonPaths(
            supportDirectory: directory,
            logDirectory: directory.appendingPathComponent("logs", isDirectory: true),
            statePlist: directory.appendingPathComponent("state.plist"),
            fleetSummaryPlist: directory.appendingPathComponent("fleet-summary.plist"),
            recentEventsLocal: directory.appendingPathComponent("recent-events.json"),
            fleetEventsPublic: directory.appendingPathComponent("fleet-events.json"),
            versionPlist: directory.appendingPathComponent("version.plist"),
            grantDatabase: directory.appendingPathComponent("grants.sqlite"),
            authDBBackupDirectory: directory.appendingPathComponent("authdb-backups", isDirectory: true)
        )
    }
}

/// Component version strings, read from `version.plist` when present.
public struct DaemonVersion: Sendable {
    public let daemonVersion: String
    public let pamModuleVersion: String
    public let cliVersion: String

    public init(daemonVersion: String, pamModuleVersion: String, cliVersion: String) {
        self.daemonVersion = daemonVersion
        self.pamModuleVersion = pamModuleVersion
        self.cliVersion = cliVersion
    }

    /// The version compiled into this build.
    public static let current = DaemonVersion(
        daemonVersion: "0.9.0",
        pamModuleVersion: "0.9.0",
        cliVersion: "0.9.0"
    )

    /// Reads `version.plist`, falling back to ``current`` for any missing key.
    public static func read(from url: URL) -> DaemonVersion {
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any] else {
            return current
        }
        return DaemonVersion(
            daemonVersion: dict["daemonVersion"] as? String ?? current.daemonVersion,
            pamModuleVersion: dict["pamModuleVersion"] as? String ?? current.pamModuleVersion,
            cliVersion: dict["cliVersion"] as? String ?? current.cliVersion
        )
    }
}
