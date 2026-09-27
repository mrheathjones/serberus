import Darwin
import Foundation
import PrivMgrCore
import SerberusCLICore

// serberus — the Serberus CLI (/usr/local/bin/serberus).
//
// `list`, `version`, `status`, and `simulate` read managed preferences and the
// daemon's state/version files directly — no daemon dependency. `grants` reads
// the root-only grant database when run as root, else reports unavailable
// rather than presenting stale data as live.

let command = CLICommand.parse(Array(CommandLine.arguments.dropFirst()))

let runner = CLIRunner(
    preferences: CFPreferencesSource(),
    statePlistURL: URL(fileURLWithPath: BundleConfig.statePlistPath),
    versionPlistURL: URL(fileURLWithPath: BundleConfig.versionPlistPath),
    username: ProcessInfo.processInfo.environment["SUDO_USER"] ?? NSUserName(),
    isRoot: getuid() == 0
)

/// `grants` needs the root-only database; fetch it only when running as root.
func liveGrants() async -> [Grant]? {
    guard getuid() == 0 else { return nil }
    guard let store = try? GrantStore(
        path: BundleConfig.grantDatabasePath,
        keyProvider: SystemKeychainKeyProvider()
    ) else {
        return nil
    }
    defer { Task { await store.close() } }
    return try? await store.activeGrants(now: Date())
}

let output: CLIOutput
if case .grants = command {
    let grants = await liveGrants()
    output = runner.run(command, grants: grants)
} else {
    output = runner.run(command)
}

print(output.text)
exit(output.exitCode)
