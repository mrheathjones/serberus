import Foundation
import PrivMgrCore

/// How far back a historical log query reaches (`log show --last <window>`).
///
/// Values are the literal argument `log(1)` expects, so they double as the
/// wire format — no formatting layer to drift out of sync.
public enum LogWindow: String, CaseIterable, Sendable, Identifiable {
    case fiveMinutes = "5m"
    case fifteenMinutes = "15m"
    case oneHour = "1h"
    case sixHours = "6h"
    case oneDay = "1d"
    case sevenDays = "7d"

    public var id: String { rawValue }

    /// Human label for the picker.
    public var label: String {
        switch self {
        case .fiveMinutes: return "Last 5 minutes"
        case .fifteenMinutes: return "Last 15 minutes"
        case .oneHour: return "Last hour"
        case .sixHours: return "Last 6 hours"
        case .oneDay: return "Last 24 hours"
        case .sevenDays: return "Last 7 days"
        }
    }
}

/// Builds the `log(1)` predicate and argument vectors for Serberus queries.
///
/// Pure and value-typed so every argv decision is unit-testable without
/// spawning a process.
///
/// ## Why not `subsystem == "com.herojoneslabs.serberus"`
///
/// That is the predicate `pam_serberus.c` documents in its header comment,
/// and it is **wrong for a capture tool**: `SerberusSentinel` logs under
/// `com.herojoneslabs.serberus.sentinel`, a different subsystem string, so an
/// equality predicate silently drops every Sentinel line. A capture that looks
/// complete but is missing a whole component is worse than one that errors.
///
/// `BEGINSWITH "com.herojoneslabs.serberus"` alone would over-match a
/// hypothetical `com.herojoneslabs.serberusEvil`, so the predicate pins the
/// exact root **or** a dot-separated child of it.
public struct LogQuery: Sendable, Equatable {
    /// Root subsystem, shared with the daemon so the two cannot drift.
    /// Mirrors ``BundleConfig/logSubsystem``.
    public static let rootSubsystem = BundleConfig.logSubsystem

    /// Matches the daemon/PAM subsystem and every dot-separated child
    /// (notably the Sentinel's `…serberus.sentinel`).
    public static let predicate =
        #"subsystem == "\#(rootSubsystem)" OR subsystem BEGINSWITH "\#(rootSubsystem).""#

    /// Include `info`- and `debug`-level messages.
    ///
    /// Off by default: every Serberus call site today logs at `notice` or
    /// above (`notice`/`error`/`critical` in the daemon, plain `os_log` —
    /// i.e. default level — in PAM), all of which `log show` returns without
    /// these flags. Turning them on multiplies volume for no gain unless a
    /// future call site drops to `.info`/`.debug`.
    public var includeInfoAndDebug: Bool

    public init(includeInfoAndDebug: Bool = false) {
        self.includeInfoAndDebug = includeInfoAndDebug
    }

    /// Argument vector for a historical query — the `--last` flag path.
    ///
    /// `ndjson` (not `compact`) because the GUI filters by category and
    /// level; parsing a human-formatted line back into fields would be a
    /// regex guessing game.
    public func showArguments(window: LogWindow) -> [String] {
        var arguments = [
            "show",
            "--predicate", Self.predicate,
            "--style", "ndjson",
            "--last", window.rawValue,
        ]
        arguments.append(contentsOf: levelArguments)
        return arguments
    }

    /// Argument vector for the live tail.
    public func streamArguments() -> [String] {
        var arguments = [
            "stream",
            "--predicate", Self.predicate,
            "--style", "ndjson",
        ]
        arguments.append(contentsOf: levelArguments)
        return arguments
    }

    // Deliberately no `log collect` / `.logarchive` support.
    //
    // `log collect` accepts no `--predicate`: it archives the entire system
    // log store regardless of window. Measured, `--last 1m` produced a 214 MB
    // archive — orders of magnitude past anything worth attaching to a Jamf
    // computer record, and almost all of it unrelated to Serberus. The
    // filtered NDJSON export carries the same Serberus content in kilobytes.

    private var levelArguments: [String] {
        includeInfoAndDebug ? ["--info", "--debug"] : []
    }

    /// Absolute path to `log(1)`.
    ///
    /// Absolute on purpose: `log` is a common shell alias/function name, and
    /// resolving via `PATH` would let a user's environment decide what binary
    /// a security tool executes.
    public static let logToolPath = "/usr/bin/log"
}
