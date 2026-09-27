import Foundation
import PrivMgrCore

/// One-shot daemon sub-commands used by the installer/uninstaller, separate
/// from the long-running `serberusd` service.
public enum DaemonMode {
    /// Restores every AuthorizationDB right from its checksummed backup
    /// (uninstall). Returns true on success.
    public static func restoreAuthorizationDB() async -> Bool {
        let paths = DaemonPaths.production
        let version = DaemonVersion.read(from: paths.versionPlist)
        let integrityLogger = try? IntegrityLogger(directory: paths.logDirectory)
        let manager = AuthorizationDBManager(
            backend: SecurityAuthorizationDB(),
            store: AuthorizationDBSnapshotStore(directory: paths.authDBBackupDirectory),
            integrityLogger: integrityLogger,
            daemonVersion: version.daemonVersion
        )
        do {
            _ = try await manager.restoreAll()
            return true
        } catch {
            DaemonLog.integrity.error("authdb restore failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    /// Removes the coarse `/etc/sudoers.d/serberus` drop-in (uninstall / teardown),
    /// symmetric with ``restoreAuthorizationDB()``. Marker-guarded: a same-named
    /// admin-authored file is never destroyed. The pkg teardown scripts use an
    /// inline `rm` so they stay independent of this binary, but `serberusd
    /// --remove-sudoers` is offered for parity with `--restore-authdb`. Removing
    /// the coarse grant only ever fails standard users CLOSED, so it is safe and
    /// unconditional. Returns true on success (including the already-absent case).
    public static func removeSudoersDropIn() async -> Bool {
        let installer = SystemSudoersInstaller()
        do {
            try installer.removeManaged()
            DaemonLog.integrity.notice("sudoers: coarse drop-in removed via --remove-sudoers")
            return true
        } catch {
            DaemonLog.integrity.error("sudoers drop-in removal failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    /// Outcome of `serberusd --demote-jit`, mapped to its process exit code.
    public enum DemoteJITOutcome: Sendable, Equatable {
        /// Every qualifying user demoted (or confirmed not an admin). Exit 0.
        case success(JITDemotionReport)
        /// Not run as root (`geteuid() != 0`). Nothing touched. Exit 1.
        case notRoot
        /// No grant database exists, so no JIT admin can have been recorded and
        /// there is nothing to demote (a Mac whose daemon never ran). Nothing
        /// touched. Exit 3 — informational, not a failure.
        case noStore(path: String)
        /// The database exists but could not be opened. Exit 1.
        case storeUnopenable(reason: String)
        /// Live rows exist but NONE verifies under any available key (key lost /
        /// rotated / tampered). Every JIT row was still handled as a demotion
        /// candidate first. Exit 1.
        case unverifiable(JITDemotionReport)
        /// At least one user could not be demoted (or a row not retired). Exit 1.
        case failed(JITDemotionReport)

        public var exitCode: Int32 {
            switch self {
            case .success: return 0
            case .noStore: return DaemonMode.demoteJITNoStoreExitCode
            case .notRoot, .storeUnopenable, .unverifiable, .failed: return 1
            }
        }
    }

    /// `--demote-jit` exit code for "no grant store, nothing to demote".
    /// Distinct from 1 so teardown scripts can log it as information rather
    /// than warn that JIT admins may remain.
    public static let demoteJITNoStoreExitCode: Int32 = 3

    /// Demotes every Serberus-created JIT admin (uninstall / teardown), run by
    /// the pkg teardown scripts as `serberusd --demote-jit` AFTER the daemon has
    /// been booted out — its demotion timers are gone, so without this a user
    /// inside a JIT window would keep `admin` after Serberus is removed.
    ///
    /// Contract (exit codes — see ``DemoteJITOutcome``):
    /// - `0`: every qualifying user demoted (or confirmed not an admin);
    /// - `3`: no grant store exists, so there is nothing to demote (information,
    ///   not a failure — a Mac whose daemon never ran);
    /// - `1`: anything else — not root, store unopenable or unverifiable, or a
    ///   user that could not be demoted;
    /// - `2`: a usage error (``DaemonCommandLine``).
    ///
    /// Behavior:
    /// - refuses unless `geteuid() == 0`;
    /// - NEVER creates anything: no key is minted (the System Keychain key and the
    ///   dev fallback file key `<support>/.grants-hmac-key.key` are only READ,
    ///   whichever exist, regardless of `SERBERUS_DEV_KEY_FALLBACK`), and the
    ///   store is opened without `SQLITE_OPEN_CREATE` — a missing store prints
    ///   "no grant store; nothing to demote" and exits 3;
    /// - rows are verified with WHICHEVER key verifies them; rows it cannot verify
    ///   are never quarantined or stamped;
    /// - removes from `admin` every user holding an UNREVOKED verified JIT grant,
    ///   and every user named by an unverifiable JIT row (conservative), marks the
    ///   verified grants revoked, logs each demotion (stdout + unified log +
    ///   integrity JSONL); every user is attempted even after a failure;
    /// - when live rows exist but none verifies, prints "grant store
    ///   unverifiable; check the admin group by hand" and exits 1 AFTER demoting
    ///   what it could.
    public static func demoteJITAdmins() async -> DemoteJITOutcome {
        let paths = DaemonPaths.production
        let version = DaemonVersion.read(from: paths.versionPlist)
        let account = BundleConfig.grantsHMACKeyAccount
        var keys: [Data] = []
        if let key = try? SystemKeychainKeyProvider(creation: .readOnly).key(account: account) {
            keys.append(key)
        }
        if let key = try? FileKeyProvider(directory: paths.supportDirectory, creation: .readOnly).key(account: account),
           !keys.contains(key) {
            keys.append(key)
        }
        return await demoteJITAdmins(
            databasePath: paths.grantDatabase.path,
            integrityKeys: keys,
            membership: DirectoryServicesGroupController(),
            integrityLogger: try? IntegrityLogger(directory: paths.logDirectory),
            daemonVersion: version.daemonVersion,
            euid: geteuid(),
            ticketClearer: SudoTimestampDirectory(),
            adminGroupScrubber: DSCLStaleAdminEntryScrubber()
        )
    }

    /// Testable core of ``demoteJITAdmins()`` over an explicit database path,
    /// candidate keys, membership and euid.
    public static func demoteJITAdmins(
        databasePath: String,
        integrityKeys: [Data],
        membership: GroupMembershipControlling,
        integrityLogger: IntegrityLogger?,
        daemonVersion: String = DaemonVersion.current.daemonVersion,
        euid: uid_t,
        ticketClearer: SudoTicketClearing = NoopSudoTicketClearer(),
        adminGroupScrubber: StaleAdminEntryScrubbing = NoopStaleAdminEntryScrubber(),
        now: Date = Date(),
        echo: @escaping @Sendable (String) -> Void = { print($0) },
        errorEcho: @escaping @Sendable (String) -> Void = { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }
    ) async -> DemoteJITOutcome {
        let byHand = "check the admin group by hand (dseditgroup -o read admin)"
        guard euid == 0 else {
            errorEcho("serberusd --demote-jit: must run as root; nothing was changed")
            return .notRoot
        }
        var info = stat()
        guard lstat(databasePath, &info) == 0 else {
            // No store ⇒ no JIT grant was ever recorded on this Mac (the daemon
            // persists the row BEFORE promoting anyone), so nothing to demote.
            let message = "serberusd --demote-jit: no grant store at \(databasePath); nothing to demote"
            echo(message)
            DaemonLog.integrity.notice("\(message, privacy: .public)")
            return .noStore(path: databasePath)
        }

        let store: GrantStore
        do {
            store = try GrantStore(path: databasePath, integrityKeys: integrityKeys,
                                   options: .existingNoQuarantine)
        } catch {
            let message = "serberusd --demote-jit: cannot open the grant store at \(databasePath): \(error). "
                + "JIT admins were NOT demoted; \(byHand)"
            errorEcho(message)
            DaemonLog.integrity.error("\(message, privacy: .public)")
            return .storeUnopenable(reason: String(describing: error))
        }
        let summary = try? await store.integritySummary()
        if integrityKeys.isEmpty {
            echo("demote-jit: no grants HMAC key found (System Keychain or dev file key); every row is unverifiable")
        }
        let report = await demoteJITAdmins(
            grantStore: store, membership: membership, integrityLogger: integrityLogger,
            daemonVersion: daemonVersion, ticketClearer: ticketClearer, adminGroupScrubber: adminGroupScrubber,
            now: now, echo: echo, errorEcho: errorEcho
        )
        await store.close()
        if summary?.isUnverifiable == true {
            let message = "serberusd --demote-jit: grant store unverifiable; \(byHand)"
            errorEcho(message)
            DaemonLog.integrity.error("\(message, privacy: .public)")
            return .unverifiable(report)
        }
        return report.succeeded && summary != nil ? .success(report) : .failed(report)
    }

    /// Testable core of ``demoteJITAdmins()`` over injected store + membership.
    public static func demoteJITAdmins(
        grantStore: GrantMaintaining,
        membership: GroupMembershipControlling,
        integrityLogger: IntegrityLogger?,
        daemonVersion: String = DaemonVersion.current.daemonVersion,
        ticketClearer: SudoTicketClearing = NoopSudoTicketClearer(),
        adminGroupScrubber: StaleAdminEntryScrubbing = NoopStaleAdminEntryScrubber(),
        now: Date = Date(),
        echo: @escaping @Sendable (String) -> Void = { print($0) },
        errorEcho: @escaping @Sendable (String) -> Void = { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }
    ) async -> JITDemotionReport {
        let report = await JITDemotionSweep.run(
            grantStore: grantStore, membership: membership, ticketClearer: ticketClearer,
            adminGroupScrubber: adminGroupScrubber, now: now
        ) { line in
            echo(line)
            DaemonLog.integrity.notice("\(line, privacy: .public)")
            guard let integrityLogger else { return }
            let event = IntegrityEvent(timestamp: Date(), kind: .grantRevocation,
                                       detail: line, daemonVersion: daemonVersion)
            try? await integrityLogger.log(event)
        }
        if !report.succeeded {
            let summary = report.failures.keys.sorted()
                .map { "\($0): \(report.failures[$0] ?? "")" }.joined(separator: "; ")
            errorEcho("serberusd --demote-jit: FAILED — \(summary)")
        }
        return report
    }
}

// MARK: - Command line

/// `serberusd` argument parsing. No argument ⇒ the long-running service
/// (launchd starts it with none); exactly one known one-shot flag ⇒ that
/// one-shot; any other `--` flag, or any stray positional argument ⇒ a usage
/// error (exit 2), never the service — a daemon started by a misspelled
/// installer command would never exit.
///
/// Single-dash `-NS… value` and `-Apple… value` pairs are ignored: that is
/// Foundation's argument-domain form for Apple's own launch arguments (Xcode
/// passes `-NSDocumentRevisionsDebugMode YES` when it runs the scheme). Any
/// other single-dash argument, such as `-demote-jit`, is a usage error.
public enum DaemonCommandLine {
    public enum Command: Sendable, Equatable {
        case service
        case restoreAuthDB
        case removeSudoers
        case demoteJIT
        case usageError(String)
    }

    public static let restoreAuthDBFlag = "--restore-authdb"
    public static let removeSudoersFlag = "--remove-sudoers"
    public static let demoteJITFlag = "--demote-jit"
    /// Exit code for an unknown / conflicting flag.
    public static let usageExitCode: Int32 = 2

    public static let usage = """
        usage: serberusd                     (run as the LaunchDaemon service)
               serberusd --restore-authdb    (restore AuthorizationDB rights from backup)
               serberusd --remove-sudoers    (remove the coarse sudoers drop-in)
               serberusd --demote-jit        (demote every Serberus JIT admin; root only)
        """

    /// - Parameter arguments: argv WITHOUT the program name.
    public static func parse(_ arguments: [String]) -> Command {
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument.hasPrefix("--") {
                index += 1
            } else if argument.hasPrefix("-NS") || argument.hasPrefix("-Apple") {
                // `-Name value`: skip the value with its name.
                index += 2
            } else if argument.hasPrefix("-"), argument.count > 1 {
                return .usageError("unknown option '\(argument)'")
            } else {
                return .usageError("unexpected argument '\(argument)'")
            }
        }
        let flags = arguments.filter { $0.hasPrefix("--") }
        guard !flags.isEmpty else { return .service }
        let known: [String: Command] = [
            restoreAuthDBFlag: .restoreAuthDB,
            removeSudoersFlag: .removeSudoers,
            demoteJITFlag: .demoteJIT,
        ]
        if let unknown = flags.first(where: { known[$0] == nil }) {
            return .usageError("unknown option '\(unknown)'")
        }
        let distinct = Set(flags)
        guard distinct.count == 1, let only = distinct.first, let command = known[only] else {
            return .usageError("only one of \(known.keys.sorted().joined(separator: ", ")) may be given")
        }
        return command
    }
}
