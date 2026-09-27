import Foundation
import PrivMgrCore

/// Collects the diagnostics a standard user cannot read, on behalf of a
/// validated Serberus Intel caller.
///
/// ## Why the daemon has to do this
///
/// `/var/db/diagnostics` is `root:admin 0750`, so `log show` fails for a
/// standard user ("Could not open local log store: Operation not permitted").
/// The `pam_serberus` and Sentinel lines live only in the unified log — they have
/// no JSONL equivalent — and so does the grant database. Making the user an
/// admin, or JIT-elevating them, to read a log would defeat the tool's purpose.
/// The daemon is already root, so it reads on their behalf and hands back a
/// directory only that user can open.
///
/// ## What this is NOT allowed to do
///
/// - **Never take a predicate from the caller.** ``LogQuery/predicate`` is a
///   constant here. A caller-supplied predicate would let any local user read
///   the entire system log through serberusd.
/// - **Never take a path from the caller.** Every path is derived internally.
/// - **Never shell out.** Arguments are passed as argv; nothing is interpolated
///   into a shell string.
public struct PrivilegedLogCollector: Sendable {
    /// The one predicate this collector will ever run.
    ///
    /// Matches the daemon/PAM subsystem and every dot-separated child, so the
    /// Sentinel's `…serberus.sentinel` is included. Dot-anchored so a lookalike
    /// (`…serberusEvil`) cannot match.
    static let predicate =
        #"subsystem == "\#(BundleConfig.logSubsystem)" OR subsystem BEGINSWITH "\#(BundleConfig.logSubsystem).""#

    /// Predicate for macOS authorization-right attempts (authURI events).
    ///
    /// Serberus records none of these itself: authURI enforcement rewrites the
    /// authorization database, after which `authd` enforces natively and the
    /// daemon is never consulted per attempt. But `authd` logs every attempt to
    /// this subsystem — `Succeeded/denied authorizing right 'X' by client
    /// '/path' [pid]` — at **Default** level, so no `--info --debug` is needed
    /// (verified: right-naming lines come back as messageType `Default`/`Error`
    /// without those flags). This is what turns rule authoring from guesswork
    /// into observing the exact right a client asked for.
    ///
    /// Like ``predicate``, a **constant** — never caller-supplied, or serberusd
    /// becomes an arbitrary-log-read oracle for any local user.
    static let authorizationPredicate = #"subsystem == "com.apple.Authorization""#

    /// Predicate for **sudo attempts** — the Capture (Rule Recorder) source.
    ///
    /// `sudo(8)` logs every invocation to the unified log itself, as process
    /// `sudo` at Default level with EMPTY subsystem/category (for example
    /// `tuser : a password is required ; PWD=… ; USER=root ;
    /// COMMAND=/usr/bin/true`; successful runs read `tuser : TTY=ttys001 ;
    /// PWD=… ; USER=root ; COMMAND=<path> <args>`). These exist for EVERY
    /// attempt — including the ones Serberus never sees because PAM returned
    /// `PAM_IGNORE` (awaiting-config / monitor) — which is what makes a
    /// capture useful on a Mac that is not yet enforcing.
    ///
    /// Pinned on the executable's **image path**, not its name: `process ==
    /// "sudo"` would match any binary a local user names `sudo` (or any os_log
    /// emitted by it), letting a user plant fake "attempts" in a capture an
    /// admin later authors rules from. `processImagePath` is recorded by logd
    /// from the real executable, so only the genuine `/usr/bin/sudo` matches
    /// (these records carry processImagePath
    /// "/usr/bin/sudo" and no `process` field at all). Like the other two, a
    /// **constant**. The lines returned are additionally scoped to the calling
    /// user — see ``pollSudoAttempts(request:callerUID:)``.
    static let sudoPredicate = #"processImagePath == "/usr/bin/sudo""#

    static let logToolPath = "/usr/bin/log"

    /// Bound on one live poll's `log show`. A poll is a seconds-long window
    /// that normally returns in well under a second; a wedged logd or a huge
    /// store must not pin a daemon thread (and a root `log` child) for longer
    /// than this — the Sentinel tailers simply poll again.
    static let pollTimeout: TimeInterval = 15

    /// How long a hand-off directory may linger before it is swept.
    ///
    /// These directories hold every Serberus log line on the Mac, so they are
    /// not left lying around. Swept on each request rather than on a timer:
    /// the daemon must not hold state for a tool that runs once a month.
    static let handoffTTL: TimeInterval = 15 * 60

    /// Bound on `log show`. A 7-day window on a busy Mac is slow, and a daemon
    /// thread blocked forever on a child process is an outage — this converts a
    /// hang into a partial capture, which is the correct fail direction for a
    /// diagnostics tool.
    static let logTimeout: TimeInterval = 120

    private let paths: DaemonPaths

    /// `FileManager` is not `Sendable` and so cannot be stored on a `Sendable`
    /// struct. `.default` is safe for the stateless operations used here.
    private var fileManager: FileManager { .default }

    public init(paths: DaemonPaths) {
        self.paths = paths
    }

    /// Collects for `request` and hands the result to `callerUID`.
    public func collect(request: IntelRequest, callerUID: uid_t) throws -> IntelHandoff {
        // Validate the window against an allowlist: it becomes an argv element,
        // and "it's only a duration" is exactly how a tainted value reaches a
        // root-run tool. Rejected rather than defaulted — a silently different
        // window would be a lie in the manifest.
        guard IntelRequest.allowedWindows.contains(request.window) else {
            throw CollectorError.invalidWindow(request.window)
        }
        // Refuse to hand root-owned logs to root-less-than-console accounts and
        // to root itself: root already has everything, and chowning a
        // world-secret directory to uid 0 here would just leave litter.
        guard callerUID != 0 else { throw CollectorError.invalidCaller }

        sweepStaleHandoffs()

        let root = URL(fileURLWithPath: BundleConfig.captureHandoffDirectory, isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        // 0755 root: the user must traverse it, but must NOT be able to create
        // entries — otherwise they could plant a symlink at the next request's
        // path and redirect a root write.
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)

        let directory = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)

        var files: [String] = []
        var unavailable: [String: String] = [:]

        // Serberus's own subsystems, honouring the caller's info/debug toggle.
        runLogShow(
            name: "unified-log.ndjson",
            predicate: Self.predicate,
            window: request.window,
            includeInfoAndDebug: request.includeInfoAndDebug,
            into: directory, files: &files, unavailable: &unavailable
        )
        // Authorization-right attempts (authURI events). Always Default-level,
        // so the info/debug flags are deliberately NOT passed — they would only
        // add unrelated noise.
        runLogShow(
            name: "authorization-log.ndjson",
            predicate: Self.authorizationPredicate,
            window: request.window,
            includeInfoAndDebug: false,
            into: directory, files: &files, unavailable: &unavailable
        )
        collectGrants(into: directory, files: &files, unavailable: &unavailable)
        collectWiring(into: directory, files: &files, unavailable: &unavailable)

        // Hand ownership to the caller LAST, once the contents are final.
        try handOff(directory: directory, to: callerUID)

        return IntelHandoff(directory: directory.path, files: files, unavailable: unavailable)
    }

    /// Returns recent authorization-right attempts as NDJSON, for the live
    /// Authorizations view.
    ///
    /// Small and stateless by design: authd emits a handful of lines an hour, a
    /// live poll uses a seconds-long window, so the output is captured to memory
    /// and returned inline — no file, no chowned hand-off, nothing to clean up.
    /// A poll that spawned a long-lived `log stream` would add orphan-process
    /// risk to the daemon; this cannot leak anything.
    public func pollAuthorizations(request: AuthorizationPollRequest, callerUID: uid_t) throws -> AuthorizationPollResult {
        // Same argv discipline as `collect`: the window is an allowlisted short
        // lookback, rejected (not defaulted) if unknown, because it becomes an
        // argv element for a root-run tool.
        guard AuthorizationPollRequest.allowedWindows.contains(request.window) else {
            throw CollectorError.invalidWindow(request.window)
        }
        guard callerUID != 0 else { throw CollectorError.invalidCaller }
        return AuthorizationPollResult(
            ndjson: try pollNDJSON(predicate: Self.authorizationPredicate, window: request.window)
        )
    }

    /// Returns recent **sudo attempts** as NDJSON — the Capture (Rule Recorder)
    /// sudo source. Identical contract and discipline to
    /// ``pollAuthorizations(request:callerUID:)``: allowlisted short window,
    /// non-root caller, constant predicate, bounded stateless `log show`.
    public func pollSudoAttempts(request: SudoPollRequest, callerUID: uid_t) throws -> SudoPollResult {
        guard SudoPollRequest.allowedWindows.contains(request.window) else {
            throw CollectorError.invalidWindow(request.window)
        }
        guard callerUID != 0 else { throw CollectorError.invalidCaller }
        // Scope to the CALLER'S OWN attempts. sudo's line begins with the
        // invoking user and the uid is the kernel-stamped audit-token uid, so a
        // standard user gets exactly their own sudo history through the daemon
        // — never another account's command lines (which can carry arguments
        // worth protecting). The authd poll stays system-wide: those lines name
        // a right and a client, not a user's command line.
        guard let user = Self.userName(forUID: callerUID) else { throw CollectorError.invalidCaller }
        let ndjson = try pollNDJSON(predicate: Self.sudoPredicate, window: request.window)
        return SudoPollResult(ndjson: Self.scopeSudoLines(ndjson, toUser: user))
    }

    /// Keeps only the NDJSON records whose `eventMessage` is one of `user`'s
    /// own sudo lines (`<user> : …`, after sudo's `%8s` right-padding).
    /// Everything else — other accounts' attempts, the `libsystem_info`
    /// activity noise, the `log` preamble, malformed records — is dropped
    /// daemon-side so it never crosses XPC. Pure; exercised directly by tests.
    static func scopeSudoLines(_ ndjson: String, toUser user: String) -> String {
        let prefix = "\(user) : "
        let kept = ndjson.split(separator: "\n", omittingEmptySubsequences: true).filter { line in
            guard line.first == "{",
                  let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  let message = object["eventMessage"] as? String else { return false }
            return message.trimmingCharacters(in: .whitespaces).hasPrefix(prefix)
        }
        guard !kept.isEmpty else { return "" }
        return kept.joined(separator: "\n") + "\n"
    }

    /// Username for an audit-token uid, via the password database.
    static func userName(forUID uid: uid_t) -> String? {
        guard let passwd = getpwuid(uid), let name = passwd.pointee.pw_name else { return nil }
        let user = String(cString: name)
        return user.isEmpty ? nil : user
    }

    /// One bounded `log show --style ndjson` for a seconds-long window.
    /// `predicate` MUST be one of this type's constants and `window` MUST
    /// already be allowlisted by the caller — this helper is private precisely
    /// so nothing else can hand it argv.
    ///
    /// stdout goes to a private scratch file rather than a `Pipe` (same
    /// deadlock-free shape as ``runLogShow``), which is what lets the wait be
    /// BOUNDED: a hung `log show` is terminated after ``pollTimeout`` instead of
    /// pinning this thread — and, via the caller's cooperative-pool task, a
    /// slice of the daemon — indefinitely.
    private func pollNDJSON(predicate: String, window: String) throws -> String {
        let arguments = [
            "show",
            "--predicate", predicate,   // one of the constants above — never from the caller
            "--style", "ndjson",
            "--last", window,           // allowlisted by the public entry points
        ]

        let scratch = fileManager.temporaryDirectory
            .appendingPathComponent("serberus-poll-\(UUID().uuidString).ndjson")
        guard fileManager.createFile(atPath: scratch.path, contents: nil, attributes: [.posixPermissions: 0o600]),
              let handle = try? FileHandle(forWritingTo: scratch) else {
            throw CollectorError.logFailed("could not create a poll scratch file")
        }
        defer { try? fileManager.removeItem(at: scratch) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.logToolPath)
        process.arguments = arguments
        process.standardOutput = handle
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            try? handle.close()
            throw CollectorError.logFailed("could not run \(Self.logToolPath): \(error.localizedDescription)")
        }
        if !Self.wait(for: process, timeout: Self.pollTimeout) {
            if process.isRunning {
                process.terminate()
                _ = Self.wait(for: process, timeout: 5)
            }
            try? handle.close()
            throw CollectorError.logFailed("log show exceeded \(Int(Self.pollTimeout))s and was terminated")
        }
        try? handle.close()
        guard process.terminationStatus == 0 else {
            throw CollectorError.logFailed("log show exited \(process.terminationStatus)")
        }
        let data = (try? Data(contentsOf: scratch)) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: Artifacts

    /// Runs `log show`, writing straight to a file.
    ///
    /// stdout is redirected to the destination file rather than a `Pipe`: with
    /// no pipe there is no buffer to fill, so there is no deadlock and no
    /// concurrent drain to get right. This is why `ProcessCommandRunner` is not
    /// used here — it drains pipes only *after* the child exits, which its own
    /// comment notes is safe for small-output tools only, and `log show` output
    /// is measured in megabytes.
    /// Runs one `log show` with a **daemon-side constant** predicate, streaming
    /// straight to `name` in the hand-off.
    ///
    /// Shared by the Serberus and authorization collections so the deadlock-safe
    /// mechanics live in one place: stdout is redirected to the file, not a
    /// `Pipe`, so there is no buffer to fill and no concurrent drain to get
    /// right — which is why `ProcessCommandRunner` (drains only after exit; safe
    /// for small output only) cannot be used for `log show`'s MBs of output.
    ///
    /// Both `predicate` and `window` are pinned by the caller from constants /
    /// the allowlist — nothing here is taken from the XPC message on trust.
    private func runLogShow(
        name: String,
        predicate: String,
        window: String,
        includeInfoAndDebug: Bool,
        into directory: URL,
        files: inout [String],
        unavailable: inout [String: String]
    ) {
        let destination = directory.appendingPathComponent(name)

        guard fileManager.createFile(atPath: destination.path, contents: nil) else {
            unavailable[name] = "could not create \(destination.path)"
            return
        }
        guard let handle = try? FileHandle(forWritingTo: destination) else {
            unavailable[name] = "could not open \(destination.path) for writing"
            return
        }
        defer { try? handle.close() }

        var arguments = [
            "show",
            "--predicate", predicate,   // constant — never from the caller
            "--style", "ndjson",
            "--last", window,           // allowlisted by collect()
        ]
        if includeInfoAndDebug {
            arguments.append(contentsOf: ["--info", "--debug"])
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.logToolPath)
        process.arguments = arguments
        process.standardOutput = handle
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            unavailable[name] = "could not run \(Self.logToolPath): \(error.localizedDescription)"
            return
        }

        guard Self.wait(for: process, timeout: Self.logTimeout) else {
            process.terminate()
            unavailable[name] = "log show exceeded \(Int(Self.logTimeout))s and was terminated; "
                + "the file holds whatever it had written"
            return
        }
        guard process.terminationStatus == 0 else {
            unavailable[name] = "log show exited \(process.terminationStatus)"
            return
        }
        files.append(name)
    }

    /// The grant database — root-only, so Intel reports it as unavailable
    /// when it collects for itself.
    private func collectGrants(into directory: URL, files: inout [String], unavailable: inout [String: String]) {
        let name = "grants.sqlite"
        let source = URL(fileURLWithPath: BundleConfig.grantDatabasePath)
        guard fileManager.fileExists(atPath: source.path) else {
            unavailable[name] = "not present at \(source.path) — no grants have been issued"
            return
        }
        do {
            try Self.copyRegularFileNoFollow(from: source.path, to: directory.appendingPathComponent(name).path)
            files.append(name)
        } catch {
            unavailable[name] = error.localizedDescription
        }
    }

    /// The actual sudo wiring.
    ///
    /// Worth more than the logs for a whole class of tickets: a symlink or
    /// argPattern bug shows up here as a drop-in that does not say what the
    /// policy author thought it said.
    private func collectWiring(into directory: URL, files: inout [String], unavailable: inout [String: String]) {
        let wiring: [(name: String, path: String, detail: String)] = [
            ("sudoers-serberus", "/etc/sudoers.d/serberus", "coarse sudoers drop-in"),
            ("pam-sudo_local", "/etc/pam.d/sudo_local", "PAM wiring"),
        ]
        for item in wiring {
            guard fileManager.fileExists(atPath: item.path) else {
                unavailable[item.name] = "\(item.detail) not present at \(item.path)"
                continue
            }
            do {
                try Self.copyRegularFileNoFollow(from: item.path,
                                                 to: directory.appendingPathComponent(item.name).path)
                files.append(item.name)
            } catch {
                unavailable[item.name] = error.localizedDescription
            }
        }
    }

    // MARK: Hand-off

    /// Gives the directory and its contents to the caller, and nobody else.
    ///
    /// 0700/0600 + chown means one user's capture is not readable by another
    /// local user — which the world-readable JSONL cannot offer. The unified
    /// log spans every user on the Mac, so this is the only isolation there is.
    private func handOff(directory: URL, to uid: uid_t) throws {
        try Self.handOffNoFollow(directory: directory.path, to: uid)
    }

    /// Changes owner and mode through descriptors opened with `O_NOFOLLOW`, so
    /// root never changes a symlink's target. Anything in the directory that is
    /// not a regular file (a symlink above all) is refused: it is removed, not
    /// handed over. The collector only ever writes regular files here, so such
    /// an entry is out of place.
    static func handOffNoFollow(directory: String, to uid: uid_t) throws {
        let dirFD = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else { throw CocoaError(.fileNoSuchFile, userInfo: [NSFilePathErrorKey: directory]) }
        defer { close(dirFD) }
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [] {
            guard entry != ".", entry != "..", !entry.contains("/") else { continue }
            var info = stat()
            guard fstatat(dirFD, entry, &info, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
            guard (info.st_mode & S_IFMT) == S_IFREG else {
                if (info.st_mode & S_IFMT) != S_IFDIR { unlinkat(dirFD, entry, 0) }
                continue
            }
            let fd = openat(dirFD, entry, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { continue }
            var opened = stat()
            if fstat(fd, &opened) == 0, (opened.st_mode & S_IFMT) == S_IFREG {
                _ = fchown(fd, uid, gid_t.max)
                _ = fchmod(fd, 0o600)
            }
            close(fd)
        }
        guard fchown(dirFD, uid, gid_t.max) == 0, fchmod(dirFD, 0o700) == 0 else {
            throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: directory])
        }
    }

    /// Copies `source` into a new file at `destination` by content. The source
    /// is opened with `O_NOFOLLOW` and must be a regular file: a symlink is
    /// refused rather than copied as a link (which the hand-off would then
    /// have to treat specially) or followed to some other file.
    static func copyRegularFileNoFollow(from source: String, to destination: String) throws {
        let input = open(source, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard input >= 0 else {
            throw CocoaError(.fileReadNoPermission, userInfo: [
                NSFilePathErrorKey: source,
                NSLocalizedDescriptionKey: "\(source) could not be opened (not copied if it is a symlink)",
            ])
        }
        defer { close(input) }
        var info = stat()
        guard fstat(input, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw CocoaError(.fileReadUnknown, userInfo: [
                NSFilePathErrorKey: source, NSLocalizedDescriptionKey: "\(source) is not a regular file",
            ])
        }
        let output = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: destination]) }
        defer { close(output) }
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(input, $0.baseAddress, $0.count) }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                throw CocoaError(.fileReadUnknown, userInfo: [NSFilePathErrorKey: source])
            }
            var offset = 0
            while offset < count {
                let written = buffer.withUnsafeBytes { write(output, $0.baseAddress! + offset, count - offset) }
                guard written > 0 else {
                    if written < 0, errno == EINTR { continue }
                    throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: destination])
                }
                offset += written
            }
        }
    }

    /// Removes hand-off directories older than ``handoffTTL``.
    private func sweepStaleHandoffs() {
        let root = URL(fileURLWithPath: BundleConfig.captureHandoffDirectory, isDirectory: true)
        guard let entries = try? fileManager.contentsOfDirectory(
            at: root, includingPropertiesForKeys: [.contentModificationDateKey]
        ) else { return }

        let cutoff = Date().addingTimeInterval(-Self.handoffTTL)
        for entry in entries {
            let modified = (try? entry.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate
            if let modified, modified > cutoff { continue }
            // NOT `FileManager.removeItem`: a handed-off directory is owned by
            // the caller, who can place anything inside it — including a
            // symlink to a root-owned tree. The no-follow walk only ever unlinks
            // the link itself.
            _ = Self.removeTreeNoFollow(parent: root.path, name: entry.lastPathComponent)
        }
    }

    /// Deepest directory nesting the no-follow removal descends into. A user
    /// can nest their own hand-off arbitrarily; beyond this the rest is left in
    /// place (it is the user's own junk) rather than exhausting fds / stack.
    static let maxRemovalDepth = 64

    /// Removes `parent/name` recursively WITHOUT ever following a symlink: every
    /// step is relative to an already-open directory fd (`openat` with
    /// `O_NOFOLLOW | O_DIRECTORY`, `fstatat(AT_SYMLINK_NOFOLLOW)`, `unlinkat`),
    /// so a symlink — at any depth, or swapped in mid-walk — is unlinked as a
    /// link, never traversed. Returns true when `name` no longer exists.
    static func removeTreeNoFollow(parent: String, name: String) -> Bool {
        let parentFD = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { return false }
        defer { close(parentFD) }
        return removeEntryNoFollow(parentFD: parentFD, name: name, depth: 0)
    }

    private static func removeEntryNoFollow(parentFD: Int32, name: String, depth: Int) -> Bool {
        guard name != ".", name != "..", !name.isEmpty, !name.contains("/") else { return false }
        var info = stat()
        guard fstatat(parentFD, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { return errno == ENOENT }

        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            // Regular file, symlink (the LINK is removed), fifo, … — never followed.
            return unlinkat(parentFD, name, 0) == 0 || errno == ENOENT
        }
        guard depth < maxRemovalDepth else { return false }

        let directoryFD = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { return false } // swapped for a symlink: refuse
        defer { close(directoryFD) }

        for child in directoryEntries(of: directoryFD) {
            _ = removeEntryNoFollow(parentFD: directoryFD, name: child, depth: depth + 1)
        }
        return unlinkat(parentFD, name, AT_REMOVEDIR) == 0 || errno == ENOENT
    }

    /// Names in the directory open at `fd` (excluding `.`/`..`). Reads through a
    /// `dup` so the caller's fd stays open and owned by the caller.
    private static func directoryEntries(of fd: Int32) -> [String] {
        let duplicate = dup(fd)
        guard duplicate >= 0 else { return [] }
        guard let stream = fdopendir(duplicate) else {
            close(duplicate)
            return []
        }
        defer { closedir(stream) }
        var names: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            if name != ".", name != ".." { names.append(name) }
        }
        return names
    }

    /// Bounded wait. Returns false on timeout.
    private static func wait(for process: Process, timeout: TimeInterval) -> Bool {
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        // Safe with no pipe: nothing can block on an undrained buffer, so the
        // child either finishes or is killed.
        return exited.wait(timeout: .now() + timeout) == .success
    }

    public enum CollectorError: Error, LocalizedError, Equatable {
        case invalidWindow(String)
        case invalidCaller
        case logFailed(String)

        public var errorDescription: String? {
            switch self {
            case let .invalidWindow(window):
                return "unsupported capture window '\(window)'"
            case .invalidCaller:
                return "capture requires an unprivileged calling user"
            case let .logFailed(reason):
                return reason
            }
        }
    }
}
