import Foundation
import os
import PrivMgrCore
import Security
import Synchronization

/// Detail log for Install/Uninstall with Serberus. Failure details (paths,
/// errno, tool output) go here, never back to the caller.
let appManagementLog = Logger(subsystem: BundleConfig.logSubsystem, category: "app-management")

// MARK: - Command runner seam

/// Runs a pinned tool and returns its status + captured output. Injected so the
/// installer's staging/verification/commit logic is unit-testable without a real
/// `installer`/`spctl`/`pkgutil`/`cp`/`ditto` — the production impl wraps ``ProcessCommandRunner``.
public protocol InstallCommandRunning: Sendable {
    /// Runs `path` with `arguments` under a wall-clock timeout. A launch failure
    /// or timeout returns a non-zero status (never throws) so callers fail closed.
    func run(_ path: String, _ arguments: [String], timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String)

    /// Runs `path` with `arguments` as `user` — real, effective and saved uid
    /// and gid — starting in `workingDirectory`, under a wall-clock timeout.
    /// The directory is opened by the (root) caller and entered by descriptor,
    /// so the child needs search permission on it alone, not on its
    /// ancestors. A launch failure, a child that didn't get exactly that
    /// identity, or a timeout returns a non-zero status.
    func runAsUser(_ path: String, _ arguments: [String], user: FileOwner, workingDirectory: String,
                   timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String)
}

extension InstallCommandRunning {
    /// Runners that can't drop privileges refuse (fail closed).
    public func runAsUser(_ path: String, _ arguments: [String], user: FileOwner, workingDirectory: String,
                          timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
        (-1, "", "running as another user isn't supported by this runner")
    }
}

public struct SystemInstallCommandRunner: InstallCommandRunning {
    public init() {}
    public func run(_ path: String, _ arguments: [String], timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
        do {
            let r = try await ProcessCommandRunner.execute(path: path, arguments: arguments, timeout: timeout)
            return (r.timedOut ? 124 : r.status, r.stdout, r.stderr)
        } catch {
            return (-1, "", String(describing: error))
        }
    }

    public func runAsUser(_ path: String, _ arguments: [String], user: FileOwner, workingDirectory: String,
                          timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
        await UserSpawn.run(path, arguments, user: user, workingDirectory: workingDirectory, timeout: timeout)
    }
}

// MARK: - Running a tool as the requesting user

/// Spawns a pinned tool with the requesting user's identity, so the kernel
/// applies that user's permissions (mode bits, ACLs, directory search,
/// sandbox-free file access) to everything the tool opens.
///
/// How the identity is dropped, without a helper binary and without
/// `fork()` in a multithreaded daemon: a dedicated, short-lived thread
/// assumes the user's uid and gid with `pthread_setugid_np` (a per-thread
/// credential; the rest of the daemon stays root), calls `posix_spawn` —
/// a child is created with the credential of the thread that spawns it —
/// then reverts and exits. The child is spawned suspended
/// (`POSIX_SPAWN_START_SUSPENDED`) and resumed only after
/// `proc_pidinfo(PROC_PIDTBSDINFO)` shows that its real, effective and
/// saved uid and gid are exactly the user's; anything else is killed and
/// reported as a failure. The child also gets:
/// - no inherited descriptors (`POSIX_SPAWN_CLOEXEC_DEFAULT`) besides
///   `/dev/null` on stdin/stdout and a pipe on stderr, so no root-opened
///   file reaches a process the user can signal;
/// - its working directory by descriptor (`posix_spawn_file_actions_addfchdir`),
///   opened by root without following a symlink, so it needn't be able to
///   traverse the root-only directories above it;
/// - default signal handlers, an empty signal mask and a fixed `PATH`.
/// On timeout the child gets `SIGKILL`. When the daemon already runs as the
/// user (tests), no identity is assumed and the same checks still apply.
///
/// The child has the user's primary group only, not their supplementary
/// groups: the per-thread credential carries just the one gid, and the calls
/// that set a group list (`setgroups`, `initgroups`) act on the whole daemon
/// and need root, which the thread no longer is once it has assumed the
/// user. An item readable only through a supplementary group therefore
/// can't be staged, and the install says so.
enum UserSpawn {
    private typealias SetUGID = @convention(c) (uid_t, gid_t) -> Int32
    /// `pthread_setugid_np`, bound with `dlsym`: the SDK marks it deprecated
    /// (per-thread identities are easy to leak), and here it is confined to a
    /// thread that exits right after the spawn.
    private static let setUGID: SetUGID? = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "pthread_setugid_np") else { return nil }
        return unsafeBitCast(symbol, to: SetUGID.self)
    }()
    /// `KAUTH_UID_NONE` / `KAUTH_GID_NONE`: revert to the process identity.
    private static let noUID = uid_t.max - 100
    private static let noGID = gid_t.max - 100
    /// Largest stderr kept for the log.
    private static let maxStderrBytes = 16 * 1024

    struct Spawned: Sendable { let pid: pid_t; let stderr: Int32 }

    static func run(_ path: String, _ arguments: [String], user: FileOwner, workingDirectory: String,
                    timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
        guard user.uid != 0 else { return (-1, "", "refusing to run as root") }
        let directory = open(workingDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { return (-1, "", "working directory: errno \(errno)") }
        defer { close(directory) }
        return await run(path, arguments, user: user, directory: directory, timeout: timeout)
    }

    /// ``run(_:_:user:workingDirectory:timeout:)`` with the working directory
    /// already open (`directory`, which stays the caller's to close).
    static func run(_ path: String, _ arguments: [String], user: FileOwner, directory: Int32,
                    timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
        guard user.uid != 0 else { return (-1, "", "refusing to run as root") }
        let spawned: Result<Spawned, SpawnError> = await withCheckedContinuation { continuation in
            let thread = Thread {
                continuation.resume(returning: spawnSuspended(path, arguments, user: user, directory: directory))
            }
            thread.start()
        }
        let child: Spawned
        switch spawned {
        case let .success(value): child = value
        case let .failure(error): return (-1, "", error.description)
        }
        defer { close(child.stderr) }
        guard hasIdentity(child.pid, user) else {
            kill(child.pid, SIGKILL)
            _ = reap(child.pid, blocking: true)
            return (-1, "", "the child didn't run as the requesting user")
        }
        kill(child.pid, SIGCONT)
        var stderr = Data()
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            drain(child.stderr, into: &stderr)
            if let status = reap(child.pid, blocking: false) {
                drain(child.stderr, into: &stderr)
                return (status, "", String(decoding: stderr, as: UTF8.self))
            }
            if Date() >= deadline {
                kill(child.pid, SIGKILL)
                _ = reap(child.pid, blocking: true)
                return (124, "", String(decoding: stderr, as: UTF8.self))
            }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    struct SpawnError: Error, CustomStringConvertible {
        let description: String
    }

    /// Runs on its own thread: assumes the user's identity (unless already
    /// running as them), spawns the child suspended, reverts.
    private static func spawnSuspended(_ path: String, _ arguments: [String], user: FileOwner,
                                       directory: Int32) -> Result<Spawned, SpawnError> {
        var pipeFDs: [Int32] = [-1, -1]
        guard pipe(&pipeFDs) == 0 else { return .failure(SpawnError(description: "pipe: errno \(errno)")) }
        _ = fcntl(pipeFDs[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(pipeFDs[0], F_SETFL, O_NONBLOCK)
        defer { close(pipeFDs[1]) }

        var attributes: posix_spawnattr_t?
        var actions: posix_spawn_file_actions_t?
        guard posix_spawnattr_init(&attributes) == 0 else { close(pipeFDs[0]); return .failure(SpawnError(description: "spawnattr")) }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_init(&actions) == 0 else { close(pipeFDs[0]); return .failure(SpawnError(description: "file actions")) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        var allSignals = sigset_t(), noSignals = sigset_t()
        sigfillset(&allSignals)
        sigemptyset(&noSignals)
        let flags = POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK
        guard posix_spawnattr_setflags(&attributes, Int16(flags)) == 0,
              posix_spawnattr_setsigdefault(&attributes, &allSignals) == 0,
              posix_spawnattr_setsigmask(&attributes, &noSignals) == 0,
              posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], 2) == 0,
              posix_spawn_file_actions_addfchdir(&actions, directory) == 0 else {
            close(pipeFDs[0])
            return .failure(SpawnError(description: "spawn setup"))
        }

        let assume = geteuid() != user.uid || getegid() != user.gid
        if assume {
            guard let setUGID, setUGID(user.uid, user.gid) == 0 else {
                close(pipeFDs[0])
                return .failure(SpawnError(description: "couldn't assume the user's identity (errno \(errno))"))
            }
        }
        defer { if assume { _ = setUGID?(noUID, noGID) } }

        let argv: [UnsafeMutablePointer<CChar>?] = ([path] + arguments).map { strdup($0) } + [nil]
        let envp: [UnsafeMutablePointer<CChar>?] = [strdup("PATH=/usr/bin:/bin:/usr/sbin:/sbin"), nil]
        defer { (argv + envp).forEach { free($0) } }
        var pid: pid_t = 0
        let status = posix_spawn(&pid, path, &actions, &attributes, argv, envp)
        guard status == 0 else {
            close(pipeFDs[0])
            return .failure(SpawnError(description: "posix_spawn: errno \(status)"))
        }
        return .success(Spawned(pid: pid, stderr: pipeFDs[0]))
    }

    /// Whether the (suspended) process `pid` has exactly `user`'s real,
    /// effective and saved uid and gid.
    private static func hasIdentity(_ pid: pid_t, _ user: FileOwner) -> Bool {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return false }
        return info.pbi_uid == user.uid && info.pbi_ruid == user.uid && info.pbi_svuid == user.uid
            && info.pbi_gid == user.gid && info.pbi_rgid == user.gid && info.pbi_svgid == user.gid
    }

    /// The exit status of `pid` once it has exited (a signal death is
    /// 128 + signal), or nil while it runs (non-blocking).
    private static func reap(_ pid: pid_t, blocking: Bool) -> Int32? {
        var status: Int32 = 0
        while true {
            let result = waitpid(pid, &status, blocking ? 0 : WNOHANG)
            if result == -1, errno == EINTR { continue }
            guard result == pid else { return result == 0 ? nil : -1 }
            let signal = status & 0x7F
            return signal == 0 ? (status >> 8) & 0xFF : 128 + signal
        }
    }

    /// Reads what's available on the non-blocking `fd`, keeping at most
    /// ``maxStderrBytes``.
    private static func drain(_ fd: Int32, into data: inout Data) {
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { return }
            if data.count < maxStderrBytes { data.append(contentsOf: buffer[0..<min(n, maxStderrBytes - data.count)]) }
        }
    }
}

/// The owner every file of a root-installed item must carry. `root:wheel` in
/// production; tests (which can't chown to root) inject their own uid/gid.
public struct FileOwner: Sendable, Equatable {
    public let uid: uid_t
    public let gid: gid_t
    public init(uid: uid_t, gid: gid_t) { self.uid = uid; self.gid = gid }
    public static let rootWheel = FileOwner(uid: 0, gid: 0)
}

// MARK: - Concurrency cap

/// Caps concurrent Install/Uninstall with Serberus requests: at most
/// ``defaultPerUserLimit`` in flight per requesting uid and
/// ``defaultTotalLimit`` per daemon. A request that would exceed either is
/// refused immediately ("busy") instead of queueing, so one user can't pile up
/// root-side staging work. Also records which staging IDs are live, so a sweep
/// never removes a request that is still running.
public final class AppManagementGate: Sendable {
    /// The daemon-wide gate shared by the installer and the uninstaller.
    public static let shared = AppManagementGate()
    public static let defaultPerUserLimit = 1
    public static let defaultTotalLimit = 2

    private struct State {
        var perUID: [uid_t: Int] = [:]
        var total = 0
        var stageIDs: Set<String> = []
    }

    private let state = Mutex(State())
    private let perUserLimit: Int
    private let totalLimit: Int

    public init(perUserLimit: Int = AppManagementGate.defaultPerUserLimit,
                totalLimit: Int = AppManagementGate.defaultTotalLimit) {
        self.perUserLimit = perUserLimit
        self.totalLimit = totalLimit
    }

    /// Reserves a slot for `uid` (and marks `stageID` live), or false when the
    /// per-user or daemon-wide cap is reached. Pair with ``release(uid:stageID:)``.
    func acquire(uid: uid_t, stageID: String? = nil) -> Bool {
        state.withLock { s in
            guard s.total < totalLimit, s.perUID[uid, default: 0] < perUserLimit else { return false }
            s.total += 1
            s.perUID[uid, default: 0] += 1
            if let stageID { s.stageIDs.insert(stageID) }
            return true
        }
    }

    func release(uid: uid_t, stageID: String? = nil) {
        state.withLock { s in
            s.total = max(0, s.total - 1)
            let remaining = s.perUID[uid, default: 0] - 1
            s.perUID[uid] = remaining > 0 ? remaining : nil
            if let stageID { s.stageIDs.remove(stageID) }
        }
    }

    /// Whether a request using `stageID` is currently in flight.
    func isActive(stageID: String) -> Bool {
        state.withLock { $0.stageIDs.contains(stageID) }
    }

    static let busyResult = InstallResult(
        status: .failed,
        message: "Serberus is busy with another install or uninstall. Try again when it finishes.")
}

// MARK: - Confirmation + audit

/// What the user is asked to approve — built only from the verified, staged
/// item (never from client-supplied text).
public struct InstallConfirmation: Sendable, Equatable {
    /// Headline: the staged app's `CFBundleName`, or the package's file name.
    public let headline: String
    /// The canonical path of the source the user chose.
    public let canonicalPath: String
    public let kind: SoftwareInstaller.Kind
    /// The verified signing authority (leaf certificate name).
    public let authority: String
    /// The verified publisher Team ID.
    public let teamID: String
    /// The staged app's bundle ID (apps only).
    public let bundleID: String?
    /// The staged app's version (apps only).
    public let version: String?
}

/// What the daemon records about an install attempt, filled in as far as the
/// pipeline got. Never returned to the caller.
public struct InstallAudit: Sendable, Equatable {
    public var canonicalPath: String?
    public var headline: String?
    public var bundleID: String?
    public var teamID: String?
    public init() {}
}

// MARK: - Installer

/// Installs a user-chosen `.pkg` (via `installer`) or copies a user-chosen `.app`
/// (via `ditto`) into `/Applications`, **as root** — the product's only run-as-root
/// verb. Guarded by these, in order, every one fail-closed:
///
/// 1. **Policy + concurrency gate** — refuses unless the install-software rule
///    is enabled, and when the caller (or the daemon) already has the maximum
///    number of app-management requests in flight.
/// 2. **Source checks** — the source must canonicalize, and its top item is
///    pinned by device + inode (opened `O_NOFOLLOW`, then `fstat`). The tree
///    is then walked through descriptors (`open`/`openat` with `O_NOFOLLOW`,
///    `fstatat(AT_SYMLINK_NOFOLLOW)`), never following a symlink: every entry
///    must be readable by the requesting user from its owner, group and mode
///    and any ACL deny entry, no regular file may have a second hard link, no
///    FIFOs/sockets/devices, ≤ ``maxSourceBytes`` (extended attributes
///    included) and ≤ ``maxSourceEntries``, with enough free space for the
///    copies.
/// 3. **Staging** — copies the source BEFORE verifying, under a daemon-chosen
///    constant name (`item.pkg` / `item.app`), so neither the user-writable
///    source nor the user's file name reaches anything that is verified or
///    parsed. The copy itself (`cp`) runs AS THE REQUESTING USER into a folder only
///    that copy can reach inside the root-only (0700) stage dir, so root is
///    never used to read something the user can't, whatever the source path
///    leads to by then (``stageCopyAsUser(_:stageDir:stagedName:user:)``).
///    Root then takes the copy back, re-owns it `root:wheel` and strips BSD
///    flags, group/other write, set-id bits and ACLs, never following a
///    symlink (system flags are refused). The source must still be the
///    pinned item after the copy, and the copy is re-scanned under the same
///    rules. Everything after this touches ONLY the staged copy.
/// 4. **Trust gate** — Gatekeeper (`spctl --assess`) must accept the staged copy
///    (exit status + a strictly-parsed `source=` line for notarization). The
///    publisher (Team ID) and the authority shown to the user come from a
///    structured source: the code signature (`SecStaticCode`, Developer ID
///    requirement) for an app, `pkgutil --check-signature` for a package — and
///    must agree with Gatekeeper's `origin=` team.
/// 5. **Content gate** — a package must not declare relocatable bundles (which
///    would let `installer` redirect a component onto a user-controlled copy)
///    or refer to content that wasn't inspected, every install location it
///    declares must be root-only, and no payload path may be one the
///    requesting user could redirect; an app may replace only a Developer-ID
///    app from the same publisher with the same bundle ID whose version is
///    the same or older on a comparable key, and never downgrades a copy of
///    itself installed under another name.
/// 6. **Pinned exec** — `installer`/`ditto` run from pinned absolute paths with
///    argv arrays (never a shell) and a timeout, targeting the pinned `/`
///    or `/Applications`. An app is copied from the root-owned staged copy into a
///    root-owned temporary sibling, re-checked to be `root:wheel` throughout, and
///    only then renamed into place.
///
/// A caller UID is required (the console user); uid 0 is refused. Never throws to
/// the XPC layer — every path returns an ``InstallResult``. Error messages to the
/// caller are generic; details go to the daemon log only.
public struct SoftwareInstaller: Sendable {
    public enum Kind: Sendable, Equatable { case pkg, app }

    /// A verified code signer: its Team ID and the leaf certificate's name
    /// (e.g. "Developer ID Installer: Acme Inc (AB12CD34EF)"), shown to the user.
    public struct Signer: Sendable, Equatable {
        public let teamID: String
        public let authority: String
        public init(teamID: String, authority: String) { self.teamID = teamID; self.authority = authority }
    }

    /// Size/entry budget for a source tree staged as root.
    public struct SourceLimits: Sendable, Equatable {
        public var maxBytes: UInt64
        public var maxEntries: Int
        public init(maxBytes: UInt64, maxEntries: Int) { self.maxBytes = maxBytes; self.maxEntries = maxEntries }
        public static let standard = SourceLimits(maxBytes: SoftwareInstaller.maxSourceBytes,
                                                  maxEntries: SoftwareInstaller.maxSourceEntries)
    }

    /// What Gatekeeper said about the staged item, from a strict parse.
    struct GatekeeperVerdict: Sendable, Equatable {
        let source: String
        let origin: String
    }

    static let notarizedSource = "Notarized Developer ID"
    static let developerIDSource = "Developer ID"
    /// The only `pkgutil --check-signature` status accepted: a Developer ID
    /// (distribution) certificate. Every other status pkgutil can print —
    /// untrusted, expired, locally trusted, development, TestFlight, App Store,
    /// "trusted by macOS" (Apple's own) — is refused.
    static let pkgutilDeveloperIDStatus = "signed by a developer certificate issued by Apple for distribution"
    /// Code requirement for an app signer: chains to Apple, issued by the
    /// Developer ID CA (1.2.840.113635.100.6.2.6), with a Developer ID
    /// Application leaf (1.2.840.113635.100.6.1.13).
    static let developerIDAppRequirement =
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"

    /// Staging budget: total bytes of a source tree.
    public static let maxSourceBytes: UInt64 = 4 << 30          // 4 GiB
    /// Staging budget: entries (files, dirs, links) in a source tree.
    public static let maxSourceEntries = 200_000
    /// Free space that must remain on the staging volume beyond the copies.
    public static let freeSpaceMargin: UInt64 = 1 << 30          // 1 GiB
    /// Wall-clock budget for staging copies and package expansion.
    static let stagingTimeout: TimeInterval = 120
    /// Default wall-clock budget for one install (large packages take a while).
    public static let defaultInstallTimeout: TimeInterval = 1800
    /// Name prefix of the temporary sibling an app is copied to in /Applications.
    static let tempAppPrefix = ".serberus-install-"

    private let runner: InstallCommandRunning
    private let stagingRoot: URL
    private let applicationsDir: URL
    private let now: @Sendable () -> Date
    /// Wall-clock budget for `installer` and the /Applications copy.
    private let installTimeout: TimeInterval
    /// The verified signer of an app bundle, or nil. Injected for tests; the
    /// default requires a Developer ID signature (``signingIdentity(ofAppAt:)``).
    private let signerOfApp: @Sendable (String) -> Signer?
    /// Owner stamped on (and required of) every installed file.
    private let installOwner: FileOwner
    private let gate: AppManagementGate
    private let sourceLimits: SourceLimits
    /// Available bytes on the volume holding a path (nil = unknown ⇒ refuse).
    private let freeSpace: @Sendable (String) -> UInt64?
    /// Whether `uid` may read the (canonical) source path.
    private let callerCanRead: @Sendable (String, uid_t) -> Bool
    /// The caller's primary and supplementary groups (nil = unknown ⇒ refuse),
    /// used to check that the caller could read every entry of the source.
    private let callerGroups: @Sendable (uid_t) -> Set<gid_t>?
    /// Whether a package's declared install location is root-only.
    private let installLocationIsRootOnly: @Sendable (String) -> Bool
    /// The identity the staging copy runs as for a caller uid: the uid and
    /// its primary group (nil = unknown ⇒ refuse).
    private let stagingUser: @Sendable (uid_t) -> FileOwner?

    public init(
        runner: InstallCommandRunning = SystemInstallCommandRunner(),
        stagingRoot: URL = URL(fileURLWithPath: BundleConfig.installStagingDirectory, isDirectory: true),
        applicationsDir: URL = URL(fileURLWithPath: BundleConfig.applicationsDirectory, isDirectory: true),
        installTimeout: TimeInterval = SoftwareInstaller.defaultInstallTimeout,
        now: @escaping @Sendable () -> Date = { Date() },
        installOwner: FileOwner = .rootWheel,
        gate: AppManagementGate = .shared,
        sourceLimits: SourceLimits = .standard,
        freeSpace: @escaping @Sendable (String) -> UInt64? = { SoftwareInstaller.availableBytes(onVolumeOf: $0) },
        callerCanRead: @escaping @Sendable (String, uid_t) -> Bool = { SoftwareInstaller.uidCanRead($0, uid: $1) },
        callerGroups: @escaping @Sendable (uid_t) -> Set<gid_t>? = { SoftwareInstaller.groupIDs(ofUID: $0) },
        installLocationIsRootOnly: @escaping @Sendable (String) -> Bool = { SoftwareInstaller.isRootOnlyInstallLocation($0) },
        stagingUser: @escaping @Sendable (uid_t) -> FileOwner? = { SoftwareInstaller.userIdentity(ofUID: $0) },
        signerOfApp: @escaping @Sendable (String) -> Signer? = { SoftwareInstaller.signingIdentity(ofAppAt: $0) }
    ) {
        self.runner = runner
        self.stagingRoot = stagingRoot
        self.applicationsDir = applicationsDir
        self.installTimeout = installTimeout
        self.now = now
        self.installOwner = installOwner
        self.gate = gate
        self.sourceLimits = sourceLimits
        self.freeSpace = freeSpace
        self.callerCanRead = callerCanRead
        self.callerGroups = callerGroups
        self.installLocationIsRootOnly = installLocationIsRootOnly
        self.stagingUser = stagingUser
        self.signerOfApp = signerOfApp
    }

    /// Runs the full pipeline for one request. `confirm` is the confirmation gate
    /// (the daemon wires it to the Sentinel prompt); it is consulted only AFTER
    /// the trust gate passes, so the user is never asked to approve something
    /// that would be refused anyway. `stageID` names the per-request staging
    /// subdir (the daemon passes a fresh UUID; injectable for deterministic tests).
    public func install(
        _ request: InstallRequest,
        callerUID: uid_t,
        policy: InstallPolicy,
        stageID: String,
        confirm: @Sendable (InstallConfirmation) async -> Bool
    ) async -> InstallResult {
        await installAudited(request, callerUID: callerUID, policy: policy, stageID: stageID, confirm: confirm).result
    }

    /// ``install(_:callerUID:policy:stageID:confirm:)`` plus what the daemon
    /// should record about the attempt (canonical path, bundle ID, team).
    public func installAudited(
        _ request: InstallRequest,
        callerUID: uid_t,
        policy: InstallPolicy,
        stageID: String,
        confirm: @Sendable (InstallConfirmation) async -> Bool
    ) async -> (result: InstallResult, audit: InstallAudit) {
        var audit = InstallAudit()
        let result = await runPipeline(request, callerUID: callerUID, policy: policy, stageID: stageID,
                                       confirm: confirm, audit: &audit)
        return (result, audit)
    }

    private func runPipeline(
        _ request: InstallRequest,
        callerUID: uid_t,
        policy: InstallPolicy,
        stageID: String,
        confirm: @Sendable (InstallConfirmation) async -> Bool,
        audit: inout InstallAudit
    ) async -> InstallResult {
        guard policy.installAllowed else {
            return InstallResult(status: .refusedByPolicy,
                                 message: "Install with Serberus is not enabled on this Mac (no app-management rule).")
        }
        guard callerUID != 0 else {
            return InstallResult(status: .failed, message: "Refused: install requests must come from a console user, not root.")
        }
        guard Self.isValidStageID(stageID) else {
            appManagementLog.error("install: invalid stage id")
            return InstallResult(status: .failed, message: "Couldn't prepare the install.")
        }
        guard gate.acquire(uid: callerUID, stageID: stageID) else {
            appManagementLog.notice("install: refused busy uid=\(callerUID, privacy: .public)")
            return AppManagementGate.busyResult
        }
        defer { gate.release(uid: callerUID, stageID: stageID) }

        // Every failure before staging gets the same message, naming the item
        // by the (sanitized) file name the caller sent — their own input — and
        // listing what's needed without saying which requirement failed, so
        // nothing about root's view of the filesystem (whether a path exists,
        // what kind of file or how big it is) is leaked. Details go to the log.
        let label = Self.displayLabel(forPath: request.sourcePath)
        let unusable = InstallResult(
            status: .failed,
            message: "Couldn't use “\(label)”. Install with Serberus needs a flat package (.pkg) or an app (.app) that you can read, of at most \(sourceLimits.maxBytes >> 30) GB and \(sourceLimits.maxEntries) files, with no hard-linked or special files.")

        // Canonicalize + classify the SOURCE (must exist; symlinks resolved;
        // control characters refused), then require the caller could read it.
        let canonical: String
        do {
            canonical = try PathCanonicalizer().canonicalize(request.sourcePath, existence: .requireExists)
        } catch {
            appManagementLog.error("install: source rejected: \(String(describing: error), privacy: .private)")
            return unusable
        }
        guard callerCanRead(canonical, callerUID) else {
            appManagementLog.notice("install: uid \(callerUID, privacy: .public) can't read \(canonical, privacy: .private)")
            return unusable
        }
        audit.canonicalPath = canonical
        guard let kind = Self.classify(canonical), let stagedName = Self.stagedItemName(forSource: canonical) else {
            appManagementLog.notice("install: not a .pkg or .app: \(canonical, privacy: .private)")
            return unusable
        }
        let fileName = URL(fileURLWithPath: canonical).lastPathComponent

        guard let groups = callerGroups(callerUID) else {
            appManagementLog.notice("install: groups of uid \(callerUID, privacy: .public) unknown")
            return unusable
        }
        let reader = SourceReader(uid: callerUID, groups: groups)
        guard let copyUser = stagingUser(callerUID), copyUser.uid != 0 else {
            appManagementLog.notice("install: identity of uid \(callerUID, privacy: .public) unknown")
            return unusable
        }
        // On a volume mounted with ownership ignored, root sees owners that
        // aren't what the kernel enforces for the user; there the copy's own
        // access checks (it runs as the user) decide what's readable.
        let preScanReader = Self.ignoresOwnership(canonical) ? nil : reader

        // PIN the source: open it from `/`, one component at a time, never
        // following a symlink and requiring the caller could search every
        // folder on the way, so a folder swapped for a symlink after the
        // checks above can't point root anywhere else. Then check and BUDGET
        // the whole tree through that descriptor before root copies any of
        // it: every entry must be readable by the caller, and no regular
        // file may be hard-linked.
        // The canonical path drops the `/private` of `/var`, `/tmp` and
        // `/etc` (system symlinks); anything else it resolves to now means
        // the path changed since it was canonicalized.
        let realSource = SoftwareUninstaller.realPath(canonical)
        guard realSource == canonical || realSource == "/private" + canonical,
              let source = Self.openSource(atPath: realSource, reader: preScanReader) else {
            appManagementLog.notice("install: couldn't open the source without following a symlink: \(canonical, privacy: .private)")
            return unusable
        }
        defer { close(source.fd) }
        let pinned = SoftwareUninstaller.FileID(source.info)
        // A flat package is a file (a folder named `.pkg`, a bundle-style
        // package, can't be checked the same way); an app is a folder.
        let sourceType = source.info.st_mode & S_IFMT
        guard sourceType == (kind == .pkg ? S_IFREG : S_IFDIR) else {
            appManagementLog.notice("install: source is a \(kind == .pkg ? "folder named .pkg (bundle-style package)" : "file named .app", privacy: .public)")
            return unusable
        }
        let sourceBytes: UInt64
        switch Self.scanSource(opened: source.fd, info: source.info, limits: sourceLimits, reader: preScanReader) {
        case let .ok(bytes, _):
            sourceBytes = bytes
        case let failure:
            appManagementLog.notice("install: source refused before staging: \(String(describing: failure), privacy: .private)")
            return unusable
        }

        // STAGE into a fresh root-only dir, under a constant name, before
        // touching anything else; then make the staged tree root-owned.
        sweepStaleStaging()
        let stageDir = stagingRoot.appendingPathComponent(stageID, isDirectory: true)
        let stagedItem = stageDir.appendingPathComponent(stagedName)
        let stagingFailed = InstallResult(status: .failed, message: "Couldn't stage “\(label)” for verification.")
        do {
            try Self.ensureStagingRoot(stagingRoot, owner: installOwner)
        } catch {
            appManagementLog.error("install: staging root: \(String(describing: error), privacy: .public)")
            return stagingFailed
        }
        // Room for the staged copy plus a second copy (the expanded package, or
        // the app's copy in /Applications), plus a margin.
        let needed = sourceBytes.multipliedReportingOverflow(by: 2).partialValue.addingReportingOverflow(Self.freeSpaceMargin)
        guard !needed.overflow, let available = freeSpace(stagingRoot.path), available >= needed.partialValue else {
            appManagementLog.notice("install: not enough free space (need \(needed.partialValue, privacy: .public))")
            return InstallResult(status: .failed, message: "Not enough free disk space to install “\(label)”.")
        }
        do {
            try Self.createRequestDir(stageDir)
        } catch {
            appManagementLog.error("install: request dir: \(String(describing: error), privacy: .public)")
            return stagingFailed
        }
        defer { FileTree.removeTreeLogged(atPath: stageDir.path, context: "staging dir") }
        // The copy runs AS THE REQUESTING USER (see ``stageCopyAsUser``), so
        // whatever the source path leads to by the time `cp` opens it —
        // even a symlink swapped in after the scan — is read with the user's
        // own permissions: root is never used to read something they can't.
        guard await stageCopyAsUser(canonical, stageDir: stageDir, stagedName: stagedName, user: copyUser) else {
            // The copy has the user's uid and primary group only (see
            // ``UserSpawn``): say so when that's why it couldn't read the item.
            if preScanReader != nil, reader.groups != [copyUser.gid],
               case .notReadableByCaller = Self.scanSource(opened: source.fd, info: source.info, limits: sourceLimits,
                                                           reader: SourceReader(uid: callerUID, groups: [copyUser.gid])) {
                appManagementLog.notice("install: staging copy failed; part of the source is readable only through a supplementary group")
                return InstallResult(status: .failed,
                                     message: "Couldn't copy “\(label)” for verification: some of its files can be read only through a group you're in other than your primary group, and Install with Serberus copies with your primary group only. Make those files readable by everyone, or ask IT to install it.")
            }
            return stagingFailed
        }
        // The source must still be the item that was scanned, and the COPY
        // must pass the same checks (with the caller's permissions, whatever
        // the volume): an entry swapped in after the scan is caught here.
        // Then make it root's.
        guard let reopened = Self.openSource(atPath: realSource, reader: nil) else {
            appManagementLog.notice("install: the source changed while it was being staged")
            return stagingFailed
        }
        let stillPinned = SoftwareUninstaller.FileID(reopened.info) == pinned
        close(reopened.fd)
        guard stillPinned else {
            appManagementLog.notice("install: the source changed while it was being staged")
            return stagingFailed
        }
        guard case .ok = Self.scanSource(atPath: stagedItem.path, limits: sourceLimits, reader: reader) else {
            appManagementLog.notice("install: staged copy failed the budget/type/readability re-check")
            return stagingFailed
        }
        guard Self.normalizeOwnership(atPath: stagedItem.path, owner: installOwner) else {
            appManagementLog.error("install: couldn't normalize the staged copy (system flags or chown/chmod failure)")
            return stagingFailed
        }

        // An app must be a real application bundle, and it is installed under
        // a name its own Info.plist declares, never just the name the user gave
        // the file (see ``installedAppName(info:fileName:)``).
        let stagedInfo = kind == .app ? SoftwareUninstaller.infoPlist(ofAppAt: stagedItem.path) : nil
        let appName: String
        switch kind {
        case .pkg:
            appName = fileName
        case .app:
            guard let stagedInfo, (stagedInfo["CFBundlePackageType"] as? String) == "APPL",
                  let identifier = stagedInfo["CFBundleIdentifier"] as? String, !identifier.isEmpty,
                  let name = Self.installedAppName(info: stagedInfo, fileName: fileName) else {
                appManagementLog.notice("install: not an application bundle with a bundle ID and a usable name")
                return InstallResult(status: .failed,
                                     message: "Refused “\(label)”: it isn't an application bundle Install with Serberus can install (it needs an Info.plist that declares an application, a bundle identifier and a name).")
            }
            appName = name
        }

        // TRUST GATE on the STAGED, root-owned copy (never the original).
        let trust = await assessTrust(stagedItem, kind: kind, policy: policy)
        guard trust.trusted, let teamID = trust.teamID else {
            return InstallResult(status: .refusedNotTrusted, message: "Refused “\(label)”: \(trust.detail)")
        }
        audit.teamID = teamID

        // What the prompt and the log call this item: from the staged bundle
        // (apps) or the package file name — never the client's displayName.
        let bundleID = stagedInfo?["CFBundleIdentifier"] as? String
        let headline = Self.headline(kind: kind, info: stagedInfo, fileName: appName)
        audit.bundleID = bundleID
        audit.headline = headline

        // PUBLISHER GATE: Gatekeeper vouches for the signature; the admin decides
        // whose software may run install scripts as root.
        guard policy.publisherAllowed(teamID: teamID) else {
            return InstallResult(status: .refusedNotTrusted,
                                 message: "Refused “\(headline)”: its publisher (\(trust.detail) [\(teamID)]) isn't on this Mac's list of allowed publishers.")
        }

        // CONTENT GATE. An app must not impersonate or replace Serberus, a
        // protected app, an app from a different publisher, or a newer version
        // (checked again at commit). A package must not be relocatable.
        switch kind {
        case .app:
            if let refusal = appPlacementRefusal(stagedItem, appName: appName, headline: headline,
                                                 teamID: teamID, policy: policy) {
                return refusal
            }
        case .pkg:
            if let refusal = await packageContentRefusal(stagedItem, stageDir: stageDir, headline: headline) {
                return refusal
            }
        }

        // Confirm (never silent by default), then COMMIT from the staged copy.
        // The prompt shows what was verified: the canonical path, the signer and
        // the Team ID.
        if policy.promptBeforeAction {
            let confirmation = InstallConfirmation(
                headline: headline, canonicalPath: canonical, kind: kind,
                authority: trust.detail, teamID: teamID, bundleID: bundleID,
                version: Self.displayVersion(stagedInfo))
            if await confirm(confirmation) == false {
                return InstallResult(status: .cancelled, message: "Install cancelled.")
            }
        }

        switch kind {
        case .pkg:  return await commitPkg(stagedItem, headline: headline, authority: trust.detail)
        case .app:  return await commitApp(stagedItem, stageDir: stageDir, stageID: stageID, appName: appName,
                                           headline: headline, authority: trust.detail, teamID: teamID, policy: policy)
        }
    }

    // MARK: Classification + naming

    /// A flat `.pkg` or an `.app`. A bundle-style `.mpkg` isn't supported: its
    /// signature and contents can't be checked the way a flat package's are.
    static func classify(_ path: String) -> Kind? {
        let lower = path.lowercased()
        if lower.hasSuffix(".pkg") { return .pkg }
        if lower.hasSuffix(".app") { return .app }
        return nil
    }

    /// The daemon-chosen name the item is staged under — never the user's file
    /// name, which would otherwise be echoed into `spctl`/`pkgutil` output.
    static func stagedItemName(forSource path: String) -> String? {
        let lower = path.lowercased()
        if lower.hasSuffix(".pkg") { return "item.pkg" }
        if lower.hasSuffix(".app") { return "item.app" }
        return nil
    }

    /// Stage IDs become path components: daemon UUIDs (letters, digits, `-`).
    static func isValidStageID(_ id: String) -> Bool {
        !id.isEmpty && id.count <= 64 && id.unicodeScalars.allSatisfy {
            ($0.isASCII && (CharacterSet.alphanumerics.contains($0))) || $0 == "-"
        }
    }

    /// An app's final name in /Applications: a visible `.app` name with no
    /// control characters (C0, DEL or C1), path separators, or invisible
    /// format characters (bidi overrides/isolates/marks, zero-width
    /// characters) that would let the name shown in Finder or the prompt
    /// differ from what it really is.
    static func isAcceptableAppName(_ name: String) -> Bool {
        name.lowercased().hasSuffix(".app") && name.count > 4 && !name.hasPrefix(".")
            && !name.contains("/") && !containsControlCharacter(name)
            && !containsFormatCharacter(name)
    }

    /// Whether `text` contains a control character: C0 (U+0000–U+001F), DEL,
    /// or C1 (U+0080–U+009F) — every Unicode `Cc` scalar.
    static func containsControlCharacter(_ text: String) -> Bool {
        PathCanonicalizer.containsControlCharacter(text) || text.unicodeScalars.contains(where: isControlScalar)
    }

    private static func isControlScalar(_ scalar: Unicode.Scalar) -> Bool {
        DisplayText.isControlScalar(scalar)
    }

    /// Whether `text` contains an invisible formatting character: any Unicode
    /// `Cf` scalar (which covers U+061C, U+200B–U+200F, U+202A–U+202E,
    /// U+2066–U+2069, U+FEFF) or a line/paragraph separator.
    static func containsFormatCharacter(_ text: String) -> Bool {
        text.unicodeScalars.contains(where: isFormatScalar)
    }

    private static func isFormatScalar(_ scalar: Unicode.Scalar) -> Bool {
        DisplayText.isFormatScalar(scalar)
    }

    /// `text` with control and format characters removed, trimmed and capped —
    /// safe to show in a prompt or message (``DisplayText/sanitized(_:maxLength:)``,
    /// which the Sentinel uses too).
    static func sanitizedForDisplay(_ text: String, maxLength: Int = 80) -> String {
        DisplayText.sanitized(text, maxLength: maxLength)
    }

    /// The caller's file name, sanitized, for messages before anything is verified.
    static func displayLabel(forPath path: String) -> String {
        let label = sanitizedForDisplay((path as NSString).lastPathComponent)
        return label.isEmpty ? "the selected item" : label
    }

    /// The prompt headline: an app's `CFBundleName` (when present and free of
    /// invisible characters), else its file name without `.app`; a package's
    /// file name.
    static func headline(kind: Kind, info: [String: Any]?, fileName: String) -> String {
        if kind == .app {
            if let name = info?["CFBundleName"] as? String, !containsFormatCharacter(name),
               !containsControlCharacter(name) {
                let clean = sanitizedForDisplay(name)
                if !clean.isEmpty { return clean }
            }
            let base = fileName.lowercased().hasSuffix(".app") ? String(fileName.dropLast(4)) : fileName
            let clean = sanitizedForDisplay(base)
            return clean.isEmpty ? "app" : clean
        }
        let clean = sanitizedForDisplay(fileName)
        return clean.isEmpty ? "package" : clean
    }

    /// Longest name, in UTF-8 bytes and without `.app`, an app is installed under.
    static let maxAppNameBytes = 200

    /// The name an app is installed under in /Applications: one its own
    /// Info.plist declares — `CFBundleDisplayName` or `CFBundleName` —
    /// cleaned like any name shown to a person (``DisplayText``), plus
    /// `.app`. The user's file name only chooses between the two: when it
    /// matches one of them (ignoring case), that one is used, in the
    /// bundle's spelling; otherwise the display name, else the bundle name.
    /// So a download renamed "Foo 2.app" still installs as "Foo.app", and no
    /// name a user types can squat another product's place in
    /// /Applications. A declared name that is empty, starts with `.`,
    /// contains `/` or `:`, or is longer than ``maxAppNameBytes`` isn't
    /// used; nil when neither is usable.
    static func installedAppName(info: [String: Any], fileName: String) -> String? {
        let candidates = ["CFBundleDisplayName", "CFBundleName"].compactMap { key -> String? in
            guard let raw = info[key] as? String else { return nil }
            let clean = DisplayText.sanitized(raw, maxLength: .max)
            guard !clean.isEmpty, clean.utf8.count <= maxAppNameBytes, !clean.contains(":"),
                  isAcceptableAppName(clean + ".app") else { return nil }
            return clean
        }
        let base = fileName.lowercased().hasSuffix(".app") ? String(fileName.dropLast(4)) : fileName
        let chosen = candidates.first { $0.caseInsensitiveCompare(base) == .orderedSame } ?? candidates.first
        return chosen.map { $0 + ".app" }
    }

    /// A human version for the prompt: `CFBundleShortVersionString` (build).
    static func displayVersion(_ info: [String: Any]?) -> String? {
        let short = (info?["CFBundleShortVersionString"] as? String).map { sanitizedForDisplay($0, maxLength: 32) }
        let build = (info?["CFBundleVersion"] as? String).map { sanitizedForDisplay($0, maxLength: 32) }
        switch (short, build) {
        case let (s?, b?) where !s.isEmpty && !b.isEmpty && s != b: return "\(s) (\(b))"
        case let (s?, _) where !s.isEmpty: return s
        case let (_, b?) where !b.isEmpty: return b
        default: return nil
        }
    }

    // MARK: Source access + budget

    /// Whether `uid` could read `path` itself: search permission on every
    /// ancestor directory and read (plus search, for a directory) on the item,
    /// evaluated from the owner/group/other mode bits against the uid and its
    /// group list. An ACL never grants (an ACL-only grant is refused, fail
    /// closed), but a deny entry for the uid or one of its groups removes the
    /// permission. Only the path is checked here; ``scanSource(atPath:limits:reader:expected:)``
    /// applies the same rule to every entry beneath it.
    public static func uidCanRead(_ path: String, uid: uid_t) -> Bool {
        guard let groups = groupIDs(ofUID: uid) else { return false }
        return self.uid(uid, groups: groups, canReadPath: SoftwareUninstaller.realPath(path))
    }

    static func uid(_ uid: uid_t, groups: Set<gid_t>, canReadPath path: String) -> Bool {
        guard path.hasPrefix("/") else { return false }
        var info = stat()
        let reader = SourceReader(uid: uid, groups: groups)
        guard lstat("/", &info) == 0, permits(info, uid: uid, groups: groups, want: S_IXOTH),
              !aclDenies(acl_get_link_np("/", ACL_TYPE_EXTENDED), want: S_IXOTH, isDirectory: true, reader: reader) else { return false }
        let components = path.split(separator: "/")
        var prefix = ""
        for (index, component) in components.enumerated() {
            prefix += "/" + component
            guard lstat(prefix, &info) == 0, info.st_mode & S_IFMT != S_IFLNK else { return false }
            let isLast = index == components.count - 1
            let isDirectory = info.st_mode & S_IFMT == S_IFDIR
            let want: mode_t = isLast ? (isDirectory ? (S_IROTH | S_IXOTH) : S_IROTH) : S_IXOTH
            guard permits(info, uid: uid, groups: groups, want: want),
                  !aclDenies(acl_get_link_np(prefix, ACL_TYPE_EXTENDED), want: want, isDirectory: isDirectory, reader: reader) else { return false }
        }
        return true
    }

    /// Classic owner → group → other permission check; `want` is in the
    /// "other" bit positions (`S_IROTH`, `S_IXOTH`).
    static func permits(_ info: stat, uid: uid_t, groups: Set<gid_t>, want: mode_t) -> Bool {
        if uid == 0 { return true }
        let mode = info.st_mode
        let bits: mode_t
        if info.st_uid == uid {
            bits = (mode >> 6) & 0o7
        } else if groups.contains(info.st_gid) {
            bits = (mode >> 3) & 0o7
        } else {
            bits = mode & 0o7
        }
        return bits & want == want
    }

    /// Whether an extended ACL (taken over; freed here) has a deny entry that
    /// applies to the object itself — not inherit-only — naming `reader`'s
    /// uid, or a group it is in, and denying part of `want` (`S_IROTH`: read
    /// data or list; `S_IXOTH`: search or execute). Deny entries are what the
    /// kernel checks before mode bits, so they take away what the mode grants.
    /// An entry that can't be read, or whose principal can't be resolved,
    /// counts as denying (fail closed). A nil ACL (none) denies nothing.
    static func aclDenies(_ acl: acl_t?, want: mode_t, isDirectory: Bool, reader: SourceReader) -> Bool {
        guard let acl else { return false }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var denied: [acl_perm_t] = []
        if want & S_IROTH != 0 { denied.append(isDirectory ? ACL_LIST_DIRECTORY : ACL_READ_DATA) }
        if want & S_IXOTH != 0 { denied.append(isDirectory ? ACL_SEARCH : ACL_EXECUTE) }
        var membership: ((gid_t) -> Bool)?
        var entry: acl_entry_t?
        var which = ACL_FIRST_ENTRY.rawValue
        while acl_get_entry(acl, which, &entry) == 0, let current = entry {
            which = ACL_NEXT_ENTRY.rawValue
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(current, &tag) == 0 else { return true }
            guard tag == ACL_EXTENDED_DENY else { continue }
            var flags: acl_flagset_t?
            guard acl_get_flagset_np(UnsafeMutableRawPointer(current), &flags) == 0, let flags else { return true }
            if acl_get_flag_np(flags, ACL_ENTRY_ONLY_INHERIT) == 1 { continue }
            var permset: acl_permset_t?
            guard acl_get_permset(current, &permset) == 0, let permset else { return true }
            guard denied.contains(where: { acl_get_perm_np(permset, $0) == 1 }) else { continue }
            guard let qualifier = acl_get_qualifier(current) else { return true }
            let principal = aclPrincipal(qualifier)
            acl_free(qualifier)
            guard let principal else { return true }
            if principal.isGroup {
                if reader.groups.contains(gid_t(principal.id)) { return true }
                if membership == nil { membership = SerberusBundleWritabilityPolicy.systemMembership(uid: reader.uid) }
                if membership?(gid_t(principal.id)) != false { return true }
            } else if uid_t(principal.id) == reader.uid {
                return true
            }
        }
        return false
    }

    /// The uid or gid an ACL qualifier (a 16-byte UUID) names, via
    /// `mbr_uuid_to_id` (`<membership.h>` isn't in Swift's Darwin module, so
    /// it's bound with `dlsym`). Nil when it can't be resolved.
    private static func aclPrincipal(_ qualifier: UnsafeMutableRawPointer) -> (id: UInt32, isGroup: Bool)? {
        typealias UUIDToID = @convention(c) (UnsafePointer<UInt8>, UnsafeMutablePointer<id_t>, UnsafeMutablePointer<Int32>) -> Int32
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "mbr_uuid_to_id") else { return nil }
        let uuidToID = unsafeBitCast(symbol, to: UUIDToID.self)
        var id: id_t = 0
        var type: Int32 = -1
        guard uuidToID(qualifier.assumingMemoryBound(to: UInt8.self), &id, &type) == 0 else { return nil }
        switch type {
        case 0: return (id, false)   // ID_TYPE_UID
        case 1: return (id, true)    // ID_TYPE_GID
        default: return nil
        }
    }

    /// Bytes of every extended attribute (a resource fork included) on the
    /// open `fd`, or nil when they can't be listed. Counted into the staging
    /// budget, because the staging copy (`cp`) copies them.
    static func extendedAttributeBytes(_ fd: Int32) -> UInt64? {
        let size = flistxattr(fd, nil, 0, 0)
        guard size >= 0 else { return nil }
        guard size > 0 else { return 0 }
        var names = [CChar](repeating: 0, count: size)
        let read = flistxattr(fd, &names, size, 0)
        guard read >= 0 else { return nil }
        var total: UInt64 = 0
        var start = 0
        while start < read {
            guard let end = names[start..<read].firstIndex(of: 0) else { return nil }
            let length = names[start..<end].withUnsafeBufferPointer { buffer -> Int in
                guard let base = buffer.baseAddress else { return -1 }
                return fgetxattr(fd, base, nil, 0, 0, 0)
            }
            guard length >= 0 else { return nil }
            total &+= UInt64(length)
            start = end + 1
        }
        return total
    }

    /// The uid's primary group plus its supplementary groups, or nil when the
    /// uid is unknown.
    public static func groupIDs(ofUID uid: uid_t) -> Set<gid_t>? {
        var pwd = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 4096)
        return buffer.withUnsafeMutableBufferPointer { buf -> Set<gid_t>? in
            guard getpwuid_r(uid, &pwd, buf.baseAddress, buf.count, &result) == 0, result != nil,
                  let name = pwd.pw_name else { return nil }
            var count: Int32 = 64
            var list = [Int32](repeating: 0, count: Int(count))
            while getgrouplist(name, Int32(bitPattern: pwd.pw_gid), &list, &count) == -1 {
                guard count < 4096 else { return nil }
                count *= 2
                list = [Int32](repeating: 0, count: Int(count))
            }
            var groups = Set(list.prefix(Int(max(0, count))).map { gid_t(bitPattern: $0) })
            groups.insert(pwd.pw_gid)
            return groups
        }
    }

    /// Who must be able to read every entry of a source: the requesting uid
    /// and its groups.
    struct SourceReader: Sendable, Equatable {
        let uid: uid_t
        let groups: Set<gid_t>
    }

    /// Outcome of walking a source tree against a ``SourceLimits`` budget.
    enum SourceScan: Equatable, Sendable {
        case ok(bytes: UInt64, entries: Int)
        /// A FIFO, socket or device at this relative path.
        case specialFile(String)
        /// A regular file with more than one hard link at this relative path.
        case hardLinked(String)
        /// An entry the reader couldn't read (or, for a directory, list and
        /// search) at this relative path.
        case notReadableByCaller(String)
        case tooLarge
        case tooManyEntries
        /// Missing, a symlink at the top, unopenable, too deep, or not the
        /// pinned item.
        case unreadable
    }

    /// The device + inode of the item at `path`, opened `O_NOFOLLOW` (and
    /// `O_NONBLOCK`, so nothing blocks) then `fstat`ed. Nil when it's missing,
    /// a symlink, or anything but a regular file or directory — a FIFO is
    /// never opened.
    static func sourceIdentity(atPath path: String) -> SoftwareUninstaller.FileID? {
        var before = stat()
        guard lstat(path, &before) == 0 else { return nil }
        let type = before.st_mode & S_IFMT
        guard type == S_IFREG || type == S_IFDIR else { return nil }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (type == S_IFDIR ? O_DIRECTORY : 0))
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == type,
              SoftwareUninstaller.FileID(info) == SoftwareUninstaller.FileID(before) else { return nil }
        return SoftwareUninstaller.FileID(info)
    }

    /// Opens the item at the absolute `path` from `/`, one component at a
    /// time with `openat`, never following a symlink: every folder on the
    /// way is opened `O_NOFOLLOW`, and must be searchable by `reader` (mode
    /// bits, and no ACL deny entry) when one is given; the item itself must
    /// be a regular file (opened non-blocking) or a directory, and the one
    /// `fstatat(AT_SYMLINK_NOFOLLOW)` classified. Returns the descriptor
    /// (the caller closes it) and its `fstat`, or nil — for a missing item,
    /// a symlink anywhere, a special file, or a folder the reader can't
    /// search — so root only ever examines what the path itself names.
    static func openSource(atPath path: String, reader: SourceReader?) -> (fd: Int32, info: stat)? {
        guard path.hasPrefix("/") else { return nil }
        let components = path.split(separator: "/").map(String.init)
        guard !components.isEmpty, !components.contains(".."), !components.contains(".") else { return nil }
        var directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard directory >= 0 else { return nil }
        defer { close(directory) }
        func searchable(_ fd: Int32) -> Bool {
            guard let reader else { return true }
            var info = stat()
            return fstat(fd, &info) == 0 && permits(info, uid: reader.uid, groups: reader.groups, want: S_IXOTH)
                && !aclDenies(acl_get_fd_np(fd, ACL_TYPE_EXTENDED), want: S_IXOTH, isDirectory: true, reader: reader)
        }
        guard searchable(directory) else { return nil }
        for component in components.dropLast() {
            let next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { return nil }
            close(directory)
            directory = next
            guard searchable(directory) else { return nil }
        }
        let name = components[components.count - 1]
        var before = stat()
        guard fstatat(directory, name, &before, AT_SYMLINK_NOFOLLOW) == 0 else { return nil }
        let type = before.st_mode & S_IFMT
        guard type == S_IFREG || type == S_IFDIR else { return nil }
        let fd = openat(directory, name, type == S_IFDIR ? (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                                                         : (O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
        guard fd >= 0 else { return nil }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == type,
              SoftwareUninstaller.FileID(info) == SoftwareUninstaller.FileID(before) else {
            close(fd)
            return nil
        }
        return (fd, info)
    }

    /// Walks the item at `path` through descriptors — `open`/`openat` with
    /// `O_NOFOLLOW` for directories, `O_SYMLINK | O_NONBLOCK` for everything
    /// else, then `fstat` checked against the `fstatat(AT_SYMLINK_NOFOLLOW)`
    /// that classified it — never following a symlink (a bundle's internal
    /// links are counted as entries, not followed) and never opening a FIFO,
    /// socket or device, so nothing can stall the walk. Every entry's size
    /// and extended attributes (resource forks included) count toward the
    /// byte budget. Stops at the first special file, hard-linked regular
    /// file, entry `reader` can't read (mode bits, or an ACL deny entry), or
    /// budget overrun. With `expected`, the top item must be that file.
    static func scanSource(atPath path: String, limits: SourceLimits, reader: SourceReader? = nil,
                           expected: SoftwareUninstaller.FileID? = nil) -> SourceScan {
        var top = stat()
        guard lstat(path, &top) == 0 else { return .unreadable }
        let type = top.st_mode & S_IFMT
        switch type {
        case S_IFREG, S_IFDIR: break
        case S_IFLNK: return .unreadable
        default: return .specialFile(".")
        }
        let fd = open(path, type == S_IFDIR ? (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                                            : (O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
        guard fd >= 0 else { return .unreadable }
        defer { close(fd) }
        var opened = stat()
        guard fstat(fd, &opened) == 0, SoftwareUninstaller.FileID(opened) == SoftwareUninstaller.FileID(top) else { return .unreadable }
        if let expected, SoftwareUninstaller.FileID(opened) != expected { return .unreadable }
        return scanSource(opened: fd, info: opened, limits: limits, reader: reader)
    }

    /// ``scanSource(atPath:limits:reader:expected:)`` of an item already
    /// open as `fd` (a regular file or a directory; `info` is its `fstat`).
    static func scanSource(opened fd: Int32, info opened: stat, limits: SourceLimits,
                           reader: SourceReader? = nil) -> SourceScan {
        let type = opened.st_mode & S_IFMT
        guard type == S_IFREG || type == S_IFDIR else { return .specialFile(".") }
        guard limits.maxEntries >= 1 else { return .tooManyEntries }
        var tally = (bytes: UInt64(0), entries: 1)
        if let failure = checkEntry(fd, opened, relative: ".", limits: limits, reader: reader, tally: &tally) { return failure }
        if type == S_IFDIR,
           let failure = scanDirectory(fd, prefix: "", depth: 0, limits: limits, reader: reader, tally: &tally) { return failure }
        return .ok(bytes: tally.bytes, entries: tally.entries)
    }

    /// Why one open entry of a source is refused, or nil, after adding its
    /// bytes (a regular file's size, plus any entry's extended attributes) to
    /// `tally`: a regular file with a second hard link (the same inode may
    /// live somewhere the caller can't read), an entry `reader` can't read —
    /// read on a regular file, read and search on a directory — judged from
    /// its owner, group and mode and any ACL deny entry, or a budget overrun.
    /// A symlink is never followed, so only its own entry matters.
    private static func checkEntry(_ fd: Int32, _ info: stat, relative: String, limits: SourceLimits,
                                   reader: SourceReader?, tally: inout (bytes: UInt64, entries: Int)) -> SourceScan? {
        let type = info.st_mode & S_IFMT
        if type == S_IFREG, info.st_nlink > 1 { return .hardLinked(relative) }
        if let reader, type == S_IFREG || type == S_IFDIR {
            let want: mode_t = type == S_IFDIR ? (S_IROTH | S_IXOTH) : S_IROTH
            guard permits(info, uid: reader.uid, groups: reader.groups, want: want),
                  !aclDenies(acl_get_fd_np(fd, ACL_TYPE_EXTENDED), want: want, isDirectory: type == S_IFDIR, reader: reader) else {
                return .notReadableByCaller(relative)
            }
        }
        guard let xattrs = extendedAttributeBytes(fd) else { return .unreadable }
        let size = type == S_IFREG ? UInt64(max(info.st_size, 0)) : 0
        let entryBytes = size.addingReportingOverflow(xattrs)
        let sum = tally.bytes.addingReportingOverflow(entryBytes.partialValue)
        tally.bytes = sum.partialValue
        return (entryBytes.overflow || sum.overflow || tally.bytes > limits.maxBytes) ? .tooLarge : nil
    }

    private static func scanDirectory(_ dirFD: Int32, prefix: String, depth: Int, limits: SourceLimits,
                                      reader: SourceReader?, tally: inout (bytes: UInt64, entries: Int)) -> SourceScan? {
        guard depth < FileTree.maxDepth else { return .unreadable }
        let remaining = max(0, limits.maxEntries - tally.entries)
        guard let names = FileTree.entryNames(dirFD, limit: remaining + 1) else { return .unreadable }
        for name in names {
            tally.entries += 1
            if tally.entries > limits.maxEntries { return .tooManyEntries }
            let relative = prefix.isEmpty ? FileTree.displayName(name) : prefix + "/" + FileTree.displayName(name)
            let failure: SourceScan? = name.withUnsafeBufferPointer { buffer in
                guard let cName = buffer.baseAddress else { return .unreadable }
                var info = stat()
                guard fstatat(dirFD, cName, &info, AT_SYMLINK_NOFOLLOW) == 0 else { return .unreadable }
                let type = info.st_mode & S_IFMT
                guard type == S_IFREG || type == S_IFDIR || type == S_IFLNK else { return .specialFile(relative) }
                let child = openat(dirFD, cName, type == S_IFDIR ? (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                                                                 : (O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC))
                guard child >= 0 else { return errno == EACCES || errno == EPERM ? .notReadableByCaller(relative) : .unreadable }
                defer { close(child) }
                var opened = stat()
                guard fstat(child, &opened) == 0,
                      SoftwareUninstaller.FileID(opened) == SoftwareUninstaller.FileID(info),
                      opened.st_mode & S_IFMT == type else { return .unreadable }
                if let refusal = checkEntry(child, opened, relative: relative, limits: limits, reader: reader, tally: &tally) {
                    return refusal
                }
                guard type == S_IFDIR else { return nil }
                return scanDirectory(child, prefix: relative, depth: depth + 1, limits: limits, reader: reader, tally: &tally)
            }
            if let failure { return failure }
        }
        return nil
    }

    /// Bytes available to root on the volume holding `path`, or nil.
    public static func availableBytes(onVolumeOf path: String) -> UInt64? {
        var info = statfs()
        guard statfs(path, &info) == 0 else { return nil }
        let result = UInt64(info.f_bavail).multipliedReportingOverflow(by: UInt64(info.f_bsize))
        return result.overflow ? UInt64.max : result.partialValue
    }

    // MARK: Staging

    /// Ensures the staging parent exists as a real directory owned by
    /// `owner` (root in production) with mode 0700, re-stamping its group and
    /// mode. Only root works in it, so no one else can watch requests come
    /// and go. Refuses one that is a symlink, not a directory, or owned by
    /// anyone else.
    static func ensureStagingRoot(_ root: URL, owner: FileOwner) throws {
        try FileManager.default.createDirectory(at: root.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        guard mkdir(root.path, 0o700) == 0 || errno == EEXIST else { throw InstallStagingError.stagingRootUnsafe(errno) }
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw InstallStagingError.stagingRootUnsafe(errno) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner.uid else { throw InstallStagingError.stagingRootUnsafe(EPERM) }
        if info.st_gid != owner.gid, fchown(fd, owner.uid, owner.gid) != 0 { throw InstallStagingError.stagingRootUnsafe(errno) }
        if info.st_mode & 0o7777 != 0o700, fchmod(fd, 0o700) != 0 { throw InstallStagingError.stagingRootUnsafe(errno) }
    }

    /// Name of the per-request folder the staging copy is written into.
    static let copyFolderName = "copy"

    /// Makes the staging copy of `source`, run as `user`, and leaves it at
    /// `<stageDir>/<stagedName>`, owned by the install owner's folder again:
    ///
    /// 1. Root creates `<stageDir>/copy` (0700) and hands it to `user`. The
    ///    stage dir and staging root above it stay root-only (0700), so no
    ///    process of the user can reach the folder by path.
    /// 2. `cp -RP -- <source> <stagedName>` (``stagingCopyArguments(source:stagedName:)``)
    ///    runs as `user`, starting in that folder by descriptor
    ///    (``InstallCommandRunning/runAsUser(_:_:user:workingDirectory:timeout:)``).
    ///    It opens the source with the user's permissions, so a symlink or
    ///    other swap after the scan can only lead to something the user could
    ///    read anyway, and ACLs, directory search and volume rules are
    ///    enforced by the kernel. The only process writing into the folder is
    ///    that `cp`, which the user can signal but not drive. Not `ditto`: it
    ///    looks up the path of its working directory, which the user can't
    ///    reach through the root-only folders above it, and fails.
    /// 3. After `cp` has exited and been reaped, root takes the folder
    ///    back through the descriptor it created it with (owner, then 0700)
    ///    before looking inside, and moves the item up to
    ///    `<stageDir>/<stagedName>`. The caller then re-checks the source pin,
    ///    re-scans the copy and normalizes it, as for any staged item.
    private func stageCopyAsUser(_ source: String, stageDir: URL, stagedName: String, user: FileOwner) async -> Bool {
        let copyDir = stageDir.appendingPathComponent(Self.copyFolderName, isDirectory: true)
        guard mkdir(copyDir.path, 0o700) == 0 else {
            appManagementLog.error("install: copy folder: errno \(errno, privacy: .public)")
            return false
        }
        let fd = open(copyDir.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var created = stat()
        guard fstat(fd, &created) == 0, fchmod(fd, 0o700) == 0, fchown(fd, user.uid, user.gid) == 0 else {
            appManagementLog.error("install: couldn't hand the copy folder to the requesting user")
            return false
        }
        let copy = await runner.runAsUser(BundleConfig.cpExecutablePath,
                                          Self.stagingCopyArguments(source: source, stagedName: stagedName),
                                          user: user, workingDirectory: copyDir.path, timeout: Self.stagingTimeout)
        var after = stat()
        guard fstat(fd, &after) == 0, SoftwareUninstaller.FileID(after) == SoftwareUninstaller.FileID(created),
              fchown(fd, installOwner.uid, installOwner.gid) == 0, fchmod(fd, 0o700) == 0 else {
            appManagementLog.error("install: couldn't take the copy folder back")
            return false
        }
        guard copy.status == 0 else {
            appManagementLog.error("install: staging copy (cp) failed (\(copy.status, privacy: .public)): \(Self.tail(copy.stderr), privacy: .private)")
            return false
        }
        guard renameat(fd, stagedName, AT_FDCWD, stageDir.appendingPathComponent(stagedName).path) == 0 else {
            appManagementLog.error("install: couldn't move the staged copy into place: errno \(errno, privacy: .public)")
            return false
        }
        return true
    }

    /// Arguments of the as-user staging copy (``BundleConfig/cpExecutablePath``):
    /// `-R` copies a bundle's tree; `-P` copies every symlink as a symlink,
    /// the source argument included, never following it. No `-p`: the copy
    /// doesn't keep the source's ACLs, file flags, owner or group (root resets
    /// all of these afterwards anyway). Extended attributes, which code
    /// signatures need, are copied. `--` ends the options.
    static func stagingCopyArguments(source: String, stagedName: String) -> [String] {
        ["-RP", "--", source, stagedName]
    }

    /// Whether the volume holding `path` is mounted with ownership ignored
    /// (`MNT_IGNORE_OWNERSHIP`, as for many disk images).
    static func ignoresOwnership(_ path: String) -> Bool {
        var info = statfs()
        return statfs(path, &info) == 0 && info.f_flags & UInt32(MNT_IGNORE_OWNERSHIP) != 0
    }

    /// `uid` with its primary group, from the password database, or nil.
    public static func userIdentity(ofUID uid: uid_t) -> FileOwner? {
        var pwd = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 4096)
        return buffer.withUnsafeMutableBufferPointer { buf -> FileOwner? in
            guard getpwuid_r(uid, &pwd, buf.baseAddress, buf.count, &result) == 0, result != nil else { return nil }
            return FileOwner(uid: uid, gid: pwd.pw_gid)
        }
    }

    /// Creates a FRESH 0700 per-request dir. Refuses if it already exists (a
    /// planted path), so a user can never pre-seed the staging target.
    private static func createRequestDir(_ requestDir: URL) throws {
        guard mkdir(requestDir.path, 0o700) == 0 else {
            throw InstallStagingError.requestDirUnavailable(errno)
        }
        // mkdir applies the umask; stamp the exact mode.
        _ = chmod(requestDir.path, 0o700)
    }

    /// Removes leftovers of earlier requests that didn't clean up (crash, a
    /// locked file, a kill mid-install): every per-request dir under the
    /// staging root and every `.serberus-install-*.app` temp sibling in
    /// /Applications owned by the install owner — except those of requests
    /// still in flight. Removal is descriptor-based and clears BSD flags first.
    /// Run at daemon start and before each staging.
    public func sweepStaleStaging() {
        Self.sweep(stagingRoot: stagingRoot, applicationsDir: applicationsDir, owner: installOwner,
                   isActive: { gate.isActive(stageID: $0) })
    }

    static func sweep(stagingRoot: URL, applicationsDir: URL, owner: FileOwner, isActive: (String) -> Bool) {
        let rootFD = open(stagingRoot.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if rootFD >= 0 {
            defer { close(rootFD) }
            for name in FileTree.entryNames(rootFD) ?? [] {
                let display = FileTree.displayName(name)
                guard !isActive(display) else { continue }
                if !FileTree.removeEntry(in: rootFD, name: name) {
                    appManagementLog.error("sweep: couldn't remove staging leftover \(display, privacy: .public)")
                }
            }
        }
        let appsFD = open(applicationsDir.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard appsFD >= 0 else { return }
        defer { close(appsFD) }
        for name in FileTree.entryNames(appsFD) ?? [] {
            let display = FileTree.displayName(name)
            guard display.hasPrefix(tempAppPrefix), display.hasSuffix(".app") else { continue }
            let id = String(display.dropFirst(tempAppPrefix.count).dropLast(4))
            guard !isActive(id) else { continue }
            var info = stat()
            let owned = name.withUnsafeBufferPointer { buffer -> Bool in
                guard let cName = buffer.baseAddress else { return false }
                return fstatat(appsFD, cName, &info, AT_SYMLINK_NOFOLLOW) == 0 && info.st_uid == owner.uid
            }
            guard owned else { continue }
            if !FileTree.removeEntry(in: appsFD, name: name) {
                appManagementLog.error("sweep: couldn't remove temp app \(display, privacy: .public)")
            }
        }
    }

    /// Re-owns every entry of the staged item to `owner`, clears its BSD flags
    /// (keeping only `UF_COMPRESSED`/`UF_TRACKED`, which don't restrict
    /// anything), and removes group/other write, setuid/setgid and extended
    /// ACLs — through descriptors, never following a symlink (a symlink itself
    /// is re-owned, not its target). Any system (`SF_*`) flag is refused: a
    /// user can't set one, so its presence means something unexpected.
    /// The staging copy is owned by the user who made it; this is what makes
    /// it root's and removable. Every directory and regular file is also made
    /// readable by everyone (and a directory searchable, a file executable by
    /// everyone when its owner could execute it): the user could read all of
    /// it, and an app in /Applications serves every user, so an owner-only
    /// (0600/0700) entry would otherwise become a root-only one the app itself
    /// can't read. False on any failure (fail closed).
    static func normalizeOwnership(atPath path: String, owner: FileOwner) -> Bool {
        FileTree.walkItem(atPath: path) { fd, info, _ in
            guard info.st_flags & FileTree.systemFlagsMask == 0 else { return false }
            // Flags first: an immutable entry refuses chown/chmod.
            let keptFlags = info.st_flags & FileTree.keptFlags
            if info.st_flags != keptFlags {
                guard fchflags(fd, keptFlags) == 0 else { return false }
            }
            if info.st_uid != owner.uid || info.st_gid != owner.gid {
                guard fchown(fd, owner.uid, owner.gid) == 0 else { return false }
            }
            if FileTree.isSymlink(info) { return true }
            var current = stat()
            guard fstat(fd, &current) == 0 else { return false }
            let mode = current.st_mode & 0o7777
            var wanted = mode & ~FileTree.forbiddenModeBits
            if FileTree.isDirectory(current) {
                wanted |= S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
            } else if current.st_mode & S_IFMT == S_IFREG {
                wanted |= S_IRUSR | S_IRGRP | S_IROTH
                if mode & S_IXUSR != 0 { wanted |= S_IXGRP | S_IXOTH }
            }
            if mode != wanted {
                guard fchmod(fd, wanted) == 0 else { return false }
            }
            return FileTree.clearExtendedACL(fd)
        }
    }

    /// Whether every entry of the item at `path` is owned by `owner` and carries
    /// no restricting BSD flag, group/other write, set-id bit or extended ACL.
    /// The gate between copying an app into /Applications and renaming it into
    /// place.
    static func isOwnedForInstall(atPath path: String, owner: FileOwner) -> Bool {
        FileTree.walkItem(atPath: path) { fd, info, _ in
            guard info.st_uid == owner.uid, info.st_gid == owner.gid,
                  info.st_flags & ~FileTree.keptFlags == 0 else { return false }
            if FileTree.isSymlink(info) { return true }
            return info.st_mode & FileTree.forbiddenModeBits == 0 && !FileTree.hasExtendedACL(fd)
        }
    }

    // MARK: Trust gate

    private struct Trust { let trusted: Bool; let detail: String; var teamID: String? = nil }

    /// Gatekeeper decides accept/reject and whether the item is notarized; the
    /// publisher comes from the signature itself, never from `spctl`'s prose —
    /// but the two must name the same team.
    private func assessTrust(_ staged: URL, kind: Kind, policy: InstallPolicy) async -> Trust {
        let type = (kind == .pkg) ? "install" : "exec"
        let r = await runner.run(BundleConfig.spctlExecutablePath,
                                 ["--assess", "--type", type, "-vv", staged.path], timeout: 60)
        // spctl prints its verdict to STDERR; combine both to be robust.
        guard r.status == 0,
              let verdict = Self.parseGatekeeperAssessment(r.stdout + "\n" + r.stderr, assessedPath: staged.path) else {
            return Trust(trusted: false, detail: "not accepted by Gatekeeper (unsigned, revoked, or not from an identified developer)")
        }
        // `source=Notarized Developer ID` is the notarized case; a bare
        // `Developer ID` (not notarized) is refused when notarization is
        // required. Anything else (assessments disabled, App Store, …) isn't
        // Developer-ID software and is never installed this way.
        let notarized = verdict.source == Self.notarizedSource
        guard notarized || verdict.source == Self.developerIDSource else {
            return Trust(trusted: false, detail: "Gatekeeper didn't identify it as Developer ID software")
        }
        if policy.requireNotarization, !notarized {
            return Trust(trusted: false, detail: "signed but NOT notarized — only notarized Developer-ID software may be installed")
        }

        let signer: Signer?
        switch kind {
        case .app: signer = signerOfApp(staged.path)
        case .pkg: signer = await packageSigner(staged)
        }
        guard let signer else {
            return Trust(trusted: false, detail: "its Developer ID signature couldn't be read")
        }
        // Cross-check: Gatekeeper's origin must name the signer's team.
        guard Self.teamID(fromAuthority: verdict.origin) == signer.teamID else {
            appManagementLog.error("install: spctl origin team disagrees with the signature team \(signer.teamID, privacy: .public)")
            return Trust(trusted: false, detail: "Gatekeeper and the signature disagree about its publisher")
        }
        return Trust(trusted: true, detail: signer.authority, teamID: signer.teamID)
    }

    /// The signer of a staged flat package, from `pkgutil --check-signature`.
    private func packageSigner(_ staged: URL) async -> Signer? {
        let r = await runner.run(BundleConfig.pkgutilExecutablePath,
                                 ["--check-signature", staged.path], timeout: 60)
        guard r.status == 0 else { return nil }
        return Self.parsePkgutilSignature(r.stdout, packageName: staged.lastPathComponent)
    }

    /// Strict parse of `spctl --assess -vv <assessedPath>`: the first line must
    /// be exactly `<assessedPath>: accepted`, followed by exactly one `source=`
    /// and exactly one `origin=` line; no `rejected` verdict or `override=`
    /// line anywhere. Any deviation is nil (refuse). The assessed path is
    /// daemon-chosen, so nothing user-supplied appears in this output.
    static func parseGatekeeperAssessment(_ output: String, assessedPath: String) -> GatekeeperVerdict? {
        guard !PathCanonicalizer.containsControlCharacter(assessedPath) else { return nil }
        let lines = nonEmptyLines(output)
        guard lines.first == "\(assessedPath): accepted",
              lines.filter({ $0.hasSuffix(": accepted") }).count == 1,
              !lines.contains(where: { $0.hasSuffix(": rejected") || $0.hasPrefix("override=") }) else { return nil }
        let sources = lines.indices.filter { lines[$0].hasPrefix("source=") }
        let origins = lines.indices.filter { lines[$0].hasPrefix("origin=") }
        guard sources.count == 1, origins.count == 1, sources[0] > 0, origins[0] > 0 else { return nil }
        return GatekeeperVerdict(source: String(lines[sources[0]].dropFirst("source=".count)),
                                 origin: String(lines[origins[0]].dropFirst("origin=".count)))
    }

    /// Strict parse of `pkgutil --check-signature <…/packageName>`: the first
    /// line must be exactly `Package "<packageName>":`; there must be exactly
    /// one `Status:` line, reading exactly ``pkgutilDeveloperIDStatus``, before
    /// the one `Certificate Chain:` line, which is immediately followed by the
    /// one and only `1. ` (leaf) line; the leaf must be a Developer ID
    /// Installer certificate ending in a well-formed `(TEAMID)`.
    static func parsePkgutilSignature(_ output: String, packageName: String) -> Signer? {
        guard !PathCanonicalizer.containsControlCharacter(packageName) else { return nil }
        let lines = nonEmptyLines(output)
        guard lines.first == "Package \"\(packageName)\":",
              lines.filter({ $0.hasPrefix("Package ") }).count == 1 else { return nil }
        let statuses = lines.indices.filter { lines[$0].hasPrefix("Status:") }
        let chains = lines.indices.filter { lines[$0] == "Certificate Chain:" }
        let leaves = lines.indices.filter { lines[$0].hasPrefix("1. ") }
        guard statuses.count == 1, chains.count == 1, leaves.count == 1,
              lines[statuses[0]] == "Status: \(pkgutilDeveloperIDStatus)",
              statuses[0] < chains[0], leaves[0] == chains[0] + 1 else { return nil }
        let authority = String(lines[leaves[0]].dropFirst("1. ".count))
        guard authority.hasPrefix("Developer ID Installer: "), !containsFormatCharacter(authority),
              !containsControlCharacter(authority),
              let team = teamID(fromAuthority: authority) else { return nil }
        return Signer(teamID: team, authority: authority)
    }

    private static func nonEmptyLines(_ output: String) -> [String] {
        output.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// The Team ID at the end of a signing authority such as
    /// "Developer ID Installer: Acme Inc (AB12CD34EF)", or nil.
    static func teamID(fromAuthority authority: String) -> String? {
        let trimmed = authority.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasSuffix(")"), let open = trimmed.lastIndex(of: "(") else { return nil }
        let candidate = String(trimmed[trimmed.index(after: open)..<trimmed.index(before: trimmed.endIndex)])
        return isWellFormedTeamID(candidate) ? candidate : nil
    }

    static func isWellFormedTeamID(_ teamID: String) -> Bool {
        teamID.count == 10 && teamID.allSatisfy { $0.isASCII && ($0.isUppercase || $0.isNumber) }
    }

    /// The Team ID of an app bundle signed with a Developer ID Application
    /// certificate, or nil (unsigned, ad-hoc, invalid, or not Developer ID).
    public static func signingTeamID(ofAppAt path: String) -> String? {
        signingIdentity(ofAppAt: path)?.teamID
    }

    /// The Team ID and leaf-certificate name of an app bundle whose signature is
    /// strictly valid — all nested code and every architecture included — and
    /// satisfies ``developerIDAppRequirement``, read from the code signature;
    /// or nil.
    public static func signingIdentity(ofAppAt path: String) -> Signer? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var requirement: SecRequirement?
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures)
        guard SecRequirementCreateWithString(developerIDAppRequirement as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCheckValidity(staticCode, flags, requirement) == errSecSuccess else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let team = dict[kSecCodeInfoTeamIdentifier as String] as? String,
              isWellFormedTeamID(team) else { return nil }
        // Display name: the leaf certificate's subject, when it names this team.
        var authority = "Developer ID (\(team))"
        if let certificates = dict[kSecCodeInfoCertificates as String] as? [SecCertificate],
           let leaf = certificates.first,
           let summary = SecCertificateCopySubjectSummary(leaf) as String?,
           !containsControlCharacter(summary),
           !containsFormatCharacter(summary),
           summary.count <= 256,
           teamID(fromAuthority: summary) == team {
            authority = summary
        }
        return Signer(teamID: team, authority: authority)
    }

    // MARK: Package content gate

    /// Expands the staged package into the stage dir and refuses it when any
    /// `PackageInfo` / `Distribution` declares a relocatable bundle, marks
    /// something `relocatable="true"`, disables local-system installs,
    /// refers to package content that wasn't inspected, declares an install
    /// location that isn't root-only, or lists a payload path the requesting
    /// user could redirect (see ``PayloadPathChecker``).
    /// A relocatable bundle lets `installer` redirect a component onto an
    /// existing copy of the app with the same bundle ID anywhere on disk —
    /// including a user-controlled one — so a root install could write into
    /// the user's tree (and then run its scripts against it). An install
    /// location someone other than root can write to lets them pre-stage or
    /// swap what root installs or runs there.
    private func packageContentRefusal(_ staged: URL, stageDir: URL, headline: String) async -> InstallResult? {
        let expanded = stageDir.appendingPathComponent("expanded", isDirectory: true)
        let r = await runner.run(BundleConfig.pkgutilExecutablePath,
                                 ["--expand", staged.path, expanded.path], timeout: Self.stagingTimeout)
        let uninspectable = InstallResult(status: .refusedNotTrusted,
                                          message: "Refused “\(headline)”: its package contents couldn't be inspected.")
        guard r.status == 0 else {
            appManagementLog.error("install: pkgutil --expand failed (\(r.status, privacy: .public))")
            return uninspectable
        }
        guard let inspection = Self.packageFindings(inExpandedPackage: expanded.path) else {
            appManagementLog.error("install: expanded package has no readable PackageInfo")
            return uninspectable
        }
        guard inspection.relocatable.isEmpty else {
            appManagementLog.notice("install: package refused: package marks bundles relocatable; relocation lets an existing copy elsewhere redirect a root install (\(inspection.relocatable.joined(separator: "; "), privacy: .public))")
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: this package must be deployed by IT; Install with Serberus can't install it.",
                                 reason: .requiresIT)
        }
        guard inspection.otherFindings.isEmpty else {
            appManagementLog.notice("install: package refused: \(inspection.otherFindings.joined(separator: "; "), privacy: .public)")
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: it installs only for one user (a per-user package), which Install with Serberus doesn't allow.",
                                 reason: .requiresIT)
        }
        guard inspection.unresolvedReferences.isEmpty else {
            appManagementLog.notice("install: package refused: package references content that wasn't inspected: \(inspection.unresolvedReferences.map { Self.sanitizedForDisplay($0, maxLength: 200) }.joined(separator: "; "), privacy: .public)")
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: it refers to package content Serberus can't inspect, so it must be deployed by IT.",
                                 reason: .requiresIT)
        }
        let unsafe = inspection.installLocations.filter { !installLocationIsRootOnly($0.location) }
        guard unsafe.isEmpty else {
            let detail = unsafe.map { "\($0.source): \($0.location)" }.joined(separator: "; ")
            appManagementLog.notice("install: package refused: install location isn't root-only: \(detail, privacy: .public)")
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: it installs into a location that isn't protected by the system, so it must be deployed by IT.",
                                 reason: .requiresIT)
        }
        return await payloadPathRefusal(inspection, expanded: expanded, headline: headline)
    }

    /// Lists each component's payload (`lsbom -p mfl` on the root-owned
    /// expanded copy: mode, path and symlink target of every entry) under its
    /// install location and every `Distribution` `customLocation`, and
    /// refuses when a user other than root could steer where root writes any
    /// of it (``PayloadPathChecker``), when an entry is written through a
    /// symlink the payload itself installs and that symlink leads outside
    /// its install location or into a shared folder
    /// (``payloadLinkRefusal(for:links:)``), or when the listing can't be
    /// read or is over ``maxPayloadPaths``. Folders only root (and admin or
    /// wheel through group write) can change — including existing root-owned
    /// vendor folders inside `/Users/Shared` — pass.
    private func payloadPathRefusal(_ inspection: PackageInspection, expanded: URL, headline: String) async -> InstallResult? {
        let uninspectable = InstallResult(status: .refusedByPolicy,
                                          message: "Refused “\(headline)”: its contents couldn't be fully inspected, so it must be deployed by IT.",
                                          reason: .requiresIT)
        let checker = PayloadPathChecker(lookup: { Self.payloadEntry(atPath: $0) },
                                         readLink: { SerberusBundleWritabilityPolicy.readLink($0) })
        var entries: [(path: String, location: String)] = []
        var links: [String: PayloadLink] = [:]
        for component in inspection.payloadComponents {
            let folder = component.directory.isEmpty ? expanded : expanded.appendingPathComponent(component.directory, isDirectory: true)
            let listing = await runner.run(Self.lsbomExecutablePath, ["-p", "mfl", folder.appendingPathComponent("Bom").path],
                                           timeout: Self.stagingTimeout)
            guard listing.status == 0 else {
                appManagementLog.error("install: lsbom failed (\(listing.status, privacy: .public))")
                return uninspectable
            }
            guard let items = Self.payloadItems(fromBomListing: listing.stdout) else {
                appManagementLog.notice("install: package refused: unexpected Bom listing line")
                return uninspectable
            }
            var locations: [String] = []
            for location in [component.installLocation] + inspection.customLocations where !locations.contains(location) {
                locations.append(location)
            }
            for location in locations {
                guard entries.count + items.count <= Self.maxPayloadPaths else {
                    appManagementLog.notice("install: package refused: more than \(Self.maxPayloadPaths, privacy: .public) payload paths")
                    return uninspectable
                }
                let base = Self.payloadBase(location)
                for item in items {
                    let path = Self.payloadPath(item.relativePath, base: base)
                    entries.append((path, base))
                    if let target = item.linkTarget { links[path] = PayloadLink(target: target, location: base) }
                }
            }
        }
        for entry in entries {
            if let reason = checker.refusal(for: entry.path) {
                appManagementLog.notice("install: package refused: payload path a user other than root could redirect: \(Self.sanitizedForDisplay(reason, maxLength: 400), privacy: .public)")
                return InstallResult(status: .refusedByPolicy,
                                     message: "Refused “\(headline)”: it installs files into a folder that users other than an administrator can change, so it must be deployed by IT.",
                                     reason: .requiresIT)
            }
            guard !links.isEmpty else { continue }
            switch Self.payloadLinkRefusal(for: entry.path, links: links) {
            case .none:
                break
            case let .through(rewritten):
                if let reason = checker.refusal(for: rewritten) {
                    appManagementLog.notice("install: package refused: payload path, through a symlink in the package, a user other than root could redirect: \(Self.sanitizedForDisplay(reason, maxLength: 400), privacy: .public)")
                    return InstallResult(status: .refusedByPolicy,
                                         message: "Refused “\(headline)”: it installs files into a folder that users other than an administrator can change, so it must be deployed by IT.",
                                         reason: .requiresIT)
                }
            case let .refused(reason):
                appManagementLog.notice("install: package refused: \(Self.sanitizedForDisplay(reason, maxLength: 400), privacy: .public)")
                return InstallResult(status: .refusedByPolicy,
                                     message: "Refused “\(headline)”: it writes files through a link that leads outside where it installs, so it must be deployed by IT.",
                                     reason: .requiresIT)
            }
        }
        return nil
    }

    /// Entries read, and directory depth walked, in an expanded package.
    static let maxExpandedEntries = 100_000
    static let maxExpandedDepth = 8

    /// Walks an expanded package (never following a symlink, not descending
    /// into `Scripts`) and scans its `Distribution` and every `PackageInfo`.
    /// Every directory holding a `Payload` or `Bom` must have a `PackageInfo`
    /// (and a `Payload` needs its `Bom`), as must every top-level `*.pkg`
    /// directory: without one, the component's install location couldn't be
    /// checked. Each `Distribution` `pkg-ref` that names package content must
    /// name an inspected top-level component as `#<name>`; anything else (a
    /// URL, a path, a component that wasn't inspected) is recorded in
    /// ``PackageInspection/unresolvedReferences``. Returns what the files
    /// declare, or nil when nothing could be inspected or any file was
    /// unreadable, malformed or over budget.
    static func packageFindings(inExpandedPackage path: String) -> PackageInspection? {
        let rootFD = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard rootFD >= 0 else { return nil }
        defer { close(rootFD) }
        /// What the walk has gathered so far.
        final class WalkState {
            var result = PackageInspection()
            var sawPackageInfo = false
            var topLevelComponents: Set<String> = []
            var budget = SoftwareInstaller.maxExpandedEntries
        }
        let state = WalkState()

        enum Read { case missing, failed, found(PackageInspection) }
        func read(_ dirFD: Int32, _ name: String) -> Read {
            switch FileTree.readRegularFile(in: dirFD, name: name, maxBytes: 4 << 20) {
            case .missing: return .missing
            case .invalid: return .failed
            case let .data(data): return PackageInfoInspector.inspect(data).map(Read.found) ?? .failed
            }
        }

        func walk(_ dirFD: Int32, relative: String, depth: Int) -> Bool {
            guard depth <= maxExpandedDepth, let names = FileTree.entryNames(dirFD, limit: state.budget + 1) else { return false }
            state.budget -= names.count
            guard state.budget >= 0 else { return false }
            let displays = Set(names.map(FileTree.displayName))
            let hasBom = displays.contains("Bom")
            let hasPayload = displays.contains("Payload")
            guard !hasPayload || hasBom else { return false }
            let required = hasBom || (depth == 1 && relative.lowercased().hasSuffix(".pkg"))
            let infoName = relative.isEmpty ? "PackageInfo" : relative + "/PackageInfo"
            switch read(dirFD, "PackageInfo") {
            case .failed:
                return false
            case .missing:
                guard !required else { return false }
            case let .found(found):
                state.sawPackageInfo = true
                state.result.merge(found, source: infoName)
                if depth == 1 { state.topLevelComponents.insert(relative) }
                if hasBom {
                    state.result.payloadComponents.append(.init(directory: relative, installLocation: found.componentLocation ?? "/"))
                }
            }
            for name in names {
                let display = FileTree.displayName(name)
                guard display != "Scripts" else { continue }
                var info = stat()
                let isDirectory = name.withUnsafeBufferPointer { buffer -> Bool in
                    guard let cName = buffer.baseAddress else { return false }
                    return fstatat(dirFD, cName, &info, AT_SYMLINK_NOFOLLOW) == 0 && FileTree.isDirectory(info)
                }
                guard isDirectory else { continue }
                let child = openat(dirFD, display, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { return false }
                defer { close(child) }
                guard walk(child, relative: relative.isEmpty ? display : relative + "/" + display, depth: depth + 1) else { return false }
            }
            return true
        }

        switch read(rootFD, "Distribution") {
        case .failed: return nil
        case .missing: break
        case let .found(found): state.result.merge(found, source: "Distribution")
        }
        guard walk(rootFD, relative: "", depth: 0), state.sawPackageInfo else { return nil }
        var result = state.result
        result.unresolvedReferences = result.pkgRefContents.filter { content in
            guard content.hasPrefix("#"), let name = String(content.dropFirst()).removingPercentEncoding else { return true }
            return !state.topLevelComponents.contains(name)
        }
        return result
    }

    // MARK: Install locations

    /// Groups whose write access to an install-location directory is
    /// accepted: wheel, and admin (`/Applications` is `root:admin 0775`;
    /// `/Library/Application Support` is `root:admin 0755`). A standard user
    /// requesting the install isn't in either.
    static let installLocationWriterGroups: Set<gid_t> = [0, 80]

    /// Locations never accepted as an install location, whoever owns them.
    static let deniedInstallLocations = ["/Users/Shared", "/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"]

    /// One path component as the install-location check sees it.
    enum LocationEntry: Equatable, Sendable {
        case missing
        /// Couldn't be examined (fail closed).
        case error
        case entry(uid: uid_t, gid: gid_t, mode: mode_t, grantsByACL: Bool)
    }

    /// Whether a package's declared install location (resolved against the
    /// `/` target) is root-only: an absolute path free of `..`, control and
    /// format characters, outside ``deniedInstallLocations``, whose existing
    /// components — as written and after resolving symlinks — are all owned
    /// by root, not writable by other, writable by group only for
    /// ``installLocationWriterGroups``, and granted nothing by an ACL. Missing
    /// trailing components are fine (root creates them) when the nearest
    /// existing ancestor passes. `/` passes.
    public static func isRootOnlyInstallLocation(_ location: String) -> Bool {
        isRootOnlyInstallLocation(location, lookup: { locationEntry(atPath: $0) }, resolve: { resolvedPath($0) })
    }

    static func isRootOnlyInstallLocation(
        _ location: String,
        lookup: (String) -> LocationEntry,
        resolve: (String) -> String?
    ) -> Bool {
        guard location.hasPrefix("/"), !containsControlCharacter(location), !containsFormatCharacter(location) else { return false }
        let components = location.split(separator: "/").map(String.init).filter { $0 != "." }
        guard !components.contains("..") else { return false }
        let literal = "/" + components.joined(separator: "/")
        guard !isDeniedInstallLocation(literal) else { return false }

        // As written: `lstat` of each prefix (intermediate symlinks resolve),
        // up to the first missing component.
        var lastExisting = "/"
        for path in prefixPaths(components) {
            let entry = lookup(path)
            if entry == .missing { break }
            guard case let .entry(uid, gid, mode, grantsByACL) = entry,
                  isRootOnly(uid: uid, gid: gid, mode: mode, grantsByACL: grantsByACL) else { return false }
            lastExisting = path
        }

        // Resolved: every component of the real path of the deepest existing
        // prefix, so a symlink can't lead somewhere writable.
        guard let real = resolve(lastExisting), real.hasPrefix("/"), !isDeniedInstallLocation(real) else { return false }
        for path in prefixPaths(real.split(separator: "/").map(String.init)) {
            guard case let .entry(uid, gid, mode, grantsByACL) = lookup(path),
                  mode & S_IFMT != S_IFLNK,
                  isRootOnly(uid: uid, gid: gid, mode: mode, grantsByACL: grantsByACL) else { return false }
        }
        return true
    }

    /// `/`, then each successively longer prefix of `components`.
    private static func prefixPaths(_ components: [String]) -> [String] {
        var paths = ["/"]
        var prefix = ""
        for component in components {
            prefix += "/" + component
            paths.append(prefix)
        }
        return paths
    }

    private static func isRootOnly(uid: uid_t, gid: gid_t, mode: mode_t, grantsByACL: Bool) -> Bool {
        uid == 0 && !grantsByACL && mode & S_IWOTH == 0
            && (mode & S_IWGRP == 0 || installLocationWriterGroups.contains(gid))
    }

    static func isDeniedInstallLocation(_ path: String) -> Bool {
        let lower = path.lowercased()
        return deniedInstallLocations.contains { denied in
            let d = denied.lowercased()
            return lower == d || lower.hasPrefix(d + "/")
        }
    }

    /// `lstat` of `path` plus whether an extended ACL on it allows anything.
    static func locationEntry(atPath path: String) -> LocationEntry {
        var info = stat()
        guard lstat(path, &info) == 0 else { return errno == ENOENT || errno == ENOTDIR ? .missing : .error }
        return .entry(uid: info.st_uid, gid: info.st_gid, mode: info.st_mode, grantsByACL: aclAllowsAnything(atPath: path))
    }

    /// Whether the extended ACL on `path` (not followed) has any allow entry.
    private static func aclAllowsAnything(atPath path: String) -> Bool {
        guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else { return false }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        var id = ACL_FIRST_ENTRY.rawValue
        while acl_get_entry(acl, id, &entry) == 0, let current = entry {
            var tag = ACL_UNDEFINED_TAG
            if acl_get_tag_type(current, &tag) != 0 || tag == ACL_EXTENDED_ALLOW { return true }
            id = ACL_NEXT_ENTRY.rawValue
        }
        return false
    }

    /// `realpath(3)` of `path`, or nil.
    static func resolvedPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    // MARK: Payload paths

    /// Most payload paths (summed over components and install locations)
    /// checked; a package listing more can't be inspected.
    static let maxPayloadPaths = 200_000
    /// Pinned `lsbom`, used to list a component's payload paths.
    static let lsbomExecutablePath = "/usr/bin/lsbom"

    /// One path as the payload-path check sees it.
    enum PayloadEntry: Equatable, Sendable {
        case missing
        /// Couldn't be examined (fail closed).
        case error
        /// `aclGrantsWrite`: an extended ACL lets someone other than root, or
        /// the admin or wheel group, change the entry (write, append, add or
        /// remove entries, delete it, or change its ACL or owner), or it
        /// can't be read.
        case entry(uid: uid_t, gid: gid_t, mode: mode_t, aclGrantsWrite: Bool)
    }

    /// Decides whether anyone other than root could influence where root
    /// writes a package's payload — the requesting user, or any other local
    /// user (for example one a vendor's script made the owner of a plug-in
    /// folder). Each payload path is walked from `/`, component by
    /// component, and refused when:
    /// - an existing component (a symlink included) is owned by anyone but
    ///   root;
    /// - an existing component that isn't a directory (a symlink or a file)
    ///   is writable by a user other than root: other write, group write for
    ///   a group other than wheel and admin, or an ACL grant;
    /// - an existing component sits in a directory a user other than root
    ///   can write to in the same way, unless that directory is sticky (so
    ///   no one but root can rename or remove the root-owned component);
    /// - a component is missing and its nearest existing directory is
    ///   writable by a user other than root, sticky or not: they could
    ///   create it first (for example `/Users/Shared/NewVendor`);
    /// - a component can't be examined, or is a file with more below it.
    /// Admins can already change everything root can, so write access
    /// through the admin or wheel group is accepted. A symlink that passes
    /// these checks (so root-owned, in a folder only root can change) is
    /// followed — its stored target, whoever the target belongs to — and
    /// the walk restarts from `/` on the result, so every component of the
    /// target is checked the same way. A missing component in a directory
    /// only root can write is fine: root creates everything from there down.
    /// Results are memoized per path, so shared prefixes are examined once.
    final class PayloadPathChecker {
        private let lookup: (String) -> PayloadEntry
        private let readLink: (String) -> String?
        private var entries: [String: PayloadEntry] = [:]
        /// Directories reached and found safe to walk into.
        private var safeDirectories: Set<String> = ["/"]
        /// Missing paths whose parent only root can write.
        private var safeMissing: Set<String> = []

        init(lookup: @escaping (String) -> PayloadEntry, readLink: @escaping (String) -> String?) {
            self.lookup = lookup
            self.readLink = readLink
        }

        private func entry(_ path: String) -> PayloadEntry {
            if let known = entries[path] { return known }
            let found = lookup(path)
            entries[path] = found
            return found
        }

        /// Whether a user other than root can change `entry` — for a
        /// directory, add, remove or rename entries in it (anything that
        /// isn't a readable entry counts as changeable: fail closed).
        private static func othersCanChange(_ entry: PayloadEntry) -> Bool {
            guard case let .entry(owner, group, mode, aclGrantsWrite) = entry else { return true }
            if owner != 0 || aclGrantsWrite || mode & S_IWOTH != 0 { return true }
            return mode & S_IWGRP != 0 && !installLocationWriterGroups.contains(group)
        }

        /// Why root writing `path` could be steered by a user other than
        /// root, or nil. `path` must be absolute.
        func refusal(for path: String) -> String? {
            guard path.hasPrefix("/"), !containsControlCharacter(path) else { return "\(path): not a clean absolute path" }
            var components = path.split(separator: "/").map(String.init).filter { $0 != "." }
            guard !components.contains("..") else { return "\(path): contains .." }
            var current = "/"
            var index = 0
            var hops = 0
            while index < components.count {
                let child = current == "/" ? "/" + components[index] : current + "/" + components[index]
                let isLast = index == components.count - 1
                if safeMissing.contains(child) { return nil }
                if safeDirectories.contains(child) {
                    current = child
                    index += 1
                    continue
                }
                let parent = entry(current)
                let parentChangeable = Self.othersCanChange(parent)
                let found = entry(child)
                switch found {
                case .error:
                    return "\(child): couldn't be examined"
                case .missing:
                    if parentChangeable { return "\(child): missing, in \(current), which a user other than root can write" }
                    safeMissing.insert(child)
                    return nil
                case let .entry(owner, _, mode, _):
                    let type = mode & S_IFMT
                    if owner != 0 { return "\(child): owned by uid \(owner)" }
                    if type != S_IFDIR, Self.othersCanChange(found) {
                        return "\(child): writable by a user other than root"
                    }
                    if parentChangeable {
                        guard case let .entry(_, _, parentMode, _) = parent, parentMode & S_ISVTX != 0 else {
                            return "\(child): in \(current), which a user other than root can write"
                        }
                    }
                    if type == S_IFLNK {
                        hops += 1
                        guard hops <= 32, let target = readLink(child), !target.isEmpty,
                              let resolved = Self.resolve(target, in: current) else {
                            return "\(child): a symlink that couldn't be resolved"
                        }
                        components = resolved + components[(index + 1)...]
                        current = "/"
                        index = 0
                        continue
                    }
                    guard type == S_IFDIR else {
                        return isLast ? nil : "\(child): not a directory"
                    }
                    safeDirectories.insert(child)
                    current = child
                    index += 1
                }
            }
            return nil
        }

        /// The components of a symlink's stored `target`, read in the real
        /// directory `directory`. `..` is allowed only leading a relative
        /// target (where it can be applied to `directory`, which contains no
        /// symlink); nil otherwise.
        static func resolve(_ target: String, in directory: String) -> [String]? {
            var base = target.hasPrefix("/") ? [] : directory.split(separator: "/").map(String.init)
            var leading = !target.hasPrefix("/")
            var result: [String] = []
            for component in target.split(separator: "/").map(String.init) where component != "." {
                if component == ".." {
                    guard leading, !base.isEmpty else { return nil }
                    base.removeLast()
                    continue
                }
                leading = false
                result.append(component)
            }
            return base + result
        }
    }

    /// The production lookup for ``PayloadPathChecker``: `lstat`, plus
    /// whether the entry's extended ACL (not followed) lets anyone other
    /// than root, wheel or admin change it (``aclGrantsWriteToOthers(atPath:)``).
    static func payloadEntry(atPath path: String) -> PayloadEntry {
        var info = stat()
        guard lstat(path, &info) == 0 else { return errno == ENOENT || errno == ENOTDIR ? .missing : .error }
        return .entry(uid: info.st_uid, gid: info.st_gid, mode: info.st_mode, aclGrantsWrite: aclGrantsWriteToOthers(atPath: path))
    }

    /// ACL permissions that let a principal change an entry, or what a
    /// directory holds.
    private static let aclWritePermissions: [acl_perm_t] = [
        ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER,
    ]

    /// Whether the extended ACL on `path` (not followed) has an allow entry
    /// — inherit-only ones included, since they reach what root creates
    /// there — granting any of ``aclWritePermissions`` to a user other than
    /// root or a group other than wheel and admin. An ACL that can't be
    /// read, or an entry whose principal can't be resolved, counts as
    /// granting (fail closed).
    static func aclGrantsWriteToOthers(atPath path: String) -> Bool {
        errno = 0
        guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else { return errno != ENOENT }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        var which = ACL_FIRST_ENTRY.rawValue
        while acl_get_entry(acl, which, &entry) == 0, let current = entry {
            which = ACL_NEXT_ENTRY.rawValue
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(current, &tag) == 0 else { return true }
            guard tag == ACL_EXTENDED_ALLOW else { continue }
            var permset: acl_permset_t?
            guard acl_get_permset(current, &permset) == 0, let permset else { return true }
            guard aclWritePermissions.contains(where: { acl_get_perm_np(permset, $0) == 1 }) else { continue }
            guard let qualifier = acl_get_qualifier(current) else { return true }
            let principal = aclPrincipal(qualifier)
            acl_free(qualifier)
            guard let principal else { return true }
            if principal.isGroup ? !installLocationWriterGroups.contains(gid_t(principal.id)) : principal.id != 0 {
                return true
            }
        }
        return false
    }

    /// One entry of a component's Bom: its path (`.` or `./…`) and, for a
    /// symlink, its stored target.
    struct PayloadItem: Equatable, Sendable {
        let relativePath: String
        let linkTarget: String?
    }

    /// The entries of `lsbom -p mfl` output: one line per entry, three
    /// tab-separated fields (octal mode, path, symlink target — empty for
    /// anything but a symlink). Nil for any line that isn't exactly that: a
    /// path that isn't `.` or `./…`, a mode that isn't octal, a target on
    /// anything but a symlink, or a tab or newline in a name or target
    /// (which would make the line ambiguous). A symlink entry with no target
    /// is kept as a plain entry: `pkgbuild` records the AppleDouble
    /// companion (`._name`) of a symlink that carries extended attributes
    /// that way, and no real symlink has an empty target.
    static func payloadItems(fromBomListing listing: String) -> [PayloadItem]? {
        var items: [PayloadItem] = []
        for line in listing.split(separator: "\n", omittingEmptySubsequences: true) {
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard fields.count == 3, !fields[0].isEmpty, fields[0].count <= 7,
                  fields[0].allSatisfy({ ("0"..."7").contains($0) }), let mode = UInt32(fields[0], radix: 8) else { return nil }
            let path = String(fields[1])
            guard path == "." || path.hasPrefix("./") else { return nil }
            let isSymlink = mode_t(truncatingIfNeeded: mode) & S_IFMT == S_IFLNK
            guard isSymlink || fields[2].isEmpty else { return nil }
            items.append(PayloadItem(relativePath: path, linkTarget: fields[2].isEmpty ? nil : String(fields[2])))
        }
        return items
    }

    /// An install location as payload paths are joined to it: no trailing
    /// slash, except `/` itself.
    static func payloadBase(_ location: String) -> String {
        var base = location
        while base.count > 1, base.hasSuffix("/") { base.removeLast() }
        return base
    }

    /// The absolute path of a Bom entry installed under `base`: `.` is the
    /// location itself, `./x` is `<location>/x`.
    static func payloadPath(_ relative: String, base: String) -> String {
        relative == "." ? base : (base == "/" ? "" : base) + "/" + relative.dropFirst(2)
    }

    /// Absolute payload paths from `lsbom` output for a component installed
    /// under `location`. Nil for a line that isn't a well-formed entry.
    static func payloadPaths(fromBomListing listing: String, location: String) -> [String]? {
        let base = payloadBase(location)
        return payloadItems(fromBomListing: listing)?.map { payloadPath($0.relativePath, base: base) }
    }

    /// A symlink a package installs: its stored target, and the install
    /// location of the component that installs it.
    struct PayloadLink: Equatable, Sendable {
        let target: String
        let location: String
    }

    enum PayloadLinkVerdict: Equatable, Sendable {
        /// Not written through a symlink the package installs.
        case none
        /// Written through one or more of them; root really writes this path
        /// (which must pass the on-disk checks too).
        case through(String)
        case refused(String)
    }

    /// Whether `path` is written through a symlink the package itself
    /// installs (`links`, by absolute path) — something the on-disk checks
    /// can't see, since the link doesn't exist yet. Each such symlink along
    /// the path (a symlink as the last component isn't written through) is
    /// replaced by its target, read in the folder that holds it; the target
    /// must stay inside that symlink's install location and outside the
    /// shared folders never accepted as install locations
    /// (``deniedInstallLocations``). The result is the path root really
    /// writes. A target that can't be resolved, or more than 32 hops, is
    /// refused.
    static func payloadLinkRefusal(for path: String, links: [String: PayloadLink]) -> PayloadLinkVerdict {
        var components = path.split(separator: "/").map(String.init).filter { $0 != "." }
        var index = 0
        var hops = 0
        var rewritten = false
        while index < components.count - 1 {
            let prefix = "/" + components[0...index].joined(separator: "/")
            guard let link = links[prefix] else {
                index += 1
                continue
            }
            hops += 1
            let folder = "/" + components[0..<index].joined(separator: "/")
            guard hops <= 32, let resolved = PayloadPathChecker.resolve(link.target, in: folder) else {
                return .refused("\(path): written through \(prefix), a symlink in the package that couldn't be resolved")
            }
            let target = "/" + resolved.joined(separator: "/")
            let location = link.location
            guard location == "/" || target == location || target.hasPrefix(location + "/") else {
                return .refused("\(path): written through \(prefix), a symlink in the package that leads outside its install location \(location) (to \(target))")
            }
            guard !isDeniedInstallLocation(target), resolvedPath(target).map(isDeniedInstallLocation) != true else {
                return .refused("\(path): written through \(prefix), a symlink in the package that leads into a shared folder (\(target))")
            }
            components = resolved + components[(index + 1)...]
            index = 0
            rewritten = true
        }
        return rewritten ? .through("/" + components.joined(separator: "/")) : .none
    }

    // MARK: App placement gate

    /// Why an app may not be placed in /Applications as `appName`, or nil when it
    /// may. An app can't claim a Serberus or protected bundle ID, and may replace
    /// an existing app only when that app is Developer ID signed by the same
    /// team, has the same bundle ID, and the new one is the same or a newer
    /// version on a comparable key. An installed copy of the same bundle ID
    /// under another name (in /Applications or /Applications/Utilities)
    /// must be the same or an older version too, on a comparable key, so
    /// installing under another name doesn't sidestep the version check.
    private func appPlacementRefusal(_ staged: URL, appName: String, headline: String, teamID: String,
                                     policy: InstallPolicy) -> InstallResult? {
        let newInfo = SoftwareUninstaller.infoPlist(ofAppAt: staged.path)
        let newBundleID = newInfo?["CFBundleIdentifier"] as? String
        if SoftwareUninstaller.isSerberusBundleID(newBundleID) {
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: it claims to be part of Serberus.")
        }
        if policy.isProtected(bundleID: newBundleID) {
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: this app is protected on this Mac.")
        }

        let destination = applicationsDir.appendingPathComponent(appName)
        if let newBundleID {
            for incumbent in installedApps(withBundleID: newBundleID, excluding: destination.path) {
                switch Self.versionVerdict(new: newInfo, installed: incumbent) {
                case .allowed:
                    continue
                case let .downgrade(newVersion, installedVersion):
                    appManagementLog.notice("install: downgrade of a same-ID app under another name refused bundle=\(newBundleID, privacy: .public) new=\(newVersion, privacy: .public) installed=\(installedVersion, privacy: .public)")
                    return Self.downgradeRefusal(headline: headline, new: newVersion, installed: installedVersion)
                case let .incomparable(newVersion, installedVersion):
                    // Whether it's older can't be told, so it's refused as if
                    // it might be: an older copy never sits beside a newer one.
                    appManagementLog.notice("install: version not comparable with a same-ID app under another name bundle=\(newBundleID, privacy: .public) new=\(newVersion ?? "none", privacy: .public) installed=\(installedVersion ?? "none", privacy: .public)")
                    return InstallResult(status: .refusedByPolicy,
                                         message: "Refused “\(headline)”: another copy of this app is already installed, and its version can't be compared with this one, so it must be deployed by IT.",
                                         reason: .requiresIT)
                }
            }
        }
        var existing = stat()
        guard lstat(destination.path, &existing) == 0 else { return nil }
        let existingInfo = SoftwareUninstaller.infoPlist(ofAppAt: destination.path)
        let existingBundleID = existingInfo?["CFBundleIdentifier"] as? String
        if SoftwareUninstaller.isSerberusBundleID(existingBundleID) || policy.isProtected(bundleID: existingBundleID) {
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: it would replace a protected app.")
        }
        // Only a Developer ID app can be replaced: its Team ID is what proves
        // the new app comes from the same publisher. An Apple-signed, Mac App
        // Store, unsigned or broken app gets its own reason, not "different
        // publisher".
        guard let existingTeam = signerOfApp(destination.path)?.teamID else {
            appManagementLog.notice("install: installed app at the destination isn't Developer ID signed; replace refused")
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: Serberus can't replace an app that isn't Developer ID signed, and the installed copy isn't.")
        }
        guard existingTeam == teamID else {
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: an app with that name is already installed from a different publisher.")
        }
        // The same publisher isn't enough: a replacement must be the same
        // product, or one app could be installed over another app of that
        // publisher simply by renaming it.
        guard let newBundleID, let existingBundleID,
              newBundleID.lowercased() == existingBundleID.lowercased() else {
            appManagementLog.notice("install: replace refused, bundle ID differs new=\(newBundleID.map { Self.sanitizedForDisplay($0, maxLength: 128) } ?? "-", privacy: .public) installed=\(existingBundleID.map { Self.sanitizedForDisplay($0, maxLength: 128) } ?? "-", privacy: .public)")
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: a different app (another bundle identifier) is already installed under that name, so this must be deployed by IT.",
                                 reason: .requiresIT)
        }
        switch Self.versionVerdict(new: newInfo, installed: existingInfo) {
        case .allowed:
            return nil
        case let .downgrade(newVersion, installedVersion):
            appManagementLog.notice("install: downgrade refused bundle=\(newBundleID, privacy: .public) new=\(newVersion, privacy: .public) installed=\(installedVersion, privacy: .public)")
            return Self.downgradeRefusal(headline: headline, new: newVersion, installed: installedVersion)
        case let .incomparable(newVersion, installedVersion):
            appManagementLog.notice("install: version not comparable bundle=\(newBundleID, privacy: .public) new=\(newVersion ?? "none", privacy: .public) installed=\(installedVersion ?? "none", privacy: .public)")
            return InstallResult(status: .refusedByPolicy,
                                 message: "Refused “\(headline)”: its version can't be compared with the installed one, so it must be deployed by IT.",
                                 reason: .requiresIT)
        }
    }

    private static func downgradeRefusal(headline: String, new: String, installed: String) -> InstallResult {
        InstallResult(status: .refusedByPolicy,
                      message: "Refused “\(headline)”: this version (\(sanitizedForDisplay(new, maxLength: 32))) is older than the one already installed (\(sanitizedForDisplay(installed, maxLength: 32))). Downgrades aren't allowed.")
    }

    /// Entries read from each Applications folder when looking for installed
    /// copies of a bundle ID.
    static let maxIncumbentScanEntries = 10_000

    /// The Info.plists of the apps directly in /Applications and
    /// /Applications/Utilities (top level only) whose `CFBundleIdentifier`
    /// equals `bundleID`, case-insensitively — other than `excluding`, and
    /// never through a symlink (a symlinked folder or app is skipped).
    func installedApps(withBundleID bundleID: String, excluding: String) -> [[String: Any]] {
        let wanted = bundleID.lowercased()
        var found: [[String: Any]] = []
        for folder in [applicationsDir, applicationsDir.appendingPathComponent("Utilities", isDirectory: true)] {
            let fd = open(folder.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { continue }
            defer { close(fd) }
            for name in (FileTree.entryNames(fd, limit: Self.maxIncumbentScanEntries) ?? []).map(FileTree.displayName)
            where name.lowercased().hasSuffix(".app") && !name.hasPrefix(".") {
                let path = folder.appendingPathComponent(name).path
                guard path != excluding, let info = SoftwareUninstaller.infoPlist(ofAppAt: path),
                      (info["CFBundleIdentifier"] as? String)?.lowercased() == wanted else { continue }
                found.append(info)
            }
        }
        return found
    }

    enum VersionVerdict: Equatable {
        case allowed
        /// The new app is older than the installed one.
        case downgrade(new: String, installed: String)
        /// The two can't be compared on the same key: a key present on both
        /// sides doesn't parse, or no key is present on both.
        case incomparable(new: String?, installed: String?)
    }

    /// Compares the new and installed apps on `CFBundleVersion`, or — only
    /// when either side lacks it — on `CFBundleShortVersionString`, as dotted
    /// numbers. Same or newer is allowed; older is a downgrade. Identical
    /// strings are always the same version. When the key compared on doesn't
    /// parse on either side (a suffix such as "1.2.10b3", a date, a hash), or
    /// no key is present on both sides, the versions are incomparable: that
    /// is never allowed, and never falls through to another key. An installed
    /// app with no version at all doesn't block replacement.
    static func versionVerdict(new: [String: Any]?, installed: [String: Any]?) -> VersionVerdict {
        let keys = ["CFBundleVersion", "CFBundleShortVersionString"]
        for key in keys {
            guard let old = installed?[key] as? String, let fresh = new?[key] as? String else { continue }
            if fresh.trimmingCharacters(in: .whitespaces) == old.trimmingCharacters(in: .whitespaces) { return .allowed }
            guard let oldParts = versionComponents(old), let newParts = versionComponents(fresh) else {
                return .incomparable(new: fresh, installed: old)
            }
            return compareVersions(newParts, oldParts) == .orderedAscending
                ? .downgrade(new: fresh, installed: old) : .allowed
        }
        let installedVersion = keys.lazy.compactMap { installed?[$0] as? String }.first
        guard let installedVersion else { return .allowed }
        return .incomparable(new: keys.lazy.compactMap { new?[$0] as? String }.first, installed: installedVersion)
    }

    /// The numeric components of a dotted version ("1.2.10" → [1, 2, 10]). Nil
    /// when any component isn't all ASCII digits — a suffix ("1.2.10b3") makes
    /// the whole version unparseable rather than being dropped.
    static func versionComponents(_ version: String) -> [UInt64]? {
        let trimmed = version.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        var parts: [UInt64] = []
        for component in trimmed.split(separator: ".", omittingEmptySubsequences: false) {
            guard !component.isEmpty, component.count <= 18,
                  component.allSatisfy({ $0.isASCII && $0.isNumber }), let value = UInt64(component) else { return nil }
            parts.append(value)
        }
        return parts
    }

    /// Numeric compare, missing trailing components counting as 0.
    static func compareVersions(_ lhs: [UInt64], _ rhs: [UInt64]) -> ComparisonResult {
        for index in 0..<max(lhs.count, rhs.count) {
            let l = index < lhs.count ? lhs[index] : 0
            let r = index < rhs.count ? rhs[index] : 0
            if l < r { return .orderedAscending }
            if l > r { return .orderedDescending }
        }
        return .orderedSame
    }

    // MARK: Commit

    private func commitPkg(_ staged: URL, headline: String, authority: String) async -> InstallResult {
        let r = await runner.run(BundleConfig.installerExecutablePath,
                                 ["-pkg", staged.path, "-target", "/"], timeout: installTimeout)
        guard r.status == 0 else {
            appManagementLog.error("install: installer failed (\(r.status, privacy: .public)): \(Self.tail(r.stderr.isEmpty ? r.stdout : r.stderr), privacy: .public)")
            return InstallResult(status: .failed,
                                 message: "The package installer reported an error (\(r.status)) installing “\(headline)”.")
        }
        return InstallResult(status: .installed, message: "Installed (\(authority)).", installedName: headline)
    }

    /// Copies the staged (root-owned, verified) app into a temporary sibling in
    /// /Applications, checks the copy is owned by root throughout, then renames
    /// it into place — swapping atomically with an existing app of the same
    /// publisher, or refusing if something appeared at the destination since the
    /// check. Nothing user-owned is ever placed in /Applications.
    ///
    /// A replaced app is never deleted by path where the user can reach it: it
    /// is renamed into the root-only (0700) stage dir and removed with it by a
    /// descriptor-based walk (`openat`/`fstatat(AT_SYMLINK_NOFOLLOW)`/`unlinkat`,
    /// flags cleared first), so swapping a subdirectory for a symlink during the
    /// delete can't redirect it. Deleting rather than moving it to the user's
    /// Trash also means an old, possibly root-owned tree (helpers, daemons) is
    /// never handed to the user. Replacing is refused up front when the stage
    /// dir isn't on the same volume as /Applications.
    private func commitApp(_ staged: URL, stageDir: URL, stageID: String, appName: String, headline: String,
                           authority: String, teamID: String, policy: InstallPolicy) async -> InstallResult {
        let dest = applicationsDir.appendingPathComponent(appName)
        let temp = applicationsDir.appendingPathComponent(Self.tempAppPrefix + stageID + ".app")
        let placeFailed = InstallResult(status: .failed, message: "Couldn't place “\(headline)” in Applications.")
        var probe = stat()
        guard lstat(temp.path, &probe) != 0 else {
            appManagementLog.error("install: temp sibling already exists")
            return placeFailed
        }
        if lstat(dest.path, &probe) == 0, !Self.sameVolume(applicationsDir.path, stageDir.path) {
            appManagementLog.error("install: staging and Applications are on different volumes; replace refused")
            return InstallResult(status: .failed,
                                 message: "Couldn't replace “\(headline)”: Serberus can't safely remove the installed copy on this Mac.")
        }
        defer { FileTree.removeTreeLogged(atPath: temp.path, context: "install temp copy") }
        let copy = await runner.run(BundleConfig.dittoExecutablePath, ["--noacl", staged.path, temp.path], timeout: installTimeout)
        guard copy.status == 0 else {
            appManagementLog.error("install: copy into Applications failed (\(copy.status, privacy: .public))")
            return placeFailed
        }
        guard Self.isOwnedForInstall(atPath: temp.path, owner: installOwner) else {
            appManagementLog.error("install: the copy in Applications wasn't owned by the install owner")
            return placeFailed
        }
        // Something may have appeared at the destination since the first check.
        if let refusal = appPlacementRefusal(staged, appName: appName, headline: headline, teamID: teamID, policy: policy) {
            return refusal
        }
        var existing = stat()
        let replacing = lstat(dest.path, &existing) == 0
        if replacing, !Self.sameVolume(applicationsDir.path, stageDir.path) { return placeFailed }
        // RENAME_SWAP leaves the old app at `temp`; RENAME_EXCL refuses if the
        // destination appeared after the check.
        let flags = replacing ? UInt32(RENAME_SWAP) : UInt32(RENAME_EXCL)
        guard renamex_np(temp.path, dest.path, flags) == 0 else {
            appManagementLog.error("install: rename into Applications failed: \(String(cString: strerror(errno)), privacy: .public)")
            return placeFailed
        }
        if replacing {
            // Park the previous app in the root-only stage dir; the stage dir's
            // descriptor-based removal deletes it. If the rename fails, the
            // deferred removal deletes it in place (also descriptor-based).
            let parked = stageDir.appendingPathComponent("replaced.app")
            if rename(temp.path, parked.path) != 0 {
                appManagementLog.error("install: couldn't park the replaced app: \(String(cString: strerror(errno)), privacy: .public)")
            }
        }
        return InstallResult(status: .installed, message: "Copied to Applications (\(authority)).", installedName: headline)
    }

    static func sameVolume(_ a: String, _ b: String) -> Bool {
        var sa = stat(), sb = stat()
        return stat(a, &sa) == 0 && stat(b, &sb) == 0 && sa.st_dev == sb.st_dev
    }

    private static func tail(_ text: String, max: Int = 300) -> String {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.count <= max ? t : "…" + t.suffix(max)
    }
}

// MARK: - PackageInfo / Distribution inspection

/// What a package's `PackageInfo` and `Distribution` files declare, as far as
/// the content gate cares.
struct PackageInspection: Equatable, Sendable {
    /// An install location and the file that declared it.
    struct Location: Equatable, Sendable {
        let source: String
        let location: String
    }

    /// Relocation markers (any one refuses the package).
    var relocatable: [String] = []
    /// Other refusals (a per-user-only install).
    var otherFindings: [String] = []
    /// Every declared install location: a `PackageInfo`'s `install-location`
    /// (`/` when it has none — what `installer` uses, and what `pkgbuild`
    /// leaves out), and a `Distribution` choice's `customLocation`.
    var installLocations: [Location] = []
    /// The install location of the top-level `pkg-info` element of one
    /// parsed `PackageInfo` (`/` when it has none); nil for a `Distribution`.
    var componentLocation: String?
    /// The non-empty text of every `pkg-ref` element (`#Foo.pkg` names the
    /// component directory `Foo.pkg`).
    var pkgRefContents: [String] = []
    /// `pkg-ref` contents that don't name an inspected top-level component.
    var unresolvedReferences: [String] = []

    /// A component directory (relative to the expanded package; "" for its
    /// top) whose `Bom` lists what it installs under `installLocation`.
    struct PayloadComponent: Equatable, Sendable {
        let directory: String
        let installLocation: String
    }
    var payloadComponents: [PayloadComponent] = []

    /// Every finding, relocation first.
    var findings: [String] { relocatable + otherFindings }

    /// The `customLocation`s declared by the `Distribution`.
    var customLocations: [String] {
        installLocations.filter { $0.source == "Distribution" }.map(\.location)
    }

    mutating func merge(_ other: PackageInspection, source: String) {
        relocatable += other.relocatable.map { "\(source): \($0)" }
        otherFindings += other.otherFindings.map { "\(source): \($0)" }
        installLocations += other.installLocations.map { Location(source: source, location: $0.location) }
        pkgRefContents += other.pkgRefContents
    }
}

/// Pure parser for a flat package's `PackageInfo` or `Distribution` XML.
/// Relocation findings:
/// - a `<bundle>` inside `<relocate>` — pkgbuild's marker for a relocatable
///   bundle (`BundleIsRelocatable`), which lets `installer` redirect the
///   component to wherever a same-ID bundle already exists;
/// - any element with `relocatable="true"`.
/// Other findings:
/// - `<domains enable_localSystem="false">` — a per-user-only install.
/// Install locations: `<pkg-info install-location=…>` (`/` when absent) and
/// `<choice customLocation=…>`. Package references: the text of every
/// `<pkg-ref>`.
/// Nil when the XML doesn't parse. External entities are never resolved; the
/// caller bounds the input size.
enum PackageInfoInspector {
    static func inspect(_ data: Data) -> PackageInspection? {
        let scanner = Scanner()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = scanner
        guard parser.parse(), scanner.sawElement else { return nil }
        return scanner.result
    }

    /// The findings alone (relocation first), or nil when the XML doesn't parse.
    static func findings(in data: Data) -> [String]? {
        inspect(data)?.findings
    }

    private final class Scanner: NSObject, XMLParserDelegate {
        var stack: [String] = []
        var result = PackageInspection()
        var sawElement = false
        var pkgRefText = ""

        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                    qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
            sawElement = true
            let name = elementName.lowercased()
            func attribute(_ key: String) -> String? {
                attributeDict.first(where: { $0.key.lowercased() == key })?.value
            }
            if name == "bundle", stack.contains("relocate") {
                result.relocatable.append("relocatable bundle \(attributeDict["id"] ?? "(no id)")")
            }
            if let value = attribute("relocatable"), value.trimmingCharacters(in: .whitespaces).lowercased() == "true" {
                result.relocatable.append("<\(elementName)> relocatable=\"true\"")
            }
            if name == "domains", let local = attribute("enable_localsystem"),
               local.trimmingCharacters(in: .whitespaces).lowercased() == "false" {
                result.otherFindings.append("local-system install disabled (enable_localSystem=false)")
            }
            if name == "pkg-info", stack.isEmpty {
                let location = attribute("install-location") ?? "/"
                result.installLocations.append(.init(source: "", location: location))
                result.componentLocation = location
            }
            if name == "pkg-ref" { pkgRefText = "" }
            if name == "choice", let custom = attribute("customlocation") {
                result.installLocations.append(.init(source: "", location: custom))
            }
            stack.append(name)
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            if stack.last == "pkg-ref" { pkgRefText += string }
        }

        func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
            // Undecodable CDATA still counts as content, so it can't pass as empty.
            if stack.last == "pkg-ref" { pkgRefText += String(data: CDATABlock, encoding: .utf8) ?? "\u{FFFD}" }
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?,
                    qualifiedName qName: String?) {
            if elementName.lowercased() == "pkg-ref" {
                let content = pkgRefText.trimmingCharacters(in: .whitespacesAndNewlines)
                if !content.isEmpty { result.pkgRefContents.append(content) }
                pkgRefText = ""
            }
            if !stack.isEmpty { stack.removeLast() }
        }
    }
}

// MARK: - Uninstaller

/// What the user is asked to approve for an uninstall — only facts the daemon
/// established itself, never client-supplied text.
public struct UninstallConfirmation: Sendable, Equatable {
    /// The bundle's file name (checked like an installable app name).
    public let appName: String
    /// The canonical path of the bundle (reached without any symlink).
    public let canonicalPath: String
    /// The bundle's `CFBundleIdentifier`, when its Info.plist could be read.
    public let bundleID: String?
    /// The result of checking the bundle's code signature.
    public let signingStatus: SigningStatus
    /// The Team ID from a valid, Apple-anchored signature; nil otherwise.
    public let teamID: String?
}

/// What the daemon records about an uninstall attempt, filled in as far as
/// the flow got. Never returned to the caller.
public struct UninstallAudit: Sendable, Equatable {
    public var canonicalPath: String?
    public var bundleID: String?
    public var teamID: String?
    public init() {}
}

/// Moves a user-chosen `/Applications` app to the user's Trash (recoverable) AS
/// ROOT — the "Uninstall with Serberus" action. Lower-risk than install (nothing
/// runs), but deleting the wrong thing as root is dangerous, so every gate is
/// fail-closed and the target is pinned to a real `.app` directly inside
/// `/Applications` or `/Applications/Utilities`, reached without any symlink.
///
/// The target is identified by device + inode before the prompt and re-checked
/// after it; the move is a `renameat` relative to the already-open parent
/// directory, so the path can't be re-resolved to something else in between.
///
/// An app with a system-level background component is refused, so IT must
/// remove it: a LaunchDaemon, LaunchAgent or privileged helper embedded in it
/// or in any app nested inside it, an `SMPrivilegedExecutables` /
/// `SMAuthorizedClients` declaration, or a `/Library/LaunchDaemons` or
/// `/Library/LaunchAgents` job that runs code from it or names its bundle ID.
/// Moving it to the user's Trash would hand its executables to the user, and a
/// registered job could still run them.
///
/// Not a permanent delete: the app lands in the CALLER's `~/.Trash`, so a
/// mistake is undoable via Finder's Put Back. Only world-readable files,
/// world-listable and -searchable directories, and symlinks are handed to the
/// user; anything else (a directory with everything in it) is deleted as root
/// instead, so a root-only file can never become the user's.
public struct SoftwareUninstaller: Sendable {
    /// The console user's home + ids, resolved from a uid. Injected so tests
    /// target a temp Trash instead of the real one; production uses `getpwuid`.
    public struct UserInfo: Sendable { public let home: String; public let uid: uid_t; public let gid: gid_t }

    /// A file's identity (device + inode).
    struct FileID: Equatable, Sendable {
        let device: dev_t
        let inode: ino_t
        init(_ info: stat) { device = info.st_dev; inode = info.st_ino }
    }

    /// A checked code signature: its status and, when it is valid and
    /// Apple-anchored, its Team ID.
    public struct AppSignature: Sendable, Equatable {
        public let status: SigningStatus
        public let teamID: String?
        public init(status: SigningStatus, teamID: String?) { self.status = status; self.teamID = teamID }
    }

    /// The system launchd job folders checked for jobs that run an app's code.
    public static let defaultLaunchdDirectories = [
        URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true),
        URL(fileURLWithPath: "/Library/LaunchAgents", isDirectory: true),
    ]

    private let applicationsDir: URL
    private let resolveUser: @Sendable (uid_t) -> UserInfo?
    private let now: @Sendable () -> Date
    private let gate: AppManagementGate
    private let launchdDirectories: [URL]
    private let signatureOfApp: @Sendable (String) -> AppSignature

    public init(
        applicationsDir: URL = URL(fileURLWithPath: BundleConfig.applicationsDirectory, isDirectory: true),
        resolveUser: @escaping @Sendable (uid_t) -> UserInfo? = SoftwareUninstaller.systemUserInfo,
        now: @escaping @Sendable () -> Date = { Date() },
        gate: AppManagementGate = .shared,
        launchdDirectories: [URL] = SoftwareUninstaller.defaultLaunchdDirectories,
        signatureOfApp: @escaping @Sendable (String) -> AppSignature = { SoftwareUninstaller.checkedSignature(ofAppAt: $0) }
    ) {
        self.applicationsDir = applicationsDir
        self.resolveUser = resolveUser
        self.now = now
        self.gate = gate
        self.launchdDirectories = launchdDirectories
        self.signatureOfApp = signatureOfApp
    }

    public func uninstall(
        _ request: UninstallRequest,
        callerUID: uid_t,
        policy: InstallPolicy,
        confirm: @Sendable (UninstallConfirmation) async -> Bool
    ) async -> InstallResult {
        await uninstallAudited(request, callerUID: callerUID, policy: policy, confirm: confirm).result
    }

    /// ``uninstall(_:callerUID:policy:confirm:)`` plus what the daemon should
    /// record about the attempt (canonical path, bundle ID, team).
    public func uninstallAudited(
        _ request: UninstallRequest,
        callerUID: uid_t,
        policy: InstallPolicy,
        confirm: @Sendable (UninstallConfirmation) async -> Bool
    ) async -> (result: InstallResult, audit: UninstallAudit) {
        var audit = UninstallAudit()
        let result = await runUninstall(request, callerUID: callerUID, policy: policy, confirm: confirm, audit: &audit)
        return (result, audit)
    }

    private func runUninstall(
        _ request: UninstallRequest,
        callerUID: uid_t,
        policy: InstallPolicy,
        confirm: @Sendable (UninstallConfirmation) async -> Bool,
        audit: inout UninstallAudit
    ) async -> InstallResult {
        guard policy.uninstallAllowed else {
            return InstallResult(status: .refusedByPolicy,
                                 message: "Uninstall with Serberus is not enabled on this Mac.")
        }
        guard callerUID != 0 else {
            return InstallResult(status: .failed, message: "Refused: uninstall must come from a console user, not root.")
        }
        guard gate.acquire(uid: callerUID) else {
            appManagementLog.notice("uninstall: refused busy uid=\(callerUID, privacy: .public)")
            return AppManagementGate.busyResult
        }
        defer { gate.release(uid: callerUID) }
        guard let user = resolveUser(callerUID) else {
            return InstallResult(status: .failed, message: "Couldn't resolve the requesting user.")
        }
        let label = SoftwareInstaller.displayLabel(forPath: request.appPath)

        // Rejects relative, `.`/`..`, control-character and missing paths.
        do {
            _ = try PathCanonicalizer().canonicalize(request.appPath, existence: .requireExists)
        } catch {
            appManagementLog.notice("uninstall: path rejected: \(String(describing: error), privacy: .private)")
            return InstallResult(status: .refusedNotEligible, message: "Couldn't resolve “\(label)”.")
        }
        let components = request.appPath.split(separator: "/").map(String.init)
        guard let name = components.last, name.lowercased().hasSuffix(".app") else {
            return InstallResult(status: .refusedNotEligible, message: "Uninstall applies only to apps (.app).")
        }
        let parentPath = "/" + components.dropLast().joined(separator: "/")
        guard Self.isEligibleLocation(parent: parentPath, name: name, applicationsDir: Self.realPath(applicationsDir.path)) else {
            return InstallResult(status: .refusedNotEligible,
                                 message: "Uninstall with Serberus only removes apps directly in /Applications or /Applications/Utilities.")
        }

        // Pin the parent (opened component-by-component, never through a
        // symlink) and the target's identity BEFORE the prompt.
        guard let parent = Self.openDirectoryNoFollow(parentPath) else {
            return InstallResult(status: .refusedNotEligible, message: "Couldn't open the folder containing “\(label)” safely.")
        }
        defer { close(parent) }
        var parentInfo = stat(), targetInfo = stat()
        guard fstat(parent, &parentInfo) == 0,
              fstatat(parent, name, &targetInfo, AT_SYMLINK_NOFOLLOW) == 0,
              targetInfo.st_mode & S_IFMT == S_IFDIR else {
            return InstallResult(status: .refusedNotEligible, message: "“\(label)” is not an app bundle.")
        }
        // A SIP-protected bundle can't be moved even by root: refuse before
        // asking, rather than failing after the user approves.
        guard targetInfo.st_flags & UInt32(SF_RESTRICTED) == 0 else {
            return InstallResult(status: .refusedNotEligible,
                                 message: "“\(label)” is protected by macOS and can't be moved to the Trash.")
        }
        let parentID = FileID(parentInfo), targetID = FileID(targetInfo)
        // Every component was opened without following a symlink and the
        // name passed the app-name check, so this path is canonical.
        let fullPath = parentPath + "/" + name
        audit.canonicalPath = fullPath

        // Never let a user uninstall Serberus itself, or anything on the admin's
        // hard-deny list (`protectedBundleIdentifiers`) — the target and every
        // enclosing bundle, evaluated BEFORE the confirmation gate with no
        // prompt and no override. Missing/empty list ⇒ the prompt is the sole gate.
        for bundle in Self.bundlePaths(inPath: fullPath) {
            let bundleID = Self.bundleID(ofAppAt: bundle)
            if Self.isSerberusBundleID(bundleID) {
                return InstallResult(status: .refusedNotEligible, message: "Serberus can't uninstall its own app.")
            }
            if policy.isProtected(bundleID: bundleID) {
                return InstallResult(status: .refusedByPolicy,
                                     message: "“\(label)” is protected from uninstall by policy.")
            }
        }

        // An app carrying a system-level background component must be removed
        // by IT: moving it to the user's Trash hands its executables to the
        // user, and anything still registered could later run them as root.
        let targetFD = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard targetFD >= 0 else {
            return InstallResult(status: .refusedNotEligible, message: "“\(label)” is not an app bundle.")
        }
        var openedInfo = stat()
        let inspection: BundleInspection? = (fstat(targetFD, &openedInfo) == 0 && FileID(openedInfo) == targetID)
            ? Self.inspectBundle(targetFD) : nil
        close(targetFD)
        let jobs = inspection.flatMap {
            Self.launchdReferences(toBundleAt: fullPath, bundleIDs: $0.bundleIDs, in: launchdDirectories)
        }
        guard let inspection, let jobs else {
            return InstallResult(status: .refusedNotEligible,
                                 message: "“\(label)” couldn't be inspected safely, so it was left in place. Ask IT to remove it.")
        }
        audit.bundleID = inspection.bundleID
        // The same self/protected rule covers every app nested inside the
        // bundle: trashing the outer app trashes them too.
        for nestedID in inspection.bundleIDs {
            if Self.isSerberusBundleID(nestedID) {
                return InstallResult(status: .refusedNotEligible, message: "Serberus can't uninstall its own app.")
            }
            if policy.isProtected(bundleID: nestedID) {
                appManagementLog.notice("uninstall: refused, nested app is protected: \(SoftwareInstaller.sanitizedForDisplay(nestedID, maxLength: 128), privacy: .public)")
                return InstallResult(status: .refusedByPolicy,
                                     message: "“\(label)” contains an app that is protected from uninstall by policy.")
            }
        }
        let privileged = inspection.findings + jobs
        guard privileged.isEmpty else {
            appManagementLog.notice("uninstall: refused, system-level components: \(privileged.joined(separator: ", "), privacy: .public)")
            return InstallResult(status: .refusedNotEligible,
                                 message: "“\(label)” includes a system-level background component (a launch daemon, launch agent or privileged helper), so it can't be moved to the Trash by Serberus. Ask IT to remove it.",
                                 reason: .requiresIT)
        }

        // What the prompt shows: the canonical path, the bundle ID read from
        // the pinned bundle, and the result of actually checking its signature.
        let signature = signatureOfApp(fullPath)
        audit.teamID = signature.teamID
        let confirmation = UninstallConfirmation(
            appName: name, canonicalPath: fullPath,
            bundleID: inspection.bundleID.map { SoftwareInstaller.sanitizedForDisplay($0, maxLength: 128) },
            signingStatus: signature.status, teamID: signature.teamID)

        // Uninstall ALWAYS confirms — it moves an app to the Trash as root, so it
        // must never be silent, regardless of `promptBeforeAction` (which
        // governs install only). A right-click never mutates /Applications
        // without a user-visible confirmation.
        if await confirm(confirmation) == false {
            return InstallResult(status: .cancelled, message: "Uninstall cancelled.")
        }

        // Re-verify after the prompt: the parent path still leads to the same
        // directory, and the same bundle is still at `name` inside it.
        var recheck = stat()
        let reopened = Self.openDirectoryNoFollow(parentPath)
        defer { if let reopened { close(reopened) } }
        guard let reopened, fstat(reopened, &recheck) == 0, FileID(recheck) == parentID,
              fstatat(parent, name, &recheck, AT_SYMLINK_NOFOLLOW) == 0,
              recheck.st_mode & S_IFMT == S_IFDIR, FileID(recheck) == targetID else {
            return InstallResult(status: .failed, message: "“\(label)” changed while waiting for confirmation, so it was left in place.")
        }

        return moveToTrash(parent: parent, name: name, target: targetID, user: user, displayName: label)
    }

    // MARK: Eligibility

    /// A target is eligible only as a visible `.app` whose parent is exactly the
    /// Applications folder or its `Utilities` subfolder — never a bundle nested
    /// in another bundle or any deeper folder — and whose name passes the same
    /// check as an installed app's (no control, bidi or other format
    /// characters), since it is shown in the prompt and the log.
    static func isEligibleLocation(parent: String, name: String, applicationsDir: String) -> Bool {
        let apps = applicationsDir.hasSuffix("/") && applicationsDir.count > 1 ? String(applicationsDir.dropLast()) : applicationsDir
        guard parent == apps || parent == apps + "/Utilities" else { return false }
        return SoftwareInstaller.isAcceptableAppName(name)
    }

    /// Whether `bundleID` belongs to Serberus (case-insensitive, matching the
    /// case-insensitive protected-bundle list).
    static func isSerberusBundleID(_ bundleID: String?) -> Bool {
        guard let bundleID else { return false }
        return bundleID.lowercased().hasPrefix(BundleConfig.logSubsystem.lowercased())
    }

    /// Every `.app` along `path` (outermost first), including `path` itself when
    /// it is one — so the self/protected checks cover enclosing bundles too.
    static func bundlePaths(inPath path: String) -> [String] {
        var result: [String] = []
        var prefix = ""
        for component in path.split(separator: "/") {
            prefix += "/" + component
            if component.lowercased().hasSuffix(".app") { result.append(prefix) }
        }
        return result
    }

    /// What inspecting an app bundle found: system-level components (relative
    /// paths or declarations), and the bundle IDs of the bundle and every app
    /// nested inside it.
    struct BundleInspection: Equatable, Sendable {
        var findings: [String] = []
        /// The top bundle's `CFBundleIdentifier`.
        var bundleID: String?
        /// The top bundle's and every nested app's bundle IDs.
        var bundleIDs: [String] = []
    }

    /// Entries walked when looking for apps nested in a bundle; over this, the
    /// bundle can't be inspected (refuse).
    static let maxInspectedEntries = 1_000_000
    /// Largest launchd job plist or Info.plist parsed.
    static let maxPlistBytes = 1 << 20
    /// Folders under `Contents/Library` whose plists (or, for
    /// `LaunchServices`, any entry) are system-level components.
    private static let componentFolders: [(String, @Sendable (String) -> Bool)] = [
        ("LaunchDaemons", { $0.lowercased().hasSuffix(".plist") }),
        ("LaunchAgents", { $0.lowercased().hasSuffix(".plist") }),
        ("LaunchServices", { _ in true }),
    ]
    /// Info.plist keys declaring an `SMJobBless` privileged helper relationship.
    private static let privilegedInfoKeys = ["SMPrivilegedExecutables", "SMAuthorizedClients"]

    /// The system-level components an app bundle carries, in the bundle itself
    /// and in every `.app` nested anywhere inside it: plists in
    /// `Contents/Library/LaunchDaemons` or `Contents/Library/LaunchAgents`,
    /// anything in `Contents/Library/LaunchServices` (legacy `SMJobBless`
    /// helpers), and an Info.plist declaring `SMPrivilegedExecutables` or
    /// `SMAuthorizedClients`. Empty when there are none; nil when the bundle
    /// couldn't be inspected without following a symlink or within the
    /// budget. `bundleFD` is an open directory descriptor for the bundle.
    static func privilegedComponents(inBundle bundleFD: Int32) -> [String]? {
        inspectBundle(bundleFD)?.findings
    }

    static func inspectBundle(_ bundleFD: Int32) -> BundleInspection? {
        var result = BundleInspection()
        guard let top = componentFindings(inBundle: bundleFD, prefix: "") else { return nil }
        result.findings = top.findings
        result.bundleID = top.bundleID
        result.bundleIDs = top.bundleID.map { [$0] } ?? []
        var budget = maxInspectedEntries
        guard findNestedApps(bundleFD, prefix: "", depth: 0, budget: &budget, into: &result) else { return nil }
        return result
    }

    /// One bundle's own components and bundle ID (not its nested apps).
    private static func componentFindings(inBundle bundleFD: Int32, prefix: String) -> (findings: [String], bundleID: String?)? {
        enum Opened { case fd(Int32), missing, failed }
        func openSubdirectory(_ dirFD: Int32, _ name: String) -> Opened {
            let fd = openat(dirFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if fd >= 0 { return .fd(fd) }
            return errno == ENOENT ? .missing : .failed
        }
        let contents: Int32
        switch openSubdirectory(bundleFD, "Contents") {
        case let .fd(fd): contents = fd
        case .missing: return ([], nil)
        case .failed: return nil
        }
        defer { close(contents) }
        var found: [String] = []
        var bundleID: String?
        switch FileTree.readRegularFile(in: contents, name: "Info.plist", maxBytes: maxPlistBytes) {
        case .missing: break
        case .invalid: return nil
        case let .data(data):
            // An Info.plist that doesn't parse is treated as declaring nothing:
            // the bundle then can't be launched as an app either.
            if let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] {
                bundleID = info["CFBundleIdentifier"] as? String
                found += privilegedInfoKeys.filter { info[$0] != nil }.map { "\(prefix)Contents/Info.plist \($0)" }
            }
        }
        let library: Int32
        switch openSubdirectory(contents, "Library") {
        case let .fd(fd): library = fd
        case .missing: return (found, bundleID)
        case .failed: return nil
        }
        defer { close(library) }
        for (folder, matches) in componentFolders {
            switch openSubdirectory(library, folder) {
            case .missing: continue
            case .failed: return nil
            case let .fd(fd):
                defer { close(fd) }
                guard let names = FileTree.entryNames(fd, limit: 10_000) else { return nil }
                found += names.map(FileTree.displayName)
                    .filter { !$0.hasPrefix(".") && matches($0) }
                    .map { "\(prefix)Contents/Library/\(folder)/\($0)" }
            }
        }
        return (found, bundleID)
    }

    /// Walks the directory `dirFD` (never following a symlink) for `.app`
    /// directories and adds each one's components and bundle ID. False when
    /// something couldn't be opened, or the depth or entry budget ran out.
    private static func findNestedApps(_ dirFD: Int32, prefix: String, depth: Int, budget: inout Int,
                                       into result: inout BundleInspection) -> Bool {
        guard depth < FileTree.maxDepth, let names = FileTree.entryNames(dirFD, limit: budget + 1) else { return false }
        budget -= names.count
        guard budget >= 0 else { return false }
        for name in names {
            let display = FileTree.displayName(name)
            let relative = prefix + display
            let ok = name.withUnsafeBufferPointer { buffer -> Bool in
                guard let cName = buffer.baseAddress else { return false }
                var info = stat()
                guard fstatat(dirFD, cName, &info, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
                guard FileTree.isDirectory(info) else { return true }
                let child = openat(dirFD, cName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { return false }
                defer { close(child) }
                if display.lowercased().hasSuffix(".app") {
                    guard let nested = componentFindings(inBundle: child, prefix: relative + "/") else { return false }
                    result.findings += nested.findings
                    if let id = nested.bundleID { result.bundleIDs.append(id) }
                }
                return findNestedApps(child, prefix: relative + "/", depth: depth + 1, budget: &budget, into: &result)
            }
            if !ok { return false }
        }
        return true
    }

    /// The system launchd jobs (`*.plist` directly in `directories`) that
    /// refer to the bundle at `bundlePath`: `Program`, any element of
    /// `ProgramArguments` (an interpreter's script counts), `BundleProgram` or
    /// `WorkingDirectory` inside it, or a `Label` or
    /// `AssociatedBundleIdentifiers` entry equal to one of `bundleIDs` (the
    /// bundle's and its nested apps'), case-insensitively. Plists are read without following a
    /// symlink, up to ``maxPlistBytes`` (a larger one refuses: it can't be
    /// inspected), and parsed as property lists (no entity resolution). A
    /// plist that doesn't parse can't be loaded by launchd and is skipped.
    /// Nil when a folder or plist couldn't be read.
    static func launchdReferences(toBundleAt bundlePath: String, bundleIDs: [String], in directories: [URL]) -> [String]? {
        let bundleLower = bundlePath.lowercased()
        let realBundleLower = realPath(bundlePath).lowercased()
        let ids = Set(bundleIDs.map { $0.lowercased() })
        func pointsIntoBundle(_ value: Any?) -> Bool {
            guard let path = value as? String, path.hasPrefix("/") else { return false }
            let candidates = [lexicallyNormalized(path), realPath(path)].map { $0.lowercased() }
            return candidates.contains { candidate in
                [bundleLower, realBundleLower].contains { candidate == $0 || candidate.hasPrefix($0 + "/") }
            }
        }
        var found: [String] = []
        for directory in directories {
            let dirFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard dirFD >= 0 else {
                if errno == ENOENT { continue }
                return nil
            }
            defer { close(dirFD) }
            guard let names = FileTree.entryNames(dirFD, limit: 10_001), names.count <= 10_000 else { return nil }
            for display in names.map(FileTree.displayName) where display.lowercased().hasSuffix(".plist") && !display.hasPrefix(".") {
                let data: Data
                switch FileTree.readRegularFile(in: dirFD, name: display, maxBytes: maxPlistBytes) {
                case .missing:
                    continue
                case .invalid:
                    // Not a regular file (launchd skips those), or too big to inspect.
                    var info = stat()
                    if fstatat(dirFD, display, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_mode & S_IFMT != S_IFREG { continue }
                    return nil
                case let .data(bytes):
                    data = bytes
                }
                guard let job = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else { continue }
                let arguments = job["ProgramArguments"] as? [Any]
                let associated: [String]
                if let list = job["AssociatedBundleIdentifiers"] as? [Any] {
                    associated = list.compactMap { $0 as? String }
                } else if let single = job["AssociatedBundleIdentifiers"] as? String {
                    associated = [single]
                } else {
                    associated = []
                }
                let label = (job["Label"] as? String)?.lowercased()
                if pointsIntoBundle(job["Program"]) || (arguments ?? []).contains(where: pointsIntoBundle)
                    || pointsIntoBundle(job["BundleProgram"]) || pointsIntoBundle(job["WorkingDirectory"])
                    || label.map(ids.contains) == true
                    || associated.contains(where: { ids.contains($0.lowercased()) }) {
                    found.append("\(directory.path)/\(display)")
                }
            }
        }
        return found
    }

    /// `path` with `.` and `..` components and repeated slashes removed,
    /// without touching the filesystem (unlike `standardizingPath`, which can
    /// also drop a `/private` prefix).
    static func lexicallyNormalized(_ path: String) -> String {
        var parts: [Substring] = []
        for component in path.split(separator: "/") where component != "." {
            if component == ".." { _ = parts.popLast() } else { parts.append(component) }
        }
        return "/" + parts.joined(separator: "/")
    }

    /// Checks an app bundle's code signature (strict validation of the bundle
    /// and its resources; nested code isn't re-verified): `.valid` with the
    /// Team ID when it is valid and anchored to Apple, `.unsigned` when it has
    /// no signature, `.adhoc` for an ad-hoc signature, `.invalid` otherwise.
    public static func checkedSignature(ofAppAt path: String) -> AppSignature {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { return AppSignature(status: .invalid, teamID: nil) }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return AppSignature(status: .invalid, teamID: nil) }
        let status = SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate), requirement)
        if status == errSecCSUnsigned { return AppSignature(status: .unsigned, teamID: nil) }
        var info: CFDictionary?
        let dict: [String: Any]? = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess
            ? info as? [String: Any] : nil
        guard status == errSecSuccess else {
            let flags = (dict?[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
            let adhoc = flags & SecCodeSignatureFlags.adhoc.rawValue != 0
            return AppSignature(status: adhoc ? .adhoc : .invalid, teamID: nil)
        }
        let team = (dict?[kSecCodeInfoTeamIdentifier as String] as? String).flatMap {
            SoftwareInstaller.isWellFormedTeamID($0) ? $0 : nil
        }
        return AppSignature(status: .valid, teamID: team)
    }

    /// `realpath(3)` of `path`, or `path` when it can't be resolved.
    static func realPath(_ path: String) -> String {
        guard let resolved = realpath(path, nil) else { return path }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    /// Opens an absolute directory path one component at a time from `/`, each
    /// with `O_NOFOLLOW | O_DIRECTORY`, so the result was reached without
    /// passing through any symlink. nil on any failure. Caller closes.
    static func openDirectoryNoFollow(_ path: String) -> Int32? {
        guard path.hasPrefix("/") else { return nil }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        for component in path.split(separator: "/") {
            guard component != ".", component != ".." else { close(fd); return nil }
            let next = openat(fd, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(fd)
            guard next >= 0 else { return nil }
            fd = next
        }
        return fd
    }

    // MARK: Move to Trash

    /// Production home resolver via the password database.
    public static let systemUserInfo: @Sendable (uid_t) -> UserInfo? = { uid in
        guard let pw = getpwuid(uid) else { return nil }
        let home = String(cString: pw.pointee.pw_dir)
        guard !home.isEmpty, home != "/var/empty" else { return nil }
        return UserInfo(home: home, uid: uid, gid: pw.pointee.pw_gid)
    }

    /// An app bundle's `Contents/Info.plist` as a dictionary, or nil. Read
    /// without following a symlink at `Contents` or `Info.plist`, only from a
    /// regular file of at most 1 MiB, opened non-blocking — so a user-owned app
    /// can't point root at another file or stall it on a FIFO.
    static func infoPlist(ofAppAt appPath: String) -> [String: Any]? {
        let appFD = open(appPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard appFD >= 0 else { return nil }
        defer { close(appFD) }
        let contentsFD = openat(appFD, "Contents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard contentsFD >= 0 else { return nil }
        defer { close(contentsFD) }
        guard case let .data(data) = FileTree.readRegularFile(in: contentsFD, name: "Info.plist", maxBytes: 1 << 20),
              let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) else { return nil }
        return obj as? [String: Any]
    }

    /// Reads `CFBundleIdentifier` from an app bundle's Info.plist, or `nil` when
    /// it can't be read. Shared by the Serberus-self check and the admin
    /// protected-bundle-id hard-deny list.
    static func bundleID(ofAppAt appPath: String) -> String? {
        infoPlist(ofAppAt: appPath)?["CFBundleIdentifier"] as? String
    }

    /// Moves the app into the user's Trash, then hands it to the user.
    /// `~/.Trash` is opened without following a symlink and checked to be their
    /// own directory; the move is `renameat` between the two open directories.
    /// Ownership is handed over only AFTER the move, through descriptors on the
    /// moved bundle (never a path the user could redirect). Files that aren't
    /// world-readable, and folders that aren't world-listable and -searchable
    /// (or that an ACL deny entry hides from the user), are deleted instead
    /// of handed over. The move never replaces anything
    /// already in the Trash (`RENAME_EXCL`): a name that's taken gets a
    /// timestamp before its `.app` suffix.
    private func moveToTrash(parent: Int32, name: String, target: FileID, user: UserInfo, displayName: String) -> InstallResult {
        guard let trash = Self.openTrash(home: user.home, user: user) else {
            return InstallResult(status: .failed,
                                 message: "Couldn't use your Trash folder safely, so “\(displayName)” was left in place.")
        }
        defer { close(trash) }

        let base = String(name.dropLast(4))
        let stamp = Int(now().timeIntervalSince1970)
        let candidates = [name, "\(base) \(stamp).app"] + (1...8).map { "\(base) \(stamp)-\($0).app" }
        var moved: String?
        for candidate in candidates {
            if renameatx_np(parent, name, trash, candidate, UInt32(RENAME_EXCL)) == 0 {
                moved = candidate
                break
            }
            guard errno == EEXIST else { break }
        }
        guard let destinationName = moved else {
            appManagementLog.error("uninstall: rename into the Trash failed: \(String(cString: strerror(errno)), privacy: .public)")
            return InstallResult(status: .failed, message: "Couldn't move “\(displayName)” to the Trash.")
        }
        let handOff = Self.handOwnership(inDirectory: trash, name: destinationName, expected: target, to: user)
        if let handOff, !handOff.removed.isEmpty || !handOff.kept.isEmpty {
            appManagementLog.notice("uninstall: hand-off deleted \(handOff.removed.joined(separator: ", "), privacy: .private); kept as system-owned \(handOff.kept.joined(separator: ", "), privacy: .private)")
        }
        return InstallResult(status: .removed, message: Self.trashMessage(handOff), installedName: displayName)
    }

    /// What the Trash hand-off did besides re-owning entries to the user.
    struct HandOff: Equatable, Sendable {
        /// Relative paths deleted as root instead of being handed over.
        var removed: [String] = []
        /// Relative paths that stayed owned by the system (couldn't be
        /// re-owned or deleted).
        var kept: [String] = []
    }

    /// The uninstall result message: a clean hand-off, or — in general terms,
    /// never naming files — that some files were deleted or stayed owned by
    /// the system (so the user knows emptying the Trash may need IT).
    static func trashMessage(_ handOff: HandOff?) -> String {
        guard let handOff else {
            return "Moved to the Trash, but it couldn't be handed over to you — it stays owned by the system. Ask IT if you can't empty the Trash."
        }
        var message = "Moved to the Trash."
        if !handOff.removed.isEmpty {
            message += " Some files in it that weren't readable by everyone were deleted instead of being handed to you."
        }
        if !handOff.kept.isEmpty {
            message += " Some items stayed owned by the system. Ask IT if you can't empty the Trash."
        }
        return message
    }

    /// Whether the Trash hand-off may re-own an entry: a directory only when
    /// everyone may list and search it (`S_IROTH | S_IXOTH`); a regular file
    /// only with exactly one link AND read permission for everyone
    /// (`S_IROTH`); a symlink (its own entry, never its target) with exactly
    /// one link. Re-owning then discloses nothing the user couldn't already
    /// read. A second link means the same inode also lives elsewhere.
    /// Anything else is deleted as root instead — a directory together with
    /// everything in it, so nothing under a folder the user couldn't search
    /// is ever handed over.
    static func mayHandOwnership(mode: mode_t, linkCount: nlink_t) -> Bool {
        switch mode & S_IFMT {
        case S_IFDIR: return mode & (S_IROTH | S_IXOTH) == (S_IROTH | S_IXOTH)
        case S_IFREG: return linkCount == 1 && mode & S_IROTH != 0
        case S_IFLNK: return linkCount == 1
        default: return false
        }
    }

    /// Whether an extended ACL deny entry on the open entry `fd` (`info` is
    /// its `fstat`) takes from `reader` what ``mayHandOwnership(mode:linkCount:)``
    /// requires everyone to have — read on a file, list and search on a
    /// directory — the same evaluation the install scan uses
    /// (``SoftwareInstaller/aclDenies(_:want:isDirectory:reader:)``). A
    /// symlink's own entry has nothing to read.
    static func aclDeniesHandOff(_ fd: Int32, _ info: stat, reader: SoftwareInstaller.SourceReader) -> Bool {
        switch info.st_mode & S_IFMT {
        case S_IFDIR:
            return SoftwareInstaller.aclDenies(acl_get_fd_np(fd, ACL_TYPE_EXTENDED), want: S_IROTH | S_IXOTH, isDirectory: true, reader: reader)
        case S_IFREG:
            return SoftwareInstaller.aclDenies(acl_get_fd_np(fd, ACL_TYPE_EXTENDED), want: S_IROTH, isDirectory: false, reader: reader)
        default:
            return false
        }
    }

    /// Re-owns the bundle at `name` in `directory` to `user`, children before
    /// their directory, through descriptors, never following a symlink. An
    /// entry that may not be handed over (``mayHandOwnership(mode:linkCount:)``,
    /// or an ACL deny entry for the user, ``aclDeniesHandOff(_:_:reader:)``)
    /// is deleted as root with `unlinkat` relative to its (still root-owned)
    /// directory. When the bundle folder itself isn't world-listable and
    /// searchable (the same two checks), everything in it is deleted through the pinned descriptor
    /// and only the empty folder is handed over. The bundle must still be the
    /// one that was moved (`expected`). Nil if the bundle couldn't be re-found.
    static func handOwnership(inDirectory directory: Int32, name: String, expected: FileID, to user: UserInfo) -> HandOff? {
        let fd = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, FileID(info) == expected else { return nil }
        var result = HandOff()
        let reader = SoftwareInstaller.SourceReader(uid: user.uid, groups: SoftwareInstaller.groupIDs(ofUID: user.uid) ?? [user.gid])
        if mayHandOwnership(mode: info.st_mode, linkCount: 1), !aclDeniesHandOff(fd, info, reader: reader) {
            if !handDirectory(fd, prefix: "", depth: 0, to: user, reader: reader, result: &result) { result.kept.append("(unreadable entries)") }
        } else {
            guard let children = FileTree.entryNames(fd) else {
                result.kept.append(".")
                return result
            }
            for child in children {
                let relative = FileTree.displayName(child)
                if FileTree.removeEntry(in: fd, name: child) {
                    result.removed.append(relative)
                } else {
                    result.kept.append(relative)
                }
            }
            // Hand over only an emptied folder.
            guard result.kept.isEmpty else {
                result.kept.append(".")
                return result
            }
        }
        if fchown(fd, user.uid, user.gid) != 0 { result.kept.append(".") }
        return result
    }

    /// Hands over (or deletes) every entry beneath the open directory `dirFD`.
    /// False when some entry couldn't be examined.
    private static func handDirectory(_ dirFD: Int32, prefix: String, depth: Int, to user: UserInfo,
                                      reader: SoftwareInstaller.SourceReader, result: inout HandOff) -> Bool {
        guard depth < FileTree.maxDepth, let names = FileTree.entryNames(dirFD) else { return false }
        var ok = true
        for name in names {
            let display = FileTree.displayName(name)
            let relative = prefix.isEmpty ? display : prefix + "/" + display
            let entryOK = name.withUnsafeBufferPointer { buffer -> Bool in
                guard let cName = buffer.baseAddress else { return false }
                var before = stat()
                guard fstatat(dirFD, cName, &before, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
                guard mayHandOwnership(mode: before.st_mode, linkCount: before.st_nlink) else {
                    if FileTree.removeEntry(in: dirFD, name: name) {
                        result.removed.append(relative)
                    } else {
                        result.kept.append(relative)
                    }
                    return true
                }
                let directory = FileTree.isDirectory(before)
                let flags = directory ? (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                                      : (O_RDONLY | O_NONBLOCK | O_SYMLINK | O_CLOEXEC)
                let fd = openat(dirFD, cName, flags)
                guard fd >= 0 else { return false }
                defer { close(fd) }
                var info = stat()
                // The entry opened must be the one examined.
                guard fstat(fd, &info) == 0, FileID(info) == FileID(before),
                      mayHandOwnership(mode: info.st_mode, linkCount: info.st_nlink) else {
                    result.kept.append(relative)
                    return true
                }
                // An ACL deny entry hides it from the user as the mode bits
                // would: once theirs they could just remove the ACL.
                if aclDeniesHandOff(fd, info, reader: reader) {
                    if FileTree.removeEntry(in: dirFD, name: name) {
                        result.removed.append(relative)
                    } else {
                        result.kept.append(relative)
                    }
                    return true
                }
                let childrenOK = directory ? handDirectory(fd, prefix: relative, depth: depth + 1, to: user, reader: reader, result: &result) : true
                if fchown(fd, user.uid, user.gid) != 0 { result.kept.append(relative) }
                return childrenOK
            }
            if !entryOK { ok = false }
        }
        return ok
    }

    /// Opens `<home>/.Trash` without following a symlink, creating it (0700,
    /// owned by the user) if it's missing. Returns nil unless it's a real
    /// directory owned by the user. The caller closes the descriptor.
    static func openTrash(home: String, user: UserInfo) -> Int32? {
        let trashPath = (home as NSString).appendingPathComponent(".Trash")
        let created = mkdir(trashPath, 0o700) == 0   // mkdir never follows a symlink
        guard created || errno == EEXIST else { return nil }
        let fd = open(trashPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        if created {
            // Created as root; the user must own their Trash.
            _ = fchown(fd, user.uid, user.gid)
        }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == user.uid else {
            close(fd)
            return nil
        }
        return fd
    }
}

// MARK: - Descriptor-based tree walk

/// Walks a file tree through descriptors without ever following a symlink:
/// every entry is opened *itself* (`O_NOFOLLOW` for directories, `O_SYMLINK`
/// for everything else, so a symlink yields the link, never its target) and
/// handed to the visitor as an open fd plus that fd's `fstat`, so a check and
/// the change that follows it apply to the same object.
enum FileTree {
    /// Bits a root-installed file must not carry: group/other write, setuid, setgid.
    static let forbiddenModeBits: mode_t = S_IWGRP | S_IWOTH | S_ISUID | S_ISGID
    static let maxDepth = 128
    /// BSD flags kept on a normalized entry: they restrict nothing (clearing
    /// `UF_COMPRESSED` would force decompression).
    static let keptFlags = UInt32(UF_COMPRESSED) | UInt32(UF_TRACKED)
    /// The system (`SF_*`) half of `st_flags`; only root can set these.
    static let systemFlagsMask: UInt32 = 0xFFFF_0000

    static func isDirectory(_ info: stat) -> Bool { info.st_mode & S_IFMT == S_IFDIR }
    static func isSymlink(_ info: stat) -> Bool { info.st_mode & S_IFMT == S_IFLNK }

    /// Visits the item at `path` (not followed if a symlink — refused) and, for
    /// a directory, everything beneath it; children before their directory.
    /// True only if every entry opened and every visit returned true.
    static func walkItem(atPath path: String,
                         _ visit: (_ fd: Int32, _ info: stat, _ relativePath: String) -> Bool) -> Bool {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, !isSymlink(info) else { return false }
        let childrenOK = isDirectory(info) ? walk(directory: fd, visit) : true
        let selfOK = visit(fd, info, ".")
        return childrenOK && selfOK
    }

    /// Visits every entry beneath the open directory `dirFD` (not `dirFD`
    /// itself), post-order. Keeps going after a failure; returns false if any
    /// entry couldn't be opened or any visit returned false.
    static func walk(directory dirFD: Int32, prefix: String = "", depth: Int = 0,
                     _ visit: (_ fd: Int32, _ info: stat, _ relativePath: String) -> Bool) -> Bool {
        guard depth < maxDepth, let names = entryNames(dirFD) else { return false }
        var ok = true
        for name in names {
            let display = displayName(name)
            let relative = prefix.isEmpty ? display : prefix + "/" + display
            let entryOK = name.withUnsafeBufferPointer { buffer -> Bool in
                guard let cName = buffer.baseAddress else { return false }
                var before = stat()
                guard fstatat(dirFD, cName, &before, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
                let directory = isDirectory(before)
                let flags = directory ? (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                                      : (O_RDONLY | O_NONBLOCK | O_SYMLINK | O_CLOEXEC)
                let fd = openat(dirFD, cName, flags)
                guard fd >= 0 else { return false }
                defer { close(fd) }
                var info = stat()
                guard fstat(fd, &info) == 0, isDirectory(info) == directory else { return false }
                let childrenOK = directory ? walk(directory: fd, prefix: relative, depth: depth + 1, visit) : true
                let selfOK = visit(fd, info, relative)
                return childrenOK && selfOK
            }
            if !entryOK { ok = false }
        }
        return ok
    }

    /// A NUL-terminated entry name as a display string.
    static func displayName(_ name: [CChar]) -> String {
        String(decoding: name.dropLast().map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// The NUL-terminated names in the open directory, excluding `.` and `..`,
    /// byte-exact (no lossy String round-trip). Stops after `limit` names, so
    /// a caller enforcing a budget never materializes a huge directory.
    static func entryNames(_ dirFD: Int32, limit: Int = .max) -> [[CChar]]? {
        let dupFD = dup(dirFD)
        guard dupFD >= 0 else { return nil }
        guard let dir = fdopendir(dupFD) else { close(dupFD); return nil }
        defer { closedir(dir) }
        rewinddir(dir)
        var names: [[CChar]] = []
        while names.count < limit, let entry = readdir(dir) {
            let length = Int(entry.pointee.d_namlen)
            var name = withUnsafeBytes(of: entry.pointee.d_name) { raw in
                raw.prefix(length).map { CChar(bitPattern: $0) }
            }
            if name == [46] || name == [46, 46] { continue }   // "." / ".."
            name.append(0)
            names.append(name)
        }
        return names
    }

    enum FileRead { case missing, invalid, data(Data) }

    /// Reads `name` in `dirFD` only if it is a regular file (opened
    /// `O_NOFOLLOW | O_NONBLOCK`, so a symlink or FIFO is refused without
    /// blocking) of at most `maxBytes`.
    static func readRegularFile(in dirFD: Int32, name: String, maxBytes: Int) -> FileRead {
        let fd = openat(dirFD, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return errno == ENOENT ? .missing : .invalid }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size >= 0, info.st_size <= maxBytes else { return .invalid }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n < 0 { if errno == EINTR { continue }; return .invalid }
            if n == 0 { break }
            data.append(contentsOf: buffer[0..<n])
            if data.count > maxBytes { return .invalid }
        }
        return .data(data)
    }

    // MARK: Removal

    /// BSD flags that stop an entry (or a directory's children) being removed.
    static let removalBlockingFlags = UInt32(UF_IMMUTABLE) | UInt32(UF_APPEND)
        | UInt32(SF_IMMUTABLE) | UInt32(SF_APPEND) | UInt32(SF_NOUNLINK)

    /// Removes the item at `path` (its parent is a daemon-controlled directory)
    /// through descriptors: see ``removeEntry(in:name:depth:)``. True when
    /// nothing remains (a missing item counts as removed).
    @discardableResult
    static func removeTree(atPath path: String) -> Bool {
        let parent = (path as NSString).deletingLastPathComponent
        let name = (path as NSString).lastPathComponent
        guard !name.isEmpty, name != ".", name != ".." else { return false }
        let parentFD = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parentFD >= 0 else { return errno == ENOENT }
        defer { close(parentFD) }
        return removeEntry(in: parentFD, name: Array(name.utf8CString))
    }

    /// ``removeTree(atPath:)``, logging (not throwing) a failure — the
    /// replacement for `try? FileManager.removeItem`, which silently leaves
    /// flag-locked residue behind.
    static func removeTreeLogged(atPath path: String, context: String) {
        if !removeTree(atPath: path) {
            appManagementLog.error("cleanup: couldn't fully remove \(context, privacy: .public) at \(path, privacy: .public)")
        }
    }

    /// Removes entry `name` of `dirFD` and, for a directory, everything under
    /// it — `fstatat(AT_SYMLINK_NOFOLLOW)`, `openat(O_NOFOLLOW)`, `unlinkat`,
    /// all relative to open descriptors, so swapping a subdirectory for a
    /// symlink mid-walk only ever removes the link. Blocking BSD flags
    /// (`uchg`, `uappnd`, `schg`, …) are cleared first. True when the entry
    /// is gone.
    @discardableResult
    static func removeEntry(in dirFD: Int32, name: [CChar], depth: Int = 0) -> Bool {
        name.withUnsafeBufferPointer { buffer -> Bool in
            guard let cName = buffer.baseAddress else { return false }
            var info = stat()
            guard fstatat(dirFD, cName, &info, AT_SYMLINK_NOFOLLOW) == 0 else { return errno == ENOENT }
            if isDirectory(info) {
                guard depth < maxDepth * 2 else { return false }
                let fd = openat(dirFD, cName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if fd >= 0 {
                    defer { close(fd) }
                    var opened = stat()
                    guard fstat(fd, &opened) == 0 else { return false }
                    clearRemovalFlags(fd, opened.st_flags)
                    guard let names = entryNames(fd) else { return false }
                    var ok = true
                    for child in names where !removeEntry(in: fd, name: child, depth: depth + 1) { ok = false }
                    guard ok else { return false }
                    return unlinkat(dirFD, cName, AT_REMOVEDIR) == 0 || errno == ENOENT
                }
                // Swapped for a non-directory since the fstatat: remove the
                // entry itself (never what a symlink points to).
                guard errno == ENOTDIR || errno == ELOOP else { return errno == ENOENT }
            } else if info.st_flags & removalBlockingFlags != 0 {
                let fd = openat(dirFD, cName, O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC)
                if fd >= 0 {
                    var opened = stat()
                    if fstat(fd, &opened) == 0 { clearRemovalFlags(fd, opened.st_flags) }
                    close(fd)
                }
            }
            return unlinkat(dirFD, cName, 0) == 0 || errno == ENOENT
        }
    }

    /// Clears every flag but ``keptFlags`` on `fd` when any is set.
    @discardableResult
    private static func clearRemovalFlags(_ fd: Int32, _ current: UInt32) -> Bool {
        let wanted = current & keptFlags
        guard current != wanted else { return true }
        return fchflags(fd, wanted) == 0
    }

    static func hasExtendedACL(_ fd: Int32) -> Bool {
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else { return false }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }

    /// Removes any extended ACL (a user-added ACL could otherwise keep granting
    /// write access to a root-owned file). True when none remains.
    static func clearExtendedACL(_ fd: Int32) -> Bool {
        guard hasExtendedACL(fd) else { return true }
        guard let empty = acl_init(0) else { return false }
        defer { acl_free(UnsafeMutableRawPointer(empty)) }
        return acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED) == 0 && !hasExtendedACL(fd)
    }
}

enum InstallStagingError: Error, CustomStringConvertible {
    case requestDirUnavailable(Int32)
    case stagingRootUnsafe(Int32)
    var description: String {
        switch self {
        case let .requestDirUnavailable(code): return "couldn't create the per-request staging dir (errno \(code))"
        case let .stagingRootUnsafe(code): return "the staging root isn't a root-only directory (errno \(code))"
        }
    }
}
