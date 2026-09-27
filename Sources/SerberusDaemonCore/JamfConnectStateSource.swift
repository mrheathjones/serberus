import Foundation
import PrivMgrCore

/// Reads a console user's IdP-group membership hint from the Jamf Connect state
/// cache (`com.jamf.connect.state`, key `UserGroups`) — the untrusted-input
/// frontier of IdP-group enrollment.
///
/// # Trust posture
/// The state file is, by default, owned and writable by the console user, so
/// its contents are a *self-asserted hint*, never an attestation. This reader's
/// job is to (a) confine the read to the verified console user's own file and
/// (b) hand the raw group array to ``IDPGroupResolver`` — which can only ever
/// turn a match into the enrollment of that same verified console user's name.
///
/// The read is TOCTOU-safe:
/// - the path is **home-relative only** (rejecting a leading `/` or any `..`
///   component) and is joined onto the `getpwuid` home directory carried by the
///   ``ConsoleUser`` — never a plist-supplied or computed `/Users/<name>` path;
/// - the file is reached by a **component-by-component `openat` walk anchored at
///   the trusted home directory**: the home is the trust anchor (its
///   path is root/system-controlled), and every component BELOW it — which the
///   console user owns and can replace — is opened `O_NOFOLLOW`, so a symlinked
///   INTERMEDIATE component (e.g. `~/Library`) can no longer redirect the read
///   the way a single `open(home + "/" + path, O_NOFOLLOW)` allowed (that guards
///   only the FINAL component). A symlinked component fails `ELOOP`/`ENOTDIR` and
///   is refused, never followed — closing both the strict-mode bypass (aiming
///   the read at an arbitrary root-owned plist) and the symlink-to-hung-mount DoS;
/// - `O_NONBLOCK` on each `openat` keeps a fifo from blocking the daemon and
///   `O_CLOEXEC` keeps the fds from leaking across exec;
/// - all ownership / mode / regular-file decisions are made against the
///   `fstat` of the **open descriptor**, not a pre-open `stat` of the path, so
///   there is no window to swap the file between check and read;
/// - the file must have exactly one link (`st_nlink == 1`) and sit on the
///   home directory's device, so a hard link to some other root-owned file
///   cannot pass the strict root-ownership check;
/// - contents are read directly and parsed with `PropertyListSerialization`,
///   **never** through `CFPreferences` (which would consult the managed layer
///   and caches rather than this exact file).
///
/// A defense-in-depth read timeout (``withDetachedTimeout``) belongs to the
/// caller (``DaemonController``): the read runs on a detached task so a
/// pathological blocking `openat` (a real hung mountpoint the `O_NOFOLLOW` walk
/// cannot detect as a symlink) can never pin the actor and stall every sudo.
///
/// Every refusal / anomaly is fail-safe: it returns `nil` or throws an
/// ``IDPSourceRefusal``, both of which the resolver maps to "no one enrolled".
public struct JamfConnectStateSource: IDPGroupSourceProviding {
    /// Hard cap on the state file size read into memory. A Jamf Connect state
    /// plist is a few KiB; anything past 1 MiB is treated as anomalous and
    /// dropped fail-safe rather than read.
    public static let maxStateFileBytes = 1 << 20 // 1 MiB

    private let warn: @Sendable (String) -> Void

    public init(warn: @escaping @Sendable (String) -> Void = JamfConnectStateSource.defaultWarn) {
        self.warn = warn
    }

    /// Default audit sink: the daemon's integrity `os.Logger` stream.
    public static let defaultWarn: @Sendable (String) -> Void = { message in
        DaemonLog.integrity.notice("idp-source: \(message, privacy: .public)")
    }

    public func readClaim(
        for user: ConsoleUser,
        config: SerberusConfig.SudoEnrollment
    ) throws -> IDPGroupClaim? {
        // This conformer only services the Jamf Connect state selector; any
        // other selector (or the disabled default) is a no-op here.
        guard config.idpSource == .jamfConnectState else { return nil }

        // The state path must be home-relative; reject traversal / absolute
        // paths outright (fail-safe, no throw — this is a config anomaly).
        guard Self.isSafeRelativePath(config.idpStatePath) else {
            warn("rejected unsafe idpStatePath (absolute or contains '..'); no enrollment")
            return nil
        }
        // The home directory is the trust anchor and must be absolute (the
        // resolver already only supplies getpwuid-sourced ConsoleUsers).
        guard user.homeDir.hasPrefix("/") else {
            warn("console-user home is not absolute; no enrollment")
            return nil
        }
        // Reach the state file with a component-by-component openat walk anchored
        // at the trusted home dir. A symlinked intermediate OR leaf
        // component is refused (never followed); a missing component is a
        // fail-safe non-enrollment; a refusal propagates as `IDPSourceRefusal`.
        guard let opened = try Self.openConfinedDescriptor(
            homeDir: user.homeDir,
            relativePath: config.idpStatePath,
            warn: warn
        ) else {
            return nil
        }
        let fd = opened.fd
        defer { close(fd) }

        // Every subsequent decision is against the OPEN descriptor (TOCTOU-safe).
        var info = stat()
        guard fstat(fd, &info) == 0 else {
            warn("fstat failed on state file; no enrollment")
            return nil
        }
        let mode = UInt16(info.st_mode & 0o7777)

        // Must be a regular file. O_NOFOLLOW already blocked a symlinked final
        // component; this additionally rejects a directory / fifo / device /
        // socket. Per the refusal contract, non-regular maps to the symlink case.
        guard (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw IDPSourceRefusal.symlink
        }

        // Ownership gate. Default (Tier-C advisory): the file must be owned by
        // the verified console user. Strict (`requireRootOwnedState`): it must
        // be root-owned, disabling the user-writable path entirely.
        let expectedOwner: uid_t = config.requireRootOwnedState ? 0 : user.uid
        if info.st_uid != expectedOwner {
            if config.requireRootOwnedState {
                throw IDPSourceRefusal.strictReject
            }
            throw IDPSourceRefusal.ownership(uid: info.st_uid, mode: mode)
        }

        // group- or other-writable is always fatal: anyone but the owner being
        // able to write the hint breaks the "the owner's own file" confinement.
        if (info.st_mode & mode_t(S_IWGRP | S_IWOTH)) != 0 {
            throw IDPSourceRefusal.ownership(uid: info.st_uid, mode: mode)
        }

        // Hard-link gate. The confined walk stops SYMLINKS, but a hard link is
        // the file itself: a user can hard-link ANY root-owned, non-writable
        // file they can see (a root-owned plist carrying a matching groups
        // array) into their own ~/Library/Preferences, and it passes the
        // ownership and mode checks above — the strict-mode bypass. A
        // legitimate state file has exactly one name and lives on the home's
        // volume (a hard link cannot cross volumes, so another volume means a
        // mount the user controls). Checked on the open descriptor, in every
        // mode; in strict mode it is the strict refusal.
        if !Self.isSingleLinkOnHomeVolume(linkCount: UInt64(info.st_nlink), fileDevice: info.st_dev,
                                          homeDevice: opened.homeDevice) {
            warn("state file has \(info.st_nlink) links or is not on the home volume; refusing (hard-link guard)")
            if config.requireRootOwnedState { throw IDPSourceRefusal.strictReject }
            throw IDPSourceRefusal.ownership(uid: info.st_uid, mode: mode)
        }

        let ownerWritable = (info.st_mode & mode_t(S_IWUSR)) != 0
        // In strict mode the root-owned file must also be non-owner-writable, so
        // even root cannot leave a writable hint sitting in place.
        if config.requireRootOwnedState && ownerWritable {
            throw IDPSourceRefusal.ownership(uid: info.st_uid, mode: mode)
        }
        if ownerWritable {
            // Expected in the default Tier-C mode — advisory only, surfaced so an
            // operator can see the hint is user-mutable.
            warn("state file is owner-writable (Tier-C advisory hint) uid=\(info.st_uid) mode=\(String(mode, radix: 8))")
        }

        // Size guard before pulling bytes into memory.
        guard info.st_size >= 0, info.st_size <= Self.maxStateFileBytes else {
            warn("state file size out of range (\(info.st_size) bytes); no enrollment")
            return nil
        }

        // Direct read from the verified descriptor. NEVER CFPreferences — this
        // must be exactly the bytes of the file we ownership-checked.
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        let data: Data
        do {
            data = try handle.read(upToCount: Self.maxStateFileBytes) ?? Data()
        } catch {
            warn("read failed on state file; no enrollment")
            return nil
        }

        // Parse as a plist dictionary and extract the configured group-array key.
        let parsed: Any
        do {
            parsed = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        } catch {
            warn("state file is not a valid property list; no enrollment")
            return nil
        }
        guard let dictionary = parsed as? [String: Any] else {
            warn("state file root is not a dictionary; no enrollment")
            return nil
        }
        guard let rawGroups = dictionary[config.idpGroupsKey] else {
            // No groups key — e.g. Jamf Connect present but never signed in.
            // Stale/missing content, fail-safe.
            return nil
        }
        guard let array = rawGroups as? [Any] else {
            warn("groups key '\(config.idpGroupsKey)' is not an array; no enrollment")
            return nil
        }

        // Keep only string entries; any non-string tokens are ignored (the
        // resolver normalizes and intersects, so junk simply never matches).
        let groups = array.compactMap { $0 as? String }
        return IDPGroupClaim(groups: groups, ownerWritable: ownerWritable)
    }

    /// The hard-link guard: exactly one directory entry names the file, and it
    /// is on the same device as the home directory the walk was anchored at.
    static func isSingleLinkOnHomeVolume(linkCount: UInt64, fileDevice: dev_t, homeDevice: dev_t) -> Bool {
        linkCount == 1 && fileDevice == homeDevice
    }

    /// A safe home-relative subpath: non-empty, no leading `/`, and no `..`
    /// path component. Backslashes and other characters are intentionally
    /// permitted — the walk is confined component-by-component under the trusted
    /// home directory and every component is refused if it is a symlink.
    static func isSafeRelativePath(_ path: String) -> Bool {
        guard !path.isEmpty, !path.hasPrefix("/") else { return false }
        for component in path.split(separator: "/", omittingEmptySubsequences: true) where component == ".." {
            return false
        }
        return true
    }

    /// Opens `relativePath` **confined under** `homeDir` with a component-by-
    /// component `openat` walk. The home directory is the trust anchor —
    /// its path is root/system-controlled, and it is opened WITHOUT `O_NOFOLLOW`
    /// because the path *to* the home legitimately traverses system symlinks
    /// (e.g. `/var` → `/private/var`). Every component BELOW the home, which the
    /// console user owns and can replace, is opened `O_NOFOLLOW`: a symlinked
    /// INTERMEDIATE (`~/Library`, `~/Library/Preferences`, …) or leaf component
    /// fails with `ELOOP` (or `ENOTDIR` for a non-directory standing where a
    /// directory must be) and is refused, never followed. This closes both the
    /// intermediate-symlink strict-mode bypass and the symlink-based DoS that a
    /// single `open(home + "/" + relativePath, O_NOFOLLOW)` left open —
    /// `O_NOFOLLOW` on one `open` guards only the final path component.
    ///
    /// - Returns: an open `O_CLOEXEC` descriptor for the leaf (the caller must
    ///   `close` it) plus the `st_dev` of the home directory (from `fstat` on
    ///   the home descriptor itself, for the hard-link guard), or `nil` for a
    ///   fail-safe non-enrollment (a missing component, or an unopenable home).
    /// - Throws: ``IDPSourceRefusal/symlink`` when any component is a symlink or
    ///   a non-directory sits where an intermediate directory must be.
    static func openConfinedDescriptor(
        homeDir: String,
        relativePath: String,
        warn: (String) -> Void
    ) throws -> (fd: Int32, homeDevice: dev_t)? {
        let components = relativePath
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
        guard !components.isEmpty else {
            warn("idpStatePath has no usable path components; no enrollment")
            return nil
        }

        // Trust anchor: the getpwuid home directory. NO O_NOFOLLOW here — only
        // the user-controlled components below the home are walked with it.
        let homeFD = homeDir.withCString { open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC) }
        if homeFD < 0 {
            warn("cannot open console-user home dir (errno=\(errno)); no enrollment")
            return nil
        }
        var homeInfo = stat()
        guard fstat(homeFD, &homeInfo) == 0 else {
            close(homeFD)
            warn("fstat failed on console-user home dir; no enrollment")
            return nil
        }

        var parentFD = homeFD
        let lastIndex = components.count - 1
        for (index, component) in components.enumerated() {
            let isLeaf = (index == lastIndex)
            // Intermediates must be directories (O_DIRECTORY); the leaf may be
            // any type (the downstream fstat gate enforces regular-file). EVERY
            // component is O_NOFOLLOW so a symlink is refused, never traversed;
            // O_NONBLOCK keeps a fifo from blocking; O_CLOEXEC prevents fd leaks.
            let flags: Int32 = isLeaf
                ? (O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                : (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            let childFD = component.withCString { openat(parentFD, $0, flags) }
            // Release the parent as we descend — never leak an intermediate fd.
            close(parentFD)
            if childFD < 0 {
                let err = errno
                switch err {
                case ELOOP, ENOTDIR:
                    // ELOOP: the component is a symlink (blocked by O_NOFOLLOW).
                    // ENOTDIR: a non-directory (incl. a symlink-to-file) sits
                    // where an intermediate directory must be. Either way the
                    // walk was about to be redirected below the home — refuse.
                    throw IDPSourceRefusal.symlink
                case ENOENT:
                    // A missing component: stale / never-signed-in. Fail-safe.
                    return nil
                default:
                    warn("openat failed (errno=\(err)) on a component below home; no enrollment")
                    return nil
                }
            }
            parentFD = childFD
        }
        // `parentFD` is now the open leaf descriptor; the caller owns it.
        return (parentFD, homeInfo.st_dev)
    }
}

// MARK: - Off-actor read timeout (defense in depth against a hung read)

/// Races a blocking, `@Sendable` closure against a wall-clock `timeout`, running
/// the closure on a **detached** task so a syscall that blocks in path
/// resolution (e.g. an `openat` into a hung autofs mount that the `O_NOFOLLOW`
/// walk cannot detect as a symlink) can never pin the caller's actor executor.
///
/// The ``DaemonController`` actor `await`s this; because it is a suspension (not
/// a thread block) the actor stays free to service `handlePAM` while the read
/// runs. On timeout the detached worker is abandoned — it unwinds on its own
/// thread when the syscall finally returns, and its result is dropped — so the
/// caller proceeds fail-safe rather than waiting out the hung mount.
///
/// - Parameter seconds: the timeout budget; values `<= 0` collapse to an
///   immediate timeout.
/// - Returns: the closure's value, or `nil` if `timeout` elapsed first. Callers
///   pass a NON-optional-producing closure, so `nil` unambiguously means timeout.
func withDetachedTimeout<T: Sendable>(
    seconds: TimeInterval,
    _ work: @escaping @Sendable () -> T
) async -> T? {
    let box = DetachedTimeoutBox<T>()
    let worker = Task.detached(priority: .utility) { box.settle(.value(work())) }
    let timer = Task.detached(priority: .utility) {
        let nanos = seconds > 0 ? UInt64(seconds * 1_000_000_000) : 0
        try? await Task.sleep(nanoseconds: nanos)
        box.settle(.timedOut)
    }
    // Whichever loses the race is abandoned. Cancelling is best-effort: a
    // blocking syscall ignores it (and unwinds later, a no-op re-settle), while
    // the sleep/cooperative work exits promptly.
    defer {
        worker.cancel()
        timer.cancel()
    }
    return await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
        box.attach(continuation)
    }
}

/// One-shot race arbiter for ``withDetachedTimeout`` and ``withAbandoningTimeout``:
/// the first of the worker or the timer to `settle` wins and the sole continuation
/// is resumed exactly once, whether it is attached before or after that first
/// settle. `@unchecked Sendable` — every field is guarded by the `NSLock`.
///
/// Internal rather than file-private so ``withAbandoningTimeout``
/// (`AsyncTimeout.swift`) can share it; the two timeouts differ only in whether
/// the work they bound is sync or async.
final class DetachedTimeoutBox<T: Sendable>: @unchecked Sendable {
    enum Outcome { case value(T); case timedOut }

    private let lock = NSLock()
    private var settled = false
    private var stored: T?
    private var continuation: CheckedContinuation<T?, Never>?

    func settle(_ outcome: Outcome) {
        lock.lock()
        if settled { lock.unlock(); return }
        settled = true
        let value: T?
        switch outcome {
        case let .value(v): value = v
        case .timedOut: value = nil
        }
        stored = value
        let waiting = continuation
        continuation = nil
        lock.unlock()
        waiting?.resume(returning: value)
    }

    func attach(_ continuation: CheckedContinuation<T?, Never>) {
        lock.lock()
        if settled {
            let value = stored
            lock.unlock()
            continuation.resume(returning: value)
        } else {
            self.continuation = continuation
            lock.unlock()
        }
    }
}
