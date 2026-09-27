import CoreFoundation
import Darwin
import Foundation

/// Persistence for the last-known-good Serberus configuration.
///
/// See ``BundleConfig/lastKnownGoodConfigPath`` for what the snapshot is FOR.
/// This protocol exists so the daemon's config resolution can be exercised
/// against an in-memory double, with no root and no `/Library` writes.
public protocol LastKnownGoodConfigStoring: Sendable {
    /// Persists `config` atomically. Only ever called with a config that
    /// satisfies ``SerberusConfig/isEnforceable`` — that is the snapshot's
    /// invariant, and the reason falling back to it can never brick a Mac.
    func save(_ config: SerberusConfig) throws
    /// The persisted config, or `nil` when there is none, it is unreadable, or
    /// it does not satisfy the enforceability invariant.
    func load() -> SerberusConfig?
    /// Whether a snapshot file exists — the "this Mac has been configured"
    /// marker. (``load()`` is the authority on whether it is USABLE.)
    func exists() -> Bool
    /// Whether an EXISTING snapshot is stale relative to what ``save(_:)``
    /// would write for `config` now (e.g. a pass-through key such as a
    /// `sudo*Message` changed without any parsed config field changing).
    func needsRefresh(for config: SerberusConfig) -> Bool
    /// Why an EXISTING snapshot does not load, for the integrity log (nil when
    /// it loads, or when there is no snapshot).
    func unusableReason() -> String?
}

public extension LastKnownGoodConfigStoring {
    /// Default: never stale (in-memory doubles hold exactly what was saved).
    func needsRefresh(for config: SerberusConfig) -> Bool { false }
    /// Default: no detail beyond ``load()`` returning nil.
    func unusableReason() -> String? { nil }
}

public enum LastKnownGoodConfigError: Error, Sendable, Equatable {
    /// The snapshot could not be serialized to an XML property list.
    case serializationFailed(String)
    /// The temp file could not be created (path, errno).
    case temporaryWriteFailed(path: String, code: Int32)
    /// `rename(2)` onto the final path failed (path, errno).
    case renameFailed(path: String, code: Int32)
}

/// File-backed last-known-good config snapshot.
///
/// # Write discipline
/// Serialize → write a sibling temp file → `chmod 0644` → `rename(2)`. The
/// rename is atomic within the filesystem, so a concurrent reader (notably
/// `pam_serberus`, mid-`sudo`) sees either the entire old snapshot or the
/// entire new one — never a truncated plist, which would parse as "no usable
/// config" and, in the worst case, drop a configured Mac into pass-through.
///
/// # Read discipline
/// The same checks `pam_config.c` applies before it trusts the file, so the
/// daemon and pam can never disagree about whether the snapshot is usable:
/// the folder must be a real directory (`lstat`, not a symlink), the file is
/// opened with `O_NOFOLLOW`, and — on the open descriptor (`fstat`) — it must
/// be a regular file; both must be owned by root (``requiredOwnerUID``) and
/// not group- or other-writable. A snapshot that fails any check does not
/// load (see ``unusableReason()``), which the daemon's resolver turns into
/// the fail-closed config and `degraded(config_missing)` — what pam does too.
///
/// ``exists()`` is deliberately NOT gated on those checks: pam keys "this Mac
/// has been configured" on an `lstat` of the path alone, so an untrusted
/// snapshot still means "configured, fail closed", never "bootstrap, pass
/// through".
///
/// # Key shape
/// EVERY enforcement-relevant key of the `com.herojoneslabs.serberus.config`
/// managed domain, with identical keys and nesting, so `pam_config.c` reads the
/// snapshot with the very same parser it uses on
/// `/Library/Managed Preferences/…config.plist`, and the daemon's
/// ``load()`` (which re-parses through `readConfig()`) gets back exactly the
/// config that was saved — a key left out would silently fall back to its
/// default (e.g. an explicit `timeBoundGrantsEnabled = false` would silently
/// become the `true` default ⇒ grants that expire when the admin chose none).
///
/// Typed keys (everything `readConfig()` parses): `daemonEnabled`,
/// `enforcementMode`, `sudoCacheSeconds`, `promptTimeoutSeconds`, `pamBypass`,
/// `sudoEnrollment`, `timeBoundGrantsEnabled`, `defaultGrantDurationMinutes`,
/// `enableBiometrics`, `commanderPublishEnabled`. Pass-through
/// keys (read by pam / the Guardian straight from the plist, not parsed into
/// ``SerberusConfig``), copied from the managed domain when a
/// `passthroughSource` is injected: ``passthroughStringKeys`` +
/// ``passthroughBoolKeys`` + ``passthroughIntKeys``.
///
/// ```xml
/// <dict>
///   <key>daemonEnabled</key>        <true/>
///   <key>enforcementMode</key>      <string>enforce</string>   <!-- enforce|audit|monitor -->
///   <key>sudoCacheSeconds</key>     <integer>0</integer>
///   <key>promptTimeoutSeconds</key> <integer>60</integer>
///   <key>pamBypass</key>            <dict>
///     <key>groups</key> <array><string>admin</string></array>
///     <key>users</key>  <array/>
///   </dict>
///   <key>sudoEnrollment</key>       <dict>
///     <key>group</key>                 <string>staff</string>   <!-- omitted when nil -->
///     <key>users</key>                 <array/>
///     <key>idpGroups</key>             <array/>
///     <key>idpSource</key>             <string>disabled</string>
///     <key>idpStatePath</key>          <string>Library/Preferences/com.jamf.connect.state.plist</string>
///     <key>idpGroupsKey</key>          <string>UserGroups</string>
///     <key>requireRootOwnedState</key> <false/>
///   </dict>
/// </dict>
/// ```
///
/// The Jamf API credential set (`jamfProURL`, `jamfAPIClientID`,
/// `jamfAPIClientSecret`) is deliberately NOT persisted — never secrets, and
/// none of it is enforcement-relevant: the snapshot is world-readable
/// (0644, because `pam_serberus` runs as the invoking user before `sudo` drops
/// to root), and the daemon re-reads credentials from the managed domain, never
/// from here.
public struct LastKnownGoodConfigStore: LastKnownGoodConfigStoring {
    private let url: URL
    private let passthroughSource: (any PreferencesSource)?
    /// The owner the snapshot and its folder must have. Root in production;
    /// tests pass their own uid so a temp directory can stand in (the same
    /// seam ``CFPreferencesSource`` and `pam_config.c` have).
    private let requiredOwnerUID: uid_t

    /// Managed-domain keys the snapshot carries verbatim (type-checked) because
    /// consumers read them straight from the plist rather than through
    /// ``SerberusConfig``: pam's user-facing sudo messages, and the Guardian.
    public static let passthroughStringKeys = [
        "sudoDenyMessage", "sudoAllowMessage", "sudoPromptDeniedMessage", "sudoPromptTimeoutMessage",
    ]
    public static let passthroughBoolKeys = ["guardianEnabled"]
    public static let passthroughIntKeys = ["guardianDetectionSeconds"]

    /// Keys that must NEVER be written to the (world-readable) snapshot.
    public static let excludedSecretKeys: Set<String> = ["jamfProURL", "jamfAPIClientID", "jamfAPIClientSecret"]

    /// - Parameters:
    ///   - url: snapshot location. Defaults to the production path; injectable
    ///     so tests write into a temp directory.
    ///   - passthroughSource: where the pass-through keys are copied from at
    ///     save time (production: the managed `CFPreferencesSource`). nil ⇒ only
    ///     the typed keys are written.
    ///   - requiredOwnerUID: the owner the snapshot and its folder must have
    ///     (root in production).
    public init(
        url: URL = URL(fileURLWithPath: BundleConfig.lastKnownGoodConfigPath),
        passthroughSource: (any PreferencesSource)? = nil,
        requiredOwnerUID: uid_t = 0
    ) {
        self.url = url
        self.passthroughSource = passthroughSource
        self.requiredOwnerUID = requiredOwnerUID
    }

    /// Whether the snapshot path is present, decided exactly as pam decides
    /// "configured" (see "Read discipline"): an `lstat` of the path, where ONLY
    /// `ENOENT` or `ENOTDIR` means absent. Any other failure (a folder that
    /// cannot be searched, an I/O error) counts as present, so both sides take
    /// the fail-closed last-known-good path rather than bootstrap. `lstat` does
    /// not follow a final symlink, so a dangling one counts as present too.
    /// (`access(F_OK)` used the caller's REAL uid, which inside setuid `sudo`
    /// is the invoking user's.)
    public func exists() -> Bool {
        var info = stat()
        if lstat(url.path, &info) == 0 { return true }
        return errno != ENOENT && errno != ENOTDIR
    }

    public func needsRefresh(for config: SerberusConfig) -> Bool {
        switch readTrusted() {
        case let .success(data):
            guard let parsed = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                  let onDisk = parsed as? NSDictionary else {
                return true // present but unparseable ⇒ rewrite
            }
            return !onDisk.isEqual(to: snapshotDictionary(for: config))
        case .failure(.absent):
            return false // exists() handles a missing file
        case .failure(.untrustedFolder):
            return false // a rewrite lands in the same folder and cannot fix it
        case .failure:
            return exists() // the file itself is wrong ⇒ a fresh atomic write replaces it
        }
    }

    public func unusableReason() -> String? {
        guard exists() else { return nil }
        switch readTrusted() {
        case let .failure(failure):
            return failure.description
        case let .success(data):
            guard let config = Self.parse(data) else { return "not a readable property list" }
            return config.isEnforceable ? nil : "not safely enforceable (enforce with an empty pamBypass)"
        }
    }

    // MARK: Trusted read

    enum ReadFailure: Error, Equatable, CustomStringConvertible {
        case absent
        case untrustedFolder
        case notOpenable(Int32)
        case notRegularFile
        case untrustedFile(owner: uid_t, mode: mode_t)
        case readFailed

        var description: String {
            switch self {
            case .absent: return "absent"
            case .untrustedFolder:
                return "its folder is a symlink, not a directory, or not root-owned and write-protected"
            case let .notOpenable(code): return "cannot be opened without following a symlink (errno \(code))"
            case .notRegularFile: return "not a regular file"
            case let .untrustedFile(owner, mode):
                return "owner uid \(owner) mode \(String(mode & 0o7777, radix: 8)): must be root-owned and not group/other-writable"
            case .readFailed: return "read failed"
            }
        }
    }

    /// Whether an ownership/mode pair may be trusted: owned by
    /// ``requiredOwnerUID`` and writable by nobody else (`pam_config.c`'s
    /// `owner_and_mode_are_trusted`).
    private func isTrusted(owner: uid_t, mode: mode_t) -> Bool {
        owner == requiredOwnerUID && (mode & mode_t(S_IWGRP | S_IWOTH)) == 0
    }

    /// The snapshot's bytes, read only through `pam_config.c`'s checks: folder
    /// via `lstat`, file via `O_NOFOLLOW` then `fstat` on the descriptor.
    func readTrusted() -> Result<Data, ReadFailure> {
        var folder = stat()
        let folderPath = url.deletingLastPathComponent().path
        guard lstat(folderPath, &folder) == 0, (folder.st_mode & S_IFMT) == S_IFDIR,
              isTrusted(owner: folder.st_uid, mode: folder.st_mode) else {
            return access(url.path, F_OK) == 0 ? .failure(.untrustedFolder) : .failure(.absent)
        }
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            let code = errno
            return code == ENOENT ? .failure(.absent) : .failure(.notOpenable(code))
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return .failure(.notRegularFile) }
        guard isTrusted(owner: info.st_uid, mode: info.st_mode) else {
            return .failure(.untrustedFile(owner: info.st_uid, mode: info.st_mode))
        }
        guard let data = try? handle.readToEnd() else { return .failure(.readFailed) }
        return .success(data)
    }

    /// The full dictionary ``save(_:)`` writes: typed keys + pass-through keys.
    func snapshotDictionary(for config: SerberusConfig) -> [String: Any] {
        var dictionary = Self.plistDictionary(for: config)
        guard let source = passthroughSource else { return dictionary }
        let domain = BundleConfig.configDomain
        for key in Self.passthroughStringKeys {
            if let value = source.managedValue(forKey: key, domain: domain) as? String {
                dictionary[key] = value
            }
        }
        for key in Self.passthroughBoolKeys {
            // CFBoolean only: a number must not satisfy a Bool key.
            if let raw = source.managedValue(forKey: key, domain: domain),
               CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID(), let value = raw as? Bool {
                dictionary[key] = value
            }
        }
        for key in Self.passthroughIntKeys {
            let raw = source.managedValue(forKey: key, domain: domain)
            if let raw, CFGetTypeID(raw as CFTypeRef) != CFBooleanGetTypeID(),
               let value = (raw as? Int) ?? (raw as? NSNumber)?.intValue {
                dictionary[key] = value
            }
        }
        for key in Self.excludedSecretKeys { dictionary[key] = nil }
        return dictionary
    }

    public func save(_ config: SerberusConfig) throws {
        let data: Data
        do {
            data = try PropertyListSerialization.data(
                fromPropertyList: snapshotDictionary(for: config),
                format: .xml,
                options: 0
            )
        } catch {
            throw LastKnownGoodConfigError.serializationFailed(error.localizedDescription)
        }

        let directory = url.deletingLastPathComponent()
        // The pkg creates this directory (root:wheel 755); create it defensively
        // so a daemon that starts before/without the pkg's postinstall still has
        // somewhere to land the snapshot.
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        // Sibling temp file: `rename(2)` is only atomic within one filesystem.
        let temporary = directory.appendingPathComponent(
            ".\(url.lastPathComponent).\(UUID().uuidString).tmp"
        )

        // Durable, atomic write: open → write every byte → fsync(fd) → close, and
        // only THEN rename. The fsync BEFORE the rename is what makes the snapshot
        // crash-safe: without it, a panic or power loss in the window between the
        // rename and the kernel flushing the data blocks can leave a 0-byte or torn
        // plist at the FINAL path. That parses as "no usable config" and would drop
        // a configured Mac into bootstrap pass-through — precisely the divergence
        // (daemon vs pam) the last-known-good marker exists to prevent. 0644 because
        // pam_serberus reads this file as the invoking (pre-elevation) user.
        // O_EXCL | O_NOFOLLOW: the temp name is fresh, so anything already there
        // (a planted file or symlink) is refused rather than written through.
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard fd >= 0 else {
            throw LastKnownGoodConfigError.temporaryWriteFailed(path: temporary.path, code: errno)
        }
        var writeErrno: Int32 = 0
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let total = raw.count
            let base = raw.baseAddress
            var offset = 0
            while offset < total {
                let written = write(fd, base?.advanced(by: offset), total - offset)
                if written < 0 {
                    if errno == EINTR { continue } // interrupted; retry the same chunk
                    writeErrno = errno
                    return
                }
                if written == 0 { break }
                offset += written
            }
        }
        if writeErrno == 0, fsync(fd) != 0 {
            writeErrno = errno
        }
        // Belt and braces: the O_CREAT mode is umask-masked, and pam_serberus must be
        // able to READ this file or break-glass would be invisible to it.
        fchmod(fd, 0o644)
        close(fd)
        guard writeErrno == 0 else {
            try? FileManager.default.removeItem(at: temporary)
            throw LastKnownGoodConfigError.temporaryWriteFailed(path: temporary.path, code: writeErrno)
        }

        guard rename(temporary.path, url.path) == 0 else {
            let code = errno
            try? FileManager.default.removeItem(at: temporary)
            throw LastKnownGoodConfigError.renameFailed(path: url.path, code: code)
        }

        // Best-effort: fsync the parent directory so the new directory entry (the
        // rename) is itself durable. Non-fatal — the data file is already flushed;
        // only the dirent's durability across a crash is at stake here.
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY)
        if directoryFD >= 0 {
            fsync(directoryFD)
            close(directoryFD)
        }
    }

    public func load() -> SerberusConfig? {
        // Only through pam's checks: a snapshot pam would refuse must not be
        // one the daemon enforces (with its break-glass) while pam enforces
        // without.
        guard case let .success(data) = readTrusted(), let config = Self.parse(data) else { return nil }

        // The invariant, re-checked on the way IN: a snapshot that does not
        // satisfy it (truncated, hand-edited, or written by an older build) is
        // treated as unusable. Adopting an enforce-without-break-glass config
        // from disk is precisely the lockout this whole mechanism exists to
        // prevent.
        guard config.isEnforceable else { return nil }
        return config
    }

    /// Parses snapshot bytes through the SAME reader the managed domain goes
    /// through, so the snapshot can never be interpreted more leniently (or
    /// differently) than the profile it was taken from.
    private static func parse(_ data: Data) -> SerberusConfig? {
        guard let parsed = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let raw = parsed as? [String: Any] else {
            return nil
        }
        let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.configDomain: Self.sendableDictionary(raw)]
        ))
        return reader.readConfig().value
    }

    // MARK: Serialization

    static func plistDictionary(for config: SerberusConfig) -> [String: Any] {
        var enrollment: [String: Any] = [
            "users": config.sudoEnrollment.users,
            "idpGroups": config.sudoEnrollment.idpGroups,
            "idpSource": config.sudoEnrollment.idpSource.rawValue,
            "idpStatePath": config.sudoEnrollment.idpStatePath,
            "idpGroupsKey": config.sudoEnrollment.idpGroupsKey,
            "requireRootOwnedState": config.sudoEnrollment.requireRootOwnedState,
        ]
        // Absent, not empty-string: `readConfig` treats a present-but-empty group
        // as a real (empty) principal name, which the sudoers generator rejects.
        if let group = config.sudoEnrollment.group {
            enrollment["group"] = group
        }
        let dictionary: [String: Any] = [
            "daemonEnabled": config.daemonEnabled,
            "enforcementMode": config.enforcementMode.rawValue,
            "sudoCacheSeconds": config.sudoCacheSeconds,
            "promptTimeoutSeconds": config.promptTimeoutSeconds,
            "pamBypass": [
                "groups": config.pamBypass.groups,
                "users": config.pamBypass.users,
            ] as [String: Any],
            "sudoEnrollment": enrollment,
            "timeBoundGrantsEnabled": config.timeBoundGrantsEnabled,
            "defaultGrantDurationMinutes": config.defaultGrantDurationMinutes,
            "enableBiometrics": config.enableBiometrics,
            "commanderPublishEnabled": config.commanderPublishEnabled,
        ]
        return dictionary
    }

    /// Re-types a parsed plist tree into Swift-native `Sendable` values so it can
    /// feed ``DictionaryPreferencesSource``. Booleans are distinguished from
    /// numbers by CFType (an `NSNumber(0)` would otherwise cast to `false` and
    /// silently satisfy a Bool key). Anything unrecognized is dropped, which the
    /// reader then reports as a finding / falls back to a default for.
    static func sendableDictionary(_ raw: [String: Any]) -> [String: any Sendable] {
        raw.compactMapValues(sendableValue(_:))
    }

    private static func sendableValue(_ value: Any) -> (any Sendable)? {
        if CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID() {
            return (value as? NSNumber)?.boolValue
        }
        switch value {
        case let string as String:
            return string
        case let number as NSNumber:
            return number.intValue
        case let array as [Any]:
            return array.compactMap(sendableValue(_:))
        case let dictionary as [String: Any]:
            return dictionary.compactMapValues(sendableValue(_:))
        default:
            return nil
        }
    }
}

/// In-memory ``LastKnownGoodConfigStoring`` for tests and dry runs.
///
/// Mirrors the file store's semantics, including the enforceability invariant on
/// the way out, so a test can distinguish "no snapshot" from "unusable snapshot".
public final class InMemoryLastKnownGoodConfigStore: LastKnownGoodConfigStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: SerberusConfig?
    private var saveError: (any Error)?
    private var _saveCount = 0

    public init(initial: SerberusConfig? = nil, saveError: (any Error)? = nil) {
        self.stored = initial
        self.saveError = saveError
    }

    /// How many times ``save(_:)`` was called (a successful adoption persists once).
    public var saveCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _saveCount
    }

    /// Begin (or, with `nil`, stop) failing ``save(_:)`` with `error`. Lets a test
    /// model a store that recovers between reloads — a transient I/O failure whose
    /// re-save the daemon retries (``DaemonController/retryLastKnownGoodSaveIfNeeded``).
    public func setSaveError(_ error: (any Error)?) {
        lock.lock(); defer { lock.unlock() }
        self.saveError = error
    }

    public func save(_ config: SerberusConfig) throws {
        lock.lock(); defer { lock.unlock() }
        _saveCount += 1
        if let saveError { throw saveError }
        stored = config
    }

    public func load() -> SerberusConfig? {
        lock.lock(); defer { lock.unlock() }
        guard let stored, stored.isEnforceable else { return nil }
        return stored
    }

    public func exists() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return stored != nil
    }
}
