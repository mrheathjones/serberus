import CryptoKit
import Foundation
import PrivMgrCore

/// The result of running the startup sequence: the state to publish plus the
/// configuration and policy the daemon should serve.
public struct StartupOutcome: Sendable, Equatable {
    public let state: DaemonState
    public let degradedReason: DegradedReason?
    /// The EFFECTIVE config (see ``EffectiveConfigResolver``): the delivered one,
    /// the last-known-good snapshot, a fail-closed config (corrupt snapshot), or —
    /// while awaiting config — a canonical EMPTY config (`monitor`, no bypass, no
    /// enrollment).
    public let config: SerberusConfig
    public let profiles: [RuleProfile]
    /// Active grants reconstructed at startup (empty on a grants DB error).
    public let activeGrants: [Grant]
    /// True when this Mac has never held a usable config AND no snapshot file exists
    /// (bootstrap). The daemon must not enforce (the config above is `monitor`), but
    /// it DOES mutate toward the native state: the AuthorizationDB is reconciled to
    /// EMPTY here (a restore) and ``DaemonController`` provisions the empty config
    /// (removing any stale sudoers drop-in). This cleans up a Mac that was mutated
    /// before its snapshot marker was planted; on a fresh install both are no-ops.
    public let awaitingConfig: Bool
    /// Human-readable notes for the integrity log / health report.
    public let notes: [String]
    /// Zero working break-glass in the delivered or served enforcing config
    /// (``EffectiveConfig/bypassUnresolvable``).
    public let bypassUnresolvable: Bool
    /// What the state was resolved from (``StartupCoordinator/resolveState(_:)``);
    /// nil under the kill switch, which returns before resolving. The daemon
    /// keeps it to re-resolve the state once a failed reconcile succeeds.
    public let stateInputs: StartupCoordinator.StateInputs?

    /// The AuthorizationDB reconcile failed outside the kill switch: part of
    /// the policy is not applied, and ``DaemonController`` retries the
    /// reconcile on every reload tick. (The kill switch's failed restore is
    /// retried by withholding the policy signature instead.)
    public var authDBFailed: Bool { stateInputs?.authDBError ?? false }

    public init(
        state: DaemonState,
        degradedReason: DegradedReason?,
        config: SerberusConfig,
        profiles: [RuleProfile],
        activeGrants: [Grant],
        awaitingConfig: Bool = false,
        notes: [String],
        bypassUnresolvable: Bool = false,
        stateInputs: StartupCoordinator.StateInputs? = nil
    ) {
        self.state = state
        self.degradedReason = degradedReason
        self.config = config
        self.profiles = profiles
        self.activeGrants = activeGrants
        self.awaitingConfig = awaitingConfig
        self.notes = notes
        self.bypassUnresolvable = bypassUnresolvable
        self.stateInputs = stateInputs
    }
}

/// Runs the daemon startup sequence and resolves the daemon's state.
///
/// All inputs are injected, so every branch — kill switch, pending_pppc,
/// pending_profiles, healthy, and each degraded cause — is unit-testable
/// without a running daemon, root, or live managed preferences.
///
/// State precedence when several conditions hold at once (a single state must
/// be reported): `kill_switch` (explicit off, returned early) outranks any
/// `degraded` (error), which outranks `awaiting_config` (never configured — no
/// enforcement, no mutations), which outranks `pending_pppc` (ESF capability
/// missing, security-relevant), which outranks `pending_profiles` (no policy;
/// native behavior preserved), which outranks `healthy`. Among degraded causes
/// the order is config_invalid → bypass_unresolvable → config_missing → grants →
/// authdb → pam_not_wired → rules.
public struct StartupCoordinator: Sendable {
    private let prefsReader: ManagedPreferencesReader
    private let grantStore: GrantMaintaining
    private let pppc: PPPCStatusChecking
    private let authDB: AuthorizationDBApplying
    private let lastKnownGood: any LastKnownGoodConfigStoring
    private let bypassResolver: BypassResolving
    private let now: @Sendable () -> Date

    public init(
        prefsReader: ManagedPreferencesReader,
        grantStore: GrantMaintaining,
        pppc: PPPCStatusChecking,
        authDB: AuthorizationDBApplying,
        lastKnownGood: any LastKnownGoodConfigStoring = LastKnownGoodConfigStore(),
        bypassResolver: BypassResolving = AssumeResolvableBypass(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.bypassResolver = bypassResolver
        self.prefsReader = prefsReader
        self.grantStore = grantStore
        self.pppc = pppc
        self.authDB = authDB
        self.lastKnownGood = lastKnownGood
        self.now = now
    }

    public func run() async -> StartupOutcome {
        var notes: [String] = []
        let timestamp = now()

        // Load and validate configuration, then resolve which config the
        // daemon actually runs on (delivered / last-known-good / none). The SAME
        // resolver runs on every managed-preferences reload — startup and reload
        // must never disagree about whether this Mac is enforceable.
        let configResult = prefsReader.readConfig()
        let configPresent = prefsReader.configIsPresent()
        let effective = EffectiveConfigResolver.resolve(
            managedConfig: configResult.value,
            configPresent: configPresent,
            lastKnownGood: lastKnownGood,
            bypassResolver: bypassResolver
        )
        let config = effective.config
        notes.append(contentsOf: effective.notes)
        for entry in effective.unresolvedBypassEntries {
            notes.append("pamBypass \(entry) does not resolve on this Mac")
        }

        // A DELIVERED config with bad keys is a genuine `config_invalid` — it is
        // reported even when the daemon went on to ignore it (fell back to the
        // snapshot or to awaiting-config), because an admin's broken profile must
        // never be silently swallowed by the safety path. An ABSENT domain has no
        // findings and is not "invalid"; it is `config_missing` / awaiting-config.
        let configInvalid = configPresent && !configResult.findings.isEmpty
        if configInvalid {
            notes.append("config findings: \(configResult.findings.count)")
        }

        // Kill switch: daemonEnabled = false. Revoke active grants, preserve
        // logs, deny future elevation. Returned immediately.
        if !config.daemonEnabled {
            let revoked = (try? await grantStore.revokeAll(now: timestamp)) ?? 0
            notes.append("kill switch active; revoked \(revoked) grant(s)")
            // Restore the authdb to native BEFORE returning — IDENTICALLY to the
            // reload kill-switch path (``DaemonController/reloadPolicyIfChanged()``,
            // which does `authDB.reconcile(profiles: [])`). Without this, a kill
            // switch delivered while the daemon was DOWN would strand a
            // Serberus-gated authright (e.g. a `deny` on a Settings pane) across the
            // next boot, because this branch returned before reaching the
            // AuthorizationDB reconcile below. The sudoers drop-in is removed by
            // ``DaemonController/start()``'s `provisionSudoers()` under the same
            // `daemonEnabled == false` guard, so startup and reload teardown are the
            // same: empty profiles, authdb restored, drop-in removed.
            //
            // A FAILED restore is not swallowed: it is reported as
            // `degraded(authdb_failure)` so the admin sees the stranded rights, and
            // ``DaemonController/start()`` withholds the initial policy signature so
            // the first reload tick re-runs the kill-switch teardown (a retry).
            do {
                try await authDB.reconcile(profiles: [])
            } catch {
                notes.append("kill switch: AuthorizationDB restore FAILED (will retry): \(error.localizedDescription)")
                return StartupOutcome(
                    state: .degraded,
                    degradedReason: .authDBFailure,
                    config: config,
                    profiles: [],
                    activeGrants: [],
                    notes: notes
                )
            }
            return StartupOutcome(
                state: .killSwitch,
                degradedReason: nil,
                config: config,
                profiles: [],
                activeGrants: [],
                notes: notes
            )
        }

        // PPPC / Full Disk Access preflight.
        let fdaReady = pppc.fullDiskAccessReady()
        if !fdaReady {
            notes.append("Full Disk Access not granted; ESF will be inactive")
        }

        // Load grants, remove expired ones, reconstruct the active set.
        var grantsError = false
        var activeGrants: [Grant] = []
        do {
            let removed = try await grantStore.cleanupExpired(now: timestamp)
            if removed > 0 { notes.append("removed \(removed) expired grant(s)") }
            // Expiry the wall-clock DELETE above cannot see: the continuous
            // clock, or a clock set back before issue. The reload tick repeats
            // this for the daemon's whole life.
            let revoked = try await grantStore.revokeExpired(now: timestamp)
            if revoked > 0 { notes.append("revoked \(revoked) expired grant(s)") }
            activeGrants = try await grantStore.activeGrants(now: timestamp)
        } catch {
            grantsError = true
            notes.append("grant database error: \(error.localizedDescription)")
        }

        // Load rule profiles.
        let profilesResult = prefsReader.readRuleProfiles()
        let profiles = profilesResult.value
        let rulesError = !profilesResult.findings.isEmpty
        if rulesError {
            notes.append("rule parse findings: \(profilesResult.findings.count)")
        }

        // Reconcile AuthorizationDB modifications. `reconcile` (not
        // `apply`) so a right DROPPED from the policy while the daemon was
        // stopped is restored on boot instead of being stranded at its prior
        // Serberus gate — a stale `deny` would otherwise brick a Settings pane
        // until an unrelated policy change happened to trigger a live reload.
        // The reconcile is differential, so rights that remain in the policy are
        // applied without being flickered back to their originals.
        //
        // While awaiting config the reconcile is NOT skipped — it is run with an
        // EMPTY desired set (`reconcile([])`), which RESTORES every Serberus-gated
        // right. A Mac that has never held a usable config keeps its stock authdb;
        // but a Mac that DID adopt a config, mutated the authdb, then lost the
        // config before the snapshot marker was planted (a failed save) is cleaned
        // up here rather than left with stranded `deny`-classed rights. Applying
        // the (empty/unsafe) policy is what we avoid — never the restore.
        var authDBError = false
        do {
            try await authDB.reconcile(profiles: AuthorizationDBApplier.profilesToApply(
                profiles, mode: effective.config.enforcementMode, awaitingConfig: effective.isAwaitingConfig))
            if effective.isAwaitingConfig {
                notes.append("awaiting config: AuthorizationDB reconciled to the native state (restore)")
            } else if effective.config.enforcementMode != .enforce {
                notes.append("\(effective.config.enforcementMode.rawValue) mode: AuthorizationDB left at the native state")
            }
        } catch {
            authDBError = true
            notes.append("AuthorizationDB error: \(error.localizedDescription)")
        }

        // Resolve the single reported state by precedence.
        let inputs = StateInputs(
            configInvalid: configInvalid,
            grantsError: grantsError,
            authDBError: authDBError,
            rulesError: rulesError,
            fdaReady: fdaReady,
            hasProfiles: !profiles.isEmpty,
            awaitingConfig: effective.isAwaitingConfig,
            configMissing: effective.reportsConfigMissing,
            bypassUnresolvable: effective.bypassUnresolvable
        )
        let resolved = Self.resolveState(inputs)

        return StartupOutcome(
            state: resolved.state,
            degradedReason: resolved.reason,
            config: config,
            // On a rules parse error the spec says retain the last valid rule
            // set; a fresh process has only what parsed cleanly this run.
            profiles: profiles,
            activeGrants: grantsError ? [] : activeGrants,
            awaitingConfig: effective.isAwaitingConfig,
            notes: notes,
            bypassUnresolvable: effective.bypassUnresolvable,
            stateInputs: inputs
        )
    }

    /// The conditions the reported state is resolved from: the parameters of
    /// ``resolveState(configInvalid:grantsError:authDBError:rulesError:fdaReady:hasProfiles:awaitingConfig:configMissing:pamNotWired:bypassUnresolvable:)``.
    public struct StateInputs: Sendable, Equatable {
        public var configInvalid: Bool
        public var grantsError: Bool
        public var authDBError: Bool
        public var rulesError: Bool
        public var fdaReady: Bool
        public var hasProfiles: Bool
        public var awaitingConfig: Bool
        public var configMissing: Bool
        public var pamNotWired: Bool
        public var bypassUnresolvable: Bool

        public init(configInvalid: Bool = false, grantsError: Bool = false, authDBError: Bool = false,
                    rulesError: Bool = false, fdaReady: Bool = true, hasProfiles: Bool = false,
                    awaitingConfig: Bool = false, configMissing: Bool = false, pamNotWired: Bool = false,
                    bypassUnresolvable: Bool = false) {
            self.configInvalid = configInvalid
            self.grantsError = grantsError
            self.authDBError = authDBError
            self.rulesError = rulesError
            self.fdaReady = fdaReady
            self.hasProfiles = hasProfiles
            self.awaitingConfig = awaitingConfig
            self.configMissing = configMissing
            self.pamNotWired = pamNotWired
            self.bypassUnresolvable = bypassUnresolvable
        }
    }

    /// ``resolveState(configInvalid:grantsError:authDBError:rulesError:fdaReady:hasProfiles:awaitingConfig:configMissing:pamNotWired:bypassUnresolvable:)``
    /// over ``StateInputs``.
    static func resolveState(_ inputs: StateInputs) -> (state: DaemonState, reason: DegradedReason?) {
        resolveState(configInvalid: inputs.configInvalid, grantsError: inputs.grantsError,
                     authDBError: inputs.authDBError, rulesError: inputs.rulesError, fdaReady: inputs.fdaReady,
                     hasProfiles: inputs.hasProfiles, awaitingConfig: inputs.awaitingConfig,
                     configMissing: inputs.configMissing, pamNotWired: inputs.pamNotWired,
                     bypassUnresolvable: inputs.bypassUnresolvable)
    }

    /// - Parameters:
    ///   - awaitingConfig: this Mac has never held a usable config. Outranks both
    ///     pending states (it is not "waiting for rules" — it is waiting for the
    ///     profile that says what Serberus is even supposed to do) but NOT a
    ///     degraded cause: a genuinely broken delivered config must still be
    ///     reported as such, and the caller gates enforcement/mutations off the
    ///     ``EffectiveConfig`` flags, never off the reported state.
    ///   - configMissing: the daemon is running on the last-known-good snapshot
    ///     (profile removed / unscoped / partial). Still enforcing, break-glass
    ///     intact — but degraded, because the delivered policy is not what the
    ///     admin's console says it is.
    ///   - pamNotWired: the daemon is enforcing but the PAM gate
    ///     (`/etc/pam.d/sudo_local` → `pam_serberus.so`) failed verification, so
    ///     the coarse sudoers drop-in was withheld. Ranks just below
    ///     `authdb_failure` (see ``overlayPAMGate(state:reason:pamNotWired:)``).
    ///   - bypassUnresolvable: a delivered or served enforcing config whose
    ///     `pamBypass` entries ALL fail to resolve to a real user/group — zero
    ///     working break-glass (break-glass resolvability). Ranks just below
    ///     `config_invalid`. The delivered config itself is not adopted (see
    ///     ``EffectiveConfigResolver``); this reports why.
    static func resolveState(
        configInvalid: Bool,
        grantsError: Bool,
        authDBError: Bool,
        rulesError: Bool,
        fdaReady: Bool,
        hasProfiles: Bool,
        awaitingConfig: Bool = false,
        configMissing: Bool = false,
        pamNotWired: Bool = false,
        bypassUnresolvable: Bool = false
    ) -> (state: DaemonState, reason: DegradedReason?) {
        if configInvalid { return (.degraded, .configInvalid) }
        if bypassUnresolvable { return (.degraded, .bypassUnresolvable) }
        if configMissing { return (.degraded, .configMissing) }
        if grantsError { return (.degraded, .grantsDBError) }
        if authDBError { return (.degraded, .authDBFailure) }
        if pamNotWired { return (.degraded, .pamNotWired) }
        if rulesError { return (.degraded, .ruleParseError) }
        if awaitingConfig { return (.awaitingConfig, nil) }
        if !fdaReady { return (.pendingPPPC, nil) }
        if !hasProfiles { return (.pendingProfiles, nil) }
        return (.healthy, nil)
    }

    /// Applies a PAM-gate verdict to an ALREADY-resolved state (startup resolves
    /// its state before provisioning runs), with the same precedence as
    /// ``resolveState(configInvalid:grantsError:authDBError:rulesError:fdaReady:hasProfiles:awaitingConfig:configMissing:pamNotWired:bypassUnresolvable:)``:
    /// the kill switch, awaiting-config, and the higher-ranked degraded causes
    /// (config_invalid, bypass_unresolvable, config_missing, grants_db_error,
    /// authdb_failure) win; anything else becomes `degraded(pam_not_wired)`.
    static func overlayPAMGate(
        state: DaemonState,
        reason: DegradedReason?,
        pamNotWired: Bool
    ) -> (state: DaemonState, reason: DegradedReason?) {
        guard pamNotWired else { return (state, reason) }
        switch state {
        case .killSwitch, .awaitingConfig:
            return (state, reason)
        case .degraded:
            switch reason {
            case .configInvalid?, .bypassUnresolvable?, .configMissing?, .grantsDBError?, .authDBFailure?:
                return (state, reason)
            default:
                return (.degraded, .pamNotWired)
            }
        case .pendingPPPC, .pendingProfiles, .healthy:
            return (.degraded, .pamNotWired)
        }
    }
}

// MARK: - Wall-clock high-water mark

/// Persists the latest wall-clock time the daemon has seen, so a clock set back
/// while the daemon was not running can be detected at the next start. Within
/// one boot the continuous clock already bounds every grant; across a reboot it
/// restarts, and this mark is what is left.
public protocol WallClockHighWaterStoring: Sendable {
    /// The stored mark, or nil when there is none or it cannot be trusted.
    func read() -> Date?
    func write(_ date: Date) throws
}

/// Production ``WallClockHighWaterStoring``: a one-key XML property list
/// (`highWaterMark`, a date) at ``fileName`` in the daemon's support directory,
/// written atomically as root:wheel 0600. A file that is not a regular file
/// owned by the daemon's user, or that is group/other-writable, is ignored.
public struct WallClockHighWaterMark: WallClockHighWaterStoring {
    public static let fileName = "clock-high-water.plist"
    static let key = "highWaterMark"

    public let url: URL
    private let requiredOwnerUID: uid_t

    public init(url: URL, requiredOwnerUID: uid_t = geteuid()) {
        self.url = url
        self.requiredOwnerUID = requiredOwnerUID
    }

    public func read() -> Date? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == requiredOwnerUID, info.st_mode & 0o022 == 0,
              info.st_size <= 4096,
              let data = try? handle.readToEnd(),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let date = (plist as? [String: Any])?[Self.key] as? Date else { return nil }
        return date
    }

    public func write(_ date: Date) throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: [Self.key: date], format: .xml, options: 0)
        let temp = url.deletingLastPathComponent()
            .appendingPathComponent(".\(Self.fileName).\(UUID().uuidString)")
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: temp.path]) }
        let written = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        let synced = fsync(fd) == 0
        close(fd)
        guard written == data.count, synced, rename(temp.path, url.path) == 0 else {
            unlink(temp.path)
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
    }
}

// MARK: - Upgrade detection

/// Remembers which daemon build last ran, so the next start can tell an
/// upgrade (or downgrade, or reinstall of a different build) from a restart.
/// An upgrade ends every live Serberus JIT admin session instead of re-arming
/// it: the old daemon may not have got to demote them before it was replaced.
public protocol DaemonBuildMarkerStoring: Sendable {
    /// The build identity recorded by the last run, or nil when there is none
    /// or it cannot be trusted.
    func read() -> String?
    func write(_ identity: String) throws
}

/// Production ``DaemonBuildMarkerStoring``: a one-key XML property list
/// (`buildIdentity`) at ``fileName`` in the daemon's support directory,
/// written atomically as root 0600, read only when it is a regular file owned
/// by the daemon's user and not group/other-writable. The same rules as
/// ``WallClockHighWaterMark``.
public struct DaemonBuildMarker: DaemonBuildMarkerStoring {
    public static let fileName = "last-daemon-build.plist"
    static let key = "buildIdentity"

    public let url: URL
    private let requiredOwnerUID: uid_t

    public init(url: URL, requiredOwnerUID: uid_t = geteuid()) {
        self.url = url
        self.requiredOwnerUID = requiredOwnerUID
    }

    public func read() -> String? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == requiredOwnerUID, info.st_mode & 0o022 == 0,
              info.st_size <= 4096,
              let data = try? handle.readToEnd(),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let identity = (plist as? [String: Any])?[Self.key] as? String, !identity.isEmpty else { return nil }
        return identity
    }

    public func write(_ identity: String) throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: [Self.key: identity], format: .xml, options: 0)
        let temp = url.deletingLastPathComponent()
            .appendingPathComponent(".\(Self.fileName).\(UUID().uuidString)")
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: temp.path]) }
        let written = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        let synced = fsync(fd) == 0
        close(fd)
        guard written == data.count, synced, rename(temp.path, url.path) == 0 else {
            unlink(temp.path)
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
    }
}

/// The marker the production preinstall writes on an upgrade, before it stops
/// the old daemon: `.upgrade-in-progress` in the support directory, root:wheel
/// 0600, one line `startedAt=<timestamp>`. Its presence at startup means an
/// upgrade, like a build change (``DaemonBuildIdentity``): a reinstall of the
/// same build still ends the JIT sessions the old daemon left open.
///
/// Trusted only when `lstat` shows a regular file owned by the daemon's user
/// (root in production), not group- or other-writable, and small. Anything
/// else is ignored and logged. The daemon removes it after startup handling.
public struct PreinstallUpgradeMarker: Sendable {
    public static let fileName = ".upgrade-in-progress"
    static let maxSize: off_t = 4096

    public enum Reading: Sendable, Equatable {
        case absent
        case present
        /// Something is at the path but fails the checks; the reason.
        case untrusted(String)
    }

    public let url: URL
    private let requiredOwnerUID: uid_t

    public init(url: URL, requiredOwnerUID: uid_t = geteuid()) {
        self.url = url
        self.requiredOwnerUID = requiredOwnerUID
    }

    public func read() -> Reading {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            return errno == ENOENT ? .absent : .untrusted("lstat failed (errno \(errno))")
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else { return .untrusted("not a regular file") }
        guard info.st_uid == requiredOwnerUID else { return .untrusted("owned by uid \(info.st_uid)") }
        guard info.st_mode & 0o022 == 0 else {
            return .untrusted(String(format: "group- or other-writable (mode %o)", info.st_mode & 0o7777))
        }
        guard info.st_size <= Self.maxSize else { return .untrusted("too large (\(info.st_size) bytes)") }
        return .present
    }

    /// Removes whatever is at the path, unless it is a directory. `unlink`
    /// never follows a symlink, so a planted link is removed, not its target.
    /// Returns false when something is left behind.
    @discardableResult
    public func remove() -> Bool {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { return errno == ENOENT }
        guard (info.st_mode & S_IFMT) != S_IFDIR else { return false }
        return unlink(url.path) == 0 || errno == ENOENT
    }
}

/// What identifies the running daemon build: the version it reports and a
/// SHA-256 of its own executable. The hash changes with every build that is
/// installed, even one that keeps the version string (a rebuilt or re-signed
/// package), which a version comparison alone would miss.
public enum DaemonBuildIdentity {
    /// `"<version> sha256:<hex>"` for the running executable, or nil when it
    /// cannot be read (upgrade detection is then skipped for this run).
    public static func current(version: String) -> String? {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        guard size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(size) + 1)
        guard _NSGetExecutablePath(&buffer, &size) == 0 else { return nil }
        let path = String(cString: buffer)
        guard let digest = SHA256Digest.file(atPath: path) else { return nil }
        return "\(version) sha256:\(digest)"
    }

    /// Whether this start follows an upgrade: the recorded identity differs
    /// from `current`, or there is none (a daemon from before this check left
    /// no record; a fresh install has nothing to end, so treating it as an
    /// upgrade costs nothing).
    public static func isUpgrade(recorded: String?, current: String) -> Bool {
        recorded != current
    }
}

/// Streaming SHA-256 of a file, opened without following a symlink.
enum SHA256Digest {
    static func file(atPath path: String) -> String? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 256 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                return nil
            }
            buffer.withUnsafeBytes { hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0.prefix(count))) }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

/// Detects a wall clock set back while the daemon was not running, and undoes
/// every timed grant when it was.
///
/// After a reboot a grant is checked against the wall clock only until the
/// startup re-stamp gives it a continuous-clock deadline, and that deadline is
/// computed from the wall clock. A clock set back before the reboot would
/// therefore hand every grant its lost time back. Comparing the clock at start
/// with the persisted high-water mark catches that; when it happens, every
/// timed grant is revoked and every JIT admin demoted.
public enum ClockRollbackGuard {
    /// How far behind the mark the clock may be before it counts as set back:
    /// room for an ordinary time-sync correction.
    ///
    /// The tolerance is allowed again at every start. Someone who can set the
    /// clock (Date & Time is open to standard users) can set it back by just
    /// under this much before each reboot; the startup re-stamp measures what is
    /// left of a timed grant on the wall clock, so each reboot can give a grant
    /// up to this much time back. Accepted: the gain is small, and a grant
    /// still only satisfies the rule that issued it.
    public static let toleranceSeconds: TimeInterval = 120

    /// Whether `now` is earlier than the mark by more than ``toleranceSeconds``.
    public static func isSetBack(now: Date, highWater: Date?) -> Bool {
        guard let highWater else { return false }
        return now < highWater.addingTimeInterval(-toleranceSeconds)
    }

    /// What was undone.
    public struct Outcome: Sendable, Equatable {
        public var jit = JITDemotionReport()
        /// Timed non-JIT grants revoked.
        public var revokedGrants = 0
        /// Failures other than the JIT report's own.
        public var failures: [String] = []

        public init() {}
    }

    /// Demotes every JIT admin and revokes their rows (``JITDemotionSweep``),
    /// then revokes every other unrevoked grant that has an expiry. JIT rows go
    /// first and are never revoked here directly: a JIT row may be revoked only
    /// after its user left `admin`, so a failed demotion keeps its row live for
    /// the manager to retry.
    public static func revokeTimedGrants(
        grantStore: GrantMaintaining,
        membership: GroupMembershipControlling,
        accountResolver: JITAccountResolving = DirectoryJITAccountResolver(),
        ticketClearer: SudoTicketClearing = NoopSudoTicketClearer(),
        adminGroupScrubber: StaleAdminEntryScrubbing = NoopStaleAdminEntryScrubber(),
        now: Date,
        log: @Sendable (String) async -> Void = { _ in }
    ) async -> Outcome {
        var outcome = Outcome()
        outcome.jit = await JITDemotionSweep.run(
            grantStore: grantStore, membership: membership, accountResolver: accountResolver,
            ticketClearer: ticketClearer, adminGroupScrubber: adminGroupScrubber, now: now, log: log)
        do {
            let timed = try await grantStore.allGrants()
                .filter { $0.revokedAt == nil && $0.expiresAt != nil && !JITAdmin.isJITGrant($0) }
            for grant in timed {
                outcome.revokedGrants += try await grantStore.revoke(grantID: grant.grantID, now: now)
            }
        } catch {
            outcome.failures.append("timed grants could not all be revoked: \(error)")
        }
        return outcome
    }
}
