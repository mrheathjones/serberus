import Darwin
import Foundation
import PrivMgrCore

// MARK: - Provisioning protocol

/// Provisions (and tears down) the coarse `/etc/sudoers.d/serberus` drop-in that
/// lets enrolled STANDARD (non-admin) users reach the curated `sudo` command
/// paths at all. `pam_serberus` + the daemon remain the authoritative *fine*
/// policy — this drop-in is only the outer allowlist.
///
/// Mirrors ``AuthorizationDBApplying``: a protocol so ``DaemonController`` can be
/// wired with a no-op in tests / degraded builds, and so the real, root-requiring
/// install pipeline is injected behind ``SudoersInstalling`` for unit testing.
///
/// # Non-fatal by contract
/// Both entry points are non-throwing. A generation / validation / install
/// failure is **not** fatal to the daemon: it leaves the prior-good drop-in (or
/// none) in place and logs loudly. Sudoers provisioning therefore never
/// contributes to `resolveState` degraded causes — a broken drop-in must not
/// take the whole daemon degraded.
///
/// # Success signal
/// Non-fatal is not the same as silent: both entry points RETURN whether the
/// on-disk drop-in now matches intent. The daemon uses this to gate its policy
/// signature — a failed *shrink* (de-enrollment / kill-switch removal that kept
/// the prior-good file) leaves the signature stale so the next reload tick
/// re-attempts it, rather than latching a removed user as still-authorized on
/// disk until an unrelated policy change.
public protocol SudoersProvisioning: Sendable {
    /// Regenerates the drop-in from `profiles` + `enrollment` and installs it
    /// (validated by `visudo`), or removes it when the generated body is empty
    /// (empty enrollment or every candidate rule excluded).
    ///
    /// - Returns: `true` when the on-disk drop-in now matches intent
    ///   (installed, byte-identical to the target, or removed as intended);
    ///   `false` when a validation / install / removal failure kept the
    ///   prior-good file (intent NOT yet realized).
    @discardableResult
    func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool

    /// Removes the managed drop-in (kill switch / teardown). Marker-guarded — a
    /// same-named admin-authored file is never destroyed.
    ///
    /// - Returns: `true` when the drop-in is gone (removed or already
    ///   absent/foreign); `false` when a removal I/O failure left it in place.
    @discardableResult
    func remove() async -> Bool
}

/// No-op provisioner: performs no filesystem work and never fails. Wired when
/// sudoers provisioning is intentionally absent (unit tests, dry runs). Reports
/// success so the caller's signature gating advances normally.
public struct NoopSudoersProvisioner: SudoersProvisioning {
    public init() {}
    @discardableResult
    public func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool { true }
    @discardableResult
    public func remove() async -> Bool { true }
}

// MARK: - Installer backend

/// The root-privileged filesystem + `visudo` operations ``SudoersManager`` needs,
/// abstracted so the manager's generate→pre-screen→validate→install/remove
/// orchestration is unit-tested with an in-memory fake — no root, no live `/etc`,
/// no real `visudo`.
public protocol SudoersInstalling: Sendable {
    /// The body of the currently-installed *managed* drop-in (guarded by the
    /// Serberus header marker), or `nil` when no file is present, the file is
    /// unreadable, or it is a foreign (non-marked) file. Used for change
    /// detection so an unchanged policy costs no `visudo` run and no file churn.
    func currentManagedBody() -> String?

    /// Validates `body` with `visudo -c -f <temp>` (temp written OUTSIDE
    /// `/etc/sudoers.d`, on the same volume as `/etc` for an atomic rename) and,
    /// **only** on `visudo` exit 0, atomically installs it as `root:wheel`,
    /// mode `0440`. Throws on pre-screen / validation / timeout without touching
    /// the installed file (prior-good preserved). Refuses to clobber a foreign
    /// (non-marked) file at the path.
    func validateAndInstall(_ body: String) async throws

    /// Removes the managed drop-in iff it carries the Serberus header marker.
    /// A foreign file, or an absent one, is left untouched. Never throws for the
    /// absent / foreign cases; throws only on an actual removal I/O failure.
    func removeManaged() throws
}

// MARK: - Errors

public enum SudoersError: Error, Equatable, Sendable {
    /// The assembled body carried a control character other than the `\n` line
    /// separators — refused before any `visudo`/install (defense in depth over
    /// the generator's per-path rejection).
    case bodyContainedControlCharacter
    /// `visudo -c` rejected the candidate file (syntax error). Fail closed.
    case visudoValidationFailed(status: Int32, stderr: String)
    /// `visudo -c` did not complete inside the timeout — treated as a validation
    /// failure (fail closed): a hung validator must never install.
    case visudoTimedOut
    /// A foreign (non-Serberus-marked) file already occupies the drop-in path;
    /// the installer refuses to overwrite admin-authored config.
    case foreignFilePresent(path: String)
    /// A filesystem step (temp write, chown/chmod, rename) failed.
    case installFailed(String)

    public var localizedDescription: String {
        switch self {
        case .bodyContainedControlCharacter:
            return "generated sudoers body contained a control character"
        case let .visudoValidationFailed(status, stderr):
            return "visudo -c rejected the candidate drop-in (status \(status)): \(stderr)"
        case .visudoTimedOut:
            return "visudo -c did not complete before the timeout"
        case let .foreignFilePresent(path):
            return "a foreign (non-Serberus) file occupies \(path); refusing to overwrite"
        case let .installFailed(detail):
            return "sudoers install failed: \(detail)"
        }
    }
}

// MARK: - Manager

/// Owns the coarse sudoers drop-in lifecycle. Pure orchestration around the
/// injected ``SudoersInstalling`` backend and the pure ``SudoersGenerator``:
/// generate → log exclusions → (empty ⇒ remove) → pre-screen → change-detect →
/// validate + atomically install. Every path is fail-safe and non-fatal.
public struct SudoersManager: SudoersProvisioning {
    private let installer: SudoersInstalling
    private let integrityLogger: IntegrityLogger?
    private let daemonVersion: String
    private let now: @Sendable () -> Date

    public init(
        installer: SudoersInstalling,
        integrityLogger: IntegrityLogger?,
        daemonVersion: String = DaemonVersion.current.daemonVersion,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.installer = installer
        self.integrityLogger = integrityLogger
        self.daemonVersion = daemonVersion
        self.now = now
    }

    @discardableResult
    public func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool {
        // Pin the header to the canonical Swift constant so the installed file's
        // first line is exactly what the pkg teardown scripts + `removeManaged`
        // marker-guard anchor on (BundleConfig.sudoersManagedHeader).
        let result = SudoersGenerator.generate(
            profiles: profiles,
            enrollmentGroup: enrollment.group,
            enrollmentUsers: enrollment.users,
            header: BundleConfig.sudoersManagedHeader
        )

        // Loud logging: every rule that could not be represented stays denied at
        // the sudoers gate (fail-safe), but the operator must be able to see why.
        for exclusion in result.excluded {
            await emit(
                "sudo rule excluded from coarse drop-in (pattern=\(exclusion.commandPattern ?? "nil") "
                + "matchType=\(exclusion.matchType)): \(exclusion.reason)"
            )
        }

        // Empty body ⇒ empty enrollment OR every command excluded ⇒ REMOVE the
        // drop-in (never install a header-only, invalid sudoers file). This is
        // the fail-safe default: enrolled standard users drop back to "denied".
        // The removal result IS the apply result — a failed shrink-to-empty must
        // report failure so the caller retries.
        guard !result.body.isEmpty else {
            return await removeInternal(reason: "no representable sudo commands / empty enrollment")
        }

        // Defense-in-depth pre-screen of the whole body: the generator already
        // rejects control characters per path, but a body-level check guarantees
        // nothing but printable text + `\n` line separators is ever handed to
        // `visudo` / written into `/etc`. Kept prior-good ⇒ intent NOT realized.
        guard Self.bodyIsClean(result.body) else {
            await emit("REFUSED to install sudoers drop-in: body contained a control character (kept prior-good)")
            return false
        }

        // Change detection: the generator emits byte-identical output for
        // identical inputs, so an unchanged policy skips the `visudo` run and the
        // rename entirely — no file churn, no log noise on every reload tick. The
        // on-disk state already matches intent, so this is a success.
        if let current = installer.currentManagedBody(), current == result.body {
            return true
        }

        do {
            try await installer.validateAndInstall(result.body)
            await emit("installed coarse sudoers drop-in (\(result.body.split(separator: "\n").count) line(s))")
            return true
        } catch {
            // NON-FATAL: keep the prior-good drop-in (or none). A malformed file
            // is never installed (visudo fail-closed); the daemon re-applies on
            // the next reload. Report failure so the signature stays stale.
            await emit("sudoers drop-in NOT installed (kept prior-good): \(describe(error))")
            return false
        }
    }

    @discardableResult
    public func remove() async -> Bool {
        await removeInternal(reason: "teardown / kill switch")
    }

    @discardableResult
    private func removeInternal(reason: String) async -> Bool {
        do {
            try installer.removeManaged()
            await emit("removed coarse sudoers drop-in (\(reason))")
            return true
        } catch {
            // NON-FATAL, but report failure: a removal I/O error left the drop-in
            // on disk, so the caller must retry the shrink on the next tick.
            await emit("sudoers drop-in removal failed (\(reason)): \(describe(error))")
            return false
        }
    }

    /// True when `body` contains only printable characters and `\n` line
    /// separators. Rejects NUL, CR, DEL, tabs, and every other C0/C1 control.
    static func bodyIsClean(_ body: String) -> Bool {
        for scalar in body.unicodeScalars {
            let value = scalar.value
            if value == 0x0A { continue } // the only permitted control: newline
            if value < 0x20 || value == 0x7F || (value >= 0x80 && value <= 0x9F) {
                return false
            }
        }
        return true
    }

    private func describe(_ error: Error) -> String {
        (error as? SudoersError)?.localizedDescription ?? String(describing: error)
    }

    private func emit(_ detail: String) async {
        DaemonLog.integrity.notice("sudoers: \(detail, privacy: .public)")
        guard let integrityLogger else { return }
        // Reuse the existing `.policyChange` integrity kind — the drop-in is a
        // projection of the current policy/enrollment onto the coarse gate.
        let event = IntegrityEvent(timestamp: now(), kind: .policyChange,
                                   detail: "sudoers: \(detail)", daemonVersion: daemonVersion)
        try? await integrityLogger.log(event)
    }
}

// MARK: - Production backend

/// Production ``SudoersInstalling`` over the real `/etc/sudoers.d/serberus` path,
/// `visudo`, and root-only `chown`/`chmod`/`rename`.
///
/// # Safety pipeline (Section: sudoers-provisioning.md)
/// A malformed drop-in breaks `sudo` for **everyone**, so install is strictly
/// fail-closed: the candidate is written to a temp file OUTSIDE `/etc/sudoers.d`
/// (so a half-written file is never parsed by the next `sudo`), validated with a
/// **timeout-bearing** `visudo -c -f`, and only on exit 0 atomically renamed into
/// place as `root:wheel 0440`. Any failure or timeout leaves the prior-good file
/// untouched.
public struct SystemSudoersInstaller: SudoersInstalling {
    private let dropInURL: URL
    /// Directory for the pre-install temp file — MUST be on the same volume as
    /// the drop-in (for an atomic rename) and OUTSIDE `/etc/sudoers.d` (so it is
    /// never parsed as an include). Defaults to the drop-in's grandparent
    /// (`/etc`), which satisfies both.
    private let tempDirectory: URL
    private let visudoPath: String
    private let visudoTimeout: TimeInterval
    private let headerMarkerPrefix: String

    public init(
        dropInPath: String = BundleConfig.sudoersDropInPath,
        tempDirectory: URL? = nil,
        visudoPath: String = "/usr/sbin/visudo",
        visudoTimeout: TimeInterval = 10
    ) {
        let url = URL(fileURLWithPath: dropInPath)
        self.dropInURL = url
        // Grandparent of /etc/sudoers.d/serberus is /etc — same volume, outside
        // the @includedir.
        self.tempDirectory = tempDirectory
            ?? url.deletingLastPathComponent().deletingLastPathComponent()
        self.visudoPath = visudoPath
        self.visudoTimeout = visudoTimeout
        // Matches PKG/Scripts/pam-lib.sh SERBERUS_SUDOERS_MARKER_RE: the stable
        // path+domain prefix shared by both header case variants.
        self.headerMarkerPrefix =
            "# \(BundleConfig.sudoersDropInPath): managed by \(BundleConfig.logSubsystem)"
    }

    public func currentManagedBody() -> String? {
        guard let body = try? String(contentsOf: dropInURL, encoding: .utf8),
              Self.isManaged(body, markerPrefix: headerMarkerPrefix) else {
            return nil
        }
        return body
    }

    public func validateAndInstall(_ body: String) async throws {
        // Never clobber a foreign, admin-authored file sitting at our path.
        if let existing = try? String(contentsOf: dropInURL, encoding: .utf8),
           !Self.isManaged(existing, markerPrefix: headerMarkerPrefix) {
            throw SudoersError.foreignFilePresent(path: dropInURL.path)
        }

        let tempURL = tempDirectory.appendingPathComponent(
            ".serberus-sudoers.\(ProcessInfo.processInfo.processIdentifier).\(UUID().uuidString).tmp"
        )
        // Best-effort cleanup of the temp file on every exit path.
        defer { try? FileManager.default.removeItem(at: tempURL) }

        do {
            try Data(body.utf8).write(to: tempURL, options: .atomic)
            // Stamp the FINAL ownership/mode on the temp before validation so the
            // rename installs exactly root:wheel 0440 with no post-rename window.
            try FileManager.default.setAttributes(
                [.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o440],
                ofItemAtPath: tempURL.path
            )
        } catch {
            throw SudoersError.installFailed("temp write/attrs: \(String(describing: error))")
        }

        // Validate with a TIMEOUT: a hung `visudo` is a validation failure.
        let validation: ProcessCommandRunner.TimedResult
        do {
            validation = try await ProcessCommandRunner.execute(
                path: visudoPath, arguments: ["-c", "-f", tempURL.path], timeout: visudoTimeout
            )
        } catch {
            throw SudoersError.installFailed("visudo could not be run: \(String(describing: error))")
        }
        if validation.timedOut {
            throw SudoersError.visudoTimedOut
        }
        guard validation.status == 0 else {
            throw SudoersError.visudoValidationFailed(
                status: validation.status,
                stderr: validation.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }

        // Atomic install: rename within the same volume replaces the target in
        // one step. `rename(2)` is atomic; a concurrent `sudo` sees either the
        // old file or the new one, never a partial write.
        let renamed = tempURL.withUnsafeFileSystemRepresentation { src -> Int32 in
            dropInURL.withUnsafeFileSystemRepresentation { dst in
                rename(src, dst)
            }
        }
        guard renamed == 0 else {
            throw SudoersError.installFailed("rename into place failed: errno \(errno)")
        }
    }

    public func removeManaged() throws {
        guard let body = try? String(contentsOf: dropInURL, encoding: .utf8) else {
            return // absent or unreadable — nothing to remove
        }
        guard Self.isManaged(body, markerPrefix: headerMarkerPrefix) else {
            return // foreign file — never destroy admin-authored config
        }
        try FileManager.default.removeItem(at: dropInURL)
    }

    /// True when any line of `body` starts with the Serberus managed-header
    /// prefix (mirrors the pkg teardown grep, matching both header case variants).
    static func isManaged(_ body: String, markerPrefix: String) -> Bool {
        body.split(separator: "\n", omittingEmptySubsequences: false)
            .contains { $0.hasPrefix(markerPrefix) }
    }
}
