import Foundation
import Security

/// Single source of truth for all identity strings in the Serberus namespace.
///
/// `com.herojoneslabs.serberus` is the maintainer's namespace; forks that need
/// their own ES entitlement change these constants (see CONTRIBUTING.md).
/// Changing them re-namespaces the entire product — no other file may
/// hard-code a bundle ID, managed preference domain, Mach service name,
/// or log subsystem.
public enum BundleConfig {
    /// Bundle ID of the root LaunchDaemon.
    public static let daemonBundleID = "com.herojoneslabs.serberus.daemon"
    /// Bundle ID of the menu bar LaunchAgent.
    public static let sentinelBundleID = "com.herojoneslabs.serberus.sentinel"
    /// Bundle ID of the Guardian — a tiny invisible LSUIElement LaunchAgent that
    /// watches the Sentinel and, when it is quit, shows a persistent "elevations
    /// won't work" panel with a relaunch button (gated by the managed
    /// `guardianEnabled` key). It calls no daemon interface.
    public static let guardianBundleID = "com.herojoneslabs.serberus.guardian"
    /// Bundle ID of the Commander app / Policy Builder.
    public static let commanderBundleID = "com.herojoneslabs.serberus.commander"
    /// Identifier of the C PAM module.
    public static let pamBundleID = "com.herojoneslabs.serberus.pam"
    /// Bundle ID of the standard-user diagnostics app (Serberus Intel).
    public static let intelBundleID = "com.herojoneslabs.serberus.intel"
    /// Bundle ID of the Finder Sync extension that gives the "Install/Uninstall
    /// with Serberus" TOP-LEVEL right-click items (with the Sentinel icon). It
    /// rides inside the `/Applications` full app, so Apple requires its id be
    /// prefixed by the container's id: `.intel`, which the Sentinel app keeps
    /// while the menu bar agent uses `.sentinel`. It is
    /// SANDBOXED and merely forwards a selected path to the agent's bridge — it
    /// is deliberately NOT a daemon principal (never added to
    /// ``ExpectedCaller/forBundleID(_:)`` / ``ExpectedCaller/interface``, so the
    /// daemon still rejects it as an unknown caller if it ever connects direct).
    public static let finderExtensionBundleID = "com.herojoneslabs.serberus.intel.finderext"
    /// Mach service name the daemon listens on.
    public static let machService = "com.herojoneslabs.serberus.daemon"
    /// Mach service the AGENT vends for the Finder-extension → agent bridge.
    /// Namespaced under `.sentinel` (the agent is the `.sentinel` principal);
    /// distinct from the daemon's ``machService``. Declared in the agent's
    /// LaunchAgent plist `MachServices` so launchd advertises it; the sandboxed
    /// extension is granted a `mach-lookup` exception for ONLY this name.
    public static let finderBridgeMachService = "com.herojoneslabs.serberus.sentinel.finder-bridge"
    /// Managed preference domain: Jamf connectivity + daemon behavior.
    public static let configDomain = "com.herojoneslabs.serberus.config"
    /// Managed preference domain: rule profiles (`rules_*` keys).
    public static let rulesDomain = "com.herojoneslabs.serberus.rules"
    /// Managed preference domain: elevation prompt presentation.
    public static let promptsDomain = "com.herojoneslabs.serberus.prompts"
    /// Managed preference domain: logging and notification behavior.
    public static let notifyDomain = "com.herojoneslabs.serberus.notify"
    /// Managed preference domain: just-in-time local-admin elevation.
    public static let jitDomain = "com.herojoneslabs.serberus.jit"
    /// Managed preference domain: opt-in debug telemetry (the `debugModeEnabled`
    /// key). Delivered by its OWN config profile so it can be added to expose the
    /// per-device decision-event list to Jamf and removed to withdraw it — the
    /// daemon always collects the events locally, but only publishes them to the
    /// EA path while this profile is present and `true`.
    public static let debugDomain = "com.herojoneslabs.serberus.debug"
    /// Managed preference domain: app management — self-service **install** of
    /// notarized Developer-ID software and **uninstall** (move to Trash) of a
    /// `/Applications` app, via the Finder "Install/Uninstall with Serberus"
    /// actions. One domain for the whole app-management surface (keys, not new
    /// domains, as features grow). Absent / disabled ⇒ the daemon refuses.
    public static let appManagementDomain = "com.herojoneslabs.serberus.appmanagement"
    /// OSLog subsystem shared by all components.
    public static let logSubsystem = "com.herojoneslabs.serberus"
    /// Apple Developer Team ID every Serberus peer must be signed by: the team
    /// that signed THIS process, read from its own code signature.
    ///
    /// Deriving it, rather than hard-coding one team, means a build signed by
    /// any team trusts only binaries from that same team. Empty when this
    /// process is unsigned, ad-hoc signed, or its signature is invalid, and
    /// ``XPCConnectionValidator`` then rejects every peer.
    public static let teamID: String = signingTeamOfCurrentProcess() ?? ""

    /// The Team ID in this process's own valid code signature, or `nil` when
    /// there is none (unsigned, ad-hoc, or a signature that fails validation).
    static func signingTeamOfCurrentProcess() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return nil
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info
        ) == errSecSuccess,
            let info = info as? [String: Any],
            let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
            !team.isEmpty else {
            return nil
        }
        return team
    }

    /// Signing identifier of Apple's platform `sudo` binary. `pam_serberus.so`
    /// runs in-process inside `sudo`, so a real curated-sudo XPC call carries
    /// **sudo's** audit token — never the module's identity. The daemon
    /// authenticates that host by this identifier plus `anchor apple` + euid 0
    /// (see ``XPCConnectionValidator/validatePAMHost(_:)``). Confirm on-device
    /// with `codesign -dvvv /usr/bin/sudo`; bake in the exact string it reports.
    public static let sudoSigningIdentifier = "com.apple.sudo"
    /// On-disk path of the platform `sudo` binary, pinned as defense-in-depth.
    public static let sudoExecutablePath = "/usr/bin/sudo"

    // MARK: Install-with-Serberus (pinned tool + target paths)

    /// Root-owned staging directory the daemon copies a user-chosen `.pkg`/`.app`
    /// into BEFORE verifying + installing it, so the source in user-writable
    /// space can't be swapped between the check and the install (TOCTOU). Same
    /// 0755 root:wheel "traverse but don't create" posture as the capture
    /// hand-off dir; per-request subdirs are created 0700 root:wheel.
    public static let installStagingDirectory = "/Library/Application Support/Serberus/install-staging"
    /// The macOS package installer, pinned.
    public static let installerExecutablePath = "/usr/sbin/installer"
    /// The Gatekeeper assessment tool, pinned — used to require notarized
    /// Developer-ID signing before an install.
    public static let spctlExecutablePath = "/usr/sbin/spctl"
    /// `pkgutil`, pinned — package receipt / signature inspection.
    public static let pkgutilExecutablePath = "/usr/sbin/pkgutil"
    /// `ditto`, pinned — signature-preserving copy of an `.app` (also used to
    /// copy an `.app` out of a mounted, read-only `.dmg`).
    public static let dittoExecutablePath = "/usr/bin/ditto"
    /// `cp`, pinned — makes Install with Serberus's staging copy as the
    /// requesting user. Unlike `ditto`, it doesn't need to search the
    /// root-only folders above its working directory.
    public static let cpExecutablePath = "/bin/cp"
    /// The one and only install destination for an `.app`, and the only directory
    /// an "Uninstall with Serberus" may remove from — pinned.
    public static let applicationsDirectory = "/Applications"

    /// Private entitlement marker required of the Sentinel when calling the daemon.
    public static let sentinelEntitlement = "com.herojoneslabs.serberus.is-ui-sentinel"

    /// Daemon support directory.
    public static let supportDirectory = "/Library/Application Support/Serberus"
    /// Installed path of the hidden Sentinel menu-bar agent bundle — the Guardian
    /// relaunches it by this path as a last resort.
    public static let sentinelAgentAppPath = "/Library/Application Support/Serberus/Serberus Sentinel Agent.app"
    /// Installed path of the Sentinel's LaunchAgent plist — the Guardian
    /// re-`bootstrap`s this if the `kickstart` primary fails.
    public static let sentinelLaunchAgentPath = "/Library/LaunchAgents/com.herojoneslabs.serberus.sentinel.plist"
    /// On-disk JSONL log directory.
    public static let logDirectory = "/Library/Logs/Serberus"
    /// Parent directory for privileged capture hand-offs.
    ///
    /// Root-owned and **0755**: the console user must be able to traverse it to
    /// read the per-request directory the daemon chowns to them, but must not
    /// be able to create entries here — otherwise a user could pre-create the
    /// next request's path (or a symlink at it) and redirect a root write.
    public static let captureHandoffDirectory = "/Library/Logs/Serberus/captures"
    /// AuthorizationDB right snapshot directory.
    public static let authDBBackupDirectory = "/Library/Application Support/Serberus/authdb-backups"
    /// Persisted grant database path.
    public static let grantDatabasePath = "/Library/Application Support/Serberus/grants.sqlite"
    /// Daemon state machine plist path.
    public static let statePlistPath = "/Library/Application Support/Serberus/state.plist"
    /// Fleet telemetry summary plist path (fleet telemetry): world-readable decision
    /// counts/trends, rewritten on each reload tick, harvested by Jamf EAs.
    public static let fleetSummaryPlistPath =
        "/Library/Application Support/Serberus/fleet-summary.plist"
    /// Recent denial/prompt events, ALWAYS written here (root-only 0600): the
    /// local collection, independent of debug mode.
    public static let recentEventsLocalPath =
        "/Library/Application Support/Serberus/recent-events.json"
    /// The EA-inspected copy of the recent events (root-only 0600: the extension
    /// attribute runs as root). Present ONLY while the `debugModeEnabled` profile
    /// is on; removed otherwise, so no per-decision detail reaches Jamf unless
    /// debug telemetry is opted in.
    public static let fleetEventsPublicPath =
        "/Library/Application Support/Serberus/fleet-events.json"
    /// Tiny world-readable marker (0644) the daemon rewrites each reload tick with
    /// the app-management master gate (`{enabled: Bool}`). The SANDBOXED Finder
    /// extension reads it (via a file-read sandbox exception) to conditionally
    /// SHOW/HIDE its "Install/Uninstall with Serberus" items — so a Mac where app
    /// management is off never even offers them. Advisory UX only; the daemon
    /// stays the authoritative gate on every action. NOTE: the same literal path
    /// is pinned in Support/SerberusFinderExtension.entitlements — keep in sync.
    public static let appManagementStatePath =
        "/Library/Application Support/Serberus/appmanagement-state.plist"
    /// Installed component version plist path.
    public static let versionPlistPath = "/Library/Application Support/Serberus/version.plist"
    /// Last-known-good configuration snapshot.
    ///
    /// Written (root:wheel 0644, atomically) every time the daemon adopts a
    /// **present and enforceable** managed config. Two roles:
    ///
    /// 1. Its EXISTENCE is the "this Mac has been configured" marker. Absent it,
    ///    Serberus has never held a usable config and must not enforce or mutate
    ///    anything (``DaemonState/awaitingConfig`` — the enrollment race where the
    ///    Core pkg lands before the config profile).
    /// 2. Its CONTENTS are the tamper/partial-profile fallback: an unscoped or
    ///    partial profile can never disable Serberus, because the daemon (and
    ///    `pam_serberus`) fall back to this snapshot — which is enforceable by
    ///    construction, so its `pamBypass` break-glass is always intact.
    ///
    /// The key shape is deliberately a subset of the `com.herojoneslabs.serberus.config`
    /// managed domain (same keys, same nesting) so `pam_config.c` parses it with
    /// the exact same code path as the managed plist. Jamf credentials are
    /// deliberately NOT persisted here — this file is world-readable.
    public static let lastKnownGoodConfigPath =
        "/Library/Application Support/Serberus/last-known-good-config.plist"

    /// Coarse sudoers drop-in Serberus provisions so standard (non-admin)
    /// users can invoke curated sudo commands at all. It is a per-command
    /// allowlist of the curated command paths only; `pam_serberus` + the
    /// daemon remain the authoritative fine policy. Installed 0440 root:wheel.
    public static let sudoersDropInPath = "/etc/sudoers.d/serberus"
    /// First line of every Serberus-provisioned sudoers drop-in. Provisioning
    /// keys ownership off this marker so it only ever rewrites or removes its
    /// own file and never clobbers an admin's hand-authored drop-in.
    public static let sudoersManagedHeader = "# \(sudoersDropInPath): managed by \(logSubsystem) — do not edit"
    /// Inline trailer appended to each generated sudoers stanza, mirroring the
    /// `# serberus-managed` tag on the sudo_local PAM line, so individual
    /// lines are recognizable as Serberus-authored.
    public static let sudoersManagedMarker = "# serberus-managed"

    /// Keychain service for daemon HMAC keys (System Keychain).
    public static let keychainService = "com.herojoneslabs.serberus.daemon"
    /// Keychain account for the log signing key.
    public static let logHMACKeyAccount = "log-hmac-key"
    /// Keychain account for the grant database integrity key.
    public static let grantsHMACKeyAccount = "grants-hmac-key"
}
