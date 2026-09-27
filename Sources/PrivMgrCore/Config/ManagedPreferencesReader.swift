import CoreFoundation
import Foundation

// MARK: - Preference source

/// Abstract source of managed preference values.
///
/// Production uses ``CFPreferencesSource`` (CFPreferences against the
/// managed domains — never `UserDefaults`); tests use
/// ``DictionaryPreferencesSource``. Serberus only ever reads managed
/// domains — there is deliberately no write API anywhere in this protocol.
public protocol PreferencesSource: Sendable {
    /// The value for `key` in `domain`, or `nil` when absent.
    func value(forKey key: String, domain: String) -> Any?
    /// All keys present in `domain`.
    func keys(inDomain domain: String) -> [String]
    /// Every known domain whose name equals `prefix` or begins with
    /// `prefix + "."` — the sibling sub-domains under a base domain. Used to
    /// compose rules delivered across several managed-preference domains
    /// (e.g. `com.herojoneslabs.serberus.rules.sudo`) so that separate config
    /// profiles never collide on the single native `rules` key. Order is the
    /// caller's responsibility (it sorts). The base domain itself need not be
    /// returned — the reader always includes it explicitly.
    func domains(matchingPrefix prefix: String) -> [String]
    /// The value for `key` in `domain` ONLY if it was delivered by management
    /// as COMPUTER-level policy (the root-owned
    /// `/Library/Managed Preferences/<domain>.plist`) — never a user-scoped
    /// profile, never the cfprefsd forced layer, never the unforced user or
    /// host preference layers. For keys that are policy rather than
    /// configuration (e.g. the Commander direct-publish gate), where anything
    /// the logged-in user can influence must not count.
    func managedValue(forKey key: String, domain: String) -> Any?
}

public extension PreferencesSource {
    /// Sources that cannot enumerate domains (test mocks, single-domain
    /// backends) report none; the reader still always reads the base domain,
    /// so this degrades to the pre-multi-domain behavior.
    func domains(matchingPrefix prefix: String) -> [String] { [] }
    /// Sources with no notion of "forced" (test dictionaries, snapshot
    /// stores) treat every value as managed.
    func managedValue(forKey key: String, domain: String) -> Any? { value(forKey: key, domain: domain) }
}

/// Source reading the host's COMPUTER-level managed preferences.
///
/// Despite the historical name, nothing here goes through CFPreferences any
/// more. Every Serberus reader — the root daemon, the authorization plugin
/// running as the console user inside SecurityAgentHelper, the Sentinel
/// agent, Commander, the CLI — reads policy from exactly one place: the
/// root-owned `/Library/Managed Preferences/<domain>.plist` a computer-level
/// MDM profile writes.
///
/// Why not CFPreferences:
/// - A root daemon cannot see the managed layer through it at all
///   (`CFPreferencesCopyKeyList` never enumerates managed keys and the root
///   composite read misses the layer).
/// - Inside a login session the cfprefsd FORCED layer also carries
///   USER-scoped profiles. A user-scope profile (which a user can often
///   install themselves, or which is scoped by user rather than device)
///   could then inject policy — for example an app branch the
///   authorization plugin would honour. Policy is device policy, so user
///   scope never counts.
/// - The unforced `/Library/Preferences` and `~/Library/Preferences` layers
///   are writable by anyone who once had root (a JIT admin) or by the user.
///
/// The plist is trusted only if it, and the directory holding it, are owned
/// by root and not group/other-writable, checked on the open descriptor.
public struct CFPreferencesSource: PreferencesSource {
    private let managedPreferencesDirectory: String
    /// The owner the managed directory and plist must have. Root in
    /// production; tests pass their own uid so a temp directory can stand in.
    private let requiredOwnerUID: uid_t

    public init(managedPreferencesDirectory: String = "/Library/Managed Preferences",
                requiredOwnerUID: uid_t = 0) {
        self.managedPreferencesDirectory = managedPreferencesDirectory
        self.requiredOwnerUID = requiredOwnerUID
    }

    /// Policy is read from the computer-level managed plist only.
    public func value(forKey key: String, domain: String) -> Any? {
        managedValue(forKey: key, domain: domain)
    }

    /// The computer-level managed plist, and nothing else — no cfprefsd
    /// forced layer (which carries user-scoped profiles), no unforced layers.
    public func managedValue(forKey key: String, domain: String) -> Any? {
        managedDomainDictionary(domain)?[key]
    }

    /// The keys of the computer-level managed plist. The current-user and
    /// any-user CFPreferences scopes are never enumerated.
    public func keys(inDomain domain: String) -> [String] {
        managedDomainDictionary(domain).map { Array($0.keys) } ?? []
    }

    /// Sibling managed domains discovered by listing the managed-preferences
    /// directory. Each computer-level profile lands as `<domain>.plist`, so a
    /// directory scan is the only way a root daemon can find domains it was not
    /// told about ahead of time. Matches the base domain and any
    /// `<base>.<suffix>` domain, never an unrelated `<base>x` domain. An
    /// unreadable or untrusted directory yields none (the reader still reads
    /// the base, which is then refused by the same check).
    public func domains(matchingPrefix prefix: String) -> [String] {
        guard directoryIsTrusted(),
              let entries = try? FileManager.default.contentsOfDirectory(atPath: managedPreferencesDirectory) else {
            return []
        }
        let suffix = ".plist"
        var matches = Set<String>()
        for entry in entries where entry.hasSuffix(suffix) {
            let domain = String(entry.dropLast(suffix.count))
            if domain == prefix || domain.hasPrefix(prefix + ".") {
                matches.insert(domain)
            }
        }
        return Array(matches)
    }

    /// Whether an ownership/mode pair is one the managed layer may carry:
    /// owned by ``requiredOwnerUID`` and writable by nobody else.
    static func isTrusted(ownerUID: uid_t, mode: mode_t, requiredOwnerUID: uid_t) -> Bool {
        ownerUID == requiredOwnerUID && (mode & mode_t(S_IWGRP | S_IWOTH)) == 0
    }

    /// The managed-preferences directory is a real directory (not a symlink)
    /// owned by ``requiredOwnerUID`` and not group/other-writable, so nobody
    /// else can drop or swap a `<domain>.plist` into it.
    private func directoryIsTrusted() -> Bool {
        var info = stat()
        guard lstat(managedPreferencesDirectory, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR else { return false }
        return Self.isTrusted(ownerUID: info.st_uid, mode: info.st_mode, requiredOwnerUID: requiredOwnerUID)
    }

    /// The computer-level managed plist for `domain`, or nil when absent,
    /// untrusted, or unparseable (a malformed managed file reads as absent —
    /// each key's fail-safe default applies — and never crashes the reader).
    ///
    /// Trust is decided on the OPEN descriptor (`O_NOFOLLOW`, then `fstat`), so
    /// the file checked is the file read: it must be a regular file owned by
    /// ``requiredOwnerUID`` and not group/other-writable.
    private func managedDomainDictionary(_ domain: String) -> [String: Any]? {
        guard !domain.contains("/"), directoryIsTrusted() else { return nil }
        let path = "\(managedPreferencesDirectory)/\(domain).plist"
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              Self.isTrusted(ownerUID: info.st_uid, mode: info.st_mode, requiredOwnerUID: requiredOwnerUID),
              let data = try? handle.readToEnd() else {
            return nil
        }
        let parsed = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return parsed as? [String: Any]
    }
}

/// Dictionary-backed source for tests and the Decision Simulator.
public struct DictionaryPreferencesSource: PreferencesSource {
    private let domains: [String: [String: any Sendable]]

    public init(domains: [String: [String: any Sendable]]) {
        self.domains = domains
    }

    public func value(forKey key: String, domain: String) -> Any? {
        domains[domain]?[key]
    }

    public func keys(inDomain domain: String) -> [String] {
        domains[domain].map { Array($0.keys) } ?? []
    }

    public func domains(matchingPrefix prefix: String) -> [String] {
        domains.keys.filter { $0 == prefix || $0.hasPrefix(prefix + ".") }
    }
}

// MARK: - Config models

/// Daemon enforcement posture.
public enum EnforcementMode: String, Codable, Sendable, CaseIterable {
    /// Full policy enforcement. The only mode with security guarantees. Default.
    case enforce
    /// Rules evaluated and logged (`would-grant`/`would-deny`) but all
    /// requests pass through to native macOS behavior.
    case audit
    /// No rule evaluation; observation and logging only.
    case monitor
}

/// PAM bypass population — checked before any daemon communication.
public struct PAMBypass: Sendable, Equatable {
    /// Group names whose members fall through to `pam_opendirectory.so`.
    public let groups: [String]
    /// Usernames that fall through to `pam_opendirectory.so`.
    public let users: [String]

    public init(groups: [String] = [], users: [String] = []) {
        self.groups = groups
        self.users = users
    }
}

/// Parsed `com.herojoneslabs.serberus.config` domain.
public struct SerberusConfig: Sendable, Equatable {
    /// Curated-sudo enrollment for standard (non-admin) users.
    ///
    /// Names the identities Serberus writes into the coarse
    /// ``BundleConfig/sudoersDropInPath`` allowlist so that sudo itself lets a
    /// standard user reach the curated command paths at all. This is only the
    /// coarse gate: `pam_serberus` + the daemon stay the authoritative fine
    /// policy and can still deny. It is fail-safe — an absent or malformed
    /// value yields empty enrollment (no drop-in identities), never a broad one.
    public struct SudoEnrollment: Sendable, Equatable {
        /// Group whose members the sudoers drop-in enrolls (rendered as a
        /// single `%group` stanza), or nil when enrollment is user-only.
        public let group: String?
        /// Usernames the sudoers drop-in enrolls individually.
        public let users: [String]
        /// IdP (e.g. Entra) group names or GUIDs to match against the console
        /// user's self-asserted membership hint (IdP-group enrollment). Empty by default —
        /// with no configured groups the resolver never enrolls anyone from an
        /// IdP hint, regardless of ``idpSource``.
        public let idpGroups: [String]
        /// Where the console user's IdP-group membership hint is read from.
        /// ``IDPGroupSource/disabled`` by default so the feature is opt-in/off.
        public let idpSource: IDPGroupSource
        /// Home-relative subpath to the IdP state cache, joined onto the
        /// verified console user's `getpwuid` home directory (never a computed
        /// `/Users/<name>` path). A leading `/` or `..` is rejected by the
        /// daemon source. Defaults to the Jamf Connect state plist location.
        public let idpStatePath: String
        /// The array key inside the IdP state file holding the group hints.
        /// Defaults to Jamf Connect's `UserGroups`.
        public let idpGroupsKey: String
        /// When true (the default), the daemon source requires the state file to
        /// be root-owned and not owner-writable, so a user can't write their own
        /// group claim into it. The Jamf Connect state file is written by the
        /// user, so enrolling from it needs either an MDM-dropped root-owned
        /// copy, or an admin who accepts the risk and sets this to false.
        public let requireRootOwnedState: Bool

        public init(
            group: String? = nil,
            users: [String] = [],
            idpGroups: [String] = [],
            idpSource: IDPGroupSource = .disabled,
            idpStatePath: String = "Library/Preferences/com.jamf.connect.state.plist",
            idpGroupsKey: String = "UserGroups",
            requireRootOwnedState: Bool = true
        ) {
            self.group = group
            self.users = users
            self.idpGroups = idpGroups
            self.idpSource = idpSource
            self.idpStatePath = idpStatePath
            self.idpGroupsKey = idpGroupsKey
            self.requireRootOwnedState = requireRootOwnedState
        }
    }

    public let jamfProURL: URL?
    public let jamfAPIClientID: String?
    public let jamfAPIClientSecret: String?
    public let daemonEnabled: Bool
    public let enforcementMode: EnforcementMode
    /// Global sudo cache TTL. Daemon ``GrantStore`` is the sole cache mechanism.
    public let sudoCacheSeconds: Int
    /// Prompt timeout — deny on expiry, never auto-allow.
    public let promptTimeoutSeconds: Int
    /// Master switch for time-bound elevation grants. When `true` (the default),
    /// grants are time-bound by their resolved duration (a rule's
    /// `maxGrantDurationSeconds`, else the global `defaultGrantDurationMinutes`)
    /// and expire, requiring re-approval. When `false`, ALL durations are
    /// ignored and grants are issued with no expiry: an approved elevation is
    /// granted indefinitely, lasting only as long as the rule remains installed
    /// on the Mac — an explicit opt-in. This never adds the user to the admins
    /// group or grants standing privilege.
    public let timeBoundGrantsEnabled: Bool
    /// Org-wide default timed-grant duration, in whole minutes. When a matched
    /// allow rule does not set its own `maxGrantDurationSeconds`, this bounds how
    /// long the approved elevation stays valid before requiring re-approval. `0`
    /// (the default) means no global default: a rule issues a timed grant only
    /// when it specifies its own duration. Fixed-minute durations only — there is
    /// no login-session-bound option. This never grants standing privilege or
    /// adds the user to the admins group; it only bounds a logged decision.
    public let defaultGrantDurationMinutes: Int
    public let pamBypass: PAMBypass
    /// Standard-user curated-sudo enrollment written into the coarse
    /// sudoers drop-in. Empty by default.
    public let sudoEnrollment: SudoEnrollment
    /// Admin-console gate (read by Serberus Commander on the admin's Mac,
    /// ignored by the daemon): whether Commander may publish RULE profiles
    /// straight to the MDM API ("Publish to Jamf"). Off by default — API-
    /// published custom-settings profiles render BLANK in the Jamf console,
    /// so the default delivery paths are the console-editable Jamf schema /
    /// `.plist` uploads; an org that wants one-click publish turns this on in
    /// the config profile scoped to its admins' Macs. Read MANAGED-only (a
    /// user's `defaults write` never counts).
    public let commanderPublishEnabled: Bool
    /// Whether an identity-scoped authURI rule's app branch authenticates the
    /// **session owner only**, instead of session-owner-or-admin.
    ///
    /// Named for what it buys: macOS offers Touch ID only when the CURRENT
    /// user alone can satisfy the rule. A rule that also admits `group=admin`
    /// makes SecurityAgent present the name-and-password form instead, because
    /// biometrics cannot stand in for a different person. Turning this on
    /// drops the admin clause from the app branch so the console user gets a
    /// Touch ID prompt; the cost is that a passing admin can no longer approve
    /// on a standard user's behalf.
    ///
    /// **The risk this trades away**, surfaced at authoring time in Commander
    /// and in the Jamf schema: turning it on removes the admin fallback for
    /// pinned apps. Only the person logged in can approve — a nearby admin can
    /// no longer authenticate on a standard user's behalf, anyone enrolled in
    /// Touch ID on that Mac can approve with a fingerprint alone, and a shared
    /// or kiosk Mac whose console account is not the intended approver loses
    /// that path entirely.
    ///
    /// Defaults to `false` — session-owner-OR-admin, the broader principal set
    /// and the behaviour that shipped first. It affects ONLY the per-app
    /// branch of a composed right; the preserved native branch (and every
    /// other Serberus layer) is untouched, so a caller matching no pinned app
    /// still gets the right's native rule either way.
    public let enableBiometrics: Bool

    public init(
        jamfProURL: URL?,
        jamfAPIClientID: String?,
        jamfAPIClientSecret: String?,
        daemonEnabled: Bool,
        enforcementMode: EnforcementMode,
        sudoCacheSeconds: Int,
        promptTimeoutSeconds: Int,
        pamBypass: PAMBypass,
        sudoEnrollment: SudoEnrollment = SudoEnrollment(),
        commanderPublishEnabled: Bool = false,
        timeBoundGrantsEnabled: Bool = true,
        defaultGrantDurationMinutes: Int = 0,
        enableBiometrics: Bool = false
    ) {
        self.jamfProURL = jamfProURL
        self.jamfAPIClientID = jamfAPIClientID
        self.jamfAPIClientSecret = jamfAPIClientSecret
        self.daemonEnabled = daemonEnabled
        self.enforcementMode = enforcementMode
        self.sudoCacheSeconds = sudoCacheSeconds
        self.promptTimeoutSeconds = promptTimeoutSeconds
        self.pamBypass = pamBypass
        self.sudoEnrollment = sudoEnrollment
        self.commanderPublishEnabled = commanderPublishEnabled
        self.timeBoundGrantsEnabled = timeBoundGrantsEnabled
        self.defaultGrantDurationMinutes = defaultGrantDurationMinutes
        self.enableBiometrics = enableBiometrics
    }

    /// The global default timed-grant duration in seconds (minutes × 60),
    /// clamped to `0...maxGrantSeconds`. This is what the rule engine consumes as
    /// `globalGrantDurationSeconds`. `0` means no global default. Note the engine
    /// ignores this entirely when ``timeBoundGrantsEnabled`` is `false`.
    public var defaultGrantDurationSeconds: Int {
        min(max(defaultGrantDurationMinutes, 0) * 60, RuleSchemaConstants.maxGrantSeconds)
    }

    /// Whether this configuration can be enforced without risking a lockout.
    ///
    /// `monitor` and `audit` are inherently safe (nothing is denied). `enforce`
    /// is safe ONLY with a non-empty ``PAMBypass`` — the break-glass population
    /// that `pam_serberus` passes straight through to `pam_opendirectory` before
    /// it ever contacts the daemon. An enforcing config with an empty bypass has
    /// no escape hatch: if the daemon (or its policy) is wrong, every `sudo` on
    /// the Mac is denied and there is no way back in.
    ///
    /// This is the same safety condition the Core pkg's preinstall checks, and
    /// it is the invariant of the last-known-good snapshot: only a config that
    /// satisfies it is ever persisted, so falling back to the LKG can never
    /// brick a Mac.
    public var isEnforceable: Bool {
        enforcementMode != .enforce || !(pamBypass.groups.isEmpty && pamBypass.users.isEmpty)
    }

    /// A copy with the enforcement mode replaced. Used to force `monitor` when
    /// the daemon has no usable configuration at all
    /// (``DaemonState/awaitingConfig``) — every other field is preserved.
    public func withEnforcementMode(_ mode: EnforcementMode) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: jamfProURL,
            jamfAPIClientID: jamfAPIClientID,
            jamfAPIClientSecret: jamfAPIClientSecret,
            daemonEnabled: daemonEnabled,
            enforcementMode: mode,
            sudoCacheSeconds: sudoCacheSeconds,
            promptTimeoutSeconds: promptTimeoutSeconds,
            pamBypass: pamBypass,
            sudoEnrollment: sudoEnrollment,
            commanderPublishEnabled: commanderPublishEnabled,
            timeBoundGrantsEnabled: timeBoundGrantsEnabled,
            defaultGrantDurationMinutes: defaultGrantDurationMinutes,
            enableBiometrics: enableBiometrics
        )
    }
}

/// Parsed `com.herojoneslabs.serberus.prompts` domain.
///
/// Only keys something reads are parsed. The prompt timeout lives in the config
/// domain (``SerberusConfig/promptTimeoutSeconds``) and justification is a
/// per-rule condition, so the prompts-domain `promptTimeoutSeconds`,
/// `promptShowCountdown`, `requireJustification` and `showProcessDetails`
/// keys are ignored if present.
public struct PromptsConfig: Sendable, Equatable {
    public let justificationMinLength: Int
    public let allowButtonLabel: String
    public let denyButtonLabel: String
    /// Org name shown in the audit prompt's brand header (e.g. "Example
    /// Corp"). `nil`/absent = the Sentinel's default product name.
    public let brandTitle: String?
    /// One-line subtitle under the brand title (e.g. "IT Security").
    public let brandSubtitle: String?
    /// How many "most-used rules" the menubar popover lists. `0` hides the
    /// section; the full list always lives in the Serberus window's My Rules
    /// tab. Default 3.
    public let menuBarTopRulesCount: Int
    /// Who the approval toast says the audited decision was sent to — the team
    /// name an org uses for itself (e.g. "Security", "Help Desk").
    /// The toast reads "event <id> · sent to <label>". Absent or blank in the
    /// profile falls back to the "IT" default; the toast drops the "sent to …"
    /// clause (reading just "logged") only for a genuinely empty label.
    public let auditRecipientLabel: String

    public init(
        justificationMinLength: Int = 0,
        allowButtonLabel: String = "Yes, continue",
        denyButtonLabel: String = "No, cancel",
        brandTitle: String? = nil,
        brandSubtitle: String? = nil,
        menuBarTopRulesCount: Int = 3,
        auditRecipientLabel: String = "IT"
    ) {
        self.justificationMinLength = justificationMinLength
        self.allowButtonLabel = allowButtonLabel
        self.denyButtonLabel = denyButtonLabel
        self.brandTitle = brandTitle
        self.brandSubtitle = brandSubtitle
        self.menuBarTopRulesCount = menuBarTopRulesCount
        self.auditRecipientLabel = auditRecipientLabel
    }
}

/// Parsed `com.herojoneslabs.serberus.notify` domain.
///
/// Only `logRetentionDays` is consumed (the daemon's decision-log pruning).
/// `logVerbosity`, `webhookURL`, `jamfProtectEvents` and
/// `stalenessThresholdMinutes` were never wired to anything and are ignored if
/// present.
public struct NotifyConfig: Sendable, Equatable {
    public let logRetentionDays: Int

    public init(logRetentionDays: Int = 90) {
        self.logRetentionDays = logRetentionDays
    }
}

// MARK: - Reader

/// Reads and validates all four Serberus managed preference domains.
///
/// Invalid configuration never crashes Serberus: parsing collects
/// ``ConfigError`` findings and falls back to safe defaults per key; the
/// daemon decides whether the finding set warrants degraded state while
/// retaining the last known valid policy.
public struct ManagedPreferencesReader: Sendable {
    private let source: PreferencesSource

    public init(source: PreferencesSource = CFPreferencesSource()) {
        self.source = source
    }

    /// Result of reading a domain: the parsed value plus every validation
    /// finding encountered along the way.
    public struct ReadResult<Value: Sendable>: Sendable {
        public let value: Value
        public let findings: [ConfigError]
    }

    // MARK: config domain

    /// Whether the config domain has been delivered AT ALL (at least one key).
    ///
    /// ``readConfig()`` cannot answer this: it is fail-safe by design, so an
    /// *absent* domain and a *delivered* domain both yield a `SerberusConfig`
    /// (the former filled entirely with defaults — `enforce` + no bypass, which
    /// is exactly the bricking shape). The daemon must distinguish "the admin
    /// asked for enforce" from "nothing has been delivered yet", so presence is
    /// probed separately, against the raw key list.
    public func configIsPresent() -> Bool {
        !source.keys(inDomain: BundleConfig.configDomain).isEmpty
    }

    /// Reads `com.herojoneslabs.serberus.config`. Unknown/invalid values fall back
    /// to fail-safe defaults (`enforce`, cache 0, timeout 60, no bypass,
    /// time-bound grants on).
    ///
    /// Note the returned config is meaningful only alongside ``configIsPresent()``
    /// — see that method.
    public func readConfig() -> ReadResult<SerberusConfig> {
        let domain = BundleConfig.configDomain
        var findings: [ConfigError] = []

        let urlString = string("jamfProURL", domain, &findings)
        var jamfURL: URL?
        if let urlString {
            if let url = URL(string: urlString), url.scheme == "https" {
                jamfURL = url
            } else {
                findings.append(.invalidValue(domain: domain, key: "jamfProURL",
                                              reason: "must be an https URL"))
            }
        }

        let modeString = string("enforcementMode", domain, &findings)
        var mode = EnforcementMode.enforce
        if let modeString {
            if let parsed = EnforcementMode(rawValue: modeString) {
                mode = parsed
            } else {
                findings.append(.invalidValue(domain: domain, key: "enforcementMode",
                                              reason: "unknown mode '\(modeString)'; defaulting to enforce"))
            }
        }

        var bypassGroups: [String] = []
        var bypassUsers: [String] = []
        if let raw = source.value(forKey: "pamBypass", domain: domain) {
            if let dict = raw as? [String: Any] {
                // Per-element filtering, matching pam_config.c's semantics
                // exactly: one mistyped element must not drop the whole array
                // (and with it every break-glass identity) — keep the valid
                // strings and report each dropped element.
                bypassGroups = stringElements(dict["groups"], domain: domain,
                                              key: "pamBypass.groups", &findings)
                bypassUsers = stringElements(dict["users"], domain: domain,
                                             key: "pamBypass.users", &findings)
            } else {
                findings.append(.invalidValue(domain: domain, key: "pamBypass",
                                              reason: "expected a dictionary with 'groups' and 'users' arrays"))
            }
        }

        // sudoEnrollment mirrors pamBypass's dict-of-arrays shape and its
        // per-element leniency: one mistyped element must not drop the whole
        // enrollment. `group` is a single optional string, `users` an array
        // parsed through the same `stringElements` helper. An absent or
        // non-dictionary value yields empty enrollment (fail-safe — the
        // coarse sudoers drop-in opens for nobody, never for everyone).
        var enrollGroup: String?
        var enrollUsers: [String] = []
        // IdP-enrollment sub-config. Absent/malformed keys stay inert
        // (source .disabled, no groups) — the coarse sudoers drop-in opens for
        // nobody from an IdP hint, never for everyone.
        var enrollIDPGroups: [String] = []
        var enrollIDPSource: IDPGroupSource = .disabled
        var enrollIDPStatePath = "Library/Preferences/com.jamf.connect.state.plist"
        var enrollIDPGroupsKey = "UserGroups"
        var enrollRequireRootOwnedState = true
        if let raw = source.value(forKey: "sudoEnrollment", domain: domain) {
            if let dict = raw as? [String: Any] {
                if let groupRaw = dict["group"] {
                    if let group = groupRaw as? String {
                        enrollGroup = group
                    } else {
                        findings.append(.invalidValue(domain: domain, key: "sudoEnrollment.group",
                                                      reason: "expected a string group name"))
                    }
                }
                enrollUsers = stringElements(dict["users"], domain: domain,
                                             key: "sudoEnrollment.users", &findings)

                // idpGroups: array of Entra group names/GUIDs, parsed through the
                // same per-element helper as users (one bad element is dropped,
                // not the whole list).
                enrollIDPGroups = stringElements(dict["idpGroups"], domain: domain,
                                                 key: "sudoEnrollment.idpGroups", &findings)

                // idpSource: fail-closed rawValue parse mirroring readJITAdmin —
                // an unknown or mistyped value degrades to .disabled (feature off).
                if let sourceRaw = dict["idpSource"] {
                    if let sourceString = sourceRaw as? String {
                        if let parsed = IDPGroupSource(rawValue: sourceString) {
                            enrollIDPSource = parsed
                        } else {
                            findings.append(.invalidValue(domain: domain, key: "sudoEnrollment.idpSource",
                                                          reason: "unknown source '\(sourceString)'; defaulting to disabled"))
                        }
                    } else {
                        findings.append(.invalidValue(domain: domain, key: "sudoEnrollment.idpSource",
                                                      reason: "expected a string source name"))
                    }
                }

                // idpStatePath / idpGroupsKey: optional string overrides; a
                // mistyped value keeps the default (never widens trust).
                if let pathRaw = dict["idpStatePath"] {
                    if let path = pathRaw as? String {
                        enrollIDPStatePath = path
                    } else {
                        findings.append(.invalidValue(domain: domain, key: "sudoEnrollment.idpStatePath",
                                                      reason: "expected a string path"))
                    }
                }
                if let keyRaw = dict["idpGroupsKey"] {
                    if let key = keyRaw as? String {
                        enrollIDPGroupsKey = key
                    } else {
                        findings.append(.invalidValue(domain: domain, key: "sudoEnrollment.idpGroupsKey",
                                                      reason: "expected a string key name"))
                    }
                }

                // requireRootOwnedState: strict flag; a mistyped value keeps the
                // strict default.
                if let strictRaw = dict["requireRootOwnedState"] {
                    // Real booleans only: an integer 0 must not switch strict
                    // mode off.
                    if let strict = Self.strictBool(strictRaw) {
                        enrollRequireRootOwnedState = strict
                    } else {
                        findings.append(.invalidValue(domain: domain, key: "sudoEnrollment.requireRootOwnedState",
                                                      reason: "expected a boolean"))
                    }
                }
            } else {
                findings.append(.invalidValue(domain: domain, key: "sudoEnrollment",
                                              reason: "expected a dictionary with 'group' and 'users'"))
            }
        }

        let config = SerberusConfig(
            jamfProURL: jamfURL,
            jamfAPIClientID: string("jamfAPIClientID", domain, &findings),
            jamfAPIClientSecret: string("jamfAPIClientSecret", domain, &findings),
            daemonEnabled: bool("daemonEnabled", domain, default: true, &findings),
            enforcementMode: mode,
            sudoCacheSeconds: int("sudoCacheSeconds", domain, default: 0,
                                  range: 0...RuleSchemaConstants.maxCacheSeconds, &findings),
            promptTimeoutSeconds: int("promptTimeoutSeconds", domain, default: 60,
                                      range: 1...3600, &findings),
            pamBypass: PAMBypass(groups: bypassGroups, users: bypassUsers),
            sudoEnrollment: SerberusConfig.SudoEnrollment(
                group: enrollGroup,
                users: enrollUsers,
                idpGroups: enrollIDPGroups,
                idpSource: enrollIDPSource,
                idpStatePath: enrollIDPStatePath,
                idpGroupsKey: enrollIDPGroupsKey,
                requireRootOwnedState: enrollRequireRootOwnedState
            ),
            // Fail-closed: absent or mistyped ⇒ Commander hides direct publish.
            // MANAGED-only: a `defaults write` by the logged-in user must not
            // turn an admin-console gate on — only a delivered profile can.
            commanderPublishEnabled: managedBool("commanderPublishEnabled", domain, default: false, &findings),
            // Master switch for time-bound grants. Absent/mistyped ⇒ TRUE, so a
            // configured duration always expires; indefinite grants need an
            // explicit `false` in the profile.
            timeBoundGrantsEnabled: bool("timeBoundGrantsEnabled", domain, default: true, &findings),
            // Org-wide default timed-grant duration (minutes). Absent/mistyped ⇒
            // 0 (no global default), so existing policies keep their exact
            // behavior; a matched rule's own `maxGrantDurationSeconds` overrides.
            defaultGrantDurationMinutes: int("defaultGrantDurationMinutes", domain, default: 0,
                                             range: 0...RuleSchemaConstants.maxGrantDurationMinutes, &findings),
            // Touch ID toggle for identity-scoped app branches. Absent/mistyped
            // ⇒ FALSE = session-owner-OR-admin, the broader principal set.
            enableBiometrics: managedBool("enableBiometrics", domain, default: false, &findings)
        )
        return ReadResult(value: config, findings: findings)
    }

    // MARK: prompts domain

    /// Reads `com.herojoneslabs.serberus.prompts` with spec defaults.
    public func readPrompts() -> ReadResult<PromptsConfig> {
        let domain = BundleConfig.promptsDomain
        var findings: [ConfigError] = []
        // Empty/whitespace branding strings (Jamf emits "" for untouched text
        // fields) are treated as absent.
        func brandString(_ key: String) -> String? {
            guard let raw = string(key, domain, &findings) else { return nil }
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        let value = PromptsConfig(
            justificationMinLength: int("justificationMinLength", domain, default: 0, range: 0...10_000, &findings),
            allowButtonLabel: string("allowButtonLabel", domain, &findings) ?? "Yes, continue",
            denyButtonLabel: string("denyButtonLabel", domain, &findings) ?? "No, cancel",
            brandTitle: brandString("brandTitle"),
            brandSubtitle: brandString("brandSubtitle"),
            menuBarTopRulesCount: int("menuBarTopRulesCount", domain, default: 3, range: 0...50, &findings),
            // Absent or blank (Jamf emits "" for untouched text) ⇒ the "IT"
            // default; any non-blank value becomes the toast's recipient label.
            auditRecipientLabel: brandString("auditRecipientLabel") ?? "IT"
        )
        return ReadResult(value: value, findings: findings)
    }

    // MARK: notify domain

    /// Reads `com.herojoneslabs.serberus.notify` with spec defaults.
    public func readNotify() -> ReadResult<NotifyConfig> {
        let domain = BundleConfig.notifyDomain
        var findings: [ConfigError] = []
        let value = NotifyConfig(
            logRetentionDays: int("logRetentionDays", domain, default: 90, range: 1...3650, &findings)
        )
        return ReadResult(value: value, findings: findings)
    }

    // MARK: debug domain

    /// Whether the opt-in debug telemetry profile (`com.herojoneslabs.serberus.debug`)
    /// is present with `debugModeEnabled == true`. Managed-only: a local
    /// `defaults write` can never enable it — it must be an MDM-delivered profile.
    /// Absent / off ⇒ `false`, so the daemon withholds the per-decision event
    /// list from the EA path.
    public func readDebugMode() -> Bool {
        var findings: [ConfigError] = []
        return managedBool("debugModeEnabled", BundleConfig.debugDomain, default: false, &findings)
    }

    // MARK: app-management domain

    /// Reads the app-management policy (`com.herojoneslabs.serberus.appmanagement`).
    /// Managed-only + fail-closed: absent / non-boolean `enabled` ⇒ disabled, so
    /// self-service install/uninstall is off unless an MDM profile turns it on.
    /// Notarization + prompt + allowUninstall default on; each can only be turned
    /// off by an explicit managed `false`.
    public func readAppManagementPolicy() -> InstallPolicy {
        var findings: [ConfigError] = []
        let domain = BundleConfig.appManagementDomain
        return InstallPolicy(
            enabled: managedBool("enabled", domain, default: false, &findings),
            requireNotarization: managedBool("requireNotarization", domain, default: true, &findings),
            promptBeforeAction: managedBool("promptBeforeAction", domain, default: true, &findings),
            allowUninstall: managedBool("allowUninstall", domain, default: true, &findings),
            // Managed-only array read (never the unforced `defaults write` layers)
            // — the admin's uninstall hard-deny list. Absent/malformed ⇒ empty.
            protectedBundleIdentifiers: managedStringArray("protectedBundleIdentifiers", domain, &findings),
            publisherScope: managedPublisherScope(domain, &findings),
            allowedPublisherTeamIDs: managedStringArray("allowedPublisherTeamIDs", domain, &findings)
        )
    }

    /// `publisherScope`: "allowlist" (the default) or "any". Anything else is a
    /// finding and falls back to the allowlist, never the open setting.
    private func managedPublisherScope(_ domain: String, _ findings: inout [ConfigError]) -> InstallPublisherScope {
        guard let raw = source.managedValue(forKey: "publisherScope", domain: domain) else { return .allowlist }
        guard let text = raw as? String, let scope = InstallPublisherScope(rawValue: text) else {
            findings.append(.invalidValue(domain: domain, key: "publisherScope",
                                          reason: "expected \"allowlist\" or \"any\""))
            return .allowlist
        }
        return scope
    }

    // MARK: jit domain

    /// Reads `com.herojoneslabs.serberus.jit` with fail-closed defaults. An absent or
    /// malformed profile yields ``JITAdminPolicy/disabledDefault`` (no
    /// elevation path), never an open one.
    public func readJITAdmin() -> ReadResult<JITAdminPolicy> {
        let domain = BundleConfig.jitDomain
        var findings: [ConfigError] = []

        var provider = JITAdminProvider.disabled
        if let raw = string("provider", domain, &findings) {
            if let parsed = JITAdminProvider(rawValue: raw) {
                provider = parsed
            } else {
                findings.append(.invalidValue(domain: domain, key: "provider",
                                              reason: "unknown provider '\(raw)'; defaulting to disabled"))
            }
        }

        var eligibleGroups: [String] = []
        if let raw = source.value(forKey: "eligibleGroups", domain: domain) {
            if let list = raw as? [String] {
                eligibleGroups = list
            } else {
                findings.append(.invalidValue(domain: domain, key: "eligibleGroups",
                                              reason: "expected an array of group names"))
            }
        }

        var command = JamfConnectCommand()
        if let raw = source.value(forKey: "jamfConnectCommand", domain: domain) {
            if let dict = raw as? [String: Any] {
                command = JamfConnectCommand(
                    path: (dict["path"] as? String) ?? "",
                    arguments: (dict["arguments"] as? [String]) ?? []
                )
            } else {
                findings.append(.invalidValue(domain: domain, key: "jamfConnectCommand",
                                              reason: "expected a dictionary with 'path' and 'arguments'"))
            }
        }

        // The command must be an absolute path: a bare name would be resolved
        // through the user's PATH, which the user controls. A relative path is
        // refused (with a finding) and the default takes its place.
        if command.isConfigured && !command.hasAbsolutePath {
            findings.append(.invalidValue(
                domain: domain, key: "jamfConnectCommand.path",
                reason: "'\(command.path)' is not an absolute path; using the default "
                    + "\(JamfConnectCommand.jamfConnectDefault.path)"))
            command = .jamfConnectDefault
        }

        // A jamf_connect provider with no explicit command falls back to the
        // standard Jamf Connect trigger, so "mark JC for JIT" works with no
        // further setup.
        if provider == .jamfConnect && !command.isConfigured {
            command = .jamfConnectDefault
        }

        let policy = JITAdminPolicy(
            provider: provider,
            eligibleGroups: eligibleGroups,
            maxDurationSeconds: int("maxDurationSeconds", domain,
                                    default: JITAdminPolicy.defaultDurationSeconds,
                                    range: 1...JITAdminPolicy.maxAllowedDurationSeconds, &findings),
            requireJustification: bool("requireJustification", domain, default: true, &findings),
            justificationMinLength: int("justificationMinLength", domain, default: 10, range: 0...10_000, &findings),
            jamfConnectCommand: command
        )
        return ReadResult(value: policy, findings: findings)
    }

    // MARK: rules domain

    /// Reads every `rules_*` key from `com.herojoneslabs.serberus.rules`, decoding
    /// each into a ``RuleProfile``.
    ///
    /// Keys are sorted before decoding so the result never depends on
    /// enumeration order. Undecodable or schema-unrecognized profiles are
    /// reported as findings and excluded — the daemon retains its last
    /// valid rule set on `rule_parse_error`.
    public func readRuleProfiles() -> ReadResult<[RuleProfile]> {
        let base = BundleConfig.rulesDomain
        var findings: [ConfigError] = []
        var profiles: [RuleProfile] = []

        // The base domain plus every sibling sub-domain
        // (`com.herojoneslabs.serberus.rules.<suffix>`). Reading each domain
        // independently is what lets a native `rules` ARRAY delivered as a
        // SEPARATE config profile compose instead of colliding on the single
        // `rules` key: sudo rules can live in `…rules.sudo`, authuri in
        // `…rules.authuri`, each its own profile. The base is always included
        // even when the source cannot enumerate domains (test mocks, or a
        // base-only deployment). Sorted for deterministic ordering; the base
        // ("…rules") sorts before any "…rules.<suffix>".
        var domainSet = Set(source.domains(matchingPrefix: base))
        domainSet.insert(base)
        for domain in domainSet.sorted() {
            readRules(inDomain: domain, base: base, into: &profiles, findings: &findings)
        }

        return ReadResult(value: profiles, findings: findings)
    }

    /// A profile identity that stays globally unique across domains. The base
    /// domain keeps the raw key (backward compatible — existing single-domain
    /// deployments are byte-identical); a sub-domain qualifies the key with its
    /// suffix so two domains carrying the same delivery key (or each carrying
    /// the singleton native `rules` array → ``RuleSchemaConstants/nativeProfileKey``)
    /// never merge into one another.
    private func qualifiedProfileKey(_ rawKey: String, domain: String, base: String) -> String {
        guard domain != base else { return rawKey }
        let suffix = String(domain.dropFirst(base.count + 1))
        return "\(suffix)/\(rawKey)"
    }

    /// Reads every `rules_*` JSON-string key and the single native `rules`
    /// array from one domain, appending each as a ``RuleProfile``. Findings are
    /// tagged with the actual domain so an admin can see which profile a
    /// problem came from.
    private func readRules(inDomain domain: String, base: String,
                           into profiles: inout [RuleProfile], findings: inout [ConfigError]) {
        let ruleKeys = source.keys(inDomain: domain)
            .filter { $0.hasPrefix(RuleSchemaConstants.profileKeyPrefix) }
            .sorted()

        for key in ruleKeys {
            guard let raw = source.value(forKey: key, domain: domain) as? String else {
                findings.append(.invalidValue(domain: domain, key: key,
                                              reason: "expected a JSON string value"))
                continue
            }
            do {
                var profile = try RuleProfile.decode(jsonString: raw, expectedKey: key)
                guard RuleSchemaConstants.recognizedSchemaVersions.contains(profile.schemaVersion) else {
                    findings.append(.invalidValue(domain: domain, key: key,
                                                  reason: "unrecognized schemaVersion '\(profile.schemaVersion)'"))
                    continue
                }
                if profile.profileKey != key {
                    // The delivery key is authoritative for merge identity.
                    findings.append(.invalidValue(domain: domain, key: key,
                                                  reason: "embedded profileKey '\(profile.profileKey)' does not match delivery key; using delivery key"))
                }
                // Qualify AFTER the embedded-key check so the check still
                // compares against the raw delivery key the admin authored.
                profile.profileKey = qualifiedProfileKey(key, domain: domain, base: base)
                // Runtime gate (the native path applies it in
                // Rule.fromManagedDictionary): drop each rule that would be
                // enforced as something other than what it says, with a
                // finding — the rest of the profile still applies.
                profile.rules = profile.rules.filter { rule in
                    guard let reason = rule.runtimeRejectionReason else { return true }
                    findings.append(.invalidValue(domain: domain, key: key,
                                                  reason: "rule '\(rule.id)' dropped: \(reason)"))
                    return false
                }
                profiles.append(profile)
            } catch {
                findings.append(.invalidValue(domain: domain, key: key,
                                              reason: error.localizedDescription))
            }
        }

        // Native rules authored directly in Jamf's "Application & Custom
        // Settings" via the Serberus Custom Schema — a `rules` ARRAY of flat
        // dicts — read alongside the JSON-string `rules_*` keys so every
        // authoring path (Serberus publish, plist upload, Jamf schema) composes.
        appendNativeRuleProfile(domain: domain, base: base, into: &profiles, findings: &findings)
    }

    /// Reads ``RuleSchemaConstants/nativeRulesKey`` (a native array of flat rule
    /// dicts) and, if it holds any valid rules, appends ONE synthetic
    /// ``RuleProfile`` carrying them. Its profileKey is
    /// ``RuleSchemaConstants/nativeProfileKey`` in the base domain and that key
    /// qualified by the sub-domain suffix elsewhere, so a native array in every
    /// sub-domain composes without colliding. Invalid or duplicate-id rules are
    /// dropped with a finding; the profile is omitted entirely when no rule
    /// survives, so a fully-malformed schema entry never disturbs the others.
    private func appendNativeRuleProfile(domain: String, base: String, into profiles: inout [RuleProfile],
                                         findings: inout [ConfigError]) {
        let key = RuleSchemaConstants.nativeRulesKey
        guard let raw = source.value(forKey: key, domain: domain) else { return }
        guard let array = raw as? [Any] else {
            findings.append(.invalidValue(domain: domain, key: key,
                                          reason: "expected an array of rule dictionaries"))
            return
        }

        var rules: [Rule] = []
        var seenIDs: Set<String> = []
        for (index, element) in array.enumerated() {
            guard let dict = element as? [String: Any] else {
                findings.append(.invalidValue(domain: domain, key: key,
                                              reason: "rule at index \(index) is not a dictionary"))
                continue
            }
            switch Rule.fromManagedDictionary(dict) {
            case .rule(let rule):
                guard seenIDs.insert(rule.id).inserted else {
                    findings.append(.invalidValue(domain: domain, key: key,
                                                  reason: "duplicate rule id '\(rule.id)' — keeping the first"))
                    continue
                }
                rules.append(rule)
            case .invalid(let reason):
                findings.append(.invalidValue(domain: domain, key: key, reason: reason))
            }
        }
        guard !rules.isEmpty else { return }

        let policyVersion = (source.value(forKey: RuleSchemaConstants.nativePolicyVersionKey, domain: domain) as? String)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .flatMap { $0.isEmpty ? nil : $0 } ?? "1.0.0"

        var profilePriority = 50
        if let rawPriority = source.value(forKey: RuleSchemaConstants.nativeProfilePriorityKey, domain: domain),
           CFGetTypeID(rawPriority as CFTypeRef) != CFBooleanGetTypeID() {
            if let i = rawPriority as? Int { profilePriority = i }
            else if let n = rawPriority as? NSNumber { profilePriority = n.intValue }
        }

        profiles.append(RuleProfile(
            schemaVersion: RuleSchemaConstants.currentSchemaVersion,
            policyVersion: policyVersion,
            profileKey: qualifiedProfileKey(RuleSchemaConstants.nativeProfileKey, domain: domain, base: base),
            profilePriority: profilePriority,
            rules: rules
        ))
    }

    // MARK: typed accessors

    /// Per-element string extraction for list values (pamBypass users/groups).
    ///
    /// Mirrors `pam_serberus`'s `serberus_config_copy_bypass_array`: string
    /// elements are kept, each non-string element is dropped with a finding,
    /// and an absent value yields an empty list. A value that is not an array
    /// at all also yields an empty list, with a finding. The daemon and the
    /// PAM module must agree on which identities can bypass — one bad element
    /// must never disable break-glass on only one side.
    private func stringElements(_ raw: Any?, domain: String, key: String,
                                _ findings: inout [ConfigError]) -> [String] {
        guard let raw else { return [] }
        guard let array = raw as? [Any] else {
            findings.append(.invalidValue(domain: domain, key: key,
                                          reason: "expected an array of strings"))
            return []
        }
        var values: [String] = []
        values.reserveCapacity(array.count)
        for (index, element) in array.enumerated() {
            if let value = element as? String {
                values.append(value)
            } else {
                findings.append(.invalidValue(domain: domain, key: key,
                                              reason: "dropped non-string element at index \(index)"))
            }
        }
        return values
    }

    private func string(_ key: String, _ domain: String, _ findings: inout [ConfigError]) -> String? {
        guard let raw = source.value(forKey: key, domain: domain) else { return nil }
        guard let value = raw as? String else {
            findings.append(.invalidValue(domain: domain, key: key, reason: "expected a string"))
            return nil
        }
        return value
    }

    /// A REAL boolean (`<true/>` / `<false/>`, i.e. a CFBoolean), or nil.
    ///
    /// `raw as? Bool` is not enough: Swift bridges any NSNumber to Bool, so
    /// `<integer>0</integer>` would read as `false`. `pam_config.c` accepts
    /// only CFBoolean and treats an integer as absent, so the two sides would
    /// disagree — e.g. `daemonEnabled = 0` was a kill switch to the daemon
    /// but "enabled" to the PAM module. Anything that is not a CFBoolean is
    /// therefore invalid here too, and the key's fail-safe default applies.
    static func strictBool(_ raw: Any) -> Bool? {
        guard CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID() else { return nil }
        return (raw as? Bool)
    }

    private func bool(_ key: String, _ domain: String, default defaultValue: Bool,
                      _ findings: inout [ConfigError]) -> Bool {
        guard let raw = source.value(forKey: key, domain: domain) else { return defaultValue }
        guard let value = Self.strictBool(raw) else {
            findings.append(.invalidValue(domain: domain, key: key, reason: "expected a boolean"))
            return defaultValue
        }
        return value
    }

    /// Like ``bool`` but reads through ``PreferencesSource/managedValue`` —
    /// only a management-delivered value counts; everything else is the default.
    private func managedBool(_ key: String, _ domain: String, default defaultValue: Bool,
                             _ findings: inout [ConfigError]) -> Bool {
        guard let raw = source.managedValue(forKey: key, domain: domain) else { return defaultValue }
        guard let value = Self.strictBool(raw) else {
            findings.append(.invalidValue(domain: domain, key: key, reason: "expected a boolean"))
            return defaultValue
        }
        return value
    }

    /// Like ``managedBool`` but for a management-delivered array of strings —
    /// only a managed value counts (never the unforced `defaults write` layers).
    /// Absent ⇒ empty; a non-array records a finding and yields empty; non-string
    /// elements are dropped.
    private func managedStringArray(_ key: String, _ domain: String,
                                    _ findings: inout [ConfigError]) -> [String] {
        guard let raw = source.managedValue(forKey: key, domain: domain) else { return [] }
        guard let array = raw as? [Any] else {
            findings.append(.invalidValue(domain: domain, key: key, reason: "expected an array of strings"))
            return []
        }
        return array.compactMap { $0 as? String }
    }

    private func int(_ key: String, _ domain: String, default defaultValue: Int,
                     range: ClosedRange<Int>, _ findings: inout [ConfigError]) -> Int {
        guard let raw = source.value(forKey: key, domain: domain) else { return defaultValue }
        guard let value = (raw as? Int) ?? (raw as? NSNumber)?.intValue else {
            findings.append(.invalidValue(domain: domain, key: key, reason: "expected an integer"))
            return defaultValue
        }
        guard range.contains(value) else {
            findings.append(.invalidValue(domain: domain, key: key,
                                          reason: "value \(value) outside \(range.lowerBound)...\(range.upperBound)"))
            return defaultValue
        }
        return value
    }
}
