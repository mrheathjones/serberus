import Foundation

// MARK: - Rule profile

/// One JSON-encoded rule profile delivered as a single `rules_*` key in the
/// `com.herojoneslabs.serberus.rules` managed preference domain.
public struct RuleProfile: Codable, Sendable, Equatable {
    /// Schema version of the profile document. Currently `"1.0"`.
    public var schemaVersion: String
    /// Semver policy version stamped by the Policy Builder on export.
    public var policyVersion: String
    /// Managed preference key this profile is delivered under.
    /// Must match `rules_authuri_<slug>` or `rules_sudo_<slug>`.
    public var profileKey: String
    /// Merge priority across profiles. Lower values evaluate first.
    public var profilePriority: Int
    /// Ordered rule list. Evaluation order is by `priority`, not array order.
    public var rules: [Rule]

    public init(
        schemaVersion: String = RuleSchemaConstants.currentSchemaVersion,
        policyVersion: String,
        profileKey: String,
        profilePriority: Int,
        rules: [Rule]
    ) {
        self.schemaVersion = schemaVersion
        self.policyVersion = policyVersion
        self.profileKey = profileKey
        self.profilePriority = profilePriority
        self.rules = rules
    }
}

/// Constants shared by schema producers and consumers.
public enum RuleSchemaConstants {
    /// The profile document schema version this build reads and writes.
    public static let currentSchemaVersion = "1.0"
    /// Profile schema versions this build can evaluate.
    public static let recognizedSchemaVersions: Set<String> = ["1.0"]
    /// Required prefix for auth URI profiles.
    public static let authURIProfilePrefix = "rules_authuri_"
    /// Required prefix for sudo profiles.
    public static let sudoProfilePrefix = "rules_sudo_"
    /// Prefix the daemon scans for in the rules domain.
    public static let profileKeyPrefix = "rules_"
    /// Inclusive upper bound for per-rule `cacheSeconds` (24 hours).
    public static let maxCacheSeconds = 86_400
    /// Inclusive upper bound for a timed grant's duration (24 hours). Bounds
    /// both a rule's `maxGrantDurationSeconds` override and the global default
    /// (`defaultGrantDurationMinutes`) after conversion to seconds.
    public static let maxGrantSeconds = 86_400
    /// The per-rule `maxGrantDurationSeconds` value meaning "evaluate every
    /// time; never issue a grant", whatever the org default. (`0` means "use
    /// the org default"; any other negative value is refused.)
    public static let neverGrantSeconds = -1
    /// Inclusive upper bound for the global `defaultGrantDurationMinutes`
    /// config key (24 hours, matching ``maxGrantSeconds``).
    public static let maxGrantDurationMinutes = 1_440

    /// Fixed key holding a NATIVE array of flat rule dictionaries authored
    /// directly in Jamf's "Application & Custom Settings" via the Serberus
    /// Custom Schema (`Support/jamf-schemas/com.herojoneslabs.serberus.rules.json`).
    /// Read ALONGSIDE the `rules_*` JSON-string keys so every authoring path
    /// (Serberus publish, plist upload, Jamf schema) composes on-device. It has
    /// no `rules_` prefix, so ``profileKeyPrefix`` never mistakes it for a
    /// JSON-string profile.
    public static let nativeRulesKey = "rules"
    /// Optional top-level keys accompanying ``nativeRulesKey`` in the schema.
    public static let nativePolicyVersionKey = "policyVersion"
    public static let nativeProfilePriorityKey = "profilePriority"
    /// Synthetic `profileKey` for the profile built from ``nativeRulesKey``.
    /// Deliberately has NO `rules_` prefix so it can never alias a JSON-string
    /// delivery key (those are only scanned by ``profileKeyPrefix``), which would
    /// otherwise produce two profiles sharing one key. It may carry BOTH
    /// mechanisms (the schema form allows either rule type).
    public static let nativeProfileKey = "jamf_custom_rules"
}

// MARK: - Rule

/// A single elevation rule inside a ``RuleProfile``.
public struct Rule: Codable, Sendable, Equatable {
    /// Unique (within its profile) stable identifier, referenced in logs and grants.
    public var id: String
    /// Whether this rule targets an AuthorizationDB right or a sudo command.
    public var type: RuleType
    /// Allow or deny. Deny wins at equal priority and is never cached.
    public var action: RuleAction
    /// Human-readable description shown in Policy Builder and prompts.
    public var description: String
    /// Evaluation order within the profile. Lower values evaluate first.
    public var priority: Int
    /// Per-rule cache TTL. `nil` = use global `sudoCacheSeconds`;
    /// `0` = never cache this rule. Ignored for deny rules.
    public var cacheSeconds: Int?
    /// What the rule matches against.
    public var match: MatchCriteria
    /// Additional requirements the requestor must satisfy.
    public var conditions: RuleConditions
    /// How an allow decision is delivered.
    public var elevation: ElevationBehavior
    /// Identity-scoped authURI rule (authuri only): pins ONE app (Team ID +
    /// bundle ID) on `match.authURI`; the branch is session-owner-or-admin. The
    /// daemon composes the right as `k-of-n: 1` over `[native-default, app…]`
    /// instead of rewriting it, so no other caller's posture changes. One
    /// rule = one (right, app) pair; absent on every other rule. Decodes as
    /// nil from documents written before it existed.
    public var appIdentity: AppIdentityBranch?

    public init(
        id: String,
        type: RuleType,
        action: RuleAction,
        description: String,
        priority: Int,
        cacheSeconds: Int? = nil,
        match: MatchCriteria,
        conditions: RuleConditions = RuleConditions(),
        elevation: ElevationBehavior = ElevationBehavior(),
        appIdentity: AppIdentityBranch? = nil
    ) {
        self.id = id
        self.type = type
        self.action = action
        self.description = description
        self.priority = priority
        self.cacheSeconds = cacheSeconds
        self.match = match
        self.conditions = conditions
        self.elevation = elevation
        self.appIdentity = appIdentity
    }

    /// True for an identity-scoped authURI rule (see ``appIdentity``).
    public var isIdentityScoped: Bool { type == .authuri && appIdentity != nil }
}

/// Rule target category.
public enum RuleType: String, Codable, Sendable, CaseIterable {
    /// Matches an AuthorizationDB right name.
    case authuri
    /// Matches a sudo command invocation.
    case sudo
}

/// Rule outcome category.
public enum RuleAction: String, Codable, Sendable, CaseIterable {
    case allow
    case deny
}

// MARK: - Match criteria

/// How a command pattern is interpreted.
public enum MatchType: String, Codable, Sendable, CaseIterable {
    /// `commandPattern` must equal the canonical executable path exactly.
    case exact
    /// `commandPattern` is an `fnmatch(3)` glob applied to the canonical path.
    case glob
    /// `commandPattern` is a regular expression that must fully match the canonical path.
    case regex
    /// `commandPattern` is a literal path prefix of the canonical path;
    /// `argPattern` (when present) is a regular expression applied to `argv`.
    case prefixRegex = "prefix-regex"
    /// Matches any command. Identity constraints in ``MatchCriteria`` still apply.
    case any
}

/// What a rule matches against.
///
/// Path is supplemental evidence only — the evaluation context always carries
/// validated binary identity (team ID, hash, signing status) collected at
/// decision time, and rules may pin `requiredTeamID` / `requiredBinaryHash`
/// to make identity authoritative for high-value rules.
public struct MatchCriteria: Codable, Sendable, Equatable {
    /// AuthorizationDB right name (authuri rules only). Exact match.
    public var authURI: String?
    /// Canonical executable path pattern (sudo rules only).
    public var commandPattern: String?
    /// Regular expression applied to the first element of `argv`
    /// (sudo rules only). Argv is never flattened before matching.
    public var argPattern: String?
    /// Interpretation of `commandPattern`. Defaults to `.exact`.
    public var matchType: MatchType?
    /// When set, the requesting binary's Team ID must equal this value.
    public var requiredTeamID: String?
    /// When set, the requesting binary's SHA-256 must equal this value.
    public var requiredBinaryHash: String?

    public init(
        authURI: String? = nil,
        commandPattern: String? = nil,
        argPattern: String? = nil,
        matchType: MatchType? = nil,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil
    ) {
        self.authURI = authURI
        self.commandPattern = commandPattern
        self.argPattern = argPattern
        self.matchType = matchType
        self.requiredTeamID = requiredTeamID
        self.requiredBinaryHash = requiredBinaryHash
    }
}

// MARK: - Conditions

/// Requirements the requestor must satisfy beyond the match block.
public struct RuleConditions: Codable, Sendable, Equatable {
    /// When true, the user must supply justification text before approval.
    public var requireJustification: Bool
    /// How long the grant created on allow lasts:
    /// - `-1` (``RuleSchemaConstants/neverGrantSeconds``): evaluate every
    ///   time; never issue a grant, whatever the org default.
    /// - `0`: use the org default (`defaultGrantDurationMinutes`).
    /// - `N`: a grant for N seconds (capped at
    ///   ``RuleSchemaConstants/maxGrantSeconds``).
    ///
    /// Any other negative value is refused (``Rule/runtimeRejectionReason``).
    public var maxGrantDurationSeconds: Int

    public init(requireJustification: Bool = false, maxGrantDurationSeconds: Int = 0) {
        self.requireJustification = requireJustification
        self.maxGrantDurationSeconds = maxGrantDurationSeconds
    }
}

// MARK: - Elevation behavior

/// Delivery mode of an allow decision.
public enum ElevationType: String, Codable, Sendable, CaseIterable {
    /// Granted without user interaction.
    case silent
    /// User must approve via the Sentinel prompt before the grant is issued.
    case prompt
}

/// How an allow decision is delivered and logged.
///
/// Profiles written while rules still carried a `notify` flag keep decoding:
/// nothing ever read it, so the key is ignored wherever it appears.
public struct ElevationBehavior: Codable, Sendable, Equatable {
    /// Silent grant or user-approved prompt.
    public var type: ElevationType
    /// When true, redacted argv is included in decision log events. Off by
    /// default: argv can carry secrets the redactor does not recognise, so a
    /// rule opts in explicitly.
    public var logArguments: Bool

    public init(type: ElevationType = .silent, logArguments: Bool = false) {
        self.type = type
        self.logArguments = logArguments
    }
}

// MARK: - Signing status

/// Code-signing posture of a binary observed at decision time.
public enum SigningStatus: String, Codable, Sendable, CaseIterable {
    case valid
    case invalid
    case adhoc
    case unsigned
}

// MARK: - Decoding

public extension RuleProfile {
    /// Decodes a profile from the JSON string stored in a `rules_*` managed
    /// preference key.
    /// - Throws: ``PolicyError/profileDecodingFailed(profileKey:underlying:)``
    static func decode(jsonString: String, expectedKey: String) throws -> RuleProfile {
        guard let data = jsonString.data(using: .utf8) else {
            throw PolicyError.profileDecodingFailed(
                profileKey: expectedKey,
                underlying: "profile value is not valid UTF-8"
            )
        }
        return try decode(jsonData: data, expectedKey: expectedKey)
    }

    /// Decodes a profile from JSON data.
    static func decode(jsonData: Data, expectedKey: String) throws -> RuleProfile {
        do {
            return try JSONDecoder().decode(RuleProfile.self, from: jsonData)
        } catch {
            throw PolicyError.profileDecodingFailed(
                profileKey: expectedKey,
                underlying: String(describing: error)
            )
        }
    }
}

// MARK: - Native (Jamf Custom Schema) rule decoding

/// Outcome of decoding one native rule dictionary: either a valid ``Rule`` or a
/// human-readable reason it was rejected (surfaced as a config finding).
public enum ManagedRuleResult: Equatable, Sendable {
    case rule(Rule)
    case invalid(String)
}

public extension Rule {
    /// Builds a ``Rule`` from the NATIVE flat dictionary a Jamf "Application &
    /// Custom Settings" Custom Schema produces (as opposed to the nested wire
    /// JSON). The schema form is flat — `commandPattern`/`matchType`/`authURI`/
    /// `elevationType`/`requireJustification`/… are sibling keys — so this maps
    /// them onto the model's nested `match`/`conditions`/`elevation`.
    ///
    /// Empty-string optionals (Jamf emits `""` for untouched text fields) are
    /// treated as absent. Security-sensitive fields are REQUIRED and never
    /// defaulted to a permissive value: a rule missing `id`, a valid `type`, a
    /// valid `action`, or its type's match target (`commandPattern` for sudo
    /// unless `matchType` is `any`; `authURI` for authuri) is REJECTED so a
    /// half-authored Jamf row can never silently become an allow-anything rule.
    ///
    /// - Returns: `.rule(Rule)` or `.invalid(reason)` for a config finding.
    ///
    /// A field that is PRESENT but of the wrong type, or an enum with an
    /// unrecognized value, is REJECTED (the whole rule becomes `.invalid` with a
    /// finding) — never silently coerced to a default. Coercing a mistyped
    /// `elevationType` to `.silent`, or a mistyped `matchType` to `.exact`, would
    /// fail *open* (a silent auto-grant, or an inert deny), so present-but-invalid
    /// must fail the rule the same way `type`/`action` do. Only ABSENT optional
    /// fields fall back to their defaults.
    static func fromManagedDictionary(_ dict: [String: Any]) -> ManagedRuleResult {
        var errors: [String] = []

        // Trimmed non-empty string. Absent/empty → nil; present-but-not-a-string
        // → nil + a finding (so a mistyped path/URI can't silently vanish).
        func optString(_ key: String) -> String? {
            guard let raw = dict[key] else { return nil }
            guard let s = raw as? String else { errors.append("'\(key)' must be a string"); return nil }
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        // Integer. Absent → nil; present-but-not-an-integer (including a
        // CFBoolean) → nil + a finding.
        func optInt(_ key: String) -> Int? {
            guard let raw = dict[key] else { return nil }
            if CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID() {
                errors.append("'\(key)' must be an integer, not a boolean"); return nil
            }
            if let i = raw as? Int { return i }
            if let n = raw as? NSNumber { return n.intValue }
            errors.append("'\(key)' must be an integer"); return nil
        }
        // Boolean. Absent → default; present-but-not-a-CFBoolean → default + a
        // finding (a mistyped security flag must never be silently dropped).
        func boolField(_ key: String, default fallback: Bool) -> Bool {
            guard let raw = dict[key] else { return fallback }
            guard CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID() else {
                errors.append("'\(key)' must be a boolean"); return fallback
            }
            return (raw as? Bool) ?? fallback
        }
        // String-raw enum. Absent/empty → default; present-but-unrecognized →
        // default + a finding.
        func enumField<E: RawRepresentable>(_ key: String, default fallback: E) -> E
        where E.RawValue == String {
            guard let raw = optString(key) else { return fallback }
            guard let value = E(rawValue: raw) else {
                errors.append("'\(key)' has unrecognized value '\(raw)'"); return fallback
            }
            return value
        }

        guard let id = optString("id") else { return .invalid("rule missing required 'id'") }
        guard let typeRaw = optString("type") else {
            return .invalid("rule '\(id)' missing required 'type' (sudo|authuri)")
        }
        guard let type = RuleType(rawValue: typeRaw) else {
            return .invalid("rule '\(id)' has invalid 'type' '\(typeRaw)' (expected sudo|authuri)")
        }
        guard let actionRaw = optString("action") else {
            return .invalid("rule '\(id)' missing required 'action' (allow|deny)")
        }
        guard let action = RuleAction(rawValue: actionRaw) else {
            return .invalid("rule '\(id)' has invalid 'action' '\(actionRaw)' (expected allow|deny)")
        }

        var match = MatchCriteria(
            requiredTeamID: optString("requiredTeamID"),
            requiredBinaryHash: optString("requiredBinaryHash")
        )
        switch type {
        case .sudo:
            let matchType = enumField("matchType", default: MatchType.exact)
            match.matchType = matchType
            match.commandPattern = optString("commandPattern")
            match.argPattern = optString("argPattern")
            if matchType != .any && match.commandPattern == nil {
                errors.append("sudo rule with matchType '\(matchType.rawValue)' requires a 'commandPattern'")
            }
        case .authuri:
            match.authURI = optString("authURI")
            if match.authURI == nil { errors.append("authuri rule requires an 'authURI'") }
        }

        // A `notify` key from an older profile is ignored (never read).
        let elevation = ElevationBehavior(
            type: enumField("elevationType", default: ElevationType.silent),
            logArguments: boolField("logArguments", default: false)
        )

        // Identity-scoped authURI rule: `appTeamID` + `appBundleID` travel
        // together (one without the other is a half-authored pin and fails
        // the rule). There is no posture key — every app branch is
        // authenticate-session-owner-or-admin.
        var appIdentity: AppIdentityBranch?
        // The action must be `allow`: a pin only ever ADDS a per-app path, so
        // an identity-scoped deny would be enforced as an allow for that app.
        // Rejected by ``runtimeRejectionReason`` below, after the other checks.
        let appTeamID = optString("appTeamID")
        let appBundleID = optString("appBundleID")
        if appTeamID != nil || appBundleID != nil {
            if type != .authuri {
                errors.append("appTeamID/appBundleID apply to authuri rules only")
            }
            guard let appTeamID, let appBundleID else {
                errors.append("identity-scoped authuri rule requires BOTH 'appTeamID' and 'appBundleID'")
                return .invalid("rule '\(id)': " + errors.joined(separator: "; "))
            }
            appIdentity = AppIdentityBranch(teamID: appTeamID, bundleID: appBundleID)
        }

        let conditions = RuleConditions(
            requireJustification: boolField("requireJustification", default: false),
            maxGrantDurationSeconds: optInt("maxGrantDurationSeconds") ?? 0
        )
        let priority = optInt("priority") ?? 50
        let cacheSeconds = optInt("cacheSeconds")

        // Any present-but-invalid field fails the whole rule with a finding —
        // never silently applied with a surprising (possibly permissive) default.
        guard errors.isEmpty else {
            return .invalid("rule '\(id)': " + errors.joined(separator: "; "))
        }

        let rule = Rule(
            id: id,
            type: type,
            action: action,
            description: (dict["description"] as? String) ?? "",
            priority: priority,
            cacheSeconds: cacheSeconds,
            match: match,
            conditions: conditions,
            elevation: elevation,
            appIdentity: appIdentity
        )
        // The same runtime gate the JSON-string path applies in
        // ManagedPreferencesReader: an identity-scoped deny, a rule-class or
        // wildcard target, or a deny on a login/unlock right is dropped with a finding (fail closed).
        if let reason = rule.runtimeRejectionReason {
            return .invalid("rule '\(id)': " + reason)
        }
        return .rule(rule)
    }

    /// Why the daemon, the authorization plugin and every other runtime reader
    /// must DROP this rule, or `nil` when it is enforceable.
    ///
    /// This is the runtime half of the checks ``PolicyValidator`` makes at
    /// authoring time. The validator only runs in Commander; a profile
    /// hand-written, uploaded as a plist, or produced by an older Commander
    /// reaches the Mac without it. So the shapes that would be enforced as
    /// something other than what they say are refused here too, where the
    /// policy is read:
    ///
    /// - an identity-scoped rule whose action is not `allow`. The composer and
    ///   the plugin only know how to ADD a per-app path; a `deny` pin would be
    ///   enforced as an allow for that app.
    /// - an authuri target ``AuthRightTargetPolicy`` refuses (invalid
    ///   characters, rule-class names, trailing-dot wildcards, Serberus's own
    ///   composition rows), a `deny` on a right whose denial locks users out,
    ///   or an `allow` on FileVault unlock / Platform SSO.
    var runtimeRejectionReason: String? {
        if conditions.maxGrantDurationSeconds < RuleSchemaConstants.neverGrantSeconds {
            return "maxGrantDurationSeconds \(conditions.maxGrantDurationSeconds) is not allowed (use -1 to evaluate every time, 0 for the org default, or a number of seconds)"
        }
        if appIdentity != nil {
            guard type == .authuri else {
                return "appIdentity applies to authuri rules only"
            }
            guard action == .allow else {
                return "identity-scoped rule must be an allow rule (action '\(action.rawValue)' would be enforced as an allow for the pinned app); deny the right with a plain authuri rule instead"
            }
        }
        guard type == .authuri, let right = match.authURI else { return nil }
        if let reason = AuthRightTargetPolicy.targetRejectionReason(right) { return reason }
        if action == .deny, let reason = AuthRightTargetPolicy.denyRejectionReason(right) { return reason }
        if action == .allow, let reason = AuthRightTargetPolicy.allowRejectionReason(right) { return reason }
        return nil
    }
}

// MARK: - AuthorizationDB right target policy

/// Which AuthorizationDB rights an authuri rule may name, and how.
///
/// Shared by the runtime parser (``ManagedPreferencesReader``, via
/// ``Rule/runtimeRejectionReason``), ``PolicyValidator``, the daemon's
/// AuthorizationDB manager and the authorization plugin, so a rule is judged
/// the same way everywhere it is read.
public enum AuthRightTargetPolicy {
    /// Right-name prefixes Serberus must NEVER modify, even if a rule names
    /// them. Modifying these risks a lockout (login / unlock / screensaver,
    /// restart / shutdown), an auth-bypass (security settings, keychain
    /// creation, Kerberos), or breaking the authdb's own integrity (the
    /// `config.*`/`rule.*` rights, and the built-in `authenticate-*` rules the
    /// projections delegate to). A rule naming one is kept (so the finding is
    /// visible) but the daemon leaves the right untouched and logs it.
    ///
    /// Install rights (`system.install.*`, `com.apple.pkgkit.*`) are
    /// deliberately NOT protected: letting standard users self-install is a
    /// legitimate use, and the projection's `allow-root=true` keeps a
    /// non-interactive Jamf/MDM `installer` (which runs as root) working.
    public static let protectedRightPrefixes: [String] = [
        "authenticate",                   // built-in auth rules Serberus delegates to
        "system.login",                   // console / screensaver / unlock
        "system.preferences.security",    // the Security & Privacy pane
        "config.",                        // rights that modify the authdb itself
        "rule.",                          // rule definitions
        "com.apple.security.",            // security-critical Apple rights
        "com.apple.builtin.",             // authd's own built-in mechanism rights
        "system.keychain.create.loginkc", // login-keychain creation during login
        "com.apple.KerberosAgent",        // Kerberos ticket acquisition (SSO / PSSO)
        "system.restart",                 // restart from the login window / Apple menu
        "system.shutdown",                // shut down from the login window / Apple menu
    ]

    /// Whether `right` is on the never-touch list.
    public static func isProtected(_ right: String) -> Bool {
        protectedRightPrefixes.contains { right == $0 || right.hasPrefix($0) }
    }

    /// Rights a plain `allow` rule must never open, matched as PREFIXES. An
    /// allow projects to "the session owner's own password", so each of these
    /// would hand every standard user root, a direct path to it, or the
    /// ability to switch off a device-wide security control. Deny rules on
    /// them are still honoured; letting ONE verified app use a right is an
    /// identity-scoped rule's job.
    ///
    /// This is a DENY-list, and the daemon adds a second check when it
    /// applies a plain allow: it reads the right's LIVE definition and refuses
    /// the rule unless that definition is a plain admin gate
    /// (``AuthRightNativeGate/plainAllowRefusal(_:lookup:)``). That catches a
    /// right created at runtime with a narrower gate, but not a right whose
    /// native gate IS an admin password and which still leads to root, so
    /// such a right must be named here. The `AuthRightTargetPolicy sweep` test
    /// keeps this list honest — it reads this Mac's
    /// `/System/Library/Security/authorization.plist` and fails on any
    /// admin-gated right that is neither protected, listed here, nor reviewed
    /// into ``knownNonRootEquivalentRights``. When in doubt a right goes HERE.
    public static let rootEquivalentRightPrefixes: [String] = [
        // Direct root / code execution as root or in other processes.
        "system.privilege.admin",            // AuthorizationExecuteWithPrivileges, "with administrator privileges"
        "system.privilege.taskport",         // attaching to other processes
        "com.apple.ServiceManagement.",      // installing privileged helpers and daemons
        "com.apple.backgroundtaskmanagement.manage-daemons", // enabling launch daemons (root code)
        "system.global-login-items.",        // login items for EVERY user (code in an admin's session)
        "com.apple.OpenScripting.additions.send", // scripting additions loaded into other processes
        "com.apple.lldb.",                   // LaunchUsingXPC: debugger-launched processes
        "com.apple.dt.",                     // developer tools; Instruments creates
                                             // com.apple.dt.instruments.process.analysis at runtime
                                             // (admin-gated), which attaches to other users' processes
        "system.admin",                      // generic "administrator" authorization
        "com.apple.auth.admin",              // generic admin check apps use as their own gate
        "com.apple.installassistant.",       // macOS installer / erase-install, run privileged
        "com.apple.docset.install",          // privileged write into shared developer locations
        "com.apple.ReportPanic.fixRight",    // undocumented privileged repair; unreviewed, so listed
        // Arbitrary file read / write.
        "sys.openfile.",                     // authopen: read/write ANY file, e.g. /etc/sudoers
        "com.apple.desktopservices",         // Finder privileged file ops (copy/move/delete anywhere; covers .scripted)
        "com.apple.app-sandbox.",            // replace-file / set-attributes / create-symlink: write anywhere
        "com.apple.container-repair",        // privileged chown/chmod of container trees (symlink-raceable)
        "com.apple.library-repair",          // privileged chown/chmod of ~/Library trees (symlink-raceable)
        "system.preferences.timemachine",    // back up every user's files to a disk the user controls
        "com.apple.system-migration.",       // Migration Assistant: imports accounts and root-owned files
        // Disks, volumes and boot.
        "com.apple.DiskManagement.",         // erase / partition / mount internal + boot volumes, FileVault KEK
        "system.volume.internal.",           // mount / erase / rename internal volumes
        "system.volume.external.adopt",      // take ownership of a volume (setuid / owners honoured)
        "system.volume.network.adopt",       // not in the plist; listed so creating it cannot open it
        "system.volume.optical.adopt",
        "system.volume.removable.adopt",
        "system.preferences.startupdisk",    // choose the boot volume (boot an attacker's OS)
        "system.preferences.nvram",          // NVRAM variables: boot-args, startup behaviour
        // Accounts, identity, trust.
        "system.preferences.accounts",       // creating users and changing who's an admin
        "system.services.directory.configure", // directory binding / node config (who is an admin)
        "system.identity.write.",            // writing users and groups
        "com.apple.trust-settings.admin",    // trusting certificates system-wide
        "system.keychain.modify",            // modifying the System keychain
        "com.apple.configurationprofiles.",  // installing configuration profiles
        "com.apple.ctkbind.",                // binding smart-card identities to accounts
        "com.apple.system-extensions.admin", // approving system extensions
        "com.apple.tcc.util.admin",          // granting TCC (privacy) permissions
        "system.preferences.accessibility",  // system-wide assistive access; unreviewed on this OS, so listed
        // Every user's network traffic.
        "system.preferences.sharing",        // Remote Login, Screen Sharing, file sharing for everyone
        "system.sharepoints.",               // share any folder over the network
        "system.services.systemconfiguration.network", // network config (proxies, DNS) for every user
        "system.services.networkextension.", // content filters / VPN that see every user's traffic
        "com.apple.pf.rule",                 // packet-filter (firewall / redirect) rules
        "com.apple.server.admin.",           // legacy macOS Server administration
        // Device-wide security controls (not root, but switching one off is a
        // policy bypass no standard user should self-serve).
        "com.apple.AOSNotification.FindMyMac.", // Find My / Activation Lock
        "com.apple.SoftwareUpdate.modify-",  // automatic security updates, Rapid Security Response removal
        "system.preferences.softwareupdate", // the Software Update settings pane
        "com.apple.activitymonitor.kill",    // kill ANY process, including security agents
        "com.apple.Safari.parental-controls", // lifting one's own restrictions
        "com.apple.iBooksX.ParentalControl",
        "system.preferences.parental-controls",
    ]

    /// Whether a plain `allow` rule may not open `right`.
    ///
    /// The bare `system.preferences` right is deliberately NOT listed: authd
    /// never uses a right without a trailing dot as a wildcard, so it doesn't
    /// govern its children, and the sensitive panes under it (accounts,
    /// security, sharing) are guarded individually. Opening it is what lets a
    /// standard user unlock a pane such as Date & Time.
    public static func isRootEquivalent(_ right: String) -> Bool {
        rootEquivalentRightPrefixes.contains { right == $0 || right.hasPrefix($0) }
    }

    /// Admin-gated rights REVIEWED as safe for a plain `allow` (the session
    /// owner self-serves with their own password). Matched EXACTLY — a
    /// trailing-dot entry names the wildcard itself, whose undefined children
    /// were reviewed along with it.
    ///
    /// Not consulted at runtime (the runtime gates are the deny-list above and
    /// the daemon's live check of the native definition); it is the other half
    /// of the sweep test's classification, so every admin-gated right on a
    /// shipping macOS is a deliberate decision rather than an omission. A right
    /// whose native gate is NOT a plain admin gate (on-console, an entitlement,
    /// another group, the session owner alone) does not belong here: the
    /// daemon refuses a plain allow on it whatever this list says.
    public static let knownNonRootEquivalentRights: Set<String> = [
        // The two namespace wildcards (`{rule = default}`, no class of their
        // own). Neither can be a rule target (trailing dot). They govern every
        // UNDEFINED `system.*` / `com.apple.*` right, which is what a rule on an
        // undefined name creates; the prefix lists above are what guard the
        // sensitive ones among those, including rights an app creates later
        // (`com.apple.dt.`).
        "com.apple.",
        "system.",
        // Settings panes the samples, library and docs ship.
        "system.preferences",                         // bare pane lock (never a wildcard; see isRootEquivalent)
        "system.preferences.datetime",                // Date & Time (sample profiles, docs)
        "system.preferences.dateandtime.changetimezone", // time zone (sample profiles)
        "system.preferences.printing",                // Printers & Scanners (library, docs)
        "system.preferences.network",                 // Network pane lock (library); system-wide SC writes stay
                                                      // behind system.services.systemconfiguration.network
        "system.preferences.energysaver",             // sleep / wake settings
        "system.preferences.version-cue",             // legacy Adobe Version Cue; inert
        // Printing.
        "system.printingmanager",                     // manage printers
        // Install rights: owner decision (see protectedRightPrefixes). A pkg's
        // scripts run as root, so system.install.software IS a root path; it is
        // accepted deliberately because standard-user self-install is a
        // supported use case. The Apple variant only runs Apple-signed payloads.
        "system.install.software",
        "system.install.apple-software",
        // Fonts: fontmover writes only into /Library/Fonts (the system fonts
        // live on the sealed system volume); routinely self-served.
        "com.apple.XType.fontmover.install",
        "com.apple.XType.fontmover.remove",
        "com.apple.XType.fontmover.restore",
        // Low-impact, user-scoped or inert.
        "com.apple.SoftwareUpdate.scan",              // check for updates (read-only)
        "com.apple.applepay.reset",                   // resets this Mac's Apple Pay cards
        "com.apple.dashboard.advisory.allow",         // Dashboard is gone; inert
        "system.device.dvd.setregion.initial",        // DVD region
        // DiskArbitration. The `system.volume.` wildcard itself is never a
        // target; its children are classified individually (`internal.` and
        // every `.adopt` are root-equivalent above). The external / network /
        // optical / removable classes are natively on-console satisfiable, not
        // admin gates, so the daemon refuses a plain allow on them.
        "system.volume.",
    ]

    /// Rights a `deny` rule must never target, matched exactly: denying them
    /// locks every user out of unlocking the disk. (`use-login-window-ui` is
    /// an authorization RULE, not a right — no dot — so
    /// ``targetRejectionReason(_:)`` already refuses it for every action.)
    public static let denyForbiddenExactRights: Set<String> = [
        "system.disk.unlock",
    ]

    /// Rights a `deny` rule must never target, matched as prefixes (login
    /// window, screensaver, Platform SSO sign-in).
    public static let denyForbiddenRightPrefixes: [String] = [
        "system.login",
        "system.platformsso",
    ]

    /// Rights an `allow` rule must never target either, matched as prefixes:
    /// FileVault unlock and Platform SSO sign-in. Opening them would replace
    /// a volume-owner / IdP authentication with the session owner's password.
    /// (A deny on them is refused by ``denyForbiddenRightPrefixes`` /
    /// ``denyForbiddenExactRights``, so neither action may name them.)
    public static let allowForbiddenRightPrefixes: [String] = [
        "system.disk.unlock",
        "system.platformsso",
    ]

    /// The only characters a real right name uses (verified against every
    /// right in `/System/Library/Security/authorization.plist` on macOS 27:
    /// ASCII letters, digits, `.`, `-`; `_` is allowed for third-party
    /// rights). Everything else — above all NUL, which truncates the C string
    /// handed to `AuthorizationRight*` so `com.apple.\u{0}x` would rewrite the
    /// `com.apple.` wildcard — is refused.
    public static func hasValidCharacters(_ right: String) -> Bool {
        guard let first = right.utf8.first, isAlphanumeric(first) else { return false }
        return right.utf8.allSatisfy { isAlphanumeric($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "_") || $0 == UInt8(ascii: "-") }
    }

    private static func isAlphanumeric(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
            || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
            || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }

    /// Why `right` can never be a rule target at all (whatever the action), or
    /// `nil` when it may be named.
    ///
    /// - A name outside `^[A-Za-z0-9][A-Za-z0-9._-]*$` (see
    ///   ``hasValidCharacters(_:)``).
    /// - A name with no dot is an authorization RULE class (`is-root`,
    ///   `is-admin`, `entitled`, `default`, `authenticate-*`, …), not a right.
    ///   Rewriting one changes every right that delegates to it.
    /// - A name ending in `.` is a wildcard: authd evaluates a right that has
    ///   no definition of its own against its nearest trailing-dot ancestor,
    ///   so `system.privilege.` would govern every undefined privilege right.
    ///   (A name WITHOUT the trailing dot, such as `system.privilege`, is
    ///   never used as a wildcard, so it can't cover a guarded right.)
    /// - A name under ``AuthURICompositionNaming/rowPrefix`` is one of
    ///   Serberus's own composition rows, never a policy target.
    public static func targetRejectionReason(_ right: String) -> String? {
        if !hasValidCharacters(right) {
            let shown = right.unicodeScalars.map { $0.isASCII && $0.value >= 0x20 && $0.value < 0x7F ? String($0) : "\\u{\(String($0.value, radix: 16))}" }.joined()
            return "'\(shown)' is not a valid right name (allowed: ASCII letters, digits, '.', '_', '-', starting with a letter or digit)"
        }
        if !right.contains(".") {
            return "'\(right)' is an authorization rule class (no dot), not a right; rewriting it would change every right that delegates to it"
        }
        if right.hasSuffix(".") {
            return "'\(right)' ends in '.': authd treats a trailing-dot right as the wildcard for every undefined child right"
        }
        if right.hasPrefix(AuthURICompositionNaming.rowPrefix) {
            return "'\(right)' is one of Serberus's own composition rows, not a right a rule can target"
        }
        return nil
    }

    /// Why a `deny` rule may not target `right`, or `nil` when it may.
    public static func denyRejectionReason(_ right: String) -> String? {
        let forbidden = denyForbiddenExactRights.contains(right)
            || denyForbiddenRightPrefixes.contains { right == $0 || right.hasPrefix($0) }
        return forbidden
            ? "a deny rule on '\(right)' would lock users out of logging in or unlocking; refused"
            : nil
    }

    /// Why an `allow` rule may not target `right`, or `nil` when it may.
    /// (Root-equivalent rights are NOT refused here: an identity-scoped allow
    /// may still name one; the daemon drops a PLAIN allow on them.)
    public static func allowRejectionReason(_ right: String) -> String? {
        allowForbiddenRightPrefixes.contains { right == $0 || right.hasPrefix($0) }
            ? "an allow rule on '\(right)' would replace FileVault / Platform SSO authentication with the session owner's password; refused"
            : nil
    }
}

// MARK: - Native gate of a right

/// Reads a right's NATIVE definition the way authd evaluates it, following
/// `rule` references, to answer two questions the static lists cannot:
///
/// - Is the right a plain admin gate, so that a plain `allow` (which rewrites
///   it to "the session owner or any admin, root passes") only adds the
///   session owner? See ``plainAllowRefusal(_:lookup:)``.
/// - Does the right delegate to a mechanism chain (keychain unlock, smart
///   card, LocalAuthentication, …) that a password rule must never replace?
///   See ``mechanismChain(_:lookup:)``.
///
/// `lookup` returns the definition of a named rule or right (the live
/// AuthorizationDB in the daemon, the `rules` dictionary of
/// `authorization.plist` in tests), or nil when it is not defined. A
/// definition with a `rule` key but no `class` is evaluated as `class=rule`,
/// as authd does.
public enum AuthRightNativeGate {
    public typealias Lookup = (String) -> [String: Any]?

    /// Rule chains deeper than this are treated as unknown (refused).
    static let maxDepth = 16

    /// The most rule references one classification or mechanism search
    /// resolves. Any user can create a right (`config.add.` is `class=allow`),
    /// so a pre-created right can reference a wide graph of other rights;
    /// past this many lookups the definition is refused rather than walked.
    static let maxLookups = 256

    /// Keys that narrow a gate below "an admin's password" (an entitlement,
    /// an Apple signature, a code requirement, or a password handed to a
    /// mechanism). A plain allow would drop them, so a definition that sets
    /// one is never treated as a plain admin gate.
    static let narrowingKeys = ["entitled", "entitled-group", "vpn-entitled-group",
                                "require-apple-signed", "extract-password"]

    /// Mechanism rules that only test a property of the caller (an
    /// entitlement, being at the console) rather than run an authentication
    /// UI. Reaching one of these is not a mechanism chain for
    /// ``mechanismChain(_:lookup:)``; it still is not an admin gate.
    static let predicateMechanisms: Set<String> = ["builtin:entitled,privileged", "builtin:on-console"]

    /// What a (sub)definition admits.
    enum Gate: Equatable {
        /// Any member of `admin` (usually with their password).
        case admin
        /// Only admins or root, but narrower than the plain admin path
        /// (root alone, or an admin who also needs an entitlement or a
        /// mechanism). Harmless as an alternative next to an admin branch.
        case adminOrRootOnly
        /// Every caller, without authentication (`class=allow`).
        case open(String)
        /// No caller (`class=deny`).
        case nobody
        /// Anything else, with the reason.
        case other(String)
    }

    /// Why a plain `allow` must not rewrite a right natively defined as
    /// `definition`, or nil when the right is a plain admin gate.
    ///
    /// Admin-gated means: the definition, or the rule chain it resolves to,
    /// is `class=user group=admin`, and nothing on the way sets an entitlement,
    /// an Apple-signature or code requirement, `extract-password`, its own
    /// `mechanisms`, or a different group. Inside a `k-of-n: 1` (any-of) array,
    /// other branches are tolerated only when they admit nobody but admins or
    /// root (`is-root`, `entitled-admin`): dropping those removes nothing a
    /// standard user could use. An all-of array is admin-gated only when every
    /// member is. Anything the reader is unsure about is refused, including a
    /// rule graph larger than ``maxLookups`` references.
    public static func plainAllowRefusal(_ definition: [String: Any], lookup: Lookup) -> String? {
        let (gate, exhausted) = withoutActuallyEscaping(lookup) { lookup in
            let walker = Classifier(lookup: lookup)
            return (walker.classify(definition, label: "the right", visiting: []), walker.exhausted)
        }
        if exhausted {
            return "its native rule graph references more than \(maxLookups) rules; it is not read further"
        }
        switch gate {
        case .admin:
            return nil
        case let .open(path):
            return "it is already open to every caller natively (\(path) is class=allow); an allow rule would add a password prompt, not remove one"
        case .nobody:
            return "it is natively denied to every caller; an allow rule would open it"
        case .adminOrRootOnly:
            return "natively only root, or an admin who also passes an entitlement or mechanism check, satisfies it; it is not a plain admin-password gate"
        case let .other(reason):
            return "its native definition is not a plain admin-password gate: \(reason)"
        }
    }

    /// Whether `definition` is a plain admin gate (see ``plainAllowRefusal(_:lookup:)``).
    public static func isAdminGated(_ definition: [String: Any], lookup: Lookup) -> Bool {
        plainAllowRefusal(definition, lookup: lookup) == nil
    }

    /// The class authd evaluates `definition` as.
    static func effectiveClass(_ definition: [String: Any]) -> String? {
        if let cls = definition["class"] as? String { return cls }
        return definition["rule"] != nil ? "rule" : nil
    }

    static func references(_ definition: [String: Any]) -> [String] {
        if let list = definition["rule"] as? [String] { return list }
        if let single = definition["rule"] as? String { return [single] }
        return []
    }

    /// The `mechanisms` a definition runs itself (any class), or empty.
    static func ownMechanisms(_ definition: [String: Any]) -> [String] {
        (definition["mechanisms"] as? [String]) ?? []
    }

    /// One classification: every rule reference is looked up at most once
    /// (the verdict for a name does not depend on the path that reached it,
    /// since loops are refused), and the walk stops after ``maxLookups``
    /// distinct lookups.
    final class Classifier {
        private let lookup: Lookup
        private var memo: [String: Gate] = [:]
        private(set) var lookups = 0
        private(set) var exhausted = false

        init(lookup: @escaping Lookup) {
            self.lookup = lookup
        }

        func classify(_ definition: [String: Any], label: String, visiting: Set<String>) -> Gate {
            if visiting.count > maxDepth { return .other("\(label): rule chain deeper than \(maxDepth) levels") }
            for key in narrowingKeys where (definition[key] as? Bool) == true {
                return .other("\(label) sets '\(key)'")
            }
            if let requirement = definition["requirement"] as? String, !requirement.isEmpty {
                return .other("\(label) carries a code requirement")
            }
            let cls = effectiveClass(definition)
            if cls != "evaluate-mechanisms", definition["mechanisms"] != nil {
                // authd runs a rule's own mechanisms (an MFA step, for
                // example) in place of the plain password check; a plain
                // allow would drop them.
                let mechanisms = ownMechanisms(definition)
                return .other("\(label) runs its own mechanisms (\(mechanisms.joined(separator: ", ")))")
            }
            switch cls {
            case "allow":
                return .open(label)
            case "deny":
                return .nobody
            case "user":
                if let group = definition["group"] as? String {
                    return group == "admin" ? .admin : .other("\(label) is gated to group '\(group)', not admin")
                }
                if (definition["session-owner"] as? Bool) == true {
                    return .other("\(label) is gated to the session owner alone")
                }
                if (definition["authenticate-user"] as? Bool) == false, (definition["allow-root"] as? Bool) == true {
                    return .adminOrRootOnly   // is-root
                }
                return .other("\(label) is class=user with no group")
            case "rule":
                let refs = references(definition)
                guard !refs.isEmpty else { return .other("\(label) is class=rule with no rule") }
                // An unsatisfiable or malformed k-of-n is refused before the
                // single-reference shortcut could read past it.
                var kofn: Int?
                if let raw = definition["k-of-n"] {
                    guard let k = raw as? Int, k >= 1, k <= refs.count else {
                        return .other("\(label) has k-of-n \(raw) over \(refs.count) rule(s), which no caller can satisfy as written")
                    }
                    kofn = k
                }
                var children: [Gate] = []
                for ref in refs {
                    guard !visiting.contains(ref) else { return .other("\(label): rule chain loops through '\(ref)'") }
                    children.append(resolve(ref, visiting: visiting))
                    if exhausted { return .other("\(label): rule graph too large") }
                }
                if children.count == 1 { return children[0] }
                if kofn == 1 { return anyOf(children) }
                if kofn == nil || kofn == refs.count { return allOf(children) }
                return .other("\(label) needs \(kofn!) of \(refs.count) rules")
            case "evaluate-mechanisms":
                return .other("\(label) is a mechanism chain (\(ownMechanisms(definition).joined(separator: ", ")))")
            case let cls?:
                return .other("\(label) has class '\(cls)'")
            case nil:
                return .other("\(label) has no class")
            }
        }

        private func resolve(_ ref: String, visiting: Set<String>) -> Gate {
            if let known = memo[ref] { return known }
            guard lookups < maxLookups else {
                exhausted = true
                return .other("rule graph too large")
            }
            lookups += 1
            let gate: Gate
            if let nested = lookup(ref) {
                gate = classify(nested, label: "'\(ref)'", visiting: visiting.union([ref]))
            } else {
                gate = .other("'\(ref)' is referenced but not defined")
            }
            if !exhausted { memo[ref] = gate }
            return gate
        }
    }

    /// `k-of-n: 1`: authd stops at the first branch that succeeds.
    static func anyOf(_ children: [Gate]) -> Gate {
        for child in children { if case .other = child { return child } }
        for child in children { if case .open = child { return child } }
        if children.contains(.admin) { return .admin }
        return children.allSatisfy { $0 == .nobody } ? .nobody : .adminOrRootOnly
    }

    /// No `k-of-n` (or k = count): every member must succeed.
    static func allOf(_ children: [Gate]) -> Gate {
        if children.allSatisfy({ $0 == .admin }) { return .admin }
        if children.contains(.nobody) { return .nobody }
        if children.contains(where: { $0 == .admin || $0 == .adminOrRootOnly }) { return .adminOrRootOnly }
        for child in children { if case .other = child { return child } }
        return children.first ?? .other("empty rule array")
    }

    /// A description of the mechanism chain `definition` runs, or nil when it
    /// runs none: its own class is `evaluate-mechanisms`, it (or a rule it
    /// reaches through `rule` references) carries `mechanisms` that are not
    /// only the entitlement / on-console predicates (``predicateMechanisms``),
    /// whatever its class. For example `com.apple.ctk.pair` → `kcunlock`
    /// (keychain unlock). A rule graph larger than ``maxLookups`` references
    /// is reported as one too, since what it reaches is unknown.
    public static func mechanismChain(_ definition: [String: Any], lookup: Lookup) -> String? {
        if effectiveClass(definition) == "evaluate-mechanisms" {
            return "class=evaluate-mechanisms (\(ownMechanisms(definition).joined(separator: ", ")))"
        }
        if definition["mechanisms"] != nil {
            let mechanisms = ownMechanisms(definition)
            if mechanisms.isEmpty || !mechanisms.allSatisfy(predicateMechanisms.contains) {
                return "runs its own mechanisms (\(mechanisms.joined(separator: ", ")))"
            }
        }
        var visited: Set<String> = []
        var queue = references(definition)
        var index = 0
        while index < queue.count {
            let ref = queue[index]
            index += 1
            guard !visited.contains(ref) else { continue }
            guard visited.count < maxLookups else {
                return "its rule graph references more than \(maxLookups) rules, so what it reaches cannot be checked"
            }
            visited.insert(ref)
            guard let nested = lookup(ref) else { continue }
            if effectiveClass(nested) == "evaluate-mechanisms" || nested["mechanisms"] != nil {
                let mechanisms = ownMechanisms(nested)
                if mechanisms.isEmpty || !mechanisms.allSatisfy(predicateMechanisms.contains) {
                    return "reaches '\(ref)', a mechanism chain (\(mechanisms.joined(separator: ", ")))"
                }
            }
            queue.append(contentsOf: references(nested))
        }
        return nil
    }

    /// The names authd tries, in order, for a right that has no definition
    /// of its own: each trailing-dot ancestor, longest first (`a.b.c` →
    /// `a.b.`, `a.`), then the catch-all `""` right.
    public static func wildcardCandidates(for right: String) -> [String] {
        var parts = right.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var names: [String] = []
        parts.removeLast()
        while !parts.isEmpty {
            names.append(parts.joined(separator: ".") + ".")
            parts.removeLast()
        }
        names.append("")
        return names
    }

    // MARK: Authoring-time reading of the shipped database

    /// Apple's shipped authorization database.
    public static let shippedDatabasePath = "/System/Library/Security/authorization.plist"

    /// `rights` and `rules` of this Mac's shipped database, read once (nil
    /// when unreadable). Immutable after the first read.
    nonisolated(unsafe) private static let shippedDatabase: (rights: [String: Any], rules: [String: Any])? = {
        guard let data = FileManager.default.contents(atPath: shippedDatabasePath),
              let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              let rights = plist["rights"] as? [String: Any] else { return nil }
        return (rights, plist["rules"] as? [String: Any] ?? [:])
    }()

    /// Why the daemon would refuse a plain `allow` on `right` on a Mac whose
    /// database is the one this Mac ships, or nil when it would accept it or
    /// that cannot be known here. Authoring-time advice only: the daemon
    /// checks each Mac's LIVE definition. An undefined right is read through
    /// the wildcard authd would answer it from, as the daemon does.
    public static func shippedPlainAllowRefusal(_ right: String) -> String? {
        guard let database = shippedDatabase else { return nil }
        return plainAllowRefusal(right, rights: database.rights, rules: database.rules)
    }

    /// The mechanism chain `right` runs in an explicit database (`rights` and
    /// `rules` of an `authorization.plist`), read through the wildcard that
    /// governs it when it is not defined, or nil when it runs none.
    public static func mechanismChain(_ right: String, rights: [String: Any], rules: [String: Any]) -> String? {
        let lookup: Lookup = { (rules[$0] ?? rights[$0]) as? [String: Any] }
        if let definition = rights[right] as? [String: Any] {
            return mechanismChain(definition, lookup: lookup)
        }
        for name in wildcardCandidates(for: right) {
            guard let definition = rights[name] as? [String: Any] else { continue }
            return mechanismChain(definition, lookup: lookup).map { "through the wildcard '\(name)': \($0)" }
        }
        return nil
    }

    /// ``shippedPlainAllowRefusal(_:)`` over an explicit database.
    public static func plainAllowRefusal(_ right: String, rights: [String: Any], rules: [String: Any]) -> String? {
        let lookup: Lookup = { (rules[$0] ?? rights[$0]) as? [String: Any] }
        if let definition = rights[right] as? [String: Any] {
            return plainAllowRefusal(definition, lookup: lookup)
        }
        for name in wildcardCandidates(for: right) {
            guard let definition = rights[name] as? [String: Any] else { continue }
            return plainAllowRefusal(definition, lookup: lookup).map { "it is not defined, and the wildcard '\(name)' that governs it: \($0)" }
        }
        return nil
    }

    /// The credential settings authd applies to `definition`, for a plain
    /// allow to carry over: `timeout`, `shared` and `password-only`.
    ///
    /// - A `class=user` definition gives its own.
    /// - A `rule` reference to one rule gives that rule's.
    /// - A `rule` array (an any-of `k-of-n: 1`, or an all-of) gives the most
    ///   restrictive across its admin-gate branches, the branches a person
    ///   authenticates through (`is-root` and other root-or-entitlement
    ///   branches are skipped): the SHORTEST `timeout` (a branch with none
    ///   counts as unlimited), `shared` true only when every admin branch sets
    ///   it, and `password-only` true when any admin branch sets it. So
    ///   `[is-admin, authenticate-admin]` (timeout 0) gives timeout 0, not
    ///   authd's unlimited default.
    ///
    /// Each value is nil when nothing sets it or the definition is not one of
    /// these shapes.
    public static func credentialSettings(_ definition: [String: Any], lookup: Lookup)
        -> (timeout: Int?, shared: Bool?, passwordOnly: Bool?) {
        withoutActuallyEscaping(lookup) { lookup in
            let settings = credentialSettings(definition, lookup: lookup, visiting: [])
            return (settings?.timeout, settings?.shared, settings?.passwordOnly)
        }
    }

    private struct CredentialSettings {
        var timeout: Int?
        var shared: Bool?
        var passwordOnly: Bool?
    }

    private static func credentialSettings(_ definition: [String: Any], lookup: @escaping Lookup,
                                           visiting: Set<String>) -> CredentialSettings? {
        guard visiting.count <= maxDepth else { return nil }
        switch effectiveClass(definition) {
        case "user":
            return CredentialSettings(timeout: definition["timeout"] as? Int,
                                      shared: definition["shared"] as? Bool,
                                      passwordOnly: definition["password-only"] as? Bool)
        case "rule":
            let refs = references(definition)
            if refs.count == 1 {
                guard !visiting.contains(refs[0]), let next = lookup(refs[0]) else { return nil }
                return credentialSettings(next, lookup: lookup, visiting: visiting.union([refs[0]]))
            }
            var branches: [CredentialSettings] = []
            for ref in refs {
                guard !visiting.contains(ref), let child = lookup(ref) else { return nil }
                let gate = Classifier(lookup: lookup).classify(child, label: "'\(ref)'", visiting: visiting.union([ref]))
                guard gate == .admin else { continue }
                guard let settings = credentialSettings(child, lookup: lookup, visiting: visiting.union([ref])) else {
                    return nil
                }
                branches.append(settings)
            }
            guard !branches.isEmpty else { return nil }
            let timeouts = branches.compactMap(\.timeout)
            let shared = branches.allSatisfy { $0.shared == true } ? true
                : (branches.contains { $0.shared != nil } ? false : nil)
            let passwordOnly = branches.contains { $0.passwordOnly == true } ? true
                : (branches.contains { $0.passwordOnly != nil } ? false : nil)
            return CredentialSettings(timeout: timeouts.min(), shared: shared, passwordOnly: passwordOnly)
        default:
            return nil
        }
    }
}
