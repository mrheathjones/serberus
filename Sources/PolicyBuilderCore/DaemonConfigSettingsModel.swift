import Foundation
import Observation
import PrivMgrCore

/// Authoring model for the daemon behavior / break-glass config (Settings pane).
///
/// Holds an editable draft of the `com.herojoneslabs.serberus.config` managed
/// domain — enforcement mode, PAM bypass (the mandatory pre-PAM-install
/// break-glass population), sudo cache TTL, prompt timeout, and the daemon
/// kill switch — persists the draft to UserDefaults so the admin's work
/// survives relaunch, and generates the `.mobileconfig` that delivers it.
/// Same author-then-deliver flow as ``JITAdminSettingsModel``.
///
/// The Jamf connection keys that live in the same domain (`jamfProURL`,
/// `jamfAPIClientID`, `jamfAPIClientSecret`) are deliberately NOT authored
/// here: they remain a separately delivered profile. Managed preferences
/// union across profiles in one domain, so the two payloads compose on the
/// device without overwriting each other.
@MainActor
@Observable
public final class DaemonConfigSettingsModel {
    /// Documented range for ``sudoCacheSeconds`` (matches the reader's).
    public static let cacheRange = 0...RuleSchemaConstants.maxCacheSeconds
    /// Range for ``promptTimeoutSeconds``. The reader accepts up to 3600, but
    /// the daemon caps the effective prompt window at 60 s so it always
    /// resolves inside pam_serberus's poll budget; offering more would be
    /// misleading.
    public static let timeoutRange = 1...60
    /// Documented range for ``defaultGrantDurationMinutes`` (matches the reader's).
    public static let grantDurationMinutesRange = 0...RuleSchemaConstants.maxGrantDurationMinutes

    public var enforcementMode: EnforcementMode
    /// Comma/newline-separated usernames, edited as free text in the UI.
    public var pamBypassUsersText: String
    /// Comma/newline-separated group names, edited as free text in the UI.
    public var pamBypassGroupsText: String
    /// Curated-sudo enrollment group, edited as free text. A single
    /// pre-existing group whose members become enrolled; blank = user-only.
    public var sudoEnrollmentGroupText: String
    /// Comma/newline-separated curated-sudo enrollment usernames, free text.
    public var sudoEnrollmentUsersText: String
    /// Global sudo cache TTL in seconds (0 = no caching).
    public var sudoCacheSeconds: Int
    /// Prompt timeout in seconds — deny on expiry, never auto-allow.
    public var promptTimeoutSeconds: Int
    /// Master switch for time-bound elevation grants. On (the default) makes
    /// grants expire by the resolved duration (global default + per-rule); off
    /// issues no grants, so a prompt rule asks every time.
    public var timeBoundGrantsEnabled: Bool
    /// Org-wide default grant duration in whole minutes, applied when
    /// ``timeBoundGrantsEnabled`` is on and a rule sets no duration of its own.
    /// `0` = no global default (each rule specifies its own).
    public var defaultGrantDurationMinutes: Int
    public var daemonEnabled: Bool
    /// Admin-console gate: lets Serberus Commander (on Macs this profile is
    /// scoped to) publish RULE profiles straight to the MDM API. Off by
    /// default — see ``SerberusConfig/commanderPublishEnabled``.
    public var commanderPublishEnabled: Bool
    /// Touch ID for identity-scoped app branches — see
    /// ``SerberusConfig/enableBiometrics``. Off by default
    /// (session-owner-or-admin).
    public var enableBiometrics: Bool
    /// Explicit operator acknowledgement of the PAM bricking risk: shipping
    /// `enforce` with an empty bypass means NOBODY falls through to
    /// `pam_opendirectory.so` if the daemon is unreachable. Mirrors the
    /// mandatory conflict acknowledgement in ``ExportModel``. Not persisted —
    /// the risk must be re-acknowledged per session.
    public var brickRiskAcknowledged = false

    public private(set) var lastExportError: String?

    private let defaults: UserDefaults
    private enum Key {
        static let enforcementMode = "serberus.config.enforcementMode"
        static let bypassUsers = "serberus.config.pamBypassUsers"
        static let bypassGroups = "serberus.config.pamBypassGroups"
        static let sudoEnrollmentGroup = "serberus.config.sudoEnrollmentGroup"
        static let sudoEnrollmentUsers = "serberus.config.sudoEnrollmentUsers"
        static let cacheSeconds = "serberus.config.sudoCacheSeconds"
        static let timeoutSeconds = "serberus.config.promptTimeoutSeconds"
        static let timeBoundGrantsEnabled = "serberus.config.timeBoundGrantsEnabled"
        static let defaultGrantDurationMinutes = "serberus.config.defaultGrantDurationMinutes"
        static let daemonEnabled = "serberus.config.daemonEnabled"
        static let commanderPublishEnabled = "serberus.config.commanderPublishEnabled"
        static let enableBiometrics = "serberus.config.enableBiometrics"
    }

    /// Defaults mirror ``ManagedPreferencesReader/readConfig()``'s fail-safe
    /// fallbacks: enforce, cache 0, timeout 60, daemon enabled, no bypass,
    /// direct publish off.
    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        self.enforcementMode = EnforcementMode(rawValue: defaults.string(forKey: Key.enforcementMode) ?? "") ?? .enforce
        self.pamBypassUsersText = defaults.string(forKey: Key.bypassUsers) ?? ""
        self.pamBypassGroupsText = defaults.string(forKey: Key.bypassGroups) ?? ""
        self.sudoEnrollmentGroupText = defaults.string(forKey: Key.sudoEnrollmentGroup) ?? ""
        self.sudoEnrollmentUsersText = defaults.string(forKey: Key.sudoEnrollmentUsers) ?? ""
        self.sudoCacheSeconds = defaults.object(forKey: Key.cacheSeconds) as? Int ?? 0
        self.promptTimeoutSeconds = defaults.object(forKey: Key.timeoutSeconds) as? Int ?? 60
        self.timeBoundGrantsEnabled = defaults.object(forKey: Key.timeBoundGrantsEnabled) as? Bool ?? true
        self.defaultGrantDurationMinutes = defaults.object(forKey: Key.defaultGrantDurationMinutes) as? Int ?? 0
        self.daemonEnabled = defaults.object(forKey: Key.daemonEnabled) as? Bool ?? true
        self.commanderPublishEnabled = defaults.object(forKey: Key.commanderPublishEnabled) as? Bool ?? false
        self.enableBiometrics = defaults.object(forKey: Key.enableBiometrics) as? Bool ?? false
    }

    /// Parsed username list from the free-text field — well-formed entries
    /// only. Malformed entries (see ``bypassValidationError``) are excluded
    /// so they can never lift the enforce+no-bypass guardrail or reach the
    /// exported profile.
    public var pamBypassUsers: [String] {
        Self.parseList(pamBypassUsersText).valid
    }

    /// Parsed group list from the free-text field — well-formed entries only.
    public var pamBypassGroups: [String] {
        Self.parseList(pamBypassGroupsText).valid
    }

    /// Users-field entries that cannot be macOS account names (they contain
    /// internal whitespace, e.g. a space-separated paste like
    /// `"helpdesk breakglass"`). Non-empty blocks export.
    public var invalidPamBypassUserEntries: [String] {
        Self.parseList(pamBypassUsersText).invalid
    }

    /// Groups-field entries that cannot be macOS group names. Non-empty
    /// blocks export.
    public var invalidPamBypassGroupEntries: [String] {
        Self.parseList(pamBypassGroupsText).invalid
    }

    /// Parsed curated-sudo enrollment usernames — strict, safe-form entries only.
    /// Uses the stricter ``parseSudoPrincipalList`` (not ``parseList``): a
    /// sudo-enrollment principal is interpolated into a `sudoers` User_Spec, so it
    /// must be a plain local account name and must never be the reserved `ALL`
    /// token or carry a sudoers sigil (`% # +`).
    public var sudoEnrollmentUsers: [String] {
        Self.parseSudoPrincipalList(sudoEnrollmentUsersText).valid
    }

    /// The single curated-sudo enrollment group, or nil when the field is
    /// blank (user-only enrollment). `sudoEnrollment.group` is one optional
    /// string in the reader, so only the first well-formed entry is used.
    public var sudoEnrollmentGroup: String? {
        Self.parseSudoPrincipalList(sudoEnrollmentGroupText).valid.first
    }

    /// Users-field entries that are not a safe local account name (internal
    /// whitespace, the reserved `ALL`, or a sudoers sigil). Non-empty blocks export.
    public var invalidSudoEnrollmentUserEntries: [String] {
        Self.parseSudoPrincipalList(sudoEnrollmentUsersText).invalid
    }

    /// Group-field entries that are not a safe local group name (internal
    /// whitespace, the reserved `ALL`, or a sudoers sigil). Non-empty blocks export.
    public var invalidSudoEnrollmentGroupEntries: [String] {
        Self.parseSudoPrincipalList(sudoEnrollmentGroupText).invalid
    }

    /// Separators recognized in the free-text fields: commas plus every
    /// Unicode newline scalar. Splitting on scalars (not `Character`s)
    /// means CRLF pastes from spreadsheets split correctly — Swift treats
    /// `"\r\n"` as a single `Character`, which the previous
    /// `split(whereSeparator:)` implementation never matched.
    private static let listSeparators: CharacterSet = {
        var set = CharacterSet.newlines
        set.insert(charactersIn: ",")
        return set
    }()

    /// Splits free text into trimmed entries, then partitions them into
    /// well-formed names and malformed ones. macOS account/group names never
    /// contain whitespace, so an entry with internal whitespace is a
    /// separator typo that would export an unmatchable name — i.e. a
    /// break-glass population that silently protects nobody.
    private static func parseList(_ text: String) -> (valid: [String], invalid: [String]) {
        let entries = text
            .components(separatedBy: listSeparators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        var valid: [String] = []
        var invalid: [String] = []
        for entry in entries {
            if entry.rangeOfCharacter(from: .whitespacesAndNewlines) == nil {
                valid.append(entry)
            } else {
                invalid.append(entry)
            }
        }
        return (valid, invalid)
    }

    /// Splits free text into trimmed entries, then partitions them into strict,
    /// safe sudo-enrollment principals and everything else. Unlike ``parseList``
    /// (used for PAM bypass, whose semantics must not change), this is the
    /// authoring mirror of the generator's authoritative guard: a sudo-enrollment
    /// principal is dropped straight into a `sudoers` User_Spec, so it must match
    /// `^[A-Za-z0-9_][A-Za-z0-9_.-]*$` and must not be the reserved `ALL` token —
    /// otherwise entries like `ALL`, `%staff`, `#0`, `+netgroup` would export a
    /// grant far broader than the admin intended (or an outright injection).
    private static func parseSudoPrincipalList(_ text: String) -> (valid: [String], invalid: [String]) {
        let entries = text
            .components(separatedBy: listSeparators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        var valid: [String] = []
        var invalid: [String] = []
        for entry in entries {
            if isSafePrincipalName(entry) {
                valid.append(entry)
            } else {
                invalid.append(entry)
            }
        }
        return (valid, invalid)
    }

    /// True when `name` is a strict, safe local account/group name: it matches
    /// `^[A-Za-z0-9_][A-Za-z0-9_.-]*$` and is not the reserved sudoers token `ALL`.
    /// Mirrors the generator-side guard so the Commander app blocks what the daemon
    /// would (authoritatively) drop.
    private static func isSafePrincipalName(_ name: String) -> Bool {
        guard name != "ALL" else { return false }
        func isWordScalar(_ scalar: Unicode.Scalar) -> Bool {
            (scalar >= "A" && scalar <= "Z")
                || (scalar >= "a" && scalar <= "z")
                || (scalar >= "0" && scalar <= "9")
                || scalar == "_"
        }
        let scalars = name.unicodeScalars
        guard let first = scalars.first, isWordScalar(first) else { return false }
        for scalar in scalars.dropFirst() where !(isWordScalar(scalar) || scalar == "." || scalar == "-") {
            return false
        }
        return true
    }

    /// Visible validation error for malformed bypass entries. Non-nil blocks
    /// export regardless of ``brickRiskAcknowledged``: a name with internal
    /// whitespace can never match a real account or group, so shipping it
    /// would provide zero break-glass while looking populated.
    public var bypassValidationError: String? {
        let bad = invalidPamBypassUserEntries + invalidPamBypassGroupEntries
        guard !bad.isEmpty else { return nil }
        let quoted = bad.map { "\u{201C}\($0)\u{201D}" }.joined(separator: ", ")
        return "Invalid PAM bypass \(bad.count == 1 ? "entry" : "entries"): \(quoted). "
            + "Account and group names cannot contain spaces — separate multiple names "
            + "with commas or newlines."
    }

    /// Visible validation error for malformed curated-sudo enrollment entries.
    /// Non-nil blocks export. Independent of the PAM-bypass brick-risk gate:
    /// empty enrollment is a valid, exportable state (it means "no grant / the
    /// drop-in is removed"), so only genuinely malformed principals block here.
    public var sudoEnrollmentValidationError: String? {
        let bad = invalidSudoEnrollmentUserEntries + invalidSudoEnrollmentGroupEntries
        guard !bad.isEmpty else { return nil }
        let quoted = bad.map { "\u{201C}\($0)\u{201D}" }.joined(separator: ", ")
        return "Invalid sudo enrollment \(bad.count == 1 ? "entry" : "entries"): \(quoted). "
            + "Each must be a single local account or group name (letters, digits, and "
            + "_ . -), cannot contain spaces, cannot start with % # or +, and cannot be "
            + "the reserved word ALL. Separate multiple names with commas or newlines."
    }

    /// The config assembled from the current editor state, clamped to the
    /// documented ranges. The Jamf connection fields are always nil — they
    /// are delivered by a separate profile in the same domain (see the type
    /// doc comment).
    public var config: SerberusConfig {
        SerberusConfig(
            jamfProURL: nil,
            jamfAPIClientID: nil,
            jamfAPIClientSecret: nil,
            daemonEnabled: daemonEnabled,
            enforcementMode: enforcementMode,
            sudoCacheSeconds: sudoCacheSeconds.clamped(to: Self.cacheRange),
            promptTimeoutSeconds: promptTimeoutSeconds.clamped(to: Self.timeoutRange),
            pamBypass: PAMBypass(groups: pamBypassGroups, users: pamBypassUsers),
            sudoEnrollment: SerberusConfig.SudoEnrollment(
                group: sudoEnrollmentGroup, users: sudoEnrollmentUsers),
            commanderPublishEnabled: commanderPublishEnabled,
            timeBoundGrantsEnabled: timeBoundGrantsEnabled,
            defaultGrantDurationMinutes: defaultGrantDurationMinutes.clamped(to: Self.grantDurationMinutesRange),
            enableBiometrics: enableBiometrics
        )
    }

    /// Whether the draft is the PAM-bricking shape: full enforcement with no
    /// break-glass population at all. pam_serberus fails CLOSED, so if the
    /// daemon is down and nobody bypasses, sudo is denied for everyone.
    /// Only well-formed entries count — a field containing nothing but
    /// malformed names (see ``bypassValidationError``) is still the bricking
    /// shape, because those names match no real account.
    public var requiresBrickRiskAcknowledgement: Bool {
        enforcementMode == .enforce && pamBypassUsers.isEmpty && pamBypassGroups.isEmpty
    }

    /// Whether the current draft can be exported. Malformed bypass entries
    /// always block (no acknowledgement escape hatch — they are typos, not
    /// choices); the brick-risk shape blocks until acknowledged.
    public var canExport: Bool {
        bypassValidationError == nil
            && sudoEnrollmentValidationError == nil
            && (!requiresBrickRiskAcknowledgement || brickRiskAcknowledged)
    }

    /// Human-readable blocker, for the UI. Validation errors take precedence
    /// over the brick-risk acknowledgement prompt. Sudo-enrollment validation
    /// is independent of the brick-risk gate — empty enrollment never blocks.
    public var exportBlocker: String? {
        if let error = bypassValidationError { return error }
        if let error = sudoEnrollmentValidationError { return error }
        guard requiresBrickRiskAcknowledgement && !brickRiskAcknowledged else { return nil }
        return "Enforce mode with no PAM bypass users or groups: if the daemon is unreachable, "
            + "sudo is denied for EVERYONE on the device (pam_serberus fails closed). "
            + "Add a break-glass user or group, or acknowledge the risk to export anyway."
    }

    public func save() {
        defaults.set(enforcementMode.rawValue, forKey: Key.enforcementMode)
        defaults.set(pamBypassUsersText, forKey: Key.bypassUsers)
        defaults.set(pamBypassGroupsText, forKey: Key.bypassGroups)
        defaults.set(sudoEnrollmentGroupText, forKey: Key.sudoEnrollmentGroup)
        defaults.set(sudoEnrollmentUsersText, forKey: Key.sudoEnrollmentUsers)
        defaults.set(sudoCacheSeconds, forKey: Key.cacheSeconds)
        defaults.set(promptTimeoutSeconds, forKey: Key.timeoutSeconds)
        defaults.set(timeBoundGrantsEnabled, forKey: Key.timeBoundGrantsEnabled)
        defaults.set(defaultGrantDurationMinutes, forKey: Key.defaultGrantDurationMinutes)
        defaults.set(daemonEnabled, forKey: Key.daemonEnabled)
        defaults.set(commanderPublishEnabled, forKey: Key.commanderPublishEnabled)
        defaults.set(enableBiometrics, forKey: Key.enableBiometrics)
    }

    /// Generates the `.mobileconfig`, or captures why it could not.
    public func export(organization: String = "Serberus") -> MobileConfigGenerator.Export? {
        save()
        guard canExport else {
            lastExportError = exportBlocker
            return nil
        }
        do {
            let export = try MobileConfigGenerator().exportDaemonConfig(config, organization: organization)
            lastExportError = nil
            return export
        } catch {
            lastExportError = error.localizedDescription
            return nil
        }
    }
}

private extension Int {
    func clamped(to range: ClosedRange<Int>) -> Int {
        Swift.min(Swift.max(self, range.lowerBound), range.upperBound)
    }
}
