import Foundation

// MARK: - Validation issues

/// Severity of a validation finding. Errors block export; warnings require
/// acknowledgement but do not block.
public enum ValidationSeverity: String, Sendable, Codable, Equatable {
    case error
    case warning
}

/// One finding from the pre-export validation pipeline.
public struct ValidationIssue: Sendable, Equatable, CustomStringConvertible {
    public let severity: ValidationSeverity
    /// Stable machine-readable identifier of the check that produced this issue.
    public let check: String
    /// Rule ID the issue concerns, when rule-scoped.
    public let ruleID: String?
    /// Human-readable explanation.
    public let message: String

    public init(severity: ValidationSeverity, check: String, ruleID: String? = nil, message: String) {
        self.severity = severity
        self.check = check
        self.ruleID = ruleID
        self.message = message
    }

    public var description: String {
        let scope = ruleID.map { " [rule \($0)]" } ?? ""
        return "\(severity.rawValue.uppercased()) (\(check))\(scope): \(message)"
    }
}

/// Aggregate result of validating one profile.
public struct ValidationReport: Sendable, Equatable {
    public let profileKey: String
    public let issues: [ValidationIssue]

    public init(profileKey: String, issues: [ValidationIssue]) {
        self.profileKey = profileKey
        self.issues = issues
    }

    /// Blocking findings. A profile with any error cannot be exported.
    public var errors: [ValidationIssue] { issues.filter { $0.severity == .error } }
    /// Non-blocking findings requiring acknowledgement.
    public var warnings: [ValidationIssue] { issues.filter { $0.severity == .warning } }
    /// True when the profile may be exported.
    public var isExportable: Bool { errors.isEmpty }
}

// MARK: - Validator

/// Pre-export validation pipeline.
///
/// Every check runs unconditionally so the report lists all problems at
/// once rather than failing on the first.
public struct PolicyValidator: Sendable {
    public init() {}

    /// Validates one profile and returns the full report.
    public func validate(_ profile: RuleProfile) -> ValidationReport {
        var issues: [ValidationIssue] = []

        // 2. schemaVersion present and recognized.
        if profile.schemaVersion.isEmpty {
            issues.append(.init(severity: .error, check: "schema-version",
                                message: "schemaVersion is empty"))
        } else if !RuleSchemaConstants.recognizedSchemaVersions.contains(profile.schemaVersion) {
            issues.append(.init(severity: .error, check: "schema-version",
                                message: "schemaVersion '\(profile.schemaVersion)' is not recognized"))
        }

        // 3. policyVersion present and semver-formatted.
        if !Self.isSemver(profile.policyVersion) {
            issues.append(.init(severity: .error, check: "policy-version",
                                message: "policyVersion '\(profile.policyVersion)' is not semver (MAJOR.MINOR.PATCH)"))
        }

        // 4. profileKey naming convention.
        if !Self.isValidProfileKey(profile.profileKey) {
            issues.append(.init(severity: .error, check: "profile-key",
                                message: "profileKey '\(profile.profileKey)' must match rules_authuri_<slug> or rules_sudo_<slug>"))
        }

        // 5. profilePriority is a positive integer.
        if profile.profilePriority <= 0 {
            issues.append(.init(severity: .error, check: "profile-priority",
                                message: "profilePriority must be a positive integer (found \(profile.profilePriority))"))
        }

        // Profile-key / rule-type coherence (derived from the naming convention).
        let expectedType: RuleType? = profile.profileKey.hasPrefix(RuleSchemaConstants.authURIProfilePrefix)
            ? .authuri
            : profile.profileKey.hasPrefix(RuleSchemaConstants.sudoProfilePrefix) ? .sudo : nil

        if profile.rules.isEmpty {
            issues.append(.init(severity: .warning, check: "empty-profile",
                                message: "Profile contains no rules"))
        }

        // Per-rule checks.
        for rule in profile.rules {
            issues.append(contentsOf: Self.validate(rule: rule, expectedType: expectedType))
        }

        // 10. No duplicate rule IDs within the profile.
        var seen: Set<String> = []
        for rule in profile.rules {
            if !seen.insert(rule.id).inserted {
                issues.append(.init(severity: .error, check: "duplicate-rule-id", ruleID: rule.id,
                                    message: "Duplicate rule ID '\(rule.id)' within profile"))
            }
        }

        // 11. No equal-priority allow/deny conflict on the same target within one profile.
        issues.append(contentsOf: ConflictDetector().intraProfileConflicts(profile))

        // 12. Identity-scoped composition shape across the profile.
        issues.append(contentsOf: Self.validateIdentityComposition(profile.rules))

        return ValidationReport(profileKey: profile.profileKey, issues: issues)
    }

    // MARK: Identity-scoped authURI checks

    /// Per-rule checks for an identity-scoped authURI rule: identity pin
    /// format, the compiled requirement's syntax, and — the
    /// verification table (`registry`), which only ever WARNS: an ineligible
    /// or unknown right warns with the reason, a provisional right warns with
    /// the "Testing — not verified" badge and the Mac(s) it is being tested
    /// on. The daemon enforces the rule regardless. While per-app pins are
    /// disabled (``AuthURIIdentityScope/perAppPinsEnabled``) every pin is
    /// an ERROR (`app-identity-disabled`).
    static func validateIdentityBranch(
        _ branch: AppIdentityBranch,
        right: String?,
        rule: Rule,
        registry: AuthURIIdentityScopeRegistry = .current,
        perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled
    ) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        // Per-app pins are disabled in this release (the daemon skips
        // them and the plugin denies), so a profile carrying one is refused
        // rather than exported as a rule that silently does nothing.
        if !perAppPinsEnabled {
            issues.append(.init(severity: .error, check: "app-identity-disabled", ruleID: rule.id,
                                message: AuthURIIdentityScope.disabledValidationMessage))
        }
        // Also enforced at runtime (Rule.runtimeRejectionReason): the daemon
        // and plugin drop such a rule rather than compose it as an allow.
        if rule.action != .allow {
            issues.append(.init(severity: .error, check: "app-identity", ruleID: rule.id,
                                message: "identity-scoped rule must be an allow rule (a deny needs no app branch — deny the right with a plain authuri rule)"))
        }
        if !CodeRequirementCompiler.isValidTeamID(branch.teamID) {
            issues.append(.init(severity: .error, check: "app-identity", ruleID: rule.id,
                                message: "Team ID '\(branch.teamID)' is not a 10-character Apple Team ID"))
        }
        if !CodeRequirementCompiler.isValidBundleID(branch.bundleID) {
            issues.append(.init(severity: .error, check: "app-identity", ruleID: rule.id,
                                message: "Bundle ID '\(branch.bundleID)' is not a valid code-signing identifier"))
        }
        // Verification state is reported on the right, independent of the pin's
        // validity, so an unverified right reads as unverified (not as a bad
        // Team ID). Warnings only — never blocking.
        if let right {
            let decision = registry.authoringDecision(for: right)
            if let reason = decision.rejectionReason {
                issues.append(.init(severity: .warning, check: "app-identity-scope", ruleID: rule.id, message: reason))
            } else if decision.state == .provisional, let entry = decision.entry {
                issues.append(.init(severity: .warning, check: "app-identity-scope", ruleID: rule.id,
                                    message: "'\(right)' is \(decision.state.label): enforced wherever this profile lands — scope it to the test Mac(s) \(entry.allowedSerials.sorted().joined(separator: ", ")) until verified"))
            }
        }
        return issues
    }

    /// Profile-wide shape: a right is EITHER composed from app branches OR
    /// projected by a plain authuri rule, never both (the daemon lets the plain
    /// projection win and skips the branches, so mixing them ships a silent
    /// no-op); and two branches on one right must not pin the same app (their
    /// auth.db rows would collide).
    static func validateIdentityComposition(_ rules: [Rule]) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        let authuri = rules.filter { $0.type == .authuri }
        let composedRights = Set(authuri.filter { $0.appIdentity != nil }.compactMap(\.match.authURI))
        for rule in authuri where rule.appIdentity == nil {
            if let right = rule.match.authURI, composedRights.contains(right) {
                issues.append(.init(severity: .error, check: "app-identity-mix", ruleID: rule.id,
                                    message: "'\(right)' has both a plain authuri rule and per-app identity rules — the plain rule would win and the app branches would never be composed"))
            }
        }
        var seen: [String: String] = [:]   // "<right>|<slug>" → first rule id
        for rule in authuri {
            guard let branch = rule.appIdentity, let right = rule.match.authURI else { continue }
            let key = right + "|" + branch.rowSlug
            if let first = seen[key] {
                issues.append(.init(severity: .error, check: "app-identity-duplicate", ruleID: rule.id,
                                    message: "Rules '\(first)' and '\(rule.id)' both pin \(branch.bundleID) (\(branch.teamID)) on '\(right)' — one rule per app/right pair"))
            } else {
                seen[key] = rule.id
            }
        }
        return issues
    }

    // MARK: Rule-level checks

    /// Validates a single rule outside a profile (used by the Rule composer for
    /// live inline feedback). `expectedType` is the type implied by the owning
    /// profile's key prefix, or `nil` when the profile key implies neither.
    public static func validate(rule: Rule, expectedType: RuleType?) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []

        if rule.id.isEmpty {
            issues.append(.init(severity: .error, check: "rule-id", ruleID: rule.id,
                                message: "Rule ID is empty"))
        }

        if let expectedType, rule.type != expectedType {
            issues.append(.init(severity: .error, check: "rule-type", ruleID: rule.id,
                                message: "Rule type '\(rule.type.rawValue)' does not match profile key type '\(expectedType.rawValue)'"))
        }

        switch rule.type {
        case .authuri:
            // 6. Auth URI format valid.
            if let uri = rule.match.authURI {
                if !Self.isValidAuthURI(uri) {
                    issues.append(.init(severity: .error, check: "auth-uri", ruleID: rule.id,
                                        message: "Auth URI '\(uri)' contains invalid characters"))
                }
                // The same target gate the daemon's runtime parser applies
                // (Rule.runtimeRejectionReason), so a profile that exports
                // cleanly is never silently dropped on the Mac.
                if let reason = AuthRightTargetPolicy.targetRejectionReason(uri) {
                    issues.append(.init(severity: .error, check: "auth-uri-target", ruleID: rule.id,
                                        message: reason))
                }
                if rule.action == .deny, let reason = AuthRightTargetPolicy.denyRejectionReason(uri) {
                    issues.append(.init(severity: .error, check: "auth-uri-deny", ruleID: rule.id,
                                        message: reason))
                }
                if rule.action == .allow, let reason = AuthRightTargetPolicy.allowRejectionReason(uri) {
                    issues.append(.init(severity: .error, check: "auth-uri-allow", ruleID: rule.id,
                                        message: reason))
                }
            } else {
                issues.append(.init(severity: .error, check: "auth-uri", ruleID: rule.id,
                                    message: "authuri rule has no match.authURI"))
            }
            if rule.match.commandPattern != nil || rule.match.argPattern != nil {
                issues.append(.init(severity: .error, check: "match-shape", ruleID: rule.id,
                                    message: "authuri rule must not declare commandPattern/argPattern"))
            }
            if let uri = rule.match.authURI, AuthRightTargetPolicy.targetRejectionReason(uri) == nil {
                issues.append(contentsOf: Self.droppedByDaemon(rule, right: uri))
            }
            if let branch = rule.appIdentity {
                issues.append(contentsOf: Self.validateIdentityBranch(branch, right: rule.match.authURI, rule: rule))
            } else if rule.action == .allow, let right = rule.match.authURI,
                      AuthURIIdentityScopeRegistry.current.isIdentityOnly(right) {
                // A plain allow REWRITES the right for every caller — the thing
                // per-app scoping exists to avoid. Enforced as authored; warned.
                // While per-app rules are disabled there is nothing to
                // point the author at, so the warning says the right has no
                // allow path in this release instead.
                let message = AuthURIIdentityScope.perAppPinsEnabled
                    ? "'\(right)' can only be allowed per app — use an App Identity definition (Team ID + bundle ID) instead of a plain authorization-right definition"
                    : "'\(right)' can only be allowed per app, and per-app (App Identity) rules are disabled in Serberus 0.9.0, so this right has no per-app allow path in this release"
                issues.append(.init(severity: .warning, check: "app-identity-required", ruleID: rule.id,
                                    message: message))
            }

        case .sudo:
            if rule.appIdentity != nil {
                issues.append(.init(severity: .error, check: "app-identity", ruleID: rule.id,
                                    message: "sudo rule must not declare appIdentity (identity scoping is authuri-only)"))
            }
            if rule.match.authURI != nil {
                issues.append(.init(severity: .error, check: "match-shape", ruleID: rule.id,
                                    message: "sudo rule must not declare match.authURI"))
            }
            let matchType = rule.match.matchType ?? .exact
            if rule.match.commandPattern == nil && matchType != .any {
                issues.append(.init(severity: .error, check: "command-pattern", ruleID: rule.id,
                                    message: "sudo rule with matchType '\(matchType.rawValue)' requires commandPattern"))
            }
            // 7. Regex syntax compiles. 8. Glob syntax valid.
            if let pattern = rule.match.commandPattern {
                switch matchType {
                case .regex:
                    if !Self.regexCompiles(pattern) {
                        issues.append(.init(severity: .error, check: "regex-syntax", ruleID: rule.id,
                                            message: "commandPattern regex '\(pattern)' does not compile"))
                    }
                case .glob:
                    if !Self.isValidGlob(pattern) {
                        issues.append(.init(severity: .error, check: "glob-syntax", ruleID: rule.id,
                                            message: "commandPattern glob '\(pattern)' is invalid"))
                    }
                case .exact, .prefixRegex:
                    if !pattern.hasPrefix("/") {
                        issues.append(.init(severity: .error, check: "command-pattern", ruleID: rule.id,
                                            message: "commandPattern '\(pattern)' must be an absolute path"))
                    }
                case .any:
                    break
                }
            }
            if let argPattern = rule.match.argPattern, !Self.regexCompiles(argPattern) {
                issues.append(.init(severity: .error, check: "regex-syntax", ruleID: rule.id,
                                    message: "argPattern regex '\(argPattern)' does not compile"))
            }
            // A sudo allow rule matching any command with no identity pin is
            // an effective blanket grant — surface it loudly.
            if matchType == .any && rule.action == .allow
                && rule.match.requiredTeamID == nil && rule.match.requiredBinaryHash == nil {
                issues.append(.init(severity: .warning, check: "broad-match", ruleID: rule.id,
                                    message: "Allow rule matches any command with no identity constraint"))
            }
        }

        // 9. cacheSeconds within range.
        if let cache = rule.cacheSeconds, !(0...RuleSchemaConstants.maxCacheSeconds).contains(cache) {
            issues.append(.init(severity: .error, check: "cache-seconds", ruleID: rule.id,
                                message: "cacheSeconds \(cache) outside 0...\(RuleSchemaConstants.maxCacheSeconds)"))
        }

        let grant = rule.conditions.maxGrantDurationSeconds
        if grant < RuleSchemaConstants.neverGrantSeconds {
            issues.append(.init(severity: .error, check: "grant-duration", ruleID: rule.id,
                                message: "maxGrantDurationSeconds must be -1 (evaluate every time), 0 (use the org default) or a number of seconds"))
        } else if grant > RuleSchemaConstants.maxGrantSeconds {
            issues.append(.init(severity: .warning, check: "grant-duration", ruleID: rule.id,
                                message: "maxGrantDurationSeconds \(grant) is above \(RuleSchemaConstants.maxGrantSeconds); the daemon caps a grant at 24 hours"))
        }

        return issues
    }

    /// Warnings for an authuri rule the daemon will accept but not enforce,
    /// so the drop is not a surprise found only in the integrity log: a
    /// protected right (never modified), a plain allow on a root-equivalent
    /// right, and a plain allow on a right that this Mac's shipped database
    /// does not gate with a plain admin password (the daemon checks the live
    /// definition on each Mac).
    static func droppedByDaemon(_ rule: Rule, right: String) -> [ValidationIssue] {
        if AuthRightTargetPolicy.isProtected(right) {
            return [.init(severity: .warning, check: "auth-uri-protected", ruleID: rule.id,
                          message: "'\(right)' is protected: Serberus never modifies it, so the Mac does not enforce this rule")]
        }
        guard rule.appIdentity == nil, rule.action == .allow else { return [] }
        if AuthRightTargetPolicy.isRootEquivalent(right) {
            return [.init(severity: .warning, check: "auth-uri-root-equivalent", ruleID: rule.id,
                          message: "an allow on '\(right)' would give every standard user root, so the Mac does not enforce it; allow one app with an identity-scoped rule instead")]
        }
        if let reason = AuthRightNativeGate.shippedPlainAllowRefusal(right) {
            return [.init(severity: .warning, check: "auth-uri-native-gate", ruleID: rule.id,
                          message: "on this Mac's macOS, an allow on '\(right)' is not enforced: \(reason). A plain allow only replaces an admin-password gate; the Mac checks its own definition of the right")]
        }
        return []
    }

    // MARK: Format helpers

    /// `MAJOR.MINOR.PATCH`, numeric components only.
    static func isSemver(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return false }
        return parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) }
    }

    /// `rules_authuri_<slug>` or `rules_sudo_<slug>` with a non-empty
    /// lowercase alphanumeric/underscore slug.
    static func isValidProfileKey(_ key: String) -> Bool {
        for prefix in [RuleSchemaConstants.authURIProfilePrefix, RuleSchemaConstants.sudoProfilePrefix] {
            if key.hasPrefix(prefix) {
                let slug = key.dropFirst(prefix.count)
                return !slug.isEmpty && slug.allSatisfy { $0.isLowercase && $0.isLetter || $0.isNumber || $0 == "_" }
            }
        }
        return false
    }

    /// Right names: the same ASCII character set the runtime gate enforces
    /// (``AuthRightTargetPolicy/hasValidCharacters(_:)``) — no whitespace, no
    /// non-ASCII letters, no NUL.
    static func isValidAuthURI(_ uri: String) -> Bool {
        AuthRightTargetPolicy.hasValidCharacters(uri)
    }

    static func regexCompiles(_ pattern: String) -> Bool {
        (try? NSRegularExpression(pattern: pattern)) != nil
    }

    /// Rejects globs with unbalanced character classes.
    static func isValidGlob(_ pattern: String) -> Bool {
        guard !pattern.isEmpty else { return false }
        var inClass = false
        for char in pattern {
            if char == "[" { inClass = true }
            if char == "]" { inClass = false }
        }
        return !inClass
    }
}
