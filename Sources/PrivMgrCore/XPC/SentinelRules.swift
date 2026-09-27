import Foundation

// MARK: - Sentinel rules surface (menubar "My rules" list)

/// How a rule presents to the end user in the Sentinel popover.
///
/// Deliberately a *display* vocabulary, not the policy vocabulary: the policy
/// model is `action allow|deny` × `elevation silent|prompt`, and the daemon's
/// enforcement mode changes what any rule actually does. The mapping is
/// resolved daemon-side (``SentinelRuleSummary/decision(for:mode:)``) so the
/// Sentinel never re-implements policy semantics.
public enum SentinelRuleDecision: String, Codable, Sendable, CaseIterable {
    /// Granted without interaction (allow + silent elevation, enforced).
    case allow
    /// Blocked outright (deny, enforced).
    case deny
    /// The user is asked to approve via the audit prompt (allow + prompt).
    case prompt
    /// Logged only: the daemon is in audit/monitor mode, so this rule watches
    /// and records but native macOS behavior is unchanged.
    case silent
}

/// One rule as shown in the Sentinel's "Rules assigned to you" list.
///
/// A read-only projection of a policy ``Rule`` — the Sentinel displays it and
/// never evaluates it. `title`/`detail` are pre-rendered daemon-side so the
/// display stays consistent with what the daemon actually loaded.
public struct SentinelRuleSummary: Codable, Sendable, Equatable, Identifiable {
    /// Stable identity across profiles (rule IDs are only unique per profile).
    public var id: String { "\(profileKey)/\(ruleID)" }

    public let ruleID: String
    public let profileKey: String
    /// Human-readable rule name (the rule's `description`, with a derived
    /// fallback when the author left it empty).
    public let title: String
    /// Machine-readable subtitle: the authorization right, or the sudo
    /// command pattern (e.g. `sudo · /opt/homebrew/bin/brew`).
    public let detail: String
    public let type: RuleType
    public let decision: SentinelRuleDecision
    /// The delivering profile's policy version. Optional so snapshots cached
    /// on disk before this field existed still decode.
    public let policyVersion: String?

    public init(
        ruleID: String,
        profileKey: String,
        title: String,
        detail: String,
        type: RuleType,
        decision: SentinelRuleDecision,
        policyVersion: String? = nil
    ) {
        self.ruleID = ruleID
        self.profileKey = profileKey
        self.title = title
        self.detail = detail
        self.type = type
        self.decision = decision
        self.policyVersion = policyVersion
    }

    /// Projects a policy rule for display under the daemon's current
    /// enforcement mode.
    public init(rule: Rule, profile: RuleProfile, mode: EnforcementMode) {
        self.init(
            ruleID: rule.id,
            profileKey: profile.profileKey,
            title: Self.title(for: rule),
            detail: Self.detail(for: rule),
            type: rule.type,
            decision: Self.decision(for: rule, mode: mode),
            policyVersion: profile.policyVersion
        )
    }

    /// What the rule *does* from the user's chair. Outside enforce mode every
    /// rule only audits — showing a red DENY badge for a rule that does not
    /// actually deny would be a lie, so audit/monitor collapse to `.silent`.
    public static func decision(for rule: Rule, mode: EnforcementMode) -> SentinelRuleDecision {
        guard mode == .enforce else { return .silent }
        switch rule.action {
        case .deny: return .deny
        case .allow: return rule.elevation.type == .prompt ? .prompt : .allow
        }
    }

    static func title(for rule: Rule) -> String {
        let trimmed = rule.description.trimmingCharacters(in: .whitespacesAndNewlines)
        // A provisional (testing-only) identity-scoped right is badged wherever
        // it appears — including the user's own rule list — so an unverified
        // rule is never mistaken for a shipped one.
        let badge: String = {
            // A per-app rule does nothing in this release; say so.
            if rule.isIdentityScoped, !AuthURIIdentityScope.perAppPinsEnabled { return " · disabled" }
            guard rule.isIdentityScoped, let right = rule.match.authURI,
                  AuthURIIdentityScopeRegistry.current.state(for: right) == .provisional else { return "" }
            return " · " + AuthURIIdentityEligibility.provisional.label
        }()
        if !trimmed.isEmpty { return trimmed + badge }
        switch rule.type {
        case .authuri:
            if let branch = rule.appIdentity {
                return "\(branch.bundleID) → \(rule.match.authURI ?? rule.id)" + badge
            }
            return rule.match.authURI ?? rule.id
        case .sudo:
            guard let pattern = rule.match.commandPattern, !pattern.isEmpty else {
                return "sudo (any command)"
            }
            return "sudo \((pattern as NSString).lastPathComponent)"
        }
    }

    static func detail(for rule: Rule) -> String {
        switch rule.type {
        case .authuri:
            if let branch = rule.appIdentity {
                let state = AuthURIIdentityScope.perAppPinsEnabled ? "" : " · per-app rules are disabled in this release; the right keeps its native definition"
                return "\(rule.match.authURI ?? "—") · app \(branch.bundleID) (\(branch.teamID))" + state
            }
            return rule.match.authURI ?? "—"
        case .sudo:
            if rule.match.matchType == .any || rule.match.commandPattern == nil {
                return "sudo · all commands"
            }
            return "sudo · \(rule.match.commandPattern ?? "")"
        }
    }
}

/// The full reply to a Sentinel `userRules` query: every loaded rule (the
/// profiles are device-scoped by MDM, so all of them apply to the console
/// user) plus the policy identity the popover shows alongside the list.
public struct SentinelRulesSnapshot: Codable, Sendable, Equatable {
    public let rules: [SentinelRuleSummary]
    /// Loaded profile keys, sorted — the popover's policy label.
    public let profileKeys: [String]
    /// Representative policy version (first sorted profile's), if any.
    public let policyVersion: String?
    public let enforcementMode: EnforcementMode
    public let generatedAt: Date

    public init(
        rules: [SentinelRuleSummary],
        profileKeys: [String],
        policyVersion: String?,
        enforcementMode: EnforcementMode,
        generatedAt: Date
    ) {
        self.rules = rules
        self.profileKeys = profileKeys
        self.policyVersion = policyVersion
        self.enforcementMode = enforcementMode
        self.generatedAt = generatedAt
    }

    /// Builds the snapshot from the daemon's loaded profiles. Rules are
    /// ordered the way they evaluate: profile priority first (lower wins),
    /// then rule priority within the profile.
    public init(profiles: [RuleProfile], enforcementMode: EnforcementMode, generatedAt: Date) {
        let orderedProfiles = profiles.sorted { lhs, rhs in
            (lhs.profilePriority, lhs.profileKey) < (rhs.profilePriority, rhs.profileKey)
        }
        var rules: [SentinelRuleSummary] = []
        for profile in orderedProfiles {
            for rule in profile.rules.sorted(by: { ($0.priority, $0.id) < ($1.priority, $1.id) }) {
                rules.append(SentinelRuleSummary(rule: rule, profile: profile, mode: enforcementMode))
            }
        }
        let sortedKeys = profiles.map(\.profileKey).sorted()
        self.init(
            rules: rules,
            profileKeys: sortedKeys,
            policyVersion: orderedProfiles.first?.policyVersion,
            enforcementMode: enforcementMode,
            generatedAt: generatedAt
        )
    }

    /// The empty snapshot (no profiles loaded / awaiting config).
    public static func empty(mode: EnforcementMode = .monitor, at date: Date) -> SentinelRulesSnapshot {
        SentinelRulesSnapshot(
            rules: [], profileKeys: [], policyVersion: nil,
            enforcementMode: mode, generatedAt: date
        )
    }
}
