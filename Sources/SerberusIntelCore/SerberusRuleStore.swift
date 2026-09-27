import Foundation
import PrivMgrCore

/// Whether a live authorization right is governed by a Serberus rule, and how.
public struct AuthorizationRuleTag: Sendable, Equatable {
    public let ruleID: String
    /// `.allow` or `.deny` — what the matching rule does.
    public let action: RuleAction
    /// The rule targets this right but ALSO pins the requesting binary's Team
    /// ID or hash. The authd log names the right, not the binary, so the live
    /// match is necessary but not sufficient — the tag says so rather than
    /// overclaiming that the rule would fire.
    public let identityGated: Bool
    /// The composed per-app branches for this right (identity-scoped rules),
    /// as row name + compiled requirement, in the composer's order. Empty
    /// when the right is not composed. Feeds the Capture's per-branch
    /// prediction (``BranchMatchResolver``).
    public let identityCandidates: [BranchMatchResolver.Candidate]

    public init(ruleID: String, action: RuleAction, identityGated: Bool,
                identityCandidates: [BranchMatchResolver.Candidate] = []) {
        self.ruleID = ruleID
        self.action = action
        self.identityGated = identityGated
        self.identityCandidates = identityCandidates
    }
}

/// Read-only view of the endpoint's Serberus authURI rules, for tagging live
/// authorization events with the rule (if any) that governs them.
///
/// Rules come from the world-readable managed-preference domains, so this needs
/// no privilege and no daemon — the same `ManagedPreferencesReader` the export
/// path uses. Matching is delegated to `RuleEngine.authURIRule` so Intel
/// never reimplements the daemon's rule semantics (exact, case-sensitive
/// equality; deny-before-allow ordering).
public struct SerberusRuleStore: Sendable {
    private let profiles: [RuleProfile]

    public init(profiles: [RuleProfile]) {
        self.profiles = profiles
    }

    /// Loads the effective rules from managed preferences. Cheap (a few small
    /// plists); safe to call again to pick up an MDM push mid-session.
    public static func load(reader: ManagedPreferencesReader = ManagedPreferencesReader()) -> SerberusRuleStore {
        SerberusRuleStore(profiles: reader.readRuleProfiles().value)
    }

    /// Number of authURI rules loaded — lets the UI distinguish "no rule for
    /// this right" from "no rules configured at all".
    public var authURIRuleCount: Int {
        profiles.reduce(0) { $0 + $1.rules.filter { $0.type == .authuri }.count }
    }

    /// The Serberus rule governing `right`, or `nil` if none targets it.
    public func tag(forRight right: String) -> AuthorizationRuleTag? {
        guard let rule = RuleEngine.authURIRule(matching: right, in: profiles) else { return nil }
        return AuthorizationRuleTag(
            ruleID: rule.id,
            action: rule.action,
            identityGated: rule.match.requiredTeamID != nil || rule.match.requiredBinaryHash != nil
                || rule.appIdentity != nil,
            identityCandidates: BranchMatchResolver.candidates(forRight: right, in: profiles)
        )
    }
}
