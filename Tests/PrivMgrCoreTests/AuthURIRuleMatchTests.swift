import Foundation
import Testing
@testable import PrivMgrCore

/// `RuleEngine.authURIRule(matching:in:)` is the matcher Serberus Intel's
/// live "matches a rule" tag calls. It must mirror the runtime authURI test
/// (exact, case-sensitive equality) and the evaluator's ordering, or the tag
/// would misrepresent what the daemon actually does.
@Suite("RuleEngine.authURIRule matcher")
struct AuthURIRuleMatchTests {
    private func authURIRule(
        id: String, action: RuleAction, right: String, priority: Int = 10,
        teamID: String? = nil, hash: String? = nil
    ) -> Rule {
        Rule(
            id: id, type: .authuri, action: action, description: id, priority: priority,
            match: MatchCriteria(authURI: right, requiredTeamID: teamID, requiredBinaryHash: hash)
        )
    }

    private func profile(_ rules: [Rule], key: String = "p", priority: Int = 0) -> RuleProfile {
        RuleProfile(policyVersion: "1", profileKey: key, profilePriority: priority, rules: rules)
    }

    @Test("exact right matches")
    func exactMatch() {
        let profiles = [profile([authURIRule(id: "deny-dt", action: .deny, right: "system.preferences.datetime")])]
        #expect(RuleEngine.authURIRule(matching: "system.preferences.datetime", in: profiles)?.id == "deny-dt")
    }

    @Test("a parent right does NOT match a more specific rule (no prefix semantics)")
    func noPrefixSemantics() {
        // The daemon does exact equality; system.preferences must not match a
        // rule targeting system.preferences.datetime, or the tag would claim
        // coverage the daemon doesn't provide.
        let profiles = [profile([authURIRule(id: "dt", action: .deny, right: "system.preferences.datetime")])]
        #expect(RuleEngine.authURIRule(matching: "system.preferences", in: profiles) == nil)
        #expect(RuleEngine.authURIRule(matching: "system.preferences.datetime.extra", in: profiles) == nil)
    }

    @Test("matching is case-sensitive")
    func caseSensitive() {
        let profiles = [profile([authURIRule(id: "dt", action: .deny, right: "system.preferences.datetime")])]
        #expect(RuleEngine.authURIRule(matching: "System.Preferences.Datetime", in: profiles) == nil)
    }

    @Test("an unconfigured right returns nil")
    func noMatch() {
        let profiles = [profile([authURIRule(id: "dt", action: .deny, right: "system.preferences.datetime")])]
        #expect(RuleEngine.authURIRule(matching: "system.preferences.security", in: profiles) == nil)
    }

    @Test("sudo rules are never matched for an authURI right")
    func ignoresSudoRules() {
        let sudo = Rule(id: "s", type: .sudo, action: .allow, description: "s", priority: 10,
                        match: MatchCriteria(commandPattern: "/usr/bin/whoami"))
        #expect(RuleEngine.authURIRule(matching: "/usr/bin/whoami", in: [profile([sudo])]) == nil)
    }

    @Test("when two rules target the same right, deny wins over allow (evaluator ordering)")
    func denyBeforeAllowSamePriority() {
        // Both at the same priority: the evaluator orders deny before allow, so
        // the tag must reflect the deny — the effective decision.
        let profiles = [profile([
            authURIRule(id: "allow-dt", action: .allow, right: "system.preferences.datetime", priority: 10),
            authURIRule(id: "deny-dt", action: .deny, right: "system.preferences.datetime", priority: 10),
        ])]
        #expect(RuleEngine.authURIRule(matching: "system.preferences.datetime", in: profiles)?.action == .deny)
    }

    @Test("lower priority number wins over deny-precedence")
    func priorityBeatsAction() {
        // Priority is ordered before action, so a priority-5 allow beats a
        // priority-10 deny.
        let profiles = [profile([
            authURIRule(id: "allow-hi", action: .allow, right: "system.preferences.datetime", priority: 5),
            authURIRule(id: "deny-lo", action: .deny, right: "system.preferences.datetime", priority: 10),
        ])]
        let matched = RuleEngine.authURIRule(matching: "system.preferences.datetime", in: profiles)
        #expect(matched?.id == "allow-hi")
    }

    @Test("identity pins do NOT stop the tag match (they are surfaced as a caveat instead)")
    func identityPinsStillMatch() {
        // The authd log has the right but not the binary's Team ID, so the
        // matcher answers "which rule targets this right"; the caller flags the
        // pin. A pinned rule must still be found.
        let profiles = [profile([
            authURIRule(id: "pinned", action: .allow, right: "system.preferences.printing", teamID: "ABC123"),
        ])]
        let matched = RuleEngine.authURIRule(matching: "system.preferences.printing", in: profiles)
        #expect(matched?.id == "pinned")
        #expect(matched?.match.requiredTeamID == "ABC123")
    }
}
