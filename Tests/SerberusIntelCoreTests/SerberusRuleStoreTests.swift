import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

@Suite("SerberusRuleStore tags")
struct SerberusRuleStoreTests {
    private func store(_ rules: [Rule]) -> SerberusRuleStore {
        SerberusRuleStore(profiles: [
            RuleProfile(policyVersion: "1", profileKey: "p", profilePriority: 0, rules: rules),
        ])
    }

    private func authURIRule(
        id: String, action: RuleAction, right: String, teamID: String? = nil
    ) -> Rule {
        Rule(id: id, type: .authuri, action: action, description: id, priority: 10,
             match: MatchCriteria(authURI: right, requiredTeamID: teamID))
    }

    @Test("a governed right yields a tag with the rule's id and action")
    func governedRight() throws {
        let tag = try #require(
            store([authURIRule(id: "deny-dt", action: .deny, right: "system.preferences.datetime")])
                .tag(forRight: "system.preferences.datetime")
        )
        #expect(tag.ruleID == "deny-dt")
        #expect(tag.action == .deny)
        #expect(!tag.identityGated)
    }

    @Test("an ungoverned right yields no tag")
    func ungovernedRight() {
        let s = store([authURIRule(id: "deny-dt", action: .deny, right: "system.preferences.datetime")])
        // The accessory right the user hit — captured, but not governed, which
        // is exactly the "worth authoring a rule" signal.
        #expect(s.tag(forRight: "system.preferences.security") == nil)
    }

    @Test("a rule with an identity pin is tagged but flagged binary-gated")
    func identityGatedTag() throws {
        let tag = try #require(
            store([authURIRule(id: "pin", action: .allow, right: "system.preferences.printing", teamID: "ABC")])
                .tag(forRight: "system.preferences.printing")
        )
        #expect(tag.identityGated)
    }

    @Test("authURIRuleCount reflects only authURI rules")
    func ruleCount() {
        let sudo = Rule(id: "s", type: .sudo, action: .allow, description: "s", priority: 10,
                        match: MatchCriteria(commandPattern: "/x"))
        let s = store([authURIRule(id: "a", action: .deny, right: "system.preferences.datetime"), sudo])
        #expect(s.authURIRuleCount == 1)
    }

    @Test("no rules configured yields no tags and zero count")
    func emptyStore() {
        let s = SerberusRuleStore(profiles: [])
        #expect(s.authURIRuleCount == 0)
        #expect(s.tag(forRight: "system.preferences.datetime") == nil)
    }
}
