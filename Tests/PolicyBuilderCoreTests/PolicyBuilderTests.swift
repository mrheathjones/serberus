import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

// MARK: - Shared fixtures

/// Fixture builders for the three-tier authoring model. Dates are pinned to
/// the shared test epoch (2026-06-12 UTC) so value comparisons never race the
/// wall clock.
private enum BuilderFixtures {
    static let now = Date(timeIntervalSince1970: 1_781_222_400) // 2026-06-12 UTC

    static func sudoDefinition(
        id: String,
        commandPattern: String? = "/opt/homebrew/bin/brew",
        argPattern: String? = nil,
        matchType: MatchType? = .exact,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil
    ) -> RuleDefinition {
        RuleDefinition(
            id: id, name: id, kind: .sudo,
            commandPattern: commandPattern, argPattern: argPattern, matchType: matchType,
            requiredTeamID: requiredTeamID, requiredBinaryHash: requiredBinaryHash,
            createdAt: now, updatedAt: now
        )
    }

    static func authuriDefinition(
        id: String,
        authURI: String? = "system.preferences.network"
    ) -> RuleDefinition {
        RuleDefinition(id: id, name: id, kind: .authuri, authURI: authURI,
                       createdAt: now, updatedAt: now)
    }

    static func rule(
        id: String,
        definitionIDs: [String] = [],
        action: RuleAction = .allow,
        elevationType: ElevationType = .silent,
        priority: Int = 10
    ) -> PolicyRule {
        PolicyRule(id: id, name: id, definitionIDs: definitionIDs,
                   action: action, elevationType: elevationType, priority: priority,
                   createdAt: now, updatedAt: now)
    }

    static func policy(
        id: String,
        ruleIDs: [String] = [],
        enabled: Bool = true,
        profilePriority: Int = 50
    ) -> Policy {
        Policy(id: id, name: id, enabled: enabled, profilePriority: profilePriority,
               rules: ruleIDs.map { PolicyRuleAssignment(ruleID: $0) },
               createdAt: now, updatedAt: now)
    }

    /// A small in-memory library exercising both mechanisms:
    /// - definitions: `brew_cli` (sudo), `network_prefs` (authuri)
    /// - rules: `allow_brew` → [brew_cli], `prompt_network` → [network_prefs]
    /// - policies: `dev` (both rules, enabled), `spare` (no rules)
    @MainActor
    static func standardModel() -> PolicyBuilderModel {
        PolicyBuilderModel(
            policies: [
                policy(id: "dev", ruleIDs: ["allow_brew", "prompt_network"]),
                policy(id: "spare", profilePriority: 60),
            ],
            rules: [
                rule(id: "allow_brew", definitionIDs: ["brew_cli"]),
                rule(id: "prompt_network", definitionIDs: ["network_prefs"],
                     elevationType: .prompt, priority: 20),
            ],
            definitions: [
                sudoDefinition(id: "brew_cli"),
                authuriDefinition(id: "network_prefs"),
            ]
        )
    }
}

// MARK: - Drafts

@MainActor
@Suite("RuleDraft ↔ PolicyRule conversion")
struct RuleDraftTests {
    @Test("a fully-specified rule round-trips through the draft")
    func roundTrip() {
        let rule = PolicyRule(
            id: "allow_brew", name: "Allow Homebrew", detail: "Package operations",
            definitionIDs: ["brew_cli", "port_cli"],
            action: .deny, elevationType: .prompt,
            priority: 7, useGlobalCache: false, cacheSeconds: 300,
            requireJustification: true, maxGrantDurationSeconds: 900,
            logArguments: false,
            createdAt: BuilderFixtures.now, updatedAt: BuilderFixtures.now
        )

        let draft = RuleDraft(rule: rule)
        #expect(draft.ruleID == "allow_brew")
        #expect(draft.name == "Allow Homebrew")
        #expect(draft.detail == "Package operations")
        #expect(draft.definitionIDs == ["brew_cli", "port_cli"])
        #expect(draft.action == .deny)
        #expect(draft.elevationType == .prompt)
        #expect(draft.priority == 7)
        #expect(draft.useGlobalCache == false)
        #expect(draft.cacheSeconds == 300)
        #expect(draft.requireJustification)
        #expect(draft.maxGrantDurationSeconds == 900)
        #expect(draft.logArguments == false)

        // Back to the value type: every persisted field survives (timestamps
        // are stamped fresh — the model preserves createdAt on upsert).
        let committed = draft.toPolicyRule()
        #expect(committed.id == rule.id)
        #expect(committed.name == rule.name)
        #expect(committed.detail == rule.detail)
        #expect(committed.definitionIDs == rule.definitionIDs)
        #expect(committed.action == rule.action)
        #expect(committed.elevationType == rule.elevationType)
        #expect(committed.priority == rule.priority)
        #expect(committed.useGlobalCache == rule.useGlobalCache)
        #expect(committed.cacheSeconds == rule.cacheSeconds)
        #expect(committed.requireJustification == rule.requireJustification)
        #expect(committed.maxGrantDurationSeconds == rule.maxGrantDurationSeconds)
        #expect(committed.logArguments == rule.logArguments)
    }

    @Test("a fresh draft carries the composer defaults")
    func freshDraftDefaults() {
        let draft = RuleDraft()
        #expect(draft.ruleID.isEmpty)
        #expect(draft.definitionIDs.isEmpty)
        #expect(draft.action == .allow)
        #expect(draft.elevationType == .silent)
        #expect(draft.priority == 50)
        #expect(draft.useGlobalCache)
        #expect(draft.cacheSeconds == 0)
        #expect(!draft.requireJustification)
        #expect(draft.maxGrantDurationSeconds == 0)
        #expect(!draft.logArguments)
    }

    @Test("the composer commit pattern uniquifies the slug before upserting")
    func commitPattern() {
        let model = BuilderFixtures.standardModel()
        var draft = RuleDraft()
        draft.name = "Allow Brew" // slug collides with the existing "allow_brew"
        draft.definitionIDs = ["brew_cli"]
        let base = AuthoringID.slugify(draft.name)
        draft.ruleID = AuthoringID.uniqueID(base: base.isEmpty ? "rule" : base,
                                            existing: Set(model.rules.map(\.id)))
        model.upsertRule(draft.toPolicyRule())
        #expect(draft.ruleID == "allow_brew_2")
        #expect(model.rule(id: "allow_brew")?.name == "allow_brew") // pre-existing untouched
        #expect(model.rule(id: "allow_brew_2")?.name == "Allow Brew")
        #expect(model.rule(id: "allow_brew_2")?.definitionIDs == ["brew_cli"])
    }
}

@MainActor
@Suite("DefinitionDraft ↔ RuleDefinition conversion")
struct DefinitionDraftTests {
    @Test("a sudo definition round-trips through the draft")
    func sudoRoundTrip() {
        let definition = RuleDefinition(
            id: "brew_cli", name: "Homebrew CLI", detail: "Package manager",
            kind: .sudo,
            commandPattern: "/opt/homebrew/bin/brew",
            argPattern: "install|upgrade",
            matchType: .prefixRegex,
            requiredTeamID: "TEAM123456",
            requiredBinaryHash: "abc123",
            createdAt: BuilderFixtures.now, updatedAt: BuilderFixtures.now
        )

        let draft = DefinitionDraft(definition: definition)
        #expect(draft.definitionID == "brew_cli")
        #expect(draft.kind == .sudo)
        #expect(draft.commandPattern == "/opt/homebrew/bin/brew")
        #expect(draft.argPattern == "install|upgrade")
        #expect(draft.matchType == .prefixRegex)
        #expect(draft.requiredTeamID == "TEAM123456")
        #expect(draft.requiredBinaryHash == "abc123")
        #expect(draft.authURI.isEmpty)

        let committed = draft.toDefinition()
        #expect(committed.id == definition.id)
        #expect(committed.kind == .sudo)
        #expect(committed.commandPattern == definition.commandPattern)
        #expect(committed.argPattern == definition.argPattern)
        #expect(committed.matchType == definition.matchType)
        #expect(committed.requiredTeamID == definition.requiredTeamID)
        #expect(committed.requiredBinaryHash == definition.requiredBinaryHash)
        #expect(committed.authURI == nil)
    }

    @Test("empty fields collapse to nil and identity pins are trimmed")
    func emptyFieldsCollapse() {
        var draft = DefinitionDraft(definitionID: "d", kind: .sudo, name: "d")
        draft.commandPattern = "/bin/x"
        draft.requiredTeamID = "   "
        draft.requiredBinaryHash = " abc123 "
        let definition = draft.toDefinition()
        #expect(definition.argPattern == nil)
        #expect(definition.requiredTeamID == nil)      // whitespace-only → nil
        #expect(definition.requiredBinaryHash == "abc123") // trimmed
    }

    @Test("conversion is kind-shaped — stale cross-kind fields never leak")
    func kindShaped() {
        // An editor session that typed sudo fields, then switched to authuri.
        var draft = DefinitionDraft(definitionID: "net", kind: .sudo, name: "Network")
        draft.commandPattern = "/stale/path"
        draft.argPattern = "stale"
        draft.kind = .authuri
        draft.authURI = "system.preferences.network"

        let definition = draft.toDefinition()
        #expect(definition.kind == .authuri)
        #expect(definition.authURI == "system.preferences.network")
        #expect(definition.commandPattern == nil)
        #expect(definition.argPattern == nil)
        #expect(definition.matchType == nil)
    }

    @Test("reverse init flattens optionals to bindable sentinels")
    func reverseDefaults() {
        let definition = RuleDefinition(id: "bare", name: "Bare", kind: .sudo,
                                        commandPattern: "/bin/x",
                                        createdAt: BuilderFixtures.now, updatedAt: BuilderFixtures.now)
        let draft = DefinitionDraft(definition: definition)
        #expect(draft.matchType == .exact) // nil matchType defaults to .exact on the wire
        #expect(draft.authURI.isEmpty)
        #expect(draft.argPattern.isEmpty)
        #expect(draft.requiredTeamID.isEmpty)
    }
}

// MARK: - Naming helpers

@MainActor
@Suite("AuthoringID + name derivation")
struct AuthoringIDTests {
    @Test("slugify lowercases, maps punctuation to underscores, and collapses runs")
    func slugifyMapping() {
        #expect(AuthoringID.slugify("New Policy") == "new_policy")
        #expect(AuthoringID.slugify("Homebrew — install / upgrade!") == "homebrew_install_upgrade")
        #expect(AuthoringID.slugify("already_slugged") == "already_slugged")
        #expect(AuthoringID.slugify("!!!").isEmpty)
        #expect(PolicyBuilderModel.slugify("New Policy") == "new_policy") // model forwards
    }

    @Test("uniqueID suffixes with _2, _3, … only on collision")
    func uniqueIDSuffixes() {
        #expect(AuthoringID.uniqueID(base: "brew", existing: []) == "brew")
        #expect(AuthoringID.uniqueID(base: "brew", existing: ["brew"]) == "brew_2")
        #expect(AuthoringID.uniqueID(base: "brew", existing: ["brew", "brew_2"]) == "brew_3")
    }

    @Test("humanize derives display names from profile keys and bare slugs")
    func humanize() {
        #expect(Policy.humanize("rules_sudo_developer_tools") == "Developer Tools")
        #expect(Policy.humanize("rules_authuri_admin_settings") == "Admin Settings")
        #expect(Policy.humanize("developer_tools") == "Developer Tools")
    }
}

// MARK: - Policy CRUD

@MainActor
@Suite("PolicyBuilderModel — policy CRUD")
struct PolicyCRUDTests {
    @Test("newPolicy slugs the id, uniquifies collisions, and steps priority")
    func newPolicyCreates() {
        let model = PolicyBuilderModel()
        let first = model.newPolicy()
        let second = model.newPolicy()
        #expect(first == "new_policy")
        #expect(second == "new_policy_2")
        #expect(model.policies.map(\.id) == ["new_policy", "new_policy_2"])
        #expect(model.policy(id: first)?.profilePriority == 50)   // (max ?? 40) + 10
        #expect(model.policy(id: second)?.profilePriority == 60)
        #expect(model.policy(id: first)?.enabled == true)
        #expect(model.policy(id: first)?.policyVersion == "1.0.0")
        // Creation never navigates — callers pair with openPolicyEditor.
        #expect(model.selectedSection == .dashboard)

        // An unsluggable name falls back to the tier's base word.
        #expect(model.newPolicy(name: "!!!") == "policy")
    }

    @Test("updatePolicy upserts by id and preserves the stored createdAt")
    func updatePolicyPreservesCreatedAt() {
        let model = BuilderFixtures.standardModel()
        var edited = model.policy(id: "dev")!
        edited.name = "Developer Tools"
        edited.createdAt = Date() // editors may carry a stale value; the store wins
        model.updatePolicy(edited)
        let stored = model.policy(id: "dev")!
        #expect(stored.name == "Developer Tools")
        #expect(stored.createdAt == BuilderFixtures.now)
        #expect(stored.updatedAt > BuilderFixtures.now)

        // Unknown id appends (upsert).
        model.updatePolicy(BuilderFixtures.policy(id: "fresh"))
        #expect(model.policy(id: "fresh") != nil)
        #expect(model.policies.count == 3)
    }

    @Test("deletePolicies(ids:) removes the batch, ignores unknown ids, keeps rules and definitions")
    func deletePoliciesBatch() {
        let model = BuilderFixtures.standardModel()
        model.deletePolicies(ids: ["dev", "ghost"])
        #expect(model.policies.map(\.id) == ["spare"])
        #expect(model.rules.count == 2)
        #expect(model.definitions.count == 2)
        let before = model.policies
        model.deletePolicies(ids: [])
        #expect(model.policies == before)
        model.deletePolicies(ids: ["spare"])
        #expect(model.policies.isEmpty)
    }

    @Test("deletePolicy removes the policy but keeps its shared rules")
    func deletePolicyKeepsRules() {
        let model = BuilderFixtures.standardModel()
        model.deletePolicy(id: "dev")
        #expect(model.policy(id: "dev") == nil)
        #expect(model.rules.map(\.id) == ["allow_brew", "prompt_network"])
        #expect(model.definitions.count == 2)
    }

    @Test("duplicatePolicy copies assignments under <id>_copy with a fresh priority")
    func duplicatePolicy() {
        let model = BuilderFixtures.standardModel()
        let copyID = model.duplicatePolicy(id: "dev")
        #expect(copyID == "dev_copy")
        let copy = model.policy(id: "dev_copy")!
        #expect(copy.name == "dev (Copy)")
        #expect(copy.profilePriority == 70) // max(50, 60) + 10
        #expect(copy.rules.map(\.ruleID) == ["allow_brew", "prompt_network"])

        // Duplicating again suffixes; a missing source returns nil.
        #expect(model.duplicatePolicy(id: "dev") == "dev_copy_2")
        #expect(model.duplicatePolicy(id: "ghost") == nil)
    }

    @Test("per-policy rule toggles flip the assignment and gate compilation")
    func setRuleTogglesCompile() {
        let model = BuilderFixtures.standardModel()
        model.setRule("allow_brew", enabled: false, inPolicy: "dev")
        #expect(model.policy(id: "dev")?.rules.first { $0.ruleID == "allow_brew" }?.enabled == false)
        #expect(model.compiledProfiles(forPolicy: "dev").map(\.profileKey) == ["rules_authuri_dev"])

        model.setRule("allow_brew", enabled: true, inPolicy: "dev")
        #expect(model.compiledProfiles(forPolicy: "dev").map(\.profileKey)
                == ["rules_authuri_dev", "rules_sudo_dev"])

        // Unknown rule or policy is a no-op.
        model.setRule("ghost", enabled: false, inPolicy: "dev")
        model.setRule("allow_brew", enabled: false, inPolicy: "ghost")
        #expect(model.policy(id: "dev")?.rules.allSatisfy { $0.enabled } == true)
    }

    @Test("addRule appends an enabled assignment with library-membership guards")
    func addRuleGuards() {
        let model = BuilderFixtures.standardModel()
        model.addRule("allow_brew", toPolicy: "spare")
        #expect(model.policy(id: "spare")?.rules.map(\.ruleID) == ["allow_brew"])
        #expect(model.policy(id: "spare")?.rules.first?.enabled == true)

        // No dangling refs by construction: unknown rule, unknown policy, and
        // an existing assignment are all no-ops.
        model.addRule("ghost", toPolicy: "spare")
        model.addRule("allow_brew", toPolicy: "ghost")
        model.addRule("allow_brew", toPolicy: "spare")
        #expect(model.policy(id: "spare")?.rules.count == 1)
    }

    @Test("removeRule drops the assignment but keeps the library rule")
    func removeRuleKeepsLibrary() {
        let model = BuilderFixtures.standardModel()
        model.removeRule("allow_brew", fromPolicy: "dev")
        #expect(model.policy(id: "dev")?.rules.map(\.ruleID) == ["prompt_network"])
        #expect(model.rule(id: "allow_brew") != nil)

        // Unknown assignment or policy is a no-op.
        model.removeRule("allow_brew", fromPolicy: "dev")
        model.removeRule("prompt_network", fromPolicy: "ghost")
        #expect(model.policy(id: "dev")?.rules.count == 1)
    }

    @Test("bumpPolicyVersion patch-bumps semver and ignores unparseable versions")
    func bumpVersion() {
        let model = BuilderFixtures.standardModel()
        model.bumpPolicyVersion(id: "dev")
        #expect(model.policy(id: "dev")?.policyVersion == "1.0.1")

        var odd = model.policy(id: "spare")!
        odd.policyVersion = "beta"
        model.updatePolicy(odd)
        model.bumpPolicyVersion(id: "spare")
        #expect(model.policy(id: "spare")?.policyVersion == "beta")
    }

    @Test("nextPatchVersion accepts only strict numeric semver")
    func nextPatchVersionParsing() {
        #expect(PolicyBuilderModel.nextPatchVersion(of: "1.0.0") == "1.0.1")
        #expect(PolicyBuilderModel.nextPatchVersion(of: "0.9.9") == "0.9.10")
        #expect(PolicyBuilderModel.nextPatchVersion(of: "1.0") == nil)
        #expect(PolicyBuilderModel.nextPatchVersion(of: "v1.0.0") == nil)
        #expect(PolicyBuilderModel.nextPatchVersion(of: "1.0.0-beta") == nil)
        #expect(PolicyBuilderModel.nextPatchVersion(of: "beta") == nil)
    }
}

// MARK: - Rule CRUD

@MainActor
@Suite("PolicyBuilderModel — rule CRUD")
struct RuleCRUDTests {
    @Test("newRule creates with standard defaults and a unique slug")
    func newRuleDefaults() {
        let model = PolicyBuilderModel()
        let first = model.newRule()
        #expect(first == "new_rule")
        #expect(model.newRule() == "new_rule_2")
        let rule = model.rule(id: first)!
        #expect(rule.action == .allow)
        #expect(rule.elevationType == .silent)
        #expect(rule.priority == 50)
        #expect(rule.useGlobalCache)
        #expect(rule.definitionIDs.isEmpty)
    }

    @Test("upsertRule replaces by id, preserving the stored createdAt")
    func upsertRulePreservesCreatedAt() {
        let model = BuilderFixtures.standardModel()
        var edited = model.rule(id: "allow_brew")!
        edited.priority = 99
        model.upsertRule(edited)
        let stored = model.rule(id: "allow_brew")!
        #expect(stored.priority == 99)
        #expect(stored.createdAt == BuilderFixtures.now)
        #expect(model.rules.count == 2)

        // Unknown id appends.
        model.upsertRule(BuilderFixtures.rule(id: "fresh_rule"))
        #expect(model.rules.count == 3)
    }

    @Test("deleteRule cascades: assignments vanish from every policy")
    func deleteRuleCascades() {
        let model = BuilderFixtures.standardModel()
        model.addRule("allow_brew", toPolicy: "spare") // now assigned twice
        model.deleteRule(id: "allow_brew")

        #expect(model.rule(id: "allow_brew") == nil)
        #expect(model.policy(id: "dev")?.rules.map(\.ruleID) == ["prompt_network"])
        #expect(model.policy(id: "spare")?.rules.isEmpty == true)
        // Unrelated assignments and the definition library are untouched.
        #expect(model.rule(id: "prompt_network") != nil)
        #expect(model.definitions.count == 2)
    }

    @Test("duplicateRule copies definition refs but starts unassigned")
    func duplicateRuleUnassigned() {
        let model = BuilderFixtures.standardModel()
        let copyID = model.duplicateRule(id: "allow_brew")
        #expect(copyID == "allow_brew_copy")
        let copy = model.rule(id: "allow_brew_copy")!
        #expect(copy.name == "allow_brew (Copy)")
        #expect(copy.definitionIDs == ["brew_cli"])
        #expect(model.policiesUsing(ruleID: "allow_brew_copy").isEmpty)
        #expect(model.duplicateRule(id: "ghost") == nil)
    }
}

// MARK: - Definition CRUD

@MainActor
@Suite("PolicyBuilderModel — definition CRUD")
struct DefinitionCRUDTests {
    @Test("newDefinition seeds kind-appropriate matcher fields")
    func newDefinitionKindDefaults() {
        let model = PolicyBuilderModel()
        let sudoID = model.newDefinition(kind: .sudo)
        let authID = model.newDefinition(kind: .authuri)
        #expect(sudoID == "new_definition")
        #expect(authID == "new_definition_2")

        let sudo = model.definition(id: sudoID)!
        #expect(sudo.kind == .sudo)
        #expect(sudo.matchType == .exact)
        let auth = model.definition(id: authID)!
        #expect(auth.kind == .authuri)
        #expect(auth.matchType == nil)
        #expect(auth.authURI == nil)
    }

    @Test("upsertDefinition replaces by id, preserving the stored createdAt")
    func upsertDefinitionPreservesCreatedAt() {
        let model = BuilderFixtures.standardModel()
        var edited = model.definition(id: "brew_cli")!
        edited.commandPattern = "/usr/local/bin/brew"
        model.upsertDefinition(edited)
        let stored = model.definition(id: "brew_cli")!
        #expect(stored.commandPattern == "/usr/local/bin/brew")
        #expect(stored.createdAt == BuilderFixtures.now)
        #expect(model.definitions.count == 2)
    }

    @Test("deleteDefinition cascades: refs vanish from every rule")
    func deleteDefinitionCascades() {
        let model = BuilderFixtures.standardModel()
        var shared = model.rule(id: "prompt_network")!
        shared.definitionIDs = ["network_prefs", "brew_cli"] // second referent
        model.upsertRule(shared)

        model.deleteDefinition(id: "brew_cli")
        #expect(model.definition(id: "brew_cli") == nil)
        #expect(model.rule(id: "allow_brew")?.definitionIDs.isEmpty == true)
        #expect(model.rule(id: "prompt_network")?.definitionIDs == ["network_prefs"])
        // The rules themselves survive — only the references are removed.
        #expect(model.rules.count == 2)
    }

    @Test("deleteRules(ids:) cascades the whole batch out of every policy and persists once")
    func deleteRulesBatchCascades() {
        let model = BuilderFixtures.standardModel()
        model.addRule("prompt_network", toPolicy: "spare")
        #expect(model.policy(id: "spare")?.rules.map(\.ruleID) == ["prompt_network"])

        model.deleteRules(ids: ["allow_brew", "prompt_network", "ghost"])
        #expect(model.rules.isEmpty)
        #expect(model.policy(id: "dev")?.rules.isEmpty == true)
        #expect(model.policy(id: "spare")?.rules.isEmpty == true)
        // Definitions are untouched — only the rule tier was deleted.
        #expect(model.definitions.count == 2)

        let before = model.policies
        model.deleteRules(ids: [])
        #expect(model.policies == before)
    }

    @Test("deleteDefinitions(ids:) cascades the whole batch and leaves unrelated refs alone")
    func deleteDefinitionsBatchCascades() {
        let model = BuilderFixtures.standardModel()
        var shared = model.rule(id: "prompt_network")!
        shared.definitionIDs = ["network_prefs", "brew_cli"]
        model.upsertRule(shared)
        model.upsertDefinition(BuilderFixtures.sudoDefinition(id: "keeper"))
        var brewRule = model.rule(id: "allow_brew")!
        brewRule.definitionIDs = ["brew_cli", "keeper"]
        model.upsertRule(brewRule)

        model.deleteDefinitions(ids: ["brew_cli", "network_prefs", "ghost"])
        #expect(model.definition(id: "brew_cli") == nil)
        #expect(model.definition(id: "network_prefs") == nil)
        #expect(model.definition(id: "keeper") != nil)
        // Both referents stripped from the shared rule; the unrelated one survives.
        #expect(model.rule(id: "prompt_network")?.definitionIDs.isEmpty == true)
        #expect(model.rule(id: "allow_brew")?.definitionIDs == ["keeper"])
        #expect(model.rules.count == 2)

        // An empty batch is a no-op.
        let before = model.definitions
        model.deleteDefinitions(ids: [])
        #expect(model.definitions == before)
    }

    @Test("duplicateDefinition starts unused by any rule")
    func duplicateDefinitionUnused() {
        let model = BuilderFixtures.standardModel()
        let copyID = model.duplicateDefinition(id: "brew_cli")
        #expect(copyID == "brew_cli_copy")
        #expect(model.definition(id: "brew_cli_copy")?.name == "brew_cli (Copy)")
        #expect(model.rulesUsing(definitionID: "brew_cli_copy").isEmpty)
        #expect(model.duplicateDefinition(id: "ghost") == nil)
    }
}

// MARK: - Lookups

@MainActor
@Suite("PolicyBuilderModel — lookups")
struct LookupTests {
    @Test("rules(in:) surfaces dangling assignments instead of hiding them")
    func rulesInPolicyIncludesDangling() {
        let model = BuilderFixtures.standardModel()
        var dev = model.policy(id: "dev")!
        dev.rules.append(PolicyRuleAssignment(ruleID: "ghost"))
        model.updatePolicy(dev)

        let pairs = model.rules(in: model.policy(id: "dev")!)
        #expect(pairs.map(\.assignment.ruleID) == ["allow_brew", "prompt_network", "ghost"])
        #expect(pairs[0].rule?.id == "allow_brew")
        #expect(pairs[2].rule == nil)
    }

    @Test("definitions(in:) drops dangling references")
    func definitionsInRuleDropsDangling() {
        let model = BuilderFixtures.standardModel()
        var rule = model.rule(id: "allow_brew")!
        rule.definitionIDs = ["brew_cli", "ghost"]
        model.upsertRule(rule)
        #expect(model.definitions(in: model.rule(id: "allow_brew")!).map(\.id) == ["brew_cli"])
    }

    @Test("usage queries count references across tiers, enabled or not")
    func usageQueries() {
        let model = BuilderFixtures.standardModel()
        model.addRule("allow_brew", toPolicy: "spare")
        model.setRule("allow_brew", enabled: false, inPolicy: "spare")

        #expect(model.policiesUsing(ruleID: "allow_brew").map(\.id) == ["dev", "spare"])
        #expect(model.policiesUsing(ruleID: "ghost").isEmpty)
        #expect(model.rulesUsing(definitionID: "brew_cli").map(\.id) == ["allow_brew"])
        #expect(model.rulesUsing(definitionID: "ghost").isEmpty)
    }
}

// MARK: - Navigation

@MainActor
@Suite("PolicyBuilderModel — navigation")
struct NavigationTests {
    @Test("openRuleEditor navigates to Rules and stages the deep link")
    func openRuleEditor() {
        let model = BuilderFixtures.standardModel()
        model.openRuleEditor(ruleID: "allow_brew")
        #expect(model.selectedSection == .rules)
        #expect(model.pendingFocus == .rule(id: "allow_brew"))

        // nil just switches screens (create-new flow).
        model.openRuleEditor(ruleID: nil)
        #expect(model.selectedSection == .rules)
        #expect(model.pendingFocus == nil)
    }

    @Test("openPolicyEditor and openDefinitionEditor target their screens")
    func openOtherEditors() {
        let model = BuilderFixtures.standardModel()
        model.openPolicyEditor(policyID: "dev")
        #expect(model.selectedSection == .policies)
        #expect(model.pendingFocus == .policy(id: "dev"))

        model.openDefinitionEditor(definitionID: "brew_cli")
        #expect(model.selectedSection == .definitions)
        #expect(model.pendingFocus == .definition(id: "brew_cli"))

        model.openDefinitionEditor(definitionID: nil)
        #expect(model.pendingFocus == nil)
    }

    @Test("the policy sidebar group carries the three tiers plus the simulator")
    func sidebarPolicyGroup() {
        #expect(SidebarGroup.policy.sections == [.policies, .rules, .definitions, .decisionSimulator])
    }
}

// MARK: - Compile plumbing

@MainActor
@Suite("PolicyBuilderModel — compile, validation, and export plumbing")
struct CompilePlumbingTests {
    @Test("compiledProfiles() compiles every policy — the legacy enabled flag is ignored")
    func legacyEnabledFlagIgnored() {
        let model = BuilderFixtures.standardModel()
        var dev = model.policy(id: "dev")!
        dev.enabled = false // a pre-2026-08-22 library could still say this
        model.updatePolicy(dev)

        // "spare" has no rules, so the library compiles to exactly dev's two.
        #expect(model.compiledProfiles().map(\.profileKey) == ["rules_authuri_dev", "rules_sudo_dev"])
        #expect(model.compiledProfiles(forPolicy: "dev").map(\.profileKey)
                == ["rules_authuri_dev", "rules_sudo_dev"])
        #expect(model.compiledProfiles(forPolicy: "ghost").isEmpty)
    }

    @Test("direct publish is gated by the managed commanderPublishEnabled key, refreshable at runtime")
    func directPublishGate() {
        func reader(_ enabled: Bool?) -> ManagedPreferencesReader {
            var config: [String: any Sendable] = [:]
            if let enabled { config["commanderPublishEnabled"] = enabled }
            return ManagedPreferencesReader(source: DictionaryPreferencesSource(
                domains: [BundleConfig.configDomain: config]))
        }
        let fixture = BuilderFixtures.standardModel()
        // Absent key ⇒ off, so nothing is publishable however healthy the policy.
        let off = PolicyBuilderModel(policies: fixture.policies, rules: fixture.rules,
                                     definitions: fixture.definitions, preferencesReader: reader(nil))
        #expect(!off.directPublishEnabled)
        #expect(!off.canPublishToMDM(id: "dev"))
        #expect(off.publishBlocker(id: "dev")?.contains("commanderPublishEnabled") == true)

        #expect(PolicyBuilderModel(preferencesReader: reader(true)).directPublishEnabled)
        #expect(!PolicyBuilderModel(preferencesReader: reader(false)).directPublishEnabled)

        // Refresh re-reads managed preferences: an MDM push can flip the key
        // either way while Commander is open, including removing it.
        let source = MutablePreferencesSource()
        let live = PolicyBuilderModel(policies: fixture.policies, rules: fixture.rules,
                                      definitions: fixture.definitions,
                                      preferencesReader: ManagedPreferencesReader(source: source))
        #expect(!live.directPublishEnabled)
        source.set([BundleConfig.configDomain: ["commanderPublishEnabled": true]])
        live.refreshDirectPublishGate()
        #expect(live.directPublishEnabled)
        source.set([BundleConfig.configDomain: ["commanderPublishEnabled": false]])
        live.refreshDirectPublishGate()
        #expect(!live.directPublishEnabled)
        source.set([BundleConfig.configDomain: ["commanderPublishEnabled": true]])
        live.refreshDirectPublishGate()
        source.set([:]) // profile removed entirely
        live.refreshDirectPublishGate()
        #expect(!live.directPublishEnabled)
    }

    @Test("with the gate on and a complete connection, a healthy policy is publishable — and the gate is the discriminating term")
    func directPublishPositivePath() {
        let fixture = BuilderFixtures.standardModel()
        func model(gate: Bool) -> PolicyBuilderModel {
            let m = PolicyBuilderModel(policies: fixture.policies, rules: fixture.rules,
                                       definitions: fixture.definitions,
                                       preferencesReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(
                                           domains: [BundleConfig.configDomain: ["commanderPublishEnabled": gate]])))
            // A complete connection, set directly (save() would touch the
            // Keychain + UserDefaults.standard).
            m.mdm.instanceURL = "https://example.jamfcloud.com"
            m.mdm.clientID = "client"
            m.mdm.clientSecret = "secret"
            return m
        }
        let on = model(gate: true)
        #expect(on.publishBlocker(id: "dev") == nil)
        #expect(on.canPublishToMDM(id: "dev"))
        // Same connection, same policy, gate off ⇒ not publishable.
        #expect(!model(gate: false).canPublishToMDM(id: "dev"))
        // Gate on but the policy compiles to nothing ⇒ the blocker says so.
        #expect(on.publishBlocker(id: "spare")?.contains("no profiles") == true)
        #expect(!on.canPublishToMDM(id: "spare"))
        // Connection incomplete ⇒ the blocker names Settings.
        on.mdm.clientSecret = ""
        #expect(on.publishBlocker(id: "dev")?.contains("Settings") == true)
    }

    @Test("publishPolicies records one summary, names each failed policy, and leaves nothing in flight")
    func publishPoliciesSummary() async {
        let fixture = BuilderFixtures.standardModel()
        let gated = PolicyBuilderModel(
            policies: fixture.policies, rules: fixture.rules, definitions: fixture.definitions,
            preferencesReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:])))
        #expect(gated.lastPublishSummary == nil)

        // Batch: every policy fails at the gate, each named in the summary.
        let batch = await gated.publishPolicies(ids: ["dev", "spare"])
        #expect(!batch.isSuccess)
        #expect(batch.published.isEmpty)
        #expect(batch.failed.count == 2)
        #expect(batch.title == "Publish failed")
        #expect(batch.message.contains("dev") && batch.message.contains("spare"))
        #expect(gated.lastPublishSummary == batch)
        #expect(gated.publishingPolicyIDs.isEmpty)

        // Single: reads like the plain outcome headline.
        let single = await gated.publishPolicies(ids: ["dev"])
        #expect(single.title == "Publish failed")
        #expect(single.message.contains("commanderPublishEnabled"))
        #expect(!single.message.hasPrefix("dev:"))
        #expect(gated.lastPublishSummary == single)
    }

    @Test("publishPolicyToMDM refuses while the gate is off — the hidden button is not the only guard")
    func publishRefusedWhenGateOff() async {
        let fixture = BuilderFixtures.standardModel()
        let gated = PolicyBuilderModel(
            policies: fixture.policies, rules: fixture.rules, definitions: fixture.definitions,
            preferencesReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:])))
        let result = await gated.publishPolicyToMDM(id: "dev")
        #expect(!result.isSuccess)
        #expect(result.headline.contains("commanderPublishEnabled"))
    }

    @Test("validationReport yields one clean report per compiled profile")
    func validationReports() {
        let model = BuilderFixtures.standardModel()
        let reports = model.validationReport(forPolicy: "dev")
        #expect(reports.count == 2)
        #expect(reports.map(\.profileKey) == ["rules_authuri_dev", "rules_sudo_dev"])
        #expect(reports.allSatisfy { $0.isExportable })

        // A policy compiling to nothing is a distinct state: empty array.
        #expect(model.validationReport(forPolicy: "spare").isEmpty)
        #expect(model.validationReport(forPolicy: "ghost").isEmpty)
    }

    @Test("validationReport surfaces compiled-content errors")
    func validationReportsErrors() {
        // A sudo definition with no command pattern compiles to a wire rule
        // the validator must reject (matchType .exact requires a pattern).
        let model = PolicyBuilderModel(
            policies: [BuilderFixtures.policy(id: "bad", ruleIDs: ["broken"])],
            rules: [BuilderFixtures.rule(id: "broken", definitionIDs: ["no_command"])],
            definitions: [BuilderFixtures.sudoDefinition(id: "no_command", commandPattern: nil)]
        )
        let reports = model.validationReport(forPolicy: "bad")
        #expect(reports.count == 1)
        #expect(reports.first?.isExportable == false)
        #expect(reports.first?.errors.contains { $0.check == "command-pattern" } == true)
    }

    @Test("prepareExport validates every compiled profile and unlocks export")
    func prepareExportForPolicy() {
        let model = BuilderFixtures.standardModel()
        model.prepareExport(forPolicy: "dev")
        #expect(model.export.reports.map(\.profileKey) == ["rules_authuri_dev", "rules_sudo_dev"])
        #expect(model.export.preparedProfiles.count == 2)
        #expect(model.export.errorCount == 0)
        #expect(model.export.canExport())

        let export = model.export.export(profiles: model.compiledProfiles(forPolicy: "dev"))
        #expect(export != nil)
        #expect((export?.data.isEmpty ?? true) == false)
    }

    @Test("prepareExport on a policy that compiles to nothing blocks with a reason")
    func prepareExportEmptyPolicy() {
        let model = BuilderFixtures.standardModel()
        model.prepareExport(forPolicy: "spare")
        #expect(model.export.reports.isEmpty)
        #expect(!model.export.canExport())
        #expect(model.export.blockingReason()?.contains("compiles to no profiles") == true)
    }
}

// MARK: - Decision Simulator parity

@MainActor
@Suite("DecisionSimulatorModel — engine parity over compiled profiles")
struct DecisionSimulatorModelTests {
    private static let now = Date(timeIntervalSince1970: 1_781_222_400)

    /// A library compiling to one sudo profile with a deny-uninstall rule
    /// (priority 1) ahead of an allow-install rule (priority 5) — the same
    /// shape the pre-rework parity suite pinned, now expressed in three tiers.
    private func simulatorModel() -> PolicyBuilderModel {
        let definitions = [
            RuleDefinition(id: "brew_uninstall", name: "brew uninstall", kind: .sudo,
                           commandPattern: "/opt/homebrew/bin/brew", argPattern: "uninstall",
                           matchType: .prefixRegex, createdAt: Self.now, updatedAt: Self.now),
            RuleDefinition(id: "brew_install", name: "brew install", kind: .sudo,
                           commandPattern: "/opt/homebrew/bin/brew", argPattern: "install|upgrade",
                           matchType: .prefixRegex, createdAt: Self.now, updatedAt: Self.now),
        ]
        let rules = [
            PolicyRule(id: "deny_uninstall", name: "Deny uninstalls",
                       definitionIDs: ["brew_uninstall"], action: .deny, priority: 1,
                       createdAt: Self.now, updatedAt: Self.now),
            PolicyRule(id: "allow_install", name: "Allow installs",
                       definitionIDs: ["brew_install"], action: .allow, priority: 5,
                       createdAt: Self.now, updatedAt: Self.now),
        ]
        let policy = Policy(id: "brew", name: "Homebrew",
                            rules: [PolicyRuleAssignment(ruleID: "deny_uninstall"),
                                    PolicyRuleAssignment(ruleID: "allow_install")],
                            createdAt: Self.now, updatedAt: Self.now)
        return PolicyBuilderModel(policies: [policy], rules: rules, definitions: definitions)
    }

    @Test("sudo install allows and uninstall denies, matching on compiled wire ids")
    func sudoSimulation() {
        let model = simulatorModel()
        model.simulator.requestKind = .sudo
        model.simulator.sudoCommand = "/opt/homebrew/bin/brew"
        model.simulator.executablePath = "/opt/homebrew/bin/brew"
        model.simulator.argvText = "install wget"
        model.runSimulation(currentTime: Self.now)
        #expect(model.simulator.result?.decision == .allow)
        #expect(model.simulator.result?.matchedRule == "allow_install__brew_install")
        #expect(model.simulator.result?.evaluationTrace.isEmpty == false)

        model.simulator.argvText = "uninstall wget"
        model.runSimulation(currentTime: Self.now)
        #expect(model.simulator.result?.decision == .deny)
        #expect(model.simulator.result?.matchedRule == "deny_uninstall__brew_uninstall")
    }

    @Test("the simulator matches the engine directly over the same compiled profiles")
    func parity() {
        let model = simulatorModel()
        let compiled = model.compiledProfiles()
        #expect(compiled.map(\.profileKey) == ["rules_sudo_brew"])

        model.simulator.requestKind = .sudo
        model.simulator.sudoCommand = "/opt/homebrew/bin/brew"
        model.simulator.executablePath = "/opt/homebrew/bin/brew"
        model.simulator.argvText = "doctor"
        model.runSimulation(currentTime: Self.now)

        let direct = RuleEngine().evaluate(
            request: ElevationRequest(
                user: model.simulator.user, uid: 501,
                kind: .sudo(command: "/opt/homebrew/bin/brew", argv: ["doctor"]),
                identity: BinaryIdentity(canonicalPath: "/opt/homebrew/bin/brew",
                                         teamID: nil, sha256: "", signingStatus: .unsigned),
                timestamp: Self.now
            ),
            profiles: compiled, globalCacheSeconds: 0, activeGrants: []
        )
        #expect(model.simulator.result?.decision == direct.decision)
        #expect(model.simulator.result?.matchedRule == direct.matchedRuleID)
    }

    @Test("ambiguous context surfaces an error, not a crash")
    func errorHandling() {
        let model = DecisionSimulatorModel(defaults: nil)
        model.requestKind = .sudo
        model.sudoCommand = "relative/path"
        model.executablePath = "relative/path"
        model.run(profiles: [])
        #expect(model.result == nil)
        #expect(model.errorMessage != nil)
    }

    // MARK: Builder (components)

    @Test("a removed component contributes its neutral value; re-adding restores the typed one")
    func removedComponentsAreNeutral() {
        let sim = DecisionSimulatorModel(defaults: nil)
        #expect(sim.activeComponents == DecisionSimulatorModel.defaultComponents)
        sim.argvText = "uninstall wget"
        sim.teamID = "ABCDE12345"          // non-neutral ⇒ activates the component
        sim.signingStatus = .valid
        #expect(sim.isActive(.teamID) && sim.isActive(.signing))

        sim.remove(.arguments)
        sim.remove(.teamID)
        sim.remove(.signing)
        sim.remove(.user)
        sim.remove(.uid)
        #expect(sim.effectiveArgv.isEmpty)
        #expect(sim.effectiveTeamID == "")
        #expect(sim.effectiveSigningStatus == .unsigned)
        #expect(sim.effectiveUser == "")
        #expect(sim.effectiveUID == 0)
        // Values survive removal …
        #expect(sim.argvText == "uninstall wget")
        #expect(sim.teamID == "ABCDE12345")
        // … and come back on add.
        sim.add(.arguments)
        sim.add(.teamID)
        #expect(sim.effectiveArgv == ["uninstall", "wget"])
        #expect(sim.effectiveTeamID == "ABCDE12345")
    }

    @Test("executable path falls back to the sudo command / /usr/bin/security, never an empty path")
    func executablePathFallback() {
        let sim = DecisionSimulatorModel(defaults: nil)
        sim.sudoCommand = "/opt/homebrew/bin/brew"
        sim.remove(.executablePath)
        #expect(sim.effectiveExecutablePath == "/opt/homebrew/bin/brew")
        sim.requestKind = .authURI
        #expect(sim.effectiveExecutablePath == "/usr/bin/security")
        // Active but blank also falls back — the canonicalizer rejects "".
        sim.add(.executablePath)
        sim.executablePath = ""
        #expect(sim.effectiveExecutablePath == "/usr/bin/security")
        sim.run(profiles: [])
        #expect(sim.errorMessage == nil)
    }

    @Test("arguments hide for auth URI requests but stay in the set across a kind switch")
    func argumentsAreSudoOnly() {
        let sim = DecisionSimulatorModel(defaults: nil)
        #expect(sim.activeComponentsInOrder.contains(.arguments))
        sim.requestKind = .authURI
        #expect(!sim.activeComponentsInOrder.contains(.arguments))
        #expect(!sim.availableComponents.contains(.arguments))
        #expect(sim.effectiveArgv.isEmpty)
        sim.requestKind = .sudo
        #expect(sim.activeComponentsInOrder.contains(.arguments))
        #expect(sim.effectiveArgv == ["install", "wget"])
    }

    @Test("removing Arguments changes the decision the engine reaches")
    func removedArgumentsChangeDecision() {
        let model = simulatorModel()
        model.simulator.requestKind = .sudo
        model.simulator.sudoCommand = "/opt/homebrew/bin/brew"
        model.simulator.argvText = "uninstall wget"
        model.runSimulation(currentTime: Self.now)
        #expect(model.simulator.result?.decision == .deny)

        model.simulator.remove(.arguments)
        model.runSimulation(currentTime: Self.now)
        // No argv ⇒ neither prefix+args definition matches ⇒ default deny by
        // a different path (no matched rule).
        #expect(model.simulator.result?.matchedRule == nil)
    }

    @Test("the active set round-trips through UserDefaults; reset restores the defaults")
    func componentsPersist() {
        let suite = "DecisionSimulatorModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }

        let first = DecisionSimulatorModel(defaults: defaults)
        first.remove(.user)
        first.add(.globalCache)
        let second = DecisionSimulatorModel(defaults: defaults)
        #expect(second.activeComponents == first.activeComponents)
        #expect(!second.isActive(.user) && second.isActive(.globalCache))

        second.resetComponents()
        #expect(second.activeComponents == DecisionSimulatorModel.defaultComponents)
        #expect(DecisionSimulatorModel(defaults: defaults).activeComponents == DecisionSimulatorModel.defaultComponents)
    }
}


// MARK: - Test helpers

/// A `PreferencesSource` whose contents the test can change between reads —
/// stands in for an MDM push flipping a managed key while Commander runs.
/// (The daemon tests carry their own copy; test targets cannot share code.)
final class MutablePreferencesSource: PreferencesSource, @unchecked Sendable {
    private let lock = NSLock()
    private var domains: [String: [String: any Sendable]]

    init(domains: [String: [String: any Sendable]] = [:]) {
        self.domains = domains
    }

    func set(_ domains: [String: [String: any Sendable]]) {
        lock.lock(); defer { lock.unlock() }
        self.domains = domains
    }

    func value(forKey key: String, domain: String) -> Any? {
        lock.lock(); defer { lock.unlock() }
        return domains[domain]?[key]
    }

    func keys(inDomain domain: String) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return domains[domain].map { Array($0.keys) } ?? []
    }
}

@MainActor
@Suite("PolicyBuilderModel — Dashboard risk signals (no sample data)")
struct RiskSignalsTests {
    @Test("an empty library reports a single nominal signal, score 0")
    func emptyLibrary() {
        let signals = PolicyBuilderModel().riskSignals()
        #expect(signals.map(\.id) == ["nominal"])
        #expect(signals.first?.score == 0)
    }

    @Test("silent, unpinned, and no-deny signals are derived from the compiled library, highest score first")
    func libraryDerivedSignals() {
        let model = BuilderFixtures.standardModel()   // dev = allow_brew (silent, unpinned) + prompt_network
        let signals = model.riskSignals()
        let ids = Set(signals.map(\.id))
        #expect(ids.contains("silent"))
        #expect(ids.contains("unpinned"))
        #expect(ids.contains("no_deny"))              // no deny rule in the fixture
        #expect(!ids.contains("offline"))             // fleet never loaded → no fleet signal
        #expect(!ids.contains("nominal"))
        // Sorted by score, descending.
        #expect(signals == signals.sorted { $0.score > $1.score })
    }

    @Test("the offline-devices signal only appears once the fleet is loaded")
    func fleetSignalGated() async {
        let model = BuilderFixtures.standardModel()
        #expect(!model.riskSignals().contains { $0.id == "offline" })
        // No fleet load happens here, so the fleet-derived signal stays absent
        // (it is never invented from sample data).
        #expect(model.fleet.state == .idle)
    }
}
