import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

// MARK: - Fixtures

/// Compiler-suite fixtures. Dates are pinned to the shared test epoch so
/// compilation inputs are value-stable (the compiler itself never reads them).
private enum CompilerFixtures {
    static let now = Date(timeIntervalSince1970: 1_781_222_400) // 2026-06-12 UTC

    static func sudoDefinition(
        id: String = "brew_cli",
        commandPattern: String? = "/opt/homebrew/bin/brew",
        argPattern: String? = "install|upgrade",
        matchType: MatchType? = .prefixRegex,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil
    ) -> RuleDefinition {
        RuleDefinition(
            id: id, name: "Homebrew CLI", detail: "Homebrew package operations.",
            kind: .sudo,
            commandPattern: commandPattern, argPattern: argPattern, matchType: matchType,
            requiredTeamID: requiredTeamID, requiredBinaryHash: requiredBinaryHash,
            createdAt: now, updatedAt: now
        )
    }

    static func authuriDefinition(
        id: String = "network_prefs",
        authURI: String? = "system.preferences.network"
    ) -> RuleDefinition {
        RuleDefinition(id: id, name: "Network preferences", kind: .authuri,
                       authURI: authURI, createdAt: now, updatedAt: now)
    }

    static func rule(
        id: String = "allow_brew",
        name: String = "Allow Homebrew",
        detail: String = "",
        definitionIDs: [String],
        action: RuleAction = .allow,
        elevationType: ElevationType = .silent,
        priority: Int = 10,
        useGlobalCache: Bool = true,
        cacheSeconds: Int = 0,
        requireJustification: Bool = false,
        maxGrantDurationSeconds: Int = 0,
        logArguments: Bool = true
    ) -> PolicyRule {
        PolicyRule(
            id: id, name: name, detail: detail, definitionIDs: definitionIDs,
            action: action, elevationType: elevationType, priority: priority,
            useGlobalCache: useGlobalCache, cacheSeconds: cacheSeconds,
            requireJustification: requireJustification,
            maxGrantDurationSeconds: maxGrantDurationSeconds,
            logArguments: logArguments,
            createdAt: now, updatedAt: now
        )
    }

    static func policy(
        id: String = "test",
        enabled: Bool = true,
        policyVersion: String = "1.0.0",
        profilePriority: Int = 50,
        assignments: [PolicyRuleAssignment]
    ) -> Policy {
        Policy(id: id, name: "Test Policy", enabled: enabled,
               policyVersion: policyVersion, profilePriority: profilePriority,
               rules: assignments, createdAt: now, updatedAt: now)
    }
}

// MARK: - Compilation

@MainActor
@Suite("PolicyCompiler — mechanism split and wire mapping")
struct PolicyCompilerTests {
    @Test("a mixed policy splits into authuri + sudo profiles with stamped metadata")
    func mechanismSplit() throws {
        let definitions = [CompilerFixtures.sudoDefinition(), CompilerFixtures.authuriDefinition()]
        let rule = CompilerFixtures.rule(id: "mixed_rule",
                                         definitionIDs: ["brew_cli", "network_prefs"])
        let policy = CompilerFixtures.policy(id: "mixed", policyVersion: "1.2.0",
                                             profilePriority: 40,
                                             assignments: [PolicyRuleAssignment(ruleID: "mixed_rule")])

        let profiles = PolicyCompiler().compile(policy, rules: [rule], definitions: definitions)
        // Sorted by profileKey: authuri before sudo, both keyed on policy.id.
        try #require(profiles.count == 2)
        #expect(profiles.map(\.profileKey) == ["rules_authuri_mixed", "rules_sudo_mixed"])
        for profile in profiles {
            #expect(profile.schemaVersion == RuleSchemaConstants.currentSchemaVersion)
            #expect(profile.policyVersion == "1.2.0")
            #expect(profile.profilePriority == 40)
            #expect(profile.rules.count == 1)
        }
        #expect(profiles[0].rules.first?.type == .authuri)
        #expect(profiles[1].rules.first?.type == .sudo)
    }

    @Test("a single-mechanism policy compiles to exactly one profile")
    func singleMechanism() {
        let profiles = PolicyCompiler().compile(
            CompilerFixtures.policy(assignments: [PolicyRuleAssignment(ruleID: "allow_brew")]),
            rules: [CompilerFixtures.rule(definitionIDs: ["brew_cli"])],
            definitions: [CompilerFixtures.sudoDefinition()]
        )
        #expect(profiles.map(\.profileKey) == ["rules_sudo_test"])
    }

    @Test("every wire field maps from the rule + definition pair")
    func wireFieldMapping() throws {
        let definition = CompilerFixtures.sudoDefinition(
            requiredTeamID: "TEAM123456", requiredBinaryHash: "abc123")
        let rule = CompilerFixtures.rule(
            id: "allow_brew", name: "Allow Homebrew", detail: "Homebrew package operations",
            definitionIDs: ["brew_cli"], action: .allow, elevationType: .prompt,
            priority: 7, useGlobalCache: false, cacheSeconds: 300,
            requireJustification: true, maxGrantDurationSeconds: 900,
            logArguments: false)

        let profiles = PolicyCompiler().compile(
            CompilerFixtures.policy(assignments: [PolicyRuleAssignment(ruleID: "allow_brew")]),
            rules: [rule], definitions: [definition])
        let wire = try #require(profiles.first?.rules.first)

        #expect(wire.id == "allow_brew__brew_cli")
        #expect(wire.id == "allow_brew" + PolicyCompiler.wireRuleIDSeparator + "brew_cli")
        #expect(wire.type == .sudo)
        #expect(wire.action == .allow)
        #expect(wire.description == "Homebrew package operations") // detail wins when set
        #expect(wire.priority == 7)
        #expect(wire.cacheSeconds == 300)
        #expect(wire.match.commandPattern == "/opt/homebrew/bin/brew")
        #expect(wire.match.argPattern == "install|upgrade")
        #expect(wire.match.matchType == .prefixRegex)
        #expect(wire.match.requiredTeamID == "TEAM123456")
        #expect(wire.match.requiredBinaryHash == "abc123")
        #expect(wire.match.authURI == nil)
        #expect(wire.conditions == RuleConditions(requireJustification: true,
                                                  maxGrantDurationSeconds: 900))
        #expect(wire.elevation == ElevationBehavior(type: .prompt, logArguments: false))
    }

    @Test("an empty detail falls back to the rule name for the wire description")
    func descriptionFallback() {
        let profiles = PolicyCompiler().compile(
            CompilerFixtures.policy(assignments: [PolicyRuleAssignment(ruleID: "allow_brew")]),
            rules: [CompilerFixtures.rule(name: "Allow Homebrew", detail: "",
                                          definitionIDs: ["brew_cli"])],
            definitions: [CompilerFixtures.sudoDefinition()])
        #expect(profiles.first?.rules.first?.description == "Allow Homebrew")
    }

    @Test("useGlobalCache emits nil wire cacheSeconds")
    func globalCacheEmitsNil() {
        let profiles = PolicyCompiler().compile(
            CompilerFixtures.policy(assignments: [PolicyRuleAssignment(ruleID: "allow_brew")]),
            rules: [CompilerFixtures.rule(definitionIDs: ["brew_cli"],
                                          useGlobalCache: true, cacheSeconds: 300)],
            definitions: [CompilerFixtures.sudoDefinition()])
        #expect(profiles.first?.rules.first?.cacheSeconds == nil)
    }

    @Test("authuri definitions compile kind-shaped — stale sudo fields never reach the wire")
    func authuriKindShaped() throws {
        // A definition that switched kind in the editor and kept stale fields.
        var definition = CompilerFixtures.authuriDefinition()
        definition.commandPattern = "/stale/path"
        definition.argPattern = "stale"
        definition.matchType = .glob
        definition.requiredTeamID = "TEAM123456"

        let profiles = PolicyCompiler().compile(
            CompilerFixtures.policy(assignments: [PolicyRuleAssignment(ruleID: "prompt_network")]),
            rules: [CompilerFixtures.rule(id: "prompt_network", name: "Network settings",
                                          definitionIDs: ["network_prefs"],
                                          elevationType: .prompt)],
            definitions: [definition])
        let wire = try #require(profiles.first?.rules.first)

        #expect(profiles.first?.profileKey == "rules_authuri_test")
        #expect(wire.match.authURI == "system.preferences.network")
        #expect(wire.match.commandPattern == nil)
        #expect(wire.match.argPattern == nil)
        #expect(wire.match.matchType == nil)
        #expect(wire.match.requiredTeamID == "TEAM123456") // pins are legal on both kinds
    }

    @Test("wire rule ids join rule and definition ids uniquely")
    func idJoinUniqueness() {
        let definitions = [
            CompilerFixtures.sudoDefinition(id: "brew_cli"),
            CompilerFixtures.sudoDefinition(id: "port_cli",
                                            commandPattern: "/opt/local/bin/port"),
        ]
        let rules = [
            // Repeated definition ref within one rule compiles once.
            CompilerFixtures.rule(id: "allow_managers", name: "Allow package managers",
                                  definitionIDs: ["brew_cli", "port_cli", "brew_cli"]),
            // A second rule sharing a definition still yields a distinct wire id.
            CompilerFixtures.rule(id: "deny_brew", name: "Deny Homebrew",
                                  definitionIDs: ["brew_cli"], action: .deny, priority: 20),
        ]
        let policy = CompilerFixtures.policy(assignments: [
            PolicyRuleAssignment(ruleID: "allow_managers"),
            PolicyRuleAssignment(ruleID: "deny_brew"),
        ])

        let profiles = PolicyCompiler().compile(policy, rules: rules, definitions: definitions)
        let ids = profiles.flatMap(\.rules).map(\.id)
        #expect(ids == ["allow_managers__brew_cli", "allow_managers__port_cli",
                        "deny_brew__brew_cli"])
        #expect(Set(ids).count == ids.count)
    }

    @Test("disabled assignments are skipped — the functional per-policy gate")
    func disabledAssignmentSkipped() {
        let definitions = [CompilerFixtures.sudoDefinition(), CompilerFixtures.authuriDefinition()]
        let rules = [
            CompilerFixtures.rule(id: "allow_brew", definitionIDs: ["brew_cli"]),
            CompilerFixtures.rule(id: "prompt_network", name: "Network settings",
                                  definitionIDs: ["network_prefs"], elevationType: .prompt),
        ]
        let policy = CompilerFixtures.policy(assignments: [
            PolicyRuleAssignment(ruleID: "allow_brew"),
            PolicyRuleAssignment(ruleID: "prompt_network", enabled: false),
        ])

        let profiles = PolicyCompiler().compile(policy, rules: rules, definitions: definitions)
        // The whole authuri half disappears with its only rule disabled.
        #expect(profiles.map(\.profileKey) == ["rules_sudo_test"])

        // All assignments disabled → the policy compiles to nothing.
        let allOff = CompilerFixtures.policy(assignments: [
            PolicyRuleAssignment(ruleID: "allow_brew", enabled: false),
            PolicyRuleAssignment(ruleID: "prompt_network", enabled: false),
        ])
        #expect(PolicyCompiler().compile(allOff, rules: rules, definitions: definitions).isEmpty)
    }

    @Test("the legacy Policy.enabled flag is ignored: compile(_:) and compileLibrary include every policy in order")
    func legacyEnabledFlagIgnored() {
        let definitions = [CompilerFixtures.sudoDefinition()]
        let rules = [CompilerFixtures.rule(definitionIDs: ["brew_cli"])]
        let assignment = [PolicyRuleAssignment(ruleID: "allow_brew")]
        let enabled = CompilerFixtures.policy(id: "first", assignments: assignment)
        // A pre-2026-08-22 library may still carry `enabled: false`; there is
        // no authoring-side kill switch any more (MDM scoping decides what is
        // live), so such a policy compiles like any other.
        let legacyDisabled = CompilerFixtures.policy(id: "second", enabled: false, assignments: assignment)
        let trailing = CompilerFixtures.policy(id: "third", assignments: assignment)

        #expect(PolicyCompiler().compile(legacyDisabled, rules: rules, definitions: definitions)
            .map(\.profileKey) == ["rules_sudo_second"])

        let library = PolicyCompiler().compileLibrary(
            policies: [enabled, legacyDisabled, trailing], rules: rules, definitions: definitions)
        #expect(library.map(\.profileKey) == ["rules_sudo_first", "rules_sudo_second", "rules_sudo_third"])
    }

    @Test("dangling references are skipped silently")
    func danglingRefsSkipped() {
        let definitions = [CompilerFixtures.sudoDefinition()]
        let rules = [
            CompilerFixtures.rule(id: "allow_brew", definitionIDs: ["brew_cli"]),
            CompilerFixtures.rule(id: "half_dangling", name: "Half dangling",
                                  definitionIDs: ["ghost_definition", "brew_cli"], priority: 20),
        ]
        let policy = CompilerFixtures.policy(assignments: [
            PolicyRuleAssignment(ruleID: "ghost_rule"),   // assignment → missing rule
            PolicyRuleAssignment(ruleID: "allow_brew"),
            PolicyRuleAssignment(ruleID: "half_dangling"), // rule → one missing definition
        ])

        let profiles = PolicyCompiler().compile(policy, rules: rules, definitions: definitions)
        #expect(profiles.count == 1)
        #expect(profiles.first?.rules.map(\.id) == ["allow_brew__brew_cli",
                                                    "half_dangling__brew_cli"])

        // Nothing resolvable at all → empty output, no placeholder profiles.
        let hollow = CompilerFixtures.policy(assignments: [
            PolicyRuleAssignment(ruleID: "ghost_rule"),
        ])
        #expect(PolicyCompiler().compile(hollow, rules: rules, definitions: definitions).isEmpty)
    }

    @Test("a policy with no assignments compiles to nothing")
    func emptyPolicy() {
        let profiles = PolicyCompiler().compile(
            CompilerFixtures.policy(assignments: []),
            rules: [CompilerFixtures.rule(definitionIDs: ["brew_cli"])],
            definitions: [CompilerFixtures.sudoDefinition()])
        #expect(profiles.isEmpty)
    }

    @Test("compilation is pure and deterministic")
    func deterministicCompilation() {
        let definitions = [CompilerFixtures.sudoDefinition(), CompilerFixtures.authuriDefinition()]
        let rules = [CompilerFixtures.rule(id: "mixed_rule",
                                           definitionIDs: ["brew_cli", "network_prefs"])]
        let policy = CompilerFixtures.policy(id: "mixed",
                                             assignments: [PolicyRuleAssignment(ruleID: "mixed_rule")])
        let first = PolicyCompiler().compile(policy, rules: rules, definitions: definitions)
        let second = PolicyCompiler().compile(policy, rules: rules, definitions: definitions)
        #expect(first == second)
    }
}

// MARK: - Validator contract

@MainActor
@Suite("PolicyCompiler — compiled output satisfies PolicyValidator")
struct PolicyCompilerValidationTests {
    @Test("a well-formed mixed policy compiles to profiles with zero blocking errors")
    func compiledProfilesValidate() {
        // Pins the id-join and profile-key conventions against the validator:
        // "__" joined rule ids pass the rule-id check, kind-bucketed rules pass
        // the rule-type/profile-key coherence check, and kind-shaped match
        // criteria pass the match-shape check.
        let definitions = [
            CompilerFixtures.sudoDefinition(requiredTeamID: "TEAM123456"),
            CompilerFixtures.authuriDefinition(),
        ]
        let rules = [
            CompilerFixtures.rule(id: "allow_brew", definitionIDs: ["brew_cli"],
                                  useGlobalCache: false, cacheSeconds: 300),
            CompilerFixtures.rule(id: "prompt_network", name: "Network settings",
                                  definitionIDs: ["network_prefs"],
                                  elevationType: .prompt, priority: 20,
                                  requireJustification: true, maxGrantDurationSeconds: 600),
        ]
        let policy = CompilerFixtures.policy(id: "mixed", policyVersion: "1.2.3",
                                             profilePriority: 40,
                                             assignments: [
                                                 PolicyRuleAssignment(ruleID: "allow_brew"),
                                                 PolicyRuleAssignment(ruleID: "prompt_network"),
                                             ])

        let profiles = PolicyCompiler().compile(policy, rules: rules, definitions: definitions)
        #expect(profiles.count == 2)
        for profile in profiles {
            let report = PolicyValidator().validate(profile)
            #expect(report.errors.isEmpty,
                    "expected no errors for \(profile.profileKey): \(report.errors)")
            #expect(report.isExportable)
        }
    }

    @Test("a three-tier library compiles to per-policy profile keys and validates clean")
    func libraryCompilesClean() {
        let profiles = PolicyCompiler().compileLibrary(
            policies: LibraryFixture.policies,
            rules: LibraryFixture.rules,
            definitions: LibraryFixture.definitions)

        #expect(profiles.map(\.profileKey) == ["rules_sudo_developer_tools",
                                               "rules_authuri_admin_settings",
                                               "rules_sudo_network_diag"])
        for profile in profiles {
            let report = PolicyValidator().validate(profile)
            #expect(report.errors.isEmpty,
                    "expected no errors for \(profile.profileKey): \(report.errors)")
        }
        // Compiled wire ids follow the <rule>__<definition> join.
        #expect(profiles.first?.rules.map(\.id).contains("allow_xcode_select__xcode_select") == true)
    }

    // MARK: - Symlinked-binary definitions (friendly + resolved twin)

    private static func symlinkDefinition(
        id: String = "jamf_bin",
        friendly: String? = "/usr/local/bin/jamf",
        resolved: String? = "/usr/local/jamf/bin/jamf",
        argPattern: String? = "^recon$"
    ) -> RuleDefinition {
        RuleDefinition(
            id: id, name: "Jamf", kind: .sudo,
            commandPattern: friendly, resolvedCommandPattern: resolved,
            argPattern: argPattern, matchType: .exact,
            createdAt: CompilerFixtures.now, updatedAt: CompilerFixtures.now
        )
    }

    private static func compileSudoRules(_ def: RuleDefinition) -> [Rule] {
        let rule = CompilerFixtures.rule(id: "allow_jamf", definitionIDs: [def.id])
        let policy = CompilerFixtures.policy(assignments: [PolicyRuleAssignment(ruleID: "allow_jamf")])
        return PolicyCompiler().compile(policy, rules: [rule], definitions: [def])
            .first(where: { $0.profileKey.hasPrefix("rules_sudo") })?.rules ?? []
    }

    @Test("a symlinked-binary definition compiles to TWO exact wire rules (friendly + resolved)")
    func symlinkedBinaryEmitsTwoWireRules() {
        let rules = Self.compileSudoRules(Self.symlinkDefinition())
        #expect(rules.count == 2)
        // Primary keeps the historical <rule>__<def> id; the twin gets __2.
        #expect(rules[0].id == "allow_jamf__jamf_bin")
        #expect(rules[1].id == "allow_jamf__jamf_bin__2")
        #expect(rules[0].match.commandPattern == "/usr/local/bin/jamf")
        #expect(rules[1].match.commandPattern == "/usr/local/jamf/bin/jamf")
        // The twin inherits everything but the path.
        for wire in rules {
            #expect(wire.match.matchType == .exact)
            #expect(wire.match.argPattern == "^recon$")
            #expect(wire.action == .allow)
            #expect(wire.priority == rules[0].priority)
        }
    }

    @Test("a plain (single-path) definition still emits exactly one wire rule with the unchanged id")
    func plainDefinitionEmitsOne() {
        let rules = Self.compileSudoRules(Self.symlinkDefinition(resolved: nil))
        #expect(rules.count == 1)
        #expect(rules[0].id == "allow_jamf__jamf_bin")
        #expect(rules[0].match.commandPattern == "/usr/local/bin/jamf")
    }

    @Test("a resolved path equal to (or blank vs) the friendly path de-duplicates to one rule")
    func redundantResolvedDeduped() {
        #expect(Self.compileSudoRules(Self.symlinkDefinition(resolved: "/usr/local/bin/jamf")).count == 1)
        #expect(Self.compileSudoRules(Self.symlinkDefinition(resolved: "   ")).count == 1)
        #expect(Self.compileSudoRules(Self.symlinkDefinition(resolved: "")).count == 1)
    }

    @Test("matchCriteriaList: two criteria for a symlink def, one otherwise; authuri never twins")
    func matchCriteriaListShape() {
        let sym = Self.symlinkDefinition()
        let list = sym.matchCriteriaList()
        #expect(list.count == 2)
        #expect(list[0].commandPattern == "/usr/local/bin/jamf")
        #expect(list[1].commandPattern == "/usr/local/jamf/bin/jamf")
        #expect(list[1].argPattern == "^recon$")
        // The primary matcher is unchanged (migration + preview rely on it).
        #expect(sym.matchCriteria().commandPattern == "/usr/local/bin/jamf")

        // An authuri definition never twins, even if the field is (illegally) set.
        var authuri = CompilerFixtures.authuriDefinition()
        authuri.resolvedCommandPattern = "/x"
        #expect(authuri.matchCriteriaList().count == 1)
    }
}
