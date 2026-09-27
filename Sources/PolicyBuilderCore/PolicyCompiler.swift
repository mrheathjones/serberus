import Foundation
import PrivMgrCore

/// Compiles the three-tier authoring model down to the frozen v1.0 wire
/// schema.
///
/// The daemon/MDM contract (`RuleProfile` + wire `Rule`, `rules_sudo_*` /
/// `rules_authuri_*` managed-preference keys) is unchanged — validation,
/// simulation, export, and publish all consume the compiler's output, so the
/// authoring model never leaks past this boundary.
///
/// Compilation is pure and deterministic: the same inputs always produce the
/// same profiles (rule order follows the policy's assignment order, profiles
/// sort by profileKey), which keeps `MobileConfigGenerator`'s
/// re-export-yields-identical-bytes guarantee intact.
public struct PolicyCompiler: Sendable {
    public init() {}

    /// Separator joining rule and definition ids into a wire rule id
    /// (`<rule.id>__<definition.id>`). `PolicyValidator`'s rule-id check only
    /// requires non-emptiness, so the double underscore is valid on the wire
    /// while remaining unambiguous against the single-underscore slugs
    /// `slugify` produces.
    public static let wireRuleIDSeparator = "__"

    /// Compiles one policy to its wire profiles: one `rules_sudo_<policy.id>`
    /// and/or one `rules_authuri_<policy.id>`, depending on which mechanisms
    /// its enabled rules' definitions cover.
    ///
    /// - Disabled assignments are skipped (the per-policy toggle is the
    ///   functional gate — the daemon never sees a disabled rule).
    /// - Dangling references (assignment → missing rule, rule → missing
    ///   definition) are skipped silently; authoring validation reports them.
    /// - Repeated definition ids within one rule are compiled once, so a
    ///   profile never carries duplicate wire rule ids from a single rule.
    /// - `policy.enabled` is a dormant legacy field (see ``Policy/enabled``)
    ///   and is never consulted.
    ///
    /// Wire mapping per (rule, definition) pair:
    /// `id = "<rule.id>__<definition.id>"`, `type = definition.kind`,
    /// `action = rule.action`, `description = rule.detail` (or `rule.name`
    /// when the detail is empty), `priority = rule.priority`,
    /// `cacheSeconds = rule.useGlobalCache ? nil : rule.cacheSeconds`,
    /// `match` from ``RuleDefinition/matchCriteriaList()``, conditions/elevation
    /// from the rule's advanced settings. A symlinked-binary sudo definition
    /// compiles to TWO wire rules (friendly + resolved path); the twin's id gets
    /// a `__<n>` suffix (see ``wireRules(rule:definition:)``).
    ///
    /// Returned profiles are sorted by `profileKey` (authuri before sudo).
    public func compile(
        _ policy: Policy,
        rules: [PolicyRule],
        definitions: [RuleDefinition]
    ) -> [RuleProfile] {
        let rulesByID = Dictionary(rules.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let definitionsByID = Dictionary(definitions.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })

        var sudoRules: [Rule] = []
        var authURIRules: [Rule] = []

        for assignment in policy.rules where assignment.enabled {
            guard let rule = rulesByID[assignment.ruleID] else { continue }
            var compiledDefinitionIDs: Set<String> = []
            for definitionID in rule.definitionIDs {
                guard compiledDefinitionIDs.insert(definitionID).inserted,
                      let definition = definitionsByID[definitionID] else { continue }
                let compiled = Self.wireRules(rule: rule, definition: definition)
                switch definition.kind {
                case .sudo: sudoRules.append(contentsOf: compiled)
                case .authuri: authURIRules.append(contentsOf: compiled)
                }
            }
        }

        var profiles: [RuleProfile] = []
        if !authURIRules.isEmpty {
            profiles.append(RuleProfile(
                policyVersion: policy.policyVersion,
                profileKey: RuleSchemaConstants.authURIProfilePrefix + policy.id,
                profilePriority: policy.profilePriority,
                rules: authURIRules
            ))
        }
        if !sudoRules.isEmpty {
            profiles.append(RuleProfile(
                policyVersion: policy.policyVersion,
                profileKey: RuleSchemaConstants.sudoProfilePrefix + policy.id,
                profilePriority: policy.profilePriority,
                rules: sudoRules
            ))
        }
        return profiles
    }

    /// All enabled policies compiled — what the fleet would enforce.
    ///
    /// Used by the Decision Simulator and cross-profile conflict checks.
    /// Every policy compiles — which of them is live on a Mac is decided by
    /// MDM scoping of the delivered profile, not by an authoring-side toggle
    /// (the legacy `Policy.enabled` flag is ignored). Policy order is
    /// preserved (each policy's profiles stay adjacent, authuri before sudo).
    public func compileLibrary(
        policies: [Policy],
        rules: [PolicyRule],
        definitions: [RuleDefinition]
    ) -> [RuleProfile] {
        policies.flatMap { compile($0, rules: rules, definitions: definitions) }
    }

    /// Folds one (rule, definition) pair into its wire rule(s).
    ///
    /// One rule for a plain definition; **two** for a symlinked-binary sudo
    /// definition (friendly + resolved path — see
    /// ``RuleDefinition/matchCriteriaList()``). The primary criterion keeps the
    /// historical `<rule.id>__<definition.id>` wire id so existing single-path
    /// definitions compile byte-identically; each additional criterion gets a
    /// `__<n>` suffix (`__2`, `__3`, …), keeping ids unique within the profile
    /// without churning the primary. All twins share the rule's action,
    /// priority, cache, conditions, and elevation — only the matcher differs.
    private static func wireRules(rule: PolicyRule, definition: RuleDefinition) -> [Rule] {
        definition.matchCriteriaList().enumerated().map { index, criteria in
            let wireID = index == 0
                ? rule.id + wireRuleIDSeparator + definition.id
                : rule.id + wireRuleIDSeparator + definition.id + wireRuleIDSeparator + String(index + 1)
            return Rule(
                id: wireID,
                type: definition.kind,
                action: rule.action,
                description: rule.detail.isEmpty ? rule.name : rule.detail,
                priority: rule.priority,
                cacheSeconds: rule.useGlobalCache ? nil : rule.cacheSeconds,
                match: criteria,
                conditions: RuleConditions(
                    requireJustification: rule.requireJustification,
                    maxGrantDurationSeconds: rule.maxGrantDurationSeconds
                ),
                elevation: ElevationBehavior(
                    type: rule.elevationType,
                    logArguments: rule.logArguments
                ),
                // App Identity definition: the wire rule is identity-scoped —
                // the daemon composes the right per app instead of rewriting
                // it (session-owner-or-admin for the app, native for the rest).
                appIdentity: definition.appIdentityBranch()
            )
        }
    }
}
