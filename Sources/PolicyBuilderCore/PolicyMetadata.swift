import Foundation
import PrivMgrCore

/// LEGACY: the retired wizard "Conditions" step — when/where a
/// policy applies. Demo-level scoping metadata that is no longer authored or
/// shown anywhere (the daemon enforces rules per-machine; fleet-wide scoping
/// is expressed through Jamf smart-group assignment of the delivered
/// profile). Kept so v2 libraries and the v1 migration decode unchanged.
public struct PolicyScope: Codable, Sendable, Equatable {
    public var userGroups: [String]
    public var devices: String
    public var schedule: String
    public var network: String

    public init(
        userGroups: [String] = [],
        devices: String = "All managed devices",
        schedule: String = "All times",
        network: String = "Any network"
    ) {
        self.userGroups = userGroups
        self.devices = devices
        self.schedule = schedule
        self.network = network
    }

    public static let deviceOptions = ["All managed devices", "Developer workstations", "Executive devices", "Lab / shared Macs"]
    public static let scheduleOptions = ["All times", "Business hours (9–17)", "After hours", "Maintenance window"]
    public static let networkOptions = ["Any network", "Corporate network", "VPN only", "On-site only"]
    public static let groupOptions = ["Developers", "IT Administrators", "Help Desk", "Designers", "Finance", "Executives", "Standard Users"]
}

/// The on-disk shape of the policy library (schema v2): the three authoring
/// tiers, referenced by id.
///
/// v1 files (`{schemaVersion: 1, profiles, metadata, unassignedRules}`) are
/// migrated in place by ``init(from:)`` — each `RuleProfile` + its
/// `PolicyMetadata` becomes a ``Policy``, each embedded wire `Rule` splits
/// into a shared ``RuleDefinition`` (deduped by identical kind + matcher) and
/// a ``PolicyRule``, and `unassignedRules` become rules referenced by no
/// policy. Migration matters because ``PolicyBuilderModel/loadOrCreate()``
/// replaces an *undecodable* file with an empty library — without it,
/// upgrading would silently destroy the user's authored library.
public struct PolicyLibraryFile: Codable, Sendable {
    /// Current on-disk schema version.
    public static let currentSchemaVersion = 2

    public var schemaVersion: Int
    public var definitions: [RuleDefinition]
    public var rules: [PolicyRule]
    public var policies: [Policy]

    public init(
        schemaVersion: Int = PolicyLibraryFile.currentSchemaVersion,
        definitions: [RuleDefinition] = [],
        rules: [PolicyRule] = [],
        policies: [Policy] = []
    ) {
        self.schemaVersion = schemaVersion
        self.definitions = definitions
        self.rules = rules
        self.policies = policies
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case definitions
        case rules
        case policies
    }

    /// v1 top-level keys, decoded only during migration.
    private enum LegacyKeys: String, CodingKey {
        case profiles
        case metadata
        case unassignedRules
    }

    /// Decodes a v2 file directly, or migrates a v1 file in place.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        if version >= 2 {
            schemaVersion = version
            definitions = try container.decodeIfPresent([RuleDefinition].self, forKey: .definitions) ?? []
            rules = try container.decodeIfPresent([PolicyRule].self, forKey: .rules) ?? []
            policies = try container.decodeIfPresent([Policy].self, forKey: .policies) ?? []
        } else {
            let legacy = try decoder.container(keyedBy: LegacyKeys.self)
            let profiles = try legacy.decode([RuleProfile].self, forKey: .profiles)
            let metadata = try legacy.decodeIfPresent([String: LegacyPolicyMetadata].self, forKey: .metadata) ?? [:]
            let unassigned = try legacy.decodeIfPresent([Rule].self, forKey: .unassignedRules) ?? []
            self = Self.migrated(profiles: profiles, metadata: metadata, unassignedRules: unassigned)
        }
    }

    // MARK: v1 → v2 migration

    /// Splits a v1 library into the three tiers.
    ///
    /// Deterministic: profiles are processed in profileKey order (the order
    /// v1 files were saved in), so re-running the migration on the same file
    /// always yields the same ids. Identical matchers — same `(kind,
    /// MatchCriteria)` — collapse into one shared definition; id collisions
    /// (two profiles both had an `allow-brew`) uniquify with `_2`, `_3`, …
    static func migrated(
        profiles: [RuleProfile],
        metadata: [String: LegacyPolicyMetadata],
        unassignedRules: [Rule]
    ) -> PolicyLibraryFile {
        let migrationDate = Date()
        var definitions: [RuleDefinition] = []
        var rules: [PolicyRule] = []
        var policies: [Policy] = []
        var definitionIDs: Set<String> = []
        var ruleIDs: Set<String> = []
        var policyIDs: Set<String> = []

        /// One v1 wire rule → (shared definition, new authoring rule).
        /// Returns the authoring rule's id for the policy assignment.
        func migrate(wireRule: Rule) -> String {
            let criteria = wireRule.match
            let definitionID: String
            if let existing = definitions.first(where: {
                $0.kind == wireRule.type && $0.matchCriteria() == criteria
                    // matchCriteria() is kind-shaped; compare raw fields too so
                    // an authuri definition with stray command fields (illegal
                    // in v1, but be safe) never swallows a distinct matcher.
                    && $0.authURI == criteria.authURI
                    && $0.commandPattern == criteria.commandPattern
                    && $0.argPattern == criteria.argPattern
                    && $0.matchType == criteria.matchType
            }) {
                definitionID = existing.id
            } else {
                let base = AuthoringID.slugify(wireRule.id)
                definitionID = AuthoringID.uniqueID(base: base.isEmpty ? "definition" : base,
                                                    existing: definitionIDs)
                definitionIDs.insert(definitionID)
                definitions.append(RuleDefinition(
                    id: definitionID,
                    name: wireRule.description.isEmpty ? wireRule.id : wireRule.description,
                    detail: "",
                    kind: wireRule.type,
                    authURI: criteria.authURI,
                    commandPattern: criteria.commandPattern,
                    argPattern: criteria.argPattern,
                    matchType: criteria.matchType,
                    requiredTeamID: criteria.requiredTeamID,
                    requiredBinaryHash: criteria.requiredBinaryHash,
                    createdAt: migrationDate,
                    updatedAt: migrationDate
                ))
            }

            let base = AuthoringID.slugify(wireRule.id)
            let ruleID = AuthoringID.uniqueID(base: base.isEmpty ? "rule" : base, existing: ruleIDs)
            ruleIDs.insert(ruleID)
            rules.append(PolicyRule(
                id: ruleID,
                name: wireRule.description.isEmpty ? wireRule.id : wireRule.description,
                detail: wireRule.description,
                definitionIDs: [definitionID],
                action: wireRule.action,
                elevationType: wireRule.elevation.type,
                priority: wireRule.priority,
                useGlobalCache: wireRule.cacheSeconds == nil,
                cacheSeconds: wireRule.cacheSeconds ?? 0,
                requireJustification: wireRule.conditions.requireJustification,
                maxGrantDurationSeconds: wireRule.conditions.maxGrantDurationSeconds,
                logArguments: wireRule.elevation.logArguments,
                createdAt: migrationDate,
                updatedAt: migrationDate
            ))
            return ruleID
        }

        for profile in profiles.sorted(by: { $0.profileKey < $1.profileKey }) {
            let assignments = profile.rules.map { PolicyRuleAssignment(ruleID: migrate(wireRule: $0)) }

            var slug = profile.profileKey
            for prefix in [RuleSchemaConstants.authURIProfilePrefix, RuleSchemaConstants.sudoProfilePrefix]
            where slug.hasPrefix(prefix) {
                slug = String(slug.dropFirst(prefix.count)); break
            }
            slug = AuthoringID.slugify(slug)
            let policyID = AuthoringID.uniqueID(base: slug.isEmpty ? "policy" : slug, existing: policyIDs)
            policyIDs.insert(policyID)

            let meta = metadata[profile.profileKey]
            policies.append(Policy(
                id: policyID,
                name: meta?.displayName ?? Policy.humanize(profile.profileKey),
                summary: meta?.summary ?? "",
                scope: meta?.scope ?? PolicyScope(),
                enabled: meta?.enabled ?? true,
                policyVersion: profile.policyVersion,
                profilePriority: profile.profilePriority,
                rules: assignments,
                createdAt: meta?.createdAt ?? migrationDate,
                updatedAt: meta?.updatedAt ?? migrationDate
            ))
        }

        // Policy-less v1 rules become library rules referenced by no policy.
        for wireRule in unassignedRules {
            _ = migrate(wireRule: wireRule)
        }

        return PolicyLibraryFile(definitions: definitions, rules: rules, policies: policies)
    }
}

/// The dissolved v1 `PolicyMetadata` shape, retained solely so migration can
/// decode old files. Never written back.
struct LegacyPolicyMetadata: Decodable, Sendable {
    var displayName: String
    var summary: String
    var scope: PolicyScope
    var enabled: Bool
    var createdAt: Date
    var updatedAt: Date
}
