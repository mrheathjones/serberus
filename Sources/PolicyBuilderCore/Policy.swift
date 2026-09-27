import Foundation
import PrivMgrCore

/// One rule reference inside a ``Policy``, toggleable per policy.
///
/// The toggle is the authoring-side representation of "this rule is part of
/// the policy but currently switched off" — a disabled assignment is simply
/// not compiled, so the daemon never sees it (unlike the old cosmetic
/// `PolicyMetadata.enabled`, this one is functional).
public struct PolicyRuleAssignment: Codable, Sendable, Equatable, Identifiable {
    /// Reference into the rule library.
    public var ruleID: String
    /// Whether this rule compiles into the policy's wire profiles.
    public var enabled: Bool

    public var id: String { ruleID }

    public init(ruleID: String, enabled: Bool = true) {
        self.ruleID = ruleID
        self.enabled = enabled
    }
}

/// Tier 1 of the authoring model: a deliverable collection of rule references.
///
/// A policy is what gets exported/published: ``PolicyCompiler`` turns it into
/// one `rules_sudo_<id>` and/or one `rules_authuri_<id>` wire profile
/// depending on which mechanisms its enabled rules' definitions cover — so a
/// single policy can now mix sudo and authuri content, with the mechanism
/// split happening at compile time instead of in the profile key. The old
/// UI-only `PolicyMetadata` (name, summary, scope, enabled, timestamps) is
/// folded in as plain fields.
public struct Policy: Codable, Sendable, Equatable, Identifiable {
    /// Stable slug, unique across the policy library. Must match
    /// `[a-z0-9_]+` — it lands inside the compiled `rules_sudo_<id>` /
    /// `rules_authuri_<id>` profile keys, which `PolicyValidator`'s
    /// profile-key check constrains to lowercase alphanumerics/underscores.
    public var id: String
    /// Display name (was `PolicyMetadata.displayName`).
    public var name: String
    /// One-line description shown in the Policies list.
    public var summary: String
    /// LEGACY: demo-level scoping metadata. No longer authored
    /// or shown — fleet scoping is the MDM group the delivered profile is
    /// assigned to. Kept (and round-tripped) so existing `policies.json`
    /// files decode unchanged.
    public var scope: PolicyScope
    /// LEGACY: the old whole-policy kill switch. No longer
    /// surfaced in Commander and ignored by ``PolicyCompiler`` — whether a
    /// policy is live on a Mac is decided by MDM scoping, not by an
    /// authoring-side toggle. Kept (and round-tripped) for on-disk
    /// compatibility; new policies are written with `true`.
    public var enabled: Bool
    /// Semver MAJOR.MINOR.PATCH, stamped on every compiled profile.
    public var policyVersion: String
    /// Merge priority stamped on every compiled profile. Lower evaluates first.
    public var profilePriority: Int
    /// Ordered rule references with per-policy enable toggles.
    public var rules: [PolicyRuleAssignment]
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: String,
        name: String,
        summary: String = "",
        scope: PolicyScope = PolicyScope(),
        enabled: Bool = true,
        policyVersion: String = "1.0.0",
        profilePriority: Int = 50,
        rules: [PolicyRuleAssignment] = [],
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.summary = summary
        self.scope = scope
        self.enabled = enabled
        self.policyVersion = policyVersion
        self.profilePriority = profilePriority
        self.rules = rules
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    /// `rules_sudo_developer_tools` (or a bare `developer_tools` slug) →
    /// "Developer Tools". Used when deriving display names from keys/ids —
    /// the surviving half of the dissolved `PolicyMetadata`.
    public static func humanize(_ key: String) -> String {
        var slug = key
        for prefix in ["rules_authuri_", "rules_sudo_", "rules_"] where slug.hasPrefix(prefix) {
            slug = String(slug.dropFirst(prefix.count)); break
        }
        let words = slug.split(whereSeparator: { $0 == "_" || $0 == "-" })
        guard !words.isEmpty else { return key }
        return words.map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined(separator: " ")
    }
}

/// Shared id helpers for all three authoring tiers.
///
/// Ids are stable slugs: generated once from a display name, uniquified
/// against the tier's library, and never rewritten when the name changes
/// (compiled wire ids, grants, and policy assignments embed them). Lives
/// outside ``PolicyBuilderModel`` so nonisolated code (the v1→v2 library
/// migration) can share the exact same generation rules.
public enum AuthoringID {
    /// Lowercases and maps every non-alphanumeric to `_`, collapsing runs —
    /// "New Policy" → "new_policy". Output satisfies the `[a-z0-9_]+`
    /// constraint `PolicyValidator.isValidProfileKey` places on compiled
    /// profile-key slugs.
    public static func slugify(_ name: String) -> String {
        let lowered = name.lowercased()
        let mapped = lowered.map { ch -> Character in
            (ch.isLetter || ch.isNumber) ? ch : "_"
        }
        return String(mapped).split(separator: "_").joined(separator: "_")
    }

    /// `base` when free, else `base_2`, `base_3`, … — the collision policy
    /// every tier (and the v1 migration) uses.
    public static func uniqueID(base: String, existing: Set<String>) -> String {
        guard existing.contains(base) else { return base }
        var n = 2
        while existing.contains("\(base)_\(n)") { n += 1 }
        return "\(base)_\(n)"
    }
}
