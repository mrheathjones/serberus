import Foundation

/// The Jamf Pro **Custom Schema** for a Serberus rules (sub-)domain — the
/// console-editable delivery path.
///
/// ## Why this exists
///
/// Jamf's GUI only *renders* a custom-settings payload when Jamf **builds** it
/// (Application & Custom Settings → External Applications → Custom Schema).
/// A profile Commander publishes through the API (the `rules_*` JSON-string
/// keys in an MCX payload) enforces correctly on the device but shows up
/// **blank** in the console — nobody can read or modify it there. For rules
/// that other engineers must be able to edit in Jamf, the answer is a Custom
/// Schema: Jamf renders a form from it and stores the values as the native
/// `rules` array the daemon already reads (`Rule.fromManagedDictionary`).
///
/// This type produces that schema document **pre-filled with a policy's
/// compiled rules** (as the properties' `default` values), so uploading it
/// yields a form that already shows the policy — editable by anyone with
/// console access from then on.
///
/// ## One owner per policy
///
/// The daemon composes every rules profile it finds (API-published `rules_*`
/// keys AND native `rules` arrays in every `com.herojoneslabs.serberus.rules.*`
/// sub-domain). A policy should therefore be delivered ONE way: either
/// published from Commander (Commander edits it) or as a schema (Jamf edits
/// it) — not both, or edits diverge.
///
/// ## Template parity
///
/// ``templateJSON`` is the verbatim content of
/// `Support/jamf-schemas/com.herojoneslabs.serberus.rules.json` (the document
/// admins paste by hand); a test asserts the two never drift.
public enum JamfRulesSchema {
    /// A generated schema ready to save.
    public struct Export: Sendable, Equatable {
        /// Pretty-printed JSON.
        public let data: Data
        /// The preference domain baked into `__preferencedomain` — what Jamf
        /// pre-fills when the schema is pasted.
        public let domain: String
        /// Suggested filename, `<domain>.json`.
        public let suggestedFilename: String
        /// How many rules were pre-filled.
        public let ruleCount: Int
        /// Which form the schema carries (full, sudo-only, authuri-only).
        public let fieldSet: FieldSet
    }

    public enum SchemaError: Error, LocalizedError, Equatable {
        case templateUnreadable
        public var errorDescription: String? { "The built-in Jamf schema template could not be parsed." }
    }

    /// Which of the rule form's fields a schema carries. The shipped template
    /// has every field for both rule types; a policy that is all-sudo or
    /// all-authuri gets a form trimmed to the fields that mean something for
    /// it (and `type` locked to that type), so Jamf admins are not shown — or
    /// tempted to fill in — fields the daemon would never use for those rules.
    public enum FieldSet: String, Sendable, Equatable {
        /// Both rule types present → the full form.
        case all
        /// Only sudo rules → everything except `authURI`.
        case sudoOnly
        /// Only authorization-right rules → `id`, `type`, `action`,
        /// `description`, `priority`, `authURI`. The AuthorizationDB projection
        /// enforces allow/deny on the RIGHT only: elevation, argument logging,
        /// justification, grant duration, cache and identity pins are sudo
        /// semantics and never apply to an authuri rule, so they are pruned —
        /// not merely hidden as cosmetics.
        case authuriOnly

        /// Picks the narrowest form the rules allow (`.all` when empty).
        public static func forRules(_ rules: [Rule]) -> FieldSet {
            let types = Set(rules.map(\.type))
            if types == [.sudo] { return .sudoOnly }
            if types == [.authuri] { return .authuriOnly }
            return .all
        }

        /// Rule-item properties removed from the form.
        var prunedFields: Set<String> {
            switch self {
            case .all: return []
            case .sudoOnly: return ["authURI", "appTeamID", "appBundleID"]
            case .authuriOnly:
                return ["commandPattern", "matchType", "argPattern", "elevationType", "logArguments",
                        "requireJustification", "maxGrantDurationSeconds", "cacheSeconds",
                        "requiredTeamID", "requiredBinaryHash"]
            }
        }

        /// The single `type` the form is locked to, if any.
        var lockedType: RuleType? {
            switch self {
            case .all: return nil
            case .sudoOnly: return .sudo
            case .authuriOnly: return .authuri
            }
        }

        /// The `action` help text for a form locked to one type, or nil to
        /// keep the template's (which covers both types).
        var actionDescription: String? {
            switch self {
            case .all, .sudoOnly: return nil
            case .authuriOnly:
                return "'Allow' lets the user unlock the authorization right with their OWN password (no Serberus prompt). "
                    + "'Deny' blocks it. Deny wins over allow at equal priority."
            }
        }

        /// Human label for titles/descriptions.
        public var label: String {
            switch self {
            case .all: return "sudo + authorization rights"
            case .sudoOnly: return "sudo commands"
            case .authuriOnly: return "authorization rights"
            }
        }
    }

    // MARK: Domain

    /// Sub-domain for one policy: `com.herojoneslabs.serberus.rules.<slug>`.
    /// One config profile == one sub-domain (two profiles cannot both own the
    /// single native `rules` key of one domain — macOS keeps one and silently
    /// drops the other), so every schema export gets its own.
    public static func subdomain(forPolicyID policyID: String) -> String {
        "\(BundleConfig.rulesDomain).\(slug(policyID))"
    }

    /// Lowercased, `[a-z0-9]` only, runs collapsed to `_` — safe as a
    /// preference-domain component.
    static func slug(_ text: String) -> String {
        let mapped = text.lowercased().map { ch -> Character in (ch.isLetter || ch.isNumber) ? ch : "_" }
        let collapsed = String(mapped).split(separator: "_", omittingEmptySubsequences: true).joined(separator: "_")
        return collapsed.isEmpty ? "policy" : collapsed
    }

    // MARK: Native dictionary — the inverse of `Rule.fromManagedDictionary`

    /// The flat dictionary the Jamf form (and the `rules` array it writes)
    /// uses for one rule. Optional fields are emitted only when set, so the
    /// form shows blanks rather than empty strings; required fields always.
    public static func nativeDictionary(for rule: Rule) -> [String: Any] {
        var dict: [String: Any] = [
            "id": rule.id,
            "type": rule.type.rawValue,
            "action": rule.action.rawValue,
            "description": rule.description,
            "priority": rule.priority,
            "elevationType": rule.elevation.type.rawValue,
            "logArguments": rule.elevation.logArguments,
            "requireJustification": rule.conditions.requireJustification,
            "maxGrantDurationSeconds": rule.conditions.maxGrantDurationSeconds,
        ]
        if let cache = rule.cacheSeconds { dict["cacheSeconds"] = cache }
        switch rule.type {
        case .sudo:
            dict["matchType"] = (rule.match.matchType ?? .exact).rawValue
            if let command = rule.match.commandPattern { dict["commandPattern"] = command }
            if let args = rule.match.argPattern { dict["argPattern"] = args }
        case .authuri:
            if let right = rule.match.authURI { dict["authURI"] = right }
        }
        if let team = rule.match.requiredTeamID { dict["requiredTeamID"] = team }
        if let hash = rule.match.requiredBinaryHash { dict["requiredBinaryHash"] = hash }
        if let branch = rule.appIdentity {
            dict["appTeamID"] = branch.teamID
            dict["appBundleID"] = branch.bundleID
        }
        return dict
    }

    // MARK: Document

    /// The schema document for `domain`, optionally pre-filled with
    /// `profiles`' rules. `title`/`description` name the policy in the Jamf
    /// sidebar so the schema is recognisable among others. `fieldSet` trims
    /// the rule form to the fields the policy's rule type(s) use (defaults to
    /// the narrowest set the pre-filled rules allow).
    public static func document(
        domain: String,
        title: String? = nil,
        description: String? = nil,
        prefilledWith profiles: [RuleProfile] = [],
        fieldSet: FieldSet? = nil
    ) throws -> [String: Any] {
        guard let data = templateJSON.data(using: .utf8),
              var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              var properties = root["properties"] as? [String: Any] else {
            throw SchemaError.templateUnreadable
        }
        root["__preferencedomain"] = domain
        if let title { root["title"] = title }
        if let description { root["description"] = description }

        // Trim the rule form to the fields this policy's rule type(s) use.
        let fields = fieldSet ?? FieldSet.forRules(profiles.flatMap(\.rules))
        if var rulesProperty = properties["rules"] as? [String: Any],
           var items = rulesProperty["items"] as? [String: Any],
           var itemProperties = items["properties"] as? [String: Any] {
            for field in fields.prunedFields { itemProperties.removeValue(forKey: field) }
            if let locked = fields.lockedType, var typeProperty = itemProperties["type"] as? [String: Any] {
                // Lock `type` to the one kind the form can express, so an admin
                // cannot flip a row to a type whose fields are not on the form.
                typeProperty["enum"] = [locked.rawValue]
                typeProperty["options"] = ["enum_titles": [locked == .sudo ? "Sudo command" : "Authorization right"]]
                typeProperty["default"] = locked.rawValue
                itemProperties["type"] = typeProperty
            }
            if let text = fields.actionDescription, var actionProperty = itemProperties["action"] as? [String: Any] {
                actionProperty["description"] = text
                itemProperties["action"] = actionProperty
            }
            items["properties"] = itemProperties
            rulesProperty["items"] = items
            properties["rules"] = rulesProperty
        }

        if let first = profiles.first {
            if var version = properties["policyVersion"] as? [String: Any] {
                version["default"] = first.policyVersion
                properties["policyVersion"] = version
            }
            if var priority = properties["profilePriority"] as? [String: Any] {
                priority["default"] = first.profilePriority
                properties["profilePriority"] = priority
            }
        }
        // Pre-fill the rules array. Ids must be unique within one domain (the
        // daemon keeps the first duplicate and drops the rest with a finding),
        // so a clash across a policy's sudo + authuri profiles is suffixed.
        var seen = Set<String>()
        var rules: [[String: Any]] = []
        for rule in profiles.flatMap(\.rules) {
            var native = nativeDictionary(for: rule)
            var id = rule.id
            var n = 2
            while seen.contains(id) { id = "\(rule.id)_\(n)"; n += 1 }
            seen.insert(id)
            native["id"] = id
            rules.append(native)
        }
        if !rules.isEmpty, var rulesProperty = properties["rules"] as? [String: Any] {
            rulesProperty["default"] = rules
            properties["rules"] = rulesProperty
        }
        root["properties"] = properties
        return root
    }

    /// Pretty JSON for a policy's compiled profiles.
    public static func export(
        policyID: String,
        policyName: String,
        profiles: [RuleProfile]
    ) throws -> Export {
        let domain = subdomain(forPolicyID: policyID)
        let rules = profiles.flatMap(\.rules)
        let count = rules.count
        let fields = FieldSet.forRules(rules)
        let document = try document(
            domain: domain,
            title: "Serberus — Rules: \(policyName) (\(fields.label))",
            description: "Serberus \(fields.label) rules for policy “\(policyName)” (\(policyID)), exported from Serberus "
                + "Commander pre-filled with \(count) rule(s). This form shows only the fields those rules use. Edit them "
                + "here; serberusd reads this preference domain (\(domain)) alongside every other Serberus rules profile. "
                + "Keep ONE owner per policy — if this policy is also published from Commander, edits will diverge. Bump "
                + "Policy version when rules change. NOTE: rules published straight from Serberus Commander (Publish to "
                + "Jamf) are delivered as a configuration profile whose rules do NOT render in the Jamf console — that "
                + "profile enforces correctly but shows blank here. This schema form is the console-editable path: "
                + "upload it as a Custom Schema and manage the rules in this form instead.",
            prefilledWith: profiles,
            fieldSet: fields
        )
        let data = try JSONSerialization.data(
            withJSONObject: document,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        return Export(data: data, domain: domain, suggestedFilename: "\(domain).json", ruleCount: count, fieldSet: fields)
    }

    // MARK: Template

    /// Verbatim `Support/jamf-schemas/com.herojoneslabs.serberus.rules.json`.
    /// Keep in lockstep (a test diffs the two).
    public static let templateJSON = #"""
    {
      "title": "Serberus — Rules",
      "description": "Author Serberus sudo and authorization-right rules directly in Jamf. Delivered to the com.herojoneslabs.serberus.rules preference domain and read by serberusd alongside any rules published from the Serberus app. Each entry in 'Rules' is one rule; fill in the fields for its type (sudo OR authorization right). The daemon rejects a rule that is missing its id, type, action, or its type's target, so a half-filled row is ignored rather than becoming an allow-anything rule.",
      "__preferencedomain": "com.herojoneslabs.serberus.rules",
      "type": "object",
      "properties": {
        "policyVersion": {
          "type": "string",
          "title": "Policy version",
          "description": "Semantic version stamped on this Jamf-authored rule set (informational; bump it when you change rules so the change is traceable).",
          "default": "1.0.0",
          "property_order": 10
        },
        "profilePriority": {
          "type": "integer",
          "title": "Profile priority",
          "description": "Merge order of this rule set against other Serberus profiles on the device. Lower evaluates first.",
          "default": 50,
          "minimum": 0,
          "property_order": 20
        },
        "rules": {
          "type": "array",
          "title": "Rules",
          "description": "The list of rules. Add one row per sudo command or authorization right.",
          "property_order": 30,
          "items": {
            "type": "object",
            "title": "Rule",
            "properties": {
              "id": {
                "type": "string",
                "title": "Rule ID",
                "description": "Unique identifier within this rule set (letters, digits, dashes/underscores). Shown in logs and grants — e.g. 'prompt-jamf-recon'.",
                "property_order": 10
              },
              "type": {
                "type": "string",
                "title": "Type",
                "description": "'Sudo command' matches a command run under sudo. 'Authorization right' matches a macOS AuthorizationDB right (System Settings unlock, etc.).",
                "enum": ["sudo", "authuri"],
                "options": { "enum_titles": ["Sudo command", "Authorization right"] },
                "default": "sudo",
                "property_order": 20
              },
              "action": {
                "type": "string",
                "title": "Action",
                "description": "'Allow' grants a sudo command (silently or via prompt, per Elevation), or lets the user unlock an authorization right with their OWN password (no Serberus prompt). 'Deny' blocks. Deny wins over allow at equal priority and is never cached.",
                "enum": ["allow", "deny"],
                "options": { "enum_titles": ["Allow", "Deny"] },
                "default": "allow",
                "property_order": 30
              },
              "description": {
                "type": "string",
                "title": "Description",
                "description": "Human-readable summary shown in the Policy Builder and in prompts.",
                "property_order": 40
              },
              "priority": {
                "type": "integer",
                "title": "Priority",
                "description": "Evaluation order within this rule set. Lower evaluates first.",
                "default": 50,
                "property_order": 50
              },
              "commandPattern": {
                "type": "string",
                "title": "Command path (Sudo only)",
                "description": "For a Sudo rule: the canonical executable path this rule matches, e.g. /usr/local/bin/jamf. Required for Sudo unless Match type is 'Any command'. Leave blank for Authorization-right rules.",
                "property_order": 60
              },
              "matchType": {
                "type": "string",
                "title": "Match type (Sudo only)",
                "description": "How the command path is interpreted. 'Exact' is strongly recommended; prefix/glob/regex are broader and easier to over-authorize.",
                "enum": ["exact", "prefix-regex", "glob", "regex", "any"],
                "options": { "enum_titles": ["Exact path", "Path prefix + arg regex", "Glob", "Regex", "Any command"] },
                "default": "exact",
                "property_order": 70
              },
              "argPattern": {
                "type": "string",
                "title": "Argument regex (Sudo, optional)",
                "description": "For a Sudo rule: a regular expression applied to the first argument (e.g. ^recon$ to allow only 'jamf recon'). Leave blank to allow any arguments.",
                "property_order": 80
              },
              "authURI": {
                "type": "string",
                "title": "Authorization right (Authorization-right only)",
                "description": "For an Authorization-right rule: the AuthorizationDB right name, e.g. system.preferences.datetime. Leave blank for Sudo rules.",
                "property_order": 90
              },
              "elevationType": {
                "type": "string",
                "title": "Elevation (Sudo allow only)",
                "description": "'Silent' grants without interaction. 'Prompt' requires the user to approve via the Serberus Sentinel before the grant is issued. Sudo rules only: an Authorization-right allow always asks for the user's own password, and this field is ignored for it.",
                "enum": ["silent", "prompt"],
                "options": { "enum_titles": ["Silent", "Prompt user"] },
                "default": "silent",
                "property_order": 100
              },
              "logArguments": {
                "type": "boolean",
                "title": "Log arguments (Sudo only)",
                "description": "When true, redacted command arguments are included in decision log events.",
                "default": false,
                "property_order": 120
              },
              "requireJustification": {
                "type": "boolean",
                "title": "Require justification (Sudo only)",
                "description": "When true, the user must supply a justification before the request is approved.",
                "default": false,
                "property_order": 130
              },
              "maxGrantDurationSeconds": {
                "type": "integer",
                "title": "Grant duration (seconds, Sudo only)",
                "description": "-1 = evaluate every time (never grant); 0 = use the org default; N = grant for N seconds",
                "default": 0,
                "minimum": -1,
                "maximum": 86400,
                "property_order": 140
              },
              "cacheSeconds": {
                "type": "integer",
                "title": "Cache (seconds, Sudo only, optional)",
                "description": "Per-rule cache TTL for an allow decision. Leave unset to use the daemon's global sudo cache; 0 = never cache this rule. Ignored for deny.",
                "minimum": 0,
                "maximum": 86400,
                "property_order": 150
              },
              "requiredTeamID": {
                "type": "string",
                "title": "Required Team ID (Sudo only, optional)",
                "description": "When set, the requesting binary's code-signing Team ID must equal this value.",
                "property_order": 160
              },
              "appTeamID": {
                "type": "string",
                "title": "App Team ID (per-app rule; ignored in 0.9.0)",
                "description": "Ignored in Serberus 0.9.0: per-app (App Identity) rules are disabled because the app's identity comes from a value the caller can forge. A rule with this field is logged and skipped, and the right keeps its native definition. Kept so existing profiles still parse. Intended use: the 10-character Apple Team ID of the ONE app a per-app rule applies to. Requires appBundleID.",
                "property_order": 180
              },
              "appBundleID": {
                "type": "string",
                "title": "App bundle ID (per-app rule; ignored in 0.9.0)",
                "description": "Ignored in Serberus 0.9.0 (see appTeamID). Kept so existing profiles still parse. Intended use: the app's code-signing identifier (bundle ID), paired with appTeamID.",
                "property_order": 181
              },
              "requiredBinaryHash": {
                "type": "string",
                "title": "Required binary SHA-256 (Sudo only, optional)",
                "description": "When set, the requesting binary's SHA-256 must equal this value.",
                "property_order": 170
              }
            }
          }
        }
      }
    }
    """#
}
