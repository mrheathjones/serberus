import Foundation
import Testing
@testable import PrivMgrCore

/// The console-editable delivery path: a Jamf Custom Schema pre-filled with a
/// policy's rules. What the form shows must be exactly what the daemon reads.
@Suite("JamfRulesSchema")
struct JamfRulesSchemaTests {
    private func sudoRule() -> Rule {
        Rule(
            id: "allow_jamf_checkjssconnection",
            type: .sudo,
            action: .allow,
            description: "Let support run jamf checkJSSConnection",
            priority: 40,
            cacheSeconds: 300,
            match: MatchCriteria(
                authURI: nil,
                commandPattern: "/usr/local/bin/jamf",
                argPattern: "^checkJSSConnection$",
                matchType: .exact,
                requiredTeamID: "483DWKW443",
                requiredBinaryHash: nil
            ),
            conditions: RuleConditions(requireJustification: true, maxGrantDurationSeconds: 900),
            elevation: ElevationBehavior(type: .prompt, logArguments: false)
        )
    }

    private func authuriRule() -> Rule {
        Rule(
            id: "allow_datetime",
            type: .authuri,
            action: .allow,
            description: "",
            priority: 50,
            match: MatchCriteria(authURI: "system.preferences.datetime")
        )
    }

    private func profile(_ rules: [Rule], key: String = "rules_sudo_x", version: String = "1.4.0", priority: Int = 30) -> RuleProfile {
        RuleProfile(schemaVersion: RuleSchemaConstants.currentSchemaVersion, policyVersion: version,
                    profileKey: key, profilePriority: priority, rules: rules)
    }

    @Test("the embedded template is byte-for-byte the shipped Support/jamf-schemas document")
    func templateParity() throws {
        // Tests/PrivMgrCoreTests/JamfRulesSchemaTests.swift → repo root is three levels up.
        let here = URL(fileURLWithPath: #filePath)
        let repo = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let shipped = repo.appendingPathComponent("Support/jamf-schemas/com.herojoneslabs.serberus.rules.json")
        let shippedObject = try JSONSerialization.jsonObject(with: try Data(contentsOf: shipped)) as? NSDictionary
        let embeddedObject = try JSONSerialization.jsonObject(with: Data(JamfRulesSchema.templateJSON.utf8)) as? NSDictionary
        #expect(shippedObject != nil)
        #expect(embeddedObject == shippedObject)
    }

    @Test("nativeDictionary round-trips through Rule.fromManagedDictionary for sudo and authuri rules")
    func roundTrip() throws {
        for rule in [sudoRule(), authuriRule()] {
            let native = JamfRulesSchema.nativeDictionary(for: rule)
            guard case let .rule(decoded) = Rule.fromManagedDictionary(native) else {
                Issue.record("native dictionary for \(rule.id) did not decode: \(native)")
                continue
            }
            #expect(decoded == rule)
        }
        // Optional fields are absent when unset (the form shows blanks, not "").
        let minimal = JamfRulesSchema.nativeDictionary(for: authuriRule())
        #expect(minimal["commandPattern"] == nil)
        #expect(minimal["argPattern"] == nil)
        #expect(minimal["cacheSeconds"] == nil)
        #expect(minimal["requiredTeamID"] == nil)
        #expect(minimal["matchType"] == nil)
        #expect(minimal["authURI"] as? String == "system.preferences.datetime")
        // Booleans stay CFBoolean so the daemon's strict type check accepts them.
        let full = JamfRulesSchema.nativeDictionary(for: sudoRule())
        #expect(CFGetTypeID(full["logArguments"] as CFTypeRef) == CFBooleanGetTypeID())
        #expect(full["notify"] == nil)
        #expect(full["priority"] as? Int == 40)
    }

    @Test("the document targets the policy's sub-domain and pre-fills version, priority and rules")
    func prefilledDocument() throws {
        let profiles = [profile([sudoRule()]), profile([authuriRule()], key: "rules_authuri_x")]
        let export = try JamfRulesSchema.export(policyID: "Jamf Support Tools", policyName: "Jamf support tools", profiles: profiles)
        #expect(export.domain == "com.herojoneslabs.serberus.rules.jamf_support_tools")
        #expect(export.suggestedFilename == "com.herojoneslabs.serberus.rules.jamf_support_tools.json")
        #expect(export.ruleCount == 2)

        let root = try #require(try JSONSerialization.jsonObject(with: export.data) as? [String: Any])
        #expect(root["__preferencedomain"] as? String == export.domain)
        #expect((root["title"] as? String)?.contains("Jamf support tools") == true)
        let properties = try #require(root["properties"] as? [String: Any])
        #expect((properties["policyVersion"] as? [String: Any])?["default"] as? String == "1.4.0")
        #expect((properties["profilePriority"] as? [String: Any])?["default"] as? Int == 30)
        let rules = try #require((properties["rules"] as? [String: Any])?["default"] as? [[String: Any]])
        #expect(rules.count == 2)
        #expect(rules.map { $0["id"] as? String } == ["allow_jamf_checkjssconnection", "allow_datetime"])
        // The rest of the template is intact (the form still has every field).
        let items = try #require(((properties["rules"] as? [String: Any])?["items"] as? [String: Any])?["properties"] as? [String: Any])
        #expect(items.keys.count == 18)
        // Every pre-filled rule decodes back through the daemon's reader.
        for native in rules {
            guard case .rule = Rule.fromManagedDictionary(native) else {
                Issue.record("pre-filled rule does not decode: \(native)"); continue
            }
        }
    }

    @Test("an authuri-only policy gets a form with only the authorization-right fields, type locked")
    func authuriOnlyForm() throws {
        let export = try JamfRulesSchema.export(policyID: "dt", policyName: "Date & Time", profiles: [profile([authuriRule()], key: "rules_authuri_dt")])
        #expect(export.fieldSet == .authuriOnly)
        let root = try #require(try JSONSerialization.jsonObject(with: export.data) as? [String: Any])
        #expect((root["title"] as? String)?.hasSuffix("(authorization rights)") == true)
        let rulesProperty = try #require((root["properties"] as? [String: Any])?["rules"] as? [String: Any])
        let items = try #require((rulesProperty["items"] as? [String: Any])?["properties"] as? [String: Any])
        #expect(Set(items.keys) == ["id", "type", "action", "description", "priority", "authURI",
                                    "appTeamID", "appBundleID"])
        let type = try #require(items["type"] as? [String: Any])
        #expect(type["enum"] as? [String] == ["authuri"])
        #expect(type["default"] as? String == "authuri")
        #expect(((type["options"] as? [String: Any])?["enum_titles"] as? [String]) == ["Authorization right"])
        // The pre-filled row still decodes through the daemon's reader.
        let rows = try #require(rulesProperty["default"] as? [[String: Any]])
        guard case let .rule(decoded) = Rule.fromManagedDictionary(rows[0]) else { Issue.record("row did not decode"); return }
        #expect(decoded.match.authURI == "system.preferences.datetime")
    }

    @Test("a sudo-only policy drops authURI and locks type to sudo; a mixed policy keeps the full form")
    func sudoOnlyAndMixedForms() throws {
        let sudoOnly = try JamfRulesSchema.export(policyID: "s", policyName: "S", profiles: [profile([sudoRule()])])
        #expect(sudoOnly.fieldSet == .sudoOnly)
        var root = try #require(try JSONSerialization.jsonObject(with: sudoOnly.data) as? [String: Any])
        var items = try #require((((root["properties"] as? [String: Any])?["rules"] as? [String: Any])?["items"] as? [String: Any])?["properties"] as? [String: Any])
        #expect(items["authURI"] == nil)
        #expect(items.keys.count == 15)
        #expect((items["type"] as? [String: Any])?["enum"] as? [String] == ["sudo"])

        let mixed = try JamfRulesSchema.export(policyID: "m", policyName: "M", profiles: [profile([sudoRule()]), profile([authuriRule()], key: "rules_authuri_m")])
        #expect(mixed.fieldSet == .all)
        root = try #require(try JSONSerialization.jsonObject(with: mixed.data) as? [String: Any])
        items = try #require((((root["properties"] as? [String: Any])?["rules"] as? [String: Any])?["items"] as? [String: Any])?["properties"] as? [String: Any])
        #expect(items.keys.count == 18)
        #expect((items["type"] as? [String: Any])?["enum"] as? [String] == ["sudo", "authuri"])
    }

    @Test("the exported schema's description warns that Commander-published profiles render blank in the console")
    func descriptionCarriesBlankConsoleNote() throws {
        let export = try JamfRulesSchema.export(policyID: "support", policyName: "Support", profiles: [])
        let root = try #require(JSONSerialization.jsonObject(with: export.data) as? [String: Any])
        let description = try #require(root["description"] as? String)
        #expect(description.contains("do NOT render in the Jamf console"))
        #expect(description.contains("Publish to Jamf"))
        #expect(description.contains("console-editable"))
    }

    @Test("duplicate rule ids across a policy's profiles are suffixed so the daemon keeps them all")
    func duplicateIDs() throws {
        let a = profile([sudoRule()])
        let b = profile([sudoRule()], key: "rules_sudo_y")
        let document = try JamfRulesSchema.document(domain: "d", prefilledWith: [a, b])
        let rules = ((document["properties"] as? [String: Any])?["rules"] as? [String: Any])?["default"] as? [[String: Any]]
        #expect(rules?.map { $0["id"] as? String } == ["allow_jamf_checkjssconnection", "allow_jamf_checkjssconnection_2"])
    }

    @Test("no profiles → the plain template on the given domain (nothing pre-filled)")
    func plainTemplate() throws {
        let document = try JamfRulesSchema.document(domain: "com.herojoneslabs.serberus.rules.x")
        #expect(document["__preferencedomain"] as? String == "com.herojoneslabs.serberus.rules.x")
        let rules = (document["properties"] as? [String: Any])?["rules"] as? [String: Any]
        #expect(rules?["default"] == nil)
    }

    @Test("sub-domain slugs are lowercase, alphanumeric + underscore, never empty")
    func slugs() {
        #expect(JamfRulesSchema.subdomain(forPolicyID: "Jamf Tools / v2!") == "com.herojoneslabs.serberus.rules.jamf_tools_v2")
        #expect(JamfRulesSchema.slug("") == "policy")
        #expect(JamfRulesSchema.slug("___") == "policy")
    }

    // MARK: Shipped Support/jamf-schemas documents

    private static let schemasDirectory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Support/jamf-schemas")

    private func shippedSchema(_ name: String) throws -> [String: Any] {
        let url = Self.schemasDirectory.appendingPathComponent(name)
        return try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func ruleItemProperties(_ schema: [String: Any]) throws -> [String: Any] {
        try #require((((schema["properties"] as? [String: Any])?["rules"] as? [String: Any])?["items"]
            as? [String: Any])?["properties"] as? [String: Any])
    }

    @Test("the sub-domain schemas are the template on their own domain; the authURI ones are the authorization-right form",
          arguments: ["sudo", "authuri", "authuri.datetime", "authuri.printers"])
    func subdomainSchemas(suffix: String) throws {
        let domain = "com.herojoneslabs.serberus.rules.\(suffix)"
        let schema = try shippedSchema("\(domain).json")
        #expect(schema["__preferencedomain"] as? String == domain)
        let items = try ruleItemProperties(schema)
        #expect(items["notify"] == nil)
        if suffix.hasPrefix("authuri") {
            // Exactly the form Commander exports for an authURI-only policy:
            // `type` locked to authuri (so a new row is never a sudo rule
            // missing its command), and no field an authURI rule ignores.
            let form = try JamfRulesSchema.document(domain: domain, fieldSet: .authuriOnly)
            #expect(NSDictionary(dictionary: items) == NSDictionary(dictionary: try ruleItemProperties(form)))
            let type = try #require(items["type"] as? [String: Any])
            #expect(type["default"] as? String == "authuri")
            #expect(type["enum"] as? [String] == ["authuri"])
            for ignored in ["elevationType", "requireJustification", "maxGrantDurationSeconds", "cacheSeconds",
                            "requiredTeamID", "requiredBinaryHash", "commandPattern", "logArguments"] {
                #expect(items[ignored] == nil, "\(ignored)")
            }
            #expect(items["authURI"] != nil && items["appTeamID"] != nil && items["appBundleID"] != nil)
        } else {
            let template = try #require(try JSONSerialization.jsonObject(with: Data(JamfRulesSchema.templateJSON.utf8)) as? [String: Any])
            #expect(NSDictionary(dictionary: items) == NSDictionary(dictionary: try ruleItemProperties(template)))
        }
    }

    @Test("no shipped rules or JIT schema still offers the retired notify key")
    func noNotifyKey() throws {
        let template = try #require(try JSONSerialization.jsonObject(with: Data(JamfRulesSchema.templateJSON.utf8)) as? [String: Any])
        #expect(try ruleItemProperties(template)["notify"] == nil)
        let jit = try shippedSchema("com.herojoneslabs.serberus.jit.json")
        #expect((jit["properties"] as? [String: Any])?["notify"] == nil)
    }

    @Test("the config schema pre-fills monitor, while the reader still treats an absent or unknown mode as enforce")
    func configSchemaEnforcementDefault() throws {
        let config = try shippedSchema("com.herojoneslabs.serberus.config.json")
        let properties = try #require(config["properties"] as? [String: Any])
        #expect((properties["enforcementMode"] as? [String: Any])?["default"] as? String == "monitor")
        let absent = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.configDomain: ["daemonEnabled": true]]))
        #expect(absent.readConfig().value.enforcementMode == .enforce)
        let unknown = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.configDomain: ["enforcementMode": "yolo"]]))
        #expect(unknown.readConfig().value.enforcementMode == .enforce)

        let bypass = try #require((properties["pamBypass"] as? [String: Any])?["description"] as? String)
        #expect(bypass.contains("sudo only"))
        #expect(bypass.contains("authURI deny still applies to everyone"))
    }
}
