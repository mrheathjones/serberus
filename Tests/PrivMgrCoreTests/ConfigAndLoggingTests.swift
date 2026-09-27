import Foundation
import Testing
@testable import PrivMgrCore

@Suite("ManagedPreferencesReader")
struct ManagedPreferencesReaderTests {
    private func reader(config: [String: any Sendable] = [:],
                        rules: [String: any Sendable] = [:]) -> ManagedPreferencesReader {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: config,
            BundleConfig.rulesDomain: rules,
        ]))
    }

    @Test("defaults are fail-safe when the domain is empty")
    func emptyDomainDefaults() {
        let result = reader().readConfig()
        #expect(result.value.enforcementMode == .enforce)
        #expect(result.value.daemonEnabled)
        #expect(result.value.sudoCacheSeconds == 0)
        #expect(result.value.promptTimeoutSeconds == 60)
        #expect(result.value.pamBypass == PAMBypass())
        // The Commander direct-publish gate is OFF unless delivered as true.
        #expect(!result.value.commanderPublishEnabled)
        // Time-bound grants are ON by default — a configured duration expires;
        // indefinite grants need an explicit `false` in the profile.
        #expect(result.value.timeBoundGrantsEnabled)
        // No global default grant duration unless delivered.
        #expect(result.value.defaultGrantDurationMinutes == 0)
        #expect(result.value.defaultGrantDurationSeconds == 0)
        #expect(result.findings.isEmpty)
    }

    @Test("timeBoundGrantsEnabled parses false, and a mistyped value keeps the ON default")
    func timeBoundSwitchParses() {
        #expect(reader(config: ["timeBoundGrantsEnabled": true]).readConfig().value.timeBoundGrantsEnabled)
        #expect(reader(config: ["timeBoundGrantsEnabled": false]).readConfig().value.timeBoundGrantsEnabled == false)
        // A mistyped value falls back to the ON default (the restrictive one), with a finding.
        let mistyped = reader(config: ["timeBoundGrantsEnabled": 0]).readConfig()
        #expect(mistyped.value.timeBoundGrantsEnabled)
        #expect(!mistyped.findings.isEmpty)
    }

    @Test("the shipped Jamf config schema carries timeBoundGrantsEnabled defaulting on")
    func shippedConfigSchemaCarriesTimeBoundSwitch() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Support/jamf-schemas/com.herojoneslabs.serberus.config.json")
        let json = try JSONSerialization.jsonObject(with: try Data(contentsOf: url)) as? [String: Any]
        let prop = (json?["properties"] as? [String: Any])?["timeBoundGrantsEnabled"] as? [String: Any]
        #expect(prop?["type"] as? String == "boolean")
        #expect(prop?["default"] as? Bool == true)
    }

    @Test("defaultGrantDurationMinutes parses and converts to seconds")
    func defaultGrantDurationParses() {
        let result = reader(config: ["defaultGrantDurationMinutes": 15]).readConfig()
        #expect(result.value.defaultGrantDurationMinutes == 15)
        #expect(result.value.defaultGrantDurationSeconds == 900)
        #expect(result.findings.isEmpty)
    }

    @Test("an out-of-range defaultGrantDurationMinutes falls back to 0 with a finding")
    func defaultGrantDurationOutOfRange() {
        let result = reader(config: ["defaultGrantDurationMinutes": 100_000]).readConfig()
        #expect(result.value.defaultGrantDurationMinutes == 0)
        #expect(result.value.defaultGrantDurationSeconds == 0)
        #expect(!result.findings.isEmpty)
    }

    @Test("the shipped Jamf config schema carries defaultGrantDurationMinutes")
    func shippedConfigSchemaCarriesGrantDuration() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Support/jamf-schemas/com.herojoneslabs.serberus.config.json")
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let props = json?["properties"] as? [String: Any]
        let prop = props?["defaultGrantDurationMinutes"] as? [String: Any]
        #expect(prop?["type"] as? String == "integer")
        #expect(prop?["default"] as? Int == 0)
    }

    @Test("commanderPublishEnabled is read through the MANAGED layer only: a managed plist counts, an unforced CFPreferences value does not")
    func commanderPublishGateIsManagedOnly() throws {
        // A throwaway managed-preferences directory standing in for
        // /Library/Managed Preferences, plus a throwaway domain name so the
        // unforced write below never touches the real config domain.
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-managed-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let domain = "com.herojoneslabs.serberus.test.\(UUID().uuidString)"
        let source = CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid())

        // Unforced user-level value (what `defaults write` produces): invisible
        // to every read, since policy comes only from management.
        CFPreferencesSetAppValue("commanderPublishEnabled" as CFString, true as CFBoolean, domain as CFString)
        CFPreferencesAppSynchronize(domain as CFString)
        defer {
            CFPreferencesSetAppValue("commanderPublishEnabled" as CFString, nil, domain as CFString)
            CFPreferencesAppSynchronize(domain as CFString)
        }
        #expect(source.value(forKey: "commanderPublishEnabled", domain: domain) == nil)
        #expect(source.managedValue(forKey: "commanderPublishEnabled", domain: domain) == nil)

        // A managed plist for the domain IS honoured by both reads.
        let plist = try PropertyListSerialization.data(
            fromPropertyList: ["commanderPublishEnabled": false], format: .xml, options: 0)
        try plist.write(to: dir.appendingPathComponent("\(domain).plist"))
        #expect(source.managedValue(forKey: "commanderPublishEnabled", domain: domain) as? Bool == false)
        #expect(source.value(forKey: "commanderPublishEnabled", domain: domain) as? Bool == false)
    }

    @Test("the shipped Jamf config schema carries commanderPublishEnabled as an opt-in boolean")
    func shippedConfigSchemaCarriesGate() throws {
        // Tests/PrivMgrCoreTests/ConfigAndLoggingTests.swift → repo root is three levels up.
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let shipped = repo.appendingPathComponent("Support/jamf-schemas/com.herojoneslabs.serberus.config.json")
        let root = try #require(JSONSerialization.jsonObject(with: try Data(contentsOf: shipped)) as? [String: Any])
        #expect(root["__preferencedomain"] as? String == BundleConfig.configDomain)
        let properties = try #require(root["properties"] as? [String: Any])
        let gate = try #require(properties["commanderPublishEnabled"] as? [String: Any])
        #expect(gate["type"] as? String == "boolean")
        #expect(gate["default"] as? Bool == false)
        #expect((gate["description"] as? String)?.contains("do NOT render") == true)
    }

    @Test("commanderPublishEnabled parses true, and a mistyped value fails closed with a finding")
    func commanderPublishGate() {
        #expect(reader(config: ["commanderPublishEnabled": true]).readConfig().value.commanderPublishEnabled)
        #expect(!reader(config: ["commanderPublishEnabled": false]).readConfig().value.commanderPublishEnabled)
        let mistyped = reader(config: ["commanderPublishEnabled": "yes"]).readConfig()
        #expect(!mistyped.value.commanderPublishEnabled)
        #expect(!mistyped.findings.isEmpty)
    }

    @Test("full config parses")
    func fullConfig() {
        let result = reader(config: [
            "jamfProURL": "https://example.jamfcloud.com",
            "jamfAPIClientID": "client-id",
            "jamfAPIClientSecret": "client-secret",
            "daemonEnabled": false,
            "enforcementMode": "audit",
            "sudoCacheSeconds": 300,
            "promptTimeoutSeconds": 90,
            "pamBypass": ["groups": ["admin", "serberus-jit"], "users": ["breakglass-admin"]],
        ]).readConfig()
        #expect(result.value.jamfProURL?.host == "example.jamfcloud.com")
        #expect(!result.value.daemonEnabled)
        #expect(result.value.enforcementMode == .audit)
        #expect(result.value.sudoCacheSeconds == 300)
        #expect(result.value.pamBypass.groups == ["admin", "serberus-jit"])
        #expect(result.value.pamBypass.users == ["breakglass-admin"])
        #expect(result.findings.isEmpty)
    }

    @Test("invalid values produce findings and fall back, never crash")
    func invalidValues() {
        let result = reader(config: [
            "jamfProURL": "http://insecure.example.com",
            "enforcementMode": "yolo",
            "sudoCacheSeconds": 999_999,
            "pamBypass": "not-a-dict",
        ]).readConfig()
        #expect(result.value.jamfProURL == nil)
        #expect(result.value.enforcementMode == .enforce)
        #expect(result.value.sudoCacheSeconds == 0)
        #expect(result.value.pamBypass == PAMBypass())
        #expect(result.findings.count == 4)
    }

    @Test("pamBypass filters per element: one mistyped entry never drops the whole array (PAM parity)")
    func pamBypassPerElementFilter() {
        let result = reader(config: [
            "pamBypass": [
                "groups": ["admin", 7] as [any Sendable],
                "users": [true, "breakglass-admin"] as [any Sendable],
            ] as [String: any Sendable],
        ]).readConfig()
        // The valid break-glass identities survive; only the mistyped
        // elements are dropped, each with its own finding — matching
        // pam_config.c's serberus_config_copy_bypass_array semantics.
        #expect(result.value.pamBypass.groups == ["admin"])
        #expect(result.value.pamBypass.users == ["breakglass-admin"])
        #expect(result.findings.count == 2)
    }

    @Test("pamBypass non-array users/groups values yield empty lists with findings")
    func pamBypassNonArrayInnerValues() {
        let result = reader(config: [
            "pamBypass": [
                "groups": "admin",
                "users": ["breakglass-admin"],
            ] as [String: any Sendable],
        ]).readConfig()
        #expect(result.value.pamBypass.groups.isEmpty)
        #expect(result.value.pamBypass.users == ["breakglass-admin"])
        #expect(result.findings.count == 1)
    }

    @Test("rule profiles load from rules_* keys in sorted order")
    func ruleProfiles() throws {
        let profileB = Fixtures.profile(key: "rules_sudo_bbb", rules: [Fixtures.sudoRule()])
        let profileA = Fixtures.profile(key: "rules_sudo_aaa", rules: [Fixtures.sudoRule(id: "other")])
        let encoder = JSONEncoder()
        let result = reader(rules: [
            "rules_sudo_bbb": String(decoding: try encoder.encode(profileB), as: UTF8.self),
            "rules_sudo_aaa": String(decoding: try encoder.encode(profileA), as: UTF8.self),
            "unrelated_key": "ignored",
        ]).readRuleProfiles()
        #expect(result.value.map(\.profileKey) == ["rules_sudo_aaa", "rules_sudo_bbb"])
        #expect(result.findings.isEmpty)
    }

    @Test("undecodable profiles are reported and excluded")
    func badProfileExcluded() throws {
        let good = Fixtures.profile(key: "rules_sudo_good", rules: [Fixtures.sudoRule()])
        let result = reader(rules: [
            "rules_sudo_good": String(decoding: try JSONEncoder().encode(good), as: UTF8.self),
            "rules_sudo_bad": "{not json",
        ]).readRuleProfiles()
        #expect(result.value.map(\.profileKey) == ["rules_sudo_good"])
        #expect(result.findings.count == 1)
    }

    @Test("embedded profileKey mismatch: delivery key wins with a finding")
    func deliveryKeyWins() throws {
        let profile = Fixtures.profile(key: "rules_sudo_embedded", rules: [Fixtures.sudoRule()])
        let result = reader(rules: [
            "rules_sudo_delivery": String(decoding: try JSONEncoder().encode(profile), as: UTF8.self),
        ]).readRuleProfiles()
        #expect(result.value.first?.profileKey == "rules_sudo_delivery")
        #expect(result.findings.count == 1)
    }

    @Test("zero rules_* keys yields an empty profile set (pending_profiles)")
    func zeroProfiles() {
        let result = reader().readRuleProfiles()
        #expect(result.value.isEmpty)
        #expect(result.findings.isEmpty)
    }

    // MARK: Native (Jamf Custom Schema) rules

    private func nativeSudo(id: String = "prompt-echo") -> [String: any Sendable] {
        ["id": id, "type": "sudo", "action": "allow", "commandPattern": "/bin/echo",
         "matchType": "exact", "elevationType": "prompt", "priority": 10]
    }
    private func nativeAuthURI(id: String = "deny-datetime") -> [String: any Sendable] {
        ["id": id, "type": "authuri", "action": "deny",
         "authURI": "system.preferences.datetime", "priority": 20]
    }

    @Test("native rules array loads as one synthetic profile carrying both mechanisms")
    func nativeRulesLoad() {
        let result = reader(rules: ["rules": [nativeSudo(), nativeAuthURI()] as [any Sendable]])
            .readRuleProfiles()
        #expect(result.findings.isEmpty)
        #expect(result.value.count == 1)
        let profile = result.value.first
        #expect(profile?.profileKey == RuleSchemaConstants.nativeProfileKey)
        #expect(profile?.rules.count == 2)
        #expect(profile?.rules.contains {
            $0.id == "prompt-echo" && $0.type == .sudo
                && $0.match.commandPattern == "/bin/echo" && $0.elevation.type == .prompt
        } == true)
        #expect(profile?.rules.contains {
            $0.id == "deny-datetime" && $0.type == .authuri && $0.action == .deny
                && $0.match.authURI == "system.preferences.datetime"
        } == true)
    }

    @Test("native rules compose with JSON-string rules_* profiles")
    func nativeAndJSONCompose() throws {
        let json = Fixtures.profile(key: "rules_sudo_json", rules: [Fixtures.sudoRule()])
        let result = reader(rules: [
            "rules_sudo_json": String(decoding: try JSONEncoder().encode(json), as: UTF8.self),
            "rules": [nativeSudo()] as [any Sendable],
        ]).readRuleProfiles()
        #expect(result.findings.isEmpty)
        #expect(Set(result.value.map(\.profileKey)) == ["rules_sudo_json", RuleSchemaConstants.nativeProfileKey])
    }

    @Test("an invalid native rule is reported but valid siblings survive")
    func nativeInvalidReported() {
        // missing id
        let bad: [String: any Sendable] = ["type": "sudo", "action": "allow", "commandPattern": "/x"]
        let result = reader(rules: ["rules": [nativeSudo(), bad] as [any Sendable]]).readRuleProfiles()
        #expect(result.value.first?.rules.map(\.id) == ["prompt-echo"])
        #expect(result.findings.count == 1)
    }

    @Test("a non-array native rules value is a finding, leaving JSON profiles intact")
    func nativeNotArray() throws {
        let json = Fixtures.profile(key: "rules_sudo_json", rules: [Fixtures.sudoRule()])
        let result = reader(rules: [
            "rules_sudo_json": String(decoding: try JSONEncoder().encode(json), as: UTF8.self),
            "rules": "oops",
        ]).readRuleProfiles()
        #expect(result.value.map(\.profileKey) == ["rules_sudo_json"])
        #expect(result.findings.count == 1)
    }

    @Test("all-invalid native rules produce no synthetic profile")
    func nativeAllInvalid() {
        let bad: [String: any Sendable] = ["type": "sudo"]  // no id/action/command
        let result = reader(rules: ["rules": [bad] as [any Sendable]]).readRuleProfiles()
        #expect(result.value.isEmpty)
        #expect(result.findings.count == 1)
    }

    @Test("native policyVersion and profilePriority are read")
    func nativeMeta() {
        let result = reader(rules: [
            "rules": [nativeSudo()] as [any Sendable],
            "policyVersion": "2.3.4",
            "profilePriority": 17,
        ]).readRuleProfiles()
        #expect(result.value.first?.policyVersion == "2.3.4")
        #expect(result.value.first?.profilePriority == 17)
    }

    @Test("duplicate native rule ids keep the first with a finding")
    func nativeDuplicateID() {
        let result = reader(rules: [
            "rules": [nativeSudo(id: "dup"), nativeAuthURI(id: "dup")] as [any Sendable],
        ]).readRuleProfiles()
        #expect(result.value.first?.rules.map(\.id) == ["dup"])
        #expect(result.value.first?.rules.first?.type == .sudo)  // first wins
        #expect(result.findings.count == 1)
    }

    @Test("a native-authored allow rule evaluates as allow through the engine")
    func nativeRuleEvaluates() {
        let profiles = reader(rules: ["rules": [
            ["id": "silent-true", "type": "sudo", "action": "allow",
             "commandPattern": "/usr/bin/true", "matchType": "exact"] as [String: any Sendable],
        ] as [any Sendable]]).readRuleProfiles().value
        let request = Fixtures.sudoRequest(command: "/usr/bin/true", argv: [],
                                           identity: BinaryIdentity(canonicalPath: "/usr/bin/true",
                                                                    teamID: nil, sha256: "cc" + String(repeating: "0", count: 62),
                                                                    signingStatus: .valid))
        let result = evaluate(request, profiles: profiles)
        #expect(result.decision == .allow)
    }

    // MARK: Multi-domain composition (rules + rules.<suffix> sub-domains)

    /// A reader over the base rules domain plus arbitrary sibling sub-domains.
    private func multiReader(_ domains: [String: [String: any Sendable]]) -> ManagedPreferencesReader {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: domains))
    }

    private func sub(_ suffix: String) -> String { "\(BundleConfig.rulesDomain).\(suffix)" }

    @Test("native arrays in separate sub-domains compose instead of colliding")
    func nativeArraysAcrossSubDomainsCompose() {
        // The exact scenario that collided in one domain: a sudo native array
        // and an authuri native array, now each in its own sub-domain.
        let result = multiReader([
            sub("sudo"): ["rules": [nativeSudo(id: "s1")] as [any Sendable]],
            sub("authuri"): ["rules": [nativeAuthURI(id: "a1")] as [any Sendable]],
        ]).readRuleProfiles()
        #expect(result.findings.isEmpty)
        // Each native array becomes its own synthetic profile, qualified by suffix.
        #expect(result.value.map(\.profileKey).sorted()
            == ["authuri/\(RuleSchemaConstants.nativeProfileKey)", "sudo/\(RuleSchemaConstants.nativeProfileKey)"])
        let allIDs = result.value.flatMap { $0.rules.map(\.id) }.sorted()
        #expect(allIDs == ["a1", "s1"])
    }

    @Test("base domain native array keeps its unqualified profileKey (backward compatible)")
    func baseDomainUnqualified() {
        let result = multiReader([
            BundleConfig.rulesDomain: ["rules": [nativeSudo(id: "base")] as [any Sendable]],
            sub("sudo"): ["rules": [nativeSudo(id: "subrule")] as [any Sendable]],
        ]).readRuleProfiles()
        #expect(result.findings.isEmpty)
        #expect(result.value.map(\.profileKey).sorted()
            == [RuleSchemaConstants.nativeProfileKey, "sudo/\(RuleSchemaConstants.nativeProfileKey)"])
    }

    @Test("rules_* keys in a sub-domain are qualified so identical keys never merge")
    func subDomainStringKeysQualified() throws {
        let p = Fixtures.profile(key: "rules_x", rules: [Fixtures.sudoRule()])
        let json = String(decoding: try JSONEncoder().encode(p), as: UTF8.self)
        let result = multiReader([
            BundleConfig.rulesDomain: ["rules_x": json],
            sub("team"): ["rules_x": json],
        ]).readRuleProfiles()
        #expect(result.findings.isEmpty)
        // Same delivery key in two domains → distinct qualified profileKeys.
        #expect(result.value.map(\.profileKey).sorted() == ["rules_x", "team/rules_x"])
    }

    @Test("all authoring shapes compose across domains: base string + base native + sub native")
    func allShapesCompose() throws {
        let p = Fixtures.profile(key: "rules_app", rules: [Fixtures.sudoRule(id: "app")])
        let json = String(decoding: try JSONEncoder().encode(p), as: UTF8.self)
        let result = multiReader([
            BundleConfig.rulesDomain: [
                "rules_app": json,
                "rules": [nativeAuthURI(id: "base-native")] as [any Sendable],
            ],
            sub("sudo"): ["rules": [nativeSudo(id: "sub-native")] as [any Sendable]],
        ]).readRuleProfiles()
        #expect(result.findings.isEmpty)
        #expect(Set(result.value.map(\.profileKey)) == [
            "rules_app",
            RuleSchemaConstants.nativeProfileKey,
            "sudo/\(RuleSchemaConstants.nativeProfileKey)",
        ])
    }

    @Test("NESTED sub-domains compose: one profile per purpose under .rules.authuri.*")
    func nestedSubDomainsCompose() {
        // The real-world need: several config profiles each carrying their own
        // native `rules` array for a different purpose. Two profiles CANNOT share
        // one domain (macOS keeps one), so each gets its own nested sub-domain.
        let result = multiReader([
            sub("authuri.datetime"): ["rules": [nativeAuthURI(id: "dt")] as [any Sendable]],
            sub("authuri.printers"): ["rules": [nativeAuthURI(id: "print")] as [any Sendable]],
            sub("sudo.jamf"): ["rules": [nativeSudo(id: "jamf")] as [any Sendable]],
        ]).readRuleProfiles()
        #expect(result.findings.isEmpty)
        // All three native arrays survive, each namespaced by its full suffix.
        #expect(result.value.map(\.profileKey).sorted() == [
            "authuri.datetime/\(RuleSchemaConstants.nativeProfileKey)",
            "authuri.printers/\(RuleSchemaConstants.nativeProfileKey)",
            "sudo.jamf/\(RuleSchemaConstants.nativeProfileKey)",
        ])
        #expect(result.value.flatMap { $0.rules.map(\.id) }.sorted() == ["dt", "jamf", "print"])
    }

    @Test("domain matching is precise: a sibling like rulesX is never swept in")
    func domainMatchPrecision() {
        let source = DictionaryPreferencesSource(domains: [
            BundleConfig.rulesDomain: [:],
            sub("sudo"): [:],
            "\(BundleConfig.rulesDomain)X": [:],   // NOT a sub-domain
            BundleConfig.configDomain: [:],        // unrelated
        ])
        let matched = Set(source.domains(matchingPrefix: BundleConfig.rulesDomain))
        #expect(matched.contains(sub("sudo")))
        #expect(!matched.contains("\(BundleConfig.rulesDomain)X"))
        #expect(!matched.contains(BundleConfig.configDomain))
    }

    @Test("results are deterministic: base sorts before sub-domains")
    func deterministicDomainOrder() {
        let result = multiReader([
            sub("zzz"): ["rules": [nativeSudo(id: "z")] as [any Sendable]],
            BundleConfig.rulesDomain: ["rules": [nativeSudo(id: "base")] as [any Sendable]],
            sub("aaa"): ["rules": [nativeSudo(id: "a")] as [any Sendable]],
        ]).readRuleProfiles()
        // Base ("…rules") first, then "…rules.aaa", then "…rules.zzz".
        #expect(result.value.map(\.profileKey) == [
            RuleSchemaConstants.nativeProfileKey,
            "aaa/\(RuleSchemaConstants.nativeProfileKey)",
            "zzz/\(RuleSchemaConstants.nativeProfileKey)",
        ])
    }
}

@Suite("Rule.fromManagedDictionary (native Jamf schema)")
struct NativeRuleConversionTests {
    private func isInvalid(_ dict: [String: Any]) -> Bool {
        if case .invalid = Rule.fromManagedDictionary(dict) { return true }
        return false
    }

    @Test("valid sudo rule maps flat keys onto the nested model")
    func validSudo() {
        let dict: [String: Any] = [
            "id": "prompt-jamf", "type": "sudo", "action": "allow",
            "description": "jamf recon", "priority": 30,
            "commandPattern": "/usr/local/bin/jamf", "matchType": "exact", "argPattern": "^recon$",
            "elevationType": "prompt", "notify": true, "logArguments": false,
            "requireJustification": true, "maxGrantDurationSeconds": 300,
            "cacheSeconds": 60, "requiredTeamID": "TEAM123",
        ]
        guard case .rule(let rule) = Rule.fromManagedDictionary(dict) else {
            Issue.record("expected .rule"); return
        }
        #expect(rule.id == "prompt-jamf")
        #expect(rule.type == .sudo)
        #expect(rule.action == .allow)
        #expect(rule.priority == 30)
        #expect(rule.match.commandPattern == "/usr/local/bin/jamf")
        #expect(rule.match.matchType == .exact)
        #expect(rule.match.argPattern == "^recon$")
        #expect(rule.match.requiredTeamID == "TEAM123")
        #expect(rule.elevation.type == .prompt)
        #expect(rule.elevation.logArguments == false)
        #expect(rule.conditions.requireJustification == true)
        #expect(rule.conditions.maxGrantDurationSeconds == 300)
        #expect(rule.cacheSeconds == 60)
    }

    @Test("valid authuri rule uses model defaults for unspecified fields")
    func validAuthURI() {
        guard case .rule(let rule) = Rule.fromManagedDictionary([
            "id": "deny-dt", "type": "authuri", "action": "deny",
            "authURI": "system.preferences.datetime",
        ]) else { Issue.record("expected .rule"); return }
        #expect(rule.type == .authuri)
        #expect(rule.match.authURI == "system.preferences.datetime")
        #expect(rule.match.commandPattern == nil)
        #expect(rule.elevation.type == .silent)
        // Off unless the rule opts in: argv can carry secrets the redactor misses.
        #expect(rule.elevation.logArguments == false)
        #expect(rule.priority == 50)
        #expect(rule.cacheSeconds == nil)
    }

    @Test("missing/invalid id, type, action are rejected — never a permissive default")
    func requiredFields() {
        #expect(isInvalid(["type": "sudo", "action": "allow", "commandPattern": "/x"]))
        #expect(isInvalid(["id": "a", "action": "allow", "commandPattern": "/x"]))
        #expect(isInvalid(["id": "a", "type": "sudo", "commandPattern": "/x"]))
        #expect(isInvalid(["id": "a", "type": "bogus", "action": "allow"]))
        #expect(isInvalid(["id": "a", "type": "sudo", "action": "maybe", "commandPattern": "/x"]))
    }

    @Test("sudo needs a commandPattern unless matchType is any; authuri needs an authURI")
    func matchTargets() {
        #expect(isInvalid(["id": "a", "type": "sudo", "action": "allow"]))
        #expect(isInvalid(["id": "a", "type": "authuri", "action": "deny"]))
        guard case .rule = Rule.fromManagedDictionary(
            ["id": "a", "type": "sudo", "action": "allow", "matchType": "any"]) else {
            Issue.record("matchType any without a command should be valid"); return
        }
    }

    @Test("empty-string optionals are treated as absent")
    func emptyStringsBecomeNil() {
        guard case .rule(let rule) = Rule.fromManagedDictionary([
            "id": "a", "type": "sudo", "action": "allow", "commandPattern": "/x",
            "argPattern": "   ", "requiredTeamID": "", "requiredBinaryHash": "",
        ]) else { Issue.record("expected .rule"); return }
        #expect(rule.match.argPattern == nil)
        #expect(rule.match.requiredTeamID == nil)
        #expect(rule.match.requiredBinaryHash == nil)
    }

    @Test("present-but-invalid enum or wrong-typed fields are rejected, never silently coerced")
    func presentButInvalidRejected() {
        // elevationType typo would have become the permissive .silent (silent grant)
        #expect(isInvalid(["id": "a", "type": "sudo", "action": "allow",
                           "commandPattern": "/x", "elevationType": "Prompt"]))
        // matchType typo would have become .exact — an inert deny = fail-open
        #expect(isInvalid(["id": "a", "type": "sudo", "action": "deny",
                           "commandPattern": "/usr/local/bin/*", "matchType": "golb"]))
        // wrong types for bool / int fields drop a security flag silently → reject
        #expect(isInvalid(["id": "a", "type": "sudo", "action": "allow",
                           "commandPattern": "/x", "requireJustification": 1]))
        // The retired `notify` key is ignored whatever its value, so an old
        // profile that still carries it keeps working.
        #expect(!isInvalid(["id": "a", "type": "sudo", "action": "allow",
                            "commandPattern": "/x", "notify": 1]))
        #expect(isInvalid(["id": "a", "type": "sudo", "action": "allow",
                           "commandPattern": "/x", "priority": true]))
        // a non-string commandPattern collapses to "missing command" → reject
        #expect(isInvalid(["id": "a", "type": "sudo", "action": "allow", "commandPattern": 123]))
    }

    @Test("valid non-default enum values are accepted; absent optionals use defaults")
    func validEnumsAndDefaults() {
        guard case .rule(let r1) = Rule.fromManagedDictionary([
            "id": "a", "type": "sudo", "action": "allow", "commandPattern": "/x",
            "matchType": "prefix-regex", "elevationType": "prompt",
        ]) else { Issue.record("expected .rule"); return }
        #expect(r1.match.matchType == .prefixRegex)
        #expect(r1.elevation.type == .prompt)

        guard case .rule(let r2) = Rule.fromManagedDictionary([
            "id": "b", "type": "sudo", "action": "allow", "commandPattern": "/y",
        ]) else { Issue.record("expected .rule"); return }
        #expect(r2.elevation.type == .silent)
        #expect(r2.match.matchType == .exact)
    }
}

@Suite("CFPreferencesSource managed directory")
struct CFPreferencesSourceManagedTests {
    /// Writes `values` as `<domain>.plist` into a fresh temp directory that
    /// stands in for /Library/Managed Preferences, returning the source.
    private func source(domain: String, values: [String: Any]) throws -> CFPreferencesSource {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-managed-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(
            fromPropertyList: values, format: .xml, options: 0)
        try data.write(to: dir.appendingPathComponent("\(domain).plist"))
        return CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid())
    }

    @Test("MDM-delivered keys and values are read from the managed plist")
    func managedPlistIsRead() throws {
        let domain = "com.serberus.test.managed-\(UUID().uuidString)"
        let src = try source(domain: domain, values: [
            "rules_authuri_a": "{\"schemaVersion\":\"1.0\"}",
            "PayloadUUID": "ABC",
        ])
        #expect(Set(src.keys(inDomain: domain)) == ["rules_authuri_a", "PayloadUUID"])
        #expect(src.value(forKey: "rules_authuri_a", domain: domain) as? String
                == "{\"schemaVersion\":\"1.0\"}")
    }

    @Test("managed value outranks the CFPreferences composite")
    func managedValueWins() throws {
        let domain = "com.serberus.test.precedence-\(UUID().uuidString)"
        let src = try source(domain: domain, values: ["shared_key": "managed-value"])
        // No CFPreferences value exists for this throwaway domain, but the
        // managed read must be consulted first and returned as-is.
        #expect(src.value(forKey: "shared_key", domain: domain) as? String == "managed-value")
    }

    @Test("policy reads ignore unforced CFPreferences values")
    func unforcedValuesAreIgnored() throws {
        let domain = "com.serberus.test.unforced-\(UUID().uuidString)"
        let emptyDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-managed-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: emptyDir, withIntermediateDirectories: true)
        let src = CFPreferencesSource(managedPreferencesDirectory: emptyDir.path, requiredOwnerUID: getuid())

        // What a `defaults write` (or a JIT admin writing /Library/Preferences)
        // would plant: an unforced value MDM never delivered.
        CFPreferencesSetAppValue("enforcementMode" as CFString, "monitor" as CFString, domain as CFString)
        CFPreferencesAppSynchronize(domain as CFString)
        defer {
            CFPreferencesSetAppValue("enforcementMode" as CFString, nil, domain as CFString)
            CFPreferencesAppSynchronize(domain as CFString)
        }

        #expect(src.value(forKey: "enforcementMode", domain: domain) == nil)
        #expect(!src.keys(inDomain: domain).contains("enforcementMode"))
    }

    @Test("absent or malformed managed plist yields no values")
    func absentManagedPlistIsSafe() throws {
        let domain = "com.serberus.test.absent-\(UUID().uuidString)"
        let emptyDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-managed-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: emptyDir, withIntermediateDirectories: true)
        let src = CFPreferencesSource(managedPreferencesDirectory: emptyDir.path, requiredOwnerUID: getuid())
        #expect(src.keys(inDomain: domain).isEmpty)
        #expect(src.value(forKey: "anything", domain: domain) == nil)

        // Malformed plist: parse failure must not throw or surface keys.
        try Data("not a plist".utf8).write(to: emptyDir.appendingPathComponent("\(domain).plist"))
        #expect(src.keys(inDomain: domain).isEmpty)
        #expect(src.value(forKey: "anything", domain: domain) == nil)
    }

    @Test("rule profiles flow end-to-end through a managed plist")
    func endToEndThroughReader() throws {
        let domain = BundleConfig.rulesDomain
        let profile = Fixtures.profile(key: "rules_authuri_mdm", rules: [Fixtures.sudoRule()])
        let json = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
        let src = try source(domain: domain, values: [
            "rules_authuri_mdm": json,
            "PayloadUUID": "ignored",
        ])
        let result = ManagedPreferencesReader(source: src).readRuleProfiles()
        #expect(result.value.map(\.profileKey) == ["rules_authuri_mdm"])
        #expect(result.findings.isEmpty)
    }
}

@Suite("JamfCredentialStore")
struct JamfCredentialStoreTests {
    @Test("missing keys are surfaced specifically, in order")
    func missingKeys() {
        func store(_ config: [String: any Sendable]) -> JamfCredentialStore {
            JamfCredentialStore(reader: ManagedPreferencesReader(
                source: DictionaryPreferencesSource(domains: [BundleConfig.configDomain: config])
            ))
        }
        #expect(store([:]).connectionState() == .notConfigured(missingKey: "jamfProURL"))
        #expect(store(["jamfProURL": "https://example.jamfcloud.com"]).connectionState()
            == .notConfigured(missingKey: "jamfAPIClientID"))
        #expect(store(["jamfProURL": "https://example.jamfcloud.com", "jamfAPIClientID": "id"]).connectionState()
            == .notConfigured(missingKey: "jamfAPIClientSecret"))

        let configured = store([
            "jamfProURL": "https://example.jamfcloud.com",
            "jamfAPIClientID": "id",
            "jamfAPIClientSecret": "secret",
        ]).connectionState()
        guard case let .configured(credentials) = configured else {
            Issue.record("expected configured state")
            return
        }
        #expect(credentials.clientID == "id")
    }
}

@Suite("ArgumentRedactor")
struct RedactionTests {
    @Test("separate-value flags are redacted")
    func separateValue() {
        let argv = ["login", "--password", "hunter2", "--user", "alice"]
        #expect(ArgumentRedactor.redact(argv) == ["login", "--password", "<redacted>", "--user", "alice"])
    }

    @Test("equals-form flags are redacted")
    func equalsForm() {
        let argv = ["deploy", "--token=abc123", "--api-key=xyz", "--count=2"]
        #expect(ArgumentRedactor.redact(argv) == ["deploy", "--token=<redacted>", "--api-key=<redacted>", "--count=2"])
    }

    @Test("all sensitive flags are covered, case-insensitively")
    func allFlags() {
        for flag in ["--password", "--token", "--secret", "--apikey", "--api-key", "--client-secret", "--PASSWORD"] {
            let redacted = ArgumentRedactor.redact([flag, "sensitive-value"])
            #expect(redacted == [flag, "<redacted>"], "flag \(flag) leaked")
        }
    }

    @Test("justification text is redacted")
    func justification() {
        let text = "needed for deploy --client-secret s3cr3t end"
        #expect(ArgumentRedactor.redact(text: text) == "needed for deploy --client-secret <redacted> end")
    }

    @Test("non-sensitive argv passes through untouched")
    func passthrough() {
        let argv = ["install", "wget", "--verbose"]
        #expect(ArgumentRedactor.redact(argv) == argv)
    }
}

@Suite("Logging — signed JSONL", .serialized)
struct LoggingTests {
    private func makeEvent(timestamp: Date = Fixtures.now) -> DecisionEvent {
        DecisionEvent(
            timestamp: timestamp,
            outcome: .granted,
            enforcementMode: .enforce,
            authURI: nil,
            sudoCommand: "/opt/homebrew/bin/brew",
            arguments: ["install", "--token", "abc"],
            processPath: "/opt/homebrew/bin/brew",
            processTeamID: "",
            processHash: Fixtures.brewIdentity.sha256,
            userName: "alice",
            userUID: 501,
            ruleID: "allow-brew",
            profileKey: "rules_sudo_test",
            grantID: nil,
            justification: nil,
            grantDurationSeconds: 0,
            cacheHit: false,
            deviceSerial: "TESTSERIAL",
            daemonVersion: "1.0.0",
            pamModuleVersion: "1.0.0",
            policyVersion: "1.0.0"
        )
    }

    @Test("decision events round-trip and the HMAC chain verifies")
    func chainVerifies() async throws {
        let directory = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let provider = InMemoryKeyProvider.random()
        let logger = try DecisionLogger(directory: directory, keyProvider: provider)

        for offset in 0..<5 {
            try await logger.log(makeEvent(timestamp: Fixtures.now.addingTimeInterval(Double(offset))))
        }
        let day = LogDay.stamp(for: Fixtures.now)
        #expect(try await logger.verify(day: day) == nil)
        #expect(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("decisions-\(day).jsonl.hmac").path
        ))
    }

    @Test("a tampered line breaks verification at its index")
    func tamperBreaksChain() async throws {
        let directory = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let provider = InMemoryKeyProvider.random()
        let logger = try DecisionLogger(directory: directory, keyProvider: provider)
        for offset in 0..<3 {
            try await logger.log(makeEvent(timestamp: Fixtures.now.addingTimeInterval(Double(offset))))
        }

        let day = LogDay.stamp(for: Fixtures.now)
        let fileURL = directory.appendingPathComponent("decisions-\(day).jsonl")
        var lines = try String(contentsOf: fileURL, encoding: .utf8)
            .split(separator: "\n").map(String.init)
        lines[1] = lines[1].replacingOccurrences(of: "alice", with: "mallory")
        try (lines.joined(separator: "\n") + "\n").write(to: fileURL, atomically: true, encoding: .utf8)

        #expect(try await logger.verify(day: day) == 1)
    }

    @Test("sensitive arguments never reach disk")
    func redactionOnDisk() async throws {
        let directory = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let logger = try DecisionLogger(directory: directory, keyProvider: InMemoryKeyProvider.random())
        try await logger.log(makeEvent())

        let day = LogDay.stamp(for: Fixtures.now)
        let content = try String(
            contentsOf: directory.appendingPathComponent("decisions-\(day).jsonl"),
            encoding: .utf8
        )
        #expect(!content.contains("\"abc\""))
        #expect(content.contains("<redacted>"))
    }

    @Test("log rotation prunes day files past retention, sidecars included")
    func rotation() throws {
        let directory = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let old = "decisions-2026-01-01.jsonl"
        let oldSidecar = "decisions-2026-01-01.jsonl.hmac"
        let fresh = "decisions-" + LogDay.stamp(for: Fixtures.now) + ".jsonl"
        let unrelated = "notes.txt"
        for name in [old, oldSidecar, fresh, unrelated] {
            FileManager.default.createFile(
                atPath: directory.appendingPathComponent(name).path,
                contents: Data("x\n".utf8)
            )
        }

        let removed = try LogRotator(directory: directory).prune(retentionDays: 90, now: Fixtures.now)
        #expect(removed == [old, oldSidecar])
        #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(fresh).path))
        #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(unrelated).path))
    }

    @Test("audit mode maps decisions to would-grant / would-deny")
    func outcomeMapping() {
        #expect(DecisionEvent.outcome(for: .allow, mode: .enforce) == .granted)
        #expect(DecisionEvent.outcome(for: .timedGrant, mode: .enforce) == .granted)
        #expect(DecisionEvent.outcome(for: .deny, mode: .enforce) == .denied)
        #expect(DecisionEvent.outcome(for: .prompt, mode: .enforce) == .denied)
        #expect(DecisionEvent.outcome(for: .allow, mode: .audit) == .wouldGrant)
        #expect(DecisionEvent.outcome(for: .deny, mode: .audit) == .wouldDeny)
    }
}

@Suite("Key providers")
struct KeyProviderTests {
    @Test("FileKeyProvider persists a 32-byte key (mode 600); distinct accounts differ")
    func fileKeyProviderPersists() throws {
        let dir = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let provider = FileKeyProvider(directory: dir)

        let k1 = try provider.key(account: "grants-hmac-key")
        let k2 = try provider.key(account: "grants-hmac-key")
        #expect(k1.count == 32)
        #expect(k1 == k2)                                        // stable / persisted
        #expect(try provider.key(account: "log-hmac-key") != k1) // distinct accounts

        let url = dir.appendingPathComponent(".grants-hmac-key.key")
        let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(perms?.intValue == 0o600)
    }

    @Test("FileKeyProvider refuses a key file others can read, or a symlink")
    func fileKeyProviderRefusesExposedKey() throws {
        let dir = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let provider = FileKeyProvider(directory: dir)
        let url = dir.appendingPathComponent(".grants-hmac-key.key")

        try Data(repeating: 7, count: 32).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        #expect(throws: LoggingError.self) { try provider.key(account: "grants-hmac-key") }

        try FileManager.default.removeItem(at: url)
        let elsewhere = dir.appendingPathComponent("planted.key")
        try Data(repeating: 9, count: 32).write(to: elsewhere)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: elsewhere.path)
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: elsewhere)
        #expect(throws: LoggingError.self) { try provider.key(account: "grants-hmac-key") }
    }

    @Test("FileKeyProvider leaves no temporary files behind")
    func fileKeyProviderNoLeftovers() throws {
        let dir = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = try FileKeyProvider(directory: dir).key(account: "log-hmac-key")
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == [".log-hmac-key.key"])
    }

    @Test("FallbackKeyProvider uses the secondary when the primary throws")
    func fallbackUsesSecondary() throws {
        let provider = FallbackKeyProvider(
            primary: InMemoryKeyProvider(keys: [:]), // throws for any account
            secondary: InMemoryKeyProvider(keys: ["acct": Data(repeating: 7, count: 32)])
        )
        #expect(try provider.key(account: "acct") == Data(repeating: 7, count: 32))
    }

    @Test("FallbackKeyProvider returns the primary key when available (no fallback)")
    func fallbackPrefersPrimary() throws {
        let provider = FallbackKeyProvider(
            primary: InMemoryKeyProvider(keys: ["acct": Data(repeating: 1, count: 32)]),
            secondary: InMemoryKeyProvider(keys: ["acct": Data(repeating: 9, count: 32)])
        )
        #expect(try provider.key(account: "acct") == Data(repeating: 1, count: 32))
    }
}

// MARK: - Enforceability + last-known-good config snapshot

/// The safety predicate the whole enrollment-race design rests on.
///
/// `enforce` with an EMPTY `pamBypass` is the shape an ABSENT config parses to
/// (fail-safe defaults) — and with `pam_serberus` wired it denies every `sudo` on
/// the Mac with no way back in. So "enforce" is only ever adopted alongside a
/// break-glass population; `monitor`/`audit` deny nothing and need none.
@Suite("SerberusConfig.isEnforceable")
struct ConfigEnforceabilityTests {
    private func config(
        _ mode: EnforcementMode,
        groups: [String] = [],
        users: [String] = []
    ) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60,
            pamBypass: PAMBypass(groups: groups, users: users)
        )
    }

    @Test("monitor and audit are always enforceable — they deny nothing")
    func nonEnforcingModesAreAlwaysSafe() {
        #expect(config(.monitor).isEnforceable)
        #expect(config(.audit).isEnforceable)
        #expect(config(.monitor, groups: ["admin"]).isEnforceable)
        #expect(config(.audit, users: ["breakglass"]).isEnforceable)
    }

    @Test("enforce with an empty pamBypass is NOT enforceable (this is the brick)")
    func enforceWithoutBreakGlassIsUnsafe() {
        #expect(!config(.enforce).isEnforceable)
    }

    @Test("enforce is enforceable with a bypass group OR a bypass user")
    func enforceWithBreakGlassIsSafe() {
        #expect(config(.enforce, groups: ["admin"]).isEnforceable)
        #expect(config(.enforce, users: ["breakglass"]).isEnforceable)
        #expect(config(.enforce, groups: ["admin"], users: ["breakglass"]).isEnforceable)
    }

    @Test("the fail-safe default config (what an ABSENT profile parses to) is not enforceable")
    func absentConfigParsesToAnUnenforceableConfig() {
        let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:]))
        #expect(!reader.configIsPresent())
        #expect(!reader.readConfig().value.isEnforceable) // ⇒ never enforced
    }

    @Test("configIsPresent distinguishes an absent domain from a delivered one")
    func configPresenceIsDetected() {
        let absent = ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.rulesDomain: ["rules_x": "{}"],
        ]))
        #expect(!absent.configIsPresent())

        // Even a PARTIAL profile (only sudoEnrollment) counts as present — which is
        // precisely why presence alone is not enough to enforce on.
        let partial = ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: ["sudoEnrollment": ["group": "staff"] as [String: any Sendable]],
        ]))
        #expect(partial.configIsPresent())
        #expect(!partial.readConfig().value.isEnforceable)
    }
}

/// The snapshot `pam_serberus` and the daemon both fall back to. Its on-disk key
/// shape is a subset of the managed config domain, so `pam_config.c` parses it
/// with the same code path.
@Suite("LastKnownGoodConfigStore")
struct LastKnownGoodConfigStoreTests {
    private func temporaryURL() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-lkg-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("last-known-good-config.plist")
    }

    private func config(
        mode: EnforcementMode = .enforce,
        groups: [String] = ["admin"],
        users: [String] = ["breakglass"]
    ) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: URL(string: "https://example.jamfcloud.com"),
            jamfAPIClientID: "client", jamfAPIClientSecret: "secret",
            daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: 120,
            promptTimeoutSeconds: 45,
            pamBypass: PAMBypass(groups: groups, users: users),
            sudoEnrollment: SerberusConfig.SudoEnrollment(
                group: "staff", users: ["carol"], idpGroups: ["Test-Name"],
                idpSource: .jamfConnectState, requireRootOwnedState: true
            )
        )
    }

    @Test("save/load round-trips the fields the break-glass decision depends on")
    func roundTripPreservesEnforcementAndBypass() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        #expect(!store.exists())

        try store.save(config())
        #expect(store.exists())

        let loaded = try #require(store.load())
        #expect(loaded.enforcementMode == .enforce)
        #expect(loaded.pamBypass.groups == ["admin"])
        #expect(loaded.pamBypass.users == ["breakglass"])
        #expect(loaded.daemonEnabled)
        #expect(loaded.sudoCacheSeconds == 120)
        #expect(loaded.promptTimeoutSeconds == 45)
        #expect(loaded.sudoEnrollment.group == "staff")
        #expect(loaded.sudoEnrollment.users == ["carol"])
        #expect(loaded.sudoEnrollment.idpGroups == ["Test-Name"])
        #expect(loaded.sudoEnrollment.idpSource == .jamfConnectState)
        #expect(loaded.sudoEnrollment.requireRootOwnedState)
    }

    /// pam_serberus reads this file as the PRE-elevation user, so it must be
    /// world-readable — otherwise break-glass would be invisible to it and a
    /// profile-less Mac would deny every sudo.
    @Test("the snapshot is written 0644, and the write is atomic (temp + rename)")
    func snapshotIsWorldReadableAndWrittenAtomically() throws {
        let url = try temporaryURL()
        let directory = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())

        try store.save(config())
        try store.save(config(groups: ["wheel"])) // overwrite in place

        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.int16Value == 0o644)
        // No temp file survives a successful save (rename consumed it).
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(leftovers == ["last-known-good-config.plist"])
        #expect(store.load()?.pamBypass.groups == ["wheel"])
    }

    @Test("the on-disk key shape is the managed config domain's, so pam_config.c can parse it")
    func keyShapeMatchesTheManagedDomain() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid()).save(config())

        let data = try #require(FileManager.default.contents(atPath: url.path))
        var format = PropertyListSerialization.PropertyListFormat.binary
        let raw = try PropertyListSerialization.propertyList(from: data, options: [], format: &format)
        let plist = try #require(raw as? [String: Any])

        #expect(format == .xml)
        #expect(plist["enforcementMode"] as? String == "enforce")
        #expect(plist["daemonEnabled"] as? Bool == true)
        #expect(plist["sudoCacheSeconds"] as? Int == 120)
        #expect(plist["promptTimeoutSeconds"] as? Int == 45)
        let bypass = try #require(plist["pamBypass"] as? [String: Any])
        #expect(bypass["groups"] as? [String] == ["admin"])
        #expect(bypass["users"] as? [String] == ["breakglass"])
        let enrollment = try #require(plist["sudoEnrollment"] as? [String: Any])
        #expect(enrollment["group"] as? String == "staff")
        #expect(enrollment["idpSource"] as? String == "jamf_connect_state")

        // Jamf credentials are NEVER persisted — this file is world-readable.
        #expect(plist["jamfAPIClientSecret"] == nil)
        #expect(plist["jamfAPIClientID"] == nil)
        #expect(plist["jamfProURL"] == nil)
    }

    @Test("a snapshot that is not enforceable is treated as absent, never adopted")
    func unenforceableSnapshotIsRejected() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        // A hand-edited / older-build snapshot: enforce with no break-glass. Adopting
        // it would be exactly the lockout the LKG exists to prevent.
        let hostile: [String: Any] = ["enforcementMode": "enforce", "daemonEnabled": true]
        try PropertyListSerialization
            .data(fromPropertyList: hostile, format: .xml, options: 0)
            .write(to: url)

        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        #expect(store.exists())   // the file is there (the resolver keys bootstrap on this)…
        #expect(store.load() == nil) // …but it is not usable ⇒ the daemon fails CLOSED, not bootstrap
    }

    @Test("a truncated / non-plist snapshot loads as nil rather than throwing")
    func corruptSnapshotLoadsAsNil() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try Data("<?xml version=\"1.0\"".utf8).write(to: url)
        #expect(LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid()).load() == nil)
    }

    @Test("an absent snapshot: exists() false, load() nil")
    func absentSnapshot() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        #expect(!store.exists())
        #expect(store.load() == nil)
    }

    /// The durable-write discipline (open → write all bytes → fsync → close →
    /// rename → fsync dir). We cannot inject a real power loss, but we CAN prove the
    /// two properties that make the write crash-safe: every byte lands (the write
    /// loop drains the whole buffer, so the final file round-trips in full), and the
    /// partial data lives at the sibling TEMP path, never at the final path, until
    /// the atomic rename — so a reader that races the save sees whole-old or
    /// whole-new, never a truncated plist that would parse as "no config".
    @Test("save is complete and durable: the whole config round-trips and no temp file survives")
    func saveIsCompleteAndDurable() throws {
        let url = try temporaryURL()
        let directory = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())

        // A deliberately large config (many bypass/enrollment entries) so the write
        // loop must issue a real multi-chunk drain — a partial write would truncate
        // the plist and fail the round-trip below.
        let big = SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: .enforce, sudoCacheSeconds: 300,
            promptTimeoutSeconds: 90,
            pamBypass: PAMBypass(
                groups: (0..<200).map { "group-\($0)" },
                users: (0..<200).map { "user-\($0)" }
            ),
            sudoEnrollment: SerberusConfig.SudoEnrollment(
                group: "staff", users: (0..<200).map { "enrolled-\($0)" }
            )
        )
        try store.save(big)

        // Every byte landed: the loaded snapshot equals the whole input.
        let loaded = try #require(store.load())
        #expect(loaded.pamBypass.groups.count == 200)
        #expect(loaded.pamBypass.users.count == 200)
        #expect(loaded.pamBypass.groups.last == "group-199")
        #expect(loaded.sudoEnrollment.users.count == 200)

        // No partial temp file survives a successful save — the rename consumed it,
        // and only the final path remains. (Partial data, pre-rename, lives in the
        // dotfile temp, never at the final path.)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(leftovers == ["last-known-good-config.plist"])
    }

    // MARK: pam's file checks

    @Test("a group- or other-writable snapshot does not load; exists() still says configured; a re-save repairs it")
    func writableSnapshotIsRefused() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        try store.save(config())
        #expect(store.load() != nil)
        #expect(store.unusableReason() == nil)

        for mode in [0o664, 0o646] as [mode_t] {
            #expect(chmod(url.path, mode) == 0)
            #expect(store.load() == nil)          // pam refuses it too
            #expect(store.exists())               // still "configured": fail closed, never bootstrap
            #expect(store.unusableReason()?.contains("root-owned") == true)
            #expect(store.needsRefresh(for: config()))
        }
        // The daemon's refresh path rewrites it (a fresh 0644 file via rename).
        try store.save(config())
        #expect(store.load() != nil)
    }

    @Test("a snapshot owned by someone else does not load")
    func foreignOwnerIsRefused() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid()).save(config())
        let asRoot = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid() &+ 1)
        #expect(asRoot.load() == nil)
        #expect(asRoot.exists())
        #expect(asRoot.unusableReason() != nil)
    }

    @Test("a writable or symlinked FOLDER makes the snapshot unusable, and a re-save cannot fix it")
    func untrustedFolderIsRefused() throws {
        let url = try temporaryURL()
        let directory = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        try store.save(config())

        #expect(chmod(directory.path, 0o775) == 0)
        #expect(store.load() == nil)
        #expect(store.unusableReason()?.contains("folder") == true)
        #expect(!store.needsRefresh(for: config()))   // rewriting into the same folder would not help
        #expect(chmod(directory.path, 0o755) == 0)
        #expect(store.load() != nil)

        // The folder reached through a symlink: lstat refuses it.
        let link = directory.deletingLastPathComponent()
            .appendingPathComponent("serberus-lkg-link-\(UUID().uuidString)")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)
        defer { try? FileManager.default.removeItem(at: link) }
        let viaLink = LastKnownGoodConfigStore(url: link.appendingPathComponent(url.lastPathComponent),
                                               requiredOwnerUID: getuid())
        #expect(viaLink.load() == nil)
        #expect(viaLink.exists())
    }

    @Test("a symlink at the snapshot path is never followed (O_NOFOLLOW)")
    func symlinkedSnapshotIsRefused() throws {
        let url = try temporaryURL()
        let directory = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: directory) }
        let real = directory.appendingPathComponent("real.plist")
        try LastKnownGoodConfigStore(url: real, requiredOwnerUID: getuid()).save(config())
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: real)

        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        #expect(store.exists())       // present by lstat, exactly like pam
        #expect(store.load() == nil)  // but it is never read through
        #expect(store.unusableReason() != nil)
    }

    @Test("exists() is lstat: a dangling symlink is present; only ENOENT / ENOTDIR is absent")
    func existsUsesLstat() throws {
        let url = try temporaryURL()
        let directory = url.deletingLastPathComponent()
        defer {
            chmod(directory.path, 0o755)
            try? FileManager.default.removeItem(at: directory)
        }
        // A dangling symlink: access(F_OK) would say absent (bootstrap); lstat
        // says present (configured, fail closed), as pam now does.
        try FileManager.default.createSymbolicLink(
            at: url, withDestinationURL: directory.appendingPathComponent("missing.plist"))
        #expect(LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid()).exists())

        // A path under a regular FILE fails with ENOTDIR: absent.
        let file = directory.appendingPathComponent("plain")
        try Data().write(to: file)
        #expect(!LastKnownGoodConfigStore(url: file.appendingPathComponent("x.plist"),
                                          requiredOwnerUID: getuid()).exists())

        // A folder that cannot be searched fails with EACCES: present (fail
        // closed). Root can search anything, so this part only runs unprivileged.
        if geteuid() != 0 {
            let locked = directory.appendingPathComponent("locked", isDirectory: true)
            try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: true)
            #expect(chmod(locked.path, 0o000) == 0)
            defer { chmod(locked.path, 0o755) }
            #expect(LastKnownGoodConfigStore(url: locked.appendingPathComponent("x.plist"),
                                             requiredOwnerUID: getuid()).exists())
        }
    }
}

@Suite("App-management publisher policy")
struct AppManagementPublisherPolicyTests {
    /// A reader over a throwaway managed-preferences directory holding `values`
    /// for the app-management domain.
    private func reader(_ values: [String: Any]) throws -> ManagedPreferencesReader {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-appmgmt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0)
        try data.write(to: dir.appendingPathComponent("\(BundleConfig.appManagementDomain).plist"))
        return ManagedPreferencesReader(source: CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid()))
    }

    @Test("defaults to an empty allowlist, so nothing is installable")
    func defaults() throws {
        let policy = try reader(["enabled": true]).readAppManagementPolicy()
        #expect(policy.publisherScope == .allowlist)
        #expect(policy.allowedPublisherTeamIDs.isEmpty)
        #expect(!policy.publisherAllowed(teamID: "AB12CD34EF"))
        #expect(!policy.publisherAllowed(teamID: nil))
    }

    @Test("allowed Team IDs match case-insensitively")
    func allowlist() throws {
        let policy = try reader(["enabled": true, "allowedPublisherTeamIDs": ["ab12cd34ef"]]).readAppManagementPolicy()
        #expect(policy.publisherAllowed(teamID: "AB12CD34EF"))
        #expect(!policy.publisherAllowed(teamID: "ZZ99ZZ99ZZ"))
    }

    @Test("\"any\" must be chosen explicitly")
    func anyScope() throws {
        let policy = try reader(["enabled": true, "publisherScope": "any"]).readAppManagementPolicy()
        #expect(policy.publisherScope == .any)
        #expect(policy.publisherAllowed(teamID: "ZZ99ZZ99ZZ"))
    }

    @Test("an unrecognised scope falls back to the allowlist, never to any")
    func unknownScope() throws {
        for value: Any in ["everyone", "ANY", 1, true] {
            let policy = try reader(["enabled": true, "publisherScope": value]).readAppManagementPolicy()
            #expect(policy.publisherScope == .allowlist, "publisherScope = \(value)")
        }
    }
}

@Suite("Managed preferences trust: computer-level, root-owned plist only")
struct ManagedPlistTrustTests {
    /// A temp directory standing in for /Library/Managed Preferences with
    /// `values` as `<domain>.plist`, at `fileMode`.
    private func directory(domain: String, values: [String: Any], fileMode: mode_t = 0o644,
                           dirMode: mode_t = 0o755) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-trust-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("\(domain).plist")
        try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0).write(to: file)
        #expect(chmod(file.path, fileMode) == 0)
        #expect(chmod(dir.path, dirMode) == 0)
        return dir
    }

    @Test("a plist owned by anyone but the required owner (root in production) is ignored")
    func wrongOwnerIgnored() throws {
        let domain = "com.serberus.test.owner-\(UUID().uuidString)"
        let dir = try directory(domain: domain, values: ["daemonEnabled": false])
        defer { try? FileManager.default.removeItem(at: dir) }
        // The production default: the file is owned by the test user, not root.
        let production = CFPreferencesSource(managedPreferencesDirectory: dir.path)
        #expect(production.value(forKey: "daemonEnabled", domain: domain) == nil)
        #expect(production.keys(inDomain: domain).isEmpty)
        #expect(production.domains(matchingPrefix: domain).isEmpty)
        // The same file under the owner the test declares is read.
        let trusted = CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid())
        #expect(trusted.value(forKey: "daemonEnabled", domain: domain) as? Bool == false)
    }

    @Test("a group- or other-writable plist is ignored", arguments: [mode_t(0o664), 0o646])
    func writablePlistIgnored(mode: mode_t) throws {
        let domain = "com.serberus.test.mode-\(UUID().uuidString)"
        let dir = try directory(domain: domain, values: ["k": "v"], fileMode: mode)
        defer { try? FileManager.default.removeItem(at: dir) }
        let src = CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid())
        #expect(src.value(forKey: "k", domain: domain) == nil)
        #expect(src.keys(inDomain: domain).isEmpty)
    }

    @Test("a group- or other-writable managed directory is ignored")
    func writableDirectoryIgnored() throws {
        let domain = "com.serberus.test.dir-\(UUID().uuidString)"
        let dir = try directory(domain: domain, values: ["k": "v"], dirMode: 0o777)
        defer { try? FileManager.default.removeItem(at: dir) }
        let src = CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid())
        #expect(src.value(forKey: "k", domain: domain) == nil)
        #expect(src.domains(matchingPrefix: domain).isEmpty)
    }

    @Test("a symlinked plist is refused (never followed)")
    func symlinkIgnored() throws {
        let domain = "com.serberus.test.link-\(UUID().uuidString)"
        let dir = try directory(domain: domain, values: ["k": "v"])
        defer { try? FileManager.default.removeItem(at: dir) }
        let linked = "com.serberus.test.linked-\(UUID().uuidString)"
        try FileManager.default.createSymbolicLink(atPath: dir.appendingPathComponent("\(linked).plist").path,
                                                   withDestinationPath: dir.appendingPathComponent("\(domain).plist").path)
        let src = CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid())
        #expect(src.value(forKey: "k", domain: domain) as? String == "v")
        #expect(src.value(forKey: "k", domain: linked) == nil)
    }

    @Test("a current-user CFPreferences value is never discovered or read (no forced/user-scope fallback)")
    func userScopeNeverRead() throws {
        let domain = "com.serberus.test.userscope-\(UUID().uuidString)"
        let dir = try directory(domain: "unrelated.\(UUID().uuidString)", values: [:])
        defer { try? FileManager.default.removeItem(at: dir) }
        CFPreferencesSetValue("rules_authuri_injected" as CFString, "{}" as CFString, domain as CFString,
                              kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSynchronize(domain as CFString, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        defer {
            CFPreferencesSetValue("rules_authuri_injected" as CFString, nil, domain as CFString,
                                  kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
            CFPreferencesSynchronize(domain as CFString, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        }
        let src = CFPreferencesSource(managedPreferencesDirectory: dir.path, requiredOwnerUID: getuid())
        #expect(src.keys(inDomain: domain).isEmpty)
        #expect(src.managedValue(forKey: "rules_authuri_injected", domain: domain) == nil)
    }
}

@Suite("Booleans are real booleans only (agreeing with pam_config.c)")
struct StrictBooleanTests {
    private func config(_ values: [String: any Sendable]) -> ManagedPreferencesReader.ReadResult<SerberusConfig> {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [BundleConfig.configDomain: values]))
            .readConfig()
    }

    @Test("daemonEnabled <integer>0</integer> is NOT a kill switch: invalid, fail-safe default (enabled)")
    func integerZeroIsNotFalse() {
        let result = config(["daemonEnabled": 0])
        #expect(result.value.daemonEnabled)
        #expect(result.findings.contains(.invalidValue(domain: BundleConfig.configDomain, key: "daemonEnabled",
                                                       reason: "expected a boolean")))
        #expect(config(["daemonEnabled": 1]).value.daemonEnabled)
    }

    @Test("real booleans are honoured")
    func realBooleans() {
        #expect(!config(["daemonEnabled": false]).value.daemonEnabled)
        #expect(config(["daemonEnabled": true]).value.daemonEnabled)
        #expect(config(["daemonEnabled": false]).findings.isEmpty)
    }

    @Test("NSNumber-backed integers never flip a managed flag off its default")
    func integerOneIsNotTrue() {
        let result = config(["commanderPublishEnabled": 1, "enableBiometrics": 1, "timeBoundGrantsEnabled": 0])
        #expect(!result.value.commanderPublishEnabled)
        #expect(!result.value.enableBiometrics)
        // Default ON: an integer 0 must not switch time-bounding off.
        #expect(result.value.timeBoundGrantsEnabled)
        #expect(result.findings.count == 3)
    }

    @Test("requireRootOwnedState 0 keeps strict mode on")
    func strictStateFlag() {
        let loose = config(["sudoEnrollment": ["requireRootOwnedState": 0] as [String: any Sendable]])
        #expect(loose.value.sudoEnrollment.requireRootOwnedState)
        let off = config(["sudoEnrollment": ["requireRootOwnedState": false] as [String: any Sendable]])
        #expect(!off.value.sudoEnrollment.requireRootOwnedState)
    }

    @Test("strictBool accepts only CFBoolean")
    func strictBoolHelper() {
        #expect(ManagedPreferencesReader.strictBool(true) == true)
        #expect(ManagedPreferencesReader.strictBool(false) == false)
        #expect(ManagedPreferencesReader.strictBool(NSNumber(value: 0)) == nil)
        #expect(ManagedPreferencesReader.strictBool(NSNumber(value: 1)) == nil)
        #expect(ManagedPreferencesReader.strictBool("true") == nil)
    }
}

@Suite("Runtime rule gate: rules that would be enforced as something else are dropped")
struct RuntimeRuleGateTests {
    private func json(_ rules: [Rule], key: String = "rules_authuri_gate") throws -> String {
        let profile = RuleProfile(policyVersion: "1.0.0", profileKey: key, profilePriority: 50, rules: rules)
        return String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
    }

    private func authuri(_ id: String, _ right: String, _ action: RuleAction, app: AppIdentityBranch? = nil) -> Rule {
        Rule(id: id, type: .authuri, action: action, description: "", priority: 10,
             match: MatchCriteria(authURI: right), appIdentity: app)
    }

    private let app = AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer")

    @Test("an identity-scoped DENY in a JSON profile is dropped with a finding; the rest of the profile stays")
    func jsonIdentityDenyDropped() throws {
        let raw = try json([
            authuri("deny-pin", "com.apple.ServiceManagement.daemons.modify", .deny, app: app),
            authuri("ok", "system.preferences.datetime", .allow),
        ])
        let result = ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.rulesDomain: ["rules_authuri_gate": raw],
        ])).readRuleProfiles()
        #expect(result.value.flatMap(\.rules).map(\.id) == ["ok"])
        #expect(result.findings.count == 1)
        #expect(String(describing: result.findings).contains("deny-pin"))
    }

    @Test("an identity-scoped DENY in the native array is rejected")
    func nativeIdentityDenyRejected() {
        let result = Rule.fromManagedDictionary([
            "id": "deny-pin", "type": "authuri", "action": "deny",
            "authURI": "com.apple.ServiceManagement.daemons.modify",
            "appTeamID": "483DWKW443", "appBundleID": "com.jamfsoftware.Composer",
        ])
        guard case let .invalid(reason) = result else { Issue.record("expected invalid"); return }
        #expect(reason.contains("must be an allow rule"))
        guard case .rule = Rule.fromManagedDictionary([
            "id": "allow-pin", "type": "authuri", "action": "allow",
            "authURI": "com.apple.ServiceManagement.daemons.modify",
            "appTeamID": "483DWKW443", "appBundleID": "com.jamfsoftware.Composer",
        ]) else { Issue.record("allow pin rejected"); return }
    }

    @Test("rule-class, wildcard and login-deny targets are dropped at read time", arguments: [
        ("is-admin", RuleAction.allow), ("authenticate-session-owner", .deny), ("system.privilege.", .deny),
        ("system.preferences.", .allow), ("system.disk.unlock", .deny),
        ("system.platformsso.login", .deny),
    ])
    func targetsDropped(right: String, action: RuleAction) throws {
        let raw = try json([authuri("bad", right, action)])
        let result = ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.rulesDomain: ["rules_authuri_gate": raw],
        ])).readRuleProfiles()
        #expect(result.value.flatMap(\.rules).isEmpty)
        #expect(result.findings.count == 1)

        guard case .invalid = Rule.fromManagedDictionary([
            "id": "bad", "type": "authuri", "action": action.rawValue, "authURI": right,
        ]) else { Issue.record("native path accepted \(right)"); return }
    }

    @Test("an allow on system.disk.unlock is refused too (it would replace FileVault unlock with the session owner's password)")
    func diskUnlockAllowRefused() {
        guard case .invalid = Rule.fromManagedDictionary([
            "id": "no", "type": "authuri", "action": "allow", "authURI": "system.disk.unlock",
        ]) else { Issue.record("allow on system.disk.unlock accepted"); return }
        guard case .rule = Rule.fromManagedDictionary([
            "id": "ok", "type": "authuri", "action": "allow", "authURI": "system.preferences.datetime",
        ]) else { Issue.record("ordinary allow rejected"); return }
    }
}
