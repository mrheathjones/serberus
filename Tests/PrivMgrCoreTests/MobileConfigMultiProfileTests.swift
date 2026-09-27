import Foundation
import Testing
@testable import PrivMgrCore

@Suite("MobileConfigGenerator — multi-profile export")
struct MobileConfigMultiProfileTests {
    /// The compiled output of one three-tier policy spanning both mechanisms:
    /// a sudo and an authuri profile sharing the policy's version.
    private func sudoProfile(version: String = "1.0.0") -> RuleProfile {
        Fixtures.profile(key: "rules_sudo_mixed", policyVersion: version,
                         rules: [Fixtures.sudoRule()])
    }

    private func authURIProfile(version: String = "1.0.0") -> RuleProfile {
        Fixtures.profile(key: "rules_authuri_mixed", policyVersion: version,
                         rules: [Fixtures.authURIRule()])
    }

    @Test("one payload carries every profile under its own rules_* key")
    func roundTrip() throws {
        let sudo = sudoProfile()
        let authuri = authURIProfile()
        let export = try MobileConfigGenerator().export(profiles: [sudo, authuri],
                                                        organization: "Test Org")

        let plist = try PropertyListSerialization.propertyList(from: export.data, format: nil)
        let root = try #require(plist as? [String: Any])
        #expect(root["PayloadType"] as? String == "Configuration")
        #expect(root["PayloadScope"] as? String == "System")

        // ONE MCX payload with N keys — install/remove stays atomic for a
        // policy that compiles to both mechanisms, and Jamf renders it.
        let contents = try #require(root["PayloadContent"] as? [[String: Any]])
        #expect(contents.count == 1)
        #expect(contents.first?["PayloadType"] as? String == "com.apple.ManagedClient.preferences")

        let settings = try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.rulesDomain)
        for profile in [sudo, authuri] {
            let embedded = try #require(settings[profile.profileKey] as? String)
            let decoded = try RuleProfile.decode(jsonString: embedded, expectedKey: profile.profileKey)
            #expect(decoded == profile)
        }
    }

    @Test("the payload is exactly the shape ManagedPreferencesReader reads")
    func readerShape() throws {
        let sudo = sudoProfile()
        let authuri = authURIProfile()
        let export = try MobileConfigGenerator().export(profiles: [sudo, authuri],
                                                        organization: "Test Org")

        // Deliver the payload's forced rules_* entries as the managed domain —
        // exactly what an MDM install composes into
        // /Library/Managed Preferences/<rulesDomain>.plist — and let the
        // daemon-side reader parse them.
        let settings = try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.rulesDomain)
        var domain: [String: any Sendable] = [:]
        for (key, value) in settings {
            guard key.hasPrefix(RuleSchemaConstants.profileKeyPrefix),
                  let json = value as? String else { continue }
            domain[key] = json
        }
        let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.rulesDomain: domain]))
        let result = reader.readRuleProfiles()
        #expect(result.findings.isEmpty)
        // The reader sorts delivery keys, so authuri precedes sudo.
        #expect(result.value == [authuri, sudo])
    }

    @Test("a single profile through the overload keeps the legacy filename and payload identity")
    func singleProfileViaOverload() throws {
        let profile = sudoProfile()
        let viaOverload = try MobileConfigGenerator().export(profiles: [profile],
                                                             organization: "Test Org")
        #expect(viaOverload.suggestedFilename == "rules_sudo_mixed-1.0.0.mobileconfig")

        // Same UUID seed as the legacy single-profile path, so Jamf sees the
        // same profile identity whichever export path produced it.
        let legacy = try MobileConfigGenerator().export(profile, organization: "Test Org")
        #expect(viaOverload.payloadUUID == legacy.payloadUUID)

        let settings = try mcxSettings(inMobileconfig: viaOverload.data, domain: BundleConfig.rulesDomain)
        let embedded = try #require(settings[profile.profileKey] as? String)
        let decoded = try RuleProfile.decode(jsonString: embedded, expectedKey: profile.profileKey)
        #expect(decoded == profile)
    }

    @Test("re-export of the same versions is byte-identical and input-order invariant")
    func deterministicExport() throws {
        let generator = MobileConfigGenerator()
        let first = try generator.export(profiles: [sudoProfile(), authURIProfile()],
                                         organization: "Test Org")
        let second = try generator.export(profiles: [authURIProfile(), sudoProfile()],
                                          organization: "Test Org")
        #expect(first.data == second.data)
        #expect(first.payloadUUID == second.payloadUUID)
        // Combined filename convention: sorted keys joined by "+", first
        // sorted member's version.
        #expect(first.suggestedFilename == "rules_authuri_mixed+rules_sudo_mixed-1.0.0.mobileconfig")
    }

    @Test("any member's version bump yields a new payload identity")
    func versionedUUIDs() throws {
        let generator = MobileConfigGenerator()
        let v1 = try generator.export(profiles: [sudoProfile(), authURIProfile()],
                                      organization: "Test Org")
        let bumped = try generator.export(profiles: [sudoProfile(version: "1.0.1"), authURIProfile()],
                                          organization: "Test Org")
        #expect(v1.payloadUUID != bumped.payloadUUID)
    }

    @Test("an empty profile set is rejected")
    func emptyInput() {
        #expect(throws: ExportError.self) {
            try MobileConfigGenerator().export(profiles: [], organization: "Test Org")
        }
    }

    @Test("duplicate profile keys are rejected")
    func duplicateKeys() {
        #expect(throws: ExportError.self) {
            try MobileConfigGenerator().export(profiles: [sudoProfile(), sudoProfile(version: "1.0.1")],
                                               organization: "Test Org")
        }
    }

    @Test("a blocking validation error in any member blocks the whole export")
    func blockedExport() {
        let bad = Fixtures.profile(key: "rules_sudo_bad", policyVersion: "not-semver",
                                   rules: [Fixtures.sudoRule()])
        #expect(throws: ExportError.self) {
            try MobileConfigGenerator().export(profiles: [sudoProfile(), bad],
                                               organization: "Test Org")
        }
    }
}

/// The MCX wrapper (`com.apple.ManagedClient.preferences`) is what makes Jamf
/// render an uploaded profile instead of showing it empty — and the settings
/// plist is the alternative "Application & Custom Settings → Upload File" input.
/// Both must carry byte-identical rule payloads and read identically on-device.
@Suite("MobileConfigGenerator — MCX wrapper + settings plist")
struct MobileConfigMCXTests {
    private func sudo() -> RuleProfile {
        Fixtures.profile(key: "rules_sudo_mcx", rules: [Fixtures.sudoRule()])
    }
    private func authuri() -> RuleProfile {
        Fixtures.profile(key: "rules_authuri_mcx", rules: [Fixtures.authURIRule()])
    }

    @Test("no bare custom-domain PayloadType survives anywhere — only the MCX type")
    func noBareDomainPayloadType() throws {
        let export = try MobileConfigGenerator().export(profiles: [sudo(), authuri()],
                                                        organization: "Org")
        let root = try #require(
            try PropertyListSerialization.propertyList(from: export.data, format: nil) as? [String: Any])
        let contents = try #require(root["PayloadContent"] as? [[String: Any]])
        // The bare custom domain as a PayloadType is exactly what Jamf refuses
        // to render — it must appear as the MCX key, never as a payload type.
        for payload in contents {
            #expect(payload["PayloadType"] as? String != BundleConfig.rulesDomain)
            #expect(payload["PayloadType"] as? String == "com.apple.ManagedClient.preferences")
        }
        // The domain lives under the MCX PayloadContent, forced.
        let inner = try #require(contents.first?["PayloadContent"] as? [String: Any])
        let domainDict = try #require(inner[BundleConfig.rulesDomain] as? [String: Any])
        #expect(domainDict["Forced"] is [[String: Any]])
    }

    @Test("settings plist carries the same rules, domain, and filename")
    func settingsPlistShape() throws {
        let generator = MobileConfigGenerator()
        let plist = try generator.rulesSettingsPlist(profiles: [sudo(), authuri()])
        #expect(plist.domain == BundleConfig.rulesDomain)
        #expect(plist.suggestedFilename == "\(BundleConfig.rulesDomain).plist")

        // The plist is a flat top-level dict of rules_* keys — exactly the
        // "Application & Custom Settings → Upload File" input.
        let root = try #require(
            try PropertyListSerialization.propertyList(from: plist.data, format: nil) as? [String: Any])
        #expect(Set(root.keys) == ["rules_sudo_mcx", "rules_authuri_mcx"])
        #expect(root["rules_sudo_mcx"] is String)
    }

    @Test("settings plist and .mobileconfig deliver byte-identical forced settings")
    func settingsPlistMatchesMobileconfig() throws {
        let generator = MobileConfigGenerator()
        let profiles = [sudo(), authuri()]
        let mobileconfig = try generator.export(profiles: profiles, organization: "Org")
        let plist = try generator.rulesSettingsPlist(profiles: profiles)

        let fromMobileconfig = try mcxSettings(inMobileconfig: mobileconfig.data,
                                               domain: BundleConfig.rulesDomain)
        let fromPlist = try #require(
            try PropertyListSerialization.propertyList(from: plist.data, format: nil) as? [String: Any])

        // Same keys, same JSON strings — the settings plist is exactly what the
        // MCX payload forces onto the device.
        #expect(Set(fromMobileconfig.keys) == Set(fromPlist.keys))
        for key in fromMobileconfig.keys {
            #expect(fromMobileconfig[key] as? String == fromPlist[key] as? String)
        }
    }

    @Test("settings plist parses identically through the production reader")
    func settingsPlistReaderRoundTrip() throws {
        let profiles = [sudo(), authuri()]
        let plist = try MobileConfigGenerator().rulesSettingsPlist(profiles: profiles)
        let root = try #require(
            try PropertyListSerialization.propertyList(from: plist.data, format: nil) as? [String: Any])

        var domain: [String: any Sendable] = [:]
        for (key, value) in root where value is String { domain[key] = value as? String }
        let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.rulesDomain: domain]))
        let result = reader.readRuleProfiles()
        #expect(result.findings.isEmpty)
        #expect(result.value.count == 2)
    }

    @Test("settings plist rejects an empty set and duplicate keys")
    func settingsPlistGating() {
        let generator = MobileConfigGenerator()
        #expect(throws: ExportError.self) {
            try generator.rulesSettingsPlist(profiles: [])
        }
        #expect(throws: ExportError.self) {
            try generator.rulesSettingsPlist(profiles: [sudo(), sudo()])
        }
    }

    @Test("settings plist is deterministic and input-order invariant")
    func settingsPlistDeterministic() throws {
        let generator = MobileConfigGenerator()
        let a = try generator.rulesSettingsPlist(profiles: [sudo(), authuri()])
        let b = try generator.rulesSettingsPlist(profiles: [authuri(), sudo()])
        #expect(a.data == b.data)
    }
}
