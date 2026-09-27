import Foundation
import Testing
@testable import PrivMgrCore

@Suite("Daemon config .mobileconfig export")
struct DaemonConfigExportTests {
    private func config(
        daemonEnabled: Bool = true,
        mode: EnforcementMode = .enforce,
        cache: Int = 300,
        timeout: Int = 90,
        groups: [String] = ["serberus-breakglass"],
        users: [String] = ["breakglass-admin"],
        enrollGroup: String? = "serberus-sudoers",
        enrollUsers: [String] = ["jane", "sam"],
        commanderPublish: Bool = false
    ) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil,
            jamfAPIClientID: nil,
            jamfAPIClientSecret: nil,
            daemonEnabled: daemonEnabled,
            enforcementMode: mode,
            sudoCacheSeconds: cache,
            promptTimeoutSeconds: timeout,
            pamBypass: PAMBypass(groups: groups, users: users),
            sudoEnrollment: SerberusConfig.SudoEnrollment(group: enrollGroup, users: enrollUsers),
            commanderPublishEnabled: commanderPublish
        )
    }

    /// The forced MCX settings the config profile delivers — exactly what lands
    /// in `/Library/Managed Preferences/<configDomain>.plist`.
    private func payloadContent(of export: MobileConfigGenerator.Export) throws -> [String: Any] {
        try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.configDomain)
    }

    @Test("payload targets the config domain with native plist types")
    func payloadShape() throws {
        let export = try MobileConfigGenerator().exportDaemonConfig(config(), organization: "Acme")
        #expect(export.suggestedFilename == "serberus-config.mobileconfig")

        // Delivered through the MCX wrapper Jamf renders, targeting the config
        // domain (settings live under Forced/mcx_preference_settings, so the
        // envelope PayloadType is the ManagedClient type, not the domain).
        let envelope = try mcxPayloadEnvelope(inMobileconfig: export.data)
        #expect(envelope["PayloadType"] as? String == "com.apple.ManagedClient.preferences")

        let content = try payloadContent(of: export)
        #expect(content["enforcementMode"] as? String == "enforce")
        #expect(content["daemonEnabled"] as? Bool == true)
        #expect(content["sudoCacheSeconds"] as? Int == 300)
        #expect(content["promptTimeoutSeconds"] as? Int == 90)
        // The Commander direct-publish gate is always emitted explicitly.
        #expect(content["commanderPublishEnabled"] as? Bool == false)
        // pamBypass must be a native dictionary of string arrays — the exact
        // shape readConfig() parses — never a JSON-encoded string.
        let bypass = content["pamBypass"] as? [String: Any]
        #expect(bypass?["groups"] as? [String] == ["serberus-breakglass"])
        #expect(bypass?["users"] as? [String] == ["breakglass-admin"])
        #expect(content["pamBypass"] as? String == nil)
        // sudoEnrollment must likewise be a native dict-of-arrays (group as a
        // String, users as [String]) — never a JSON-encoded string.
        let enrollment = content["sudoEnrollment"] as? [String: Any]
        #expect(enrollment?["group"] as? String == "serberus-sudoers")
        #expect(enrollment?["users"] as? [String] == ["jane", "sam"])
        #expect(content["sudoEnrollment"] as? String == nil)
    }

    @Test("nil enrollment group omits the group key; empty enrollment is left out")
    func enrollmentGroupOmittedWhenNil() throws {
        // group nil (user-only) — PropertyListSerialization would reject a nil
        // value, so the key must be absent rather than present-and-null.
        let userOnly = try MobileConfigGenerator().exportDaemonConfig(
            config(enrollGroup: nil, enrollUsers: ["jane"]), organization: "Acme")
        let userOnlyContent = try payloadContent(of: userOnly)
        let userOnlyEnrollment = try #require(userOnlyContent["sudoEnrollment"] as? [String: Any])
        #expect(userOnlyEnrollment["group"] == nil)
        #expect(userOnlyEnrollment.keys.contains("group") == false)
        #expect(userOnlyEnrollment["users"] as? [String] == ["jane"])

        // Fully empty enrollment is left out: absence already means "enroll
        // nobody", and emitting it would collide with a separately delivered
        // enrollment profile.
        let empty = try MobileConfigGenerator().exportDaemonConfig(
            config(enrollGroup: nil, enrollUsers: []), organization: "Acme")
        #expect(try payloadContent(of: empty)["sudoEnrollment"] == nil)
    }

    @Test("IdP enrollment keys survive the export")
    func idpEnrollmentKeysExported() throws {
        let base = config(enrollGroup: nil, enrollUsers: [])
        let idp = SerberusConfig.SudoEnrollment(
            idpGroups: ["Test-Name"], idpSource: .jamfConnectState,
            idpStatePath: "Library/Preferences/example.plist", idpGroupsKey: "Groups",
            requireRootOwnedState: false)
        let withIDP = SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: base.daemonEnabled, enforcementMode: base.enforcementMode,
            sudoCacheSeconds: base.sudoCacheSeconds, promptTimeoutSeconds: base.promptTimeoutSeconds,
            pamBypass: base.pamBypass, sudoEnrollment: idp)
        let content = try payloadContent(of: MobileConfigGenerator().exportDaemonConfig(withIDP, organization: "Acme"))
        let enrollment = try #require(content["sudoEnrollment"] as? [String: Any])
        #expect(enrollment["idpSource"] as? String == IDPGroupSource.jamfConnectState.rawValue)
        #expect(enrollment["idpGroups"] as? [String] == ["Test-Name"])
        #expect(enrollment["idpStatePath"] as? String == "Library/Preferences/example.plist")
        #expect(enrollment["idpGroupsKey"] as? String == "Groups")
        #expect(enrollment["requireRootOwnedState"] as? Bool == false)
    }

    @Test("Jamf connection keys are never emitted")
    func excludesJamfKeys() throws {
        // Those keys are a separately delivered profile in the same domain;
        // this exporter must not clobber or carry them.
        let content = try payloadContent(
            of: MobileConfigGenerator().exportDaemonConfig(config(), organization: "Acme"))
        #expect(content["jamfProURL"] == nil)
        #expect(content["jamfAPIClientID"] == nil)
        #expect(content["jamfAPIClientSecret"] == nil)
    }

    @Test("UUIDs are deterministic across exports")
    func stableUUIDs() throws {
        let generator = MobileConfigGenerator()
        let first = try generator.exportDaemonConfig(config(), organization: "Acme")
        let second = try generator.exportDaemonConfig(config(), organization: "Acme")
        #expect(first.payloadUUID == second.payloadUUID)
        #expect(first.data == second.data)

        let plist = try PropertyListSerialization.propertyList(from: first.data, format: nil) as? [String: Any]
        #expect(plist?["PayloadUUID"] as? String == first.payloadUUID.uuidString)
    }

    @Test("export round-trips through ManagedPreferencesReader.readConfig()")
    func readerRoundTrip() throws {
        let authored = config(daemonEnabled: false, mode: .audit, cache: 600, timeout: 45,
                              groups: ["admin", "serberus-jit"], users: ["breakglass-admin"],
                              enrollGroup: "serberus-sudoers", enrollUsers: ["jane", "sam"],
                              commanderPublish: true)
        let export = try MobileConfigGenerator().exportDaemonConfig(authored, organization: "Acme")
        let content = try payloadContent(of: export)

        // Re-materialize the payload as the managed-preferences dictionary the
        // MDM client would compose, then read it with the production reader.
        let bypass = content["pamBypass"] as? [String: Any]
        let enrollment = content["sudoEnrollment"] as? [String: Any]
        let domainValues: [String: any Sendable] = [
            "enforcementMode": try #require(content["enforcementMode"] as? String),
            "daemonEnabled": try #require(content["daemonEnabled"] as? Bool),
            "sudoCacheSeconds": try #require(content["sudoCacheSeconds"] as? Int),
            "promptTimeoutSeconds": try #require(content["promptTimeoutSeconds"] as? Int),
            "pamBypass": [
                "groups": try #require(bypass?["groups"] as? [String]),
                "users": try #require(bypass?["users"] as? [String]),
            ] as [String: [String]],
            "sudoEnrollment": [
                "group": try #require(enrollment?["group"] as? String),
                "users": try #require(enrollment?["users"] as? [String]),
            ] as [String: any Sendable],
            "commanderPublishEnabled": try #require(content["commanderPublishEnabled"] as? Bool),
        ]
        let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.configDomain: domainValues]))
        let result = reader.readConfig()

        #expect(result.findings.isEmpty)
        #expect(result.value.enforcementMode == .audit)
        #expect(!result.value.daemonEnabled)
        #expect(result.value.commanderPublishEnabled)
        #expect(result.value.sudoCacheSeconds == 600)
        #expect(result.value.promptTimeoutSeconds == 45)
        #expect(result.value.pamBypass == PAMBypass(groups: ["admin", "serberus-jit"],
                                                    users: ["breakglass-admin"]))
        #expect(result.value.sudoEnrollment == SerberusConfig.SudoEnrollment(
            group: "serberus-sudoers", users: ["jane", "sam"]))
    }
}
