import Foundation
import Testing
@testable import PrivMgrCore

@Suite("JITAdminPolicy")
struct JITAdminPolicyTests {
    @Test("disabled default never elevates")
    func disabledDefault() {
        let policy = JITAdminPolicy.disabledDefault
        #expect(policy.provider == .disabled)
        #expect(!policy.isEligible(user: "alice", groups: ["admin", "staff"]))
    }

    @Test("serberus eligibility requires membership in a named group")
    func serberusEligibility() {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"])
        #expect(policy.isEligible(user: "alice", groups: ["developers", "staff"]))
        #expect(!policy.isEligible(user: "bob", groups: ["staff"]))
        // Empty eligible list = nobody.
        let none = JITAdminPolicy(provider: .serberus, eligibleGroups: [])
        #expect(!none.isEligible(user: "alice", groups: ["admin"]))
    }

    @Test("jamfConnect is always eligible and resolves to a runnable command")
    func jamfConnectEligibility() {
        // No explicit command → falls back to the standard JC trigger.
        let policy = JITAdminPolicy(provider: .jamfConnect)
        #expect(policy.isEligible(user: "alice", groups: []))
        #expect(policy.effectiveJamfConnectCommand == JamfConnectCommand.jamfConnectDefault)
        #expect(policy.effectiveJamfConnectCommand.path == "/usr/local/bin/jamfconnect")
        #expect(policy.effectiveJamfConnectCommand.arguments == ["acc-promo", "--elevate"])
        // An explicit command overrides the default.
        let custom = JITAdminPolicy(provider: .jamfConnect,
                                    jamfConnectCommand: JamfConnectCommand(path: "/usr/local/bin/jc", arguments: ["go"]))
        #expect(custom.effectiveJamfConnectCommand.path == "/usr/local/bin/jc")
        // A relative command is never run: the default takes its place.
        let relative = JITAdminPolicy(provider: .jamfConnect,
                                      jamfConnectCommand: JamfConnectCommand(path: "jamfconnect", arguments: ["go"]))
        #expect(relative.effectiveJamfConnectCommand == JamfConnectCommand.jamfConnectDefault)
    }

    @Test("only a clean absolute command path counts as absolute")
    func absolutePathRule() {
        #expect(JamfConnectCommand.isAbsolutePath("/usr/local/bin/jamfconnect"))
        #expect(JamfConnectCommand.isAbsolutePath("/Applications/Jamf Connect.app/Contents/MacOS/Jamf Connect"))
        #expect(!JamfConnectCommand.isAbsolutePath("jamfconnect"))
        #expect(!JamfConnectCommand.isAbsolutePath("./jamfconnect"))
        #expect(!JamfConnectCommand.isAbsolutePath("/"))
        #expect(!JamfConnectCommand.isAbsolutePath(""))
        #expect(!JamfConnectCommand.isAbsolutePath("/usr/local/../tmp/jamfconnect"))
        #expect(!JamfConnectCommand.isAbsolutePath("/usr/local/bin/jamf\nconnect"))
        #expect(JamfConnectCommand.expectedTeamID == "483DWKW443")
    }

    @Test("duration is clamped to the allowed ceiling and floor")
    func durationClamp() {
        #expect(JITAdminPolicy(maxDurationSeconds: 999_999).effectiveDurationSeconds
                == JITAdminPolicy.maxAllowedDurationSeconds)
        #expect(JITAdminPolicy(maxDurationSeconds: 0).effectiveDurationSeconds == 1)
        #expect(JITAdminPolicy(maxDurationSeconds: 900).effectiveDurationSeconds == 900)
    }

    @Test("justification gate honors requireJustification + min length")
    func justification() {
        let required = JITAdminPolicy(requireJustification: true, justificationMinLength: 5)
        #expect(!required.justificationSatisfied("abc"))
        #expect(required.justificationSatisfied("abcdefg"))
        #expect(!required.justificationSatisfied("   ab   "))
        let optional = JITAdminPolicy(requireJustification: false)
        #expect(optional.justificationSatisfied(""))
    }

    @Test("JITAdminInfo derives availability from the policy")
    func infoAvailability() {
        #expect(!JITAdminInfo(policy: .disabledDefault).available)
        #expect(JITAdminInfo(policy: JITAdminPolicy(provider: .serberus, eligibleGroups: ["x"])).available)
        // JC is available even with no explicit command (falls back to default).
        #expect(JITAdminInfo(policy: JITAdminPolicy(provider: .jamfConnect)).available)
    }

    @Test("Jamf Connect info carries the command and skips justification")
    func jamfConnectInfo() {
        // JC owns its own reason prompt, so the Serberus affordance is a bare
        // button, and the command is carried down for the Agent to launch.
        let policy = JITAdminPolicy(provider: .jamfConnect, requireJustification: true)
        let info = JITAdminInfo(policy: policy)
        #expect(!info.requireJustification)
        #expect(info.jamfConnectCommand == JamfConnectCommand.jamfConnectDefault)
        // Serberus-native still honors its justification setting and carries no command.
        let native = JITAdminPolicy(provider: .serberus, eligibleGroups: ["x"], requireJustification: true)
        let nativeInfo = JITAdminInfo(policy: native)
        #expect(nativeInfo.requireJustification)
        #expect(nativeInfo.jamfConnectCommand == nil)
    }
}

@Suite("JITAdmin managed-preferences reader")
struct JITAdminReaderTests {
    private func reader(_ values: [String: any Sendable]) -> ManagedPreferencesReader {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [BundleConfig.jitDomain: values]))
    }

    @Test("absent domain yields the fail-closed default")
    func absent() {
        let result = reader([:]).readJITAdmin()
        #expect(result.value.provider == .disabled)
        #expect(result.value.eligibleGroups.isEmpty)
    }

    @Test("serberus policy parses groups, duration, and guardrails")
    func serberus() {
        let result = reader([
            "provider": "serberus",
            "eligibleGroups": ["developers", "staff"],
            "maxDurationSeconds": 1800,
            "requireJustification": true,
            "justificationMinLength": 12,
            "notify": true,
        ]).readJITAdmin()
        #expect(result.value.provider == .serberus)
        #expect(result.value.eligibleGroups == ["developers", "staff"])
        #expect(result.value.effectiveDurationSeconds == 1800)
        #expect(result.value.justificationMinLength == 12)
        #expect(result.findings.isEmpty)
    }

    @Test("jamf_connect provider with no command falls back to the standard trigger")
    func jamfConnectDefaultsCommand() {
        let result = reader(["provider": "jamf_connect"]).readJITAdmin()
        #expect(result.value.provider == .jamfConnect)
        #expect(result.value.effectiveJamfConnectCommand == JamfConnectCommand.jamfConnectDefault)
        #expect(result.findings.isEmpty)
    }

    @Test("an explicit jamf_connect command overrides the default")
    func jamfConnectExplicitCommand() {
        let command: [String: any Sendable] = ["path": "/opt/jc", "arguments": ["run"]]
        let result = reader([
            "provider": "jamf_connect",
            "jamfConnectCommand": command,
        ]).readJITAdmin()
        #expect(result.value.jamfConnectCommand.path == "/opt/jc")
        #expect(result.value.jamfConnectCommand.arguments == ["run"])
    }

    @Test("a relative jamf_connect command path is refused with a finding and the default is used")
    func jamfConnectRelativeCommand() {
        let command: [String: any Sendable] = ["path": "jamfconnect", "arguments": ["acc-promo", "--elevate"]]
        let result = reader([
            "provider": "jamf_connect",
            "jamfConnectCommand": command,
        ]).readJITAdmin()
        #expect(result.value.provider == .jamfConnect)
        #expect(result.value.jamfConnectCommand == JamfConnectCommand.jamfConnectDefault)
        #expect(result.value.effectiveJamfConnectCommand.path == "/usr/local/bin/jamfconnect")
        #expect(result.findings.count == 1)
    }

    @Test("an out-of-range duration falls back to the default with a finding")
    func durationOutOfRange() {
        let result = reader(["provider": "serberus", "eligibleGroups": ["x"], "maxDurationSeconds": 10_000_000]).readJITAdmin()
        #expect(result.value.maxDurationSeconds == JITAdminPolicy.defaultDurationSeconds)
        #expect(!result.findings.isEmpty)
    }
}

@Suite("JITAdmin .mobileconfig export")
struct JITAdminExportTests {
    @Test("serberus policy exports a JIT-domain profile")
    func exportsSerberus() throws {
        let policy = JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"], maxDurationSeconds: 1200)
        let export = try MobileConfigGenerator().exportJITAdmin(policy, organization: "Acme")
        #expect(export.suggestedFilename == "serberus-jit-admin.mobileconfig")

        let envelope = try mcxPayloadEnvelope(inMobileconfig: export.data)
        #expect(envelope["PayloadType"] as? String == "com.apple.ManagedClient.preferences")
        let content = try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.jitDomain)
        #expect(content["provider"] as? String == "serberus")
        #expect(content["eligibleGroups"] as? [String] == ["developers"])
        #expect(content["maxDurationSeconds"] as? Int == 1200)
    }

    @Test("jamf_connect export carries the default command when none is set")
    func exportsJamfConnectDefault() throws {
        let policy = JITAdminPolicy(provider: .jamfConnect)
        let export = try MobileConfigGenerator().exportJITAdmin(policy, organization: "Acme")
        let content = try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.jitDomain)
        let command = content["jamfConnectCommand"] as? [String: Any]
        #expect(command?["path"] as? String == "/usr/local/bin/jamfconnect")
        #expect(command?["arguments"] as? [String] == ["acc-promo", "--elevate"])
    }
}
