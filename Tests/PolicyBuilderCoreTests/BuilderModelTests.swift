import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

// MARK: - MCX payload helpers (module-shared across this test target)

/// The single `com.apple.ManagedClient.preferences` payload inside a serialized
/// `.mobileconfig` produced by `MobileConfigGenerator`.
func mcxPayloadEnvelope(inMobileconfig data: Data) throws -> [String: Any] {
    let root = try #require(
        try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    let contents = try #require(root["PayloadContent"] as? [[String: Any]])
    return try #require(
        contents.first { $0["PayloadType"] as? String == "com.apple.ManagedClient.preferences" },
        "no com.apple.ManagedClient.preferences payload")
}

/// The flat forced settings for `domain` — the dict that lands in
/// `/Library/Managed Preferences/<domain>.plist`, unwrapped from the
/// `Forced` → `mcx_preference_settings` envelope.
func mcxSettings(inMobileconfig data: Data, domain: String) throws -> [String: Any] {
    let payload = try mcxPayloadEnvelope(inMobileconfig: data)
    let inner = try #require(payload["PayloadContent"] as? [String: Any])
    let domainDict = try #require(inner[domain] as? [String: Any], "no MCX entry for \(domain)")
    let forced = try #require(domainDict["Forced"] as? [[String: Any]])
    return try #require(forced.first?["mcx_preference_settings"] as? [String: Any])
}

@MainActor
@Suite("PatternTesterModel")
struct PatternTesterModelTests {
    @Test("glob match preview")
    func glob() {
        let model = PatternTesterModel()
        model.matchType = .glob
        model.commandPattern = "/opt/homebrew/bin/*"
        model.samplePath = "/opt/homebrew/bin/brew"
        model.argPattern = ""
        #expect(model.verdict == .match)

        model.samplePath = "/usr/bin/brew"
        #expect(model.verdict == .noMatch)
    }

    @Test("invalid regex is surfaced distinctly")
    func invalidRegex() {
        let model = PatternTesterModel()
        model.matchType = .regex
        model.commandPattern = "([unclosed"
        #expect(model.verdict == .invalidCommandPattern)
    }

    @Test("arg pattern gates the overall match")
    func argGate() {
        let model = PatternTesterModel()
        model.matchType = .prefixRegex
        model.commandPattern = "/opt/homebrew/bin/brew"
        model.samplePath = "/opt/homebrew/bin/brew"
        model.argPattern = "install|upgrade"
        model.sampleArgument = "install"
        #expect(model.verdict == .match)
        model.sampleArgument = "doctor"
        #expect(model.verdict == .noMatch)
    }
}

@MainActor
@Suite("ExportModel")
struct ExportModelTests {
    /// One three-tier policy can compile to BOTH a sudo and an authuri
    /// profile; export validates and delivers them together. These two are
    /// the shape of that compiled pair.
    private func validSudoProfile() -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: "rules_sudo_a", profilePriority: 50,
                    rules: [Rule(id: "allow_brew__homebrew_cli", type: .sudo, action: .allow,
                                 description: "d", priority: 10,
                                 match: MatchCriteria(commandPattern: "/opt/homebrew/bin/brew", matchType: .exact))])
    }

    private func validAuthURIProfile() -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a", profilePriority: 50,
                    rules: [Rule(id: "prompt_network__network_preferences", type: .authuri, action: .allow,
                                 description: "d", priority: 10,
                                 match: MatchCriteria(authURI: "system.preferences.network"))])
    }

    @Test("a valid sudo+authuri pair exports as one combined mobileconfig")
    func validPairExports() throws {
        let profiles = [validSudoProfile(), validAuthURIProfile()]
        let model = ExportModel()
        model.prepare(profiles: profiles, library: [])
        #expect(model.preparedProfiles == profiles)
        #expect(model.reports.count == 2)
        #expect(model.errorCount == 0)
        #expect(model.canExport())

        let export = try #require(model.export(profiles: profiles))
        #expect(model.lastError == nil)

        // ONE mobileconfig: a single MCX payload carrying both keys, so
        // install/remove of the policy stays atomic on the device and the
        // whole profile renders in the Jamf console.
        let plist = try PropertyListSerialization.propertyList(from: export.data, format: nil)
        let root = try #require(plist as? [String: Any])
        let contents = try #require(root["PayloadContent"] as? [[String: Any]])
        #expect(contents.count == 1)
        #expect(contents.first?["PayloadType"] as? String == "com.apple.ManagedClient.preferences")
        let settings = try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.rulesDomain)
        #expect(settings["rules_sudo_a"] is String)
        #expect(settings["rules_authuri_a"] is String)
        #expect(export.suggestedFilename == "rules_authuri_a+rules_sudo_a-1.0.0.mobileconfig")
    }

    @Test("a blocking error in ANY compiled profile blocks the whole export")
    func errorsBlock() {
        let bad = RuleProfile(policyVersion: "bad", profileKey: "rules_sudo_b", profilePriority: 50,
                              rules: [Rule(id: "r", type: .sudo, action: .allow, description: "d", priority: 1,
                                           match: MatchCriteria(commandPattern: "/x", matchType: .exact))])
        let model = ExportModel()
        model.prepare(profiles: [validSudoProfile(), bad], library: [])
        // Errors aggregate across every compiled profile of the policy.
        #expect(model.errorCount > 0)
        #expect(!model.canExport())
        #expect(model.blockingReason()?.contains("validation error") == true)
        #expect(model.export(profiles: [validSudoProfile(), bad]) == nil)
        #expect(model.lastError != nil)
    }

    @Test("a policy compiling to no profiles cannot export")
    func emptyCompilationBlocks() {
        let model = ExportModel()
        model.prepare(profiles: [], library: [])
        #expect(!model.canExport())
        #expect(model.blockingReason()?.contains("no profiles") == true)
    }

    @Test("cross-profile conflicts from any member require acknowledgement")
    func conflictsRequireAck() {
        let published = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_sudo_published", profilePriority: 50,
                                    rules: [Rule(id: "deny-brew", type: .sudo, action: .deny, description: "d", priority: 10,
                                                 match: MatchCriteria(commandPattern: "/opt/homebrew/bin/brew", matchType: .exact))])
        let model = ExportModel()
        model.prepare(profiles: [validSudoProfile(), validAuthURIProfile()], library: [published])
        #expect(!model.conflicts.isEmpty)
        #expect(!model.canExport())

        model.conflictsAcknowledged = true
        #expect(model.canExport())

        // Re-preparing resets the acknowledgement — a fresh compile always
        // requires a fresh ack.
        model.prepare(profiles: [validSudoProfile()], library: [published])
        #expect(!model.conflictsAcknowledged)
        #expect(!model.canExport())
    }
}

@MainActor
@Suite("ProfileHistory")
struct ProfileHistoryTests {
    @Test("records versions, replacing duplicates, ordered by version")
    func record() {
        let history = ProfileHistory()
        func profile(_ version: String, rules: Int) -> RuleProfile {
            RuleProfile(policyVersion: version, profileKey: "rules_sudo_a", profilePriority: 50,
                        rules: (0..<rules).map { Rule(id: "r\($0)", type: .sudo, action: .allow, description: "d",
                                                      priority: $0, match: MatchCriteria(commandPattern: "/x\($0)", matchType: .exact)) })
        }
        history.record(profile("1.0.0", rules: 1))
        history.record(profile("1.0.1", rules: 2))
        history.record(profile("1.0.0", rules: 3)) // replaces 1.0.0
        #expect(history.versions.count == 2)
        #expect(history.versions.first?.rules.count == 3)
        #expect(history.latest?.policyVersion == "1.0.1")
    }
}

// MARK: - Jamf publish

/// Scripted transport for the admin tests.
actor AdminMockTransport: HTTPTransport {
    private var script: [(Int, Data)]
    private(set) var requestCount = 0

    init(script: [(Int, Data)]) { self.script = script }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requestCount += 1
        guard !script.isEmpty else { throw URLError(.cannotConnectToHost) }
        let (status, body) = script.removeFirst()
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        return (body, response)
    }
}

@MainActor
@Suite("PublishModel")
struct PublishModelTests {
    private func store() -> JamfCredentialStore {
        JamfCredentialStore(reader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: [
                "jamfProURL": "https://example.jamfcloud.com",
                "jamfAPIClientID": "id",
                "jamfAPIClientSecret": "secret",
            ],
        ])))
    }

    private let token = Data(#"{"access_token":"t","expires_in":1800}"#.utf8)

    @Test("publish creates a new profile when none matches the name")
    func createsNew() async {
        let transport = AdminMockTransport(script: [
            (200, token),
            (200, Data(#"{"os_x_configuration_profiles":[]}"#.utf8)),
            (201, Data("<os_x_configuration_profile><id>42</id></os_x_configuration_profile>".utf8)),
        ])
        let client = JamfAPIClient(credentialStore: store(),
                                   tokenManager: JamfTokenManager(credentialStore: store(), transport: transport),
                                   transport: transport)
        let model = PublishModel(client: client)
        await model.publish(name: "Serberus — rules_sudo_a", mobileconfig: Data("<plist/>".utf8))
        #expect(model.status == .published(id: 42, updated: false))
    }

    @Test("publish updates the existing profile of the same name")
    func updatesExisting() async {
        let transport = AdminMockTransport(script: [
            (200, token),
            (200, Data(#"{"os_x_configuration_profiles":[{"id":7,"name":"Serberus — rules_sudo_a"}]}"#.utf8)),
            (201, Data("<os_x_configuration_profile><id>7</id></os_x_configuration_profile>".utf8)),
        ])
        let client = JamfAPIClient(credentialStore: store(),
                                   tokenManager: JamfTokenManager(credentialStore: store(), transport: transport),
                                   transport: transport)
        let model = PublishModel(client: client)
        await model.publish(name: "Serberus — rules_sudo_a", mobileconfig: Data("<plist/>".utf8))
        #expect(model.status == .published(id: 7, updated: true))
    }

    @Test("permissions checklist exposes the three V1-required permissions")
    func permissions() {
        // Read Computers joined the required set when the Fleet Observer went live.
        #expect(JamfPermission.requiredInV1.count == 4)
        #expect(JamfPermission.requiredInV1.map(\.id).contains("Read Computers"))
        #expect(JamfPermission.all.count == 8)
    }
}
