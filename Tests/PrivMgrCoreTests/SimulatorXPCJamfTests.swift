import Foundation
import Testing
@testable import PrivMgrCore

@Suite("DecisionSimulator — parity with the daemon code path")
struct DecisionSimulatorTests {
    private func context(
        authURI: String? = nil,
        sudoCommand: String? = "/opt/homebrew/bin/brew",
        argv: [String] = ["install", "wget"],
        grants: [SimulatedGrant] = []
    ) -> SimulationContext {
        SimulationContext(
            user: "alice",
            uid: 501,
            authURI: authURI,
            sudoCommand: sudoCommand,
            argv: argv,
            executablePath: "/opt/homebrew/bin/brew",
            teamID: "",
            binaryHash: Fixtures.brewIdentity.sha256,
            signingStatus: .unsigned,
            activeGrants: grants,
            currentTime: Fixtures.now
        )
    }

    @Test("simulator and engine return identical decisions for the same inputs")
    func parity() throws {
        let profiles = [Fixtures.profile(rules: [
            Fixtures.sudoRule(id: "deny-uninstall", action: .deny, priority: 1,
                              argPattern: "uninstall", matchType: .prefixRegex),
            Fixtures.sudoRule(id: "allow-install", priority: 5,
                              argPattern: "install|upgrade", matchType: .prefixRegex),
        ])]

        for argv in [["install", "wget"], ["uninstall", "wget"], ["doctor"]] {
            let simulated = try DecisionSimulator().simulate(
                context: context(argv: argv), profiles: profiles
            )
            let direct = evaluate(Fixtures.sudoRequest(argv: argv), profiles: profiles)
            #expect(simulated.decision == direct.decision, "argv \(argv)")
            #expect(simulated.matchedRule == direct.matchedRuleID, "argv \(argv)")
            #expect(simulated.reason == direct.reason, "argv \(argv)")
            #expect(simulated.evaluationTrace == direct.trace, "argv \(argv)")
        }
    }

    @Test("simulated grants flow through as snapshots")
    func simulatedGrants() throws {
        let rule = Fixtures.sudoRule(id: "prompt-brew", elevation: ElevationBehavior(type: .prompt))
        let grant = SimulatedGrant(
            user: "alice",
            ruleID: "prompt-brew",
            profileKey: "rules_sudo_test",
            canonicalPath: "/opt/homebrew/bin/brew",
            binaryHash: Fixtures.brewIdentity.sha256,
            expiresAt: Fixtures.now.addingTimeInterval(600)
        )
        let result = try DecisionSimulator().simulate(
            context: context(grants: [grant]),
            profiles: [Fixtures.profile(rules: [rule])]
        )
        #expect(result.decision == .allow)
    }

    @Test("ambiguous context is rejected")
    func contextValidation() {
        #expect(throws: PolicyError.self) {
            try DecisionSimulator().simulate(
                context: context(authURI: "system.keychain-modify"),
                profiles: []
            )
        }
        #expect(throws: PolicyError.self) {
            try DecisionSimulator().simulate(
                context: context(sudoCommand: nil),
                profiles: []
            )
        }
    }

    @Test("cache behavior strings are explicit")
    func cacheBehavior() throws {
        let cached = try DecisionSimulator().simulate(
            context: context(),
            profiles: [Fixtures.profile(rules: [Fixtures.sudoRule(cacheSeconds: 300)])]
        )
        #expect(cached.cacheBehavior == "cache 300s")

        let denied = try DecisionSimulator().simulate(
            context: context(),
            profiles: [Fixtures.profile(rules: [Fixtures.sudoRule(action: .deny)])]
        )
        #expect(denied.cacheBehavior == "deny decisions are never cached")
    }
}

@Suite("PathCanonicalizer")
struct PathCanonicalizerTests {
    @Test("relative, empty, and traversal paths are rejected")
    func rejections() {
        let canonicalizer = PathCanonicalizer()
        #expect(throws: PathError.emptyPath) {
            try canonicalizer.canonicalize("", existence: .allowMissing)
        }
        #expect(throws: PathError.relativePath("bin/brew")) {
            try canonicalizer.canonicalize("bin/brew", existence: .allowMissing)
        }
    }

    @Test("symlinks resolve to the canonical target")
    func symlinkResolution() throws {
        let directory = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("real-binary")
        FileManager.default.createFile(atPath: target.path, contents: Data())
        let link = directory.appendingPathComponent("link-binary")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let canonical = try PathCanonicalizer().canonicalize(link.path, existence: .requireExists)
        #expect(canonical.hasSuffix("/real-binary"))
    }

    @Test("missing executables rejected only when existence is required")
    func existencePolicy() throws {
        let missing = "/nonexistent/serberus-test-binary"
        #expect(throws: PathError.missingExecutable(missing)) {
            try PathCanonicalizer().canonicalize(missing, existence: .requireExists)
        }
        #expect(try PathCanonicalizer().canonicalize(missing, existence: .allowMissing) == missing)
    }

    @Test("dot components are normalized away")
    func normalization() throws {
        let result = try PathCanonicalizer()
            .canonicalize("/usr/bin/../bin/./true", existence: .allowMissing)
        #expect(result == "/usr/bin/true")
    }
}

@Suite("XPCConnectionValidator — decision table")
struct XPCValidatorTests {
    /// A fixed synthetic team. The real expected team comes from this process's
    /// own signature, which the test runner doesn't have, so the decision
    /// table pins every preset to this team instead.
    private static let team = "TEAM123456"

    /// `preset` with its team pinned to ``team``.
    private func expected(_ preset: ExpectedCaller) -> ExpectedCaller {
        ExpectedCaller(bundleID: preset.bundleID, teamID: Self.team,
                       requiredEntitlement: preset.requiredEntitlement)
    }

    private func identity(
        bundleID: String? = BundleConfig.sentinelBundleID,
        teamID: String? = XPCValidatorTests.team,
        signatureValid: Bool = true,
        adHoc: Bool = false,
        hardened: Bool = true,
        satisfiesDR: Bool = true,
        entitlements: Set<String> = [BundleConfig.sentinelEntitlement]
    ) -> PeerIdentity {
        PeerIdentity(
            bundleID: bundleID,
            teamID: teamID,
            signatureValid: signatureValid,
            adHocSigned: adHoc,
            hardenedRuntime: hardened,
            satisfiesDesignatedRequirement: satisfiesDR,
            trueEntitlements: entitlements
        )
    }

    @Test("a fully valid agent peer passes")
    func validAgent() throws {
        try XPCConnectionValidator().validate(identity: identity(), against: expected(.sentinel))
    }

    @Test("every single failing check rejects the peer")
    func eachCheckRejects() {
        let validator = XPCConnectionValidator()
        let cases: [(PeerIdentity, String)] = [
            (identity(signatureValid: false), "invalid signature"),
            (identity(adHoc: true), "ad-hoc signature"),
            (identity(hardened: false), "hardened runtime disabled"),
            (identity(teamID: "EVIL999999"), "wrong team ID"),
            (identity(teamID: nil), "missing team ID"),
            (identity(bundleID: "com.evil.app"), "unknown bundle ID"),
            (identity(bundleID: nil), "missing bundle ID"),
            (identity(satisfiesDR: false), "designated requirement unsatisfied"),
            (identity(entitlements: []), "missing entitlement"),
        ]
        for (peer, label) in cases {
            #expect(throws: XPCValidationError.self, "\(label) must reject") {
                try validator.validate(identity: peer, against: expected(.sentinel))
            }
        }
    }

    @Test("the Commander app is not a daemon caller: no expected caller, no interface")
    func commanderIsNotACaller() {
        // The Commander has no daemon XPC client; a peer signed with its bundle
        // ID is an unknown caller and the listener rejects it.
        #expect(ExpectedCaller.forBundleID(BundleConfig.commanderBundleID) == nil)
        let forged = ExpectedCaller(bundleID: BundleConfig.commanderBundleID, teamID: Self.team,
                                    requiredEntitlement: nil)
        #expect(forged.interface == nil)
        #expect(!XPCInterface.allCases.map(\.rawValue).contains("commander"))
    }

    @Test("a team-signed peer claiming the PAM module identifier is refused (no PAM route by bundle ID)")
    func pamIdentifierPeerIsRefused() {
        // Fully valid, team-signed, hardened — but claiming the PAM module's
        // signing identifier (a dev test client's shape). The daemon's
        // dispatch table must not recognize it, so the listener falls through
        // to the sudo-host branch (euid 0 + Apple sudo pin) or "unknown caller".
        #expect(ExpectedCaller.forBundleID(BundleConfig.pamBundleID) == nil)
        let pamClaimant = identity(bundleID: BundleConfig.pamBundleID, entitlements: [])
        let validator = XPCConnectionValidator()
        for preset in [ExpectedCaller.sentinel, .intelApp] {
            #expect(preset.interface != .pam, "\(preset.bundleID)")
            #expect(throws: XPCValidationError.self, "\(preset.bundleID)") {
                try validator.validate(identity: pamClaimant, against: expected(preset))
            }
        }
        // An ExpectedCaller built for the identifier still does not map to `.pam`.
        let forged = ExpectedCaller(bundleID: BundleConfig.pamBundleID, teamID: Self.team,
                                    requiredEntitlement: nil)
        #expect(forged.interface != .pam)
    }

    @Test("designated requirement string pins identifier and team")
    func requirementString() {
        let requirement = expected(.sentinel).designatedRequirement
        #expect(requirement.contains("identifier \"\(BundleConfig.sentinelBundleID)\""))
        #expect(requirement.contains("anchor apple generic"))
        #expect(requirement.contains("certificate leaf[subject.OU] = \"\(Self.team)\""))
    }

    @Test("a process with no signing team of its own trusts no peer")
    func noOwnTeamRejectsEveryPeer() {
        let validator = XPCConnectionValidator()
        let untrusting = ExpectedCaller(bundleID: BundleConfig.sentinelBundleID, teamID: "",
                                        requiredEntitlement: BundleConfig.sentinelEntitlement)
        // Including the peer an empty-vs-empty comparison would otherwise match.
        for team in [Self.team, "", nil] as [String?] {
            #expect(throws: XPCValidationError.expectedTeamIDUnavailable, "peer team \(team ?? "nil")") {
                try validator.validate(identity: identity(teamID: team), against: untrusting)
            }
        }
    }

    @Test("every preset expects the team this process is signed with")
    func presetsUseOwnTeam() {
        let own = BundleConfig.signingTeamOfCurrentProcess() ?? ""
        #expect(BundleConfig.teamID == own)
        for preset in [ExpectedCaller.sentinel, .intelApp, .finderExtension] {
            #expect(preset.teamID == own, "\(preset.bundleID)")
        }
        // A real Apple Team ID is 10 uppercase letters and digits.
        if !own.isEmpty {
            #expect(own.count == 10 && own.allSatisfy { $0.isASCII && ($0.isUppercase || $0.isNumber) })
        }
    }

    @Test("bundle IDs map to the right expected caller and interface")
    func callerMatching() {
        #expect(ExpectedCaller.forBundleID(BundleConfig.pamBundleID) == nil)
        #expect(ExpectedCaller.forBundleID(BundleConfig.sentinelBundleID) == .sentinel)
        #expect(ExpectedCaller.forBundleID(BundleConfig.commanderBundleID) == nil)
        #expect(ExpectedCaller.forBundleID(BundleConfig.intelBundleID) == .intelApp)
        #expect(ExpectedCaller.forBundleID("com.evil.app") == nil)
        #expect(ExpectedCaller.forBundleID(nil) == nil)

        #expect(ExpectedCaller.sentinel.interface == .sentinel)
        #expect(ExpectedCaller.intelApp.interface == .intel)
        #expect(ExpectedCaller.finderExtension.interface == nil)
    }

    @Test("the Finder extension caller validates on identity alone (no entitlement)")
    func finderExtensionCaller() throws {
        let validator = XPCConnectionValidator()
        // A valid appex peer passes with NO entitlement required (like intel/pam):
        // an Apple-Development-signed sandboxed appex cannot carry a custom marker.
        let ext = identity(bundleID: BundleConfig.finderExtensionBundleID, entitlements: [])
        try validator.validate(identity: ext, against: expected(.finderExtension))
        // Every identity pin still bites — only this team's signed appex passes.
        let rejected: [PeerIdentity] = [
            identity(bundleID: BundleConfig.finderExtensionBundleID, teamID: "EVIL999999", entitlements: []),
            identity(bundleID: "com.evil.finderext", entitlements: []),
            identity(bundleID: BundleConfig.finderExtensionBundleID, adHoc: true, entitlements: []),
            identity(bundleID: BundleConfig.finderExtensionBundleID, hardened: false, entitlements: []),
            identity(bundleID: BundleConfig.finderExtensionBundleID, satisfiesDR: false, entitlements: []),
            identity(bundleID: BundleConfig.finderExtensionBundleID, signatureValid: false, entitlements: []),
        ]
        for peer in rejected {
            #expect(throws: XPCValidationError.self) {
                try validator.validate(identity: peer, against: expected(.finderExtension))
            }
        }
    }

    @Test("the Finder extension is NOT a daemon principal — the daemon rejects it as unknown")
    func finderExtensionIsNotADaemonCaller() {
        // The daemon's listener picks a caller via forBundleID; the extension must
        // return nil there, so if the appex ever connected to the DAEMON directly
        // it falls through to "unknown caller" and is rejected. It talks only to
        // the AGENT's bridge, which validates against .finderExtension explicitly.
        #expect(ExpectedCaller.forBundleID(BundleConfig.finderExtensionBundleID) == nil)
        #expect(ExpectedCaller.finderExtension.requiredEntitlement == nil)
        #expect(ExpectedCaller.finderExtension.bundleID == BundleConfig.finderExtensionBundleID)
    }
}

/// The sudo-host acceptance path: `pam_serberus.so` runs inside `/usr/bin/sudo`,
/// so the daemon authenticates the host (euid 0 + `anchor apple` + sudo pin)
/// rather than the module identity it can never see.
@Suite("XPCConnectionValidator — PAM host (sudo) decision table")
struct XPCPAMHostTests {
    private func host(
        euid: uid_t = 0,
        signatureValid: Bool = true,
        adHoc: Bool = false,
        applePlatform: Bool = true,
        identifier: String? = BundleConfig.sudoSigningIdentifier,
        path: String? = BundleConfig.sudoExecutablePath
    ) -> PAMHostIdentity {
        PAMHostIdentity(
            euid: euid,
            signatureValid: signatureValid,
            adHocSigned: adHoc,
            isApplePlatformBinary: applePlatform,
            signingIdentifier: identifier,
            executablePath: path
        )
    }

    @Test("a genuine root Apple sudo host is accepted")
    func validSudoHost() throws {
        try XPCConnectionValidator().validatePAMHost(host())
    }

    @Test("euid != 0 is the load-bearing rejection (a standard user cannot pass)")
    func nonRootRejected() {
        // Everything else valid; only euid is wrong — must still reject.
        #expect(throws: XPCValidationError.pamHostNotRoot(found: 501)) {
            try XPCConnectionValidator().validatePAMHost(host(euid: 501))
        }
    }

    @Test("every single failing check rejects the host")
    func eachCheckRejects() {
        let validator = XPCConnectionValidator()
        let cases: [(PAMHostIdentity, String)] = [
            (host(euid: 501), "non-root euid"),
            (host(signatureValid: false), "invalid signature"),
            (host(adHoc: true), "ad-hoc signature"),
            (host(applePlatform: false), "not an Apple platform binary"),
            (host(identifier: "com.apple.su"), "wrong Apple binary (su, not sudo)"),
            (host(identifier: nil), "missing identifier"),
            (host(path: "/tmp/sudo"), "wrong executable path"),
            (host(path: nil), "missing executable path"),
        ]
        for (h, label) in cases {
            #expect(throws: XPCValidationError.self, "\(label) must reject") {
                try validator.validatePAMHost(h)
            }
        }
    }

    @Test("an Apple-signed root binary that is not sudo is rejected")
    func otherApplePlatformBinaryRejected() {
        // e.g. /usr/bin/su — anchor apple + euid 0, but identifier/path differ.
        #expect(throws: XPCValidationError.self) {
            try XPCConnectionValidator().validatePAMHost(
                host(identifier: "com.apple.su", path: "/usr/bin/su")
            )
        }
    }
}

// MARK: - Jamf mocks

/// Scripted transport: pops one response per request, records requests.
actor MockTransport: HTTPTransport {
    struct Scripted {
        let status: Int
        let body: Data
    }

    private var script: [Scripted]
    private(set) var requests: [URLRequest] = []

    init(script: [Scripted]) {
        self.script = script
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        guard !script.isEmpty else { throw URLError(.cannotConnectToHost) }
        let next = script.removeFirst()
        let response = HTTPURLResponse(
            url: request.url ?? URL(fileURLWithPath: "/"),
            statusCode: next.status,
            httpVersion: nil,
            headerFields: nil
        )!
        return (next.body, response)
    }

    func requestCount() -> Int { requests.count }
}

private func makeCredentialStore() -> JamfCredentialStore {
    JamfCredentialStore(reader: ManagedPreferencesReader(
        source: DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: [
                "jamfProURL": "https://example.jamfcloud.com",
                "jamfAPIClientID": "client-id",
                "jamfAPIClientSecret": "client-secret",
            ],
        ])
    ))
}

private let tokenBody = Data(#"{"access_token":"tok-1","expires_in":1800}"#.utf8)

@Suite("JamfTokenManager")
struct JamfTokenManagerTests {
    @Test("token is cached in memory and reused before the refresh window")
    func caching() async throws {
        let transport = MockTransport(script: [.init(status: 200, body: tokenBody)])
        let manager = JamfTokenManager(
            credentialStore: makeCredentialStore(),
            transport: transport,
            now: { Fixtures.now }
        )
        #expect(try await manager.token() == "tok-1")
        #expect(try await manager.token() == "tok-1")
        #expect(await transport.requestCount() == 1)
    }

    @Test("token refreshes 60 seconds before expiry")
    func proactiveRefresh() async throws {
        let transport = MockTransport(script: [
            .init(status: 200, body: tokenBody),
            .init(status: 200, body: Data(#"{"access_token":"tok-2","expires_in":1800}"#.utf8)),
        ])
        // Clock advances to 61 seconds before expiry after the first fetch.
        let clock = ClockBox(now: Fixtures.now)
        let manager = JamfTokenManager(
            credentialStore: makeCredentialStore(),
            transport: transport,
            now: { clock.current() }
        )
        #expect(try await manager.token() == "tok-1")
        clock.advance(by: 1800 - 59) // inside the 60s leeway → refresh
        #expect(try await manager.token() == "tok-2")
    }

    @Test("401 surfaces credentialsInvalid and invalidates the cache")
    func unauthorized() async throws {
        let transport = MockTransport(script: [.init(status: 401, body: Data())])
        let manager = JamfTokenManager(
            credentialStore: makeCredentialStore(),
            transport: transport,
            now: { Fixtures.now }
        )
        await #expect(throws: JamfError.credentialsInvalid) {
            _ = try await manager.token()
        }
    }

    @Test("missing configuration surfaces the specific key")
    func notConfigured() async throws {
        let store = JamfCredentialStore(reader: ManagedPreferencesReader(
            source: DictionaryPreferencesSource(domains: [:])
        ))
        let manager = JamfTokenManager(
            credentialStore: store,
            transport: MockTransport(script: []),
            now: { Fixtures.now }
        )
        await #expect(throws: JamfError.notConfigured(missingKey: "jamfProURL")) {
            _ = try await manager.token()
        }
    }
}

/// Mutable clock for expiry tests.
final class ClockBox: @unchecked Sendable {
    private let lock = NSLock()
    private var now: Date
    init(now: Date) { self.now = now }
    func current() -> Date {
        lock.lock(); defer { lock.unlock() }
        return now
    }
    func advance(by seconds: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        now = now.addingTimeInterval(seconds)
    }
}

@Suite("JamfAPIClient")
struct JamfAPIClientTests {
    private func client(script: [MockTransport.Scripted]) -> (JamfAPIClient, MockTransport) {
        let transport = MockTransport(script: script)
        let store = makeCredentialStore()
        let manager = JamfTokenManager(credentialStore: store, transport: transport, now: { Fixtures.now })
        return (JamfAPIClient(credentialStore: store, tokenManager: manager, transport: transport), transport)
    }

    @Test("listConfigurationProfiles decodes and sorts")
    func listProfiles() async throws {
        let body = Data("""
            {"os_x_configuration_profiles":[{"id":7,"name":"B"},{"id":3,"name":"A"}]}
            """.utf8)
        let (client, _) = client(script: [
            .init(status: 200, body: tokenBody),
            .init(status: 200, body: body),
        ])
        let profiles = try await client.listConfigurationProfiles()
        #expect(profiles.map(\.id) == [3, 7])
    }

    @Test("403 maps to insufficientPermissions with the endpoint")
    func forbidden() async throws {
        let (client, _) = client(script: [
            .init(status: 200, body: tokenBody),
            .init(status: 403, body: Data()),
        ])
        await #expect(throws: JamfError.insufficientPermissions(
            endpoint: "JSSResource/osxconfigurationprofiles"
        )) {
            _ = try await client.listConfigurationProfiles()
        }
    }

    @Test("create extracts the new profile ID from Classic API XML")
    func create() async throws {
        let (client, _) = client(script: [
            .init(status: 200, body: tokenBody),
            .init(status: 201, body: Data("<os_x_configuration_profile><id>42</id></os_x_configuration_profile>".utf8)),
        ])
        let id = try await client.createConfigurationProfile(
            name: "Serberus — test",
            mobileconfig: Data("<plist/>".utf8)
        )
        #expect(id == 42)
    }

    @Test("unreachable transport maps to JamfError.unreachable")
    func unreachable() async throws {
        let (client, _) = client(script: [.init(status: 200, body: tokenBody)])
        // Script exhausted → transport throws → unreachable.
        await #expect(throws: JamfError.self) {
            _ = try await client.listConfigurationProfiles()
        }
    }
}

@Suite("XPC coding")
struct XPCCodingTests {
    @Test("PromptContext round-trips through the Data bridge")
    func promptContextRoundTrip() throws {
        let context = PromptContext(
            user: "alice",
            processName: "brew",
            canonicalPath: "/opt/homebrew/bin/brew",
            teamID: nil,
            signingStatus: .unsigned,
            humanReadableRequest: "sudo brew install wget",
            requireJustification: true,
            justificationMinLength: 10,
            timeoutSeconds: 60
        )
        let data = try SerberusXPCCoding.encode(context)
        let decoded = try SerberusXPCCoding.decode(PromptContext.self, from: data)
        #expect(decoded == context)
    }
}
