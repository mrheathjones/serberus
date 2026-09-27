import Foundation
import Testing
@testable import PrivMgrCore

@Suite("Error descriptions — every case is presentable")
struct ErrorDescriptionTests {
    @Test("all error enums produce non-empty localized descriptions")
    func descriptions() {
        let errors: [any LocalizedError] = [
            PolicyError.profileDecodingFailed(profileKey: "k", underlying: "u"),
            PolicyError.unrecognizedSchemaVersion(profileKey: "k", version: "9"),
            PolicyError.invalidRegex(ruleID: "r", pattern: "(", underlying: "u"),
            PolicyError.invalidEvaluationContext(reason: "r"),
            PathError.relativePath("a/b"),
            PathError.ambiguousPath("/a/../b"),
            PathError.missingExecutable("/x"),
            PathError.emptyPath,
            ConfigError.missingKey(domain: "d", key: "k"),
            ConfigError.invalidValue(domain: "d", key: "k", reason: "r"),
            GrantStoreError.openFailed(path: "/p", code: 14, message: "m"),
            GrantStoreError.statementFailed(sql: "s", code: 1, message: "m"),
            GrantStoreError.migrationFailed(from: 1, to: 2, underlying: "u"),
            GrantStoreError.schemaTooNew(found: 9, supported: 1),
            GrantStoreError.integrityViolation(grantID: "g"),
            GrantStoreError.rowDecodingFailed(grantID: "g", reason: "r"),
            LoggingError.directoryUnavailable(path: "/p", underlying: "u"),
            LoggingError.encodingFailed(reason: "r"),
            LoggingError.signingKeyUnavailable(reason: "r"),
            JamfError.notConfigured(missingKey: "jamfProURL"),
            JamfError.credentialsInvalid,
            JamfError.insufficientPermissions(endpoint: "e"),
            JamfError.unreachable(underlying: "u"),
            JamfError.unexpectedStatus(code: 500, endpoint: "e"),
            JamfError.responseDecodingFailed(endpoint: "e", reason: "r"),
            ExportError.validationFailed(issues: ["i"]),
            ExportError.serializationFailed(reason: "r"),
            XPCValidationError.signatureInvalid(reason: "r"),
            XPCValidationError.teamIDMismatch(found: nil),
            XPCValidationError.expectedTeamIDUnavailable,
            XPCValidationError.unknownBundleID(found: "x"),
            XPCValidationError.missingEntitlement(name: "n"),
            XPCValidationError.hardenedRuntimeDisabled,
            XPCValidationError.auditTokenUnresolvable,
        ]
        for error in errors {
            #expect(!(error.errorDescription ?? "").isEmpty, "\(error)")
        }
    }
}

@Suite("ManagedPreferencesReader — prompts and notify domains")
struct PromptsNotifyTests {
    private func reader(prompts: [String: any Sendable] = [:],
                        notify: [String: any Sendable] = [:]) -> ManagedPreferencesReader {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.promptsDomain: prompts,
            BundleConfig.notifyDomain: notify,
        ]))
    }

    @Test("prompts defaults match the spec")
    func promptsDefaults() {
        let prompts = reader().readPrompts().value
        #expect(prompts == PromptsConfig())
        #expect(prompts.justificationMinLength == 0)
        #expect(prompts.allowButtonLabel == "Yes, continue")
        #expect(prompts.denyButtonLabel == "No, cancel")
        #expect(prompts.brandTitle == nil)
        #expect(prompts.brandSubtitle == nil)
        #expect(prompts.menuBarTopRulesCount == 3)
        // The audit-recipient label defaults to "IT" until an org sets its own.
        #expect(prompts.auditRecipientLabel == "IT")
    }

    @Test("auditRecipientLabel parses, and blank falls back to the IT default")
    func auditRecipientLabel() {
        #expect(reader(prompts: ["auditRecipientLabel": "Security"]).readPrompts().value.auditRecipientLabel == "Security")
        // Jamf emits "" for an untouched text field → treated as absent → default.
        #expect(reader(prompts: ["auditRecipientLabel": "   "]).readPrompts().value.auditRecipientLabel == "IT")
        #expect(reader(prompts: [:]).readPrompts().value.auditRecipientLabel == "IT")
    }

    @Test("menuBarTopRulesCount parses and clamps out-of-range")
    func topRulesCount() {
        #expect(reader(prompts: ["menuBarTopRulesCount": 5]).readPrompts().value.menuBarTopRulesCount == 5)
        #expect(reader(prompts: ["menuBarTopRulesCount": 0]).readPrompts().value.menuBarTopRulesCount == 0)
        // Out of range → default, with a finding.
        let bad = reader(prompts: ["menuBarTopRulesCount": 999]).readPrompts()
        #expect(bad.value.menuBarTopRulesCount == 3)
        #expect(!bad.findings.isEmpty)
    }

    @Test("prompts overrides parse")
    func promptsOverrides() {
        let result = reader(prompts: [
            "promptTimeoutSeconds": 30,
            "requireJustification": true,
            "justificationMinLength": 15,
            "allowButtonLabel": "Yes",
            "brandTitle": "Acme Inc",
            "brandSubtitle": "IT Security",
        ]).readPrompts()
        // The retired prompts keys are ignored, not parsed and not a finding.
        #expect(result.value == PromptsConfig(justificationMinLength: 15, allowButtonLabel: "Yes",
                                              brandTitle: "Acme Inc", brandSubtitle: "IT Security"))
        #expect(result.value.justificationMinLength == 15)
        #expect(result.value.allowButtonLabel == "Yes")
        #expect(result.value.brandTitle == "Acme Inc")
        #expect(result.value.brandSubtitle == "IT Security")
        #expect(result.findings.isEmpty)
    }

    @Test("empty branding strings mean unbranded — Jamf emits \"\" for untouched fields")
    func brandingEmptyIsAbsent() {
        let result = reader(prompts: ["brandTitle": "  ", "brandSubtitle": ""]).readPrompts()
        #expect(result.value.brandTitle == nil)
        #expect(result.value.brandSubtitle == nil)
        #expect(result.findings.isEmpty)
    }

    @Test("notify defaults match the spec")
    func notifyDefaults() {
        let notify = reader().readNotify().value
        #expect(notify == NotifyConfig())
        #expect(notify.logRetentionDays == 90)
    }

    @Test("retired notify keys (webhookURL, logVerbosity, …) are ignored — no finding, no effect")
    func retiredNotifyKeysIgnored() {
        let result = reader(notify: ["webhookURL": "http://x.example", "logVerbosity": "debug",
                                     "jamfProtectEvents": true, "stalenessThresholdMinutes": 5,
                                     "logRetentionDays": 30]).readNotify()
        #expect(result.value == NotifyConfig(logRetentionDays: 30))
        #expect(result.findings.isEmpty)
    }
}

@Suite("Crypto support")
struct CryptoSupportTests {
    @Test("HMAC verification rejects wrong key, wrong message, wrong length")
    func hmacVerify() {
        let key = HMACSHA256.generateKey()
        let message = Data("payload".utf8)
        let signature = HMACSHA256.hexSignature(message: message, key: key)

        #expect(HMACSHA256.verify(message: message, key: key, expectedHex: signature))
        #expect(!HMACSHA256.verify(message: Data("other".utf8), key: key, expectedHex: signature))
        #expect(!HMACSHA256.verify(message: message, key: HMACSHA256.generateKey(), expectedHex: signature))
        #expect(!HMACSHA256.verify(message: message, key: key, expectedHex: "deadbeef"))
    }

    @Test("file digest matches data digest")
    func fileDigest() throws {
        let directory = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("blob")
        let data = Data("serberus".utf8)
        try data.write(to: url)
        #expect(try SHA256Hasher.hexDigest(fileAt: url) == SHA256Hasher.hexDigest(data))
        #expect(SHA256Hasher.hexDigest(data).count == 64)
    }

    @Test("InMemoryKeyProvider surfaces missing accounts")
    func missingAccount() {
        let provider = InMemoryKeyProvider(keys: [:])
        #expect(throws: LoggingError.self) {
            _ = try provider.key(account: "nope")
        }
    }

    @Test("stable UUIDs are valid RFC 4122 and stable")
    func stableUUID() {
        let a = MobileConfigGenerator.stableUUID(seed: "seed")
        let b = MobileConfigGenerator.stableUUID(seed: "seed")
        let c = MobileConfigGenerator.stableUUID(seed: "other")
        #expect(a == b)
        #expect(a != c)
        #expect(a.uuidString.count == 36)
    }
}

@Suite("XPC DTO round-trips")
struct DTORoundTripTests {
    @Test("PromptResponse and Grant round-trip")
    func roundTrips() throws {
        let response = PromptResponse(requestID: UUID(), verdict: .timedOut)
        #expect(try SerberusXPCCoding.decode(
            PromptResponse.self, from: try SerberusXPCCoding.encode(response)
        ) == response)

        let grant = Grant(
            user: "alice", uid: 501, ruleID: "r", profileKey: "rules_sudo_test",
            teamID: "", binaryHash: "ff", canonicalPath: "/bin/x",
            grantedAt: Fixtures.now, expiresAt: nil, policyVersion: "1.0.0"
        )
        let decodedGrant = try SerberusXPCCoding.decode(
            Grant.self, from: try SerberusXPCCoding.encode(grant)
        )
        #expect(decodedGrant.grantID == grant.grantID)
        #expect(decodedGrant.isActive(at: Fixtures.now))

        // The continuous-clock fields cross XPC too (the Sentinel checks them).
        let stamped = Grant(
            user: "alice", uid: 501, ruleID: "r", profileKey: "rules_sudo_test",
            teamID: "", binaryHash: "ff", canonicalPath: "/bin/x",
            grantedAt: Fixtures.now, expiresAt: Fixtures.now.addingTimeInterval(60), policyVersion: "1.0.0",
            bootSessionID: "boot-a", continuousDeadlineNanos: 42
        )
        #expect(try SerberusXPCCoding.decode(Grant.self, from: try SerberusXPCCoding.encode(stamped)) == stamped)
    }

    @Test("every daemon state and degraded reason has a stable raw value")
    func stateRawValues() {
        #expect(DaemonState.pendingPPPC.rawValue == "pending_pppc")
        #expect(DaemonState.pendingProfiles.rawValue == "pending_profiles")
        #expect(DaemonState.killSwitch.rawValue == "kill_switch")
        #expect(DegradedReason.configInvalid.rawValue == "config_invalid")
        #expect(DegradedReason.authDBFailure.rawValue == "authdb_failure")
        #expect(DegradedReason.xpcFailure.rawValue == "xpc_failure")
        #expect(DegradedReason.reloadStalled.rawValue == "reload_stalled")
    }
}

@Suite("SessionGrantCache — maintenance")
struct SessionGrantCacheMaintenanceTests {
    @Test("pruneExpired and count")
    func pruneAndCount() async {
        let cache = SessionGrantCache()
        let live = SessionGrantCache.Key(user: "a", ruleID: "r1", binaryHash: "00")
        let dead = SessionGrantCache.Key(user: "b", ruleID: "r2", binaryHash: "11")
        await cache.store(decision: .allow, key: live, ttlSeconds: 600, now: Fixtures.now)
        await cache.store(decision: .allow, key: dead, ttlSeconds: 10, now: Fixtures.now)

        let later = Fixtures.now.addingTimeInterval(60)
        #expect(await cache.count(now: later) == 1)
        await cache.removeAll()
        #expect(await cache.count(now: later) == 0)
    }
}

@Suite("Jamf surface details")
struct JamfSurfaceTests {
    @Test("form encoding is deterministic and escapes reserved characters")
    func formEncode() {
        let encoded = JamfTokenManager.formEncode([
            "client_secret": "p@ss w&rd=",
            "client_id": "id",
            "grant_type": "client_credentials",
        ])
        #expect(encoded == "client_id=id&client_secret=p%40ss%20w%26rd%3D&grant_type=client_credentials")
    }

    @Test("XML escaping covers all five entities")
    func xmlEscape() {
        #expect(JamfAPIClient.xmlEscape(#"<a & "b" 'c'>"#) == "&lt;a &amp; &quot;b&quot; &apos;c&apos;&gt;")
    }

    @Test("ID extraction tolerates missing tags")
    func extractID() {
        #expect(JamfAPIClient.extractID(fromXML: Data("<x><id>9</id></x>".utf8)) == 9)
        #expect(JamfAPIClient.extractID(fromXML: Data("<x/>".utf8)) == nil)
        #expect(JamfAPIClient.extractID(fromXML: Data("<id>not-a-number</id>".utf8)) == nil)
    }

    @Test("malformed token response surfaces a decoding error")
    func badTokenBody() async throws {
        let transport = MockTransport(script: [.init(status: 200, body: Data("{}".utf8))])
        let store = JamfCredentialStore(reader: ManagedPreferencesReader(
            source: DictionaryPreferencesSource(domains: [
                BundleConfig.configDomain: [
                    "jamfProURL": "https://example.jamfcloud.com",
                    "jamfAPIClientID": "id",
                    "jamfAPIClientSecret": "secret",
                ],
            ])
        ))
        let manager = JamfTokenManager(credentialStore: store, transport: transport, now: { Fixtures.now })
        await #expect(throws: JamfError.self) {
            _ = try await manager.token()
        }
    }

    @Test("updateConfigurationProfile sends PUT to the right endpoint")
    func update() async throws {
        let transport = MockTransport(script: [
            .init(status: 200, body: Data(#"{"access_token":"t","expires_in":1800}"#.utf8)),
            .init(status: 201, body: Data("<id>5</id>".utf8)),
        ])
        let store = JamfCredentialStore(reader: ManagedPreferencesReader(
            source: DictionaryPreferencesSource(domains: [
                BundleConfig.configDomain: [
                    "jamfProURL": "https://example.jamfcloud.com",
                    "jamfAPIClientID": "id",
                    "jamfAPIClientSecret": "secret",
                ],
            ])
        ))
        let manager = JamfTokenManager(credentialStore: store, transport: transport, now: { Fixtures.now })
        let client = JamfAPIClient(credentialStore: store, tokenManager: manager, transport: transport)
        try await client.updateConfigurationProfile(id: 5, name: "n", mobileconfig: Data("<plist/>".utf8))
        let request = await transport.requests.last
        #expect(request?.httpMethod == "PUT")
        #expect(request?.url?.path.hasSuffix("/osxconfigurationprofiles/id/5") == true)
    }

    @Test("profile name matching is case-insensitive and trims whitespace")
    func nameMatching() {
        #expect(JamfAPIClient.profileNamesMatch("Serberus — Rules", " serberus — rules "))
        #expect(!JamfAPIClient.profileNamesMatch("Serberus — Rules A", "Serberus — Rules B"))
    }

    @Test("MDM publish updates in place when a profile already carries the name")
    func publishUpdatesExisting() async throws {
        let list = #"{"os_x_configuration_profiles":[{"id":7,"name":"SERBERUS — rules_authuri_a "}]}"#
        let transport = MockTransport(script: [
            .init(status: 200, body: Data(#"{"access_token":"t","expires_in":1800}"#.utf8)),
            .init(status: 200, body: Data(list.utf8)),
            .init(status: 201, body: Data("<id>7</id>".utf8)),
        ])
        let provider = JamfMDMProvider(transport: transport)
        let connection = MDMConnection(
            vendor: .jamf, instanceURL: "https://example.jamfcloud.com", clientID: "id", clientSecret: "secret")
        let result = await provider.publish(
            name: "Serberus — rules_authuri_a", mobileconfig: Data("<plist/>".utf8), connection: connection)
        #expect(result == .success(7))
        let last = await transport.requests.last
        #expect(last?.httpMethod == "PUT")
        #expect(last?.url?.path.hasSuffix("/osxconfigurationprofiles/id/7") == true)
    }

    @Test("MDM publish creates when no existing name matches")
    func publishCreatesNew() async throws {
        let transport = MockTransport(script: [
            .init(status: 200, body: Data(#"{"access_token":"t","expires_in":1800}"#.utf8)),
            .init(status: 200, body: Data(#"{"os_x_configuration_profiles":[]}"#.utf8)),
            .init(status: 201, body: Data("<id>9</id>".utf8)),
        ])
        let provider = JamfMDMProvider(transport: transport)
        let connection = MDMConnection(
            vendor: .jamf, instanceURL: "https://example.jamfcloud.com", clientID: "id", clientSecret: "secret")
        let result = await provider.publish(
            name: "Serberus — rules_new", mobileconfig: Data("<plist/>".utf8), connection: connection)
        #expect(result == .success(9))
        let last = await transport.requests.last
        #expect(last?.httpMethod == "POST")
        #expect(last?.url?.path.hasSuffix("/osxconfigurationprofiles/id/0") == true)
    }

    @Test("409 name conflict maps to an actionable message, not 'unreachable'")
    func conflictMapping() {
        let mapped = JamfMDMProvider.map(
            JamfError.unexpectedStatus(code: 409, endpoint: "JSSResource/osxconfigurationprofiles/id/0"))
        guard case let .misconfigured(detail) = mapped else {
            Issue.record("expected .misconfigured, got \(mapped)")
            return
        }
        #expect(detail.contains("409"))
    }

    @Test("instanceInfo decodes the Jamf Pro version")
    func instanceInfo() async throws {
        let transport = MockTransport(script: [
            .init(status: 200, body: Data(#"{"access_token":"t","expires_in":1800}"#.utf8)),
            .init(status: 200, body: Data(#"{"version":"11.9.0"}"#.utf8)),
        ])
        let store = JamfCredentialStore(reader: ManagedPreferencesReader(
            source: DictionaryPreferencesSource(domains: [
                BundleConfig.configDomain: [
                    "jamfProURL": "https://example.jamfcloud.com",
                    "jamfAPIClientID": "id",
                    "jamfAPIClientSecret": "secret",
                ],
            ])
        ))
        let manager = JamfTokenManager(credentialStore: store, transport: transport, now: { Fixtures.now })
        let client = JamfAPIClient(credentialStore: store, tokenManager: manager, transport: transport)
        #expect(try await client.instanceInfo().version == "11.9.0")
    }
}

@Suite("Log file naming")
struct LogNamingTests {
    @Test("day stamp parsing accepts only well-formed Serberus names")
    func dayStampParsing() {
        #expect(LogRotator.dayStamp(fromFilename: "decisions-2026-06-12.jsonl") == "2026-06-12")
        #expect(LogRotator.dayStamp(fromFilename: "integrity-2026-06-12.jsonl.hmac") == "2026-06-12")
        #expect(LogRotator.dayStamp(fromFilename: "decisions.jsonl") == nil)
        #expect(LogRotator.dayStamp(fromFilename: "notes.txt") == nil)
        #expect(LogRotator.dayStamp(fromFilename: "decisions-2026-6-12.jsonl") == nil)
    }

    @Test("UTC day stamp is stable across the day boundary")
    func dayStamp() {
        #expect(LogDay.stamp(for: Fixtures.now) == "2026-06-12")
        #expect(LogDay.stamp(for: Fixtures.now.addingTimeInterval(-1)) == "2026-06-11")
    }
}
