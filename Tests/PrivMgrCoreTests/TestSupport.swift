import Foundation
import Testing
@testable import PrivMgrCore

// MARK: - MCX payload helpers

/// The single `com.apple.ManagedClient.preferences` payload inside a serialized
/// `.mobileconfig` produced by ``MobileConfigGenerator``.
func mcxPayloadEnvelope(inMobileconfig data: Data) throws -> [String: Any] {
    let root = try #require(
        try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    let contents = try #require(root["PayloadContent"] as? [[String: Any]])
    return try #require(
        contents.first { $0["PayloadType"] as? String == "com.apple.ManagedClient.preferences" },
        "no com.apple.ManagedClient.preferences payload")
}

/// The flat forced settings for `domain` inside a serialized `.mobileconfig` —
/// the exact dict macOS composes into `/Library/Managed Preferences/<domain>.plist`,
/// which is what ``ManagedPreferencesReader`` reads. Unwraps the
/// `Forced` → `mcx_preference_settings` envelope.
func mcxSettings(inMobileconfig data: Data, domain: String) throws -> [String: Any] {
    let payload = try mcxPayloadEnvelope(inMobileconfig: data)
    let inner = try #require(payload["PayloadContent"] as? [String: Any])
    let domainDict = try #require(inner[domain] as? [String: Any], "no MCX entry for \(domain)")
    let forced = try #require(domainDict["Forced"] as? [[String: Any]])
    return try #require(forced.first?["mcx_preference_settings"] as? [String: Any])
}

/// Shared fixtures. Fixed timestamps keep every test deterministic.
enum Fixtures {
    /// 2026-06-12 00:00:00 UTC.
    static let now = Date(timeIntervalSince1970: 1_781_222_400)

    static let brewIdentity = BinaryIdentity(
        canonicalPath: "/opt/homebrew/bin/brew",
        teamID: nil,
        sha256: "aa" + String(repeating: "0", count: 62),
        signingStatus: .unsigned
    )

    static let signedToolIdentity = BinaryIdentity(
        canonicalPath: "/usr/local/bin/signedtool",
        teamID: "TEAM123456",
        sha256: "bb" + String(repeating: "0", count: 62),
        signingStatus: .valid
    )

    static func sudoRequest(
        user: String = "alice",
        command: String = "/opt/homebrew/bin/brew",
        argv: [String] = ["install", "wget"],
        identity: BinaryIdentity = brewIdentity,
        justificationProvided: Bool = false,
        timestamp: Date = now
    ) -> ElevationRequest {
        ElevationRequest(
            user: user,
            uid: 501,
            kind: .sudo(command: command, argv: argv),
            identity: identity,
            justificationProvided: justificationProvided,
            timestamp: timestamp
        )
    }

    static func authURIRequest(
        user: String = "alice",
        uri: String = "system.keychain-modify",
        identity: BinaryIdentity = signedToolIdentity,
        timestamp: Date = now
    ) -> ElevationRequest {
        ElevationRequest(
            user: user,
            uid: 501,
            kind: .authURI(uri),
            identity: identity,
            timestamp: timestamp
        )
    }

    static func sudoRule(
        id: String = "allow-brew",
        action: RuleAction = .allow,
        priority: Int = 10,
        cacheSeconds: Int? = nil,
        commandPattern: String? = "/opt/homebrew/bin/brew",
        argPattern: String? = nil,
        matchType: MatchType? = .exact,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil,
        conditions: RuleConditions = RuleConditions(),
        elevation: ElevationBehavior = ElevationBehavior()
    ) -> Rule {
        Rule(
            id: id,
            type: .sudo,
            action: action,
            description: "test rule \(id)",
            priority: priority,
            cacheSeconds: cacheSeconds,
            match: MatchCriteria(
                commandPattern: commandPattern,
                argPattern: argPattern,
                matchType: matchType,
                requiredTeamID: requiredTeamID,
                requiredBinaryHash: requiredBinaryHash
            ),
            conditions: conditions,
            elevation: elevation
        )
    }

    static func authURIRule(
        id: String = "allow-keychain",
        action: RuleAction = .allow,
        priority: Int = 10,
        authURI: String = "system.keychain-modify",
        conditions: RuleConditions = RuleConditions(),
        elevation: ElevationBehavior = ElevationBehavior(),
        appIdentity: AppIdentityBranch? = nil
    ) -> Rule {
        Rule(
            id: id,
            type: .authuri,
            action: action,
            description: "test rule \(id)",
            priority: priority,
            match: MatchCriteria(authURI: authURI),
            conditions: conditions,
            elevation: elevation,
            appIdentity: appIdentity
        )
    }

    static func profile(
        key: String = "rules_sudo_test",
        priority: Int = 50,
        policyVersion: String = "1.0.0",
        rules: [Rule]
    ) -> RuleProfile {
        RuleProfile(
            policyVersion: policyVersion,
            profileKey: key,
            profilePriority: priority,
            rules: rules
        )
    }

    /// A grant snapshot covering ``brewIdentity`` for `ruleID`.
    static func grantSnapshot(
        user: String = "alice",
        ruleID: String,
        binaryHash: String = brewIdentity.sha256,
        expiresAt: Date? = now.addingTimeInterval(600)
    ) -> GrantSnapshot {
        GrantSnapshot(
            grantID: UUID(),
            user: user,
            ruleID: ruleID,
            profileKey: "rules_sudo_test",
            canonicalPath: "/opt/homebrew/bin/brew",
            binaryHash: binaryHash,
            expiresAt: expiresAt
        )
    }

    /// A unique temp file path for SQLite-backed tests.
    static func tempDatabasePath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-test-\(UUID().uuidString).sqlite")
            .path
    }

    /// A unique temp directory URL for log tests.
    static func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}

let engine = RuleEngine()

func evaluate(
    _ request: ElevationRequest,
    profiles: [RuleProfile],
    globalCacheSeconds: Int = 0,
    globalGrantDurationSeconds: Int = 0,
    timeBoundGrantsEnabled: Bool = true,
    grants: [GrantSnapshot] = []
) -> EvaluationResult {
    engine.evaluate(
        request: request,
        profiles: profiles,
        globalCacheSeconds: globalCacheSeconds,
        globalGrantDurationSeconds: globalGrantDurationSeconds,
        timeBoundGrantsEnabled: timeBoundGrantsEnabled,
        activeGrants: grants
    )
}
