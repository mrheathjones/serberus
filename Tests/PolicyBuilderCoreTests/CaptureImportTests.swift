import Foundation
import PrivMgrCore
import Testing
@testable import PolicyBuilderCore

/// Capture → Definition mapping (Import Capture). The pre-filled draft must be
/// exactly what the engine will match: exact command path, realpath for a
/// symlinked binary, an anchored/escaped `argPattern` over `argv[0]`, and the
/// Team ID as the default pin — never the hash.
@Suite("CaptureImporter")
struct CaptureImportTests {
    private static let base = Date(timeIntervalSince1970: 1_784_000_000)

    private var capture: RuleCapture {
        RuleCapture(
            host: CaptureHost(serialNumber: "SER1", computerName: "TESTMAC-2291", osVersion: "26.4", userName: "tuser",
                              daemonState: "healthy", enforcementMode: "enforce"),
            startedAt: Self.base, endedAt: Self.base.addingTimeInterval(30), attempts: []
        )
    }

    private func sudoAttempt(command: String = "/usr/local/bin/jamf", resolved: String? = "/usr/local/jamf/bin/jamf",
                             argv: [String]? = ["policy", "-event", "x"], teamID: String? = "483DWKW443",
                             outcome: CapturedOutcome = .denied, status: String? = "command not allowed",
                             rule: String? = nil) -> CapturedAttempt {
        CapturedAttempt(id: UUID().uuidString, kind: .sudo, timestamp: Self.base.addingTimeInterval(5), user: "tuser",
                        sudoCommand: command, resolvedCommand: resolved, argv: argv, sudoStatus: status,
                        teamID: teamID, binaryHash: "cafe", outcome: outcome, matchedRuleID: rule, rawLines: ["x"])
    }

    private func rightAttempt(right: String = "system.preferences.datetime", teamID: String? = nil) -> CapturedAttempt {
        CapturedAttempt(id: UUID().uuidString, kind: .authuri, timestamp: Self.base.addingTimeInterval(6), user: "tuser",
                        authURI: right, clientPath: "/System/Applications/System Settings.app/Contents/MacOS/System Settings",
                        teamID: teamID, outcome: .granted, rawLines: ["y"])
    }

    @Test("a sudo attempt → exact command, realpath, anchored argv[0] pattern, Team ID pin, no hash")
    func sudoDraft() {
        let draft = CaptureImporter.draft(for: sudoAttempt(), capture: capture, existingIDs: [])
        #expect(draft.kind == .sudo)
        #expect(draft.definitionID == "sudo_jamf_policy")
        #expect(draft.name == "sudo jamf policy")
        #expect(draft.commandPattern == "/usr/local/bin/jamf")
        #expect(draft.resolvedCommandPattern == "/usr/local/jamf/bin/jamf")
        #expect(draft.argPattern == "^policy$")
        #expect(draft.matchType == .exact)
        #expect(draft.requiredTeamID == "483DWKW443")
        #expect(draft.requiredBinaryHash.isEmpty)
        #expect(draft.detail.contains("TESTMAC-2291"))
        #expect(draft.detail.contains("by tuser"))
        #expect(draft.detail.contains("(denied)"))
        // And the draft round-trips into a valid RuleDefinition.
        let definition = draft.toDefinition()
        #expect(definition.commandPattern == "/usr/local/bin/jamf")
        #expect(definition.resolvedCommandPattern == "/usr/local/jamf/bin/jamf")
        #expect(definition.argPattern == "^policy$")
        #expect(definition.requiredTeamID == "483DWKW443")
        #expect(definition.requiredBinaryHash == nil)
    }

    @Test("argv[0] metacharacters are escaped so the pattern matches only what was seen")
    func escapedArgument() {
        let draft = CaptureImporter.draft(for: sudoAttempt(argv: ["a.b+c*"]), capture: nil, existingIDs: [])
        #expect(draft.argPattern == "^a\\.b\\+c\\*$")
        let regex = try? NSRegularExpression(pattern: draft.argPattern)
        #expect(regex?.firstMatch(in: "a.b+c*", range: NSRange(location: 0, length: 6)) != nil)
        #expect(regex?.firstMatch(in: "aXb+c*", range: NSRange(location: 0, length: 6)) == nil)
    }

    @Test("no arguments (or redacted) → no argPattern, name is just the binary")
    func noArguments() {
        let none = CaptureImporter.draft(for: sudoAttempt(argv: []), capture: nil, existingIDs: [])
        #expect(none.argPattern.isEmpty)
        #expect(none.name == "sudo jamf")
        let redacted = CaptureImporter.draft(for: sudoAttempt(argv: nil), capture: nil, existingIDs: [])
        #expect(redacted.argPattern.isEmpty)
        #expect(redacted.definitionID == "sudo_jamf")
    }

    @Test("an authuri attempt → exact right, slug id, and NO pre-filled Team ID pin (the authdb layer cannot enforce one)")
    func rightDraft() {
        let draft = CaptureImporter.draft(for: rightAttempt(teamID: "APPLE"), capture: capture, existingIDs: [])
        #expect(draft.kind == .authuri)
        #expect(draft.authURI == "system.preferences.datetime")
        #expect(draft.name == "system.preferences.datetime")
        #expect(draft.definitionID == "system_preferences_datetime")
        #expect(draft.requiredTeamID.isEmpty)
        #expect(draft.commandPattern.isEmpty)
    }

    @Test("the definition's detail names the command and argv[0] only — never later arguments")
    func detailOmitsLaterArguments() {
        let draft = CaptureImporter.draft(for: sudoAttempt(argv: ["policy", "-p", "hunter2"]), capture: capture, existingIDs: [])
        #expect(draft.detail.contains("/usr/local/bin/jamf policy"))
        #expect(!draft.detail.contains("hunter2"))
        #expect(!draft.detail.contains("-p"))
    }

    @Test("ids stay unique across the library and across a batch")
    func uniqueIDs() {
        let one = CaptureImporter.draft(for: sudoAttempt(), capture: nil, existingIDs: ["sudo_jamf_policy"])
        #expect(one.definitionID == "sudo_jamf_policy_2")
        let batch = CaptureImporter.drafts(for: [sudoAttempt(), sudoAttempt(), rightAttempt()], capture: nil,
                                           existingIDs: ["system_preferences_datetime"])
        #expect(batch.map(\.definitionID) == ["sudo_jamf_policy", "sudo_jamf_policy_2", "system_preferences_datetime_2"])
    }

    @Test("an attempt with nothing to name falls back to a safe slug")
    func emptySlug() {
        let empty = CapturedAttempt(id: "e", kind: .authuri, timestamp: Self.base, user: nil, authURI: "",
                                    outcome: .unknown, rawLines: [])
        #expect(CaptureImporter.draft(for: empty, capture: nil, existingIDs: []).definitionID == "captured_attempt")
    }

    /// Two captures in the real on-disk format, anonymized: host, serial, and
    /// user are synthetic, and the free-text notes are rewritten. If the format
    /// or the mapping drifts, these fail first.
    private static let liveSudoCapture = #"""
    {
      "argumentsRedacted" : false,
      "attempts" : [
        {
          "argv" : [ "checkJSSConnection" ],
          "binaryHash" : "70c8361b68cf488e75fac62d95efbe0b6f4e4eb0eb5213eddac00331576fa6ea",
          "id" : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx1",
          "kind" : "sudo",
          "outcome" : "unknown",
          "pid" : 64627,
          "rawLines" : [
            "testuser : denied by Serberus - see the message above ; TTY=ttys002 ; PWD=/Users/testuser ; USER=root ; COMMAND=/usr/local/bin/jamf checkJSSConnection"
          ],
          "resolvedCommand" : "/usr/local/jamf/bin/jamf",
          "serberusOutcome" : "denied",
          "sudoCommand" : "/usr/local/bin/jamf",
          "sudoStatus" : "denied by Serberus - see the message above",
          "teamID" : "483DWKW443",
          "timestamp" : "2026-08-22T23:13:56Z",
          "user" : "testuser"
        }
      ],
      "componentVersions" : { "daemonVersion" : "3.8", "installedBy" : "SerberusSentinelAgent test pkg (baked in payload)", "pamModuleVersion" : "3.8" },
      "endedAt" : "2026-08-22T23:14:02Z",
      "host" : { "computerName" : "TESTMAC01", "daemonState" : "healthy", "enforcementMode" : "enforce", "osVersion" : "Version 27.0 (Build 26A5416b)", "serialNumber" : "SYNTHSER01", "userName" : "testuser" },
      "notes" : "Check the Jamf connection",
      "schemaVersion" : "1.0",
      "startedAt" : "2026-08-22T23:13:53Z"
    }
    """#

    private static let liveAuthuriCapture = #"""
    {
      "argumentsRedacted" : false,
      "attempts" : [
        { "authURI" : "system.preferences.accounts", "id" : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx2", "kind" : "authuri", "outcome" : "requested", "pid" : 610,
          "rawLines" : [ "Validating shared credential testuser (504) for system.preferences.accounts (engine 7222)" ],
          "timestamp" : "2026-08-22T23:15:21Z", "user" : "testuser" },
        { "authURI" : "system.preferences.accounts", "id" : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx3", "kind" : "authuri", "outcome" : "denied", "pid" : 610,
          "rawLines" : [
            "Validating shared credential testuser (504) for system.preferences.accounts (engine 7226)",
            "Validating session owner testuser (504) for system.preferences.accounts (engine 7226)",
            "UID 504 authenticated as user testuser (UID 504) for right 'system.preferences.accounts'",
            "Validating credential testuser (504) for system.preferences.accounts (engine 7226)"
          ],
          "timestamp" : "2026-08-22T23:15:30Z", "user" : "testuser" }
      ],
      "componentVersions" : { "daemonVersion" : "3.8", "installedBy" : "SerberusSentinelAgent test pkg (baked in payload)", "pamModuleVersion" : "3.8" },
      "endedAt" : "2026-08-22T23:15:35Z",
      "host" : { "computerName" : "TESTMAC01", "daemonState" : "healthy", "enforcementMode" : "enforce", "osVersion" : "Version 27.0 (Build 26A5416b)", "serialNumber" : "SYNTHSER01", "userName" : "testuser" },
      "notes" : "Manage local user accounts",
      "schemaVersion" : "1.0",
      "startedAt" : "2026-08-22T23:15:18Z"
    }
    """#

    @Test("the first LIVE sudo capture decodes and maps to exactly the jamf definition the admin needs")
    func liveSudoCapture() throws {
        let capture = try RuleCapture.decode(from: Data(Self.liveSudoCapture.utf8))
        #expect(capture.host.serialNumber == "SYNTHSER01")
        #expect(capture.host.enforcementMode == "enforce")
        let attempt = try #require(capture.attempts.first)
        #expect(attempt.serberusOutcome == "denied")
        #expect(attempt.matchedRuleID == nil)          // denied because NO rule matched
        let draft = CaptureImporter.draft(for: attempt, capture: capture, existingIDs: [])
        #expect(draft.kind == .sudo)
        #expect(draft.definitionID == "sudo_jamf_checkjssconnection")
        #expect(draft.commandPattern == "/usr/local/bin/jamf")
        #expect(draft.resolvedCommandPattern == "/usr/local/jamf/bin/jamf")
        #expect(draft.argPattern == "^checkJSSConnection$")
        #expect(draft.requiredTeamID == "483DWKW443")
        #expect(draft.requiredBinaryHash.isEmpty)
        #expect(draft.detail.contains("TESTMAC01"))
        #expect(draft.detail.contains("Serberus denied"))
        #expect(!draft.detail.contains("70c8361b"))       // the hash is not prose
    }

    @Test("the first LIVE authuri capture decodes; both attempts map to the same right, one definition")
    func liveAuthuriCapture() throws {
        let capture = try RuleCapture.decode(from: Data(Self.liveAuthuriCapture.utf8))
        #expect(capture.attempts.count == 2)
        #expect(capture.attempts.map(\.outcome) == [.requested, .denied])
        let drafts = CaptureImporter.drafts(for: capture.attempts, capture: capture, existingIDs: [])
        #expect(drafts.map(\.authURI) == ["system.preferences.accounts", "system.preferences.accounts"])
        #expect(drafts.map(\.definitionID) == ["system_preferences_accounts", "system_preferences_accounts_2"])
        #expect(drafts.allSatisfy { $0.requiredTeamID.isEmpty })
    }

    @Test("load(url:) decodes a valid file and refuses an oversize one before reading it")
    func loadGuards() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("capture-import-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let valid = dir.appendingPathComponent("a.serberuscapture")
        try capture.encoded().write(to: valid)
        let loaded = try CaptureImporter.load(url: valid)
        #expect(loaded.host.serialNumber == "SER1")

        let huge = dir.appendingPathComponent("huge.serberuscapture")
        try Data(count: RuleCapture.maxEncodedBytes + 1).write(to: huge)
        #expect(throws: CaptureDecodeError.tooLarge(bytes: RuleCapture.maxEncodedBytes + 1)) {
            try CaptureImporter.load(url: huge)
        }

        let missing = dir.appendingPathComponent("missing.serberuscapture")
        #expect(throws: CaptureDecodeError.self) { try CaptureImporter.load(url: missing) }
    }
}
