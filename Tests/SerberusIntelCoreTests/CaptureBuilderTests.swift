import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

/// The Capture (Rule Recorder) mapping: raw authd + sudo lines (+ the daemon's
/// decision events) → `RuleCapture` attempts a Commander can author from.
@Suite("CaptureBuilder")
struct CaptureBuilderTests {
    // Whole-second base so ISO-8601 round-trips compare equal.
    private static let base = Date(timeIntervalSince1970: 1_784_000_000)
    private var started: Date { Self.base }
    private var ended: Date { Self.base.addingTimeInterval(60) }

    private static let systemSettings = "/System/Applications/System Settings.app/Contents/MacOS/System Settings"

    private func authd(_ message: String, at offset: TimeInterval) -> LogEntry {
        LogEntry(timestamp: "t+\(offset)", date: Self.base.addingTimeInterval(offset), level: .default,
                 subsystem: "com.apple.Authorization", category: "authd", message: message,
                 processImagePath: "/usr/libexec/authd", processID: 253)
    }

    private func sudo(_ message: String, at offset: TimeInterval, pid: Int = 6730) -> LogEntry {
        LogEntry(timestamp: "t+\(offset)", date: Self.base.addingTimeInterval(offset), level: .default,
                 subsystem: "", category: "", message: message,
                 processImagePath: "/usr/bin/sudo", processID: pid)
    }

    private func decision(
        at offset: TimeInterval, user: String = "tuser", command: String = "/usr/local/jamf/bin/jamf",
        outcome: DecisionEvent.Outcome = .denied, ruleID: String? = "jamf_policy_deny",
        profileKey: String? = "rules_sudo_jamf", teamID: String = "483DWKW443", hash: String = "cafe"
    ) -> DecisionEvent {
        DecisionEvent(
            timestamp: Self.base.addingTimeInterval(offset), outcome: outcome, enforcementMode: .enforce,
            authURI: nil, sudoCommand: command, arguments: nil, processPath: command,
            processTeamID: teamID, processHash: hash, userName: user, userUID: 501,
            ruleID: ruleID, profileKey: profileKey, grantID: nil, justification: nil,
            grantDurationSeconds: 0, cacheHit: false, deviceSerial: "SER1", daemonVersion: "3.8",
            pamModuleVersion: "3.8", policyVersion: "1.4.0"
        )
    }

    private var host: CaptureHost {
        CaptureHost(serialNumber: "SER1", computerName: "TESTMAC-2291", osVersion: "26.4",
                    userName: "tuser", daemonState: "healthy", enforcementMode: "enforce")
    }

    /// Deterministic builder: `/usr/local/bin/jamf` is a symlink to the real
    /// binary, the known paths exist as regular files, everything is signed
    /// by one Team ID; only the Date & Time right has a Serberus rule.
    private func makeBuilder(includeOtherUsers: Bool = false, hugeFile: Bool = false) -> CaptureBuilder {
        CaptureBuilder(
            identity: StaticBinaryIdentityInspector(identity: BinaryIdentity(
                canonicalPath: "", teamID: "ABCDE12345", sha256: "deadbeef", signingStatus: .valid)),
            ruleTagProvider: {
                { right in
                    right == "system.preferences.datetime"
                        ? AuthorizationRuleTag(ruleID: "datetime_allow", action: .allow, identityGated: false) : nil
                }
            },
            fileInfo: { path in
                let regular: Set<String> = ["/usr/local/jamf/bin/jamf", "/usr/bin/true", "/bin/sh", Self.systemSettings]
                if path == "/usr/local/bin/jamf" { return CaptureBuilder.FileInfo(isRegularFile: false, size: 0) } // symlink
                guard regular.contains(path) else { return nil }
                return CaptureBuilder.FileInfo(isRegularFile: true,
                                               size: hugeFile ? CaptureBuilder.maxHashedBinaryBytes + 1 : 1_000)
            },
            resolveSymlinks: { $0 == "/usr/local/bin/jamf" ? "/usr/local/jamf/bin/jamf" : $0 },
            includeOtherUsers: includeOtherUsers
        )
    }
    private var builder: CaptureBuilder { makeBuilder() }

    @Test("a sudo line becomes a sudo attempt with realpath, argv, identity pin and outcome")
    func sudoAttempt() throws {
        let capture = builder.build(
            authorizationEntries: [],
            sudoEntries: [sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf policy -event x", at: 5)],
            decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended
        )
        let attempt = try #require(capture.attempts.first)
        #expect(capture.attempts.count == 1)
        #expect(attempt.kind == .sudo)
        #expect(attempt.user == "tuser")
        #expect(attempt.sudoCommand == "/usr/local/bin/jamf")
        #expect(attempt.resolvedCommand == "/usr/local/jamf/bin/jamf")
        #expect(attempt.argv == ["policy", "-event", "x"])
        // Pinned from the REAL binary (the symlink itself is not a regular file).
        #expect(attempt.teamID == "ABCDE12345")
        #expect(attempt.binaryHash == "deadbeef")
        #expect(attempt.outcome == .granted)
        #expect(attempt.pid == 6730)
        #expect(attempt.matchedRuleID == nil)
        #expect(attempt.rawLines.count == 1)
        #expect(attempt.target == "/usr/local/bin/jamf policy -event x")
        #expect(attempt.binaryPath == "/usr/local/bin/jamf")
    }

    @Test("a Serberus decision for the same user+command enriches the attempt and its identity PAIR wins")
    func decisionEnrichment() throws {
        let capture = builder.build(
            authorizationEntries: [],
            sudoEntries: [sudo("tuser : command not allowed ; TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf policy", at: 10)],
            // The daemon records the CANONICAL path and decides just BEFORE sudo logs.
            decisions: [decision(at: 9.6, hash: "")],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended
        )
        let attempt = try #require(capture.attempts.first)
        #expect(attempt.matchedRuleID == "jamf_policy_deny")
        #expect(attempt.matchedProfileKey == "rules_sudo_jamf")
        #expect(attempt.serberusOutcome == "denied")
        #expect(attempt.teamID == "483DWKW443")
        // The decision carried no hash → NOT back-filled from disk (never a mixed pair).
        #expect(attempt.binaryHash == nil)
        // sudo's own verdict is kept as the attempt outcome.
        #expect(attempt.outcome == .denied)
        #expect(attempt.sudoStatus == "command not allowed")
    }

    @Test("a decision for another user, another command, or too far away is NOT matched")
    func decisionNotMatched() throws {
        let line = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf recon", at: 10)
        let farAway = decision(at: 10 + CaptureBuilder.decisionMatchTolerance + 1)
        let otherUser = decision(at: 10.2, user: "alice")
        let otherCommand = decision(at: 10.2, command: "/usr/bin/true")
        let capture = builder.build(
            authorizationEntries: [], sudoEntries: [line], decisions: [farAway, otherUser, otherCommand],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended
        )
        let attempt = try #require(capture.attempts.first)
        #expect(attempt.matchedRuleID == nil)
        #expect(attempt.serberusOutcome == nil)
        // Falls back to the on-disk identity.
        #expect(attempt.teamID == "ABCDE12345")
    }

    @Test("back-to-back runs of the same command each get their own decision, in order, never shared")
    func oneToOneDecisionAssignment() throws {
        let first = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf recon", at: 10)
        let second = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf recon", at: 11)
        // Decisions precede their lines by ~0.3 s; both are within tolerance of both lines.
        let d1 = decision(at: 9.7, outcome: .granted, ruleID: "r1")
        let d2 = decision(at: 10.7, outcome: .denied, ruleID: "r2")
        let capture = builder.build(
            authorizationEntries: [], sudoEntries: [second, first], decisions: [d2, d1],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended
        )
        #expect(capture.attempts.map(\.matchedRuleID) == ["r1", "r2"])
        #expect(capture.attempts.map(\.serberusOutcome) == ["granted", "denied"])
    }

    @Test("a decision that lands AFTER the line (prompt think-time) still matches when nothing precedes it")
    func laterDecisionFallback() throws {
        let line = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf recon", at: 10)
        let later = decision(at: 10 + 8, outcome: .granted, ruleID: "prompted")
        let capture = builder.build(
            authorizationEntries: [], sudoEntries: [line], decisions: [later],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended
        )
        #expect(capture.attempts.first?.matchedRuleID == "prompted")
    }

    @Test("sudo lines by other users are dropped unless includeOtherUsers is set")
    func consoleUserScoping() {
        let mine = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", at: 5)
        let theirs = sudo("alice : TTY=ttys002 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", at: 6)
        let scoped = builder.build(authorizationEntries: [], sudoEntries: [mine, theirs], decisions: [],
                                   host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(scoped.attempts.map(\.user) == ["tuser"])
        let all = makeBuilder(includeOtherUsers: true).build(
            authorizationEntries: [], sudoEntries: [mine, theirs], decisions: [],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(all.attempts.map(\.user) == ["tuser", "alice"])
    }

    @Test("binaries over the hash cap, non-regular files, and missing paths are not pinned")
    func pinGuards() throws {
        let huge = makeBuilder(hugeFile: true).build(
            authorizationEntries: [],
            sudoEntries: [sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", at: 5)],
            decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(huge.attempts.first?.teamID == nil)
        #expect(huge.attempts.first?.binaryHash == nil)
        let missing = builder.build(
            authorizationEntries: [],
            sudoEntries: [sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/nope/tool", at: 5)],
            decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(missing.attempts.first?.teamID == nil)
        #expect(missing.attempts.first?.resolvedCommand == nil)
    }

    @Test("authd lines become one authuri attempt per (engine, right) with client pin and rule tag")
    func authuriAttempt() throws {
        let client = Self.systemSettings
        let capture = builder.build(
            authorizationEntries: [
                authd("Validating credential tuser (501) for system.preferences.datetime (engine 42)", at: 20),
                authd("Succeeded authorizing right 'system.preferences.datetime' by client '\(client)' [900] for authorization created by '\(client)' [900] (2,0) (engine 42)", at: 21),
            ],
            sudoEntries: [], decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended
        )
        let attempt = try #require(capture.attempts.first)
        #expect(capture.attempts.count == 1)
        #expect(attempt.kind == .authuri)
        #expect(attempt.authURI == "system.preferences.datetime")
        #expect(attempt.clientPath == client)
        #expect(attempt.outcome == .granted)
        #expect(attempt.user == "tuser")
        #expect(attempt.matchedRuleID == "datetime_allow")
        #expect(attempt.teamID == "ABCDE12345")
        #expect(attempt.rawLines.count == 2)
        #expect(attempt.target == "system.preferences.datetime")
        #expect(attempt.binaryPath == client)
    }

    @Test("an unclassifiable sudo status is settled by the daemon's verdict when one matched")
    func unknownStatusSettledByDecision() throws {
        // A custom deny message no phrase-list knows, plus a matching deny decision.
        let line = sudo("tuser : Nope, talk to IT ; TTY=ttys002 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf checkJSSConnection", at: 10)
        let withDecision = builder.build(
            authorizationEntries: [], sudoEntries: [line], decisions: [decision(at: 9.8, outcome: .denied, ruleID: nil, profileKey: nil)],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(withDecision.attempts.first?.outcome == .denied)
        #expect(withDecision.attempts.first?.serberusOutcome == "denied")
        #expect(withDecision.attempts.first?.matchedRuleID == nil)
        let without = builder.build(
            authorizationEntries: [], sudoEntries: [line], decisions: [],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(without.attempts.first?.outcome == .unknown)
        // A monitor-mode "would-deny" says nothing about what sudo did.
        let monitor = builder.build(
            authorizationEntries: [], sudoEntries: [line], decisions: [decision(at: 9.8, outcome: .wouldDeny)],
            host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(monitor.attempts.first?.outcome == .unknown)
    }

    @Test("an authuri attempt carries the CLIENT's pid from 'by client … [pid]', never authd's own")
    func authuriClientPID() throws {
        let client = Self.systemSettings
        let named = builder.build(
            authorizationEntries: [
                authd("Succeeded authorizing right 'system.print.admin' by client '\(client)' [4242] for authorization created by '\(client)' [4242] (2,0) (engine 9)", at: 5),
            ],
            sudoEntries: [], decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(named.attempts.first?.pid == 4242)
        // The live capture shape: credential-validation lines only, no client — no pid.
        let unnamed = builder.build(
            authorizationEntries: [
                authd("Validating shared credential testuser (504) for system.preferences.accounts (engine 7226)", at: 6),
                authd("UID 504 authenticated as user testuser (UID 504) for right 'system.preferences.accounts'", at: 7),
            ],
            sudoEntries: [], decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended)
        #expect(unnamed.attempts.first?.pid == nil)
        #expect(unnamed.attempts.first?.authURI == "system.preferences.accounts")
    }

    @Test("entries outside the session window, activity noise, and duplicate sudo lines are dropped; output is time-ordered")
    func windowNoiseDedupOrder() {
        let inside = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", at: 30)
        let duplicate = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", at: 30)
        let before = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", at: -10)
        let after = sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", at: 70)
        let noise = sudo("Retrieve Group by ID", at: 31)
        let right = authd("Succeeded authorizing right 'system.print.admin' by client '/usr/bin/x' [1] (engine 7)", at: 5)
        let capture = builder.build(
            authorizationEntries: [right, authd("Succeeded authorizing right 'system.preferences' by client '/usr/bin/x' [1] (engine 8)", at: -5)],
            sudoEntries: [after, inside, duplicate, before, noise],
            decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended
        )
        #expect(capture.attempts.count == 2)
        #expect(capture.attempts.map(\.kind) == [.authuri, .sudo])
        #expect(capture.attempts.map(\.timestamp) == capture.attempts.map(\.timestamp).sorted())
    }

    @Test("redactingArguments strips argv and sudo raw lines but keeps everything else")
    func redaction() throws {
        let capture = builder.build(
            authorizationEntries: [authd("Succeeded authorizing right 'system.print.admin' by client '/usr/bin/x' [1] (engine 7)", at: 5)],
            sudoEntries: [sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true --token=SECRET", at: 6)],
            decisions: [], host: host, consoleUser: "tuser", startedAt: started, endedAt: ended, notes: "user asked for X"
        )
        let redacted = capture.redactingArguments()
        #expect(redacted.argumentsRedacted)
        #expect(redacted.notes == "user asked for X")
        let sudoAttempt = try #require(redacted.attempts.first { $0.kind == .sudo })
        #expect(sudoAttempt.argv == nil)
        #expect(sudoAttempt.rawLines.isEmpty)
        #expect(sudoAttempt.sudoCommand == "/usr/bin/true")
        let authAttempt = try #require(redacted.attempts.first { $0.kind == .authuri })
        #expect(authAttempt.rawLines.count == 1)
        #expect(!String(decoding: try redacted.encoded(), as: UTF8.self).contains("SECRET"))
    }

    @Test("a capture round-trips through its JSON encoding unchanged")
    func roundTrip() throws {
        let capture = builder.build(
            authorizationEntries: [authd("Succeeded authorizing right 'system.print.admin' by client '/usr/bin/x' [1] (engine 7)", at: 5)],
            sudoEntries: [sudo("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf recon", at: 6)],
            decisions: [decision(at: 5.7, command: "/usr/local/jamf/bin/jamf", outcome: .granted)],
            host: host, componentVersions: ["daemonVersion": "3.8"], consoleUser: "tuser",
            startedAt: started, endedAt: ended, notes: "n"
        )
        let data = try capture.encoded()
        let decoded = try RuleCapture.decode(from: data)
        #expect(decoded == capture)
        #expect(decoded.schemaVersion == RuleCapture.currentSchemaVersion)
        #expect(decoded.suggestedFileName.hasPrefix("Serberus-Capture-SER1-"))
        #expect(decoded.suggestedFileName.hasSuffix(".serberuscapture"))
    }
}

@Suite("PolledLogTailer dedup")
struct PolledLogTailerTests {
    private func line(_ message: String, at timestamp: String, pid: Int = 6730) -> String {
        let fields = [
            "\"eventType\":\"logEvent\"", "\"messageType\":\"Default\"", "\"subsystem\":\"\"", "\"category\":\"\"",
            "\"eventMessage\":\"\(message)\"", "\"timestamp\":\"\(timestamp)\"",
            "\"processImagePath\":\"/usr/bin/sudo\"", "\"processID\":\(pid)",
        ]
        return "{" + fields.joined(separator: ",") + "}"
    }

    @Test("overlapping polls don't emit the same entry twice")
    func dedup() {
        let tailer = PolledLogTailer { "" }
        let a = line("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", at: "2026-08-22 10:00:01.000000-0400")
        let b = line("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", at: "2026-08-22 10:00:03.000000-0400")
        #expect(tailer.freshEntries(from: a + "\n" + b).count == 2)
        let c = line("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ls", at: "2026-08-22 10:00:04.000000-0400")
        let second = tailer.freshEntries(from: b + "\n" + c)
        #expect(second.count == 1)
        #expect(second.first?.message.hasSuffix("/usr/bin/ls") == true)
        #expect(tailer.freshEntries(from: "").isEmpty)
        #expect(tailer.freshEntries(from: c).isEmpty)
    }

    @Test("a DISTINCT event that shares the newest timestamp is still emitted once (eventual-consistency gap)")
    func sameTimestampDistinctEvent() {
        let tailer = PolledLogTailer { "" }
        let t = "2026-08-22 10:00:05.000000-0400"
        let a = line("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", at: t, pid: 1)
        #expect(tailer.freshEntries(from: a).count == 1)
        // Next poll: the same a (dup) plus a new line b stamped the same instant.
        let b = line("tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", at: t, pid: 2)
        let fresh = tailer.freshEntries(from: a + "\n" + b)
        #expect(fresh.count == 1)
        #expect(fresh.first?.processID == 2)
        // And b is a duplicate from now on.
        #expect(tailer.freshEntries(from: a + "\n" + b).isEmpty)
    }
}
