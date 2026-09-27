import Foundation
import Testing
@testable import SerberusIntelCore

/// Grounded in the real authd flow captured on TESTMAC02 — engine 12009, where
/// one "Allow accessories to connect" click produced five near-identical rows.
@Suite("AuthorizationGrouper")
struct AuthorizationGroupingTests {
    private func entry(_ message: String, at offset: TimeInterval) -> LogEntry {
        LogEntry(
            timestamp: "t+\(offset)",
            date: Date(timeIntervalSince1970: 1_784_000_000 + offset),
            level: .default,
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: message,
            processImagePath: "/usr/libexec/authd",
            processID: 253
        )
    }

    @Test("the five lines of one attempt collapse to a single row")
    func collapsesOneAttempt() {
        // Verbatim shapes from the screenshot, engine 12009.
        let entries = [
            entry("Validating credential testuser (502) for system.preferences.security (engine 12009)", at: 0),
            entry("Validating shared credential testuser (502) for system.preferences.security (engine 12009)", at: 1),
            entry("Validating session owner testuser (502) for system.preferences.security (engine 12009)", at: 2),
            entry("UID 502 authenticated as user testuser (UID 502) for right 'system.preferences.security'", at: 3),
            entry("Validating credential testuser (502) for system.preferences.security (engine 12009)", at: 4),
        ]
        let attempts = AuthorizationGrouper.group(entries)
        #expect(attempts.count == 1)
        #expect(attempts.first?.right == "system.preferences.security")
        // Including the engine-less "UID … authenticated" line, folded in.
        #expect(attempts.first?.lines.count == 5)
    }

    @Test("one engine touching two rights yields two rows, not one")
    func twoRightsOneEngineStaySeparate() {
        // 9 of 35 engines did this in real data — merging them would report one
        // decision for two different rights.
        let entries = [
            entry("Succeeded authorizing right 'system.preferences' by client '/x.appex' [1] (engine 11891)", at: 0),
            entry("Validating credential testuser (502) for system.preferences.security (engine 11891)", at: 1),
        ]
        let attempts = AuthorizationGrouper.group(entries)
        #expect(attempts.count == 2)
        #expect(Set(attempts.map(\.right)) == ["system.preferences", "system.preferences.security"])
    }

    @Test("a right with no verdict inherits the engine's failure — the accessory case")
    func inheritsEngineFailure() throws {
        // This is what makes the failed accessory authorization read DENIED
        // instead of a neutral REQUESTED.
        let entries = [
            entry("Succeeded authorizing right 'system.preferences' by client '/x.appex' [1] (engine 11891)", at: 0),
            entry("Validating credential testuser (502) for system.preferences.security (engine 11891)", at: 1),
            entry("User credential for rule failed (-60005) (engine 11891)", at: 2),
            entry("copy_rights: authorization failed", at: 3),
        ]
        let attempts = AuthorizationGrouper.group(entries)
        let security = try #require(attempts.first { $0.right == "system.preferences.security" })
        #expect(security.outcome == .denied)
        #expect(security.verdictInherited)

        // The right that DID succeed keeps its own verdict — the engine failure
        // must not overwrite an explicit success.
        let prefs = try #require(attempts.first { $0.right == "system.preferences" })
        #expect(prefs.outcome == .granted)
        #expect(!prefs.verdictInherited)
    }

    @Test("engine success is never inferred onto a right that lacks its own success line")
    func doesNotInferSuccess() throws {
        // Inferring success would manufacture an approval that never happened.
        let entries = [
            entry("Validating credential testuser (502) for system.preferences.security (engine 12010)", at: 0),
            entry("Authorization result :0", at: 1),
        ]
        let attempt = try #require(AuthorizationGrouper.group(entries).first)
        #expect(attempt.outcome == .requested)
        #expect(!attempt.verdictInherited)
    }

    @Test("an orphan line does NOT fold into a different right that shares its prefix")
    func noPrefixCollision() {
        // Key "12009|system.preferences.security" CONTAINS "|system.preferences",
        // so a substring match would wrongly merge these two rights.
        let entries = [
            entry("Validating credential testuser (502) for system.preferences.security (engine 12009)", at: 0),
            entry("UID 502 authenticated as user testuser (UID 502) for right 'system.preferences'", at: 1),
        ]
        let attempts = AuthorizationGrouper.group(entries)
        #expect(attempts.count == 2)
        #expect(Set(attempts.map(\.right)) == ["system.preferences", "system.preferences.security"])
    }

    @Test("an orphan line outside the attach window starts its own attempt")
    func orphanOutsideWindow() {
        let entries = [
            entry("Validating credential testuser (502) for system.preferences.security (engine 12009)", at: 0),
            entry("UID 502 authenticated as user testuser (UID 502) for right 'system.preferences.security'", at: 600),
        ]
        // 10 minutes later is a different authorization, not the same one.
        #expect(AuthorizationGrouper.group(entries).count == 2)
    }

    @Test("the client is carried onto the attempt")
    func capturesClient() throws {
        let attempt = try #require(AuthorizationGrouper.group([
            entry("Succeeded authorizing right 'system.print.admin' by client '/usr/bin/security' [20545] (engine 5)", at: 0),
        ]).first)
        #expect(attempt.client == "/usr/bin/security")
        #expect(attempt.outcome == .granted)
    }

    @Test("noise lines that name no right create no attempts")
    func noiseCreatesNothing() {
        let entries = [
            entry("Displaying sheet", at: 0),
            entry("engine 12009: running mechanism builtin:authenticate,privileged (3 of 3)", at: 1),
            entry("FVUnlock result: 0", at: 2),
        ]
        #expect(AuthorizationGrouper.group(entries).isEmpty)
    }

    @Test("attempts come back in first-seen order")
    func stableOrder() {
        let entries = [
            entry("Succeeded authorizing right 'a.b' by client '/x' [1] (engine 1)", at: 0),
            entry("Succeeded authorizing right 'c.d' by client '/x' [1] (engine 2)", at: 1),
        ]
        #expect(AuthorizationGrouper.group(entries).map(\.right) == ["a.b", "c.d"])
    }
}
