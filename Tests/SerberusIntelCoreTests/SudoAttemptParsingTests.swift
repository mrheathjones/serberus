import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

/// Grounded in real `sudo(8)` unified-log lines (captured live on the dev Mac
/// 2026-08-22 plus sudo's documented failure phrasings).
@Suite("SudoAttemptParser")
struct SudoAttemptParsingTests {
    @Test("a success line: user, tty, pwd, run-as, command, no status → granted")
    func successLine() throws {
        let info = try #require(SudoAttemptParser.info(
            from: "tuser : TTY=ttys001 ; PWD=/Users/tuser ; USER=root ; COMMAND=/usr/bin/true"
        ))
        #expect(info.user == "tuser")
        #expect(info.status == nil)
        #expect(info.tty == "ttys001")
        #expect(info.pwd == "/Users/tuser")
        #expect(info.runAsUser == "root")
        #expect(info.command == "/usr/bin/true")
        #expect(info.arguments.isEmpty)
        #expect(info.outcome == .granted)
    }

    @Test("the live-captured non-interactive failure (leading spaces, no TTY) → failed")
    func passwordRequired() throws {
        // Verbatim from `log show --predicate 'process == "sudo"'` on 2026-08-22,
        // including the three leading spaces sudo emits.
        let info = try #require(SudoAttemptParser.info(
            from: "   tuser : a password is required ; PWD=/Users/tuser/Library/Mobile Documents/x ; USER=root ; COMMAND=/usr/bin/true"
        ))
        #expect(info.user == "tuser")
        #expect(info.status == "a password is required")
        #expect(info.tty == nil)
        #expect(info.pwd == "/Users/tuser/Library/Mobile Documents/x")
        #expect(info.command == "/usr/bin/true")
        #expect(info.outcome == .failed)
    }

    @Test("arguments after the command are split on spaces, in order")
    func arguments() throws {
        let info = try #require(SudoAttemptParser.info(
            from: "testuser : TTY=ttys000 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf policy -event serberus-posture"
        ))
        #expect(info.command == "/usr/local/bin/jamf")
        #expect(info.arguments == ["policy", "-event", "serberus-posture"])
        #expect(info.outcome == .granted)
    }

    @Test("sudoers denial → denied; PAM/password failures → failed; unknown prose → unknown")
    func statusMapping() throws {
        func outcome(_ status: String) throws -> CapturedOutcome {
            try #require(SudoAttemptParser.info(
                from: "u : \(status) ; TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
            )).outcome
        }
        #expect(try outcome("command not allowed") == .denied)
        #expect(try outcome("user NOT in sudoers") == .denied)
        // Serberus's own deny text, verbatim from the first live capture
        // (test Mac TESTMAC01, 2026-08-22).
        #expect(try outcome("denied by Serberus - see the message above") == .denied)
        #expect(try outcome("3 incorrect password attempts") == .failed)
        #expect(try outcome("1 incorrect password attempt") == .failed)
        #expect(try outcome("a password is required") == .failed)
        #expect(try outcome("some future phrasing") == .unknown)
        // The prose is kept either way so the admin can read it.
        #expect(try #require(SudoAttemptParser.info(
            from: "u : some future phrasing ; TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        )).status == "some future phrasing")
    }

    @Test("a GROUP= segment is skipped, not mistaken for a status")
    func groupSegment() throws {
        let info = try #require(SudoAttemptParser.info(
            from: "tuser : TTY=ttys001 ; PWD=/ ; USER=root ; GROUP=wheel ; COMMAND=/usr/bin/id"
        ))
        #expect(info.status == nil)
        #expect(info.outcome == .granted)
        #expect(info.command == "/usr/bin/id")
    }

    @Test("COMMAND= is the last segment and is never split on ' ; ' itself")
    func commandWithSeparatorInside() throws {
        let info = try #require(SudoAttemptParser.info(
            from: "tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c echo a ; echo b"
        ))
        #expect(info.command == "/bin/sh")
        #expect(info.arguments == ["-c", "echo", "a", ";", "echo", "b"])
    }

    @Test("a space in the command path arrives as #040 and is decoded; a literal # survives")
    func octalEscapesInCommand() throws {
        let info = try #require(SudoAttemptParser.info(
            from: "tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/Library/Application#040Support/Vendor/tool --flag"
        ))
        #expect(info.command == "/Library/Application Support/Vendor/tool")
        #expect(info.arguments == ["--flag"])
        let hash = try #require(SudoAttemptParser.info(
            from: "tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/opt/c#1/bin/x#9z run"
        ))
        #expect(hash.command == "/opt/c#1/bin/x#9z")
        #expect(SudoAttemptParser.decodeOctalEscapes("a#011b") == "a\tb")
        #expect(SudoAttemptParser.decodeOctalEscapes("no-escapes") == "no-escapes")
    }

    @Test("single-quoted arguments with spaces and escaped quotes are one argv element each")
    func quotedArguments() throws {
        let info = try #require(SudoAttemptParser.info(
            from: #"tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/bin/echo 'hello world' plain 'it\'s' 'back\\slash' ''"#
        ))
        #expect(info.command == "/bin/echo")
        #expect(info.arguments == ["hello world", "plain", "it's", "back\\slash", ""])
    }

    @Test("lines that are not attempts are rejected — the libsystem_info activity noise")
    func nonAttemptLines() {
        #expect(SudoAttemptParser.info(from: "Retrieve Group by ID") == nil)
        #expect(SudoAttemptParser.info(from: "") == nil)
        #expect(SudoAttemptParser.info(from: "tuser : TTY=ttys001 ; PWD=/ ; USER=root") == nil)
        let noise = LogEntry(timestamp: "t", level: .default, subsystem: "", category: "",
                             message: "Retrieve Group by ID", processImagePath: "/usr/bin/sudo", processID: 1)
        #expect(!SudoAttemptParser.isAttemptLine(noise))
        let attempt = LogEntry(timestamp: "t", level: .default, subsystem: "", category: "",
                               message: "tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
                               processImagePath: "/usr/bin/sudo", processID: 1)
        #expect(SudoAttemptParser.isAttemptLine(attempt))
    }
}
