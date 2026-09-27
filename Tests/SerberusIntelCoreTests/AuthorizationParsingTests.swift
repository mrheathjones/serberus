import Foundation
import Testing
@testable import SerberusIntelCore

/// Grounded in real authd output captured on TESTMAC02 — every message shape
/// here was observed in a live bundle, not invented.
@Suite("AuthorizationParser")
struct AuthorizationParsingTests {
    @Test("a Succeeded line yields the right and a granted verdict")
    func succeeded() {
        let info = AuthorizationParser.info(
            from: "Succeeded authorizing right 'system.preferences' by client '/x.appex' [8816] for authorization created by '/y' [1] (2,0) (engine 11891)"
        )
        #expect(info.right == "system.preferences")
        #expect(info.outcome == .granted)
        #expect(info.namesRight)
    }

    @Test("Sandbox denied yields the right and a denied verdict")
    func sandboxDenied() {
        let info = AuthorizationParser.info(
            from: "Sandbox denied authorizing right 'system.install.apple-software.standard-user' by client '/Applications/Safari.app' [73534] (engine 8529)"
        )
        #expect(info.right == "system.install.apple-software.standard-user")
        #expect(info.outcome == .denied)
    }

    @Test("the accessory right is recovered from the 'for right' form (the case the user hit)")
    func accessoryRightFromForRight() {
        // "Allow accessories to connect" → system.preferences.security, and
        // because a standard user can't satisfy it, it shows up in this shape
        // rather than a clean Succeeded line. This is exactly the line that was
        // buried in the raw stream.
        let info = AuthorizationParser.info(
            from: "UID 502 authenticated as user testuser (UID 502) for right 'system.preferences.security'"
        )
        #expect(info.right == "system.preferences.security")
        // No verdict verb on this line — the outcome is on a neighbouring
        // line, so it is reported neutrally rather than guessed as success.
        #expect(info.outcome == .requested)
    }

    @Test("credential/mechanism/sheet noise names no right")
    func noiseNamesNoRight() {
        let noise = [
            // Undotted tokens after "for" are authd RULE names, never rights.
            "Validating credential testuser (502) for authenticate-session-owner-or-admin (engine 11891)",
            "Validating session owner tuser (501) for is-admin (engine 100)",
            "Validating shared credential tuser (501) for is-root (engine 100)",
            "Validating session owner tuser (501) for use-login-window-ui (engine 100)",
            "credential 502 (does NOT satisfy rule), reason -1 (engine 11891)",
            "engine 11891: running mechanism builtin:authenticate,privileged (3 of 3)",
            "Displaying sheet",
            "FVUnlock result: 0",
            "copy_rights: authorization failed",
            "Fatal: interaction not allowed (kAuthorizationFlagInteractionAllowed not set) (engine 11886)",
            "Sheet ended with success (method 1, sheet result 0)",
        ]
        for line in noise {
            #expect(!AuthorizationParser.info(from: line).namesRight, "should not name a right: \(line)")
        }
    }

    @Test("a right that ONLY ever appears unquoted is still surfaced")
    func unquotedOnlyRightIsFound() {
        // Measured over 24h of live authd, FOUR rights appeared only in this
        // shape — including system.preferences.datetime, which Serberus ships
        // rules for. Parsing quoted forms alone silently hid them.
        let cases = [
            ("Validating session owner tuser (501) for system.install.software (engine 100)", "system.install.software"),
            ("Validating shared credential tuser (501) for system.install.software.iap (engine 100)", "system.install.software.iap"),
            ("Validating credential tuser (501) for system.preferences.datetime (engine 100)", "system.preferences.datetime"),
            ("Validating session owner tuser (501) for system.install.app-store-software.standard-user (engine 100)",
             "system.install.app-store-software.standard-user"),
        ]
        for (line, expected) in cases {
            let info = AuthorizationParser.info(from: line)
            #expect(info.right == expected, "failed on: \(line)")
            // These lines carry no verdict — neutral, never guessed.
            #expect(info.outcome == .requested)
        }
    }

    @Test("a quoted right wins over the trailing 'for authorization created by' clause")
    func quotedFormTakesPrecedence() {
        // The clean line ends with "for authorization created by '/path'" — the
        // unquoted fallback must not fire and misread anything there.
        let info = AuthorizationParser.info(
            from: "Succeeded authorizing right 'system.preferences' by client '/a.appex' [1] for authorization created by '/b.appex' [2] (42,0) (engine 11978)"
        )
        #expect(info.right == "system.preferences")
        #expect(info.outcome == .granted)
    }

    @Test("paths and versions after 'for' are not mistaken for rights")
    func noFalsePositives() {
        #expect(!AuthorizationParser.info(from: "waiting for /System/Library/Foo.appex to respond").namesRight)
        #expect(!AuthorizationParser.info(from: "retrying for 1.2.3 seconds").namesRight)
        #expect(!AuthorizationParser.info(from: "for authorization created by client").namesRight)
    }

    @Test("the first quoted right wins when a line quotes two")
    func firstRightWins() {
        // The clean form quotes the right first, then the client path; the
        // client is not a right.
        let info = AuthorizationParser.info(
            from: "Succeeded authorizing right 'system.print.admin' by client '/usr/bin/security' [20545] for authorization created by '/usr/bin/security' [20545]"
        )
        #expect(info.right == "system.print.admin")
    }

    @Test("Failed authorizing right yields a failed verdict")
    func failedVerdict() {
        let info = AuthorizationParser.info(from: "Failed authorizing right 'system.foo' by client '/x' [1]")
        #expect(info.outcome == .failed)
    }
}
