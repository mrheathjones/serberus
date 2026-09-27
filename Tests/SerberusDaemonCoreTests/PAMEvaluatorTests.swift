import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("PAMEvaluator — daemon-side rule evaluation")
struct PAMEvaluatorTests {
    private let brewHash = "aa" + String(repeating: "0", count: 62)

    private func inspector(teamID: String? = nil, status: SigningStatus = .unsigned) -> StaticBinaryIdentityInspector {
        StaticBinaryIdentityInspector(identity: BinaryIdentity(
            canonicalPath: "", teamID: teamID, sha256: brewHash, signingStatus: status
        ))
    }

    private func env(
        profiles: [RuleProfile],
        mode: EnforcementMode = .enforce,
        grants: [Grant] = [],
        sudoCache: Int = 0,
        timeBound: Bool = true
    ) -> PAMEvaluator.Environment {
        PAMEvaluator.Environment(
            profiles: profiles,
            config: SerberusConfig(
                jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
                daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: sudoCache,
                promptTimeoutSeconds: 60, pamBypass: PAMBypass(),
                timeBoundGrantsEnabled: timeBound
            ),
            activeGrants: grants,
            deviceSerial: "TESTSERIAL",
            version: .current,
            policyVersion: "1.0.0",
            now: CoordinatorFixtures.now
        )
    }

    /// Use a real existing binary so canonicalization (requireExists) passes.
    private func sudoRequest(command: String = "/bin/echo", argv: [String] = ["hello"]) -> PAMRequest {
        PAMRequest(user: "root", kind: .sudo(command: command, argv: argv, tty: "ttys000"))
    }

    private func allowEchoProfile(argPattern: String? = nil) -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "allow-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", argPattern: argPattern,
                                     matchType: argPattern == nil ? .exact : .prefixRegex),
                elevation: ElevationBehavior(type: .silent, logArguments: true)
            )]
        )
    }

    @Test("an allow rule returns allow and logs granted")
    func allow() {
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [allowEchoProfile()]))
        #expect(outcome.response.decision == .allow)
        #expect(outcome.response.isAllow)
        #expect(outcome.event.outcome == .granted)
        #expect(outcome.event.ruleID == "allow-echo")
        #expect(outcome.issuedGrant == nil)
    }

    @Test("no matching rule fails closed to deny")
    func noMatch() {
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: "/bin/echo", argv: []), environment: env(profiles: []))
        #expect(outcome.response.decision == .deny)
        #expect(outcome.event.outcome == .denied)
    }

    @Test("a non-existent command fails closed")
    func missingCommand() {
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: "/nonexistent/binary"), environment: env(profiles: [allowEchoProfile()]))
        #expect(outcome.response.decision == .deny)
    }

    @Test("argv is passed through — arg-pattern rules match via PAM")
    func argvMatching() {
        let profile = allowEchoProfile(argPattern: "hello|world")
        let allow = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(argv: ["hello"]), environment: env(profiles: [profile]))
        #expect(allow.response.decision == .allow)

        let deny = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(argv: ["goodbye"]), environment: env(profiles: [profile]))
        #expect(deny.response.decision == .deny)
    }

    @Test("a timed-grant rule issues a persisted grant pinned to the binary")
    func timedGrant() throws {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "grant-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                cacheSeconds: nil,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(maxGrantDurationSeconds: 900)
            )]
        )
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [profile]))
        #expect(outcome.response.decision == .allow)
        let grant = try #require(outcome.issuedGrant)
        #expect(grant.binaryHash == brewHash)
        #expect(grant.ruleID == "grant-echo")
        #expect(grant.expiresAt == CoordinatorFixtures.now.addingTimeInterval(900))
        #expect(outcome.response.grantID == grant.grantID)
    }

    @Test("a prompt rule surfaces a prompt directive for the Sentinel round-trip")
    func promptSurfacesDirective() throws {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "prompt-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                elevation: ElevationBehavior(type: .prompt)
            )]
        )
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [profile]))

        #expect(outcome.response.decision == .prompt)
        let directive = try #require(outcome.promptDirective)
        // PAM polls with this ticket; it must match the context shown to the user.
        #expect(outcome.response.promptRequestID == directive.context.requestID)
        #expect(directive.context.user == "root")
        #expect(directive.context.timeoutSeconds == 60)
        #expect(directive.context.requireJustification == false)
        #expect(directive.context.humanReadableRequest == "sudo /bin/echo hello")
        // No grant duration on this rule → nothing is persisted on approval, and
        // nothing is issued up front (the grant is conditional on the verdict).
        #expect(directive.grantOnApproval == nil)
        #expect(outcome.issuedGrant == nil)
    }

    @Test("the prompt shows hidden characters in argv as escapes; the decision log keeps the real argv")
    func promptEscapesHiddenCharacters() throws {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "prompt-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                elevation: ElevationBehavior(type: .prompt, logArguments: true)
            )]
        )
        let argv = ["IT-approved-\u{202E}gkp.live\u{202C}", "a\nb"]
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(argv: argv), environment: env(profiles: [profile]))

        #expect(outcome.response.decision == .prompt)
        let directive = try #require(outcome.promptDirective)
        #expect(directive.context.humanReadableRequest == #"sudo /bin/echo IT-approved-\u{202E}gkp.live\u{202C} a\nb"#)
        #expect(outcome.event.arguments == argv)
    }

    @Test("a prompt rule with a grant duration carries the timed grant to persist on approval")
    func promptCarriesConditionalGrant() throws {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "prompt-grant-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(requireJustification: true, maxGrantDurationSeconds: 900),
                elevation: ElevationBehavior(type: .prompt)
            )]
        )
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [profile]))

        #expect(outcome.response.decision == .prompt)
        let directive = try #require(outcome.promptDirective)
        #expect(directive.context.requireJustification == true)
        let grant = try #require(directive.grantOnApproval)
        #expect(grant.ruleID == "prompt-grant-echo")
        #expect(grant.binaryHash == brewHash)
        #expect(grant.expiresAt == CoordinatorFixtures.now.addingTimeInterval(900))
        // The prompt shown to the user carries the time-bound window so they see
        // how long access will last before approving.
        #expect(directive.context.grantDurationSeconds == 900)
        // Still conditional: the daemon only persists it once the user approves.
        #expect(outcome.issuedGrant == nil)
    }

    @Test("a prompt with no time-bound grant shows no duration on the prompt")
    func promptWithoutGrantShowsNoDuration() throws {
        // No per-rule duration and time-bound off ⇒ no bounded window to show.
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "prompt-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                elevation: ElevationBehavior(type: .prompt)
            )]
        )
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [profile]))
        let directive = try #require(outcome.promptDirective)
        #expect(directive.context.grantDurationSeconds == nil)
    }

    @Test("time-bound disabled: a silent grant rule becomes a plain allow, no grant persisted")
    func timeBoundDisabledSilentIssuesNoGrant() {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "grant-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(maxGrantDurationSeconds: 900)
            )]
        )
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [profile], timeBound: false))
        #expect(outcome.response.decision == .allow)
        // No timed-grant row: the silent rule already allows for as long as it
        // is installed, so nothing needs persisting.
        #expect(outcome.issuedGrant == nil)
    }

    @Test("time-bound disabled: a prompt rule persists NO grant on approval, so it prompts every time")
    func timeBoundDisabledPromptKeepsNoGrant() throws {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "prompt-grant-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(maxGrantDurationSeconds: 900),
                elevation: ElevationBehavior(type: .prompt)
            )]
        )
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [profile], timeBound: false))
        #expect(outcome.response.decision == .prompt)
        let directive = try #require(outcome.promptDirective)
        #expect(directive.grantOnApproval == nil)
        #expect(directive.context.grantDurationSeconds == nil)
    }

    @Test("audit mode logs would-grant but the response is informational")
    func auditMode() {
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [allowEchoProfile()], mode: .audit))
        #expect(outcome.event.outcome == .wouldGrant)
        #expect(outcome.event.enforcementMode == .audit)
    }

    @Test("monitor mode performs no evaluation (defensive deny)")
    func monitorMode() {
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(), environment: env(profiles: [allowEchoProfile()], mode: .monitor))
        #expect(outcome.response.decision == .deny)
    }

    @Test("a team-pinned rule matches only the right team")
    func teamPin() {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "team-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact, requiredTeamID: "ABCDE12345")
            )]
        )
        let wrong = PAMEvaluator(inspector: inspector(teamID: "EVIL999999", status: .valid))
            .evaluate(sudoRequest(), environment: env(profiles: [profile]))
        #expect(wrong.response.decision == .deny)

        let right = PAMEvaluator(inspector: inspector(teamID: "ABCDE12345", status: .valid))
            .evaluate(sudoRequest(), environment: env(profiles: [profile]))
        #expect(right.response.decision == .allow)
    }

    @Test("arguments are logged only when the matched rule opts in")
    func argRedactionGate() {
        // logArguments true (default in allowEchoProfile)
        let logged = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(argv: ["hello"]), environment: env(profiles: [allowEchoProfile()]))
        #expect(logged.event.arguments == ["hello"])
    }
}

@Suite("PAMEvaluator — prompt request line")
struct PAMEvaluatorPromptLineTests {
    @Test("the request line sent to the Sentinel is redacted like the decision log")
    func requestLineIsRedacted() {
        let unlock = PAMRequest(user: "alice", kind: .sudo(
            command: "/usr/bin/security", argv: ["unlock-keychain", "-p", "hunter2", "login.keychain"], tty: nil
        ))
        #expect(PAMEvaluator.humanReadableRequest(unlock)
                == "sudo /usr/bin/security unlock-keychain -p \(ArgumentRedactor.placeholder) login.keychain")

        let clone = PAMRequest(user: "alice", kind: .sudo(
            command: "/usr/bin/git", argv: ["clone", "https://TOKEN@github.com/x.git"], tty: nil
        ))
        #expect(!PAMEvaluator.humanReadableRequest(clone).contains("TOKEN"))

        let plain = PAMRequest(user: "alice", kind: .sudo(command: "/bin/ls", argv: ["-la", "/var"], tty: nil))
        #expect(PAMEvaluator.humanReadableRequest(plain) == "sudo /bin/ls -la /var")
    }

    @Test("hidden characters in argv show as escapes on the request line")
    func requestLineEscapesHiddenCharacters() {
        // Rendered raw, this reads "…/Users/Shared/IT-approved-evil.pkg -target /".
        let spoof = PAMRequest(user: "alice", kind: .sudo(
            command: "/usr/sbin/installer",
            argv: ["-pkg", "/Users/Shared/IT-approved-\u{202E}gkp.live\u{202C}", "-target", "/"], tty: nil
        ))
        #expect(PAMEvaluator.humanReadableRequest(spoof)
                == #"sudo /usr/sbin/installer -pkg /Users/Shared/IT-approved-\u{202E}gkp.live\u{202C} -target /"#)

        let hidden = PAMRequest(user: "alice", kind: .sudo(
            command: "/bin/cat",
            argv: ["/etc/pass\u{200B}wd", "a\u{2066}b\u{2069}\u{200E}", "x\ny\r\tz", "\u{0000}\u{007F}\u{0085}\u{009B}",
                   "n\u{00A0}b\u{3000}", "\u{00AD}\u{3164}\u{E0041}", "日本 🍺"],
            tty: nil
        ))
        #expect(PAMEvaluator.humanReadableRequest(hidden)
                == #"sudo /bin/cat /etc/pass\u{200B}wd a\u{2066}b\u{2069}\u{200E} x\ny\r\tz "#
                + #"\u{0000}\u{007F}\u{0085}\u{009B} n\u{00A0}b\u{3000} \u{00AD}\u{3164}\u{E0041} 日本 🍺"#)

        // Shown whole, however long.
        let long = String(repeating: "a", count: 4_000)
        let longRequest = PAMRequest(user: "alice", kind: .sudo(
            command: "/bin/echo", argv: [long, "\u{202E}"], tty: nil
        ))
        #expect(PAMEvaluator.humanReadableRequest(longRequest) == "sudo /bin/echo \(long) " + #"\u{202E}"#)
    }

    @Test("redaction still runs first, and an authorization right is escaped too")
    func requestLineRedactsThenEscapes() {
        let unlock = PAMRequest(user: "alice", kind: .sudo(
            command: "/usr/bin/security",
            argv: ["unlock-keychain", "-p", "hun\u{202E}ter2", "login\u{200B}.keychain"], tty: nil
        ))
        #expect(PAMEvaluator.humanReadableRequest(unlock)
                == "sudo /usr/bin/security unlock-keychain -p \(ArgumentRedactor.placeholder) "
                + #"login\u{200B}.keychain"#)

        let right = PAMRequest(user: "alice", kind: .authURI("system.preferences\u{202E}.network\n"))
        #expect(PAMEvaluator.humanReadableRequest(right)
                == PromptContext.authURIRequestPrefix + #"system.preferences\u{202E}.network\n"#)
    }
}
