import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// Branch coverage for ``PAMEvaluator``:
/// match-type variants driven through `evaluate()` (not the engine directly),
/// the `requiredBinaryHash` identity pin, the authURI identity-unknown path,
/// invalid-regex fail-closed skips, and argv redaction.
///
/// Deliberately does NOT cover audit-mode prompt behavior, cacheSeconds
/// propagation, or justification logging — those are owned (and changed) by
/// the daemon-sudo-gaps package.
@Suite("PAMEvaluator — match-type, identity-pin, and fail-closed branch coverage")
struct PAMEvaluatorCoverageTests {
    private let pinnedHash = "aa" + String(repeating: "0", count: 62)

    private func inspector(teamID: String? = nil, status: SigningStatus = .unsigned) -> StaticBinaryIdentityInspector {
        StaticBinaryIdentityInspector(identity: BinaryIdentity(
            canonicalPath: "", teamID: teamID, sha256: pinnedHash, signingStatus: status
        ))
    }

    private func env(profiles: [RuleProfile], mode: EnforcementMode = .enforce) -> PAMEvaluator.Environment {
        PAMEvaluator.Environment(
            profiles: profiles,
            config: SerberusConfig(
                jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
                daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: 0,
                promptTimeoutSeconds: 60, pamBypass: PAMBypass()
            ),
            activeGrants: [],
            deviceSerial: "TESTSERIAL",
            version: .current,
            policyVersion: "1.0.0",
            now: CoordinatorFixtures.now
        )
    }

    /// A real existing binary so canonicalization (requireExists) passes.
    private func sudoRequest(command: String = "/bin/echo", argv: [String] = ["hello"]) -> PAMRequest {
        PAMRequest(user: "root", kind: .sudo(command: command, argv: argv, tty: "ttys000"))
    }

    private func sudoProfile(_ rules: [Rule]) -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: "rules_sudo_coverage", profilePriority: 50, rules: rules)
    }

    private func allowRule(
        id: String,
        commandPattern: String?,
        matchType: MatchType,
        argPattern: String? = nil,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil,
        priority: Int = 10,
        logArguments: Bool = true
    ) -> Rule {
        Rule(
            id: id, type: .sudo, action: .allow, description: "d", priority: priority,
            match: MatchCriteria(
                commandPattern: commandPattern, argPattern: argPattern, matchType: matchType,
                requiredTeamID: requiredTeamID, requiredBinaryHash: requiredBinaryHash
            ),
            elevation: ElevationBehavior(type: .silent, logArguments: logArguments)
        )
    }

    private func evaluate(_ request: PAMRequest, rules: [Rule], teamID: String? = nil) -> PAMEvaluator.Outcome {
        PAMEvaluator(inspector: inspector(teamID: teamID))
            .evaluate(request, environment: env(profiles: [sudoProfile(rules)]))
    }

    // MARK: Match types through evaluate()

    @Test("glob matchType matches fnmatch-style patterns through the evaluator")
    func globMatch() {
        let rule = allowRule(id: "glob-echo", commandPattern: "/bin/ec*", matchType: .glob)
        #expect(evaluate(sudoRequest(), rules: [rule]).response.decision == .allow)

        let miss = allowRule(id: "glob-usr", commandPattern: "/usr/bin/*", matchType: .glob)
        #expect(evaluate(sudoRequest(), rules: [miss]).response.decision == .deny)
    }

    @Test("regex matchType requires a full-path match through the evaluator")
    func regexMatch() {
        let rule = allowRule(id: "re-echo", commandPattern: "/bin/(echo|ls)", matchType: .regex)
        #expect(evaluate(sudoRequest(), rules: [rule]).response.decision == .allow)

        // A partial match (prefix only) is not a match: regex must cover the
        // whole canonical path.
        let partial = allowRule(id: "re-partial", commandPattern: "/bin/e", matchType: .regex)
        #expect(evaluate(sudoRequest(), rules: [partial]).response.decision == .deny)
    }

    @Test("any matchType matches every command, even with no commandPattern")
    func anyMatch() {
        let rule = allowRule(id: "any-cmd", commandPattern: nil, matchType: .any)
        let outcome = evaluate(sudoRequest(), rules: [rule])
        #expect(outcome.response.decision == .allow)
        #expect(outcome.event.ruleID == "any-cmd")
    }

    @Test("prefix-regex matchType is a literal prefix at a path-component boundary")
    func prefixRegexMatch() {
        let rule = allowRule(id: "prefix-bin", commandPattern: "/bin", matchType: .prefixRegex)
        #expect(evaluate(sudoRequest(), rules: [rule]).response.decision == .allow)

        // "/bin/ec" is a string prefix of "/bin/echo" but not a component
        // boundary — it must not match.
        let partial = allowRule(id: "prefix-partial", commandPattern: "/bin/ec", matchType: .prefixRegex)
        #expect(evaluate(sudoRequest(), rules: [partial]).response.decision == .deny)
    }

    // MARK: requiredBinaryHash identity pin

    @Test("a hash-pinned rule allows only the exact observed binary hash")
    func hashPinMatch() {
        let rule = allowRule(id: "hash-echo", commandPattern: "/bin/echo", matchType: .exact,
                             requiredBinaryHash: pinnedHash)
        #expect(evaluate(sudoRequest(), rules: [rule]).response.decision == .allow)
    }

    @Test("a hash mismatch fails closed even when the path matches")
    func hashPinMismatch() {
        let wrongHash = "bb" + String(repeating: "0", count: 62)
        let rule = allowRule(id: "hash-echo", commandPattern: "/bin/echo", matchType: .exact,
                             requiredBinaryHash: wrongHash)
        let outcome = evaluate(sudoRequest(), rules: [rule])
        #expect(outcome.response.decision == .deny)
        #expect(outcome.event.ruleID == nil)
    }

    @Test("the hash pin comparison is case-insensitive")
    func hashPinCaseInsensitive() {
        let rule = allowRule(id: "hash-echo", commandPattern: "/bin/echo", matchType: .exact,
                             requiredBinaryHash: pinnedHash.uppercased())
        #expect(evaluate(sudoRequest(), rules: [rule]).response.decision == .allow)
    }

    @Test("the hash pin applies to .any-match rules too")
    func hashPinConstrainsAny() {
        let wrongHash = "cc" + String(repeating: "0", count: 62)
        let rule = allowRule(id: "any-pinned", commandPattern: nil, matchType: .any,
                             requiredBinaryHash: wrongHash)
        #expect(evaluate(sudoRequest(), rules: [rule]).response.decision == .deny)
    }

    // MARK: authURI kind — the identity-unknown branch

    private func authURIRule(
        id: String,
        uri: String?,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil
    ) -> Rule {
        Rule(
            id: id, type: .authuri, action: .allow, description: "d", priority: 10,
            match: MatchCriteria(authURI: uri, requiredTeamID: requiredTeamID,
                                 requiredBinaryHash: requiredBinaryHash)
        )
    }

    @Test("an authURI request matches its rule with the identity-unknown placeholder")
    func authURIMatches() {
        let uri = "system.preferences.datetime"
        let request = PAMRequest(user: "root", kind: .authURI(uri))
        let outcome = evaluate(request, rules: [authURIRule(id: "dt", uri: uri)])
        #expect(outcome.response.decision == .allow)
        #expect(outcome.event.ruleID == "dt")
        // authURI via PAM carries no requesting binary: the event reflects the
        // unknown-identity placeholder, and the sudo fields stay empty.
        #expect(outcome.event.authURI == uri)
        #expect(outcome.event.sudoCommand == nil)
        #expect(outcome.event.arguments == nil)
        #expect(outcome.event.processPath == "")
        #expect(outcome.event.processHash == "")
        #expect(outcome.event.processTeamID == "")
    }

    @Test("a team-pinned authURI rule fails closed: PAM-path identity is unknown, the inspector is bypassed")
    func authURITeamPinFailsClosed() {
        let uri = "system.preferences.datetime"
        let request = PAMRequest(user: "root", kind: .authURI(uri))
        // Even with an inspector that WOULD report the pinned team, the
        // empty-canonicalPath branch must use the unknown-identity placeholder
        // — so the pinned rule can never match on the PAM authURI path.
        let outcome = evaluate(request, rules: [authURIRule(id: "dt-pinned", uri: uri, requiredTeamID: "ABCDE12345")],
                               teamID: "ABCDE12345")
        #expect(outcome.response.decision == .deny)
        #expect(outcome.event.ruleID == nil)
    }

    @Test("a hash-pinned authURI rule fails closed on the PAM path")
    func authURIHashPinFailsClosed() {
        let uri = "system.preferences.datetime"
        let request = PAMRequest(user: "root", kind: .authURI(uri))
        let outcome = evaluate(request, rules: [authURIRule(id: "dt-hash", uri: uri, requiredBinaryHash: pinnedHash)])
        #expect(outcome.response.decision == .deny)
    }

    @Test("an authURI request never matches sudo rules (and vice versa)")
    func kindSeparation() {
        let uri = "system.preferences.datetime"
        let sudoRule = allowRule(id: "any-cmd", commandPattern: nil, matchType: .any)
        let outcome = evaluate(PAMRequest(user: "root", kind: .authURI(uri)), rules: [sudoRule])
        #expect(outcome.response.decision == .deny)

        let uriRule = authURIRule(id: "dt", uri: uri)
        #expect(evaluate(sudoRequest(), rules: [uriRule]).response.decision == .deny)
    }

    // MARK: Invalid regex — skip, never match, fail closed

    @Test("an invalid regex commandPattern is skipped and the evaluation fails closed")
    func invalidRegexFailsClosed() {
        let rule = allowRule(id: "bad-re", commandPattern: "(", matchType: .regex)
        let outcome = evaluate(sudoRequest(), rules: [rule])
        #expect(outcome.response.decision == .deny)
        #expect(outcome.event.ruleID == nil)
    }

    @Test("an invalid-regex rule is a skip, not a fatal error: later rules still evaluate")
    func invalidRegexSkipsToNextRule() {
        let broken = allowRule(id: "bad-re", commandPattern: "(", matchType: .regex, priority: 5)
        let valid = allowRule(id: "allow-echo", commandPattern: "/bin/echo", matchType: .exact, priority: 10)
        let outcome = evaluate(sudoRequest(), rules: [broken, valid])
        #expect(outcome.response.decision == .allow)
        #expect(outcome.event.ruleID == "allow-echo")
    }

    @Test("an invalid argPattern regex is skipped and fails closed")
    func invalidArgPatternFailsClosed() {
        let rule = allowRule(id: "bad-arg-re", commandPattern: "/bin/echo", matchType: .exact, argPattern: "(")
        let outcome = evaluate(sudoRequest(), rules: [rule])
        #expect(outcome.response.decision == .deny)
    }

    // MARK: argv redaction

    @Test("logArguments=false redacts argv from the decision event on an allow")
    func argvRedactedWhenOptedOut() {
        let rule = allowRule(id: "quiet-echo", commandPattern: "/bin/echo", matchType: .exact,
                             logArguments: false)
        let outcome = evaluate(sudoRequest(argv: ["secret-token"]), rules: [rule])
        #expect(outcome.response.decision == .allow)
        #expect(outcome.event.arguments == nil)
        // The command itself is still logged — only argv is redacted.
        #expect(outcome.event.sudoCommand == "/bin/echo")
    }

    @Test("a no-match deny never logs argv (there is no rule to opt in)")
    func argvRedactedOnNoMatch() {
        let outcome = evaluate(sudoRequest(argv: ["secret-token"]), rules: [])
        #expect(outcome.response.decision == .deny)
        #expect(outcome.event.arguments == nil)
    }
}
