import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// Daemon pattern canonicalization: a sudo rule authored against a symlink
/// path (`/usr/local/bin/jamf`) must match the canonical command the engine
/// evaluates (`/usr/local/jamf/bin/jamf`). ``PAMEvaluator`` resolves the
/// *command* to its canonical form but the shared, filesystem-free
/// ``RuleEngine`` matches the *pattern* verbatim, so the evaluator feeds the
/// engine a canonicalized view of every literal-path (`.exact` / `.prefixRegex`)
/// sudo pattern.
@Suite("PAMEvaluator — sudo pattern canonicalization")
struct PAMEvaluatorCanonicalizationTests {
    private let hash = "aa" + String(repeating: "0", count: 62)

    private func inspector() -> StaticBinaryIdentityInspector {
        StaticBinaryIdentityInspector(identity: BinaryIdentity(
            canonicalPath: "", teamID: nil, sha256: hash, signingStatus: .unsigned
        ))
    }

    private func env(profiles: [RuleProfile]) -> PAMEvaluator.Environment {
        PAMEvaluator.Environment(
            profiles: profiles,
            config: SerberusConfig(
                jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
                daemonEnabled: true, enforcementMode: .enforce, sudoCacheSeconds: 0,
                promptTimeoutSeconds: 60, pamBypass: PAMBypass()
            ),
            activeGrants: [],
            deviceSerial: "TESTSERIAL",
            version: .current,
            policyVersion: "1.0.0",
            now: CoordinatorFixtures.now
        )
    }

    private func sudoRequest(command: String, argv: [String] = []) -> PAMRequest {
        PAMRequest(user: "root", kind: .sudo(command: command, argv: argv, tty: "ttys000"))
    }

    // MARK: - Symlink fixture

    /// A real executable plus a symlink pointing at it, in a private temp tree.
    private struct SymlinkFixture {
        let root: URL
        /// Path the admin would author the rule against (the symlink).
        let symlinkPath: String
        /// Path the command canonicalizes to (the real, symlink-resolved file).
        let canonicalPath: String
    }

    /// Creates `<tmp>/link -> <tmp>/real/tool` and returns both paths. The
    /// caller must `defer` `remove(_:)`. `canonicalPath` is the fully
    /// symlink-resolved real path, so it equals what ``PathCanonicalizer``
    /// produces for either the symlink or the real path.
    private func makeSymlink(realComponents: [String], linkName: String) throws -> SymlinkFixture {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("serberus-canon-\(UUID().uuidString)")
        let realFile = realComponents.reduce(root) { $0.appendingPathComponent($1) }
        try fm.createDirectory(at: realFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        fm.createFile(atPath: realFile.path, contents: Data("#!/bin/sh\n".utf8))
        let link = root.appendingPathComponent(linkName)
        try fm.createSymbolicLink(atPath: link.path, withDestinationPath: realFile.path)
        let canonical = (realFile.path as NSString).resolvingSymlinksInPath
        return SymlinkFixture(root: root, symlinkPath: link.path, canonicalPath: canonical)
    }

    private func remove(_ fixture: SymlinkFixture) {
        try? FileManager.default.removeItem(at: fixture.root)
    }

    private func sudoRule(
        id: String, commandPattern: String, matchType: MatchType, argPattern: String? = nil
    ) -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_test", profilePriority: 50,
            rules: [Rule(
                id: id, type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: commandPattern, argPattern: argPattern, matchType: matchType)
            )]
        )
    }

    // MARK: - End-to-end evaluation

    @Test("a symlink-path exact rule matches when the command is the canonical path")
    func symlinkExactMatchesCanonicalCommand() throws {
        let fx = try makeSymlink(realComponents: ["real", "tool"], linkName: "tool-link")
        defer { remove(fx) }

        // Rule authored against the SYMLINK; command is the CANONICAL real path.
        let profile = sudoRule(id: "allow-tool", commandPattern: fx.symlinkPath, matchType: .exact)
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: fx.canonicalPath), environment: env(profiles: [profile]))

        #expect(outcome.response.decision == .allow)
        #expect(outcome.event.ruleID == "allow-tool")
    }

    @Test("after canonicalization the rule's argPattern is enforced (match → allow, mismatch → deny)")
    func symlinkRuleEnforcesArgPattern() throws {
        let fx = try makeSymlink(realComponents: ["real", "tool"], linkName: "tool-link")
        defer { remove(fx) }

        let profile = sudoRule(
            id: "allow-tool-recon", commandPattern: fx.symlinkPath,
            matchType: .prefixRegex, argPattern: "^recon$"
        )

        let allow = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: fx.canonicalPath, argv: ["recon"]), environment: env(profiles: [profile]))
        #expect(allow.response.decision == .allow)

        // Command still canonicalizes and the pattern still matches, but the arg
        // fails the argPattern → no rule matches → fail closed to deny.
        let deny = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: fx.canonicalPath, argv: ["policy"]), environment: env(profiles: [profile]))
        #expect(deny.response.decision == .deny)
    }

    @Test("jamf scenario: symlink rule /bin/jamf + argPattern ^recon$ enforces recon-only")
    func jamfScenario() throws {
        // The Jamf layout: /usr/local/bin/jamf → /usr/local/jamf/bin/jamf.
        // The link name must not collide with the real tree's top component
        // ("jamf"), which is a directory at the temp root.
        let fx = try makeSymlink(realComponents: ["jamf", "bin", "jamf"], linkName: "jamf-link")
        defer { remove(fx) }

        let profile = sudoRule(
            id: "jamf-recon", commandPattern: fx.symlinkPath,
            matchType: .prefixRegex, argPattern: "^recon$"
        )

        let recon = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: fx.canonicalPath, argv: ["recon"]), environment: env(profiles: [profile]))
        #expect(recon.response.decision == .allow)

        let policy = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: fx.canonicalPath, argv: ["policy"]), environment: env(profiles: [profile]))
        #expect(policy.response.decision == .deny)
    }

    @Test("without the fix the symlink rule would be inert — canonical command still matches now")
    func symlinkRuleIsNotInert() throws {
        // Regression guard: the command the daemon evaluates is the canonical
        // path; a raw symlink-path pattern never equals it. The fix rewrites the
        // pattern so the two agree.
        let fx = try makeSymlink(realComponents: ["real", "tool"], linkName: "tool-link")
        defer { remove(fx) }
        #expect(fx.symlinkPath != fx.canonicalPath) // fixture really is a redirect

        let profile = sudoRule(id: "allow-tool", commandPattern: fx.symlinkPath, matchType: .exact)
        let outcome = PAMEvaluator(inspector: inspector())
            .evaluate(sudoRequest(command: fx.canonicalPath), environment: env(profiles: [profile]))
        #expect(outcome.response.decision == .allow)
    }

    // MARK: - Canonicalization view (direct, pure)

    @Test("only .exact and .prefixRegex patterns are canonicalized; glob/regex/any stay raw")
    func onlyLiteralPathTypesAreCanonicalized() throws {
        let fx = try makeSymlink(realComponents: ["real", "tool"], linkName: "tool-link")
        defer { remove(fx) }

        func rewritten(_ matchType: MatchType) -> String? {
            let profile = sudoRule(id: "r", commandPattern: fx.symlinkPath, matchType: matchType, argPattern: "^x$")
            let view = PAMEvaluator.canonicalizedProfiles([profile], canonicalizer: PathCanonicalizer())
            let rule = view[0].rules[0]
            // argPattern, id, and action must be preserved verbatim.
            #expect(rule.match.argPattern == "^x$")
            #expect(rule.id == "r")
            #expect(rule.action == .allow)
            return rule.match.commandPattern
        }

        #expect(rewritten(.exact) == fx.canonicalPath)
        #expect(rewritten(.prefixRegex) == fx.canonicalPath)
        // Metacharacter-bearing types are left raw (resolution would corrupt them).
        #expect(rewritten(.glob) == fx.symlinkPath)
        #expect(rewritten(.regex) == fx.symlinkPath)
        #expect(rewritten(.any) == fx.symlinkPath)
    }

    @Test("authURI rules are untouched by sudo pattern canonicalization")
    func authURIRulesUntouched() {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_authuri_test", profilePriority: 50,
            rules: [Rule(
                id: "auth-r", type: .authuri, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(authURI: "system.preferences.datetime", commandPattern: "/usr/local/bin/jamf", matchType: .exact)
            )]
        )
        let view = PAMEvaluator.canonicalizedProfiles([profile], canonicalizer: PathCanonicalizer())
        // Not a sudo rule → commandPattern preserved verbatim even though it is a path.
        #expect(view[0].rules[0].match.commandPattern == "/usr/local/bin/jamf")
        #expect(view[0].rules[0].match.authURI == "system.preferences.datetime")
    }

    @Test("a pattern that fails to canonicalize falls back to the raw pattern")
    func canonicalizeThrowFallsBackToRaw() {
        // A relative path throws PathError.relativePath under any existence policy.
        let profile = sudoRule(id: "rel", commandPattern: "usr/local/bin/jamf", matchType: .exact)
        let view = PAMEvaluator.canonicalizedProfiles([profile], canonicalizer: PathCanonicalizer())
        #expect(view[0].rules[0].match.commandPattern == "usr/local/bin/jamf")
    }

    @Test("ordering, priorities, and other rules are preserved through the view")
    func viewPreservesStructure() throws {
        let fx = try makeSymlink(realComponents: ["real", "tool"], linkName: "tool-link")
        defer { remove(fx) }

        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_multi", profilePriority: 7,
            rules: [
                Rule(id: "deny-first", type: .sudo, action: .deny, description: "d", priority: 5,
                     match: MatchCriteria(commandPattern: fx.symlinkPath, matchType: .exact)),
                Rule(id: "glob-rule", type: .sudo, action: .allow, description: "d", priority: 10,
                     match: MatchCriteria(commandPattern: "/opt/*/bin/*", matchType: .glob)),
            ]
        )
        let view = PAMEvaluator.canonicalizedProfiles([profile], canonicalizer: PathCanonicalizer())
        #expect(view.count == 1)
        #expect(view[0].profilePriority == 7)
        #expect(view[0].rules.count == 2)
        // Same order, same ids/actions/priorities.
        #expect(view[0].rules[0].id == "deny-first")
        #expect(view[0].rules[0].action == .deny)
        #expect(view[0].rules[0].priority == 5)
        #expect(view[0].rules[0].match.commandPattern == fx.canonicalPath) // exact → canonicalized
        #expect(view[0].rules[1].id == "glob-rule")
        #expect(view[0].rules[1].match.commandPattern == "/opt/*/bin/*")   // glob → raw
    }
}
