import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// Load-time diagnostic for the *silent inert rule* trap: an `.exact` /
/// `.prefixRegex` sudo `commandPattern` that neither resolves through a live
/// symlink nor exists on disk can never match a `.requireExists` command and
/// fails closed — the exact shape behind the `jamf` deny (a rule authored
/// against `/usr/local/bin/jamf` when that symlink is absent). See
/// ``PAMEvaluator/unresolvableSudoCommandPatterns(_:canonicalizer:fileExists:)``.
@Suite("PAMEvaluator — unresolvable sudo commandPattern diagnostics")
struct PAMEvaluatorUnresolvablePatternTests {
    private func profile(
        key: String = "rules_sudo_test",
        _ rules: [Rule]
    ) -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: key, profilePriority: 50, rules: rules)
    }

    private func sudoRule(
        id: String, commandPattern: String?, matchType: MatchType, argPattern: String? = nil
    ) -> Rule {
        Rule(
            id: id, type: .sudo, action: .allow, description: "d", priority: 10,
            match: MatchCriteria(commandPattern: commandPattern, argPattern: argPattern, matchType: matchType)
        )
    }

    private func run(_ profiles: [RuleProfile], fileExists: @escaping (String) -> Bool) -> [String] {
        PAMEvaluator.unresolvableSudoCommandPatterns(
            profiles, canonicalizer: PathCanonicalizer(), fileExists: fileExists
        )
    }

    @Test("an absent literal exact path warns and names the rule + profile")
    func absentExactWarns() {
        let path = "/opt/serberus-does-not-exist/bin/tool"
        let warnings = run(
            [profile(key: "rules_sudo_jamf", [sudoRule(id: "allow_jamf_recon", commandPattern: path, matchType: .prefixRegex)])],
            fileExists: { _ in false }
        )
        #expect(warnings.count == 1)
        #expect(warnings[0].contains("allow_jamf_recon"))
        #expect(warnings[0].contains("rules_sudo_jamf"))
        #expect(warnings[0].contains(path))
    }

    @Test("an authored path that exists on disk does not warn")
    func existingPathSilent() {
        // canonicalize leaves an already-real path unchanged; existence clears it.
        let path = "/opt/serberus-does-not-exist/bin/tool"
        let warnings = run(
            [profile([sudoRule(id: "r", commandPattern: path, matchType: .exact)])],
            fileExists: { _ in true }
        )
        #expect(warnings.isEmpty)
    }

    @Test("a live symlink that resolves does not warn (canonical != raw)")
    func resolvingSymlinkSilent() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("serberus-unres-\(UUID().uuidString)")
        let real = root.appendingPathComponent("real").appendingPathComponent("tool")
        try fm.createDirectory(at: real.deletingLastPathComponent(), withIntermediateDirectories: true)
        fm.createFile(atPath: real.path, contents: Data("#!/bin/sh\n".utf8))
        let link = root.appendingPathComponent("tool-link")
        try fm.createSymbolicLink(atPath: link.path, withDestinationPath: real.path)
        defer { try? fm.removeItem(at: root) }

        // Author the symlink path; it resolves on disk, so canonical != raw → no warning
        // even though the symlink literal itself is what was authored.
        let warnings = run(
            [profile([sudoRule(id: "r", commandPattern: link.path, matchType: .exact)])],
            fileExists: { fm.fileExists(atPath: $0) }
        )
        #expect(warnings.isEmpty)
    }

    @Test("glob, regex, any, and authURI rules are never flagged")
    func nonLiteralPatternsIgnored() {
        let absent = "/opt/serberus-does-not-exist/bin/tool"
        let profiles = [profile([
            sudoRule(id: "glob", commandPattern: absent, matchType: .glob),
            sudoRule(id: "regex", commandPattern: absent, matchType: .regex),
            sudoRule(id: "any", commandPattern: absent, matchType: .any),
            Rule(id: "authuri", type: .authuri, action: .allow, description: "d", priority: 10,
                 match: MatchCriteria(authURI: "system.preferences")),
        ])]
        #expect(run(profiles, fileExists: { _ in false }).isEmpty)
    }

    @Test("each offending rule across profiles produces its own warning")
    func multipleOffenders() {
        let absent = "/opt/serberus-does-not-exist/bin/tool"
        let profiles = [
            profile(key: "p1", [sudoRule(id: "a", commandPattern: absent, matchType: .exact)]),
            profile(key: "p2", [sudoRule(id: "b", commandPattern: absent, matchType: .prefixRegex)]),
        ]
        let warnings = run(profiles, fileExists: { _ in false })
        #expect(warnings.count == 2)
    }
}
