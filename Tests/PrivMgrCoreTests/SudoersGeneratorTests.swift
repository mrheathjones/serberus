import Foundation
import Testing
@testable import PrivMgrCore

@Suite("SudoersGenerator")
struct SudoersGeneratorTests {

    // MARK: - Fixtures

    private static let header = "# test-header"

    /// The full per-principal `Defaults` block the generator emits (presentation
    /// hardening). Kept in one place so the exact-body assertions track the
    /// generator's constants instead of hard-coding the message strings.
    private func defaultsBlock(_ principal: String) -> String {
        """
        Defaults:\(principal) timestamp_timeout=0
        Defaults:\(principal) !env_keep
        Defaults:\(principal) passwd_tries=1
        Defaults:\(principal) authfail_message="\(SudoersGenerator.authFailMessage)"
        Defaults:\(principal) badpass_message="\(SudoersGenerator.badPassMessage)"
        """
    }

    /// The canonical single-`alice`, single-command body used by several tests.
    private func aliceToolBody(command: String = "/opt/serberus-test/bin/tool") -> String {
        "# test-header\n" + defaultsBlock("alice") + "\nalice ALL = \(command)\n"
    }

    /// Builds a single-rule sudo profile.
    private func profile(
        _ rules: [Rule],
        key: String = "rules_sudo_test",
        priority: Int = 0
    ) -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0",
            profileKey: key,
            profilePriority: priority,
            rules: rules
        )
    }

    private func sudoRule(
        id: String = "r1",
        pattern: String?,
        matchType: MatchType?,
        action: RuleAction = .allow,
        type: RuleType = .sudo,
        elevation: ElevationType = .silent,
        argPattern: String? = nil,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil
    ) -> Rule {
        Rule(
            id: id,
            type: type,
            action: action,
            description: id,
            priority: 0,
            match: MatchCriteria(
                commandPattern: pattern,
                argPattern: argPattern,
                matchType: matchType,
                requiredTeamID: requiredTeamID,
                requiredBinaryHash: requiredBinaryHash
            ),
            elevation: ElevationBehavior(type: elevation)
        )
    }

    private func generate(
        _ rules: [Rule],
        group: String? = nil,
        users: [String] = ["alice"]
    ) -> SudoersGenerator.Result {
        SudoersGenerator.generate(
            profiles: [profile(rules)],
            enrollmentGroup: group,
            enrollmentUsers: users,
            header: Self.header
        )
    }

    // MARK: - Match-type translation

    @Test("exact rule emits one literal command spec; absent binary is kept (.allowMissing)")
    func exactRule() {
        // Absolute, no symlink, does not exist -> .allowMissing must NOT drop it.
        let result = generate([sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)])
        #expect(result.excluded.isEmpty)
        #expect(result.body == aliceToolBody())
    }

    @Test("exact match type defaults when matchType is nil")
    func exactDefaultsWhenNil() {
        let result = generate([sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: nil)])
        #expect(result.body.contains("alice ALL = /opt/serberus-test/bin/tool"))
        #expect(result.excluded.isEmpty)
    }

    @Test("glob rule keeps wildcards and is not canonicalized")
    func globRule() {
        let result = generate([sudoRule(pattern: "/opt/homebrew/bin/*", matchType: .glob)])
        #expect(result.body.contains("alice ALL = /opt/homebrew/bin/*"))
        #expect(result.excluded.isEmpty)
    }

    @Test("glob preserves all fnmatch metacharacters * ? [ ]")
    func globMetacharsPreserved() {
        let result = generate([sudoRule(pattern: "/opt/b?n/[abc]/*", matchType: .glob)])
        #expect(result.body.contains("/opt/b?n/[abc]/*"))
    }

    @Test("prefix-regex emits BOTH the bare prefix and the prefix/* spec")
    func prefixRegexTwoSpecs() {
        let result = generate([sudoRule(pattern: "/opt/serberus-test/bin/brew", matchType: .prefixRegex)])
        // Command list is sorted: "/opt/.../brew" sorts before "/opt/.../brew/*".
        #expect(result.body.contains("/opt/serberus-test/bin/brew, /opt/serberus-test/bin/brew/*"))
        #expect(result.excluded.isEmpty)
    }

    @Test("prefix-regex with metachars is treated literally (not canonicalized) and still emits both specs")
    func prefixRegexWithMetachars() {
        let result = generate([sudoRule(pattern: "/opt/x*/bin", matchType: .prefixRegex)])
        #expect(result.body.contains("/opt/x*/bin"))
        #expect(result.body.contains("/opt/x*/bin/*"))
    }

    // MARK: - Exclusions

    @Test("regex match type is excluded, never emitted")
    func regexExcluded() {
        let result = generate([sudoRule(pattern: "/bin/ec.o", matchType: .regex)])
        #expect(result.body == "")
        #expect(result.excluded.count == 1)
        #expect(result.excluded.first?.matchType == "regex")
        #expect(result.excluded.first?.reason == "regex match type not representable in sudoers")
        #expect(result.excluded.first?.commandPattern == "/bin/ec.o")
    }

    @Test("any match type is excluded as a forbidden ALL grant")
    func anyExcluded() {
        let result = generate([sudoRule(pattern: nil, matchType: .any)])
        #expect(result.body == "")
        #expect(result.excluded.count == 1)
        #expect(result.excluded.first?.matchType == "any")
        #expect(result.excluded.first?.reason.contains("ALL-commands grant") == true)
    }

    @Test("nil command pattern on a path match type is excluded")
    func nilPatternExcluded() {
        let result = generate([sudoRule(pattern: nil, matchType: .exact)])
        #expect(result.body == "")
        #expect(result.excluded.count == 1)
        #expect(result.excluded.first?.reason == "command pattern is missing")
    }

    @Test("blank command pattern is excluded")
    func blankPatternExcluded() {
        let result = generate([sudoRule(pattern: "   ", matchType: .exact)])
        #expect(result.body == "")
        #expect(result.excluded.first?.reason == "command pattern is missing")
    }

    @Test("relative / ambiguous exact path is excluded (canonicalization failure), not fatal")
    func relativePathExcluded() {
        let result = generate([
            sudoRule(id: "bad", pattern: "relative/path", matchType: .exact),
            sudoRule(id: "good", pattern: "/opt/serberus-test/bin/tool", matchType: .exact)
        ])
        // Good rule survives; bad rule is logged.
        #expect(result.body.contains("/opt/serberus-test/bin/tool"))
        #expect(result.excluded.contains { $0.commandPattern == "relative/path" })
    }

    // MARK: - Safety invariants

    @Test("deny rules are never emitted")
    func denyNeverEmitted() {
        let result = generate([
            sudoRule(id: "d", pattern: "/bin/rm", matchType: .exact, action: .deny),
            sudoRule(id: "a", pattern: "/opt/serberus-test/bin/tool", matchType: .exact, action: .allow)
        ])
        #expect(!result.body.contains("/bin/rm"))
        #expect(result.body.contains("/opt/serberus-test/bin/tool"))
        // A deny rule is not an unrepresentable *allow* rule, so it isn't logged either.
        #expect(result.excluded.isEmpty)
    }

    @Test("authuri rules are ignored entirely")
    func authuriIgnored() {
        let result = generate([
            sudoRule(pattern: "/should/not/appear", matchType: .exact, type: .authuri)
        ])
        #expect(result.body == "")
        #expect(result.excluded.isEmpty)
    }

    @Test("NOPASSWD is never emitted and no ALL-commands token is ever produced")
    func noNopasswdNoAllCommands() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "devs",
            users: ["alice", "bob"]
        )
        #expect(!result.body.contains("NOPASSWD"))
        // The only "ALL" is the runas host spec ("<principal> ALL = ..."), never a
        // command "= ALL".
        #expect(!result.body.contains("= ALL"))
    }

    @Test("argPattern / requiredTeamID / requiredBinaryHash are ignored (path-only spec)")
    func identityPinsIgnored() {
        let result = generate([
            sudoRule(
                pattern: "/opt/serberus-test/bin/tool",
                matchType: .exact,
                argPattern: "install.*",
                requiredTeamID: "ABCDE12345",
                requiredBinaryHash: "deadbeef"
            )
        ])
        #expect(result.body == aliceToolBody())
        #expect(!result.body.contains("install"))
        #expect(!result.body.contains("ABCDE12345"))
    }

    @Test("every enrolled principal gets timestamp_timeout=0 (defeats sudo's tty cache)")
    func timestampTimeoutPerPrincipal() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "devs",   // generator adds the '%'
            users: ["alice", "bob"]
        )
        // One Defaults line per principal, and each has a matching command line.
        for principal in ["%devs", "alice", "bob"] {
            #expect(result.body.contains("Defaults:\(principal) timestamp_timeout=0"),
                    "\(principal) must get timestamp_timeout=0")
            #expect(result.body.contains("\(principal) ALL = "))
        }
        // No blanket (unscoped) Defaults — the disable is per-principal only.
        #expect(!result.body.contains("\nDefaults timestamp_timeout"))
    }

    @Test("each principal gets the clean-deny Defaults (passwd_tries=1 + custom messages), scoped only")
    func cleanDenyDefaultsPerPrincipal() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "devs",
            users: ["alice", "bob"]
        )
        for principal in ["%devs", "alice", "bob"] {
            // passwd_tries=1 collapses sudo's retry loop → no "Sorry, try again"/count noise.
            #expect(result.body.contains("Defaults:\(principal) passwd_tries=1"))
            #expect(result.body.contains(
                "Defaults:\(principal) authfail_message=\"\(SudoersGenerator.authFailMessage)\""))
            #expect(result.body.contains(
                "Defaults:\(principal) badpass_message=\"\(SudoersGenerator.badPassMessage)\""))
        }
        // Never blanket/unscoped — admins' normal 3-try sudo must be untouched.
        #expect(!result.body.contains("\nDefaults passwd_tries"))
        #expect(!result.body.contains("\nDefaults authfail_message"))
        // The replacement text must not itself say "incorrect password" / "try again".
        #expect(!result.body.lowercased().contains("incorrect password"))
        #expect(!result.body.lowercased().contains("try again"))
    }

    @Test("each principal gets !env_keep, so curated commands never run with the user's HOME, PATH or EDITOR")
    func envKeepClearedPerPrincipal() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "devs",
            users: ["alice", "bob"]
        )
        for principal in ["%devs", "alice", "bob"] {
            #expect(result.body.contains("Defaults:\(principal) !env_keep"),
                    "\(principal) must get !env_keep")
        }
        // Scoped only: an admin's own sudo keeps macOS's environment behaviour.
        #expect(!result.body.contains("\nDefaults !env_keep"))
        #expect(!result.body.contains("\nDefaults env_keep"))
    }

    @Test("the generated drop-in, including !env_keep, passes the real visudo -c")
    func generatedBodyPassesRealVisudo() throws {
        let visudo = "/usr/sbin/visudo"
        guard FileManager.default.isExecutableFile(atPath: visudo) else { return }
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "devs",
            users: ["alice"]
        )
        #expect(result.body.contains("!env_keep"))
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sudoers-gen-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("serberus")
        try Data(result.body.utf8).write(to: file)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: visudo)
        process.arguments = ["-c", "-f", file.path]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        #expect(process.terminationStatus == 0, "visudo -c rejected the drop-in: \(text)")
    }

    @Test("no hardening Defaults when there is nothing to enroll (empty body)")
    func noHardeningDefaultsWhenEmpty() {
        let result = generate([sudoRule(pattern: "/bin/ec.o", matchType: .regex)])
        #expect(result.body == "")
        #expect(!result.body.contains("passwd_tries"))
        #expect(!result.body.contains("authfail_message"))
    }

    @Test("no timestamp_timeout line when there is nothing to enroll (empty body)")
    func noTimestampWhenEmpty() {
        // No valid commands -> empty body -> no Defaults leakage.
        let result = generate([sudoRule(pattern: "/bin/ec.o", matchType: .regex)])
        #expect(result.body == "")
        #expect(!result.body.contains("timestamp_timeout"))
    }

    @Test("path with embedded newline is excluded without aborting the whole body")
    func newlineExcluded() {
        let result = generate([
            sudoRule(id: "evil", pattern: "/opt/tool\nroot ALL = ALL", matchType: .exact),
            sudoRule(id: "good", pattern: "/opt/serberus-test/bin/tool", matchType: .exact)
        ])
        #expect(!result.body.contains("root ALL = ALL"))
        #expect(result.body.contains("/opt/serberus-test/bin/tool"))
        #expect(result.excluded.contains { $0.reason.contains("control character") })
    }

    @Test("glob with control character is excluded")
    func globControlExcluded() {
        let result = generate([sudoRule(pattern: "/opt/\u{07}bell/*", matchType: .glob)])
        #expect(result.body == "")
        #expect(result.excluded.first?.reason.contains("control character") == true)
    }

    // MARK: - Escaping

    @Test("exact spec escapes separators + '#' but NOT '!' (space, comma, colon, equals, hash)")
    func exactEscapesSeparatorsAndHashNotBang() {
        // No backslash, no wildcard: exercises the shared separator/hash escaping.
        // '#' MUST be escaped (else it starts a sudoers comment); '!' must NOT be
        // escaped (visudo rejects `\!`).
        let result = generate([
            sudoRule(pattern: "/opt/a b,c:d=e#f!g", matchType: .exact)
        ])
        #expect(result.body.contains("/opt/a\\ b\\,c\\:d\\=e\\#f!g"))
        // Defensive: no `\!` was emitted anywhere.
        #expect(!result.body.contains("\\!"))
    }

    @Test("a comma in a path never splits into two command specs")
    func commaDoesNotSplit() {
        let result = generate([sudoRule(pattern: "/opt/a,b", matchType: .exact)])
        #expect(result.body.contains("alice ALL = /opt/a\\,b\n"))
    }

    // MARK: - '#' comment-injection

    @Test("exact '/usr/bin/git#sub' escapes '#' and does not drop later specs")
    func f1HashEscapedNoSpecDrop() {
        // `/usr/bin` exists; the `git#sub` leaf is missing but .allowMissing keeps it.
        let result = generate([
            sudoRule(id: "hash", pattern: "/usr/bin/git#sub", matchType: .exact),
            sudoRule(id: "other", pattern: "/bin/other", matchType: .exact)
        ])
        // '#' is escaped to `\#` (literal), so sudo does NOT read it as a comment.
        #expect(result.body.contains("/usr/bin/git\\#sub"))
        // The un-escaped, broader `/usr/bin/git` grant must NOT appear on its own.
        #expect(!result.body.contains("= /usr/bin/git,"))
        #expect(!result.body.contains("= /usr/bin/git\n"))
        // The later curated spec is still present (no silent drop).
        #expect(result.body.contains("/bin/other"))
        #expect(result.excluded.isEmpty)
    }

    // MARK: - Exact-match must never emit a live wildcard

    // NOTE: escaping the wildcard for `.exact` (`*` -> `\*`) does not work:
    // visudo 1.9.17p2 REJECTS `\* \? \[ \]` ("expected a fully-qualified path
    // name"), so escaping would itself brick the file. The security goal — an
    // exact rule must NOT become a live directory-wide wildcard — is instead met
    // by EXCLUDING exact paths that contain an fnmatch metacharacter (fail-safe:
    // the command stays denied at the coarse gate; the fine gate still governs).
    @Test("exact '/usr/bin/*' is EXCLUDED, never emitted as a live or escaped wildcard")
    func f3ExactWildcardExcluded() {
        let result = generate([sudoRule(pattern: "/usr/bin/*", matchType: .exact)])
        #expect(result.body == "")
        // Neither a live `/usr/bin/*` nor a (visudo-rejected) `/usr/bin/\*` appears.
        #expect(!result.body.contains("/usr/bin/*"))
        #expect(!result.body.contains("/usr/bin/\\*"))
        #expect(result.excluded.contains { $0.commandPattern == "/usr/bin/*" && $0.reason.contains("fnmatch wildcard") })
    }

    @Test("exact '/opt/a?b[c]' (with ? [ ]) is EXCLUDED, and other specs still emit")
    func f3ExactAllWildcardsExcluded() {
        let result = generate([
            sudoRule(id: "wild", pattern: "/opt/a?b[c]", matchType: .exact),
            sudoRule(id: "ok", pattern: "/opt/serberus-test/bin/tool", matchType: .exact)
        ])
        #expect(!result.body.contains("/opt/a"))
        #expect(result.body.contains("/opt/serberus-test/bin/tool"))
        #expect(result.excluded.contains { $0.commandPattern == "/opt/a?b[c]" && $0.reason.contains("fnmatch wildcard") })
    }

    @Test("glob '/usr/local/bin/*' KEEPS the wildcard live (glob is meant to be a wildcard)")
    func f3GlobWildcardStaysLive() {
        let result = generate([sudoRule(pattern: "/usr/local/bin/*", matchType: .glob)])
        #expect(result.body.contains("alice ALL = /usr/local/bin/*\n"))
        // Live, not escaped.
        #expect(!result.body.contains("/usr/local/bin/\\*"))
        #expect(result.excluded.isEmpty)
    }

    // MARK: - Invalid-escape / non-absolute exclusion

    @Test("a path containing '!' is emitted literally (no backslash before '!')")
    func f2BangNotEscaped() {
        let result = generate([sudoRule(pattern: "/opt/tool!run", matchType: .exact)])
        #expect(result.body.contains("alice ALL = /opt/tool!run\n"))
        #expect(!result.body.contains("\\!"))
        #expect(result.excluded.isEmpty)
    }

    @Test("a path containing a backslash is EXCLUDED, and other specs still emit")
    func f2BackslashExcluded() {
        let result = generate([
            sudoRule(id: "bs", pattern: "/opt/a\\b", matchType: .exact),
            sudoRule(id: "ok", pattern: "/opt/serberus-test/bin/tool", matchType: .exact)
        ])
        // The backslash path never reaches the body (no `\\` ever emitted).
        #expect(!result.body.contains("\\\\"))
        #expect(!result.body.contains("/opt/a"))
        // The valid, unrelated spec survives.
        #expect(result.body.contains("/opt/serberus-test/bin/tool"))
        #expect(result.excluded.contains { $0.commandPattern == "/opt/a\\b" && $0.reason.contains("backslash") })
    }

    @Test("a glob backslash path is EXCLUDED")
    func f2GlobBackslashExcluded() {
        let result = generate([sudoRule(pattern: "/opt/a\\b/*", matchType: .glob)])
        #expect(result.body == "")
        #expect(result.excluded.contains { $0.reason.contains("backslash") })
    }

    @Test("non-absolute glob specs '*' and 'bin/*' are EXCLUDED (would brick the file)")
    func f2NonAbsoluteGlobExcluded() {
        let star = generate([sudoRule(pattern: "*", matchType: .glob)])
        #expect(star.body == "")
        #expect(star.excluded.contains { $0.reason.contains("fully qualified") })

        let relative = generate([sudoRule(pattern: "bin/*", matchType: .glob)])
        #expect(relative.body == "")
        #expect(relative.excluded.contains { $0.reason.contains("fully qualified") })
    }

    // MARK: - Empty / fail-safe

    @Test("empty enrollment (nil group + no users) yields an empty body")
    func emptyEnrollment() {
        let result = SudoersGenerator.generate(
            profiles: [profile([sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)])],
            enrollmentGroup: nil,
            enrollmentUsers: [],
            header: Self.header
        )
        #expect(result.body == "")
    }

    @Test("blank group + blank/whitespace users is treated as empty enrollment")
    func blankEnrollment() {
        let result = SudoersGenerator.generate(
            profiles: [profile([sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)])],
            enrollmentGroup: "  ",
            enrollmentUsers: ["  ", ""],
            header: Self.header
        )
        #expect(result.body == "")
    }

    @Test("all rules excluded yields an empty body even with valid enrollment")
    func allExcludedEmptyBody() {
        let result = generate(
            [sudoRule(pattern: nil, matchType: .any)],
            users: ["alice"]
        )
        #expect(result.body == "")
        #expect(result.excluded.count == 1)
    }

    @Test("no profiles yields an empty body")
    func noProfiles() {
        let result = SudoersGenerator.generate(
            profiles: [],
            enrollmentGroup: nil,
            enrollmentUsers: ["alice"],
            header: Self.header
        )
        #expect(result.body == "")
        #expect(result.excluded.isEmpty)
    }

    // MARK: - Ordering, dedup, idempotency

    @Test("identical inputs produce byte-identical output")
    func idempotency() {
        let rules = [
            sudoRule(id: "a", pattern: "/opt/serberus-test/bin/z", matchType: .exact),
            sudoRule(id: "b", pattern: "/opt/serberus-test/bin/a", matchType: .exact)
        ]
        let first = generate(rules, group: "devs", users: ["bob", "alice"])
        let second = generate(rules, group: "devs", users: ["bob", "alice"])
        #expect(first.body == second.body)
    }

    @Test("command specs are de-duplicated and sorted deterministically")
    func dedupAndSortCommands() {
        let result = generate([
            sudoRule(id: "a", pattern: "/opt/serberus-test/bin/z", matchType: .exact),
            sudoRule(id: "b", pattern: "/opt/serberus-test/bin/a", matchType: .exact),
            sudoRule(id: "dup", pattern: "/opt/serberus-test/bin/z", matchType: .exact)
        ])
        // Sorted: a before z; the duplicate z appears once.
        #expect(result.body.contains(
            "alice ALL = /opt/serberus-test/bin/a, /opt/serberus-test/bin/z\n"
        ))
        // Only one occurrence of the z spec.
        let occurrences = result.body.components(separatedBy: "/opt/serberus-test/bin/z").count - 1
        #expect(occurrences == 1)
    }

    @Test("users are sorted, each get their own line, and the group is appended last as %group")
    func principalsOrderingAndGroup() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "devs",
            users: ["bob", "alice"]
        )
        let expected = "# test-header\n"
            + defaultsBlock("alice") + "\n"
            + defaultsBlock("bob") + "\n"
            + defaultsBlock("%devs") + "\n"
            + """
            alice ALL = /opt/serberus-test/bin/tool
            bob ALL = /opt/serberus-test/bin/tool
            %devs ALL = /opt/serberus-test/bin/tool

            """
        #expect(result.body == expected)
    }

    @Test("duplicate / blank users are de-duplicated and dropped")
    func principalsDedup() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            users: ["alice", "alice", "  ", "bob"]
        )
        let userLines = result.body
            .split(separator: "\n")
            .filter { $0.contains("ALL =") }
        #expect(userLines.count == 2)
    }

    @Test("prompt-elevation allow rules are included identically to silent allow rules")
    func promptElevationIncluded() {
        let silent = generate([
            sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact, elevation: .silent)
        ])
        let prompt = generate([
            sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact, elevation: .prompt)
        ])
        #expect(prompt.body == silent.body)
        #expect(prompt.body.contains("/opt/serberus-test/bin/tool"))
    }

    @Test("body ends with exactly one trailing newline")
    func trailingNewline() {
        let result = generate([sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)])
        #expect(result.body.hasSuffix("\n"))
        #expect(!result.body.hasSuffix("\n\n"))
    }

    @Test("default header is the managed marker string")
    func defaultHeader() {
        let result = SudoersGenerator.generate(
            profiles: [profile([sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)])],
            enrollmentGroup: nil,
            enrollmentUsers: ["alice"]
        )
        #expect(result.body.hasPrefix(SudoersGenerator.defaultHeader + "\n"))
        #expect(SudoersGenerator.defaultHeader.contains("com.herojoneslabs.serberus"))
        #expect(SudoersGenerator.defaultHeader.contains("DO NOT EDIT"))
    }

    // MARK: - Principal (user/group) injection

    @Test("the reserved 'ALL' user token is excluded, never emitted")
    func f4AllUserExcluded() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            users: ["ALL"]
        )
        // No principals remain -> empty (remove) body.
        #expect(result.body == "")
        #expect(result.excluded.contains { $0.principal == "ALL" && $0.matchType == "principal" })
    }

    @Test("an injection-crafted principal is excluded and never reaches the body")
    func f4InjectionPrincipalExcluded() {
        let evil = "attacker ALL=(ALL) NOPASSWD: ALL #"
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            users: [evil, "alice"]
        )
        // The crafted principal is dropped; the valid one still gets a grant.
        #expect(!result.body.contains("NOPASSWD"))
        #expect(!result.body.contains("attacker"))
        #expect(result.body.contains("alice ALL = /opt/serberus-test/bin/tool"))
        #expect(result.excluded.contains { $0.principal == evil && $0.matchType == "principal" })
    }

    @Test("valid users and group are emitted; users verbatim, group as %group")
    func f4ValidPrincipalsEmitted() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "staff",
            users: ["alice", "bob_1"]
        )
        let expected = "# test-header\n"
            + defaultsBlock("alice") + "\n"
            + defaultsBlock("bob_1") + "\n"
            + defaultsBlock("%staff") + "\n"
            + """
            alice ALL = /opt/serberus-test/bin/tool
            bob_1 ALL = /opt/serberus-test/bin/tool
            %staff ALL = /opt/serberus-test/bin/tool

            """
        #expect(result.body == expected)
        #expect(result.excluded.isEmpty)
    }

    @Test("an admin-supplied '%'-prefixed group is excluded (we own the '%')")
    func f4AlreadyPrefixedGroupExcluded() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "%staff",
            users: ["alice"]
        )
        // Group dropped; the user still gets a grant, and no `%%` is emitted.
        #expect(result.body.contains("alice ALL = /opt/serberus-test/bin/tool"))
        #expect(!result.body.contains("%staff"))
        #expect(!result.body.contains("%%"))
        #expect(result.excluded.contains { $0.principal == "%staff" && $0.matchType == "principal" })
    }

    @Test("the reserved 'ALL' group token is excluded")
    func f4AllGroupExcluded() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "ALL",
            users: ["alice"]
        )
        #expect(result.body.contains("alice ALL = /opt/serberus-test/bin/tool"))
        #expect(!result.body.contains("%ALL"))
        #expect(result.excluded.contains { $0.principal == "ALL" && $0.matchType == "principal" })
    }

    @Test("all principals invalid yields an empty (remove) body")
    func f4AllPrincipalsInvalidEmptyBody() {
        let result = generate(
            [sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact)],
            group: "bad group",
            users: ["ALL", "has space", "%pct"]
        )
        #expect(result.body == "")
        // Every offending principal was recorded.
        #expect(result.excluded.filter { $0.matchType == "principal" }.count == 4)
    }

    // MARK: - Mixed corpus is byte-stable & every line is fully-qualified

    @Test("mixed valid corpus is byte-stable and every emitted spec is a fully-qualified path")
    func mixedCorpusByteStableAndFullyQualified() {
        let rules = [
            sudoRule(id: "hash", pattern: "/usr/bin/git#sub", matchType: .exact),
            sudoRule(id: "glob", pattern: "/usr/local/bin/*", matchType: .glob),
            sudoRule(id: "bang", pattern: "/opt/tool!run", matchType: .exact),
            sudoRule(id: "prefix", pattern: "/opt/serberus-test/bin/brew", matchType: .prefixRegex),
            // Excluded, must not perturb the emitted body:
            sudoRule(id: "star", pattern: "/usr/bin/*", matchType: .exact),   // exact + wildcard
            sudoRule(id: "bs", pattern: "/opt/a\\b", matchType: .exact),      // backslash
            sudoRule(id: "rel", pattern: "bin/*", matchType: .glob)           // non-absolute
        ]
        let first = generate(rules, group: "staff", users: ["bob", "alice"])
        let second = generate(rules, group: "staff", users: ["bob", "alice"])
        #expect(first.body == second.body)
        #expect(!first.body.isEmpty)

        // Every command spec on every principal line is a fully-qualified path.
        for line in first.body.split(separator: "\n") where line.contains(" ALL = ") {
            let specs = line.components(separatedBy: " ALL = ")[1].components(separatedBy: ", ")
            for spec in specs {
                #expect(spec.hasPrefix("/"), "spec is not fully qualified: \(spec)")
            }
        }
        // No live wildcard leaked from the excluded exact `/usr/bin/*`.
        #expect(!first.body.contains("/usr/bin/*"))
        // The excluded exact-wildcard, backslash + relative specs are recorded, not emitted.
        #expect(!first.body.contains("\\\\"))
        #expect(first.excluded.contains { $0.commandPattern == "/usr/bin/*" })
        #expect(first.excluded.contains { $0.commandPattern == "/opt/a\\b" })
        #expect(first.excluded.contains { $0.commandPattern == "bin/*" })
    }

    // MARK: - FIX 1: dual authored + canonical path emission (symlink)

    /// Creates `<tmp>/<link> -> <tmp>/<real…>` and returns both the authored
    /// (symlink) path and the symlink-resolved canonical path. Mirrors the live
    /// jamf redirect `/usr/local/bin/jamf -> /usr/local/jamf/bin/jamf`.
    private func makeSymlink(
        realComponents: [String], linkName: String
    ) throws -> (root: URL, symlink: String, canonical: String) {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("serberus-sudoers-\(UUID().uuidString)")
        let realFile = realComponents.reduce(root) { $0.appendingPathComponent($1) }
        try fm.createDirectory(at: realFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        fm.createFile(atPath: realFile.path, contents: Data("#!/bin/sh\n".utf8))
        let link = root.appendingPathComponent(linkName)
        try fm.createSymbolicLink(atPath: link.path, withDestinationPath: realFile.path)
        return (root, link.path, (realFile.path as NSString).resolvingSymlinksInPath)
    }

    @Test("FIX 1: exact rule authored against a symlink emits BOTH the authored and canonical paths")
    func exactSymlinkEmitsDualPaths() throws {
        let fx = try makeSymlink(realComponents: ["real", "tool"], linkName: "tool-link")
        defer { try? FileManager.default.removeItem(at: fx.root) }
        #expect(fx.symlink != fx.canonical) // fixture really is a redirect

        let result = generate([sudoRule(pattern: fx.symlink, matchType: .exact)])
        #expect(result.excluded.isEmpty)
        // `sudo` matches the typed (symlink) path; the daemon canonicalizes. Both
        // must be authorized at the coarse gate or `sudo <symlink>` is denied.
        #expect(result.body.contains(fx.symlink))
        #expect(result.body.contains(fx.canonical))
    }

    @Test("FIX 1: jamf scenario — symlink prefix-regex + ^recon$ emits BOTH dual paths, path-only (no arg pin)")
    func jamfSymlinkPrefixIsPathOnly() throws {
        let fx = try makeSymlink(realComponents: ["jamf", "bin", "jamf"], linkName: "jamf-link")
        defer { try? FileManager.default.removeItem(at: fx.root) }
        #expect(fx.symlink != fx.canonical)

        let result = generate([
            sudoRule(pattern: fx.symlink, matchType: .prefixRegex, argPattern: "^recon$")
        ])
        #expect(result.excluded.isEmpty)
        // Path-only: the coarse layer IGNORES argPattern, so it emits
        // the bare authored + canonical prefix and each `/*` sub-path spec — never a
        // `<path> recon` arg-pinned spec (which would deny `sudo jamf recon -verbose`).
        for base in [fx.symlink, fx.canonical] {
            #expect(result.body.contains(base))
            #expect(result.body.contains("\(base)/*"))
        }
        // No arg-pinned spec was emitted anywhere.
        #expect(!result.body.contains(" recon"))
    }

    // MARK: - argPattern is ignored by the path-only coarse layer

    @Test("a fully-anchored literal ^recon$ is IGNORED: exact rule stays path-only (dual path, no arg pin)")
    func exactRuleWithAnchoredArgStaysPathOnly() {
        let result = generate([
            sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact, argPattern: "^recon$")
        ])
        #expect(result.excluded.isEmpty)
        // Path-only: exact -> the bare path, no ` recon` suffix.
        #expect(result.body == aliceToolBody())
        #expect(!result.body.contains("recon"))
    }

    @Test("a fully-anchored literal ^recon$ is IGNORED: prefix-regex rule emits path + path/* (no arg pin)")
    func prefixRegexRuleWithAnchoredArgStaysPathOnly() {
        let result = generate([
            sudoRule(pattern: "/opt/serberus-test/bin/jamf", matchType: .prefixRegex, argPattern: "^recon$")
        ])
        #expect(result.excluded.isEmpty)
        // prefix-regex -> BOTH the bare prefix AND the `/*` sub-path spec, path-only.
        #expect(result.body.contains(
            "/opt/serberus-test/bin/jamf, /opt/serberus-test/bin/jamf/*"
        ))
        #expect(!result.body.contains("recon"))
    }

    @Test("jamf exact rule with ^recon$ emits BOTH friendly + resolved paths, no ` recon` suffix")
    func jamfExactDualPathNoArgSuffix() throws {
        let fx = try makeSymlink(realComponents: ["jamf", "bin", "jamf"], linkName: "jamf-link")
        defer { try? FileManager.default.removeItem(at: fx.root) }
        #expect(fx.symlink != fx.canonical)

        let result = generate([
            sudoRule(pattern: fx.symlink, matchType: .exact, argPattern: "^recon$")
        ])
        #expect(result.excluded.isEmpty)
        // Dual-path: both the authored symlink and its canonical
        // target are authorized. Neither carries a ` recon` argument suffix.
        #expect(result.body.contains(fx.symlink))
        #expect(result.body.contains(fx.canonical))
        #expect(!result.body.contains(" recon"))
        // Each is a bare path spec (no arg pin, and exact never emits `/*`).
        for line in result.body.split(separator: "\n") where line.contains(" ALL = ") {
            let specs = line.components(separatedBy: " ALL = ")[1].components(separatedBy: ", ")
            #expect(specs.contains(fx.symlink))
            #expect(specs.contains(fx.canonical))
        }
    }

    @Test("a regex-metachar / unanchored arg pattern is likewise ignored (path-only)")
    func regexOrUnanchoredArgStaysPathOnly() {
        // Every argPattern shape is ignored by the coarse layer now — anchored literal,
        // regex-metachar, and unanchored all collapse to the same path-only body.
        for arg in ["^re.on$", "recon", "^(recon|policy)$"] {
            let result = generate([
                sudoRule(pattern: "/opt/serberus-test/bin/tool", matchType: .exact, argPattern: arg)
            ])
            #expect(result.body == aliceToolBody())
        }
    }
}
