import Foundation
import Testing
@testable import PrivMgrCore

@Suite("PatternMatcher")
struct PatternMatcherTests {
    @Test("exact matches only the identical path")
    func exact() {
        #expect(PatternMatcher.matchCommand(pattern: "/bin/echo", matchType: .exact, command: "/bin/echo") == .matched)
        #expect(PatternMatcher.matchCommand(pattern: "/bin/echo", matchType: .exact, command: "/bin/echoo") == .noMatch)
    }

    @Test("glob honors fnmatch wildcards")
    func glob() {
        #expect(PatternMatcher.matchCommand(pattern: "/opt/homebrew/bin/*", matchType: .glob, command: "/opt/homebrew/bin/brew") == .matched)
        #expect(PatternMatcher.matchCommand(pattern: "/opt/homebrew/bin/*", matchType: .glob, command: "/usr/bin/brew") == .noMatch)
    }

    @Test("regex must fully match and reports invalid patterns")
    func regex() {
        #expect(PatternMatcher.matchCommand(pattern: "/bin/ec.o", matchType: .regex, command: "/bin/echo") == .matched)
        #expect(PatternMatcher.matchCommand(pattern: "/bin/echo", matchType: .regex, command: "/bin/echo-extra") == .noMatch)
        #expect(PatternMatcher.matchCommand(pattern: "([bad", matchType: .regex, command: "/bin/echo") == .invalidPattern)
    }

    @Test("prefix-regex respects path-component boundaries")
    func prefixRegex() {
        #expect(PatternMatcher.matchCommand(pattern: "/opt/homebrew/bin/brew", matchType: .prefixRegex, command: "/opt/homebrew/bin/brew") == .matched)
        #expect(PatternMatcher.matchCommand(pattern: "/opt/homebrew/bin/brew", matchType: .prefixRegex, command: "/opt/homebrew/bin/brew-evil") == .noMatch)
    }

    @Test("any always matches; nil pattern only matches under any")
    func anyAndNil() {
        #expect(PatternMatcher.matchCommand(pattern: nil, matchType: .any, command: "/x") == .matched)
        #expect(PatternMatcher.matchCommand(pattern: nil, matchType: .exact, command: "/x") == .noMatch)
    }

    @Test("argument matching is anchored and nil-safe")
    func argument() {
        #expect(PatternMatcher.matchArgument(pattern: "install", argument: "install") == .matched)
        #expect(PatternMatcher.matchArgument(pattern: "install", argument: "reinstall") == .noMatch)
        #expect(PatternMatcher.matchArgument(pattern: "install", argument: nil) == .noMatch)
        #expect(PatternMatcher.matchArgument(pattern: "(bad", argument: "x") == .invalidPattern)
    }

    // A full match must consider every alternative, not just the leftmost one
    // that matches a prefix: `boot|bootout` has to match `bootout`.
    @Test("an alternation fully matches its longer alternative (argPattern)")
    func argumentAlternation() {
        #expect(PatternMatcher.matchArgument(pattern: "boot|bootout", argument: "bootout") == .matched)
        #expect(PatternMatcher.matchArgument(pattern: "boot|bootout", argument: "boot") == .matched)
        #expect(PatternMatcher.matchArgument(pattern: "(boot|bootout)", argument: "bootout") == .matched)
        #expect(PatternMatcher.matchArgument(pattern: "unload|unloadall", argument: "unloadall") == .matched)
        #expect(PatternMatcher.matchArgument(pattern: "boot|bootout", argument: "bootstrap") == .noMatch)
        #expect(PatternMatcher.matchArgument(pattern: "boot|bootout", argument: "xboot") == .noMatch)
    }

    @Test("an alternation fully matches its longer alternative (commandPattern)")
    func commandAlternation() {
        #expect(PatternMatcher.matchCommand(pattern: "/usr/bin/(python3|python3\\.12)", matchType: .regex,
                                            command: "/usr/bin/python3.12") == .matched)
        #expect(PatternMatcher.matchCommand(pattern: "/bin/launchctl|/bin/launchctl2", matchType: .regex,
                                            command: "/bin/launchctl2") == .matched)
        #expect(PatternMatcher.matchCommand(pattern: "/usr/bin/(python3|python3\\.12)", matchType: .regex,
                                            command: "/usr/bin/python3.12-evil") == .noMatch)
    }

    @Test("a lazy quantifier still has to cover the whole value")
    func lazyQuantifier() {
        #expect(PatternMatcher.matchCommand(pattern: "/usr/bin/.*?", matchType: .regex,
                                            command: "/usr/bin/foo") == .matched)
    }

    @Test("already-anchored patterns behave the same")
    func alreadyAnchored() {
        #expect(PatternMatcher.matchArgument(pattern: "^recon$", argument: "recon") == .matched)
        #expect(PatternMatcher.matchArgument(pattern: "^recon$", argument: "recon2") == .noMatch)
        #expect(PatternMatcher.matchArgument(pattern: "^(?:boot|bootout)$", argument: "bootout") == .matched)
    }

    @Test("a trailing newline is never absorbed by $")
    func trailingNewline() {
        #expect(PatternMatcher.matchArgument(pattern: "^recon$", argument: "recon\n") == .noMatch)
        #expect(PatternMatcher.matchArgument(pattern: "recon", argument: "recon\n") == .noMatch)
        #expect(PatternMatcher.matchCommand(pattern: "/bin/echo", matchType: .regex, command: "/bin/echo\n") == .noMatch)
    }
}

@Suite("RuleEngine — deny with a regex alternation")
struct DenyAlternationTests {
    @Test("a deny written as boot|bootout blocks bootout ahead of a broader allow")
    func denyAlternationBeatsAllow() {
        let deny = Fixtures.sudoRule(id: "deny-launchctl-boot", action: .deny, priority: 5,
                                     commandPattern: "/bin/launchctl", argPattern: "boot|bootout",
                                     matchType: .exact)
        let allow = Fixtures.sudoRule(id: "allow-launchctl", action: .allow, priority: 10,
                                      commandPattern: "/bin/launchctl", matchType: .exact)
        let profile = Fixtures.profile(rules: [deny, allow])
        let identity = BinaryIdentity(canonicalPath: "/bin/launchctl", teamID: nil,
                                      sha256: "cc" + String(repeating: "0", count: 62),
                                      signingStatus: .valid)
        for verb in ["boot", "bootout"] {
            let request = Fixtures.sudoRequest(command: "/bin/launchctl", argv: [verb, "system/x"],
                                               identity: identity)
            let result = evaluate(request, profiles: [profile])
            #expect(result.decision == .deny, "launchctl \(verb) must be denied")
            #expect(result.matchedRuleID == "deny-launchctl-boot")
        }
        let list = Fixtures.sudoRequest(command: "/bin/launchctl", argv: ["list"], identity: identity)
        #expect(evaluate(list, profiles: [profile]).matchedRuleID == "allow-launchctl")
    }

    @Test("a deny regex with a longer alternative blocks it ahead of a glob allow")
    func denyCommandAlternationBeatsGlobAllow() {
        let deny = Fixtures.sudoRule(id: "deny-python", action: .deny, priority: 5,
                                     commandPattern: "/usr/bin/(python3|python3\\.12)", matchType: .regex)
        let allow = Fixtures.sudoRule(id: "allow-usrbin", action: .allow, priority: 10,
                                      commandPattern: "/usr/bin/*", matchType: .glob)
        let profile = Fixtures.profile(rules: [deny, allow])
        let identity = BinaryIdentity(canonicalPath: "/usr/bin/python3.12", teamID: nil,
                                      sha256: "dd" + String(repeating: "0", count: 62),
                                      signingStatus: .valid)
        let request = Fixtures.sudoRequest(command: "/usr/bin/python3.12", argv: [], identity: identity)
        let result = evaluate(request, profiles: [profile])
        #expect(result.decision == .deny)
        #expect(result.matchedRuleID == "deny-python")
    }
}
