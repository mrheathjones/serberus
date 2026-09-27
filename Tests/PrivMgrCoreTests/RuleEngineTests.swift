import Foundation
import Testing
@testable import PrivMgrCore

@Suite("RuleEngine — match types")
struct MatchTypeTests {
    @Test("exact matches the canonical path and nothing else")
    func exactMatch() {
        let profile = Fixtures.profile(rules: [Fixtures.sudoRule(matchType: .exact)])
        #expect(evaluate(Fixtures.sudoRequest(), profiles: [profile]).decision == .allow)
        let other = Fixtures.sudoRequest(command: "/opt/homebrew/bin/brew2")
        let result = evaluate(other, profiles: [profile])
        #expect(result.decision == .deny)
        #expect(result.noMatch)
    }

    @Test("glob matches fnmatch patterns")
    func globMatch() {
        let rule = Fixtures.sudoRule(commandPattern: "/opt/homebrew/bin/*", matchType: .glob)
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(), profiles: [profile]).decision == .allow)
        #expect(evaluate(Fixtures.sudoRequest(command: "/usr/bin/brew"), profiles: [profile]).decision == .deny)
    }

    @Test("regex must fully match the path")
    func regexMatch() {
        let rule = Fixtures.sudoRule(commandPattern: "/opt/homebrew/bin/br.w", matchType: .regex)
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(), profiles: [profile]).decision == .allow)
        // Partial match must not count.
        let partial = Fixtures.sudoRequest(command: "/opt/homebrew/bin/brew-extra")
        #expect(evaluate(partial, profiles: [profile]).decision == .deny)
    }

    @Test("prefix-regex: path prefix plus argv[0] regex")
    func prefixRegexMatch() {
        let rule = Fixtures.sudoRule(
            commandPattern: "/opt/homebrew/bin/brew",
            argPattern: "install|upgrade|uninstall",
            matchType: .prefixRegex
        )
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(argv: ["install", "wget"]), profiles: [profile]).decision == .allow)
        #expect(evaluate(Fixtures.sudoRequest(argv: ["upgrade"]), profiles: [profile]).decision == .allow)
        #expect(evaluate(Fixtures.sudoRequest(argv: ["doctor"]), profiles: [profile]).decision == .deny)
        // argPattern present + empty argv must fail closed.
        #expect(evaluate(Fixtures.sudoRequest(argv: []), profiles: [profile]).decision == .deny)
        // Prefix must respect path-component boundaries.
        let lookalike = Fixtures.sudoRequest(command: "/opt/homebrew/bin/brew-evil", argv: ["install"])
        #expect(evaluate(lookalike, profiles: [profile]).decision == .deny)
    }

    @Test("any matches every command")
    func anyMatch() {
        let rule = Fixtures.sudoRule(commandPattern: nil, matchType: .any)
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(command: "/sbin/anything"), profiles: [profile]).decision == .allow)
    }

    @Test("argv full-match is anchored — superstrings of the pattern do not match")
    func argvAnchored() {
        let rule = Fixtures.sudoRule(argPattern: "install", matchType: .exact)
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(argv: ["install"]), profiles: [profile]).decision == .allow)
        #expect(evaluate(Fixtures.sudoRequest(argv: ["reinstall"]), profiles: [profile]).decision == .deny)
    }

    @Test("authuri matches exactly")
    func authURIMatch() {
        let profile = Fixtures.profile(key: "rules_authuri_test", rules: [Fixtures.authURIRule()])
        #expect(evaluate(Fixtures.authURIRequest(), profiles: [profile]).decision == .allow)
        #expect(evaluate(Fixtures.authURIRequest(uri: "system.keychain-modify.extra"), profiles: [profile]).decision == .deny)
    }

    @Test("rule type and request kind never cross-match")
    func kindIsolation() {
        let sudoProfile = Fixtures.profile(rules: [Fixtures.sudoRule(commandPattern: nil, matchType: .any)])
        #expect(evaluate(Fixtures.authURIRequest(), profiles: [sudoProfile]).decision == .deny)
        let authProfile = Fixtures.profile(key: "rules_authuri_test", rules: [Fixtures.authURIRule()])
        #expect(evaluate(Fixtures.sudoRequest(), profiles: [authProfile]).decision == .deny)
    }
}

@Suite("RuleEngine — identity constraints")
struct IdentityConstraintTests {
    @Test("requiredTeamID gates the match")
    func teamIDPin() {
        let rule = Fixtures.sudoRule(
            commandPattern: "/usr/local/bin/signedtool",
            requiredTeamID: "TEAM123456"
        )
        let profile = Fixtures.profile(rules: [rule])
        let signed = Fixtures.sudoRequest(command: "/usr/local/bin/signedtool",
                                          identity: Fixtures.signedToolIdentity)
        #expect(evaluate(signed, profiles: [profile]).decision == .allow)

        let impostor = BinaryIdentity(
            canonicalPath: "/usr/local/bin/signedtool",
            teamID: "EVIL999999",
            sha256: Fixtures.signedToolIdentity.sha256,
            signingStatus: .valid
        )
        let spoofed = Fixtures.sudoRequest(command: "/usr/local/bin/signedtool", identity: impostor)
        #expect(evaluate(spoofed, profiles: [profile]).decision == .deny)
    }

    @Test("requiredBinaryHash gates the match case-insensitively")
    func hashPin() {
        let rule = Fixtures.sudoRule(requiredBinaryHash: Fixtures.brewIdentity.sha256.uppercased())
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(), profiles: [profile]).decision == .allow)

        let modified = BinaryIdentity(
            canonicalPath: "/opt/homebrew/bin/brew",
            teamID: nil,
            sha256: "cc" + String(repeating: "0", count: 62),
            signingStatus: .unsigned
        )
        #expect(evaluate(Fixtures.sudoRequest(identity: modified), profiles: [profile]).decision == .deny)
    }
}

@Suite("RuleEngine — priority and conflicts")
struct PriorityTests {
    @Test("lower rule priority evaluates first")
    func priorityOrdering() {
        let denyFirst = Fixtures.profile(rules: [
            Fixtures.sudoRule(id: "deny-early", action: .deny, priority: 1),
            Fixtures.sudoRule(id: "allow-late", action: .allow, priority: 5),
        ])
        let result = evaluate(Fixtures.sudoRequest(), profiles: [denyFirst])
        #expect(result.decision == .deny)
        #expect(result.matchedRuleID == "deny-early")
    }

    @Test("deny wins at equal priority")
    func denyWins() {
        let profile = Fixtures.profile(rules: [
            Fixtures.sudoRule(id: "a-allow", action: .allow, priority: 5),
            Fixtures.sudoRule(id: "z-deny", action: .deny, priority: 5),
        ])
        let result = evaluate(Fixtures.sudoRequest(), profiles: [profile])
        #expect(result.decision == .deny)
        #expect(result.matchedRuleID == "z-deny")
    }

    @Test("lower profilePriority wins across profiles")
    func profilePriority() {
        let high = Fixtures.profile(key: "rules_sudo_high", priority: 10,
                                    rules: [Fixtures.sudoRule(id: "high-deny", action: .deny)])
        let low = Fixtures.profile(key: "rules_sudo_low", priority: 90,
                                   rules: [Fixtures.sudoRule(id: "low-allow", action: .allow)])
        let result = evaluate(Fixtures.sudoRequest(), profiles: [low, high])
        #expect(result.decision == .deny)
        #expect(result.matchedProfileKey == "rules_sudo_high")
    }

    @Test("first match wins — later rules are not consulted")
    func firstMatchWins() {
        let profile = Fixtures.profile(rules: [
            Fixtures.sudoRule(id: "allow-first", action: .allow, priority: 1),
            Fixtures.sudoRule(id: "deny-second", action: .deny, priority: 2),
        ])
        let result = evaluate(Fixtures.sudoRequest(), profiles: [profile])
        #expect(result.decision == .allow)
        #expect(result.matchedRuleID == "allow-first")
    }
}

@Suite("RuleEngine — determinism")
struct DeterminismTests {
    @Test("shuffled profile and rule input order never changes the decision")
    func inputOrderInvariance() {
        let rules = (0..<20).map { index in
            Fixtures.sudoRule(
                id: "rule-\(index)",
                action: index.isMultiple(of: 3) ? .deny : .allow,
                priority: index % 5
            )
        }
        let profiles = [
            Fixtures.profile(key: "rules_sudo_a", priority: 50, rules: Array(rules[0..<10])),
            Fixtures.profile(key: "rules_sudo_b", priority: 50, rules: Array(rules[10..<20])),
        ]
        let request = Fixtures.sudoRequest()
        let baseline = evaluate(request, profiles: profiles)

        // Engine output must be a pure function of content, not ordering.
        var generator = SeededGenerator(seed: 42)
        for _ in 0..<25 {
            let shuffledProfiles = profiles
                .map { profile in
                    RuleProfile(
                        policyVersion: profile.policyVersion,
                        profileKey: profile.profileKey,
                        profilePriority: profile.profilePriority,
                        rules: profile.rules.shuffled(using: &generator)
                    )
                }
                .shuffled(using: &generator)
            let result = evaluate(request, profiles: shuffledProfiles)
            #expect(result.decision == baseline.decision)
            #expect(result.matchedRuleID == baseline.matchedRuleID)
            #expect(result.matchedProfileKey == baseline.matchedProfileKey)
        }
    }

    @Test("repeated evaluation of identical input is identical")
    func repeatStability() {
        let profile = Fixtures.profile(rules: [Fixtures.sudoRule()])
        let request = Fixtures.sudoRequest()
        let first = evaluate(request, profiles: [profile])
        for _ in 0..<10 {
            #expect(evaluate(request, profiles: [profile]) == first)
        }
    }
}

@Suite("RuleEngine — decisions and grants")
struct DecisionResolutionTests {
    @Test("zero rules → fail closed with noMatch")
    func failClosed() {
        let result = evaluate(Fixtures.sudoRequest(), profiles: [])
        #expect(result.decision == .deny)
        #expect(result.noMatch)
        #expect(result.resolvedCacheSeconds == 0)
    }

    @Test("prompt elevation type yields prompt decision")
    func promptDecision() {
        let rule = Fixtures.sudoRule(elevation: ElevationBehavior(type: .prompt))
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])])
        #expect(result.decision == .prompt)
    }

    @Test("maxGrantDurationSeconds yields timedGrant with duration")
    func timedGrantDecision() {
        let rule = Fixtures.sudoRule(conditions: RuleConditions(maxGrantDurationSeconds: 900))
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])])
        #expect(result.decision == .timedGrant)
        #expect(result.grantDurationSeconds == 900)
    }

    @Test("global default duration applies when a rule sets none")
    func globalDefaultGrantDuration() {
        // A plain silent-allow rule (no per-rule duration). Without a global
        // default it is a bare allow; with one it becomes a bounded timed grant.
        let rule = Fixtures.sudoRule()
        let profile = Fixtures.profile(rules: [rule])
        let plain = evaluate(Fixtures.sudoRequest(), profiles: [profile])
        #expect(plain.decision == .allow)
        #expect(plain.grantDurationSeconds == nil)

        let bounded = evaluate(Fixtures.sudoRequest(), profiles: [profile],
                               globalGrantDurationSeconds: 600)
        #expect(bounded.decision == .timedGrant)
        #expect(bounded.grantDurationSeconds == 600)
    }

    @Test("a rule's own duration overrides the global default")
    func perRuleDurationOverridesGlobal() {
        let rule = Fixtures.sudoRule(conditions: RuleConditions(maxGrantDurationSeconds: 120))
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])],
                              globalGrantDurationSeconds: 600)
        #expect(result.decision == .timedGrant)
        #expect(result.grantDurationSeconds == 120)
    }

    @Test("the global default flows to a prompt rule's grant-on-approval")
    func globalDefaultAppliesToPromptRule() {
        // A prompt rule with no per-rule duration issues no grant on its own;
        // the global default supplies the window the approved elevation lasts.
        let rule = Fixtures.sudoRule(elevation: ElevationBehavior(type: .prompt))
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(), profiles: [profile]).grantDurationSeconds == nil)
        let withDefault = evaluate(Fixtures.sudoRequest(), profiles: [profile],
                                   globalGrantDurationSeconds: 300)
        #expect(withDefault.decision == .prompt)
        #expect(withDefault.grantDurationSeconds == 300)
    }

    @Test("resolved grant duration is clamped to the 24h maximum")
    func grantDurationClamp() {
        let huge = RuleSchemaConstants.maxGrantSeconds + 10_000
        let rule = Fixtures.sudoRule(conditions: RuleConditions(maxGrantDurationSeconds: huge))
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])])
        #expect(result.grantDurationSeconds == RuleSchemaConstants.maxGrantSeconds)
    }

    @Test("time-bound disabled: a silent rule's duration is ignored — plain allow")
    func timeBoundDisabledSilent() {
        // A silent rule with an explicit duration would be a timed grant when
        // enabled; disabled, the duration is ignored and it is a plain allow.
        let rule = Fixtures.sudoRule(conditions: RuleConditions(maxGrantDurationSeconds: 900))
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])],
                              timeBoundGrantsEnabled: false)
        #expect(result.decision == .allow)
        #expect(result.grantDurationSeconds == nil)
    }

    @Test("time-bound disabled: the global default is ignored too")
    func timeBoundDisabledIgnoresGlobal() {
        let rule = Fixtures.sudoRule()
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])],
                              globalGrantDurationSeconds: 600, timeBoundGrantsEnabled: false)
        #expect(result.decision == .allow)
        #expect(result.grantDurationSeconds == nil)
    }

    @Test("time-bound disabled: a prompt rule issues no grant, so it prompts every time")
    func timeBoundDisabledPromptEveryTime() {
        // Only a time-bound grant may skip a prompt; with time-bound grants off
        // the rule's duration is ignored and nothing is remembered on approval.
        let rule = Fixtures.sudoRule(conditions: RuleConditions(maxGrantDurationSeconds: 900),
                                     elevation: ElevationBehavior(type: .prompt))
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])],
                              timeBoundGrantsEnabled: false)
        #expect(result.decision == .prompt)
        #expect(result.grantDurationSeconds == nil)
    }

    @Test("time-bound disabled with no duration configured: prompt keeps no grant")
    func timeBoundDisabledPromptNoDuration() {
        let rule = Fixtures.sudoRule(elevation: ElevationBehavior(type: .prompt))
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])],
                              timeBoundGrantsEnabled: false)
        #expect(result.decision == .prompt)
        #expect(result.grantDurationSeconds == nil)
    }

    @Test("requireJustification without justification forces prompt")
    func justificationGate() {
        let rule = Fixtures.sudoRule(conditions: RuleConditions(requireJustification: true))
        let profile = Fixtures.profile(rules: [rule])
        #expect(evaluate(Fixtures.sudoRequest(), profiles: [profile]).decision == .prompt)
        let justified = Fixtures.sudoRequest(justificationProvided: true)
        #expect(evaluate(justified, profiles: [profile]).decision == .allow)
    }

    @Test("active grant satisfies a prompt rule as a cache hit")
    func grantSatisfies() {
        let rule = Fixtures.sudoRule(id: "prompt-brew", elevation: ElevationBehavior(type: .prompt))
        let grant = Fixtures.grantSnapshot(ruleID: "prompt-brew")
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])],
                              grants: [grant])
        #expect(result.decision == .allow)
        #expect(result.cacheHit)
        #expect(result.satisfyingGrantID == grant.grantID)
    }

    @Test("expired, wrong-user, and wrong-binary grants do not satisfy")
    func grantScoping() {
        let rule = Fixtures.sudoRule(id: "prompt-brew", elevation: ElevationBehavior(type: .prompt))
        let profile = Fixtures.profile(rules: [rule])
        let expired = Fixtures.grantSnapshot(ruleID: "prompt-brew",
                                             expiresAt: Fixtures.now.addingTimeInterval(-1))
        let wrongUser = Fixtures.grantSnapshot(user: "mallory", ruleID: "prompt-brew")
        let wrongBinary = Fixtures.grantSnapshot(ruleID: "prompt-brew",
                                                 binaryHash: "dd" + String(repeating: "0", count: 62))
        for grant in [expired, wrongUser, wrongBinary] {
            let result = evaluate(Fixtures.sudoRequest(), profiles: [profile], grants: [grant])
            #expect(result.decision == .prompt)
            #expect(!result.cacheHit)
        }
    }

    @Test("deny rules ignore grants — deny wins over a live grant")
    func denyBeatsGrant() {
        let deny = Fixtures.sudoRule(id: "deny-brew", action: .deny, priority: 1)
        let allow = Fixtures.sudoRule(id: "allow-brew2", action: .allow, priority: 5)
        let grant = Fixtures.grantSnapshot(ruleID: "allow-brew2")
        let result = evaluate(Fixtures.sudoRequest(),
                              profiles: [Fixtures.profile(rules: [deny, allow])],
                              grants: [grant])
        #expect(result.decision == .deny)
    }

    @Test("trace explains the decision end to end")
    func traceContent() {
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [Fixtures.sudoRule()])])
        #expect(!result.trace.isEmpty)
        #expect(result.trace.first?.detail == "request")
        #expect(result.reason.contains("allow-brew"))
    }
}

@Suite("RuleEngine — cache TTL resolution")
struct CacheTTLTests {
    @Test("per-rule cacheSeconds overrides global")
    func perRuleOverride() {
        let rule = Fixtures.sudoRule(cacheSeconds: 120)
        #expect(RuleEngine.resolvedCacheSeconds(rule: rule, globalCacheSeconds: 600) == 120)
    }

    @Test("nil cacheSeconds falls back to global")
    func globalFallback() {
        let rule = Fixtures.sudoRule(cacheSeconds: nil)
        #expect(RuleEngine.resolvedCacheSeconds(rule: rule, globalCacheSeconds: 600) == 600)
    }

    @Test("zero means never cache; hardcoded default is zero")
    func zeroAndDefault() {
        #expect(RuleEngine.resolvedCacheSeconds(rule: Fixtures.sudoRule(cacheSeconds: 0), globalCacheSeconds: 600) == 0)
        #expect(RuleEngine.resolvedCacheSeconds(rule: Fixtures.sudoRule(), globalCacheSeconds: 0) == 0)
    }

    @Test("deny rules always resolve to zero")
    func denyNeverCached() {
        let rule = Fixtures.sudoRule(action: .deny, cacheSeconds: 600)
        #expect(RuleEngine.resolvedCacheSeconds(rule: rule, globalCacheSeconds: 600) == 0)
    }

    @Test("TTL clamps to 86400")
    func clamp() {
        let rule = Fixtures.sudoRule(cacheSeconds: 999_999)
        #expect(RuleEngine.resolvedCacheSeconds(rule: rule, globalCacheSeconds: 0) == 86_400)
    }
}

/// Deterministic RNG so shuffle-based tests are reproducible.
struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        return state
    }
}

@Suite("RuleEngine — grants match their profile; -1 evaluates every time")
struct RuleEngineGrantScopeTests {
    private func grant(profileKey: String, ruleID: String = "prompt-brew") -> GrantSnapshot {
        GrantSnapshot(grantID: UUID(), user: "alice", ruleID: ruleID, profileKey: profileKey,
                      canonicalPath: "/opt/homebrew/bin/brew", binaryHash: Fixtures.brewIdentity.sha256,
                      expiresAt: nil)
    }

    private func promptRule(duration: Int = 0) -> Rule {
        Fixtures.sudoRule(id: "prompt-brew", conditions: RuleConditions(requireJustification: true,
                                                                       maxGrantDurationSeconds: duration),
                          elevation: ElevationBehavior(type: .prompt))
    }

    @Test("a grant from another profile with the same rule id does not satisfy the request")
    func otherProfileGrantIgnored() {
        let profile = Fixtures.profile(key: "rules_sudo_new", rules: [promptRule()])
        let result = evaluate(Fixtures.sudoRequest(), profiles: [profile],
                              grants: [grant(profileKey: "rules_sudo_old")])
        #expect(!result.cacheHit)
        #expect(result.decision == .prompt)
        // The same profile's grant still does.
        let same = evaluate(Fixtures.sudoRequest(), profiles: [profile],
                            grants: [grant(profileKey: "rules_sudo_new")])
        #expect(same.cacheHit && same.decision == .allow)
    }

    @Test("maxGrantDurationSeconds -1 issues no grant whatever the org default, and ignores existing grants")
    func minusOneNeverGrants() {
        let rule = promptRule(duration: RuleSchemaConstants.neverGrantSeconds)
        #expect(RuleEngine.grantResolution(rule, 28_800, true) == .none)
        #expect(RuleEngine.grantResolution(rule, 28_800, false) == .none)
        let result = evaluate(Fixtures.sudoRequest(), profiles: [Fixtures.profile(rules: [rule])],
                              globalGrantDurationSeconds: 28_800,
                              grants: [grant(profileKey: "rules_sudo_test")])
        #expect(!result.cacheHit)
        #expect(result.decision == .prompt)
        #expect(result.grantDurationSeconds == nil)
    }

    @Test("0 keeps meaning the org default")
    func zeroUsesDefault() {
        #expect(RuleEngine.grantResolution(promptRule(duration: 0), 1_800, true) == .bounded(1_800))
        #expect(RuleEngine.grantResolution(promptRule(duration: 0), 0, true) == .none)
        #expect(RuleEngine.grantResolution(promptRule(duration: 600), 1_800, true) == .bounded(600))
    }
}
