import Foundation
import Testing
@testable import PrivMgrCore

@Suite("SentinelRuleSummary")
struct SentinelRuleSummaryTests {
    private func rule(
        id: String = "r1",
        type: RuleType = .authuri,
        action: RuleAction = .allow,
        description: String = "Change network settings",
        elevationType: ElevationType = .silent,
        authURI: String? = "system.preferences.network",
        commandPattern: String? = nil,
        matchType: MatchType? = nil
    ) -> Rule {
        Rule(
            id: id, type: type, action: action, description: description, priority: 50,
            match: MatchCriteria(authURI: authURI, commandPattern: commandPattern, matchType: matchType),
            elevation: ElevationBehavior(type: elevationType)
        )
    }

    @Test("decisions map by user-visible behavior in enforce mode")
    func enforceDecisions() {
        #expect(SentinelRuleSummary.decision(for: rule(action: .deny), mode: .enforce) == .deny)
        #expect(SentinelRuleSummary.decision(for: rule(elevationType: .prompt), mode: .enforce) == .prompt)
        #expect(SentinelRuleSummary.decision(for: rule(elevationType: .silent), mode: .enforce) == .allow)
    }

    @Test("audit and monitor modes collapse every rule to silent — nothing is actually enforced")
    func nonEnforceModesAreSilent() {
        for mode in [EnforcementMode.audit, .monitor] {
            #expect(SentinelRuleSummary.decision(for: rule(action: .deny), mode: mode) == .silent)
            #expect(SentinelRuleSummary.decision(for: rule(elevationType: .prompt), mode: mode) == .silent)
            #expect(SentinelRuleSummary.decision(for: rule(elevationType: .silent), mode: mode) == .silent)
        }
    }

    @Test("title uses the description; falls back to the match target")
    func titles() {
        #expect(SentinelRuleSummary.title(for: rule()) == "Change network settings")
        #expect(SentinelRuleSummary.title(for: rule(description: "  ")) == "system.preferences.network")
        #expect(SentinelRuleSummary.title(for: rule(
            type: .sudo, description: "", authURI: nil,
            commandPattern: "/opt/homebrew/bin/brew"
        )) == "sudo brew")
        #expect(SentinelRuleSummary.title(for: rule(
            type: .sudo, description: "", authURI: nil, matchType: .any
        )) == "sudo (any command)")
    }

    @Test("detail shows the right or the sudo command pattern")
    func details() {
        #expect(SentinelRuleSummary.detail(for: rule()) == "system.preferences.network")
        #expect(SentinelRuleSummary.detail(for: rule(
            type: .sudo, authURI: nil, commandPattern: "/usr/bin/systemsetup"
        )) == "sudo · /usr/bin/systemsetup")
        #expect(SentinelRuleSummary.detail(for: rule(
            type: .sudo, authURI: nil, matchType: .any
        )) == "sudo · all commands")
    }

    @Test("id is unique across profiles sharing rule ids; version rides per rule")
    func identity() {
        let profileA = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_a",
                                   profilePriority: 10, rules: [])
        let profileB = RuleProfile(policyVersion: "2.0.0", profileKey: "rules_authuri_b",
                                   profilePriority: 20, rules: [])
        let a = SentinelRuleSummary(rule: rule(), profile: profileA, mode: .enforce)
        let b = SentinelRuleSummary(rule: rule(), profile: profileB, mode: .enforce)
        #expect(a.id != b.id)
        #expect(a.policyVersion == "1.0.0")
        #expect(b.policyVersion == "2.0.0")
    }
}

@Suite("SentinelRulesSnapshot")
struct SentinelRulesSnapshotTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func profile(key: String, priority: Int, version: String = "1.0.0", rules: [Rule]) -> RuleProfile {
        RuleProfile(policyVersion: version, profileKey: key, profilePriority: priority, rules: rules)
    }

    private func rule(id: String, priority: Int) -> Rule {
        Rule(id: id, type: .authuri, action: .allow, description: id, priority: priority,
             match: MatchCriteria(authURI: "system.test.\(id)"))
    }

    @Test("rules order by profile priority then rule priority — evaluation order")
    func ordering() {
        let snapshot = SentinelRulesSnapshot(
            profiles: [
                profile(key: "rules_authuri_b", priority: 20, rules: [rule(id: "b2", priority: 60), rule(id: "b1", priority: 10)]),
                profile(key: "rules_authuri_a", priority: 10, version: "2.0.0", rules: [rule(id: "a1", priority: 50)]),
            ],
            enforcementMode: .enforce,
            generatedAt: now
        )
        #expect(snapshot.rules.map(\.ruleID) == ["a1", "b1", "b2"])
        #expect(snapshot.profileKeys == ["rules_authuri_a", "rules_authuri_b"])
        // Representative version comes from the highest-priority profile.
        #expect(snapshot.policyVersion == "2.0.0")
    }

    @Test("round-trips through the XPC coding used on the wire")
    func codableRoundTrip() throws {
        let snapshot = SentinelRulesSnapshot(
            profiles: [profile(key: "rules_authuri_a", priority: 10, rules: [rule(id: "a1", priority: 1)])],
            enforcementMode: .audit,
            generatedAt: now
        )
        let data = try SerberusXPCCoding.encode(snapshot)
        let decoded = try SerberusXPCCoding.decode(SentinelRulesSnapshot.self, from: data)
        #expect(decoded == snapshot)
    }

    @Test("empty profiles produce the empty snapshot shape")
    func empty() {
        let snapshot = SentinelRulesSnapshot(profiles: [], enforcementMode: .enforce, generatedAt: now)
        #expect(snapshot.rules.isEmpty)
        #expect(snapshot.policyVersion == nil)
    }

    @Test("cached snapshots written before per-rule policyVersion still decode")
    func decodesLegacyCachedSnapshot() throws {
        let legacyJSON = """
        {"enforcementMode":"enforce","generatedAt":"2026-06-12T00:00:00Z",
        "profileKeys":["rules_authuri_a"],"policyVersion":"1.0.0",
        "rules":[{"ruleID":"a1","profileKey":"rules_authuri_a","title":"t",
        "detail":"system.test.a1","type":"authuri","decision":"allow"}]}
        """
        let decoded = try SerberusXPCCoding.decode(SentinelRulesSnapshot.self, from: Data(legacyJSON.utf8))
        #expect(decoded.rules.first?.policyVersion == nil)
        #expect(decoded.rules.first?.ruleID == "a1")
    }
}

@Suite("PromptContext request row")
struct PromptContextRequestRowTests {
    private func context(request: String) -> PromptContext {
        PromptContext(
            user: "alice", processName: "x", canonicalPath: "/bin/x",
            teamID: nil, signingStatus: .valid, humanReadableRequest: request,
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60
        )
    }

    @Test("authURI requests render as a bare RIGHT row")
    func authURIRow() {
        let ctx = context(request: PromptContext.authURIRequestPrefix + "system.preferences.network")
        #expect(ctx.isAuthURIRequest)
        #expect(ctx.requestRowLabel == "Right")
        #expect(ctx.requestRowValue == "system.preferences.network")
    }

    @Test("sudo requests render as a full COMMAND row")
    func sudoRow() {
        let ctx = context(request: "sudo /opt/homebrew/bin/brew install wget")
        #expect(!ctx.isAuthURIRequest)
        #expect(ctx.requestRowLabel == "Command")
        #expect(ctx.requestRowValue == "sudo /opt/homebrew/bin/brew install wget")
    }

    @Test("the COMMAND row shows hidden characters as escapes, even from an older daemon")
    func sudoRowEscapesHiddenCharacters() {
        // An older daemon sends the line raw; rendered as is, it reads
        // "…/Users/Shared/IT-approved-evil.pkg -target /".
        let spoof = context(
            request: "sudo /usr/sbin/installer -pkg /Users/Shared/IT-approved-\u{202E}gkp.live\u{202C} -target /"
        )
        #expect(spoof.requestRowLabel == "Command")
        #expect(spoof.requestRowValue
                == #"sudo /usr/sbin/installer -pkg /Users/Shared/IT-approved-\u{202E}gkp.live\u{202C} -target /"#)

        let hidden = context(
            request: "sudo /bin/cat /etc/pass\u{200B}wd\n/etc/hosts\t\u{0085}\u{00A0}\u{3000}\u{00AD}\u{3164}\u{E0041}"
        )
        #expect(hidden.requestRowValue
                == #"sudo /bin/cat /etc/pass\u{200B}wd\n/etc/hosts\t\u{0085}\u{00A0}\u{3000}\u{00AD}\u{3164}\u{E0041}"#)

        // Shown whole, however long.
        let long = "sudo /bin/echo " + String(repeating: "a", count: 4_000)
        #expect(context(request: long + "\u{2066}").requestRowValue == long + #"\u{2066}"#)
    }

    @Test("a line a current daemon already escaped shows unchanged")
    func escapedRowIsStable() {
        let line = #"sudo /bin/echo IT-approved-\u{202E}gkp.live\u{202C}\nreboot"#
        #expect(context(request: line).requestRowValue == line)
    }

    @Test("the RIGHT row, and the rule name that falls back to it, show hidden characters as escapes")
    func authURIRowEscapesHiddenCharacters() {
        let ctx = context(request: PromptContext.authURIRequestPrefix + "system.preferences\u{202E}krowten.\u{200B}\n")
        #expect(ctx.isAuthURIRequest)
        #expect(ctx.requestRowLabel == "Right")
        #expect(ctx.requestRowValue == #"system.preferences\u{202E}krowten.\u{200B}\n"#)
        #expect(ctx.ruleDisplayName == ctx.requestRowValue)
    }

    @Test("ruleDisplayName prefers the description, falling back like the rules list")
    func ruleDisplayName() {
        // Described rule → the description verbatim (same as the list title).
        let described = PromptContext(
            user: "a", processName: "jamf", canonicalPath: "/usr/local/jamf/bin/jamf",
            teamID: nil, signingStatus: .valid, humanReadableRequest: "sudo /usr/local/jamf/bin/jamf log",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60,
            ruleName: "jamf_custom_rules · r1", ruleDescription: "Collect Jamf logs"
        )
        #expect(described.ruleDisplayName == "Collect Jamf logs")

        // Description-less sudo rule → "sudo <binary>", matching the list fallback.
        let sudoNoDesc = PromptContext(
            user: "a", processName: "jamf", canonicalPath: "/usr/local/jamf/bin/jamf",
            teamID: nil, signingStatus: .valid, humanReadableRequest: "sudo /usr/local/jamf/bin/jamf log",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60,
            ruleName: "jamf_custom_rules · r1", ruleDescription: "  "
        )
        #expect(sudoNoDesc.ruleDisplayName == "sudo jamf")

        // Description-less authURI rule → the bare right.
        let authNoDesc = PromptContext(
            user: "a", processName: "System Settings", canonicalPath: "/System/Applications/System Settings.app",
            teamID: nil, signingStatus: .valid,
            humanReadableRequest: PromptContext.authURIRequestPrefix + "system.preferences.datetime",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60
        )
        #expect(authNoDesc.ruleDisplayName == "system.preferences.datetime")
    }
}

@Suite("PromptContext wire compatibility")
struct PromptContextWireTests {
    @Test("payloads without the rule fields still decode — older daemons")
    func decodesLegacyPayload() throws {
        let legacyJSON = """
        {"canonicalPath":"/bin/x","humanReadableRequest":"sudo /bin/x","justificationMinLength":0,
        "processName":"x","requestID":"00000000-0000-0000-0000-000000000001",
        "requireJustification":false,"signingStatus":"valid","timeoutSeconds":60,"user":"alice"}
        """
        let context = try SerberusXPCCoding.decode(PromptContext.self, from: Data(legacyJSON.utf8))
        #expect(context.ruleName == nil)
        #expect(context.ruleDescription == nil)
        #expect(context.user == "alice")
    }

    @Test("rule fields round-trip when present")
    func roundTripsRuleFields() throws {
        let context = PromptContext(
            user: "alice", processName: "System Settings",
            canonicalPath: "/System/Applications/System Settings.app",
            teamID: nil, signingStatus: .valid,
            humanReadableRequest: "Authorization right: system.preferences.network",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60,
            ruleName: "rules_authuri_standard · net", ruleDescription: "Change network settings"
        )
        let data = try SerberusXPCCoding.encode(context)
        let decoded = try SerberusXPCCoding.decode(PromptContext.self, from: data)
        #expect(decoded == context)
    }
}
