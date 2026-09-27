import Foundation
import Testing
@testable import PrivMgrCore

// MARK: - Fixtures

private enum IdentityFixtures {
    static let postman = AppIdentityBranch(teamID: "H7H8Q7M5CK", bundleID: "com.postmanlabs.mac")
    static let composer = AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer")
    static let daemonsModify = "com.apple.ServiceManagement.daemons.modify"
    static let blesshelper = "com.apple.ServiceManagement.blesshelper"

    static func rule(id: String, right: String, branch: AppIdentityBranch?, action: RuleAction = .allow) -> Rule {
        Rule(id: id, type: .authuri, action: action, description: "", priority: 50,
             match: MatchCriteria(authURI: right), appIdentity: branch)
    }

    static func profile(_ rules: [Rule], key: String = "rules_authuri_test") -> RuleProfile {
        RuleProfile(policyVersion: "1.0.0", profileKey: key, profilePriority: 50, rules: rules)
    }

    /// A right under test, for exercising the provisional path. No SHIPPED
    /// right is provisional any more (both ServiceManagement rights are
    /// verified), so the badge/warning machinery is covered through a
    /// synthetic table rather than by pinning a test to whatever happens to
    /// be unverified today.
    static let underTest = "com.example.right.under.test"
    static let provisionalRegistry = AuthURIIdentityScopeRegistry(entries: [
        AuthURIIdentityScopeEntry(match: .exact(underTest), state: .provisional, verifiedMacOSMajors: nil,
                                  allowedSerials: ["SYNTHSER01"], notes: "under test"),
    ])
}

// MARK: - Scope guard

@Suite("AuthURIIdentityScopeRegistry — four-state scope guard")
struct AuthURIIdentityScopeRegistryTests {
    let registry = AuthURIIdentityScopeRegistry.current

    @Test("seed data: both ServiceManagement rights verified, install rights ineligible, everything else unknown")
    func seedStates() {
        // Both were verified end to end on macOS 27 (2026-09-02): pinned app
        // allowed, non-pinned denied then falling through to native.
        #expect(registry.state(for: IdentityFixtures.daemonsModify) == .verifiedEligible)
        #expect(registry.state(for: IdentityFixtures.blesshelper) == .verifiedEligible)
        #expect(registry.state(for: "com.apple.system.install.software") == .confirmedIneligible)
        #expect(registry.state(for: "system.install.software") == .confirmedIneligible)
        #expect(registry.state(for: "system.install.apple-software") == .confirmedIneligible)   // prefix
        #expect(registry.state(for: "system.preferences.datetime") == .unknown)                 // default = blocked
    }

    @Test("advisory verdict: verified and provisional clean; ineligible and unknown carry a specific warning")
    func authoringDecisions() {
        #expect(registry.authoringDecision(for: IdentityFixtures.daemonsModify).isPermitted)
        #expect(registry.authoringDecision(for: IdentityFixtures.blesshelper).isPermitted)
        // A provisional right is permitted too, but badged.
        let provisional = IdentityFixtures.provisionalRegistry.authoringDecision(for: IdentityFixtures.underTest)
        #expect(provisional.isPermitted)
        #expect(provisional.badge == "Testing — not verified")

        let ineligible = registry.authoringDecision(for: "system.install.software")
        #expect(!ineligible.isPermitted)
        #expect(ineligible.rejectionReason?.contains("confirmed ineligible") == true)
        #expect(ineligible.rejectionReason?.contains("Installer") == true)

        let unknown = registry.authoringDecision(for: "system.preferences.datetime")
        #expect(!unknown.isPermitted)
        #expect(unknown.state == .unknown)
        #expect(unknown.rejectionReason?.contains("not been verified") == true)
        #expect(unknown.rejectionReason?.contains("enforced as authored") == true)
    }

    @Test("verified entries record the macOS majors they were tested on and carry no open question or serial gate")
    func entryMetadata() throws {
        let bless = try #require(registry.entry(for: IdentityFixtures.blesshelper))
        #expect(bless.verifiedMacOSMajors == 27...27)
        #expect(bless.allowedSerials.isEmpty)
        #expect(bless.openQuestion == nil)

        let daemons = try #require(registry.entry(for: IdentityFixtures.daemonsModify))
        #expect(daemons.verifiedMacOSMajors == 26...27)
        // The old "app must not also use SMJobBless" condition was DISPROVEN:
        // Composer uses both rights, and the creator identifies it even on the
        // smd-mediated leg.
        #expect(daemons.authorMustConfirm == nil)

        // A provisional entry is where the serial allow-list lives.
        let underTest = try #require(IdentityFixtures.provisionalRegistry.entry(for: IdentityFixtures.underTest))
        #expect(underTest.allowedSerials == ["SYNTHSER01"])
        #expect(underTest.verifiedMacOSMajors == nil)
    }

    @Test("OS-version warning fires only when the fleet is on a NEWER major than verified")
    func osVersionWarning() {
        #expect(registry.osVersionWarning(for: IdentityFixtures.daemonsModify, fleetMajor: 27) == nil)
        #expect(registry.osVersionWarning(for: IdentityFixtures.daemonsModify, fleetMajor: 26) == nil)
        let warning = registry.osVersionWarning(for: IdentityFixtures.daemonsModify, fleetMajor: 28)
        #expect(warning?.contains("macOS 28 is newer") == true)
        // blesshelper was verified on 27 only, so 28 is newer than its range.
        #expect(registry.osVersionWarning(for: IdentityFixtures.blesshelper, fleetMajor: 27) == nil)
        #expect(registry.osVersionWarning(for: IdentityFixtures.blesshelper, fleetMajor: 28) != nil)
        // No verified range (provisional) or no entry at all → nothing to compare against.
        #expect(IdentityFixtures.provisionalRegistry.osVersionWarning(for: IdentityFixtures.underTest, fleetMajor: 99) == nil)
        #expect(registry.osVersionWarning(for: "system.preferences.datetime", fleetMajor: 99) == nil)
    }

    @Test("exact entries win over prefix entries")
    func exactBeatsPrefix() {
        let table = AuthURIIdentityScopeRegistry(entries: [
            AuthURIIdentityScopeEntry(match: .prefix("a."), state: .confirmedIneligible, verifiedMacOSMajors: nil, notes: "prefix"),
            AuthURIIdentityScopeEntry(match: .exact("a.b"), state: .verifiedEligible, verifiedMacOSMajors: 26...26, notes: "exact"),
        ])
        #expect(table.state(for: "a.b") == .verifiedEligible)
        #expect(table.state(for: "a.c") == .confirmedIneligible)
    }

    @Test("macOS major parsing")
    func majorParsing() {
        #expect(MacOSVersion.major(from: "27.0") == 27)
        #expect(MacOSVersion.major(from: "26.6.2") == 26)
        #expect(MacOSVersion.major(from: "Version 26.6.2 (Build 25G83)") == 26)
        #expect(MacOSVersion.major(from: "") == nil)
        #expect(MacOSVersion.major(from: "beta") == nil)
    }
}

// MARK: - Requirement compiler

@Suite("CodeRequirementCompiler")
struct CodeRequirementCompilerTests {
    @Test("Team ID + bundle ID compile to the designated-requirement core")
    func compiles() throws {
        let requirement = try CodeRequirementCompiler.compile(teamID: "H7H8Q7M5CK", bundleID: "com.postmanlabs.mac")
        #expect(requirement == "identifier \"com.postmanlabs.mac\" and anchor apple generic and certificate leaf[subject.OU] = \"H7H8Q7M5CK\"")
    }

    @Test("format gate rejects malformed pins before any Security call")
    func formatGate() {
        #expect(throws: CodeRequirementError.invalidTeamID("short")) {
            try CodeRequirementCompiler.compile(teamID: "short", bundleID: "com.example.app")
        }
        #expect(throws: CodeRequirementError.invalidTeamID("h7h8q7m5ck")) {
            try CodeRequirementCompiler.compile(teamID: "h7h8q7m5ck", bundleID: "com.example.app")   // lowercase
        }
        #expect(throws: CodeRequirementError.invalidBundleID("com.example.app\" or anchor apple")) {
            try CodeRequirementCompiler.compile(teamID: "H7H8Q7M5CK", bundleID: "com.example.app\" or anchor apple")
        }
        #expect(throws: CodeRequirementError.invalidBundleID("")) {
            try CodeRequirementCompiler.compile(teamID: "H7H8Q7M5CK", bundleID: "")
        }
    }

    @Test("SecRequirementCreateWithString accepts a compiled requirement and rejects garbage")
    func securityValidation() throws {
        let good = try CodeRequirementCompiler.compileAndValidate(IdentityFixtures.postman)
        #expect(good.contains("anchor apple generic"))
        #expect(throws: CodeRequirementError.self) {
            try CodeRequirementCompiler.validate("this is not a requirement ((")
        }
    }
}

// MARK: - Row naming

@Suite("AuthURICompositionNaming")
struct AuthURICompositionNamingTests {
    @Test("rows are namespaced and recognisable; owned rows are extracted from a definition")
    func naming() {
        let right = IdentityFixtures.daemonsModify
        let native = AuthURICompositionNaming.nativeDefaultRow(for: right)
        let app = AuthURICompositionNaming.appRow(for: right, branch: IdentityFixtures.postman)
        #expect(native == "com.herojoneslabs.serberus.branch.\(right).native-default")
        #expect(app == "com.herojoneslabs.serberus.branch.\(right).app.H7H8Q7M5CK.com.postmanlabs.mac")
        #expect(AuthURICompositionNaming.isOwnedRow(app))
        #expect(!AuthURICompositionNaming.isOwnedRow("authenticate-admin"))
        let owned = AuthURICompositionNaming.ownedRows(referencedBy: ["class": "rule", "rule": [app, "authenticate-admin", native]])
        #expect(owned == [app, native])
    }

    @Test("row slug folds unsafe characters so two distinct pins never alias")
    func slug() {
        let odd = AppIdentityBranch(teamID: "ABCDEFGHIJ", bundleID: "com.example.app")
        #expect(odd.rowSlug == "ABCDEFGHIJ.com.example.app")
    }
}

// MARK: - Wire schema

@Suite("Rule.appIdentity wire + Jamf forms")
struct AppIdentityWireTests {
    @Test("JSON round-trip carries appIdentity; a document without it decodes as nil")
    func jsonRoundTrip() throws {
        let rule = IdentityFixtures.rule(id: "r", right: IdentityFixtures.daemonsModify, branch: IdentityFixtures.postman)
        let data = try JSONEncoder().encode(IdentityFixtures.profile([rule]))
        let decoded = try RuleProfile.decode(jsonData: data, expectedKey: "rules_authuri_test")
        #expect(decoded.rules.first?.appIdentity == IdentityFixtures.postman)
        #expect(decoded.rules.first?.isIdentityScoped == true)

        let legacy = """
        {"schemaVersion":"1.0","policyVersion":"1.0.0","profileKey":"rules_authuri_test","profilePriority":50,
         "rules":[{"id":"r","type":"authuri","action":"allow","description":"","priority":50,
                   "match":{"authURI":"system.preferences.datetime"},
                   "conditions":{"requireJustification":false,"maxGrantDurationSeconds":0},
                   "elevation":{"type":"silent","notify":false,"logArguments":true}}]}
        """
        let old = try RuleProfile.decode(jsonString: legacy, expectedKey: "rules_authuri_test")
        #expect(old.rules.first?.appIdentity == nil)
    }

    @Test("Jamf flat dictionary: the three app keys travel together")
    func managedDictionary() throws {
        let full: [String: Any] = [
            "id": "postman", "type": "authuri", "action": "allow",
            "authURI": IdentityFixtures.daemonsModify,
            "appTeamID": "H7H8Q7M5CK", "appBundleID": "com.postmanlabs.mac",
        ]
        guard case let .rule(rule) = Rule.fromManagedDictionary(full) else { Issue.record("expected a rule"); return }
        #expect(rule.appIdentity == IdentityFixtures.postman)

        let half: [String: Any] = ["id": "p", "type": "authuri", "action": "allow", "authURI": "x", "appTeamID": "H7H8Q7M5CK"]
        guard case let .invalid(reason) = Rule.fromManagedDictionary(half) else { Issue.record("expected invalid"); return }
        #expect(reason.contains("BOTH"))

        // The exact Jamf row from the test Mac (team + bundle, nothing else).
        let jamfRow: [String: Any] = ["id": "allow_composer_helper_bless", "type": "authuri", "action": "allow",
                                      "authURI": "com.apple.ServiceManagement.blesshelper", "elevationType": "silent",
                                      "appTeamID": "483DWKW443", "appBundleID": "com.jamfsoftware.Composer"]
        guard case let .rule(composer) = Rule.fromManagedDictionary(jamfRow) else { Issue.record("expected a rule"); return }
        #expect(composer.appIdentity == AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer"))

        // A legacy row that still carries appPosture is accepted; the key is ignored.
        var legacy = jamfRow; legacy["appPosture"] = "allow"
        guard case .rule = Rule.fromManagedDictionary(legacy) else { Issue.record("expected a rule"); return }

        let onSudo: [String: Any] = ["id": "p", "type": "sudo", "action": "allow", "commandPattern": "/bin/ls",
                                     "appTeamID": "H7H8Q7M5CK", "appBundleID": "b"]
        guard case let .invalid(reason3) = Rule.fromManagedDictionary(onSudo) else { Issue.record("expected invalid"); return }
        #expect(reason3.contains("authuri rules only"))
    }

    @Test("Jamf native dictionary emits the app keys and round-trips through the flat parser")
    func nativeDictionaryRoundTrip() {
        let rule = IdentityFixtures.rule(id: "postman", right: IdentityFixtures.daemonsModify, branch: IdentityFixtures.postman)
        let dict = JamfRulesSchema.nativeDictionary(for: rule)
        #expect(dict["appTeamID"] as? String == "H7H8Q7M5CK")
        #expect(dict["appBundleID"] as? String == "com.postmanlabs.mac")
        #expect(dict["appPosture"] == nil)
        guard case let .rule(parsed) = Rule.fromManagedDictionary(dict) else { Issue.record("expected a rule"); return }
        #expect(parsed.appIdentity == rule.appIdentity)
        #expect(!JamfRulesSchema.templateJSON.contains("\"appPosture\""))
    }
}

// MARK: - Validator

@Suite("PolicyValidator — identity-scoped checks")
struct AppIdentityValidatorTests {
    @Test("a verified right with a valid pin is clean; an unknown right is a WARNING, never an error")
    func verificationInValidator() {
        let ok = IdentityFixtures.profile([IdentityFixtures.rule(id: "ok", right: IdentityFixtures.daemonsModify, branch: IdentityFixtures.postman)])
        #expect(PolicyValidator().validate(ok).issues.filter { $0.check == "app-identity-scope" }.isEmpty)

        let unverified = IdentityFixtures.profile([IdentityFixtures.rule(id: "no", right: "system.preferences.datetime", branch: IdentityFixtures.postman)])
        let report = PolicyValidator().validate(unverified)
        // The only error is the release switch; the verification table
        // itself never errors.
        #expect(report.errors.map(\.check) == ["app-identity-disabled"])
        #expect(report.warnings.contains { $0.check == "app-identity-scope" })
        #expect(!report.isExportable)
    }

    @Test("a provisional right is a warning carrying the badge and the Mac(s) it is under test on")
    func provisionalWarning() {
        let rule = IdentityFixtures.rule(id: "p", right: IdentityFixtures.underTest, branch: IdentityFixtures.composer)
        let issues = PolicyValidator.validateIdentityBranch(
            IdentityFixtures.composer, right: IdentityFixtures.underTest, rule: rule,
            registry: IdentityFixtures.provisionalRegistry)
        let warning = issues.first { $0.check == "app-identity-scope" }
        #expect(warning?.severity == .warning)
        #expect(warning?.message.contains("Testing — not verified") == true)
        #expect(warning?.message.contains("SYNTHSER01") == true)

        // A verified right produces no scope finding at all.
        let verified = IdentityFixtures.profile([IdentityFixtures.rule(id: "v", right: IdentityFixtures.blesshelper, branch: IdentityFixtures.composer)])
        let report = PolicyValidator().validate(verified)
        #expect(report.issues.filter { $0.check == "app-identity-scope" }.isEmpty)
        #expect(report.errors.map(\.check) == ["app-identity-disabled"])   // release switch only
    }

    @Test("the verification warning is reported on the right, even when the pin is ALSO malformed")
    func verificationReportedIndependently() {
        let bad = AppIdentityBranch(teamID: "nope", bundleID: "x")
        let profile = IdentityFixtures.profile([IdentityFixtures.rule(id: "bad", right: "system.install.software", branch: bad)])
        let checks = Set(PolicyValidator().validate(profile).issues.map(\.check))
        #expect(checks.contains("app-identity-scope"))
        #expect(checks.contains("app-identity"))
    }

    @Test("mixing a plain rule and app branches on one right is an error; duplicate pins are an error; deny is an error")
    func compositionShape() {
        let right = IdentityFixtures.daemonsModify
        let mixed = IdentityFixtures.profile([
            IdentityFixtures.rule(id: "plain", right: right, branch: nil),
            IdentityFixtures.rule(id: "app", right: right, branch: IdentityFixtures.postman),
        ])
        #expect(PolicyValidator().validate(mixed).errors.contains { $0.check == "app-identity-mix" })

        let dup = IdentityFixtures.profile([
            IdentityFixtures.rule(id: "a", right: right, branch: IdentityFixtures.postman),
            IdentityFixtures.rule(id: "b", right: right, branch: IdentityFixtures.postman),
        ])
        #expect(PolicyValidator().validate(dup).errors.contains { $0.check == "app-identity-duplicate" })

        let deny = IdentityFixtures.profile([IdentityFixtures.rule(id: "deny", right: right, branch: IdentityFixtures.postman, action: .deny)])
        #expect(PolicyValidator().validate(deny).errors.contains { $0.check == "app-identity" })
    }
}

// MARK: - Engine + simulator

@Suite("RuleEngine / DecisionSimulator — identity-scoped rights")
struct AppIdentitySimulatorTests {
    private func context(right: String, teamID: String) -> SimulationContext {
        SimulationContext(user: "alice", uid: 501, authURI: right, sudoCommand: nil,
                          executablePath: "/Applications/Postman.app/Contents/MacOS/Postman",
                          teamID: teamID, binaryHash: "", signingStatus: .valid, currentTime: Date())
    }

    @Test("the engine pins the Team ID; the simulator adds the syntax-only caveat")
    func teamPinAndCaveat() throws {
        let profiles = [IdentityFixtures.profile([IdentityFixtures.rule(id: "postman", right: IdentityFixtures.daemonsModify, branch: IdentityFixtures.postman)])]
        let match = try DecisionSimulator(perAppPinsEnabled: true).simulate(context: context(right: IdentityFixtures.daemonsModify, teamID: "H7H8Q7M5CK"), profiles: profiles)
        #expect(match.decision == .allow)
        #expect(match.matchedRule == "postman")
        #expect(match.warnings.contains { $0.contains("Only the SYNTAX is checked") })
        // No app-condition caveat any more: the SMJobBless concern was disproven.
        #expect(!match.warnings.contains { $0.contains("SMJobBless") })

        let other = try DecisionSimulator(perAppPinsEnabled: true).simulate(context: context(right: IdentityFixtures.daemonsModify, teamID: "OTHER00000"), profiles: profiles)
        #expect(other.decision == .deny)   // no rule matched → fail closed
    }

    @Test("a provisional right adds the eligibility-unconfirmed caveat")
    func provisionalCaveat() {
        let profiles = [IdentityFixtures.profile([IdentityFixtures.rule(id: "c", right: IdentityFixtures.underTest, branch: IdentityFixtures.composer)])]
        let caveats = DecisionSimulator.identityCaveats(right: IdentityFixtures.underTest, profiles: profiles,
                                                        registry: IdentityFixtures.provisionalRegistry,
                                                        perAppPinsEnabled: true)
        #expect(caveats.contains { $0.contains("Testing — not verified") && $0.contains("unconfirmed") })
        // A verified right still gets the syntax-only caveat, but no badge.
        let verified = [IdentityFixtures.profile([IdentityFixtures.rule(id: "v", right: IdentityFixtures.blesshelper, branch: IdentityFixtures.composer)])]
        let plain = DecisionSimulator.identityCaveats(right: IdentityFixtures.blesshelper, profiles: verified,
                                                      perAppPinsEnabled: true)
        #expect(plain.contains { $0.contains("Only the SYNTAX is checked") })
        #expect(!plain.contains { $0.contains("Testing — not verified") })
    }

    @Test("a right with no identity rules gets no caveats")
    func noCaveatsForPlainRight() throws {
        let profiles = [IdentityFixtures.profile([IdentityFixtures.rule(id: "plain", right: "system.preferences.datetime", branch: nil)])]
        let result = try DecisionSimulator().simulate(context: context(right: "system.preferences.datetime", teamID: ""), profiles: profiles)
        #expect(!result.warnings.contains { $0.contains("Per-app branch") })
    }
}

// MARK: - Branch resolver

@Suite("BranchMatchResolver")
struct BranchMatchResolverTests {
    @Test("predicts the first satisfied app branch, else native-default; nothing when the right is not composed")
    func prediction() {
        let right = IdentityFixtures.daemonsModify
        let profiles = [IdentityFixtures.profile([
            IdentityFixtures.rule(id: "postman", right: right, branch: IdentityFixtures.postman),
            IdentityFixtures.rule(id: "composer", right: right, branch: IdentityFixtures.composer),
        ])]
        let candidates = BranchMatchResolver.candidates(forRight: right, in: profiles)
        #expect(candidates.count == 2)

        let resolver = BranchMatchResolver { path, requirement in
            path.contains("Postman") && requirement.contains("com.postmanlabs.mac")
        }
        #expect(resolver.predictedBranch(clientPath: "/Applications/Postman.app", candidates: candidates)
                == AuthURICompositionNaming.appRow(for: right, branch: IdentityFixtures.postman))
        #expect(resolver.predictedBranch(clientPath: "/usr/libexec/smd", candidates: candidates) == BranchMatchResolver.nativeDefault)
        #expect(resolver.predictedBranch(clientPath: nil, candidates: candidates) == nil)
        #expect(resolver.predictedBranch(clientPath: "/usr/libexec/smd", candidates: []) == nil)
    }

    @Test("evidence keeps only lines naming a branch row")
    func evidence() {
        let row = AuthURICompositionNaming.appRow(for: "r", branch: IdentityFixtures.postman)
        let lines = ["Succeeded authorizing right 'r' by client '/Applications/Postman.app' [1]", "engine 4: evaluating rule '\(row)'"]
        #expect(BranchMatchResolver.evidence(in: lines) == [lines[1]])
    }
}

// MARK: - Per-app pins disabled in production

@Suite("Per-app (App Identity) rules disabled in 0.9.0")
struct PerAppPinsDisabledTests {
    static let message = "Per-app (App Identity) rules are disabled in Serberus 0.9.0 because the app's identity comes from a value the requesting process can forge, so this rule would never take effect and the right keeps its native definition."

    @Test("the validator reports a pin as an ERROR, so the profile is not exportable")
    func validatorRefusesPin() {
        let pin = IdentityFixtures.rule(id: "composer", right: IdentityFixtures.blesshelper, branch: IdentityFixtures.composer)
        let issues = PolicyValidator.validate(rule: pin, expectedType: .authuri)
        let disabled = issues.filter { $0.check == "app-identity-disabled" }
        #expect(disabled.count == 1)
        #expect(disabled.first?.severity == .error)
        #expect(disabled.first?.message == Self.message)

        let report = PolicyValidator().validate(IdentityFixtures.profile([pin]))
        #expect(report.errors.contains { $0.check == "app-identity-disabled" && $0.ruleID == "composer" })
        #expect(!report.isExportable)
    }

    @Test("a plain authuri rule and a sudo-free profile get no app-identity-disabled error")
    func validatorLeavesPlainRules() {
        let plain = IdentityFixtures.rule(id: "dt", right: "system.preferences.datetime", branch: nil)
        #expect(!PolicyValidator.validate(rule: plain, expectedType: .authuri).contains { $0.check == "app-identity-disabled" })
    }

    @Test("the decision simulator never reports a pin as allowing, and says why")
    func simulatorNeverAllowsPin() throws {
        let profiles = [IdentityFixtures.profile([IdentityFixtures.rule(id: "postman", right: IdentityFixtures.daemonsModify, branch: IdentityFixtures.postman)])]
        let context = SimulationContext(user: "alice", uid: 501, authURI: IdentityFixtures.daemonsModify, sudoCommand: nil,
                                        executablePath: "/Applications/Postman.app/Contents/MacOS/Postman",
                                        teamID: "H7H8Q7M5CK", binaryHash: "", signingStatus: .valid, currentTime: Date())
        let result = try DecisionSimulator().simulate(context: context, profiles: profiles)
        #expect(result.decision == .deny)
        #expect(result.matchedRule == nil)
        #expect(result.warnings.contains { $0.contains("disabled in Serberus 0.9.0") && $0.contains("can forge") })
    }
}
