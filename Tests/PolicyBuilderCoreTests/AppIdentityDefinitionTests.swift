import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

/// App Identity as a DEFINITION kind: a `.authuri` definition pinned to one
/// app, compiled into an identity-scoped wire rule whose posture follows the
/// referencing rule's decision.
@Suite("App Identity definitions")
struct AppIdentityDefinitionTests {
    static let now = Date(timeIntervalSince1970: 1_781_222_400)
    static let daemonsModify = "com.apple.ServiceManagement.daemons.modify"
    static let bless = "com.apple.ServiceManagement.blesshelper"

    private func policy(id: String = "svc", ruleIDs: [String]) -> Policy {
        Policy(id: id, name: "Services", rules: ruleIDs.map { PolicyRuleAssignment(ruleID: $0) },
               createdAt: Self.now, updatedAt: Self.now)
    }

    private func postman(id: String = "postman_daemons", right: String = AppIdentityDefinitionTests.daemonsModify,
                         bundle: String? = "com.postmanlabs.mac") -> RuleDefinition {
        RuleDefinition(id: id, name: "Postman", kind: .authuri, authURI: right,
                       appTeamID: "H7H8Q7M5CK", appBundleID: bundle, createdAt: Self.now, updatedAt: Self.now)
    }

    private func rule(id: String = "allow_postman", definitionIDs: [String], action: RuleAction = .allow,
                      elevation: ElevationType = .silent) -> PolicyRule {
        PolicyRule(id: id, name: id, definitionIDs: definitionIDs, action: action, elevationType: elevation,
                   createdAt: Self.now, updatedAt: Self.now)
    }

    @Test("authoring kind derives from the app fields; wire kind stays authuri")
    func authoringKind() {
        #expect(postman().authoringKind == .appIdentity)
        #expect(postman().kind == .authuri)
        #expect(postman(bundle: nil).authoringKind == .authuri)
        #expect(RuleDefinition(id: "s", name: "s", kind: .sudo, commandPattern: "/bin/ls").authoringKind == .sudo)
        #expect(DefinitionKind.appIdentity.wireType == .authuri)
    }

    @Test("compiles to an identity-scoped wire rule (team + bundle; the branch is always session-owner-or-admin)")
    func compilesBranch() {
        let definitions = [postman()]
        let silent = PolicyCompiler().compile(policy(ruleIDs: ["allow_postman"]),
                                              rules: [rule(definitionIDs: ["postman_daemons"])], definitions: definitions)
        let wire = silent[0].rules[0]
        #expect(silent[0].profileKey == "rules_authuri_svc")
        #expect(wire.id == "allow_postman__postman_daemons")
        #expect(wire.match.authURI == Self.daemonsModify)
        #expect(wire.appIdentity == AppIdentityBranch(teamID: "H7H8Q7M5CK", bundleID: "com.postmanlabs.mac"))
        // The only error is the release switch (per-app rules disabled).
        #expect(PolicyValidator().validate(silent[0]).errors.map(\.check) == ["app-identity-disabled"])

        // silent vs prompt on the rule does not change the branch.
        let prompt = PolicyCompiler().compile(policy(ruleIDs: ["allow_postman"]),
                                              rules: [rule(definitionIDs: ["postman_daemons"], elevation: .prompt)], definitions: definitions)
        #expect(prompt[0].rules[0].appIdentity == wire.appIdentity)

        // A plain authuri definition never carries a branch.
        let plain = PolicyCompiler().compile(policy(ruleIDs: ["r"]),
                                             rules: [rule(id: "r", definitionIDs: ["dt"])],
                                             definitions: [RuleDefinition(id: "dt", name: "dt", kind: .authuri, authURI: "system.preferences.datetime")])
        #expect(plain[0].rules[0].appIdentity == nil)
    }

    @Test("a deny rule on an App Identity definition is a validation error")
    func denyRejected() {
        let profiles = PolicyCompiler().compile(policy(ruleIDs: ["deny"]),
                                                rules: [rule(id: "deny", definitionIDs: ["postman_daemons"], action: .deny)],
                                                definitions: [postman()])
        #expect(PolicyValidator().validate(profiles[0]).errors.contains { $0.check == "app-identity" })
    }

    @Test("a plain allow on an identity-only right is warned (still exportable); a plain deny is silent")
    func plainAllowWarned() {
        let plain = RuleDefinition(id: "dm", name: "dm", kind: .authuri, authURI: Self.daemonsModify)
        let allow = PolicyCompiler().compile(policy(ruleIDs: ["a"]), rules: [rule(id: "a", definitionIDs: ["dm"])], definitions: [plain])
        let report = PolicyValidator().validate(allow[0])
        #expect(report.warnings.contains { $0.check == "app-identity-required" })
        #expect(report.isExportable)
        let deny = PolicyCompiler().compile(policy(ruleIDs: ["d"]), rules: [rule(id: "d", definitionIDs: ["dm"], action: .deny)], definitions: [plain])
        #expect(!PolicyValidator().validate(deny[0]).issues.contains { $0.check == "app-identity-required" })
        #expect(AuthURIIdentityScopeRegistry.current.identityOnlyRights == [Self.bless, Self.daemonsModify])
    }

    @Test("draft round-trip keeps the app pin and never emits the generic pins for App Identity")
    func draftRoundTrip() {
        var draft = DefinitionDraft(definitionID: "postman", kind: .authuri, name: "Postman", authURI: Self.daemonsModify,
                                    requiredTeamID: "IGNORED000", requiredBinaryHash: "cafe")
        draft.authoringKind = .appIdentity
        draft.appTeamID = "h7h8q7m5ck"
        draft.appBundleID = " com.postmanlabs.mac "
        let definition = draft.toDefinition()
        #expect(definition.isAppIdentity)
        #expect(definition.appTeamID == "H7H8Q7M5CK")   // uppercased + trimmed
        #expect(definition.appBundleID == "com.postmanlabs.mac")
        #expect(definition.requiredTeamID == nil)
        #expect(definition.requiredBinaryHash == nil)
        let back = DefinitionDraft(definition: definition)
        #expect(back.authoringKind == .appIdentity)
        #expect(back.appBundleID == "com.postmanlabs.mac")

        draft.authoringKind = .authuri
        #expect(!draft.toDefinition().isAppIdentity)
        draft.authoringKind = .sudo
        #expect(draft.kind == .sudo)
    }

    @Test("a half-filled App Identity draft stays App Identity and reports the missing bundle ID")
    func halfFilled() {
        var draft = DefinitionDraft(kind: .authuri, name: "x", authURI: Self.daemonsModify)
        draft.authoringKind = .appIdentity
        draft.appTeamID = "H7H8Q7M5CK"
        let definition = draft.toDefinition()
        #expect(definition.isAppIdentity)
        let scratch = Rule(id: "d", type: .authuri, action: .allow, description: "", priority: 50,
                           match: definition.matchCriteria(),
                           appIdentity: definition.appIdentityBranch())
        #expect(PolicyValidator.validate(rule: scratch, expectedType: nil).contains { $0.check == "app-identity" && $0.message.contains("Bundle ID") })
    }

    @Test("library file round-trips the app fields; an older file decodes them as nil")
    func libraryRoundTrip() throws {
        let file = PolicyLibraryFile(definitions: [postman()])
        let decoded = try JSONDecoder().decode(PolicyLibraryFile.self, from: try JSONEncoder().encode(file))
        #expect(decoded.definitions[0].appBundleID == "com.postmanlabs.mac")
        let old = """
        {"schemaVersion":2,"definitions":[{"id":"dt","name":"dt","detail":"","kind":"authuri","authURI":"system.preferences.datetime",
          "createdAt":0,"updatedAt":0}],"rules":[],"policies":[]}
        """
        let legacy = try JSONDecoder().decode(PolicyLibraryFile.self, from: Data(old.utf8))
        #expect(legacy.definitions[0].authoringKind == .authuri)
    }

    @Test("capture import drafts an identity-only right as App Identity with the captured Team ID")
    func captureImport() {
        let attempt = CapturedAttempt(id: "1", kind: .authuri, timestamp: Self.now, user: "tuser",
                                      authURI: Self.daemonsModify, clientPath: "/Applications/Postman.app",
                                      teamID: "H7H8Q7M5CK", outcome: .granted, rawLines: [])
        let draft = CaptureImporter.draft(for: attempt, existingIDs: [])
        #expect(draft.authoringKind == .appIdentity)
        #expect(draft.appTeamID == "H7H8Q7M5CK")
        #expect(draft.appBundleID == "")
        let other = CapturedAttempt(id: "2", kind: .authuri, timestamp: Self.now, user: "tuser",
                                    authURI: "system.preferences.datetime", teamID: "H7H8Q7M5CK", outcome: .granted, rawLines: [])
        #expect(CaptureImporter.draft(for: other, existingIDs: []).authoringKind == .authuri)
    }

    @MainActor
    @Test("model helpers: provisional rules are surfaced for warnings, never block publish")
    func modelHelpers() {
        let model = PolicyBuilderModel(
            policies: [policy(ruleIDs: ["allow_composer"])],
            rules: [rule(id: "allow_composer", definitionIDs: ["composer"])],
            definitions: [RuleDefinition(id: "composer", name: "Composer", kind: .authuri, authURI: Self.bless,
                                         appTeamID: "483DWKW443", appBundleID: "com.jamfsoftware.Composer")])
        #expect(model.appIdentityDefinitions.map(\.id) == ["composer"])
        // Both ServiceManagement rights are verified now (live-tested
        // 2026-09-02), so nothing in this policy is provisional.
        #expect(model.provisionalAppIdentityRules(inPolicy: "svc").isEmpty)
        #expect(model.appIdentityScopeDecision(forRight: Self.bless).state == .verifiedEligible)
        #expect(!model.appIdentityScopeDecision(forRight: "system.preferences.datetime").isPermitted)
        // Direct publish is gated only by the commanderPublishEnabled profile key, never by verification state.
        #expect(model.publishBlocker(id: "svc")?.contains("Direct publish is off") == true)
        #expect(!model.riskSignals().contains { $0.kind == .unpinned })
    }
}
