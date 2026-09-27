import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

/// Per-branch instrumentation on composed (identity-scoped) rights: the
/// Capture predicts which branch the logged client satisfies and keeps any
/// authd line that names a branch row.
@Suite("CaptureBuilder — composed-right branch prediction")
struct BranchPredictionTests {
    private static let base = Date(timeIntervalSince1970: 1_784_000_000)
    private static let right = "com.apple.ServiceManagement.daemons.modify"
    private static let postman = AppIdentityBranch(teamID: "H7H8Q7M5CK", bundleID: "com.postmanlabs.mac")
    private static let postmanPath = "/Applications/Postman.app/Contents/MacOS/Postman"

    private func authd(_ message: String, at offset: TimeInterval) -> LogEntry {
        LogEntry(timestamp: "t+\(offset)", date: Self.base.addingTimeInterval(offset), level: .default,
                 subsystem: "com.apple.Authorization", category: "authd", message: message,
                 processImagePath: "/usr/libexec/authd", processID: 253)
    }

    private var host: CaptureHost {
        CaptureHost(serialNumber: "SYNTHSER01", computerName: "TESTMAC01", osVersion: "27.0", userName: "testuser")
    }

    private func builder(composed: Bool) -> CaptureBuilder {
        let candidates = composed ? BranchMatchResolver.candidates(forRight: Self.right, in: [
            RuleProfile(policyVersion: "1", profileKey: "rules_authuri_svc", profilePriority: 50, rules: [
                Rule(id: "appid__postman", type: .authuri, action: .allow, description: "", priority: 50,
                     match: MatchCriteria(authURI: Self.right), appIdentity: Self.postman),
            ]),
        ]) : []
        return CaptureBuilder(
            identity: StaticBinaryIdentityInspector(identity: BinaryIdentity(
                canonicalPath: "", teamID: "H7H8Q7M5CK", sha256: "cafe", signingStatus: .valid)),
            ruleTagProvider: {
                { right in
                    right == Self.right
                        ? AuthorizationRuleTag(ruleID: "appid__postman", action: .allow, identityGated: true,
                                               identityCandidates: candidates)
                        : nil
                }
            },
            fileInfo: { _ in CaptureBuilder.FileInfo(isRegularFile: true, size: 1_000) },
            resolveSymlinks: { $0 },
            // Deterministic matcher: only Postman's own binary satisfies its branch.
            branchResolver: BranchMatchResolver { path, requirement in
                path == Self.postmanPath && requirement.contains("com.postmanlabs.mac")
            }
        )
    }

    private func build(_ builder: CaptureBuilder, lines: [LogEntry]) -> RuleCapture {
        builder.build(authorizationEntries: lines, sudoEntries: [], decisions: [], host: host,
                      consoleUser: "testuser", startedAt: Self.base, endedAt: Self.base.addingTimeInterval(60))
    }

    @Test("the app itself as client → its own branch is predicted; smd as client → native-default")
    func predictsBranch() throws {
        let direct = build(builder(composed: true), lines: [
            authd("Succeeded authorizing right '\(Self.right)' by client '\(Self.postmanPath)' [900] for authorization created by '\(Self.postmanPath)' [900] (2,0) (engine 41)", at: 5),
        ])
        let attempt = try #require(direct.attempts.first)
        #expect(attempt.predictedBranch == AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman))
        #expect(attempt.branchEvidence == [])   // authd named no branch row on this line
        #expect(attempt.matchedRuleID == "appid__postman")

        let mediated = build(builder(composed: true), lines: [
            authd("Succeeded authorizing right '\(Self.right)' by client '/usr/libexec/smd' [77] for authorization created by '/usr/libexec/smd' [77] (2,0) (engine 42)", at: 6),
        ])
        #expect(mediated.attempts.first?.predictedBranch == BranchMatchResolver.nativeDefault)
    }

    @Test("authd lines naming a branch row are kept verbatim as evidence")
    func keepsEvidence() throws {
        let row = AuthURICompositionNaming.appRow(for: Self.right, branch: Self.postman)
        let capture = build(builder(composed: true), lines: [
            authd("engine 41: evaluating rule '\(row)' for right '\(Self.right)'", at: 4),
            authd("Succeeded authorizing right '\(Self.right)' by client '\(Self.postmanPath)' [900] (engine 41)", at: 5),
        ])
        let attempt = try #require(capture.attempts.first)
        #expect(attempt.branchEvidence?.count == 1)
        #expect(attempt.branchEvidence?.first?.contains(row) == true)
    }

    @Test("a right that is not composed carries no prediction and no evidence")
    func notComposed() throws {
        let capture = build(builder(composed: false), lines: [
            authd("Succeeded authorizing right '\(Self.right)' by client '\(Self.postmanPath)' [900] (engine 41)", at: 5),
        ])
        let attempt = try #require(capture.attempts.first)
        #expect(attempt.predictedBranch == nil)
        #expect(attempt.branchEvidence == nil)
    }

    @Test("prediction and evidence survive the capture's JSON round-trip and redaction")
    func roundTrip() throws {
        let capture = build(builder(composed: true), lines: [
            authd("Succeeded authorizing right '\(Self.right)' by client '\(Self.postmanPath)' [900] (engine 41)", at: 5),
        ])
        let decoded = try RuleCapture.decode(from: try capture.redactingArguments().encoded())
        #expect(decoded.attempts.first?.predictedBranch == capture.attempts.first?.predictedBranch)
        #expect(decoded.attempts.first?.branchEvidence == capture.attempts.first?.branchEvidence)
    }
}
