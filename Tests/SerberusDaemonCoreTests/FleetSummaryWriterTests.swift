import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("FleetSummaryWriter")
struct FleetSummaryWriterTests {
    private func makeDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-fleet-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func line(outcome: String, at date: Date, prompt: Bool? = nil) -> String {
        var fields = ["\"outcome\":\"\(outcome)\"", "\"timestamp\":\"\(ISO8601.string(from: date))\""]
        if let prompt { fields.append("\"requiredPrompt\":\(prompt)") }
        return "{\(fields.joined(separator: ","))}"
    }

    private func writeDecisions(_ lines: [String], day: String, in dir: URL) throws {
        try (lines.joined(separator: "\n") + "\n")
            .write(to: dir.appendingPathComponent("decisions-\(day).jsonl"), atomically: true, encoding: .utf8)
    }

    @Test("summary folds outcomes into 24h counts and carries active grants + genuine latest")
    func summaryComputes() throws {
        let logDir = try makeDir()
        defer { try? FileManager.default.removeItem(at: logDir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let today = LogDay.stamp(for: now)
        let yesterday = LogDay.stamp(for: now.addingTimeInterval(-86_400))
        try writeDecisions([
            line(outcome: "denied", at: now.addingTimeInterval(-1_000), prompt: true),
            line(outcome: "would-deny", at: now.addingTimeInterval(-2_000)),
            line(outcome: "granted", at: now.addingTimeInterval(-500)),
        ], day: today, in: logDir)
        try writeDecisions([
            line(outcome: "denied", at: now.addingTimeInterval(-90_000)),   // ~25h ago, excluded
            line(outcome: "granted", at: now.addingTimeInterval(-7_200)),
        ], day: yesterday, in: logDir)

        let writer = FleetSummaryWriter(
            logDirectory: logDir, outputURL: logDir.appendingPathComponent("fleet-summary.plist"),
            daemonVersion: "3.9.0"
        )
        let summary = writer.summary(activeGrants: 4, now: now)
        #expect(summary.denials24h == 2)     // denied + would-deny; the 25h-old deny excluded
        #expect(summary.grants24h == 2)
        #expect(summary.prompts24h == 1)
        #expect(summary.activeGrants == 4)
        #expect(summary.lastDecisionAt == now.addingTimeInterval(-500))
        #expect(summary.daemonVersion == "3.9.0")
        #expect(summary.updatedAt == now)
    }

    @Test("write emits a world-readable plist with the EA-facing scalar keys")
    func writeEmitsPlist() throws {
        let logDir = try makeDir()
        defer { try? FileManager.default.removeItem(at: logDir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try writeDecisions([line(outcome: "denied", at: now.addingTimeInterval(-60))],
                           day: LogDay.stamp(for: now), in: logDir)
        let outURL = logDir.appendingPathComponent("sub/fleet-summary.plist")
        let writer = FleetSummaryWriter(logDirectory: logDir, outputURL: outURL, daemonVersion: "3.9.0")

        #expect(writer.write(activeGrants: 2, now: now))
        let data = try Data(contentsOf: outURL)
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["denials24h"] as? Int == 1)
        #expect(plist["grants24h"] as? Int == 0)
        #expect(plist["activeGrants"] as? Int == 2)
        #expect(plist["daemonVersion"] as? String == "3.9.0")
        #expect(plist["lastDecisionAt"] as? String == ISO8601.secondString(from: now.addingTimeInterval(-60)))
        #expect(plist["updatedAt"] as? String == ISO8601.secondString(from: now))
        // Whole-second precision (no ".000Z" fraction) so the Jamf Date EA's
        // `date -j -f '%Y-%m-%dT%H:%M:%SZ'` can parse it.
        #expect(plist["lastDecisionAt"] as? String == "2023-11-14T22:12:20Z")

        let perms = try FileManager.default.attributesOfItem(atPath: outURL.path)[.posixPermissions] as? Int
        #expect(perms == 0o644)
    }

    @Test("an empty log directory yields a zeroed summary with no lastDecisionAt and never throws")
    func emptyLogDir() throws {
        let logDir = try makeDir()
        defer { try? FileManager.default.removeItem(at: logDir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let outURL = logDir.appendingPathComponent("fleet-summary.plist")
        let writer = FleetSummaryWriter(logDirectory: logDir, outputURL: outURL, daemonVersion: "3.9.0")

        #expect(writer.write(activeGrants: 0, now: now))
        let summary = writer.summary(activeGrants: 0, now: now)
        #expect(summary.denials24h == 0)
        #expect(summary.grants24h == 0)
        #expect(summary.prompts24h == 0)
        #expect(summary.lastDecisionAt == nil)

        let plist = try #require(
            try PropertyListSerialization.propertyList(from: Data(contentsOf: outURL), format: nil) as? [String: Any]
        )
        #expect(plist["lastDecisionAt"] == nil)   // omitted, not empty-string
    }
}
