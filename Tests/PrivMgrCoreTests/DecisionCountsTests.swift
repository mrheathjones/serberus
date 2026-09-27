import Foundation
import Testing
@testable import PrivMgrCore

@Suite("DecisionCountReader")
struct DecisionCountsTests {
    /// A throwaway log directory; caller writes `decisions-<day>.jsonl` files.
    private func makeDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-counts-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// One JSONL line with only the fields the reader decodes. `prompt: nil`
    /// omits the key, standing in for a line written before the field existed.
    private func line(outcome: String, at date: Date, prompt: Bool? = nil) -> String {
        var fields = ["\"outcome\":\"\(outcome)\"", "\"timestamp\":\"\(ISO8601.string(from: date))\""]
        if let prompt { fields.append("\"requiredPrompt\":\(prompt)") }
        return "{\(fields.joined(separator: ","))}"
    }

    private func write(_ lines: [String], day: String, in dir: URL) throws {
        let body = lines.joined(separator: "\n") + "\n"
        try body.write(to: dir.appendingPathComponent("decisions-\(day).jsonl"), atomically: true, encoding: .utf8)
    }

    @Test("tallies each outcome, folding audit would-* into grant/deny, plus prompts and latest")
    func tallies() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let day = LogDay.stamp(for: now)
        try write([
            line(outcome: "granted", at: now.addingTimeInterval(-100)),
            line(outcome: "would-grant", at: now.addingTimeInterval(-200)),
            line(outcome: "denied", at: now.addingTimeInterval(-300), prompt: true),
            line(outcome: "would-deny", at: now.addingTimeInterval(-400)),
            line(outcome: "granted", at: now.addingTimeInterval(-50), prompt: true),
        ], day: day, in: dir)

        let counts = DecisionCountReader(directory: dir).counts(day: day)
        #expect(counts.granted == 3)   // granted + would-grant + granted
        #expect(counts.denied == 2)    // denied + would-deny
        #expect(counts.prompts == 2)
        #expect(counts.latest == now.addingTimeInterval(-50))
    }

    @Test("a since window excludes older events from counts but latest still reflects the genuine newest")
    func rollingWindow() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let day = LogDay.stamp(for: now)
        let old = now.addingTimeInterval(-90_000)     // ~25h ago (outside 24h)
        let recent = now.addingTimeInterval(-3_600)   // 1h ago
        try write([
            line(outcome: "denied", at: old),
            line(outcome: "denied", at: recent),
            line(outcome: "granted", at: recent),
        ], day: day, in: dir)

        let counts = DecisionCountReader(directory: dir)
            .counts(day: day, since: now.addingTimeInterval(-86_400))
        #expect(counts.denied == 1)          // the ~25h-old deny is excluded
        #expect(counts.granted == 1)
        #expect(counts.latest == recent)     // latest tracks all events regardless
    }

    @Test("an absent day file yields all-zeros and never throws")
    func absentDay() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let counts = DecisionCountReader(directory: dir).counts(day: "2020-01-01")
        #expect(counts == DecisionDayCounts())
    }

    @Test("a malformed line is skipped, not fatal, and a missing requiredPrompt counts as no prompt")
    func malformedAndLegacyLines() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let day = LogDay.stamp(for: now)
        try write([
            "this is not json",
            line(outcome: "granted", at: now),          // legacy line, no requiredPrompt key
            "{\"outcome\":\"denied\"}",                   // no timestamp — counted, no latest bump
        ], day: day, in: dir)

        let counts = DecisionCountReader(directory: dir).counts(day: day)
        #expect(counts.granted == 1)
        #expect(counts.denied == 1)
        #expect(counts.prompts == 0)
        #expect(counts.latest == now)
    }

    @Test("counts(days:) sums the window across today and yesterday")
    func multiDaySum() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let today = LogDay.stamp(for: now)
        let yesterday = LogDay.stamp(for: now.addingTimeInterval(-86_400))
        try write([line(outcome: "denied", at: now.addingTimeInterval(-100))], day: today, in: dir)
        try write([line(outcome: "denied", at: now.addingTimeInterval(-3_600))], day: yesterday, in: dir)

        let counts = DecisionCountReader(directory: dir).counts(days: [today, yesterday])
        #expect(counts.denied == 2)
    }

    /// A richer line carrying the fields recentEvents needs.
    private func eventLine(outcome: String, at date: Date, prompt: Bool? = nil,
                           sudo: String? = nil, authURI: String? = nil, user: String? = nil,
                           ruleID: String? = nil, args: [String]? = nil,
                           justification: String? = nil) -> String {
        var fields = ["\"outcome\":\"\(outcome)\"", "\"timestamp\":\"\(ISO8601.string(from: date))\""]
        if let prompt { fields.append("\"requiredPrompt\":\(prompt)") }
        if let sudo { fields.append("\"sudoCommand\":\"\(sudo)\"") }
        if let authURI { fields.append("\"authURI\":\"\(authURI)\"") }
        if let user { fields.append("\"userName\":\"\(user)\"") }
        if let ruleID { fields.append("\"ruleID\":\"\(ruleID)\"") }
        if let args { fields.append("\"arguments\":[\(args.map { "\"\($0)\"" }.joined(separator: ","))]") }
        if let justification { fields.append("\"justification\":\"\(justification)\"") }
        return "{\(fields.joined(separator: ","))}"
    }

    @Test("recentEvents returns only denials & prompts, newest first, with typed fields")
    func recentEventsFilterAndOrder() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let day = LogDay.stamp(for: now)
        try write([
            eventLine(outcome: "granted", at: now.addingTimeInterval(-500), sudo: "/bin/ls", user: "u1"),        // silent grant → excluded
            eventLine(outcome: "denied", at: now.addingTimeInterval(-400), sudo: "/usr/bin/jamf", user: "u2"),    // denial
            eventLine(outcome: "granted", at: now.addingTimeInterval(-300), prompt: true, authURI: "system.privilege.admin", user: "u3", justification: "Installing approved app"), // prompt (granted, with justification)
            eventLine(outcome: "denied", at: now.addingTimeInterval(-100), prompt: true, sudo: "/sbin/reboot", user: "u4"),   // prompt + denial
        ], day: day, in: dir)

        let events = DecisionCountReader(directory: dir).recentEvents(days: [day])
        #expect(events.count == 3)                                   // silent grant excluded
        #expect(events.map(\.at) == [now.addingTimeInterval(-100), now.addingTimeInterval(-300), now.addingTimeInterval(-400)]) // newest first
        let reboot = events[0]
        #expect(reboot.kind == "sudo")
        #expect(reboot.target == "/sbin/reboot")
        #expect(reboot.user == "u4")
        #expect(reboot.outcome == "denied")
        #expect(reboot.prompt)
        #expect(reboot.reason == "Prompt required")            // prompt, no rule id
        #expect(reboot.justification == nil)                   // denial carries no justification
        let authPrompt = events[1]
        #expect(authPrompt.kind == "authuri")
        #expect(authPrompt.target == "system.privilege.admin")
        #expect(authPrompt.outcome == "granted")
        #expect(authPrompt.prompt)
        #expect(authPrompt.justification == "Installing approved app")  // approved prompt surfaces the user's reason
        let jamf = events[2]                                    // the plain denial
        #expect(jamf.reason == "No matching rule")             // denied, ruleID nil
    }

    @Test("recentEvents shows the full command (redacted args) and a rule-based reason")
    func recentEventsCommandAndReason() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let day = LogDay.stamp(for: now)
        try write([
            eventLine(outcome: "denied", at: now.addingTimeInterval(-10), sudo: "/usr/bin/jamf",
                      user: "tuser", args: ["checkJSSConnection"]),
            eventLine(outcome: "denied", at: now.addingTimeInterval(-20), sudo: "/sbin/reboot",
                      user: "tuser", ruleID: "block_reboot"),
        ], day: day, in: dir)

        let events = DecisionCountReader(directory: dir).recentEvents(days: [day])
        #expect(events[0].target == "/usr/bin/jamf checkJSSConnection")   // command + args
        #expect(events[0].reason == "No matching rule")
        #expect(events[1].reason == "Matched deny rule block_reboot")
    }

    @Test("recentEvents honours the since window and the limit")
    func recentEventsWindowAndLimit() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let day = LogDay.stamp(for: now)
        var lines = [eventLine(outcome: "denied", at: now.addingTimeInterval(-90_000), sudo: "/old", user: "u")] // ~25h → out of window
        for i in 0..<10 { lines.append(eventLine(outcome: "denied", at: now.addingTimeInterval(Double(-i * 60)), sudo: "/c\(i)", user: "u")) }
        try write(lines, day: day, in: dir)

        let windowed = DecisionCountReader(directory: dir)
            .recentEvents(days: [day], since: now.addingTimeInterval(-86_400), limit: 3)
        #expect(windowed.count == 3)                        // capped
        #expect(!windowed.contains { $0.target == "/old" }) // 25h-old excluded
        #expect(windowed.first?.target == "/c0")            // newest first
    }

    @Test("FleetDecisionEvent encodeList/decodeList round-trips; empty/garbage decode to []")
    func eventCodecRoundTrip() {
        let events = [
            FleetDecisionEvent(at: Date(timeIntervalSince1970: 1_700_000_000), kind: "sudo",
                               target: "/usr/bin/jamf", user: "tuser", outcome: "denied", prompt: false),
            FleetDecisionEvent(at: Date(timeIntervalSince1970: 1_700_000_300), kind: "authuri",
                               target: "system.privilege.admin", user: "tuser", outcome: "granted", prompt: true),
        ]
        let json = FleetDecisionEvent.encodeList(events)
        #expect(!json.contains("\n"))                       // single line for the EA
        #expect(FleetDecisionEvent.decodeList(from: json) == events)
        #expect(FleetDecisionEvent.decodeList(from: "").isEmpty)
        #expect(FleetDecisionEvent.decodeList(from: "not json").isEmpty)
        #expect(FleetDecisionEvent.decodeList(from: "[]").isEmpty)
    }

    @Test("maxLines bounds the read so a runaway log cannot stall the tick")
    func maxLinesBound() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let day = LogDay.stamp(for: now)
        let lines = (0..<50).map { line(outcome: "granted", at: now.addingTimeInterval(Double(-$0))) }
        try write(lines, day: day, in: dir)

        let counts = DecisionCountReader(directory: dir, maxLines: 10).counts(day: day)
        #expect(counts.granted == 10)
    }
}
