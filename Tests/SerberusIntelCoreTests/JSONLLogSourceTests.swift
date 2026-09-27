import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

/// Writes real JSONL through the daemon's own logger, so these tests break if
/// the on-disk format ever changes — the whole point of this source is that it
/// reads what `DecisionLogger` writes.
private struct JSONLFixture {
    let directory: URL

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("jsonl-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    /// Writes through the daemon's own `SignedJSONLWriter` (unsigned — the
    /// HMAC sidecar is irrelevant to reading, and `DecisionLogger` requires a
    /// real Keychain-backed key provider).
    func writeDecision(
        user: String,
        outcome: DecisionEvent.Outcome = .denied,
        command: String = "/usr/bin/jamf",
        at date: Date
    ) async throws {
        let writer = try SignedJSONLWriter(directory: directory, filePrefix: "decisions", keyProvider: nil)
        try await writer.append(
            Self.decision(user: user, outcome: outcome, command: command, at: date),
            timestamp: date
        )
    }

    func writeIntegrity(kind: IntegrityEvent.Kind, detail: String, at date: Date) async throws {
        let writer = try SignedJSONLWriter(directory: directory, filePrefix: "integrity", keyProvider: nil)
        let event = IntegrityEvent(timestamp: date, kind: kind, detail: detail, daemonVersion: "1.0")
        try await writer.append(event, timestamp: date)
    }

    static func decision(
        user: String,
        outcome: DecisionEvent.Outcome,
        command: String,
        at date: Date
    ) -> DecisionEvent {
        DecisionEvent(
            timestamp: date,
            outcome: outcome,
            enforcementMode: .enforce,
            authURI: nil,
            sudoCommand: command,
            arguments: ["recon"],
            processPath: "/usr/bin/sudo",
            processTeamID: "ABCDE12345",
            processHash: "hash",
            userName: user,
            userUID: 501,
            ruleID: "rule-1",
            profileKey: nil,
            grantID: nil,
            justification: nil,
            grantDurationSeconds: 0,
            cacheHit: false,
            deviceSerial: "C02XY",
            daemonVersion: "1.0",
            pamModuleVersion: "1.0",
            policyVersion: "1.0"
        )
    }

    func cleanUp() { try? FileManager.default.removeItem(at: directory) }
}

@Suite("JSONLLogSource")
struct JSONLLogSourceTests {
    @Test("reads a decision the daemon's own logger wrote")
    func readsDecision() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeDecision(user: "alice", at: now)

        let source = JSONLLogSource(directory: fixture.directory, userName: "alice")
        let entries = source.entries(window: .oneHour, now: now)

        #expect(entries.count == 1)
        let entry = try #require(entries.first)
        #expect(entry.category == "decisions")
        #expect(entry.message.contains("DENY"))
        #expect(entry.message.contains("/usr/bin/jamf"))
        #expect(entry.userName == "alice")
        // A denial is what the user opened Intel to find.
        #expect(entry.level == .error)
    }

    @Test("scopes to the calling user and hides other users' decisions")
    func scopesToUser() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeDecision(user: "alice", at: now)
        try await fixture.writeDecision(user: "bob", at: now)

        let entries = JSONLLogSource(directory: fixture.directory, userName: "alice")
            .entries(window: .oneHour, now: now)
        #expect(entries.count == 1)
        #expect(entries.first?.userName == "alice")
    }

    @Test("a nil user reads every user's decisions")
    func unscopedReadsAll() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeDecision(user: "alice", at: now)
        try await fixture.writeDecision(user: "bob", at: now)

        let entries = JSONLLogSource(directory: fixture.directory, userName: nil)
            .entries(window: .oneHour, now: now)
        #expect(entries.count == 2)
    }

    @Test("integrity events survive user scoping")
    func integrityNotScopedAway() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeIntegrity(kind: .policyChange, detail: "rules reloaded", at: now)

        // Integrity events are daemon-wide and carry no user. They are the
        // context that explains a decision (mode changes, policy reloads), so
        // scoping them away would leave the user's own denials unexplained.
        let entries = JSONLLogSource(directory: fixture.directory, userName: "alice")
            .entries(window: .oneHour, now: now)
        #expect(entries.count == 1)
        #expect(entries.first?.category == "integrity")
        #expect(entries.first?.message.contains("rules reloaded") == true)
    }

    @Test("an hmac violation is surfaced at fault level")
    func hmacViolationIsFault() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeIntegrity(kind: .hmacViolation, detail: "chain broken at 4", at: now)

        let entries = JSONLLogSource(directory: fixture.directory, userName: "alice")
            .entries(window: .oneHour, now: now)
        // Someone tampered with the record itself — the loudest thing the log
        // can say.
        #expect(entries.first?.level == .fault)
    }

    @Test("events outside the window are excluded")
    func windowFiltering() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeDecision(user: "alice", command: "/bin/recent", at: now)
        try await fixture.writeDecision(user: "alice", command: "/bin/old", at: now.addingTimeInterval(-3_600))

        let entries = JSONLLogSource(directory: fixture.directory, userName: "alice")
            .entries(window: .fiveMinutes, now: now)
        #expect(entries.count == 1)
        #expect(entries.first?.message.contains("/bin/recent") == true)
    }

    @Test("a window spanning a UTC midnight reads both day files")
    func spansDayBoundary() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        // 00:30 UTC — the 24h window reaches back into the previous day file.
        let now = ISO8601.date(from: "2026-07-16T00:30:00.000Z")!
        try await fixture.writeDecision(user: "alice", command: "/bin/today", at: now)
        try await fixture.writeDecision(user: "alice", command: "/bin/yesterday", at: now.addingTimeInterval(-3_600))

        let entries = JSONLLogSource(directory: fixture.directory, userName: "alice")
            .entries(window: .oneDay, now: now)
        // Files rotate at UTC midnight; reading only "today" would silently
        // drop everything before it.
        #expect(entries.count == 2)
        #expect(entries.map(\.message).contains { $0.contains("/bin/yesterday") })
    }

    @Test("entries come back in timestamp order")
    func sortedByTime() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeDecision(user: "alice", command: "/bin/second", at: now)
        try await fixture.writeDecision(user: "alice", command: "/bin/first", at: now.addingTimeInterval(-60))

        let entries = JSONLLogSource(directory: fixture.directory, userName: "alice")
            .entries(window: .oneHour, now: now)
        #expect(entries.map(\.date) == entries.map(\.date).sorted())
        #expect(entries.first?.message.contains("/bin/first") == true)
    }

    @Test("day stamps cover the whole span, UTC")
    func dayStamps() async {
        let end = ISO8601.date(from: "2026-07-16T00:30:00.000Z")!
        let start = end.addingTimeInterval(-2 * 86_400)
        #expect(JSONLLogSource.dayStamps(from: start, to: end) == ["2026-07-14", "2026-07-15", "2026-07-16"])
    }

    @Test("a missing directory yields no entries rather than throwing")
    func missingDirectory() {
        let source = JSONLLogSource(
            directory: URL(fileURLWithPath: "/nonexistent/serberus-logs"),
            userName: "alice"
        )
        // A Mac where the daemon has never logged is not an error state.
        #expect(source.entries(window: .oneHour, now: Date()).isEmpty)
    }

    @Test("would-deny is not shown as a denial")
    func monitorModeIsNotADenial() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        try await fixture.writeDecision(user: "alice", outcome: .wouldDeny, at: now)

        let entry = try #require(
            JSONLLogSource(directory: fixture.directory, userName: "alice")
                .entries(window: .oneHour, now: now).first
        )
        // In monitor/audit the command still ran; flagging it as an error would
        // send the user chasing a block that never happened.
        #expect(entry.level == .default)
        #expect(entry.message.contains("WOULD-DENY"))
    }
}

@Suite("Incremental JSONL reads")
struct JSONLIncrementalTests {
    @Test("resuming from an offset returns only what was appended")
    func incrementalRead() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        let day = LogDay.stamp(for: now)
        let source = JSONLLogSource(directory: fixture.directory, userName: "alice")

        try await fixture.writeDecision(user: "alice", command: "/bin/one", at: now)
        let first = source.readIncremental(prefix: "decisions", day: day, from: 0)
        #expect(first.entries.count == 1)
        #expect(first.offset > 0)

        try await fixture.writeDecision(user: "alice", command: "/bin/two", at: now)
        let second = source.readIncremental(prefix: "decisions", day: day, from: first.offset)
        #expect(second.entries.count == 1)
        #expect(second.entries.first?.message.contains("/bin/two") == true)
    }

    @Test("no new bytes yields nothing and holds the offset")
    func idempotentAtEOF() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        let day = LogDay.stamp(for: now)
        let source = JSONLLogSource(directory: fixture.directory, userName: "alice")
        try await fixture.writeDecision(user: "alice", at: now)

        let first = source.readIncremental(prefix: "decisions", day: day, from: 0)
        let again = source.readIncremental(prefix: "decisions", day: day, from: first.offset)
        #expect(again.entries.isEmpty)
        #expect(again.offset == first.offset)
    }

    @Test("a truncated file restarts from zero instead of going silent")
    func handlesTruncation() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let now = Date()
        let day = LogDay.stamp(for: now)
        let source = JSONLLogSource(directory: fixture.directory, userName: "alice")
        try await fixture.writeDecision(user: "alice", at: now)

        // Offset past EOF (rotation/truncation). Seeking past the end would
        // make the tail permanently silent with no error.
        let result = source.readIncremental(prefix: "decisions", day: day, from: 999_999)
        #expect(result.entries.count == 1)
    }

    @Test("a partial trailing line is not consumed until it is complete")
    func partialLineHeldBack() async throws {
        let fixture = try JSONLFixture()
        defer { fixture.cleanUp() }
        let day = LogDay.stamp(for: Date())
        let url = fixture.directory.appendingPathComponent("decisions-\(day).jsonl")
        // The daemon appends with a plain write, so a read can land mid-line;
        // parsing a partial JSON object would drop a real event.
        try Data(#"{"partial":"#.utf8).write(to: url)

        let source = JSONLLogSource(directory: fixture.directory, userName: nil)
        let result = source.readIncremental(prefix: "decisions", day: day, from: 0)
        #expect(result.entries.isEmpty)
        #expect(result.offset == 0)
    }

    @Test("a missing file is not an error")
    func missingFile() {
        let source = JSONLLogSource(directory: URL(fileURLWithPath: "/nonexistent"), userName: nil)
        let result = source.readIncremental(prefix: "decisions", day: "2026-07-16", from: 0)
        #expect(result.entries.isEmpty)
        #expect(result.offset == 0)
    }
}

@Suite("UnifiedLogAccess")
struct UnifiedLogAccessTests {
    @Test("probes the real unified log store path")
    func storePath() {
        // root:admin 0750 — readable by an admin, not by a standard user. This
        // is the whole reason the JSONL source exists.
        #expect(UnifiedLogAccess.storePath == "/var/db/diagnostics")
    }

    @Test("the unavailable reason explains the boundary and the fallback")
    func reasonIsActionable() {
        let reason = UnifiedLogAccess.unavailableReason
        #expect(reason.contains("admin"))
        // "No lines" must never read as "nothing happened".
        #expect(reason.lowercased().contains("decision"))
    }
}
