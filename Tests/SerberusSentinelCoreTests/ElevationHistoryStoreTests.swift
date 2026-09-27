import Foundation
import Testing
import PrivMgrCore
@testable import SerberusSentinelCore

@MainActor
@Suite("ElevationHistoryStore")
struct ElevationHistoryStoreTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func context(process: String = "brew", requestID: UUID = UUID()) -> PromptContext {
        PromptContext(
            requestID: requestID, user: "alice", processName: process,
            canonicalPath: "/opt/homebrew/bin/\(process)", teamID: nil, signingStatus: .unsigned,
            humanReadableRequest: "sudo \(process)", requireJustification: false,
            justificationMinLength: 0, timeoutSeconds: 60
        )
    }

    private func response(_ verdict: PromptResponse.Verdict, for context: PromptContext,
                          justification: String? = nil) -> PromptResponse {
        PromptResponse(requestID: context.requestID, verdict: verdict, justificationText: justification)
    }

    private func tempFile() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-history-tests", isDirectory: true)
            .appendingPathComponent("\(UUID().uuidString).json")
    }

    @Test("records newest-first with the prompt's identity and outcome")
    func recordsNewestFirst() {
        let store = ElevationHistoryStore(fileURL: nil, now: { self.now })
        let first = context(process: "brew")
        let second = context(process: "softwareupdate")
        store.record(context: first, response: response(.approved, for: first, justification: "deploying"))
        store.record(context: second, response: response(.denied, for: second))

        #expect(store.entries.count == 2)
        #expect(store.entries[0].processName == "softwareupdate")
        #expect(store.entries[0].verdict == .denied)
        #expect(store.entries[1].id == first.requestID)
        #expect(store.entries[1].justificationText == "deploying")
        #expect(store.entries[1].date == now)
    }

    @Test("caps retained entries at capacity, dropping the oldest")
    func caps() {
        let store = ElevationHistoryStore(fileURL: nil, now: { self.now })
        for i in 0..<(ElevationHistoryStore.capacity + 25) {
            let ctx = context(process: "cmd\(i)")
            store.record(context: ctx, response: response(.approved, for: ctx))
        }
        #expect(store.entries.count == ElevationHistoryStore.capacity)
        #expect(store.entries.first?.processName == "cmd\(ElevationHistoryStore.capacity + 24)")
        #expect(store.entries.last?.processName == "cmd25")
    }

    @Test("recent(limit) returns the newest entries only")
    func recent() {
        let store = ElevationHistoryStore(fileURL: nil, now: { self.now })
        for i in 0..<5 {
            let ctx = context(process: "cmd\(i)")
            store.record(context: ctx, response: response(.approved, for: ctx))
        }
        let recent = store.recent(3)
        #expect(recent.map(\.processName) == ["cmd4", "cmd3", "cmd2"])
    }

    @Test("persists across instances via the backing file")
    func persistence() throws {
        let file = tempFile()
        defer { try? FileManager.default.removeItem(at: file) }

        let store = ElevationHistoryStore(fileURL: file, now: { self.now })
        let ctx = context(process: "brew")
        store.record(context: ctx, response: response(.timedOut, for: ctx))

        let reloaded = ElevationHistoryStore(fileURL: file, now: { self.now })
        #expect(reloaded.entries.count == 1)
        #expect(reloaded.entries.first?.verdict == .timedOut)
        #expect(reloaded.entries.first?.id == ctx.requestID)
    }

    @Test("a corrupt backing file starts empty instead of failing")
    func corruptFile() throws {
        let file = tempFile()
        defer { try? FileManager.default.removeItem(at: file) }
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not json".utf8).write(to: file)

        let store = ElevationHistoryStore(fileURL: file, now: { self.now })
        #expect(store.entries.isEmpty)
    }

    @Test("auditedTodayCount counts today's prompts regardless of verdict")
    func auditedToday() throws {
        let file = tempFile()
        defer { try? FileManager.default.removeItem(at: file) }

        // Record one entry yesterday, then two today (same backing file).
        let yesterday = ElevationHistoryStore(fileURL: file, now: { self.now.addingTimeInterval(-86_400) })
        let old = context(process: "old")
        yesterday.record(context: old, response: response(.approved, for: old))

        let store = ElevationHistoryStore(fileURL: file, now: { self.now })
        let approved = context(process: "brew")
        let denied = context(process: "systemsetup")
        store.record(context: approved, response: response(.approved, for: approved))
        store.record(context: denied, response: response(.denied, for: denied))

        #expect(store.entries.count == 3)
        #expect(store.auditedTodayCount() == 2)
    }

    @Test("ruleName rides through record and drives lastEntry(forRuleNamed:)")
    func ruleNameRoundTrip() {
        let store = ElevationHistoryStore(fileURL: nil, now: { self.now })
        let ctx = PromptContext(
            user: "alice", processName: "System Settings",
            canonicalPath: "/System/Applications/System Settings.app",
            teamID: nil, signingStatus: .valid,
            humanReadableRequest: "Authorization right: system.preferences.network",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60,
            ruleName: "rules_authuri_standard · net"
        )
        store.record(context: ctx, response: response(.approved, for: ctx))
        #expect(store.entries.first?.ruleName == "rules_authuri_standard · net")
        #expect(store.lastEntry(forRuleNamed: "rules_authuri_standard · net")?.id == ctx.requestID)
        #expect(store.lastEntry(forRuleNamed: "rules_authuri_standard · other") == nil)
    }

    @Test("history files written before ruleName existed still decode")
    func legacyEntriesDecode() throws {
        let file = tempFile()
        defer { try? FileManager.default.removeItem(at: file) }
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        let legacyJSON = """
        [{"canonicalPath":"/opt/homebrew/bin/brew","date":"2026-06-11T12:00:00Z",
        "humanReadableRequest":"sudo brew","id":"00000000-0000-0000-0000-000000000001",
        "processName":"brew","user":"alice","verdict":"approved"}]
        """
        try Data(legacyJSON.utf8).write(to: file)

        let store = ElevationHistoryStore(fileURL: file, now: { self.now })
        #expect(store.entries.count == 1)
        #expect(store.entries.first?.ruleName == nil)
    }

    @Test("history rows show hidden characters as escapes, even in entries older versions recorded raw")
    func displayRequestEscapesLegacyEntries() throws {
        let file = tempFile()
        defer { try? FileManager.default.removeItem(at: file) }
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        // An older daemon's raw line: RLO … PDF around a reversed name, then a
        // newline, a zero-width space, a C1 control and an NBSP.
        let legacyJSON = #"""
        [{"canonicalPath":"/usr/sbin/installer","date":"2026-06-11T12:00:00Z",
        "humanReadableRequest":"sudo /usr/sbin/installer -pkg IT-approved-\u202Egkp.live\u202C\n-target /\u200B\u0085\u00A0",
        "id":"00000000-0000-0000-0000-000000000001","processName":"installer","user":"alice","verdict":"approved"}]
        """#
        try Data(legacyJSON.utf8).write(to: file)

        let store = ElevationHistoryStore(fileURL: file, now: { self.now })
        let entry = try #require(store.entries.first)
        // The stored text stays raw (the search matches it); the row escapes it.
        #expect(entry.humanReadableRequest
                == "sudo /usr/sbin/installer -pkg IT-approved-\u{202E}gkp.live\u{202C}\n-target /\u{200B}\u{0085}\u{00A0}")
        #expect(entry.displayRequest
                == #"sudo /usr/sbin/installer -pkg IT-approved-\u{202E}gkp.live\u{202C}\n-target /\u{200B}\u{0085}\u{00A0}"#)
    }

    @Test("a history row shows the whole request, and a line the daemon already escaped as it is")
    func displayRequestWholeAndStable() {
        let store = ElevationHistoryStore(fileURL: nil, now: { self.now })
        let long = "sudo /bin/echo " + String(repeating: "word ", count: 1_000) + #"IT-approved-\u{202E}gkp.live\nend"#
        let ctx = PromptContext(
            user: "alice", processName: "echo", canonicalPath: "/bin/echo", teamID: nil, signingStatus: .valid,
            humanReadableRequest: long, requireJustification: false, justificationMinLength: 0, timeoutSeconds: 60
        )
        store.record(context: ctx, response: response(.approved, for: ctx))
        #expect(store.entries.first?.displayRequest == long)
    }

    @Test("clear empties the trail and persists the empty state")
    func clear() {
        let file = tempFile()
        defer { try? FileManager.default.removeItem(at: file) }

        let store = ElevationHistoryStore(fileURL: file, now: { self.now })
        let ctx = context()
        store.record(context: ctx, response: response(.approved, for: ctx))
        store.clear()
        #expect(store.entries.isEmpty)

        let reloaded = ElevationHistoryStore(fileURL: file, now: { self.now })
        #expect(reloaded.entries.isEmpty)
    }
}

@MainActor
@Suite("MenubarStateModel offline handling")
struct MenubarOfflineTests {
    @Test("a failed pull presents offline; a successful pull restores the state icon")
    func offlineRoundTrip() {
        let model = MenubarStateModel(daemonState: .pendingProfiles, daemonReachable: false)
        #expect(model.icon == .offline)

        model.update(state: .healthy)
        #expect(model.daemonReachable)
        #expect(model.icon == .healthy)

        model.markUnreachable()
        #expect(model.icon == .offline)
        // Last-known daemon state is retained underneath.
        #expect(model.daemonState == .healthy)

        model.update(state: .degraded)
        #expect(model.icon == .degraded)
    }

    @Test("offline icon has a symbol and tooltip")
    func presentation() {
        #expect(!MenubarIcon.offline.symbolName.isEmpty)
        #expect(MenubarIcon.offline.tooltip.contains("Serberus"))
    }
}
