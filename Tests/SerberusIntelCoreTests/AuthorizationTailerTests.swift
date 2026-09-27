import Foundation
import Testing
@testable import SerberusIntelCore

@Suite("AuthorizationTailer dedup")
struct AuthorizationTailerTests {
    /// A real authd ndjson line at a given timestamp.
    private func line(_ message: String, at timestamp: String) -> String {
        let fields = [
            "\"eventType\":\"logEvent\"",
            "\"messageType\":\"Default\"",
            "\"subsystem\":\"com.apple.Authorization\"",
            "\"category\":\"authd\"",
            "\"eventMessage\":\"\(message)\"",
            "\"timestamp\":\"\(timestamp)\"",
            "\"processImagePath\":\"/usr/libexec/authd\"",
            "\"processID\":253",
        ]
        return "{" + fields.joined(separator: ",") + "}"
    }

    @Test("overlapping polls don't emit the same entry twice")
    func dedupAcrossOverlap() {
        let tailer = AuthorizationTailer()
        let a = line("authorizing right 'system.preferences.datetime'", at: "2026-07-18 10:00:01.000000-0400")
        let b = line("authorizing right 'system.print.admin'", at: "2026-07-18 10:00:03.000000-0400")

        // First poll sees both.
        let first = tailer.freshEntries(from: a + "\n" + b)
        #expect(first.count == 2)

        // Second poll overlaps (windows overlap by design) and re-includes b
        // plus a new event c. Only the genuinely new ones come through.
        let c = line("authorizing right 'system.preferences'", at: "2026-07-18 10:00:04.000000-0400")
        let second = tailer.freshEntries(from: b + "\n" + c)
        #expect(second.count == 1)
        #expect(second.first?.message.contains("system.preferences'") == true)
    }

    @Test("entries come out in ascending time even if the poll is unordered")
    func sortsAscending() {
        let tailer = AuthorizationTailer()
        let later = line("right B", at: "2026-07-18 10:00:05.000000-0400")
        let earlier = line("right A", at: "2026-07-18 10:00:01.000000-0400")
        let fresh = tailer.freshEntries(from: later + "\n" + earlier)
        #expect(fresh.map(\.date) == fresh.map(\.date).sorted())
        #expect(fresh.first?.message == "right A")
    }

    @Test("the log-stream preamble line is ignored, not emitted as an entry")
    func skipsPreamble() {
        let tailer = AuthorizationTailer()
        let preamble = "Filtering the log data using \"subsystem == ...\""
        let doc = preamble + "\n" + line("right X", at: "2026-07-18 10:00:01.000000-0400")
        #expect(tailer.freshEntries(from: doc).count == 1)
    }

    @Test("an empty poll yields nothing and doesn't move the high-water mark")
    func emptyPoll() {
        let tailer = AuthorizationTailer()
        let a = line("right A", at: "2026-07-18 10:00:02.000000-0400")
        #expect(tailer.freshEntries(from: a).count == 1)
        #expect(tailer.freshEntries(from: "").isEmpty)
        // The same line, seen again after an empty poll, is still a duplicate.
        #expect(tailer.freshEntries(from: a).isEmpty)
    }
}
