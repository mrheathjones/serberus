import Foundation
import Testing
@testable import SerberusIntelCore

@Suite("JamfUploadLedger — the Sentinel's device-side record of Jamf uploads")
struct JamfUploadLedgerTests {
    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("ledger-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("jamf-uploads.json")
    }

    @Test("records append in time order, survive a re-read, and the file is world-readable JSON")
    func recordAndRead() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        nonisolated(unsafe) var clock = Date(timeIntervalSince1970: 1_787_000_000)
        let ledger = JamfUploadLedger(fileURL: url, now: { clock })
        #expect(ledger.entries().isEmpty)

        try ledger.record(kind: .capture, fileName: "Serberus-Capture-S1-20260822-101500.serberuscapture",
                          computerID: "7", serialNumber: "S1", sizeBytes: 2048)
        clock = clock.addingTimeInterval(60)
        try ledger.record(kind: .intel, fileName: "Serberus-Intel-S1-20260822-101600Z.zip",
                          computerID: "7", serialNumber: "S1", sizeBytes: 99_999)

        let entries = JamfUploadLedger(fileURL: url).entries()
        #expect(entries.map(\.kind) == [.capture, .intel])
        #expect(entries.last?.computerID == "7")
        #expect(entries.last?.sizeBytes == 99_999)
        let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        #expect(perms == 0o644)
        // Plain JSON array with ISO-8601 dates — what the EA's jq reads.
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(text.contains("\"uploadedAt\" : \"2026-"))
        #expect(text.hasPrefix("["))
    }

    @Test("entries older than the retention window and beyond the cap are pruned on write")
    func pruning() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let now = Date(timeIntervalSince1970: 1_787_000_000)
        nonisolated(unsafe) var clock = now.addingTimeInterval(-JamfUploadLedger.retention - 60) // expired
        let ledger = JamfUploadLedger(fileURL: url, now: { clock })
        try ledger.record(kind: .capture, fileName: "old", computerID: "7", serialNumber: nil, sizeBytes: nil)
        clock = now
        try ledger.record(kind: .capture, fileName: "new", computerID: "7", serialNumber: nil, sizeBytes: nil)
        #expect(ledger.entries().map(\.fileName) == ["new"])

        for index in 0..<(JamfUploadLedger.maxEntries + 5) {
            clock = now.addingTimeInterval(Double(index))
            try ledger.record(kind: .intel, fileName: "bundle-\(index)", computerID: "7", serialNumber: nil, sizeBytes: nil)
        }
        let kept = ledger.entries()
        #expect(kept.count == JamfUploadLedger.maxEntries)
        #expect(kept.last?.fileName == "bundle-\(JamfUploadLedger.maxEntries + 4)")
    }

    @Test("a corrupt or missing ledger reads as empty, never throws")
    func corruptLedger() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not json".utf8).write(to: url)
        #expect(JamfUploadLedger(fileURL: url).entries().isEmpty)
        #expect(JamfUploadLedger(fileURL: url.appendingPathExtension("missing")).entries().isEmpty)
    }
}
