import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("RecentEventsWriter (debug-gated per-device events)")
struct RecentEventsWriterTests {
    private func makeDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-events-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func writeDecisions(_ lines: [String], day: String, in dir: URL) throws {
        try (lines.joined(separator: "\n") + "\n")
            .write(to: dir.appendingPathComponent("decisions-\(day).jsonl"), atomically: true, encoding: .utf8)
    }

    private func line(outcome: String, at date: Date, sudo: String, user: String, prompt: Bool = false) -> String {
        "{\"outcome\":\"\(outcome)\",\"timestamp\":\"\(ISO8601.string(from: date))\",\"sudoCommand\":\"\(sudo)\",\"userName\":\"\(user)\"\(prompt ? ",\"requiredPrompt\":true" : "")}"
    }

    private func makeWriter(logDir: URL, dir: URL) -> (RecentEventsWriter, URL, URL) {
        let local = dir.appendingPathComponent("recent-events.json")
        let pub = dir.appendingPathComponent("fleet-events.json")
        return (RecentEventsWriter(logDirectory: logDir, localURL: local, publicURL: pub), local, pub)
    }

    @Test("debug ON publishes to the EA path AND writes the local copy, both root-only")
    func debugOnPublishes() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try writeDecisions([line(outcome: "denied", at: now.addingTimeInterval(-100), sudo: "/usr/bin/jamf", user: "tuser")],
                           day: LogDay.stamp(for: now), in: dir)
        let (writer, local, pub) = makeWriter(logDir: dir, dir: dir)

        writer.write(debugEnabled: true, now: now)

        #expect(FileManager.default.fileExists(atPath: local.path))
        #expect(FileManager.default.fileExists(atPath: pub.path))
        let events = FleetDecisionEvent.decodeList(from: (try? String(contentsOf: pub, encoding: .utf8)) ?? "")
        #expect(events.count == 1)
        #expect(events.first?.target == "/usr/bin/jamf")
        // Root-only like the local copy: the extension attribute runs as root.
        let perms = try FileManager.default.attributesOfItem(atPath: pub.path)[.posixPermissions] as? Int
        #expect(perms == 0o600)
        let localPerms = try FileManager.default.attributesOfItem(atPath: local.path)[.posixPermissions] as? Int
        #expect(localPerms == 0o600)
    }

    @Test("debug OFF removes the EA-path file but still writes the local copy")
    func debugOffWithdraws() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try writeDecisions([line(outcome: "denied", at: now.addingTimeInterval(-100), sudo: "/usr/bin/jamf", user: "tuser")],
                           day: LogDay.stamp(for: now), in: dir)
        let (writer, local, pub) = makeWriter(logDir: dir, dir: dir)

        // Publish first (debug on), then turn debug off → the EA file is withdrawn.
        writer.write(debugEnabled: true, now: now)
        #expect(FileManager.default.fileExists(atPath: pub.path))
        writer.write(debugEnabled: false, now: now)
        #expect(!FileManager.default.fileExists(atPath: pub.path))   // withdrawn from Jamf's reach
        #expect(FileManager.default.fileExists(atPath: local.path))   // still collected locally
    }

    @Test("an empty decision log yields an empty JSON array, never a throw")
    func emptyLog() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (writer, local, pub) = makeWriter(logDir: dir, dir: dir)
        writer.write(debugEnabled: true, now: now)
        #expect((try? String(contentsOf: pub, encoding: .utf8)) == "[]")
        #expect((try? String(contentsOf: local, encoding: .utf8)) == "[]")
    }

    @Test("debug-captured arguments join the root-only lists by event ID; logged arguments still win")
    func debugArgumentsJoined() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let captured = UUID()
        let optedIn = UUID()
        func line(_ id: UUID, args: String? = nil) -> String {
            "{\"eventID\":\"\(id.uuidString)\",\"outcome\":\"denied\",\"timestamp\":\"\(ISO8601.string(from: now.addingTimeInterval(-60)))\",\"sudoCommand\":\"/usr/bin/jamf\",\"userName\":\"tuser\"\(args.map { ",\"arguments\":\($0)" } ?? "")}"
        }
        try writeDecisions([line(captured), line(optedIn, args: "[\"recon\"]")], day: LogDay.stamp(for: now), in: dir)
        let (writer, local, pub) = makeWriter(logDir: dir, dir: dir)
        writer.debugArguments.record(eventID: captured, arguments: ["policy", "-id", "7"], at: now.addingTimeInterval(-60))
        writer.debugArguments.record(eventID: optedIn, arguments: ["ignored"], at: now.addingTimeInterval(-60))

        writer.write(debugEnabled: true, now: now)
        for url in [local, pub] {
            let targets = Set(FleetDecisionEvent.decodeList(from: (try? String(contentsOf: url, encoding: .utf8)) ?? "")
                .map(\.target))
            #expect(targets == ["/usr/bin/jamf policy -id 7", "/usr/bin/jamf recon"])
        }
    }

    @Test("both files come out 0600, even over files already there at 0644")
    func existingFilesReplacedRootOnly() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let (writer, local, pub) = makeWriter(logDir: dir, dir: dir)
        for url in [local, pub] {
            try "stale".write(to: url, atomically: false, encoding: .utf8)
            #expect(chmod(url.path, 0o644) == 0)
        }

        writer.write(debugEnabled: true, now: Date(timeIntervalSince1970: 1_700_000_000))

        for url in [local, pub] {
            var info = stat()
            #expect(stat(url.path, &info) == 0 && info.st_mode & 0o777 == 0o600)
            #expect((try? String(contentsOf: url, encoding: .utf8)) == "[]")
        }
    }

    @Test("the temp file is never group- or other-readable, and it is the file that lands at the path")
    func tempFileOwnerOnly() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let (writer, local, _) = makeWriter(logDir: dir, dir: dir)
        let contents = String(repeating: "x", count: 100_000)

        var seen: (path: String, info: stat)?
        writer.writeFile(contents, to: local, permissions: 0o600, beforeRename: { temp in
            var info = stat()
            if stat(temp, &info) == 0 { seen = (temp, info) }
        })

        let (temp, info) = try #require(seen)
        #expect(info.st_mode & 0o077 == 0)                    // with every byte already in it:
        #expect(info.st_size == off_t(contents.utf8.count))
        #expect((temp as NSString).deletingLastPathComponent == dir.path)   // beside the target,
        var landed = stat()
        #expect(stat(local.path, &landed) == 0 && landed.st_ino == info.st_ino)   // and renamed onto it
    }

    @Test("a successful write leaves no temp file behind")
    func noTempFileLeft() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (writer, _, _) = makeWriter(logDir: dir, dir: dir)

        writer.write(debugEnabled: true, now: now)
        writer.write(debugEnabled: true, now: now)   // and over the files already there

        // Hidden files included: the temp names start with a dot.
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
        #expect(names == ["fleet-events.json", "recent-events.json"])
    }

    @Test("a failed write leaves no temp file behind and doesn't crash")
    func failedWriteCleansUp() throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // The folder can't be created: a regular file is in the way.
        let blocker = dir.appendingPathComponent("not-a-folder")
        try "x".write(to: blocker, atomically: false, encoding: .utf8)
        let (blocked, _, _) = makeWriter(logDir: dir, dir: blocker)
        blocked.write(debugEnabled: true, now: Date(timeIntervalSince1970: 1_700_000_000))
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["not-a-folder"])

        // The rename fails (a folder is at the path) after the temp file is written.
        let (writer, local, _) = makeWriter(logDir: dir, dir: dir)
        try FileManager.default.createDirectory(at: local, withIntermediateDirectories: false)
        var temp: String?
        writer.writeFile("[]", to: local, permissions: 0o600, beforeRename: { path in
            if FileManager.default.fileExists(atPath: path) { temp = path }
        })
        let written = try #require(temp)
        #expect(!FileManager.default.fileExists(atPath: written))
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
        #expect(names == ["not-a-folder", "recent-events.json"])
    }

    @Test("the in-memory argument store is bounded and ages out")
    func debugArgumentStoreBounded() {
        let store = DebugArgumentStore()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        for index in 0..<(DebugArgumentStore.capacity + 50) {
            store.record(eventID: UUID(), arguments: ["a"], at: now.addingTimeInterval(TimeInterval(index)))
        }
        #expect(store.snapshot(since: .distantPast).count == DebugArgumentStore.capacity)
        #expect(store.snapshot(since: now.addingTimeInterval(1_000_000)).isEmpty)
        store.record(eventID: UUID(), arguments: [], at: now)   // nothing to keep
        #expect(store.snapshot(since: .distantPast).count == DebugArgumentStore.capacity)
    }
}
