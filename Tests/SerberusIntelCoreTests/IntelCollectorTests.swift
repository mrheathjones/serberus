import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

/// Builds a fake endpoint layout so collection is exercised without a daemon.
private struct Fixture {
    let root: URL
    let paths: IntelPaths
    let destination: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("capture-tests-\(UUID().uuidString)", isDirectory: true)

        let logs = root.appendingPathComponent("Logs", isDirectory: true)
        let managed = root.appendingPathComponent("Managed Preferences", isDirectory: true)
        let support = root.appendingPathComponent("Support", isDirectory: true)
        destination = root.appendingPathComponent("out", isDirectory: true)
        for directory in [logs, managed, support, destination] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        try Data("{}\n".utf8).write(to: logs.appendingPathComponent("decisions-2026-07-16.jsonl"))
        try Data("sig".utf8).write(to: logs.appendingPathComponent("decisions-2026-07-16.jsonl.hmac"))
        try Data("{}\n".utf8).write(to: logs.appendingPathComponent("integrity-2026-07-16.jsonl"))
        try Data("noise".utf8).write(to: logs.appendingPathComponent("unrelated.txt"))

        try Data("<plist/>".utf8)
            .write(to: managed.appendingPathComponent("com.herojoneslabs.serberus.config.plist"))
        try Data("<plist/>".utf8)
            .write(to: managed.appendingPathComponent("com.herojoneslabs.serberus.rules.sudo.plist"))
        try Data("<plist/>".utf8)
            .write(to: managed.appendingPathComponent("com.apple.loginwindow.plist"))

        try Data("<plist/>".utf8).write(to: support.appendingPathComponent("state.plist"))

        paths = IntelPaths(
            jsonlLogDirectory: logs,
            managedPreferencesDirectory: managed,
            statePlist: support.appendingPathComponent("state.plist"),
            versionPlist: support.appendingPathComponent("version.plist"),   // deliberately absent
            lastKnownGoodConfig: support.appendingPathComponent("lkg.plist") // deliberately absent
        )
    }

    func cleanUp() { try? FileManager.default.removeItem(at: root) }
}

private let stubEntry = LogEntry(
    timestamp: "2026-07-16 19:19:06.595808-0400",
    level: .error,
    subsystem: "com.herojoneslabs.serberus",
    category: "decisions",
    message: "denied /usr/bin/jamf recon",
    processImagePath: "/usr/bin/sudo",
    processID: 42
)

@Suite("IntelCollector")
struct IntelCollectorTests {
    /// Builds a collector with BOTH privileged paths stubbed.
    ///
    /// `privilegedSource` defaults to "daemon unavailable" so tests never open
    /// a real XPC connection to whatever daemon happens to be on the build
    /// machine — that would make results depend on the host.
    private func makeCollector(
        _ fixture: Fixture,
        logSource: (@Sendable (LogWindow) async throws -> [LogEntry])? = nil,
        privilegedSource: (@Sendable (IntelRequest) async throws -> IntelHandoff)? = nil
    ) -> IntelCollector {
        IntelCollector(
            paths: fixture.paths,
            now: { Date(timeIntervalSince1970: 1_784_000_000) },
            logSource: logSource ?? { _ in [stubEntry] },
            privilegedSource: privilegedSource ?? { _ in
                throw IntelXPCClient.ClientError.unavailable("no daemon in tests")
            }
        )
    }

    @Test("produces a zip and a manifest")
    func producesArchive() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let bundle = try await makeCollector(fixture)
            .collect(window: .oneHour, destinationDirectory: fixture.destination)

        #expect(FileManager.default.fileExists(atPath: bundle.archiveURL.path))
        #expect(bundle.archiveURL.pathExtension == "zip")
        #expect(bundle.manifest.window == "1h")
        #expect(bundle.manifest.predicate == LogQuery.predicate)
    }

    @Test("staging directory is removed, leaving only the zip")
    func stagingCleanedUp() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        _ = try await makeCollector(fixture)
            .collect(window: .oneHour, destinationDirectory: fixture.destination)

        let leftovers = try FileManager.default
            .contentsOfDirectory(atPath: fixture.destination.path)
        #expect(leftovers.allSatisfy { $0.hasSuffix(".zip") })
    }

    @Test("collects the signed JSONL together with its hmac sidecar")
    func collectsSignedLogs() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let bundle = try await makeCollector(fixture)
            .collect(window: .oneHour, destinationDirectory: fixture.destination)
        let collected = bundle.manifest.artifacts.filter { $0.status.isCollected }.map(\.path)

        // The sidecar is what makes the decision log tamper-evident; shipping
        // the log without it would make it unverifiable.
        #expect(collected.contains("jsonl-logs/decisions-2026-07-16.jsonl"))
        #expect(collected.contains("jsonl-logs/decisions-2026-07-16.jsonl.hmac"))
        #expect(collected.contains("jsonl-logs/integrity-2026-07-16.jsonl"))
        #expect(!collected.contains("jsonl-logs/unrelated.txt"))
    }

    @Test("collects every serberus managed domain, including rules sub-domains, and nothing else")
    func collectsManagedPreferences() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let bundle = try await makeCollector(fixture)
            .collect(window: .oneHour, destinationDirectory: fixture.destination)
        let collected = bundle.manifest.artifacts.filter { $0.status.isCollected }.map(\.path)

        // Rules compose across `…rules.<suffix>` sub-domains, so a fixed
        // domain list would miss exactly the profile a rules bug involves.
        #expect(collected.contains("managed-preferences/com.herojoneslabs.serberus.config.plist"))
        #expect(collected.contains("managed-preferences/com.herojoneslabs.serberus.rules.sudo.plist"))
        #expect(!collected.contains { $0.contains("com.apple.loginwindow") })
    }

    @Test("a missing file is recorded as unavailable, not dropped")
    func missingFilesAreRecorded() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let bundle = try await makeCollector(fixture)
            .collect(window: .oneHour, destinationDirectory: fixture.destination)

        let missing = bundle.manifest.missing.map(\.path)
        #expect(missing.contains("state/version.plist"))
        #expect(missing.contains("state/lkg.plist"))
        // A bundle that omits a file silently is indistinguishable from one
        // where the file was empty.
        for artifact in bundle.manifest.missing {
            if case let .unavailable(reason) = artifact.status {
                #expect(!reason.isEmpty)
            }
        }
    }

    @Test("without the daemon, the root-only grant database is reported as unavailable with a reason")
    func grantsUnavailableWithoutDaemon() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let bundle = try await makeCollector(fixture)
            .collect(window: .oneHour, destinationDirectory: fixture.destination)
        let grants = try #require(bundle.manifest.artifacts.first { $0.path == "state/grants.sqlite" })

        guard case let .unavailable(reason) = grants.status else {
            Issue.record("grants cannot be read by an unprivileged capture without the daemon")
            return
        }
        // Names the daemon as the reason, so a reader knows this is a daemon
        // problem rather than "no grants exist".
        #expect(reason.contains("daemon"))
    }

    @Test("with the daemon, privileged artifacts land in the bundle")
    func adoptsDaemonHandoff() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        // Stand in for the daemon's hand-off directory.
        let handoffDir = fixture.root.appendingPathComponent("handoff", isDirectory: true)
        try FileManager.default.createDirectory(at: handoffDir, withIntermediateDirectories: true)
        try Data(#"{"eventMessage":"pam denied"}"#.utf8)
            .write(to: handoffDir.appendingPathComponent("unified-log.ndjson"))
        try Data(#"{"eventMessage":"denied authorizing right 'system.preferences.datetime'"}"#.utf8)
            .write(to: handoffDir.appendingPathComponent("authorization-log.ndjson"))
        try Data("sqlite".utf8).write(to: handoffDir.appendingPathComponent("grants.sqlite"))
        try Data("Defaults:alice timestamp_timeout=0".utf8)
            .write(to: handoffDir.appendingPathComponent("sudoers-serberus"))

        let bundle = try await makeCollector(fixture, privilegedSource: { request in
            #expect(request.window == "1h")
            return IntelHandoff(
                directory: handoffDir.path,
                files: ["unified-log.ndjson", "authorization-log.ndjson", "grants.sqlite", "sudoers-serberus"],
                unavailable: ["pam-sudo_local": "PAM wiring not present at /etc/pam.d/sudo_local"]
            )
        }).collect(window: .oneHour, destinationDirectory: fixture.destination)

        let collected = bundle.manifest.artifacts.filter { $0.status.isCollected }.map(\.path)
        // The whole point: a standard user's bundle now carries the lines they
        // cannot read for themselves.
        #expect(collected.contains("unified-log.ndjson"))
        // authURI events — the two logs sit together at the top level.
        #expect(collected.contains("authorization-log.ndjson"))
        #expect(collected.contains("state/grants.sqlite"))
        #expect(collected.contains("state/sudoers-serberus"))
        // And the daemon's own "couldn't get this" reasons are preserved.
        #expect(bundle.manifest.missing.map(\.path).contains("state/pam-sudo_local"))
    }

    @Test("the daemon's hand-off directory is removed once adopted")
    func handoffIsCleanedUp() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let handoffDir = fixture.root.appendingPathComponent("handoff2", isDirectory: true)
        try FileManager.default.createDirectory(at: handoffDir, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: handoffDir.appendingPathComponent("unified-log.ndjson"))

        _ = try await makeCollector(fixture, privilegedSource: { _ in
            IntelHandoff(directory: handoffDir.path, files: ["unified-log.ndjson"], unavailable: [:])
        }).collect(window: .oneHour, destinationDirectory: fixture.destination)

        // It holds every Serberus log line on the Mac and is chowned to this
        // user — it must not be left lying around after the copy.
        #expect(!FileManager.default.fileExists(atPath: handoffDir.path))
    }

    @Test("a failing log query degrades to an unavailable artifact instead of failing the capture")
    func logFailureDegrades() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let collector = makeCollector(fixture) { _ in
            throw LogReaderError.toolFailed(exitCode: 1, stderr: "boom")
        }
        // The whole point of the manifest: a partial bundle still ships.
        let bundle = try await collector.collect(window: .oneHour, destinationDirectory: fixture.destination)

        let log = try #require(bundle.manifest.artifacts.first { $0.path == "unified-log.ndjson" })
        #expect(!log.status.isCollected)
        #expect(FileManager.default.fileExists(atPath: bundle.archiveURL.path))
    }

    @Test("the zip expands into one folder and carries no AppleDouble junk")
    func archiveIsClean() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanUp() }

        let bundle = try await makeCollector(fixture)
            .collect(window: .oneHour, destinationDirectory: fixture.destination)

        let list = Process()
        list.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        list.arguments = ["-Z", "-1", bundle.archiveURL.path]
        let pipe = Pipe()
        list.standardOutput = pipe
        try list.run()
        let output = String(decoding: (try pipe.fileHandleForReading.readToEnd()) ?? Data(), as: UTF8.self)
        list.waitUntilExit()

        let names = output.split(separator: "\n").map(String.init)
        // ditto sequesters xattrs/resource forks into a parallel __MACOSX/._*
        // tree unless told not to — pure noise in a support bundle.
        #expect(!names.contains { $0.hasPrefix("__MACOSX") })
        #expect(!names.contains { $0.contains("/._") })
        // --keepParent: everything lives under one folder, so expanding the
        // zip never scatters files across the reader's Downloads directory.
        let stem = bundle.archiveURL.deletingPathExtension().lastPathComponent
        #expect(names.allSatisfy { $0.hasPrefix(stem + "/") })
        #expect(names.contains("\(stem)/manifest.json"))
    }

    @Test("filename timestamp is filesystem- and header-safe")
    func timestampIsSafe() {
        // Cross-checked against `date -u -r 1784000000` — the stamp is UTC,
        // so a bundle's name means the same thing in every timezone.
        let stamp = IntelCollector.fileTimestamp(Date(timeIntervalSince1970: 1_784_000_000))
        #expect(stamp == "20260714-033320Z")
        #expect(!stamp.contains(":"))
        #expect(!stamp.contains(" "))
        #expect(!stamp.contains("/"))
    }

    @Test("text rendering includes the fields a reader triages on")
    func rendersReadableLine() {
        let line = IntelCollector.renderLine(stubEntry)
        #expect(line.contains("denied /usr/bin/jamf recon"))
        #expect(line.contains("decisions"))
        #expect(line.contains("sudo"))
        #expect(line.contains("Error"))
    }
}
