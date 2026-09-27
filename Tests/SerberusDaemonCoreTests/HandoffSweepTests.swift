import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("PrivilegedLogCollector — no-follow hand-off removal", .serialized)
struct HandoffSweepTests {
    private func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-sweep-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test("symlinks planted inside a hand-off (at any depth) are unlinked, never followed")
    func neverFollowsSymlinks() throws {
        let root = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fm = FileManager.default

        // Something the "user" must not be able to get root to delete.
        let protected = root.appendingPathComponent("protected", isDirectory: true)
        try fm.createDirectory(at: protected, withIntermediateDirectories: true)
        let precious = protected.appendingPathComponent("precious.txt")
        try Data("keep".utf8).write(to: precious)

        // The captures parent + one user-controlled hand-off full of traps.
        let captures = root.appendingPathComponent("captures", isDirectory: true)
        let handoff = captures.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let nested = handoff.appendingPathComponent("a/b", isDirectory: true)
        try fm.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data("log".utf8).write(to: handoff.appendingPathComponent("unified-log.ndjson"))
        try fm.createSymbolicLink(at: handoff.appendingPathComponent("link-to-dir"), withDestinationURL: protected)
        try fm.createSymbolicLink(at: nested.appendingPathComponent("deep-link"), withDestinationURL: protected)
        try fm.createSymbolicLink(at: handoff.appendingPathComponent("link-to-file"), withDestinationURL: precious)

        let removed = PrivilegedLogCollector.removeTreeNoFollow(parent: captures.path,
                                                               name: handoff.lastPathComponent)

        #expect(removed)
        #expect(!fm.fileExists(atPath: handoff.path))
        #expect(fm.fileExists(atPath: precious.path))                         // target untouched
        #expect((try? String(contentsOf: precious, encoding: .utf8)) == "keep")
        #expect(fm.fileExists(atPath: captures.path))                         // parent kept
    }

    @Test("a hand-off that IS a symlink is removed as a link; its target survives")
    func topLevelSymlink() throws {
        let root = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fm = FileManager.default
        let target = root.appendingPathComponent("target", isDirectory: true)
        try fm.createDirectory(at: target, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: target.appendingPathComponent("f"))
        let captures = root.appendingPathComponent("captures", isDirectory: true)
        try fm.createDirectory(at: captures, withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: captures.appendingPathComponent("evil"), withDestinationURL: target)

        #expect(PrivilegedLogCollector.removeTreeNoFollow(parent: captures.path, name: "evil"))
        #expect(fm.fileExists(atPath: target.appendingPathComponent("f").path))
    }

    @Test("path-like names are refused")
    func refusesPathNames() throws {
        let root = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(!PrivilegedLogCollector.removeTreeNoFollow(parent: root.path, name: ".."))
        #expect(!PrivilegedLogCollector.removeTreeNoFollow(parent: root.path, name: "a/b"))
        #expect(FileManager.default.fileExists(atPath: root.path))
    }

    @Test("the hand-off never changes a symlink's target, and removes the link")
    func handOffRefusesSymlinks() throws {
        let root = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fm = FileManager.default
        let outside = root.appendingPathComponent("outside.txt")
        try Data("keep".utf8).write(to: outside)
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: outside.path)

        let handoff = root.appendingPathComponent("handoff", isDirectory: true)
        try fm.createDirectory(at: handoff, withIntermediateDirectories: false)
        let regular = handoff.appendingPathComponent("unified-log.ndjson")
        try Data("log".utf8).write(to: regular)
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: regular.path)
        let link = handoff.appendingPathComponent("pam-sudo_local")
        try fm.createSymbolicLink(at: link, withDestinationURL: outside)

        try PrivilegedLogCollector.handOffNoFollow(directory: handoff.path, to: getuid())

        // The link's target keeps its mode; the link itself is gone.
        let outsideMode = (try fm.attributesOfItem(atPath: outside.path)[.posixPermissions] as? NSNumber)?.intValue
        #expect(outsideMode == 0o644)
        #expect((try? fm.destinationOfSymbolicLink(atPath: link.path)) == nil)
        // Regular files and the directory are handed over.
        let fileMode = (try fm.attributesOfItem(atPath: regular.path)[.posixPermissions] as? NSNumber)?.intValue
        #expect(fileMode == 0o600)
        let dirMode = (try fm.attributesOfItem(atPath: handoff.path)[.posixPermissions] as? NSNumber)?.intValue
        #expect(dirMode == 0o700)
    }

    @Test("wiring and grant copies refuse a symlinked source and copy regular files by content")
    func copyRefusesSymlinks() throws {
        let root = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fm = FileManager.default
        let source = root.appendingPathComponent("sudo_local")
        try Data("auth sufficient pam_serberus.so\n".utf8).write(to: source)
        let link = root.appendingPathComponent("linked")
        try fm.createSymbolicLink(at: link, withDestinationURL: source)

        let copy = root.appendingPathComponent("copy")
        try PrivilegedLogCollector.copyRegularFileNoFollow(from: source.path, to: copy.path)
        #expect(try Data(contentsOf: copy) == Data(contentsOf: source))
        #expect((try? fm.destinationOfSymbolicLink(atPath: copy.path)) == nil)

        let refused = root.appendingPathComponent("refused")
        #expect(throws: (any Error).self) {
            try PrivilegedLogCollector.copyRegularFileNoFollow(from: link.path, to: refused.path)
        }
        #expect(!fm.fileExists(atPath: refused.path))
    }
}

@Suite("DaemonController — program-aware argv redaction")
struct DaemonArgvRedactionTests {
    @Test("a logged decision's argv is re-redacted with its sudoCommand (security -w)")
    func securityDashWRedacted() {
        let event = DecisionEvent(
            timestamp: Date(), outcome: .granted, enforcementMode: .enforce,
            authURI: nil, sudoCommand: "/usr/bin/security",
            arguments: ["add-generic-password", "-s", "svc", "-w", "hunter2"],
            processPath: "/usr/bin/security", processTeamID: "", processHash: "",
            userName: "alice", userUID: 501, ruleID: "r", profileKey: nil, grantID: nil,
            justification: nil, grantDurationSeconds: 0, cacheHit: false,
            deviceSerial: "S", daemonVersion: "t", pamModuleVersion: "t", policyVersion: "1"
        )
        // The event initializer alone cannot know the tool (argv excludes it)…
        #expect(event.arguments?.last == "hunter2")
        let outcome = PAMEvaluator.Outcome(response: .deny, event: event, issuedGrant: nil)
        // …the daemon's pass supplies it.
        let redacted = DaemonController.redactingArguments(outcome)
        #expect(redacted.event.arguments == ["add-generic-password", "-s", "svc", "-w", ArgumentRedactor.placeholder])
    }
}

@Suite("DaemonController — install/uninstall paths in the decision log")
struct AppManagementLogPathTests {
    @Test("a path in a user's folder keeps only its file name and a hash")
    func userPathShortened() {
        let logged = DaemonController.decisionLogPath("/Users/alice/Documents/Project X/Tool.pkg")
        #expect(logged.hasPrefix("…/Tool.pkg [sha256:"))
        #expect(!logged.contains("alice") && !logged.contains("Project X"))
        // Stable, and different for a different folder.
        #expect(logged == DaemonController.decisionLogPath("/Users/alice/Documents/Project X/Tool.pkg"))
        #expect(logged != DaemonController.decisionLogPath("/Users/bob/Downloads/Tool.pkg"))
    }

    @Test("an unresolved request is shortened too; public locations are kept whole")
    func unresolvedAndPublic() {
        let unresolved = DaemonController.decisionLogPath("unresolved:/Users/alice/secret-plans/App.app")
        #expect(unresolved.hasPrefix("unresolved:…/App.app [sha256:"))
        #expect(!unresolved.contains("secret-plans"))
        #expect(DaemonController.decisionLogPath("/Applications/Safari.app") == "/Applications/Safari.app")
        #expect(DaemonController.decisionLogPath("/Applications/../Users/a/x.app") != "/Applications/../Users/a/x.app")
        #expect(DaemonController.decisionLogPath("/private/tmp/x.pkg").hasPrefix("…/x.pkg"))
    }

    @Test("home-folder paths inside a result message are shortened")
    func messageScrubbed() {
        let message = DaemonController.scrubUserPaths("Couldn't read /Users/alice/Private/Tool.pkg for verification.")
        #expect(!message.contains("alice") && message.contains("…/Tool.pkg"))
        #expect(DaemonController.scrubUserPaths("Refused “Tool”: not trusted.") == "Refused “Tool”: not trusted.")
    }
}
