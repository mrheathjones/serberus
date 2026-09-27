import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// P3-daemon-sources: the untrusted-input frontier ``JamfConnectStateSource``.
/// These exercise the real TOCTOU-safe file read against temp files owned by
/// the current test user (the console uid is set to `getuid()` so ownership
/// checks pass without root). Each case pins a fail-safe outcome.
@Suite("Jamf Connect state source")
struct JamfConnectStateSourceTests {

    // MARK: Fixture

    /// A temp "home" directory that is cleaned up at deinit.
    private final class TempHome {
        let url: URL
        init() {
            url = FileManager.default.temporaryDirectory
                .appendingPathComponent("serberus-jcstate-\(UUID().uuidString)", isDirectory: true)
            try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
        deinit { try? FileManager.default.removeItem(at: url) }
    }

    private let relPath = "Library/Preferences/com.jamf.connect.state.plist"

    private func consoleUser(home: URL, uid: uid_t = getuid()) -> ConsoleUser {
        ConsoleUser(uid: uid, name: "tester", homeDir: home.path)
    }

    private func config(
        source: IDPGroupSource = .jamfConnectState,
        statePath: String? = nil,
        groupsKey: String = "UserGroups",
        requireRootOwnedState: Bool = false
    ) -> SerberusConfig.SudoEnrollment {
        SerberusConfig.SudoEnrollment(
            idpGroups: ["Test-Name"],
            idpSource: source,
            idpStatePath: statePath ?? relPath,
            idpGroupsKey: groupsKey,
            requireRootOwnedState: requireRootOwnedState)
    }

    /// Write a plist object at `home/relPath`, creating parent dirs, then chmod.
    @discardableResult
    private func writeState(_ object: Any, home: URL, at rel: String? = nil, mode: mode_t = 0o644) throws -> URL {
        let fileURL = home.appendingPathComponent(rel ?? relPath)
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
        try data.write(to: fileURL)
        _ = fileURL.path.withCString { chmod($0, mode) }
        return fileURL
    }

    // MARK: Happy path

    @Test("valid owner-writable state file yields the group array")
    func validClaim() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Engineering", "Test-Name"]], home: home.url, mode: 0o644)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim?.groups == ["Engineering", "Test-Name"])
        #expect(claim?.ownerWritable == true)
    }

    @Test("owner read-only file parses and reports ownerWritable false")
    func ownerReadOnly() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Test-Name"]], home: home.url, mode: 0o444)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim?.groups == ["Test-Name"])
        #expect(claim?.ownerWritable == false)
    }

    @Test("non-string group entries are filtered out")
    func filtersNonStrings() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Test-Name", 42, ["nested"]] as [Any]], home: home.url)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim?.groups == ["Test-Name"])
    }

    @Test("custom groups key is honored")
    func customGroupsKey() throws {
        let home = TempHome()
        try writeState(["Groups": ["Test-Name"]], home: home.url)
        let claim = try JamfConnectStateSource().readClaim(
            for: consoleUser(home: home.url), config: config(groupsKey: "Groups"))
        #expect(claim?.groups == ["Test-Name"])
    }

    // MARK: Fail-safe nil returns

    @Test("disabled/other source selector is a no-op")
    func wrongSelectorNoOp() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Test-Name"]], home: home.url)
        let claim = try JamfConnectStateSource().readClaim(
            for: consoleUser(home: home.url), config: config(source: .disabled))
        #expect(claim == nil)
    }

    @Test("missing state file returns nil (stale)")
    func missingFile() throws {
        let home = TempHome()
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim == nil)
    }

    @Test("absolute idpStatePath is rejected fail-safe")
    func absolutePathRejected() throws {
        let home = TempHome()
        let claim = try JamfConnectStateSource().readClaim(
            for: consoleUser(home: home.url), config: config(statePath: "/etc/passwd"))
        #expect(claim == nil)
    }

    @Test("traversal idpStatePath is rejected fail-safe")
    func traversalRejected() throws {
        let home = TempHome()
        let claim = try JamfConnectStateSource().readClaim(
            for: consoleUser(home: home.url), config: config(statePath: "../../etc/passwd"))
        #expect(claim == nil)
    }

    @Test("missing groups key returns nil")
    func missingGroupsKey() throws {
        let home = TempHome()
        try writeState(["Other": "value"], home: home.url)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim == nil)
    }

    @Test("groups value that is not an array returns nil")
    func groupsNotArray() throws {
        let home = TempHome()
        try writeState(["UserGroups": "Test-Name"], home: home.url)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim == nil)
    }

    @Test("plist whose root is not a dictionary returns nil")
    func nonDictRoot() throws {
        let home = TempHome()
        try writeState(["just", "an", "array"], home: home.url)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim == nil)
    }

    @Test("non-plist bytes return nil")
    func nonPlistBytes() throws {
        let home = TempHome()
        let fileURL = home.url.appendingPathComponent(relPath)
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not a plist".utf8).write(to: fileURL)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim == nil)
    }

    // MARK: Refusals (throws)

    @Test("group-writable file is refused on ownership")
    func groupWritableRefused() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Test-Name"]], home: home.url, mode: 0o620)
        #expect(throws: IDPSourceRefusal.self) {
            _ = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        }
    }

    @Test("other-writable file is refused on ownership")
    func otherWritableRefused() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Test-Name"]], home: home.url, mode: 0o602)
        #expect(throws: IDPSourceRefusal.self) {
            _ = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        }
    }

    @Test("owner-uid mismatch is refused on ownership")
    func ownerMismatchRefused() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Test-Name"]], home: home.url, mode: 0o644)
        // File is owned by getuid(); tell the source a different console uid.
        let user = consoleUser(home: home.url, uid: getuid() &+ 1)
        do {
            _ = try JamfConnectStateSource().readClaim(for: user, config: config())
            Issue.record("expected an ownership refusal")
        } catch let refusal as IDPSourceRefusal {
            guard case .ownership = refusal else {
                Issue.record("expected .ownership, got \(refusal)")
                return
            }
        }
    }

    @Test("symlinked final component is refused as symlink")
    func symlinkRefused() throws {
        let home = TempHome()
        // Real target elsewhere in the home; state path is a symlink to it.
        let target = try writeState(["UserGroups": ["Test-Name"]], home: home.url, at: "real-state.plist")
        let linkURL = home.url.appendingPathComponent(relPath)
        try FileManager.default.createDirectory(
            at: linkURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: linkURL, withDestinationURL: target)
        #expect(throws: IDPSourceRefusal.symlink) {
            _ = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        }
    }

    @Test("a symlinked INTERMEDIATE component is refused (not just the leaf)")
    func intermediateSymlinkRefused() throws {
        let home = TempHome()
        // The console user owns their whole home, so they replace the INTERMEDIATE
        // `Library` component with a symlink to a sibling that holds a perfectly
        // valid, owner-legit state file. The old single `open(home + "/" + relPath,
        // O_NOFOLLOW)` would happily follow this (O_NOFOLLOW guards ONLY the leaf)
        // and read the redirected file; the openat walk refuses it as ELOOP.
        let realDir = home.url.appendingPathComponent("elsewhere/Preferences", isDirectory: true)
        try FileManager.default.createDirectory(at: realDir, withIntermediateDirectories: true)
        let realState = realDir.appendingPathComponent("com.jamf.connect.state.plist")
        let data = try PropertyListSerialization.data(
            fromPropertyList: ["UserGroups": ["Test-Name"]], format: .xml, options: 0)
        try data.write(to: realState)
        // home/Library → home/elsewhere  (the first path component is the symlink)
        try FileManager.default.createSymbolicLink(
            at: home.url.appendingPathComponent("Library"),
            withDestinationURL: home.url.appendingPathComponent("elsewhere"))

        // relPath = "Library/Preferences/com.jamf.connect.state.plist": the walk
        // hits the symlinked `Library` first and refuses — never following it.
        #expect(throws: IDPSourceRefusal.symlink) {
            _ = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        }
    }

    @Test("a symlinked intermediate is refused even in strict mode (no bypass to a root-owned plist)")
    func intermediateSymlinkRefusedUnderStrictMode() throws {
        // The intermediate-symlink redirect was also a strict-mode bypass vector
        // (aim the read at any root-owned, non-owner-writable plist carrying the
        // leaf name). The walk refuses at the symlink, before ownership is ever
        // consulted, so strict mode cannot be tricked into trusting a redirect.
        let home = TempHome()
        let realDir = home.url.appendingPathComponent("elsewhere/Preferences", isDirectory: true)
        try FileManager.default.createDirectory(at: realDir, withIntermediateDirectories: true)
        try PropertyListSerialization
            .data(fromPropertyList: ["UserGroups": ["Test-Name"]], format: .xml, options: 0)
            .write(to: realDir.appendingPathComponent("com.jamf.connect.state.plist"))
        try FileManager.default.createSymbolicLink(
            at: home.url.appendingPathComponent("Library"),
            withDestinationURL: home.url.appendingPathComponent("elsewhere"))

        #expect(throws: IDPSourceRefusal.symlink) {
            _ = try JamfConnectStateSource().readClaim(
                for: consoleUser(home: home.url), config: config(requireRootOwnedState: true))
        }
    }

    @Test("a deep, legitimate (non-symlink) path still reads through the walk")
    func deepLegitPathStillReads() throws {
        // The three-component default relPath is exercised by the happy-path tests
        // already; this pins an even deeper real directory chain to prove the walk
        // descends legitimate intermediates without refusing them.
        let home = TempHome()
        let deep = "Library/Application Support/Serberus/nested/com.jamf.connect.state.plist"
        try writeState(["UserGroups": ["Test-Name"]], home: home.url, at: deep)
        let claim = try JamfConnectStateSource().readClaim(
            for: consoleUser(home: home.url), config: config(statePath: deep))
        #expect(claim?.groups == ["Test-Name"])
    }

    @Test("a directory at the state path is refused (non-regular)")
    func nonRegularRefused() throws {
        let home = TempHome()
        let dirURL = home.url.appendingPathComponent(relPath, isDirectory: true)
        try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        #expect(throws: IDPSourceRefusal.symlink) {
            _ = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        }
    }

    @Test("requireRootOwnedState refuses a user-owned file with strictReject")
    func strictRejectsUserOwned() throws {
        let home = TempHome()
        try writeState(["UserGroups": ["Test-Name"]], home: home.url, mode: 0o644)
        #expect(throws: IDPSourceRefusal.strictReject) {
            _ = try JamfConnectStateSource().readClaim(
                for: consoleUser(home: home.url), config: config(requireRootOwnedState: true))
        }
    }

    // MARK: Hard-link guard

    @Test("a hard-linked state file (st_nlink > 1) is refused — the strict-mode hard-link bypass")
    func hardLinkRefused() throws {
        let home = TempHome()
        // Stand-in for a root-owned file elsewhere carrying a matching group:
        // the user hard-links it into their own ~/Library/Preferences.
        let elsewhere = home.url.appendingPathComponent("elsewhere.plist")
        let data = try PropertyListSerialization.data(fromPropertyList: ["UserGroups": ["Test-Name"]],
                                                      format: .xml, options: 0)
        try data.write(to: elsewhere)
        let target = home.url.appendingPathComponent(relPath)
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        #expect(link(elsewhere.path, target.path) == 0)

        #expect(throws: IDPSourceRefusal.self) {
            _ = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        }
        // Once the second name is gone the same file reads normally.
        try FileManager.default.removeItem(at: elsewhere)
        let claim = try JamfConnectStateSource().readClaim(for: consoleUser(home: home.url), config: config())
        #expect(claim?.groups == ["Test-Name"])
    }

    @Test("the hard-link guard needs exactly one link on the home directory's device")
    func hardLinkGuardPredicate() {
        #expect(JamfConnectStateSource.isSingleLinkOnHomeVolume(linkCount: 1, fileDevice: 7, homeDevice: 7))
        #expect(!JamfConnectStateSource.isSingleLinkOnHomeVolume(linkCount: 2, fileDevice: 7, homeDevice: 7))
        #expect(!JamfConnectStateSource.isSingleLinkOnHomeVolume(linkCount: 1, fileDevice: 8, homeDevice: 7))
        #expect(!JamfConnectStateSource.isSingleLinkOnHomeVolume(linkCount: 0, fileDevice: 7, homeDevice: 7))
    }
}

/// Defense in depth against a hung read: the off-actor read timeout wrapper. A read that
/// blocks past the budget must return a fail-safe refusal (`nil`) PROMPTLY —
/// abandoning the blocked worker — so a hung mountpoint can never pin the daemon
/// actor and brick machine-wide sudo.
@Suite("Off-actor read timeout wrapper")
struct DetachedTimeoutTests {

    @Test("a fast closure returns its value")
    func fastClosureReturnsValue() async {
        let result = await withDetachedTimeout(seconds: 5) { 42 }
        #expect(result == 42)
    }

    @Test("a value of zero (not nil) is distinguishable from a timeout")
    func zeroValueIsNotTimeout() async {
        let result = await withDetachedTimeout(seconds: 5) { 0 }
        #expect(result == 0) // a real 0, not the nil-means-timeout sentinel
    }

    @Test("a closure that outlasts the budget returns nil (refusal) without waiting it out")
    func blockedClosureTimesOut() async {
        let started = Date()
        // A blocking closure that outlives the timeout by an order of magnitude.
        // `Thread.sleep` (not `Task.sleep`) does NOT honor cancellation — exactly
        // like a real blocking `openat` on a hung mount — so this proves the
        // wrapper returns on the timeout, not on the block completing.
        let result: Int? = await withDetachedTimeout(seconds: 0.2) {
            Thread.sleep(forTimeInterval: 2)
            return 7
        }
        let elapsed = Date().timeIntervalSince(started)
        #expect(result == nil)          // fail-safe refusal
        #expect(elapsed < 1.5)          // returned promptly, did not wait out the block
    }

    @Test("a non-positive budget collapses to an immediate timeout")
    func nonPositiveBudgetTimesOutImmediately() async {
        let result: Int? = await withDetachedTimeout(seconds: 0) {
            Thread.sleep(forTimeInterval: 1)
            return 7
        }
        #expect(result == nil)
    }
}
