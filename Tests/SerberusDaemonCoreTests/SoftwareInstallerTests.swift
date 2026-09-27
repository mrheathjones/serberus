import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("SoftwareInstaller — the root-install trust pipeline")
struct SoftwareInstallerTests {
    /// A scripted command runner: matches on the tool's last path component and
    /// returns a canned (status, stdout). Records the argv it saw.
    final class FakeRunner: InstallCommandRunning, @unchecked Sendable {
        struct Reply { var status: Int32; var stdout: String = ""; var stderr: String = "" }
        private let lock = NSLock()
        var replies: [String: Reply]
        private(set) var calls: [(tool: String, args: [String])] = []
        /// The (user, working directory) of each run-as-user call.
        private(set) var userRuns: [(user: FileOwner, directory: String)] = []
        /// When set, cp (staging) and ditto (into /Applications) also create
        /// the destination path, so they "copy".
        var copyCreatesDest = true
        /// Run just before the staging copy (to change the source mid-staging).
        var beforeStagingCopy: (() -> Void)?

        init(_ replies: [String: Reply]) { self.replies = replies }

        /// The PackageInfo `pkgutil --expand` writes (nil: expand creates nothing).
        var expandedPackageInfo: String? = SoftwareInstallerTests.plainPackageInfo
        /// Extra files `pkgutil --expand` writes at the top level (name → contents).
        var expandedExtras: [String: String] = [:]

        /// Mimics a run as the user: a relative destination lands in the
        /// working directory.
        func runAsUser(_ path: String, _ arguments: [String], user: FileOwner, workingDirectory: String,
                       timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
            lock.withLock { userRuns.append((user, workingDirectory)) }
            var resolved = arguments
            if let last = resolved.last, !last.hasPrefix("/") {
                resolved[resolved.count - 1] = (workingDirectory as NSString).appendingPathComponent(last)
            }
            let r = await run(path, resolved, timeout: timeout)
            // Record what the tool was really given.
            lock.withLock { if !calls.isEmpty { calls[calls.count - 1].args = arguments } }
            return r
        }

        func run(_ path: String, _ arguments: [String], timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
            let tool = (path as NSString).lastPathComponent
            lock.withLock { calls.append((tool, arguments)) }
            if tool == "pkgutil", arguments.first == "--expand", let dest = arguments.last {
                // Mimic `pkgutil --expand`: a directory holding PackageInfo.
                try? FileManager.default.createDirectory(atPath: dest, withIntermediateDirectories: true)
                if let info = lock.withLock({ expandedPackageInfo }) {
                    try? Data(info.utf8).write(to: URL(fileURLWithPath: dest).appendingPathComponent("PackageInfo"))
                }
                for (name, body) in lock.withLock({ expandedExtras }) {
                    try? Data(body.utf8).write(to: URL(fileURLWithPath: dest).appendingPathComponent(name))
                }
                let r = lock.withLock { replies["pkgutil-expand"] } ?? Reply(status: 0)
                return (r.status, r.stdout, r.stderr)
            }
            if tool == "cp", let hook = lock.withLock({ () -> (() -> Void)? in
                defer { beforeStagingCopy = nil }
                return beforeStagingCopy
            }) {
                hook()
            }
            if tool == "cp" || tool == "ditto", copyCreatesDest, arguments.count >= 2, let dest = arguments.last {
                // Mimic cp/ditto: copy the source when it exists (so a staged .app
                // keeps its Info.plist), else create a placeholder.
                let source = arguments[arguments.count - 2]
                if FileManager.default.fileExists(atPath: source) {
                    try? FileManager.default.copyItem(atPath: source, toPath: dest)
                } else {
                    try? FileManager.default.createDirectory(atPath: dest, withIntermediateDirectories: true)
                }
            }
            let r = lock.withLock { replies[tool] } ?? Reply(status: 0)
            // "{PATH}" in a canned reply stands for the path the tool was run on,
            // as spctl echoes it.
            let path = arguments.last ?? ""
            return (r.status, r.stdout.replacingOccurrences(of: "{PATH}", with: path),
                    r.stderr.replacingOccurrences(of: "{PATH}", with: path))
        }
    }

    /// Thread-safe holder for a value captured by the `@Sendable` confirm closure.
    final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var _value: String?
        var value: String? { lock.withLock { _value } }
        func set(_ v: String?) { lock.withLock { _value = v } }
    }

    private func tempDir() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-inst-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return URL(fileURLWithPath: SoftwareUninstaller.realPath(d.path), isDirectory: true)
    }

    /// A source .pkg (just a file) the user "chose".
    private func makeSource(_ dir: URL, name: String) throws -> String {
        let url = dir.appendingPathComponent(name)
        try Data("x".utf8).write(to: url)
        return url.path
    }

    static let acmeApp = SoftwareInstaller.Signer(teamID: "AB12CD34EF", authority: "Developer ID Application: Acme Inc (AB12CD34EF)")

    /// The staged copy (always `…/item.app`) is signed by `stagedSigner`; an
    /// installed app's team comes from `installedTeams[path]`. Files are
    /// "root-owned" as the current user, since tests can't chown to root.
    private func installer(_ runner: FakeRunner, staging: URL, apps: URL,
                           installedTeams: [String: String] = [:],
                           stagedSigner: SoftwareInstaller.Signer? = SoftwareInstallerTests.acmeApp,
                           gate: AppManagementGate = AppManagementGate(),
                           limits: SoftwareInstaller.SourceLimits = .standard,
                           freeSpace: @escaping @Sendable (String) -> UInt64? = { _ in .max },
                           callerCanRead: @escaping @Sendable (String, uid_t) -> Bool = { _, _ in true },
                           callerGroups: @escaping @Sendable (uid_t) -> Set<gid_t>? = { _ in [] },
                           installLocationIsRootOnly: @escaping @Sendable (String) -> Bool = { SoftwareInstaller.isRootOnlyInstallLocation($0) }) -> SoftwareInstaller {
        SoftwareInstaller(runner: runner, stagingRoot: staging, applicationsDir: apps, installTimeout: 5,
                          installOwner: FileOwner(uid: getuid(), gid: getgid()),
                          gate: gate, sourceLimits: limits, freeSpace: freeSpace, callerCanRead: callerCanRead,
                          callerGroups: callerGroups, installLocationIsRootOnly: installLocationIsRootOnly,
                          stagingUser: { _ in FileOwner(uid: getuid(), gid: getgid()) },
                          signerOfApp: { path in
                              if path.hasSuffix("/item.app") { return stagedSigner }
                              return installedTeams[path].map {
                                  SoftwareInstaller.Signer(teamID: $0, authority: "Developer ID Application: Installed (\($0))")
                              }
                          })
    }

    /// Install enabled, with the fixture publisher (AB12CD34EF) allowed.
    private let enabled = InstallPolicy(enabled: true, allowedPublisherTeamIDs: ["AB12CD34EF"])

    /// A minimal .app bundle: just an Info.plist declaring an application
    /// named after the folder, carrying `bundleID`.
    private func makeApp(_ dir: URL, name: String, bundleID: String) throws -> String {
        let contents = dir.appendingPathComponent(name).appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        let plist = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": bundleID, "CFBundlePackageType": "APPL",
                                                                          "CFBundleName": String(name.dropLast(4))],
                                                        format: .xml, options: 0)
        try plist.write(to: contents.appendingPathComponent("Info.plist"))
        return dir.appendingPathComponent(name).path
    }

    private let acceptedApp = FakeRunner.Reply(status: 0, stderr: "{PATH}: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Acme Inc (AB12CD34EF)\n")

    private let accepted = FakeRunner.Reply(status: 0, stderr: "{PATH}: accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: Acme Inc (AB12CD34EF)\n")

    /// Real-format `pkgutil --check-signature` output for the staged package.
    static func pkgutilOutput(leaf: String, packageName: String = "item.pkg") -> String {
        """
        Package "\(packageName)":
           Status: signed by a developer certificate issued by Apple for distribution
           Notarization: trusted by the Apple notary service
           Signed with a trusted timestamp on: 2026-09-21 16:29:41 +0000
           Certificate Chain:
            1. \(leaf)
               Expires: 2027-02-01 22:12:15 +0000
               SHA256 Fingerprint:
                   68 0F F3 72 93 85 F6 F6 35 51 1E E9 AE 9B C6 DE D5 1A BB 82 F4 44
               ------------------------------------------------------------------------
            2. Developer ID Certification Authority
               Expires: 2027-02-01 22:12:15 +0000
               ------------------------------------------------------------------------
            3. Apple Root CA
               Expires: 2035-02-09 21:40:36 +0000

        """
    }

    private let pkgutilAcme = FakeRunner.Reply(status: 0, stdout: SoftwareInstallerTests.pkgutilOutput(leaf: "Developer ID Installer: Acme Inc (AB12CD34EF)"))

    @Test("disabled policy refuses before doing anything")
    func refusedByPolicy() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner([:])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: .disabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedByPolicy)
        #expect(runner.calls.isEmpty)     // never staged, never assessed
    }

    @Test("root caller is refused")
    func refusesRoot() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let result = await installer(FakeRunner([:]), staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 0,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
    }

    @Test("a notarized Developer-ID pkg is staged, assessed, confirmed, then installed")
    func happyPkg() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "installer": .init(status: 0), "cp": .init(status: 0)])
        let apps = dir.appendingPathComponent("apps"); try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        let confirmedWith = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1",
                     confirm: { auth in confirmedWith.set(auth.authority); return true })
        #expect(result.status == .installed)
        #expect(confirmedWith.value?.contains("Developer ID Installer: Acme") == true)   // prompt got the authority
        // Order: cp (stage) → spctl (assess) → pkgutil (publisher) → pkgutil
        // (expand, relocation check) → installer (commit).
        #expect(runner.calls.map(\.tool) == ["cp", "spctl", "pkgutil", "pkgutil", "installer"])
        // installer ran on the STAGED copy under the staging dir, targeting /.
        let inst = runner.calls.first { $0.tool == "installer" }!.args
        #expect(inst.contains("-target") && inst.contains("/"))
        #expect(inst.contains { $0.hasSuffix("/stage/s1/item.pkg") })
    }

    @Test("a signed-but-NOT-notarized item is refused (never installed)")
    func refusesUnnotarized() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let devIDOnly = FakeRunner.Reply(status: 0, stderr: "{PATH}: accepted\nsource=Developer ID\norigin=Developer ID Installer: Acme Inc (AB12CD34EF)\n")
        let runner = FakeRunner(["spctl": devIDOnly, "installer": .init(status: 0), "cp": .init(status: 0)])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
        #expect(!runner.calls.contains { $0.tool == "installer" })   // never committed
    }

    @Test("Gatekeeper rejection is refused")
    func refusesRejected() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let rejected = FakeRunner.Reply(status: 3, stderr: "{PATH}: rejected\n")
        let runner = FakeRunner(["spctl": rejected, "cp": .init(status: 0)])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
    }

    @Test("declining the confirmation cancels — after the trust gate, before any commit")
    func cancel() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "cp": .init(status: 0)])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in false })
        #expect(result.status == .cancelled)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    @Test("a non-pkg/app source is refused")
    func rejectsUnknownKind() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "notes.txt")
        let result = await installer(FakeRunner([:]), staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "notes.txt"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
    }

    @Test("classify recognises a flat pkg and an app only; mpkg is not supported")
    func classify() {
        #expect(SoftwareInstaller.classify("/x/Foo.pkg") == .pkg)
        #expect(SoftwareInstaller.classify("/x/Foo.mpkg") == nil)
        #expect(SoftwareInstaller.classify("/Volumes/DMG/Foo.app") == .app)
        #expect(SoftwareInstaller.classify("/x/Foo.dmg") == nil)
        #expect(SoftwareInstaller.classify("/x/foo") == nil)
        #expect(SoftwareInstaller.stagedItemName(forSource: "/x/Foo.pkg") == "item.pkg")
        #expect(SoftwareInstaller.stagedItemName(forSource: "/x/Foo.mpkg") == nil)
        #expect(SoftwareInstaller.stagedItemName(forSource: "/x/Foo.app") == "item.app")
    }

    @Test("an mpkg is refused before anything is staged")
    func mpkgRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.mpkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.mpkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(runner.calls.isEmpty)
    }

    // MARK: - Publisher allowlist

    @Test("a publisher not on the allowlist is refused before the prompt")
    func publisherNotAllowed() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let asked = Box()
        let policy = InstallPolicy(enabled: true, allowedPublisherTeamIDs: ["ZZ99ZZ99ZZ"])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: policy, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedNotTrusted)
        #expect(asked.value == nil)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    @Test("enabling the feature with no publishers listed installs nothing")
    func emptyAllowlistRefusesAll() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: InstallPolicy(enabled: true), stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    @Test("the admin can allow any notarized publisher explicitly")
    func anyPublisherScope() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let policy = InstallPolicy(enabled: true, publisherScope: .any)
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: policy, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
    }

    @Test("the Team ID is read from the end of the signing authority", arguments: [
        ("Developer ID Installer: Acme Inc (AB12CD34EF)", "AB12CD34EF"),
        ("Developer ID Application: A (Co) Ltd (AB12CD34EF)", "AB12CD34EF"),
        ("Developer ID Installer: Acme Inc", nil),
        ("Developer ID Installer: Acme (ab12cd34ef)", nil),
        ("Developer ID Installer: Acme (AB12CD34E)", nil),
    ] as [(String, String?)])
    func teamIDParsing(authority: String, expected: String?) {
        #expect(SoftwareInstaller.teamID(fromAuthority: authority) == expected)
    }

    // MARK: - App placement

    @Test("an app may replace an installed app from the same publisher")
    func replaceSamePublisher() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let apps = dir.appendingPathComponent("apps")
        let installed = try makeApp(apps, name: "Foo.app", bundleID: "com.acme.foo")
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo")
        let runner = FakeRunner(["spctl": acceptedApp])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps,
                                     installedTeams: [installed: "AB12CD34EF"])
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
    }

    @Test("an app from a different publisher can't replace an installed one")
    func replaceDifferentPublisher() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let apps = dir.appendingPathComponent("apps")
        let installed = try makeApp(apps, name: "Browser.app", bundleID: "com.vendor.browser")
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Browser.app", bundleID: "com.vendor.browser")
        let runner = FakeRunner(["spctl": acceptedApp])
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps,
                                     installedTeams: [installed: "VENDOR1234"])
            .install(InstallRequest(sourcePath: src, displayName: "Browser.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(asked.value == nil)
    }

    @Test("an installed app that isn't Developer ID signed is never replaced, with its own reason")
    func replaceUnknownPublisher() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let apps = dir.appendingPathComponent("apps")
        _ = try makeApp(apps, name: "Foo.app", bundleID: "com.acme.foo")
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo")
        let runner = FakeRunner(["spctl": acceptedApp])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.message.contains("isn't Developer ID signed"))
        #expect(!result.message.contains("different publisher"))
    }

    @Test("an app can't claim a Serberus or protected bundle ID, or replace one", arguments: [
        ("com.herojoneslabs.serberus.sentinel", nil),
        ("com.jamf.management.Jamf", ["com.jamf.management.jamf"]),
    ] as [(String, [String]?)])
    func impersonationRefused(bundleID: String, protected: [String]?) async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Thing.app", bundleID: bundleID)
        let runner = FakeRunner(["spctl": acceptedApp])
        var policy = enabled
        policy.protectedBundleIdentifiers = protected ?? []
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Thing.app"), callerUID: 501,
                     policy: policy, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedByPolicy)
    }

    // MARK: - Control characters in paths

    @Test("the canonicalizer rejects any path containing a control character", arguments: [
        "/tmp/evil\norigin=Developer ID Installer: X (AB12CD34EF)\n.pkg",
        "/tmp/a\rb.pkg",
        "/tmp/tab\there.pkg",
        "/tmp/nul\u{0}.pkg",
        "/tmp/bell\u{7}.app",
        "/tmp/del\u{7F}.pkg",
    ])
    func controlCharactersRejected(path: String) {
        #expect(throws: PathError.self) {
            try PathCanonicalizer().canonicalize(path, existence: .allowMissing)
        }
    }

    @Test("a clean path that resolves through a symlink to a control-character name is rejected")
    func controlCharacterSymlinkTargetRejected() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let hostile = dir.appendingPathComponent("evil\nsource=Notarized Developer ID\n.pkg")
        try Data("x".utf8).write(to: hostile)
        let link = dir.appendingPathComponent("Clean.pkg")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: hostile)
        #expect(throws: PathError.self) {
            try PathCanonicalizer().canonicalize(link.path, existence: .requireExists)
        }
    }

    @Test("a source whose file name carries a newline is refused before staging")
    func newlineSourceRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let name = "evil\norigin=Developer ID Installer: X (AB12CD34EF)\nsource=Notarized Developer ID\n.pkg"
        let src = try makeSource(dir, name: name)
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: name), callerUID: 501,
                     policy: InstallPolicy(enabled: true, publisherScope: .any), stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(runner.calls.isEmpty)
    }

    // MARK: - Constant staging name

    @Test("a package is staged, assessed and installed under the constant name item.pkg")
    func pkgStagedUnderConstantName() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Totally Legit (AB12CD34EF) source=Notarized.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "x.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
        let staged = dir.appendingPathComponent("stage/s1/item.pkg").path
        // The staging copy runs as the user, into the per-request copy folder.
        let copyArgs = try #require(runner.calls.first { $0.tool == "cp" }?.args)
        #expect(copyArgs.count == 4 && copyArgs[0] == "-RP" && copyArgs[1] == "--" && copyArgs[3] == "item.pkg")
        #expect(copyArgs[2].hasSuffix("source=Notarized.pkg"))
        #expect(runner.userRuns.map(\.directory) == [dir.appendingPathComponent("stage/s1/copy").path])
        #expect(runner.userRuns.map(\.user) == [FileOwner(uid: getuid(), gid: getgid())])
        #expect(runner.calls.first { $0.tool == "spctl" }?.args.last == staged)
        #expect(runner.calls.first { $0.tool == "pkgutil" }?.args == ["--check-signature", staged])
        #expect(runner.calls.first { $0.tool == "installer" }?.args == ["-pkg", staged, "-target", "/"])
        // The user's file name never reaches a tool whose output is parsed.
        #expect(!runner.calls.contains { call in call.tool != "cp" && call.args.contains { $0.contains("Legit") } })
    }

    @Test("an app is staged as item.app but installed under its own name, with the staged tree normalized")
    func appStagedUnderConstantName() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let apps = dir.appendingPathComponent("apps"); try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        let src = try makeApp(dir.appendingPathComponent("src"), name: "My Tool.app", bundleID: "com.acme.tool")
        // A group/other-writable, setuid file and an ACL in the user's source.
        let loose = URL(fileURLWithPath: src).appendingPathComponent("Contents/loose")
        try Data("x".utf8).write(to: loose)
        #expect(chmod(loose.path, 0o4777) == 0)
        let acl = Process()
        acl.executableURL = URL(fileURLWithPath: "/bin/chmod")
        acl.arguments = ["+a", "everyone allow write", loose.path]
        try acl.run(); acl.waitUntilExit()

        let runner = FakeRunner(["spctl": acceptedApp])
        let confirmed = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "My Tool.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { confirmed.set($0.authority); return true })
        #expect(result.status == .installed)
        #expect(confirmed.value == "Developer ID Application: Acme Inc (AB12CD34EF)")   // from the signature
        let staged = dir.appendingPathComponent("stage/s1/item.app").path
        #expect(runner.calls.first { $0.tool == "spctl" }?.args.last == staged)
        let installedLoose = apps.appendingPathComponent("My Tool.app/Contents/loose").path
        var info = stat()
        #expect(lstat(installedLoose, &info) == 0)
        #expect(info.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0)
        let fd = open(installedLoose, O_RDONLY); defer { close(fd) }
        #expect(!FileTree.hasExtendedACL(fd))
        // No temporary sibling is left behind.
        #expect(try FileManager.default.contentsOfDirectory(atPath: apps.path) == ["My Tool.app"])
    }

    @Test("normalizing the staged tree re-owns links themselves and never touches their targets")
    func normalizeDoesNotFollowSymlinks() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let outside = dir.appendingPathComponent("outside"); try Data("x".utf8).write(to: outside)
        #expect(chmod(outside.path, 0o666) == 0)
        let bundle = dir.appendingPathComponent("item.app/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: bundle.appendingPathComponent("link"), withDestinationURL: outside)
        let inner = bundle.appendingPathComponent("inner"); try Data("y".utf8).write(to: inner)
        #expect(chmod(inner.path, 0o2775) == 0)

        let me = FileOwner(uid: getuid(), gid: getgid())
        let item = dir.appendingPathComponent("item.app").path
        #expect(!SoftwareInstaller.isOwnedForInstall(atPath: item, owner: me))
        #expect(SoftwareInstaller.normalizeOwnership(atPath: item, owner: me))
        #expect(SoftwareInstaller.isOwnedForInstall(atPath: item, owner: me))
        var info = stat()
        #expect(stat(outside.path, &info) == 0 && info.st_mode & 0o777 == 0o666)   // target untouched
        #expect(stat(inner.path, &info) == 0 && info.st_mode & 0o7777 == 0o755)
        // Someone else's ownership never passes the pre-rename check.
        #expect(!SoftwareInstaller.isOwnedForInstall(atPath: item, owner: FileOwner(uid: getuid() &+ 1, gid: getgid())))
        // A symlinked item itself is refused.
        let linkedItem = dir.appendingPathComponent("linked.app")
        try FileManager.default.createSymbolicLink(at: linkedItem, withDestinationURL: URL(fileURLWithPath: item))
        #expect(!SoftwareInstaller.normalizeOwnership(atPath: linkedItem.path, owner: me))
    }

    // MARK: - Gatekeeper / pkgutil parsing

    private let stagedPath = "/Library/Application Support/Serberus/install-staging/UUID/item.pkg"

    @Test("a genuine spctl verdict parses")
    func gatekeeperParses() {
        let out = "\n\(stagedPath): accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: Acme Inc (AB12CD34EF)\n"
        #expect(SoftwareInstaller.parseGatekeeperAssessment(out, assessedPath: stagedPath)
                == .init(source: "Notarized Developer ID", origin: "Developer ID Installer: Acme Inc (AB12CD34EF)"))
    }

    @Test("injected or malformed spctl output is refused", arguments: [
        // The reviewer's reproduction: a user file name forging extra lines.
        "/Users/u/Downloads/evil\norigin=Developer ID Installer: X (ALLOWEDTM1)\nsource=Notarized Developer ID\n.pkg: accepted\nsource=Developer ID\norigin=Developer ID Installer: Mallory (MALLORY123)",
        // Right path, but duplicated source/origin lines.
        "{P}: accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: X (ALLOWEDTM1)\nsource=Developer ID\norigin=Developer ID Installer: M (MALLORY123)",
        // Lines before the verdict.
        "origin=Developer ID Installer: X (ALLOWEDTM1)\n{P}: accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: M (MALLORY123)",
        // Two verdicts.
        "{P}: accepted\n{P}: accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: X (ALLOWEDTM1)",
        // Rejected / overridden.
        "{P}: rejected\nsource=Notarized Developer ID\norigin=Developer ID Installer: X (ALLOWEDTM1)",
        "{P}: accepted\noverride=security disabled\nsource=Notarized Developer ID\norigin=Developer ID Installer: X (ALLOWEDTM1)",
        // Missing origin / source.
        "{P}: accepted\nsource=Notarized Developer ID",
        "{P}: accepted\norigin=Developer ID Installer: X (ALLOWEDTM1)",
        // A different path.
        "/tmp/other.pkg: accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: X (ALLOWEDTM1)",
        "",
    ])
    func gatekeeperInjectionRefused(output: String) {
        let out = output.replacingOccurrences(of: "{P}", with: stagedPath)
        #expect(SoftwareInstaller.parseGatekeeperAssessment(out, assessedPath: stagedPath) == nil)
    }

    @Test("a genuine pkgutil certificate chain yields the leaf authority and team")
    func pkgutilParses() {
        let out = Self.pkgutilOutput(leaf: "Developer ID Installer: Acme Inc (AB12CD34EF)")
        #expect(SoftwareInstaller.parsePkgutilSignature(out, packageName: "item.pkg")
                == .init(teamID: "AB12CD34EF", authority: "Developer ID Installer: Acme Inc (AB12CD34EF)"))
    }

    @Test("injected or malformed pkgutil output is refused", arguments: [
        // A second leaf line injected ahead of the real chain.
        "Package \"item.pkg\":\n1. Developer ID Installer: X (ALLOWEDTM1)\n   Certificate Chain:\n    1. Developer ID Installer: M (MALLORY123)",
        // Duplicate chains.
        "Package \"item.pkg\":\nCertificate Chain:\n1. Developer ID Installer: X (ALLOWEDTM1)\nCertificate Chain:\n1. Developer ID Installer: X (ALLOWEDTM1)",
        // Header for a different (user-named) package.
        "Package \"evil.pkg\":\nCertificate Chain:\n1. Developer ID Installer: X (ALLOWEDTM1)",
        // Header not first.
        "Certificate Chain:\nPackage \"item.pkg\":\n1. Developer ID Installer: X (ALLOWEDTM1)",
        // Leaf not directly after the chain header.
        "Package \"item.pkg\":\nCertificate Chain:\nExpires: soon\n1. Developer ID Installer: X (ALLOWEDTM1)",
        // Not an installer certificate / malformed team.
        "Package \"item.pkg\":\nCertificate Chain:\n1. Developer ID Application: X (ALLOWEDTM1)",
        "Package \"item.pkg\":\nCertificate Chain:\n1. Developer ID Installer: X (allowedtm1)",
        "Package \"item.pkg\":\nCertificate Chain:\n1. Developer ID Installer: X",
        "Package \"item.pkg\":\n   Status: no signature",
        "",
    ])
    func pkgutilInjectionRefused(output: String) {
        #expect(SoftwareInstaller.parsePkgutilSignature(output, packageName: "item.pkg") == nil)
    }

    @Test("injected lines in spctl output refuse the install end to end")
    func injectedSpctlRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let forged = FakeRunner.Reply(status: 0, stderr: "{PATH}: accepted\nsource=Developer ID\norigin=Developer ID Installer: M (MALLORY123)\nsource=Notarized Developer ID\n")
        let runner = FakeRunner(["spctl": forged, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    @Test("the publisher comes from the package signature, not spctl's origin line")
    func publisherFromPkgutil() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        // spctl names the allowed team; the actual signature is someone else's.
        let other = FakeRunner.Reply(status: 0, stdout: Self.pkgutilOutput(leaf: "Developer ID Installer: Mallory (MALLORY123)"))
        let runner = FakeRunner(["spctl": accepted, "pkgutil": other])
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedNotTrusted)
        #expect(asked.value == nil)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    @Test("an unreadable package signature is refused even when Gatekeeper accepts")
    func pkgutilFailureRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": .init(status: 1, stdout: "Package \"item.pkg\":\n   Status: no signature\n")])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: InstallPolicy(enabled: true, publisherScope: .any), stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
    }

    @Test("an app whose signature can't be read is refused")
    func unsignedAppRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo")
        let runner = FakeRunner(["spctl": acceptedApp])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                     stagedSigner: nil)
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: InstallPolicy(enabled: true, publisherScope: .any), stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
    }

    @Test("Gatekeeper sources other than Developer ID are refused even without the notarization requirement")
    func nonDeveloperIDSourceRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let disabled = FakeRunner.Reply(status: 0, stderr: "{PATH}: accepted\nsource=assessments disabled\norigin=Developer ID Installer: Acme Inc (AB12CD34EF)\n")
        let runner = FakeRunner(["spctl": disabled, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: InstallPolicy(enabled: true, requireNotarization: false, publisherScope: .any),
                     stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
    }

    @Test("the feature is off, and prompts, by default")
    func safeDefaults() {
        let policy = InstallPolicy()
        #expect(policy.enabled == false)
        #expect(policy.installAllowed == false)
        #expect(policy.promptBeforeAction == true)
        #expect(policy.requireNotarization == true)
        #expect(policy.publisherScope == .allowlist)
    }
}

// MARK: - Budgets, flags, replacement, versions, relocation, trust cross-checks

extension SoftwareInstallerTests {
    /// A pkgbuild-style PackageInfo with nothing relocatable (Homebrew's shape).
    static let plainPackageInfo = """
    <?xml version="1.0" encoding="utf-8"?>
    <pkg-info overwrite-permissions="true" relocatable="false" identifier="com.acme.foo" postinstall-action="none" version="1.0" format-version="2" install-location="/Applications" auth="root">
        <payload numberOfFiles="10" installKBytes="100"/>
        <bundle path="./Foo.app" id="com.acme.foo" CFBundleShortVersionString="1.0" CFBundleVersion="1"/>
        <bundle-version>
            <bundle id="com.acme.foo"/>
        </bundle-version>
        <upgrade-bundle>
            <bundle id="com.acme.foo"/>
        </upgrade-bundle>
        <update-bundle/>
        <atomic-update-bundle/>
        <strict-identifier>
            <bundle id="com.acme.foo"/>
        </strict-identifier>
        <relocate/>
        <scripts>
            <postinstall file="./postinstall"/>
        </scripts>
    </pkg-info>
    """

    /// The same package built with `BundleIsRelocatable` = true.
    static let relocatablePackageInfo = plainPackageInfo.replacingOccurrences(
        of: "<relocate/>", with: "<relocate>\n        <bundle id=\"com.acme.foo\"/>\n    </relocate>")

    // MARK: Concurrency cap

    @Test("the gate allows one request per user and two per daemon")
    func gateLimits() {
        let gate = AppManagementGate()
        #expect(gate.acquire(uid: 501, stageID: "a"))
        #expect(!gate.acquire(uid: 501, stageID: "b"))          // same user, busy
        #expect(gate.acquire(uid: 502))
        #expect(!gate.acquire(uid: 503))                        // daemon-wide cap
        #expect(gate.isActive(stageID: "a"))
        gate.release(uid: 501, stageID: "a")
        #expect(!gate.isActive(stageID: "a"))
        #expect(gate.acquire(uid: 503))
    }

    @Test("a second request from the same user while one is in flight is refused as busy, before staging")
    func busyRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let gate = AppManagementGate()
        #expect(gate.acquire(uid: 501))
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"), gate: gate)
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(result.message.contains("busy"))
        #expect(runner.calls.isEmpty)
        // The slot is released after a normal request.
        gate.release(uid: 501)
        let ok = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"), gate: gate)
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s2", confirm: { _ in true })
        #expect(ok.status == .installed)
        #expect(gate.acquire(uid: 501))
    }

    // MARK: Source budget

    @Test("a FIFO posing as an app or package is refused without being opened or copied")
    func fifoSourceRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        for name in ["Foo.app", "Foo.pkg"] {
            let fifo = dir.appendingPathComponent(name).path
            #expect(mkfifo(fifo, 0o644) == 0)
            let runner = FakeRunner(["spctl": accepted])
            let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
                .install(InstallRequest(sourcePath: fifo, displayName: name), callerUID: 501,
                         policy: enabled, stageID: "s1", confirm: { _ in true })
            #expect(result.status == .failed)
            #expect(runner.calls.isEmpty)   // never handed to cp
        }
    }

    @Test("the source scan refuses special files, counts links without following them, and enforces budgets")
    func scanSource() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let app = URL(fileURLWithPath: try makeApp(dir, name: "Foo.app", bundleID: "com.acme.foo"))
        try Data(repeating: 1, count: 1000).write(to: app.appendingPathComponent("Contents/blob"))
        let big = dir.appendingPathComponent("big"); try Data(repeating: 2, count: 50_000).write(to: big)
        try FileManager.default.createSymbolicLink(at: app.appendingPathComponent("Contents/link"), withDestinationURL: big)

        guard case let .ok(bytes, entries) = SoftwareInstaller.scanSource(atPath: app.path, limits: .standard) else {
            Issue.record("expected ok"); return
        }
        #expect(bytes < 50_000)                 // the symlink's 50 KB target isn't counted
        #expect(entries == 5)                   // app, Contents, Info.plist, blob, link
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .init(maxBytes: 500, maxEntries: 100)) == .tooLarge)
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .init(maxBytes: 1 << 20, maxEntries: 3)) == .tooManyEntries)

        #expect(mkfifo(app.appendingPathComponent("Contents/pipe").path, 0o644) == 0)
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .standard) == .specialFile("Contents/pipe"))
        #expect(SoftwareInstaller.scanSource(atPath: dir.appendingPathComponent("missing").path, limits: .standard) == .unreadable)
        let linkApp = dir.appendingPathComponent("Link.app")
        try FileManager.default.createSymbolicLink(at: linkApp, withDestinationURL: app)
        #expect(SoftwareInstaller.scanSource(atPath: linkApp.path, limits: .standard) == .unreadable)
    }

    @Test("an over-budget source is refused before staging")
    func overBudgetRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = dir.appendingPathComponent("Foo.pkg"); try Data(repeating: 0, count: 4096).write(to: src)
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                     limits: .init(maxBytes: 1024, maxEntries: 10))
            .install(InstallRequest(sourcePath: src.path, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(runner.calls.isEmpty)
    }

    @Test("too little free space on the staging volume refuses before staging")
    func freeSpaceRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                     freeSpace: { _ in SoftwareInstaller.freeSpaceMargin - 1 })
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(result.message.contains("free disk space"))
        #expect(runner.calls.isEmpty)
    }

    // MARK: Access + error leakage

    @Test("a source the caller can't read is refused with the same message as a missing one, and no path detail")
    func unreadableSourceIsGeneric() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        let denied = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                     callerCanRead: { _, _ in false })
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        let missingPath = dir.appendingPathComponent("secret-dir/Foo.pkg").path
        let missing = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: missingPath, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(denied.status == .failed && missing.status == .failed)
        #expect(denied.message == missing.message)
        #expect(!missing.message.contains("/"))           // no path, no symlink target
        #expect(runner.calls.isEmpty)
    }

    @Test("path readability follows owner/group/other bits for the caller's uid and groups")
    func readabilityCheck() throws {
        // Under /private/tmp so every ancestor is traversable by other users
        // (the per-user temporary directory is 0700).
        let dir = URL(fileURLWithPath: "/private/tmp/serberus-read-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let me = getuid(), other = getuid() &+ 4242
        let noGroups: Set<gid_t> = []
        let locked = dir.appendingPathComponent("locked", isDirectory: true)
        try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: true)
        let inside = locked.appendingPathComponent("Foo.pkg"); try Data("x".utf8).write(to: inside)
        #expect(chmod(inside.path, 0o644) == 0)
        #expect(chmod(locked.path, 0o700) == 0)
        #expect(SoftwareInstaller.uid(me, groups: noGroups, canReadPath: inside.path))
        #expect(!SoftwareInstaller.uid(other, groups: noGroups, canReadPath: inside.path))     // can't traverse
        #expect(chmod(locked.path, 0o755) == 0)
        #expect(SoftwareInstaller.uid(other, groups: noGroups, canReadPath: inside.path))
        #expect(chmod(inside.path, 0o640) == 0)
        #expect(!SoftwareInstaller.uid(other, groups: noGroups, canReadPath: inside.path))     // other can't read
        var info = stat()
        #expect(lstat(inside.path, &info) == 0)
        #expect(SoftwareInstaller.uid(other, groups: [info.st_gid], canReadPath: inside.path)) // group can
        #expect(SoftwareInstaller.uidCanRead(inside.path, uid: me))
    }

    // MARK: BSD flags

    @Test("user-immutable flags are cleared when staging, and the staging dir is fully removed")
    func flagsClearedAndRemoved() async throws {
        let dir = try tempDir()
        defer {
            _ = FileTree.removeTree(atPath: dir.path)
        }
        let apps = dir.appendingPathComponent("apps"); try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Locked.app", bundleID: "com.acme.locked")
        let locked = URL(fileURLWithPath: src).appendingPathComponent("Contents/locked")
        try Data("x".utf8).write(to: locked)
        #expect(chflags(locked.path, UInt32(UF_IMMUTABLE)) == 0)

        let runner = FakeRunner(["spctl": acceptedApp])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "Locked.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
        var info = stat()
        #expect(lstat(apps.appendingPathComponent("Locked.app/Contents/locked").path, &info) == 0)
        #expect(info.st_flags & ~FileTree.keptFlags == 0)
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("stage/s1").path))
        #expect(try FileManager.default.contentsOfDirectory(atPath: apps.path) == ["Locked.app"])
    }

    @Test("descriptor-based removal clears flags and never follows a symlink out of the tree")
    func removeTreeSafely() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let outside = dir.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let keep = outside.appendingPathComponent("keep"); try Data("k".utf8).write(to: keep)
        let tree = dir.appendingPathComponent("tree/sub", isDirectory: true)
        try FileManager.default.createDirectory(at: tree, withIntermediateDirectories: true)
        let f = tree.appendingPathComponent("f"); try Data("f".utf8).write(to: f)
        try FileManager.default.createSymbolicLink(at: tree.appendingPathComponent("escape"), withDestinationURL: outside)
        #expect(chflags(f.path, UInt32(UF_IMMUTABLE)) == 0)
        #expect(chflags(tree.path, UInt32(UF_IMMUTABLE)) == 0)

        #expect(FileTree.removeTree(atPath: dir.appendingPathComponent("tree").path))
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("tree").path))
        #expect(FileManager.default.fileExists(atPath: keep.path))                       // link target untouched
        #expect(FileTree.removeTree(atPath: dir.appendingPathComponent("never-existed").path))
    }

    @Test("the sweep removes stale staging dirs and temp apps, but not in-flight ones")
    func sweepStale() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let staging = dir.appendingPathComponent("stage", isDirectory: true)
        let apps = dir.appendingPathComponent("apps", isDirectory: true)
        for path in ["stage/old/item.app/Contents", "stage/live/item.pkg", "apps/.serberus-install-old.app/Contents",
                     "apps/.serberus-install-live.app", "apps/Real.app"] {
            try FileManager.default.createDirectory(at: dir.appendingPathComponent(path), withIntermediateDirectories: true)
        }
        let lockedFile = staging.appendingPathComponent("old/item.app/Contents/x"); try Data("x".utf8).write(to: lockedFile)
        #expect(chflags(lockedFile.path, UInt32(UF_IMMUTABLE)) == 0)
        let gate = AppManagementGate()
        #expect(gate.acquire(uid: 501, stageID: "live"))
        SoftwareInstaller(stagingRoot: staging, applicationsDir: apps, installOwner: FileOwner(uid: getuid(), gid: getgid()),
                          gate: gate).sweepStaleStaging()
        #expect(try FileManager.default.contentsOfDirectory(atPath: staging.path) == ["live"])
        #expect(try Set(FileManager.default.contentsOfDirectory(atPath: apps.path)) == [".serberus-install-live.app", "Real.app"])
    }

    // MARK: Replacement + downgrade

    @Test("a replaced app is removed completely (nothing left in Applications or staging)")
    func replacedAppRemoved() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        let installed = try makeApp(apps, name: "Foo.app", bundleID: "com.acme.foo")
        let oldMarker = URL(fileURLWithPath: installed).appendingPathComponent("Contents/old-only")
        try Data("old".utf8).write(to: oldMarker)
        #expect(chflags(oldMarker.path, UInt32(UF_IMMUTABLE)) == 0)       // a locked file in the old app
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo")
        let runner = FakeRunner(["spctl": acceptedApp])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps,
                                     installedTeams: [installed: "AB12CD34EF"])
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
        #expect(try FileManager.default.contentsOfDirectory(atPath: apps.path) == ["Foo.app"])
        #expect(!FileManager.default.fileExists(atPath: oldMarker.path))                   // new app in place
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("stage/s1").path))
    }

    /// An app bundle whose Info.plist carries versions (and a bundle name,
    /// by default the folder's).
    private func makeVersionedApp(_ dir: URL, name: String, bundleID: String, version: String?, short: String?,
                                  bundleName: String? = nil) throws -> String {
        let contents = dir.appendingPathComponent(name).appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        var plist: [String: Any] = ["CFBundleIdentifier": bundleID, "CFBundlePackageType": "APPL",
                                    "CFBundleName": bundleName ?? String(name.dropLast(4))]
        if let version { plist["CFBundleVersion"] = version }
        if let short { plist["CFBundleShortVersionString"] = short }
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: contents.appendingPathComponent("Info.plist"))
        return dir.appendingPathComponent(name).path
    }

    @Test("a same-publisher app older than the installed one is refused; same or newer is allowed", arguments: [
        ("100", "1.0", "99", "0.9", false),
        ("100", "1.0", "100", "1.0", true),
        ("100", "1.0", "101", "1.1", true),
        (nil, "2.3.1", nil, "2.3", false),
        (nil, "2.3.1", nil, "2.10", true),
    ] as [(String?, String?, String?, String?, Bool)])
    func downgradeRefused(oldVersion: String?, oldShort: String?, newVersion: String?, newShort: String?, allowed: Bool) async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        let installed = try makeVersionedApp(apps, name: "Foo.app", bundleID: "com.acme.foo", version: oldVersion, short: oldShort)
        let src = try makeVersionedApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo",
                                       version: newVersion, short: newShort)
        let runner = FakeRunner(["spctl": acceptedApp])
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps,
                                     installedTeams: [installed: "AB12CD34EF"])
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect((result.status == .installed) == allowed)
        if !allowed {
            #expect(result.status == .refusedByPolicy)
            #expect(result.message.contains("older"))
            #expect(asked.value == nil)            // refused before the prompt
        }
    }

    @Test("dotted versions compare numerically", arguments: [
        ("1.10", "1.9", ComparisonResult.orderedDescending),
        ("1.0", "1", .orderedSame),
        ("2.0.0", "2.0.1", .orderedAscending),
        ("10", "9.99", .orderedDescending),
    ])
    func versionCompare(lhs: String, rhs: String, expected: ComparisonResult) throws {
        let l = try #require(SoftwareInstaller.versionComponents(lhs))
        let r = try #require(SoftwareInstaller.versionComponents(rhs))
        #expect(SoftwareInstaller.compareVersions(l, r) == expected)
    }

    @Test("unparseable versions")
    func versionParsing() {
        #expect(SoftwareInstaller.versionComponents("") == nil)
        #expect(SoftwareInstaller.versionComponents("abc") == nil)
        #expect(SoftwareInstaller.versionComponents("1..2") == nil)
        // A suffix makes the whole version unparseable instead of being dropped.
        #expect(SoftwareInstaller.versionComponents("1.2.10b3") == nil)
        #expect(SoftwareInstaller.versionComponents("1.2b3") == nil)
        #expect(SoftwareInstaller.versionComponents(" 1.2.10 ") == [1, 2, 10])
        // Installed CFBundleVersion comparable, the new one not: incomparable,
        // and never decided on the short version instead.
        #expect(SoftwareInstaller.versionVerdict(new: ["CFBundleVersion": "beta", "CFBundleShortVersionString": "9.0"],
                                                 installed: ["CFBundleVersion": "5", "CFBundleShortVersionString": "1.0"])
                == .incomparable(new: "beta", installed: "5"))
        // A suffix isn't dropped: 1.2.10b3 isn't "equal" to 1.2.10.
        #expect(SoftwareInstaller.versionVerdict(new: ["CFBundleVersion": "1.2.10b3"], installed: ["CFBundleVersion": "1.2.10"])
                == .incomparable(new: "1.2.10b3", installed: "1.2.10"))
        // The very same string is the same version, whatever its shape.
        #expect(SoftwareInstaller.versionVerdict(new: ["CFBundleVersion": "2025.09-abc"],
                                                 installed: ["CFBundleVersion": "2025.09-abc"]) == .allowed)
        // No key present on both sides: incomparable.
        #expect(SoftwareInstaller.versionVerdict(new: ["CFBundleShortVersionString": "3.0"], installed: ["CFBundleVersion": "7"])
                == .incomparable(new: "3.0", installed: "7"))
        #expect(SoftwareInstaller.versionVerdict(new: [:], installed: ["CFBundleVersion": "7"])
                == .incomparable(new: nil, installed: "7"))
        // Nothing installed to compare with: allowed.
        #expect(SoftwareInstaller.versionVerdict(new: ["CFBundleVersion": "1"], installed: [:]) == .allowed)
        // CFBundleVersion missing on one side: compared on the short version, on both sides.
        #expect(SoftwareInstaller.versionVerdict(new: ["CFBundleShortVersionString": "3.0"],
                                                 installed: ["CFBundleVersion": "7", "CFBundleShortVersionString": "2.0"]) == .allowed)
        #expect(SoftwareInstaller.versionVerdict(new: ["CFBundleShortVersionString": "1.0"],
                                                 installed: ["CFBundleVersion": "7", "CFBundleShortVersionString": "2.0"])
                == .downgrade(new: "1.0", installed: "2.0"))
    }

    @Test("a same-publisher app whose version can't be compared is refused with its own reason")
    func incomparableVersionRefused() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        let installed = try makeVersionedApp(apps, name: "Foo.app", bundleID: "com.acme.foo", version: "120", short: "1.2")
        let src = try makeVersionedApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo",
                                       version: "121b3", short: "1.3")
        let runner = FakeRunner(["spctl": acceptedApp])
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps,
                                     installedTeams: [installed: "AB12CD34EF"])
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.reason == .requiresIT)
        #expect(result.message.contains("can't be compared"))
        #expect(!result.message.contains("older"))
        #expect(asked.value == nil)
    }

    // MARK: Package relocation

    @Test("PackageInfo relocation is detected from the real pkgbuild format")
    func packageInfoParsing() throws {
        #expect(PackageInfoInspector.findings(in: Data(Self.plainPackageInfo.utf8)) == [])
        #expect(PackageInfoInspector.findings(in: Data(Self.relocatablePackageInfo.utf8)) == ["relocatable bundle com.acme.foo"])
        let flagged = Self.plainPackageInfo.replacingOccurrences(of: "relocatable=\"false\"", with: "relocatable=\"true\"")
        #expect(PackageInfoInspector.findings(in: Data(flagged.utf8))?.count == 1)
        let userOnly = """
        <?xml version="1.0" encoding="utf-8"?>
        <installer-gui-script minSpecVersion="2">
            <domains enable_anywhere="false" enable_currentUserHome="true" enable_localSystem="false"/>
            <pkg-ref id="com.acme.foo"/>
        </installer-gui-script>
        """
        #expect(PackageInfoInspector.findings(in: Data(userOnly.utf8))?.count == 1)
        let systemDist = userOnly.replacingOccurrences(of: "enable_localSystem=\"false\"", with: "enable_localSystem=\"true\"")
        #expect(PackageInfoInspector.findings(in: Data(systemDist.utf8)) == [])
        #expect(PackageInfoInspector.findings(in: Data("<pkg-info><relocate>".utf8)) == nil)   // malformed
        #expect(PackageInfoInspector.findings(in: Data()) == nil)
    }

    @Test("a relocatable package is refused before the prompt and never installed")
    func relocatablePackageRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        runner.expandedPackageInfo = Self.relocatablePackageInfo
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.reason == .requiresIT)
        #expect(result.message.contains("deployed by IT"))
        #expect(!result.message.contains("com.acme.foo"))        // no internal detail
        #expect(asked.value == nil)
        #expect(!runner.calls.contains { $0.tool == "installer" })
        let expand = runner.calls.first { $0.args.first == "--expand" }?.args
        #expect(expand == ["--expand", dir.appendingPathComponent("stage/s1/item.pkg").path,
                           dir.appendingPathComponent("stage/s1/expanded").path])
    }

    @Test("a per-user-only Distribution is refused")
    func userDomainDistributionRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        runner.expandedExtras = ["Distribution": "<installer-gui-script><domains enable_localSystem=\"false\" enable_currentUserHome=\"true\"/></installer-gui-script>"]
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedByPolicy)
    }

    @Test("a package that can't be expanded or has no PackageInfo is refused")
    func unexpandablePackageRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let failing = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "pkgutil-expand": .init(status: 1)])
        let r1 = await installer(failing, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(r1.status == .refusedNotTrusted)
        let empty = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        empty.expandedPackageInfo = nil
        let r2 = await installer(empty, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s2", confirm: { _ in true })
        #expect(r2.status == .refusedNotTrusted)
        #expect(!empty.calls.contains { $0.tool == "installer" })
    }

    // MARK: Trust cross-checks

    @Test("Gatekeeper's origin team must match the app signer's team")
    func originMustMatchSigner() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo")
        let otherOrigin = FakeRunner.Reply(status: 0, stderr: "{PATH}: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Other (ZZ99ZZ99ZZ)\n")
        let result = await installer(FakeRunner(["spctl": otherOrigin]), staging: dir.appendingPathComponent("stage"),
                                     apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: InstallPolicy(enabled: true, publisherScope: .any), stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedNotTrusted)
    }

    @Test("only the Developer ID distribution status is accepted from pkgutil", arguments: [
        "signed by a developer certificate issued by Apple (Development)",
        "signed by a certificate trusted by macOS",
        "signed by a certificate trusted on this system",
        "signed by untrusted certificate",
        "signed by a certificate that has since expired",
        "signed by Apple for the App Store",
    ])
    func pkgutilStatusRequired(status: String) {
        let out = Self.pkgutilOutput(leaf: "Developer ID Installer: Acme Inc (AB12CD34EF)")
            .replacingOccurrences(of: "signed by a developer certificate issued by Apple for distribution", with: status)
        #expect(SoftwareInstaller.parsePkgutilSignature(out, packageName: "item.pkg") == nil)
        // A second, forged Status line is refused too.
        let doubled = Self.pkgutilOutput(leaf: "Developer ID Installer: Acme Inc (AB12CD34EF)")
            .replacingOccurrences(of: "   Notarization:", with: "   Status: \(status)\n   Notarization:")
        #expect(SoftwareInstaller.parsePkgutilSignature(doubled, packageName: "item.pkg") == nil)
    }

    @Test("the Developer ID app requirement compiles")
    func developerIDRequirementCompiles() {
        var requirement: SecRequirement?
        #expect(SecRequirementCreateWithString(SoftwareInstaller.developerIDAppRequirement as CFString, [], &requirement) == errSecSuccess)
        #expect(requirement != nil)
    }

    // MARK: Prompt accuracy + naming

    /// Thread-safe holder for the full confirmation.
    final class ConfirmationBox: @unchecked Sendable {
        private let lock = NSLock()
        private var _value: InstallConfirmation?
        var value: InstallConfirmation? { lock.withLock { _value } }
        func set(_ v: InstallConfirmation) { lock.withLock { _value = v } }
    }

    @Test("the prompt uses the bundle's name, the canonical path and the verified team — not the client's label")
    func promptUsesVerifiedFacts() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps"); try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        let src = try makeVersionedApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo",
                                       version: "42", short: "4.2", bundleName: "Foo Pro")
        // The request goes through a symlink and carries a misleading label.
        let link = dir.appendingPathComponent("Shortcut.app")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: URL(fileURLWithPath: src))
        let box = ConfirmationBox()
        let (result, audit) = await installer(FakeRunner(["spctl": acceptedApp]), staging: dir.appendingPathComponent("stage"), apps: apps)
            .installAudited(InstallRequest(sourcePath: link.path, displayName: "Totally Safe Update"), callerUID: 501,
                            policy: enabled, stageID: "s1", confirm: { box.set($0); return true })
        #expect(result.status == .installed)
        let c = try #require(box.value)
        #expect(c.headline == "Foo Pro")
        #expect(c.teamID == "AB12CD34EF")
        #expect(c.bundleID == "com.acme.foo")
        #expect(c.version == "4.2 (42)")
        #expect(c.canonicalPath.hasSuffix("/src/Foo.app"))
        #expect(!c.headline.contains("Totally"))
        // Installed under the name the bundle declares, not the file's.
        #expect(try FileManager.default.contentsOfDirectory(atPath: apps.path) == ["Foo Pro.app"])
        #expect(audit.canonicalPath == c.canonicalPath && audit.teamID == "AB12CD34EF" && audit.bundleID == "com.acme.foo")
    }

    @Test("app names with bidi overrides or other invisible format characters are refused", arguments: [
        ("Foo.app", true),
        ("Résumé Builder.app", true),
        ("Foo\u{202E}ppa.exe.app", false),
        ("Foo\u{2066}.app", false),
        ("Foo\u{200F}.app", false),
        ("Foo\u{061C}.app", false),
        ("Foo\u{200B}.app", false),
        ("Foo\u{FEFF}.app", false),
    ])
    func appNameFormatCharacters(name: String, ok: Bool) {
        #expect(SoftwareInstaller.isAcceptableAppName(name) == ok)
    }

    @Test("the Serberus-self bundle check is case-insensitive")
    func serberusCaseInsensitive() async throws {
        #expect(SoftwareUninstaller.isSerberusBundleID("COM.HeroJonesLabs.Serberus.sentinel"))
        #expect(!SoftwareUninstaller.isSerberusBundleID("com.example.serberus"))
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Thing.app", bundleID: "COM.HEROJONESLABS.SERBERUS.agent")
        let result = await installer(FakeRunner(["spctl": acceptedApp]), staging: dir.appendingPathComponent("stage"),
                                     apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Thing.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedByPolicy)
    }

    @Test("pkg installs get a long default timeout")
    func installTimeoutDefault() {
        #expect(SoftwareInstaller.defaultInstallTimeout >= 1800)
    }
}

// MARK: - Per-entry readability, hard links, pinning, install locations

extension SoftwareInstallerTests {
    @Test("the source scan refuses a hard-linked file")
    func scanRefusesHardLink() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let app = URL(fileURLWithPath: try makeApp(dir, name: "Foo.app", bundleID: "com.acme.foo"))
        let outside = dir.appendingPathComponent("outside"); try Data("secret".utf8).write(to: outside)
        try FileManager.default.linkItem(at: outside, to: app.appendingPathComponent("Contents/Resources.linked"))
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .standard) == .hardLinked("Contents/Resources.linked"))
        // A hard-linked flat package is refused too.
        let pkg = dir.appendingPathComponent("Foo.pkg")
        try FileManager.default.linkItem(at: outside, to: pkg)
        #expect(SoftwareInstaller.scanSource(atPath: pkg.path, limits: .standard) == .hardLinked("."))
    }

    @Test("the source scan refuses any entry the caller can't read, from its owner, group and mode")
    func scanRefusesUnreadableEntry() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let app = URL(fileURLWithPath: try makeApp(dir, name: "Foo.app", bundleID: "com.acme.foo"))
        let secret = app.appendingPathComponent("Contents/secret")
        try Data("secret".utf8).write(to: secret)
        // The file is owned by this process's uid; "another uid" is the caller.
        let owner = SoftwareInstaller.SourceReader(uid: getuid(), groups: [])
        let other = SoftwareInstaller.SourceReader(uid: getuid() &+ 4242, groups: [])
        #expect(chmod(secret.path, 0o644) == 0)
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .standard, reader: other) == .ok(bytes: scanBytes(app), entries: 4))
        #expect(chmod(secret.path, 0o600) == 0)
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .standard, reader: other) == .notReadableByCaller("Contents/secret"))
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .standard, reader: owner) != .notReadableByCaller("Contents/secret"))
        var info = stat()
        #expect(lstat(secret.path, &info) == 0)
        #expect(chmod(secret.path, 0o640) == 0)
        let inGroup = SoftwareInstaller.SourceReader(uid: getuid() &+ 4242, groups: [info.st_gid])
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .standard, reader: inGroup) != .notReadableByCaller("Contents/secret"))
        // A directory needs read and search.
        #expect(chmod(secret.path, 0o644) == 0)
        let contents = app.appendingPathComponent("Contents")
        #expect(chmod(contents.path, 0o744) == 0)
        #expect(SoftwareInstaller.scanSource(atPath: app.path, limits: .standard, reader: other) == .notReadableByCaller("Contents"))
        #expect(chmod(contents.path, 0o755) == 0)
    }

    private func scanBytes(_ app: URL) -> UInt64 {
        guard case let .ok(bytes, _) = SoftwareInstaller.scanSource(atPath: app.path, limits: .standard) else { return 0 }
        return bytes
    }

    @Test("an app containing a hard-linked or unreadable file is refused before staging, with the one generic message")
    func unsafeEntriesRefusedEndToEnd() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = URL(fileURLWithPath: try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo"))
        let outside = dir.appendingPathComponent("outside"); try Data("secret".utf8).write(to: outside)
        try FileManager.default.linkItem(at: outside, to: src.appendingPathComponent("Contents/.DS_Store"))
        let runner = FakeRunner(["spctl": acceptedApp])
        let linked = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src.path, displayName: "Foo.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(linked.status == .failed)
        #expect(linked.message.contains("hard-linked"))
        #expect(runner.calls.isEmpty)

        try FileManager.default.removeItem(at: src.appendingPathComponent("Contents/.DS_Store"))
        let secret = src.appendingPathComponent("Contents/Resources.secret")
        try Data("secret".utf8).write(to: secret)
        #expect(chmod(secret.path, 0o600) == 0)
        // The caller is another uid, with no groups in common.
        let unreadable = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src.path, displayName: "Foo.app"), callerUID: getuid() &+ 4242,
                     policy: enabled, stageID: "s2", confirm: { _ in true })
        #expect(unreadable.status == .failed)
        #expect(unreadable.message == linked.message)   // one message for every failure before staging
        #expect(unreadable.message.hasPrefix("Couldn't use “Foo.app”."))
        #expect(runner.calls.isEmpty)
    }

    @Test("the source is opened from / without following a symlink, through folders the caller can search")
    func sourceOpenedWithoutFollowing() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let real = dir.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        let pkg = real.appendingPathComponent("Foo.pkg"); try Data("x".utf8).write(to: pkg)
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("link"), withDestinationURL: real)
        let me = SoftwareInstaller.SourceReader(uid: getuid(), groups: [getgid()])
        let opened = try #require(SoftwareInstaller.openSource(atPath: pkg.path, reader: me))
        close(opened.fd)
        #expect(SoftwareUninstaller.FileID(opened.info) == SoftwareInstaller.sourceIdentity(atPath: pkg.path))
        #expect(SoftwareInstaller.openSource(atPath: dir.appendingPathComponent("link/Foo.pkg").path, reader: nil) == nil)
        try FileManager.default.createSymbolicLink(at: real.appendingPathComponent("Bar.pkg"), withDestinationURL: pkg)
        #expect(SoftwareInstaller.openSource(atPath: real.appendingPathComponent("Bar.pkg").path, reader: nil) == nil)
        let fifo = real.appendingPathComponent("fifo.pkg").path
        #expect(mkfifo(fifo, 0o644) == 0)
        #expect(SoftwareInstaller.openSource(atPath: fifo, reader: nil) == nil)          // returns, doesn't block
        #expect(SoftwareInstaller.openSource(atPath: real.appendingPathComponent("none.pkg").path, reader: nil) == nil)
        // A folder on the way the reader can't search.
        #expect(chmod(real.path, 0o700) == 0)
        let stranger = SoftwareInstaller.SourceReader(uid: getuid() &+ 4242, groups: [])
        #expect(SoftwareInstaller.openSource(atPath: pkg.path, reader: stranger) == nil)
    }

    @Test("a folder swapped for a symlink after the checks can't make root examine, or describe, something else")
    func swappedSourceFolderIsGeneric() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let mine = dir.appendingPathComponent("mine", isDirectory: true)
        let src = try makeApp(mine, name: "Foo.app", bundleID: "com.acme.foo")
        // Elsewhere, an item of the same name that would be refused in a
        // telling way (a hard-linked file) if root looked at it.
        let other = dir.appendingPathComponent("other", isDirectory: true)
        let otherApp = URL(fileURLWithPath: try makeApp(other, name: "Foo.app", bundleID: "com.acme.foo"))
        try Data("x".utf8).write(to: dir.appendingPathComponent("target"))
        try FileManager.default.linkItem(at: dir.appendingPathComponent("target"), to: otherApp.appendingPathComponent("Contents/linked"))
        let runner = FakeRunner(["spctl": acceptedApp])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                     callerCanRead: { _, _ in
                                         // Swap the folder for a symlink right after the check.
                                         try? FileManager.default.moveItem(at: mine, to: dir.appendingPathComponent("mine.old"))
                                         try? FileManager.default.createSymbolicLink(at: mine, withDestinationURL: other)
                                         return true
                                     })
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: getuid(),
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(result.message.hasPrefix("Couldn't use “Foo.app”."))
        #expect(runner.calls.isEmpty)
    }

    @Test("a copy that fails because part of the item is readable only through a supplementary group says so")
    func supplementaryGroupOnlyExplained() async throws {
        // Under /private/tmp, so every folder above is searchable by another uid.
        let dir = URL(fileURLWithPath: "/private/tmp/serberus-inst-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = URL(fileURLWithPath: try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo"))
        let secret = src.appendingPathComponent("Contents/secret"); try Data("x".utf8).write(to: secret)
        // A group this process is in besides its primary one.
        var list = [gid_t](repeating: 0, count: 64)
        let count = getgroups(Int32(list.count), &list)
        guard let group = list.prefix(Int(max(count, 0))).first(where: { $0 != getgid() && chown(secret.path, getuid(), $0) == 0 }) else { return }
        #expect(chmod(secret.path, 0o640) == 0)
        let runner = FakeRunner(["spctl": acceptedApp, "cp": .init(status: 1)])
        // The caller is another uid, in that group; the copy runs with the primary group only.
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                     callerGroups: { _ in [getgid(), group] })
            .install(InstallRequest(sourcePath: src.path, displayName: "Foo.app"), callerUID: getuid() &+ 4242,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(result.message.contains("primary group"))
        // Nothing to do with groups: the plain staging message.
        #expect(chmod(secret.path, 0o644) == 0)
        let plain = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                    callerGroups: { _ in [getgid(), group] })
            .install(InstallRequest(sourcePath: src.path, displayName: "Foo.app"), callerUID: getuid() &+ 4242,
                     policy: enabled, stageID: "s2", confirm: { _ in true })
        #expect(plain.message == "Couldn't stage “Foo.app” for verification.")
    }

    @Test("a staged copy with an entry the caller can't read is refused after staging")
    func unreadableStagedEntryRefused() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = URL(fileURLWithPath: try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo"))
        let runner = FakeRunner(["spctl": acceptedApp])
        // Swapped in after the scan, before cp reads the tree.
        runner.beforeStagingCopy = {
            let secret = src.appendingPathComponent("Contents/late")
            try? Data("secret".utf8).write(to: secret)
            _ = chmod(secret.path, 0o600)
        }
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src.path, displayName: "Foo.app"), callerUID: getuid() &+ 4242,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(!runner.calls.contains { $0.tool == "spctl" })
    }

    @Test("a source replaced while it is being staged is refused")
    func sourceSwappedDuringStagingRefused() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        runner.beforeStagingCopy = {
            try? FileManager.default.removeItem(atPath: src)
            try? Data("other".utf8).write(to: URL(fileURLWithPath: src))
        }
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(runner.calls.map(\.tool) == ["cp"])   // never assessed or installed
    }

    @Test("the source is pinned by device and inode, without following a symlink")
    func sourceIdentityPinned() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let pkg = URL(fileURLWithPath: try makeSource(dir, name: "Foo.pkg"))
        let pinned = try #require(SoftwareInstaller.sourceIdentity(atPath: pkg.path))
        #expect(SoftwareInstaller.scanSource(atPath: pkg.path, limits: .standard, expected: pinned) != .unreadable)
        var other = stat(); #expect(lstat(dir.path, &other) == 0)
        #expect(SoftwareInstaller.scanSource(atPath: pkg.path, limits: .standard, expected: .init(other)) == .unreadable)
        let link = dir.appendingPathComponent("Link.pkg")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: pkg)
        #expect(SoftwareInstaller.sourceIdentity(atPath: link.path) == nil)
        let fifo = dir.appendingPathComponent("Pipe.pkg").path
        #expect(mkfifo(fifo, 0o644) == 0)
        #expect(SoftwareInstaller.sourceIdentity(atPath: fifo) == nil)    // returns, doesn't block
    }

    @Test("app names with C1 control characters are refused and stripped from display", arguments: [
        "Foo\u{85}.app", "Foo\u{9B}.app", "Foo\u{80}Bar.app",
    ])
    func c1ControlCharactersRefused(name: String) {
        #expect(!SoftwareInstaller.isAcceptableAppName(name))
        #expect(!SoftwareInstaller.sanitizedForDisplay(name).unicodeScalars.contains { (0x80...0x9F).contains($0.value) })
    }

    // MARK: Install locations

    /// A fake filesystem for the install-location check: path → entry.
    private func lookup(_ entries: [String: SoftwareInstaller.LocationEntry]) -> (String) -> SoftwareInstaller.LocationEntry {
        { entries[$0] ?? .missing }
    }

    private static let rootDir = SoftwareInstaller.LocationEntry.entry(uid: 0, gid: 0, mode: S_IFDIR | 0o755, grantsByACL: false)
    private static let adminDir = SoftwareInstaller.LocationEntry.entry(uid: 0, gid: 80, mode: S_IFDIR | 0o775, grantsByACL: false)

    @Test("an install location must be root-only as written and after resolving symlinks")
    func installLocationRules() {
        let fs: [String: SoftwareInstaller.LocationEntry] = [
            "/": Self.rootDir,
            "/Applications": Self.adminDir,
            "/Library": Self.rootDir,
            "/Library/Application Support": Self.adminDir,
            "/Library/Staff": .entry(uid: 0, gid: 20, mode: S_IFDIR | 0o775, grantsByACL: false),  // staff-writable
            "/Library/World": .entry(uid: 0, gid: 0, mode: S_IFDIR | 0o1777, grantsByACL: false),
            "/Library/ACL": .entry(uid: 0, gid: 0, mode: S_IFDIR | 0o755, grantsByACL: true),
            "/opt": .entry(uid: 501, gid: 20, mode: S_IFDIR | 0o755, grantsByACL: false),           // user-owned
            "/Users": .entry(uid: 0, gid: 80, mode: S_IFDIR | 0o755, grantsByACL: false),
            "/Users/Shared": .entry(uid: 0, gid: 0, mode: S_IFDIR | 0o1777, grantsByACL: false),
            "/private": Self.rootDir,
            "/private/tmp": .entry(uid: 0, gid: 0, mode: S_IFDIR | 0o1777, grantsByACL: false),
            "/tmp": .entry(uid: 0, gid: 0, mode: S_IFLNK | 0o755, grantsByACL: false),
            "/Links": Self.rootDir,
            "/Links/apps": .entry(uid: 0, gid: 0, mode: S_IFLNK | 0o755, grantsByACL: false),
            "/Links/user": .entry(uid: 0, gid: 0, mode: S_IFLNK | 0o755, grantsByACL: false),
            "/Links/error": .error,
        ]
        let resolve: (String) -> String? = { path in
            ["/tmp": "/private/tmp", "/Links/apps": "/Applications", "/Links/user": "/opt"][path] ?? path
        }
        func check(_ location: String) -> Bool {
            SoftwareInstaller.isRootOnlyInstallLocation(location, lookup: lookup(fs), resolve: resolve)
        }
        #expect(check("/"))
        #expect(check("/Applications"))
        #expect(check("/Applications/"))
        #expect(check("/Library/Application Support/Acme"))          // missing leaf; ancestor passes
        #expect(check("/Library/New/Deeper"))                        // missing components under /Library
        #expect(check("/Links/apps"))                                 // root symlink to a root-only dir
        #expect(!check("/Library/Staff"))                             // group-writable by a non-admin group
        #expect(!check("/Library/Staff/Sub"))
        #expect(!check("/Library/World"))
        #expect(!check("/Library/ACL"))
        #expect(!check("/opt/acme"))                                  // user-owned ancestor
        #expect(!check("/Links/user/acme"))                           // symlink into a user-owned dir
        #expect(!check("/Links/error"))
        #expect(!check("/Users/Shared"))
        #expect(!check("/users/shared/Acme"))                         // denied, case-insensitively
        #expect(!check("/tmp/acme"))
        #expect(!check("/private/tmp"))
        #expect(!check("/var/tmp/x"))
        #expect(!check("Applications"))                               // not absolute
        #expect(!check(""))
        #expect(!check("/Applications/../Users/Shared"))
        #expect(!check("/Applications/\u{202E}ppa"))
        #expect(!check("/Applications/\u{85}"))
    }

    @Test("the real /Applications and / are root-only install locations; /Users/Shared and /tmp aren't")
    func installLocationRealFilesystem() {
        #expect(SoftwareInstaller.isRootOnlyInstallLocation("/"))
        #expect(SoftwareInstaller.isRootOnlyInstallLocation("/Applications"))
        #expect(SoftwareInstaller.isRootOnlyInstallLocation("/Library/Serberus-Test-\(UUID().uuidString)/Sub"))
        #expect(!SoftwareInstaller.isRootOnlyInstallLocation("/Users/Shared/Acme"))
        #expect(!SoftwareInstaller.isRootOnlyInstallLocation("/tmp"))
        #expect(!SoftwareInstaller.isRootOnlyInstallLocation(FileManager.default.temporaryDirectory.path))
    }

    @Test("install locations are read from PackageInfo (default /) and Distribution choices")
    func installLocationParsing() throws {
        let plain = try #require(PackageInfoInspector.inspect(Data(Self.plainPackageInfo.utf8)))
        #expect(plain.installLocations.map(\.location) == ["/Applications"])
        // pkgbuild leaves install-location out when it is "/".
        let noLocation = Self.plainPackageInfo.replacingOccurrences(of: " install-location=\"/Applications\"", with: "")
        #expect(try #require(PackageInfoInspector.inspect(Data(noLocation.utf8))).installLocations.map(\.location) == ["/"])
        let dist = """
        <?xml version="1.0" encoding="utf-8"?>
        <installer-gui-script minSpecVersion="1">
            <pkg-ref id="com.acme.foo"/>
            <choice id="default"/>
            <choice id="com.acme.foo" customLocation="/Users/Shared/Acme">
                <pkg-ref id="com.acme.foo"/>
            </choice>
        </installer-gui-script>
        """
        #expect(try #require(PackageInfoInspector.inspect(Data(dist.utf8))).installLocations.map(\.location) == ["/Users/Shared/Acme"])
        let relocatable = try #require(PackageInfoInspector.inspect(Data(Self.relocatablePackageInfo.utf8)))
        #expect(relocatable.relocatable == ["relocatable bundle com.acme.foo"])
        #expect(relocatable.otherFindings.isEmpty)
    }

    @Test("a package whose install location isn't root-only is refused before the prompt", arguments: [
        ("PackageInfo", "/Users/Shared/Acme"),
        ("PackageInfo", "/tmp"),
        ("PackageInfo", "relative/path"),
        ("Distribution", "/Users/Shared"),
    ])
    func unsafeInstallLocationRefused(file: String, location: String) async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        if file == "PackageInfo" {
            runner.expandedPackageInfo = Self.plainPackageInfo.replacingOccurrences(
                of: "install-location=\"/Applications\"", with: "install-location=\"\(location)\"")
        } else {
            runner.expandedExtras = ["Distribution": "<installer-gui-script><choice id=\"a\" customLocation=\"\(location)\"/></installer-gui-script>"]
        }
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.reason == .requiresIT)
        #expect(!result.message.contains(location))
        #expect(asked.value == nil)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    @Test("a package with no install-location (installs to /) is allowed")
    func defaultInstallLocationAllowed() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "installer": .init(status: 0)])
        runner.expandedPackageInfo = Self.plainPackageInfo.replacingOccurrences(of: " install-location=\"/Applications\"", with: "")
        let seen = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"),
                                     installLocationIsRootOnly: { seen.set($0); return SoftwareInstaller.isRootOnlyInstallLocation($0) })
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
        #expect(seen.value == "/")
    }

    @Test("every component package's install location is collected, and a component without PackageInfo is uninspectable")
    func componentInstallLocations() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let component = dir.appendingPathComponent("Foo.pkg", isDirectory: true)
        try FileManager.default.createDirectory(at: component, withIntermediateDirectories: true)
        try Data("<installer-gui-script><pkg-ref id=\"com.acme.foo\"/></installer-gui-script>".utf8)
            .write(to: dir.appendingPathComponent("Distribution"))
        #expect(SoftwareInstaller.packageFindings(inExpandedPackage: dir.path) == nil)
        let shared = Self.plainPackageInfo.replacingOccurrences(of: "install-location=\"/Applications\"",
                                                               with: "install-location=\"/Users/Shared\"")
        try Data(shared.utf8).write(to: component.appendingPathComponent("PackageInfo"))
        let inspection = try #require(SoftwareInstaller.packageFindings(inExpandedPackage: dir.path))
        #expect(inspection.installLocations == [.init(source: "Foo.pkg/PackageInfo", location: "/Users/Shared")])
        #expect(inspection.findings.isEmpty)
    }

    @Test("a refusal reason survives the wire, and an unknown one decodes as none")
    func refusalReasonCoding() throws {
        let original = InstallResult(status: .refusedByPolicy, message: "m", reason: .requiresIT)
        let data = try JSONEncoder().encode(original)
        #expect(try JSONDecoder().decode(InstallResult.self, from: data) == original)
        let unknown = Data(#"{"status":"refusedByPolicy","message":"m","reason":"somethingNew"}"#.utf8)
        #expect(try JSONDecoder().decode(InstallResult.self, from: unknown).reason == nil)
        let older = Data(#"{"status":"installed","message":"m"}"#.utf8)
        #expect(try JSONDecoder().decode(InstallResult.self, from: older).reason == nil)
    }
}

// MARK: - Replacement identity, package references, payload paths, staging as the user

extension SoftwareInstallerTests {
    // MARK: Replacement identity

    @Test("a same-publisher app with a different bundle ID can't replace an installed app by taking its name")
    func replaceDifferentBundleIDRefused() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        let installed = try makeApp(apps, name: "Defender.app", bundleID: "com.acme.defender")
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Defender.app", bundleID: "com.acme.word")
        let runner = FakeRunner(["spctl": acceptedApp])
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps,
                                     installedTeams: [installed: "AB12CD34EF"])
            .install(InstallRequest(sourcePath: src, displayName: "Defender.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.reason == .requiresIT)
        #expect(result.message.contains("bundle identifier"))
        #expect(asked.value == nil)
        #expect(SoftwareUninstaller.bundleID(ofAppAt: installed) == "com.acme.defender")   // untouched
    }

    @Test("the bundle ID match for a replacement is case-insensitive")
    func replaceBundleIDCaseInsensitive() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        let installed = try makeApp(apps, name: "Foo.app", bundleID: "com.acme.Foo")
        let src = try makeApp(dir.appendingPathComponent("src"), name: "Foo.app", bundleID: "com.acme.foo")
        let result = await installer(FakeRunner(["spctl": acceptedApp]), staging: dir.appendingPathComponent("stage"), apps: apps,
                                     installedTeams: [installed: "AB12CD34EF"])
            .install(InstallRequest(sourcePath: src, displayName: "Foo.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
    }

    @Test("an older copy of an installed app is refused under any name, in Applications or Utilities", arguments: [
        "", "Utilities",
    ])
    func renamedDowngradeRefused(folder: String) async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        _ = try makeVersionedApp(folder.isEmpty ? apps : apps.appendingPathComponent(folder), name: "Foo.app",
                                 bundleID: "com.acme.foo", version: "200", short: "2.0")
        let src = try makeVersionedApp(dir.appendingPathComponent("src"), name: "Foo 2.app", bundleID: "COM.ACME.FOO",
                                       version: "100", short: "1.0")
        let asked = Box()
        let result = await installer(FakeRunner(["spctl": acceptedApp]), staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "Foo 2.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.message.contains("older"))
        #expect(asked.value == nil)
        #expect(!FileManager.default.fileExists(atPath: apps.appendingPathComponent("Foo 2.app").path))
    }

    @Test("a same or newer copy under another name, or an unrelated app, doesn't block an install")
    func renamedUpgradeAllowed() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        _ = try makeVersionedApp(apps, name: "Foo.app", bundleID: "com.acme.foo", version: "100", short: "1.0")
        _ = try makeVersionedApp(apps, name: "Bar.app", bundleID: "com.acme.bar", version: "900", short: "9.0")
        let src = try makeVersionedApp(dir.appendingPathComponent("src"), name: "Foo 2.app", bundleID: "com.acme.foo",
                                       version: "101", short: "1.1")
        let result = await installer(FakeRunner(["spctl": acceptedApp]), staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "Foo 2.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
    }

    @Test("a copy under another name whose version can't be compared with the installed one is refused")
    func renamedIncomparableRefused() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps")
        _ = try makeVersionedApp(apps, name: "Foo.app", bundleID: "com.acme.foo", version: "2.0b7", short: nil)
        let src = try makeVersionedApp(dir.appendingPathComponent("src"), name: "Foo Legacy.app", bundleID: "com.acme.foo",
                                       version: "1.0b1", short: nil)
        let asked = Box()
        let result = await installer(FakeRunner(["spctl": acceptedApp]), staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "Foo Legacy.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.reason == .requiresIT)
        #expect(result.message.contains("can't be compared"))
        #expect(asked.value == nil)
        #expect(!FileManager.default.fileExists(atPath: apps.appendingPathComponent("Foo Legacy.app").path))
    }

    // MARK: What counts as an app, and its installed name

    @Test("an app is installed under a name its bundle declares; the file name only picks which one")
    func installedAppNameFromBundle() {
        let both: [String: Any] = ["CFBundleDisplayName": "Foo Studio", "CFBundleName": "Foo"]
        #expect(SoftwareInstaller.installedAppName(info: both, fileName: "Foo.app") == "Foo.app")
        #expect(SoftwareInstaller.installedAppName(info: both, fileName: "foo studio.app") == "Foo Studio.app")
        // A renamed download, or a squatted product name, gets the bundle's name.
        #expect(SoftwareInstaller.installedAppName(info: both, fileName: "Foo 2.app") == "Foo Studio.app")
        #expect(SoftwareInstaller.installedAppName(info: both, fileName: "Jamf Connect.app") == "Foo Studio.app")
        #expect(SoftwareInstaller.installedAppName(info: ["CFBundleName": "Bar"], fileName: "X.app") == "Bar.app")
        // Cleaned like any displayed name: invisible characters go.
        #expect(SoftwareInstaller.installedAppName(info: ["CFBundleName": "Ev\u{202E}il\u{200B}"], fileName: "X.app") == "Evil.app")
        // Names that can't be a file name in /Applications aren't used.
        for bad in ["", "   ", ".hidden", "a/b", "a:b", String(repeating: "x", count: 201)] {
            #expect(SoftwareInstaller.installedAppName(info: ["CFBundleName": bad], fileName: "X.app") == nil, "\(bad)")
        }
        #expect(SoftwareInstaller.installedAppName(info: ["CFBundleDisplayName": "a/b", "CFBundleName": "Good"], fileName: "X.app") == "Good.app")
        #expect(SoftwareInstaller.installedAppName(info: [:], fileName: "X.app") == nil)
    }

    @Test("a renamed app is installed under its bundle's name")
    func renamedAppUsesBundleName() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("apps"); try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        let src = try makeVersionedApp(dir.appendingPathComponent("src"), name: "Jamf Connect.app", bundleID: "com.acme.foo",
                                       version: "1", short: "1.0", bundleName: "Foo")
        let result = await installer(FakeRunner(["spctl": acceptedApp]), staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src, displayName: "Jamf Connect.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .installed)
        #expect(try FileManager.default.contentsOfDirectory(atPath: apps.path) == ["Foo.app"])
    }

    @Test("a .app that isn't an application bundle is refused before the signature is checked", arguments: [
        "file", "noInfoPlist", "notAPPL", "noBundleID", "noName",
    ])
    func nonBundleAppRefused(scenario: String) async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = dir.appendingPathComponent("src/X.app")
        try FileManager.default.createDirectory(at: src.deletingLastPathComponent(), withIntermediateDirectories: true)
        var plist: [String: Any] = ["CFBundleIdentifier": "com.acme.x", "CFBundlePackageType": "APPL", "CFBundleName": "X"]
        switch scenario {
        case "file":
            // A signed Mach-O renamed X.app.
            try Data("\u{CF}\u{FA}\u{ED}\u{FE}".utf8).write(to: src)
        case "noInfoPlist":
            try FileManager.default.createDirectory(at: src.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        default:
            if scenario == "notAPPL" { plist["CFBundlePackageType"] = "BNDL" }
            if scenario == "noBundleID" { plist["CFBundleIdentifier"] = nil }
            if scenario == "noName" { plist["CFBundleName"] = nil }
            try FileManager.default.createDirectory(at: src.appendingPathComponent("Contents"), withIntermediateDirectories: true)
            try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
                .write(to: src.appendingPathComponent("Contents/Info.plist"))
        }
        let runner = FakeRunner(["spctl": acceptedApp])
        let apps = dir.appendingPathComponent("apps")
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: apps)
            .install(InstallRequest(sourcePath: src.path, displayName: "X.app"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(!runner.calls.contains { $0.tool == "spctl" })
        #expect(!FileManager.default.fileExists(atPath: apps.appendingPathComponent("X.app").path))
    }

    // MARK: Package references

    private func expandedPackage(_ dir: URL, distribution: String?, components: [String: [String]]) throws {
        if let distribution { try Data(distribution.utf8).write(to: dir.appendingPathComponent("Distribution")) }
        for (name, files) in components {
            let component = dir.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(at: component, withIntermediateDirectories: true)
            for file in files {
                let body = file == "PackageInfo" ? Self.plainPackageInfo : "x"
                try Data(body.utf8).write(to: component.appendingPathComponent(file))
            }
        }
    }

    @Test("a Distribution pkg-ref must name an inspected top-level component as #name", arguments: [
        ("#Foo.pkg", true),
        ("#Foo%20Bar.pkg", true),
        ("#Missing.pkg", false),
        ("file:./Foo.pkg", false),
        ("https://example.com/Foo.pkg", false),
        ("#Resources", false),
        ("#Foo.pkg/Nested.pkg", false),
    ])
    func pkgRefResolution(content: String, resolves: Bool) throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try expandedPackage(dir, distribution: """
            <installer-gui-script minSpecVersion="2">
                <pkg-ref id="com.acme.foo"><bundle-version/></pkg-ref>
                <pkg-ref id="com.acme.foo" version="1.0">\(content)</pkg-ref>
            </installer-gui-script>
            """, components: ["Foo.pkg": ["PackageInfo", "Bom", "Payload"], "Foo Bar.pkg": ["PackageInfo"],
                              "Resources": ["en.lproj"]])
        let inspection = try #require(SoftwareInstaller.packageFindings(inExpandedPackage: dir.path))
        #expect(inspection.unresolvedReferences.isEmpty == resolves)
    }

    @Test("a CDATA pkg-ref counts as content")
    func pkgRefCDATA() throws {
        let data = Data("<installer-gui-script><pkg-ref id=\"a\"><![CDATA[http://x/y.pkg]]></pkg-ref></installer-gui-script>".utf8)
        #expect(PackageInfoInspector.inspect(data)?.pkgRefContents == ["http://x/y.pkg"])
    }

    @Test("a PackageInfo is required wherever a Payload or Bom exists, and a Payload needs its Bom", arguments: [
        (["Sub": ["Bom"]], false),
        (["Sub": ["Payload", "Bom"]], false),
        (["Foo.pkg": ["PackageInfo", "Payload"]], false),
        (["Foo.pkg": ["PackageInfo", "Payload", "Bom"]], true),
        (["Resources": ["Welcome.rtf"]], true),
        (["Foo.pkg/Scripts": ["Bom"]], true),        // a Scripts folder isn't a component
    ] as [([String: [String]], Bool)])
    func payloadNeedsPackageInfo(components: [String: [String]], inspectable: Bool) throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data(Self.plainPackageInfo.utf8).write(to: dir.appendingPathComponent("PackageInfo"))
        var all = components
        if components.keys.contains(where: { $0.hasPrefix("Foo.pkg/") }) { all["Foo.pkg"] = ["PackageInfo"] }
        try expandedPackage(dir, distribution: nil, components: all)
        #expect((SoftwareInstaller.packageFindings(inExpandedPackage: dir.path) != nil) == inspectable)
    }

    @Test("a package referring to content that wasn't inspected is refused before the prompt")
    func unresolvedReferenceRefused() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme])
        runner.expandedExtras = ["Distribution": "<installer-gui-script><pkg-ref id=\"x\">#Elsewhere.pkg</pkg-ref></installer-gui-script>"]
        let asked = Box()
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.reason == .requiresIT)
        #expect(asked.value == nil)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    // MARK: Payload paths

    /// A fake filesystem for the payload-path check (anything unlisted is missing).
    private func fakeFS(_ entries: [String: SoftwareInstaller.PayloadEntry], links: [String: String] = [:]) -> SoftwareInstaller.PayloadPathChecker {
        SoftwareInstaller.PayloadPathChecker(lookup: { entries[$0] ?? .missing }, readLink: { links[$0] })
    }

    private static func dir(_ uid: uid_t, _ gid: gid_t, _ mode: mode_t, acl: Bool = false) -> SoftwareInstaller.PayloadEntry {
        .entry(uid: uid, gid: gid, mode: S_IFDIR | mode, aclGrantsWrite: acl)
    }
    private static func file(_ uid: uid_t, _ mode: mode_t = 0o644) -> SoftwareInstaller.PayloadEntry {
        .entry(uid: uid, gid: 0, mode: S_IFREG | mode, aclGrantsWrite: false)
    }
    private static func link(_ uid: uid_t) -> SoftwareInstaller.PayloadEntry {
        .entry(uid: uid, gid: 0, mode: S_IFLNK | 0o755, aclGrantsWrite: false)
    }

    /// A Mac-like base: `/`, `/Library`, `/Library/Application Support`,
    /// `/Applications` (root:admin 0775), `/Users` and a sticky `/Users/Shared`.
    private var baseFS: [String: SoftwareInstaller.PayloadEntry] {
        ["/": Self.dir(0, 0, 0o755), "/Library": Self.dir(0, 0, 0o755),
         "/Library/Application Support": Self.dir(0, 80, 0o755), "/Applications": Self.dir(0, 80, 0o775),
         "/Users": Self.dir(0, 80, 0o755), "/Users/Shared": Self.dir(0, 0, 0o1777),
         "/private": Self.dir(0, 0, 0o755), "/private/tmp": Self.dir(0, 0, 0o1777), "/tmp": Self.link(0),
         "/usr": Self.dir(0, 0, 0o755), "/usr/local": Self.dir(0, 0, 0o755)]
    }

    @Test("payload paths only root (and admin or wheel through group write) can change pass")
    func payloadPathsPass() {
        var fs = baseFS
        fs["/Library/Application Support/Acme"] = Self.dir(0, 0, 0o755)
        fs["/Library/Application Support/Acme/tool"] = Self.file(0)
        fs["/Users/Shared/Acme"] = Self.dir(0, 0, 0o755)                       // root's, in a sticky folder
        fs["/Users/Shared/Acme/data"] = Self.dir(0, 0, 0o755)
        fs["/Applications/Admin.app"] = Self.dir(0, 80, 0o775)                  // admin group write is accepted
        let checker = fakeFS(fs)
        for path in ["/Applications/New.app/Contents/MacOS/new", "/Library/Application Support/Acme/tool",
                     "/Library/Application Support/Acme/new/deeper", "/Users/Shared/Acme/data/file",
                     "/Applications/Admin.app/Contents", "/", "/Library"] {
            #expect(checker.refusal(for: path) == nil, "\(path)")
        }
    }

    @Test("payload paths a user other than root could redirect are refused", arguments: [
        "missingInSticky", "userOwnedInSticky", "userSymlink", "tmpSymlink", "otherWritable", "groupWritable",
        "aclWritable", "ownerCanChmod", "stickyButUserOwnsParent", "lookupError", "fileMidPath", "dotDot",
        "rootSymlinkToUserFolder", "danglingEscape", "otherUserFolder", "otherUserSymlink", "writableFile",
        "otherUserApp", "staffWritable",
    ])
    func payloadPathsRefused(scenario: String) {
        var fs = baseFS
        var links: [String: String] = ["/tmp": "private/tmp"]
        var path = ""
        switch scenario {
        case "missingInSticky": path = "/Users/Shared/NewVendor/file"
        case "userOwnedInSticky":
            fs["/Users/Shared/Vendor"] = Self.dir(501, 20, 0o755); path = "/Users/Shared/Vendor/file"
        case "userSymlink":
            fs["/Library/Application Support/Acme"] = Self.link(501); links["/Library/Application Support/Acme"] = "/etc"
            path = "/Library/Application Support/Acme/file"
        case "tmpSymlink": path = "/tmp/acme/file"
        case "otherWritable":
            fs["/Library/Acme"] = Self.dir(0, 0, 0o777); fs["/Library/Acme/sub"] = Self.dir(0, 0, 0o755)
            path = "/Library/Acme/sub/file"
        case "groupWritable":
            fs["/Library/Acme"] = Self.dir(0, 20, 0o775); path = "/Library/Acme/file"
        case "aclWritable":
            fs["/Library/Acme"] = Self.dir(0, 0, 0o755, acl: true); path = "/Library/Acme/file"
        case "ownerCanChmod":
            fs["/Library/Acme"] = Self.dir(501, 0, 0o555); path = "/Library/Acme/file"
        case "stickyButUserOwnsParent":
            fs["/Library/Drop"] = Self.dir(501, 0, 0o1777); fs["/Library/Drop/x"] = Self.dir(0, 0, 0o755)
            path = "/Library/Drop/x/file"
        case "lookupError":
            fs["/Library/Acme"] = .error; path = "/Library/Acme/file"
        case "fileMidPath":
            fs["/Library/Acme"] = Self.file(0); path = "/Library/Acme/file"
        case "dotDot": path = "/Library/../Users/Shared/x"
        case "otherUserFolder":
            // A vendor script made another local user the owner of a plug-in folder.
            fs["/Library/Application Support/V"] = Self.dir(0, 0, 0o755)
            fs["/Library/Application Support/V/Plugins"] = Self.dir(502, 20, 0o755)
            path = "/Library/Application Support/V/Plugins/Common/x.plugin"
        case "otherUserSymlink":
            fs["/Library/Application Support/V"] = Self.link(502); links["/Library/Application Support/V"] = "/Library/LaunchDaemons"
            fs["/Library/LaunchDaemons"] = Self.dir(0, 0, 0o755)
            path = "/Library/Application Support/V/com.v.plist"
        case "writableFile":
            fs["/Library/Acme"] = Self.dir(0, 0, 0o755); fs["/Library/Acme/tool"] = Self.file(0, 0o666)
            path = "/Library/Acme/tool"
        case "otherUserApp":
            // Dragged in by an administrator, so owned by them.
            fs["/Applications/Foo.app"] = Self.dir(501, 80, 0o755); path = "/Applications/Foo.app/Contents"
        case "staffWritable":
            fs["/Library/Acme"] = Self.dir(0, 20, 0o775); fs["/Library/Acme/sub"] = Self.dir(0, 0, 0o755)
            path = "/Library/Acme/sub/file"
        case "rootSymlinkToUserFolder":
            fs["/usr/local/acme"] = Self.link(0); links["/usr/local/acme"] = "../../Users/Shared/acme"
            path = "/usr/local/acme/bin/tool"
        default:
            fs["/usr/local/acme"] = Self.link(0); links["/usr/local/acme"] = "x/../../y"
            path = "/usr/local/acme/tool"
        }
        #expect(fakeFS(fs, links: links).refusal(for: path) != nil)
    }

    @Test("a root-owned symlink in a safe folder is followed to a safe target")
    func rootSymlinkFollowed() {
        var fs = baseFS
        fs["/usr/local/acme"] = Self.link(0)
        fs["/Library/Acme"] = Self.dir(0, 0, 0o755)
        let checker = fakeFS(fs, links: ["/usr/local/acme": "../../Library/Acme"])
        #expect(checker.refusal(for: "/usr/local/acme/bin/tool") == nil)
        #expect(SoftwareInstaller.PayloadPathChecker.resolve("../../Library/Acme", in: "/usr/local") == ["Library", "Acme"])
        #expect(SoftwareInstaller.PayloadPathChecker.resolve("/a/./b", in: "/usr") == ["a", "b"])
        #expect(SoftwareInstaller.PayloadPathChecker.resolve("a/../b", in: "/usr") == nil)
    }

    /// `lsbom -p mfl` lines for `paths` (folders, except `links`, which are symlinks).
    static func bomListing(_ paths: [String], links: [String: String] = [:], files: Set<String> = []) -> String {
        paths.map { path in
            if let target = links[path] { return "120755\t\(path)\t\(target)\n" }
            return files.contains(path) ? "100644\t\(path)\t\n" : "40755\t\(path)\t\n"
        }.joined()
    }

    @Test("Bom listings become absolute payload paths under the install location")
    func bomListingParsing() {
        #expect(SoftwareInstaller.payloadPaths(fromBomListing: Self.bomListing([".", "./Foo.app", "./Foo.app/Contents"]), location: "/Applications/")
                == ["/Applications", "/Applications/Foo.app", "/Applications/Foo.app/Contents"])
        #expect(SoftwareInstaller.payloadPaths(fromBomListing: Self.bomListing([".", "./usr/local/bin/x"], files: ["./usr/local/bin/x"]), location: "/")
                == ["/", "/usr/local/bin/x"])
        #expect(SoftwareInstaller.payloadItems(fromBomListing: "40755\t.\t\n120755\t./l\t../x\n")
                == [.init(relativePath: ".", linkTarget: nil), .init(relativePath: "./l", linkTarget: "../x")])
        // The AppleDouble companion pkgbuild records for a symlink with
        // extended attributes: a link mode, no target. A plain entry.
        #expect(SoftwareInstaller.payloadItems(fromBomListing: "120755\t./._l\t\n")
                == [.init(relativePath: "./._l", linkTarget: nil)])
        // Anything but three well-formed fields is refused: a bare path, a
        // name split by a newline or holding a tab, a target on something
        // that isn't a link, a mode that isn't octal.
        for bad in ["./x\n", "40755\t./a\n./b\t\n", "100644\t./a\tb\t\n",
                    "40755\t./d\t/etc\n", "4x755\t./d\t\n", "40755\tsplit name\t\n"] {
            #expect(SoftwareInstaller.payloadItems(fromBomListing: bad) == nil, "\(bad)")
        }
    }

    @Test("an entry written through a symlink the package installs is checked where it really lands")
    func payloadLinksModelled() {
        let links: [String: SoftwareInstaller.PayloadLink] = [
            "/Library/Vendor": .init(target: "/Users/Shared/Vendor", location: "/"),
            "/Library/Acme/Current": .init(target: "Versions/A", location: "/"),
            "/Library/Acme/Up": .init(target: "../../etc", location: "/"),
            "/Applications/Foo.app/Contents/Out": .init(target: "/Library/LaunchDaemons", location: "/Applications"),
            "/Applications/Foo.app/Contents/Esc": .init(target: "../../../Library", location: "/Applications"),
            "/Library/Loop": .init(target: "/Library/Loop", location: "/"),
            "/Library/Tmp": .init(target: "/tmp", location: "/"),
        ]
        func verdict(_ path: String) -> SoftwareInstaller.PayloadLinkVerdict {
            SoftwareInstaller.payloadLinkRefusal(for: path, links: links)
        }
        // Not through a link, or the link itself: nothing to model.
        #expect(verdict("/Library/Other/file") == .none)
        #expect(verdict("/Library/Vendor") == .none)
        // Into a shared folder, or out of the install location: refused.
        if case .refused = verdict("/Library/Vendor/tool") {} else { Issue.record("shared folder") }
        if case .refused = verdict("/Library/Tmp/x") {} else { Issue.record("tmp") }
        if case .refused = verdict("/Applications/Foo.app/Contents/Out/com.acme.plist") {} else { Issue.record("outside the location") }
        if case .refused = verdict("/Applications/Foo.app/Contents/Esc/x") {} else { Issue.record("escape by ..") }
        if case .refused = verdict("/Library/Loop/x") {} else { Issue.record("loop") }
        // Inside the location: rewritten, so the on-disk check sees the real path.
        #expect(verdict("/Library/Acme/Current/Resources/x") == .through("/Library/Acme/Versions/A/Resources/x"))
        #expect(verdict("/Library/Acme/Up/x") == .through("/etc/x"))
    }

    @Test("a package whose payload lands in a folder the user could create is refused; one into /Applications passes")
    func payloadPathsEndToEnd() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let noLocation = Self.plainPackageInfo.replacingOccurrences(of: " install-location=\"/Applications\"", with: "")
        let vendor = "SerberusTestNoSuchVendor-\(UUID().uuidString)"
        for (listing, installs) in [(Self.bomListing([".", "./Users", "./Users/Shared", "./Users/Shared/\(vendor)", "./Users/Shared/\(vendor)/tool"]), false),
                                    (Self.bomListing([".", "./Applications", "./Applications/\(vendor).app", "./Applications/\(vendor).app/Contents"]), true),
                                    // A symlink the package installs, then a file written through it.
                                    (Self.bomListing([".", "./Library", "./Library/\(vendor)", "./Library/\(vendor)/tool"],
                                                     links: ["./Library/\(vendor)": "/Users/Shared/\(vendor)"]), false)] {
            let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "installer": .init(status: 0),
                                     "lsbom": .init(status: 0, stdout: listing)])
            runner.expandedPackageInfo = noLocation
            runner.expandedExtras = ["Bom": "bom", "Payload": "payload"]
            let asked = Box()
            let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
                .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: getuid(),
                         policy: enabled, stageID: "s1", confirm: { asked.set($0.authority); return true })
            #expect(runner.calls.first { $0.tool == "lsbom" }?.args.prefix(2) == ["-p", "mfl"])
            #expect((result.status == .installed) == installs, "\(listing)")
            if !installs {
                #expect(result.reason == .requiresIT)
                #expect(asked.value == nil)
                #expect(!result.message.contains(vendor))
            }
        }
    }

    @Test("an unreadable or over-budget Bom listing is uninspectable")
    func bomListingFailures() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = try makeSource(dir, name: "Foo.pkg")
        let runner = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "installer": .init(status: 0),
                                 "lsbom": .init(status: 1)])
        runner.expandedExtras = ["Bom": "bom", "Payload": "payload"]
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src, displayName: "Foo.pkg"), callerUID: getuid(),
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedByPolicy)
        #expect(result.reason == .requiresIT)
        #expect(!runner.calls.contains { $0.tool == "installer" })
    }

    /// Runs `pkgutil --expand` and `lsbom` for real (``SystemInstallCommandRunner``),
    /// everything else through a ``FakeRunner``.
    final class RealListingRunner: InstallCommandRunning, @unchecked Sendable {
        let fake: FakeRunner
        let real = SystemInstallCommandRunner()
        init(_ fake: FakeRunner) { self.fake = fake }

        func run(_ path: String, _ arguments: [String], timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
            let tool = (path as NSString).lastPathComponent
            if tool == "lsbom" || (tool == "pkgutil" && arguments.first == "--expand") {
                return await real.run(path, arguments, timeout: timeout)
            }
            return await fake.run(path, arguments, timeout: timeout)
        }

        func runAsUser(_ path: String, _ arguments: [String], user: FileOwner, workingDirectory: String,
                       timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
            await fake.runAsUser(path, arguments, user: user, workingDirectory: workingDirectory, timeout: timeout)
        }
    }

    private func runTool(_ path: String, _ arguments: [String]) throws -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = arguments
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        return p.terminationStatus
    }

    @Test("a real package with thousands of payload paths is listed through the real runner well within the time limit")
    func realPackageListing() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        // A payload of 3,000 files (about 200 KB of lsbom output, several
        // times a pipe's buffer) in a vendor folder that doesn't exist yet.
        let vendor = "SerberusTestNoSuchVendor-\(UUID().uuidString)"
        let root = dir.appendingPathComponent("root", isDirectory: true)
        let files = root.appendingPathComponent("\(vendor)/Resources/Localized-Strings", isDirectory: true)
        try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
        for index in 0..<3_000 {
            try Data().write(to: files.appendingPathComponent("resource-file-with-a-long-descriptive-name-\(index).strings"))
        }
        let pkg = dir.appendingPathComponent("Vendor.pkg")
        #expect(try runTool("/usr/bin/pkgbuild", ["--root", root.path, "--identifier", "com.acme.serberustest",
                                                  "--version", "1.0", "--install-location", "/Library/Application Support",
                                                  pkg.path]) == 0)

        let fake = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "installer": .init(status: 0)])
        let runner = RealListingRunner(fake)
        let started = Date()
        let result = await SoftwareInstaller(
            runner: runner, stagingRoot: dir.appendingPathComponent("stage"), applicationsDir: dir.appendingPathComponent("apps"),
            installTimeout: 5, installOwner: FileOwner(uid: getuid(), gid: getgid()), gate: AppManagementGate(),
            freeSpace: { _ in .max }, callerCanRead: { _, _ in true }, callerGroups: { _ in [] },
            stagingUser: { _ in FileOwner(uid: getuid(), gid: getgid()) }, signerOfApp: { _ in nil })
            .install(InstallRequest(sourcePath: pkg.path, displayName: "Vendor.pkg"), callerUID: getuid(),
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        let elapsed = Date().timeIntervalSince(started)
        #expect(elapsed < 30, "took \(elapsed) s; the staging limit is \(SoftwareInstaller.stagingTimeout) s")
        #expect(result.status == .installed, "\(result.message)")
        #expect(fake.calls.contains { $0.tool == "installer" })
    }

    @Test("a real package whose one component installs a symlink into a shared folder and another writes through it is refused")
    func realPackageWritingThroughItsOwnSymlink() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let vendor = "SerberusTestNoSuchVendor-\(UUID().uuidString)"
        // Component A: /Library/<vendor> -> /Users/Shared/<vendor>.
        let rootA = dir.appendingPathComponent("rootA/Library", isDirectory: true)
        try FileManager.default.createDirectory(at: rootA, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: rootA.appendingPathComponent(vendor).path,
                                                   withDestinationPath: "/Users/Shared/\(vendor)")
        // Component B: a file at /Library/<vendor>/tool — root writes it through A's link.
        let rootB = dir.appendingPathComponent("rootB/Library/\(vendor)", isDirectory: true)
        try FileManager.default.createDirectory(at: rootB, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: rootB.appendingPathComponent("tool"))
        let a = dir.appendingPathComponent("a.pkg"), b = dir.appendingPathComponent("b.pkg")
        let pkg = dir.appendingPathComponent("Vendor.pkg")
        #expect(try runTool("/usr/bin/pkgbuild", ["--root", dir.appendingPathComponent("rootA").path, "--identifier", "com.acme.a",
                                                  "--version", "1", "--install-location", "/", a.path]) == 0)
        #expect(try runTool("/usr/bin/pkgbuild", ["--root", dir.appendingPathComponent("rootB").path, "--identifier", "com.acme.b",
                                                  "--version", "1", "--install-location", "/", b.path]) == 0)
        #expect(try runTool("/usr/bin/productbuild", ["--package", a.path, "--package", b.path, pkg.path]) == 0)

        let fake = FakeRunner(["spctl": accepted, "pkgutil": pkgutilAcme, "installer": .init(status: 0)])
        let result = await SoftwareInstaller(
            runner: RealListingRunner(fake), stagingRoot: dir.appendingPathComponent("stage"), applicationsDir: dir.appendingPathComponent("apps"),
            installTimeout: 5, installOwner: FileOwner(uid: getuid(), gid: getgid()), gate: AppManagementGate(),
            freeSpace: { _ in .max }, callerCanRead: { _, _ in true }, callerGroups: { _ in [] },
            stagingUser: { _ in FileOwner(uid: getuid(), gid: getgid()) }, signerOfApp: { _ in nil })
            .install(InstallRequest(sourcePath: pkg.path, displayName: "Vendor.pkg"), callerUID: getuid(),
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .refusedByPolicy, "\(result.message)")
        #expect(result.reason == .requiresIT)
        #expect(result.message.contains("link"))
        #expect(!fake.calls.contains { $0.tool == "installer" })
    }

    // MARK: ACLs, extended attributes, staging root, normalization

    private func runChmod(_ arguments: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/chmod")
        p.arguments = arguments
        try p.run(); p.waitUntilExit()
        #expect(p.terminationStatus == 0)
    }

    @Test("an ACL deny entry for the caller makes an entry unreadable; an inherit-only one doesn't")
    func aclDenyRespected() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let app = dir.appendingPathComponent("Foo.app/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        let file = app.appendingPathComponent("data"); try Data("x".utf8).write(to: file)
        let me = SoftwareInstaller.SourceReader(uid: getuid(), groups: [getgid()])
        let top = dir.appendingPathComponent("Foo.app").path
        func isOK(_ scan: SoftwareInstaller.SourceScan) -> Bool { if case .ok = scan { return true } else { return false } }
        #expect(isOK(SoftwareInstaller.scanSource(atPath: top, limits: .standard, reader: me)))
        try runChmod(["+a", "user:\(NSUserName()) deny list,search,file_inherit,directory_inherit,only_inherit", app.path])
        #expect(isOK(SoftwareInstaller.scanSource(atPath: top, limits: .standard, reader: me)))
        try runChmod(["+a", "user:\(NSUserName()) deny read", file.path])
        #expect(SoftwareInstaller.scanSource(atPath: top, limits: .standard, reader: me) == .notReadableByCaller("Contents/data"))
        #expect(!SoftwareInstaller.uid(getuid(), groups: [getgid()], canReadPath: file.path))
        try runChmod(["-N", file.path])
        #expect(SoftwareInstaller.uid(getuid(), groups: [getgid()], canReadPath: file.path))
        try runChmod(["+a", "user:\(NSUserName()) deny search", app.path])
        #expect(SoftwareInstaller.scanSource(atPath: top, limits: .standard, reader: me) == .notReadableByCaller("Contents"))
        #expect(!SoftwareInstaller.uid(getuid(), groups: [getgid()], canReadPath: file.path))
        try runChmod(["-N", app.path])
    }

    @Test("extended attributes count toward the staging budget, and symlinks still scan")
    func xattrsCounted() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let app = dir.appendingPathComponent("Foo.app/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        let file = app.appendingPathComponent("tiny"); try Data("x".utf8).write(to: file)
        try FileManager.default.createSymbolicLink(at: app.appendingPathComponent("link"), withDestinationURL: file)
        let top = dir.appendingPathComponent("Foo.app").path
        guard case let .ok(before, entries) = SoftwareInstaller.scanSource(atPath: top, limits: .standard) else {
            Issue.record("scan failed"); return
        }
        #expect(entries == 4)
        let blob = [UInt8](repeating: 7, count: 4000)
        #expect(setxattr(file.path, "com.example.big", blob, blob.count, 0, 0) == 0)
        #expect(SoftwareInstaller.scanSource(atPath: top, limits: .standard) == .ok(bytes: before + 4000, entries: 4))
        #expect(SoftwareInstaller.scanSource(atPath: top, limits: .init(maxBytes: before + 3999, maxEntries: 100)) == .tooLarge)
    }

    @Test("the staging root is created 0700, re-stamped, and refused when it's a symlink or someone else's")
    func stagingRootRootOnly() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let me = FileOwner(uid: getuid(), gid: getgid())
        let root = dir.appendingPathComponent("Serberus/install-staging", isDirectory: true)
        try SoftwareInstaller.ensureStagingRoot(root, owner: me)
        var info = stat()
        #expect(lstat(root.path, &info) == 0 && info.st_mode & 0o7777 == 0o700)
        #expect(chmod(root.path, 0o755) == 0)
        try SoftwareInstaller.ensureStagingRoot(root, owner: me)
        #expect(lstat(root.path, &info) == 0 && info.st_mode & 0o7777 == 0o700)
        #expect(throws: InstallStagingError.self) {
            try SoftwareInstaller.ensureStagingRoot(root, owner: FileOwner(uid: getuid() &+ 1, gid: getgid()))
        }
        let linked = dir.appendingPathComponent("linked", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: root)
        #expect(throws: InstallStagingError.self) { try SoftwareInstaller.ensureStagingRoot(linked, owner: me) }
    }

    @Test("normalizing makes owner-only entries readable by everyone, keeping execute where the owner had it")
    func normalizeWidensOwnerOnly() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let contents = dir.appendingPathComponent("item.app/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        let data = contents.appendingPathComponent("data"); try Data("x".utf8).write(to: data)
        let tool = contents.appendingPathComponent("tool"); try Data("x".utf8).write(to: tool)
        #expect(chmod(data.path, 0o600) == 0 && chmod(tool.path, 0o700) == 0 && chmod(contents.path, 0o700) == 0)
        #expect(SoftwareInstaller.normalizeOwnership(atPath: dir.appendingPathComponent("item.app").path,
                                                     owner: FileOwner(uid: getuid(), gid: getgid())))
        var info = stat()
        #expect(stat(data.path, &info) == 0 && info.st_mode & 0o7777 == 0o644)
        #expect(stat(tool.path, &info) == 0 && info.st_mode & 0o7777 == 0o755)
        #expect(stat(contents.path, &info) == 0 && info.st_mode & 0o7777 == 0o755)
    }

    @Test("a folder named .pkg is refused up front")
    func bundlePackageRefused() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src = dir.appendingPathComponent("Foo.pkg", isDirectory: true)
        try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        let runner = FakeRunner([:])
        let result = await installer(runner, staging: dir.appendingPathComponent("stage"), apps: dir.appendingPathComponent("apps"))
            .install(InstallRequest(sourcePath: src.path, displayName: "Foo.pkg"), callerUID: 501,
                     policy: enabled, stageID: "s1", confirm: { _ in true })
        #expect(result.status == .failed)
        #expect(result.message.contains("flat"))
        #expect(runner.calls.isEmpty)
    }

    // MARK: Running the staging copy as the user

    @Test("the copy runs in the given folder, reached by descriptor, and a relative destination lands there")
    func userSpawnCopies() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let source = dir.appendingPathComponent("src.app/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("hello".utf8).write(to: source.appendingPathComponent("file"))
        let work = dir.appendingPathComponent("work", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        let me = FileOwner(uid: getuid(), gid: getgid())
        let r = await SystemInstallCommandRunner().runAsUser(BundleConfig.cpExecutablePath,
                                                             SoftwareInstaller.stagingCopyArguments(
                                                                 source: dir.appendingPathComponent("src.app").path, stagedName: "item.app"),
                                                             user: me, workingDirectory: work.path, timeout: 30)
        #expect(r.status == 0)
        #expect(try String(contentsOf: work.appendingPathComponent("item.app/Contents/file"), encoding: .utf8) == "hello")
        // A failing tool reports its status and stderr.
        let failed = await SystemInstallCommandRunner().runAsUser(BundleConfig.cpExecutablePath,
                                                                  SoftwareInstaller.stagingCopyArguments(
                                                                      source: dir.appendingPathComponent("none").path, stagedName: "x"),
                                                                  user: me, workingDirectory: work.path, timeout: 30)
        #expect(failed.status != 0)
        #expect(!failed.stderr.isEmpty)
    }

    /// Runs the staging copy for real (``UserSpawn``, as ``SystemInstallCommandRunner``
    /// does) with the staging root unsearchable, as it is for the user under the root daemon;
    /// everything else through a ``FakeRunner``. Records what the real copy
    /// left in the copy folder before root takes it back.
    final class UnsearchableStagingRunner: InstallCommandRunning, @unchecked Sendable {
        struct Staged { var status: Int32; var stderr: String; var walked: Bool; var hasACL: Bool; var linkIsSymlink: Bool? }
        let fake: FakeRunner
        let stagingRoot: URL
        private let lock = NSLock()
        private var _staged: Staged?
        var staged: Staged? { lock.withLock { _staged } }
        init(_ fake: FakeRunner, stagingRoot: URL) { self.fake = fake; self.stagingRoot = stagingRoot }

        func run(_ path: String, _ arguments: [String], timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
            await fake.run(path, arguments, timeout: timeout)
        }

        func runAsUser(_ path: String, _ arguments: [String], user: FileOwner, workingDirectory: String,
                       timeout: TimeInterval) async -> (status: Int32, stdout: String, stderr: String) {
            // Open the folder first, as root does in production (the test
            // daemon is the user, so it couldn't once the root is closed).
            let directory = open(workingDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else { return (-1, "", "working directory: errno \(errno)") }
            defer { close(directory) }
            guard chmod(stagingRoot.path, 0) == 0 else { return (-1, "", "chmod: errno \(errno)") }
            let r = await UserSpawn.run(path, arguments, user: user, directory: directory, timeout: timeout)
            _ = chmod(stagingRoot.path, 0o700)
            let item = URL(fileURLWithPath: workingDirectory).appendingPathComponent(arguments.last ?? "")
            var hasACL = false
            let walked = FileTree.walkItem(atPath: item.path) { fd, info, _ in
                if !FileTree.isSymlink(info), FileTree.hasExtendedACL(fd) { hasACL = true }
                return true
            }
            var link = stat()
            let linkIsSymlink = lstat(item.appendingPathComponent("Contents/Current").path, &link) == 0
                ? FileTree.isSymlink(link) : nil
            lock.withLock { _staged = Staged(status: r.status, stderr: r.stderr, walked: walked, hasACL: hasACL, linkIsSymlink: linkIsSymlink) }
            return r
        }
    }

    @Test("the real staging copy works when the user can't search the folders above it, and carries no ACL",
          arguments: ["Foo.pkg", "Foo.app"])
    func realStagingCopyUnderUnsearchableParent(name: String) async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let src: URL
        if name.hasSuffix(".app") {
            src = URL(fileURLWithPath: try makeApp(dir.appendingPathComponent("src"), name: name, bundleID: "com.acme.foo"))
            try FileManager.default.createDirectory(at: src.appendingPathComponent("Contents/A"), withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(atPath: src.appendingPathComponent("Contents/Current").path,
                                                       withDestinationPath: "A")
        } else {
            src = URL(fileURLWithPath: try makeSource(dir, name: name))
        }
        // ACLs the copy must not carry (the owner may add them).
        #expect(try runTool("/bin/chmod", ["+a", "everyone allow read", src.path]) == 0)
        if name.hasSuffix(".app") {
            #expect(try runTool("/bin/chmod", ["+a", "everyone allow read", src.appendingPathComponent("Contents/Info.plist").path]) == 0)
        }
        let staging = dir.appendingPathComponent("stage", isDirectory: true)
        let fake = FakeRunner(["spctl": name.hasSuffix(".app") ? acceptedApp : accepted, "pkgutil": pkgutilAcme])
        let runner = UnsearchableStagingRunner(fake, stagingRoot: staging)
        defer { _ = chmod(staging.path, 0o700) }
        let result = await SoftwareInstaller(
            runner: runner, stagingRoot: staging, applicationsDir: dir.appendingPathComponent("apps"),
            installTimeout: 5, installOwner: FileOwner(uid: getuid(), gid: getgid()), gate: AppManagementGate(),
            freeSpace: { _ in .max }, callerCanRead: { _, _ in true }, callerGroups: { _ in [] },
            stagingUser: { _ in FileOwner(uid: getuid(), gid: getgid()) }, signerOfApp: { _ in nil })
            .install(InstallRequest(sourcePath: src.path, displayName: name), callerUID: getuid(),
                     policy: enabled, stageID: "s1", confirm: { _ in false })
        let staged = try #require(runner.staged)
        #expect(staged.status == 0, "\(staged.stderr)")
        #expect(result.message != "Couldn't stage “\(name)” for verification.")
        #expect(fake.calls.contains { $0.tool == "spctl" })   // staged, then assessed
        #expect(staged.walked && !staged.hasACL)
        if name.hasSuffix(".app") { #expect(staged.linkIsSymlink == true) }
    }

    @Test("run-as-user refuses root, an identity it can't assume, a symlinked folder, and kills a child at the timeout")
    func userSpawnRefusals() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let me = FileOwner(uid: getuid(), gid: getgid())
        let runner = SystemInstallCommandRunner()
        #expect(await runner.runAsUser("/usr/bin/true", [], user: FileOwner(uid: 0, gid: 0), workingDirectory: dir.path, timeout: 5).status != 0)
        if geteuid() != 0 {
            // Only root can take on another user's identity: fail closed.
            let other = FileOwner(uid: getuid() &+ 1, gid: getgid())
            #expect(await runner.runAsUser("/usr/bin/true", [], user: other, workingDirectory: dir.path, timeout: 5).status != 0)
        }
        let linked = dir.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: dir)
        #expect(await runner.runAsUser("/usr/bin/true", [], user: me, workingDirectory: linked.path, timeout: 5).status != 0)
        let started = Date()
        let slow = await runner.runAsUser("/bin/sleep", ["30"], user: me, workingDirectory: dir.path, timeout: 0.5)
        #expect(slow.status == 124)
        #expect(Date().timeIntervalSince(started) < 10)
        #expect(await runner.runAsUser("/usr/bin/true", [], user: me, workingDirectory: dir.path, timeout: 5).status == 0)
    }
}
