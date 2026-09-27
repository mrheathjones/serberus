import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("SoftwareUninstaller — move a /Applications app to the Trash")
struct SoftwareUninstallerTests {
    /// A temp dir by its real path (`/private/var/…`): the uninstaller refuses
    /// any request path that passes through a symlink, and `/var` is one.
    private func tempDir() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-uninst-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return URL(fileURLWithPath: SoftwareUninstaller.realPath(d.path), isDirectory: true)
    }

    /// Creates a fake `.app` bundle (a dir + Contents/Info.plist with `bundleID`).
    @discardableResult
    private func makeApp(_ dir: URL, name: String, bundleID: String = "com.example.foo") throws -> URL {
        let app = dir.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: app.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        let plist = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": bundleID], format: .xml, options: 0)
        try plist.write(to: app.appendingPathComponent("Contents/Info.plist"))
        return app
    }

    /// (uninstaller, appsDir, homeDir). resolveUser points at a temp home so the
    /// real ~/.Trash is never touched; uid/gid are the current process's.
    private func harness(_ dir: URL, launchdDirectories: [URL] = [],
                         signature: SoftwareUninstaller.AppSignature? = nil) throws -> (SoftwareUninstaller, URL, URL) {
        let apps = dir.appendingPathComponent("Applications", isDirectory: true)
        let home = dir.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let user = SoftwareUninstaller.UserInfo(home: home.path, uid: getuid(), gid: getgid())
        // A private gate: tests run in parallel and must not trip the shared cap.
        // The system launchd folders are replaced by (by default, no) test folders.
        let uninstaller = SoftwareUninstaller(applicationsDir: apps, resolveUser: { _ in user }, gate: AppManagementGate(),
                                              launchdDirectories: launchdDirectories,
                                              signatureOfApp: { signature ?? SoftwareUninstaller.checkedSignature(ofAppAt: $0) })
        return (uninstaller, apps, home)
    }

    private func req(_ url: URL) -> UninstallRequest { UninstallRequest(appPath: url.path, displayName: url.lastPathComponent) }

    @Test("disabled or allowUninstall=false refuses by policy")
    func policyGate() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        let disabled = await u.uninstall(req(app), callerUID: 501, policy: .disabled, confirm: { _ in true })
        #expect(disabled.status == .refusedByPolicy)
        let noUninstall = await u.uninstall(req(app), callerUID: 501,
                                            policy: InstallPolicy(enabled: true, allowUninstall: false), confirm: { _ in true })
        #expect(noUninstall.status == .refusedByPolicy)
        #expect(FileManager.default.fileExists(atPath: app.path))   // never moved
    }

    @Test("root caller is refused")
    func refusesRoot() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        let r = await u.uninstall(req(app), callerUID: 0, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .failed)
    }

    @Test("an app outside /Applications is refused (not eligible)")
    func rejectsOutsideApplications() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, _, _) = try harness(dir)
        let elsewhere = try makeApp(dir, name: "Downloads-Foo.app")   // NOT under the apps dir
        let r = await u.uninstall(req(elsewhere), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .refusedNotEligible)
        #expect(FileManager.default.fileExists(atPath: elsewhere.path))
    }

    @Test("a non-.app target is refused")
    func rejectsNonApp() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let file = apps.appendingPathComponent("notes.txt"); try Data("x".utf8).write(to: file)
        let r = await u.uninstall(req(file), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .refusedNotEligible)
    }

    @Test("Serberus's own app can't be uninstalled through Serberus")
    func refusesSerberusApp() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let serberus = try makeApp(apps, name: "Serberus Commander.app", bundleID: "com.herojoneslabs.serberus.commander")
        let r = await u.uninstall(req(serberus), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .refusedNotEligible)
        #expect(FileManager.default.fileExists(atPath: serberus.path))   // never moved
    }

    @Test("declining the confirmation cancels (nothing moved)")
    func cancel() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in false })
        #expect(r.status == .cancelled)
        #expect(FileManager.default.fileExists(atPath: app.path))
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Foo.app").path))
    }

    @Test("a valid app is moved to the user's Trash and re-owned to them")
    func happyPath() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let apps = dir.appendingPathComponent("Applications", isDirectory: true)
        let home = dir.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let user = SoftwareUninstaller.UserInfo(home: home.path, uid: getuid(), gid: getgid())
        let u = SoftwareUninstaller(applicationsDir: apps, resolveUser: { _ in user }, gate: AppManagementGate(),
                                    launchdDirectories: [])
        let app = try makeApp(apps, name: "Foo.app")

        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .removed)
        #expect(r.message == "Moved to the Trash.")                                                   // clean hand-off
        #expect(!FileManager.default.fileExists(atPath: app.path))                                   // gone from Applications
        let trashed = home.appendingPathComponent(".Trash/Foo.app").path
        #expect(FileManager.default.fileExists(atPath: trashed))                                      // in the Trash
        var info = stat()
        #expect(lstat(trashed + "/Contents/Info.plist", &info) == 0 && info.st_uid == getuid())
    }

    @Test("a ~/.Trash that is a symlink is refused, and nothing lands at its target")
    func trashSymlinkRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let elsewhere = dir.appendingPathComponent("privileged", isDirectory: true)
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: home.appendingPathComponent(".Trash"), withDestinationURL: elsewhere)
        let app = try makeApp(apps, name: "Foo.app")

        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .failed)
        #expect(FileManager.default.fileExists(atPath: app.path))
        #expect(try FileManager.default.contentsOfDirectory(atPath: elsewhere.path).isEmpty)
    }

    @Test("a ~/.Trash that isn't a directory is refused")
    func trashNotDirectoryRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        try Data("x".utf8).write(to: home.appendingPathComponent(".Trash"))
        let app = try makeApp(apps, name: "Foo.app")

        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .failed)
        #expect(FileManager.default.fileExists(atPath: app.path))
    }

    /// Thread-safe "was the confirm prompt consulted?" flag for the @Sendable closure.
    final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var flag = false
        func set() { lock.withLock { flag = true } }
        var value: Bool { lock.withLock { flag } }
    }

    @Test("a protected bundle id is hard-denied with NO prompt (before confirmation)")
    func protectedBundleIsHardDenied() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps, name: "Guard.app", bundleID: "com.corp.edr")
        let consulted = Flag()
        // Case-insensitive match; the prompt must never even be reached.
        let policy = InstallPolicy(enabled: true, protectedBundleIdentifiers: ["COM.CORP.EDR"])
        let r = await u.uninstall(req(app), callerUID: 501, policy: policy,
                                  confirm: { _ in consulted.set(); return true })
        #expect(r.status == .refusedByPolicy)
        #expect(consulted.value == false)                                   // hard-denied BEFORE any prompt
        #expect(FileManager.default.fileExists(atPath: app.path))           // never moved
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Guard.app").path))
    }

    @Test("an app NOT on the protected list is still uninstallable (with confirmation)")
    func unprotectedAppProceeds() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app", bundleID: "com.example.foo")
        let policy = InstallPolicy(enabled: true, protectedBundleIdentifiers: ["com.corp.edr"])  // different id
        let r = await u.uninstall(req(app), callerUID: 501, policy: policy, confirm: { _ in true })
        #expect(r.status == .removed)
        #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Foo.app").path))
    }

    @Test("uninstall ALWAYS confirms even when promptBeforeAction is false")
    func uninstallAlwaysConfirms() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        // promptBeforeAction=false must NOT make uninstall silent: declining cancels.
        let declined = await u.uninstall(req(app), callerUID: 501,
                                         policy: InstallPolicy(enabled: true, promptBeforeAction: false),
                                         confirm: { _ in false })
        #expect(declined.status == .cancelled)
        #expect(FileManager.default.fileExists(atPath: app.path))           // never moved
        // Approving still proceeds (confirm WAS consulted despite the silent setting).
        let approved = await u.uninstall(req(app), callerUID: 501,
                                         policy: InstallPolicy(enabled: true, promptBeforeAction: false),
                                         confirm: { _ in true })
        #expect(approved.status == .removed)
        #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Foo.app").path))
    }

    // MARK: - Location rules

    @Test("a bundle nested inside another app is refused (never moved)")
    func nestedBundleRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let outer = try makeApp(apps, name: "Outer.app")
        let helpers = outer.appendingPathComponent("Contents/Helpers", isDirectory: true)
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
        let inner = try makeApp(helpers, name: "Inner.app")
        let r = await u.uninstall(req(inner), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .refusedNotEligible)
        #expect(FileManager.default.fileExists(atPath: inner.path))
    }

    @Test("an app in a subfolder other than Utilities is refused")
    func deeperFolderRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let app = try makeApp(apps.appendingPathComponent("Foo", isDirectory: true), name: "Bar.app")
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .refusedNotEligible)
        #expect(FileManager.default.fileExists(atPath: app.path))
    }

    @Test("an app in /Applications/Utilities is eligible")
    func utilitiesAllowed() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps.appendingPathComponent("Utilities", isDirectory: true), name: "Bar.app")
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .removed)
        #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Bar.app").path))
    }

    @Test("a symlinked app, or a path through a symlinked folder, is refused")
    func symlinkComponentsRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        // /Applications/Foo.app -> elsewhere/Foo.app
        let real = try makeApp(dir.appendingPathComponent("elsewhere", isDirectory: true), name: "Foo.app")
        let linkedApp = apps.appendingPathComponent("Foo.app")
        try FileManager.default.createSymbolicLink(at: linkedApp, withDestinationURL: real)
        let r1 = await u.uninstall(req(linkedApp), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r1.status == .refusedNotEligible)
        #expect(FileManager.default.fileExists(atPath: real.path))
        // <dir>/AppsLink -> Applications; request <dir>/AppsLink/Bar.app
        let bar = try makeApp(apps, name: "Bar.app")
        let appsLink = dir.appendingPathComponent("AppsLink")
        try FileManager.default.createSymbolicLink(at: appsLink, withDestinationURL: apps)
        let r2 = await u.uninstall(req(appsLink.appendingPathComponent("Bar.app")), callerUID: 501,
                                   policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r2.status == .refusedNotEligible)
        #expect(FileManager.default.fileExists(atPath: bar.path))
    }

    @Test("a bundle swapped in while the prompt is up is not moved")
    func swappedAfterPromptRefused() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        let parked = dir.appendingPathComponent("parked.app")
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in
            // Replace the confirmed bundle with a different one at the same path.
            try? FileManager.default.moveItem(at: app, to: parked)
            _ = try? self.makeApp(apps, name: "Foo.app", bundleID: "com.example.other")
            return true
        })
        #expect(r.status == .failed)
        #expect(FileManager.default.fileExists(atPath: app.path))
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Foo.app").path))
    }

    @Test("eligible locations: directly in Applications or Applications/Utilities only", arguments: [
        ("/Applications", "Foo.app", true),
        ("/Applications/Utilities", "Foo.app", true),
        ("/Applications", "foo.APP", true),
        ("/Applications/Foo.app/Contents/Helpers", "Bar.app", false),
        ("/Applications/Foo", "Bar.app", false),
        ("/Applications/Utilities/Sub", "Bar.app", false),
        ("/Users/u/Applications", "Foo.app", false),
        ("/", "Applications", false),
        ("/Applications", ".serberus-install-X.app", false),
        ("/Applications", ".app", false),
        ("/Applications", "notes.txt", false),
        ("/Applications", "Foo\u{202E}ppa.app", false),
        ("/Applications", "Foo\u{200B}.app", false),
        ("/Applications", "Foo\u{85}.app", false),
        ("/Applications", "Foo\n.app", false),
    ] as [(String, String, Bool)])
    func eligibleLocation(parent: String, name: String, expected: Bool) {
        #expect(SoftwareUninstaller.isEligibleLocation(parent: parent, name: name, applicationsDir: "/Applications") == expected)
    }

    @Test("every enclosing bundle is found for the self/protected checks")
    func enclosingBundles() {
        #expect(SoftwareUninstaller.bundlePaths(inPath: "/Applications/Outer.app/Contents/Helpers/Inner.app")
                == ["/Applications/Outer.app", "/Applications/Outer.app/Contents/Helpers/Inner.app"])
        #expect(SoftwareUninstaller.bundlePaths(inPath: "/Applications/Foo.app") == ["/Applications/Foo.app"])
    }

    // MARK: - Ownership hand-off

    @Test("hand-off re-owns world-listable and -searchable directories, singly-linked symlinks, and singly-linked world-readable files only", arguments: [
        (S_IFDIR | 0o755, 5, true),
        (S_IFDIR | 0o705, 2, true),
        (S_IFDIR | 0o700, 1, false),
        (S_IFDIR | 0o711, 2, false),
        (S_IFDIR | 0o744, 2, false),
        (S_IFREG | 0o644, 1, true),
        (S_IFREG | 0o444, 1, true),
        (S_IFREG | 0o644, 2, false),
        (S_IFREG | 0o600, 1, false),
        (S_IFREG | 0o640, 1, false),
        (S_IFLNK | 0o755, 1, true),
        (S_IFLNK | 0o755, 2, false),
        (S_IFIFO | 0o644, 1, false),
    ] as [(mode_t, Int, Bool)])
    func handOffPredicate(mode: mode_t, links: Int, expected: Bool) {
        #expect(SoftwareUninstaller.mayHandOwnership(mode: mode, linkCount: nlink_t(links)) == expected)
    }

    @Test("hand-off deletes a hard-linked file (not its other link) and never follows a symlink")
    func handOffSkipsHardLinks() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let foreign = dir.appendingPathComponent("foreign"); try Data("secret".utf8).write(to: foreign)
        let bundle = try makeApp(dir, name: "Foo.app")
        try FileManager.default.linkItem(at: foreign, to: bundle.appendingPathComponent("Contents/linked"))
        try FileManager.default.createSymbolicLink(at: bundle.appendingPathComponent("Contents/link"), withDestinationURL: foreign)

        let parent = open(dir.path, O_RDONLY | O_DIRECTORY); defer { close(parent) }
        var info = stat()
        #expect(fstatat(parent, "Foo.app", &info, AT_SYMLINK_NOFOLLOW) == 0)
        let user = SoftwareUninstaller.UserInfo(home: dir.path, uid: getuid(), gid: getgid())
        let handOff = SoftwareUninstaller.handOwnership(inDirectory: parent, name: "Foo.app",
                                                        expected: .init(info), to: user)
        #expect(handOff == .init(removed: ["Contents/linked"], kept: []))
        #expect(!FileManager.default.fileExists(atPath: bundle.appendingPathComponent("Contents/linked").path))
        #expect(FileManager.default.fileExists(atPath: foreign.path))                        // the other link survives
        var linkInfo = stat()
        #expect(lstat(bundle.appendingPathComponent("Contents/link").path, &linkInfo) == 0)  // the symlink is kept
        // A different bundle (identity mismatch) is not touched at all.
        var other = info; other.st_ino &+= 1
        #expect(SoftwareUninstaller.handOwnership(inDirectory: parent, name: "Foo.app",
                                                  expected: .init(other), to: user) == nil)
    }

    // MARK: - Privileged components, result messages and Info.plist reads

    @Test("an app embedding a LaunchDaemon or privileged helper is refused before the prompt", arguments: [
        "Contents/Library/LaunchDaemons/com.example.foo.helper.plist",
        "Contents/Library/LaunchServices/com.example.foo.helper",
    ])
    func privilegedComponentsRefused(relative: String) async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        let file = app.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("x".utf8).write(to: file)
        let consulted = Flag()
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true),
                                  confirm: { _ in consulted.set(); return true })
        #expect(r.status == .refusedNotEligible)
        #expect(r.message.contains("IT"))
        #expect(consulted.value == false)
        #expect(FileManager.default.fileExists(atPath: app.path))
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Foo.app").path))
    }

    @Test("privileged-component scan: none, LaunchAgents, LaunchDaemons, and a symlinked Library")
    func privilegedComponentScan() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let app = try makeApp(dir, name: "Foo.app")
        func scan() -> [String]? {
            let fd = open(app.path, O_RDONLY | O_DIRECTORY); defer { close(fd) }
            return SoftwareUninstaller.privilegedComponents(inBundle: fd)
        }
        #expect(scan() == [])
        let agents = app.appendingPathComponent("Contents/Library/LaunchAgents", isDirectory: true)
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: agents.appendingPathComponent("com.example.agent.plist"))
        #expect(scan() == ["Contents/Library/LaunchAgents/com.example.agent.plist"])
        try FileManager.default.removeItem(at: agents)
        let daemons = app.appendingPathComponent("Contents/Library/LaunchDaemons", isDirectory: true)
        try FileManager.default.createDirectory(at: daemons, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: daemons.appendingPathComponent(".DS_Store"))
        #expect(scan() == [])                                  // hidden files ignored
        try Data("x".utf8).write(to: daemons.appendingPathComponent("com.example.d.plist"))
        #expect(scan() == ["Contents/Library/LaunchDaemons/com.example.d.plist"])
        // A symlinked Library can't be inspected without following it: refuse.
        try FileManager.default.removeItem(at: app.appendingPathComponent("Contents/Library"))
        try FileManager.default.createSymbolicLink(at: app.appendingPathComponent("Contents/Library"), withDestinationURL: dir)
        #expect(scan() == nil)
    }

    @Test("the uninstall result reports deleted and system-owned entries only in general terms")
    func skippedEntriesSurfaced() {
        #expect(SoftwareUninstaller.trashMessage(.init()) == "Moved to the Trash.")
        let removed = SoftwareUninstaller.trashMessage(.init(removed: ["Contents/secret"], kept: []))
        #expect(removed.contains("deleted") && !removed.contains("Contents/secret"))
        let kept = SoftwareUninstaller.trashMessage(.init(removed: [], kept: ["Contents/locked"]))
        #expect(kept.contains("owned by the system") && !kept.contains("Contents/locked"))
        #expect(SoftwareUninstaller.trashMessage(nil).contains("owned by the system"))
    }

    @Test("an uninstall deletes a hard-linked file instead of handing it over, and doesn't name it")
    func hardLinkSurfacedEndToEnd() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, home) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        let foreign = dir.appendingPathComponent("foreign"); try Data("secret".utf8).write(to: foreign)
        try FileManager.default.linkItem(at: foreign, to: app.appendingPathComponent("Contents/linked"))
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .removed)
        #expect(r.message.contains("deleted"))
        #expect(!r.message.contains("Contents/linked"))
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".Trash/Foo.app/Contents/linked").path))
        #expect(FileManager.default.fileExists(atPath: foreign.path))
    }

    @Test("Serberus's own app is recognized case-insensitively")
    func refusesSerberusAppAnyCase() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let serberus = try makeApp(apps, name: "Serberus.app", bundleID: "COM.HEROJONESLABS.SERBERUS.Commander")
        let r = await u.uninstall(req(serberus), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .refusedNotEligible)
        #expect(FileManager.default.fileExists(atPath: serberus.path))
    }

    @Test("an uninstall while the same user has a request in flight is refused as busy")
    func uninstallBusy() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let apps = dir.appendingPathComponent("Applications", isDirectory: true)
        let home = dir.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let user = SoftwareUninstaller.UserInfo(home: home.path, uid: getuid(), gid: getgid())
        let gate = AppManagementGate()
        #expect(gate.acquire(uid: 501))
        let u = SoftwareUninstaller(applicationsDir: apps, resolveUser: { _ in user }, gate: gate, launchdDirectories: [])
        let app = try makeApp(apps, name: "Foo.app")
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .failed && r.message.contains("busy"))
        #expect(FileManager.default.fileExists(atPath: app.path))
    }

    @Test("Info.plist is read only from a regular file, never through a symlink or FIFO")
    func infoPlistReadSafely() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let app = try makeApp(dir, name: "Foo.app", bundleID: "com.example.foo")
        #expect(SoftwareUninstaller.bundleID(ofAppAt: app.path) == "com.example.foo")
        let plist = app.appendingPathComponent("Contents/Info.plist")
        try FileManager.default.removeItem(at: plist)
        #expect(mkfifo(plist.path, 0o644) == 0)
        #expect(SoftwareUninstaller.bundleID(ofAppAt: app.path) == nil)          // returns, doesn't block
        try FileManager.default.removeItem(at: plist)
        let other = try makeApp(dir, name: "Other.app", bundleID: "com.example.other")
        try FileManager.default.createSymbolicLink(at: plist, withDestinationURL: other.appendingPathComponent("Contents/Info.plist"))
        #expect(SoftwareUninstaller.bundleID(ofAppAt: app.path) == nil)
    }

    // MARK: - Hand-off, nested components, launchd jobs and the prompt

    @Test("hand-off deletes a file that isn't world-readable instead of handing it over")
    func handOffDeletesNonWorldReadable() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let bundle = try makeApp(dir, name: "Foo.app")
        let secret = bundle.appendingPathComponent("Contents/Resources/secret")
        try FileManager.default.createDirectory(at: secret.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("root only".utf8).write(to: secret)
        #expect(chmod(secret.path, 0o600) == 0)
        let parent = open(dir.path, O_RDONLY | O_DIRECTORY); defer { close(parent) }
        var info = stat()
        #expect(fstatat(parent, "Foo.app", &info, AT_SYMLINK_NOFOLLOW) == 0)
        let user = SoftwareUninstaller.UserInfo(home: dir.path, uid: getuid(), gid: getgid())
        let handOff = SoftwareUninstaller.handOwnership(inDirectory: parent, name: "Foo.app", expected: .init(info), to: user)
        #expect(handOff == .init(removed: ["Contents/Resources/secret"], kept: []))
        #expect(!FileManager.default.fileExists(atPath: secret.path))
        #expect(FileManager.default.fileExists(atPath: bundle.appendingPathComponent("Contents/Info.plist").path))  // world-readable: kept
    }

    private func chmodACL(_ arguments: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/chmod")
        p.arguments = arguments
        try p.run(); p.waitUntilExit()
        #expect(p.terminationStatus == 0)
    }

    @Test("hand-off deletes a file or folder an ACL deny entry hides from the user, even when the mode allows everyone")
    func handOffHonoursACLDeny() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let bundle = try makeApp(dir, name: "Foo.app")
        let resources = bundle.appendingPathComponent("Contents/Resources")
        let hidden = bundle.appendingPathComponent("Contents/Hidden")
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: hidden, withIntermediateDirectories: true)
        let secret = resources.appendingPathComponent("secret"); try Data("x".utf8).write(to: secret)
        let plain = resources.appendingPathComponent("plain"); try Data("x".utf8).write(to: plain)
        try Data("x".utf8).write(to: hidden.appendingPathComponent("inside"))
        #expect(chmod(secret.path, 0o644) == 0)
        // The entries name the user the app is handed to (`nobody`, so the
        // test process itself can still open everything, as root would).
        let nobody = try #require(getpwnam("nobody")?.pointee)
        try chmodACL(["+a", "user:nobody deny read", secret.path])
        try chmodACL(["+a", "user:nobody deny list,search", hidden.path])
        // An inherit-only deny doesn't apply to the folder itself.
        try chmodACL(["+a", "user:nobody deny read,file_inherit,only_inherit", resources.path])
        let parent = open(dir.path, O_RDONLY | O_DIRECTORY); defer { close(parent) }
        var info = stat()
        #expect(fstatat(parent, "Foo.app", &info, AT_SYMLINK_NOFOLLOW) == 0)
        let user = SoftwareUninstaller.UserInfo(home: dir.path, uid: nobody.pw_uid, gid: nobody.pw_gid)
        let handOff = SoftwareUninstaller.handOwnership(inDirectory: parent, name: "Foo.app", expected: .init(info), to: user)
        // (Re-owning to `nobody` needs root, so everything else is "kept" here.)
        #expect(Set(handOff?.removed ?? []) == ["Contents/Resources/secret", "Contents/Hidden"])
        #expect(!FileManager.default.fileExists(atPath: secret.path))
        #expect(!FileManager.default.fileExists(atPath: hidden.path))
        #expect(FileManager.default.fileExists(atPath: plain.path))
    }

    @Test("an app declaring or nesting a privileged component is refused before the prompt", arguments: [
        "infoKey", "nestedDaemon", "nestedAgent", "nestedInfoKey",
    ])
    func privilegedDeclarationsRefused(kind: String) async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        let nested = try makeApp(app.appendingPathComponent("Contents/Library/LoginItems", isDirectory: true),
                                 name: "Helper.app", bundleID: "com.example.foo.helper")
        func writeInfo(_ bundle: URL, _ extra: [String: Any]) throws {
            var plist: [String: Any] = ["CFBundleIdentifier": "com.example.x"]
            plist.merge(extra) { $1 }
            try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
                .write(to: bundle.appendingPathComponent("Contents/Info.plist"))
        }
        func writeJob(_ bundle: URL, _ folder: String) throws {
            let d = bundle.appendingPathComponent("Contents/Library/\(folder)", isDirectory: true)
            try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
            try Data("x".utf8).write(to: d.appendingPathComponent("com.example.job.plist"))
        }
        switch kind {
        case "infoKey": try writeInfo(app, ["SMPrivilegedExecutables": ["com.example.helper": "anchor apple"]])
        case "nestedDaemon": try writeJob(nested, "LaunchDaemons")
        case "nestedAgent": try writeJob(nested, "LaunchAgents")
        default: try writeInfo(nested, ["SMAuthorizedClients": ["identifier com.example.foo"]])
        }
        let consulted = Flag()
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true),
                                  confirm: { _ in consulted.set(); return true })
        #expect(r.status == .refusedNotEligible)
        #expect(r.reason == .requiresIT)
        #expect(consulted.value == false)
        #expect(FileManager.default.fileExists(atPath: app.path))
    }

    @Test("a nested app without privileged components doesn't block uninstall")
    func plainNestedAppAllowed() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app")
        try makeApp(app.appendingPathComponent("Contents/Helpers", isDirectory: true), name: "Helper.app")
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .removed)
    }

    @Test("a system launchd job that runs code from the app, or names its bundle ID, blocks uninstall", arguments: [
        "Program", "ProgramArguments", "BundleProgram", "AssociatedBundleIdentifiers", "AssociatedNested",
        "InterpreterScript", "Label", "LabelNested", "WorkingDirectory",
    ])
    func systemLaunchdJobRefused(key: String) async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let daemons = dir.appendingPathComponent("LaunchDaemons", isDirectory: true)
        let agents = dir.appendingPathComponent("LaunchAgents", isDirectory: true)
        try FileManager.default.createDirectory(at: daemons, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        let (u, apps, _) = try harness(dir, launchdDirectories: [daemons, agents])
        let app = try makeApp(apps, name: "Foo.app", bundleID: "com.example.foo")
        try makeApp(app.appendingPathComponent("Contents/Helpers", isDirectory: true), name: "Helper.app",
                    bundleID: "com.example.foo.helper")
        let binary = app.path + "/Contents/MacOS/foo-daemon"
        var job: [String: Any] = ["Label": "com.example.job"]
        switch key {
        case "Program": job["Program"] = binary
        case "ProgramArguments": job["ProgramArguments"] = [binary.uppercased(), "--daemon"]   // case-insensitive
        case "BundleProgram": job["BundleProgram"] = binary
        case "AssociatedBundleIdentifiers": job["AssociatedBundleIdentifiers"] = ["COM.EXAMPLE.FOO"]
        case "InterpreterScript": job["ProgramArguments"] = ["/bin/sh", app.path + "/Contents/Resources/agent.sh"]
        case "Label": job = ["Label": "Com.Example.Foo", "ProgramArguments": ["/usr/bin/true"]]
        case "LabelNested": job = ["Label": "com.example.foo.helper", "Program": "/usr/bin/true"]
        case "WorkingDirectory": job = ["Label": "com.example.job", "Program": "/usr/bin/true", "WorkingDirectory": app.path + "/Contents"]
        default: job["AssociatedBundleIdentifiers"] = "com.example.foo.helper"
        }
        let folder = key == "Program" ? agents : daemons
        try PropertyListSerialization.data(fromPropertyList: job, format: .binary, options: 0)
            .write(to: folder.appendingPathComponent("com.example.job.plist"))
        // An unrelated job and a malformed plist don't matter.
        try PropertyListSerialization.data(fromPropertyList: ["Label": "other", "Program": "/usr/bin/true"], format: .xml, options: 0)
            .write(to: daemons.appendingPathComponent("other.plist"))
        try Data("not a plist".utf8).write(to: daemons.appendingPathComponent("broken.plist"))
        let consulted = Flag()
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true),
                                  confirm: { _ in consulted.set(); return true })
        #expect(r.status == .refusedNotEligible)
        #expect(r.message.contains("IT"))
        #expect(consulted.value == false)
        #expect(FileManager.default.fileExists(atPath: app.path))
    }

    @Test("launchd job scan: unrelated jobs pass, a sibling app's path doesn't match, an oversized plist refuses")
    func launchdScan() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let daemons = dir.appendingPathComponent("LaunchDaemons", isDirectory: true)
        try FileManager.default.createDirectory(at: daemons, withIntermediateDirectories: true)
        let bundle = dir.path + "/Applications/Foo.app"
        func scan() -> [String]? {
            SoftwareUninstaller.launchdReferences(toBundleAt: bundle, bundleIDs: ["com.example.foo"], in: [daemons])
        }
        #expect(scan() == [])
        try PropertyListSerialization.data(fromPropertyList: ["Program": dir.path + "/Applications/Foo.app2/x"], format: .xml, options: 0)
            .write(to: daemons.appendingPathComponent("sibling.plist"))
        #expect(scan() == [])
        try PropertyListSerialization.data(fromPropertyList: ["Program": bundle + "/Contents/../Contents/MacOS/x"], format: .xml, options: 0)
            .write(to: daemons.appendingPathComponent("dotted.plist"))
        #expect(scan() == [daemons.path + "/dotted.plist"])
        try FileManager.default.removeItem(at: daemons.appendingPathComponent("dotted.plist"))
        try Data(repeating: 0x20, count: SoftwareUninstaller.maxPlistBytes + 1).write(to: daemons.appendingPathComponent("huge.plist"))
        #expect(scan() == nil)
        // A missing folder is fine.
        #expect(SoftwareUninstaller.launchdReferences(toBundleAt: bundle, bundleIDs: [], in: [dir.appendingPathComponent("none")]) == [])
    }

    @Test("an app nesting a protected or Serberus app is refused before the prompt", arguments: [
        ("com.vendor.agent", ["COM.VENDOR.AGENT"], InstallResult.Status.refusedByPolicy),
        ("com.herojoneslabs.serberus.helper", [], InstallResult.Status.refusedNotEligible),
    ] as [(String, [String], InstallResult.Status)])
    func nestedProtectedAppRefused(nestedID: String, protected: [String], status: InstallResult.Status) async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let (u, apps, _) = try harness(dir)
        let app = try makeApp(apps, name: "Vendor.app", bundleID: "com.vendor.app")
        try makeApp(app.appendingPathComponent("Contents/Library/LoginItems", isDirectory: true), name: "Agent.app",
                    bundleID: nestedID)
        let consulted = Flag()
        let r = await u.uninstall(req(app), callerUID: 501,
                                  policy: InstallPolicy(enabled: true, protectedBundleIdentifiers: protected),
                                  confirm: { _ in consulted.set(); return true })
        #expect(r.status == status)
        #expect(consulted.value == false)
        #expect(FileManager.default.fileExists(atPath: app.path))
    }

    @Test("hand-off deletes a folder that isn't world-searchable with everything in it, even world-readable files")
    func handOffDeletesPrivateFolder() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let bundle = try makeApp(dir, name: "Foo.app")
        let privateDir = bundle.appendingPathComponent("Contents/Resources/private", isDirectory: true)
        try FileManager.default.createDirectory(at: privateDir, withIntermediateDirectories: true)
        let licence = privateDir.appendingPathComponent("licence.key")
        try Data("token".utf8).write(to: licence)
        #expect(chmod(licence.path, 0o644) == 0)
        #expect(chmod(privateDir.path, 0o700) == 0)
        let parent = open(dir.path, O_RDONLY | O_DIRECTORY); defer { close(parent) }
        var info = stat()
        #expect(fstatat(parent, "Foo.app", &info, AT_SYMLINK_NOFOLLOW) == 0)
        let user = SoftwareUninstaller.UserInfo(home: dir.path, uid: getuid(), gid: getgid())
        let handOff = SoftwareUninstaller.handOwnership(inDirectory: parent, name: "Foo.app", expected: .init(info), to: user)
        #expect(handOff == .init(removed: ["Contents/Resources/private"], kept: []))
        #expect(!FileManager.default.fileExists(atPath: privateDir.path))
        #expect(FileManager.default.fileExists(atPath: bundle.appendingPathComponent("Contents/Info.plist").path))
    }

    @Test("a bundle folder that isn't world-searchable is emptied, and only the empty folder is handed over")
    func handOffEmptiesPrivateBundle() throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let bundle = try makeApp(dir, name: "Foo.app")
        #expect(chmod(bundle.path, 0o700) == 0)
        let parent = open(dir.path, O_RDONLY | O_DIRECTORY); defer { close(parent) }
        var info = stat()
        #expect(fstatat(parent, "Foo.app", &info, AT_SYMLINK_NOFOLLOW) == 0)
        let user = SoftwareUninstaller.UserInfo(home: dir.path, uid: getuid(), gid: getgid())
        let handOff = SoftwareUninstaller.handOwnership(inDirectory: parent, name: "Foo.app", expected: .init(info), to: user)
        #expect(handOff == .init(removed: ["Contents"], kept: []))
        #expect(try FileManager.default.contentsOfDirectory(atPath: bundle.path).isEmpty)
    }

    @Test("the move never replaces something already in the Trash; a taken name gets a timestamp before .app")
    func trashNameCollision() async throws {
        let dir = try tempDir(); defer { _ = FileTree.removeTree(atPath: dir.path) }
        let apps = dir.appendingPathComponent("Applications", isDirectory: true)
        let home = dir.appendingPathComponent("home", isDirectory: true)
        let trash = home.appendingPathComponent(".Trash", isDirectory: true)
        try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: trash, withIntermediateDirectories: true)
        let user = SoftwareUninstaller.UserInfo(home: home.path, uid: getuid(), gid: getgid())
        let u = SoftwareUninstaller(applicationsDir: apps, resolveUser: { _ in user },
                                    now: { Date(timeIntervalSince1970: 1_700_000_000) }, gate: AppManagementGate(),
                                    launchdDirectories: [], signatureOfApp: { _ in .init(status: .unsigned, teamID: nil) })
        // Something the user planted at both the plain and the timestamped name.
        try FileManager.default.createDirectory(at: trash.appendingPathComponent("Foo.app"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: trash.appendingPathComponent("Foo 1700000000.app"),
                                                   withDestinationURL: dir)
        let app = try makeApp(apps, name: "Foo.app")
        let r = await u.uninstall(req(app), callerUID: 501, policy: InstallPolicy(enabled: true), confirm: { _ in true })
        #expect(r.status == .removed)
        #expect(FileManager.default.fileExists(atPath: trash.appendingPathComponent("Foo 1700000000-1.app/Contents/Info.plist").path))
        #expect(FileManager.default.fileExists(atPath: trash.appendingPathComponent("Foo.app").path))
        var link = stat()
        #expect(lstat(trash.appendingPathComponent("Foo 1700000000.app").path, &link) == 0 && link.st_mode & S_IFMT == S_IFLNK)
    }

    /// Thread-safe holder for the confirmation the uninstaller asked about.
    final class ConfirmationBox: @unchecked Sendable {
        private let lock = NSLock()
        private var _value: UninstallConfirmation?
        var value: UninstallConfirmation? { lock.withLock { _value } }
        func set(_ v: UninstallConfirmation) { lock.withLock { _value = v } }
    }

    @Test("the uninstall prompt shows only checked facts: canonical path, bundle ID, and the signature check's result")
    func confirmationUsesCheckedFacts() async throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        // An unsigned test bundle: the real check says so, never "valid".
        let (u, apps, _) = try harness(dir)
        let app = try makeApp(apps, name: "Foo.app", bundleID: "com.example.foo")
        let seen = ConfirmationBox()
        let r = await u.uninstall(UninstallRequest(appPath: app.path, displayName: "Totally Safe.app"), callerUID: 501,
                                  policy: InstallPolicy(enabled: true), confirm: { seen.set($0); return false })
        #expect(r.status == .cancelled)
        let item = try #require(seen.value)
        #expect(item.appName == "Foo.app")
        #expect(item.canonicalPath == app.path)
        #expect(item.bundleID == "com.example.foo")
        #expect(item.signingStatus != .valid)
        #expect(item.teamID == nil)

        let (signed, signedApps, _) = try harness(dir.appendingPathComponent("signed"),
                                                  signature: .init(status: .valid, teamID: "AB12CD34EF"))
        let other = try makeApp(signedApps, name: "Bar.app", bundleID: "com.example.bar")
        let (_, audit) = await signed.uninstallAudited(req(other), callerUID: 501, policy: InstallPolicy(enabled: true),
                                                       confirm: { seen.set($0); return false })
        #expect(seen.value?.signingStatus == .valid && seen.value?.teamID == "AB12CD34EF")
        #expect(audit == { var a = UninstallAudit(); a.canonicalPath = other.path; a.bundleID = "com.example.bar"; a.teamID = "AB12CD34EF"; return a }())
    }
}
