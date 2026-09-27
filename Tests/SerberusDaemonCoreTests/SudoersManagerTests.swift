import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// In-memory ``SudoersInstalling`` recording installs/removes and simulating a
/// currently-installed managed file — so the manager's generate → screen →
/// change-detect → validate/install/remove orchestration is verified without
/// root, `/etc`, or a real `visudo`.
final class MockSudoersInstaller: SudoersInstalling, @unchecked Sendable {
    private let lock = NSLock()
    /// The body of the "installed" managed file (nil = absent/foreign).
    var storedBody: String?
    var failInstall = false
    var failRemove = false
    private(set) var installedBodies: [String] = []
    private(set) var removeCount = 0

    init(storedBody: String? = nil) { self.storedBody = storedBody }

    func currentManagedBody() -> String? {
        lock.lock(); defer { lock.unlock() }
        return storedBody
    }

    func validateAndInstall(_ body: String) async throws {
        if failInstall { throw SudoersError.visudoValidationFailed(status: 1, stderr: "parse error") }
        recordInstall(body)
    }

    /// Synchronous critical section — NSLock is unavailable across an async
    /// boundary under Swift 6, and the mutation itself never awaits.
    private func recordInstall(_ body: String) {
        lock.lock(); defer { lock.unlock() }
        installedBodies.append(body)
        storedBody = body
    }

    func removeManaged() throws {
        if failRemove { throw SudoersError.installFailed("rm failed") }
        lock.lock(); defer { lock.unlock() }
        removeCount += 1
        storedBody = nil
    }
}

@Suite("SudoersManager", .serialized)
struct SudoersManagerTests {
    private func manager(_ installer: SudoersInstalling) -> SudoersManager {
        SudoersManager(installer: installer, integrityLogger: nil,
                       daemonVersion: "1.0.0", now: { CoordinatorFixtures.now })
    }

    private func sudoAllowProfile(pattern: String = "/bin/echo",
                                  matchType: MatchType = .exact) -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo", profilePriority: 50,
            rules: [Rule(
                id: "allow-cmd", type: .sudo, action: .allow, description: "d", priority: 10,
                match: MatchCriteria(commandPattern: pattern, matchType: matchType)
            )]
        )
    }

    private let jane = SerberusConfig.SudoEnrollment(group: nil, users: ["jane"])

    // MARK: apply — install

    @Test("apply installs the generated body pinned to the canonical managed header")
    func applyInstalls() async throws {
        let installer = MockSudoersInstaller()
        await manager(installer).apply(profiles: [sudoAllowProfile()], enrollment: jane)

        #expect(installer.installedBodies.count == 1)
        let body = try #require(installer.installedBodies.first)
        // First line is exactly the canonical Swift header the pkg teardown
        // marker-guard anchors on.
        #expect(body.hasPrefix(BundleConfig.sudoersManagedHeader))
        #expect(body.contains("jane ALL ="))
        #expect(body.contains("/bin/echo"))
        // Never a NOPASSWD tag, never an ALL-commands token.
        #expect(!body.contains("NOPASSWD"))
        #expect(!body.contains("ALL = ALL"))
    }

    @Test("apply with a group enrollment renders a %group principal")
    func applyGroup() async throws {
        let installer = MockSudoersInstaller()
        let enrollment = SerberusConfig.SudoEnrollment(group: "serberus-sudoers", users: [])
        await manager(installer).apply(profiles: [sudoAllowProfile()], enrollment: enrollment)

        let body = try #require(installer.installedBodies.first)
        #expect(body.contains("%serberus-sudoers ALL ="))
    }

    // MARK: apply — remove on empty

    @Test("empty enrollment removes the drop-in and never installs")
    func emptyEnrollmentRemoves() async {
        let installer = MockSudoersInstaller(storedBody: "stale")
        await manager(installer).apply(profiles: [sudoAllowProfile()],
                                       enrollment: SerberusConfig.SudoEnrollment())
        #expect(installer.installedBodies.isEmpty)
        #expect(installer.removeCount == 1)
        #expect(installer.storedBody == nil)
    }

    @Test("all-rules-excluded (regex/any only) removes rather than installing a header-only file")
    func allExcludedRemoves() async {
        let installer = MockSudoersInstaller(storedBody: "stale")
        // A .regex rule is not representable → excluded → empty body → remove.
        await manager(installer).apply(profiles: [sudoAllowProfile(pattern: ".*", matchType: .regex)],
                                       enrollment: jane)
        #expect(installer.installedBodies.isEmpty)
        #expect(installer.removeCount == 1)
    }

    @Test("deny rules never feed the drop-in (empty body ⇒ remove)")
    func denyRulesNotEmitted() async {
        let installer = MockSudoersInstaller()
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo", profilePriority: 50,
            rules: [Rule(id: "deny", type: .sudo, action: .deny, description: "d", priority: 10,
                         match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact))]
        )
        await manager(installer).apply(profiles: [profile], enrollment: jane)
        #expect(installer.installedBodies.isEmpty)
        #expect(installer.removeCount == 1)
    }

    // MARK: apply — change detection

    @Test("an unchanged body skips the install entirely (no churn)")
    func changeDetectionSkips() async {
        let installer = MockSudoersInstaller()
        let m = manager(installer)
        // First apply installs and populates the stored body.
        await m.apply(profiles: [sudoAllowProfile()], enrollment: jane)
        #expect(installer.installedBodies.count == 1)
        // Second apply with identical inputs short-circuits before validate/install.
        await m.apply(profiles: [sudoAllowProfile()], enrollment: jane)
        #expect(installer.installedBodies.count == 1)
    }

    // MARK: apply — non-fatal failure

    @Test("a validation/install failure is non-fatal and keeps the prior-good file")
    func installFailureIsNonFatal() async {
        let installer = MockSudoersInstaller(storedBody: "prior-good")
        installer.failInstall = true
        // Must not crash; the attempt is made, but storedBody is left as prior-good.
        await manager(installer).apply(profiles: [sudoAllowProfile()], enrollment: jane)
        #expect(installer.storedBody == "prior-good")
    }

    // MARK: apply/remove — success signal

    @Test("apply returns true on a successful install")
    func applyReportsSuccess() async {
        let installer = MockSudoersInstaller()
        let ok = await manager(installer).apply(profiles: [sudoAllowProfile()], enrollment: jane)
        #expect(ok)
    }

    @Test("apply returns true when the body is byte-identical (no churn is still success)")
    func applyUnchangedReportsSuccess() async {
        let installer = MockSudoersInstaller()
        let m = manager(installer)
        _ = await m.apply(profiles: [sudoAllowProfile()], enrollment: jane)
        let ok = await m.apply(profiles: [sudoAllowProfile()], enrollment: jane)
        #expect(ok) // on-disk state already matches intent
    }

    @Test("apply returns true when a shrink-to-empty removes the drop-in")
    func applyEmptyRemovalReportsSuccess() async {
        let installer = MockSudoersInstaller(storedBody: "stale")
        let ok = await manager(installer).apply(
            profiles: [sudoAllowProfile()], enrollment: SerberusConfig.SudoEnrollment())
        #expect(ok)
        #expect(installer.storedBody == nil)
    }

    @Test("apply returns false when a validation/install failure keeps the prior-good file")
    func applyFailureReportsFailure() async {
        let installer = MockSudoersInstaller(storedBody: "prior-good")
        installer.failInstall = true
        let ok = await manager(installer).apply(profiles: [sudoAllowProfile()], enrollment: jane)
        #expect(!ok) // intent NOT realized — caller must leave the signature stale
    }

    @Test("apply returns false when a shrink-to-empty removal fails")
    func applyEmptyRemovalFailureReportsFailure() async {
        let installer = MockSudoersInstaller(storedBody: "stale")
        installer.failRemove = true
        let ok = await manager(installer).apply(
            profiles: [sudoAllowProfile()], enrollment: SerberusConfig.SudoEnrollment())
        #expect(!ok)
    }

    // MARK: remove

    @Test("remove() delegates to the marker-guarded backend removal")
    func removeDelegates() async {
        let installer = MockSudoersInstaller(storedBody: "managed")
        await manager(installer).remove()
        #expect(installer.removeCount == 1)
        #expect(installer.storedBody == nil)
    }

    @Test("a removal failure is non-fatal")
    func removeFailureIsNonFatal() async {
        let installer = MockSudoersInstaller(storedBody: "managed")
        installer.failRemove = true
        await manager(installer).remove()  // must not throw/crash
        #expect(installer.removeCount == 0)
    }

    @Test("remove returns true on success, false when the removal I/O fails")
    func removeReportsSuccessSignal() async {
        let ok = await manager(MockSudoersInstaller(storedBody: "managed")).remove()
        #expect(ok)

        let failing = MockSudoersInstaller(storedBody: "managed")
        failing.failRemove = true
        let failed = await manager(failing).remove()
        #expect(!failed) // left in place — caller must retry the shrink
    }

    // MARK: body pre-screen

    @Test("bodyIsClean accepts printable text with newlines, rejects control chars")
    func bodyIsClean() {
        #expect(SudoersManager.bodyIsClean("# header\njane ALL = /bin/echo\n"))
        #expect(!SudoersManager.bodyIsClean("jane ALL = /bin/echo\u{0}"))   // NUL
        #expect(!SudoersManager.bodyIsClean("jane ALL = /bin/echo\r\n"))    // CR
        #expect(!SudoersManager.bodyIsClean("jane\tALL = /bin/echo"))       // tab
    }

    // MARK: marker guard (installer helper)

    @Test("isManaged matches both header case variants and rejects foreign files")
    func markerGuard() {
        let prefix = "# \(BundleConfig.sudoersDropInPath): managed by \(BundleConfig.logSubsystem)"
        // Uppercase generator-default variant.
        #expect(SystemSudoersInstaller.isManaged(
            SudoersGenerator.defaultHeader + "\njane ALL = /bin/echo\n", markerPrefix: prefix))
        // Lowercase BundleConfig variant.
        #expect(SystemSudoersInstaller.isManaged(
            BundleConfig.sudoersManagedHeader + "\njane ALL = /bin/echo\n", markerPrefix: prefix))
        // Foreign admin-authored file at the same path — never claimed as managed.
        #expect(!SystemSudoersInstaller.isManaged(
            "# my own sudoers\njane ALL = /usr/bin/true\n", markerPrefix: prefix))
    }
}
