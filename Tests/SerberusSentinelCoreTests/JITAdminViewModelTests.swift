import Foundation
import Testing
import PrivMgrCore
@testable import SerberusSentinelCore

@MainActor
@Suite("JITAdminViewModel")
struct JITAdminViewModelTests {
    private func info(available: Bool, requireJustification: Bool = true, minLength: Int = 10) -> JITAdminInfo {
        JITAdminInfo(available: available, provider: .serberus,
                     requireJustification: requireJustification,
                     justificationMinLength: minLength, maxDurationSeconds: 900)
    }

    private func model(info: JITAdminInfo,
                       request: @escaping @Sendable (String) async -> JITAdminResult? = { _ in nil },
                       end: @escaping @Sendable () async -> Bool = { false },
                       runJamfConnect: @escaping @Sendable (JamfConnectCommand) async -> Bool = { _ in false },
                       checkJamfConnect: @escaping @Sendable (JamfConnectCommand) async -> JamfConnectAvailability = { _ in .ready })
        -> JITAdminViewModel {
        JITAdminViewModel(actions: .init(loadInfo: { info }, request: request, end: end,
                                         runJamfConnect: runJamfConnect, checkJamfConnect: checkJamfConnect))
    }

    @Test("unavailable policy resolves to the unavailable phase")
    func unavailable() async {
        let vm = model(info: info(available: false))
        await vm.refresh(activeExpiry: nil)
        #expect(vm.phase == .unavailable)
    }

    @Test("an active grant expiry drives the active phase")
    func active() async {
        let expires = Date().addingTimeInterval(600)
        let vm = model(info: info(available: true))
        await vm.refresh(activeExpiry: expires)
        #expect(vm.phase == .active(expiresAt: expires))
    }

    @Test("submit is gated on justification length")
    func submitGate() async {
        let vm = model(info: info(available: true, minLength: 10))
        await vm.refresh(activeExpiry: nil)
        #expect(!vm.canSubmit)
        vm.justification = "short"
        #expect(!vm.canSubmit)
        vm.justification = "a sufficiently long reason"
        #expect(vm.canSubmit)
    }

    @Test("a granted result moves to the active phase and clears the field")
    func grantedFlow() async {
        let expires = Date().addingTimeInterval(900)
        let vm = model(info: info(available: true),
                       request: { _ in JITAdminResult(outcome: .granted, message: "ok", expiresAt: expires) })
        await vm.refresh(activeExpiry: nil)
        vm.justification = "installing developer tools"
        await vm.submit()
        #expect(vm.phase == .active(expiresAt: expires))
        #expect(vm.justification.isEmpty)
    }

    @Test("a denied result surfaces the daemon's message")
    func deniedFlow() async {
        let vm = model(info: info(available: true),
                       request: { _ in JITAdminResult(outcome: .denied, message: "You are not eligible.") })
        await vm.refresh(activeExpiry: nil)
        vm.justification = "a sufficiently long reason"
        await vm.submit()
        #expect(vm.phase == .message("You are not eligible."))
    }

    @Test("ending early returns to idle")
    func endFlow() async {
        let vm = model(info: info(available: true), end: { true })
        await vm.refresh(activeExpiry: Date().addingTimeInterval(300))
        await vm.end()
        #expect(vm.phase == .idle)
    }

    @Test("Jamf Connect mode launches JC and never calls the daemon request path")
    func jamfConnectLaunches() async {
        let jcInfo = JITAdminInfo(available: true, provider: .jamfConnect, requireJustification: false,
                                  justificationMinLength: 0, maxDurationSeconds: 900,
                                  jamfConnectCommand: .jamfConnectDefault)
        let requestCalled = LockedFlag()
        let launched = LockedFlag()
        let vm = model(info: jcInfo,
                       request: { _ in await requestCalled.set(); return nil },
                       runJamfConnect: { _ in await launched.set(); return true })
        await vm.refresh(activeExpiry: nil)
        #expect(vm.canSubmit)  // no justification required in JC mode
        await vm.submit()
        #expect(await launched.value)
        #expect(!(await requestCalled.value))  // daemon request path untouched
        #expect(vm.phase == .message("Admin elevation started in Jamf Connect."))
    }

    @Test("Jamf Connect missing or unsigned: the item is disabled with the reason and nothing runs",
          arguments: [JamfConnectAvailability.notInstalled, .failedSignatureCheck])
    func jamfConnectUnavailable(_ availability: JamfConnectAvailability) async {
        let jcInfo = JITAdminInfo(available: true, provider: .jamfConnect, requireJustification: false,
                                  justificationMinLength: 0, maxDurationSeconds: 900,
                                  jamfConnectCommand: .jamfConnectDefault)
        let launched = LockedFlag()
        let vm = model(info: jcInfo,
                       runJamfConnect: { _ in await launched.set(); return true },
                       checkJamfConnect: { _ in availability })
        await vm.refresh(activeExpiry: nil)
        #expect(!vm.canSubmit)
        #expect(vm.unavailableReason == availability.unavailableReason)
        await vm.submit()
        #expect(!(await launched.value))
    }

    @Test("the unavailable reasons read as the owner specified")
    func unavailableReasons() {
        #expect(JamfConnectAvailability.notInstalled.unavailableReason == "Jamf Connect isn't installed.")
        #expect(JamfConnectAvailability.failedSignatureCheck.unavailableReason
                == "Jamf Connect failed its signature check.")
        #expect(JamfConnectAvailability.ready.unavailableReason == nil)
    }
}

@Suite("JamfConnectVerifier")
struct JamfConnectVerifierTests {
    private func tempFile() throws -> String {
        let path = NSTemporaryDirectory() + "jc-verify-\(UUID().uuidString)"
        try Data("#!/bin/sh\n".utf8).write(to: URL(fileURLWithPath: path))
        return path
    }

    @Test("a missing binary, a directory, or a relative path is 'not installed'")
    func notInstalled() {
        let verifier = JamfConnectVerifier(signatureCheck: { _ in true })
        #expect(verifier.availability(of: JamfConnectCommand(path: "/nonexistent/jamfconnect")) == .notInstalled)
        #expect(verifier.availability(of: JamfConnectCommand(path: NSTemporaryDirectory())) == .notInstalled)
        #expect(verifier.availability(of: JamfConnectCommand(path: "jamfconnect")) == .notInstalled)
    }

    @Test("a regular file is ready only when it passes the signature check")
    func signature() throws {
        let path = try tempFile()
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(JamfConnectVerifier(signatureCheck: { _ in true }).availability(of: JamfConnectCommand(path: path)) == .ready)
        #expect(JamfConnectVerifier(signatureCheck: { _ in false }).availability(of: JamfConnectCommand(path: path))
                == .failedSignatureCheck)
        // The real check refuses an unsigned file.
        #expect(JamfConnectVerifier().availability(of: JamfConnectCommand(path: path)) == .failedSignatureCheck)
    }

    @Test("a symlink is checked at its target")
    func symlinkTarget() throws {
        let target = try tempFile()
        let link = target + "-link"
        defer {
            try? FileManager.default.removeItem(atPath: target)
            try? FileManager.default.removeItem(atPath: link)
        }
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        let checked = CheckedPaths()
        let verifier = JamfConnectVerifier(signatureCheck: { checked.record($0); return true })
        #expect(verifier.availability(of: JamfConnectCommand(path: link)) == .ready)
        #expect(checked.paths == [(target as NSString).resolvingSymlinksInPath])
        // The path to run is the checked target, not the link.
        #expect(verifier.verifiedExecutable(of: JamfConnectCommand(path: link))
                == (target as NSString).resolvingSymlinksInPath)
        #expect(JamfConnectVerifier(signatureCheck: { _ in false })
            .verifiedExecutable(of: JamfConnectCommand(path: link)) == nil)
    }

    @Test("the requirement pins Jamf's team on an Apple-issued certificate")
    func requirementText() {
        #expect(JamfConnectVerifier.requirement
                == "anchor apple generic and certificate leaf[subject.OU] = \"483DWKW443\"")
    }

    @Test("the launcher refuses a command that does not verify")
    func launcherRefuses() async {
        let launcher = JamfConnectLauncher(verifier: JamfConnectVerifier(signatureCheck: { _ in false }))
        #expect(!(await launcher.run(JamfConnectCommand(path: "/bin/echo", arguments: ["x"]))))
        #expect(!(await JamfConnectLauncher().run(JamfConnectCommand(path: "echo"))))
    }
}

private final class CheckedPaths: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String] = []
    func record(_ path: String) { lock.lock(); stored.append(path); lock.unlock() }
    var paths: [String] { lock.lock(); defer { lock.unlock() }; return stored }
}

/// Tiny async-safe flag for asserting which action closure ran.
private actor LockedFlag {
    private(set) var value = false
    func set() { value = true }
}
