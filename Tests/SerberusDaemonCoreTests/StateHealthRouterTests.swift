import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

@Suite("DaemonStateController", .serialized)
struct DaemonStateControllerTests {
    private func tempStateURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-daemon-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("state.plist")
    }

    @Test("transition writes state.plist with the expected keys")
    func writesStateFile() async throws {
        let url = tempStateURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let controller = DaemonStateController(
            statePlist: url, integrityLogger: nil, daemonVersion: "1.2.3",
            now: { CoordinatorFixtures.now }
        )
        await controller.transition(to: .healthy, enforcementMode: .audit)

        let data = try Data(contentsOf: url)
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["state"] as? String == "healthy")
        #expect(plist["enforcementMode"] as? String == "audit")
        #expect(plist["daemonVersion"] as? String == "1.2.3")
        #expect(plist["degradedReason"] == nil)
    }

    @Test("degraded transition records the reason; clearing it removes the key")
    func degradedReason() async throws {
        let url = tempStateURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let controller = DaemonStateController(statePlist: url, integrityLogger: nil, now: { CoordinatorFixtures.now })

        await controller.transition(to: .degraded, reason: .authDBFailure)
        var plist = try PropertyListSerialization.propertyList(
            from: try Data(contentsOf: url), format: nil) as? [String: Any]
        #expect(plist?["degradedReason"] as? String == "authdb_failure")
        #expect(await controller.current().reason == .authDBFailure)

        await controller.transition(to: .healthy)
        plist = try PropertyListSerialization.propertyList(
            from: try Data(contentsOf: url), format: nil) as? [String: Any]
        #expect(plist?["degradedReason"] == nil)
        #expect(await controller.current().reason == nil)
    }

    @Test("transitions emit integrity events")
    func emitsIntegrity() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-int-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let logger = try IntegrityLogger(directory: directory)
        let controller = DaemonStateController(
            statePlist: directory.appendingPathComponent("state.plist"),
            integrityLogger: logger, now: { CoordinatorFixtures.now }
        )
        await controller.transition(to: .healthy)

        let logFile = try #require(
            try FileManager.default.contentsOfDirectory(atPath: directory.path)
                .first { $0.hasPrefix("integrity-") && $0.hasSuffix(".jsonl") }
        )
        let content = try String(contentsOf: directory.appendingPathComponent(logFile), encoding: .utf8)
        #expect(content.contains("state_transition"))
        #expect(content.contains("healthy"))
    }
}

// MARK: - Health monitor

struct StubHealthChecks: DaemonHealthChecks {
    var xpc = true, engine = true, grants = true, authDB = true, esf = true
    func xpcListenerIsActive() async -> Bool { xpc }
    func ruleEngineIsResponsive() async -> Bool { engine }
    func grantDatabaseIsResponsive() async -> Bool { grants }
    func authDBManagerIsHealthy() async -> Bool { authDB }
    func esfSubscriptionIsActive() async -> Bool { esf }
}

actor FailureRecorder {
    private(set) var failures: [[String]] = []
    func record(_ f: [String]) { failures.append(f) }
}

@Suite("HealthMonitor")
struct HealthMonitorTests {
    @Test("all checks passing reports no failures")
    func healthy() async {
        let monitor = HealthMonitor(checks: StubHealthChecks()) { _ in }
        #expect(await monitor.evaluate().isEmpty)
    }

    @Test("each failing check is named")
    func eachCheck() async {
        let cases: [(StubHealthChecks, String)] = [
            (StubHealthChecks(xpc: false), "XPC listener not active"),
            (StubHealthChecks(engine: false), "Rule engine unresponsive"),
            (StubHealthChecks(grants: false), "Grant database unresponsive"),
            (StubHealthChecks(authDB: false), "AuthorizationDB manager unhealthy"),
            (StubHealthChecks(esf: false), "ESF subscription dropped"),
        ]
        for (checks, expected) in cases {
            let monitor = HealthMonitor(checks: checks) { _ in }
            #expect(await monitor.evaluate() == [expected])
        }
    }

    @Test("runOnce invokes the unhealthy reaction with the failures")
    func reaction() async {
        let recorder = FailureRecorder()
        let monitor = HealthMonitor(checks: StubHealthChecks(grants: false, esf: false)) { failures in
            await recorder.record(failures)
        }
        await monitor.runOnce()
        let recorded = await recorder.failures
        #expect(recorded.count == 1)
        #expect(recorded.first?.count == 2)
    }

    @Test("runOnce stays silent when healthy")
    func silentWhenHealthy() async {
        let recorder = FailureRecorder()
        let monitor = HealthMonitor(checks: StubHealthChecks()) { failures in
            await recorder.record(failures)
        }
        await monitor.runOnce()
        #expect(await recorder.failures.isEmpty)
    }
}

// MARK: - Message router

actor MockDaemon: DaemonQuerying {
    var pamResponse: PAMResponse = .deny
    var state: DaemonState = .healthy
    var grants: [Grant] = []
    private(set) var lastPAMRequest: PAMRequest?

    func handlePAM(_ request: PAMRequest) async -> PAMResponse {
        lastPAMRequest = request
        return pamResponse
    }
    func currentDaemonState() async -> DaemonState { state }
    func activeGrants(forUser user: String?) async -> [Grant] {
        guard let user else { return grants }
        return grants.filter { $0.user == user }
    }
    var rulesSnapshot = SentinelRulesSnapshot.empty(mode: .enforce, at: CoordinatorFixtures.now)
    func setRulesSnapshot(_ snapshot: SentinelRulesSnapshot) { rulesSnapshot = snapshot }
    func userRules() async -> SentinelRulesSnapshot { rulesSnapshot }
    var jitInfo = JITAdminInfo.unavailable
    var jitResult = JITAdminResult(outcome: .denied, message: "test")
    private(set) var lastJITUser: String?
    private(set) var lastJITJustification: String?
    private(set) var endedJITUser: String?
    func jitAdminInfo() async -> JITAdminInfo { jitInfo }
    func requestAdminElevation(user: String, justification: String) async -> JITAdminResult {
        lastJITUser = user; lastJITJustification = justification; return jitResult
    }
    func endAdminElevation(user: String) async -> Bool { endedJITUser = user; return true }

    /// Records what the capture route passed through, so the router tests can
    /// assert the caller uid is the daemon's, not the message's.
    var captureOutcome: IntelCollectionOutcome = .collected(
        IntelHandoff(directory: "/tmp/capture", files: ["unified-log.ndjson"], unavailable: [:])
    )
    private(set) var lastIntelRequest: IntelRequest?
    private(set) var lastCaptureUID: uid_t?

    func setCaptureOutcome(_ outcome: IntelCollectionOutcome) { captureOutcome = outcome }

    var authorizationOutcome: AuthorizationPollOutcome = .collected(AuthorizationPollResult(ndjson: ""))
    private(set) var lastPollUID: uid_t?
    func setAuthorizationOutcome(_ outcome: AuthorizationPollOutcome) { authorizationOutcome = outcome }

    func pollAuthorizations(
        request: AuthorizationPollRequest,
        callerUID: uid_t
    ) async -> AuthorizationPollOutcome {
        lastPollUID = callerUID
        return authorizationOutcome
    }

    var sudoOutcome: SudoPollOutcome = .collected(SudoPollResult(ndjson: ""))
    private(set) var lastSudoPollUID: uid_t?
    private(set) var lastSudoPollRequest: SudoPollRequest?
    func setSudoOutcome(_ outcome: SudoPollOutcome) { sudoOutcome = outcome }

    func pollSudoAttempts(
        request: SudoPollRequest,
        callerUID: uid_t
    ) async -> SudoPollOutcome {
        lastSudoPollUID = callerUID
        lastSudoPollRequest = request
        return sudoOutcome
    }

    func collectPrivilegedDiagnostics(
        request: IntelRequest,
        callerUID: uid_t
    ) async -> IntelCollectionOutcome {
        lastIntelRequest = request
        lastCaptureUID = callerUID
        return captureOutcome
    }

    var lastInstallRequest: InstallRequest?
    var lastInstallUID: uid_t?
    var installResult = InstallResult(status: .installed, message: "ok")
    func installSoftware(request: InstallRequest, callerUID: uid_t, callerUser: String?) async -> InstallResult {
        lastInstallRequest = request
        lastInstallUID = callerUID
        return installResult
    }

    var lastUninstallRequest: UninstallRequest?
    var lastUninstallUID: uid_t?
    var uninstallResult = InstallResult(status: .removed, message: "ok")
    func uninstallSoftware(request: UninstallRequest, callerUID: uid_t, callerUser: String?) async -> InstallResult {
        lastUninstallRequest = request
        lastUninstallUID = callerUID
        return uninstallResult
    }
}

@Suite("XPCMessageRouter")
struct XPCMessageRouterTests {
    @Test("PAM requests reach the daemon")
    func pam() async {
        let daemon = MockDaemon()
        await daemon.setPAMResponse(.init(decision: .allow, cacheSeconds: 300, grantID: nil, ruleID: "r"))
        let router = XPCMessageRouter(daemon: daemon)
        let reply = await router.routePAM(PAMRequest(user: "alice", kind: .sudo(command: "/bin/x", argv: [], tty: nil)))
        guard case let .pam(response) = reply else { Issue.record("expected pam reply"); return }
        #expect(response.isAllow)
        #expect(await daemon.lastPAMRequest?.user == "alice")
    }

    @Test("the retired commander interface does not exist: no revoke or policy-read route")
    func commanderInterfaceIsGone() async {
        let router = XPCMessageRouter(daemon: MockDaemon())
        for method in ["daemonHealth", "activeGrants", "effectivePolicy", "revokeGrant", "revokeAll"] {
            let reply = await router.routeTyped(
                validatedInterface: .sentinel, interface: "commander",
                method: method, payload: nil, callerUser: "alice"
            )
            guard case let .failure(message) = reply else { Issue.record("expected failure for \(method)"); return }
            #expect(message.contains("unknown interface"))
        }
    }

    @Test("interface mismatch is rejected — a PAM-validated peer cannot call sentinel methods")
    func interfaceMismatch() async {
        let router = XPCMessageRouter(daemon: MockDaemon())
        let reply = await router.routeTyped(
            validatedInterface: .pam, interface: "sentinel",
            method: "daemonState", payload: nil, callerUser: "alice"
        )
        guard case let .failure(message) = reply else { Issue.record("expected failure"); return }
        #expect(message.contains("interface mismatch"))
    }

    @Test("the Sentinel may reach the read-only Intel interface (it absorbed the Intel UI)")
    func sentinelMayUseIntel() async {
        let daemon = MockDaemon()
        let router = XPCMessageRouter(daemon: daemon)
        let payload = try? SerberusXPCCoding.encode(AuthorizationPollRequest(window: "30s"))
        let reply = await router.routeTyped(
            validatedInterface: .sentinel, interface: "intel",
            method: "pollAuthorizations", payload: payload, callerUser: "alice", callerUID: 501
        )
        // Routed to the intel handler (not rejected as a mismatch).
        guard case .payload = reply else { Issue.record("expected the intel poll to route"); return }
        #expect(await daemon.lastPollUID == 501)
    }

    @Test("installSoftware routes the InstallRequest with the kernel-stamped uid; a missing uid is refused")
    func installRoutes() async {
        let daemon = MockDaemon()
        let router = XPCMessageRouter(daemon: daemon)
        let payload = try? SerberusXPCCoding.encode(InstallRequest(sourcePath: "/Volumes/DMG/Foo.app", displayName: "Foo.app"))
        let reply = await router.routeTyped(
            validatedInterface: .sentinel, interface: "sentinel",
            method: "installSoftware", payload: payload, callerUser: "alice", callerUID: 501
        )
        guard case .payload = reply else { Issue.record("expected installSoftware to route"); return }
        #expect(await daemon.lastInstallUID == 501)
        #expect(await daemon.lastInstallRequest?.sourcePath == "/Volumes/DMG/Foo.app")

        // Without a kernel uid the router refuses (never message-supplied).
        let noUID = await router.routeTyped(
            validatedInterface: .sentinel, interface: "sentinel",
            method: "installSoftware", payload: payload, callerUser: "alice", callerUID: nil
        )
        guard case let .failure(message) = noUID else { Issue.record("expected failure without uid"); return }
        #expect(message.contains("uid"))
    }

    @Test("uninstallSoftware routes the UninstallRequest with the kernel-stamped uid")
    func uninstallRoutes() async {
        let daemon = MockDaemon()
        let router = XPCMessageRouter(daemon: daemon)
        let payload = try? SerberusXPCCoding.encode(UninstallRequest(appPath: "/Applications/Foo.app", displayName: "Foo.app"))
        let reply = await router.routeTyped(
            validatedInterface: .sentinel, interface: "sentinel",
            method: "uninstallSoftware", payload: payload, callerUser: "alice", callerUID: 501
        )
        guard case .payload = reply else { Issue.record("expected uninstallSoftware to route"); return }
        #expect(await daemon.lastUninstallUID == 501)
        #expect(await daemon.lastUninstallRequest?.appPath == "/Applications/Foo.app")
    }

    @Test("the allowance is one-way — Intel can never reach Sentinel methods")
    func intelCannotUseOtherInterfaces() async {
        let router = XPCMessageRouter(daemon: MockDaemon())
        let reply = await router.routeTyped(
            validatedInterface: .intel, interface: "sentinel",
            method: "daemonState", payload: nil, callerUser: "alice", callerUID: 501
        )
        guard case let .failure(message) = reply else { Issue.record("expected failure"); return }
        #expect(message.contains("interface mismatch"))
    }

    @Test("sentinel activeGrants is scoped to the caller's user")
    func sentinelScoped() async {
        let daemon = MockDaemon()
        await daemon.setGrants([TestGrants.make(user: "alice"), TestGrants.make(user: "bob")])
        let router = XPCMessageRouter(daemon: daemon)
        let reply = await router.routeTyped(
            validatedInterface: .sentinel, interface: "sentinel",
            method: "activeGrants", payload: nil, callerUser: "alice"
        )
        guard case let .payload(data) = reply else { Issue.record("expected payload"); return }
        let grants = try? SerberusXPCCoding.decode([Grant].self, from: data)
        #expect(grants?.count == 1)
        #expect(grants?.first?.user == "alice")
    }

    @Test("sentinel userRules returns the daemon's rules snapshot")
    func sentinelUserRules() async {
        let daemon = MockDaemon()
        let snapshot = SentinelRulesSnapshot(
            rules: [SentinelRuleSummary(
                ruleID: "net", profileKey: "rules_authuri_standard",
                title: "Change network settings", detail: "system.preferences.network",
                type: .authuri, decision: .prompt
            )],
            profileKeys: ["rules_authuri_standard"],
            policyVersion: "1.2.0",
            enforcementMode: .enforce,
            generatedAt: CoordinatorFixtures.now
        )
        await daemon.setRulesSnapshot(snapshot)
        let router = XPCMessageRouter(daemon: daemon)
        let reply = await router.routeTyped(
            validatedInterface: .sentinel, interface: "sentinel",
            method: "userRules", payload: nil, callerUser: "alice"
        )
        guard case let .payload(data) = reply else { Issue.record("expected payload"); return }
        let decoded = try? SerberusXPCCoding.decode(SentinelRulesSnapshot.self, from: data)
        #expect(decoded == snapshot)
    }

    @Test("unknown methods are rejected")
    func unknownMethod() async {
        let router = XPCMessageRouter(daemon: MockDaemon())
        let reply = await router.routeTyped(
            validatedInterface: .sentinel, interface: "sentinel",
            method: "dropDatabase", payload: nil, callerUser: nil
        )
        guard case .failure = reply else { Issue.record("expected failure"); return }
    }
}

extension MockDaemon {
    func setPAMResponse(_ response: PAMResponse) { pamResponse = response }
    func setGrants(_ value: [Grant]) { grants = value }
}

// MARK: - Grant DB liveness probe

/// A grant store whose reads never return — used to simulate a wedged
/// (deadlocked) actor, the only condition the liveness probe must flag.
struct WedgedGrantStore: GrantMaintaining {
    func insert(_ grant: Grant) async throws {}
    func cleanupExpired(now: Date) async throws -> Int { 0 }
    func activeGrants(now: Date) async throws -> [Grant] {
        try await Task.sleep(for: .seconds(3600))
        return []
    }
    func activeGrants(for user: String, now: Date) async throws -> [Grant] { [] }
    func revokeAll(now: Date) async throws -> Int { 0 }
    func revoke(grantID: UUID, now: Date) async throws -> Int { 0 }
}

@Suite("DaemonHealthProbe.grantDatabaseIsResponsive")
struct GrantDBLivenessProbeTests {
    private func probe(store: GrantMaintaining) -> DaemonHealthProbe {
        DaemonHealthProbe(
            listener: XPCListenerService(machServiceName: "test.serberus.probe",
                                         router: XPCMessageRouter(daemon: MockDaemon())),
            grantStore: store,
            probeTimeout: .milliseconds(100),
            now: { CoordinatorFixtures.now }
        )
    }

    @Test("a throwing store (degraded NullGrantStore) reads as responsive, not a restart trigger")
    func throwingStoreIsResponsive() async {
        // Regression: the probe is liveness, not correctness. A store that answers
        // by throwing proves its actor isn't wedged — restarting cannot fix a
        // degraded(grants_db_error) daemon and previously looped forever.
        #expect(await probe(store: NullGrantStore()).grantDatabaseIsResponsive())
    }

    @Test("a wedged store (never returns) reads as unresponsive")
    func wedgedStoreIsUnresponsive() async {
        #expect(await probe(store: WedgedGrantStore()).grantDatabaseIsResponsive() == false)
    }
}
