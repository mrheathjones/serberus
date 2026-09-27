import Foundation
import PrivMgrCore
import Testing
@testable import SerberusDaemonCore

/// The Intel XPC route is a NEW privileged surface on a security daemon: it
/// runs `log` as root on behalf of an unprivileged caller. These tests pin the
/// properties that keep that safe.
@Suite("Intel XPC route")
struct IntelRouteTests {
    private func router(_ daemon: MockDaemon) -> XPCMessageRouter {
        XPCMessageRouter(daemon: daemon)
    }

    private func payload(_ request: IntelRequest) throws -> Data {
        try SerberusXPCCoding.encode(request)
    }

    @Test("a validated intel caller can collect")
    func collects() async throws {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.collectPrivilegedDiagnostics.rawValue,
            payload: try payload(IntelRequest(window: "1h", includeInfoAndDebug: false)),
            callerUser: "alice",
            callerUID: 501
        )
        guard case let .payload(data) = reply else {
            Issue.record("expected a payload reply, got \(reply)")
            return
        }
        let handoff = try SerberusXPCCoding.decode(IntelHandoff.self, from: data)
        #expect(handoff.files == ["unified-log.ndjson"])
        #expect(await daemon.lastIntelRequest?.window == "1h")
    }

    @Test("the caller uid comes from the audit token, never the message")
    func usesValidatedUID() async throws {
        let daemon = MockDaemon()
        _ = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.collectPrivilegedDiagnostics.rawValue,
            payload: try payload(IntelRequest(window: "1h", includeInfoAndDebug: false)),
            callerUser: "alice",
            callerUID: 502
        )
        // The hand-off is chowned to this uid. If it came from the message body
        // a caller could hand another user's logs to themselves.
        #expect(await daemon.lastCaptureUID == 502)
    }

    @Test("without a validated uid the request is refused, not defaulted")
    func refusesMissingUID() async throws {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.collectPrivilegedDiagnostics.rawValue,
            payload: try payload(IntelRequest(window: "1h", includeInfoAndDebug: false)),
            callerUser: "alice",
            callerUID: nil
        )
        // Defaulting to 0 would chown a directory of every user's logs to root
        // and hand back a path the caller cannot read — refuse instead.
        guard case .failure = reply else {
            Issue.record("expected failure, got \(reply)")
            return
        }
        #expect(await daemon.lastCaptureUID == nil)
    }

    @Test("the retired commander interface is refused outright")
    func retiredCommanderInterfaceIsRefused() async throws {
        let daemon = MockDaemon()
        // There is no grant-revoking interface any more: a peer claiming the old
        // commander interface name gets an unknown-interface failure.
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "commander",
            method: "revokeAll",
            payload: nil,
            callerUser: "alice",
            callerUID: 501
        )
        guard case let .failure(message) = reply else {
            Issue.record("expected failure, got \(reply)")
            return
        }
        #expect(message.contains("unknown interface"))
    }

    @Test("a PAM-validated peer cannot invoke the intel method")
    func pamCannotUseIntelInterface() async throws {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .pam,
            interface: "intel",
            method: IntelXPCMethod.collectPrivilegedDiagnostics.rawValue,
            payload: try payload(IntelRequest(window: "1h", includeInfoAndDebug: false)),
            callerUser: "root",
            callerUID: 0
        )
        guard case .failure = reply else {
            Issue.record("expected interface-mismatch failure, got \(reply)")
            return
        }
    }

    @Test("an unknown intel method is refused")
    func unknownMethod() async {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: "rmRF",
            payload: nil,
            callerUser: "alice",
            callerUID: 501
        )
        guard case let .failure(message) = reply else {
            Issue.record("expected failure, got \(reply)")
            return
        }
        #expect(message.contains("unknown intel method"))
    }

    @Test("a validated caller can poll authorizations, and the uid is the audit-token uid")
    func pollsAuthorizations() async throws {
        let daemon = MockDaemon()
        await daemon.setAuthorizationOutcome(.collected(AuthorizationPollResult(ndjson: #"{"eventMessage":"x"}"#)))
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.pollAuthorizations.rawValue,
            payload: try SerberusXPCCoding.encode(AuthorizationPollRequest(window: "10s")),
            callerUser: "alice",
            callerUID: 501
        )
        guard case let .payload(data) = reply else {
            Issue.record("expected payload, got \(reply)"); return
        }
        let result = try SerberusXPCCoding.decode(AuthorizationPollResult.self, from: data)
        #expect(result.ndjson.contains("eventMessage"))
        #expect(await daemon.lastPollUID == 501)
    }

    @Test("polling without a validated uid is refused")
    func pollRefusesMissingUID() async throws {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.pollAuthorizations.rawValue,
            payload: try SerberusXPCCoding.encode(AuthorizationPollRequest(window: "10s")),
            callerUser: "alice",
            callerUID: nil
        )
        guard case .failure = reply else { Issue.record("expected failure, got \(reply)"); return }
    }

    // MARK: pollSudoAttempts (Capture / Rule Recorder sudo source)

    @Test("a validated caller can poll sudo attempts, and the uid is the audit-token uid")
    func pollsSudoAttempts() async throws {
        let daemon = MockDaemon()
        await daemon.setSudoOutcome(.collected(SudoPollResult(
            ndjson: #"{"eventMessage":"tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true"}"#
        )))
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.pollSudoAttempts.rawValue,
            payload: try SerberusXPCCoding.encode(SudoPollRequest(window: "10s")),
            callerUser: "alice",
            callerUID: 501
        )
        guard case let .payload(data) = reply else {
            Issue.record("expected payload, got \(reply)"); return
        }
        let result = try SerberusXPCCoding.decode(SudoPollResult.self, from: data)
        #expect(result.ndjson.contains("COMMAND="))
        #expect(await daemon.lastSudoPollUID == 501)
        #expect(await daemon.lastSudoPollRequest?.window == "10s")
    }

    @Test("the Sentinel may poll sudo attempts through the one-way intel allowance")
    func sentinelPollsSudo() async throws {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .sentinel,
            interface: "intel",
            method: IntelXPCMethod.pollSudoAttempts.rawValue,
            payload: try SerberusXPCCoding.encode(SudoPollRequest(window: "10s")),
            callerUser: "alice",
            callerUID: 501
        )
        guard case .payload = reply else { Issue.record("expected the sudo poll to route, got \(reply)"); return }
        #expect(await daemon.lastSudoPollUID == 501)
    }

    @Test("sudo polling without a validated uid is refused")
    func sudoPollRefusesMissingUID() async throws {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.pollSudoAttempts.rawValue,
            payload: try SerberusXPCCoding.encode(SudoPollRequest(window: "10s")),
            callerUser: "alice",
            callerUID: nil
        )
        guard case .failure = reply else { Issue.record("expected failure, got \(reply)"); return }
        #expect(await daemon.lastSudoPollUID == nil)
    }

    @Test("sudo polling with a missing or wrong-typed payload is refused")
    func sudoPollRefusesBadPayload() async throws {
        let daemon = MockDaemon()
        let missing = await router(daemon).routeTyped(
            validatedInterface: .intel, interface: "intel",
            method: IntelXPCMethod.pollSudoAttempts.rawValue,
            payload: nil, callerUser: "alice", callerUID: 501
        )
        guard case .failure = missing else { Issue.record("expected failure for missing payload, got \(missing)"); return }
        // A payload that is not JSON at all must be refused. (Any JSON object
        // carrying a `window` key decodes — JSONDecoder ignores extra keys —
        // so a bad WINDOW is rejected by the collector's allowlist, not here.)
        let notJSON = await router(daemon).routeTyped(
            validatedInterface: .intel, interface: "intel",
            method: IntelXPCMethod.pollSudoAttempts.rawValue,
            payload: Data("not json".utf8), callerUser: "alice", callerUID: 501
        )
        guard case .failure = notJSON else { Issue.record("expected failure for bad payload, got \(notJSON)"); return }
        #expect(await daemon.lastSudoPollUID == nil)
    }

    @Test("a PAM-validated peer cannot reach the intel interface at all")
    func pamCannotPollSudo() async throws {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .pam,
            interface: "intel",
            method: IntelXPCMethod.pollSudoAttempts.rawValue,
            payload: try SerberusXPCCoding.encode(SudoPollRequest(window: "10s")),
            callerUser: nil,
            callerUID: 501
        )
        guard case let .failure(message) = reply else { Issue.record("expected failure, got \(reply)"); return }
        #expect(message.contains("interface mismatch"))
        #expect(await daemon.lastSudoPollUID == nil)
    }

    @Test("a missing payload is refused")
    func missingPayload() async {
        let daemon = MockDaemon()
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.collectPrivilegedDiagnostics.rawValue,
            payload: nil,
            callerUser: "alice",
            callerUID: 501
        )
        guard case .failure = reply else {
            Issue.record("expected failure, got \(reply)")
            return
        }
    }

    @Test("a daemon-side failure surfaces as an error, not a silent empty success")
    func failureSurfaces() async throws {
        let daemon = MockDaemon()
        await daemon.setCaptureOutcome(.failed("unsupported capture window 'rm -rf'"))
        let reply = await router(daemon).routeTyped(
            validatedInterface: .intel,
            interface: "intel",
            method: IntelXPCMethod.collectPrivilegedDiagnostics.rawValue,
            payload: try payload(IntelRequest(window: "rm -rf", includeInfoAndDebug: false)),
            callerUser: "alice",
            callerUID: 501
        )
        guard case let .failure(message) = reply else {
            Issue.record("expected failure, got \(reply)")
            return
        }
        #expect(message.contains("unsupported capture window"))
    }
}

@Suite("PrivilegedLogCollector")
struct PrivilegedLogCollectorTests {
    private var collector: PrivilegedLogCollector {
        PrivilegedLogCollector(paths: .production)
    }

    @Test("the predicate is a constant covering daemon, PAM and Sentinel")
    func predicateIsConstant() {
        // Never caller-supplied: a caller-chosen predicate would let any local
        // user read the ENTIRE system log through a root daemon.
        #expect(PrivilegedLogCollector.predicate.contains(#"subsystem == "com.herojoneslabs.serberus""#))
        // BEGINSWITH catches the Sentinel's `…serberus.sentinel`.
        #expect(PrivilegedLogCollector.predicate.contains(#"BEGINSWITH "com.herojoneslabs.serberus.""#))
    }

    @Test("the authorization predicate is a constant scoped to authd")
    func authorizationPredicateIsConstant() {
        // authURI events = macOS authorization-right attempts, which authd logs
        // to this subsystem. Also a daemon-side constant — the same
        // whole-system-log-oracle risk applies.
        #expect(PrivilegedLogCollector.authorizationPredicate == #"subsystem == "com.apple.Authorization""#)
        // Scoped to authd only, not a catch-all.
        #expect(!PrivilegedLogCollector.authorizationPredicate.contains("BEGINSWITH"))
    }

    @Test("the sudo predicate is a constant pinned on sudo's IMAGE PATH, not its name")
    func sudoPredicateIsConstant() {
        // sudo's own lines have an EMPTY subsystem/category (checked against real log output), so
        // the pin is on the executable. Image path, not `process == "sudo"`: a
        // process NAME is spoofable (cp /usr/bin/logger /tmp/sudo), and a fake
        // line would otherwise become an attempt an admin authors a rule from.
        #expect(PrivilegedLogCollector.sudoPredicate == #"processImagePath == "/usr/bin/sudo""#)
        #expect(!PrivilegedLogCollector.sudoPredicate.contains(#"process == "#))
        #expect(!PrivilegedLogCollector.sudoPredicate.contains("BEGINSWITH"))
    }

    @Test("sudo poll output is scoped to the caller's own lines; other users and noise never cross XPC")
    func sudoScoping() {
        let lines = [
            #"{"eventMessage":"   tuser : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true"}"#,
            #"{"eventMessage":"   alice : TTY=ttys002 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id"}"#,
            #"{"eventMessage":"Retrieve Group by ID"}"#,
            "Filtering the log data using \"processImagePath == ...\"",
            // A prefix-lookalike user must not leak through.
            #"{"eventMessage":"tuserx : TTY=ttys003 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"}"#,
            "not json at all",
        ].joined(separator: "\n")
        let scoped = PrivilegedLogCollector.scopeSudoLines(lines, toUser: "tuser")
        #expect(scoped.contains("/usr/bin/true"))
        #expect(!scoped.contains("alice"))
        #expect(!scoped.contains("Retrieve Group"))
        #expect(!scoped.contains("tuserx"))
        #expect(!scoped.contains("Filtering"))
        #expect(!scoped.contains("not json"))
        #expect(scoped.hasSuffix("\n"))
        #expect(PrivilegedLogCollector.scopeSudoLines("", toUser: "tuser").isEmpty)
        #expect(PrivilegedLogCollector.scopeSudoLines(lines, toUser: "nobody-here").isEmpty)
    }

    @Test("a live poll is bounded and the in-flight count is capped")
    func pollBounds() {
        #expect(PrivilegedLogCollector.pollTimeout <= 30)
        #expect(DaemonController.maxInFlightLogPolls >= 1)
        #expect(DaemonController.maxInFlightLogPolls <= 4)
    }

    @Test("the sudo poll window allowlist is the same short-only set as authorizations")
    func sudoPollWindowsAreShort() {
        #expect(SudoPollRequest.allowedWindows == AuthorizationPollRequest.allowedWindows)
        #expect(SudoPollRequest.allowedWindows.contains("10s"))
        #expect(!SudoPollRequest.allowedWindows.contains("7d"))
        #expect(!SudoPollRequest.allowedWindows.contains("--predicate"))
    }

    @Test("a sudo poll rejects a window outside the allowlist and a root caller")
    func sudoPollGuards() {
        #expect(throws: PrivilegedLogCollector.CollectorError.invalidWindow("1d")) {
            try collector.pollSudoAttempts(request: SudoPollRequest(window: "1d"), callerUID: 501)
        }
        #expect(throws: PrivilegedLogCollector.CollectorError.invalidCaller) {
            try collector.pollSudoAttempts(request: SudoPollRequest(window: "10s"), callerUID: 0)
        }
    }

    @Test("the live-poll window allowlist is short only")
    func pollWindowsAreShort() {
        // A live poll every ~2s has no business pulling a 7-day window; the
        // allowlist is disjoint from the export windows on purpose.
        #expect(AuthorizationPollRequest.allowedWindows.contains("10s"))
        #expect(!AuthorizationPollRequest.allowedWindows.contains("7d"))
        #expect(!AuthorizationPollRequest.allowedWindows.contains("--predicate"))
    }

    @Test("the window is allowlisted, so argv can't be poisoned")
    func windowAllowlist() {
        #expect(IntelRequest.allowedWindows.contains("1h"))
        #expect(IntelRequest.allowedWindows.contains("7d"))
        #expect(!IntelRequest.allowedWindows.contains("--predicate"))
        #expect(!IntelRequest.allowedWindows.contains(""))
    }

    @Test("a window outside the allowlist is rejected, not defaulted")
    func rejectsBadWindow() {
        // It becomes an argv element for a root-run tool. Rejecting beats
        // silently substituting a different window and lying in the manifest.
        #expect(throws: PrivilegedLogCollector.CollectorError.invalidWindow("--info")) {
            try collector.collect(
                request: IntelRequest(window: "--info", includeInfoAndDebug: false),
                callerUID: 501
            )
        }
    }

    @Test("root is not a valid intel caller")
    func rejectsRootCaller() {
        #expect(throws: PrivilegedLogCollector.CollectorError.invalidCaller) {
            try collector.collect(
                request: IntelRequest(window: "1h", includeInfoAndDebug: false),
                callerUID: 0
            )
        }
    }

    @Test("the hand-off parent is under the daemon's own log directory")
    func handoffPathIsInternal() {
        // Derived internally, never from the caller.
        #expect(BundleConfig.captureHandoffDirectory.hasPrefix(BundleConfig.logDirectory))
    }

    @Test("log is invoked by absolute path")
    func absoluteLogPath() {
        #expect(PrivilegedLogCollector.logToolPath == "/usr/bin/log")
    }
}
