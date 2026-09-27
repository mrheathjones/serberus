import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// Daemon sudo-path gaps (package daemon-sudo-gaps): SessionGrantCache wiring
/// through `handlePAM`, audit-mode prompt softening, the justification audit
/// trail, the prompts-domain justification minimum, and fail-closed grant
/// persistence — all through the real daemon path.
@Suite("Daemon sudo path — session cache, audit softening, justification", .serialized)
struct SudoCacheAuditJustificationTests {
    private let echoHash = "bb" + String(repeating: "0", count: 62)

    // MARK: Fixtures

    private func config(
        mode: EnforcementMode = .enforce,
        sudoCache: Int = 0,
        promptTimeout: Int = 60
    ) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true, enforcementMode: mode, sudoCacheSeconds: sudoCache,
            promptTimeoutSeconds: promptTimeout, pamBypass: PAMBypass(),
            // These tests exercise the time-bound (expiring) grant path.
            timeBoundGrantsEnabled: true
        )
    }

    private func allowEchoProfile(ruleCacheSeconds: Int? = nil) -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "allow-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                cacheSeconds: ruleCacheSeconds,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact)
            )]
        )
    }

    private func promptEchoProfile(
        ruleCacheSeconds: Int? = nil,
        grantDuration: Int = 0,
        requireJustification: Bool = false
    ) -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "prompt-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                cacheSeconds: ruleCacheSeconds,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(
                    requireJustification: requireJustification,
                    maxGrantDurationSeconds: grantDuration
                ),
                elevation: ElevationBehavior(type: .prompt)
            )]
        )
    }

    private func denyEchoProfile() -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "deny-echo", type: .sudo, action: .deny, description: "d", priority: 10,
                cacheSeconds: 300,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact)
            )]
        )
    }

    private func echoRequest(argv: [String] = ["hi"]) -> PAMRequest {
        PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: argv, tty: nil))
    }

    private func makeController(
        grantStore: GrantMaintaining,
        paths: DaemonPaths,
        decisionLogger: DecisionLogger? = nil,
        prefsReader: ManagedPreferencesReader =
            ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:]))
    ) -> DaemonController {
        DaemonController(
            paths: paths,
            machServiceName: "test.unused",
            prefsReader: prefsReader,
            grantStore: grantStore,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil,
            decisionLogger: decisionLogger,
            pppc: StaticPPPCStatus(ready: true),
            authDB: NoopAuthorizationDBApplier(),
            // Never the production snapshot store: a unit test must not read or
            // write /Library/Application Support.
            lastKnownGood: InMemoryLastKnownGoodConfigStore(
                initial: CoordinatorFixtures.lastKnownGoodConfig()
            ),
            inspector: StaticBinaryIdentityInspector(identity: BinaryIdentity(
                canonicalPath: "", teamID: nil, sha256: echoHash, signingStatus: .unsigned
            )),
            deviceSerial: "TESTSERIAL",
            now: { CoordinatorFixtures.now }
        )
    }

    /// Every decision-log JSON line in the ephemeral log directory, decoded
    /// as raw dictionaries (avoids date-strategy coupling to the encoder).
    private func decisionLines(in logDirectory: URL) -> [[String: Any]] {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: logDirectory, includingPropertiesForKeys: nil
        )) ?? []
        var lines: [[String: Any]] = []
        for file in files
        where file.lastPathComponent.hasPrefix("decisions-") && file.pathExtension == "jsonl" {
            guard let content = try? String(contentsOf: file, encoding: .utf8) else { continue }
            for raw in content.split(separator: "\n", omittingEmptySubsequences: true) {
                if let object = try? JSONSerialization.jsonObject(with: Data(raw.utf8)),
                   let dict = object as? [String: Any] {
                    lines.append(dict)
                }
            }
        }
        return lines
    }

    /// Polls the decision log until `count` lines exist (prompt resolutions
    /// log from a detached task) or the retry budget is spent.
    private func decisionLines(in logDirectory: URL, until count: Int) async -> [[String: Any]] {
        for _ in 0..<200 {
            let lines = decisionLines(in: logDirectory)
            if lines.count >= count { return lines }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return decisionLines(in: logDirectory)
    }

    /// Polls the controller's session cache until it holds `expected` entries.
    private func cacheCount(of controller: DaemonController, until expected: Int) async -> Int {
        let cache = await controller.sessionCacheForTesting()
        for _ in 0..<200 {
            let count = await cache.count(now: CoordinatorFixtures.now)
            if count >= expected { return count }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return await cache.count(now: CoordinatorFixtures.now)
    }

    // MARK: Session cache — hit path

    @Test("a second identical request is served from the session cache without re-evaluation")
    func cacheServesSecondRequest() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let logger = try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random())
        let controller = makeController(grantStore: MockGrantStore(), paths: paths, decisionLogger: logger)
        await controller.loadPolicyForTesting(
            profiles: [allowEchoProfile(ruleCacheSeconds: 300)], config: config()
        )

        let first = await controller.handlePAM(echoRequest())
        #expect(first.decision == .allow)
        #expect(first.cacheSeconds == 300)
        #expect(await cacheCount(of: controller, until: 1) == 1)

        // Remove every rule: only the cache can answer the second request. If
        // the daemon re-evaluated, the empty policy would fail closed to deny.
        await controller.loadPolicyForTesting(profiles: [], config: config())
        let second = await controller.handlePAM(echoRequest())
        #expect(second.decision == .allow)
        #expect(second.ruleID == "allow-echo")
        #expect(second.grantID == nil)

        // A cache hit is still a decision: both events are in the signed log,
        // and the second is marked as the hit it is.
        let lines = await decisionLines(in: paths.logDirectory, until: 2)
        #expect(lines.count == 2)
        #expect(lines.last?["cacheHit"] as? Bool == true)
        #expect(lines.last?["outcome"] as? String == "granted")
        #expect(lines.last?["ruleID"] as? String == "allow-echo")
    }

    @Test("a cached allow requires the exact argv — a different argv misses and re-evaluates")
    func cacheMissOnDifferentArgv() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [allowEchoProfile(ruleCacheSeconds: 300)], config: config()
        )

        let first = await controller.handlePAM(echoRequest(argv: ["read", "com.example"]))
        #expect(first.decision == .allow)
        #expect(await cacheCount(of: controller, until: 1) == 1)

        // Remove every rule: only the cache can answer now. The identical argv
        // is a hit; ANY other argv must miss and take the full evaluation path
        // (which fails closed under the now-empty policy).
        await controller.loadPolicyForTesting(profiles: [], config: config())
        let sameArgv = await controller.handlePAM(echoRequest(argv: ["read", "com.example"]))
        #expect(sameArgv.decision == .allow)
        #expect(sameArgv.ruleID == "allow-echo")

        let differentArgv = await controller.handlePAM(echoRequest(argv: ["delete", "com.example"]))
        #expect(differentArgv.decision == .deny)
        let extraArg = await controller.handlePAM(echoRequest(argv: ["read", "com.example", "extra"]))
        #expect(extraArg.decision == .deny)
        let noArgs = await controller.handlePAM(echoRequest(argv: []))
        #expect(noArgs.decision == .deny)
    }

    @Test("a deny rule pinned to a specific argv is never bypassed by a cached allow for other argv")
    func denyRuleForSpecificArgvNeverServedFromCache() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let logger = try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random())
        let controller = makeController(grantStore: MockGrantStore(), paths: paths, decisionLogger: logger)
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [
                Rule(
                    id: "deny-echo-forbidden", type: .sudo, action: .deny, description: "d", priority: 5,
                    match: MatchCriteria(commandPattern: "/bin/echo", argPattern: "^forbidden$", matchType: .exact)
                ),
                Rule(
                    id: "allow-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                    cacheSeconds: 300,
                    match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact)
                ),
            ]
        )
        await controller.loadPolicyForTesting(profiles: [profile], config: config())

        // Warm the cache with an allow for a benign argv.
        let benign = await controller.handlePAM(echoRequest(argv: ["harmless"]))
        #expect(benign.decision == .allow)
        #expect(await cacheCount(of: controller, until: 1) == 1)

        // The argv the deny rule pins must take the full evaluation path and
        // hit the higher-priority deny — never ride the cached allow.
        let forbidden = await controller.handlePAM(echoRequest(argv: ["forbidden"]))
        #expect(forbidden.decision == .deny)
        #expect(forbidden.ruleID == "deny-echo-forbidden")

        let lines = await decisionLines(in: paths.logDirectory, until: 2)
        let last = try #require(lines.last)
        #expect(last["outcome"] as? String == "denied")
        #expect(last["cacheHit"] as? Bool == false)
    }

    // MARK: TTL resolution through the evaluator

    @Test("per-rule cacheSeconds overrides the global sudoCacheSeconds")
    func perRuleTTLOverridesGlobal() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [allowEchoProfile(ruleCacheSeconds: 120)], config: config(sudoCache: 300)
        )
        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .allow)
        #expect(response.cacheSeconds == 120)
        #expect(await cacheCount(of: controller, until: 1) == 1)
    }

    @Test("a rule without cacheSeconds falls back to the global sudoCacheSeconds")
    func globalTTLFallback() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [allowEchoProfile(ruleCacheSeconds: nil)], config: config(sudoCache: 300)
        )
        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .allow)
        #expect(response.cacheSeconds == 300)
        #expect(await cacheCount(of: controller, until: 1) == 1)
    }

    @Test("resolved TTL 0 means never cache — the next request is re-evaluated")
    func zeroTTLNeverCaches() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [allowEchoProfile(ruleCacheSeconds: nil)], config: config(sudoCache: 0)
        )
        let first = await controller.handlePAM(echoRequest())
        #expect(first.decision == .allow)
        #expect(first.cacheSeconds == 0)
        #expect(await controller.sessionCacheForTesting().count(now: CoordinatorFixtures.now) == 0)

        // Nothing cached: with the rules gone, the second request fails closed.
        await controller.loadPolicyForTesting(profiles: [], config: config())
        let second = await controller.handlePAM(echoRequest())
        #expect(second.decision == .deny)
    }

    @Test("deny is never cached, even when the rule carries cacheSeconds")
    func denyNeverCached() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [denyEchoProfile()], config: config(sudoCache: 300)
        )
        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .deny)
        #expect(response.cacheSeconds == 0)
        #expect(await controller.sessionCacheForTesting().count(now: CoordinatorFixtures.now) == 0)
    }

    @Test("monitor mode ignores the session cache (defensive deny is preserved)")
    func monitorModeBypassesCache() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [allowEchoProfile(ruleCacheSeconds: 300)], config: config(mode: .monitor)
        )
        // Pre-seed a matching entry (same user/binary/path/argv as the request);
        // the probe must not consult it outside enforce.
        await controller.sessionCacheForTesting().store(
            decision: .allow,
            key: SessionGrantCache.Key(user: "root", ruleID: "allow-echo", binaryHash: echoHash, argv: ["hi"]),
            canonicalPath: "/bin/echo",
            ttlSeconds: 300,
            now: CoordinatorFixtures.now
        )
        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .deny)
    }

    // MARK: Prompt round-trip caching

    @Test("an approved prompt is cached for the rule's TTL — no re-prompt inside the window")
    func approvedPromptCachesAndSkipsReprompt() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [promptEchoProfile(ruleCacheSeconds: 300)], config: config()
        )

        let recorder = PromptRecorder()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await recorder.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let first = await controller.handlePAM(echoRequest())
        #expect(first.decision == .prompt)
        let requestID = try #require(first.promptRequestID)
        let presented = await recorder.next()
        #expect(presented.requestID == requestID)
        await push.receiveResponse(PromptResponse(requestID: requestID, verdict: .approved))

        // The detached resolution task populates the cache after approval.
        #expect(await cacheCount(of: controller, until: 1) == 1)

        let second = await controller.handlePAM(echoRequest())
        #expect(second.decision == .allow)
        #expect(second.ruleID == "prompt-echo")
        try? await Task.sleep(for: .milliseconds(50))
        #expect(await recorder.totalPresented == 1)
    }

    // MARK: Invalidation

    @Test("a managed-preferences policy reload clears the session cache")
    func policyReloadInvalidatesCache() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = MutablePreferencesSource()
        let controller = makeController(
            grantStore: MockGrantStore(),
            paths: DaemonPaths.ephemeral(in: dir),
            prefsReader: ManagedPreferencesReader(source: source)
        )
        await controller.loadPolicyForTesting(
            profiles: [allowEchoProfile(ruleCacheSeconds: 300)], config: config()
        )
        _ = await controller.handlePAM(echoRequest())
        #expect(await cacheCount(of: controller, until: 1) == 1)

        source.set([BundleConfig.configDomain: ["daemonEnabled": true, "sudoCacheSeconds": 60]])
        await controller.reloadPolicyIfChanged()
        #expect(await controller.sessionCacheForTesting().count(now: CoordinatorFixtures.now) == 0)
    }

    // MARK: Audit-mode prompt softening

    @Test("audit mode resolves a prompt rule immediately: no push, no grant, would-grant logged")
    func auditModeSoftensPrompt() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let logger = try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random())
        let store = MockGrantStore()
        let controller = makeController(grantStore: store, paths: paths, decisionLogger: logger)
        await controller.loadPolicyForTesting(
            profiles: [promptEchoProfile(ruleCacheSeconds: 300, grantDuration: 900)],
            config: config(mode: .audit)
        )

        let recorder = PromptRecorder()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await recorder.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let response = await controller.handlePAM(echoRequest())
        // Pass-through reply, resolved without blocking on the Sentinel: the PAM
        // module converts any audit-mode reply to PAM_IGNORE.
        #expect(response.decision == .allow)
        #expect(response.promptRequestID == nil)
        #expect(response.grantID == nil)
        #expect(response.cacheSeconds == 0)
        #expect(response.ruleID == "prompt-echo")

        try? await Task.sleep(for: .milliseconds(50))
        #expect(await recorder.totalPresented == 0)
        #expect(try await store.activeGrants(now: CoordinatorFixtures.now).isEmpty)
        #expect(await controller.sessionCacheForTesting().count(now: CoordinatorFixtures.now) == 0)

        let lines = await decisionLines(in: paths.logDirectory, until: 1)
        #expect(lines.count == 1)
        #expect(lines.first?["outcome"] as? String == "would-grant")
        #expect(lines.first?["ruleID"] as? String == "prompt-echo")
    }

    // MARK: Justification audit trail

    @Test("an approved prompt's justification lands in the resolved DecisionEvent")
    func justificationReachesDecisionLog() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let logger = try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random())
        let store = try GrantStore(path: paths.grantDatabase.path, keyProvider: InMemoryKeyProvider.random())
        let controller = makeController(grantStore: store, paths: paths, decisionLogger: logger)
        await controller.loadPolicyForTesting(
            profiles: [promptEchoProfile(grantDuration: 900, requireJustification: true)],
            config: config()
        )

        let recorder = PromptRecorder()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await recorder.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .prompt)
        let requestID = try #require(response.promptRequestID)
        let presented = await recorder.next()
        // Prompts-domain minimum unset → the default of 1 (require justification
        // means "type any non-empty reason"; the button enables on first char).
        #expect(presented.justificationMinLength == 1)

        await push.receiveResponse(PromptResponse(
            requestID: requestID, verdict: .approved,
            justificationText: "deploying hotfix build 42"
        ))

        let lines = await decisionLines(in: paths.logDirectory, until: 1)
        let resolved = try #require(lines.last)
        #expect(resolved["outcome"] as? String == "granted")
        #expect(resolved["justification"] as? String == "deploying hotfix build 42")
        #expect(resolved["grantID"] as? String != nil)
        #expect(resolved["grantDurationSeconds"] as? Int == 900)

        // The resolution task publishes the approval for PAM's poll only after
        // the grant persisted; the publication precedes the log write we just
        // observed, so by now the poll must see the allow — and the grant it
        // stands on must exist.
        #expect(await push.pollVerdict(for: requestID) == .approved)
        #expect(try await store.activeGrants(now: CoordinatorFixtures.now).count == 1)
        await store.close()
    }

    @Test("the prompts-domain justificationMinLength reaches the prompt context")
    func justificationMinLengthFromPromptsDomain() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [promptEchoProfile(requireJustification: true)],
            config: config(),
            prompts: PromptsConfig(justificationMinLength: 42)
        )

        let recorder = PromptRecorder()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await recorder.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .prompt)
        let presented = await recorder.next()
        #expect(presented.requireJustification)
        #expect(presented.justificationMinLength == 42)
        await push.receiveResponse(PromptResponse(
            requestID: presented.requestID, verdict: .denied
        ))
    }

    @Test("the daemon clamps a large promptTimeoutSeconds to the PAM poll window")
    func promptTimeoutClamped() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(grantStore: MockGrantStore(), paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(
            profiles: [promptEchoProfile()], config: config(promptTimeout: 3600)
        )

        let recorder = PromptRecorder()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await recorder.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .prompt)
        let presented = await recorder.next()
        // 3600s config clamps to the ≤60s window PAM actually polls.
        #expect(presented.timeoutSeconds == 60)
        await push.receiveResponse(PromptResponse(
            requestID: presented.requestID, verdict: .denied
        ))
    }

    // MARK: Grant-persistence fail-closed

    @Test("a timed-grant insert failure denies instead of returning a phantom grantID")
    func grantInsertFailureFailsClosed() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let logger = try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random())
        let controller = makeController(grantStore: FailingInsertStore(), paths: paths, decisionLogger: logger)

        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: "rules_sudo_echo", profilePriority: 50,
            rules: [Rule(
                id: "grant-echo", type: .sudo, action: .allow, description: "d", priority: 10,
                cacheSeconds: 300,
                match: MatchCriteria(commandPattern: "/bin/echo", matchType: .exact),
                conditions: RuleConditions(maxGrantDurationSeconds: 900)
            )]
        )
        await controller.loadPolicyForTesting(profiles: [profile], config: config())

        let response = await controller.handlePAM(echoRequest())
        // Fail closed, consistent with degraded grants_db_error semantics
        // ("deny all timed grants"): no allow, no grantID, nothing cached.
        #expect(response.decision == .deny)
        #expect(response.grantID == nil)
        #expect(await controller.sessionCacheForTesting().count(now: CoordinatorFixtures.now) == 0)

        let lines = await decisionLines(in: paths.logDirectory, until: 1)
        let event = try #require(lines.first)
        #expect(event["outcome"] as? String == "denied")
        #expect(event["grantID"] == nil)
        #expect(event["cacheHit"] as? Bool == false)
        #expect(event["grantDurationSeconds"] as? Int == 0)
    }

    @Test("an approved prompt whose grant fails to persist is recorded as denied, uncached, with no grantID")
    func promptGrantInsertFailureRecordsDenied() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let logger = try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random())
        let controller = makeController(grantStore: FailingInsertStore(), paths: paths, decisionLogger: logger)
        await controller.loadPolicyForTesting(
            profiles: [promptEchoProfile(ruleCacheSeconds: 300, grantDuration: 900)],
            config: config()
        )

        let recorder = PromptRecorder()
        let push = SentinelPushService(now: { CoordinatorFixtures.now })
        await push.setDelivery({ ctx in Task { await recorder.record(ctx) } }, forUID: 0)
        await controller.setSentinelPushServiceForTesting(push)

        let response = await controller.handlePAM(echoRequest())
        #expect(response.decision == .prompt)
        let requestID = try #require(response.promptRequestID)
        _ = await recorder.next()
        await push.receiveResponse(PromptResponse(requestID: requestID, verdict: .approved))

        // The daemon's durable record must reflect the REAL outcome: the
        // approval's grant never persisted, so it is logged as denied — no
        // phantom "granted", no grantID, no grant window.
        let lines = await decisionLines(in: paths.logDirectory, until: 1)
        let resolved = try #require(lines.last)
        #expect(resolved["outcome"] as? String == "denied")
        #expect(resolved["grantID"] == nil)
        #expect(resolved["grantDurationSeconds"] as? Int == 0)

        // PAM's poll observes DENY, closing the fail-open window (not merely
        // logging it): the approval was never published — the push service
        // held it at resolution, and the failed insert published a deny in
        // its place before the log line above was written.
        #expect(await push.pollVerdict(for: requestID) == .denied)

        // Nothing cached: a broken grants DB must not hand out repeat allows,
        // so the identical request re-prompts instead of riding a cache entry.
        #expect(await controller.sessionCacheForTesting().count(now: CoordinatorFixtures.now) == 0)
        let again = await controller.handlePAM(echoRequest())
        #expect(again.decision == .prompt)
        // Resolve the re-prompt so no watchdog task outlives the test.
        let reprompted = await recorder.next()
        await push.receiveResponse(PromptResponse(requestID: reprompted.requestID, verdict: .denied))
    }
}

// MARK: - Test doubles

/// Records daemon → Sentinel prompt presentations, with a total counter so tests
/// can assert that a cached allow raised no second prompt.
private actor PromptRecorder {
    private(set) var totalPresented = 0
    private var presented: [PromptContext] = []
    private var waiters: [CheckedContinuation<PromptContext, Never>] = []

    func record(_ context: PromptContext) {
        totalPresented += 1
        if waiters.isEmpty {
            presented.append(context)
        } else {
            waiters.removeFirst().resume(returning: context)
        }
    }

    func next() async -> PromptContext {
        if !presented.isEmpty {
            return presented.removeFirst()
        }
        return await withCheckedContinuation { waiters.append($0) }
    }
}

/// Grant store whose inserts always fail — drives the fail-closed
/// grant-persistence path in `handlePAM`.
private actor FailingInsertStore: GrantMaintaining {
    func insert(_ grant: Grant) async throws {
        throw GrantStoreError.openFailed(path: "x", code: 14, message: "insert refused")
    }

    func cleanupExpired(now: Date) async throws -> Int { 0 }
    func activeGrants(now: Date) async throws -> [Grant] { [] }
    func activeGrants(for user: String, now: Date) async throws -> [Grant] { [] }
    func revokeAll(now: Date) async throws -> Int { 0 }
    func revoke(grantID: UUID, now: Date) async throws -> Int { 0 }
}

/// Mutable managed-preferences source so a test can change the delivered
/// policy between `reloadPolicyIfChanged()` calls.
/// Internal (not file-private): the awaiting-config reload tests in
/// StartupCoordinatorTests drive MDM delivery through this same source.
final class MutablePreferencesSource: PreferencesSource, @unchecked Sendable {
    private let lock = NSLock()
    private var domains: [String: [String: any Sendable]]

    init(domains: [String: [String: any Sendable]] = [:]) {
        self.domains = domains
    }

    func set(_ domains: [String: [String: any Sendable]]) {
        lock.lock()
        defer { lock.unlock() }
        self.domains = domains
    }

    func value(forKey key: String, domain: String) -> Any? {
        lock.lock()
        defer { lock.unlock() }
        return domains[domain]?[key]
    }

    func keys(inDomain domain: String) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return domains[domain].map { Array($0.keys) } ?? []
    }
}
