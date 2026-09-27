import Foundation
import PrivMgrCore

/// Turns a validated ``PAMRequest`` into an allow/deny decision by running the
/// shared ``RuleEngine`` — the daemon, not the PAM
/// module, is the policy authority.
///
/// Identity inspection is injected so the decision logic is unit-testable
/// without signed binaries. The evaluator is pure: it returns the response,
/// the decision event to log, and (for a timed-grant allow) the grant to
/// persist — it performs no I/O itself.
public struct PAMEvaluator: Sendable {
    private let engine = RuleEngine()
    private let canonicalizer = PathCanonicalizer()
    private let inspector: BinaryIdentityInspecting

    public init(inspector: BinaryIdentityInspecting) {
        self.inspector = inspector
    }

    /// Inputs that vary per request but aren't part of the PAM message.
    public struct Environment: Sendable {
        public let profiles: [RuleProfile]
        public let config: SerberusConfig
        /// Prompt-domain managed preferences (justification minimum). Defaults
        /// to the spec defaults so existing call sites are unaffected.
        public let prompts: PromptsConfig
        public let activeGrants: [Grant]
        public let deviceSerial: String
        public let version: DaemonVersion
        public let policyVersion: String?
        public let now: Date

        public init(
            profiles: [RuleProfile],
            config: SerberusConfig,
            prompts: PromptsConfig = PromptsConfig(),
            activeGrants: [Grant],
            deviceSerial: String,
            version: DaemonVersion,
            policyVersion: String?,
            now: Date
        ) {
            self.profiles = profiles
            self.config = config
            self.prompts = prompts
            self.activeGrants = activeGrants
            self.deviceSerial = deviceSerial
            self.version = version
            self.policyVersion = policyVersion
            self.now = now
        }
    }

    public struct Outcome: Sendable {
        public let response: PAMResponse
        public let event: DecisionEvent
        /// Present only for a timed-grant allow in enforce mode; the caller
        /// persists it before returning the response.
        public let issuedGrant: Grant?
        /// Present only for a `.prompt` decision. The caller pushes the prompt
        /// to the Sentinel and, on approval, persists ``PromptDirective/grantOnApproval``.
        public let promptDirective: PromptDirective?

        public init(
            response: PAMResponse,
            event: DecisionEvent,
            issuedGrant: Grant?,
            promptDirective: PromptDirective? = nil
        ) {
            self.response = response
            self.event = event
            self.issuedGrant = issuedGrant
            self.promptDirective = promptDirective
        }
    }

    /// Everything the daemon needs to run a prompt round-trip for a `.prompt`
    /// decision: the context to show the user, and the timed grant to persist
    /// if they approve (`nil` when the rule carries no grant duration).
    public struct PromptDirective: Sendable {
        public let context: PromptContext
        public let grantOnApproval: Grant?
        /// Session-cache TTL to apply on approval (the matched rule's resolved
        /// `cacheSeconds`); `0` = never cache the approved allow.
        public let cacheSeconds: Int

        public init(context: PromptContext, grantOnApproval: Grant?, cacheSeconds: Int = 0) {
            self.context = context
            self.grantOnApproval = grantOnApproval
            self.cacheSeconds = cacheSeconds
        }
    }

    /// Default justification minimum when a rule requires justification but
    /// neither the schema (``RuleConditions`` carries no per-rule length) nor
    /// the prompts domain provides one. `1` means "require justification"
    /// simply demands non-empty text (after trimming whitespace) — the button
    /// enables the moment the user types a real character. Admins that want a
    /// longer floor set `justificationMinLength` in the prompts profile, and
    /// the Sentinel shows a live "Minimum N characters" hint for any floor > 1.
    static let defaultJustificationMinLength = 1

    /// The effective justification minimum: the managed prompts-domain value
    /// when set (> 0), else ``defaultJustificationMinLength``. The reader's
    /// unset default is 0, so 0 means "not configured", never "no minimum".
    static func effectiveJustificationMinLength(_ prompts: PromptsConfig) -> Int {
        prompts.justificationMinLength > 0 ? prompts.justificationMinLength : defaultJustificationMinLength
    }

    /// Upper bound on the effective prompt window, in seconds. Kept strictly
    /// inside PAM's fixed poll budget (`pam_serberus.c`: 80 × 0.8s ≈ 64s) with
    /// margin, so the daemon's timeout fires — and PAM observes the resulting
    /// deny — before PAM gives up. Both the Sentinel countdown (``PromptContext``)
    /// and the daemon watchdog clamp to this value, so a large admin-configured
    /// `promptTimeoutSeconds` can never leave the daemon resolving a prompt
    /// after PAM has stopped polling.
    static let maxPromptWindowSeconds = 60

    /// The canonicalized command plus its inspected identity — the exact pair
    /// ``evaluate(_:environment:resolvedCommand:)`` computes for a sudo
    /// request, exposed so the daemon can key its session-cache probe on the
    /// same canonical path and binary hash without hashing the binary twice.
    struct ResolvedCommand: Sendable {
        let canonicalPath: String
        let identity: BinaryIdentity
    }

    /// Canonicalizes and inspects a sudo request's command. Returns `nil` for
    /// authURI requests and non-canonicalizable commands — both take the full
    /// evaluation path, which fails closed with the detailed reason.
    func resolveCommand(_ request: PAMRequest) -> ResolvedCommand? {
        guard case let .sudo(command, _, _) = request.kind,
              let canonicalPath = try? canonicalizer.canonicalize(command, existence: .requireExists) else {
            return nil
        }
        return ResolvedCommand(
            canonicalPath: canonicalPath,
            identity: inspector.inspect(canonicalPath: canonicalPath)
        )
    }

    /// Returns a canonicalized *view* of the profiles for the rule engine: each
    /// `sudo` rule whose `commandPattern` is interpreted as a literal path
    /// (`matchType` `.exact` or `.prefixRegex`) has that pattern symlink-resolved,
    /// so a rule authored against a symlink path (`/usr/local/bin/jamf`) matches
    /// the canonical command the engine evaluates (`/usr/local/jamf/bin/jamf`),
    /// which ``evaluate(_:environment:resolvedCommand:)`` has already resolved.
    ///
    /// This keeps the shared, filesystem-free ``RuleEngine``/``PatternMatcher`` pure — the
    /// symlink resolution lives here, in the daemon, not in the matcher.
    ///
    /// Scope is deliberately narrow:
    /// - Only `sudo` rules with a `commandPattern` are touched; authURI rules and
    ///   patternless rules pass through unchanged.
    /// - Only `.exact` / `.prefixRegex` are canonicalized — their pattern is a
    ///   literal path. `.glob` / `.regex` / `.any` carry metacharacters that
    ///   `resolvingSymlinksInPath` would corrupt, so they are left raw.
    /// - Existence is `.allowMissing`: an authored path that does not resolve is
    ///   still a valid pattern (audit/simulation), and a symlink whose target is
    ///   absent stays as authored.
    /// - Only `commandPattern` is rewritten. `argPattern`, identity pins, action,
    ///   elevation, conditions, IDs, priorities, and rule/profile ordering are
    ///   preserved verbatim.
    /// - A pattern that fails to canonicalize keeps its raw form (fail-safe: no
    ///   worse than the pre-fix behavior).
    static func canonicalizedProfiles(_ profiles: [RuleProfile], canonicalizer: PathCanonicalizer) -> [RuleProfile] {
        profiles.map { profile in
            var profile = profile
            profile.rules = profile.rules.map { rule in
                guard rule.type == .sudo, let pattern = rule.match.commandPattern else { return rule }
                switch rule.match.matchType ?? .exact {
                case .exact, .prefixRegex:
                    guard let canonical = try? canonicalizer.canonicalize(pattern, existence: .allowMissing) else {
                        return rule
                    }
                    var rule = rule
                    rule.match.commandPattern = canonical
                    return rule
                case .glob, .regex, .any:
                    return rule
                }
            }
            return profile
        }
    }

    /// Diagnostics for `sudo` rules whose literal-path `commandPattern`
    /// (`.exact` / `.prefixRegex`) can never match an enforce-mode request
    /// because the authored path neither resolves through a live symlink nor
    /// exists on disk.
    ///
    /// This is the *silent inert rule* failure mode. ``canonicalizedProfiles``
    /// rewrites a literal-path pattern only when `resolvingSymlinksInPath`
    /// actually resolves a symlink present on disk; a rule authored against a
    /// symlink that is absent at evaluation time (e.g. `/usr/local/bin/jamf`
    /// before a vendor framework recreates it) keeps its raw form, never equals
    /// the canonical request command (which enforce mode resolves with
    /// `.requireExists`), and fails closed — indistinguishable from "no such
    /// rule" in the decision log without this warning.
    ///
    /// Called at policy-load time (startup and managed-preferences reload), not
    /// per request. Returns one human-readable line per offending rule; empty
    /// when every literal-path rule either resolves or exists. `fileExists` is
    /// injectable for tests.
    static func unresolvableSudoCommandPatterns(
        _ profiles: [RuleProfile],
        canonicalizer: PathCanonicalizer,
        fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    ) -> [String] {
        var warnings: [String] = []
        for profile in profiles {
            for rule in profile.rules {
                guard rule.type == .sudo, let pattern = rule.match.commandPattern else { continue }
                let matchType = rule.match.matchType ?? .exact
                switch matchType {
                case .exact, .prefixRegex:
                    guard let canonical = try? canonicalizer.canonicalize(pattern, existence: .allowMissing) else {
                        continue
                    }
                    // canonical != pattern  → a live symlink resolved it → matches.
                    // canonical == pattern, exists on disk → already the real path → matches.
                    // canonical == pattern, absent → can never match a `.requireExists` command.
                    if canonical == pattern && !fileExists(pattern) {
                        warnings.append(
                            "rule '\(rule.id)' in profile '\(profile.profileKey)': commandPattern '\(pattern)' " +
                            "(matchType \(matchType.rawValue)) neither resolves through a symlink nor exists on disk — " +
                            "it will match no sudo request and fail closed. Author the resolved real binary path."
                        )
                    }
                case .glob, .regex, .any:
                    continue
                }
            }
        }
        return warnings
    }

    public func evaluate(_ request: PAMRequest, environment env: Environment) -> Outcome {
        evaluate(request, environment: env, resolvedCommand: nil)
    }

    /// Evaluates with an optional pre-resolved command identity. The daemon
    /// resolves once (for its session-cache probe) and passes the pair in so
    /// the binary is not canonicalized and hashed a second time here.
    func evaluate(_ request: PAMRequest, environment env: Environment, resolvedCommand: ResolvedCommand?) -> Outcome {
        // Monitor mode performs no rule evaluation. PAM should not
        // even contact the daemon in monitor; this is a defensive fail-closed.
        if env.config.enforcementMode == .monitor {
            return failClosed(request: request, env: env, reason: "monitor mode: no evaluation")
        }

        // Canonicalize the command and build the elevation request.
        let kind: ElevationRequestKind
        let canonicalPath: String
        let identity: BinaryIdentity
        switch request.kind {
        case let .sudo(command, argv, _):
            if let resolved = resolvedCommand {
                canonicalPath = resolved.canonicalPath
                identity = resolved.identity
            } else {
                do {
                    canonicalPath = try canonicalizer.canonicalize(command, existence: .requireExists)
                } catch {
                    return failClosed(request: request, env: env, reason: "command not canonicalizable: \(error.localizedDescription)")
                }
                identity = inspector.inspect(canonicalPath: canonicalPath)
            }
            kind = .sudo(command: canonicalPath, argv: argv)
        case let .authURI(uri):
            // AuthURI via PAM carries no requesting-binary path; identity is
            // unknown until the ESF/authdb path. Identity-pinned
            // rules fail closed.
            canonicalPath = ""
            identity = BinaryIdentity(canonicalPath: "", teamID: nil, sha256: "", signingStatus: .unsigned)
            kind = .authURI(uri)
        }

        // An unknown user never becomes uid 0: grants are keyed by uid, so that
        // would record a grant for root.
        guard let uid = Self.uid(forUser: request.user) else {
            return failClosed(request: request, env: env, reason: "unknown user '\(request.user)'")
        }
        let elevation = ElevationRequest(
            user: request.user,
            uid: uid,
            kind: kind,
            identity: identity,
            justificationProvided: false,
            timestamp: env.now
        )

        let result = engine.evaluate(
            request: elevation,
            profiles: Self.canonicalizedProfiles(env.profiles, canonicalizer: canonicalizer),
            globalCacheSeconds: env.config.sudoCacheSeconds,
            globalGrantDurationSeconds: env.config.defaultGrantDurationSeconds,
            timeBoundGrantsEnabled: env.config.timeBoundGrantsEnabled,
            activeGrants: env.activeGrants.map { $0.snapshot() }
        )

        return resolve(result: result, request: request, elevation: elevation, identity: identity, env: env)
    }

    // MARK: Resolution

    private func resolve(
        result: EvaluationResult,
        request: PAMRequest,
        elevation: ElevationRequest,
        identity: BinaryIdentity,
        env: Environment
    ) -> Outcome {
        var issuedGrant: Grant?
        var promptDirective: PromptDirective?
        let pamResponse: PAMResponse

        switch result.decision {
        case .allow:
            pamResponse = PAMResponse(
                decision: .allow,
                cacheSeconds: result.resolvedCacheSeconds,
                grantID: result.satisfyingGrantID,
                ruleID: result.matchedRuleID
            )
        case .timedGrant:
            // Issue a persisted grant pinned to this binary.
            let grant = Grant(
                user: request.user,
                uid: elevation.uid,
                ruleID: result.matchedRuleID ?? "unknown",
                profileKey: result.matchedProfileKey ?? "unknown",
                teamID: identity.teamID ?? "",
                binaryHash: identity.sha256,
                canonicalPath: identity.canonicalPath,
                argvPattern: result.matchedRule?.match.argPattern,
                grantedAt: env.now,
                expiresAt: result.grantDurationSeconds.map { env.now.addingTimeInterval(TimeInterval($0)) },
                policyVersion: env.policyVersion ?? "unknown"
            )
            issuedGrant = grant
            pamResponse = PAMResponse(
                decision: .allow,
                cacheSeconds: result.resolvedCacheSeconds,
                grantID: grant.grantID,
                ruleID: result.matchedRuleID
            )
        case .prompt:
            // Audit is a pass-through observation mode: pushing a
            // real Sentinel prompt would block sudo for the whole poll window and
            // persisting an approval grant would carry audit-time decisions
            // into enforce mode. Resolve immediately — log the would-grant
            // with the matched rule; PAM converts the reply to PAM_IGNORE.
            if env.config.enforcementMode == .audit {
                let event = makeEvent(
                    request: request, identity: identity, decision: .allow,
                    ruleID: result.matchedRuleID, profileKey: result.matchedProfileKey,
                    grantID: nil, cacheHit: false,
                    grantDuration: result.grantDurationSeconds ?? 0,
                    logArguments: result.matchedRule?.elevation.logArguments ?? false,
                    env: env
                )
                return Outcome(
                    response: PAMResponse(
                        decision: .allow, cacheSeconds: 0, grantID: nil, ruleID: result.matchedRuleID
                    ),
                    event: event,
                    issuedGrant: nil
                )
            }
            // Surface the prompt to the daemon: it pushes the request to the
            // Sentinel and PAM polls for the verdict. The wire response carries
            // `.prompt` + the requestID so the listener emits `prompt_pending`.
            let directive = Self.makePromptDirective(
                result: result, request: request, elevation: elevation, identity: identity, env: env
            )
            promptDirective = directive
            pamResponse = PAMResponse(
                decision: .prompt,
                cacheSeconds: 0,
                grantID: nil,
                ruleID: result.matchedRuleID,
                promptRequestID: directive.context.requestID
            )
        case .deny:
            pamResponse = PAMResponse(decision: .deny, cacheSeconds: 0, grantID: nil, ruleID: result.matchedRuleID)
        }

        let event = makeEvent(
            request: request,
            elevation: elevation,
            identity: identity,
            result: result,
            grantID: issuedGrant?.grantID ?? result.satisfyingGrantID,
            env: env
        )
        return Outcome(response: pamResponse, event: event, issuedGrant: issuedGrant, promptDirective: promptDirective)
    }

    // MARK: Prompt directive

    /// Builds the ``PromptDirective`` for a `.prompt` decision: the human-facing
    /// ``PromptContext`` plus the timed grant to persist on approval (`nil` when
    /// the matched rule carries no grant duration).
    private static func makePromptDirective(
        result: EvaluationResult,
        request: PAMRequest,
        elevation: ElevationRequest,
        identity: BinaryIdentity,
        env: Environment
    ) -> PromptDirective {
        let requiresJustification = result.matchedRule?.conditions.requireJustification ?? false
        // Rule identity for the prompt's RULE row and body sentence. Only ever
        // display strings — the Sentinel renders them and decides nothing.
        let ruleName = result.matchedProfileKey.flatMap { profileKey in
            result.matchedRuleID.map { "\(profileKey) · \($0)" }
        }
        let ruleDescription = (result.matchedRule?.description)
            .flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .flatMap { $0.isEmpty ? nil : $0 }
        let context = PromptContext(
            user: request.user,
            processName: processName(canonicalPath: identity.canonicalPath, request: request),
            canonicalPath: identity.canonicalPath,
            teamID: identity.teamID,
            signingStatus: identity.signingStatus,
            humanReadableRequest: humanReadableRequest(request),
            requireJustification: requiresJustification,
            justificationMinLength: requiresJustification ? effectiveJustificationMinLength(env.prompts) : 0,
            timeoutSeconds: min(env.config.promptTimeoutSeconds, maxPromptWindowSeconds),
            ruleName: ruleName,
            ruleDescription: ruleDescription,
            // Show the active window on the prompt only for a time-bound grant,
            // the only kind there is.
            grantDurationSeconds: result.grantDurationSeconds
        )
        // The grant persisted on approval: only a time-bound one, stamped with
        // its expiry. A rule with no grant (none configured, -1, or time-bound
        // grants off) persists nothing, so the next invocation prompts again.
        let grantExpiry: Date? = result.grantDurationSeconds.map {
            env.now.addingTimeInterval(TimeInterval($0))
        }
        let grant: Grant? = grantExpiry != nil
            ? Grant(
                user: request.user,
                uid: elevation.uid,
                ruleID: result.matchedRuleID ?? "unknown",
                profileKey: result.matchedProfileKey ?? "unknown",
                teamID: identity.teamID ?? "",
                binaryHash: identity.sha256,
                canonicalPath: identity.canonicalPath,
                argvPattern: result.matchedRule?.match.argPattern,
                grantedAt: env.now,
                expiresAt: grantExpiry,
                policyVersion: env.policyVersion ?? "unknown"
            )
            : nil
        return PromptDirective(
            context: context,
            grantOnApproval: grant,
            cacheSeconds: result.resolvedCacheSeconds
        )
    }

    private static func processName(canonicalPath: String, request: PAMRequest) -> String {
        if !canonicalPath.isEmpty {
            let name = (canonicalPath as NSString).lastPathComponent
            if !name.isEmpty { return name }
        }
        switch request.kind {
        case let .sudo(command, _, _): return (command as NSString).lastPathComponent
        case let .authURI(uri): return uri
        }
    }

    /// The request line shown in the Sentinel's prompt. The arguments are
    /// redacted exactly as the decision log redacts them: this string crosses
    /// XPC to the Sentinel, which keeps it in the user's elevation history.
    /// Hidden characters (bidi overrides, zero-width characters, newlines…)
    /// are then written as visible escapes (``DisplayText/escapingInvisibles(_:)``),
    /// so the line can't read differently from what runs.
    static func humanReadableRequest(_ request: PAMRequest) -> String {
        switch request.kind {
        case let .sudo(command, argv, _):
            return DisplayText.escapingInvisibles(
                (["sudo", command] + ArgumentRedactor.redact(argv, program: command)).joined(separator: " ")
            )
        case let .authURI(uri):
            // The shared prefix constant — the Sentinel parses it back out to
            // render the RIGHT detail row (PromptContext.requestRowValue).
            return PromptContext.authURIRequestPrefix + DisplayText.escapingInvisibles(uri)
        }
    }

    private func failClosed(request: PAMRequest, env: PAMEvaluator.Environment, reason: String) -> Outcome {
        let identity = BinaryIdentity(canonicalPath: "", teamID: nil, sha256: "", signingStatus: .unsigned)
        let event = makeEvent(
            request: request, identity: identity, decision: .deny,
            ruleID: nil, profileKey: nil, grantID: nil, cacheHit: false,
            grantDuration: 0, logArguments: false, env: env
        )
        return Outcome(response: .deny, event: event, issuedGrant: nil)
    }

    // MARK: Event construction

    private func makeEvent(
        request: PAMRequest,
        elevation: ElevationRequest,
        identity: BinaryIdentity,
        result: EvaluationResult,
        grantID: UUID?,
        env: Environment
    ) -> DecisionEvent {
        makeEvent(
            request: request, identity: identity, decision: result.decision,
            ruleID: result.matchedRuleID, profileKey: result.matchedProfileKey,
            grantID: grantID, cacheHit: result.cacheHit,
            grantDuration: result.grantDurationSeconds ?? 0,
            logArguments: result.matchedRule?.elevation.logArguments ?? false,
            env: env
        )
    }

    private func makeEvent(
        request: PAMRequest,
        identity: BinaryIdentity,
        decision: Decision,
        ruleID: String?,
        profileKey: String?,
        grantID: UUID?,
        cacheHit: Bool,
        grantDuration: Int,
        logArguments: Bool,
        env: Environment
    ) -> DecisionEvent {
        let argv: [String]?
        let sudoCommand: String?
        let authURI: String?
        switch request.kind {
        case let .sudo(command, args, _):
            sudoCommand = identity.canonicalPath.isEmpty ? command : identity.canonicalPath
            authURI = nil
            argv = logArguments ? args : nil
        case let .authURI(uri):
            sudoCommand = nil
            authURI = uri
            argv = nil
        }

        return DecisionEvent(
            timestamp: env.now,
            outcome: DecisionEvent.outcome(for: decision, mode: env.config.enforcementMode),
            enforcementMode: env.config.enforcementMode,
            authURI: authURI,
            sudoCommand: sudoCommand,
            arguments: argv,
            processPath: identity.canonicalPath,
            processTeamID: identity.teamID ?? "",
            processHash: identity.sha256,
            userName: request.user,
            userUID: Self.uid(forUser: request.user).map { Int($0) } ?? -1,
            ruleID: ruleID,
            profileKey: profileKey,
            grantID: grantID,
            justification: nil,
            grantDurationSeconds: grantDuration,
            cacheHit: cacheHit,
            deviceSerial: env.deviceSerial,
            daemonVersion: env.version.daemonVersion,
            pamModuleVersion: env.version.pamModuleVersion,
            policyVersion: env.policyVersion ?? "unknown"
        )
    }

    /// Resolves a username to its UID, or nil when there's no such user.
    static func uid(forUser user: String) -> uid_t? {
        guard let entry = getpwnam(user) else { return nil }
        return entry.pointee.pw_uid
    }
}
