import Foundation
import Darwin

// MARK: - Decision

/// Outcome of a policy evaluation.
public enum Decision: String, Codable, Sendable, CaseIterable {
    /// Elevation permitted without interaction.
    case allow
    /// Elevation refused.
    case deny
    /// Elevation requires user approval via the Sentinel prompt.
    case prompt
    /// Elevation permitted and a timed grant is created.
    case timedGrant
}

// MARK: - Trace

/// One step in the evaluation trace, explaining how a decision was reached.
public struct TraceStep: Sendable, Equatable, CustomStringConvertible {
    /// Ordinal position in the trace.
    public let index: Int
    /// What the engine examined.
    public let detail: String
    /// What it concluded.
    public let outcome: String

    public init(index: Int, detail: String, outcome: String) {
        self.index = index
        self.detail = detail
        self.outcome = outcome
    }

    public var description: String { "[\(index)] \(detail) → \(outcome)" }
}

// MARK: - Result

/// Full result of one rule-engine evaluation.
public struct EvaluationResult: Sendable, Equatable {
    /// The decision.
    public let decision: Decision
    /// Profile key of the matched rule, if any.
    public let matchedProfileKey: String?
    /// ID of the matched rule, if any.
    public let matchedRuleID: String?
    /// Priority of the matched rule, if any.
    public let matchedPriority: Int?
    /// The matched rule, if any.
    public let matchedRule: Rule?
    /// Resolved cache TTL in seconds. Always `0` for deny and no-match.
    public let resolvedCacheSeconds: Int
    /// Timed grant duration in seconds, when `decision == .timedGrant`.
    public let grantDurationSeconds: Int?
    /// True when an active grant satisfied the request.
    public let cacheHit: Bool
    /// The grant that satisfied the request, when `cacheHit`.
    public let satisfyingGrantID: UUID?
    /// True when no rule matched and the engine failed closed.
    public let noMatch: Bool
    /// Human-readable explanation of the decision.
    public let reason: String
    /// Non-fatal observations (skipped rules, invalid patterns).
    public let warnings: [String]
    /// Step-by-step evaluation trace.
    public let trace: [TraceStep]

    public init(
        decision: Decision,
        matchedProfileKey: String?,
        matchedRuleID: String?,
        matchedPriority: Int?,
        matchedRule: Rule?,
        resolvedCacheSeconds: Int,
        grantDurationSeconds: Int?,
        cacheHit: Bool,
        satisfyingGrantID: UUID?,
        noMatch: Bool,
        reason: String,
        warnings: [String],
        trace: [TraceStep]
    ) {
        self.decision = decision
        self.matchedProfileKey = matchedProfileKey
        self.matchedRuleID = matchedRuleID
        self.matchedPriority = matchedPriority
        self.matchedRule = matchedRule
        self.resolvedCacheSeconds = resolvedCacheSeconds
        self.grantDurationSeconds = grantDurationSeconds
        self.cacheHit = cacheHit
        self.satisfyingGrantID = satisfyingGrantID
        self.noMatch = noMatch
        self.reason = reason
        self.warnings = warnings
        self.trace = trace
    }
}

// MARK: - Engine

/// Deterministic policy evaluation engine.
///
/// This is the only component that may interpret rules. The daemon and the
/// Decision Simulator both call ``evaluate(request:profiles:globalCacheSeconds:activeGrants:)``
/// — there is no divergent simulation logic anywhere.
///
/// Determinism: profiles and rules are explicitly sorted before evaluation
/// (profile priority, profile key, rule priority, deny-before-allow, rule ID).
/// Given identical inputs the engine always returns the same decision.
/// Evaluation never depends on dictionary ordering, load order, or timing.
///
/// Fail-closed: when no rule matches, the decision is `deny`
/// (`noMatch == true`). Mode-dependent softening (audit/monitor pass-through)
/// is the daemon's responsibility, not the engine's.
public struct RuleEngine: Sendable {
    /// Whether an identity-scoped (per-app) authURI rule can match at all.
    /// ``AuthURIIdentityScope/perAppPinsEnabled`` in production (false in
    /// 0.9.0): such a rule then never matches, exactly as the daemon
    /// never composes it. Tests inject `true` to exercise the Team ID pin.
    private let perAppPinsEnabled: Bool

    public init(perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled) {
        self.perAppPinsEnabled = perAppPinsEnabled
    }

    /// Evaluates one elevation request against the supplied profiles.
    ///
    /// - Parameters:
    ///   - request: The validated elevation request.
    ///   - profiles: All loaded rule profiles (any order; the engine sorts).
    ///   - globalCacheSeconds: `sudoCacheSeconds` from the config domain,
    ///     used when a matched rule's `cacheSeconds` is `nil`.
    ///   - globalGrantDurationSeconds: The org-wide default timed-grant duration
    ///     (`defaultGrantDurationMinutes` × 60 from the config domain), used when
    ///     a matched rule does not set its own `maxGrantDurationSeconds`. `0`
    ///     (the default) means no global default — a rule issues a timed grant
    ///     only when it specifies its own duration, exactly as before this key
    ///     existed.
    ///   - timeBoundGrantsEnabled: The master switch (`timeBoundGrantsEnabled`
    ///     from the config domain). When `true` (the default), grants are
    ///     time-bound by the resolved duration above. When `false`, ALL durations
    ///     — per-rule and global — are ignored and no grant is issued: a prompt
    ///     rule asks on every invocation, and a silent rule is a plain allow.
    ///   - activeGrants: Point-in-time grant snapshots for the requesting user.
    /// - Returns: The evaluation result with full trace.
    public func evaluate(
        request: ElevationRequest,
        profiles: [RuleProfile],
        globalCacheSeconds: Int,
        globalGrantDurationSeconds: Int = 0,
        timeBoundGrantsEnabled: Bool = true,
        activeGrants: [GrantSnapshot]
    ) -> EvaluationResult {
        var trace: [TraceStep] = []
        var warnings: [String] = []
        var step = 0
        func record(_ detail: String, _ outcome: String) {
            trace.append(TraceStep(index: step, detail: detail, outcome: outcome))
            step += 1
        }

        record("request", Self.describe(request))

        let ordered = Self.orderedRules(in: profiles)
        record("policy", "\(profiles.count) profile(s), \(ordered.count) rule(s) in deterministic order")

        for entry in ordered {
            let rule = entry.rule
            guard Self.kindMatches(rule: rule, kind: request.kind) else { continue }

            let match = Self.matches(rule: rule, request: request, warnings: &warnings,
                                     perAppPinsEnabled: perAppPinsEnabled)
            record(
                "rule '\(rule.id)' (profile \(entry.profileKey), priority \(rule.priority), \(rule.action.rawValue))",
                match ? "matched" : "no match"
            )
            guard match else { continue }

            return Self.resolve(
                rule: rule,
                profileKey: entry.profileKey,
                request: request,
                globalCacheSeconds: globalCacheSeconds,
                globalGrantDurationSeconds: globalGrantDurationSeconds,
                timeBoundGrantsEnabled: timeBoundGrantsEnabled,
                activeGrants: activeGrants,
                trace: &trace,
                step: &step,
                warnings: warnings
            )
        }

        record("no rule matched", "fail closed: deny")
        return EvaluationResult(
            decision: .deny,
            matchedProfileKey: nil,
            matchedRuleID: nil,
            matchedPriority: nil,
            matchedRule: nil,
            resolvedCacheSeconds: 0,
            grantDurationSeconds: nil,
            cacheHit: false,
            satisfyingGrantID: nil,
            noMatch: true,
            reason: "No rule matched the request; Serberus fails closed.",
            warnings: warnings,
            trace: trace
        )
    }

    // MARK: Cache TTL resolution

    /// Resolves the effective cache TTL for a matched rule.
    ///
    /// Order: per-rule `cacheSeconds` when non-nil, otherwise the global
    /// `sudoCacheSeconds`, otherwise the hardcoded default of `0`.
    /// Deny rules are never cached regardless of `cacheSeconds`.
    /// The result is clamped to `0...86400`.
    public static func resolvedCacheSeconds(rule: Rule, globalCacheSeconds: Int) -> Int {
        guard rule.action == .allow else { return 0 }
        let raw = rule.cacheSeconds ?? globalCacheSeconds
        return min(max(raw, 0), RuleSchemaConstants.maxCacheSeconds)
    }

    // MARK: Deterministic ordering

    struct OrderedRule {
        let profileKey: String
        let profilePriority: Int
        let rule: Rule
    }

    /// Returns all rules in deterministic evaluation order:
    /// profile priority ascending, then rule priority ascending, then deny
    /// before allow (deny wins at equal priority), then rule ID, then
    /// profile key.
    static func orderedRules(in profiles: [RuleProfile]) -> [OrderedRule] {
        var entries: [OrderedRule] = []
        for profile in profiles {
            for rule in profile.rules {
                entries.append(OrderedRule(
                    profileKey: profile.profileKey,
                    profilePriority: profile.profilePriority,
                    rule: rule
                ))
            }
        }
        entries.sort { a, b in
            if a.profilePriority != b.profilePriority { return a.profilePriority < b.profilePriority }
            if a.rule.priority != b.rule.priority { return a.rule.priority < b.rule.priority }
            if a.rule.action != b.rule.action { return a.rule.action == .deny }
            if a.rule.id != b.rule.id { return a.rule.id < b.rule.id }
            return a.profileKey < b.profileKey
        }
        return entries
    }

    /// The authURI rule that governs `right`, if any.
    ///
    /// For read-only tooling that has a right string but not the requesting
    /// binary's identity — e.g. Serberus Intel's live "matches a rule" tag
    /// over authd log lines. It mirrors the runtime authURI test exactly
    /// (`match.authURI == right`, case-sensitive, `type == .authuri`) and the
    /// same ordering ``evaluate(request:profiles:globalCacheSeconds:activeGrants:)``
    /// applies (profile priority → rule priority → deny-before-allow), so it
    /// returns the rule that would win.
    ///
    /// Identity pins (`requiredTeamID`/`requiredBinaryHash`) are deliberately
    /// **not** applied: the authd log names the right but not the binary's Team
    /// ID or hash, so this answers "which rule targets this right." A caller
    /// that wants to be honest about a pinned rule can inspect
    /// `rule.match.requiredTeamID` / `requiredBinaryHash` and caveat the tag —
    /// the pin means the live match on the right is necessary but not
    /// sufficient for the actual decision. Kept here because this type is "the
    /// only component that may interpret rules"; tooling must not reimplement
    /// the equality/ordering semantics.
    public static func authURIRule(matching right: String, in profiles: [RuleProfile]) -> Rule? {
        orderedRules(in: profiles)
            .first { $0.rule.type == .authuri && $0.rule.match.authURI == right }?
            .rule
    }

    // MARK: Matching

    static func kindMatches(rule: Rule, kind: ElevationRequestKind) -> Bool {
        switch (rule.type, kind) {
        case (.authuri, .authURI), (.sudo, .sudo):
            return true
        default:
            return false
        }
    }

    static func matches(rule: Rule, request: ElevationRequest, warnings: inout [String],
                        perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled) -> Bool {
        // Identity constraints apply to every rule type and every match type.
        if let requiredTeamID = rule.match.requiredTeamID {
            guard request.identity.teamID == requiredTeamID else { return false }
        }
        if let requiredHash = rule.match.requiredBinaryHash {
            guard request.identity.sha256.lowercased() == requiredHash.lowercased() else { return false }
        }

        switch request.kind {
        case let .authURI(uri):
            guard let ruleURI = rule.match.authURI else { return false }
            guard ruleURI == uri else { return false }
            // Identity-scoped rule: the engine can check the Team ID pin (the
            // request carries it) but NOT the bundle-ID requirement — that is
            // matched live by authd against the caller's code signature. The
            // simulator says so (``DecisionSimulator`` caveats).
            if let branch = rule.appIdentity {
                // Per-app rules are disabled; the right stays native.
                guard perAppPinsEnabled else {
                    warnings.append("Rule '\(rule.id)' skipped: \(AuthURIIdentityScope.disabledSkipReason)")
                    return false
                }
                guard request.identity.teamID == branch.teamID else { return false }
            }
            return true

        case let .sudo(command, argv):
            return sudoMatches(rule: rule, command: command, argv: argv, warnings: &warnings)
        }
    }

    private static func sudoMatches(
        rule: Rule,
        command: String,
        argv: [String],
        warnings: inout [String]
    ) -> Bool {
        let matchType = rule.match.matchType ?? .exact

        // Argv is preserved as [String]; it is never flattened before matching.
        switch PatternMatcher.matchCommand(pattern: rule.match.commandPattern, matchType: matchType, command: command) {
        case .invalidPattern:
            warnings.append("Rule '\(rule.id)' skipped: invalid regex '\(rule.match.commandPattern ?? "")'")
            return false
        case .noMatch:
            return false
        case .matched:
            break
        }

        // argPattern is a regex applied to argv[0] only. A rule that
        // constrains arguments cannot match an argument-less invocation.
        if let argPattern = rule.match.argPattern {
            switch PatternMatcher.matchArgument(pattern: argPattern, argument: argv.first) {
            case .invalidPattern:
                warnings.append("Rule '\(rule.id)' skipped: invalid argPattern '\(argPattern)'")
                return false
            case .noMatch:
                return false
            case .matched:
                return true
            }
        }
        return true
    }

    // MARK: Decision resolution

    private static func resolve(
        rule: Rule,
        profileKey: String,
        request: ElevationRequest,
        globalCacheSeconds: Int,
        globalGrantDurationSeconds: Int,
        timeBoundGrantsEnabled: Bool,
        activeGrants: [GrantSnapshot],
        trace: inout [TraceStep],
        step: inout Int,
        warnings: [String]
    ) -> EvaluationResult {
        func record(_ detail: String, _ outcome: String) {
            trace.append(TraceStep(index: step, detail: detail, outcome: outcome))
            step += 1
        }

        let cacheSeconds = resolvedCacheSeconds(rule: rule, globalCacheSeconds: globalCacheSeconds)
        let grant = grantResolution(rule, globalGrantDurationSeconds, timeBoundGrantsEnabled)

        if rule.action == .deny {
            record("action", "deny (deny decisions are never cached)")
            return EvaluationResult(
                decision: .deny,
                matchedProfileKey: profileKey,
                matchedRuleID: rule.id,
                matchedPriority: rule.priority,
                matchedRule: rule,
                resolvedCacheSeconds: 0,
                grantDurationSeconds: nil,
                cacheHit: false,
                satisfyingGrantID: nil,
                noMatch: false,
                reason: "Denied by rule '\(rule.id)' in profile '\(profileKey)'.",
                warnings: warnings,
                trace: trace
            )
        }

        // An unexpired grant for the same user, profile, rule, and exact
        // binary satisfies the request without re-prompting. Grants are pinned
        // to the binary hash observed when the grant was issued, and to the
        // profile that issued them: a rule id reused by another profile (or a
        // grant left over from a profile that was removed) is not the same
        // rule. A rule that says "evaluate every time" is never satisfied by a
        // grant, even one issued before it said so.
        let evaluatesEveryTime = rule.conditions.maxGrantDurationSeconds < 0
        let satisfying = evaluatesEveryTime ? nil : activeGrants
            .filter {
                $0.user == request.user
                    && $0.profileKey == profileKey
                    && $0.ruleID == rule.id
                    && $0.binaryHash.lowercased() == request.identity.sha256.lowercased()
                    && $0.isActive(at: request.timestamp)
            }
            .sorted { $0.grantID.uuidString < $1.grantID.uuidString }
            .first

        if let grant = satisfying {
            record("grant check", "active grant \(grant.grantID) covers this request (cache hit)")
            return EvaluationResult(
                decision: .allow,
                matchedProfileKey: profileKey,
                matchedRuleID: rule.id,
                matchedPriority: rule.priority,
                matchedRule: rule,
                resolvedCacheSeconds: cacheSeconds,
                grantDurationSeconds: nil,
                cacheHit: true,
                satisfyingGrantID: grant.grantID,
                noMatch: false,
                reason: "Allowed by rule '\(rule.id)': active grant \(grant.grantID) covers this request.",
                warnings: warnings,
                trace: trace
            )
        }
        record("grant check", "no active grant covers this request")

        // Justification gate: an allow rule requiring justification cannot
        // resolve silently. Without justification the request must prompt.
        if rule.conditions.requireJustification && !request.justificationProvided {
            record("conditions", "justification required but not provided → prompt")
            return EvaluationResult(
                decision: .prompt,
                matchedProfileKey: profileKey,
                matchedRuleID: rule.id,
                matchedPriority: rule.priority,
                matchedRule: rule,
                resolvedCacheSeconds: cacheSeconds,
                grantDurationSeconds: grant.boundedSeconds,
                cacheHit: false,
                satisfyingGrantID: nil,
                noMatch: false,
                reason: "Rule '\(rule.id)' requires justification; user must be prompted.",
                warnings: warnings,
                trace: trace
            )
        }

        if rule.elevation.type == .prompt {
            record("elevation", "prompt-type rule → user approval required")
            return EvaluationResult(
                decision: .prompt,
                matchedProfileKey: profileKey,
                matchedRuleID: rule.id,
                matchedPriority: rule.priority,
                matchedRule: rule,
                resolvedCacheSeconds: cacheSeconds,
                grantDurationSeconds: grant.boundedSeconds,
                cacheHit: false,
                satisfyingGrantID: nil,
                noMatch: false,
                reason: "Rule '\(rule.id)' requires user approval via the Sentinel prompt.",
                warnings: warnings,
                trace: trace
            )
        }

        if case let .bounded(duration) = grant {
            record("elevation", "silent allow with timed grant (\(duration)s)")
            return EvaluationResult(
                decision: .timedGrant,
                matchedProfileKey: profileKey,
                matchedRuleID: rule.id,
                matchedPriority: rule.priority,
                matchedRule: rule,
                resolvedCacheSeconds: cacheSeconds,
                grantDurationSeconds: duration,
                cacheHit: false,
                satisfyingGrantID: nil,
                noMatch: false,
                reason: "Allowed by rule '\(rule.id)' with a \(duration)s timed grant.",
                warnings: warnings,
                trace: trace
            )
        }

        // Silent allow with no bounded grant: a plain allow on every invocation.
        record("elevation", "silent allow")
        return EvaluationResult(
            decision: .allow,
            matchedProfileKey: profileKey,
            matchedRuleID: rule.id,
            matchedPriority: rule.priority,
            matchedRule: rule,
            resolvedCacheSeconds: cacheSeconds,
            grantDurationSeconds: nil,
            cacheHit: false,
            satisfyingGrantID: nil,
            noMatch: false,
            reason: "Allowed by rule '\(rule.id)' in profile '\(profileKey)'.",
            warnings: warnings,
            trace: trace
        )
    }

    /// How a matched allow rule issues (or doesn't issue) a grant.
    enum GrantResolution: Equatable {
        /// No grant is remembered — a plain allow / prompt-every-time.
        case none
        /// A time-bound grant of this many seconds (already clamped).
        case bounded(Int)

        /// The bounded duration in seconds, or `nil` for `.none`.
        var boundedSeconds: Int? {
            if case let .bounded(seconds) = self { return seconds }
            return nil
        }
    }

    /// Resolves how a matched allow rule grants.
    ///
    /// A grant is remembered only when a duration is configured: the rule's own
    /// `maxGrantDurationSeconds` when set (`> 0`), otherwise the org-wide
    /// `globalGrantDurationSeconds` default. With neither set the result is
    /// `.none` — a plain allow that re-evaluates every invocation. A rule value
    /// below zero (``RuleSchemaConstants/neverGrantSeconds``) is `.none` too,
    /// whatever the org default: "evaluate every time". `0` means "use the
    /// org default".
    ///
    /// The master switch then decides: when `timeBoundGrantsEnabled` is `true`
    /// the grant is `.bounded` (clamped to `maxGrantSeconds`) and expires; when
    /// `false` no grant is remembered at all (`.none`), so a prompt rule asks on
    /// every invocation and a silent rule is a plain allow. Only a time-bound
    /// grant ever lets a prompt rule skip its prompt, and only for its window.
    /// Only allow rules reach here (deny returns earlier).
    static func grantResolution(
        _ rule: Rule,
        _ globalGrantDurationSeconds: Int,
        _ timeBoundGrantsEnabled: Bool
    ) -> GrantResolution {
        guard rule.conditions.maxGrantDurationSeconds >= 0 else { return .none }
        let raw = rule.conditions.maxGrantDurationSeconds > 0
            ? rule.conditions.maxGrantDurationSeconds
            : globalGrantDurationSeconds
        guard raw > 0 else { return .none }
        guard timeBoundGrantsEnabled else { return .none }
        return .bounded(min(raw, RuleSchemaConstants.maxGrantSeconds))
    }

    private static func describe(_ request: ElevationRequest) -> String {
        switch request.kind {
        case let .authURI(uri):
            return "authuri '\(uri)' by \(request.user) (uid \(request.uid)), binary \(request.identity.canonicalPath)"
        case let .sudo(command, argv):
            return "sudo '\(command)' argv[\(argv.count)] by \(request.user) (uid \(request.uid))"
        }
    }
}
