import Foundation

/// Result of one simulation run.
public struct SimulationResult: Sendable, Equatable {
    public let decision: Decision
    public let matchedProfile: String?
    public let matchedRule: String?
    public let priority: Int?
    /// Human-readable cache behavior, e.g. `"cache 300s"` / `"no caching"`.
    public let cacheBehavior: String
    public let grantDuration: TimeInterval?
    public let reason: String
    public let warnings: [String]
    /// Full step-by-step explanation.
    public let evaluationTrace: [TraceStep]
}

/// Policy Builder / CLI Decision Simulator.
///
/// Uses the exact same ``RuleEngine`` code path as the daemon — the only
/// work done here is translating ``SimulationContext`` into an
/// ``ElevationRequest`` and the engine's result into a ``SimulationResult``.
/// There is no duplicate or divergent simulation logic anywhere.
public struct DecisionSimulator: Sendable {
    private let engine: RuleEngine
    private let perAppPinsEnabled: Bool

    /// - Parameter perAppPinsEnabled: ``AuthURIIdentityScope/perAppPinsEnabled``
    ///   in production (false in 0.9.0): a per-app rule then never
    ///   matches, so the simulator never reports it as allowing. Tests inject
    ///   `true` to exercise the engine's Team ID pin.
    public init(perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled) {
        self.perAppPinsEnabled = perAppPinsEnabled
        self.engine = RuleEngine(perAppPinsEnabled: perAppPinsEnabled)
    }

    /// Simulates one request against `profiles`.
    ///
    /// - Parameters:
    ///   - context: Synthetic input. Exactly one of `authURI`/`sudoCommand`
    ///     must be set.
    ///   - profiles: Profiles to evaluate (typically drafts in the Policy
    ///     Builder, or live managed-pref profiles for `serberus simulate`).
    ///   - globalCacheSeconds: `sudoCacheSeconds` to assume for TTL resolution.
    ///   - globalGrantDurationSeconds: `defaultGrantDurationMinutes × 60` to
    ///     assume as the org-wide default timed-grant duration for rules that
    ///     don't set their own. `0` = no global default.
    ///   - timeBoundGrantsEnabled: The `timeBoundGrantsEnabled` master switch.
    ///     `false` makes grants indefinite (durations ignored).
    /// - Throws: ``PolicyError/invalidEvaluationContext(reason:)``
    public func simulate(
        context: SimulationContext,
        profiles: [RuleProfile],
        globalCacheSeconds: Int = 0,
        globalGrantDurationSeconds: Int = 0,
        timeBoundGrantsEnabled: Bool = true
    ) throws -> SimulationResult {
        let kind: ElevationRequestKind
        switch (context.authURI, context.sudoCommand) {
        case let (.some(uri), nil):
            kind = .authURI(uri)
        case let (nil, .some(command)):
            // Simulation input: existence on this machine is not required,
            // but the path must still be absolute and unambiguous.
            let canonical = try PathCanonicalizer().canonicalize(command, existence: .allowMissing)
            kind = .sudo(command: canonical, argv: context.argv)
        case (nil, nil):
            throw PolicyError.invalidEvaluationContext(reason: "set exactly one of authURI or sudoCommand (both nil)")
        case (.some, .some):
            throw PolicyError.invalidEvaluationContext(reason: "set exactly one of authURI or sudoCommand (both set)")
        }

        let executablePath = try PathCanonicalizer()
            .canonicalize(context.executablePath, existence: .allowMissing)

        let request = ElevationRequest(
            user: context.user,
            uid: context.uid,
            kind: kind,
            identity: BinaryIdentity(
                canonicalPath: executablePath,
                teamID: context.teamID.isEmpty ? nil : context.teamID,
                sha256: context.binaryHash,
                signingStatus: context.signingStatus
            ),
            justificationProvided: context.justificationProvided,
            justificationText: context.justificationText,
            timestamp: context.currentTime
        )

        let result = engine.evaluate(
            request: request,
            profiles: profiles,
            globalCacheSeconds: globalCacheSeconds,
            globalGrantDurationSeconds: globalGrantDurationSeconds,
            timeBoundGrantsEnabled: timeBoundGrantsEnabled,
            activeGrants: context.activeGrants.map { $0.snapshot() }
        )

        let cacheBehavior: String
        if result.decision == .deny {
            cacheBehavior = "deny decisions are never cached"
        } else if result.resolvedCacheSeconds > 0 {
            cacheBehavior = "cache \(result.resolvedCacheSeconds)s"
        } else {
            cacheBehavior = "no caching"
        }

        var warnings = result.warnings
        if case let .authURI(uri) = kind {
            warnings.append(contentsOf: Self.identityCaveats(right: uri, profiles: profiles,
                                                             perAppPinsEnabled: perAppPinsEnabled))
        }

        return SimulationResult(
            decision: result.decision,
            matchedProfile: result.matchedProfileKey,
            matchedRule: result.matchedRuleID,
            priority: result.matchedPriority,
            cacheBehavior: cacheBehavior,
            grantDuration: result.grantDurationSeconds.map(TimeInterval.init),
            reason: result.reason,
            warnings: warnings,
            evaluationTrace: result.trace
        )
    }

    /// Caveats for a right that carries identity-scoped (per-app) rules.
    ///
    /// The simulator runs the daemon's engine, but per-app authURI branches
    /// are enforced by **authd** matching a compiled code requirement against
    /// the live caller — something no offline engine can replay. So the
    /// simulator validates the requirement string's SYNTAX only (the same
    /// `SecRequirementCreateWithString` gate the daemon uses before writing)
    /// and says so; a provisional right gets the further caveat that its
    /// eligibility itself is unconfirmed.
    static func identityCaveats(
        right: String,
        profiles: [RuleProfile],
        registry: AuthURIIdentityScopeRegistry = .current,
        perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled
    ) -> [String] {
        let branches = profiles.flatMap(\.rules)
            .filter { $0.type == .authuri && $0.match.authURI == right }
            .compactMap(\.appIdentity)
        guard !branches.isEmpty else { return [] }
        // Per-app rules never match and are never composed.
        guard perAppPinsEnabled else {
            return ["Per-app branch(es) on '\(right)' ignored: \(AuthURIIdentityScope.disabledSkipReason)."]
        }

        var caveats: [String] = []
        for branch in branches {
            do {
                let requirement = try CodeRequirementCompiler.compileAndValidate(branch)
                caveats.append("Per-app branch \(branch.bundleID) (\(branch.teamID)): requirement syntax valid — `\(requirement)`. Only the SYNTAX is checked here; whether the live caller's signature matches is decided by authd at request time, not by this simulator.")
            } catch {
                caveats.append("Per-app branch \(branch.bundleID) (\(branch.teamID)): requirement REJECTED — \(error.localizedDescription). The daemon will refuse to compose this branch.")
            }
        }
        let decision = registry.authoringDecision(for: right)
        switch decision.state {
        case .provisional:
            caveats.append("'\(right)' is \(decision.state.label): identity scoping on this right is unconfirmed, so even a syntactically valid branch may never match. Enforced as authored; under test on Mac(s) \(decision.entry?.allowedSerials.sorted().joined(separator: ", ") ?? "—").")
        case .confirmedIneligible, .unknown:
            caveats.append(decision.rejectionReason ?? "'\(right)' cannot be identity-scoped.")
        case .verifiedEligible:
            if let confirm = decision.entry?.authorMustConfirm {
                caveats.append("Verified right, conditional on the app: \(confirm)")
            }
        }
        return caveats
    }
}
