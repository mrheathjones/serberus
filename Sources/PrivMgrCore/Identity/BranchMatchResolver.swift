import Foundation
import Security

/// Predicts which branch of a composed (identity-scoped) right a given
/// client binary resolves against, by evaluating each app branch's compiled
/// code requirement against the binary on disk — the same
/// `SecRequirement` check authd performs, run locally by the Sentinel's
/// Capture at record time.
///
/// This is instrumentation for the open verification question ("did the
/// composed sub-rule for app X actually match, or did authd fall back to
/// native-default because the caller was a mediator like `/usr/libexec/smd`?").
/// It yields a PREDICTION from the client path authd logged; the raw authd /
/// authorizationhost lines that name a branch row remain the source of truth
/// (``CapturedAttempt/branchEvidence``).
public struct BranchMatchResolver: Sendable {
    /// One composed branch to test: the row name authd would reference and
    /// the compiled requirement string it carries.
    public struct Candidate: Sendable, Equatable {
        public let rowName: String
        public let requirement: String
        public init(rowName: String, requirement: String) {
            self.rowName = rowName
            self.requirement = requirement
        }
    }

    /// The fallback verdict when no app branch matches.
    public static let nativeDefault = "native-default"

    /// `(binaryPath, requirement) → satisfied`. Injected so the resolver is
    /// unit-testable without signed fixtures; production uses
    /// ``BranchMatchResolver/securityFrameworkMatcher``.
    public let matcher: @Sendable (String, String) -> Bool

    public init(matcher: @escaping @Sendable (String, String) -> Bool = BranchMatchResolver.securityFrameworkMatcher) {
        self.matcher = matcher
    }

    /// Candidates for `right` from the loaded rule profiles: every
    /// identity-scoped rule targeting it whose requirement compiles. Order is
    /// the composer's (sorted row name) so predictions are deterministic.
    public static func candidates(forRight right: String, in profiles: [RuleProfile]) -> [Candidate] {
        profiles.flatMap(\.rules)
            .filter { $0.type == .authuri && $0.match.authURI == right }
            .compactMap { rule -> Candidate? in
                guard let branch = rule.appIdentity,
                      let requirement = try? CodeRequirementCompiler.compile(teamID: branch.teamID, bundleID: branch.bundleID)
                else { return nil }
                return Candidate(rowName: AuthURICompositionNaming.appRow(for: right, branch: branch), requirement: requirement)
            }
            .sorted { $0.rowName < $1.rowName }
    }

    /// The predicted branch for `clientPath`: the first candidate whose
    /// requirement the binary satisfies, else ``nativeDefault``. Nil when
    /// there are no candidates (the right is not composed) or no client path.
    public func predictedBranch(clientPath: String?, candidates: [Candidate]) -> String? {
        guard !candidates.isEmpty, let clientPath, !clientPath.isEmpty else { return nil }
        for candidate in candidates where matcher(clientPath, candidate.requirement) {
            return candidate.rowName
        }
        return Self.nativeDefault
    }

    /// Lines mentioning any composed branch row — authd's own word on which
    /// sub-rule it evaluated, when it says so.
    public static func evidence(in lines: [String]) -> [String] {
        lines.filter { $0.contains(AuthURICompositionNaming.rowPrefix) }
    }

    /// Production matcher: `SecStaticCodeCreateWithPath` +
    /// `SecStaticCodeCheckValidity` against the compiled requirement. Any
    /// failure (unreadable path, unsigned, requirement mismatch) is `false`.
    public static let securityFrameworkMatcher: @Sendable (String, String) -> Bool = { path, requirement in
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { return false }
        var compiled: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess,
              let compiled else { return false }
        return SecStaticCodeCheckValidity(staticCode, [], compiled) == errSecSuccess
    }
}
