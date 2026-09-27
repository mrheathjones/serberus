import Darwin
import Foundation

/// Shared command/argument matching primitives.
///
/// The ``RuleEngine`` and the Policy Builder's live Glob/Regex tester both use
/// these — there is no separate matching logic anywhere, so the tester's
/// preview is guaranteed to agree with real evaluation.
public enum PatternMatcher {
    /// Outcome of matching a pattern. `invalidPattern` distinguishes a regex
    /// that does not compile from a valid pattern that simply does not match,
    /// which the tester surfaces and the engine treats as a skip (no match).
    public enum Outcome: Equatable, Sendable {
        case matched
        case noMatch
        case invalidPattern
    }

    /// Full-string regex match. Returns `nil` when the pattern fails to compile.
    ///
    /// The pattern is wrapped as `\A(?:…)\z` so the engine itself must cover the
    /// whole value. Checking the leftmost match's range instead is wrong for
    /// alternations: `boot|bootout` finds `boot` in `bootout` and stops, so a
    /// deny written that way would miss `bootout`. `\z` (not `$`, which ICU also
    /// matches before a final newline) keeps `recon\n` from fully matching
    /// `^recon$`. A pattern that is already anchored is unaffected. The
    /// unwrapped pattern is compiled first so an invalid pattern is reported as
    /// invalid, not as a wrapper artefact.
    public static func fullRegexMatch(pattern: String, value: String) -> Bool? {
        guard (try? NSRegularExpression(pattern: pattern)) != nil,
              let regex = try? NSRegularExpression(pattern: "\\A(?:" + pattern + ")\\z") else { return nil }
        let range = NSRange(value.startIndex..., in: value)
        return regex.firstMatch(in: value, range: range) != nil
    }

    /// Matches a canonical command path against `pattern` under `matchType`.
    /// A `nil` pattern matches nothing except `.any`.
    public static func matchCommand(pattern: String?, matchType: MatchType, command: String) -> Outcome {
        switch matchType {
        case .any:
            return .matched
        case .exact:
            guard let pattern else { return .noMatch }
            return pattern == command ? .matched : .noMatch
        case .glob:
            guard let pattern else { return .noMatch }
            return fnmatch(pattern, command, 0) == 0 ? .matched : .noMatch
        case .regex:
            guard let pattern else { return .noMatch }
            guard let matched = fullRegexMatch(pattern: pattern, value: command) else { return .invalidPattern }
            return matched ? .matched : .noMatch
        case .prefixRegex:
            guard let pattern else { return .noMatch }
            // Literal path prefix at a path-component boundary.
            return (command == pattern || command.hasPrefix(pattern + "/")) ? .matched : .noMatch
        }
    }

    /// Matches the first argument against a regular expression. A `nil`
    /// argument never matches (an argument-constrained rule fails closed on an
    /// argument-less invocation).
    public static func matchArgument(pattern: String, argument: String?) -> Outcome {
        guard let argument else { return .noMatch }
        guard let matched = fullRegexMatch(pattern: pattern, value: argument) else { return .invalidPattern }
        return matched ? .matched : .noMatch
    }
}
