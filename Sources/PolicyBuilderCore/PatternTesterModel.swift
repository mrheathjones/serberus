import Foundation
import Observation
import PrivMgrCore

/// Live Glob/Regex tester. Uses the shared ``PatternMatcher`` —
/// the same primitives the daemon's engine uses — so the preview can never
/// disagree with real evaluation.
@MainActor
@Observable
public final class PatternTesterModel {
    public var matchType: MatchType = .glob
    public var commandPattern: String = "/opt/homebrew/bin/*"
    public var argPattern: String = ""
    public var samplePath: String = "/opt/homebrew/bin/brew"
    public var sampleArgument: String = "install"

    public init() {}

    public enum Verdict: Equatable, Sendable {
        case match
        case noMatch
        case invalidCommandPattern
        case invalidArgPattern
    }

    /// Evaluates the sample against the current pattern + match type.
    public var verdict: Verdict {
        switch PatternMatcher.matchCommand(pattern: commandPattern.isEmpty ? nil : commandPattern,
                                           matchType: matchType, command: samplePath) {
        case .invalidPattern:
            return .invalidCommandPattern
        case .noMatch:
            return .noMatch
        case .matched:
            break
        }
        guard !argPattern.isEmpty else { return .match }
        switch PatternMatcher.matchArgument(pattern: argPattern,
                                            argument: sampleArgument.isEmpty ? nil : sampleArgument) {
        case .invalidPattern: return .invalidArgPattern
        case .noMatch: return .noMatch
        case .matched: return .match
        }
    }
}
