import Foundation

/// Detects rule conflicts within a profile and across profiles.
///
/// Equal-priority allow/deny on the same target inside one profile is a
/// blocking error (a pre-export validation check). Cross-profile overlaps are
/// non-blocking warnings surfaced before export with mandatory
/// acknowledgement.
public struct ConflictDetector: Sendable {
    public init() {}

    // MARK: Intra-profile (blocking)

    /// Returns blocking issues for equal-priority allow/deny pairs targeting
    /// the same right or command pattern within one profile.
    public func intraProfileConflicts(_ profile: RuleProfile) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        let rules = profile.rules
        for i in rules.indices {
            for j in rules.indices where j > i {
                let a = rules[i], b = rules[j]
                guard a.priority == b.priority,
                      a.action != b.action,
                      Self.sameTarget(a, b) else { continue }
                issues.append(ValidationIssue(
                    severity: .error,
                    check: "priority-conflict",
                    ruleID: a.id,
                    message: "Rules '\(a.id)' and '\(b.id)' have equal priority \(a.priority) with opposing actions on the same target"
                ))
            }
        }
        return issues
    }

    // MARK: Cross-profile (warnings)

    /// One detected overlap between two profiles.
    public struct CrossProfileConflict: Sendable, Equatable, CustomStringConvertible {
        public let profileA: String
        public let ruleA: String
        public let profileB: String
        public let ruleB: String
        public let detail: String

        public var description: String {
            "\(profileA)/\(ruleA) ↔ \(profileB)/\(ruleB): \(detail)"
        }
    }

    /// Returns non-blocking overlaps between `profile` and every profile in
    /// `published` that targets the same right or command with a different
    /// action or different effective ordering.
    public func crossProfileConflicts(
        _ profile: RuleProfile,
        against published: [RuleProfile]
    ) -> [CrossProfileConflict] {
        var conflicts: [CrossProfileConflict] = []
        for other in published where other.profileKey != profile.profileKey {
            for a in profile.rules {
                for b in other.rules where Self.sameTarget(a, b) {
                    let detail: String
                    if a.action != b.action {
                        detail = "opposing actions (\(a.action.rawValue) vs \(b.action.rawValue)) on the same target; "
                            + "effective outcome depends on profile priority (\(profile.profilePriority) vs \(other.profilePriority))"
                    } else {
                        detail = "duplicate \(a.action.rawValue) coverage of the same target"
                    }
                    conflicts.append(CrossProfileConflict(
                        profileA: profile.profileKey, ruleA: a.id,
                        profileB: other.profileKey, ruleB: b.id,
                        detail: detail
                    ))
                }
            }
        }
        return conflicts
    }

    // MARK: Target comparison

    /// Two rules target the same thing when their type and match criteria
    /// describe an identical target. Pattern *overlap* (distinct globs that
    /// can match the same path) is intentionally out of scope for V1 —
    /// identical patterns only.
    ///
    /// Identity-scoped authuri rules are the one exception: two rules pinning
    /// DIFFERENT apps on the same right are independent `k-of-n` branches
    /// (``AuthorizationDBManager/desiredCompositions(in:)`` composes N apps
    /// onto one right without interference), not a conflict. The same app
    /// pinned twice, or an identity-scoped rule alongside a plain rewrite of
    /// that right, still targets the same thing — a plain projection silently
    /// wins over composition (``AuthorizationDBManager/skippedByProjection(_:)``),
    /// which is exactly the kind of overlap worth flagging.
    static func sameTarget(_ a: Rule, _ b: Rule) -> Bool {
        guard a.type == b.type else { return false }
        switch a.type {
        case .authuri:
            guard let ua = a.match.authURI, let ub = b.match.authURI, ua == ub else { return false }
            if let brA = a.appIdentity, let brB = b.appIdentity, brA.rowSlug != brB.rowSlug {
                return false
            }
            return true
        case .sudo:
            let typeA = a.match.matchType ?? .exact
            let typeB = b.match.matchType ?? .exact
            guard typeA == typeB else { return false }
            return a.match.commandPattern == b.match.commandPattern
                && a.match.argPattern == b.match.argPattern
        }
    }
}
