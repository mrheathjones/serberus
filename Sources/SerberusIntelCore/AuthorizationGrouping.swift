import Foundation

/// One authorization attempt: a single right, evaluated once by authd.
///
/// authd narrates a decision across several lines sharing an `(engine N)` id —
/// credential validation, mechanism runs, then a verdict. Showing each line as
/// its own row buries the signal (one real attempt produced 5 near-identical
/// rows in testing). An attempt is `(engine, right)`, **not engine alone**:
/// measured over 24h, 9 of 35 engines touched more than one distinct right
/// (e.g. `system.preferences` succeeding while `system.preferences.security`
/// failed in the same engine), so grouping by engine alone would merge two
/// different decisions into one misleading row.
public struct AuthorizationAttempt: Sendable, Identifiable, Equatable {
    public let id: String
    /// The right being authorized.
    public let right: String
    /// authd's engine id, when the lines carried one.
    public let engine: String?
    /// Resolved verdict for this right (see ``AuthorizationGrouper``).
    public let outcome: AuthorizationOutcome
    /// Requesting process, when any line named one.
    public let client: String?
    /// The authd lines that make up this attempt, in time order.
    public let lines: [LogEntry]
    /// True when the verdict was inherited from an engine-level failure rather
    /// than stated on this right's own line. Surfaced so an inferred verdict is
    /// never presented as though authd said it directly.
    public let verdictInherited: Bool

    public var date: Date { lines.first?.date ?? .distantPast }
    public var timestamp: String { lines.first?.timestamp ?? "" }

    public init(
        id: String, right: String, engine: String?, outcome: AuthorizationOutcome,
        client: String?, lines: [LogEntry], verdictInherited: Bool
    ) {
        self.id = id
        self.right = right
        self.engine = engine
        self.outcome = outcome
        self.client = client
        self.lines = lines
        self.verdictInherited = verdictInherited
    }
}

/// Accumulator for one `(engine, right)` attempt while grouping.
private struct AttemptBucket {
    let right: String
    let engine: String?
    var lines: [LogEntry] = []
    var explicitOutcome: AuthorizationOutcome?
    var client: String?
    var lastDate: Date = .distantPast
}

/// Collapses authd lines into one row per authorization attempt.
public enum AuthorizationGrouper {
    /// A line naming no engine is folded into an existing group for the *same*
    /// right whose last line is within this window. The
    /// `UID N authenticated … for right 'X'` shape carries no `(engine N)`
    /// (3 of 73 right-naming lines measured) but is emitted in the same instant
    /// as the engine's other lines, so this reunites it instead of spawning a
    /// duplicate row.
    static let orphanAttachWindow: TimeInterval = 5

    public static func group(_ entries: [LogEntry]) -> [AuthorizationAttempt] {
        let ordered = entries.sorted { $0.date < $1.date }

        // Engine-level failure signals first: a failure line often names no
        // right, so it can only be applied once the whole engine is known.
        var failedEngines = Set<String>()
        for entry in ordered {
            let info = AuthorizationParser.info(from: entry.message)
            if info.statesEngineFailure, let engine = info.engine {
                failedEngines.insert(engine)
            }
        }

        var buckets: [String: AttemptBucket] = [:]
        var order: [String] = []

        for entry in ordered {
            let info = AuthorizationParser.info(from: entry.message)
            guard let right = info.right else { continue }

            let key: String
            if let engine = info.engine {
                key = "\(engine)|\(right)"
            } else if let recent = attachableKey(
                right: right, at: entry.date, buckets: buckets, order: order
            ) {
                key = recent
            } else {
                // No engine and nothing to attach to — its own attempt.
                key = "orphan|\(right)|\(entry.timestamp)"
            }

            if buckets[key] == nil {
                buckets[key] = AttemptBucket(right: right, engine: info.engine)
                order.append(key)
            }
            buckets[key]?.lines.append(entry)
            buckets[key]?.lastDate = entry.date
            if let client = info.client, buckets[key]?.client == nil {
                buckets[key]?.client = client
            }
            // A line stating a verdict for this right is authoritative.
            if let outcome = info.outcome, outcome != .requested {
                buckets[key]?.explicitOutcome = outcome
            }
        }

        return order.compactMap { key -> AuthorizationAttempt? in
            guard let bucket = buckets[key] else { return nil }
            let engineFailed = bucket.engine.map(failedEngines.contains) ?? false

            let outcome: AuthorizationOutcome
            let inherited: Bool
            if let explicit = bucket.explicitOutcome {
                outcome = explicit
                inherited = false
            } else if engineFailed {
                // The engine failed and this right never got its own success
                // line — so this is the right that could not be satisfied.
                outcome = .denied
                inherited = true
            } else {
                outcome = .requested
                inherited = false
            }
            return AuthorizationAttempt(
                id: key, right: bucket.right, engine: bucket.engine, outcome: outcome,
                client: bucket.client, lines: bucket.lines, verdictInherited: inherited
            )
        }
    }

    /// Newest existing bucket for **exactly** this right whose last line is
    /// within ``orphanAttachWindow``.
    ///
    /// Compares `bucket.right` rather than substring-matching the key: a key
    /// like `12009|system.preferences.security` *contains* the string
    /// `|system.preferences`, so a substring test would wrongly fold a
    /// `system.preferences` orphan into a `system.preferences.security` attempt.
    private static func attachableKey(
        right: String,
        at date: Date,
        buckets: [String: AttemptBucket],
        order: [String]
    ) -> String? {
        for key in order.reversed() {
            guard let bucket = buckets[key], bucket.right == right else { continue }
            guard date.timeIntervalSince(bucket.lastDate) <= orphanAttachWindow else { return nil }
            return key
        }
        return nil
    }
}
