import Foundation

/// In-memory decision cache for sudo session caching.
///
/// The daemon ``GrantStore`` is the sole durable cache mechanism; this actor
/// holds the short-lived per-session allow decisions whose TTL comes from
/// ``RuleEngine/resolvedCacheSeconds(rule:globalCacheSeconds:)``:
/// per-rule `cacheSeconds` when non-nil, else global `sudoCacheSeconds`,
/// else the hardcoded default of 0 (no caching).
///
/// Deny decisions are never cached, regardless of `cacheSeconds`.
public actor SessionGrantCache {
    /// Cache key: one user + one rule + one exact binary + one exact argv.
    ///
    /// Argv is part of the key, not metadata: a cached allow for
    /// `defaults read …` must never answer `defaults delete …` — different
    /// arguments can match a different rule (including a higher-priority
    /// deny), so anything but this exact argument vector is a miss and takes
    /// the full evaluation path.
    public struct Key: Hashable, Sendable {
        public let user: String
        public let ruleID: String
        public let binaryHash: String
        /// The exact argv the decision was evaluated for (may be empty).
        public let argv: [String]

        public init(user: String, ruleID: String, binaryHash: String, argv: [String] = []) {
            self.user = user
            self.ruleID = ruleID
            self.binaryHash = binaryHash.lowercased()
            self.argv = argv
        }
    }

    /// A command-scoped cache hit: the allow-family decision plus the rule
    /// that produced it, so the daemon can write the decision-log entry a
    /// cache hit still requires (the audit trail never skips a decision).
    public struct CommandHit: Sendable, Equatable {
        public let decision: Decision
        public let ruleID: String

        public init(decision: Decision, ruleID: String) {
            self.decision = decision
            self.ruleID = ruleID
        }
    }

    private struct Entry {
        let decision: Decision
        let storedAt: Date
        let expiresAt: Date
        /// The same expiry on the continuous clock, which setting the date and
        /// time cannot move. Either clock expiring ends the entry.
        let continuousDeadline: ContinuousClock.Instant
        /// Canonical command path recorded at store time. Command-scoped
        /// lookups require it; `nil` entries are reachable by ``Key`` only.
        let canonicalPath: String?
    }

    private var entries: [Key: Entry] = [:]

    public init() {}

    /// Caches an allow-family decision for `ttlSeconds`.
    ///
    /// Deny decisions and zero/negative TTLs are silently not cached —
    /// callers may pass every decision through without pre-filtering.
    /// `canonicalPath` (the canonicalized sudo command) makes the entry
    /// reachable by ``lookup(user:canonicalPath:binaryHash:argv:now:)``.
    public func store(decision: Decision, key: Key, canonicalPath: String? = nil, ttlSeconds: Int, now: Date) {
        guard decision != .deny, ttlSeconds > 0 else { return }
        let clamped = min(ttlSeconds, RuleSchemaConstants.maxCacheSeconds)
        entries[key] = Entry(
            decision: decision,
            storedAt: now,
            expiresAt: now.addingTimeInterval(TimeInterval(clamped)),
            continuousDeadline: ContinuousClock.now.advanced(by: .seconds(clamped)),
            canonicalPath: canonicalPath
        )
    }

    /// Whether `entry` is still live at `now`: the wall clock is at or after
    /// the store time and before the expiry (a clock set back cannot revive or
    /// stretch it), and the continuous clock has not passed its deadline.
    private static func isLive(_ entry: Entry, now: Date) -> Bool {
        now >= entry.storedAt && now < entry.expiresAt && ContinuousClock.now < entry.continuousDeadline
    }

    /// Returns the cached decision for `key` when unexpired, else `nil`.
    public func lookup(key: Key, now: Date) -> Decision? {
        guard let entry = entries[key] else { return nil }
        guard Self.isLive(entry, now: now) else {
            entries.removeValue(forKey: key)
            return nil
        }
        return entry.decision
    }

    /// The daemon's pre-evaluation probe: the unexpired allow-family decision
    /// cached for this exact user + canonical command path + binary content +
    /// exact argv, else `nil`.
    ///
    /// The canonical path is part of the match, not just the binary hash — a
    /// byte-identical binary copied to a different path must never ride a
    /// cached allow, because no rule was ever evaluated for that path.
    /// Argv must match exactly for the same reason: different arguments can
    /// resolve to a different rule (including a higher-priority deny), so a
    /// mismatch is a miss and the request takes the full evaluation path.
    public func lookup(user: String, canonicalPath: String, binaryHash: String, argv: [String], now: Date) -> CommandHit? {
        guard !canonicalPath.isEmpty, !binaryHash.isEmpty else { return nil }
        let hash = binaryHash.lowercased()
        for (key, entry) in entries {
            guard key.user == user,
                  key.binaryHash == hash,
                  key.argv == argv,
                  entry.canonicalPath == canonicalPath else { continue }
            guard Self.isLive(entry, now: now) else {
                entries.removeValue(forKey: key)
                continue
            }
            return CommandHit(decision: entry.decision, ruleID: key.ruleID)
        }
        return nil
    }

    /// Removes every entry (kill switch / policy reload).
    public func removeAll() {
        entries.removeAll()
    }

    /// Removes entries for one user (per-user threat signal).
    public func removeAll(for user: String) {
        entries = entries.filter { $0.key.user != user }
    }

    /// Removes entries produced by one rule (policy reload diff).
    public func removeAll(forRuleID ruleID: String) {
        entries = entries.filter { $0.key.ruleID != ruleID }
    }

    /// Drops expired entries. The daemon calls this periodically.
    public func pruneExpired(now: Date) {
        entries = entries.filter { Self.isLive($0.value, now: now) }
    }

    /// Current live entry count (after pruning expired entries).
    public func count(now: Date) -> Int {
        pruneExpired(now: now)
        return entries.count
    }
}
