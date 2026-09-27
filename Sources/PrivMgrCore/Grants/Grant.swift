import Foundation

/// A persisted elevation grant.
///
/// Grants survive reboot, daemon restart, crash, and software upgrade until
/// expired or revoked. The database never stores passwords, tokens, Jamf
/// credentials, or authorization credentials.
public struct Grant: Codable, Sendable, Equatable, Identifiable {
    public var id: UUID { grantID }

    /// Primary key.
    public let grantID: UUID
    /// User the grant was issued to.
    public let user: String
    /// UID of that user at issue time.
    public let uid: uid_t
    /// Rule that produced the grant.
    public let ruleID: String
    /// Profile the rule belongs to.
    public let profileKey: String
    /// Team ID of the covered binary at issue time ("" when unsigned).
    public let teamID: String
    /// SHA-256 of the covered binary at issue time.
    public let binaryHash: String
    /// Canonical path of the covered binary.
    public let canonicalPath: String
    /// Optional argv constraint carried from the rule.
    public let argvPattern: String?
    /// Issue timestamp.
    public let grantedAt: Date
    /// Expiry. `nil` = no expiry.
    public let expiresAt: Date?
    /// Revocation timestamp. `nil` = not revoked.
    public let revokedAt: Date?
    /// Policy version in force when the grant was issued.
    public let policyVersion: String
    /// Row schema version.
    public let schemaVersion: Int
    /// `kern.bootsessionuuid` of the boot in which ``continuousDeadlineNanos``
    /// was taken. `nil` for a grant with no expiry, and for rows written before
    /// the store recorded it (those expire on the wall clock alone).
    public let bootSessionID: String?
    /// The expiry on the continuous clock (`mach_continuous_time`, in
    /// nanoseconds), which the wall clock cannot move. Meaningful only while
    /// ``bootSessionID`` is the current boot session. See ``hasExpired(at:monotonic:)``.
    public let continuousDeadlineNanos: UInt64?
    /// The account's `GeneratedUID` at issue time, recorded for JIT admin
    /// grants so a uid later reused by a DIFFERENT account is not mistaken for
    /// a rename of the one Serberus promoted. `nil` for other grants and for
    /// rows written before the store recorded it.
    public let generatedUID: String?

    public init(
        grantID: UUID = UUID(),
        user: String,
        uid: uid_t,
        ruleID: String,
        profileKey: String,
        teamID: String,
        binaryHash: String,
        canonicalPath: String,
        argvPattern: String? = nil,
        grantedAt: Date,
        expiresAt: Date?,
        revokedAt: Date? = nil,
        policyVersion: String,
        schemaVersion: Int = GrantStoreSchema.currentVersion,
        bootSessionID: String? = nil,
        continuousDeadlineNanos: UInt64? = nil,
        generatedUID: String? = nil
    ) {
        self.grantID = grantID
        self.user = user
        self.uid = uid
        self.ruleID = ruleID
        self.profileKey = profileKey
        self.teamID = teamID
        self.binaryHash = binaryHash
        self.canonicalPath = canonicalPath
        self.argvPattern = argvPattern
        self.grantedAt = grantedAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.policyVersion = policyVersion
        self.schemaVersion = schemaVersion
        self.bootSessionID = bootSessionID
        self.continuousDeadlineNanos = continuousDeadlineNanos
        self.generatedUID = (generatedUID?.isEmpty ?? true) ? nil : generatedUID
    }

    /// Whether the grant is active (not revoked, not expired) at `date`.
    ///
    /// `monotonic` is the current continuous-clock reading; it defaults to the
    /// live clock. See ``hasExpired(at:monotonic:)`` for what counts as expired.
    public func isActive(at date: Date, monotonic: MonotonicInstant? = MonotonicClock.now()) -> Bool {
        revokedAt == nil && !hasExpired(at: date, monotonic: monotonic)
    }

    /// Whether the grant's window is over at `date`, regardless of revocation.
    ///
    /// The wall clock can be set by anyone who can open Date & Time, so it is
    /// not trusted to keep a window open:
    /// - a `date` before ``grantedAt`` means the clock was set back past the
    ///   issue time, and the grant counts as expired;
    /// - past ``expiresAt`` on the wall clock, it is expired;
    /// - in the SAME boot session it was issued in, it is also expired once the
    ///   continuous clock passes ``continuousDeadlineNanos``, whatever the wall
    ///   clock says.
    ///
    /// Either clock expiring is enough. A grant from another boot session (the
    /// continuous clock restarts at boot) or one without a continuous deadline
    /// falls back to the wall clock plus the ``grantedAt`` check.
    public func hasExpired(at date: Date, monotonic: MonotonicInstant? = MonotonicClock.now()) -> Bool {
        if date < grantedAt { return true }
        guard let expiresAt else { return false }
        if date >= expiresAt { return true }
        if let remaining = continuousRemainingSeconds(monotonic: monotonic), remaining <= 0 { return true }
        return false
    }

    /// Seconds left in the window at `date`: the smaller of what the wall clock
    /// and (same boot session only) the continuous clock say. `nil` for a grant
    /// with no expiry; `0` once ``hasExpired(at:monotonic:)`` holds. Used to
    /// re-arm a timer after a restart without trusting the wall clock alone.
    public func remainingSeconds(at date: Date, monotonic: MonotonicInstant? = MonotonicClock.now()) -> TimeInterval? {
        guard let expiresAt else { return nil }
        if hasExpired(at: date, monotonic: monotonic) { return 0 }
        var remaining = expiresAt.timeIntervalSince(date)
        if let continuous = continuousRemainingSeconds(monotonic: monotonic) {
            remaining = min(remaining, continuous)
        }
        return max(0, remaining)
    }

    /// Continuous-clock seconds left, or nil when there is no deadline or it
    /// belongs to another boot session.
    private func continuousRemainingSeconds(monotonic: MonotonicInstant?) -> TimeInterval? {
        guard let deadline = continuousDeadlineNanos, let bootSessionID,
              let monotonic, monotonic.bootSessionID == bootSessionID else { return nil }
        if monotonic.nanoseconds >= deadline { return 0 }
        return TimeInterval(deadline - monotonic.nanoseconds) / 1_000_000_000
    }

    /// This grant with a continuous-clock deadline taken at `instant`: the
    /// window's length (``expiresAt`` − ``grantedAt``) from now on the
    /// continuous clock. Unchanged when the grant has no expiry, already
    /// carries a deadline, or no clock reading is available.
    public func stampingContinuousDeadline(at instant: MonotonicInstant?) -> Grant {
        guard let expiresAt, continuousDeadlineNanos == nil, let instant else { return self }
        let seconds = max(0, expiresAt.timeIntervalSince(grantedAt))
        let nanos = seconds >= Double(UInt64.max / 2) / 1_000_000_000
            ? UInt64.max / 2
            : UInt64(seconds * 1_000_000_000)
        return Grant(
            grantID: grantID, user: user, uid: uid, ruleID: ruleID, profileKey: profileKey,
            teamID: teamID, binaryHash: binaryHash, canonicalPath: canonicalPath,
            argvPattern: argvPattern, grantedAt: grantedAt, expiresAt: expiresAt,
            revokedAt: revokedAt, policyVersion: policyVersion, schemaVersion: schemaVersion,
            bootSessionID: instant.bootSessionID,
            continuousDeadlineNanos: instant.nanoseconds &+ nanos,
            generatedUID: generatedUID
        )
    }

    /// This grant with a continuous-clock deadline for the boot session of
    /// `instant`, or nil when none is needed: the grant is revoked, has no
    /// expiry, or already carries a deadline taken in that boot session.
    ///
    /// For a row from an earlier boot, or one migrated without the columns, the
    /// deadline is what is left of the window by the wall clock at `now`,
    /// clamped to the window's original length, from `instant` on. It can only
    /// shorten the grant: the signed ``expiresAt`` still applies, and either
    /// clock expiring is enough. From then on, setting the wall clock back in
    /// this boot session cannot stretch it.
    public func restampingContinuousDeadline(at instant: MonotonicInstant, now: Date) -> Grant? {
        guard revokedAt == nil, let expiresAt else { return nil }
        if continuousDeadlineNanos != nil, bootSessionID == instant.bootSessionID { return nil }
        let window = max(0, expiresAt.timeIntervalSince(grantedAt))
        let remaining = min(max(0, expiresAt.timeIntervalSince(now)), window)
        let nanos = remaining >= Double(UInt64.max / 2) / 1_000_000_000
            ? UInt64.max / 2
            : UInt64(remaining * 1_000_000_000)
        return Grant(
            grantID: grantID, user: user, uid: uid, ruleID: ruleID, profileKey: profileKey,
            teamID: teamID, binaryHash: binaryHash, canonicalPath: canonicalPath,
            argvPattern: argvPattern, grantedAt: grantedAt, expiresAt: expiresAt,
            revokedAt: revokedAt, policyVersion: policyVersion, schemaVersion: schemaVersion,
            bootSessionID: instant.bootSessionID,
            continuousDeadlineNanos: instant.nanoseconds &+ nanos,
            generatedUID: generatedUID
        )
    }

    /// This (indefinite) grant with an expiry `seconds` from `now`, and a
    /// continuous-clock deadline the same distance from `instant` when a
    /// reading is available. Used when time-bound grants are switched back on.
    public func bounding(seconds: Int, now: Date, instant: MonotonicInstant?) -> Grant {
        let window = TimeInterval(max(0, seconds))
        return Grant(
            grantID: grantID, user: user, uid: uid, ruleID: ruleID, profileKey: profileKey,
            teamID: teamID, binaryHash: binaryHash, canonicalPath: canonicalPath,
            argvPattern: argvPattern, grantedAt: grantedAt, expiresAt: now.addingTimeInterval(window),
            revokedAt: revokedAt, policyVersion: policyVersion, schemaVersion: schemaVersion,
            bootSessionID: instant?.bootSessionID,
            continuousDeadlineNanos: instant.map { $0.nanoseconds &+ UInt64(window * 1_000_000_000) },
            generatedUID: generatedUID
        )
    }

    /// Point-in-time snapshot for rule-engine evaluation.
    public func snapshot() -> GrantSnapshot {
        GrantSnapshot(
            grantID: grantID,
            user: user,
            ruleID: ruleID,
            profileKey: profileKey,
            canonicalPath: canonicalPath,
            binaryHash: binaryHash,
            expiresAt: expiresAt
        )
    }

    /// Canonical byte string the row HMAC is computed over. Field order is
    /// fixed; timestamps use ISO8601 with fractional seconds.
    ///
    /// ``bootSessionID`` and ``continuousDeadlineNanos`` are deliberately NOT
    /// signed. Leaving them out keeps every existing row verifiable and keeps
    /// rows written now verifiable by older builds. It costs nothing: the
    /// continuous deadline can only make a grant expire EARLIER than the signed
    /// ``expiresAt`` (either clock expiring is enough), so rewriting or clearing
    /// the unsigned columns can at most fall back to the signed wall-clock
    /// window. Writing the database needs root in any case.
    ///
    /// ``generatedUID`` IS signed, but only when present: it is appended as a
    /// trailing field, so a row without one (every row written before schema 3,
    /// and every non-JIT grant) produces exactly the message it always did and
    /// still verifies. It is signed because it decides whether a demotion may
    /// skip an account ("the uid was reused by someone else"); an unsigned value
    /// could be edited to make the daemon leave a promoted user in `admin`.
    /// Clearing or changing it on a signed row fails verification, and the row
    /// is then handled as an unverifiable JIT row (a demotion candidate).
    func integrityMessage() -> Data {
        let fields: [String] = [
            grantID.uuidString,
            user,
            String(uid),
            ruleID,
            profileKey,
            teamID,
            binaryHash,
            canonicalPath,
            argvPattern ?? "",
            ISO8601.string(from: grantedAt),
            expiresAt.map(ISO8601.string(from:)) ?? "",
            revokedAt.map(ISO8601.string(from:)) ?? "",
            policyVersion,
            String(schemaVersion),
        ] + (generatedUID.map { [$0] } ?? [])
        return Data(fields.joined(separator: "\u{1f}").utf8)
    }
}

/// Brings stored grants in line with the policy being served. Run by the
/// daemon at startup and on every policy reload it adopts.
///
/// - A grant whose (profile key, rule id) is no longer in the policy is
///   revoked. The rule engine matches grants on both, so such a grant could
///   not be used, but left in place it would come back to life if the same
///   profile (or a new version keeping the id) were scoped again.
/// - A grant whose rule now says "evaluate every time" (a negative
///   `maxGrantDurationSeconds`) is revoked.
/// - No grant may be indefinite. One with no expiry (issued by an older
///   version while the switch was off) is revoked while `timeBoundGrantsEnabled`
///   is off, since only a time-bound grant may skip a prompt; while it is on,
///   it is given the duration the rule would issue now (its own, else the org
///   default), counted from now, or revoked when that is no grant at all. This
///   is checked on every run, not only on a change of the switch.
///
/// JIT admin grants are left alone: they are the JIT manager's, and one may
/// be revoked only after its user left `admin`.
public enum GrantPolicyAlignment {
    public struct RuleKey: Hashable, Sendable {
        public let profileKey: String
        public let ruleID: String

        public init(profileKey: String, ruleID: String) {
            self.profileKey = profileKey
            self.ruleID = ruleID
        }
    }

    public struct Plan: Sendable, Equatable {
        /// Grants to revoke.
        public var revoke: [UUID] = []
        /// Indefinite grants to bound, with the duration (seconds from now).
        public var bound: [UUID: Int] = [:]

        public init() {}

        public var isEmpty: Bool { revoke.isEmpty && bound.isEmpty }
    }

    /// The changes for `grants` under `rules` (every rule in the served policy,
    /// by profile key and id).
    public static func plan(
        grants: [Grant],
        rules: [RuleKey: Rule],
        timeBoundGrantsEnabled: Bool,
        defaultGrantSeconds: Int
    ) -> Plan {
        var plan = Plan()
        for grant in grants where grant.revokedAt == nil && !JITAdminGrant.isJITGrant(grant) {
            guard let rule = rules[RuleKey(profileKey: grant.profileKey, ruleID: grant.ruleID)],
                  rule.conditions.maxGrantDurationSeconds >= 0 else {
                plan.revoke.append(grant.grantID)
                continue
            }
            guard grant.expiresAt == nil else { continue }
            // A grant with no expiry. Time-bound grants off: nothing may skip a
            // prompt beyond a time-bound window, so it is revoked (prompt rules
            // ask every time again). On: it gets the rule's duration, else the
            // org default, else it is revoked.
            guard timeBoundGrantsEnabled else {
                plan.revoke.append(grant.grantID)
                continue
            }
            switch RuleEngine.grantResolution(rule, defaultGrantSeconds, true) {
            case let .bounded(seconds) where seconds > 0:
                plan.bound[grant.grantID] = seconds
            default:
                plan.revoke.append(grant.grantID)
            }
        }
        return plan
    }
}

/// A reading of the continuous clock, tied to the boot session it was taken in.
public struct MonotonicInstant: Sendable, Equatable {
    /// `kern.bootsessionuuid`: changes on every boot, so a reading can only be
    /// compared with another from the same boot.
    public let bootSessionID: String
    /// `mach_continuous_time` in nanoseconds. Keeps counting through sleep and
    /// is not affected by setting the date and time.
    public let nanoseconds: UInt64

    public init(bootSessionID: String, nanoseconds: UInt64) {
        self.bootSessionID = bootSessionID
        self.nanoseconds = nanoseconds
    }
}

/// The live continuous clock.
public enum MonotonicClock {
    /// The current reading, or nil when the boot session cannot be read (the
    /// wall clock is then the only clock grants are checked against).
    public static func now() -> MonotonicInstant? {
        guard let bootSessionID = currentBootSessionID, let nanoseconds = continuousNanoseconds() else { return nil }
        return MonotonicInstant(bootSessionID: bootSessionID, nanoseconds: nanoseconds)
    }

    /// The boot session never changes while a process runs, so it is read once.
    public static let currentBootSessionID: String? = {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return nil }
        let value = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        return value.isEmpty ? nil : value
    }()

    private static let timebase: mach_timebase_info_data_t? = {
        var info = mach_timebase_info_data_t()
        guard mach_timebase_info(&info) == KERN_SUCCESS, info.denom != 0 else { return nil }
        return info
    }()

    private static func continuousNanoseconds() -> UInt64? {
        guard let timebase else { return nil }
        let ticks = mach_continuous_time()
        let (product, overflow) = ticks.multipliedReportingOverflow(by: UInt64(timebase.numer))
        return overflow ? ticks / UInt64(timebase.denom) &* UInt64(timebase.numer) : product / UInt64(timebase.denom)
    }
}

/// Fixed ISO8601 formatting shared by grant persistence and log events.
public enum ISO8601 {
    // ISO8601DateFormatter is documented thread-safe; nonisolated(unsafe)
    // acknowledges the shared instance under strict concurrency.
    nonisolated(unsafe) private static let shared: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    public static func string(from date: Date) -> String {
        shared.string(from: date)
    }

    public static func date(from string: String) -> Date? {
        shared.date(from: string)
    }

    // Whole-second variant (no fractional seconds) for values consumed by
    // shell/`date` parsers — the Jamf EAs read `fleet-summary.plist` dates with
    // `%Y-%m-%dT%H:%M:%SZ`, which a `.123Z` fraction would fail to parse.
    nonisolated(unsafe) private static let secondPrecision: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    /// ISO-8601 at whole-second precision, e.g. `2026-08-23T21:00:00Z`.
    public static func secondString(from date: Date) -> String {
        secondPrecision.string(from: date)
    }
}
