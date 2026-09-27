import Foundation
import Observation
import PrivMgrCore

/// One resolved elevation prompt as the Sentinel saw it — what was asked, and how
/// it ended. This is the user-visible activity trail: the Sentinel
/// records every prompt it presents, so History and the menubar "Recent" list
/// show real decisions without needing read access to the daemon's root-owned
/// signed decision log.
public struct ElevationHistoryEntry: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public let date: Date
    public let user: String
    public let processName: String
    public let canonicalPath: String
    public let humanReadableRequest: String
    public let verdict: PromptResponse.Verdict
    public let justificationText: String?
    /// Matched rule identity (`profileKey · ruleID`) as delivered in the
    /// prompt context. Optional: entries recorded before this field existed
    /// (and prompts from older daemons) decode as `nil`.
    public let ruleName: String?

    public init(
        id: UUID,
        date: Date,
        user: String,
        processName: String,
        canonicalPath: String,
        humanReadableRequest: String,
        verdict: PromptResponse.Verdict,
        justificationText: String?,
        ruleName: String? = nil
    ) {
        self.id = id
        self.date = date
        self.user = user
        self.processName = processName
        self.canonicalPath = canonicalPath
        self.humanReadableRequest = humanReadableRequest
        self.verdict = verdict
        self.justificationText = justificationText
        self.ruleName = ruleName
    }

    /// Builds an entry from a resolved prompt round-trip.
    public init(context: PromptContext, response: PromptResponse, date: Date) {
        self.init(
            id: context.requestID,
            date: date,
            user: context.user,
            processName: context.processName,
            canonicalPath: context.canonicalPath,
            humanReadableRequest: context.humanReadableRequest,
            verdict: response.verdict,
            justificationText: response.justificationText,
            ruleName: context.ruleName
        )
    }

    /// ``humanReadableRequest`` as My Activity shows it, with hidden characters
    /// (bidi overrides, zero-width characters, newlines…) as visible escapes
    /// (``DisplayText/escapingInvisibles(_:)``). The daemon escapes them
    /// already; this covers entries that older versions recorded raw.
    public var displayRequest: String {
        DisplayText.escapingInvisibles(humanReadableRequest)
    }
}

/// Persists the Sentinel's local elevation history, newest first, capped so the
/// file can't grow without bound. Corrupt or missing files start empty — the
/// history is a convenience trail, never a decision input, so it fails open
/// to an empty list rather than blocking the Sentinel.
@MainActor
@Observable
public final class ElevationHistoryStore {

    /// Maximum entries retained (newest win).
    public static let capacity = 200

    public private(set) var entries: [ElevationHistoryEntry] = []

    private let fileURL: URL?
    private let now: @Sendable () -> Date

    /// - Parameters:
    ///   - fileURL: backing store; `nil` keeps history in memory only (tests,
    ///     previews). Defaults to the Sentinel's Application Support directory.
    ///   - now: injectable clock for tests.
    public init(
        fileURL: URL? = ElevationHistoryStore.defaultFileURL(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.fileURL = fileURL
        self.now = now
        self.entries = Self.load(from: fileURL)
    }

    /// Records a resolved prompt at the head of the history and persists.
    ///
    /// The file is shared between the two Serberus GUI processes — the menubar
    /// **agent** (which records prompts) and the full **Serberus Sentinel.app**
    /// (which only reads, but can Clear). So we reconcile with the on-disk copy
    /// *before* prepending: without this, a Clear performed in the full app
    /// while the agent holds a stale in-memory list would be silently undone by
    /// the agent's next write (lost update). Every mutation here persists
    /// immediately, so the disk copy is never behind our memory — reloading it
    /// can only pick up another process's newer writes, never drop our own.
    public func record(context: PromptContext, response: PromptResponse) {
        // Reconcile only for a real backing file. An in-memory store (fileURL
        // nil — tests, previews) has no shared truth to reconcile against, and
        // loading nil would return [] and wipe accumulated entries.
        if fileURL != nil { entries = Self.load(from: fileURL) }
        let entry = ElevationHistoryEntry(context: context, response: response, date: now())
        entries.insert(entry, at: 0)
        if entries.count > Self.capacity {
            entries.removeLast(entries.count - Self.capacity)
        }
        persist()
    }

    /// Re-reads the on-disk history, adopting writes made by the *other*
    /// Serberus process since the last load. The full app calls this on a light
    /// timer so prompts the agent records appear in "My Activity" without a
    /// relaunch; the agent calls it on each poll so the popover's counters
    /// notice a Clear performed in the full app. Only reassigns `entries` when
    /// the file actually changed, so the full app's periodic reload does not
    /// re-render (and scroll-jump) an unchanged list.
    public func reloadFromDisk() {
        guard fileURL != nil else { return }
        let loaded = Self.load(from: fileURL)
        if loaded != entries { entries = loaded }
    }

    /// The newest `limit` entries, for the menubar "Recent" list.
    public func recent(_ limit: Int) -> [ElevationHistoryEntry] {
        Array(entries.prefix(limit))
    }

    /// Prompts resolved today (any verdict) — the popover's "Audited today"
    /// counter. Every presented prompt is an audit event regardless of how it
    /// ended, so all verdicts count.
    public func auditedTodayCount() -> Int {
        let calendar = Calendar.current
        let today = now()
        return entries.count { calendar.isDate($0.date, inSameDayAs: today) }
    }

    /// The most recent entry matching a rule identity — drives the popover's
    /// highlighted "last prompted" row and the per-rule last-used timestamp.
    public func lastEntry(forRuleNamed ruleName: String) -> ElevationHistoryEntry? {
        entries.first { $0.ruleName == ruleName }
    }

    /// How many times each rule (by `ruleName`) has been prompted — the data
    /// behind the menubar "top rules" list. Only prompted rules appear: the
    /// Sentinel records prompts it presented, so silent/allow/deny rules that
    /// never prompt have no count here (a daemon-wide per-rule hit count is a
    /// deferred enhancement). Entries with no `ruleName` (older records) are
    /// ignored.
    public func ruleHitCounts() -> [String: Int] {
        var counts: [String: Int] = [:]
        for entry in entries {
            guard let name = entry.ruleName else { continue }
            counts[name, default: 0] += 1
        }
        return counts
    }

    /// Entries resolved on the same calendar day as `now()` — the "My Activity"
    /// today filter (and the source of ``auditedTodayCount()``).
    public func entriesToday() -> [ElevationHistoryEntry] {
        let calendar = Calendar.current
        let today = now()
        return entries.filter { calendar.isDate($0.date, inSameDayAs: today) }
    }

    /// Clears the trail (user-initiated from History).
    public func clear() {
        entries.removeAll()
        persist()
    }

    // MARK: Persistence

    /// `~/Library/Application Support/Serberus/elevation-history.json`
    public static func defaultFileURL() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return base
            .appendingPathComponent("Serberus", isDirectory: true)
            .appendingPathComponent("elevation-history.json")
    }

    private static func load(from fileURL: URL?) -> [ElevationHistoryEntry] {
        guard let fileURL, let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([ElevationHistoryEntry].self, from: data)) ?? []
    }

    private func persist() {
        guard let fileURL else { return }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(entries) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? data.write(to: fileURL, options: .atomic)
    }
}
