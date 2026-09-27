import Foundation
import Observation
import PrivMgrCore

/// The popover's rule list state: the latest ``SentinelRulesSnapshot`` pulled
/// from the daemon, persisted so the list still renders when the daemon is
/// unreachable (the design's "Offline · cached policy" state).
///
/// The cache is a display convenience, never a decision input — a corrupt or
/// missing file just starts empty, exactly like ``ElevationHistoryStore``.
@MainActor
@Observable
public final class SentinelRulesStore {

    /// The rules to display (live or cached).
    public private(set) var snapshot: SentinelRulesSnapshot?
    /// When the snapshot was last pulled from a live daemon. `nil` means the
    /// current snapshot (if any) came from the on-disk cache.
    public private(set) var lastSyncedAt: Date?
    /// Whether ``snapshot`` was loaded from cache rather than a live pull.
    public var isFromCache: Bool { snapshot != nil && lastSyncedAt == nil }

    private let fileURL: URL?
    private let now: @Sendable () -> Date

    /// - Parameters:
    ///   - fileURL: backing store; `nil` keeps the snapshot in memory only
    ///     (tests, previews). Defaults to the Sentinel's Application Support
    ///     directory.
    ///   - now: injectable clock for tests.
    public init(
        fileURL: URL? = SentinelRulesStore.defaultFileURL(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.fileURL = fileURL
        self.now = now
        self.snapshot = Self.load(from: fileURL)
    }

    /// Adopts a live pull from the daemon and persists it for offline use.
    /// The poll runs every few seconds for the app's lifetime, so an
    /// unchanged policy (everything but the daemon's `generatedAt` stamp)
    /// only refreshes the sync time — no disk write.
    public func adopt(_ snapshot: SentinelRulesSnapshot) {
        let unchanged = self.snapshot.map { current in
            current.rules == snapshot.rules
                && current.profileKeys == snapshot.profileKeys
                && current.policyVersion == snapshot.policyVersion
                && current.enforcementMode == snapshot.enforcementMode
        } ?? false
        self.snapshot = snapshot
        self.lastSyncedAt = now()
        if !unchanged { persist() }
    }

    /// A failed pull: keep showing whatever we have (live or cached), but mark
    /// the data as no longer live.
    public func markOffline() {
        lastSyncedAt = nil
    }

    /// Re-reads the on-disk rules cache written by the menubar agent.
    ///
    /// The full **Serberus Sentinel.app** never issues a `userRules` pull itself
    /// — that is a `.sentinel`-interface privilege held only by the agent (the
    /// full app is a read-only `.intel` caller). Instead it displays whatever
    /// snapshot the agent has cached to the shared support directory, refreshing
    /// on a light timer so a policy change the agent adopts appears in the
    /// window without a relaunch. A `nil`/corrupt/empty file leaves the current
    /// snapshot untouched (never blanks a good list on a transient read). The
    /// data is always "from cache" from the full app's point of view. Only
    /// reassigns when the policy actually changed (same comparison as
    /// ``adopt(_:)``), so the full app's periodic reload does not re-render an
    /// unchanged list.
    public func reloadFromDisk() {
        guard let loaded = Self.load(from: fileURL) else { return }
        let unchanged = snapshot.map { current in
            current.rules == loaded.rules
                && current.profileKeys == loaded.profileKeys
                && current.policyVersion == loaded.policyVersion
                && current.enforcementMode == loaded.enforcementMode
        } ?? false
        guard !unchanged else { return }
        snapshot = loaded
        lastSyncedAt = nil
    }

    // MARK: Persistence

    /// `~/Library/Application Support/Serberus/rules-cache.json`
    public static func defaultFileURL() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return base
            .appendingPathComponent("Serberus", isDirectory: true)
            .appendingPathComponent("rules-cache.json")
    }

    private static func load(from fileURL: URL?) -> SentinelRulesSnapshot? {
        guard let fileURL, let data = try? Data(contentsOf: fileURL) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(SentinelRulesSnapshot.self, from: data)
    }

    private func persist() {
        guard let fileURL, let snapshot else { return }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(snapshot) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? data.write(to: fileURL, options: .atomic)
    }
}
