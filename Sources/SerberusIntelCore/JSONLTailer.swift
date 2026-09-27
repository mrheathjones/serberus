import Foundation
import PrivMgrCore

/// Whether this process can read the system's unified log store.
///
/// `/var/db/diagnostics` is `root:admin 0750`, so `log show` works for an
/// admin and fails for a standard user. Intel checks rather than assumes:
/// the app must degrade to the JSONL source silently for standard users,
/// and must never tell a Service Desk technician (who *is* an admin) that
/// data is unavailable when it isn't.
public enum UnifiedLogAccess {
    static let storePath = "/var/db/diagnostics"

    /// True when the unified log store is readable by this process.
    public static func isReadable(fileManager: FileManager = .default) -> Bool {
        fileManager.isReadableFile(atPath: storePath)
    }

    /// Why the unified log is unavailable, for the UI.
    public static var unavailableReason: String {
        "\(storePath) is readable only by root and the admin group, so the "
            + "system log is not available to a standard user. Serberus's own "
            + "decision and integrity records are shown instead — they are the "
            + "authoritative record of every allow/deny."
    }
}

/// Tails the daemon's JSONL logs and publishes appended events.
///
/// Polls rather than watching with FSEvents/DispatchSource: the daemon appends
/// with a plain `write`, a poll needs no file descriptor held open across
/// rotation, and a diagnostics tail does not need sub-second latency. Each poll
/// resumes from a byte offset, so cost is proportional to what was appended,
/// not to the file's size.
public final class JSONLTailer: @unchecked Sendable {
    private let source: JSONLLogSource
    private let interval: TimeInterval
    private let now: @Sendable () -> Date

    private let lock = NSLock()
    private var cancelled = false
    /// Byte offset per `<prefix>-<day>` file.
    private var offsets: [String: UInt64] = [:]

    public init(
        source: JSONLLogSource = JSONLLogSource(),
        interval: TimeInterval = 1.0,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.source = source
        self.interval = interval
        self.now = now
    }

    /// Streams events appended after this call.
    ///
    /// Starts at each file's current end rather than replaying the day: this is
    /// the *live* view, and the history view already covers what came before.
    public func stream() -> AsyncStream<LogEntry> {
        // Reset the cancel flag so a tailer reused across mode switches (stop →
        // start) doesn't begin already-cancelled and exit on the first check.
        lock.lock()
        cancelled = false
        lock.unlock()
        return AsyncStream { continuation in
            let task = Task { [weak self] in
                guard let self else { return }
                self.seekToEnd()
                while !Task.isCancelled, !self.isCancelled {
                    for entry in self.poll() {
                        continuation.yield(entry)
                    }
                    try? await Task.sleep(for: .seconds(self.interval))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in
                task.cancel()
                self.stop()
            }
        }
    }

    public func stop() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    private var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    /// Prime offsets at end-of-file so the first poll yields only new events.
    private func seekToEnd() {
        let day = LogDay.stamp(for: now())
        for prefix in Self.prefixes {
            let result = source.readIncremental(prefix: prefix, day: day, from: 0)
            lock.lock()
            offsets[Self.key(prefix, day)] = result.offset
            lock.unlock()
        }
    }

    private func poll() -> [LogEntry] {
        // Re-derive the day every poll: these files rotate at UTC midnight, and
        // a tail that cached the day stamp would go permanently silent at the
        // rollover with no error.
        let day = LogDay.stamp(for: now())
        var fresh: [LogEntry] = []
        for prefix in Self.prefixes {
            let key = Self.key(prefix, day)
            lock.lock()
            let offset = offsets[key] ?? 0
            lock.unlock()

            let result = source.readIncremental(prefix: prefix, day: day, from: offset)
            lock.lock()
            offsets[key] = result.offset
            lock.unlock()
            fresh.append(contentsOf: result.entries)
        }
        return fresh.sorted { $0.date < $1.date }
    }

    private static let prefixes = ["decisions", "integrity"]

    private static func key(_ prefix: String, _ day: String) -> String { "\(prefix)-\(day)" }
}
