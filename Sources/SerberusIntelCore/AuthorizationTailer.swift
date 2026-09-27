import Foundation
import PrivMgrCore

/// Live feed of macOS authorization-right attempts (authURI events), polled
/// through the daemon.
///
/// A standard user cannot run `log stream` ("Must be admin to run 'stream'
/// command") and cannot read the unified-log store at all, so this cannot use
/// the direct `LogStreamer` path the way the Serberus live tail does for an
/// admin. Instead it polls the daemon on an interval: each poll is a bounded,
/// stateless `log show` on the daemon side, returned inline. No long-lived
/// privileged `log stream` process exists to leak.
///
/// Overlap-and-dedup: each poll asks for a window a little longer than the
/// interval so no event falls in the gap between polls, and entries no newer
/// than the last one already emitted are dropped.
public final class AuthorizationTailer: @unchecked Sendable {
    private let client: IntelXPCClient
    private let parser = LogLineParser()
    private let interval: TimeInterval
    /// Lookback per poll. Longer than `interval` so a slow poll cannot open a
    /// gap; the overlap is removed by the newer-than-last-seen filter.
    private let window: String

    private let lock = NSLock()
    private var cancelled = false
    /// Timestamp of the newest entry emitted so far — the dedup high-water mark.
    private var lastEmitted: Date = .distantPast

    public init(
        client: IntelXPCClient = IntelXPCClient(),
        interval: TimeInterval = 2.0,
        window: String = "10s"
    ) {
        self.client = client
        self.interval = interval
        self.window = window
    }

    /// Emits authorization entries as they appear, and surfaces the first poll
    /// failure once (so the UI can explain why the feed is empty — e.g. the
    /// daemon isn't running) rather than spinning silently.
    public enum Event: Sendable {
        case entry(LogEntry)
        case unavailable(String)
    }

    public func stream() -> AsyncStream<Event> {
        // Reset the cancel flag so a tailer reused across mode switches (stop →
        // start) doesn't begin already-cancelled and exit on the first check.
        lock.lock()
        cancelled = false
        lock.unlock()
        return AsyncStream { continuation in
            let task = Task { [weak self] in
                guard let self else { return }
                var reportedFailure = false
                while !Task.isCancelled, !self.isCancelled {
                    do {
                        let result = try await self.client.pollAuthorizations(
                            request: AuthorizationPollRequest(window: self.window)
                        )
                        reportedFailure = false
                        for entry in self.freshEntries(from: result.ndjson) {
                            continuation.yield(.entry(entry))
                        }
                    } catch {
                        // Report once, then stay quiet until it recovers — a
                        // down daemon should not scroll an error every 2s.
                        if !reportedFailure {
                            reportedFailure = true
                            continuation.yield(.unavailable(error.localizedDescription))
                        }
                    }
                    try? await Task.sleep(for: .seconds(self.interval))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
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

    /// Parses a poll's NDJSON and returns only entries newer than the last one
    /// already emitted, advancing the high-water mark.
    func freshEntries(from ndjson: String) -> [LogEntry] {
        let parsed = parser.parse(document: ndjson).sorted { $0.date < $1.date }
        lock.lock()
        let cutoff = lastEmitted
        // A strict `>` drops the exact-cutoff entry so it is never emitted
        // twice across overlapping polls; two events in the same microsecond
        // are vanishingly rare and only cost one skipped line.
        let fresh = parsed.filter { $0.date > cutoff }
        if let newest = fresh.last?.date { lastEmitted = newest }
        lock.unlock()
        return fresh
    }
}
