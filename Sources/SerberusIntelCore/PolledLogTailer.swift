import Foundation
import PrivMgrCore

/// Generic poll-and-dedup feed over a daemon-brokered `log show` — the engine
/// behind ``SudoTailer`` (and the shape ``AuthorizationTailer`` hand-rolled
/// before it existed; that class is kept as-is for its tests and call sites,
/// and can delegate here later).
///
/// Why polling, again: a standard user cannot `log stream`, and a long-lived
/// root `log stream` child tied to an app session is orphan-process risk on a
/// security daemon. Each poll is a bounded, stateless `log show` on the daemon
/// side; the client asks for a window a little longer than the interval so no
/// event falls in the gap, and drops anything it has already emitted.
public final class PolledLogTailer: @unchecked Sendable {
    public enum Event: Sendable {
        case entry(LogEntry)
        /// The first poll failure after success (e.g. the daemon went away).
        case unavailable(String)
        /// The first successful poll after a failure.
        case recovered
    }

    private let parser = LogLineParser()
    private let interval: TimeInterval
    /// Fetches one poll's NDJSON. Injected so the loop is testable without XPC.
    private let poll: @Sendable () async throws -> String

    private let lock = NSLock()
    private var cancelled = false
    /// Newest entry date emitted so far — the dedup high-water mark.
    private var lastEmitted: Date = .distantPast
    /// Keys of every entry already emitted AT `lastEmitted`. The unified-log
    /// store is eventually consistent, so a later poll can surface a distinct
    /// record bearing exactly the previous newest timestamp; a strict `>`
    /// cutoff alone would drop it forever.
    private var emittedAtCutoff: Set<String> = []

    public init(interval: TimeInterval = 2.0, poll: @escaping @Sendable () async throws -> String) {
        self.interval = interval
        self.poll = poll
    }

    public func stream() -> AsyncStream<Event> {
        lock.lock()
        cancelled = false
        lock.unlock()
        return AsyncStream { continuation in
            let task = Task { [weak self] in
                guard let self else { return }
                var failing = false
                while !Task.isCancelled, !self.isCancelled {
                    do {
                        let ndjson = try await self.poll()
                        if failing {
                            failing = false
                            continuation.yield(.recovered)
                        }
                        for entry in self.freshEntries(from: ndjson) {
                            continuation.yield(.entry(entry))
                        }
                    } catch {
                        // Report once, then stay quiet until it recovers.
                        if !failing {
                            failing = true
                            continuation.yield(.unavailable(error.localizedDescription))
                        }
                    }
                    // Guarded: a cancelled sleep returns immediately, and an
                    // unguarded loop would then spin hot until the next check.
                    if Task.isCancelled || self.isCancelled { break }
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

    /// Parses a poll's NDJSON and returns only entries not yet emitted,
    /// advancing the high-water mark.
    func freshEntries(from ndjson: String) -> [LogEntry] {
        let parsed = parser.parse(document: ndjson).sorted { $0.date < $1.date }
        lock.lock()
        defer { lock.unlock() }
        let cutoff = lastEmitted
        var fresh: [LogEntry] = []
        for entry in parsed {
            if entry.date > cutoff {
                fresh.append(entry)
            } else if entry.date == cutoff, !emittedAtCutoff.contains(Self.key(entry)) {
                fresh.append(entry)
            }
        }
        guard let newest = fresh.last?.date else { return fresh }
        if newest > cutoff {
            lastEmitted = newest
            emittedAtCutoff = Set(fresh.filter { $0.date == newest }.map(Self.key))
        } else {
            emittedAtCutoff.formUnion(fresh.map(Self.key))
        }
        return fresh
    }

    private static func key(_ entry: LogEntry) -> String {
        "\(entry.timestamp)|\(entry.processID)|\(entry.message)"
    }
}

/// Live feed of `sudo` attempts (sudo's own unified-log lines, scoped by the
/// daemon to the calling user), polled through `pollSudoAttempts` — the
/// Capture session's sudo source.
public final class SudoTailer: @unchecked Sendable {
    private let tailer: PolledLogTailer

    public init(
        client: IntelXPCClient = IntelXPCClient(),
        interval: TimeInterval = 2.0,
        window: String = "10s"
    ) {
        tailer = PolledLogTailer(interval: interval) {
            try await client.pollSudoAttempts(request: SudoPollRequest(window: window)).ndjson
        }
    }

    public func stream() -> AsyncStream<PolledLogTailer.Event> { tailer.stream() }
    public func stop() { tailer.stop() }
}
