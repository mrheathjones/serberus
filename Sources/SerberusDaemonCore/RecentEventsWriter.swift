import Foundation
import PrivMgrCore

/// Debug telemetry: the per-device list of recent denial / prompt
/// events Commander shows on a device record.
///
/// The daemon **always** collects the events locally (`recentEventsLocal`,
/// root-only 0600). It publishes them to the EA-inspected path
/// (`fleetEventsPublic`, also root-only 0600: the extension attribute runs as
/// root) **only while the `debugModeEnabled` profile is on**; when debug is
/// off (or the profile is removed) the published file is deleted, so no
/// per-decision detail reaches Jamf unless it was explicitly opted in.
///
/// Under debug mode the daemon also captures each sudo request's (redacted)
/// arguments. Those go into ``debugArguments``, in memory, and from there only
/// into these two root-only files, never into the decision log
/// (`decisions-*.jsonl`, 0644, readable by every local user).
///
/// Fail-safe like the rest of the telemetry tick: bounded read, best-effort
/// writes, never throws, never blocks the reload loop.
public struct RecentEventsWriter: Sendable {
    private let reader: DecisionCountReader
    private let localURL: URL
    private let publicURL: URL
    private let limit: Int
    /// Arguments captured under debug mode, by decision event ID.
    public let debugArguments: DebugArgumentStore

    public init(logDirectory: URL, localURL: URL, publicURL: URL, limit: Int = 40,
                debugArguments: DebugArgumentStore = DebugArgumentStore()) {
        self.reader = DecisionCountReader(directory: logDirectory)
        self.localURL = localURL
        self.publicURL = publicURL
        self.limit = limit
        self.debugArguments = debugArguments
    }

    private func windowDays(now: Date) -> [String] {
        [LogDay.stamp(for: now), LogDay.stamp(for: now.addingTimeInterval(-86_400))]
    }

    /// The rolling-24h denial/prompt events (pure; for tests).
    public func events(now: Date) -> [FleetDecisionEvent] {
        let since = now.addingTimeInterval(-86_400)
        return reader.recentEvents(days: windowDays(now: now), since: since, limit: limit,
                                   debugArguments: debugArguments.snapshot(since: since))
    }

    /// Writes the local collection always, then publishes to (or clears) the EA
    /// path per `debugEnabled`.
    public func write(debugEnabled: Bool, now: Date) {
        let json = FleetDecisionEvent.encodeList(events(now: now))
        writeFile(json, to: localURL, permissions: 0o600)

        if debugEnabled {
            writeFile(json, to: publicURL, permissions: 0o600)
        } else {
            // Withdraw the exposure: remove the EA-inspected file so the next
            // recon collects nothing. Idempotent — absent is success.
            try? FileManager.default.removeItem(at: publicURL)
        }
    }

    /// Writes `contents` to `url`, never more open than `permissions` at any
    /// point: a fresh temp file beside `url` is created 0600 (`O_EXCL |
    /// O_NOFOLLOW`: nothing already at the name is written through) and
    /// `fchmod`ed to `permissions` before the first byte, then `fsync`ed and
    /// renamed over `url`. Not `Data.write(options: .atomic)`: its temp file is
    /// created with the process umask (022 for the daemon, so 0644), and `url`
    /// keeps that mode until a chmod after the rename. Any failure removes the
    /// temp file.
    ///
    /// `beforeRename` is a test seam: it gets the temp file's path once every
    /// byte is written, just before the rename.
    func writeFile(_ contents: String, to url: URL, permissions: Int,
                   beforeRename: ((String) -> Void)? = nil) {
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            let temp = url.deletingLastPathComponent()
                .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
            let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            var failure = fchmod(fd, mode_t(permissions)) == 0 ? 0 : errno
            if failure == 0 { failure = Self.writeAll(Data(contents.utf8), to: fd) }
            if failure == 0, fsync(fd) != 0 { failure = errno }
            close(fd)
            if failure == 0 {
                beforeRename?(temp.path)
                if rename(temp.path, url.path) != 0 { failure = errno }
            }
            guard failure == 0 else {
                unlink(temp.path)
                throw POSIXError(POSIXErrorCode(rawValue: failure) ?? .EIO)
            }
        } catch {
            DaemonLog.integrity.error(
                "Failed to write \(url.lastPathComponent, privacy: .public): \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    /// Writes every byte of `data` to `fd`, retrying partial writes and EINTR.
    /// Returns 0, or the errno of the write that failed.
    private static func writeAll(_ data: Data, to fd: Int32) -> Int32 {
        data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Int32 in
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(fd, buffer.baseAddress?.advanced(by: offset), buffer.count - offset)
                if written < 0, errno == EINTR { continue }
                guard written > 0 else { return written < 0 ? errno : EIO }
                offset += written
            }
            return 0
        }
    }
}

/// The arguments captured under debug mode, keyed by the decision event they
/// belong to. In memory only and bounded (``capacity`` entries, 24 hours): a
/// debug aid, not a record, so a restart simply starts a new list.
public final class DebugArgumentStore: @unchecked Sendable {
    public static let capacity = 500
    private static let maxAge: TimeInterval = 86_400

    private let lock = NSLock()
    private var entries: [UUID: (at: Date, arguments: [String])] = [:]

    public init() {}

    /// Records `arguments` (already redacted) for the event `eventID` logged at `at`.
    public func record(eventID: UUID, arguments: [String], at: Date) {
        guard !arguments.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        entries[eventID] = (at, arguments)
        if entries.count > Self.capacity {
            let cutoff = at.addingTimeInterval(-Self.maxAge)
            entries = entries.filter { $0.value.at >= cutoff }
            while entries.count > Self.capacity,
                  let oldest = entries.min(by: { $0.value.at < $1.value.at })?.key {
                entries[oldest] = nil
            }
        }
    }

    /// Every entry recorded at or after `since`.
    public func snapshot(since: Date) -> [UUID: [String]] {
        lock.lock(); defer { lock.unlock() }
        return entries.filter { $0.value.at >= since }.mapValues(\.arguments)
    }
}
