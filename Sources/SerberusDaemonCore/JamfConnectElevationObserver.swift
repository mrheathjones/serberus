import Darwin
import Foundation
import PrivMgrCore

// MARK: - Log entries and parsing

/// One privilege-elevation event Jamf Connect / Self Service+ wrote to the
/// unified log, after the sender checks in ``JamfConnectLogParser``.
public struct JamfConnectElevationEvent: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        /// "<user> elevated to admin for <N> minutes".
        case elevated(user: String, minutes: Int)
        /// "Added user <user> to admin group" (no duration: the "time
        /// remaining" entry Jamf writes next gives it).
        case added(user: String)
        /// "Removed user <user> from admin group".
        case removed(user: String)
        /// "[User|Privilege] elevation time remaining: [h:]mm:ss" (no user named).
        case remaining(seconds: Int)
    }

    public let kind: Kind
    /// When the entry was logged.
    public let date: Date
    /// The logging process's image path (checked against the Jamf bundles).
    public let processImagePath: String

    public init(kind: Kind, date: Date, processImagePath: String) {
        self.kind = kind
        self.date = date
        self.processImagePath = processImagePath
    }
}

/// Turns `log stream --style ndjson` / `log show --style ndjson` lines into
/// ``JamfConnectElevationEvent``s.
///
/// # Trust
/// Any process can write a log entry claiming Jamf's subsystem, so an entry is
/// accepted only when BOTH hold:
/// - its subsystem is one of ``subsystems`` and its category is ``category``;
/// - the process that wrote it — `processImagePath`, which the logging system
///   records from the kernel, not from the message — runs from inside the Jamf
///   Connect or Self Service+ app bundle, the Jamf Connect daemon inside Self
///   Service (`JCDaemon.app`), or `/Library/Application Support/JamfConnect`.
///   Writing to any of them needs admin rights (`/Applications` is
///   admin-writable).
///
/// Even so this is an OBSERVED signal, not an attestation: an admin can put a
/// binary in those places, and the message text is Jamf's own. It is never
/// enough on its own to change a decision. The daemon acts on an observed
/// window only together with the user's LIVE membership in the local `admin`
/// group, checked at the moment of the sudo request — a spoofed entry for a
/// user who is not an admin changes nothing.
public enum JamfConnectLogParser {
    /// Subsystems Jamf documents for privilege-elevation events.
    public static let subsystems: Set<String> = ["com.jamf.connect.daemon.ssp", "com.jamf.connect"]
    /// The category Jamf documents for them.
    public static let category = "PrivilegeElevation"
    /// Where a sending process must run from (prefixes, each ending in `/`).
    /// Self Service (the app that bundles Jamf Connect) is trusted only for
    /// its daemon, `JCDaemon.app`, which is what writes the elevation entries;
    /// not the rest of the app, and not the Jamf Connect menu app inside it.
    public static let trustedImageRoots = [
        "/Applications/Jamf Connect.app/",
        "/Applications/Self Service+.app/",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/",
        "/Library/Application Support/JamfConnect/",
    ]

    /// The `log` predicate: Jamf's subsystems and category only. The sender
    /// check is applied per entry, because the predicate language cannot
    /// express "inside this directory" robustly.
    public static let predicate =
        #"(subsystem == "com.jamf.connect.daemon.ssp" OR subsystem == "com.jamf.connect") AND category == "PrivilegeElevation""#

    /// Parses one ndjson line. nil for anything that is not an accepted
    /// elevation entry (including the tool's own non-JSON banner lines).
    /// `fallbackDate` stands in for an unparseable timestamp.
    public static func parse(line: String, fallbackDate: Date?) -> JamfConnectElevationEvent? {
        guard line.hasPrefix("{"),
              let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)),
              let entry = object as? [String: Any] else { return nil }
        guard let subsystem = entry["subsystem"] as? String, subsystems.contains(subsystem),
              entry["category"] as? String == category,
              let imagePath = entry["processImagePath"] as? String, isTrustedImagePath(imagePath),
              let message = entry["eventMessage"] as? String,
              let kind = parseMessage(message) else { return nil }
        guard let date = (entry["timestamp"] as? String).flatMap(parseTimestamp) ?? fallbackDate else { return nil }
        return JamfConnectElevationEvent(kind: kind, date: date, processImagePath: imagePath)
    }

    /// Whether `path` lies inside one of ``trustedImageRoots``: absolute, with
    /// no `.` or `..` component, and under one of the prefixes.
    public static func isTrustedImagePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
            return false
        }
        return trustedImageRoots.contains { path.hasPrefix($0) && path.count > $0.count }
    }

    /// Recognizes Jamf's privilege-elevation messages. Each pattern must
    /// match the WHOLE message (leading and trailing white space aside), so
    /// matching text inside a longer message, such as the reason the user
    /// typed ("User <user> elevated to admin for stated reason: <reason>"),
    /// is not an elevation entry.
    public static func parseMessage(_ rawMessage: String) -> JamfConnectElevationEvent.Kind? {
        let message = rawMessage.trimmingCharacters(in: .whitespacesAndNewlines)
        let range = NSRange(message.startIndex..., in: message)
        if let match = elevatedPattern.firstMatch(in: message, range: range),
           let user = capture(match, 1, in: message), let minutesText = capture(match, 2, in: message) {
            // A value too large for Int is clamped later to the ceiling anyway.
            let minutes = Int(minutesText) ?? Int.max
            guard minutes > 0 else { return nil }
            return .elevated(user: user, minutes: minutes)
        }
        if let match = addedPattern.firstMatch(in: message, range: range),
           let user = capture(match, 1, in: message) {
            return .added(user: user)
        }
        if let match = removedPattern.firstMatch(in: message, range: range),
           let user = capture(match, 1, in: message) {
            return .removed(user: user)
        }
        if let match = remainingPattern.firstMatch(in: message, range: range),
           let minutes = capture(match, 2, in: message).flatMap({ Int($0) }),
           let seconds = capture(match, 3, in: message).flatMap({ Int($0) }), seconds < 60 {
            let hours = capture(match, 1, in: message).flatMap { Int($0) } ?? 0
            guard hours < 1_000, minutes < 100_000 else { return nil }
            return .remaining(seconds: hours * 3600 + minutes * 60 + seconds)
        }
        return nil
    }

    // Account names: the characters macOS short names use. Anything else —
    // notably a redacted "<private>" — does not match, so the entry is ignored.
    private static let userPattern = #"([A-Za-z0-9._@-]+)"#

    // The known forms, anchored at both ends:
    //   [User] <user> elevated to admin[istrator] for <N> minute[s][.]
    //   Added user <user> to [the] admin group[.]
    //   Removed user <user> from [the] admin group[.]
    //   [User|Privilege] elevation time remaining: [h:]mm:ss[.]
    private static let elevatedPattern = try! NSRegularExpression(
        pattern: #"^(?:user\s+)?"?"# + userPattern
            + #""?\s+elevated\s+to\s+admin(?:istrator)?\s+for\s+(\d+)\s+minutes?\.?$"#,
        options: [.caseInsensitive])
    private static let addedPattern = try! NSRegularExpression(
        pattern: #"^added\s+user\s+"?"# + userPattern + #""?\s+to\s+(?:the\s+)?admin\s+group\.?$"#,
        options: [.caseInsensitive])
    private static let removedPattern = try! NSRegularExpression(
        pattern: #"^removed\s+user\s+"?"# + userPattern + #""?\s+from\s+(?:the\s+)?admin\s+group\.?$"#,
        options: [.caseInsensitive])
    private static let remainingPattern = try! NSRegularExpression(
        pattern: #"^(?:user\s+|privilege\s+)?elevation\s+time\s+remaining:\s*(?:(\d+):)?(\d+):(\d{2})\.?$"#,
        options: [.caseInsensitive])

    private static func capture(_ match: NSTextCheckingResult, _ index: Int, in text: String) -> String? {
        guard index < match.numberOfRanges, let range = Range(match.range(at: index), in: text) else { return nil }
        return String(text[range])
    }

    /// `log`'s ndjson timestamp, e.g. `2026-09-26 10:15:02.123456-0700`.
    static func parseTimestamp(_ text: String) -> Date? {
        timestampFormatters.lazy.compactMap { $0.date(from: text) }.first
    }

    private static let timestampFormatters: [DateFormatter] = {
        ["yyyy-MM-dd HH:mm:ss.SSSSSSZ", "yyyy-MM-dd HH:mm:ssZ"].map { format in
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = format
            return formatter
        }
    }()
}

// MARK: - Windows

/// An observed Jamf Connect elevation for one user.
///
/// Like a grant, a window is bounded on two clocks: the wall-clock ``end``,
/// and a continuous-clock ``continuousDeadline`` taken when the window opened,
/// which setting the date cannot move. Either one passing ends the window, and
/// a wall clock earlier than ``start`` (set back since) counts as ended too.
public struct JamfConnectElevationWindow: Sendable, Equatable {
    public let user: String
    public let start: Date
    /// The earlier of the logged duration (capped at the JIT hard ceiling) and
    /// any "time remaining" Jamf logged since. An "Added user" entry has no
    /// duration: its window lasts
    /// ``JamfConnectElevationWindows/addedDefaultSeconds`` until the "time
    /// remaining" entry right after it sets the end (still capped). Ended early
    /// by a removal entry or by the user leaving `admin`
    /// (``JamfConnectElevationObserver/sweep()``).
    public var end: Date
    public let processImagePath: String
    /// The end on the continuous clock, in the boot session the window opened
    /// in. nil when no reading was available (the wall clock alone applies).
    public var continuousDeadline: MonotonicInstant?
    /// The account's uid, resolved by exact name when the window opened. Used
    /// to delete the right sudo ticket when the window ends (sudo names
    /// tickets by uid). nil when the name did not resolve.
    public var uid: uid_t?

    public init(user: String, start: Date, end: Date, processImagePath: String,
                continuousDeadline: MonotonicInstant? = nil, uid: uid_t? = nil) {
        self.user = user
        self.start = start
        self.end = end
        self.processImagePath = processImagePath
        self.continuousDeadline = continuousDeadline
        self.uid = uid
    }

    /// Whether the window is still open at `now`: not before ``start``, before
    /// ``end``, and (same boot session only) before ``continuousDeadline``.
    public func isOpen(at now: Date, monotonic: MonotonicInstant?) -> Bool {
        guard now >= start, now < end else { return false }
        if let remaining = continuousRemainingSeconds(monotonic: monotonic), remaining <= 0 { return false }
        return true
    }

    /// Seconds until the window ends by either clock (0 once it is not open).
    public func remainingSeconds(at now: Date, monotonic: MonotonicInstant?) -> TimeInterval {
        guard isOpen(at: now, monotonic: monotonic) else { return 0 }
        var remaining = end.timeIntervalSince(now)
        if let continuous = continuousRemainingSeconds(monotonic: monotonic) {
            remaining = min(remaining, continuous)
        }
        return max(0, remaining)
    }

    private func continuousRemainingSeconds(monotonic: MonotonicInstant?) -> TimeInterval? {
        guard let deadline = continuousDeadline, let monotonic,
              monotonic.bootSessionID == deadline.bootSessionID else { return nil }
        if monotonic.nanoseconds >= deadline.nanoseconds { return 0 }
        return TimeInterval(deadline.nanoseconds - monotonic.nanoseconds) / 1_000_000_000
    }

    /// A continuous-clock deadline `seconds` after `instant`.
    static func deadline(after seconds: TimeInterval, from instant: MonotonicInstant?) -> MonotonicInstant? {
        guard let instant else { return nil }
        let clamped = max(0, seconds)
        let nanos = clamped >= Double(UInt64.max / 2) / 1_000_000_000
            ? UInt64.max / 2 : UInt64(clamped * 1_000_000_000)
        return MonotonicInstant(bootSessionID: instant.bootSessionID, nanoseconds: instant.nanoseconds &+ nanos)
    }
}

/// The in-memory window per user, fed by parsed events. Pure; the observer
/// owns the side effects of each ``Change``.
public struct JamfConnectElevationWindows: Sendable {
    public enum Change: Sendable, Equatable {
        case opened(JamfConnectElevationWindow)
        /// An open window's end was set from the "time remaining" entry that
        /// followed its "Added user" entry.
        case resized(JamfConnectElevationWindow)
        case closed(JamfConnectElevationWindow, reason: String)
    }

    /// Hard ceiling on a window: the JIT maximum (8 hours).
    public static let ceilingSeconds = TimeInterval(JITAdminPolicy.maxAllowedDurationSeconds)
    /// The length of a window opened by "Added user <user> to admin group",
    /// which carries no duration, until the "time remaining" entry Jamf
    /// writes right after it gives the real one: Serberus's own default JIT
    /// window (15 minutes). Short on purpose: if the duration never comes,
    /// the user is gated early (and can elevate again) rather than kept
    /// native for hours.
    public static let addedDefaultSeconds = TimeInterval(JITAdminPolicy.defaultDurationSeconds)
    /// How soon after "Added user" the "time remaining" entry must be logged
    /// to set that window's length. Jamf writes it within milliseconds.
    public static let addedDurationGraceSeconds: TimeInterval = 60

    public private(set) var byUser: [String: JamfConnectElevationWindow] = [:]
    /// The latest "Added user" window still waiting for its "time remaining"
    /// entry. Kept even when its default length is already over (a history
    /// read), so the duration that follows can still restore it.
    private var awaitingDuration: JamfConnectElevationWindow?

    public init() {}

    /// Applies one event received at `now` (`monotonic` is the continuous
    /// clock at the same moment). An event older than the user's current window
    /// is ignored (a history read can land after live events).
    public mutating func apply(_ event: JamfConnectElevationEvent, now: Date,
                               monotonic: MonotonicInstant? = nil) -> [Change] {
        switch event.kind {
        case let .elevated(user, minutes):
            return open(user: user, seconds: min(Double(minutes) * 60, Self.ceilingSeconds),
                        event: event, now: now, monotonic: monotonic, awaitingDuration: false)
        case let .added(user):
            return open(user: user, seconds: Self.addedDefaultSeconds,
                        event: event, now: now, monotonic: monotonic, awaitingDuration: true)
        case let .removed(user):
            if let pending = awaitingDuration, pending.user == user, pending.start <= event.date {
                awaitingDuration = nil
            }
            guard let current = byUser[user], current.start <= event.date else { return [] }
            byUser[user] = nil
            return [.closed(current, reason: "Jamf Connect removed \(user) from the admin group")]
        case let .remaining(seconds):
            if let changes = applyDuration(seconds: seconds, event: event, now: now, monotonic: monotonic) {
                return changes
            }
            // Jamf does not name the user here; it can only shorten, and only
            // when exactly one window is open.
            guard byUser.count == 1, var only = byUser.values.first, only.start <= event.date else { return [] }
            let end = event.date.addingTimeInterval(TimeInterval(seconds))
            guard end < only.end else { return [] }
            only.end = end
            if let shorter = JamfConnectElevationWindow.deadline(after: end.timeIntervalSince(now), from: monotonic),
               only.continuousDeadline.map({ $0.bootSessionID != shorter.bootSessionID || shorter.nanoseconds < $0.nanoseconds }) ?? true {
                only.continuousDeadline = shorter
            }
            byUser[only.user] = only
            return only.isOpen(at: now, monotonic: monotonic)
                ? [] : close(user: only.user, reason: "Jamf Connect reported no time remaining").map { [$0] } ?? []
        }
    }

    /// Opens `user`'s window for `seconds` from the event. `awaitingDuration`
    /// marks an "Added user" window, whose length the next "time remaining"
    /// entry may set.
    private mutating func open(user: String, seconds: TimeInterval, event: JamfConnectElevationEvent,
                               now: Date, monotonic: MonotonicInstant?, awaitingDuration waits: Bool) -> [Change] {
        // An older entry never replaces a newer window, and an "Added user"
        // read again (a history replay) never resets its own.
        if let current = byUser[user], current.start > event.date || (waits && current.start == event.date) {
            return []
        }
        // Any newer start ends the wait for an earlier "Added user" duration.
        let newest = awaitingDuration.map { $0.start <= event.date } ?? true
        if newest { awaitingDuration = nil }
        let end = event.date.addingTimeInterval(seconds)
        // The continuous deadline is what is left by the wall clock now,
        // counted on the continuous clock from now on.
        let window = JamfConnectElevationWindow(
            user: user, start: event.date, end: end, processImagePath: event.processImagePath,
            continuousDeadline: JamfConnectElevationWindow.deadline(after: end.timeIntervalSince(now),
                                                                    from: monotonic))
        if waits && newest { awaitingDuration = window }
        // An entry dated after `now` means the clock was set back since it
        // was written: treated as over, like a window whose end has passed.
        guard window.isOpen(at: now, monotonic: monotonic) else {
            // Already over (a late or historical entry): nothing to open,
            // but an older open window for the user is now superseded.
            return byUser.removeValue(forKey: user).map { [.closed($0, reason: "superseded by an elapsed elevation")] } ?? []
        }
        byUser[user] = window
        return [.opened(window)]
    }

    /// Sets the length of the window waiting for its duration from a "time
    /// remaining" entry logged within ``addedDurationGraceSeconds`` after its
    /// "Added user" entry, capped at ``ceilingSeconds`` from the start. This is
    /// the one case where "time remaining" may lengthen a window. nil when the
    /// entry is not that duration (the caller then treats it as usual).
    private mutating func applyDuration(seconds: Int, event: JamfConnectElevationEvent,
                                        now: Date, monotonic: MonotonicInstant?) -> [Change]? {
        guard let pending = awaitingDuration, event.date >= pending.start else { return nil }
        awaitingDuration = nil // one duration per "Added user"
        guard event.date.timeIntervalSince(pending.start) <= Self.addedDurationGraceSeconds else { return nil }
        // The entry names no user: it counts only when that window is the
        // only one it could be about. Ambiguous: ignored (the default stays).
        guard byUser.keys.allSatisfy({ $0 == pending.user }) else { return [] }
        let current = byUser[pending.user]
        if let current, current.start != pending.start { return [] }
        var window = current ?? pending
        window.end = min(event.date.addingTimeInterval(TimeInterval(seconds)),
                         window.start.addingTimeInterval(Self.ceilingSeconds))
        if let deadline = JamfConnectElevationWindow.deadline(after: window.end.timeIntervalSince(now), from: monotonic) {
            window.continuousDeadline = deadline
        }
        guard window.isOpen(at: now, monotonic: monotonic) else {
            guard current != nil else { return [] }
            byUser[window.user] = nil
            return [.closed(window, reason: "Jamf Connect reported no time remaining")]
        }
        byUser[window.user] = window
        return [current == nil ? .opened(window) : .resized(window)]
    }

    /// Closes every window that is no longer open by either clock.
    public mutating func expire(now: Date, monotonic: MonotonicInstant? = nil) -> [Change] {
        let over = byUser.values.filter { !$0.isOpen(at: now, monotonic: monotonic) }.map(\.user).sorted()
        return over.compactMap { close(user: $0, reason: "elevation window elapsed") }
    }

    /// Records the account's uid on `user`'s window.
    mutating func setUID(_ uid: uid_t?, for user: String) {
        byUser[user]?.uid = uid
    }

    /// Closes `user`'s window, if one is open.
    public mutating func close(user: String, reason: String) -> Change? {
        if awaitingDuration?.user == user { awaitingDuration = nil }
        guard let window = byUser.removeValue(forKey: user) else { return nil }
        return .closed(window, reason: reason)
    }

    /// Closes every window.
    public mutating func closeAll(reason: String) -> [Change] {
        byUser.keys.sorted().compactMap { close(user: $0, reason: reason) }
    }

    /// `user`'s window if it is still open at `now`.
    public func active(for user: String, at now: Date, monotonic: MonotonicInstant? = nil) -> JamfConnectElevationWindow? {
        guard let window = byUser[user], window.isOpen(at: now, monotonic: monotonic) else { return nil }
        return window
    }
}

// MARK: - Log source

/// Where observed lines come from. Injectable so the observer is testable with
/// fixture lines and no `log` process.
public protocol JamfConnectLogStreaming: Sendable {
    /// Live ndjson lines. The stream finishes when the underlying reader ends.
    func liveLines() -> AsyncStream<String>
    /// Past ndjson lines covering the last `seconds` (a bounded, one-shot read).
    func history(seconds: Int) async -> [String]
}

/// Production ``JamfConnectLogStreaming``: `/usr/bin/log` as a bounded child.
///
/// Why `log stream --style ndjson` rather than `OSLogStore(scope: .system)`:
/// the sender check needs the logging process's full image path. The ndjson
/// output carries `processImagePath` (and `senderImagePath`) for every entry;
/// `OSLogEntryLog` only exposes the process NAME and the sender image's base
/// name, which any binary can share. `log stream` also pushes entries as they
/// are written, where `OSLogStore` would have to be polled.
///
/// Bounded: stdout is read as it arrives, one line at a time; a line longer
/// than ``maxLineBytes`` is dropped, the stream buffers at most
/// ``maxBufferedLines`` lines, stderr is discarded, and the child is terminated
/// (then killed) when the reader stops. The history read has a wall-clock
/// limit and a line cap.
///
/// The child never outlives the daemon (see ``ChildReader``): it runs in its
/// own process group, which is signalled when the reader stops and on the
/// daemon's SIGTERM path (``terminateAllChildren()``), and it exits by itself
/// if the daemon dies without either.
public struct UnifiedLogStream: JamfConnectLogStreaming {
    public static let maxLineBytes = 64 * 1024
    public static let maxBufferedLines = 1_000
    public static let historyTimeoutSeconds: TimeInterval = 60
    public static let maxHistoryLines = 20_000

    private let logTool: String

    public init(logTool: String = "/usr/bin/log") {
        self.logTool = logTool
    }

    /// Stops every `log` child still running. Called on the daemon's SIGTERM
    /// path before it exits; safe from any thread.
    public static func terminateAllChildren() {
        ChildReader.terminateAll()
    }

    public func liveLines() -> AsyncStream<String> {
        let arguments = ["stream", "--style", "ndjson", "--level", "info",
                         "--predicate", JamfConnectLogParser.predicate]
        return AsyncStream(bufferingPolicy: .bufferingNewest(Self.maxBufferedLines)) { continuation in
            let child = ChildReader(path: logTool, arguments: arguments) { line in
                continuation.yield(line)
            } onExit: {
                continuation.finish()
            }
            continuation.onTermination = { _ in child.stop() }
            if !child.start() { continuation.finish() }
        }
    }

    public func history(seconds: Int) async -> [String] {
        let arguments = ["show", "--style", "ndjson", "--info", "--last", "\(max(1, seconds))s",
                         "--predicate", JamfConnectLogParser.predicate]
        let collected = LockedLines(limit: Self.maxHistoryLines)
        let done = DispatchSemaphore(value: 0)
        let child = ChildReader(path: logTool, arguments: arguments) { collected.append($0) } onExit: { done.signal() }
        guard child.start() else { return [] }
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                if done.wait(timeout: .now() + Self.historyTimeoutSeconds) == .timedOut { child.stop() }
                continuation.resume(returning: collected.lines)
            }
        }
    }
}

/// A child process whose stdout is split into lines as it arrives.
///
/// The command runs under a small `/bin/sh` wrapper so that it cannot be
/// orphaned:
/// - `Process` starts the wrapper in a new process group, and the command and
///   the wrapper's watcher inherit it. ``stop()`` and ``terminateAll()`` signal
///   the whole group.
/// - The wrapper's stdin is a pipe whose write end only this process holds (a
///   lifeline). When this process exits for any reason, SIGKILL included, the
///   kernel closes that end, the watcher's `read` returns, and the command is
///   terminated. `log stream` on its own would notice only at its next write,
///   which for a quiet predicate may be hours away.
/// - The wrapper exits with the command, stopping the watcher.
final class ChildReader: @unchecked Sendable {
    /// `sh -c` script: `$@` is the command. fd 3 keeps the lifeline; the
    /// command itself gets /dev/null as stdin.
    static let wrapperScript = #"exec 3<&0 0</dev/null; "#
        + #"trap 'kill -TERM "$c" 2>/dev/null' TERM HUP INT; "#
        + #""$@" & c=$!; "#
        + #"{ read -r _ <&3; kill -TERM "$c" 2>/dev/null; } & w=$!; "#
        + #"wait "$c"; s=$?; kill "$w" 2>/dev/null; exit "$s""#
    static let shellPath = "/bin/sh"

    private let process = Process()
    private let pipe = Pipe()
    private let lifeline = Pipe()
    private let lock = NSLock()
    private var pending = Data()
    private var discarding = false
    private let onLine: @Sendable (String) -> Void
    private let onExit: @Sendable () -> Void

    init(path: String, arguments: [String],
         onLine: @escaping @Sendable (String) -> Void, onExit: @escaping @Sendable () -> Void) {
        process.executableURL = URL(fileURLWithPath: Self.shellPath)
        process.arguments = ["-c", Self.wrapperScript, "sh", path] + arguments
        self.onLine = onLine
        self.onExit = onExit
    }

    /// The child's process group (its pid), once started.
    var processGroup: pid_t? {
        lock.lock(); defer { lock.unlock() }
        return started ? process.processIdentifier : nil
    }
    private var started = false

    func start() -> Bool {
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        process.standardInput = lifeline
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                return
            }
            self?.consume(data)
        }
        process.terminationHandler = { [weak self] _ in
            guard let self else { return }
            Self.registry.remove(self)
            self.pipe.fileHandleForReading.readabilityHandler = nil
            // Whatever is still in the pipe after exit.
            if let rest = try? self.pipe.fileHandleForReading.readToEnd(), !rest.isEmpty { self.consume(rest) }
            self.onExit()
        }
        do {
            try process.run()
            lock.lock(); started = true; lock.unlock()
            // The child has its copy of the read end; ours is not needed.
            try? lifeline.fileHandleForReading.close()
            Self.registry.insert(self)
            return true
        } catch {
            return false
        }
    }

    /// Terminates the child's process group, then kills it if anything in it
    /// is still running shortly after.
    func stop() {
        guard let group = processGroup, process.isRunning else { return }
        signalGroup(group, SIGTERM)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) { [self] in
            if self.process.isRunning { self.signalGroup(group, SIGKILL) }
        }
    }

    /// Closes the lifeline, which the wrapper reads as "the parent is gone".
    /// Internal for tests; the kernel does the same when this process dies.
    func closeLifeline() {
        try? lifeline.fileHandleForWriting.close()
    }

    private func signalGroup(_ group: pid_t, _ signal: Int32) {
        closeLifeline()
        // Callers check first that the group leader (the wrapper) has not been
        // reaped, so its pid, and with it the group id, is still ours.
        guard group > 1 else { return }
        _ = kill(-group, signal)
    }

    /// Stops every running child now, without the grace period: the process
    /// is about to exit.
    static func terminateAll() {
        for reader in registry.all() {
            guard let group = reader.processGroup, reader.process.isRunning else { continue }
            reader.signalGroup(group, SIGTERM)
        }
    }

    private static let registry = ChildRegistry()

    private func consume(_ data: Data) {
        var lines: [String] = []
        lock.lock()
        pending.append(data)
        while let newline = pending.firstIndex(of: 0x0A) {
            let lineData = pending[pending.startIndex..<newline]
            pending.removeSubrange(pending.startIndex...newline)
            if discarding {
                discarding = false // the over-long line ends here
                continue
            }
            if let line = String(data: lineData, encoding: .utf8) { lines.append(line) }
        }
        if pending.count > UnifiedLogStream.maxLineBytes {
            pending.removeAll(keepingCapacity: false)
            discarding = true
        }
        lock.unlock()
        lines.forEach(onLine)
    }
}

/// Children still running, so the SIGTERM path can stop them.
private final class ChildRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var readers: [ObjectIdentifier: ChildReader] = [:]
    func insert(_ reader: ChildReader) { lock.lock(); readers[ObjectIdentifier(reader)] = reader; lock.unlock() }
    func remove(_ reader: ChildReader) { lock.lock(); readers[ObjectIdentifier(reader)] = nil; lock.unlock() }
    func all() -> [ChildReader] { lock.lock(); defer { lock.unlock() }; return Array(readers.values) }
}

private final class LockedLines: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String] = []
    private let limit: Int
    init(limit: Int) { self.limit = limit }
    func append(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        if stored.count < limit { stored.append(line) }
    }
    var lines: [String] { lock.lock(); defer { lock.unlock() }; return stored }
}

// MARK: - Observer

/// What ``DaemonController`` needs from the observer. Injectable for tests.
public protocol JamfConnectElevationObserving: Sendable {
    /// Starts observing (idempotent).
    func start() async
    /// Stops observing and ends every open window (idempotent).
    func stop() async
    /// Ends windows that elapsed or whose user left `admin`. Run on the reload tick.
    func sweep() async
    /// `user`'s open window, if any.
    func activeWindow(for user: String) async -> JamfConnectElevationWindow?
}

/// Follows Jamf Connect / Self Service+ privilege elevations in the unified
/// log (see ``JamfConnectLogParser`` for what is accepted and why it is only a
/// hint), keeping an in-memory window per user.
///
/// - Run only while the JIT provider is `jamf_connect` (and Serberus is on).
/// - An opened window and a closed one are written to the decision log, like
///   a Serberus JIT grant and demotion (`jit_admin_elevation` /
///   `jit_admin_demotion`, rule `jamf-connect`), so fleet telemetry and the
///   Intel view show both providers side by side.
/// - When a window ends, the user's sudo ticket is deleted.
/// - At start, the last ``JamfConnectElevationWindows/ceilingSeconds`` of the
///   log are read once so a window that began before the daemon started is not
///   missed; those are restored silently (the previous daemon logged them).
///   The live stream runs meanwhile, and a history entry no newer than the
///   last live entry for the same user is dropped, so a history read that
///   finishes late cannot re-open a window a live removal already closed.
public actor JamfConnectElevationObserver: JamfConnectElevationObserving {
    private let source: JamfConnectLogStreaming
    private let membership: GroupMembershipControlling
    private let ticketClearer: SudoTicketClearing
    private let decisionLogger: DecisionLogger?
    private let deviceSerial: String
    private let version: DaemonVersion
    private let now: @Sendable () -> Date
    /// The continuous clock windows are also bounded by. Injectable for tests.
    private let monotonicNow: @Sendable () -> MonotonicInstant?
    /// The uid of an account, by exact name. Injectable for tests.
    private let uidForUser: @Sendable (String) -> uid_t?
    private let restartDelay: Duration

    private var windows = JamfConnectElevationWindows()
    /// The date of the latest live entry per user, and of any live entry (for
    /// "time remaining", which names no user). History entries no newer than
    /// these are stale.
    private var lastLiveEvent: [String: Date] = [:]
    private var lastLiveAnyEvent: Date?
    private var running = false
    private var streamTask: Task<Void, Never>?
    private var historyTask: Task<Void, Never>?
    private var endTimers: [String: Task<Void, Never>] = [:]

    public init(
        source: JamfConnectLogStreaming = UnifiedLogStream(),
        membership: GroupMembershipControlling,
        ticketClearer: SudoTicketClearing,
        decisionLogger: DecisionLogger?,
        deviceSerial: String = "UNKNOWN",
        version: DaemonVersion = .current,
        now: @escaping @Sendable () -> Date = { Date() },
        monotonicNow: @escaping @Sendable () -> MonotonicInstant? = { MonotonicClock.now() },
        uidForUser: @escaping @Sendable (String) -> uid_t? = { SudoTimestampDirectory.exactUID($0) },
        restartDelay: Duration = .seconds(5)
    ) {
        self.monotonicNow = monotonicNow
        self.uidForUser = uidForUser
        self.source = source
        self.membership = membership
        self.ticketClearer = ticketClearer
        self.decisionLogger = decisionLogger
        self.deviceSerial = deviceSerial
        self.version = version
        self.now = now
        self.restartDelay = restartDelay
    }

    public func start() async {
        guard !running else { return }
        running = true
        DaemonLog.integrity.notice("jamf-connect observer: started")
        let source = source
        let delay = restartDelay
        historyTask = Task { [weak self] in
            let lines = await source.history(seconds: Int(JamfConnectElevationWindows.ceilingSeconds))
            await self?.restore(fromHistory: lines)
        }
        streamTask = Task { [weak self] in
            while !Task.isCancelled {
                for await line in source.liveLines() {
                    await self?.ingest(line: line)
                }
                guard !Task.isCancelled, self != nil else { return }
                // The child ended (log was restarted, or failed): start another
                // after a pause, so a failing tool cannot spin.
                try? await Task.sleep(for: delay)
            }
        }
    }

    public func stop() async {
        guard running else { return }
        running = false
        streamTask?.cancel()
        historyTask?.cancel()
        streamTask = nil
        historyTask = nil
        DaemonLog.integrity.notice("jamf-connect observer: stopped")
        for change in windows.closeAll(reason: "Jamf Connect observation stopped") {
            await handle(change)
        }
    }

    public func sweep() async {
        for change in windows.expire(now: now(), monotonic: monotonicNow()) { await handle(change) }
        for user in windows.byUser.keys.sorted() {
            // Only a definite "not a member" ends the window here; an unknown
            // answer leaves it (the sudo-time check needs a definite "member").
            guard (try? await membership.isMember(user: user, group: JITAdmin.adminGroup)) == false else { continue }
            if let change = windows.close(user: user, reason: "\(user) is no longer in the admin group") {
                await handle(change)
            }
        }
    }

    public func activeWindow(for user: String) -> JamfConnectElevationWindow? {
        windows.active(for: user, at: now(), monotonic: monotonicNow())
    }

    /// Feeds one live line. Internal so tests can drive it directly.
    func ingest(line: String) async {
        guard running, let event = JamfConnectLogParser.parse(line: line, fallbackDate: now()) else { return }
        noteLive(event)
        for change in windows.apply(event, now: now(), monotonic: monotonicNow()) { await handle(change) }
    }

    /// Replays the history read: windows still open are restored without
    /// logging them again. An entry no newer than the last live entry for its
    /// user is skipped: the live stream has already seen it or something later.
    func restore(fromHistory lines: [String]) async {
        guard running else { return }
        let events = lines.compactMap { JamfConnectLogParser.parse(line: $0, fallbackDate: nil) }
            .filter { !isStale($0) }
            .sorted { $0.date < $1.date }
        var restored = 0
        for event in events {
            for change in windows.apply(event, now: now(), monotonic: monotonicNow()) {
                switch change {
                case let .opened(window):
                    recordUID(for: window.user)
                    scheduleEnd(for: window.user)
                    restored += 1
                case let .resized(window):
                    scheduleEnd(for: window.user)
                case .closed:
                    break
                }
            }
        }
        if restored > 0 {
            DaemonLog.integrity.notice("jamf-connect observer: restored \(restored, privacy: .public) elevation window(s) from the log")
        }
    }

    private func noteLive(_ event: JamfConnectElevationEvent) {
        lastLiveAnyEvent = max(lastLiveAnyEvent ?? event.date, event.date)
        switch event.kind {
        case let .elevated(user, _), let .added(user), let .removed(user):
            lastLiveEvent[user] = max(lastLiveEvent[user] ?? event.date, event.date)
        case .remaining:
            break
        }
    }

    private func isStale(_ event: JamfConnectElevationEvent) -> Bool {
        switch event.kind {
        case let .elevated(user, _), let .added(user), let .removed(user):
            guard let last = lastLiveEvent[user] else { return false }
            return event.date <= last
        case .remaining:
            guard let last = lastLiveAnyEvent else { return false }
            return event.date <= last
        }
    }

    // MARK: Effects

    /// Resolves and stores the uid of a newly opened window's account.
    private func recordUID(for user: String) {
        windows.setUID(uidForUser(user), for: user)
    }

    private func handle(_ change: JamfConnectElevationWindows.Change) async {
        switch change {
        case let .opened(opened):
            recordUID(for: opened.user)
            let window = windows.byUser[opened.user] ?? opened
            scheduleEnd(for: window.user)
            DaemonLog.integrity.notice(
                "jamf-connect observer: \(window.user, privacy: .public) elevated until \(ISO8601.string(from: window.end), privacy: .public)")
            await log(window: window, outcome: .granted, eventType: "jit_admin_elevation",
                      durationSeconds: Int(window.end.timeIntervalSince(window.start)))
        case let .resized(window):
            // The decision log keeps the opening entry; only the timer and
            // the daemon log follow the new end.
            scheduleEnd(for: window.user)
            DaemonLog.integrity.notice(
                "jamf-connect observer: \(window.user, privacy: .public) elevated until \(ISO8601.string(from: window.end), privacy: .public) (time remaining from Jamf Connect)")
        case let .closed(window, reason):
            endTimers.removeValue(forKey: window.user)?.cancel()
            // The elevation is over: a sudo ticket from inside it must not let
            // the user skip the gate afterwards. sudo names the ticket by uid,
            // resolved when the window opened (the account may have been
            // renamed or deleted since); the name file covers older sudo.
            if let uid = window.uid {
                ticketClearer.clearTicket(uid: uid, user: window.user)
            } else {
                ticketClearer.clearTicket(user: window.user)
            }
            DaemonLog.integrity.notice(
                "jamf-connect observer: \(window.user, privacy: .public) elevation ended (\(reason, privacy: .public))")
            await log(window: window, outcome: .denied, eventType: "jit_admin_demotion", durationSeconds: 0)
        }
    }

    /// Ends the window when it runs out by either clock, timed on the
    /// continuous clock.
    private func scheduleEnd(for user: String) {
        endTimers[user]?.cancel()
        guard let window = windows.byUser[user] else { return }
        let seconds = window.remainingSeconds(at: now(), monotonic: monotonicNow())
        endTimers[user] = Task { [weak self] in
            try? await Task.sleep(until: ContinuousClock.now.advanced(by: .seconds(seconds)), clock: .continuous)
            guard !Task.isCancelled else { return }
            await self?.endIfElapsed(user: user)
        }
    }

    private func endIfElapsed(user: String) async {
        guard let window = windows.byUser[user] else { return }
        guard !window.isOpen(at: now(), monotonic: monotonicNow()) else {
            // Woken early (the wall clock was moved forward and back): re-arm.
            scheduleEnd(for: user)
            return
        }
        if let change = windows.close(user: user, reason: "elevation window elapsed") { await handle(change) }
    }


    private func log(window: JamfConnectElevationWindow, outcome: DecisionEvent.Outcome,
                     eventType: String, durationSeconds: Int) async {
        guard let decisionLogger else { return }
        let event = DecisionEvent(
            timestamp: now(), eventType: eventType, outcome: outcome,
            enforcementMode: .enforce, authURI: nil, sudoCommand: nil, arguments: nil,
            processPath: window.processImagePath, processTeamID: "", processHash: "",
            userName: window.user, userUID: window.uid.map { Int($0) } ?? -1,
            ruleID: JamfConnectElevationObserver.ruleID, profileKey: JITAdmin.grantProfileKey,
            grantID: nil, justification: nil,
            grantDurationSeconds: durationSeconds, cacheHit: false,
            deviceSerial: deviceSerial, daemonVersion: version.daemonVersion,
            pamModuleVersion: version.pamModuleVersion, policyVersion: JITAdminProvider.jamfConnect.rawValue
        )
        try? await decisionLogger.log(event)
    }

    /// Rule ID on the decision-log events for observed Jamf Connect elevations.
    public static let ruleID = "jamf-connect"
}
