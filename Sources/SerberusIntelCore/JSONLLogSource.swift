import Foundation
import PrivMgrCore

/// Reads the daemon's signed JSONL decision/integrity logs.
///
/// ## Why this exists
///
/// The unified log store (`/var/db/diagnostics`) is `root:admin 0750`, so a
/// standard user cannot read it: `log show` fails and `log stream` cannot be
/// relied on. Making the user an admin (or JIT-elevating them) to read a log
/// would defeat the point of a least-privilege tool.
///
/// The daemon already writes every decision and integrity event to
/// `/Library/Logs/Serberus/*.jsonl` as root, and those files
/// are world-readable — the unified-log categories are a *mirror* of them
/// (see `DaemonLog`). So the authoritative Serberus record is readable by a
/// standard user with **no privilege at all**, which is what this source uses.
///
/// What it does NOT cover: `pam_serberus`'s own module lines and the Sentinel's,
/// which are os_log-only and have no JSONL equivalent. Those need the
/// daemon-brokered export.
public struct JSONLLogSource: Sendable {
    /// Directory holding `decisions-YYYY-MM-DD.jsonl` / `integrity-…`.
    private let directory: URL
    /// When set, only events for this user are returned.
    private let userName: String?

    /// Default log directory, honouring a dev override.
    ///
    /// `SERBERUS_INTEL_LOG_DIR` exists so Intel can be exercised on a Mac
    /// with no daemon installed — `/Library/Logs` is root-owned, so a test
    /// fixture cannot be written to the real path without root. It grants no
    /// privilege: it only redirects Intel at files the user can already read
    /// for themselves, and it is read once here rather than threaded through
    /// every call site.
    public static var defaultDirectory: URL {
        if let override = ProcessInfo.processInfo.environment["SERBERUS_INTEL_LOG_DIR"],
           !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return URL(fileURLWithPath: BundleConfig.logDirectory, isDirectory: true)
    }

    /// - Parameters:
    ///   - directory: JSONL log directory.
    ///   - userName: Restrict to one user's events. Pass `nil` for all.
    public init(
        directory: URL? = nil,
        userName: String? = NSUserName()
    ) {
        self.directory = directory ?? Self.defaultDirectory
        self.userName = userName
    }

    /// Filenames the window spans, newest last.
    ///
    /// Day stamps come from ``LogDay/stamp(for:)`` — the writer's own rule, not
    /// a copy — so reader and writer cannot disagree about which file a given
    /// instant lives in.
    static func dayStamps(from start: Date, to end: Date) -> [String] {
        var stamps: [String] = []
        var cursor = start
        // UTC day stamps, so step in UTC days rather than local ones.
        while cursor <= end {
            let stamp = LogDay.stamp(for: cursor)
            if stamps.last != stamp { stamps.append(stamp) }
            cursor = cursor.addingTimeInterval(86_400)
        }
        let endStamp = LogDay.stamp(for: end)
        if stamps.last != endStamp { stamps.append(endStamp) }
        return stamps
    }

    /// Reads every event in `window` ending at `now`.
    public func entries(window: LogWindow, now: Date = Date()) -> [LogEntry] {
        let start = now.addingTimeInterval(-window.seconds)
        var entries: [LogEntry] = []
        for stamp in Self.dayStamps(from: start, to: now) {
            entries.append(contentsOf: read(prefix: "decisions", day: stamp))
            entries.append(contentsOf: read(prefix: "integrity", day: stamp))
        }
        return entries
            .filter { $0.date >= start }
            .sorted { $0.date < $1.date }
    }

    /// The daemon's **structured** decision events between `start` and `end`
    /// (inclusive), honouring the source's user scope. Used by a Capture
    /// session to enrich sudo attempts with what Serberus decided (rule,
    /// profile, outcome, pinned identity) — the display `LogEntry` flattens
    /// those fields into prose, so the enrichment reads the events themselves.
    public func decisionEvents(from start: Date, to end: Date) -> [DecisionEvent] {
        let decoder = Self.makeDecoder()
        var events: [DecisionEvent] = []
        for stamp in Self.dayStamps(from: start, to: end) {
            let url = directory.appendingPathComponent("decisions-\(stamp).jsonl")
            guard let data = try? Data(contentsOf: url), !data.isEmpty else { continue }
            for line in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true) {
                guard let event = try? decoder.decode(DecisionEvent.self, from: Data(line.utf8)) else { continue }
                guard event.timestamp >= start, event.timestamp <= end else { continue }
                if let userName, event.userName != userName { continue }
                events.append(event)
            }
        }
        return events.sorted { $0.timestamp < $1.timestamp }
    }

    /// Reads one day file from `offset` bytes, returning the new entries and
    /// the offset to resume from.
    ///
    /// Byte-offset resumption (rather than re-reading and de-duplicating) is
    /// what makes the live tail cheap: these files only ever grow, and a day's
    /// decisions on a busy Mac would otherwise be re-parsed every poll.
    func readIncremental(prefix: String, day: String, from offset: UInt64) -> (entries: [LogEntry], offset: UInt64) {
        let url = directory.appendingPathComponent("\(prefix)-\(day).jsonl")
        guard let handle = try? FileHandle(forReadingFrom: url) else { return ([], offset) }
        defer { try? handle.close() }

        guard let size = try? handle.seekToEnd() else { return ([], offset) }
        // A shrinking file means rotation or truncation; restart from 0 rather
        // than seeking past the end and going silent forever.
        let start = size < offset ? 0 : offset
        guard size > start else { return ([], size) }

        try? handle.seek(toOffset: start)
        guard let data = try? handle.readToEnd(), !data.isEmpty else { return ([], start) }

        // Only consume through the last newline: the daemon appends with a
        // plain write, so a read can land mid-line and parsing a partial JSON
        // object would drop a real event.
        guard let lastNewline = data.lastIndex(of: 0x0A) else { return ([], start) }
        let complete = data[data.startIndex...lastNewline]
        let consumed = start + UInt64(complete.count)

        let text = String(decoding: complete, as: UTF8.self)
        let entries = text.split(separator: "\n", omittingEmptySubsequences: true)
            .compactMap { decode(line: String($0), prefix: prefix) }
            .filter { matchesUser($0) }
        return (entries, consumed)
    }

    private func read(prefix: String, day: String) -> [LogEntry] {
        readIncremental(prefix: prefix, day: day, from: 0).entries
    }

    private func matchesUser(_ entry: LogEntry) -> Bool {
        guard let userName else { return true }
        // Integrity events are daemon-wide and carry no user; they are the
        // context that explains a decision (mode changes, policy reloads), so
        // scoping them away would leave the user's own denials unexplained.
        guard let owner = entry.userName else { return true }
        return owner == userName
    }

    // MARK: Decoding

    /// Decoder matching `LogEncoding.encodeLine`'s ISO8601 date strategy.
    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            guard let date = ISO8601.date(from: text) else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath, debugDescription: "bad ISO8601 date: \(text)")
                )
            }
            return date
        }
        return decoder
    }

    private func decode(line: String, prefix: String) -> LogEntry? {
        let decoder = Self.makeDecoder()
        let data = Data(line.utf8)
        if prefix == "integrity" {
            guard let event = try? decoder.decode(IntegrityEvent.self, from: data) else { return nil }
            return LogEntry(event)
        }
        guard let event = try? decoder.decode(DecisionEvent.self, from: data) else { return nil }
        return LogEntry(event)
    }
}

// MARK: - Mapping onto the display model

extension LogEntry {
    /// Renders a decision event as a log line.
    init(_ event: DecisionEvent) {
        let verb: String
        let level: LogLevel
        switch event.outcome {
        case .granted:
            verb = "ALLOW"
            level = .default
        case .denied:
            verb = "DENY"
            // A denial is what the user opened Intel to find, so it is
            // surfaced at error level rather than blending into the stream.
            level = .error
        case .wouldGrant:
            verb = "WOULD-ALLOW"
            level = .default
        case .wouldDeny:
            // Not a real denial: in monitor/audit the command still ran.
            verb = "WOULD-DENY"
            level = .default
        }

        let subject = event.sudoCommand ?? event.authURI ?? event.processPath
        var text = "\(verb) \(subject)"
        if let arguments = event.arguments, !arguments.isEmpty {
            text += " \(arguments.joined(separator: " "))"
        }
        text += "  [user=\(event.userName) mode=\(event.enforcementMode.rawValue)"
        if let ruleID = event.ruleID { text += " rule=\(ruleID)" }
        if event.cacheHit { text += " cached" }
        text += "]"

        self.init(
            timestamp: ISO8601.string(from: event.timestamp),
            date: event.timestamp,
            level: level,
            subsystem: BundleConfig.logSubsystem,
            category: "decisions",
            message: text,
            processImagePath: event.processPath,
            processID: 0,
            userName: event.userName
        )
    }

    /// Renders an integrity event as a log line.
    init(_ event: IntegrityEvent) {
        // These are the daemon's own state changes; an hmac violation is the
        // one that means someone tampered with the record itself.
        let level: LogLevel = event.kind == .hmacViolation ? .fault : .default
        self.init(
            timestamp: ISO8601.string(from: event.timestamp),
            date: event.timestamp,
            level: level,
            subsystem: BundleConfig.logSubsystem,
            category: "integrity",
            message: "\(event.kind.rawValue): \(event.detail)",
            processImagePath: "/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon",
            processID: 0,
            userName: nil
        )
    }
}

extension LogWindow {
    /// Window length in seconds, for filtering JSONL (which `log`'s `--last`
    /// flag cannot do for us).
    public var seconds: TimeInterval {
        switch self {
        case .fiveMinutes: return 5 * 60
        case .fifteenMinutes: return 15 * 60
        case .oneHour: return 3_600
        case .sixHours: return 6 * 3_600
        case .oneDay: return 24 * 3_600
        case .sevenDays: return 7 * 24 * 3_600
        }
    }
}
