import Foundation

/// Severity of one unified-log line, as reported by `log(1)`'s `messageType`.
public enum LogLevel: String, Sendable, CaseIterable, Codable {
    case debug = "Debug"
    case info = "Info"
    case `default` = "Default"
    case error = "Error"
    case fault = "Fault"

    /// Ordering for "this level and above" filtering.
    public var severity: Int {
        switch self {
        case .debug: return 0
        case .info: return 1
        case .default: return 2
        case .error: return 3
        case .fault: return 4
        }
    }

    public var label: String {
        switch self {
        case .debug: return "Debug"
        case .info: return "Info"
        case .default: return "Notice"
        case .error: return "Error"
        case .fault: return "Fault"
        }
    }

    /// Label for a minimum-level FILTER menu, where choosing a level keeps
    /// that level and everything more severe: "All levels" for the floor,
    /// "<Level> and above" for the rest.
    public var filterLabel: String {
        switch self {
        case .debug: return "All levels"
        default: return "\(label) and above"
        }
    }
}

/// One parsed unified-log line.
///
/// Field names mirror `log show --style ndjson` output verbatim (verified
/// against live output, not assumed).
public struct LogEntry: Sendable, Identifiable, Equatable, Codable {
    public let id: UUID
    /// Display string, verbatim from the source.
    public let timestamp: String
    /// Parsed instant, used to merge and window entries from different
    /// sources (the unified log and the JSONL logs order independently, so
    /// the display string alone cannot sort them against each other).
    public let date: Date
    public let level: LogLevel
    public let subsystem: String
    public let category: String
    public let message: String
    public let processImagePath: String
    public let processID: Int
    /// User the event belongs to, when the source knows it (JSONL decision
    /// events do; unified-log lines do not). `nil` means "not user-scoped".
    public let userName: String?

    /// Last path component of the emitting process, for display.
    public var processName: String {
        (processImagePath as NSString).lastPathComponent
    }

    public init(
        id: UUID = UUID(),
        timestamp: String,
        date: Date = Date(),
        level: LogLevel,
        subsystem: String,
        category: String,
        message: String,
        processImagePath: String,
        processID: Int,
        userName: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.date = date
        self.level = level
        self.subsystem = subsystem
        self.category = category
        self.message = message
        self.processImagePath = processImagePath
        self.processID = processID
        self.userName = userName
    }
}

/// Decodes `log(1)` NDJSON lines into ``LogEntry`` values.
///
/// ## Why this tolerates garbage
///
/// `log stream --style ndjson` writes a human preamble —
/// `Filtering the log data using "…"` — to **stdout**, interleaved with the
/// JSON, not to stderr (verified against live output). A parser that decoded
/// every line strictly would throw on the first line of every stream. Lines
/// that are not decodable log events are skipped rather than surfaced as
/// errors.
public struct LogLineParser: Sendable {
    public init() {}

    /// Parses `log`'s timestamp, e.g. `2026-07-16 19:19:06.595808-0400`.
    ///
    /// Not ISO8601: `log` uses a space separator and 6-digit fractional
    /// seconds, which `ISO8601DateFormatter` rejects. Verified against live
    /// `log show --style ndjson` output.
    static func parseTimestamp(_ text: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"
        if let date = formatter.date(from: text) { return date }
        // Some records carry milliseconds rather than microseconds.
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
        return formatter.date(from: text)
    }

    /// Raw NDJSON shape emitted by `log(1)`.
    private struct Raw: Decodable {
        let timestamp: String?
        let messageType: String?
        let eventMessage: String?
        let subsystem: String?
        let category: String?
        let processImagePath: String?
        let processID: Int?
        let eventType: String?
    }

    /// Parses one line, returning `nil` for the preamble, blank lines, and
    /// any non-`logEvent` record.
    public func parse(line: String) -> LogEntry? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        // Cheap gate before paying for a JSON decode on the preamble.
        guard trimmed.hasPrefix("{") else { return nil }
        guard let raw = try? JSONDecoder().decode(Raw.self, from: Data(trimmed.utf8)) else {
            return nil
        }
        // `log` also emits activity/state records; only real messages carry a
        // usable eventMessage.
        guard let message = raw.eventMessage, let timestamp = raw.timestamp else { return nil }
        if let eventType = raw.eventType, eventType != "logEvent" { return nil }

        return LogEntry(
            timestamp: timestamp,
            // An unparseable timestamp still yields a usable line — the
            // display string is verbatim either way; only cross-source
            // ordering degrades, which beats dropping the record.
            date: Self.parseTimestamp(timestamp) ?? Date(),
            // An unrecognised messageType is treated as Default rather than
            // dropped: losing a line is worse than mislabelling its severity.
            level: raw.messageType.flatMap(LogLevel.init(rawValue:)) ?? .default,
            subsystem: raw.subsystem ?? "",
            category: raw.category ?? "",
            message: message,
            processImagePath: raw.processImagePath ?? "",
            processID: raw.processID ?? 0
        )
    }

    /// Parses a full NDJSON document (the `log show` path).
    public func parse(document: String) -> [LogEntry] {
        document.split(separator: "\n", omittingEmptySubsequences: true)
            .compactMap { parse(line: String($0)) }
    }
}
