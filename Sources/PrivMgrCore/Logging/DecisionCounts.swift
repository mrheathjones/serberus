import Foundation

/// Outcome tallies for one day's `decisions-YYYY-MM-DD.jsonl` file.
///
/// Feeds the fleet-summary plist (fleet telemetry). "granted" folds in the
/// audit-mode `would-grant`, "denied" folds in `would-deny`, so the numbers
/// read the same whether a Mac is enforcing or observing.
public struct DecisionDayCounts: Sendable, Equatable {
    /// `granted` + `would-grant`.
    public var granted: Int
    /// `denied` + `would-deny`.
    public var denied: Int
    /// Decisions that raised an interactive elevation prompt.
    public var prompts: Int
    /// Newest event timestamp seen, or `nil` for an empty/absent day.
    public var latest: Date?

    public init(granted: Int = 0, denied: Int = 0, prompts: Int = 0, latest: Date? = nil) {
        self.granted = granted
        self.denied = denied
        self.prompts = prompts
        self.latest = latest
    }

    /// Adds two days' tallies (keeping the later `latest`).
    public static func + (lhs: DecisionDayCounts, rhs: DecisionDayCounts) -> DecisionDayCounts {
        DecisionDayCounts(
            granted: lhs.granted + rhs.granted,
            denied: lhs.denied + rhs.denied,
            prompts: lhs.prompts + rhs.prompts,
            latest: [lhs.latest, rhs.latest].compactMap { $0 }.max()
        )
    }
}

/// One denial or prompt event, as the debug-telemetry EA carries it per device
/// and Commander lists it on the device record. Compact + redacted (arguments
/// are already stripped in the decision log); shared by the daemon writer and
/// the Commander reader (both link PrivMgrCore).
public struct FleetDecisionEvent: Codable, Sendable, Equatable, Identifiable, Hashable {
    /// When the decision was made.
    public var at: Date
    /// `sudo` or `authuri`.
    public var kind: String
    /// The sudo command path (or its redacted argv-less form) or the authorization right.
    public var target: String
    /// The user the decision was made for.
    public var user: String
    /// `granted` or `denied` (mode-aware `would-*` folded in).
    public var outcome: String
    /// Whether this decision raised an interactive prompt.
    public var prompt: Bool
    /// Why this decision landed the way it did — "No matching rule" (default
    /// deny), the matched rule id, or the prompt rule. Optional so a list written
    /// by an older daemon (no reason) still decodes.
    public var reason: String?
    /// The user's typed justification for an elevation prompt (already redacted
    /// in the decision log). Present only on prompts that required one and were
    /// approved; `nil` for denials, silent decisions, and older lists.
    public var justification: String?

    public init(at: Date, kind: String, target: String, user: String,
                outcome: String, prompt: Bool, reason: String? = nil,
                justification: String? = nil) {
        self.at = at
        self.kind = kind
        self.target = target
        self.user = user
        self.outcome = outcome
        self.prompt = prompt
        self.reason = reason
        self.justification = justification
    }

    // Stable identity for SwiftUI lists (two identical events a second apart
    // still differ by `at`).
    public var id: String { "\(at.timeIntervalSince1970)|\(kind)|\(target)|\(user)|\(outcome)|\(prompt)" }

    /// Encodes a list to a single-line JSON string — the exact bytes the daemon
    /// writes and the EA carries. Dates are ISO-8601 so a shell/`jq` reader can
    /// also make sense of them.
    public static func encodeList(_ events: [FleetDecisionEvent]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(ISO8601.string(from: date))
        }
        guard let data = try? encoder.encode(events) else { return "[]" }
        return String(decoding: data, as: UTF8.self)
    }

    /// Decodes the list the EA carried (Commander side). Empty on any failure.
    public static func decodeList(from json: String) -> [FleetDecisionEvent] {
        let trimmed = json.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            return ISO8601.date(from: raw) ?? .distantPast
        }
        return (try? decoder.decode([FleetDecisionEvent].self, from: data)) ?? []
    }
}

/// Reads a day's signed decision JSONL and tallies outcomes without loading the
/// whole file into memory or trusting its size.
///
/// Deliberately independent of ``DecisionLogger``'s signing actor: counting is a
/// read-only, key-free operation, and the fleet-summary writer must never block
/// the daemon reload loop. It decodes only the three fields it needs from each
/// line (a tolerant subset of ``DecisionEvent``), so a malformed or truncated
/// line is skipped, never fatal, and older lines written before `requiredPrompt`
/// existed count as "no prompt".
public struct DecisionCountReader: Sendable {
    private let directory: URL
    /// Hard cap on lines read per day file — a runaway log can never stall a
    /// reload tick. At ~one line per decision this is far above any real day.
    private let maxLines: Int

    public init(directory: URL, maxLines: Int = 200_000) {
        self.directory = directory
        self.maxLines = max(0, maxLines)
    }

    /// The minimal shape decoded from each JSONL line. Optional throughout so a
    /// partial or older line still parses; unknown keys are ignored. The last
    /// four fields are read only by ``recentEvents(days:since:limit:)``.
    private struct Record: Decodable {
        var outcome: DecisionEvent.Outcome?
        var timestamp: Date?
        var requiredPrompt: Bool?
        var sudoCommand: String?
        var authURI: String?
        var processPath: String?
        var userName: String?
        var ruleID: String?
        var eventID: UUID?
        /// Redacted argv — present only when the matched rule opted in. Lets the
        /// event show the full attempted command (e.g. "jamf checkJSSConnection"),
        /// not just the path.
        var arguments: [String]?
        /// The user's (already-redacted) justification, present on approved
        /// prompts that required one.
        var justification: String?
    }

    private func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            guard let date = ISO8601.date(from: raw) else {
                throw DecodingError.dataCorruptedError(
                    in: container, debugDescription: "unparseable timestamp \(raw)"
                )
            }
            return date
        }
        return decoder
    }

    /// Tallies one day. An unreadable or absent file contributes all-zeros and
    /// never throws — a missing day is normal (the Mac made no decisions).
    ///
    /// - Parameter since: When non-nil, only events at or after this instant are
    ///   counted (a true rolling window, so `denials24h` means the last 24h and
    ///   not "today + yesterday's calendar days"). `latest` always reflects the
    ///   genuine newest event regardless of the window, so a stale Mac still
    ///   reports its true last-decision time.
    public func counts(day: String, since: Date? = nil) -> DecisionDayCounts {
        let fileURL = directory.appendingPathComponent("decisions-\(day).jsonl")
        guard let content = try? String(contentsOf: fileURL, encoding: .utf8) else {
            return DecisionDayCounts()
        }

        let decoder = makeDecoder()
        var counts = DecisionDayCounts()
        var seen = 0
        for line in content.split(separator: "\n", omittingEmptySubsequences: true) {
            if seen >= maxLines { break }
            seen += 1
            guard let record = try? decoder.decode(Record.self, from: Data(line.utf8)) else { continue }
            // `latest` tracks every decoded event, even ones outside the window.
            if let ts = record.timestamp {
                counts.latest = max(counts.latest ?? ts, ts)
            }
            // Windowed counts skip events older than the cutoff. A line with no
            // timestamp is counted (it cannot be placed, so it is not excluded).
            if let since, let ts = record.timestamp, ts < since { continue }
            switch record.outcome {
            case .granted, .wouldGrant: counts.granted += 1
            case .denied, .wouldDeny: counts.denied += 1
            case .none: break
            }
            if record.requiredPrompt == true { counts.prompts += 1 }
        }
        return counts
    }

    /// Sum of `counts(day:since:)` over `days` (typically today + yesterday).
    public func counts(days: [String], since: Date? = nil) -> DecisionDayCounts {
        days.reduce(DecisionDayCounts()) { $0 + counts(day: $1, since: since) }
    }

    /// The recent denial / prompt events across `days`, newest first, capped at
    /// `limit`. A qualifying event is one that was DENIED (or would-deny) OR that
    /// raised a prompt — the "individual denials and prompts" the debug EA
    /// publishes. Silent grants are excluded. Never throws.
    ///
    /// `debugArguments` are the arguments the daemon captured under debug mode,
    /// by decision event ID. They are never written to the decision log (which
    /// every local user can read); they are joined in here, for the root-only
    /// event list, when the logged event carries none of its own.
    public func recentEvents(days: [String], since: Date? = nil, limit: Int = 40,
                             debugArguments: [UUID: [String]] = [:]) -> [FleetDecisionEvent] {
        let decoder = makeDecoder()
        var events: [FleetDecisionEvent] = []
        for day in days {
            let fileURL = directory.appendingPathComponent("decisions-\(day).jsonl")
            guard let content = try? String(contentsOf: fileURL, encoding: .utf8) else { continue }
            var seen = 0
            for line in content.split(separator: "\n", omittingEmptySubsequences: true) {
                if seen >= maxLines { break }
                seen += 1
                guard let record = try? decoder.decode(Record.self, from: Data(line.utf8)) else { continue }
                if let since, let ts = record.timestamp, ts < since { continue }
                let isDenial = record.outcome == .denied || record.outcome == .wouldDeny
                let isPrompt = record.requiredPrompt == true
                guard isDenial || isPrompt else { continue }
                let isGrant = record.outcome == .granted || record.outcome == .wouldGrant
                let kind = (record.authURI?.isEmpty == false) ? "authuri" : "sudo"
                let target: String
                if kind == "authuri" {
                    target = record.authURI ?? ""
                } else {
                    // Command + its (redacted) args when captured, so a denial
                    // reads "jamf checkJSSConnection" not just "/usr/bin/jamf".
                    let command = record.sudoCommand ?? record.processPath ?? ""
                    let captured = record.eventID.flatMap { debugArguments[$0] }
                    if let args = record.arguments ?? captured, !args.isEmpty {
                        target = ([command] + args).joined(separator: " ")
                    } else {
                        target = command
                    }
                }
                let reason: String
                if isPrompt {
                    reason = record.ruleID.map { "Prompt required (rule \($0))" } ?? "Prompt required"
                } else {   // denial (silent grants were filtered out above)
                    reason = record.ruleID.map { "Matched deny rule \($0)" } ?? "No matching rule"
                }
                events.append(FleetDecisionEvent(
                    at: record.timestamp ?? .distantPast,
                    kind: kind,
                    target: target,
                    user: record.userName ?? "",
                    outcome: isGrant ? "granted" : "denied",
                    prompt: isPrompt,
                    reason: reason,
                    justification: record.justification?.isEmpty == false ? record.justification : nil
                ))
            }
        }
        return Array(events.sorted { $0.at > $1.at }.prefix(max(0, limit)))
    }
}
