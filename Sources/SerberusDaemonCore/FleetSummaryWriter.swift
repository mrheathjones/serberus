import Foundation
import PrivMgrCore

/// Fleet telemetry: the decision counts/trends the daemon publishes for
/// Jamf Extension Attributes to harvest.
///
/// All scalars, so each key drops straight into an EA. `lastDecisionAt` is the
/// genuine newest event (even if older than the 24h window) so a silent Mac
/// reads as silent; the count keys are a true rolling 24h.
public struct FleetSummary: Sendable, Equatable {
    public var denials24h: Int
    public var grants24h: Int
    public var prompts24h: Int
    public var activeGrants: Int
    public var lastDecisionAt: Date?
    public var updatedAt: Date
    public var daemonVersion: String

    public init(
        denials24h: Int,
        grants24h: Int,
        prompts24h: Int,
        activeGrants: Int,
        lastDecisionAt: Date?,
        updatedAt: Date,
        daemonVersion: String
    ) {
        self.denials24h = denials24h
        self.grants24h = grants24h
        self.prompts24h = prompts24h
        self.activeGrants = activeGrants
        self.lastDecisionAt = lastDecisionAt
        self.updatedAt = updatedAt
        self.daemonVersion = daemonVersion
    }

    /// The property-list representation written to disk / read by the EAs.
    /// Optional dates are simply omitted when absent (the EA treats a missing
    /// key as "no decisions yet").
    public var plistDictionary: [String: Any] {
        // Whole-second ISO (no fractional seconds) so the Jamf Date EA's
        // `date -j -f '%Y-%m-%dT%H:%M:%SZ'` parses lastDecisionAt cleanly.
        var dict: [String: Any] = [
            "denials24h": denials24h,
            "grants24h": grants24h,
            "prompts24h": prompts24h,
            "activeGrants": activeGrants,
            "updatedAt": ISO8601.secondString(from: updatedAt),
            "daemonVersion": daemonVersion,
        ]
        if let lastDecisionAt {
            dict["lastDecisionAt"] = ISO8601.secondString(from: lastDecisionAt)
        }
        return dict
    }
}

/// Computes ``FleetSummary`` from the signed decision log + active grants and
/// writes it to a world-readable plist, atomically, on each daemon reload tick.
///
/// Fail-safe by contract: an unreadable log or missing day contributes zeros,
/// never an error, and a write failure is logged but never propagated — the
/// writer must never block or crash the reload loop it runs inside.
public struct FleetSummaryWriter: Sendable {
    private let reader: DecisionCountReader
    private let outputURL: URL
    private let daemonVersion: String

    public init(logDirectory: URL, outputURL: URL, daemonVersion: String) {
        self.reader = DecisionCountReader(directory: logDirectory)
        self.outputURL = outputURL
        self.daemonVersion = daemonVersion
    }

    /// The day-stamp files spanning a rolling 24h window: yesterday (UTC) may
    /// still hold events inside the last 24h around the day boundary.
    private func windowDays(now: Date) -> [String] {
        [LogDay.stamp(for: now), LogDay.stamp(for: now.addingTimeInterval(-86_400))]
    }

    /// Pure computation (no I/O beyond the log read) so tests assert on the
    /// typed value rather than a serialized plist.
    public func summary(activeGrants: Int, now: Date) -> FleetSummary {
        let counts = reader.counts(days: windowDays(now: now), since: now.addingTimeInterval(-86_400))
        return FleetSummary(
            denials24h: counts.denied,
            grants24h: counts.granted,
            prompts24h: counts.prompts,
            activeGrants: max(0, activeGrants),
            lastDecisionAt: counts.latest,
            updatedAt: now,
            daemonVersion: daemonVersion
        )
    }

    /// Computes and writes the summary plist atomically. Returns whether the
    /// write landed; never throws.
    @discardableResult
    public func write(activeGrants: Int, now: Date) -> Bool {
        let summary = summary(activeGrants: activeGrants, now: now)
        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: summary.plistDictionary, format: .xml, options: 0
        ) else {
            DaemonLog.integrity.error("Failed to serialize fleet-summary.plist")
            return false
        }
        do {
            try FileManager.default.createDirectory(
                at: outputURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: outputURL, options: .atomic)
            // World-readable: standard-user EAs run as the Jamf recon context and
            // must read it. The support dir is already root-owned/traversable.
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o644], ofItemAtPath: outputURL.path
            )
            return true
        } catch {
            DaemonLog.integrity.error(
                "Failed to write fleet-summary.plist: \(error.localizedDescription, privacy: .public)"
            )
            return false
        }
    }
}
