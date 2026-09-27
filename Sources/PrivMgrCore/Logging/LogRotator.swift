import Foundation

/// Daily log retention enforcement.
///
/// Rotation is implicit — writers stamp filenames by day. The rotator
/// deletes day files (and their `.hmac` sidecars) older than the configured
/// retention window (`logRetentionDays`, default 90).
public struct LogRotator: Sendable {
    private let directory: URL

    public init(directory: URL = URL(fileURLWithPath: BundleConfig.logDirectory)) {
        self.directory = directory
    }

    /// Deletes Serberus log files whose day stamp is older than
    /// `retentionDays` before `now`.
    ///
    /// Only files matching `<prefix>-YYYY-MM-DD.jsonl[.hmac]` are touched;
    /// anything else in the directory is left alone.
    /// - Returns: Names of the files removed, sorted.
    @discardableResult
    public func prune(retentionDays: Int, now: Date) throws -> [String] {
        guard retentionDays > 0 else { return [] }
        let fileManager = FileManager.default
        guard let names = try? fileManager.contentsOfDirectory(atPath: directory.path) else {
            return []
        }
        let cutoff = LogDay.stamp(for: now.addingTimeInterval(-Double(retentionDays) * 86_400))

        var removed: [String] = []
        for name in names.sorted() {
            guard let day = Self.dayStamp(fromFilename: name) else { continue }
            // Day stamps are zero-padded ISO dates, so string comparison is
            // chronological comparison.
            if day < cutoff {
                try fileManager.removeItem(at: directory.appendingPathComponent(name))
                removed.append(name)
            }
        }
        return removed
    }

    /// Extracts `YYYY-MM-DD` from `<prefix>-YYYY-MM-DD.jsonl[.hmac]`.
    static func dayStamp(fromFilename name: String) -> String? {
        guard name.hasSuffix(".jsonl") || name.hasSuffix(".jsonl.hmac") else { return nil }
        let stem = name.replacingOccurrences(of: ".jsonl.hmac", with: "")
            .replacingOccurrences(of: ".jsonl", with: "")
        guard stem.count > 11 else { return nil }
        let day = String(stem.suffix(10))
        let separator = stem[stem.index(stem.endIndex, offsetBy: -11)]
        guard separator == "-" else { return nil }
        let parts = day.split(separator: "-")
        guard parts.count == 3,
              parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
              parts.allSatisfy({ $0.allSatisfy(\.isNumber) }) else { return nil }
        return day
    }
}
