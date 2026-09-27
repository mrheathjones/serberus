import Foundation

/// One file the Sentinel attached to this Mac's Jamf computer record — a
/// capture (`.serberuscapture`) or an Intel support bundle (`.zip`).
public struct JamfUploadRecord: Codable, Sendable, Equatable, Identifiable {
    public enum Kind: String, Codable, Sendable, Equatable, CaseIterable {
        case capture
        case intel
    }

    public let id: String
    public let kind: Kind
    public let fileName: String
    public let uploadedAt: Date
    public let computerID: String
    public let serialNumber: String?
    public let sizeBytes: Int?

    public init(id: String = UUID().uuidString, kind: Kind, fileName: String, uploadedAt: Date,
                computerID: String, serialNumber: String?, sizeBytes: Int?) {
        self.id = id
        self.kind = kind
        self.fileName = fileName
        self.uploadedAt = uploadedAt
        self.computerID = computerID
        self.serialNumber = serialNumber
        self.sizeBytes = sizeBytes
    }
}

/// The Sentinel's record of what it uploaded to Jamf, for the **Serberus —
/// Uploads** / **Serberus — Last Upload** extension attributes: a root EA
/// script at recon reads every user's ledger and reports "this Mac uploaded
/// N files recently", which Jamf smart groups and Commander's Fleet Observer
/// posture chips pick up. Commander's own truth for *what is still on the
/// record* is the inventory's attachments list (it deletes what it has
/// harvested) — the ledger is the device-side signal, not the queue.
///
/// Lives next to the Sentinel's other per-user caches
/// (`~/Library/Application Support/Serberus/
/// jamf-uploads.json`), world-readable by design (the EA runs as root;
/// nothing in it is secret — file names, times, the Jamf computer id).
/// Capped so it never grows without bound; entries older than
/// ``retention`` are dropped on every write.
public struct JamfUploadLedger: Sendable {
    /// How long an upload stays in the ledger (the EA's "recent" window).
    public static let retention: TimeInterval = 30 * 86_400
    public static let maxEntries = 200

    public let fileURL: URL
    private let now: @Sendable () -> Date

    /// `~/Library/Application Support/Serberus/jamf-uploads.json`
    public static func defaultURL() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return base.appendingPathComponent("Serberus", isDirectory: true)
            .appendingPathComponent("jamf-uploads.json")
    }

    public init(fileURL: URL? = nil, now: @escaping @Sendable () -> Date = { Date() }) {
        self.fileURL = fileURL ?? Self.defaultURL()
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("jamf-uploads.json")
        self.now = now
    }

    /// Everything currently in the ledger, oldest first. A missing or
    /// unreadable file is an empty ledger (never an error — the EA must
    /// still report).
    public func entries() -> [JamfUploadRecord] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        return (try? Self.decoder.decode([JamfUploadRecord].self, from: data)) ?? []
    }

    /// Appends one upload, prunes expired / excess entries, and writes the
    /// file atomically (0644 so a root EA — or any reader — can see it).
    @discardableResult
    public func record(kind: JamfUploadRecord.Kind, fileName: String, computerID: String,
                       serialNumber: String?, sizeBytes: Int?) throws -> JamfUploadRecord {
        let entry = JamfUploadRecord(kind: kind, fileName: fileName, uploadedAt: now(),
                                     computerID: computerID, serialNumber: serialNumber, sizeBytes: sizeBytes)
        var all = entries()
        all.append(entry)
        try write(Self.pruned(all, now: now()))
        return entry
    }

    /// Drops entries older than ``retention`` and keeps the newest ``maxEntries``.
    static func pruned(_ entries: [JamfUploadRecord], now: Date) -> [JamfUploadRecord] {
        let cutoff = now.addingTimeInterval(-retention)
        let kept = entries.filter { $0.uploadedAt >= cutoff }.sorted { $0.uploadedAt < $1.uploadedAt }
        return Array(kept.suffix(maxEntries))
    }

    private func write(_ entries: [JamfUploadRecord]) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try Self.encoder.encode(entries)
        try data.write(to: fileURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: fileURL.path)
    }

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }()

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
