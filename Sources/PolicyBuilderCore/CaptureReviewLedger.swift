import Foundation
import Observation
import PrivMgrCore

/// Commander's own record of which Sentinel uploads it has already **dealt
/// with** — imported into a definition, rejected after review, or downloaded
/// to disk. Jamf only knows whether a file is still attached to a computer
/// record; it cannot say whether an admin has looked at it. Without this
/// ledger "Uploads waiting" on the Dashboard could only ever drop when the
/// file was deleted from Jamf (the harvest switch, off by default, and it
/// needs the Update Computers API role) — so an imported or reviewed capture
/// kept counting as waiting. With it, *waiting = on a record AND not in the
/// ledger*, whether or not the record was cleaned up.
///
/// Keyed by the upload's file name (the Sentinel stamps serial + time into
/// it, so it is unique and survives a refresh — Jamf attachment ids do not
/// have to). Persisted as JSON next to the policy library; `nil` URL keeps
/// it in memory (tests).
@MainActor
@Observable
public final class CaptureReviewLedger {
    public enum Decision: String, Codable, Sendable, CaseIterable, Equatable {
        /// At least one definition was created from the capture.
        case imported
        /// Reviewed, and deliberately NOT made into a definition.
        case rejected
        /// Saved to disk from the Fleet Observer (captures and Intel bundles).
        case downloaded

        public var label: String {
            switch self {
            case .imported: return "Imported"
            case .rejected: return "Rejected"
            case .downloaded: return "Downloaded"
            }
        }
    }

    public struct Entry: Codable, Equatable, Sendable, Identifiable {
        public var id: String { key }
        /// ``CaptureReviewLedger/key(forFileName:)`` of `fileName`.
        public let key: String
        public let fileName: String
        public let decision: Decision
        public let reviewedAt: Date
        public let deviceName: String?
        public let serialNumber: String?
        public let computerID: String?
        /// Definitions created from the capture (imported only).
        public let definitionIDs: [String]
        public let note: String?

        public init(fileName: String, decision: Decision, reviewedAt: Date = Date(),
                    deviceName: String? = nil, serialNumber: String? = nil, computerID: String? = nil,
                    definitionIDs: [String] = [], note: String? = nil) {
            self.key = CaptureReviewLedger.key(forFileName: fileName)
            self.fileName = fileName
            self.decision = decision
            self.reviewedAt = reviewedAt
            self.deviceName = deviceName
            self.serialNumber = serialNumber
            self.computerID = computerID
            self.definitionIDs = definitionIDs
            self.note = note
        }
    }

    /// Every review, keyed by the normalized file name.
    public private(set) var entries: [String: Entry] = [:]
    /// Set when the last write failed (disk full, permissions) — the in-memory
    /// ledger still applies for this session; the UI can mention it.
    public private(set) var lastSaveError: String?

    @ObservationIgnored private let url: URL?

    /// - Parameter url: the JSON file; `nil` keeps the ledger in memory only.
    public init(url: URL? = nil) {
        self.url = url
        reload()
    }

    /// `~/Library/Application Support/Serberus/capture-reviews.json`
    /// — beside `policies.json` (same app-support directory Commander already owns).
    nonisolated public static func defaultURL() -> URL {
        ProfileLibraryStore.defaultURL().deletingLastPathComponent().appendingPathComponent("capture-reviews.json")
    }

    // MARK: Keys

    /// The identity of an upload across Jamf / disk / Sentinel: the file name
    /// lowercased and trimmed, with a capture's extension made canonical
    /// (`…serberuscapture` without the dot — as Jamf has returned it — and
    /// `….serberuscapture` are the same file).
    nonisolated public static func key(forFileName name: String) -> String {
        var key = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let ext = RuleCapture.fileExtension
        if key.hasSuffix(ext), !key.hasSuffix(".\(ext)") {
            key = String(key.dropLast(ext.count)) + ".\(ext)"
        }
        return key
    }

    // MARK: Reads

    public func entry(forFileName name: String) -> Entry? { entries[Self.key(forFileName: name)] }
    public func entry(for upload: FleetUpload) -> Entry? { entry(forFileName: upload.fileName) }
    public func decision(forFileName name: String) -> Decision? { entry(forFileName: name)?.decision }
    public func decision(for upload: FleetUpload) -> Decision? { entry(for: upload)?.decision }
    public func isReviewed(_ upload: FleetUpload) -> Bool { entry(for: upload) != nil }

    public var count: Int { entries.count }
    /// Newest first.
    public var all: [Entry] { entries.values.sorted { $0.reviewedAt > $1.reviewedAt } }

    // MARK: Writes

    /// Records (or replaces) the decision for a file name. A later decision
    /// overrides an earlier one — a "downloaded" capture that is then imported
    /// reads as imported.
    @discardableResult
    public func record(fileName: String, decision: Decision, deviceName: String? = nil, serialNumber: String? = nil,
                       computerID: String? = nil, definitionIDs: [String] = [], note: String? = nil,
                       at date: Date = Date()) -> Entry {
        let entry = Entry(fileName: fileName, decision: decision, reviewedAt: date, deviceName: deviceName,
                          serialNumber: serialNumber, computerID: computerID, definitionIDs: definitionIDs, note: note)
        entries[entry.key] = entry
        save()
        return entry
    }

    /// Records a decision for a Fleet Observer upload (device facts come from it).
    @discardableResult
    public func record(_ upload: FleetUpload, decision: Decision, definitionIDs: [String] = [], note: String? = nil,
                       at date: Date = Date()) -> Entry {
        record(fileName: upload.fileName, decision: decision, deviceName: upload.deviceName,
               serialNumber: upload.serialNumber, computerID: upload.computerID,
               definitionIDs: definitionIDs, note: note, at: date)
    }

    /// Drops a review so the upload counts as waiting again ("Reset review").
    public func forget(fileName: String) {
        guard entries.removeValue(forKey: Self.key(forFileName: fileName)) != nil else { return }
        save()
    }

    public func removeAll() {
        entries = [:]
        save()
    }

    // MARK: Persistence

    /// Re-reads the file (another Commander on the same account, or a restore).
    public func reload() {
        guard let url, let data = try? Data(contentsOf: url),
              let decoded = try? Self.decoder.decode([Entry].self, from: data) else { return }
        entries = Dictionary(decoded.map { ($0.key, $0) }, uniquingKeysWith: { a, b in a.reviewedAt >= b.reviewedAt ? a : b })
    }

    @discardableResult
    private func save() -> Bool {
        guard let url else { return true }
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try Self.encoder.encode(entries.values.sorted { $0.key < $1.key })
            try data.write(to: url, options: .atomic)
            lastSaveError = nil
            return true
        } catch {
            lastSaveError = error.localizedDescription
            return false
        }
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}
