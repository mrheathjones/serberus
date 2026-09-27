import Foundation
import PrivMgrCore
import Security
import SQLite3

// MARK: - Backend

/// The minimal AuthorizationDB operations the manager needs. Abstracted so the
/// manager's snapshot/diff/restore logic is unit-testable with an in-memory
/// mock — the real backend requires root and live `/etc/authorization`.
public protocol AuthorizationDBBackend: Sendable {
    /// True when the right already exists.
    func rightExists(_ name: String) -> Bool
    /// The right's current definition as a serialized XML plist.
    func definition(of name: String) throws -> Data
    /// Replaces (or, if the right does not yet exist, creates) the right's
    /// definition. Requires root in the real backend. authd refuses to
    /// overwrite a right another (non-root) process created, root included
    /// (-60005), though root may remove it; see
    /// ``AuthorizationDBManager`` `writeOverExisting`.
    func setDefinition(_ data: Data, for name: String) throws
    /// Removes a right from the database entirely. Used to roll back a right
    /// Serberus *created* (one that did not exist before) on restore/uninstall,
    /// so a created right never outlives the daemon. Requires root.
    func removeRight(_ name: String) throws
    /// Every right and rule name in the live database, or nil when this
    /// backend cannot enumerate (the Security framework has no "list rights"
    /// API). The restore sweep uses it to find Serberus-written rights whose
    /// snapshot records are gone; nil makes it fall back to the names it can
    /// derive (the shipped defaults + its own records).
    func allRightNames() -> [String]?
}

public extension AuthorizationDBBackend {
    func allRightNames() -> [String]? { nil }
}

/// Production backend over the Security framework's AuthorizationDB API.
///
/// Every name is validated (``validateName(_:)``) BEFORE any
/// `AuthorizationRight*` call: those functions take a C string, so an embedded
/// NUL would silently truncate the name — `com.apple.\u{0}x` would read and
/// WRITE the `com.apple.` wildcard. The policy layer already refuses such names
/// (``AuthRightTargetPolicy/targetRejectionReason(_:)``); this is the last line.
public struct SecurityAuthorizationDB: AuthorizationDBBackend {
    /// The live database, opened READ-ONLY for enumeration only.
    public static let authDBPath = "/var/db/auth.db"

    private let databasePath: String

    public init(databasePath: String = SecurityAuthorizationDB.authDBPath) {
        self.databasePath = databasePath
    }

    /// Throws ``AuthorizationDBError/invalidRightName(_:)`` for an empty name,
    /// or one carrying a NUL or any non-ASCII / non-printable byte.
    public static func validateName(_ name: String) throws {
        guard !name.isEmpty, name.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else {
            throw AuthorizationDBError.invalidRightName(name)
        }
    }

    /// Reads also accept the empty name: it is the catch-all right authd
    /// answers an undefined right from when no wildcard matches, and an empty
    /// C string cannot be truncated into another name. Writes never do.
    public func rightExists(_ name: String) -> Bool {
        guard name.isEmpty || (try? Self.validateName(name)) != nil else { return false }
        return AuthorizationRightGet(name, nil) == errAuthorizationSuccess
    }

    public func definition(of name: String) throws -> Data {
        if !name.isEmpty { try Self.validateName(name) }
        var definition: CFDictionary?
        let status = AuthorizationRightGet(name, &definition)
        guard status == errAuthorizationSuccess, let definition else {
            throw AuthorizationDBError.rightUnreadable(name: name, status: status)
        }
        return try PropertyListSerialization.data(fromPropertyList: definition, format: .xml, options: 0)
    }

    public func setDefinition(_ data: Data, for name: String) throws {
        try Self.validateName(name)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        var authRef: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authRef) == errAuthorizationSuccess, let authRef else {
            throw AuthorizationDBError.authorizationUnavailable
        }
        defer { AuthorizationFree(authRef, []) }
        let status = AuthorizationRightSet(authRef, name, plist as CFTypeRef, nil, nil, nil)
        guard status == errAuthorizationSuccess else {
            throw AuthorizationDBError.rightUnwritable(name: name, status: status)
        }
    }

    public func removeRight(_ name: String) throws {
        try Self.validateName(name)
        var authRef: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authRef) == errAuthorizationSuccess, let authRef else {
            throw AuthorizationDBError.authorizationUnavailable
        }
        defer { AuthorizationFree(authRef, []) }
        let status = AuthorizationRightRemove(authRef, name)
        guard status == errAuthorizationSuccess else {
            throw AuthorizationDBError.rightUnwritable(name: name, status: status)
        }
    }

    /// Every `name` in auth.db's `rules` table (rights AND rule classes),
    /// read through a READ-ONLY SQLite connection (`SQLITE_OPEN_READONLY`,
    /// never a write). Root-only file; nil when it cannot be opened or read,
    /// so a non-root caller or a schema change degrades to the fallback
    /// candidate set rather than failing the restore.
    public func allRightNames() -> [String]? {
        Self.readRuleNames(databasePath: databasePath)
    }

    static func readRuleNames(databasePath: String) -> [String]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(databasePath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil) == SQLITE_OK,
              let db else {
            sqlite3_close(db)
            return nil
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 2_000)
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT name FROM rules", -1, &statement, nil) == SQLITE_OK,
              let statement else { return nil }
        defer { sqlite3_finalize(statement) }
        var names: [String] = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { break }
            guard step == SQLITE_ROW else { return nil }
            if let text = sqlite3_column_text(statement, 0) {
                names.append(String(cString: text))
            }
        }
        return names
    }
}

// MARK: - Errors

public enum AuthorizationDBError: Error, LocalizedError, Equatable, Sendable {
    case rightUnreadable(name: String, status: OSStatus)
    case rightUnwritable(name: String, status: OSStatus)
    case authorizationUnavailable
    /// A right name carrying a NUL, whitespace or non-ASCII byte — refused
    /// before any `AuthorizationRight*` call could truncate it.
    case invalidRightName(String)
    case snapshotChecksumMismatch(name: String)
    case snapshotMissing(name: String)
    case restoreFailed(name: String, underlying: String)
    /// ``AuthorizationDBManager/apply(_:compositions:)`` attempted every right
    /// and composition, and at least one could not be applied. The result
    /// holds what did land, and each right that did not, with the reason, in
    /// ``AuthorizationDBManager/ApplyResult/failed``.
    case applyIncomplete(AuthorizationDBManager.ApplyResult)
    /// The scope guard refused to compose per-app branches on this right.
    case compositionRejected(name: String, reason: String)
    /// A branch's compiled code requirement failed `SecRequirementCreateWithString`.
    case requirementInvalid(name: String, reason: String)

    public var errorDescription: String? {
        switch self {
        case let .rightUnreadable(name, status):
            return "AuthorizationDB right '\(name)' is unreadable (status \(status))"
        case let .rightUnwritable(name, status):
            return "AuthorizationDB right '\(name)' is unwritable (status \(status))"
        case .authorizationUnavailable:
            return "Could not create an AuthorizationRef"
        case let .invalidRightName(name):
            return "AuthorizationDB right name '\(name.debugDescription)' contains a NUL, whitespace or non-ASCII character; refused"
        case let .snapshotChecksumMismatch(name):
            return "AuthorizationDB snapshot for '\(name)' failed checksum verification"
        case let .snapshotMissing(name):
            return "AuthorizationDB snapshot for '\(name)' is missing"
        case let .restoreFailed(name, underlying):
            return "AuthorizationDB restore of '\(name)' failed: \(underlying)"
        case let .applyIncomplete(result):
            let failed = result.failed.keys.sorted()
            return "AuthorizationDB apply incomplete: \(failed.count) right(s) not applied, the rest applied: "
                + failed.map { "'\($0)' (\(result.failed[$0] ?? ""))" }.joined(separator: "; ")
        case let .compositionRejected(name, reason):
            return "AuthorizationDB composition of '\(name)' refused: \(reason)"
        case let .requirementInvalid(name, reason):
            return "AuthorizationDB branch requirement for '\(name)' invalid: \(reason)"
        }
    }
}

// MARK: - Snapshot

/// A checksum-protected snapshot of an original right definition.
///
/// When `wasAbsent` is true the right did NOT exist before Serberus created it,
/// so `originalDefinition` is empty and restore *removes* the right rather than
/// rewriting a definition.
public struct AuthorizationDBSnapshot: Codable, Sendable, Equatable {
    public let rightName: String
    /// The original definition as a serialized XML plist (base64 in JSON). Empty
    /// when `wasAbsent`.
    public let originalDefinition: Data
    public let timestamp: Date
    public let daemonVersion: String
    /// SHA-256 of `originalDefinition`, verified before any restore.
    public let sha256: String
    /// True when Serberus created a right that did not previously exist; restore
    /// removes it instead of writing `originalDefinition` back.
    public let wasAbsent: Bool
    /// True when the original was FOREIGN: macOS does not ship the right,
    /// Serberus had no record of it, and its definition was not Serberus's.
    /// Any user can create such a right (`config.add.` is `class=allow`), so
    /// its definition is kept only to put back on restore and is never
    /// trusted as the right's native gate.
    public let foreign: Bool

    /// Snapshot of an existing right's original definition (before modification).
    public init(rightName: String, originalDefinition: Data, timestamp: Date, daemonVersion: String,
                foreign: Bool = false) {
        self.rightName = rightName
        self.originalDefinition = originalDefinition
        self.timestamp = timestamp
        self.daemonVersion = daemonVersion
        self.sha256 = SHA256Hasher.hexDigest(originalDefinition)
        self.wasAbsent = false
        self.foreign = foreign
    }

    /// Tombstone snapshot for a right Serberus is about to create — one that did
    /// not exist. Restore removes the right.
    public init(absentRightName: String, timestamp: Date, daemonVersion: String) {
        self.rightName = absentRightName
        self.originalDefinition = Data()
        self.timestamp = timestamp
        self.daemonVersion = daemonVersion
        self.sha256 = SHA256Hasher.hexDigest(Data())
        self.wasAbsent = true
        self.foreign = false
    }

    /// Backward-compatible decode: snapshots written before created-right support
    /// have no `wasAbsent` key and are always modifications of existing rights;
    /// ones written before foreign originals were recorded have no `foreign` key.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        rightName = try c.decode(String.self, forKey: .rightName)
        originalDefinition = try c.decode(Data.self, forKey: .originalDefinition)
        timestamp = try c.decode(Date.self, forKey: .timestamp)
        daemonVersion = try c.decode(String.self, forKey: .daemonVersion)
        sha256 = try c.decode(String.self, forKey: .sha256)
        wasAbsent = try c.decodeIfPresent(Bool.self, forKey: .wasAbsent) ?? false
        foreign = try c.decodeIfPresent(Bool.self, forKey: .foreign) ?? false
    }

    /// True when the stored checksum matches the stored definition (tamper check).
    public var isIntact: Bool {
        sha256 == SHA256Hasher.hexDigest(originalDefinition)
    }
}

/// Reads/writes snapshots as JSON files under the backup directory.
public struct AuthorizationDBSnapshotStore: Sendable {
    private let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    public func save(_ snapshot: AuthorizationDBSnapshot) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let data = try encoder.encode(snapshot)
        try data.write(to: url(for: snapshot.rightName), options: .atomic)
    }

    public func load(rightName: String) throws -> AuthorizationDBSnapshot {
        let url = url(for: rightName)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw AuthorizationDBError.snapshotMissing(name: rightName)
        }
        let snapshot = try JSONDecoder().decode(AuthorizationDBSnapshot.self, from: try Data(contentsOf: url))
        guard snapshot.isIntact else {
            throw AuthorizationDBError.snapshotChecksumMismatch(name: rightName)
        }
        return snapshot
    }

    public func hasSnapshot(rightName: String) -> Bool {
        FileManager.default.fileExists(atPath: url(for: rightName).path)
    }

    public func allSnapshots() throws -> [AuthorizationDBSnapshot] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else {
            return []
        }
        return try names.filter { $0.hasSuffix(".json") }.sorted().map { name in
            let snapshot = try JSONDecoder().decode(
                AuthorizationDBSnapshot.self,
                from: try Data(contentsOf: directory.appendingPathComponent(name))
            )
            guard snapshot.isIntact else {
                throw AuthorizationDBError.snapshotChecksumMismatch(name: snapshot.rightName)
            }
            return snapshot
        }
    }

    /// Best-effort enumeration for restore: one entry per snapshot file. A file
    /// that is unreadable, undecodable, or checksum-failed yields a `nil`
    /// snapshot paired with the right name recovered from the filename — so the
    /// caller can still reset that right to a safe default instead of leaving it
    /// stuck in Serberus's modified state. Never throws.
    public func allSnapshotsBestEffort() -> [(rightName: String, snapshot: AuthorizationDBSnapshot?)] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return [] }
        return names.filter { $0.hasSuffix(".json") }.sorted().map { fileName in
            let rightFromName = String(fileName.dropLast(5)) // ".json"
            guard let data = try? Data(contentsOf: directory.appendingPathComponent(fileName)),
                  let snapshot = try? JSONDecoder().decode(AuthorizationDBSnapshot.self, from: data),
                  snapshot.isIntact else {
                return (rightFromName, nil)
            }
            return (snapshot.rightName, snapshot)
        }
    }

    public func remove(rightName: String) throws {
        let url = url(for: rightName)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        let projection = projectionDigestURL(for: rightName)
        if FileManager.default.fileExists(atPath: projection.path) {
            try FileManager.default.removeItem(at: projection)
        }
        try removeOwnedRows(rightName: rightName)
    }

    // MARK: Projection digest

    /// Records the digest (``AuthorizationDBManager/canonicalDigest(_:)``) of
    /// the definition Serberus wrote over a projected right, as authd
    /// returned it right after the write, so an edit in place — or a
    /// replacement by someone else — is told apart from Serberus's own
    /// write. Kept in a `<right>.projection` sidecar beside the snapshot and
    /// removed with it.
    public func saveProjectionDigest(_ digest: String, rightName: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(digest.utf8).write(to: projectionDigestURL(for: rightName), options: .atomic)
    }

    /// The digest recorded by ``saveProjectionDigest(_:rightName:)``, or nil.
    public func projectionDigest(rightName: String) -> String? {
        guard let data = try? Data(contentsOf: projectionDigestURL(for: rightName)),
              let digest = String(data: data, encoding: .utf8), !digest.isEmpty else { return nil }
        return digest
    }

    // MARK: Admin-auth stand-in

    /// Records that Serberus wrote its admin-auth stand-in over `rightName`
    /// (the original could not be recovered), with the digest
    /// (``AuthorizationDBManager/canonicalDigest(_:)``) of the stand-in as
    /// authd returned it right after the write. Kept in a `<right>.standin`
    /// sidecar that ``remove(rightName:)`` leaves in place: the stand-in stays
    /// in force after the right is restored, and this record, not the
    /// stand-in's comment (which anyone creating a right could copy), is how
    /// Serberus recognises it later. The stand-in names no SerberusAuth
    /// mechanism, so the record never means the plugin is still needed.
    public func saveStandInDigest(_ digest: String, rightName: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(digest.utf8).write(to: standInURL(for: rightName), options: .atomic)
    }

    /// The digest recorded by ``saveStandInDigest(_:rightName:)``, or nil.
    public func standInDigest(rightName: String) -> String? {
        guard let data = try? Data(contentsOf: standInURL(for: rightName)),
              let digest = String(data: data, encoding: .utf8), !digest.isEmpty else { return nil }
        return digest
    }

    public func removeStandIn(rightName: String) throws {
        let url = standInURL(for: rightName)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    // MARK: Owned composition rows

    /// The ownership sidecar for a composed right: the EXTRA auth.db rows
    /// Serberus created (its `native-default` fallback + the rows of every app
    /// branch), and a digest of each row as authd returned it right after
    /// Serberus wrote it.
    ///
    /// The digests are what let Serberus trust those rows: `config.add.` is
    /// `class=allow` on macOS, so ANY user can create a right — including one
    /// named `…branch.<right>.native-default` holding `class=allow`, or an app
    /// row carrying extra keys. A row is used as the original, or left in
    /// place by the composer, only when this record names it and its digest
    /// (``AuthorizationDBManager/canonicalDigest(_:)``) still matches.
    public struct OwnedRowsRecord: Codable, Sendable, Equatable {
        public var rows: [String]
        public var nativeDefaultSHA256: String?
        /// Digest of every owned row (row name → SHA-256). Absent in records
        /// written before per-row digests existed; such rows are rewritten
        /// once and then recorded.
        public var rowSHA256: [String: String]?

        public init(rows: [String], nativeDefaultSHA256: String? = nil, rowSHA256: [String: String]? = nil) {
            self.rows = rows.sorted()
            self.nativeDefaultSHA256 = nativeDefaultSHA256
            self.rowSHA256 = rowSHA256
        }

        /// The recorded digest of `row`, or nil when this record does not name
        /// the row or holds no digest for it.
        public func digest(of row: String, nativeRow: String) -> String? {
            guard rows.contains(row) else { return nil }
            if let digest = rowSHA256?[row] { return digest }
            return row == nativeRow ? nativeDefaultSHA256 : nil
        }
    }

    /// Records the EXTRA auth.db rows Serberus created for a composed right
    /// (its `native-default` fallback + one row per app branch), so restore
    /// and reconcile can delete exactly those rows and nothing else. Kept in
    /// a sidecar (`<right>.branches`, deliberately NOT `.json`) beside the
    /// snapshot so the snapshot enumeration never mistakes it for a right and
    /// so an unreadable/tampered snapshot still leaves the ownership record
    /// intact for the sweep. `nativeDefaultSHA256` is recorded only when the
    /// caller verified the row it just wrote (see ``OwnedRowsRecord``), and
    /// `rowSHA256` holds the digest of each row read back after writing.
    public func saveOwnedRows(_ rows: [String], rightName: String, nativeDefaultSHA256: String? = nil,
                              rowSHA256: [String: String]? = nil) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let record = OwnedRowsRecord(rows: rows, nativeDefaultSHA256: nativeDefaultSHA256, rowSHA256: rowSHA256)
        try encoder.encode(record).write(to: ownedRowsURL(for: rightName), options: .atomic)
    }

    /// The full ownership record, or nil when none is readable. A sidecar in
    /// the older bare-array format decodes with no digest (so its
    /// `native-default` row is never trusted until a compose re-records it).
    public func ownedRowsRecord(rightName: String) -> OwnedRowsRecord? {
        guard let data = try? Data(contentsOf: ownedRowsURL(for: rightName)) else { return nil }
        if let record = try? JSONDecoder().decode(OwnedRowsRecord.self, from: data) { return record }
        if let legacy = try? JSONDecoder().decode([String].self, from: data) { return OwnedRowsRecord(rows: legacy) }
        return nil
    }

    /// The rows recorded by ``saveOwnedRows(_:rightName:nativeDefaultSHA256:)``;
    /// empty when none.
    public func ownedRows(rightName: String) -> [String] {
        ownedRowsRecord(rightName: rightName)?.rows ?? []
    }

    public func removeOwnedRows(rightName: String) throws {
        let url = ownedRowsURL(for: rightName)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    /// Every right with an ownership record — including one whose snapshot
    /// file is gone — so a restore sweep can still find orphaned rows.
    public func rightsWithOwnedRows() -> [String] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return [] }
        return names.filter { $0.hasSuffix(".branches") }.map { String($0.dropLast(9)) }.sorted()
    }

    private func url(for rightName: String) -> URL {
        // Right names contain dots and hyphens but no path separators; encode
        // any stray slash defensively.
        let safe = rightName.replacingOccurrences(of: "/", with: "_")
        return directory.appendingPathComponent("\(safe).json")
    }

    private func projectionDigestURL(for rightName: String) -> URL {
        let safe = rightName.replacingOccurrences(of: "/", with: "_")
        return directory.appendingPathComponent("\(safe).projection")
    }

    private func standInURL(for rightName: String) -> URL {
        let safe = rightName.replacingOccurrences(of: "/", with: "_")
        return directory.appendingPathComponent("\(safe).standin")
    }

    private func ownedRowsURL(for rightName: String) -> URL {
        let safe = rightName.replacingOccurrences(of: "/", with: "_")
        return directory.appendingPathComponent("\(safe).branches")
    }
}
