import Darwin
import Foundation
import SQLite3

/// Grant database schema constants and migrations.
public enum GrantStoreSchema {
    /// Current row/database schema version.
    ///
    /// - 1: the original table.
    /// - 2: adds the nullable `bootSessionID` / `continuousDeadline` columns
    ///   (the continuous-clock expiry; see ``Grant/hasExpired(at:monotonic:)``).
    ///   Existing rows keep NULL there and expire on the wall clock alone. The
    ///   columns are not part of the row HMAC, so every existing row still
    ///   verifies.
    /// - 3: adds the nullable `generatedUID` column (the promoted account's
    ///   GeneratedUID, recorded for JIT admin grants). Existing rows keep NULL
    ///   and verify exactly as before: the value joins the row HMAC only when
    ///   present (see ``Grant/integrityMessage()``).
    public static let currentVersion = 3

    /// `sqlite3_destructor_type` for transient text bindings.
    static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}

/// Persisted grant store.
///
/// - SQLite in WAL mode at ``BundleConfig/grantDatabasePath``. The database
///   and its `-wal`/`-shm` companions are created — and, if found looser,
///   tightened to — mode 0600 here (``filePermissions``); root:wheel ownership
///   follows from the daemon running as root.
/// - Crash-safe writes, schema versioning with migration support.
/// - Per-row HMAC integrity marker; tampered rows are revoked on load and
///   reported so the daemon can emit an integrity event.
/// - Expired grants are removed at startup (``cleanupExpired(now:)``), and
///   revoked on every daemon tick (``revokeExpired(now:)``) — expiry that the
///   continuous clock or a clock set back before issue decides, too.
/// - Never stores secrets of any kind.
///
/// Revocation is forward-looking only: running processes already elevated
/// are not terminated.
public actor GrantStore {
    /// How the store opens its database and treats rows it cannot verify.
    public struct OpenOptions: Sendable, Equatable {
        /// Create the database (and run migrations) when absent. When false the
        /// file must already exist; it is opened without `SQLITE_OPEN_CREATE`,
        /// never pre-created, and never migrated (a store with no schema yet is
        /// read as empty).
        public var createIfMissing: Bool
        /// Revoke-and-mark (`rowHMAC = 'tampered'`) a NON-JIT row whose HMAC
        /// fails (fail closed). JIT admin rows are never quarantined on read —
        /// see ``unverifiedJITCandidates()``.
        public var quarantineUnverifiedRows: Bool

        public init(createIfMissing: Bool, quarantineUnverifiedRows: Bool) {
            self.createIfMissing = createIfMissing
            self.quarantineUnverifiedRows = quarantineUnverifiedRows
        }

        /// The daemon's store.
        public static let standard = OpenOptions(createIfMissing: true, quarantineUnverifiedRows: true)
        /// A read-mostly view of an EXISTING store (`serberusd --demote-jit`):
        /// no create, no migration, no quarantine of rows it cannot verify.
        public static let existingNoQuarantine = OpenOptions(createIfMissing: false, quarantineUnverifiedRows: false)
    }

    /// `rowHMAC` marker of a row this store already quarantined.
    public static let quarantineMarker = "tampered"

    private var db: OpaquePointer?
    private let path: String
    private let options: OpenOptions
    /// Candidate integrity keys. A row verifies when ANY of them matches; the
    /// FIRST signs new rows, and a rewritten row (revocation) is re-signed with
    /// the key that verified it.
    private let integrityKeys: [Data]
    /// False when an existing-only open found no `grants` table yet.
    private var schemaPresent = true
    /// False when an existing-only open found a version-1 table, which has no
    /// continuous-clock columns (reads substitute NULL).
    private var continuousColumnsPresent = true
    /// False when an existing-only open found a table older than version 3,
    /// which has no `generatedUID` column (reads substitute NULL).
    private var generatedUIDColumnPresent = true
    /// The continuous clock rows are stamped and checked against. Injectable so
    /// tests can move it independently of the wall clock.
    private let monotonicNow: @Sendable () -> MonotonicInstant?

    /// Integrity violations detected while loading rows. The daemon drains
    /// this to emit integrity log events.
    public private(set) var integrityViolations: [GrantStoreError] = []

    // MARK: Lifecycle

    /// Opens (creating if needed) the grant database and runs migrations.
    ///
    /// - Parameters:
    ///   - path: Database file path. Use `":memory:"` or a temp path in tests.
    ///   - keyProvider: Source of the `grants-hmac-key` integrity key.
    ///   - options: ``OpenOptions/standard`` unless a caller needs otherwise.
    /// - Throws: ``GrantStoreError`` on open or migration failure. Migration
    ///   failure is the caller's signal to enter degraded state
    ///   (`grants_db_error`) — deny all timed grants, allow silent.
    ///   - monotonicNow: the continuous clock (the live one unless a test
    ///     injects its own).
    public init(path: String, keyProvider: SigningKeyProvider, options: OpenOptions = .standard,
                monotonicNow: @escaping @Sendable () -> MonotonicInstant? = { MonotonicClock.now() }) throws {
        let key = try keyProvider.key(account: BundleConfig.grantsHMACKeyAccount)
        try self.init(path: path, integrityKeys: [key], options: options, monotonicNow: monotonicNow)
    }

    /// Opens the store with an explicit list of candidate integrity keys (the
    /// one-shot teardown tries both the System Keychain and the dev file key).
    /// An EMPTY list is allowed for ``OpenOptions/existingNoQuarantine``: every
    /// row is then unverifiable, and ``insert(_:)`` throws.
    public init(path: String, integrityKeys: [Data], options: OpenOptions,
                monotonicNow: @escaping @Sendable () -> MonotonicInstant? = { MonotonicClock.now() }) throws {
        self.path = path
        self.options = options
        self.integrityKeys = integrityKeys
        self.monotonicNow = monotonicNow

        if options.createIfMissing {
            // Create the file 0600 BEFORE SQLite does: `sqlite3_open_v2` creates at
            // 0644 & ~umask, and SQLite gives the -wal/-shm files the main file's
            // mode, so pre-creating it closes the world-readable window for all three.
            Self.precreatePrivateFile(path)
        }

        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
            | (options.createIfMissing ? SQLITE_OPEN_CREATE : 0)
        guard sqlite3_open_v2(path, &handle, flags, nil) == SQLITE_OK, let handle else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            sqlite3_close(handle)
            throw GrantStoreError.openFailed(path: path, code: SQLITE_CANTOPEN, message: message)
        }
        self.db = handle

        try Self.execute(handle, "PRAGMA journal_mode=WAL")
        try Self.execute(handle, "PRAGMA synchronous=FULL")
        try Self.execute(handle, "PRAGMA foreign_keys=ON")
        if options.createIfMissing {
            try Self.migrate(handle)
        } else {
            let found = try Self.userVersion(handle)
            if found > GrantStoreSchema.currentVersion {
                throw GrantStoreError.schemaTooNew(found: found, supported: GrantStoreSchema.currentVersion)
            }
            self.schemaPresent = try Self.tableExists(handle, "grants")
            self.continuousColumnsPresent = found >= 2
            self.generatedUIDColumnPresent = found >= 3
        }
        // An existing database from an older build (created at umask) is
        // tightened in place, together with whatever WAL files now exist.
        Self.tightenPermissions(path)
    }

    /// Number of rows in the `grants` table of the database at `path`, opened
    /// READ-ONLY (never created, never migrated). `0` when the file is absent
    /// or has no `grants` table yet; nil when it exists but cannot be read — a
    /// caller deciding whether minting a fresh HMAC key would orphan existing
    /// rows must treat nil as "rows exist".
    public static func existingRowCount(atPath path: String) -> Int? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return errno == ENOENT ? 0 : nil }
        guard (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        if info.st_size == 0 { return 0 }
        var handle: OpaquePointer?
        defer { sqlite3_close_v2(handle) }
        guard sqlite3_open_v2(path, &handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
              let handle else { return nil }
        guard let exists = try? tableExists(handle, "grants") else { return nil }
        guard exists else { return 0 }
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(handle, "SELECT count(*) FROM grants", -1, &statement, nil) == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return Int(sqlite3_column_int64(statement, 0))
    }

    private static func tableExists(_ db: OpaquePointer?, _ name: String) throws -> Bool {
        let sql = "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?"
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw statementError(db, sql)
        }
        sqlite3_bind_text(statement, 1, name, -1, GrantStoreSchema.transient)
        guard sqlite3_step(statement) == SQLITE_ROW else { throw statementError(db, sql) }
        return sqlite3_column_int64(statement, 0) > 0
    }

    // MARK: File permissions

    /// Mode for the grant database and its `-wal` / `-shm` companions.
    public static let filePermissions: mode_t = 0o600

    /// Whether `path` names an on-disk database (not `:memory:` / a URI / "").
    private static func isOnDiskPath(_ path: String) -> Bool {
        !path.isEmpty && path != ":memory:" && !path.hasPrefix("file:")
    }

    /// Creates `path` empty at ``filePermissions`` when absent. Never follows a
    /// symlink and never truncates; an existing file is left for
    /// ``tightenPermissions(_:)``.
    private static func precreatePrivateFile(_ path: String) {
        guard isOnDiskPath(path) else { return }
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, filePermissions)
        if fd >= 0 {
            fchmod(fd, filePermissions) // O_CREAT's mode is umask-masked; be exact
            Darwin.close(fd)
        }
    }

    /// Strips group/other bits from the database and its WAL companions. Uses
    /// `lstat` + an `O_NOFOLLOW` open so a symlink planted at a companion path
    /// is never chmod-ed through.
    static func tightenPermissions(_ path: String) {
        guard isOnDiskPath(path) else { return }
        for candidate in [path, path + "-wal", path + "-shm", path + "-journal"] {
            var info = stat()
            guard lstat(candidate, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { continue }
            guard info.st_mode & 0o077 != 0 else { continue }
            let fd = open(candidate, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { continue }
            fchmod(fd, filePermissions)
            Darwin.close(fd)
        }
    }

    isolated deinit {
        if let db { sqlite3_close_v2(db) }
    }

    /// Closes the database. Subsequent calls throw.
    public func close() {
        if let db { sqlite3_close_v2(db) }
        db = nil
    }

    // MARK: Migration

    private static func migrate(_ db: OpaquePointer?) throws {
        let found = try userVersion(db)
        if found > GrantStoreSchema.currentVersion {
            throw GrantStoreError.schemaTooNew(found: found, supported: GrantStoreSchema.currentVersion)
        }
        guard found < GrantStoreSchema.currentVersion else { return }

        try execute(db, "BEGIN IMMEDIATE TRANSACTION")
        do {
            var version = found
            while version < GrantStoreSchema.currentVersion {
                try applyMigration(db, from: version)
                version += 1
            }
            try execute(db, "PRAGMA user_version = \(GrantStoreSchema.currentVersion)")
            try execute(db, "COMMIT")
        } catch {
            try? execute(db, "ROLLBACK")
            throw GrantStoreError.migrationFailed(
                from: found,
                to: GrantStoreSchema.currentVersion,
                underlying: String(describing: error)
            )
        }
    }

    private static func applyMigration(_ db: OpaquePointer?, from version: Int) throws {
        switch version {
        case 0:
            try execute(db, """
                CREATE TABLE IF NOT EXISTS grants (
                    grantID         TEXT PRIMARY KEY,
                    user            TEXT NOT NULL,
                    uid             INTEGER NOT NULL,
                    ruleID          TEXT NOT NULL,
                    profileKey      TEXT NOT NULL,
                    teamID          TEXT NOT NULL,
                    binaryHash      TEXT NOT NULL,
                    canonicalPath   TEXT NOT NULL,
                    argvPattern     TEXT,
                    grantedAt       TEXT NOT NULL,
                    expiresAt       TEXT,
                    revokedAt       TEXT,
                    policyVersion   TEXT NOT NULL,
                    schemaVersion   INTEGER NOT NULL DEFAULT 1,
                    rowHMAC         TEXT NOT NULL
                )
                """)
            try execute(db, "CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user)")
            try execute(db, "CREATE INDEX IF NOT EXISTS idx_grants_profile ON grants(profileKey)")
        case 1:
            // Nullable, so existing rows need no rewrite: NULL means "wall clock
            // only", exactly how those rows were checked before.
            try execute(db, "ALTER TABLE grants ADD COLUMN bootSessionID TEXT")
            try execute(db, "ALTER TABLE grants ADD COLUMN continuousDeadline INTEGER")
        case 2:
            // Nullable and additive: existing rows keep NULL, which is also what
            // their (unchanged) HMAC message assumes.
            try execute(db, "ALTER TABLE grants ADD COLUMN generatedUID TEXT")
        default:
            throw GrantStoreError.migrationFailed(
                from: version, to: version + 1,
                underlying: "no migration registered for version \(version)"
            )
        }
    }

    private static func userVersion(_ db: OpaquePointer?) throws -> Int {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &statement, nil) == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_ROW else {
            throw statementError(db, "PRAGMA user_version")
        }
        return Int(sqlite3_column_int(statement, 0))
    }

    // MARK: Insert

    /// Persists a new grant with its integrity marker.
    ///
    /// A timed grant that does not already carry a continuous-clock deadline is
    /// stamped with one here, from the current continuous-clock reading plus the
    /// window's length. Every issuance path persists through this call right as
    /// it issues, so the stamp cannot be forgotten by a caller.
    /// - Throws: ``GrantStoreError``
    public func insert(_ grant: Grant) throws {
        let grant = grant.stampingContinuousDeadline(at: monotonicNow())
        let sql = """
            INSERT INTO grants (grantID, user, uid, ruleID, profileKey, teamID, binaryHash,
                                canonicalPath, argvPattern, grantedAt, expiresAt, revokedAt,
                                policyVersion, schemaVersion, rowHMAC, bootSessionID, continuousDeadline,
                                generatedUID)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        guard let signingKey = integrityKeys.first, schemaPresent, continuousColumnsPresent,
              generatedUIDColumnPresent else {
            throw GrantStoreError.openFailed(path: path, code: SQLITE_READONLY,
                                             message: "grant store opened without a signing key or schema")
        }
        let hmac = HMACSHA256.hexSignature(message: grant.integrityMessage(), key: signingKey)
        bindText(statement, 1, grant.grantID.uuidString)
        bindText(statement, 2, grant.user)
        sqlite3_bind_int64(statement, 3, Int64(grant.uid))
        bindText(statement, 4, grant.ruleID)
        bindText(statement, 5, grant.profileKey)
        bindText(statement, 6, grant.teamID)
        bindText(statement, 7, grant.binaryHash)
        bindText(statement, 8, grant.canonicalPath)
        bindOptionalText(statement, 9, grant.argvPattern)
        bindText(statement, 10, ISO8601.string(from: grant.grantedAt))
        bindOptionalText(statement, 11, grant.expiresAt.map(ISO8601.string(from:)))
        bindOptionalText(statement, 12, grant.revokedAt.map(ISO8601.string(from:)))
        bindText(statement, 13, grant.policyVersion)
        sqlite3_bind_int64(statement, 14, Int64(grant.schemaVersion))
        bindText(statement, 15, hmac)
        bindOptionalText(statement, 16, grant.bootSessionID)
        if let deadline = grant.continuousDeadlineNanos {
            sqlite3_bind_int64(statement, 17, Int64(clamping: deadline))
        } else {
            sqlite3_bind_null(statement, 17)
        }
        bindOptionalText(statement, 18, grant.generatedUID)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw Self.statementError(db, sql)
        }
    }

    // MARK: Queries

    /// All grants active at `now` (unexpired on both clocks, unrevoked,
    /// integrity-verified).
    public func activeGrants(now: Date) throws -> [Grant] {
        let monotonic = monotonicNow()
        return try loadGrants(where: "revokedAt IS NULL", arguments: [])
            .filter { $0.isActive(at: now, monotonic: monotonic) }
    }

    /// Active grants for one user at `now`.
    public func activeGrants(for user: String, now: Date) throws -> [Grant] {
        let monotonic = monotonicNow()
        return try loadGrants(where: "revokedAt IS NULL AND user = ?", arguments: [user])
            .filter { $0.isActive(at: now, monotonic: monotonic) }
    }

    /// Whether `grant` has expired at `now` by the store's clocks (wall clock,
    /// issue time, and the continuous clock). Lets a caller holding rows from
    /// ``allGrants()`` apply the same test the store's queries apply.
    public func hasExpired(_ grant: Grant, now: Date) -> Bool {
        grant.hasExpired(at: now, monotonic: monotonicNow())
    }

    /// One grant by ID, if present and integrity-verified.
    public func grant(id: UUID) throws -> Grant? {
        try loadGrants(where: "grantID = ?", arguments: [id.uuidString]).first
    }

    /// Every row in the table, including revoked and expired grants.
    ///
    /// Declared `async` on purpose: `GrantMaintaining` (daemon) has a
    /// protocol-extension DEFAULT `allGrants() async throws` that returns ACTIVE
    /// grants only. A call on a concrete `GrantStore` from an async context
    /// preferred that async default over a synchronous actor method — silently
    /// dropping expired and revoked rows. The exact signature removes the trap.
    public func allGrants() async throws -> [Grant] {
        try loadGrants(where: "1=1", arguments: [])
    }

    // MARK: Revocation (all four paths)

    /// Kill switch: revokes every active grant EXCEPT JIT admin grants.
    ///
    /// A JIT row stands for a real `admin` group membership. It may be marked
    /// revoked only by the JIT manager, and only AFTER the group removal landed;
    /// every demotion path (`demoteAll`, `reconcile`, expiry, `--demote-jit`)
    /// enumerates unrevoked JIT rows, so a blanket revoke here would hide a
    /// still-promoted user from all of them — a permanent admin. The kill
    /// switch demotes JIT admins through the manager instead.
    /// - Returns: Number of grants revoked.
    @discardableResult
    public func revokeAll(now: Date) throws -> Int {
        try revoke(where: "revokedAt IS NULL AND NOT (profileKey = ? AND canonicalPath = ?)",
                   arguments: [JITAdminGrant.profileKey, JITAdminGrant.canonicalPath], now: now)
    }

    /// Per-user threat signal: revokes every active grant for `user`.
    @discardableResult
    public func revokeAll(for user: String, now: Date) throws -> Int {
        try revoke(where: "revokedAt IS NULL AND user = ?", arguments: [user], now: now)
    }

    /// Single-grant revocation (Fleet Observer, V1.1).
    @discardableResult
    public func revoke(grantID: UUID, now: Date) throws -> Int {
        try revoke(where: "revokedAt IS NULL AND grantID = ?", arguments: [grantID.uuidString], now: now)
    }

    /// Policy reload: a profile was removed, revoke its grants.
    @discardableResult
    public func revokeAll(forProfileKey profileKey: String, now: Date) throws -> Int {
        try revoke(where: "revokedAt IS NULL AND profileKey = ?", arguments: [profileKey], now: now)
    }

    /// Gives one unrevoked, verified, INDEFINITE non-JIT grant an expiry
    /// `seconds` from `now` (and a continuous-clock deadline the same distance
    /// away), re-signing the row with the key that verified it. See
    /// ``GrantPolicyAlignment``. `async` for the same reason as ``allGrants()``.
    /// - Returns: 1 when the row was bounded, 0 when there was no such row.
    @discardableResult
    public func bound(grantID: UUID, seconds: Int, now: Date) async throws -> Int {
        guard continuousColumnsPresent else { return 0 }
        let targets = try loadVerifiedRows(
            where: "revokedAt IS NULL AND expiresAt IS NULL AND grantID = ? AND NOT (profileKey = ? AND canonicalPath = ?)",
            arguments: [grantID.uuidString, JITAdminGrant.profileKey, JITAdminGrant.canonicalPath])
        guard let (grant, verifyingKey) = targets.first else { return 0 }
        let bounded = grant.bounding(seconds: seconds, now: now, instant: monotonicNow())
        let hmac = HMACSHA256.hexSignature(message: bounded.integrityMessage(), key: verifyingKey)
        let sql = """
            UPDATE grants SET expiresAt = ?, rowHMAC = ?, bootSessionID = ?, continuousDeadline = ?
            WHERE grantID = ? AND revokedAt IS NULL AND expiresAt IS NULL
            """
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        bindOptionalText(statement, 1, bounded.expiresAt.map(ISO8601.string(from:)))
        bindText(statement, 2, hmac)
        bindOptionalText(statement, 3, bounded.bootSessionID)
        if let deadline = bounded.continuousDeadlineNanos {
            sqlite3_bind_int64(statement, 4, Int64(clamping: deadline))
        } else {
            sqlite3_bind_null(statement, 4)
        }
        bindText(statement, 5, grant.grantID.uuidString)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw Self.statementError(db, sql) }
        return Int(sqlite3_changes(db))
    }

    /// Records the account's GeneratedUID on unrevoked, verified JIT rows that
    /// have none: rows written before schema 3, which the migration left NULL.
    /// `resolve(user, uid)` returns the GeneratedUID only when the row's name
    /// and uid still name the same account; a row it answers nil for keeps
    /// NULL (and the rename-by-uid behaviour rows without one always had).
    ///
    /// The GeneratedUID is inside the row HMAC, so each stamped row is
    /// re-signed exactly as a new row would be (with the key that verified it).
    /// Rows without one keep verifying as before, since the value joins the
    /// signed message only when present. Run at daemon start, before the JIT
    /// manager reads the rows. `async` for the same reason as ``allGrants()``.
    /// - Returns: Number of rows stamped.
    @discardableResult
    public func stampGeneratedUIDs(resolve: @Sendable (String, uid_t) -> String?) async throws -> Int {
        guard schemaPresent, generatedUIDColumnPresent, !integrityKeys.isEmpty else { return 0 }
        let targets = try loadVerifiedRows(
            where: "revokedAt IS NULL AND generatedUID IS NULL AND profileKey = ? AND canonicalPath = ?",
            arguments: [JITAdminGrant.profileKey, JITAdminGrant.canonicalPath])
        var stamped = 0
        for (grant, verifyingKey) in targets {
            guard let generatedUID = resolve(grant.user, grant.uid), !generatedUID.isEmpty else { continue }
            let updated = Grant(
                grantID: grant.grantID, user: grant.user, uid: grant.uid, ruleID: grant.ruleID,
                profileKey: grant.profileKey, teamID: grant.teamID, binaryHash: grant.binaryHash,
                canonicalPath: grant.canonicalPath, argvPattern: grant.argvPattern,
                grantedAt: grant.grantedAt, expiresAt: grant.expiresAt, revokedAt: grant.revokedAt,
                policyVersion: grant.policyVersion, schemaVersion: grant.schemaVersion,
                bootSessionID: grant.bootSessionID, continuousDeadlineNanos: grant.continuousDeadlineNanos,
                generatedUID: generatedUID)
            let hmac = HMACSHA256.hexSignature(message: updated.integrityMessage(), key: verifyingKey)
            let sql = "UPDATE grants SET generatedUID = ?, rowHMAC = ? WHERE grantID = ? AND generatedUID IS NULL AND revokedAt IS NULL"
            var statement: OpaquePointer?
            defer { sqlite3_finalize(statement) }
            guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
                throw Self.statementError(db, sql)
            }
            bindText(statement, 1, generatedUID)
            bindText(statement, 2, hmac)
            bindText(statement, 3, grant.grantID.uuidString)
            guard sqlite3_step(statement) == SQLITE_DONE else { throw Self.statementError(db, sql) }
            stamped += Int(sqlite3_changes(db))
        }
        return stamped
    }

    private func revoke(where clause: String, arguments: [String], now: Date) throws -> Int {
        // Revocation rewrites each row's HMAC, so rows are updated
        // individually inside one transaction.
        let targets = try loadVerifiedRows(where: clause, arguments: arguments)
        guard !targets.isEmpty else { return 0 }

        try Self.execute(db, "BEGIN IMMEDIATE TRANSACTION")
        do {
            for (grant, verifyingKey) in targets {
                let revoked = Grant(
                    grantID: grant.grantID,
                    user: grant.user,
                    uid: grant.uid,
                    ruleID: grant.ruleID,
                    profileKey: grant.profileKey,
                    teamID: grant.teamID,
                    binaryHash: grant.binaryHash,
                    canonicalPath: grant.canonicalPath,
                    argvPattern: grant.argvPattern,
                    grantedAt: grant.grantedAt,
                    expiresAt: grant.expiresAt,
                    revokedAt: now,
                    policyVersion: grant.policyVersion,
                    schemaVersion: grant.schemaVersion,
                    bootSessionID: grant.bootSessionID,
                    continuousDeadlineNanos: grant.continuousDeadlineNanos,
                    generatedUID: grant.generatedUID
                )
                // Re-signed with the key that verified the row, so a store read
                // with a fallback key stays self-consistent.
                let hmac = HMACSHA256.hexSignature(message: revoked.integrityMessage(), key: verifyingKey)
                let sql = "UPDATE grants SET revokedAt = ?, rowHMAC = ? WHERE grantID = ?"
                var statement: OpaquePointer?
                defer { sqlite3_finalize(statement) }
                guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
                    throw Self.statementError(db, sql)
                }
                bindText(statement, 1, ISO8601.string(from: now))
                bindText(statement, 2, hmac)
                bindText(statement, 3, grant.grantID.uuidString)
                guard sqlite3_step(statement) == SQLITE_DONE else {
                    throw Self.statementError(db, sql)
                }
            }
            try Self.execute(db, "COMMIT")
        } catch {
            try? Self.execute(db, "ROLLBACK")
            throw error
        }
        return targets.count
    }

    /// Revokes every unrevoked, verified NON-JIT grant whose window is over by
    /// ``Grant/hasExpired(at:monotonic:)`` — including one kept "alive" by a
    /// wall clock set back. Run on every daemon tick, so a grant that expired
    /// never comes back when the clock moves again. JIT admin rows are left to
    /// the JIT manager, which demotes the user before the row may be revoked.
    /// - Returns: Number of grants revoked.
    @discardableResult
    public func revokeExpired(now: Date) async throws -> Int {
        let monotonic = monotonicNow()
        let expired = try loadGrants(where: "revokedAt IS NULL AND NOT (profileKey = ? AND canonicalPath = ?)",
                                     arguments: [JITAdminGrant.profileKey, JITAdminGrant.canonicalPath])
            .filter { $0.hasExpired(at: now, monotonic: monotonic) }
        var count = 0
        for grant in expired {
            count += try revoke(grantID: grant.grantID, now: now)
        }
        return count
    }

    /// Gives every unrevoked, verified, timed row that has no continuous-clock
    /// deadline in THIS boot session one (``Grant/restampingContinuousDeadline(at:now:)``):
    /// rows from an earlier boot, and rows migrated from schema 1. Run once at
    /// daemon start, before grants are served, so a wall clock set back later in
    /// this boot cannot stretch them.
    ///
    /// The two columns are outside the row HMAC and a new deadline can only
    /// shorten a grant, so rows are not re-signed. No-op without a continuous
    /// clock reading or on a store without the columns.
    ///
    /// `async` for the same reason as ``allGrants()``: the daemon's
    /// `GrantMaintaining` has an async no-op default this must not lose to.
    /// - Returns: Number of rows stamped.
    @discardableResult
    public func restampContinuousDeadlines(now: Date) async throws -> Int {
        guard schemaPresent, continuousColumnsPresent, let monotonic = monotonicNow() else { return 0 }
        let targets = try loadGrants(where: "revokedAt IS NULL AND expiresAt IS NOT NULL", arguments: [])
            .compactMap { $0.restampingContinuousDeadline(at: monotonic, now: now) }
        guard !targets.isEmpty else { return 0 }
        let sql = "UPDATE grants SET bootSessionID = ?, continuousDeadline = ? WHERE grantID = ? AND revokedAt IS NULL"
        try Self.execute(db, "BEGIN IMMEDIATE TRANSACTION")
        do {
            for grant in targets {
                guard let deadline = grant.continuousDeadlineNanos else { continue }
                var statement: OpaquePointer?
                defer { sqlite3_finalize(statement) }
                guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
                    throw Self.statementError(db, sql)
                }
                bindOptionalText(statement, 1, grant.bootSessionID)
                sqlite3_bind_int64(statement, 2, Int64(clamping: deadline))
                bindText(statement, 3, grant.grantID.uuidString)
                guard sqlite3_step(statement) == SQLITE_DONE else {
                    throw Self.statementError(db, sql)
                }
            }
            try Self.execute(db, "COMMIT")
        } catch {
            try? Self.execute(db, "ROLLBACK")
            throw error
        }
        return targets.count
    }

    // MARK: Cleanup

    /// Deletes rows whose expiry has passed. Run at startup and periodically.
    ///
    /// An expired JIT admin grant that is still UNREVOKED is kept: its demotion
    /// never landed (the daemon was down at expiry, or the removal failed), and
    /// startup cleanup runs BEFORE the JIT manager's `reconcile()` — deleting the
    /// row would erase the only record that the user must still be demoted.
    /// - Returns: Number of rows removed.
    @discardableResult
    public func cleanupExpired(now: Date) throws -> Int {
        guard schemaPresent else { return 0 }
        let sql = """
            DELETE FROM grants WHERE expiresAt IS NOT NULL AND expiresAt < ?
              AND NOT (profileKey = ? AND canonicalPath = ? AND revokedAt IS NULL)
            """
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        bindText(statement, 1, ISO8601.string(from: now))
        bindText(statement, 2, JITAdminGrant.profileKey)
        bindText(statement, 3, JITAdminGrant.canonicalPath)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw Self.statementError(db, sql)
        }
        return Int(sqlite3_changes(db))
    }

    /// Drains integrity violations recorded since the last call.
    public func drainIntegrityViolations() -> [GrantStoreError] {
        defer { integrityViolations.removeAll() }
        return integrityViolations
    }

    // MARK: Row loading

    private func loadGrants(where clause: String, arguments: [String]) throws -> [Grant] {
        try loadVerifiedRows(where: clause, arguments: arguments).map(\.grant)
    }

    /// The key (of ``integrityKeys``) that verifies `hmac` over `grant`, if any.
    private func verifyingKey(for grant: Grant, storedHMAC: String) -> Data? {
        integrityKeys.first { key in
            HMACSHA256.verify(message: grant.integrityMessage(), key: key, expectedHex: storedHMAC)
        }
    }

    private func loadVerifiedRows(where clause: String, arguments: [String]) throws -> [(grant: Grant, key: Data)] {
        guard schemaPresent else { return [] }
        let sql = """
            SELECT \(rowColumns)
            FROM grants WHERE \(clause) ORDER BY grantID
            """
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        for (index, argument) in arguments.enumerated() {
            bindText(statement, Int32(index + 1), argument)
        }

        var rows: [(grant: Grant, key: Data)] = []
        var tampered: [UUID] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            let storedHMAC = columnText(statement, 14) ?? ""
            // A row this store already quarantined stays excluded without
            // re-reporting (and re-stamping) it on every read.
            if storedHMAC == Self.quarantineMarker { continue }
            guard let grant = decodeRow(statement) else { continue }
            if let key = verifyingKey(for: grant, storedHMAC: storedHMAC) {
                rows.append((grant, key))
                continue
            }
            integrityViolations.append(.integrityViolation(grantID: grant.grantID.uuidString))
            // JIT admin rows are NEVER quarantined here: a JIT row stands for a
            // real `admin` membership, and stamping it revoked would hide a
            // possibly-still-promoted user from every demotion path. They are
            // surfaced by ``unverifiedJITCandidates()`` and retired only after
            // the demotion lands (``retireUnverifiedRow(rowID:)``).
            if options.quarantineUnverifiedRows, !JITAdminGrant.isJITGrant(grant) {
                tampered.append(grant.grantID)
            }
        }
        sqlite3_finalize(statement)
        statement = nil

        // Tamper response: a row that fails verification is immediately
        // revoked (fail closed) and reported via integrityViolations.
        for grantID in tampered {
            try? quarantine(grantID: grantID)
        }
        return rows
    }

    /// Marks a tampered row revoked-now with a fresh HMAC over its current
    /// (untrusted) contents so it can never satisfy a request again.
    private func quarantine(grantID: UUID) throws {
        let sql = "UPDATE grants SET revokedAt = ?, rowHMAC = ? WHERE grantID = ?"
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        bindText(statement, 1, ISO8601.string(from: Date()))
        bindText(statement, 2, Self.quarantineMarker)
        bindText(statement, 3, grantID.uuidString)
        _ = sqlite3_step(statement)
    }

    // MARK: Unverifiable JIT rows

    /// JIT admin rows (identified by the — untrusted — JIT sentinel
    /// `profileKey` / `canonicalPath` columns) that fail HMAC verification or do
    /// not decode, are not yet quarantined, and whose (untrusted) `revokedAt` is
    /// NULL. Each stands for a membership Serberus may have granted and can no
    /// longer vouch for, so callers treat it as a DEMOTION CANDIDATE
    /// (conservative: an unverifiable JIT row demotes rather than being
    /// silently revoked, which would strand a permanent admin).
    public func unverifiedJITCandidates() throws -> [UnverifiedJITRow] {
        guard schemaPresent else { return [] }
        let sql = """
            SELECT \(rowColumns), rowid
            FROM grants WHERE profileKey = ? AND canonicalPath = ? AND revokedAt IS NULL
              AND rowHMAC IS NOT ? ORDER BY rowid
            """
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        bindText(statement, 1, JITAdminGrant.profileKey)
        bindText(statement, 2, JITAdminGrant.canonicalPath)
        bindText(statement, 3, Self.quarantineMarker)
        var candidates: [UnverifiedJITRow] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            let storedHMAC = columnText(statement, 14) ?? ""
            let reason: String
            if let grant = decodeRow(statement, recordViolation: false) {
                if verifyingKey(for: grant, storedHMAC: storedHMAC) != nil { continue }
                reason = "HMAC verification failed"
            } else {
                reason = "row does not decode"
            }
            let user = columnText(statement, 1)
            candidates.append(UnverifiedJITRow(
                rowID: sqlite3_column_int64(statement, Self.rowColumnCount),
                grantID: columnText(statement, 0),
                user: (user?.isEmpty ?? true) ? nil : user,
                reason: reason
            ))
        }
        return candidates
    }

    /// Quarantines one unverifiable row by SQLite `rowid` (revoked-now,
    /// `rowHMAC = 'tampered'`), after its demotion landed. A no-op returning
    /// false on a store opened without quarantine (the read-mostly one-shot
    /// never stamps rows it cannot verify).
    @discardableResult
    public func retireUnverifiedRow(rowID: Int64) throws -> Bool {
        guard options.quarantineUnverifiedRows, schemaPresent else { return false }
        let sql = "UPDATE grants SET revokedAt = ?, rowHMAC = ? WHERE rowid = ?"
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        bindText(statement, 1, ISO8601.string(from: Date()))
        bindText(statement, 2, Self.quarantineMarker)
        sqlite3_bind_int64(statement, 3, rowID)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw Self.statementError(db, sql) }
        return sqlite3_changes(db) > 0
    }

    /// Row counts by verifiability, for the teardown's "rows exist but none
    /// verify" check. Quarantined rows are counted separately (they are old
    /// tamper evidence, not live state).
    public func integritySummary() throws -> GrantStoreIntegritySummary {
        guard schemaPresent else { return GrantStoreIntegritySummary() }
        let sql = """
            SELECT \(rowColumns)
            FROM grants
            """
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw Self.statementError(db, sql)
        }
        var summary = GrantStoreIntegritySummary()
        while sqlite3_step(statement) == SQLITE_ROW {
            let storedHMAC = columnText(statement, 14) ?? ""
            if storedHMAC == Self.quarantineMarker {
                summary.quarantined += 1
            } else if let grant = decodeRow(statement, recordViolation: false),
                      verifyingKey(for: grant, storedHMAC: storedHMAC) != nil {
                summary.verified += 1
            } else {
                summary.unverifiable += 1
            }
        }
        return summary
    }

    /// The result columns every row read selects, in ``decodeRow(_:recordViolation:)``
    /// order: the 15 original columns, then `bootSessionID` / `continuousDeadline`
    /// (15, 16) and `generatedUID` (17) — NULLs where an existing-only open found
    /// an older table without them. Every read uses the same list, so a row's
    /// signed `generatedUID` is never dropped by one query and seen by another
    /// (that would make a valid row look tampered).
    private var rowColumns: String {
        """
        grantID, user, uid, ruleID, profileKey, teamID, binaryHash, canonicalPath, \
        argvPattern, grantedAt, expiresAt, revokedAt, policyVersion, schemaVersion, rowHMAC, \
        \(continuousColumnsPresent ? "bootSessionID, continuousDeadline" : "NULL, NULL"), \
        \(generatedUIDColumnPresent ? "generatedUID" : "NULL")
        """
    }

    /// Number of result columns in ``rowColumns``.
    static let rowColumnCount: Int32 = 18

    /// Continuous-clock columns at result indexes 15/16.
    private func decodeContinuous(_ statement: OpaquePointer?) -> (String?, UInt64?) {
        guard sqlite3_column_count(statement) >= 17 else { return (nil, nil) }
        let boot = columnText(statement, 15)
        let deadline: UInt64? = sqlite3_column_type(statement, 16) == SQLITE_NULL
            ? nil
            : UInt64(clamping: sqlite3_column_int64(statement, 16))
        return (boot, deadline)
    }

    private func decodeRow(_ statement: OpaquePointer?, recordViolation: Bool = true) -> Grant? {
        guard
            let idString = columnText(statement, 0),
            let grantID = UUID(uuidString: idString),
            let user = columnText(statement, 1),
            let ruleID = columnText(statement, 3),
            let profileKey = columnText(statement, 4),
            let teamID = columnText(statement, 5),
            let binaryHash = columnText(statement, 6),
            let canonicalPath = columnText(statement, 7),
            let grantedAtString = columnText(statement, 9),
            let grantedAt = ISO8601.date(from: grantedAtString),
            let policyVersion = columnText(statement, 12)
        else {
            if recordViolation {
                let id = columnText(statement, 0) ?? "<unreadable>"
                integrityViolations.append(.rowDecodingFailed(grantID: id, reason: "required column missing or malformed"))
            }
            return nil
        }
        let expiresAt = columnText(statement, 10).flatMap(ISO8601.date(from:))
        let revokedAt = columnText(statement, 11).flatMap(ISO8601.date(from:))
        let (bootSessionID, continuousDeadline) = decodeContinuous(statement)
        let generatedUID = sqlite3_column_count(statement) >= Self.rowColumnCount ? columnText(statement, 17) : nil
        return Grant(
            grantID: grantID,
            user: user,
            uid: uid_t(sqlite3_column_int64(statement, 2)),
            ruleID: ruleID,
            profileKey: profileKey,
            teamID: teamID,
            binaryHash: binaryHash,
            canonicalPath: canonicalPath,
            argvPattern: columnText(statement, 8),
            grantedAt: grantedAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            policyVersion: policyVersion,
            schemaVersion: Int(sqlite3_column_int64(statement, 13)),
            bootSessionID: bootSessionID,
            continuousDeadlineNanos: continuousDeadline,
            generatedUID: generatedUID
        )
    }

    // MARK: SQLite helpers

    private static func execute(_ db: OpaquePointer?, _ sql: String) throws {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw statementError(db, sql)
        }
        let result = sqlite3_step(statement)
        guard result == SQLITE_DONE || result == SQLITE_ROW else {
            throw statementError(db, sql)
        }
    }

    private func bindText(_ statement: OpaquePointer?, _ index: Int32, _ value: String) {
        sqlite3_bind_text(statement, index, value, -1, GrantStoreSchema.transient)
    }

    private func bindOptionalText(_ statement: OpaquePointer?, _ index: Int32, _ value: String?) {
        if let value {
            bindText(statement, index, value)
        } else {
            sqlite3_bind_null(statement, index)
        }
    }

    private func columnText(_ statement: OpaquePointer?, _ index: Int32) -> String? {
        guard let cString = sqlite3_column_text(statement, index) else { return nil }
        return String(cString: cString)
    }

    private static func statementError(_ db: OpaquePointer?, _ sql: String) -> GrantStoreError {
        let code = sqlite3_errcode(db)
        let message = db.map { String(cString: sqlite3_errmsg($0)) } ?? "database closed"
        return .statementFailed(sql: sql, code: code, message: message)
    }
}

/// A JIT admin row the store cannot vouch for (HMAC failure or undecodable).
/// Every field is UNTRUSTED — read straight from the row.
public struct UnverifiedJITRow: Sendable, Equatable {
    /// SQLite `rowid` — stable even when `grantID` is malformed.
    public let rowID: Int64
    public let grantID: String?
    /// The (untrusted) user the row names; nil when unreadable/empty.
    public let user: String?
    public let reason: String

    public init(rowID: Int64, grantID: String?, user: String?, reason: String) {
        self.rowID = rowID
        self.grantID = grantID
        self.user = user
        self.reason = reason
    }
}

/// Row counts by verifiability (see ``GrantStore/integritySummary()``).
public struct GrantStoreIntegritySummary: Sendable, Equatable {
    public var verified = 0
    public var unverifiable = 0
    public var quarantined = 0

    public init(verified: Int = 0, unverifiable: Int = 0, quarantined: Int = 0) {
        self.verified = verified
        self.unverifiable = unverifiable
        self.quarantined = quarantined
    }

    /// Live (non-quarantined) rows exist, yet none verifies under any key.
    public var isUnverifiable: Bool { unverifiable > 0 && verified == 0 }
}
