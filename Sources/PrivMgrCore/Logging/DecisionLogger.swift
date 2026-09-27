import Foundation

// MARK: - Day stamping

/// Day stamp used in JSONL filenames.
///
/// Public because it is a **contract**, not an implementation detail: the
/// writer here and any reader (Serberus Intel reads these files directly)
/// must agree on the filename byte-for-byte. A second copy of this rule would
/// drift and silently read the wrong day's file.
public enum LogDay {
    /// `YYYY-MM-DD` in UTC for filename rotation. UTC avoids duplicate or
    /// skipped day files around DST transitions.
    public static func stamp(for date: Date) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .current
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }
}

// MARK: - Signed JSONL writer

/// Appends JSON lines to daily files with a chained HMAC-SHA256 sidecar.
///
/// Sidecar line *n* is `HMAC(key, sidecar[n-1] + "\n" + line[n])` — chaining
/// makes deletion and reordering detectable, not just edits. Verification
/// returns the first broken line so the daemon can emit an integrity event
/// naming it.
public actor SignedJSONLWriter {
    private let directory: URL
    private let filePrefix: String
    private let key: Data?

    /// - Parameters:
    ///   - directory: Log directory (created on first write if needed).
    ///   - filePrefix: e.g. `decisions` or `integrity`.
    ///   - keyProvider: When non-nil, an HMAC sidecar is maintained using the
    ///     `log-hmac-key` account.
    /// - Throws: ``LoggingError/signingKeyUnavailable(reason:)``
    public init(directory: URL, filePrefix: String, keyProvider: SigningKeyProvider?) throws {
        self.directory = directory
        self.filePrefix = filePrefix
        self.key = try keyProvider?.key(account: BundleConfig.logHMACKeyAccount)
    }

    /// Appends one encodable event as a JSON line stamped by its `timestamp`.
    /// - Throws: ``LoggingError``
    public func append(_ event: some Encodable & Sendable, timestamp: Date) throws {
        let line = try LogEncoding.encodeLine(event)
        let day = LogDay.stamp(for: timestamp)
        let fileURL = directory.appendingPathComponent("\(filePrefix)-\(day).jsonl")

        try ensureDirectory()
        try appendLine(line, to: fileURL)

        if let key {
            let sidecarURL = directory.appendingPathComponent("\(filePrefix)-\(day).jsonl.hmac")
            let previous = Self.lastLine(of: sidecarURL) ?? ""
            let signature = HMACSHA256.hexSignature(
                message: Data((previous + "\n" + line).utf8),
                key: key
            )
            try appendLine(signature, to: sidecarURL)
        }
    }

    /// Verifies the chained sidecar of one day file.
    ///
    /// - Returns: `nil` when intact, else the zero-based index of the first
    ///   broken line. A broken HMAC must trigger an immediate integrity
    ///   OSLog event from the caller.
    public func verify(day: String) throws -> Int? {
        guard let key else { return nil }
        let fileURL = directory.appendingPathComponent("\(filePrefix)-\(day).jsonl")
        let sidecarURL = directory.appendingPathComponent("\(filePrefix)-\(day).jsonl.hmac")
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }

        let lines = try Self.lines(of: fileURL)
        let signatures = (try? Self.lines(of: sidecarURL)) ?? []
        guard signatures.count == lines.count else {
            return min(signatures.count, lines.count)
        }

        var previous = ""
        for (index, line) in lines.enumerated() {
            let expected = HMACSHA256.hexSignature(
                message: Data((previous + "\n" + line).utf8),
                key: key
            )
            guard HMACSHA256.verify(
                message: Data((previous + "\n" + line).utf8),
                key: key,
                expectedHex: signatures[index]
            ) else { return index }
            previous = expected
        }
        return nil
    }

    // MARK: File primitives

    /// Mode for the day files and their `.hmac` sidecars.
    ///
    /// Deliberately world-READABLE (never writable): Serberus Intel / the
    /// Sentinel's Intel tab and Capture read these files directly as the
    /// standard console user (`JSONLTailer`, `JSONLLogSource`,
    /// `IntelCollector`) — there is no daemon/XPC path for them yet — so 0600
    /// would silently break those readers. Set explicitly (not via umask) so the
    /// mode is deterministic.
    static let fileMode: mode_t = 0o644

    /// Creates the log directory and strips any group/other WRITE bit from it.
    /// A writable log directory would let a local user plant a symlink at the
    /// next day's filename and redirect a root append. (Read/execute stay: the
    /// directory is traversed by the Intel readers above and by the capture
    /// hand-off under `captures/`.)
    private func ensureDirectory() throws {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw LoggingError.directoryUnavailable(path: directory.path, underlying: String(describing: error))
        }
        var info = stat()
        if lstat(directory.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_mode & 0o022 != 0 {
            chmod(directory.path, (info.st_mode & 0o7777) & ~0o022)
        }
    }

    /// Appends one line. Opens with `O_NOFOLLOW` so a symlink at the path is
    /// refused rather than written through (as root), creates at ``fileMode``
    /// exactly, and uses `O_APPEND` so concurrent appends never interleave
    /// mid-line.
    private func appendLine(_ line: String, to url: URL) throws {
        let data = Data((line + "\n").utf8)
        let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, Self.fileMode)
        guard fd >= 0 else {
            let code = errno
            throw LoggingError.directoryUnavailable(
                path: url.path, underlying: "open failed: \(String(cString: strerror(code)))")
        }
        defer { close(fd) }
        // Never group/other-WRITABLE, whatever created the file. (Tightening
        // only: an admin who made a file stricter is not overridden.)
        var info = stat()
        if fstat(fd, &info) == 0, info.st_mode & 0o022 != 0 {
            fchmod(fd, (info.st_mode & 0o7777) & ~0o022)
        }
        var writeError: Int32 = 0
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var offset = 0
            while offset < raw.count {
                let written = write(fd, raw.baseAddress?.advanced(by: offset), raw.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    writeError = errno
                    return
                }
                offset += written
            }
        }
        guard writeError == 0 else {
            throw LoggingError.directoryUnavailable(
                path: url.path, underlying: "write failed: \(String(cString: strerror(writeError)))")
        }
    }

    private static func lines(of url: URL) throws -> [String] {
        let content = try String(contentsOf: url, encoding: .utf8)
        return content.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    private static func lastLine(of url: URL) -> String? {
        guard let content = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        return content.split(separator: "\n", omittingEmptySubsequences: true).last.map(String.init)
    }
}

// MARK: - Decision logger

/// Writes elevation decision events to daily signed JSONL files
/// (`decisions-YYYY-MM-DD.jsonl` + `.hmac` sidecar).
///
/// OSLog mirroring (`decisions` category under
/// ``BundleConfig/logSubsystem``) is layered on by the daemon target —
/// PrivMgrCore stays UI/OS-framework light.
public actor DecisionLogger {
    private let writer: SignedJSONLWriter
    private let reader: DecisionCountReader

    /// - Parameters:
    ///   - directory: Log directory; defaults to ``BundleConfig/logDirectory``.
    ///   - keyProvider: Source of the `log-hmac-key` signing key.
    /// - Throws: ``LoggingError``
    public init(
        directory: URL = URL(fileURLWithPath: BundleConfig.logDirectory),
        keyProvider: SigningKeyProvider
    ) throws {
        self.writer = try SignedJSONLWriter(
            directory: directory,
            filePrefix: "decisions",
            keyProvider: keyProvider
        )
        self.reader = DecisionCountReader(directory: directory)
    }

    /// Appends one decision event.
    public func log(_ event: DecisionEvent) async throws {
        try await writer.append(event, timestamp: event.timestamp)
    }

    /// Verifies one day's chain. `nil` = intact.
    public func verify(day: String) async throws -> Int? {
        try await writer.verify(day: day)
    }

    /// Tallies one day's decisions by outcome (read-only; never throws).
    public func counts(day: String, since: Date? = nil) -> DecisionDayCounts {
        reader.counts(day: day, since: since)
    }

    /// Sum of ``counts(day:since:)`` over `days` (e.g. today + yesterday).
    public func counts(days: [String], since: Date? = nil) -> DecisionDayCounts {
        reader.counts(days: days, since: since)
    }
}

// MARK: - Integrity logger

/// Writes integrity events to daily JSONL files
/// (`integrity-YYYY-MM-DD.jsonl`).
public actor IntegrityLogger {
    private let writer: SignedJSONLWriter

    /// - Throws: ``LoggingError``
    public init(directory: URL = URL(fileURLWithPath: BundleConfig.logDirectory)) throws {
        self.writer = try SignedJSONLWriter(
            directory: directory,
            filePrefix: "integrity",
            keyProvider: nil
        )
    }

    /// Appends one integrity event.
    public func log(_ event: IntegrityEvent) async throws {
        try await writer.append(event, timestamp: event.timestamp)
    }
}
