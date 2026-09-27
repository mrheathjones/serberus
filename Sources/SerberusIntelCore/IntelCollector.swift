import Foundation
import PrivMgrCore

/// A finished capture bundle on disk.
public struct IntelBundle: Sendable, Equatable {
    /// The zip archive.
    public let archiveURL: URL
    /// Manifest describing what made it in and what did not.
    public let manifest: IntelManifest

    public var suggestedFileName: String { archiveURL.lastPathComponent }
}

public enum IntelError: Error, LocalizedError {
    case archiveFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .archiveFailed(reason):
            return "Could not create the zip archive: \(reason)"
        }
    }
}

/// Collects Serberus diagnostics into a single zip.
///
/// Every collection step is best-effort and records an ``ArtifactStatus``.
/// A failure to read one artifact never fails the capture — it is recorded
/// as `unavailable` with a reason and the bundle is still produced. Running
/// as a standard user, some misses are expected by design (the grant
/// database is root-only), so the manifest is the source of truth about
/// completeness.
/// Filesystem locations the collector reads.
///
/// Injected rather than referenced through ``BundleConfig`` directly so the
/// collection logic is testable against fixture directories — otherwise the
/// only way to exercise it would be to install a daemon.
public struct IntelPaths: Sendable {
    public let jsonlLogDirectory: URL
    public let managedPreferencesDirectory: URL
    public let statePlist: URL
    public let versionPlist: URL
    public let lastKnownGoodConfig: URL

    public init(
        jsonlLogDirectory: URL = URL(fileURLWithPath: BundleConfig.logDirectory, isDirectory: true),
        managedPreferencesDirectory: URL = URL(fileURLWithPath: "/Library/Managed Preferences", isDirectory: true),
        statePlist: URL = URL(fileURLWithPath: BundleConfig.statePlistPath),
        versionPlist: URL = URL(fileURLWithPath: BundleConfig.versionPlistPath),
        lastKnownGoodConfig: URL = URL(fileURLWithPath: BundleConfig.lastKnownGoodConfigPath)
    ) {
        self.jsonlLogDirectory = jsonlLogDirectory
        self.managedPreferencesDirectory = managedPreferencesDirectory
        self.statePlist = statePlist
        self.versionPlist = versionPlist
        self.lastKnownGoodConfig = lastKnownGoodConfig
    }
}

public struct IntelCollector: Sendable {
    private let query: LogQuery
    private let reader: LogReader
    private let probe: HostProbe
    private let paths: IntelPaths
    private let now: @Sendable () -> Date
    /// Injectable log source so a collect test doesn't depend on whatever
    /// this machine happens to have logged.
    private let logSource: @Sendable (LogWindow) async throws -> [LogEntry]
    /// Asks the daemon for what this process cannot read. Injectable so the
    /// collect path is testable without a running daemon.
    private let privilegedSource: @Sendable (IntelRequest) async throws -> IntelHandoff

    /// `FileManager` is not `Sendable`, so it cannot be stored on a
    /// `Sendable` struct. `.default` is safe for the stateless file
    /// operations used here.
    private var fileManager: FileManager { .default }

    public init(
        query: LogQuery = LogQuery(),
        probe: HostProbe = HostProbe(),
        paths: IntelPaths = IntelPaths(),
        now: @escaping @Sendable () -> Date = { Date() },
        logSource: (@Sendable (LogWindow) async throws -> [LogEntry])? = nil,
        privilegedSource: (@Sendable (IntelRequest) async throws -> IntelHandoff)? = nil
    ) {
        let reader = LogReader(query: query)
        self.query = query
        self.reader = reader
        self.probe = probe
        self.paths = paths
        self.now = now
        self.logSource = logSource ?? { window in try await reader.show(window: window) }
        self.privilegedSource = privilegedSource ?? { request in
            try await IntelXPCClient().collect(request: request)
        }
    }

    /// Collects everything for `window` and writes a zip into `destinationDirectory`.
    public func collect(
        window: LogWindow,
        destinationDirectory: URL
    ) async throws -> IntelBundle {
        let host = probe.current()
        let timestamp = Self.fileTimestamp(now())
        let stem = "Serberus-Intel-\(host.serialNumber ?? host.computerName)-\(timestamp)"

        let staging = destinationDirectory
            .appendingPathComponent(".\(stem)-staging", isDirectory: true)
        try? fileManager.removeItem(at: staging)
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: true)
        // The staging tree is an implementation detail; never leave it behind,
        // even on the throwing paths below.
        defer { try? fileManager.removeItem(at: staging) }

        let root = staging.appendingPathComponent(stem, isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)

        var artifacts: [IntelArtifact] = []
        artifacts.append(contentsOf: await collectPrivileged(window: window, into: root))
        artifacts.append(contentsOf: collectJSONLLogs(into: root))
        artifacts.append(contentsOf: collectState(into: root))
        artifacts.append(contentsOf: collectManagedPreferences(into: root))

        let manifest = IntelManifest(
            createdAt: now(),
            window: window,
            host: host,
            artifacts: artifacts
        )
        try manifest.encoded().write(to: root.appendingPathComponent("manifest.json"))

        let archiveURL = destinationDirectory.appendingPathComponent("\(stem).zip")
        try? fileManager.removeItem(at: archiveURL)
        try Self.zip(directory: root, to: archiveURL)

        return IntelBundle(archiveURL: archiveURL, manifest: manifest)
    }

    // MARK: Privileged artifacts (via the daemon)

    /// Asks the daemon for what this process cannot read, then falls back to
    /// reading the unified log directly if that is possible.
    ///
    /// Order matters: the daemon path is tried first because it is the one that
    /// works for a standard user — the direct read only succeeds for an admin.
    /// Neither is required; a bundle is still produced from the JSONL either
    /// way, with the manifest saying what is missing.
    private func collectPrivileged(window: LogWindow, into root: URL) async -> [IntelArtifact] {
        let request = IntelRequest(
            window: window.rawValue,
            includeInfoAndDebug: query.includeInfoAndDebug
        )
        do {
            let handoff = try await privilegedSource(request)
            return adopt(handoff: handoff, into: root)
        } catch {
            // The daemon is absent, down, or refused. An admin can still read
            // the log directly; a standard user cannot, and that is recorded.
            var artifacts = [await collectUnifiedLog(window: window, into: root)]
            artifacts.append(IntelArtifact(
                path: "state/grants.sqlite",
                detail: "Active elevation grants (root-only)",
                status: .unavailable(reason: "the daemon could not collect it: \(error.localizedDescription)")
            ))
            return artifacts
        }
    }

    /// Moves the daemon's hand-off into the bundle and removes it.
    ///
    /// The hand-off directory holds every Serberus log line on the Mac and is
    /// chowned to this user, so it is not left behind once copied.
    private func adopt(handoff: IntelHandoff, into root: URL) -> [IntelArtifact] {
        let source = URL(fileURLWithPath: handoff.directory, isDirectory: true)
        defer { try? fileManager.removeItem(at: source) }

        var artifacts: [IntelArtifact] = []
        for name in handoff.files {
            let path = Self.bundlePath(for: name)
            let destination = root.appendingPathComponent(path)
            try? fileManager.createDirectory(
                at: destination.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            artifacts.append(copy(
                from: source.appendingPathComponent(name),
                to: destination,
                path: path,
                detail: Self.privilegedDetail(for: name)
            ))
        }
        for (name, reason) in handoff.unavailable.sorted(by: { $0.key < $1.key }) {
            artifacts.append(IntelArtifact(
                path: Self.bundlePath(for: name),
                detail: Self.privilegedDetail(for: name),
                status: .unavailable(reason: reason)
            ))
        }
        return artifacts
    }

    /// Where a daemon-collected artifact belongs in the bundle.
    ///
    /// The log sits at the top next to Intel's own `unified-log.txt`;
    /// everything else is machine state and joins `state/`. Explicit rather
    /// than inferred from the extension, so a collected file and its
    /// `unavailable` counterpart always report the same path — otherwise a
    /// reader would see the same artifact under two names depending on whether
    /// it was collected.
    static func bundlePath(for name: String) -> String {
        // Logs sit at the top next to Intel's own unified-log.txt; the grant
        // DB and the sudo/PAM wiring are machine state and join state/.
        ["unified-log.ndjson", "authorization-log.ndjson"].contains(name) ? name : "state/\(name)"
    }

    static func privilegedDetail(for name: String) -> String {
        switch name {
        case "unified-log.ndjson":
            return "System unified log, collected by the daemon (includes pam_serberus + Sentinel lines)"
        case "authorization-log.ndjson":
            return "macOS authorization-right attempts from authd — every right requested, its client, and allow/deny (authURI events; use these to author rules)"
        case "grants.sqlite":
            return "Active elevation grants (root-only database)"
        case "sudoers-serberus":
            return "The live /etc/sudoers.d/serberus drop-in — the coarse sudo gate as actually written"
        case "pam-sudo_local":
            return "The live /etc/pam.d/sudo_local — proves whether pam_serberus is wired"
        default:
            return "Collected by the Serberus daemon"
        }
    }

    // MARK: Unified log

    private func collectUnifiedLog(window: LogWindow, into root: URL) async -> IntelArtifact {
        let path = "unified-log.ndjson"
        // Report the permission boundary as a fact rather than letting `log`'s
        // raw error surface: for a standard user this is the expected outcome,
        // and the Serberus records in jsonl-logs/ carry the decisions anyway.
        guard UnifiedLogAccess.isReadable() else {
            return IntelArtifact(
                path: path,
                detail: "System unified log (pam_serberus + Sentinel lines)",
                status: .unavailable(reason: UnifiedLogAccess.unavailableReason)
            )
        }
        do {
            let entries = try await logSource(window)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            var document = Data()
            for entry in entries {
                document.append(try encoder.encode(entry))
                document.append(0x0A)
            }
            try document.write(to: root.appendingPathComponent(path))

            // A plain-text rendering alongside the NDJSON: rendered from the
            // already-parsed entries, so it costs no second `log show`.
            let text = entries.map(Self.renderLine).joined(separator: "\n")
            try Data(text.utf8).write(to: root.appendingPathComponent("unified-log.txt"))

            return IntelArtifact(
                path: path,
                detail: "Unified log for \(LogQuery.predicate) over \(window.rawValue) (\(entries.count) entries)",
                status: .collected(byteCount: document.count)
            )
        } catch {
            return IntelArtifact(
                path: path,
                detail: "Unified log export",
                status: .unavailable(reason: error.localizedDescription)
            )
        }
    }

    static func renderLine(_ entry: LogEntry) -> String {
        "\(entry.timestamp)  \(entry.level.label.padding(toLength: 7, withPad: " ", startingAt: 0))  "
            + "\(entry.subsystem):\(entry.category)  [\(entry.processName):\(entry.processID)]  \(entry.message)"
    }

    // MARK: Signed JSONL

    /// Copies the daemon's HMAC-signed decision/integrity JSONL.
    ///
    /// The `.hmac` sidecars are copied alongside their `.jsonl` files: the
    /// signature is what makes these tamper-evident, and a decision log
    /// shipped without its sidecar cannot be verified by whoever receives it.
    private func collectJSONLLogs(into root: URL) -> [IntelArtifact] {
        let source = paths.jsonlLogDirectory
        let destination = root.appendingPathComponent("jsonl-logs", isDirectory: true)

        guard let names = try? fileManager.contentsOfDirectory(atPath: source.path) else {
            return [IntelArtifact(
                path: "jsonl-logs/",
                detail: "Signed decision/integrity JSONL from \(source.path)",
                status: .unavailable(reason: "\(source.path) is unreadable or does not exist")
            )]
        }
        let wanted = names.filter { $0.hasSuffix(".jsonl") || $0.hasSuffix(".jsonl.hmac") }.sorted()
        guard !wanted.isEmpty else {
            return [IntelArtifact(
                path: "jsonl-logs/",
                detail: "Signed decision/integrity JSONL",
                status: .unavailable(reason: "no .jsonl files present — the daemon may not have logged yet")
            )]
        }

        try? fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
        return wanted.map { name in
            copy(
                from: source.appendingPathComponent(name),
                to: destination.appendingPathComponent(name),
                path: "jsonl-logs/\(name)",
                detail: name.hasSuffix(".hmac")
                    ? "HMAC sidecar proving \(name.replacingOccurrences(of: ".hmac", with: "")) is untampered"
                    : "Signed \(name.hasPrefix("integrity") ? "integrity" : "decision") log"
            )
        }
    }

    // MARK: Daemon state

    private func collectState(into root: URL) -> [IntelArtifact] {
        let destination = root.appendingPathComponent("state", isDirectory: true)
        try? fileManager.createDirectory(at: destination, withIntermediateDirectories: true)

        let files: [(URL, String)] = [
            (paths.statePlist, "Daemon state machine: state, enforcementMode, degradedReason"),
            (paths.versionPlist, "Installed component versions"),
            (paths.lastKnownGoodConfig, "Last-known-good config snapshot (existence = this Mac is configured)"),
        ]
        return files.map { source, detail in
            let name = source.lastPathComponent
            return copy(
                from: source,
                to: destination.appendingPathComponent(name),
                path: "state/\(name)",
                detail: detail
            )
        }
    }

    /// Copies the managed-preference plists the daemon actually reads.
    ///
    /// Scans by prefix rather than naming the domains: Serberus composes rules
    /// from the base `…rules` domain plus every `…rules.<suffix>` sub-domain,
    /// so a fixed list would miss exactly the sub-domain profiles a rules bug
    /// is most likely to involve.
    private func collectManagedPreferences(into root: URL) -> [IntelArtifact] {
        let source = paths.managedPreferencesDirectory
        let destination = root.appendingPathComponent("managed-preferences", isDirectory: true)
        // Same root string the daemon's own domains are built from.
        let prefix = BundleConfig.logSubsystem  // "com.herojoneslabs.serberus"

        guard let enumerator = fileManager.enumerator(
            at: source,
            includingPropertiesForKeys: nil
        ) else {
            return [IntelArtifact(
                path: "managed-preferences/",
                detail: "Effective MDM policy",
                status: .unavailable(reason: "/Library/Managed Preferences is unreadable")
            )]
        }

        // Recursive: per-user profiles land in a <username>/ subdirectory,
        // device-level ones at the top. Both matter.
        let matches = enumerator.compactMap { $0 as? URL }.filter {
            $0.lastPathComponent.hasPrefix(prefix) && $0.pathExtension == "plist"
        }.sorted { $0.path < $1.path }

        guard !matches.isEmpty else {
            return [IntelArtifact(
                path: "managed-preferences/",
                detail: "Effective MDM policy",
                status: .unavailable(reason: "no \(prefix)* profile is installed on this Mac")
            )]
        }

        try? fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
        // Compare resolved paths: string-stripping the source prefix breaks
        // whenever the enumerator hands back a symlink-resolved URL that no
        // longer starts with the prefix (`/var` → `/private/var`), which
        // silently mangles the whole absolute path into the filename.
        let sourceDepth = source.resolvingSymlinksInPath().standardizedFileURL.pathComponents.count
        return matches.map { url in
            // Flatten <user>/domain.plist to <user>__domain.plist so a
            // per-user profile never collides with the device-level one.
            let relative = url.resolvingSymlinksInPath().standardizedFileURL
                .pathComponents
                .dropFirst(sourceDepth)
                .joined(separator: "__")
            return copy(
                from: url,
                to: destination.appendingPathComponent(relative),
                path: "managed-preferences/\(relative)",
                detail: "Effective managed policy as the daemon sees it"
            )
        }
    }

    /// The grant database is root-only by design; record the gap explicitly.
    private func grantsArtifact() -> IntelArtifact {
        IntelArtifact(
            path: "state/grants.sqlite",
            detail: "Active elevation grants",
            status: .unavailable(
                reason: "root-only by design; Intel runs as the console user. "
                    + "Run `sudo serberus grants` on this Mac to read it."
            )
        )
    }

    // MARK: Helpers

    private func copy(from: URL, to: URL, path: String, detail: String) -> IntelArtifact {
        guard fileManager.fileExists(atPath: from.path) else {
            return IntelArtifact(path: path, detail: detail, status: .unavailable(reason: "not present at \(from.path)"))
        }
        do {
            try? fileManager.removeItem(at: to)
            try fileManager.copyItem(at: from, to: to)
            let attributes = try? fileManager.attributesOfItem(atPath: to.path)
            let size = (attributes?[.size] as? Int) ?? 0
            return IntelArtifact(path: path, detail: detail, status: .collected(byteCount: size))
        } catch {
            return IntelArtifact(path: path, detail: detail, status: .unavailable(reason: error.localizedDescription))
        }
    }

    static func fileTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        // Colon-free and space-free: this lands in a filename, a shell
        // argument, and a Jamf multipart filename header.
        formatter.dateFormat = "yyyyMMdd-HHmmss'Z'"
        return formatter.string(from: date)
    }

    /// Zips via `ditto`, which is the system's own archiver and produces
    /// archives Archive Utility opens cleanly.
    static func zip(directory: URL, to archive: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = [
            "-c", "-k",
            // Expand into one named folder instead of scattering files into
            // the reader's Downloads directory.
            "--keepParent",
            // No resource forks or xattrs. Diagnostics are plain files, and
            // preserving them makes ditto emit a parallel __MACOSX/._* tree
            // that is pure noise in a support bundle.
            "--norsrc", "--noextattr",
            directory.path, archive.path,
        ]

        let errorPipe = Pipe()
        process.standardError = errorPipe
        do {
            try process.run()
        } catch {
            throw IntelError.archiveFailed(error.localizedDescription)
        }
        let errorData = (try? errorPipe.fileHandleForReading.readToEnd()) ?? Data()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw IntelError.archiveFailed(
                "ditto exited \(process.terminationStatus): \(String(decoding: errorData, as: UTF8.self))"
            )
        }
    }
}
