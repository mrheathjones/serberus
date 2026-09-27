import Foundation

/// Outcome of collecting one artifact.
///
/// `unavailable` carries a reason rather than being dropped. Intel runs as
/// a standard user and some Serberus state is deliberately root-only (the
/// grant database), so a partial bundle is the normal case, not an error
/// case. A support bundle that omits a file silently is indistinguishable
/// from one where the file was empty — the manifest has to say which.
public enum ArtifactStatus: Sendable, Equatable, Codable {
    case collected(byteCount: Int)
    case unavailable(reason: String)

    public var isCollected: Bool {
        if case .collected = self { return true }
        return false
    }
}

/// One item in the capture bundle.
public struct IntelArtifact: Sendable, Equatable, Codable, Identifiable {
    /// Path of this artifact inside the bundle.
    public let path: String
    /// Human explanation for the manifest and the GUI.
    public let detail: String
    public var status: ArtifactStatus

    public var id: String { path }

    public init(path: String, detail: String, status: ArtifactStatus) {
        self.path = path
        self.detail = detail
        self.status = status
    }
}

/// Identifies the Mac and the Serberus install a bundle came from.
public struct HostContext: Sendable, Equatable, Codable {
    public let serialNumber: String?
    public let computerName: String
    public let osVersion: String
    public let userName: String
    /// Daemon/PAM versions from the installed `version.plist`, when readable.
    public let componentVersions: [String: String]
    /// `state.plist` → `state`, the daemon's state machine value
    /// (e.g. `awaitingConfig`). Nil when the plist is absent, which itself
    /// means the daemon has likely never run.
    public let daemonState: String?
    /// `state.plist` → `enforcementMode` (`enforce`/`monitor`/`audit`).
    ///
    /// Distinct from `daemonState` and the single most load-bearing field in
    /// a support bundle: "sudo wasn't blocked" is expected behaviour in
    /// monitor/audit and a bug in enforce.
    public let enforcementMode: String?
    /// `state.plist` → `degradedReason`, present only when the daemon has
    /// self-reported degradation.
    public let degradedReason: String?
    /// `state.plist` → `updatedAt`. Its age tells the reader whether the
    /// daemon is actually alive or the state is stale.
    public let stateUpdatedAt: String?
    /// Whether the last-known-good config exists — the daemon's own
    /// "this Mac has been configured" marker.
    public let hasConfiguration: Bool

    public init(
        serialNumber: String?,
        computerName: String,
        osVersion: String,
        userName: String,
        componentVersions: [String: String],
        daemonState: String?,
        enforcementMode: String?,
        degradedReason: String?,
        stateUpdatedAt: String?,
        hasConfiguration: Bool
    ) {
        self.serialNumber = serialNumber
        self.computerName = computerName
        self.osVersion = osVersion
        self.userName = userName
        self.componentVersions = componentVersions
        self.daemonState = daemonState
        self.enforcementMode = enforcementMode
        self.degradedReason = degradedReason
        self.stateUpdatedAt = stateUpdatedAt
        self.hasConfiguration = hasConfiguration
    }
}

/// Top-level `manifest.json` written into every bundle.
///
/// The manifest is the contract with whoever opens the zip: it states what
/// was asked for, what arrived, and what did not — so a reader never has to
/// infer completeness from the file list.
public struct IntelManifest: Sendable, Equatable, Codable {
    public let formatVersion: Int
    public let createdAt: Date
    public let window: String
    public let predicate: String
    public let host: HostContext
    public let artifacts: [IntelArtifact]

    public static let currentFormatVersion = 1

    public init(
        formatVersion: Int = IntelManifest.currentFormatVersion,
        createdAt: Date,
        window: LogWindow,
        predicate: String = LogQuery.predicate,
        host: HostContext,
        artifacts: [IntelArtifact]
    ) {
        self.formatVersion = formatVersion
        self.createdAt = createdAt
        self.window = window.rawValue
        self.predicate = predicate
        self.host = host
        self.artifacts = artifacts
    }

    /// Artifacts that could not be collected — surfaced in the GUI so the
    /// user knows before they send the bundle.
    public var missing: [IntelArtifact] {
        artifacts.filter { !$0.status.isCollected }
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(self)
    }
}
