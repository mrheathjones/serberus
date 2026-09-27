import Foundation

// MARK: - Binary identity

/// Validated identity of the requesting binary, collected at decision time.
///
/// Never match solely on path. The type system enforces this —
/// an ``ElevationRequest`` cannot be constructed without full identity
/// evidence (canonical path, team ID, hash, signing status), so a path-only
/// matching code path cannot be built.
public struct BinaryIdentity: Codable, Sendable, Equatable {
    /// Canonical executable path, post-symlink resolution.
    public let canonicalPath: String
    /// Apple Developer Team ID, or `nil` for unsigned/ad-hoc binaries.
    public let teamID: String?
    /// SHA-256 of the binary at decision time (hex string).
    public let sha256: String
    /// Code-signing posture observed at decision time.
    public let signingStatus: SigningStatus

    public init(canonicalPath: String, teamID: String?, sha256: String, signingStatus: SigningStatus) {
        self.canonicalPath = canonicalPath
        self.teamID = teamID
        self.sha256 = sha256
        self.signingStatus = signingStatus
    }
}

// MARK: - Request kind

/// What kind of elevation is being requested.
public enum ElevationRequestKind: Sendable, Equatable {
    /// An AuthorizationDB right evaluation.
    case authURI(String)
    /// A sudo command invocation. `argv` excludes the command itself.
    case sudo(command: String, argv: [String])
}

// MARK: - Elevation request

/// A single elevation request presented to the rule engine.
///
/// The daemon constructs this from live PAM/authdb data; the Decision
/// Simulator constructs it from a ``SimulationContext``. Both flow through
/// the identical ``RuleEngine`` code path.
public struct ElevationRequest: Sendable, Equatable {
    /// Authenticating username.
    public let user: String
    /// Authenticating user's UID.
    public let uid: uid_t
    /// Right name or sudo command being requested.
    public let kind: ElevationRequestKind
    /// Validated identity of the requesting binary.
    public let identity: BinaryIdentity
    /// Whether justification text was provided with the request.
    public let justificationProvided: Bool
    /// Justification text, if provided.
    public let justificationText: String?
    /// Evaluation timestamp. Injectable for deterministic testing.
    public let timestamp: Date

    public init(
        user: String,
        uid: uid_t,
        kind: ElevationRequestKind,
        identity: BinaryIdentity,
        justificationProvided: Bool = false,
        justificationText: String? = nil,
        timestamp: Date
    ) {
        self.user = user
        self.uid = uid
        self.kind = kind
        self.identity = identity
        self.justificationProvided = justificationProvided
        self.justificationText = justificationText
        self.timestamp = timestamp
    }
}

// MARK: - Grant snapshot

/// A point-in-time view of an active grant, used during evaluation.
///
/// The engine never reads the live ``GrantStore`` directly — the daemon
/// snapshots relevant grants into values, and the simulator supplies
/// ``SimulatedGrant`` mocks converted to this type.
public struct GrantSnapshot: Codable, Sendable, Equatable {
    /// Grant identifier.
    public let grantID: UUID
    /// User the grant was issued to.
    public let user: String
    /// Rule that produced the grant.
    public let ruleID: String
    /// Profile the rule belongs to.
    public let profileKey: String
    /// Canonical path of the binary the grant covers.
    public let canonicalPath: String
    /// SHA-256 of the binary the grant covers.
    public let binaryHash: String
    /// Expiry. `nil` = no expiry.
    public let expiresAt: Date?

    public init(
        grantID: UUID,
        user: String,
        ruleID: String,
        profileKey: String,
        canonicalPath: String,
        binaryHash: String,
        expiresAt: Date?
    ) {
        self.grantID = grantID
        self.user = user
        self.ruleID = ruleID
        self.profileKey = profileKey
        self.canonicalPath = canonicalPath
        self.binaryHash = binaryHash
        self.expiresAt = expiresAt
    }

    /// Whether the grant is unexpired at `date`.
    public func isActive(at date: Date) -> Bool {
        guard let expiresAt else { return true }
        return date < expiresAt
    }
}
