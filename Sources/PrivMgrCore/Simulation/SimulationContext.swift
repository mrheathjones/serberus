import Foundation

/// Mock grant for simulation. A value type — never a reference to the live
/// daemon ``GrantStore``. The simulator must work without a running daemon.
public struct SimulatedGrant: Codable, Sendable, Equatable {
    public let grantID: UUID
    public let user: String
    public let ruleID: String
    public let profileKey: String
    public let canonicalPath: String
    public let binaryHash: String
    public let expiresAt: Date?

    public init(
        grantID: UUID = UUID(),
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

    func snapshot() -> GrantSnapshot {
        GrantSnapshot(
            grantID: grantID,
            user: user,
            ruleID: ruleID,
            profileKey: profileKey,
            canonicalPath: canonicalPath,
            binaryHash: binaryHash,
            expiresAt: expiresAt
        )
    }
}

/// Synthetic input to the Decision Simulator.
public struct SimulationContext: Sendable, Equatable {
    public let user: String
    public let uid: uid_t
    /// AuthorizationDB right name. Exactly one of `authURI`/`sudoCommand`
    /// must be set.
    public let authURI: String?
    /// Sudo command path. Must be canonical (symlinks resolved).
    public let sudoCommand: String?
    /// Arguments to the sudo command. Preserved as `[String]`.
    public let argv: [String]
    /// Canonical executable path of the requesting binary.
    public let executablePath: String
    public let teamID: String
    public let binaryHash: String
    public let signingStatus: SigningStatus
    public let justificationProvided: Bool
    public let justificationText: String?
    /// Mock grant state — never live ``GrantStore`` references.
    public let activeGrants: [SimulatedGrant]
    /// Injectable evaluation time for time-based rule testing.
    public let currentTime: Date

    public init(
        user: String,
        uid: uid_t,
        authURI: String?,
        sudoCommand: String?,
        argv: [String] = [],
        executablePath: String,
        teamID: String,
        binaryHash: String,
        signingStatus: SigningStatus,
        justificationProvided: Bool = false,
        justificationText: String? = nil,
        activeGrants: [SimulatedGrant] = [],
        currentTime: Date
    ) {
        self.user = user
        self.uid = uid
        self.authURI = authURI
        self.sudoCommand = sudoCommand
        self.argv = argv
        self.executablePath = executablePath
        self.teamID = teamID
        self.binaryHash = binaryHash
        self.signingStatus = signingStatus
        self.justificationProvided = justificationProvided
        self.justificationText = justificationText
        self.activeGrants = activeGrants
        self.currentTime = currentTime
    }
}
