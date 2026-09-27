import Foundation

// MARK: - Decision event

/// One elevation decision event, written to
/// `decisions-YYYY-MM-DD.jsonl` and the `decisions` OSLog category.
public struct DecisionEvent: Codable, Sendable, Equatable {
    /// Enforcement-mode-aware outcome.
    public enum Outcome: String, Codable, Sendable {
        case granted
        case denied
        case wouldGrant = "would-grant"
        case wouldDeny = "would-deny"
    }

    public var schemaVersion: String
    public var eventID: UUID
    public var timestamp: Date
    public var eventType: String
    public var outcome: Outcome
    public var enforcementMode: EnforcementMode
    public var authURI: String?
    public var sudoCommand: String?
    /// Redacted argv, present only when the matched rule sets `logArguments`.
    public var arguments: [String]?
    public var processPath: String
    public var processTeamID: String
    public var processHash: String
    public var userName: String
    public var userUID: Int
    public var ruleID: String?
    public var profileKey: String?
    public var grantID: UUID?
    /// Justification text, redacted before encoding.
    public var justification: String?
    public var grantDurationSeconds: Int
    public var cacheHit: Bool
    public var deviceSerial: String
    public var daemonVersion: String
    public var pamModuleVersion: String
    public var policyVersion: String
    /// `true` only for a decision that raised an interactive elevation prompt
    /// (the terminal verdict is still carried in `outcome`).
    ///
    /// Optional so the synthesized coder omits the key when absent and decodes
    /// older log lines — written before this field existed — without error.
    /// Readers treat a missing value as `false` (no prompt).
    public var requiredPrompt: Bool?

    public init(
        schemaVersion: String = "1.0",
        eventID: UUID = UUID(),
        timestamp: Date,
        eventType: String = "elevation_decision",
        outcome: Outcome,
        enforcementMode: EnforcementMode,
        authURI: String?,
        sudoCommand: String?,
        arguments: [String]?,
        processPath: String,
        processTeamID: String,
        processHash: String,
        userName: String,
        userUID: Int,
        ruleID: String?,
        profileKey: String?,
        grantID: UUID?,
        justification: String?,
        grantDurationSeconds: Int,
        cacheHit: Bool,
        deviceSerial: String,
        daemonVersion: String,
        pamModuleVersion: String,
        policyVersion: String,
        requiredPrompt: Bool? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.eventID = eventID
        self.timestamp = timestamp
        self.eventType = eventType
        self.outcome = outcome
        self.enforcementMode = enforcementMode
        self.authURI = authURI
        self.sudoCommand = sudoCommand
        self.arguments = arguments.map(ArgumentRedactor.redact)
        self.processPath = processPath
        self.processTeamID = processTeamID
        self.processHash = processHash
        self.userName = userName
        self.userUID = userUID
        self.ruleID = ruleID
        self.profileKey = profileKey
        self.grantID = grantID
        self.justification = justification.map(ArgumentRedactor.redact(text:))
        self.grantDurationSeconds = grantDurationSeconds
        self.cacheHit = cacheHit
        self.deviceSerial = deviceSerial
        self.daemonVersion = daemonVersion
        self.pamModuleVersion = pamModuleVersion
        self.policyVersion = policyVersion
        self.requiredPrompt = requiredPrompt
    }

    /// Maps a rule-engine decision to the mode-aware outcome string.
    ///
    /// In audit mode decisions are logged as `would-grant`/`would-deny`
    /// while all requests pass through to native behavior.
    public static func outcome(for decision: Decision, mode: EnforcementMode) -> Outcome {
        let granted = decision == .allow || decision == .timedGrant
        switch mode {
        case .enforce, .monitor:
            return granted ? .granted : .denied
        case .audit:
            return granted ? .wouldGrant : .wouldDeny
        }
    }
}

// MARK: - Integrity event

/// One integrity event: policy changes, daemon restarts, state transitions,
/// kill switch, HMAC breaks, AuthorizationDB modifications.
public struct IntegrityEvent: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case stateTransition = "state_transition"
        case policyChange = "policy_change"
        case daemonStart = "daemon_start"
        case daemonStop = "daemon_stop"
        case killSwitch = "kill_switch"
        case hmacViolation = "hmac_violation"
        case authDBModification = "authdb_modification"
        case authDBRestore = "authdb_restore"
        case grantRevocation = "grant_revocation"
        case upgradeValidation = "upgrade_validation"
        case configurationError = "configuration_error"
    }

    public var schemaVersion: String
    public var eventID: UUID
    public var timestamp: Date
    public var kind: Kind
    public var detail: String
    public var daemonVersion: String

    public init(
        schemaVersion: String = "1.0",
        eventID: UUID = UUID(),
        timestamp: Date,
        kind: Kind,
        detail: String,
        daemonVersion: String
    ) {
        self.schemaVersion = schemaVersion
        self.eventID = eventID
        self.timestamp = timestamp
        self.kind = kind
        self.detail = detail
        self.daemonVersion = daemonVersion
    }
}

// MARK: - Encoding

enum LogEncoding {
    /// Deterministic single-line JSON encoder shared by both log streams.
    static func encodeLine(_ event: some Encodable) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(ISO8601.string(from: date))
        }
        let data: Data
        do {
            data = try encoder.encode(event)
        } catch {
            throw LoggingError.encodingFailed(reason: String(describing: error))
        }
        return String(decoding: data, as: UTF8.self)
    }
}
