import Foundation

// MARK: - Rule Capture (the "Rule Recorder" hand-off document)
//
// A **Capture** is a short, user-initiated recording of every privilege
// touch-point on one Mac — each sudo attempt and each authorization-right
// (authURI) attempt in the window — taken in Serberus Sentinel (Intel tab →
// Capture) and handed to Serberus Commander (Definitions → Import Capture),
// where attempts become pre-filled Definitions. It is the discovery half of
// the discovery → authoring loop: the admin authors a rule from what the user
// actually did instead of guessing.
//
// These types live in PrivMgrCore because BOTH apps already link it: the
// Sentinel writes a capture, Commander reads it. They are pure `Codable` data
// with no dependencies, encoded as JSON in a `.serberuscapture` file. Raw log
// lines are kept on every attempt: Apple's log prose is not a contract and
// can be reworded, and the admin may want to see exactly what was logged.
//
// A capture is **untrusted input** to Commander: it is a user-supplied file
// (or a Jamf attachment any local user on the recording Mac could have
// written). Commander validates the schema, caps the size and attempt count,
// and never applies anything automatically — the Recorder PROPOSES.

/// Which mechanism an attempt went through.
public enum CapturedAttemptKind: String, Codable, Sendable, Equatable, CaseIterable {
    /// A `sudo` invocation (from sudo's own unified-log line, optionally
    /// enriched by Serberus's `DecisionEvent` when the daemon was consulted).
    case sudo
    /// An AuthorizationDB right attempt (from authd's unified-log lines).
    case authuri
}

/// What happened to the attempt, as far as the logs say.
///
/// Kept deliberately coarse and source-neutral. `requested` means the right /
/// command was named but the logs stated no verdict; `unknown` means the line
/// could not be classified. Never guessed — an inferred verdict is worse than
/// a neutral one for a tool whose output becomes policy.
public enum CapturedOutcome: String, Codable, Sendable, Equatable, CaseIterable {
    /// sudo ran the command / authd granted the right.
    case granted
    /// sudoers `command not allowed` / authd denied.
    case denied
    /// Authentication failed (sudo `N incorrect password attempts`, `a
    /// password is required` in a non-interactive run) / authd `Failed …`.
    case failed
    /// Named but no verdict on the line.
    case requested
    case unknown
}

/// One privilege touch-point observed during a capture.
public struct CapturedAttempt: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let kind: CapturedAttemptKind
    public let timestamp: Date
    /// The invoking user (sudo) or the console user at capture time (authuri —
    /// authd lines do not name the user; the capture records who was recording).
    public let user: String?

    // sudo
    /// The command path exactly as sudo logged it (`COMMAND=<path> …`).
    public let sudoCommand: String?
    /// `realpath` of `sudoCommand` at capture time when it differs (symlinked
    /// binaries — `/usr/local/bin/jamf` → `/usr/local/jamf/bin/jamf`). Maps to
    /// `RuleDefinition.resolvedCommandPattern`.
    public let resolvedCommand: String?
    /// Arguments after the command, as logged. `nil` when the recorder chose to
    /// redact arguments (they can carry secrets).
    public let argv: [String]?
    /// Raw status prose from sudo's line, when it stated one (`a password is
    /// required`, `command not allowed`, `3 incorrect password attempts`).
    public let sudoStatus: String?

    // authuri
    /// The AuthorizationDB right (`system.preferences.datetime`).
    public let authURI: String?
    /// The requesting client from authd's `by client '/path'`, when named.
    public let clientPath: String?

    // identity (captured on the recording Mac while the binary is on disk)
    /// Team ID of the command / client binary's signature, when signed.
    public let teamID: String?
    /// SHA-256 of the command / client binary, when readable.
    public let binaryHash: String?
    public let pid: Int?

    public let outcome: CapturedOutcome
    /// Serberus's own view of the same event, when the daemon was consulted
    /// (sudo `DecisionEvent`) or a Serberus authURI rule targets the right.
    public let matchedRuleID: String?
    public let matchedProfileKey: String?
    /// `DecisionEvent.outcome` verbatim (`granted` / `denied` / `would-grant` /
    /// `would-deny`) for sudo; nil when Serberus did not see it.
    public let serberusOutcome: String?
    /// The log lines this attempt was built from, verbatim, in time order.
    public let rawLines: [String]

    // identity-scoped (composed) rights — per-branch instrumentation
    /// Which composed branch the recording Mac PREDICTS authd resolved this
    /// attempt against: an app row name (`com.herojoneslabs.serberus.branch.…`)
    /// when the client binary satisfies that branch's code requirement, or
    /// `native-default` when none does (e.g. the client is a mediator such as
    /// `/usr/libexec/smd`). Nil when the right is not composed on this Mac or
    /// the client could not be inspected. A prediction, not authd's word —
    /// see ``branchEvidence`` for what authd actually said.
    public let predictedBranch: String?
    /// Raw authd / authorizationhost lines from this attempt that NAME a
    /// composed branch row, verbatim — the source of truth for which sub-rule
    /// actually matched. Empty when authd named none.
    public let branchEvidence: [String]?

    public init(
        id: String,
        kind: CapturedAttemptKind,
        timestamp: Date,
        user: String?,
        sudoCommand: String? = nil,
        resolvedCommand: String? = nil,
        argv: [String]? = nil,
        sudoStatus: String? = nil,
        authURI: String? = nil,
        clientPath: String? = nil,
        teamID: String? = nil,
        binaryHash: String? = nil,
        pid: Int? = nil,
        outcome: CapturedOutcome,
        matchedRuleID: String? = nil,
        matchedProfileKey: String? = nil,
        serberusOutcome: String? = nil,
        rawLines: [String],
        predictedBranch: String? = nil,
        branchEvidence: [String]? = nil
    ) {
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self.user = user
        self.sudoCommand = sudoCommand
        self.resolvedCommand = resolvedCommand
        self.argv = argv
        self.sudoStatus = sudoStatus
        self.authURI = authURI
        self.clientPath = clientPath
        self.teamID = teamID
        self.binaryHash = binaryHash
        self.pid = pid
        self.outcome = outcome
        self.matchedRuleID = matchedRuleID
        self.matchedProfileKey = matchedProfileKey
        self.serberusOutcome = serberusOutcome
        self.rawLines = rawLines
        self.predictedBranch = predictedBranch
        self.branchEvidence = branchEvidence
    }

    /// The path a Definition would pin on: the command (sudo) or the client
    /// (authuri). Nil when the attempt named none.
    public var binaryPath: String? {
        switch kind {
        case .sudo: return sudoCommand
        case .authuri: return clientPath
        }
    }

    /// One-line human label — what the admin scans in the import list.
    public var target: String {
        switch kind {
        case .sudo:
            let command = sudoCommand ?? "(unknown command)"
            guard let argv, !argv.isEmpty else { return command }
            return "\(command) \(argv.joined(separator: " "))"
        case .authuri:
            return authURI ?? "(unknown right)"
        }
    }
}

/// The Mac a capture was recorded on — identity only, so Commander can say
/// "from TESTMAC-2291 (serial …), user sample.user, enforce mode" without the
/// whole Intel host context.
public struct CaptureHost: Codable, Sendable, Equatable {
    public let serialNumber: String?
    public let computerName: String
    public let osVersion: String
    /// Console user who ran the capture.
    public let userName: String
    /// `state.plist` values at capture time, when present — tells the admin
    /// whether Serberus was even consulted (monitor/awaiting-config means the
    /// sudo attempts came from sudo's own log only).
    public let daemonState: String?
    public let enforcementMode: String?

    public init(
        serialNumber: String?,
        computerName: String,
        osVersion: String,
        userName: String,
        daemonState: String? = nil,
        enforcementMode: String? = nil
    ) {
        self.serialNumber = serialNumber
        self.computerName = computerName
        self.osVersion = osVersion
        self.userName = userName
        self.daemonState = daemonState
        self.enforcementMode = enforcementMode
    }
}

/// A finished capture: the document Sentinel saves / uploads and Commander
/// imports.
public struct RuleCapture: Codable, Sendable, Equatable {
    /// Bumped on any incompatible change. Commander refuses unknown majors.
    public static let currentSchemaVersion = "1.0"
    /// File extension for a saved capture.
    public static let fileExtension = "serberuscapture"
    /// Hard cap Commander applies before decoding (a capture is a short
    /// session; anything near this is not a capture).
    public static let maxEncodedBytes = 8 * 1024 * 1024
    /// Hard cap on attempts Commander will import from one file.
    public static let maxAttempts = 5_000

    public let schemaVersion: String
    public let host: CaptureHost
    /// Serberus component versions at capture time (`daemonVersion`, …), when
    /// readable — so the admin knows which parser/daemon produced the lines.
    public let componentVersions: [String: String]
    public let startedAt: Date
    public let endedAt: Date
    public let attempts: [CapturedAttempt]
    /// Free text the recorder typed ("user wanted to install the CAD plugin").
    public let notes: String
    /// True when the recorder chose to strip sudo arguments before saving.
    public let argumentsRedacted: Bool

    public init(
        schemaVersion: String = RuleCapture.currentSchemaVersion,
        host: CaptureHost,
        componentVersions: [String: String] = [:],
        startedAt: Date,
        endedAt: Date,
        attempts: [CapturedAttempt],
        notes: String = "",
        argumentsRedacted: Bool = false
    ) {
        self.schemaVersion = schemaVersion
        self.host = host
        self.componentVersions = componentVersions
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.attempts = attempts
        self.notes = notes
        self.argumentsRedacted = argumentsRedacted
    }

    /// Suggested file name: `Serberus-Capture-<serial-or-name>-<yyyyMMdd-HHmmss>.serberuscapture`.
    public var suggestedFileName: String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let who = host.serialNumber ?? host.computerName
        let safe = who.replacingOccurrences(of: "[^A-Za-z0-9_-]", with: "_", options: .regularExpression)
        return "Serberus-Capture-\(safe)-\(formatter.string(from: startedAt)).\(Self.fileExtension)"
    }

    /// A copy with sudo arguments removed from every attempt (and the
    /// `argumentsRedacted` flag set) — the recorder's "Redact arguments" option.
    public func redactingArguments() -> RuleCapture {
        RuleCapture(
            schemaVersion: schemaVersion,
            host: host,
            componentVersions: componentVersions,
            startedAt: startedAt,
            endedAt: endedAt,
            attempts: attempts.map { attempt in
                CapturedAttempt(
                    id: attempt.id, kind: attempt.kind, timestamp: attempt.timestamp, user: attempt.user,
                    sudoCommand: attempt.sudoCommand, resolvedCommand: attempt.resolvedCommand,
                    argv: nil, sudoStatus: attempt.sudoStatus,
                    authURI: attempt.authURI, clientPath: attempt.clientPath,
                    teamID: attempt.teamID, binaryHash: attempt.binaryHash, pid: attempt.pid,
                    outcome: attempt.outcome, matchedRuleID: attempt.matchedRuleID,
                    matchedProfileKey: attempt.matchedProfileKey, serberusOutcome: attempt.serberusOutcome,
                    // Raw sudo lines carry the full COMMAND= text; redaction
                    // must strip them too or it is no redaction at all.
                    rawLines: attempt.kind == .sudo ? [] : attempt.rawLines,
                    predictedBranch: attempt.predictedBranch,
                    branchEvidence: attempt.branchEvidence
                )
            },
            notes: notes,
            argumentsRedacted: true
        )
    }

    // MARK: Coding

    /// Stable, diff-friendly JSON (sorted keys, ISO-8601 dates, pretty).
    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(self)
    }

    /// Decodes and validates a capture Commander is about to import.
    ///
    /// Refuses (rather than truncating) oversize documents, unknown schema
    /// majors, and attempt counts over ``maxAttempts`` — a capture is
    /// untrusted input and a silently trimmed import would misrepresent what
    /// the user did.
    public static func decode(from data: Data) throws -> RuleCapture {
        guard data.count <= maxEncodedBytes else {
            throw CaptureDecodeError.tooLarge(bytes: data.count)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let capture: RuleCapture
        do {
            capture = try decoder.decode(RuleCapture.self, from: data)
        } catch {
            throw CaptureDecodeError.malformed(error.localizedDescription)
        }
        let major = capture.schemaVersion.split(separator: ".").first.map(String.init) ?? ""
        let supportedMajor = currentSchemaVersion.split(separator: ".").first.map(String.init) ?? ""
        guard major == supportedMajor else {
            throw CaptureDecodeError.unsupportedSchema(capture.schemaVersion)
        }
        guard capture.attempts.count <= maxAttempts else {
            throw CaptureDecodeError.tooManyAttempts(capture.attempts.count)
        }
        guard capture.endedAt >= capture.startedAt else {
            throw CaptureDecodeError.malformed("endedAt precedes startedAt")
        }
        // Per-attempt invariants the UI keys on: non-empty unique ids, and a
        // target that matches the kind. Refused rather than skipped — a
        // partially-valid untrusted file is still an invalid file.
        var ids = Set<String>()
        for attempt in capture.attempts {
            guard !attempt.id.isEmpty, ids.insert(attempt.id).inserted else {
                throw CaptureDecodeError.malformed("attempt ids must be non-empty and unique")
            }
            switch attempt.kind {
            case .sudo:
                guard let command = attempt.sudoCommand, !command.isEmpty else {
                    throw CaptureDecodeError.malformed("a sudo attempt without a command")
                }
            case .authuri:
                guard let right = attempt.authURI, !right.isEmpty else {
                    throw CaptureDecodeError.malformed("an authorization attempt without a right")
                }
            }
        }
        return capture
    }
}

public enum CaptureDecodeError: Error, LocalizedError, Equatable {
    case tooLarge(bytes: Int)
    case malformed(String)
    case unsupportedSchema(String)
    case tooManyAttempts(Int)

    public var errorDescription: String? {
        switch self {
        case let .tooLarge(bytes):
            return "This capture is \(bytes) bytes — larger than the \(RuleCapture.maxEncodedBytes)-byte limit. A capture is a short recording; this file is not one."
        case let .malformed(detail):
            return "This file is not a valid Serberus capture: \(detail)"
        case let .unsupportedSchema(version):
            return "This capture uses schema \(version); this Commander reads \(RuleCapture.currentSchemaVersion). Update Commander or re-record with a matching Sentinel."
        case let .tooManyAttempts(count):
            return "This capture holds \(count) attempts — more than the \(RuleCapture.maxAttempts) Commander will import at once."
        }
    }
}
