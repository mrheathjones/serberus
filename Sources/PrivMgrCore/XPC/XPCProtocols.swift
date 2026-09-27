import Foundation

// MARK: - PAM dictionary contract (C ↔ Swift boundary)

/// Key names for the PAM ↔ daemon XPC dictionary contract.
///
/// No Swift types cross the C boundary — the PAM module uses pure
/// `xpc_dictionary_*` calls with these exact key strings, which are also
/// defined in the shared C header `serberus_xpc_keys.h`. Keep both in sync.
public enum PAMXPCKey {
    // PAM → Daemon request
    /// `"sudo"` or `"authuri"`.
    public static let type = "type"
    /// Authenticating username.
    public static let user = "user"
    /// Fully-qualified command, post-symlink (sudo only).
    public static let command = "command"
    /// Argument vector for the command, as an xpc array of strings (sudo
    /// only). Excludes the command itself. Argv is preserved as a list — it
    /// is never flattened.
    public static let argv = "argv"
    /// Right name (authuri only).
    public static let authURI = "authURI"
    /// Calling PID — informational only, never used for validation
    /// (PID checks are TOCTOU-vulnerable; audit tokens are authoritative).
    public static let pid = "pid"
    /// Terminal device (sudo only).
    public static let tty = "tty"

    // Daemon → PAM response
    /// `"allow"`, `"deny"`, `"prompt_pending"`, `"pending"` or `"native"`.
    public static let decision = "decision"
    /// Cache TTL; `0` = do not cache.
    public static let cacheSeconds = "cacheSeconds"
    /// UUID of the created ``Grant``.
    public static let grantID = "grantID"
    /// Matched rule ID (for logging).
    public static let ruleID = "ruleID"
    /// Prompt round-trip ticket: PAM receives this with a `prompt_pending`
    /// reply and echoes it on each `poll_prompt` request.
    public static let requestID = "requestID"
    /// Poll deny detail: how the prompt resolved (`denied` = the user
    /// declined, `timed-out` = it expired unanswered). Optional — absent on
    /// non-prompt denies and from older daemons; PAM falls back to the
    /// generic deny message when missing.
    public static let verdict = "verdict"

    /// Request type values.
    public static let typeSudo = "sudo"
    public static let typeAuthURI = "authuri"
    /// PAM polls the daemon for a pending prompt's verdict.
    public static let typePollPrompt = "poll_prompt"
    /// Decision values.
    public static let decisionAllow = "allow"
    public static let decisionDeny = "deny"
    /// Initial reply when a `.prompt` rule fires: the prompt is being shown;
    /// PAM must poll with ``requestID``.
    public static let decisionPromptPending = "prompt_pending"
    /// Poll reply while the user has not yet decided.
    public static let decisionPending = "pending"
    /// Initial reply for a user who is a JIT admin right now (an active
    /// Serberus JIT grant or an observed Jamf Connect elevation, and live
    /// `admin` membership): PAM returns PAM_IGNORE so sudo runs exactly as
    /// native macOS, password prompt included, and does not clear the ticket.
    public static let decisionNative = "native"
    /// ``verdict`` values on a poll deny.
    public static let verdictDenied = "denied"
    public static let verdictTimedOut = "timed-out"
}

// MARK: - Typed DTOs (Sentinel / Intel callers)

/// Prompt request pushed from daemon to Sentinel.
public struct PromptContext: Codable, Sendable, Equatable {
    public let requestID: UUID
    public let user: String
    public let processName: String
    public let canonicalPath: String
    public let teamID: String?
    public let signingStatus: SigningStatus
    /// Auth URI or sudo command formatted for humans.
    public let humanReadableRequest: String
    public let requireJustification: Bool
    public let justificationMinLength: Int
    public let timeoutSeconds: Int
    /// Matched rule identity (`profileKey · ruleID`) for the prompt's RULE
    /// row. Optional for wire compatibility with older peers.
    public let ruleName: String?
    /// The matched rule's human-readable description, for the prompt's
    /// "asking to …" sentence. Optional for wire compatibility.
    public let ruleDescription: String?
    /// When the matched rule issues a TIME-BOUND grant on approval, how long (in
    /// seconds) the elevation stays active before it must be re-approved. `nil`
    /// when the grant is indefinite (time-bound disabled) or the rule issues no
    /// grant — the prompt then shows no duration. Optional for wire compatibility.
    public let grantDurationSeconds: Int?

    public init(
        requestID: UUID = UUID(),
        user: String,
        processName: String,
        canonicalPath: String,
        teamID: String?,
        signingStatus: SigningStatus,
        humanReadableRequest: String,
        requireJustification: Bool,
        justificationMinLength: Int,
        timeoutSeconds: Int,
        ruleName: String? = nil,
        ruleDescription: String? = nil,
        grantDurationSeconds: Int? = nil
    ) {
        self.requestID = requestID
        self.user = user
        self.processName = processName
        self.canonicalPath = canonicalPath
        self.teamID = teamID
        self.signingStatus = signingStatus
        self.humanReadableRequest = humanReadableRequest
        self.requireJustification = requireJustification
        self.justificationMinLength = justificationMinLength
        self.timeoutSeconds = timeoutSeconds
        self.ruleName = ruleName
        self.ruleDescription = ruleDescription
        self.grantDurationSeconds = grantDurationSeconds
    }
}

public extension PromptContext {
    /// Prefix the daemon puts on ``humanReadableRequest`` for authorization
    /// (authURI) requests. One constant so the Sentinel's display parsing can
    /// never drift from the daemon's formatting.
    static let authURIRequestPrefix = "Authorization right: "

    /// Whether this prompt is for an authorization right (vs a sudo command).
    var isAuthURIRequest: Bool {
        humanReadableRequest.hasPrefix(Self.authURIRequestPrefix)
    }

    /// ``processName`` of the confirmation prompt the daemon raises for
    /// "Install with Serberus". One constant so the Sentinel's display logic
    /// (row label, "Installing…" toast) can never drift from the daemon.
    static let installProcessName = "Install with Serberus"
    /// ``processName`` of the "Uninstall with Serberus" confirmation prompt.
    static let uninstallProcessName = "Uninstall with Serberus"

    /// Whether this prompt confirms an install or uninstall (the app-management
    /// path) rather than a sudo command or an authorization right.
    var isAppManagementRequest: Bool {
        processName == Self.installProcessName || processName == Self.uninstallProcessName
    }

    /// The prompt's detail-row label for this request: `RIGHT` for an
    /// authorization right, `ITEM` for an install or uninstall, `COMMAND` for a
    /// sudo command.
    var requestRowLabel: String {
        if isAuthURIRequest { return "Right" }
        return isAppManagementRequest ? "Item" : "Command"
    }

    /// The detail-row value: the bare right name for authURI requests, the
    /// full command line for sudo. Hidden characters (bidi overrides,
    /// zero-width characters, newlines…) show as escapes
    /// (``DisplayText/escapingInvisibles(_:)``): the daemon escapes them
    /// already, and this covers a context from an older daemon.
    var requestRowValue: String {
        guard humanReadableRequest.hasPrefix(Self.authURIRequestPrefix) else {
            return DisplayText.escapingInvisibles(humanReadableRequest)
        }
        return DisplayText.escapingInvisibles(String(humanReadableRequest.dropFirst(Self.authURIRequestPrefix.count)))
    }

    /// The rule's friendly name for the prompt's Rule row — the SAME name the
    /// Sentinel "My rules" list shows (the rule's description). When the rule
    /// carries no description, this mirrors the list's fallbacks
    /// (``SentinelRuleSummary/title(for:)``): the bare right for authURI, and
    /// `sudo <binary>` for a sudo command — so the prompt and the list never
    /// disagree about a rule's name.
    var ruleDisplayName: String {
        if let description = ruleDescription?.trimmingCharacters(in: .whitespacesAndNewlines),
           !description.isEmpty {
            return description
        }
        if isAuthURIRequest {
            return requestRowValue
        }
        let binary = (canonicalPath as NSString).lastPathComponent
        return binary.isEmpty ? "sudo command" : "sudo \(binary)"
    }
}

/// Sentinel's answer to a ``PromptContext``. Timeout and Escape always deny.
public struct PromptResponse: Codable, Sendable, Equatable {
    public enum Verdict: String, Codable, Sendable {
        case approved
        case denied
        case timedOut = "timed-out"
    }

    public let requestID: UUID
    public let verdict: Verdict
    public let justificationText: String?

    public init(requestID: UUID, verdict: Verdict, justificationText: String? = nil) {
        self.requestID = requestID
        self.verdict = verdict
        self.justificationText = justificationText
    }
}

/// Daemon state as exposed over XPC (mirrors state.plist).
public enum DaemonState: String, Codable, Sendable, CaseIterable {
    /// This Mac has never held a usable configuration: no managed config (or an
    /// unsafe/partial one) AND no last-known-good snapshot. The daemon serves,
    /// polls, and logs — but enforces NOTHING (effective mode is forced to
    /// ``EnforcementMode/monitor``) and mutates NOTHING (no AuthorizationDB
    /// reconcile, no sudoers drop-in). This is the Jamf enrollment race: the
    /// Core pkg can install before APNS delivers the config profile, and an
    /// enforcing daemon with no break-glass would brick sudo.
    ///
    /// It is deliberately the ONLY fail-open state, and it is unreachable once a
    /// config has ever been adopted (see ``BundleConfig/lastKnownGoodConfigPath``).
    case awaitingConfig = "awaiting_config"
    case pendingPPPC = "pending_pppc"
    case pendingProfiles = "pending_profiles"
    case degraded
    case healthy
    case killSwitch = "kill_switch"
}

/// Cause recorded in state.plist when ``DaemonState/degraded``.
public enum DegradedReason: String, Codable, Sendable, CaseIterable {
    /// Retain last valid policy.
    case configInvalid = "config_invalid"
    /// The managed config is absent (or present but not safely enforceable) on a
    /// Mac that HAS been configured before: the daemon fell back to the
    /// last-known-good snapshot and keeps enforcing it (break-glass intact).
    /// Removing the config profile can never disable Serberus.
    case configMissing = "config_missing"
    /// Part of the enforced policy isn't in the AuthorizationDB: a right's
    /// definition couldn't be read, its original couldn't be saved (Serberus
    /// never rewrites a right without a record to restore it from), or the
    /// write failed. The rest of the policy is applied, denies first; a failed
    /// right keeps the definition it had, and nothing is denied in its place.
    /// The daemon retries on every reload tick and clears this once the retry
    /// succeeds. Under the kill switch: restoring the rights Serberus changed
    /// failed (also retried every tick).
    case authDBFailure = "authdb_failure"
    /// Deny all timed grants; allow silent.
    case grantsDBError = "grants_db_error"
    /// Retain last valid rule set.
    case ruleParseError = "rule_parse_error"
    /// Health monitor triggers restart.
    case xpcFailure = "xpc_failure"
    /// A managed-preferences reload pass exceeded its deadline and was abandoned
    /// by the watchdog. Retain last valid policy; policy updates are NOT being
    /// applied. Enforcement of the already-loaded policy is unaffected — which is
    /// exactly why this must be reported loudly: the failure is otherwise silent
    /// policy drift. Self-clears when a later pass completes; after several
    /// consecutive stalls the daemon exits for a launchd restart.
    case reloadStalled = "reload_stalled"
    /// The daemon is enforcing, but `/etc/pam.d/sudo_local` does not route sudo
    /// authentication through `pam_serberus.so` as the FIRST, `requisite` auth
    /// module (or the module / its directories are not root-controlled). The
    /// coarse `/etc/sudoers.d/serberus` drop-in is withheld (removed) — without
    /// the PAM gate it would hand enrolled standard users ungated sudo — and is
    /// restored automatically once the gate verifies on a later reload tick.
    case pamNotWired = "pam_not_wired"
    /// The daemon is enforcing, but NONE of the configured `pamBypass` entries
    /// (users via `getpwnam`, groups via `getgrnam`) resolves on this Mac —
    /// enforcement with zero working break-glass, e.g. a typo'd profile
    /// (break-glass resolvability). Re-checked on every reload tick. A delivered
    /// profile in this state is not adopted: the daemon keeps enforcing its
    /// last-known-good config (or, on a Mac that never had one, stays awaiting
    /// config), exactly as for an empty `pamBypass`. Fix the profile's
    /// `pamBypass`. Ranks just below `config_invalid`.
    case bypassUnresolvable = "bypass_unresolvable"
    /// Identity-scoped authURI rules are in the enforced policy, but the
    /// SerberusAuth authorization plugin (`/Library/Security/SecurityAgentPlugins/
    /// SerberusAuth.bundle`) is missing or fails its ownership / signature
    /// check. Their rights are left (or put back) at their native definitions —
    /// never composed around a mechanism authd cannot load, which would fail
    /// the right for every caller. Re-checked every reload tick (a cheap
    /// `lstat` fingerprint; the full signature check only on change); clears
    /// once the plugin verifies and the rights are recomposed. Status only;
    /// ranks below every other degraded cause.
    case authPluginUnavailable = "auth_plugin_unavailable"
}

/// A point-in-time status snapshot of the daemon: state, degraded reason,
/// versions, and the loaded policy. Not served over XPC; the daemon builds it
/// for diagnostics and tests (``DaemonController`` `healthReport()`).
public struct HealthReport: Codable, Sendable, Equatable {
    public let state: DaemonState
    public let degradedReason: DegradedReason?
    public let daemonVersion: String
    public let policyVersion: String?
    public let enforcementMode: EnforcementMode
    public let loadedProfileKeys: [String]
    public let activeGrantCount: Int
    public let generatedAt: Date

    public init(
        state: DaemonState,
        degradedReason: DegradedReason?,
        daemonVersion: String,
        policyVersion: String?,
        enforcementMode: EnforcementMode,
        loadedProfileKeys: [String],
        activeGrantCount: Int,
        generatedAt: Date
    ) {
        self.state = state
        self.degradedReason = degradedReason
        self.daemonVersion = daemonVersion
        self.policyVersion = policyVersion
        self.enforcementMode = enforcementMode
        self.loadedProfileKeys = loadedProfileKeys
        self.activeGrantCount = activeGrantCount
        self.generatedAt = generatedAt
    }
}

// MARK: - Low-level XPC message contract

/// Every caller — including the C PAM module — talks to the single daemon
/// Mach service over **low-level XPC dictionaries**. NSXPC cannot be used
/// here: PAM is C and sends raw `xpc_dictionary_*` messages, and the spec
/// mandates one Mach service shared by all callers, so the daemon runs a
/// low-level `xpc_connection` listener and validates every peer by audit
/// token before dispatching.
///
/// PAM messages are flat dictionaries keyed by ``PAMXPCKey``. Sentinel and Intel
/// messages carry an ``XPCInterface`` discriminator, a method name, and a
/// Codable-encoded ``Data`` payload (see ``SerberusXPCCoding``). The daemon
/// confirms the validated code identity matches the claimed interface — an
/// Intel-signed peer can never invoke a Sentinel method.

/// Which caller interface a message targets.
public enum XPCInterface: String, Sendable, CaseIterable {
    case pam
    case sentinel
    /// Serberus Intel — the standard-user diagnostics app. Read-only: its
    /// methods collect diagnostics and mutate no policy or grant state.
    case intel
}

/// Dictionary keys for Sentinel/Intel messages (PAM uses ``PAMXPCKey``).
public enum XPCMessageKey {
    /// ``XPCInterface`` raw value.
    public static let interface = "interface"
    /// Method name — ``SentinelXPCMethod`` / ``IntelXPCMethod`` raw value.
    public static let method = "method"
    /// Codable-encoded request payload (xpc_data), when the method takes one.
    public static let payload = "payload"
    /// Codable-encoded reply payload (xpc_data).
    public static let reply = "reply"
    /// Boolean reply for methods that only report success.
    public static let success = "success"
    /// Error string set when the daemon rejects or fails a request.
    public static let error = "error"
}

/// Agent ↔ daemon methods (mirrors `SerberusSentinelProtocol`).
public enum SentinelXPCMethod: String, Sendable, CaseIterable {
    /// Sentinel → daemon: announce the Sentinel so the daemon retains its peer
    /// connection for daemon-initiated `presentPrompt` pushes (reply `success`).
    case registerSentinel
    /// Daemon → Sentinel: deliver a ``PromptContext``; reply is a ``PromptResponse``.
    case presentPrompt
    /// Sentinel → daemon: list active grants for the logged-in user (reply `[Grant]`).
    case activeGrants
    /// Sentinel → daemon: current ``DaemonState`` for the menubar icon.
    case daemonState
    /// Sentinel → daemon: the loaded rules as display summaries for the
    /// popover's "Rules assigned to you" list (reply ``SentinelRulesSnapshot``).
    case userRules
    /// Sentinel → daemon: effective JIT-admin availability (reply ``JITAdminInfo``).
    case jitAdminInfo
    /// Sentinel → daemon: request JIT local-admin elevation. Payload: justification
    /// string. Reply: ``JITAdminResult``.
    case requestAdminElevation
    /// Sentinel → daemon: end the caller's active JIT-admin window early
    /// (reply `success`).
    case endAdminElevation
    /// Sentinel → daemon: install a user-chosen notarized Developer-ID `.pkg`/`.app`
    /// (the Finder "Install with Serberus" action). Payload: ``InstallRequest``.
    /// Reply: ``InstallResult``. Gated by the app-management rule; the daemon
    /// stages + verifies + (optionally) prompts before installing as root.
    case installSoftware
    /// Sentinel → daemon: uninstall (move to Trash) a `/Applications` app (the
    /// Finder "Uninstall with Serberus" action). Payload: ``UninstallRequest``.
    /// Reply: ``InstallResult``. Gated by the app-management rule + `allowUninstall`.
    case uninstallSoftware
}

/// Intel ↔ daemon methods.
public enum IntelXPCMethod: String, Sendable, CaseIterable {
    /// Intel → daemon: collect the diagnostics the console user cannot read
    /// for themselves. Payload: ``IntelRequest``. Reply: ``IntelHandoff``.
    case collectPrivilegedDiagnostics
    /// Intel → daemon: return recent macOS authorization-right attempts
    /// (authURI events) as NDJSON, for the live Authorizations view. Payload:
    /// ``AuthorizationPollRequest``. Reply: ``AuthorizationPollResult``.
    ///
    /// Polled on an interval rather than streamed: a standard user cannot run
    /// `log stream` ("Must be admin to run 'stream' command"), and a long-lived
    /// root `log stream` child tied to the app session would add orphan-process
    /// and lifecycle risk to a security daemon for latency no human watching
    /// authorizations needs. Each poll is a bounded, stateless `log show`.
    case pollAuthorizations
    /// Intel → daemon: return recent **sudo attempts** as NDJSON — the lines
    /// `sudo(8)` itself writes to the unified log (`<user> : … ; USER=root ;
    /// COMMAND=<path> <args>`), which exist for EVERY attempt regardless of
    /// whether Serberus was consulted (awaiting-config / monitor return
    /// `PAM_IGNORE` and write no `DecisionEvent`). Payload: ``SudoPollRequest``.
    /// Reply: ``SudoPollResult``. Same poll-not-stream, bounded, stateless
    /// contract as ``pollAuthorizations``; the predicate is a daemon-side
    /// constant. Feeds the Sentinel's **Capture** (Rule Recorder) session.
    case pollSudoAttempts
}

/// What Intel may ask the daemon to collect.
///
/// ## The predicate is NOT in here — deliberately
///
/// The daemon runs `log(1)` as root. If a caller could supply the predicate,
/// any local user could read the **entire system unified log** — every other
/// user's activity — through serberusd. That would make a security daemon an
/// arbitrary log-exfiltration oracle and would be a straight privilege
/// escalation. The predicate is hard-coded daemon-side to the Serberus
/// subsystems; the caller chooses only *how far back* and *how verbose*.
public struct IntelRequest: Codable, Sendable, Equatable {
    /// `log`'s `--last` argument. Validated daemon-side against an allowlist —
    /// it becomes an argv element, so it is never taken on trust.
    public let window: String
    /// Include `--info --debug`.
    public let includeInfoAndDebug: Bool

    public init(window: String, includeInfoAndDebug: Bool) {
        self.window = window
        self.includeInfoAndDebug = includeInfoAndDebug
    }

    /// Windows the daemon will accept. Mirrors Intel's `LogWindow`.
    public static let allowedWindows: Set<String> = ["5m", "15m", "1h", "6h", "1d", "7d"]
}

/// One live-Authorizations poll.
///
/// Like ``IntelRequest``, carries **no predicate** — the daemon pins it to
/// `com.apple.Authorization`. The window is a short, allowlisted lookback, not
/// a caller-chosen duration, so it can be dropped into argv safely.
public struct AuthorizationPollRequest: Codable, Sendable, Equatable {
    /// Short lookback for this poll (`log show --last`). Overlaps the poll
    /// interval so no event slips through the gap between polls; Intel
    /// de-duplicates on its side.
    public let window: String

    public init(window: String) {
        self.window = window
    }

    /// Windows the daemon accepts for a live poll — deliberately short. A live
    /// view has no business pulling a 7-day window every couple of seconds.
    public static let allowedWindows: Set<String> = ["5s", "10s", "30s", "1m"]
}

/// NDJSON from one authorization poll.
public struct AuthorizationPollResult: Codable, Sendable, Equatable {
    /// Raw `log show --style ndjson` output for the authorization subsystem.
    /// Small by construction (authd emits a handful of lines an hour), so it
    /// rides inline in the XPC reply rather than through a file hand-off.
    public let ndjson: String

    public init(ndjson: String) {
        self.ndjson = ndjson
    }
}

/// One sudo-attempts poll (the Capture / Rule Recorder source for sudo).
///
/// Carries **no predicate** — the daemon pins it to `process == "sudo"`. The
/// window is the same short, allowlisted lookback as an authorization poll.
public struct SudoPollRequest: Codable, Sendable, Equatable {
    /// Short lookback for this poll (`log show --last`); overlaps the poll
    /// interval, the client de-duplicates.
    public let window: String

    public init(window: String) {
        self.window = window
    }

    /// Same short-only allowlist as ``AuthorizationPollRequest`` — a capture
    /// session polls every couple of seconds and must never pull days.
    public static let allowedWindows: Set<String> = AuthorizationPollRequest.allowedWindows
}

/// NDJSON from one sudo poll.
public struct SudoPollResult: Codable, Sendable, Equatable {
    /// Raw `log show --style ndjson` output for `process == "sudo"`. sudo emits
    /// a few lines per invocation (plus `libsystem_info` activity noise the
    /// client drops), so it rides inline like the authorization poll.
    public let ndjson: String

    public init(ndjson: String) {
        self.ndjson = ndjson
    }
}

/// Where the daemon left the privileged artifacts.
public struct IntelHandoff: Codable, Sendable, Equatable {
    /// Directory containing the collected files, chowned to the calling user
    /// (mode 0700) so only they can read it.
    public let directory: String
    /// Files written, relative to `directory`.
    public let files: [String]
    /// Artifacts that could not be collected, and why — the daemon never fails
    /// the whole capture for one missing piece.
    public let unavailable: [String: String]

    public init(directory: String, files: [String], unavailable: [String: String]) {
        self.directory = directory
        self.files = files
        self.unavailable = unavailable
    }
}

/// Codable ↔ Data bridging for low-level XPC payloads.
public enum SerberusXPCCoding {
    public static func encode(_ value: some Encodable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value)
    }

    public static func decode<Value: Decodable>(_ type: Value.Type, from data: Data) throws -> Value {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: data)
    }
}
