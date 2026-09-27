import Foundation

/// Where just-in-time local-admin elevation is handled.
public enum JITAdminProvider: String, Codable, Sendable, CaseIterable {
    /// JIT admin disabled — the default. No self-elevation path exists.
    case disabled
    /// Serberus manages it natively: the daemon adds the user to the local
    /// `admin` group for a bounded window and auto-demotes.
    case serberus
    /// Serberus hands off to the privilege elevation of Jamf Connect / Self
    /// Service+; eligibility, duration, and audit are owned by the Jamf Connect
    /// config. The daemon only observes the elevations it logs
    /// (``JamfConnectElevationObserver``).
    case jamfConnect = "jamf_connect"
}

/// The command Serberus runs to trigger Jamf Connect privilege elevation.
///
/// In Jamf Connect mode Serberus is only a launcher: it runs this exact command
/// and does nothing else. Jamf Connect owns the reason prompt, eligibility, and
/// expiration, so no user/duration/reason is passed in — the command and its
/// (static) arguments are run verbatim. Kept MDM-configurable rather than
/// hard-coded because the invocation varies by Jamf Connect version. An empty
/// `path` means "not configured" (the default is used). The path must be
/// absolute: a relative one is refused when the policy is read, so the command
/// is never resolved through the user's `PATH`.
public struct JamfConnectCommand: Codable, Sendable, Equatable {
    public var path: String
    public var arguments: [String]

    public init(path: String = "", arguments: [String] = []) {
        self.path = path
        self.arguments = arguments
    }

    public var isConfigured: Bool { !path.trimmingCharacters(in: .whitespaces).isEmpty }

    /// Whether ``path`` is an absolute path with no `.` or `..` component and no
    /// control characters — the only form the Sentinel will run.
    public var hasAbsolutePath: Bool { Self.isAbsolutePath(path) }

    /// See ``hasAbsolutePath``.
    public static func isAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), path.count > 1 else { return false }
        guard !path.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else { return false }
        return !path.split(separator: "/").contains { $0 == "." || $0 == ".." }
    }

    /// The standard Jamf Connect / Self Service+ privilege-elevation trigger,
    /// as Jamf documents it (run as the logged-in user). Used when a
    /// jamf_connect policy names no command, so "mark JC for JIT" works with no
    /// further setup; overridable via MDM, with an absolute path only.
    public static let jamfConnectDefault = JamfConnectCommand(
        path: "/usr/local/bin/jamfconnect", arguments: ["acc-promo", "--elevate"])

    /// Jamf's Apple Developer Team ID. The Sentinel runs the command only when
    /// the binary is signed by this team (anchor apple generic + leaf OU).
    /// Fixed on purpose: no MDM key can point the check at another team.
    public static let expectedTeamID = "483DWKW443"
}

/// Parsed `com.herojoneslabs.serberus.jit` domain — the just-in-time local-admin policy.
///
/// Delivered by MDM like every other Serberus policy. Fail-safe defaults are
/// fully locked down: `disabled` provider, no eligible groups, justification
/// required — so an absent or malformed profile can never grant admin.
public struct JITAdminPolicy: Codable, Sendable, Equatable {
    /// Hard ceiling on any configured window, regardless of MDM value.
    public static let maxAllowedDurationSeconds = 8 * 3600
    public static let defaultDurationSeconds = 15 * 60

    public var provider: JITAdminProvider
    /// Local/directory group names whose members may self-elevate (serberus
    /// provider). Empty = nobody may elevate (fail-closed).
    public var eligibleGroups: [String]
    /// Admin window length in seconds (serberus provider), clamped to
    /// `1...maxAllowedDurationSeconds`.
    public var maxDurationSeconds: Int
    /// Whether the user must supply a justification before elevating.
    public var requireJustification: Bool
    /// Minimum justification length when required.
    public var justificationMinLength: Int
    /// Jamf Connect handoff command (jamfConnect provider).
    public var jamfConnectCommand: JamfConnectCommand

    public init(
        provider: JITAdminProvider = .disabled,
        eligibleGroups: [String] = [],
        maxDurationSeconds: Int = JITAdminPolicy.defaultDurationSeconds,
        requireJustification: Bool = true,
        justificationMinLength: Int = 10,
        jamfConnectCommand: JamfConnectCommand = JamfConnectCommand()
    ) {
        self.provider = provider
        self.eligibleGroups = eligibleGroups
        self.maxDurationSeconds = maxDurationSeconds
        self.requireJustification = requireJustification
        self.justificationMinLength = justificationMinLength
        self.jamfConnectCommand = jamfConnectCommand
    }

    /// The fully locked-down default used when no profile is present.
    public static let disabledDefault = JITAdminPolicy()

    /// The effective window, clamped to the allowed range.
    public var effectiveDurationSeconds: Int {
        min(max(1, maxDurationSeconds), Self.maxAllowedDurationSeconds)
    }

    /// The Jamf Connect command to run, falling back to the standard trigger
    /// when the policy names none — so a jamf_connect provider always resolves
    /// to a runnable command.
    public var effectiveJamfConnectCommand: JamfConnectCommand {
        jamfConnectCommand.isConfigured && jamfConnectCommand.hasAbsolutePath
            ? jamfConnectCommand : .jamfConnectDefault
    }

    /// Whether `user`, given its `groups`, may self-elevate under this policy.
    /// Jamf Connect eligibility is owned by Jamf Connect, so this returns
    /// `true` for that provider (there is always a runnable command).
    public func isEligible(user: String, groups: Set<String>) -> Bool {
        switch provider {
        case .disabled: return false
        case .jamfConnect: return true
        case .serberus: return !eligibleGroups.isEmpty && !groups.isDisjoint(with: eligibleGroups)
        }
    }

    /// Whether a justification string satisfies the policy.
    public func justificationSatisfied(_ text: String) -> Bool {
        guard requireJustification else { return true }
        return text.trimmingCharacters(in: .whitespacesAndNewlines).count >= justificationMinLength
    }
}

// MARK: - Grant sentinels (shared by daemon + agent)

/// Identifies a ``Grant`` as a JIT local-admin grant rather than a binary
/// grant. A JIT grant carries admin *group* membership, not a command, so it
/// uses sentinel path/profile values both sides recognize.
public enum JITAdminGrant {
    /// Sentinel `canonicalPath` for a JIT admin grant.
    public static let canonicalPath = "group:admin"
    /// Sentinel `profileKey` for a JIT admin grant.
    public static let profileKey = "jit_admin"

    public static func isJITGrant(_ grant: Grant) -> Bool {
        grant.canonicalPath == canonicalPath && grant.profileKey == profileKey
    }
}

// MARK: - Cross-boundary DTOs (shared by daemon + agent over XPC)

/// Outcome of a JIT-admin request.
public enum JITAdminOutcome: String, Codable, Sendable {
    /// Serberus added the user to admin for a bounded window.
    case granted
    /// The user already holds an active JIT grant; the existing window stands.
    case alreadyActive = "already_active"
    /// The user is already a permanent admin; nothing changed (and nothing
    /// will be demoted).
    case alreadyAdmin = "already_admin"
    /// Handed off to Jamf Connect.
    case delegated
    /// Refused (disabled, ineligible, missing justification, or an error).
    case denied
}

/// Result of a JIT-admin request, returned to the Agent.
public struct JITAdminResult: Codable, Sendable, Equatable {
    public let outcome: JITAdminOutcome
    public let message: String
    public let grantID: UUID?
    public let expiresAt: Date?

    public init(outcome: JITAdminOutcome, message: String, grantID: UUID? = nil, expiresAt: Date? = nil) {
        self.outcome = outcome
        self.message = message
        self.grantID = grantID
        self.expiresAt = expiresAt
    }
}

/// What the Agent needs to render the JIT-admin affordance without exposing the
/// full policy: whether it's available, whether a justification is required,
/// and the window length.
public struct JITAdminInfo: Codable, Sendable, Equatable {
    public let available: Bool
    public let provider: JITAdminProvider
    public let requireJustification: Bool
    public let justificationMinLength: Int
    public let maxDurationSeconds: Int
    /// Present only for the jamf_connect provider: the command the Agent runs in
    /// the user's session to trigger Jamf Connect elevation.
    public let jamfConnectCommand: JamfConnectCommand?

    public init(available: Bool, provider: JITAdminProvider, requireJustification: Bool,
                justificationMinLength: Int, maxDurationSeconds: Int,
                jamfConnectCommand: JamfConnectCommand? = nil) {
        self.available = available
        self.provider = provider
        self.requireJustification = requireJustification
        self.justificationMinLength = justificationMinLength
        self.maxDurationSeconds = maxDurationSeconds
        self.jamfConnectCommand = jamfConnectCommand
    }

    /// Built from the effective policy. In Jamf Connect mode Serberus is a pure
    /// launcher — JC owns the reason prompt — so justification is never required
    /// of the Serberus UI, and the command is carried down so the *Agent* (user
    /// session) runs it; the root daemon never does.
    public init(policy: JITAdminPolicy) {
        self.available = policy.provider != .disabled
        self.provider = policy.provider
        self.requireJustification = policy.provider == .jamfConnect ? false : policy.requireJustification
        self.justificationMinLength = policy.justificationMinLength
        self.maxDurationSeconds = policy.effectiveDurationSeconds
        self.jamfConnectCommand = policy.provider == .jamfConnect ? policy.effectiveJamfConnectCommand : nil
    }

    /// The affordance the Agent shows when JIT admin is not configured.
    public static let unavailable = JITAdminInfo(
        available: false, provider: .disabled, requireJustification: true,
        justificationMinLength: 10, maxDurationSeconds: JITAdminPolicy.defaultDurationSeconds)
}
