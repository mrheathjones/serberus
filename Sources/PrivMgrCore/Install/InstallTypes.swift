import Foundation

/// App-management policy: whether self-service **install** of notarized
/// Developer-ID software ("Install with Serberus") and **uninstall** of a
/// `/Applications` app to the Trash ("Uninstall with Serberus") are permitted on
/// this Mac. Delivered by the single `com.herojoneslabs.serberus.appmanagement`
/// managed profile (one domain for the whole app-management surface, so features
/// can be added without a new domain each time). Absent / disabled ⇒ every
/// request is refused.
///
/// Install trust has two layers. Gatekeeper must accept the staged copy as
/// notarized Developer-ID software, and its publisher (the signing Team ID) must
/// be allowed: by default only Team IDs the admin lists, or any publisher when
/// the admin explicitly sets ``InstallPublisherScope/any``. A package's install
/// scripts run as root, so the publisher list is the real control.
public struct InstallPolicy: Sendable, Equatable {
    /// Master gate. `false` (the default, and when the profile is absent) refuses
    /// every install and uninstall.
    public var enabled: Bool
    /// Require notarization (Gatekeeper "Notarized Developer ID"), not merely a
    /// Developer-ID signature. Default `true`; there is no path that installs
    /// un-notarized software when this is on. (Install only.)
    public var requireNotarization: Bool
    /// Show a confirmation prompt before installing. Default `true`. (Install
    /// only: "Uninstall with Serberus" ALWAYS confirms, whatever this says.)
    public var promptBeforeAction: Bool
    /// Permit "Uninstall with Serberus" — moving a `/Applications` app to the
    /// user's Trash (recoverable) as root. Default `true` (so enabling the
    /// feature enables uninstall too); set `false` for install-only. Uninstall
    /// needs BOTH `enabled` and this.
    public var allowUninstall: Bool
    /// Bundle identifiers that are **hard-denied** from "Uninstall with Serberus"
    /// — evaluated BEFORE the confirmation prompt, with no prompt and no override.
    /// The admin defines this list; there is **no built-in default**. When it is
    /// missing or empty, the confirmation prompt is the sole gate (any app can be
    /// trashed with user confirmation). Case-insensitive, exact bundle-ID match.
    ///
    /// The same list also stops "Install with Serberus" from installing or
    /// replacing an app with one of these bundle identifiers.
    public var protectedBundleIdentifiers: [String]
    /// Which publishers may be installed. Default ``InstallPublisherScope/allowlist``.
    public var publisherScope: InstallPublisherScope
    /// Team IDs allowed under ``InstallPublisherScope/allowlist``. Empty (the
    /// default) allows no one, so enabling the feature installs nothing until
    /// the admin names publishers.
    public var allowedPublisherTeamIDs: [String]

    public init(enabled: Bool = false, requireNotarization: Bool = true,
                promptBeforeAction: Bool = true, allowUninstall: Bool = true,
                protectedBundleIdentifiers: [String] = [],
                publisherScope: InstallPublisherScope = .allowlist,
                allowedPublisherTeamIDs: [String] = []) {
        self.enabled = enabled
        self.requireNotarization = requireNotarization
        self.promptBeforeAction = promptBeforeAction
        self.allowUninstall = allowUninstall
        self.protectedBundleIdentifiers = protectedBundleIdentifiers
        self.publisherScope = publisherScope
        self.allowedPublisherTeamIDs = allowedPublisherTeamIDs
    }

    /// Install is permitted iff the feature is enabled.
    public var installAllowed: Bool { enabled }
    /// Uninstall is permitted iff enabled AND uninstall is allowed.
    public var uninstallAllowed: Bool { enabled && allowUninstall }

    /// Whether software signed by `teamID` may be installed. An unknown
    /// publisher (no Team ID) never passes the allowlist.
    public func publisherAllowed(teamID: String?) -> Bool {
        switch publisherScope {
        case .any:
            return true
        case .allowlist:
            guard let teamID, !teamID.isEmpty else { return false }
            return allowedPublisherTeamIDs.contains { $0.caseInsensitiveCompare(teamID) == .orderedSame }
        }
    }

    /// Whether `bundleID` is on the admin's hard-deny list (case-insensitive).
    /// A `nil` bundle ID (unreadable Info.plist) is never protected by this list —
    /// the other eligibility gates still apply. Empty list ⇒ nothing is protected.
    public func isProtected(bundleID: String?) -> Bool {
        guard let bundleID, !protectedBundleIdentifiers.isEmpty else { return false }
        return protectedBundleIdentifiers.contains { $0.caseInsensitiveCompare(bundleID) == .orderedSame }
    }

    /// The refuse-everything default (no profile / disabled).
    public static let disabled = InstallPolicy(enabled: false)
}

/// Which publishers "Install with Serberus" accepts, once Gatekeeper has.
public enum InstallPublisherScope: String, Sendable, Equatable, CaseIterable {
    /// Only Team IDs in ``InstallPolicy/allowedPublisherTeamIDs``. The default.
    case allowlist
    /// Any notarized Developer-ID publisher. The admin must choose this
    /// explicitly; it lets any user install software whose scripts run as root.
    case any
}

/// A request to install one user-chosen item, brokered to the daemon by the
/// Sentinel on behalf of the Finder action.
public struct InstallRequest: Codable, Sendable, Equatable {
    /// The absolute path the user selected — a flat `.pkg` or an `.app` (for
    /// example one inside a mounted disk image). A `.dmg` or a bundle-style
    /// `.mpkg` is NOT accepted. Validated + canonicalized daemon-side; never
    /// trusted.
    public var sourcePath: String
    /// A short human label (the file name), supplied by the caller. Not used by
    /// the daemon for any decision, prompt text or log: the prompt headline
    /// comes from the verified, staged item.
    public var displayName: String

    public init(sourcePath: String, displayName: String) {
        self.sourcePath = sourcePath
        self.displayName = displayName
    }
}

/// A request to uninstall (move to Trash) one `/Applications` app.
public struct UninstallRequest: Codable, Sendable, Equatable {
    /// The absolute path of the `.app` to remove. Validated daemon-side (must be
    /// a `.app` directly in `/Applications` or `/Applications/Utilities`, reached
    /// without any symlink); never trusted.
    public var appPath: String
    /// The app's name for the confirmation prompt (display only).
    public var displayName: String

    public init(appPath: String, displayName: String) {
        self.appPath = appPath
        self.displayName = displayName
    }
}

/// The outcome of an install/uninstall, returned to the Sentinel for display.
public struct InstallResult: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case installed          // pkg installed / app copied
        case removed            // app moved to the user's Trash (uninstall)
        case refusedByPolicy    // no app-management rule / disabled / uninstall not allowed
        case refusedNotTrusted  // failed the notarized-Developer-ID gate
        case refusedNotEligible // not a valid /Applications app to uninstall
        case cancelled          // user declined the confirmation prompt
        case failed             // staging / installer / copy / move error
    }
    /// Why a request was refused, when the reason is one the UI can safely
    /// name. Never carries paths, tool output or other internal detail.
    public enum Reason: String, Codable, Sendable {
        /// The item is legitimate software, but installing or removing it is
        /// outside what self-service allows (for example a relocatable
        /// package, a package that installs outside a root-only location, a
        /// version that can't be compared, or an app with system-level
        /// components). IT must deploy or remove it.
        case requiresIT
    }

    public var status: Status
    /// Human-readable detail for the UI (the verified authority, or the failure).
    public var message: String
    /// What was installed (name), on success.
    public var installedName: String?
    /// A non-sensitive refusal category, when one applies. Optional on the
    /// wire: an older peer omits it, and an unknown value decodes as nil.
    public var reason: Reason?

    public init(status: Status, message: String, installedName: String? = nil, reason: Reason? = nil) {
        self.status = status
        self.message = message
        self.installedName = installedName
        self.reason = reason
    }

    private enum CodingKeys: String, CodingKey { case status, message, installedName, reason }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(Status.self, forKey: .status)
        message = try container.decode(String.self, forKey: .message)
        installedName = try container.decodeIfPresent(String.self, forKey: .installedName)
        reason = (try? container.decodeIfPresent(String.self, forKey: .reason)).flatMap { $0.flatMap(Reason.init(rawValue:)) }
    }
}
