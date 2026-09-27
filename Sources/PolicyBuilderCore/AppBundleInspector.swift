import Foundation
import PrivMgrCore
import Security

/// What the Security framework says about an app bundle on disk — the same
/// facts PPPC Utility reads when an app is dropped on it: the code-signing
/// identifier, the Team ID, the designated requirement, and whether the
/// signature is valid. Feeds the Definition composer's App Identity form.
public struct AppSignatureInfo: Sendable, Equatable {
    /// The bundle path as given.
    public let path: String
    /// Display name (`CFBundleName` / `CFBundleDisplayName`, else the file name).
    public let name: String
    /// `CFBundleIdentifier` from Info.plist, when readable.
    public let infoBundleID: String?
    /// The code-signing identifier (`kSecCodeInfoIdentifier`) — what a
    /// requirement's `identifier "…"` clause matches. Usually the bundle ID.
    public let signingIdentifier: String?
    /// `kSecCodeInfoTeamIdentifier` — the leaf certificate's OU. Nil for
    /// Apple platform apps and unsigned/ad-hoc code.
    public let teamID: String?
    /// The signature's designated requirement, as text.
    public let designatedRequirement: String?
    /// `CFBundleShortVersionString`, when readable.
    public let version: String?
    public let signingStatus: SigningStatus

    public init(path: String, name: String, infoBundleID: String?, signingIdentifier: String?, teamID: String?,
                designatedRequirement: String?, version: String?, signingStatus: SigningStatus) {
        self.path = path
        self.name = name
        self.infoBundleID = infoBundleID
        self.signingIdentifier = signingIdentifier
        self.teamID = teamID
        self.designatedRequirement = designatedRequirement
        self.version = version
        self.signingStatus = signingStatus
    }

    /// The identifier an App Identity definition should pin: the signing
    /// identifier (authoritative), else the Info.plist bundle ID.
    public var pinIdentifier: String? { signingIdentifier ?? infoBundleID }

    /// True when the app can be pinned by Team ID + identifier at all.
    public var isPinnable: Bool { teamID != nil && pinIdentifier != nil }
}

/// Reads ``AppSignatureInfo`` for a bundle. Never throws: an unreadable or
/// unsigned bundle yields nil identifiers and `.unsigned`.
public enum AppBundleInspector {
    public static func inspect(url: URL) -> AppSignatureInfo {
        let bundle = Bundle(url: url)
        let info = bundle?.infoDictionary ?? [:]
        let fileName = url.deletingPathExtension().lastPathComponent
        let name = (info["CFBundleDisplayName"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            ?? (info["CFBundleName"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            ?? fileName
        let infoBundleID = info["CFBundleIdentifier"] as? String
        let version = info["CFBundleShortVersionString"] as? String

        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess, let staticCode else {
            return AppSignatureInfo(path: url.path, name: name, infoBundleID: infoBundleID, signingIdentifier: nil,
                                    teamID: nil, designatedRequirement: nil, version: version, signingStatus: .unsigned)
        }

        let validity = SecStaticCodeCheckValidity(staticCode, [], nil)
        var signing: CFDictionary?
        SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation), &signing)
        let dict = signing as? [String: Any] ?? [:]

        let identifier = dict[kSecCodeInfoIdentifier as String] as? String
        let teamID = (dict[kSecCodeInfoTeamIdentifier as String] as? String).flatMap { $0.isEmpty ? nil : $0 }
        let flags = (dict[kSecCodeInfoFlags as String] as? UInt32) ?? 0
        let adHoc = (flags & SecCodeSignatureFlags.adhoc.rawValue) != 0

        var requirementText: String?
        if let raw = dict[kSecCodeInfoDesignatedRequirement as String] {
            let requirement = raw as! SecRequirement
            var text: CFString?
            if SecRequirementCopyString(requirement, [], &text) == errSecSuccess, let text {
                requirementText = text as String
            }
        }

        let status: SigningStatus
        if identifier == nil {
            status = .unsigned
        } else if adHoc {
            status = .adhoc
        } else if validity == errSecSuccess {
            status = .valid
        } else {
            status = .invalid
        }

        return AppSignatureInfo(path: url.path, name: name, infoBundleID: infoBundleID, signingIdentifier: identifier,
                                teamID: teamID, designatedRequirement: requirementText, version: version, signingStatus: status)
    }
}
