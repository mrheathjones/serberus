import Foundation
import Observation
import PrivMgrCore

/// Authoring model for the just-in-time local-admin policy (Settings pane).
///
/// Holds an editable ``JITAdminPolicy``, persists the draft to UserDefaults so
/// the admin's work survives relaunch, and generates the `.mobileconfig` that
/// delivers it into the `com.herojoneslabs.serberus.jit` managed domain — the same
/// author-then-deliver flow as sudo/authURI rules.
@MainActor
@Observable
public final class JITAdminSettingsModel {
    public var provider: JITAdminProvider
    /// Comma/newline-separated group names, edited as free text in the UI.
    public var eligibleGroupsText: String
    public var durationMinutes: Int
    public var requireJustification: Bool
    public var justificationMinLength: Int
    public var jamfConnectPath: String
    /// Space-separated argument template, edited as free text.
    public var jamfConnectArgsText: String

    public private(set) var lastExportError: String?

    private let defaults: UserDefaults
    private enum Key {
        static let provider = "serberus.jit.provider"
        static let groups = "serberus.jit.groups"
        static let duration = "serberus.jit.durationMinutes"
        static let requireJustification = "serberus.jit.requireJustification"
        static let minLength = "serberus.jit.justificationMinLength"
        static let jcPath = "serberus.jit.jamfConnectPath"
        static let jcArgs = "serberus.jit.jamfConnectArgs"
    }

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        self.provider = JITAdminProvider(rawValue: defaults.string(forKey: Key.provider) ?? "") ?? .disabled
        self.eligibleGroupsText = defaults.string(forKey: Key.groups) ?? "admin"
        let storedDuration = defaults.integer(forKey: Key.duration)
        self.durationMinutes = storedDuration > 0 ? storedDuration : 15
        self.requireJustification = defaults.object(forKey: Key.requireJustification) as? Bool ?? true
        let storedMin = defaults.object(forKey: Key.minLength) as? Int
        self.justificationMinLength = storedMin ?? 10
        self.jamfConnectPath = defaults.string(forKey: Key.jcPath) ?? ""
        self.jamfConnectArgsText = defaults.string(forKey: Key.jcArgs) ?? ""
    }

    /// Parsed group list from the free-text field.
    public var eligibleGroups: [String] {
        eligibleGroupsText
            .split(whereSeparator: { $0 == "," || $0 == "\n" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// The policy assembled from the current editor state.
    public var policy: JITAdminPolicy {
        JITAdminPolicy(
            provider: provider,
            eligibleGroups: eligibleGroups,
            maxDurationSeconds: max(1, durationMinutes) * 60,
            requireJustification: requireJustification,
            justificationMinLength: justificationMinLength,
            jamfConnectCommand: JamfConnectCommand(
                path: jamfConnectPath.trimmingCharacters(in: .whitespaces),
                arguments: jamfConnectArgsText
                    .split(separator: " ").map(String.init)
            )
        )
    }

    /// Whether the current draft can be exported.
    public var canExport: Bool {
        switch provider {
        case .disabled: return true
        case .serberus: return !eligibleGroups.isEmpty
        case .jamfConnect: return jamfConnectPathError == nil
        }
    }

    /// Why the Jamf Connect command path can't be exported, or nil. A blank
    /// path is fine: the daemon and the Sentinel then use the default
    /// (`/usr/local/bin/jamfconnect acc-promo --elevate`). A path that is set
    /// must be absolute, because the reader refuses anything else.
    public var jamfConnectPathError: String? {
        let path = jamfConnectPath.trimmingCharacters(in: .whitespaces)
        guard !path.isEmpty, !JamfConnectCommand.isAbsolutePath(path) else { return nil }
        return "The Jamf Connect command path must be a full path starting with / (for example "
            + "\(JamfConnectCommand.jamfConnectDefault.path)), or blank for the default."
    }

    /// Human-readable blocker, for the UI.
    public var exportBlocker: String? {
        switch provider {
        case .disabled, .serberus:
            if provider == .serberus && eligibleGroups.isEmpty {
                return "Add at least one eligible group."
            }
            return nil
        case .jamfConnect:
            return jamfConnectPathError
        }
    }

    public func save() {
        defaults.set(provider.rawValue, forKey: Key.provider)
        defaults.set(eligibleGroupsText, forKey: Key.groups)
        defaults.set(durationMinutes, forKey: Key.duration)
        defaults.set(requireJustification, forKey: Key.requireJustification)
        defaults.set(justificationMinLength, forKey: Key.minLength)
        defaults.set(jamfConnectPath, forKey: Key.jcPath)
        defaults.set(jamfConnectArgsText, forKey: Key.jcArgs)
    }

    /// Generates the `.mobileconfig`, or captures why it could not.
    public func export(organization: String = "Serberus") -> MobileConfigGenerator.Export? {
        save()
        do {
            let export = try MobileConfigGenerator().exportJITAdmin(policy, organization: organization)
            lastExportError = nil
            return export
        } catch {
            lastExportError = error.localizedDescription
            return nil
        }
    }
}
