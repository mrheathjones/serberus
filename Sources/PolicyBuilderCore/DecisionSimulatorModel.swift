import Foundation
import Observation
import PrivMgrCore

/// Drives the Decision Simulator pane.
///
/// Holds editable synthetic input, runs the **same** ``DecisionSimulator`` the
/// daemon and CLI use, and exposes the result + reasoning trace. No daemon
/// required — grant state is mocked via ``SimulatedGrant``.
///
/// The input is a **builder**: the request target (the sudo command or the
/// authorization right) is always present; every other facet of the request
/// is a ``Component`` the operator adds or removes. A removed component
/// contributes its *neutral* value (``Component/neutralDescription``) so the
/// request stays evaluable, and keeps its last typed value so re-adding it
/// restores what was there. Setting a component's value to something other
/// than neutral (Load example, tests) activates it implicitly — a value the
/// engine would see differently than "absent" means the component is there.
@MainActor
@Observable
public final class DecisionSimulatorModel {
    public enum RequestKind: String, CaseIterable, Sendable {
        case sudo
        case authURI
    }

    /// One removable facet of the simulated request, in display order.
    public enum Component: String, CaseIterable, Sendable, Identifiable, Codable {
        case user
        case uid
        case arguments
        case executablePath
        case teamID
        case binaryHash
        case signing
        case justification
        case globalCache

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .user: return "User"
            case .uid: return "UID"
            case .arguments: return "Arguments"
            case .executablePath: return "Executable path"
            case .teamID: return "Team ID"
            case .binaryHash: return "SHA-256"
            case .signing: return "Signing"
            case .justification: return "Justification"
            case .globalCache: return "Global cache"
            }
        }

        /// SF Symbol for menus and row labels.
        public var symbol: String {
            switch self {
            case .user: return "person"
            case .uid: return "number"
            case .arguments: return "text.word.spacing"
            case .executablePath: return "doc.text.magnifyingglass"
            case .teamID: return "person.2.badge.key"
            case .binaryHash: return "number.square"
            case .signing: return "checkmark.seal"
            case .justification: return "text.bubble"
            case .globalCache: return "clock.arrow.circlepath"
            }
        }

        /// What the engine sees when the component is absent — shown on the
        /// row's remove button so "remove" is never a mystery.
        public var neutralDescription: String {
            switch self {
            case .user: return "no user name"
            case .uid: return "uid 0"
            case .arguments: return "no arguments"
            case .executablePath: return "the sudo command itself (sudo) or /usr/bin/security (auth URI)"
            case .teamID: return "no Team ID"
            case .binaryHash: return "no hash"
            case .signing: return "unsigned"
            case .justification: return "no justification"
            case .globalCache: return "0 s"
            }
        }

        /// Arguments belong to sudo requests only; the component stays in the
        /// active set across a kind switch but is hidden for auth URIs.
        public var isSudoOnly: Bool { self == .arguments }
    }

    /// The starting set — what a bare simulation needs to be legible plus the
    /// two identity facets (user, uid) Commander always showed.
    public static let defaultComponents: Set<Component> = [.user, .uid, .arguments, .executablePath]

    private static let componentsKey = "DecisionSimulator.activeComponents"

    // Input
    public var requestKind: RequestKind = .sudo
    public var user: String = "alice" { didSet { activateIfPresent(.user, user != Self.neutralUser) } }
    public var uid: Int = 501 { didSet { activateIfPresent(.uid, uid != Self.neutralUID) } }
    public var authURI: String = "system.preferences.datetime"
    public var sudoCommand: String = "/opt/homebrew/bin/brew"
    public var argvText: String = "install wget" { didSet { activateIfPresent(.arguments, !argv.isEmpty) } }
    public var executablePath: String = "/opt/homebrew/bin/brew" { didSet { activateIfPresent(.executablePath, !executablePath.isEmpty) } }
    public var teamID: String = "" { didSet { activateIfPresent(.teamID, !teamID.isEmpty) } }
    public var binaryHash: String = "" { didSet { activateIfPresent(.binaryHash, !binaryHash.isEmpty) } }
    public var signingStatus: SigningStatus = .unsigned { didSet { activateIfPresent(.signing, signingStatus != .unsigned) } }
    public var justificationProvided: Bool = false { didSet { activateIfPresent(.justification, justificationProvided) } }
    public var justificationText: String = "" { didSet { activateIfPresent(.justification, !justificationText.isEmpty) } }
    public var globalCacheSeconds: Int = 0 { didSet { activateIfPresent(.globalCache, globalCacheSeconds != 0) } }

    /// The components currently part of the request. Persisted (when a
    /// `UserDefaults` was given) so the operator's builder layout survives a
    /// relaunch.
    public private(set) var activeComponents: Set<Component> {
        didSet { persistComponents() }
    }

    // Output
    public private(set) var result: SimulationResult?
    public private(set) var errorMessage: String?

    @ObservationIgnored private let defaults: UserDefaults?

    /// - Parameter defaults: where the active-component set is remembered;
    ///   `nil` keeps the builder layout in memory only (tests).
    public init(defaults: UserDefaults? = .standard) {
        self.defaults = defaults
        if let stored = defaults?.stringArray(forKey: Self.componentsKey) {
            activeComponents = Set(stored.compactMap(Component.init(rawValue:)))
        } else {
            activeComponents = Self.defaultComponents
        }
    }

    // MARK: Builder

    public func isActive(_ component: Component) -> Bool { activeComponents.contains(component) }

    public func add(_ component: Component) { activeComponents.insert(component) }

    /// Removes a component from the request. Its typed value is kept so
    /// re-adding restores it; the engine sees the neutral value meanwhile.
    public func remove(_ component: Component) { activeComponents.remove(component) }

    /// Back to ``defaultComponents`` (values are left alone).
    public func resetComponents() { activeComponents = Self.defaultComponents }

    /// Active components in display order, filtered for the current request
    /// kind (``Component/isSudoOnly`` ones hide for auth URIs).
    public var activeComponentsInOrder: [Component] {
        Component.allCases.filter { activeComponents.contains($0) && (requestKind == .sudo || !$0.isSudoOnly) }
    }

    /// Components that can still be added for the current request kind.
    public var availableComponents: [Component] {
        Component.allCases.filter { !activeComponents.contains($0) && (requestKind == .sudo || !$0.isSudoOnly) }
    }

    private func activateIfPresent(_ component: Component, _ present: Bool) {
        if present, !activeComponents.contains(component) { activeComponents.insert(component) }
    }

    private func persistComponents() {
        defaults?.set(activeComponents.map(\.rawValue).sorted(), forKey: Self.componentsKey)
    }

    // MARK: Effective values (what the engine is handed)

    static let neutralUser = ""
    static let neutralUID = 0
    /// A real, canonicalizable CLI that requests rights — the neutral
    /// requesting binary for an auth URI request with no executable path.
    static let neutralAuthURIExecutable = "/usr/bin/security"

    /// argv parsed from the whitespace-separated input field.
    public var argv: [String] {
        argvText.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" }).map(String.init)
    }

    public var effectiveUser: String { isActive(.user) ? user : Self.neutralUser }
    public var effectiveUID: Int { isActive(.uid) ? uid : Self.neutralUID }
    public var effectiveArgv: [String] { requestKind == .sudo && isActive(.arguments) ? argv : [] }
    /// Falls back to the sudo command itself (the binary sudo runs) or to
    /// `/usr/bin/security` for an auth URI — never an empty path, which the
    /// canonicalizer rejects.
    public var effectiveExecutablePath: String {
        if isActive(.executablePath), !executablePath.isEmpty { return executablePath }
        return requestKind == .sudo ? sudoCommand : Self.neutralAuthURIExecutable
    }
    public var effectiveTeamID: String { isActive(.teamID) ? teamID : "" }
    public var effectiveBinaryHash: String { isActive(.binaryHash) ? binaryHash : "" }
    public var effectiveSigningStatus: SigningStatus { isActive(.signing) ? signingStatus : .unsigned }
    public var effectiveJustificationProvided: Bool { isActive(.justification) && justificationProvided }
    public var effectiveJustificationText: String? {
        guard isActive(.justification), !justificationText.isEmpty else { return nil }
        return justificationText
    }
    public var effectiveGlobalCacheSeconds: Int { isActive(.globalCache) ? globalCacheSeconds : 0 }

    // MARK: Run

    /// Runs the simulation against `profiles`, capturing the result or a
    /// human-readable error (never throws to the UI). Only ACTIVE components
    /// reach the engine; the rest contribute their neutral values.
    public func run(profiles: [RuleProfile], currentTime: Date = Date()) {
        let context = SimulationContext(
            user: effectiveUser,
            uid: uid_t(max(0, effectiveUID)),
            authURI: requestKind == .authURI ? authURI : nil,
            sudoCommand: requestKind == .sudo ? sudoCommand : nil,
            argv: effectiveArgv,
            executablePath: effectiveExecutablePath,
            teamID: effectiveTeamID,
            binaryHash: effectiveBinaryHash,
            signingStatus: effectiveSigningStatus,
            justificationProvided: effectiveJustificationProvided,
            justificationText: effectiveJustificationText,
            activeGrants: [],
            currentTime: currentTime
        )
        do {
            result = try DecisionSimulator().simulate(
                context: context,
                profiles: profiles,
                globalCacheSeconds: effectiveGlobalCacheSeconds
            )
            errorMessage = nil
        } catch {
            result = nil
            errorMessage = error.localizedDescription
        }
    }
}
