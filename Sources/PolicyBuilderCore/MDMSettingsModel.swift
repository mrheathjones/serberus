import Foundation
import Observation
import PrivMgrCore

/// View-model for the Settings MDM connection: holds the admin's user-entered
/// connection (persisted to UserDefaults + Keychain), runs the live
/// connectivity test, lists the MDM's configuration profiles, and publishes
/// Serberus policies as `.mobileconfig` profiles.
@MainActor
@Observable
public final class MDMSettingsModel {
    public var vendor: MDMVendor {
        didSet {
            guard vendor != oldValue else { return }
            clientSecret = Keychain.get(account: secretAccount) ?? ""
            testState = .idle
            profilesState = .idle
        }
    }
    public var instanceURL: String
    public var clientID: String
    public var clientSecret: String

    public enum TestState: Sendable, Equatable {
        case idle, testing
        case result(MDMResult)
    }
    public enum ProfilesState: Sendable, Equatable {
        case idle, loading
        case loaded([MDMProfile])
        case failed(MDMResult)
    }
    public enum PublishState: Sendable, Equatable {
        case idle, working
        case result(MDMResult)
    }

    public private(set) var testState: TestState = .idle
    public private(set) var profilesState: ProfilesState = .idle
    public private(set) var publishState: PublishState = .idle
    public private(set) var savedAt: Date?

    private let defaults: UserDefaults
    private static let kVendor = "serberus.mdm.vendor"
    private static let kURL = "serberus.mdm.instanceURL"
    private static let kClientID = "serberus.mdm.clientID"

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let v = MDMVendor(rawValue: defaults.string(forKey: Self.kVendor) ?? "") ?? .jamf
        self.vendor = v
        self.instanceURL = defaults.string(forKey: Self.kURL) ?? ""
        self.clientID = defaults.string(forKey: Self.kClientID) ?? ""
        self.clientSecret = Keychain.get(account: "serberus.mdm.secret.\(v.rawValue)") ?? ""
    }

    private var secretAccount: String { "serberus.mdm.secret.\(vendor.rawValue)" }

    public var connection: MDMConnection {
        MDMConnection(vendor: vendor, instanceURL: instanceURL, clientID: clientID, clientSecret: clientSecret)
    }

    public var hasSavedConnection: Bool {
        !(defaults.string(forKey: Self.kURL) ?? "").isEmpty
    }

    /// Persists the connection: non-secret fields in UserDefaults, the secret
    /// in the Keychain.
    public func save() {
        defaults.set(vendor.rawValue, forKey: Self.kVendor)
        defaults.set(instanceURL, forKey: Self.kURL)
        defaults.set(clientID, forKey: Self.kClientID)
        Keychain.set(clientSecret, account: secretAccount)
        savedAt = Date()
    }

    public func test() async {
        testState = .testing
        testState = .result(await vendor.provider.test(connection))
    }

    public func fetchProfiles() async {
        profilesState = .loading
        switch await vendor.provider.listProfiles(connection) {
        case let .success(list): profilesState = .loaded(list)
        case let .failure(err):  profilesState = .failed(err)
        }
    }

    /// Publishes an already-generated `.mobileconfig`, updating the existing
    /// configuration profile when one already carries this name (scope is
    /// preserved), else creating a new one — scope new profiles in the MDM.
    ///
    /// Returns the outcome directly (as well as publishing it to
    /// ``publishState``) so a caller can react to its own publish without
    /// re-reading the shared state a concurrent publish may have overwritten.
    @discardableResult
    public func publish(name: String, mobileconfig: Data) async -> MDMResult {
        publishState = .working
        let result: MDMResult
        switch await vendor.provider.publish(name: name, mobileconfig: mobileconfig, connection: connection) {
        case let .success(id):
            result = .connected(detail: "Published “\(name)” as profile #\(id)")
        case let .failure(err):
            result = err
        }
        publishState = .result(result)
        return result
    }

    public var isConnected: Bool {
        if case .result(.connected) = testState { return true }
        return false
    }
}

public extension MDMResult {
    /// Short UI label.
    var headline: String {
        switch self {
        case let .connected(detail):              return detail
        case .invalidCredentials:                 return "Invalid credentials"
        case let .insufficientPermissions(detail): return "Insufficient permissions (\(detail))"
        case let .unreachable(detail):            return "Unreachable — \(detail)"
        case let .misconfigured(detail):          return detail
        case let .notSupported(vendor):           return "\(vendor) is not supported yet"
        }
    }
    var isSuccess: Bool { if case .connected = self { return true }; return false }
}
