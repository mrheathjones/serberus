import Foundation

/// The MDM vendor an admin can connect Serberus to. Jamf Pro is fully
/// implemented in V1; the others are recognized so the connection UI can be
/// configured ahead of provider support landing.
public enum MDMVendor: String, CaseIterable, Sendable, Identifiable {
    case jamf
    case intune
    case mosyle
    case kandji

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .jamf:   return "Jamf Pro"
        case .intune: return "Microsoft Intune"
        case .mosyle: return "Mosyle"
        case .kandji: return "Kandji"
        }
    }

    /// Whether a real provider implementation exists yet.
    public var isSupported: Bool { self == .jamf }

    public var instanceLabel: String {
        switch self {
        case .jamf:   return "Jamf Pro URL"
        case .intune: return "Tenant URL"
        case .mosyle: return "Mosyle URL"
        case .kandji: return "Kandji subdomain"
        }
    }
    public var clientIDLabel: String {
        switch self {
        case .intune: return "Application (client) ID"
        default:      return "API Client ID"
        }
    }
    public var clientSecretLabel: String {
        switch self {
        case .intune: return "Client secret"
        default:      return "API Client Secret"
        }
    }
    public var instancePlaceholder: String {
        switch self {
        case .jamf:   return "https://yourcompany.jamfcloud.com"
        case .intune: return "https://graph.microsoft.com"
        case .mosyle: return "https://businessapi.mosyle.com"
        case .kandji: return "https://yourcompany.api.kandji.io"
        }
    }

    public var provider: MDMProvider {
        switch self {
        case .jamf: return JamfMDMProvider()
        default:    return UnsupportedMDMProvider(vendor: self)
        }
    }
}

/// A user-entered MDM connection (Commander app). The secret is held in the
/// Keychain; this value object carries it transiently for a request.
public struct MDMConnection: Sendable, Equatable {
    public var vendor: MDMVendor
    public var instanceURL: String
    public var clientID: String
    public var clientSecret: String

    public init(vendor: MDMVendor, instanceURL: String, clientID: String, clientSecret: String) {
        self.vendor = vendor
        self.instanceURL = instanceURL
        self.clientID = clientID
        self.clientSecret = clientSecret
    }

    public var isComplete: Bool {
        !instanceURL.trimmingCharacters(in: .whitespaces).isEmpty
            && !clientID.trimmingCharacters(in: .whitespaces).isEmpty
            && !clientSecret.isEmpty
    }
}

/// The outcome of a connectivity / API operation, mapped to a UI-friendly state.
public enum MDMResult: Sendable, Equatable, Error {
    case connected(detail: String)
    case invalidCredentials
    case insufficientPermissions(detail: String)
    case unreachable(detail: String)
    case misconfigured(detail: String)
    case notSupported(vendor: String)
}

/// A configuration profile known to the MDM.
public struct MDMProfile: Sendable, Identifiable, Equatable {
    public let id: Int
    public let name: String
    public init(id: Int, name: String) { self.id = id; self.name = name }
}

/// Vendor-neutral MDM operations the Policy Builder needs.
public protocol MDMProvider: Sendable {
    func test(_ connection: MDMConnection) async -> MDMResult
    func listProfiles(_ connection: MDMConnection) async -> Result<[MDMProfile], MDMResult>
    func publish(name: String, mobileconfig: Data, connection: MDMConnection) async -> Result<Int, MDMResult>
}

/// Jamf Pro provider — wraps ``JamfAPIClient`` with the admin's user-entered
/// credentials (via ``JamfCredentialStore`` override).
public struct JamfMDMProvider: MDMProvider {
    private let transport: HTTPTransport

    public init(transport: HTTPTransport = URLSessionTransport()) {
        self.transport = transport
    }

    private func makeClient(_ c: MDMConnection) -> JamfAPIClient? {
        guard let url = URL(string: c.instanceURL.trimmingCharacters(in: .whitespaces)),
              url.scheme != nil, !c.clientID.isEmpty, !c.clientSecret.isEmpty else { return nil }
        let creds = JamfCredentials(serverURL: url, clientID: c.clientID, clientSecret: c.clientSecret)
        return JamfAPIClient(credentialStore: JamfCredentialStore(override: creds), transport: transport)
    }

    public func test(_ c: MDMConnection) async -> MDMResult {
        guard let client = makeClient(c) else {
            return .misconfigured(detail: "Enter a valid URL, client ID, and secret.")
        }
        do {
            let info = try await client.instanceInfo()
            return .connected(detail: "Jamf Pro \(info.version)")
        } catch {
            return Self.map(error)
        }
    }

    public func listProfiles(_ c: MDMConnection) async -> Result<[MDMProfile], MDMResult> {
        guard let client = makeClient(c) else { return .failure(.misconfigured(detail: "Connection is incomplete.")) }
        do {
            let summaries = try await client.listConfigurationProfiles()
            return .success(summaries.map { MDMProfile(id: $0.id, name: $0.name) })
        } catch {
            return .failure(Self.map(error))
        }
    }

    public func publish(name: String, mobileconfig: Data, connection c: MDMConnection) async -> Result<Int, MDMResult> {
        guard let client = makeClient(c) else { return .failure(.misconfigured(detail: "Connection is incomplete.")) }
        do {
            // Update in place when a profile already carries this name — Jamf
            // rejects duplicate names with 409, and its check is looser than an
            // exact string match. The PUT sends only name + payloads, so the
            // existing profile's scope is preserved across republishes.
            let existing = try await client.listConfigurationProfiles()
            if let match = existing.first(where: { JamfAPIClient.profileNamesMatch($0.name, name) }) {
                try await client.updateConfigurationProfile(id: match.id, name: match.name, mobileconfig: mobileconfig)
                return .success(match.id)
            }
            let id = try await client.createConfigurationProfile(name: name, mobileconfig: mobileconfig)
            return .success(id)
        } catch {
            return .failure(Self.map(error))
        }
    }

    static func map(_ error: Error) -> MDMResult {
        guard let jamf = error as? JamfError else {
            return .unreachable(detail: error.localizedDescription)
        }
        switch jamf {
        case .credentialsInvalid:
            return .invalidCredentials
        case let .insufficientPermissions(endpoint):
            return .insufficientPermissions(detail: endpoint)
        case let .unreachable(underlying):
            return .unreachable(detail: underlying)
        case let .notConfigured(missingKey):
            return .misconfigured(detail: "Missing \(missingKey)")
        case let .unexpectedStatus(code, _) where code == 409:
            return .misconfigured(detail: "Jamf reports a name conflict (409): a profile with this name already exists but isn't visible to this API client. Check the client's site access, or rename/delete the duplicate in Jamf.")
        default:
            return .unreachable(detail: String(describing: jamf))
        }
    }
}

/// Placeholder for vendors not yet implemented; every operation reports
/// `notSupported` so the UI can guide the user without crashing.
public struct UnsupportedMDMProvider: MDMProvider {
    public let vendor: MDMVendor
    public init(vendor: MDMVendor) { self.vendor = vendor }

    public func test(_ c: MDMConnection) async -> MDMResult { .notSupported(vendor: vendor.displayName) }
    public func listProfiles(_ c: MDMConnection) async -> Result<[MDMProfile], MDMResult> { .failure(.notSupported(vendor: vendor.displayName)) }
    public func publish(name: String, mobileconfig: Data, connection c: MDMConnection) async -> Result<Int, MDMResult> { .failure(.notSupported(vendor: vendor.displayName)) }
}
