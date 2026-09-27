import Foundation

/// Jamf Pro OAuth client credentials, read from the MDM-delivered config
/// domain.
///
/// Credentials in managed preferences are configuration, not secure secret
/// storage — assume privileged local processes can recover them (intentional
/// V1 architecture choice, surfaced in Settings). Mitigations enforced here
/// and downstream: minimum API privileges, no credential logging, no disk
/// cache, memory-only token cache, rotation support (every read goes back
/// to the managed domain, so MDM-pushed rotation takes effect immediately).
public struct JamfCredentials: Sendable, Equatable {
    public let serverURL: URL
    public let clientID: String
    public let clientSecret: String

    public init(serverURL: URL, clientID: String, clientSecret: String) {
        self.serverURL = serverURL
        self.clientID = clientID
        self.clientSecret = clientSecret
    }
}

/// Reads Jamf credentials from `com.herojoneslabs.serberus.config`.
///
/// Never caches: rotation pushed via MDM is picked up on the next read.
/// Never writes — Serberus does not write to managed preference domains,
/// and Jamf credentials never enter the Keychain.
public struct JamfCredentialStore: Sendable {
    private let reader: ManagedPreferencesReader
    /// When set, these user-entered credentials are returned instead of the
    /// MDM-delivered managed preferences. The Policy Builder uses this so the
    /// admin can connect to a Jamf instance configured in Settings; the endpoint
    /// daemon path always uses the managed domain (override == nil).
    private let override: JamfCredentials?

    public init(reader: ManagedPreferencesReader = ManagedPreferencesReader(),
                override: JamfCredentials? = nil) {
        self.reader = reader
        self.override = override
    }

    /// Connection state for the read-only Settings panel — surfaces which
    /// specific key is missing rather than a generic error.
    public enum ConnectionState: Sendable, Equatable {
        case configured(JamfCredentials)
        case notConfigured(missingKey: String)
    }

    /// Reads current credentials from the managed domain.
    public func connectionState() -> ConnectionState {
        if let override {
            return .configured(override)
        }
        let config = reader.readConfig().value
        guard let url = config.jamfProURL else {
            return .notConfigured(missingKey: "jamfProURL")
        }
        guard let clientID = config.jamfAPIClientID, !clientID.isEmpty else {
            return .notConfigured(missingKey: "jamfAPIClientID")
        }
        guard let secret = config.jamfAPIClientSecret, !secret.isEmpty else {
            return .notConfigured(missingKey: "jamfAPIClientSecret")
        }
        return .configured(JamfCredentials(serverURL: url, clientID: clientID, clientSecret: secret))
    }

    /// Returns credentials or throws the specific missing-key error.
    /// - Throws: ``JamfError/notConfigured(missingKey:)``
    public func credentials() throws -> JamfCredentials {
        switch connectionState() {
        case let .configured(credentials):
            return credentials
        case let .notConfigured(missingKey):
            throw JamfError.notConfigured(missingKey: missingKey)
        }
    }
}
