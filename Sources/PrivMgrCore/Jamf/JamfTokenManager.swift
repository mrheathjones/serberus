import Foundation

// MARK: - Transport abstraction

/// Minimal HTTP transport so Jamf components are testable without a server.
public protocol HTTPTransport: Sendable {
    /// Sends one request and returns the body + response.
    /// - Throws: Transport-level errors (mapped to ``JamfError/unreachable(underlying:)``).
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// URLSession-backed production transport.
public struct URLSessionTransport: HTTPTransport {
    private let session: URLSession

    public init(timeout: TimeInterval = 30) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        // Memory-only: no URL cache, no cookie persistence, no disk anything.
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        self.session = URLSession(configuration: configuration)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        return (data, httpResponse)
    }
}

// MARK: - Token manager

/// OAuth client-credentials token flow against Jamf Pro.
///
/// - Bearer tokens live in this actor's memory only — never written to
///   disk or Keychain.
/// - Tokens are proactively refreshed 60 seconds before expiry.
/// - ``invalidate()`` is called on any 401 so the next request
///   re-authenticates; the 401 itself surfaces as
///   ``JamfError/credentialsInvalid`` without silent retry.
/// - Credentials are re-read from managed preferences on every
///   authentication, so MDM-pushed rotation takes effect immediately.
public actor JamfTokenManager {
    private let credentialStore: JamfCredentialStore
    private let transport: HTTPTransport
    private let now: @Sendable () -> Date

    private var cachedToken: String?
    private var expiresAt: Date?

    /// Seconds before expiry at which the cached token is considered stale.
    private static let refreshLeeway: TimeInterval = 60

    /// - Parameters:
    ///   - credentialStore: Source of MDM-delivered client credentials.
    ///   - transport: HTTP transport (mockable in tests).
    ///   - now: Clock injection for deterministic expiry tests.
    public init(
        credentialStore: JamfCredentialStore = JamfCredentialStore(),
        transport: HTTPTransport = URLSessionTransport(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.credentialStore = credentialStore
        self.transport = transport
        self.now = now
    }

    /// Returns a valid bearer token, authenticating or refreshing as needed.
    /// - Throws: ``JamfError``
    public func token() async throws -> String {
        if let cachedToken, let expiresAt,
           now().addingTimeInterval(Self.refreshLeeway) < expiresAt {
            return cachedToken
        }
        return try await authenticate()
    }

    /// Discards the cached token (called on 401 and credential rotation).
    public func invalidate() {
        cachedToken = nil
        expiresAt = nil
    }

    private struct TokenResponse: Decodable {
        let access_token: String
        let expires_in: Double
    }

    private func authenticate() async throws -> String {
        let credentials = try credentialStore.credentials()

        var request = URLRequest(url: credentials.serverURL.appendingPathComponent("api/oauth/token"))
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(Self.formEncode([
            "grant_type": "client_credentials",
            "client_id": credentials.clientID,
            "client_secret": credentials.clientSecret,
        ]).utf8)

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.send(request)
        } catch {
            throw JamfError.unreachable(underlying: error.localizedDescription)
        }

        switch response.statusCode {
        case 200:
            break
        case 401:
            invalidate()
            throw JamfError.credentialsInvalid
        default:
            throw JamfError.unexpectedStatus(code: response.statusCode, endpoint: "api/oauth/token")
        }

        let tokenResponse: TokenResponse
        do {
            tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw JamfError.responseDecodingFailed(endpoint: "api/oauth/token", reason: String(describing: error))
        }

        cachedToken = tokenResponse.access_token
        expiresAt = now().addingTimeInterval(tokenResponse.expires_in)
        return tokenResponse.access_token
    }

    /// Deterministic form encoding (sorted keys) with strict percent-escaping.
    static func formEncode(_ parameters: [String: String]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return parameters.keys.sorted().map { key in
            let value = parameters[key] ?? ""
            let escapedKey = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
            let escapedValue = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
            return "\(escapedKey)=\(escapedValue)"
        }.joined(separator: "&")
    }
}
