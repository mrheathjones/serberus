import Foundation

/// Minimal Jamf Pro API client for V1 Policy Builder needs:
/// listing, creating, and updating configuration profiles, plus a
/// connectivity probe for the read-only Settings panel.
///
/// Error mapping:
/// - 401 → invalidate token, surface ``JamfError/credentialsInvalid``,
///   never silently retry.
/// - 403 → ``JamfError/insufficientPermissions(endpoint:)`` mapped to the
///   Settings permission checklist.
/// - timeout/unreachable → ``JamfError/unreachable(underlying:)`` so the UI
///   shows staleness and disables publish while remaining usable offline.
public actor JamfAPIClient {
    private let credentialStore: JamfCredentialStore
    private let tokenManager: JamfTokenManager
    private let transport: HTTPTransport

    public init(
        credentialStore: JamfCredentialStore = JamfCredentialStore(),
        tokenManager: JamfTokenManager? = nil,
        transport: HTTPTransport = URLSessionTransport()
    ) {
        self.credentialStore = credentialStore
        self.transport = transport
        self.tokenManager = tokenManager ?? JamfTokenManager(
            credentialStore: credentialStore,
            transport: transport
        )
    }

    // MARK: Connectivity

    /// Jamf instance info for the Settings status row.
    public struct InstanceInfo: Sendable, Equatable {
        public let version: String
    }

    /// Probes connectivity and returns the Jamf Pro version.
    public func instanceInfo() async throws -> InstanceInfo {
        let data = try await get(path: "api/v1/jamf-pro-version")
        struct VersionResponse: Decodable { let version: String }
        do {
            let decoded = try JSONDecoder().decode(VersionResponse.self, from: data)
            return InstanceInfo(version: decoded.version)
        } catch {
            throw JamfError.responseDecodingFailed(
                endpoint: "api/v1/jamf-pro-version",
                reason: String(describing: error)
            )
        }
    }

    // MARK: Configuration profiles

    /// Summary of one configuration profile known to Jamf.
    public struct ProfileSummary: Sendable, Equatable {
        public let id: Int
        public let name: String
    }

    /// Whether two profile names collide in Jamf. Jamf's duplicate-name check
    /// is case-insensitive (and tolerant of stray whitespace), so every
    /// create-vs-update decision must compare the same way — an exact-string
    /// match can miss a profile that Jamf will still 409 against on create.
    public static func profileNamesMatch(_ a: String, _ b: String) -> Bool {
        a.trimmingCharacters(in: .whitespacesAndNewlines)
            .caseInsensitiveCompare(b.trimmingCharacters(in: .whitespacesAndNewlines)) == .orderedSame
    }

    /// Lists computer configuration profiles (Classic API, JSON read).
    public func listConfigurationProfiles() async throws -> [ProfileSummary] {
        let endpoint = "JSSResource/osxconfigurationprofiles"
        let data = try await get(path: endpoint, accept: "application/json")
        struct ListResponse: Decodable {
            struct Item: Decodable {
                let id: Int
                let name: String
            }
            let os_x_configuration_profiles: [Item]
        }
        do {
            let decoded = try JSONDecoder().decode(ListResponse.self, from: data)
            return decoded.os_x_configuration_profiles
                .map { ProfileSummary(id: $0.id, name: $0.name) }
                .sorted { $0.id < $1.id }
        } catch {
            throw JamfError.responseDecodingFailed(endpoint: endpoint, reason: String(describing: error))
        }
    }

    /// Creates a configuration profile from a `.mobileconfig` payload.
    /// - Returns: The new profile's Jamf ID.
    public func createConfigurationProfile(name: String, mobileconfig: Data) async throws -> Int {
        let endpoint = "JSSResource/osxconfigurationprofiles/id/0"
        let body = Self.profileXML(name: name, mobileconfig: mobileconfig)
        let data = try await send(method: "POST", path: endpoint, contentType: "application/xml", body: body)
        guard let id = Self.extractID(fromXML: data) else {
            throw JamfError.responseDecodingFailed(endpoint: endpoint, reason: "no profile ID in response")
        }
        return id
    }

    /// Updates an existing configuration profile's payload.
    public func updateConfigurationProfile(id: Int, name: String, mobileconfig: Data) async throws {
        let endpoint = "JSSResource/osxconfigurationprofiles/id/\(id)"
        let body = Self.profileXML(name: name, mobileconfig: mobileconfig)
        _ = try await send(method: "PUT", path: endpoint, contentType: "application/xml", body: body)
    }

    // MARK: Request plumbing

    private func get(path: String, accept: String = "application/json") async throws -> Data {
        try await send(method: "GET", path: path, accept: accept, contentType: nil, body: nil)
    }

    private func send(
        method: String,
        path: String,
        accept: String = "application/json",
        contentType: String?,
        body: Data?
    ) async throws -> Data {
        let credentials = try credentialStore.credentials()
        let token = try await tokenManager.token()

        var request = URLRequest(url: credentials.serverURL.appendingPathComponent(path))
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(accept, forHTTPHeaderField: "Accept")
        if let contentType {
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }
        request.httpBody = body

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.send(request)
        } catch {
            throw JamfError.unreachable(underlying: error.localizedDescription)
        }

        switch response.statusCode {
        case 200, 201:
            return data
        case 401:
            await tokenManager.invalidate()
            throw JamfError.credentialsInvalid
        case 403:
            throw JamfError.insufficientPermissions(endpoint: path)
        default:
            throw JamfError.unexpectedStatus(code: response.statusCode, endpoint: path)
        }
    }

    // MARK: Classic API XML

    static func profileXML(name: String, mobileconfig: Data) -> Data {
        let escapedName = Self.xmlEscape(name)
        let escapedPayload = Self.xmlEscape(String(decoding: mobileconfig, as: UTF8.self))
        let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <os_x_configuration_profile>
            <general>
            <name>\(escapedName)</name>
            <distribution_method>Install Automatically</distribution_method>
            <payloads>\(escapedPayload)</payloads>
            </general>
            </os_x_configuration_profile>
            """
        return Data(xml.utf8)
    }

    static func xmlEscape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    /// Extracts `<id>…</id>` from a Classic API response document.
    static func extractID(fromXML data: Data) -> Int? {
        let text = String(decoding: data, as: UTF8.self)
        guard let open = text.range(of: "<id>"), let close = text.range(of: "</id>") else {
            return nil
        }
        return Int(text[open.upperBound..<close.lowerBound])
    }
}
