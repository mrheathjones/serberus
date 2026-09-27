import Foundation
import PrivMgrCore

/// Uploads a capture bundle to the Mac's own computer record in Jamf Pro.
///
/// Reuses ``JamfTokenManager`` / ``HTTPTransport`` / ``JamfCredentialStore``
/// from PrivMgrCore rather than re-implementing OAuth — the only genuinely
/// new surface here is multipart upload, which the existing
/// ``JamfAPIClient`` does not support.
///
/// ## Credential exposure
///
/// This runs on every managed endpoint as a standard user, and Jamf
/// credentials in managed preferences are configuration, not secrets — any
/// local user can recover them. The API role backing these credentials must
/// therefore be scoped to the absolute minimum: **Update Computers** (for
/// the attachment POST) and **Read Computers** (for the serial lookup), and
/// nothing else. Anyone on any managed Mac can use that role directly.
///
/// ## Endpoint choice
///
/// `POST /api/v3/computers-inventory/{id}/attachments` (field `file`) is the
/// current Jamf Pro API path. Jamf's reference renders both the v1 and v3
/// attachment endpoints with a deprecation marker, so ``Endpoint/classic``
/// is offered as a fallback to the Classic `fileuploads` resource (field
/// `name`), which remains the documented route for file attachments.
public actor JamfAttachmentUploader {
    /// Which attachment API to target.
    public enum Endpoint: Sendable, Equatable {
        /// `POST /api/v3/computers-inventory/{id}/attachments`, field `file`.
        case jamfProAPI
        /// `POST /JSSResource/fileuploads/computers/id/{id}`, field `name`.
        case classic

        var fieldName: String {
            switch self {
            case .jamfProAPI: return "file"
            case .classic: return "name"
            }
        }

        func path(computerID: String) -> String {
            switch self {
            case .jamfProAPI: return "api/v3/computers-inventory/\(computerID)/attachments"
            case .classic: return "JSSResource/fileuploads/computers/id/\(computerID)"
            }
        }
    }

    public struct UploadResult: Sendable, Equatable {
        public let computerID: String
        public let fileName: String
    }

    public enum UploadError: Error, LocalizedError, Equatable {
        case noSerialNumber
        case computerNotFound(serial: String)

        public var errorDescription: String? {
            switch self {
            case .noSerialNumber:
                return "Could not read this Mac's serial number, so its Jamf record cannot be located."
            case let .computerNotFound(serial):
                return "No computer in Jamf matches serial \(serial). Is this Mac enrolled and has it submitted inventory?"
            }
        }
    }

    private let credentialStore: JamfCredentialStore
    private let tokenManager: JamfTokenManager
    private let transport: HTTPTransport
    private let endpoint: Endpoint
    /// Whether a bearer token was ever issued to this uploader — gates
    /// server-side invalidation. See ``invalidateToken()``.
    private var didObtainToken = false

    public init(
        credentialStore: JamfCredentialStore = JamfCredentialStore(),
        tokenManager: JamfTokenManager? = nil,
        transport: HTTPTransport = URLSessionTransport(),
        endpoint: Endpoint = .jamfProAPI
    ) {
        self.credentialStore = credentialStore
        self.transport = transport
        self.endpoint = endpoint
        self.tokenManager = tokenManager ?? JamfTokenManager(
            credentialStore: credentialStore,
            transport: transport
        )
    }

    /// Resolves this Mac's Jamf record and uploads `bundle` to it.
    ///
    /// The server-side token is always invalidated before returning, on both
    /// the success and failure paths — see ``invalidateToken()``.
    public func upload(bundle: IntelBundle) async throws -> UploadResult {
        try await upload(
            fileURL: bundle.archiveURL,
            mimeType: "application/zip",
            serialNumber: bundle.manifest.host.serialNumber
        )
    }

    /// Resolves this Mac's Jamf record by `serialNumber` and attaches the file
    /// at `fileURL` to it — the shared path under ``upload(bundle:)`` (support
    /// bundle zip) and the Sentinel's Capture upload (`.serberuscapture` JSON).
    /// Same endpoint, same minimal API role (`Read Computers` + `Update
    /// Computers`), same always-invalidate token contract.
    public func upload(fileURL: URL, mimeType: String, serialNumber: String?) async throws -> UploadResult {
        // Not `defer { Task { … } }`: that would detach the invalidation and
        // let `upload` return while the token is still live, which is the
        // exact leak this is here to prevent. Both paths await it.
        do {
            let result = try await performUpload(fileURL: fileURL, mimeType: mimeType, serialNumber: serialNumber)
            await invalidateToken()
            return result
        } catch {
            await invalidateToken()
            throw error
        }
    }

    private func performUpload(fileURL: URL, mimeType: String, serialNumber: String?) async throws -> UploadResult {
        guard let serial = serialNumber else {
            throw UploadError.noSerialNumber
        }
        let computerID = try await computerID(forSerial: serial)
        let payload = try Data(contentsOf: fileURL)
        let fileName = fileURL.lastPathComponent

        let multipart = MultipartBody(boundary: MultipartBody.randomBoundary())
        let body = multipart.encode(
            fieldName: endpoint.fieldName,
            fileName: fileName,
            mimeType: mimeType,
            payload: payload
        )

        _ = try await send(
            method: "POST",
            path: endpoint.path(computerID: computerID),
            contentType: multipart.contentType,
            body: body
        )
        return UploadResult(computerID: computerID, fileName: fileName)
    }

    /// Looks up the Jamf computer ID for a serial.
    ///
    /// The ID is resolved per session and never persisted: a Mac that is
    /// wiped and re-enrolled keeps its serial but gets a **new** computer ID,
    /// so a cached ID would silently attach this Mac's logs to a stale record.
    func computerID(forSerial serial: String) async throws -> String {
        let credentials = try credentialStore.credentials()
        var components = URLComponents(
            url: credentials.serverURL.appendingPathComponent("api/v2/computers-inventory"),
            resolvingAgainstBaseURL: false
        )
        // RSQL. URLComponents percent-encodes the quotes and leaves `==`
        // intact, which is exactly the encoding Jamf expects.
        components?.queryItems = [
            URLQueryItem(name: "filter", value: "hardware.serialNumber==\"\(serial)\""),
            URLQueryItem(name: "section", value: "GENERAL"),
            URLQueryItem(name: "page-size", value: "1"),
        ]
        guard let url = components?.url else {
            throw JamfError.unreachable(underlying: "could not build the computer lookup URL")
        }

        let data = try await send(method: "GET", url: url, path: "api/v2/computers-inventory")
        struct SearchResponse: Decodable {
            struct Computer: Decodable { let id: String }
            let totalCount: Int
            let results: [Computer]
        }
        let decoded: SearchResponse
        do {
            decoded = try JSONDecoder().decode(SearchResponse.self, from: data)
        } catch {
            throw JamfError.responseDecodingFailed(
                endpoint: "api/v2/computers-inventory",
                reason: String(describing: error)
            )
        }
        guard let first = decoded.results.first else {
            throw UploadError.computerNotFound(serial: serial)
        }
        return first.id
    }

    /// Invalidates the bearer token **server-side**.
    ///
    /// ``JamfTokenManager/invalidate()`` only drops the local cache; the
    /// token stays live on the server until it expires, holding a database
    /// connection. That is survivable for a single Commander app, but Intel
    /// runs fleet-wide — thousands of endpoints each abandoning a live token
    /// is the documented route to Jamf Pro connection-pool exhaustion and
    /// fleet-wide policy failures. Best-effort: a failure to invalidate must
    /// never mask the upload's own result.
    public func invalidateToken() async {
        // Only invalidate a token this uploader actually obtained. Calling
        // `tokenManager.token()` unconditionally would *authenticate* purely
        // in order to invalidate, so a run that failed before any request
        // (no serial, no credentials) would still mint a fresh token — the
        // opposite of the leak this exists to prevent.
        guard didObtainToken else { return }
        if let credentials = try? credentialStore.credentials(),
           let token = try? await tokenManager.token() {
            var request = URLRequest(
                url: credentials.serverURL.appendingPathComponent("api/v1/auth/invalidate-token")
            )
            request.httpMethod = "POST"
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            _ = try? await transport.send(request)
        }
        await tokenManager.invalidate()
    }

    // MARK: Request plumbing

    private func send(
        method: String,
        path: String,
        contentType: String? = nil,
        body: Data? = nil
    ) async throws -> Data {
        let credentials = try credentialStore.credentials()
        return try await send(
            method: method,
            url: credentials.serverURL.appendingPathComponent(path),
            path: path,
            contentType: contentType,
            body: body
        )
    }

    private func send(
        method: String,
        url: URL,
        path: String,
        contentType: String? = nil,
        body: Data? = nil
    ) async throws -> Data {
        let token = try await tokenManager.token()
        didObtainToken = true

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
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
        case 200, 201, 204:
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
}
