import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

/// Records every request and replies from a scripted queue.
private final class MockTransport: HTTPTransport, @unchecked Sendable {
    struct Reply {
        let status: Int
        let body: Data
        init(status: Int = 200, body: Data = Data()) {
            self.status = status
            self.body = body
        }
    }

    private let lock = NSLock()
    private var replies: [Reply]
    private(set) var requests: [URLRequest] = []

    init(replies: [Reply]) { self.replies = replies }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        // Scoped, not lock()/unlock(): NSLock's imperative pair is unavailable
        // from an async context because the lock could span a suspension.
        let reply = lock.withLock {
            requests.append(request)
            return replies.isEmpty ? Reply() : replies.removeFirst()
        }
        let response = HTTPURLResponse(
            url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: nil
        )!
        return (reply.body, response)
    }

    /// Requests excluding OAuth token traffic, which every call performs.
    var apiRequests: [URLRequest] {
        requests.filter { !($0.url?.path.contains("oauth/token") ?? false) }
    }

    func path(containing needle: String) -> URLRequest? {
        requests.first { $0.url?.absoluteString.contains(needle) ?? false }
    }
}

private let credentials = JamfCredentials(
    serverURL: URL(string: "https://example.jamfcloud.com")!,
    clientID: "id",
    clientSecret: "secret"
)

private func tokenReply() -> MockTransport.Reply {
    MockTransport.Reply(body: Data(#"{"access_token":"TOKEN","expires_in":3600}"#.utf8))
}

private func makeBundle(serial: String?) throws -> IntelBundle {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("uploader-\(UUID().uuidString).zip")
    try Data("PK\u{03}\u{04}".utf8).write(to: url)
    let host = HostContext(
        serialNumber: serial,
        computerName: "TEST-MAC",
        osVersion: "26.0",
        userName: "alice",
        componentVersions: [:],
        daemonState: "enforce",
        enforcementMode: "enforce",
        degradedReason: nil,
        stateUpdatedAt: nil,
        hasConfiguration: true
    )
    return IntelBundle(
        archiveURL: url,
        manifest: IntelManifest(createdAt: Date(), window: .oneHour, host: host, artifacts: [])
    )
}

private func makeUploader(
    transport: MockTransport,
    endpoint: JamfAttachmentUploader.Endpoint = .jamfProAPI
) -> JamfAttachmentUploader {
    let store = JamfCredentialStore(override: credentials)
    return JamfAttachmentUploader(
        credentialStore: store,
        tokenManager: JamfTokenManager(credentialStore: store, transport: transport),
        transport: transport,
        endpoint: endpoint
    )
}

@Suite("JamfAttachmentUploader")
struct JamfAttachmentUploaderTests {
    @Test("looks the computer up by serial with an RSQL filter")
    func looksUpBySerial() async throws {
        let transport = MockTransport(replies: [
            tokenReply(),
            .init(body: Data(#"{"totalCount":1,"results":[{"id":"77"}]}"#.utf8)),
        ])
        let id = try await makeUploader(transport: transport).computerID(forSerial: "C02XY123")
        #expect(id == "77")

        let request = try #require(transport.path(containing: "computers-inventory"))
        let url = try #require(request.url?.absoluteString)
        // Quotes must be percent-encoded; `==` must survive intact.
        #expect(url.contains("hardware.serialNumber%3D%3D%22C02XY123%22")
            || url.contains("hardware.serialNumber==%22C02XY123%22"))
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer TOKEN")
    }

    @Test("an unknown serial surfaces an actionable error")
    func unknownSerial() async throws {
        let transport = MockTransport(replies: [
            tokenReply(),
            .init(body: Data(#"{"totalCount":0,"results":[]}"#.utf8)),
        ])
        await #expect(throws: JamfAttachmentUploader.UploadError.computerNotFound(serial: "NOPE")) {
            try await makeUploader(transport: transport).computerID(forSerial: "NOPE")
        }
    }

    @Test("posts multipart to the v3 attachment endpoint using field `file`")
    func uploadsToJamfProAPI() async throws {
        let transport = MockTransport(replies: [
            tokenReply(),
            .init(body: Data(#"{"totalCount":1,"results":[{"id":"77"}]}"#.utf8)),
            .init(status: 201),
        ])
        let result = try await makeUploader(transport: transport).upload(bundle: try makeBundle(serial: "C02XY123"))
        #expect(result.computerID == "77")

        let post = try #require(transport.path(containing: "/attachments"))
        #expect(post.httpMethod == "POST")
        #expect(post.url?.path == "/api/v3/computers-inventory/77/attachments")
        let contentType = try #require(post.value(forHTTPHeaderField: "Content-Type"))
        #expect(contentType.hasPrefix("multipart/form-data; boundary="))
        let body = String(decoding: try #require(post.httpBody), as: UTF8.self)
        #expect(body.contains(#"name="file""#))
    }

    @Test("the classic fallback posts to fileuploads using field `name`")
    func uploadsToClassic() async throws {
        let transport = MockTransport(replies: [
            tokenReply(),
            .init(body: Data(#"{"totalCount":1,"results":[{"id":"77"}]}"#.utf8)),
            .init(status: 201),
        ])
        // Jamf's reference renders both v1 and v3 attachment endpoints as
        // deprecated, so the Classic route stays reachable.
        _ = try await makeUploader(transport: transport, endpoint: .classic)
            .upload(bundle: try makeBundle(serial: "C02XY123"))

        let post = try #require(transport.path(containing: "fileuploads"))
        #expect(post.url?.path == "/JSSResource/fileuploads/computers/id/77")
        #expect(String(decoding: try #require(post.httpBody), as: UTF8.self).contains(#"name="name""#))
    }

    @Test("the bearer token is invalidated server-side after a successful upload")
    func invalidatesTokenOnSuccess() async throws {
        let transport = MockTransport(replies: [
            tokenReply(),
            .init(body: Data(#"{"totalCount":1,"results":[{"id":"77"}]}"#.utf8)),
            .init(status: 201),
        ])
        _ = try await makeUploader(transport: transport).upload(bundle: try makeBundle(serial: "C02XY123"))

        // Fleet-wide, abandoned tokens hold Jamf DB connections until expiry —
        // the documented route to pool exhaustion and fleet policy failures.
        #expect(transport.path(containing: "auth/invalidate-token") != nil)
    }

    @Test("the token is invalidated even when the upload fails")
    func invalidatesTokenOnFailure() async throws {
        let transport = MockTransport(replies: [
            tokenReply(),
            .init(body: Data(#"{"totalCount":1,"results":[{"id":"77"}]}"#.utf8)),
            .init(status: 500),
        ])
        await #expect(throws: (any Error).self) {
            try await makeUploader(transport: transport).upload(bundle: try makeBundle(serial: "C02XY123"))
        }
        #expect(transport.path(containing: "auth/invalidate-token") != nil)
    }

    @Test("a Mac with no readable serial fails before any network call")
    func noSerialFailsEarly() async throws {
        let transport = MockTransport(replies: [tokenReply()])
        await #expect(throws: JamfAttachmentUploader.UploadError.noSerialNumber) {
            try await makeUploader(transport: transport).upload(bundle: try makeBundle(serial: nil))
        }
        #expect(transport.apiRequests.isEmpty)
    }

    @Test("403 maps to insufficient permissions, naming the endpoint")
    func forbiddenMapsToPermissions() async throws {
        let transport = MockTransport(replies: [tokenReply(), .init(status: 403)])
        await #expect(throws: JamfError.insufficientPermissions(endpoint: "api/v2/computers-inventory")) {
            try await makeUploader(transport: transport).computerID(forSerial: "C02XY123")
        }
    }
}
