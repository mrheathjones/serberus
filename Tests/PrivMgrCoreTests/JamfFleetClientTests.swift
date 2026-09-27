import Foundation
import Testing
@testable import PrivMgrCore

/// Records every request and replies from a scripted queue.
private final class FleetMockTransport: HTTPTransport, @unchecked Sendable {
    struct Reply {
        let status: Int
        let body: Data
        init(status: Int = 200, body: Data = Data()) {
            self.status = status
            self.body = body
        }
        init(status: Int = 200, json: String) {
            self.status = status
            self.body = Data(json.utf8)
        }
    }

    private let lock = NSLock()
    private var replies: [Reply]
    private(set) var requests: [URLRequest] = []

    init(replies: [Reply]) { self.replies = replies }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let reply = lock.withLock {
            requests.append(request)
            return replies.isEmpty ? Reply(status: 500) : replies.removeFirst()
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: nil)!
        return (reply.body, response)
    }

    var apiRequests: [URLRequest] {
        requests.filter { !($0.url?.path.contains("oauth/token") ?? false) }
    }

    var apiURLs: [String] { apiRequests.compactMap { $0.url?.absoluteString } }
}

private let credentials = JamfCredentials(
    serverURL: URL(string: "https://example.jamfcloud.com")!, clientID: "id", clientSecret: "secret")

private func token() -> FleetMockTransport.Reply {
    FleetMockTransport.Reply(json: #"{"access_token":"TOKEN","expires_in":3600}"#)
}

/// A v4-shaped record (`general.lastContact`); `contactKey` lets a test emit the v2/v3 spelling.
private func computerJSON(id: Int, name: String = "MAC", serial: String = "C02XYZ", contactKey: String = "lastContact",
                          contact: String = "2026-08-22T12:34:56.789Z", attachments: String = "[]", eas: String = "[]") -> String {
    """
    {"id":"\(id)","udid":"u-\(id)",
     "general":{"name":"\(name)","\(contactKey)":"\(contact)","lastEnrolledDate":"2026-01-02T03:04:05Z","remoteManagement":{"managed":true}},
     "hardware":{"serialNumber":"\(serial)","model":"MacBook Pro","modelIdentifier":"Mac16,1"},
     "operatingSystem":{"version":"26.4","build":"25E123"},
     "userAndLocation":{"username":"jdoe","realname":"Jane Doe","email":"jdoe@example.com"},
     "extensionAttributes":\(eas),
     "attachments":\(attachments),
     "packageReceipts":{"installedByJamfPro":["SerberusSentinelAgent-3.8.pkg"],"installedByInstallerSwu":["com.apple.pkg.Safari","com.herojoneslabs.serberus.commanderpkg"],"cached":["Serberus-9.9.pkg"]}}
    """
}

private func page(total: Int, computers: [String]) -> String {
    #"{"totalCount":\#(total),"results":[\#(computers.joined(separator: ","))]}"#
}

/// The 1-item probe answer every inventory walk starts with.
private func probeReply() -> FleetMockTransport.Reply {
    FleetMockTransport.Reply(json: page(total: 1, computers: [computerJSON(id: 1)]))
}

private func client(_ transport: FleetMockTransport) -> JamfFleetClient {
    JamfFleetClient(credentialStore: JamfCredentialStore(override: credentials), transport: transport)
}

@Suite("JamfFleetClient — inventory probe/paging/decoding, attachment download, token hygiene")
struct JamfFleetClientTests {
    @Test("decodes the sections a fleet card needs (v4 field names), including attachments and extension attributes")
    func decodesSummary() async throws {
        let transport = FleetMockTransport(replies: [
            token(),
            probeReply(),
            FleetMockTransport.Reply(json: page(total: 1, computers: [computerJSON(
                id: 7,
                attachments: #"[{"id":"41","name":"Serberus-Capture-C02XYZ-20260822-101500.serberuscapture","fileType":"application/json","sizeBytes":2048},{"id":"42","name":"photo.png","fileType":"image/png","sizeBytes":99}]"#,
                eas: #"[{"definitionId":"3","name":"Serberus — State","values":["enforce"]},{"definitionId":"4","name":"Other","values":["x"]}]"#)])),
        ])
        let inventory = try await client(transport).listComputers()
        let mac = try #require(inventory.computers.first)
        #expect(inventory.computers.count == 1)
        #expect(inventory.totalCount == 1)
        #expect(!inventory.truncated)
        #expect(mac.id == "7")
        #expect(mac.name == "MAC")
        #expect(mac.serialNumber == "C02XYZ")
        #expect(mac.model == "MacBook Pro")
        #expect(mac.osVersion == "26.4")
        #expect(mac.username == "jdoe")
        #expect(mac.realName == "Jane Doe")
        #expect(mac.managed == true)
        #expect(mac.lastContactTime != nil)          // v4 `general.lastContact`
        #expect(mac.lastEnrolledDate != nil)
        #expect(mac.attachments.count == 2)
        #expect(mac.captures.map(\.id) == ["41"])
        #expect(mac.extensionAttributes.map(\.name) == ["Serberus — State", "Other"])
        // Jamf's real key is installedByInstallerSwu; Waiting-Room `cached` is not an install.
        #expect(mac.packageReceipts == ["SerberusSentinelAgent-3.8.pkg", "com.apple.pkg.Safari", "com.herojoneslabs.serberus.commanderpkg"])

        // Request shape: a v4 probe (1 item, GENERAL only), then the real
        // walk on v4 with every section, page 0, paged on the stable id key —
        // never the version-specific contact-time sort.
        let urls = transport.apiURLs
        #expect(urls.count == 2)
        #expect(urls[0].contains("/api/v4/computers-inventory?") && urls[0].contains("page-size=1") && urls[0].contains("section=GENERAL"))
        for section in JamfFleetClient.sections { #expect(urls[1].contains("section=\(section)")) }
        #expect(urls[1].contains("section=PACKAGE_RECEIPTS"))
        #expect(urls[1].contains("page=0"))
        #expect(urls[1].contains("page-size=\(JamfFleetClient.pageSize)"))
        #expect(urls[1].contains("sort=id:asc"))
        #expect(!urls[1].contains("lastContactTime"))
    }

    @Test("the v2/v3 contact spelling still decodes, and devices come back newest contact first")
    func legacyContactAndOrdering() async throws {
        let transport = FleetMockTransport(replies: [
            token(),
            probeReply(),
            FleetMockTransport.Reply(json: page(total: 3, computers: [
                computerJSON(id: 1, contactKey: "lastContactTime", contact: "2026-08-20T00:00:00Z"),
                computerJSON(id: 2, contactKey: "lastContactTime", contact: "2026-08-22T00:00:00Z"),
                #"{"id":"3","general":{"name":"no-contact"}}"#,
            ])),
        ])
        let inventory = try await client(transport).listComputers()
        #expect(inventory.computers.map(\.id) == ["2", "1", "3"])
        #expect(inventory.computers.last?.lastContactTime == nil)
    }

    @Test("pages until the page is short or totalCount is reached, de-duplicating ids across pages")
    func paging() async throws {
        let full = (0..<JamfFleetClient.pageSize).map { computerJSON(id: $0) }
        // Page 1 repeats the last id of page 0 (a mid-walk shift) plus two new ones.
        let transport = FleetMockTransport(replies: [
            token(),
            probeReply(),
            FleetMockTransport.Reply(json: page(total: JamfFleetClient.pageSize + 2, computers: full)),
            FleetMockTransport.Reply(json: page(total: JamfFleetClient.pageSize + 2,
                                                computers: [computerJSON(id: JamfFleetClient.pageSize - 1), computerJSON(id: 900), computerJSON(id: 901)])),
        ])
        let inventory = try await client(transport).listComputers()
        #expect(inventory.computers.count == JamfFleetClient.pageSize + 2)
        #expect(Set(inventory.computers.map(\.id)).count == inventory.computers.count)
        #expect(!inventory.truncated)
        let urls = transport.apiURLs
        #expect(urls.count == 3)
        #expect(urls[1].contains("page=0") && urls[2].contains("page=1"))
    }

    @Test("a 404 on the newest inventory version steps down at the probe only; the learned version is reused for detail")
    func versionFallback() async throws {
        let transport = FleetMockTransport(replies: [
            token(),
            FleetMockTransport.Reply(status: 404),                                                 // v4 probe
            probeReply(),                                                                          // v3 probe
            FleetMockTransport.Reply(json: page(total: 1, computers: [computerJSON(id: 1)])),     // v3 walk
            FleetMockTransport.Reply(json: computerJSON(id: 1)),                                  // v3 detail (no probe)
        ])
        let fleet = client(transport)
        let inventory = try await fleet.listComputers()
        #expect(inventory.computers.count == 1)
        _ = try await fleet.computer(id: "1")
        let urls = transport.apiURLs.compactMap { URL(string: $0)?.path }
        #expect(urls == ["/api/v4/computers-inventory", "/api/v3/computers-inventory", "/api/v3/computers-inventory",
                         "/api/v3/computers-inventory-detail/1"])
    }

    @Test("a detail 404 after the version is learned is the real thing — thrown as-is, never walked")
    func detailNotFound() async throws {
        let transport = FleetMockTransport(replies: [token(), probeReply(), FleetMockTransport.Reply(status: 404)])
        let fleet = client(transport)
        await #expect(throws: JamfError.unexpectedStatus(code: 404, endpoint: "api/v4/computers-inventory-detail/gone")) {
            _ = try await fleet.computer(id: "gone")
        }
        #expect(transport.apiURLs.count == 2)
    }

    @Test("attachment download walks v4 → v3 → v2 once, remembers the winner, and reports a later 404 on the learned path")
    func downloadFallback() async throws {
        let transport = FleetMockTransport(replies: [
            token(),
            FleetMockTransport.Reply(status: 404),                      // v4
            FleetMockTransport.Reply(body: Data("capture-bytes".utf8)),  // v3
            FleetMockTransport.Reply(body: Data("second".utf8)),         // straight to v3
            FleetMockTransport.Reply(status: 404),                      // learned v3: attachment gone
        ])
        let fleet = client(transport)
        let data = try await fleet.downloadAttachment(computerID: "7", attachmentID: "41")
        #expect(String(decoding: data, as: UTF8.self) == "capture-bytes")
        _ = try await fleet.downloadAttachment(computerID: "7", attachmentID: "42")
        await #expect(throws: JamfError.unexpectedStatus(code: 404, endpoint: "api/v3/computers-inventory/7/attachments/43")) {
            _ = try await fleet.downloadAttachment(computerID: "7", attachmentID: "43")
        }
        #expect(transport.apiURLs == [
            "https://example.jamfcloud.com/api/v4/computers-inventory/7/attachments/41",
            "https://example.jamfcloud.com/api/v3/computers-inventory/7/attachments/41",
            "https://example.jamfcloud.com/api/v3/computers-inventory/7/attachments/42",
            "https://example.jamfcloud.com/api/v3/computers-inventory/7/attachments/43",
        ])
        // Downloads accept any content type; inventory asks for JSON.
        #expect(transport.apiRequests.first?.value(forHTTPHeaderField: "Accept") == "*/*")
    }

    @Test("download seeds its version walk with the inventory's learned version")
    func downloadSeededByInventory() async throws {
        let transport = FleetMockTransport(replies: [
            token(),
            FleetMockTransport.Reply(status: 404),  // v4 probe
            probeReply(),                           // v3 probe
            FleetMockTransport.Reply(json: page(total: 1, computers: [computerJSON(id: 1)])),
            FleetMockTransport.Reply(body: Data("x".utf8)),  // download goes to v3 first
        ])
        let fleet = client(transport)
        _ = try await fleet.listComputers()
        _ = try await fleet.downloadAttachment(computerID: "1", attachmentID: "9")
        #expect(transport.apiURLs.last == "https://example.jamfcloud.com/api/v3/computers-inventory/1/attachments/9")
    }

    @Test("when every route 404s the FIRST (newest) path is reported, not a deprecated one")
    func allRoutesMissing() async throws {
        let transport = FleetMockTransport(replies: [token(), .init(status: 404), .init(status: 404), .init(status: 404)])
        await #expect(throws: JamfError.unexpectedStatus(code: 404, endpoint: "api/v4/computers-inventory/7/attachments/41")) {
            _ = try await client(transport).downloadAttachment(computerID: "7", attachmentID: "41")
        }
    }

    @Test("403 maps to insufficientPermissions naming the endpoint; 401 invalidates and maps to credentialsInvalid")
    func errorMapping() async throws {
        let forbidden = FleetMockTransport(replies: [token(), FleetMockTransport.Reply(status: 403)])
        await #expect(throws: JamfError.insufficientPermissions(endpoint: "/api/v4/computers-inventory")) {
            _ = try await client(forbidden).listComputers()
        }
        let unauthorized = FleetMockTransport(replies: [token(), FleetMockTransport.Reply(status: 401)])
        let fleet = client(unauthorized)
        await #expect(throws: JamfError.credentialsInvalid) {
            _ = try await fleet.listComputers()
        }
        // A 401 leaves nothing to invalidate — no re-authentication just to kill a token.
        await fleet.invalidateToken()
        #expect(unauthorized.requests.count == 2)
    }

    @Test("invalidateToken only calls the server when a token was actually obtained")
    func tokenInvalidation() async throws {
        let idle = FleetMockTransport(replies: [])
        await client(idle).invalidateToken()
        #expect(idle.requests.isEmpty)

        let used = FleetMockTransport(replies: [token(), probeReply(), FleetMockTransport.Reply(json: page(total: 0, computers: [])), FleetMockTransport.Reply(status: 204)])
        let fleet = client(used)
        _ = try await fleet.listComputers()
        await fleet.invalidateToken()
        #expect(used.requests.last?.url?.path.hasSuffix("api/v1/auth/invalidate-token") == true)
    }

    @Test("a capture is recognised by extension, by a mangled extension, and by the Sentinel file-name prefix; Intel bundles by theirs")
    func captureRecognition() {
        #expect(JamfAttachment(id: "1", name: "Serberus-Capture-X-20260822-101500.serberuscapture").isSerberusCapture)
        #expect(JamfAttachment(id: "2", name: "Serberus-Capture-X-20260822-101500serberuscapture").isSerberusCapture)
        #expect(JamfAttachment(id: "3", name: "renamed.SERBERUSCAPTURE").isSerberusCapture)
        #expect(!JamfAttachment(id: "4", name: "support-bundle.zip").isSerberusCapture)
        let intel = JamfAttachment(id: "5", name: "Serberus-Intel-C02X-20260822-101500Z.zip")
        #expect(intel.isSerberusIntel && intel.isSerberusUpload && !intel.isSerberusCapture)
        #expect(!JamfAttachment(id: "6", name: "photo.png").isSerberusUpload)
    }

    @Test("deleteAttachment walks the learned/seeded version, accepts 204, and reports a 404 on the newest path")
    func deleteAttachment() async throws {
        let transport = FleetMockTransport(replies: [
            token(),
            FleetMockTransport.Reply(status: 404),   // v4
            FleetMockTransport.Reply(status: 204),   // v3 — learned
            FleetMockTransport.Reply(status: 204),   // straight to v3
        ])
        let fleet = client(transport)
        try await fleet.deleteAttachment(computerID: "7", attachmentID: "41")
        try await fleet.deleteAttachment(computerID: "7", attachmentID: "42")
        #expect(transport.apiRequests.map { $0.httpMethod } == ["DELETE", "DELETE", "DELETE"])
        #expect(transport.apiURLs == [
            "https://example.jamfcloud.com/api/v4/computers-inventory/7/attachments/41",
            "https://example.jamfcloud.com/api/v3/computers-inventory/7/attachments/41",
            "https://example.jamfcloud.com/api/v3/computers-inventory/7/attachments/42",
        ])
        // A 403 (no Update Computers) maps to insufficientPermissions.
        let forbidden = FleetMockTransport(replies: [token(), FleetMockTransport.Reply(status: 403)])
        await #expect(throws: JamfError.insufficientPermissions(endpoint: "api/v4/computers-inventory/7/attachments/41")) {
            try await client(forbidden).deleteAttachment(computerID: "7", attachmentID: "41")
        }
    }
}
