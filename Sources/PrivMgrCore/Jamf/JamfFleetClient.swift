import Foundation

// MARK: - Fleet inventory models

/// One file attached to a Jamf computer record (Jamf → computer → Attachments
/// tab). Sentinel's Capture upload lands here as a `.serberuscapture`.
public struct JamfAttachment: Sendable, Equatable, Identifiable, Hashable {
    public let id: String
    public let name: String
    public let fileType: String?
    public let sizeBytes: Int?

    public init(id: String, name: String, fileType: String? = nil, sizeBytes: Int? = nil) {
        self.id = id
        self.name = name
        self.fileType = fileType
        self.sizeBytes = sizeBytes
    }

    /// Whether this attachment is a Serberus capture (by extension, or by the
    /// Sentinel's file-name prefix for a capture whose extension was mangled
    /// on the way through Jamf — observed in testing: the "." before `serberuscapture`
    /// dropped).
    public var isSerberusCapture: Bool {
        let lower = name.lowercased()
        return lower.hasSuffix(".\(RuleCapture.fileExtension)")
            || lower.hasSuffix(RuleCapture.fileExtension)
            || lower.hasPrefix("serberus-capture-")
    }

    /// Whether this attachment is an Intel support bundle the Sentinel
    /// uploaded (`Serberus-Intel-<serial>-<timestamp>.zip`).
    public var isSerberusIntel: Bool {
        name.lowercased().hasPrefix("serberus-intel-")
    }

    /// Any file the Sentinel uploads — the set Commander harvests.
    public var isSerberusUpload: Bool { isSerberusCapture || isSerberusIntel }
}

/// One extension-attribute value on a computer record.
public struct JamfExtensionAttributeValue: Sendable, Equatable, Hashable {
    public let definitionID: String?
    public let name: String
    public let values: [String]

    public init(definitionID: String?, name: String, values: [String]) {
        self.definitionID = definitionID
        self.name = name
        self.values = values
    }
}

/// A computer as Commander's Fleet Observer needs it — the handful of
/// inventory fields worth a card, plus attachments (captures) and extension
/// attributes (Serberus posture, when the org deploys the EA). Keyed by the
/// Jamf computer id for THIS refresh; the serial is the durable identity.
public struct JamfComputerSummary: Sendable, Equatable, Identifiable, Hashable {
    public let id: String
    public let name: String
    public let serialNumber: String?
    public let model: String?
    public let modelIdentifier: String?
    public let osVersion: String?
    public let osBuild: String?
    public let username: String?
    public let realName: String?
    public let email: String?
    /// `general.lastContact` (v4) / `general.lastContactTime` (v2, v3) — the
    /// last time the Mac talked to Jamf.
    public let lastContactTime: Date?
    public let lastEnrolledDate: Date?
    public let managed: Bool?
    public let attachments: [JamfAttachment]
    public let extensionAttributes: [JamfExtensionAttributeValue]
    /// Installed package receipts / Jamf-installed package names
    /// (`PACKAGE_RECEIPTS`: `installedByJamfPro` = Jamf-policy package names,
    /// `installedByInstallerSwu` = pkgutil receipt ids) — how Commander tells a
    /// Serberus Mac from the rest of the fleet when no Serberus EA has been
    /// collected yet. `cached` (Waiting Room) is deliberately not included.
    public let packageReceipts: [String]

    public init(
        id: String,
        name: String,
        serialNumber: String? = nil,
        model: String? = nil,
        modelIdentifier: String? = nil,
        osVersion: String? = nil,
        osBuild: String? = nil,
        username: String? = nil,
        realName: String? = nil,
        email: String? = nil,
        lastContactTime: Date? = nil,
        lastEnrolledDate: Date? = nil,
        managed: Bool? = nil,
        attachments: [JamfAttachment] = [],
        extensionAttributes: [JamfExtensionAttributeValue] = [],
        packageReceipts: [String] = []
    ) {
        self.id = id
        self.name = name
        self.serialNumber = serialNumber
        self.model = model
        self.modelIdentifier = modelIdentifier
        self.osVersion = osVersion
        self.osBuild = osBuild
        self.username = username
        self.realName = realName
        self.email = email
        self.lastContactTime = lastContactTime
        self.lastEnrolledDate = lastEnrolledDate
        self.managed = managed
        self.attachments = attachments
        self.extensionAttributes = extensionAttributes
        self.packageReceipts = packageReceipts
    }

    public var captures: [JamfAttachment] { attachments.filter(\.isSerberusCapture) }
    /// Every Sentinel upload on the record (captures + Intel bundles).
    public var uploads: [JamfAttachment] { attachments.filter(\.isSerberusUpload) }
}

/// The result of one inventory walk: every computer (de-duplicated, newest
/// contact first) plus what Jamf said the total was, so a fleet larger than
/// ``JamfFleetClient/maxPages`` × ``JamfFleetClient/pageSize`` is reported as
/// truncated instead of passing for complete.
public struct JamfInventory: Sendable, Equatable {
    public let computers: [JamfComputerSummary]
    public let totalCount: Int
    /// True when the page cap stopped the walk before `totalCount` was reached.
    public let truncated: Bool

    public init(computers: [JamfComputerSummary], totalCount: Int, truncated: Bool) {
        self.computers = computers
        self.totalCount = totalCount
        self.truncated = truncated
    }
}

// MARK: - Client

/// Read-only Jamf Pro client for Commander's Fleet Observer: the computer
/// inventory (paged, with the sections a fleet card needs), one computer's
/// detail, and attachment download (the Capture hand-off from Sentinel, in
/// reverse). Same OAuth / transport / error mapping as ``JamfAPIClient``;
/// kept separate because the inventory API is versioned independently and
/// this surface needs only **Read Computers**.
///
/// Jamf's inventory API is versioned per resource (`/api/v2|v3|v4/
/// computers-inventory`) and the current version moves; older ones live on
/// for a year then 404. Rather than hard-code one, the client PROBES once per
/// session — newest first, against the collection (where a 404 can only mean
/// "no such route", never "no such computer") — remembers the winner, and
/// then issues every real request exactly once on it. Attachment download
/// walks the same family (v4 → v3 → v2), seeded with the inventory's answer.
public actor JamfFleetClient {
    /// Inventory sections a fleet card needs. `ATTACHMENTS` makes captures
    /// visible across the whole fleet in ONE paged call instead of a detail
    /// call per computer.
    public static let sections = ["GENERAL", "HARDWARE", "OPERATING_SYSTEM", "USER_AND_LOCATION",
                                  "EXTENSION_ATTRIBUTES", "ATTACHMENTS", "PACKAGE_RECEIPTS"]
    /// Jamf's practical page-size ceiling for inventory (larger can time out).
    public static let pageSize = 100
    /// Hard stop on paging — 50 × 100 = 5,000 computers, far above the fleet.
    /// A walk that hits it reports ``JamfInventory/truncated``.
    public static let maxPages = 50
    /// Paging key: stable across the walk (a new enrolment lands after it,
    /// a check-in does not reorder anything). The fleet is then sorted newest
    /// contact first on the client — `general.lastContact` (v4) is spelled
    /// `lastContactTime` on v2/v3, so a server sort would be version-specific.
    static let pagingSort = "id:asc"

    /// Newest first; v1 is past Jamf's one-year deprecation window and omitted.
    static let inventoryVersions = ["v4", "v3", "v2"]
    static let attachmentVersions = ["v4", "v3", "v2"]

    private let credentialStore: JamfCredentialStore
    private let tokenManager: JamfTokenManager
    private let transport: HTTPTransport
    /// Learned per session: the first inventory version whose collection answered.
    private var inventoryVersion: String?
    /// Learned per session: the first attachment route version that answered.
    private var attachmentVersion: String?
    private var didObtainToken = false

    public init(
        credentialStore: JamfCredentialStore = JamfCredentialStore(),
        tokenManager: JamfTokenManager? = nil,
        transport: HTTPTransport = URLSessionTransport()
    ) {
        self.credentialStore = credentialStore
        self.transport = transport
        self.tokenManager = tokenManager ?? JamfTokenManager(credentialStore: credentialStore, transport: transport)
    }

    // MARK: Inventory

    /// Every computer in the instance (up to ``maxPages`` × ``pageSize``),
    /// de-duplicated by id and sorted newest contact first. Throws the first
    /// hard error; a partial fleet is never returned silently (a capped walk
    /// is flagged ``JamfInventory/truncated``).
    public func listComputers() async throws -> JamfInventory {
        let version = try await resolveInventoryVersion()
        var all: [JamfComputerSummary] = []
        var seen = Set<String>()
        var totalCount = 0
        var page = 0
        var hitCap = true
        while page < Self.maxPages {
            let url = try inventoryURL(version: version, page: page, pageSize: Self.pageSize)
            let data = try await send(method: "GET", url: url, path: url.path)
            let decoded = try Self.decode(InventoryPage.self, from: data, endpoint: "computers-inventory")
            totalCount = decoded.totalCount
            for record in decoded.results {
                let summary = Self.summary(record)
                if seen.insert(summary.id).inserted { all.append(summary) }
            }
            // Stop when the page was short or we have everything Jamf counted.
            if decoded.results.count < Self.pageSize || all.count >= decoded.totalCount {
                hitCap = false
                break
            }
            page += 1
        }
        all.sort { ($0.lastContactTime ?? .distantPast) > ($1.lastContactTime ?? .distantPast) }
        return JamfInventory(computers: all, totalCount: totalCount, truncated: hitCap && all.count < totalCount)
    }

    /// One computer's full record (always carries its attachments, whether or
    /// not the list request could include the `ATTACHMENTS` section). A 404
    /// here means the computer is gone (re-enrolled, deleted) — it is thrown
    /// as-is, never mistaken for a missing route.
    public func computer(id: String) async throws -> JamfComputerSummary {
        let version = try await resolveInventoryVersion()
        let path = "api/\(version)/computers-inventory-detail/\(id)"
        let data = try await send(method: "GET", url: try baseURL().appendingPathComponent(path), path: path)
        let record = try Self.decode(ComputerRecord.self, from: data, endpoint: "computers-inventory-detail")
        return Self.summary(record)
    }

    // MARK: Attachments

    /// Downloads one attachment's bytes (e.g. a `.serberuscapture`). The route
    /// version is walked newest-first ONLY until one answers (seeded with the
    /// inventory's learned version); once learned, a 404 is the real thing
    /// (attachment removed) and is reported on the newest path.
    public func downloadAttachment(computerID: String, attachmentID: String) async throws -> Data {
        let candidates: [String]
        if let learned = attachmentVersion {
            candidates = [learned]
        } else if let seed = inventoryVersion {
            candidates = [seed] + Self.attachmentVersions.filter { $0 != seed }
        } else {
            candidates = Self.attachmentVersions
        }
        var firstError: Error?
        for version in candidates {
            let path = "api/\(version)/computers-inventory/\(computerID)/attachments/\(attachmentID)"
            do {
                let data = try await send(method: "GET", url: try baseURL().appendingPathComponent(path),
                                          path: path, accept: "*/*")
                attachmentVersion = version
                return data
            } catch JamfError.unexpectedStatus(let code, let endpoint) where code == 404 {
                if firstError == nil { firstError = JamfError.unexpectedStatus(code: code, endpoint: endpoint) }
                continue
            }
        }
        throw firstError ?? JamfError.unexpectedStatus(code: 404, endpoint: "computers-inventory/attachments")
    }

    /// Removes one attachment from the computer record — Commander calls
    /// this after it has downloaded (and kept) the file, so the record does
    /// not accumulate harvested uploads. Needs the **Update Computers**
    /// privilege. Same version walk as download.
    public func deleteAttachment(computerID: String, attachmentID: String) async throws {
        let candidates: [String]
        if let learned = attachmentVersion {
            candidates = [learned]
        } else if let seed = inventoryVersion {
            candidates = [seed] + Self.attachmentVersions.filter { $0 != seed }
        } else {
            candidates = Self.attachmentVersions
        }
        var firstError: Error?
        for version in candidates {
            let path = "api/\(version)/computers-inventory/\(computerID)/attachments/\(attachmentID)"
            do {
                _ = try await send(method: "DELETE", url: try baseURL().appendingPathComponent(path), path: path)
                attachmentVersion = version
                return
            } catch JamfError.unexpectedStatus(let code, let endpoint) where code == 404 {
                if firstError == nil { firstError = JamfError.unexpectedStatus(code: code, endpoint: endpoint) }
                continue
            }
        }
        throw firstError ?? JamfError.unexpectedStatus(code: 404, endpoint: "computers-inventory/attachments")
    }

    // MARK: Token hygiene

    /// Invalidates the bearer token server-side (best effort) and locally —
    /// the Intel uploader's contract, so a Fleet refresh never leaves a live
    /// token holding a Jamf connection. Call after a refresh completes.
    public func invalidateToken() async {
        guard didObtainToken else { return }
        if let credentials = try? credentialStore.credentials(),
           let token = try? await tokenManager.token() {
            var request = URLRequest(url: credentials.serverURL.appendingPathComponent("api/v1/auth/invalidate-token"))
            request.httpMethod = "POST"
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            _ = try? await transport.send(request)
        }
        await tokenManager.invalidate()
        didObtainToken = false
    }

    // MARK: Version probe + request plumbing

    /// The inventory version this instance serves, probed once per session
    /// against the collection with a 1-item page (a 404 there is a missing
    /// route, never a missing computer). Newest first.
    private func resolveInventoryVersion() async throws -> String {
        if let inventoryVersion { return inventoryVersion }
        var firstError: Error?
        for version in Self.inventoryVersions {
            let url = try inventoryURL(version: version, page: 0, pageSize: 1, sections: ["GENERAL"])
            do {
                _ = try await send(method: "GET", url: url, path: url.path)
                inventoryVersion = version
                return version
            } catch JamfError.unexpectedStatus(let code, let endpoint) where code == 404 {
                if firstError == nil { firstError = JamfError.unexpectedStatus(code: code, endpoint: endpoint) }
                continue
            }
        }
        throw firstError ?? JamfError.unexpectedStatus(code: 404, endpoint: "computers-inventory")
    }

    private func inventoryURL(version: String, page: Int, pageSize: Int, sections: [String] = sections) throws -> URL {
        var components = URLComponents(
            url: try baseURL().appendingPathComponent("api/\(version)/computers-inventory"),
            resolvingAgainstBaseURL: false)
        var items = sections.map { URLQueryItem(name: "section", value: $0) }
        items.append(URLQueryItem(name: "page", value: String(page)))
        items.append(URLQueryItem(name: "page-size", value: String(pageSize)))
        items.append(URLQueryItem(name: "sort", value: Self.pagingSort))
        components?.queryItems = items
        guard let url = components?.url else {
            throw JamfError.unreachable(underlying: "could not build the inventory URL")
        }
        return url
    }

    private func baseURL() throws -> URL {
        try credentialStore.credentials().serverURL
    }

    private func send(method: String, url: URL, path: String, accept: String = "application/json") async throws -> Data {
        let token = try await tokenManager.token()
        didObtainToken = true
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(accept, forHTTPHeaderField: "Accept")

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
            // The token is dead server-side already — nothing to invalidate
            // later (and never re-authenticate just to kill a token).
            await tokenManager.invalidate()
            didObtainToken = false
            throw JamfError.credentialsInvalid
        case 403:
            throw JamfError.insufficientPermissions(endpoint: path)
        default:
            throw JamfError.unexpectedStatus(code: response.statusCode, endpoint: path)
        }
    }

    // MARK: Decoding (lenient — every section optional)

    struct InventoryPage: Decodable {
        let totalCount: Int
        let results: [ComputerRecord]
    }

    struct ComputerRecord: Decodable {
        struct General: Decodable {
            let name: String?
            /// v4 (`ComputerGeneralV4`).
            let lastContact: String?
            /// v2 / v3.
            let lastContactTime: String?
            /// v4 — the last check-in (policy), a fallback when contact is absent.
            let lastCheckIn: String?
            let lastEnrolledDate: String?
            let remoteManagement: RemoteManagement?
            struct RemoteManagement: Decodable { let managed: Bool? }
        }
        struct Hardware: Decodable {
            let serialNumber: String?
            let model: String?
            let modelIdentifier: String?
        }
        struct OperatingSystem: Decodable {
            let version: String?
            let build: String?
        }
        struct UserAndLocation: Decodable {
            let username: String?
            let realname: String?
            let email: String?
        }
        struct ExtensionAttribute: Decodable {
            let definitionId: String?
            let name: String?
            let values: [String]?
        }
        struct Attachment: Decodable {
            let id: String
            let name: String
            let fileType: String?
            let sizeBytes: Int?
        }
        struct PackageReceipts: Decodable {
            let installedByJamfPro: [String]?
            /// Jamf's spelling of "installed by Installer / software update"
            /// — pinned so a refactor cannot silently stop decoding it.
            let installedByInstallerSwu: [String]?
            enum CodingKeys: String, CodingKey {
                case installedByJamfPro
                case installedByInstallerSwu
            }
        }
        let id: String
        let general: General?
        let hardware: Hardware?
        let operatingSystem: OperatingSystem?
        let userAndLocation: UserAndLocation?
        let extensionAttributes: [ExtensionAttribute]?
        let attachments: [Attachment]?
        let packageReceipts: PackageReceipts?
    }

    static func summary(_ record: ComputerRecord) -> JamfComputerSummary {
        let contact = record.general?.lastContact ?? record.general?.lastContactTime ?? record.general?.lastCheckIn
        return JamfComputerSummary(
            id: record.id,
            name: record.general?.name ?? record.hardware?.serialNumber ?? record.id,
            serialNumber: record.hardware?.serialNumber,
            model: record.hardware?.model,
            modelIdentifier: record.hardware?.modelIdentifier,
            osVersion: record.operatingSystem?.version,
            osBuild: record.operatingSystem?.build,
            username: record.userAndLocation?.username,
            realName: record.userAndLocation?.realname,
            email: record.userAndLocation?.email,
            lastContactTime: contact.flatMap(Self.date),
            lastEnrolledDate: record.general?.lastEnrolledDate.flatMap(Self.date),
            managed: record.general?.remoteManagement?.managed,
            attachments: (record.attachments ?? []).map {
                JamfAttachment(id: $0.id, name: $0.name, fileType: $0.fileType, sizeBytes: $0.sizeBytes)
            },
            extensionAttributes: (record.extensionAttributes ?? []).compactMap {
                guard let name = $0.name else { return nil }
                return JamfExtensionAttributeValue(definitionID: $0.definitionId, name: name, values: $0.values ?? [])
            },
            packageReceipts: (record.packageReceipts?.installedByJamfPro ?? []) + (record.packageReceipts?.installedByInstallerSwu ?? [])
        )
    }

    /// Jamf emits ISO-8601 with fractional seconds (`2026-08-22T12:34:56.789Z`);
    /// accept the plain form too.
    static func date(_ string: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: string) { return date }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: string)
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data, endpoint: String) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw JamfError.responseDecodingFailed(endpoint: endpoint, reason: String(describing: error))
        }
    }
}
