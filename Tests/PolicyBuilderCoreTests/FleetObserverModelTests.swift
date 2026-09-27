import Foundation
import PrivMgrCore
import Testing
@testable import PolicyBuilderCore

private final class ScriptedTransport: HTTPTransport, @unchecked Sendable {
    struct Reply { let status: Int; let body: Data }
    private let lock = NSLock()
    private var replies: [Reply]
    private(set) var requests: [URLRequest] = []
    init(_ replies: [(Int, String)]) { self.replies = replies.map { Reply(status: $0.0, body: Data($0.1.utf8)) } }
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let reply = lock.withLock {
            requests.append(request)
            return replies.isEmpty ? Reply(status: 500, body: Data()) : replies.removeFirst()
        }
        return (reply.body, HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: nil)!)
    }
}

private let token = #"{"access_token":"T","expires_in":3600}"#
private let connection = MDMConnection(vendor: .jamf, instanceURL: "https://example.jamfcloud.com", clientID: "id", clientSecret: "s")

private func summary(id: String, name: String, serial: String? = "SER1", lastContact: Date? = Date(),
                     attachments: [JamfAttachment] = [], eas: [JamfExtensionAttributeValue] = [],
                     receipts: [String] = []) -> JamfComputerSummary {
    JamfComputerSummary(id: id, name: name, serialNumber: serial, osVersion: "26.4", username: "jdoe",
                        lastContactTime: lastContact, attachments: attachments, extensionAttributes: eas,
                        packageReceipts: receipts)
}

@MainActor
@Suite("PolicyBuilderModel — effective Jamf connection (Settings or the config profile)")
struct EffectiveJamfConnectionTests {
    @Test("the entered Settings connection wins when complete")
    func enteredWins() {
        let model = PolicyBuilderModel()
        model.mdm.instanceURL = "https://typed.jamfcloud.com"
        model.mdm.clientID = "typed-id"
        model.mdm.clientSecret = "typed-secret"
        #expect(model.effectiveJamfConnection.instanceURL == "https://typed.jamfcloud.com")
        #expect(model.effectiveJamfConnection.isComplete)
    }

    @Test("with Settings empty, the config-profile-delivered credentials are used")
    func fallsBackToProfile() {
        let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: [
                "jamfProURL": "https://managed.jamfcloud.com",
                "jamfAPIClientID": "managed-id",
                "jamfAPIClientSecret": "managed-secret",
            ],
        ]))
        let model = PolicyBuilderModel(credentialStore: JamfCredentialStore(reader: reader))
        // Nothing typed into Settings.
        #expect(!model.mdm.connection.isComplete)
        let effective = model.effectiveJamfConnection
        #expect(effective.vendor == .jamf)
        #expect(effective.instanceURL == "https://managed.jamfcloud.com")
        #expect(effective.clientID == "managed-id")
        #expect(effective.clientSecret == "managed-secret")
        #expect(effective.isComplete)
        #expect(FleetObserverModel.connectionProblem(effective) == nil)
    }

    @Test("neither source configured → incomplete, so the 'connect Jamf' guidance still fires")
    func neitherConfigured() {
        let model = PolicyBuilderModel(credentialStore: JamfCredentialStore(
            reader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:]))))
        #expect(!model.effectiveJamfConnection.isComplete)
        #expect(FleetObserverModel.connectionProblem(model.effectiveJamfConnection) != nil)
    }
}

@MainActor
@Suite("FleetObserverModel — devices, captures, posture, refresh")
struct FleetObserverModelTests {
    @Test("a device keeps only capture attachments, newest first, and Serberus-prefixed EAs as posture")
    func deviceMapping() {
        let contact = Date(timeIntervalSince1970: 1_787_000_000)
        let device = FleetDevice(summary: summary(
            id: "7", name: "MAC", lastContact: contact,
            attachments: [
                JamfAttachment(id: "a", name: "Serberus-Capture-SER1-20260820-090000.serberuscapture", sizeBytes: 10),
                JamfAttachment(id: "b", name: "photo.png"),
                JamfAttachment(id: "c", name: "Serberus-Capture-SER1-20260822-101500.serberuscapture", sizeBytes: 20),
            ],
            eas: [
                JamfExtensionAttributeValue(definitionID: "1", name: "Serberus — State", values: ["enforce"]),
                JamfExtensionAttributeValue(definitionID: "2", name: "Battery", values: ["ok"]),
                JamfExtensionAttributeValue(definitionID: "3", name: "Serberus — Daemon", values: ["3.8"]),
            ]))
        #expect(device.attachmentCount == 3)
        #expect(device.captures.map(\.id) == ["c", "a"])
        #expect(device.captures.first?.recordedAt != nil)
        #expect(device.captures.first?.deviceName == "MAC")
        #expect(device.captures.first?.serialNumber == "SER1")
        // State ranks ahead of the non-trio "Daemon" EA on the card.
        #expect(device.posture.map(\.name) == ["Serberus — State", "Serberus — Daemon"])
        #expect(device.posture.map(\.value) == ["enforce", "3.8"])
        #expect(FleetDevice.postureRank("Serberus — Last Upload") > FleetDevice.postureRank("Serberus — Version"))
        #expect(FleetDevice.postureRank("Serberus — Mode") < FleetDevice.postureRank("Serberus — Uploads"))
        // Any naming convention: an admin's EA_Serberus_<Purpose>, em-dash, colon, shouting.
        for name in ["EA_Serberus_State", "Serberus — State", "serberus: state", "SERBERUS_STATE", "EA Serberus State"] {
            #expect(FleetDevice.isSerberusEAName(name), "\(name)")
            #expect(FleetDevice.postureKey(name) == "state", "\(name)")
            #expect(FleetDevice.postureLabel(name) == "State", "\(name)")
            #expect(FleetDevice.postureRank(name) == 0, "\(name)")
        }
        #expect(FleetDevice.postureLabel("EA_Serberus_Last_Upload") == "Last Upload")
        #expect(FleetDevice.postureKey("EA_Serberus_Daemon_Version") == "daemon version")
        #expect(FleetDevice.postureRank("EA_Serberus_Daemon_Version") == 2)      // "…version" tail still ranks
        #expect(!FleetDevice.isSerberusEAName("EA_Battery_Health"))
        let convention = FleetDevice(summary: summary(id: "9", name: "HJ",
            eas: [JamfExtensionAttributeValue(definitionID: "1", name: "EA_Serberus_Uploads", values: ["none"]),
                  JamfExtensionAttributeValue(definitionID: "2", name: "EA_Serberus_State", values: ["healthy"]),
                  JamfExtensionAttributeValue(definitionID: "3", name: "EA_Battery_Health", values: ["ok"])]))
        #expect(convention.posture.map(\.label) == ["State", "Uploads"])
        #expect(convention.hasSerberus)
        #expect(convention.serberusEvidence == ["EA EA_Serberus_State = healthy"])
        // Synthesized equality covers every displayed field (no hand-written ==).
        #expect(device == FleetDevice(summary: summary(id: "7", name: "MAC", lastContact: contact,
            attachments: [JamfAttachment(id: "a", name: "Serberus-Capture-SER1-20260820-090000.serberuscapture", sizeBytes: 10),
                          JamfAttachment(id: "b", name: "photo.png"),
                          JamfAttachment(id: "c", name: "Serberus-Capture-SER1-20260822-101500.serberuscapture", sizeBytes: 20)],
            eas: [JamfExtensionAttributeValue(definitionID: "1", name: "Serberus — State", values: ["enforce"]),
                  JamfExtensionAttributeValue(definitionID: "2", name: "Battery", values: ["ok"]),
                  JamfExtensionAttributeValue(definitionID: "3", name: "Serberus — Daemon", values: ["3.8"])])))
    }

    @Test("freshness buckets by last contact")
    func freshness() {
        let now = Date()
        #expect(FleetDevice(summary: summary(id: "1", name: "a", lastContact: now.addingTimeInterval(-3600))).freshness(now: now) == .fresh)
        #expect(FleetDevice(summary: summary(id: "2", name: "b", lastContact: now.addingTimeInterval(-3 * 86_400))).freshness(now: now) == .stale)
        #expect(FleetDevice(summary: summary(id: "3", name: "c", lastContact: now.addingTimeInterval(-30 * 86_400))).freshness(now: now) == .offline)
        #expect(FleetDevice(summary: summary(id: "4", name: "d", lastContact: nil)).freshness(now: now) == .unknown)
    }

    @Test("capture time parses from the Sentinel file name; a renamed file has none; save names keep the extension")
    func captureNames() {
        let parsed = FleetUpload.recordedAt(fromFileName: "Serberus-Capture-C02X-20260822-101500.serberuscapture")
        #expect(parsed != nil)
        #expect(FleetUpload.recordedAt(fromFileName: "renamed.serberuscapture") == nil)
        let mangled = FleetUpload(id: "1", kind: .capture, computerID: "7", deviceName: "M", serialNumber: nil,
                                  fileName: "Serberus-Capture-C02X-20260822-101500serberuscapture", sizeBytes: nil, recordedAt: nil)
        #expect(mangled.suggestedSaveName == "Serberus-Capture-C02X-20260822-101500.serberuscapture")
        let fine = FleetUpload(id: "2", kind: .capture, computerID: "7", deviceName: "M", serialNumber: nil,
                               fileName: "x.serberuscapture", sizeBytes: nil, recordedAt: nil)
        #expect(fine.suggestedSaveName == "x.serberuscapture")
        let renamed = FleetUpload(id: "3", kind: .capture, computerID: "7", deviceName: "M", serialNumber: nil,
                                  fileName: "notes.txt", sizeBytes: nil, recordedAt: nil)
        #expect(renamed.suggestedSaveName == "notes.txt.serberuscapture")
        // Intel bundles keep .zip and stamp UTC (trailing Z) — parsed as UTC.
        let intel = FleetUpload(id: "4", kind: .intel, computerID: "7", deviceName: "M", serialNumber: nil,
                                fileName: "Serberus-Intel-C02X-20260822-101500Z.zip", sizeBytes: nil,
                                recordedAt: FleetUpload.recordedAt(fromFileName: "Serberus-Intel-C02X-20260822-101500Z.zip"))
        #expect(intel.suggestedSaveName == "Serberus-Intel-C02X-20260822-101500Z.zip")
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = TimeZone(identifier: "UTC")!
        #expect(intel.recordedAt.map { utc.component(.hour, from: $0) } == 10)
    }

    @Test("connectionProblem explains an incomplete, non-Jamf, or scheme-less connection")
    func connectionProblems() {
        #expect(FleetObserverModel.connectionProblem(connection) == nil)
        #expect(FleetObserverModel.connectionProblem(MDMConnection(vendor: .jamf, instanceURL: "", clientID: "", clientSecret: ""))?.contains("Settings") == true)
        #expect(FleetObserverModel.connectionProblem(MDMConnection(vendor: .intune, instanceURL: "https://graph.microsoft.com", clientID: "a", clientSecret: "b"))?.contains("Jamf Pro only") == true)
        #expect(FleetObserverModel.connectionProblem(MDMConnection(vendor: .jamf, instanceURL: "yourcompany.jamfcloud.com", clientID: "a", clientSecret: "b"))?.contains("https://") == true)
    }

    @Test("an oversize capture is refused before any byte moves; the walk's page cap is reported as truncated")
    func sizeGate() async {
        let transport = ScriptedTransport([])
        let model = FleetObserverModel(transport: transport)
        let huge = FleetUpload(id: "1", kind: .capture, computerID: "7", deviceName: "M", serialNumber: nil,
                               fileName: "Serberus-Capture-X.serberuscapture", sizeBytes: RuleCapture.maxEncodedBytes + 1, recordedAt: nil)
        await #expect(throws: FleetCaptureError.tooLarge(fileName: "Serberus-Capture-X.serberuscapture",
                                                         bytes: RuleCapture.maxEncodedBytes + 1, limit: RuleCapture.maxEncodedBytes)) {
            _ = try await model.downloadUpload(huge, connection: connection)
        }
        #expect(transport.requests.isEmpty)
        #expect(model.downloading.isEmpty)
    }

    @Test("needsLoad: first visit, and again after the connection changes; never mid-load")
    func needsLoad() async {
        let inventory = #"{"totalCount":0,"results":[]}"#
        let transport = ScriptedTransport([(200, token), (200, inventory), (200, inventory), (204, "")])
        let model = FleetObserverModel(transport: transport)
        #expect(model.needsLoad(for: connection))
        await model.refresh(connection: connection)
        #expect(model.state == .loaded)
        #expect(!model.needsLoad(for: connection))
        let other = MDMConnection(vendor: .jamf, instanceURL: "https://other.jamfcloud.com", clientID: "id", clientSecret: "s")
        #expect(model.needsLoad(for: other))
    }

    @Test("refresh loads devices and aggregates captures fleet-wide; a failure keeps the old fleet and reports why")
    func refreshAndFailure() async {
        let inventory = """
        {"totalCount":2,"results":[
          {"id":"1","general":{"name":"A","lastContactTime":"2026-08-22T10:00:00Z"},"hardware":{"serialNumber":"S1"},
           "attachments":[{"id":"10","name":"Serberus-Capture-S1-20260822-101500.serberuscapture","sizeBytes":5}]},
          {"id":"2","general":{"name":"B"},"hardware":{"serialNumber":"S2"},
           "attachments":[{"id":"20","name":"Serberus-Capture-S2-20260821-080000.serberuscapture","sizeBytes":6},{"id":"21","name":"notes.txt"}]}
        ]}
        """
        // probe (1-item page) + the walk, then invalidate; second refresh: probe already learned → walk 403.
        let transport = ScriptedTransport([(200, token), (200, inventory), (200, inventory), (204, ""), (200, token), (403, ""), (204, "")])
        let model = FleetObserverModel(transport: transport)
        #expect(model.state == .idle)
        await model.refresh(connection: connection)
        #expect(model.state == .loaded)
        #expect(model.devices.map(\.id) == ["1", "2"])
        #expect(model.uploads.map(\.id) == ["10", "20"])
        #expect(model.devicesWithUploads == 2)
        #expect(model.lastRefreshed != nil)
        // The token was invalidated server-side after the refresh.
        #expect(transport.requests.contains { $0.url?.path.hasSuffix("auth/invalidate-token") == true })

        await model.refresh(connection: connection)
        guard case .failed(let reason) = model.state else { Issue.record("expected failure"); return }
        #expect(reason.contains("Read Computers"))
        #expect(model.devices.count == 2) // stale fleet stays visible
    }

    @Test("an incomplete connection fails fast without touching the network")
    func incompleteConnection() async {
        let transport = ScriptedTransport([])
        let model = FleetObserverModel(transport: transport)
        await model.refresh(connection: MDMConnection(vendor: .jamf, instanceURL: "", clientID: "", clientSecret: ""))
        guard case .failed = model.state else { Issue.record("expected failure"); return }
        #expect(transport.requests.isEmpty)
    }

    @Test("fetchCapture downloads, validates, and rejects non-capture bytes with a typed error")
    func fetchCapture() async throws {
        let capture = FleetUpload(id: "10", kind: .capture, computerID: "1", deviceName: "A", serialNumber: "S1",
                                  fileName: "x.serberuscapture", sizeBytes: 3, recordedAt: nil)
        let bad = ScriptedTransport([(200, token), (200, "not json"), (204, "")])
        let model = FleetObserverModel(transport: bad)
        do {
            _ = try await model.fetchCapture(capture, connection: connection)
            Issue.record("expected a decode failure")
        } catch let error as FleetCaptureError {
            guard case .invalidCapture(let name, _) = error else { Issue.record("wrong case"); return }
            #expect(name == "x.serberuscapture")
            #expect(FleetObserverModel.describe(error).contains("not a valid capture"))
        }
        #expect(model.downloading.isEmpty)
        #expect(model.importing.isEmpty)
        #expect(model.lastError == nil) // throwing paths never leave a stale side-channel error
    }

    @Test("Intel bundles are uploads too (kind .intel), never importable, and a delete drops them from the device")
    func intelUploadsAndDelete() async throws {
        let device = FleetDevice(summary: summary(
            id: "7", name: "MAC",
            attachments: [
                JamfAttachment(id: "a", name: "Serberus-Capture-SER1-20260820-090000.serberuscapture", sizeBytes: 10),
                JamfAttachment(id: "z", name: "Serberus-Intel-SER1-20260822-101500Z.zip", sizeBytes: 5_000),
                JamfAttachment(id: "b", name: "photo.png"),
            ]))
        #expect(device.uploads.map(\.id) == ["z", "a"])          // newest first (intel is newer)
        #expect(device.captures.map(\.id) == ["a"])
        #expect(device.intelBundles.map(\.id) == ["z"])
        #expect(device.removingUpload(id: "z").uploads.map(\.id) == ["a"])
        #expect(device.removingUpload(id: "z").attachmentCount == 2)

        // Importing an Intel bundle is refused without touching the network.
        let intel = device.intelBundles[0]
        let quiet = ScriptedTransport([])
        let model = FleetObserverModel(transport: quiet)
        await #expect(throws: FleetCaptureError.self) {
            _ = try await model.fetchCapture(intel, connection: connection)
        }
        #expect(quiet.requests.isEmpty)

        // Delete: token, DELETE (204), invalidate — then the device loses the upload.
        let inventory = """
        {"totalCount":1,"results":[{"id":"7","general":{"name":"MAC"},"hardware":{"serialNumber":"SER1"},
          "attachments":[{"id":"a","name":"Serberus-Capture-SER1-20260820-090000.serberuscapture"},{"id":"z","name":"Serberus-Intel-SER1-20260822-101500Z.zip"}]}]}
        """
        let transport = ScriptedTransport([(200, token), (200, inventory), (200, inventory), (204, ""), (200, token), (204, ""), (204, "")])
        let fleet = FleetObserverModel(transport: transport)
        await fleet.refresh(connection: connection)
        #expect(fleet.uploads.count == 2)
        let target = try #require(fleet.device(id: "7")?.intelBundles.first)
        try await fleet.deleteUpload(target, connection: connection)
        #expect(fleet.device(id: "7")?.uploads.map(\.id) == ["a"])
        #expect(fleet.deleting.isEmpty)
        let deleteRequest = try #require(transport.requests.first { $0.httpMethod == "DELETE" })
        #expect(deleteRequest.url?.path.hasSuffix("/computers-inventory/7/attachments/z") == true)
    }

    @Test("a Mac counts as Serberus-installed on EA value, package receipt, or upload — and not on an EA that says 'not installed'")
    func serberusEvidence() {
        let bare = FleetDevice(summary: summary(id: "1", name: "plain"))
        #expect(!bare.hasSerberus)
        let eaOnly = FleetDevice(summary: summary(id: "2", name: "ea",
            eas: [JamfExtensionAttributeValue(definitionID: "1", name: "Serberus — State", values: ["healthy"])]))
        #expect(eaOnly.hasSerberus)
        #expect(eaOnly.serberusEvidence == ["EA Serberus — State = healthy"])
        let absent = FleetDevice(summary: summary(id: "3", name: "absent",
            eas: [JamfExtensionAttributeValue(definitionID: "1", name: "Serberus — State", values: ["not installed"]),
                  JamfExtensionAttributeValue(definitionID: "2", name: "Serberus — Uploads", values: ["none"])]))
        #expect(!absent.hasSerberus)
        let receipt = FleetDevice(summary: summary(id: "4", name: "pkg", receipts: ["com.apple.pkg.Safari", "SerberusSentinelAgent-3.8.pkg"]))
        #expect(receipt.serberusEvidence == ["package SerberusSentinelAgent-3.8.pkg"])
        #expect(receipt.hasInstallEvidence)
        // A pkgutil-only receipt (manual / PreStage install) counts too.
        let pkgutilOnly = FleetDevice(summary: summary(id: "4b", name: "manual", receipts: ["com.herojoneslabs.serberus.sentineltestpkg"]))
        #expect(pkgutilOnly.hasSerberus)
        // The uninstaller's own receipt is not evidence, and an explicit "not installed" State EA
        // vetoes stale Jamf receipt stubs (receipts are history; the EA is current).
        let uninstalled = FleetDevice(summary: summary(id: "4c", name: "gone",
            eas: [JamfExtensionAttributeValue(definitionID: "1", name: "EA_Serberus_State", values: ["not installed"])],
            receipts: ["SerberusSentinelAgent-3.8.pkg", "SerberusUninstall-1.0.pkg"]))
        #expect(!uninstalled.hasSerberus)
        let onlyUninstaller = FleetDevice(summary: summary(id: "4d", name: "only-uninstaller", receipts: ["SerberusUninstall-1.0.pkg"]))
        #expect(!onlyUninstaller.hasSerberus)
        let uploaded = FleetDevice(summary: summary(id: "5", name: "up",
            attachments: [JamfAttachment(id: "a", name: "Serberus-Capture-S-20260822-101500.serberuscapture")]))
        #expect(uploaded.hasSerberus)
        #expect(uploaded.serberusEvidence.first?.contains("upload") == true)

        let model = FleetObserverModel(transport: ScriptedTransport([]))
        #expect(model.serberusDevices.isEmpty && model.otherDeviceCount == 0)
    }

    @Test("serberusDevices / otherDeviceCount split the fetched fleet")
    func fleetScope() async {
        let inventory = """
        {"totalCount":3,"results":[
          {"id":"1","general":{"name":"A"},"packageReceipts":{"installedByInstallerSwu":["com.herojoneslabs.serberus.sentineltestpkg"]}},
          {"id":"2","general":{"name":"B"},"extensionAttributes":[{"definitionId":"9","name":"Serberus — State","values":["not installed"]}]},
          {"id":"3","general":{"name":"C"},"attachments":[{"id":"10","name":"Serberus-Intel-S3-20260822-101500Z.zip"}]}
        ]}
        """
        let transport = ScriptedTransport([(200, token), (200, inventory), (200, inventory), (204, "")])
        let model = FleetObserverModel(transport: transport)
        await model.refresh(connection: connection)
        #expect(model.devices.count == 3)
        #expect(model.serberusDevices.map(\.id) == ["1", "3"])
        #expect(model.otherDeviceCount == 1)
    }
}
