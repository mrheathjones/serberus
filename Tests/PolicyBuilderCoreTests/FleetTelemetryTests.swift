import Foundation
import PrivMgrCore
import Testing
@testable import PolicyBuilderCore

// Fleet telemetry: the daemon publishes decision counts via
// Jamf EAs; FleetDevice types them (postureInt) and FleetObserverModel sums them
// across the Serberus fleet for the Dashboard's enforcement tiles.

private func ea(_ name: String, _ value: String) -> JamfExtensionAttributeValue {
    JamfExtensionAttributeValue(definitionID: name, name: name, values: [value])
}

private func summary(id: String, name: String, eas: [JamfExtensionAttributeValue]) -> JamfComputerSummary {
    JamfComputerSummary(id: id, name: name, serialNumber: "S\(id)", osVersion: "26.4", username: "jdoe",
                        lastContactTime: Date(), attachments: [], extensionAttributes: eas, packageReceipts: [])
}

@Suite("FleetDevice.postureInt (fleet telemetry EA typing)")
struct FleetDevicePostureIntTests {
    @Test("parses clean integers from the telemetry EAs across naming conventions")
    func parsesIntegers() {
        let device = FleetDevice(summary: summary(id: "1", name: "A", eas: [
            ea("EA_Serberus_Denials_24h", "7"),
            ea("Serberus — Grants Active", "2"),
            ea("serberus_prompts_24h", "0"),
        ]))
        #expect(device.denials24h == 7)
        #expect(device.activeGrants == 2)
        #expect(device.prompts24h == 0)
    }

    @Test("a non-integer or absent EA reads nil, never a phantom 0")
    func rejectsNonIntegers() {
        let device = FleetDevice(summary: summary(id: "1", name: "A", eas: [
            ea("EA_Serberus_Denials_24h", "not installed"),   // the EA's absent-vocabulary
            ea("EA_Serberus_Prompts_24h", ""),                 // empty
        ]))
        #expect(device.denials24h == nil)
        #expect(device.prompts24h == nil)
        #expect(device.activeGrants == nil)                    // EA not deployed at all
    }

    @Test("recentDecisionEvents parses the debug EA's JSON list; absent/empty → []")
    func recentEventsParsing() {
        let json = "[{\"at\":\"2026-08-24T10:00:00Z\",\"kind\":\"sudo\",\"target\":\"/usr/bin/jamf\",\"user\":\"tuser\",\"outcome\":\"denied\",\"prompt\":false}]"
        let device = FleetDevice(summary: summary(id: "1", name: "A", eas: [ea("EA_Serberus_Recent_Events", json)]))
        #expect(device.recentDecisionEvents.count == 1)
        #expect(device.recentDecisionEvents.first?.target == "/usr/bin/jamf")
        #expect(device.recentDecisionEvents.first?.outcome == "denied")

        let none = FleetDevice(summary: summary(id: "2", name: "B", eas: [ea("EA_Serberus_Recent_Events", "")]))
        #expect(none.recentDecisionEvents.isEmpty)
        let bare = FleetDevice(summary: summary(id: "3", name: "C", eas: [ea("EA_Serberus_State", "healthy")]))
        #expect(bare.recentDecisionEvents.isEmpty)   // EA not deployed
    }
}

@MainActor
@Suite("FleetObserverModel telemetry — sums across the Serberus fleet")
struct FleetTelemetryModelTests {
    private let token = #"{"access_token":"T","expires_in":3600}"#
    private let connection = MDMConnection(vendor: .jamf, instanceURL: "https://example.jamfcloud.com", clientID: "id", clientSecret: "s")

    private final class ScriptedTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var replies: [(Int, Data)]
        init(_ replies: [(Int, String)]) { self.replies = replies.map { ($0.0, Data($0.1.utf8)) } }
        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let reply = lock.withLock { replies.isEmpty ? (500, Data()) : replies.removeFirst() }
            return (reply.1, HTTPURLResponse(url: request.url!, statusCode: reply.0, httpVersion: nil, headerFields: nil)!)
        }
    }

    // Three Serberus Macs reporting telemetry EAs + one that reports none + one
    // plain (non-Serberus) Mac that must be excluded from the sums.
    private let inventory = """
    {"totalCount":5,"results":[
      {"id":"1","general":{"name":"A","lastContactTime":"2026-08-23T20:00:00Z"},"hardware":{"serialNumber":"S1"},
       "extensionAttributes":[{"definitionId":"1","name":"EA_Serberus_State","values":["healthy"]},
         {"definitionId":"2","name":"EA_Serberus_Denials_24h","values":["10"]},
         {"definitionId":"3","name":"EA_Serberus_Grants_Active","values":["1"]},
         {"definitionId":"4","name":"EA_Serberus_Prompts_24h","values":["4"]}]},
      {"id":"2","general":{"name":"B","lastContactTime":"2026-08-23T20:00:00Z"},"hardware":{"serialNumber":"S2"},
       "extensionAttributes":[{"definitionId":"1","name":"EA_Serberus_State","values":["healthy"]},
         {"definitionId":"2","name":"EA_Serberus_Denials_24h","values":["25"]},
         {"definitionId":"3","name":"EA_Serberus_Grants_Active","values":["0"]}]},
      {"id":"3","general":{"name":"C","lastContactTime":"2026-08-23T20:00:00Z"},"hardware":{"serialNumber":"S3"},
       "extensionAttributes":[{"definitionId":"1","name":"EA_Serberus_State","values":["healthy"]}]},
      {"id":"4","general":{"name":"plain","lastContactTime":"2026-08-23T20:00:00Z"},"hardware":{"serialNumber":"S4"}}
    ]}
    """

    private func loaded() async -> FleetObserverModel {
        let transport = ScriptedTransport([(200, token), (200, inventory), (200, inventory), (204, "")])
        let fleet = FleetObserverModel(transport: transport)
        await fleet.refresh(connection: connection)
        precondition(fleet.state == .loaded)
        return fleet
    }

    @Test("telemetry sums only the reporting Serberus Macs and counts coverage")
    func sums() async {
        let fleet = await loaded()
        let t = fleet.telemetry
        #expect(t.denials24h == 35)          // 10 + 25 (C reports none, plain excluded)
        #expect(t.activeGrants == 1)          // 1 + 0
        #expect(t.prompts24h == 4)            // only A reports prompts
        #expect(t.reportingDevices == 2)      // A and B; C reports no telemetry EA
        #expect(t.serberusDevices == 3)       // A, B, C (plain excluded)
        #expect(t.hasData)
    }

    @Test("topDenialSources ranks reporting Macs by denials, dropping zero/non-reporters")
    func topSources() async {
        let fleet = await loaded()
        let sources = fleet.topDenialSources()
        #expect(sources.map(\.device.name) == ["B", "A"])   // 25 before 10
        #expect(sources.map(\.denials) == [25, 10])
    }

    @Test("a fleet with no telemetry EAs reports no data (tiles show the deploy hint, not zeros)")
    func noData() async {
        let bare = """
        {"totalCount":1,"results":[
          {"id":"1","general":{"name":"A","lastContactTime":"2026-08-23T20:00:00Z"},"hardware":{"serialNumber":"S1"},
           "extensionAttributes":[{"definitionId":"1","name":"EA_Serberus_State","values":["healthy"]}]}
        ]}
        """
        let transport = ScriptedTransport([(200, token), (200, bare), (200, bare), (204, "")])
        let fleet = FleetObserverModel(transport: transport)
        await fleet.refresh(connection: connection)
        let t = fleet.telemetry
        #expect(!t.hasData)
        #expect(t.reportingDevices == 0)
        #expect(t.serberusDevices == 1)
        #expect(fleet.topDenialSources().isEmpty)
    }
}
