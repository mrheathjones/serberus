import Foundation
import PrivMgrCore
import Testing
@testable import PolicyBuilderCore

// Commander enhancements (2026-08-23): the upload review ledger ("Uploads
// waiting" = on a record AND not reviewed), configurable check-in thresholds,
// Fleet Observer filters + routes, and the risk-signal switches/explanations.

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

private func upload(_ id: String, file: String, kind: FleetUpload.Kind = .capture, computer: String = "7", device: String = "MAC") -> FleetUpload {
    FleetUpload(id: id, kind: kind, computerID: computer, deviceName: device, serialNumber: "SER1",
                fileName: file, sizeBytes: 10, recordedAt: FleetUpload.recordedAt(fromFileName: file))
}

private func summary(id: String, name: String, lastContact: Date? = Date(), eas: [JamfExtensionAttributeValue] = [],
                     attachments: [JamfAttachment] = []) -> JamfComputerSummary {
    JamfComputerSummary(id: id, name: name, serialNumber: "S\(id)", osVersion: "26.4", username: "jdoe",
                        lastContactTime: lastContact, attachments: attachments, extensionAttributes: eas,
                        packageReceipts: [])
}

private func ea(_ name: String, _ value: String) -> JamfExtensionAttributeValue {
    JamfExtensionAttributeValue(definitionID: name, name: name, values: [value])
}

/// Three Serberus Macs (state/mode EAs; one with uploads) + one plain Mac.
private let inventory = """
{"totalCount":4,"results":[
  {"id":"1","general":{"name":"A","lastContactTime":"__FRESH__"},"hardware":{"serialNumber":"S1"},
   "extensionAttributes":[{"definitionId":"1","name":"EA_Serberus_State","values":["healthy"]},{"definitionId":"2","name":"EA_Serberus_Mode","values":["enforce"]}],
   "attachments":[{"id":"10","name":"Serberus-Capture-S1-20260822-101500.serberuscapture","sizeBytes":5},{"id":"11","name":"Serberus-Intel-S1-20260823-111500Z.zip","sizeBytes":50}]},
  {"id":"2","general":{"name":"B","lastContactTime":"__STALE__"},"hardware":{"serialNumber":"S2"},
   "extensionAttributes":[{"definitionId":"1","name":"EA_Serberus_State","values":["degraded"]},{"definitionId":"2","name":"EA_Serberus_Mode","values":["audit"]}]},
  {"id":"3","general":{"name":"C","lastContactTime":"__OFFLINE__"},"hardware":{"serialNumber":"S3"},
   "extensionAttributes":[{"definitionId":"1","name":"EA_Serberus_State","values":["healthy"]}],
   "attachments":[{"id":"30","name":"Serberus-Capture-S3-20260820-090000.serberuscapture","sizeBytes":5}]},
  {"id":"4","general":{"name":"plain","lastContactTime":"__FRESH__"},"hardware":{"serialNumber":"S4"}}
]}
"""

private func stamp(_ date: Date) -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f.string(from: date)
}

@MainActor
private func loadedFleet(now: Date = Date(), reviews: CaptureReviewLedger = CaptureReviewLedger(),
                         defaults: UserDefaults? = nil) async -> FleetObserverModel {
    let json = inventory
        .replacingOccurrences(of: "__FRESH__", with: stamp(now.addingTimeInterval(-3600)))
        .replacingOccurrences(of: "__STALE__", with: stamp(now.addingTimeInterval(-3 * 86_400)))
        .replacingOccurrences(of: "__OFFLINE__", with: stamp(now.addingTimeInterval(-30 * 86_400)))
    let transport = ScriptedTransport([(200, token), (200, json), (200, json), (204, "")])
    let fleet = FleetObserverModel(transport: transport, defaults: defaults, reviews: reviews)
    await fleet.refresh(connection: connection)
    precondition(fleet.state == .loaded)
    return fleet
}

// MARK: - Ledger

@MainActor
@Suite("CaptureReviewLedger — what Commander already dealt with")
struct CaptureReviewLedgerTests {
    @Test("keys normalise case, whitespace, and the dot-less capture extension Jamf can return")
    func keys() {
        #expect(CaptureReviewLedger.key(forFileName: "Serberus-Capture-X-20260822-101500.serberuscapture")
                == "serberus-capture-x-20260822-101500.serberuscapture")
        #expect(CaptureReviewLedger.key(forFileName: "Serberus-Capture-X-20260822-101500serberuscapture")
                == "serberus-capture-x-20260822-101500.serberuscapture")
        #expect(CaptureReviewLedger.key(forFileName: "  Serberus-Intel-X-20260822-101500Z.ZIP ")
                == "serberus-intel-x-20260822-101500z.zip")
    }

    @Test("record / decision / later decision wins / forget")
    func lifecycle() {
        let ledger = CaptureReviewLedger()
        let capture = upload("10", file: "Serberus-Capture-S1-20260822-101500.serberuscapture")
        #expect(ledger.decision(for: capture) == nil)
        #expect(!ledger.isReviewed(capture))
        ledger.record(capture, decision: .downloaded)
        #expect(ledger.decision(for: capture) == .downloaded)
        // The same file, mangled the way Jamf returns it, is the same review.
        #expect(ledger.decision(forFileName: "Serberus-Capture-S1-20260822-101500serberuscapture") == .downloaded)
        ledger.record(capture, decision: .imported, definitionIDs: ["jamf_check"])
        let entry = try! #require(ledger.entry(for: capture))
        #expect(entry.decision == .imported)
        #expect(entry.definitionIDs == ["jamf_check"])
        #expect(entry.deviceName == "MAC")
        #expect(entry.computerID == "7")
        #expect(ledger.count == 1)
        ledger.forget(fileName: capture.fileName)
        #expect(ledger.decision(for: capture) == nil)
        #expect(ledger.count == 0)
    }

    @Test("persists to disk and reloads; a fresh instance at the same URL sees the reviews")
    func persistence() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-ledger-\(UUID().uuidString)", isDirectory: true)
        let url = dir.appendingPathComponent("capture-reviews.json")
        defer { try? FileManager.default.removeItem(at: dir) }
        let ledger = CaptureReviewLedger(url: url)
        ledger.record(fileName: "Serberus-Capture-A-20260822-101500.serberuscapture", decision: .rejected,
                      deviceName: "A", serialNumber: "S1", computerID: "1")
        ledger.record(fileName: "Serberus-Intel-A-20260822-111500Z.zip", decision: .downloaded)
        #expect(ledger.lastSaveError == nil)
        #expect(FileManager.default.fileExists(atPath: url.path))
        let again = CaptureReviewLedger(url: url)
        #expect(again.count == 2)
        #expect(again.decision(forFileName: "Serberus-Capture-A-20260822-101500.serberuscapture") == .rejected)
        #expect(again.entry(forFileName: "Serberus-Capture-A-20260822-101500.serberuscapture")?.computerID == "1")
        #expect(again.decision(forFileName: "serberus-intel-a-20260822-111500z.zip") == .downloaded)
        // The decoded file is plain JSON an operator can read.
        let data = try Data(contentsOf: url)
        #expect(String(decoding: data, as: UTF8.self).contains("\"decision\" : \"rejected\""))
        // A missing file is an empty ledger, not an error.
        #expect(CaptureReviewLedger(url: dir.appendingPathComponent("nope.json")).count == 0)
    }
}

// MARK: - Waiting uploads

@MainActor
@Suite("FleetObserverModel — uploads waiting vs reviewed")
struct WaitingUploadsTests {
    @Test("waiting = on a record and not reviewed; reviewing (any decision) removes it from waiting without touching Jamf")
    func waitingVsReviewed() async {
        let fleet = await loadedFleet()
        #expect(fleet.uploads.map(\.id) == ["11", "10", "30"])     // newest first
        #expect(fleet.waitingUploads.count == 3)
        #expect(fleet.reviewedUploads.isEmpty)
        #expect(fleet.devicesWithWaitingUploads.map(\.id) == ["1", "3"])
        #expect(fleet.waitingUploads(on: "1").count == 2)

        let capture = fleet.uploads.first { $0.id == "10" }!
        fleet.reviews.record(capture, decision: .imported, definitionIDs: ["d1"])
        #expect(fleet.waitingUploads.map(\.id) == ["11", "30"])
        #expect(fleet.reviewedUploads.map(\.id) == ["10"])
        #expect(fleet.uploads.count == 3)                           // still on the record
        #expect(fleet.waitingUploads(on: "1").map(\.id) == ["11"])

        fleet.reviews.record(fleet.uploads.first { $0.id == "11" }!, decision: .downloaded)
        fleet.reviews.record(fleet.uploads.first { $0.id == "30" }!, decision: .rejected)
        #expect(fleet.waitingUploads.isEmpty)
        #expect(fleet.devicesWithWaitingUploads.isEmpty)
        #expect(fleet.reviewedUploads.count == 3)

        // "Mark as waiting again".
        fleet.reviews.forget(fileName: capture.fileName)
        #expect(fleet.waitingUploads.map(\.id) == ["10"])
    }

    @Test("a review survives a refresh (keyed by file name, not the attachment id)")
    func reviewSurvivesRefresh() async {
        let ledger = CaptureReviewLedger()
        ledger.record(fileName: "Serberus-Capture-S3-20260820-090000.serberuscapture", decision: .rejected)
        let fleet = await loadedFleet(reviews: ledger)
        #expect(fleet.waitingUploads.map(\.id) == ["11", "10"])
        #expect(fleet.reviews.decision(for: fleet.uploads.first { $0.id == "30" }!) == .rejected)
    }
}

// MARK: - Thresholds

@MainActor
@Suite("Check-in thresholds — configurable stale / offline windows")
struct FreshnessThresholdTests {
    @Test("freshness honours custom thresholds; normalisation keeps stale ≥ 1 and offline > stale")
    func customThresholds() {
        let now = Date()
        let threeDays = FleetDevice(summary: summary(id: "1", name: "a", lastContact: now.addingTimeInterval(-3 * 86_400)))
        #expect(threeDays.freshness(now: now) == .stale)
        #expect(threeDays.freshness(now: now, thresholds: .init(staleAfterDays: 5, offlineAfterDays: 14)) == .fresh)
        #expect(threeDays.freshness(now: now, thresholds: .init(staleAfterDays: 1, offlineAfterDays: 2)) == .offline)
        // Inverted / zero windows are clamped, never "everything offline".
        let clamped = FleetDevice.FreshnessThresholds(staleAfterDays: 0, offlineAfterDays: 0).normalized
        #expect(clamped == .init(staleAfterDays: 1, offlineAfterDays: 2))
        let inverted = FleetDevice.FreshnessThresholds(staleAfterDays: 10, offlineAfterDays: 3).normalized
        #expect(inverted == .init(staleAfterDays: 10, offlineAfterDays: 11))
        #expect(FleetDevice.FreshnessThresholds.default.normalized == .default)
        #expect(FleetDevice.Freshness.stale.label(thresholds: .default) == "Stale (1–7 days)")
        #expect(FleetDevice.Freshness.offline.label(thresholds: .init(staleAfterDays: 2, offlineAfterDays: 30)) == "Offline (> 30 days)")
    }

    @Test("the model's thresholds drive freshness(of:), postureCounts, and persist to UserDefaults")
    func modelThresholds() async {
        let suite = "serberus-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let now = Date()
        let fleet = await loadedFleet(now: now, defaults: defaults)
        #expect(fleet.thresholds == .default)
        #expect(fleet.postureCounts(now: now) == [.fresh: 1, .stale: 1, .offline: 1, .unknown: 0])

        fleet.thresholds = .init(staleAfterDays: 5, offlineAfterDays: 60)
        #expect(fleet.postureCounts(now: now) == [.fresh: 2, .stale: 1, .offline: 0, .unknown: 0])
        #expect(fleet.freshness(of: fleet.device(id: "3")!, now: now) == .stale)
        // Setter normalises.
        fleet.thresholds = .init(staleAfterDays: 0, offlineAfterDays: 0)
        #expect(fleet.thresholds == .init(staleAfterDays: 1, offlineAfterDays: 2))
        // Persisted: a new model on the same defaults starts from them.
        fleet.thresholds = .init(staleAfterDays: 3, offlineAfterDays: 21)
        let again = FleetObserverModel(transport: ScriptedTransport([]), defaults: defaults)
        #expect(again.thresholds == .init(staleAfterDays: 3, offlineAfterDays: 21))
        // No defaults → in-memory defaults.
        #expect(FleetObserverModel(transport: ScriptedTransport([])).thresholds == .default)
    }
}

// MARK: - Filters + routes

@MainActor
@Suite("FleetFilter / FleetRoute — state, mode, check-in, uploads")
struct FleetFilterTests {
    @Test("postureValue / daemonState / enforcementMode read the EA trio in any naming convention")
    func postureLookups() {
        let device = FleetDevice(summary: summary(id: "1", name: "a", eas: [
            ea("EA_Serberus_State", "Healthy"), ea("Serberus — Mode", "enforce"), ea("serberus: version", "3.8"),
            ea("EA_Serberus_Daemon_Version", "ignored-by-state"),
        ]))
        #expect(device.postureValue("state") == "Healthy")
        #expect(device.daemonState == "healthy")
        #expect(device.enforcementMode == "enforce")
        #expect(device.daemonVersion == "3.8")
        let bare = FleetDevice(summary: summary(id: "2", name: "b", eas: [ea("EA_Serberus_State", "")]))
        #expect(bare.daemonState == nil)
        #expect(bare.enforcementMode == nil)
    }

    @Test("matches(): each constraint narrows; not-reported selects Macs without the EA value")
    func matching() {
        let healthy = FleetDevice(summary: summary(id: "1", name: "a", eas: [ea("EA_Serberus_State", "healthy"), ea("EA_Serberus_Mode", "enforce")]))
        let bare = FleetDevice(summary: summary(id: "2", name: "b"))
        #expect(FleetFilter.all.matches(healthy, freshness: .fresh, waitingUploads: 0))
        #expect(!FleetFilter.all.isActive)
        #expect(FleetFilter(freshness: .fresh).matches(healthy, freshness: .fresh, waitingUploads: 0))
        #expect(!FleetFilter(freshness: .offline).matches(healthy, freshness: .fresh, waitingUploads: 0))
        #expect(FleetFilter(state: "HEALTHY").matches(healthy, freshness: .fresh, waitingUploads: 0))     // lowercased on init
        #expect(!FleetFilter(state: "degraded").matches(healthy, freshness: .fresh, waitingUploads: 0))
        #expect(FleetFilter(state: FleetDevice.postureNotReported).matches(bare, freshness: .fresh, waitingUploads: 0))
        #expect(!FleetFilter(state: FleetDevice.postureNotReported).matches(healthy, freshness: .fresh, waitingUploads: 0))
        #expect(FleetFilter(mode: "enforce").matches(healthy, freshness: .fresh, waitingUploads: 0))
        #expect(FleetFilter(waitingUploadsOnly: true).matches(healthy, freshness: .fresh, waitingUploads: 2))
        #expect(!FleetFilter(waitingUploadsOnly: true).matches(healthy, freshness: .fresh, waitingUploads: 0))
        // denials24hOnly: only Macs whose telemetry EA reports a nonzero count.
        let denying = FleetDevice(summary: summary(id: "3", name: "c", eas: [ea("EA_Serberus_Denials_24h", "5")]))
        let zeroDenials = FleetDevice(summary: summary(id: "4", name: "d", eas: [ea("EA_Serberus_Denials_24h", "0")]))
        #expect(FleetFilter(denials24hOnly: true).matches(denying, freshness: .fresh, waitingUploads: 0))
        #expect(!FleetFilter(denials24hOnly: true).matches(zeroDenials, freshness: .fresh, waitingUploads: 0))
        #expect(!FleetFilter(denials24hOnly: true).matches(bare, freshness: .fresh, waitingUploads: 0))   // no EA → nil → excluded
        let combo = FleetFilter(freshness: .stale, state: "healthy", mode: "audit", waitingUploadsOnly: true, denials24hOnly: true)
        #expect(combo.activeCount == 5)
        #expect(combo.summary() == "Stale · State: healthy · Mode: audit · Uploads waiting · Denials · 24h")
    }

    @Test("the model filters Serberus Macs and reports state / mode counts (not-reported included)")
    func modelFiltering() async {
        let now = Date()
        let fleet = await loadedFleet(now: now)
        #expect(fleet.serberusDevices.map(\.id) == ["1", "2", "3"])
        #expect(fleet.serberusDevices(matching: FleetFilter(freshness: .offline), now: now).map(\.id) == ["3"])
        #expect(fleet.serberusDevices(matching: FleetFilter(state: "healthy"), now: now).map(\.id) == ["1", "3"])
        #expect(fleet.serberusDevices(matching: FleetFilter(state: "healthy", mode: "enforce"), now: now).map(\.id) == ["1"])
        #expect(fleet.serberusDevices(matching: FleetFilter(mode: FleetDevice.postureNotReported), now: now).map(\.id) == ["3"])
        #expect(fleet.serberusDevices(matching: FleetFilter(waitingUploadsOnly: true), now: now).map(\.id) == ["1", "3"])
        fleet.reviews.record(fleet.uploads.first { $0.id == "30" }!, decision: .rejected)
        #expect(fleet.serberusDevices(matching: FleetFilter(waitingUploadsOnly: true), now: now).map(\.id) == ["1"])
        // Counts, most common first; ties by value.
        #expect(fleet.stateCounts.map(\.value) == ["healthy", "degraded"])
        #expect(fleet.stateCounts.map(\.count) == [2, 1])
        #expect(fleet.modeCounts.map { "\($0.value):\($0.count)" } == ["audit:1", "enforce:1", "not reported:1"])
        // The plain Mac (no Serberus) never enters the counts.
        #expect(fleet.stateCounts.map(\.count).reduce(0, +) == 3)
    }

    @Test("openFleetObserver sets the route and navigates; routes compare by value")
    func routes() {
        let model = PolicyBuilderModel()
        #expect(model.pendingFleetRoute == nil)
        model.openFleetObserver(.devices(FleetFilter(freshness: .offline)))
        #expect(model.selectedSection == .fleetObserver)
        #expect(model.pendingFleetRoute == .devices(FleetFilter(freshness: .offline)))
        model.openFleetObserver(.uploads(deviceID: "7"))
        #expect(model.pendingFleetRoute == .uploads(deviceID: "7"))
        #expect(FleetRoute.allUploads == .uploads(deviceID: nil))
        #expect(FleetRoute.allDevices == .devices(.all))
    }
}

// MARK: - Risk signals

@MainActor
@Suite("Risk signals — switches, explanations, thresholds")
struct RiskSignalSettingsTests {
    @Test("every configurable kind has a title and a formula; levels bucket 35 / 65")
    func kinds() {
        for kind in RiskSignal.Kind.configurable {
            #expect(!kind.title.isEmpty)
            #expect(kind.explanation.contains("Score"), "\(kind) explains its score")
        }
        #expect(!RiskSignal.Kind.configurable.contains(.nominal))
        #expect(RiskSignal.Kind.offline.isFleetDerived)
        #expect(!RiskSignal.Kind.silent.isFleetDerived)
        #expect(RiskSignal.Level.bucket(0) == .low)
        #expect(RiskSignal.Level.bucket(34) == .low)
        #expect(RiskSignal.Level.bucket(35) == .medium)
        #expect(RiskSignal.Level.bucket(64) == .medium)
        #expect(RiskSignal.Level.bucket(65) == .high)
        #expect(RiskSignal.Kind(rawValue: "long_grants") == .longGrants)   // ids stay stable
        #expect(RiskSignal.Kind(rawValue: "no_deny") == .noDeny)
    }

    @Test("every signal's level equals its score bucket — the badge never contradicts the legend")
    func levelMatchesBucket() {
        // A library that trips several kinds at once (silent + unpinned allow,
        // long grants, wildcard/broad, no deny).
        let model = PolicyBuilderModel(
            policies: LibraryFixture.policies, rules: LibraryFixture.rules, definitions: LibraryFixture.definitions)
        let signals = model.riskSignals()
        #expect(!signals.isEmpty)
        for signal in signals {
            #expect(signal.level == RiskSignal.Level.bucket(signal.score),
                    "\(signal.kind) score \(signal.score) → \(signal.level), bucket \(RiskSignal.Level.bucket(signal.score))")
        }
        // The specific cases the review flagged (were hard-coded to the wrong level).
        let empty = PolicyBuilderModel()
        #expect(empty.riskSignals().allSatisfy { $0.level == RiskSignal.Level.bucket($0.score) })
    }

    @Test("a disabled signal disappears from the Dashboard; the switch persists")
    func disabledSignals() {
        let suite = "serberus-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = PolicyBuilderModel(
            policies: LibraryFixture.policies, rules: LibraryFixture.rules, definitions: LibraryFixture.definitions,
            defaults: defaults)
        let before = Set(model.riskSignals().map(\.kind))
        #expect(before.contains(.silent) || before.contains(.unpinned))
        let target = before.contains(.silent) ? RiskSignal.Kind.silent : .unpinned
        model.disabledRiskSignals.insert(target)
        #expect(!model.riskSignals().map(\.kind).contains(target))
        #expect(model.riskSignals().allSatisfy { $0.explanation == $0.kind.explanation })
        let again = PolicyBuilderModel(defaults: defaults)
        #expect(again.disabledRiskSignals == [target])
        // Everything off → the nominal placeholder, never an empty card.
        model.disabledRiskSignals = Set(RiskSignal.Kind.configurable)
        #expect(model.riskSignals().map(\.kind) == [.nominal])
    }

    @Test("the offline signal follows the model's thresholds and scales with the Mac count")
    func offlineSignal() async {
        let now = Date()
        let fleet = await loadedFleet(now: now)
        let model = PolicyBuilderModel(fleet: fleet)
        let offline = model.riskSignals(now: now).first { $0.kind == .offline }
        #expect(offline?.score == 44)              // 40 + 4 × 1 Mac
        #expect(offline?.level == .medium)
        #expect(offline?.detail.contains("over a week") == true)
        fleet.thresholds = .init(staleAfterDays: 1, offlineAfterDays: 2)
        let more = model.riskSignals(now: now).first { $0.kind == .offline }
        #expect(more?.score == 48)                 // 2 Macs now past a 2-day window
        #expect(more?.detail.contains("over 2 days") == true)
        fleet.thresholds = .init(staleAfterDays: 5, offlineAfterDays: 60)
        #expect(model.riskSignals(now: now).first { $0.kind == .offline } == nil)
        model.disabledRiskSignals = [.offline]
        fleet.thresholds = .default
        #expect(model.riskSignals(now: now).first { $0.kind == .offline } == nil)
    }
}
