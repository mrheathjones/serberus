import Foundation
import Observation
import PrivMgrCore

// MARK: - Fleet models

/// One file a device uploaded to its Jamf record from Sentinel — a **capture**
/// (Intel → Capture → Upload to Jamf, `.serberuscapture`) or an **Intel**
/// support bundle (Intel → Export → Upload, `.zip`) — as the Fleet Observer
/// lists it. The attachment id is only stable for the current refresh; the
/// file name carries the recording Mac and time
/// (`Serberus-Capture-<serial>-yyyyMMdd-HHmmss.serberuscapture`,
/// `Serberus-Intel-<serial>-yyyyMMdd-HHmmssZ.zip`).
public struct FleetUpload: Identifiable, Sendable, Equatable, Hashable {
    public enum Kind: String, Sendable, Equatable, Hashable {
        case capture
        case intel

        public var label: String {
            switch self {
            case .capture: return "Capture"
            case .intel: return "Intel bundle"
            }
        }
    }

    public let id: String
    public let kind: Kind
    public let computerID: String
    public let deviceName: String
    public let serialNumber: String?
    public let fileName: String
    public let sizeBytes: Int?
    /// Parsed from the Sentinel's file-name pattern; nil for a renamed file.
    public let recordedAt: Date?

    public init(id: String, kind: Kind, computerID: String, deviceName: String, serialNumber: String?,
                fileName: String, sizeBytes: Int?, recordedAt: Date?) {
        self.id = id
        self.kind = kind
        self.computerID = computerID
        self.deviceName = deviceName
        self.serialNumber = serialNumber
        self.fileName = fileName
        self.sizeBytes = sizeBytes
        self.recordedAt = recordedAt
    }

    /// `…-yyyyMMdd-HHmmss[Z]…` → the recording time. Captures stamp the
    /// recording Mac's LOCAL time (read back the same way); Intel bundles
    /// stamp UTC with a trailing `Z`.
    public static func recordedAt(fromFileName name: String) -> Date? {
        guard let range = name.range(of: #"\d{8}-\d{6}"#, options: .regularExpression) else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        if name[range.upperBound...].hasPrefix("Z") {
            formatter.timeZone = TimeZone(identifier: "UTC")
        }
        return formatter.date(from: String(name[range]))
    }

    /// A file name with the right extension for Save panels — captures always
    /// end in `.serberuscapture` (a mangled upload gets its dot back), Intel
    /// bundles in `.zip`.
    public var suggestedSaveName: String {
        switch kind {
        case .intel:
            return fileName.lowercased().hasSuffix(".zip") ? fileName : fileName + ".zip"
        case .capture:
            let ext = ".\(RuleCapture.fileExtension)"
            if fileName.lowercased().hasSuffix(ext) { return fileName }
            if fileName.lowercased().hasSuffix(RuleCapture.fileExtension) {
                return String(fileName.dropLast(RuleCapture.fileExtension.count)) + ext
            }
            return fileName + ext
        }
    }
}

/// One Serberus posture value published through a Jamf extension attribute.
public struct PostureItem: Sendable, Equatable, Hashable {
    /// The EA's display name exactly as named in Jamf (any convention —
    /// `EA_Serberus_State`, `Serberus — State`, `serberus_mode`, …).
    public let name: String
    public let value: String
    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }

    /// The name minus the convention: `EA_Serberus_Last_Upload` → "Last Upload",
    /// `Serberus — State` → "State". For chips and detail rows.
    public var label: String { FleetDevice.postureLabel(name) }
}

/// One device as the Fleet Observer shows it — a Jamf computer record reduced
/// to the facts a card needs, plus its Serberus captures and any Serberus
/// posture the org publishes through extension attributes (script EAs whose
/// display name contains "Serberus", filled at recon; see
/// Support/jamf-extension-attributes/).
public struct FleetDevice: Identifiable, Sendable, Equatable, Hashable {
    public enum Freshness: String, Sendable, CaseIterable, Codable, Hashable {
        /// Contacted Jamf within the stale threshold (default: the last day).
        case fresh
        /// Between the stale and offline thresholds (default 1–7 days).
        case stale
        /// Past the offline threshold (default more than a week) — likely
        /// off, wiped, or unenrolled.
        case offline
        /// Jamf reported no contact time.
        case unknown

        public var label: String {
            switch self {
            case .fresh: return "Checked in"
            case .stale: return "Stale"
            case .offline: return "Offline"
            case .unknown: return "Unknown"
            }
        }

        /// The label with the threshold window spelled out ("Stale (1–7 days)").
        public func label(thresholds: FreshnessThresholds) -> String {
            switch self {
            case .fresh: return "Checked in"
            case .stale: return "Stale (\(thresholds.staleAfterDays)–\(thresholds.offlineAfterDays) days)"
            case .offline: return "Offline (> \(thresholds.offlineAfterDays) days)"
            case .unknown: return "No check-in reported"
            }
        }
    }

    /// How old a Jamf last-contact time may be before a Mac counts as stale,
    /// then offline. Operator-configurable (Commander Settings → Dashboard &
    /// fleet posture) because fleets differ: a lab of always-on Macs and a
    /// field fleet that checks in weekly need different windows. Drives the
    /// Dashboard posture ring, the Fleet Observer check-in filter, the menu
    /// bar counts and the "Offline Serberus Macs" risk signal — one source.
    public struct FreshnessThresholds: Equatable, Sendable, Codable, Hashable {
        /// Days since last contact after which a Mac is **stale** (default 1).
        public var staleAfterDays: Int
        /// Days since last contact after which a Mac is **offline** (default 7).
        public var offlineAfterDays: Int

        public static let `default` = FreshnessThresholds(staleAfterDays: 1, offlineAfterDays: 7)
        public static let minimumDays = 1
        public static let maximumDays = 365

        public init(staleAfterDays: Int, offlineAfterDays: Int) {
            self.staleAfterDays = staleAfterDays
            self.offlineAfterDays = offlineAfterDays
        }

        /// The same thresholds clamped to a sane, ordered range — stale at
        /// least 1 day, offline strictly after stale (a zero or inverted
        /// window would make every Mac offline). Always applied on read.
        public var normalized: FreshnessThresholds {
            let stale = min(max(staleAfterDays, Self.minimumDays), Self.maximumDays)
            let offline = min(max(offlineAfterDays, stale + 1), Self.maximumDays + 1)
            return FreshnessThresholds(staleAfterDays: stale, offlineAfterDays: offline)
        }
    }

    public let id: String
    public let name: String
    public let serialNumber: String?
    public let user: String?
    public let realName: String?
    public let email: String?
    public let osVersion: String?
    public let osBuild: String?
    public let model: String?
    public let lastContact: Date?
    public let lastEnrolled: Date?
    public let managed: Bool?
    public private(set) var attachmentCount: Int
    /// Every Sentinel upload still on the record (captures + Intel bundles), newest first.
    public private(set) var uploads: [FleetUpload]
    /// Extension attributes whose name starts with "Serberus" in name order —
    /// empty until the org deploys the posture EA.
    public let posture: [PostureItem]

    /// Why Commander believes Serberus is installed on this Mac — each line is
    /// one piece of inventory evidence ("EA Serberus — State = healthy",
    /// "package SerberusSentinelAgent-3.8.pkg", "uploads on the record").
    /// Empty = no sign of Serberus: the Fleet Observer hides such Macs by
    /// default (a fleet usually has many Macs Serberus is not deployed to).
    public let serberusEvidence: [String]
    public var hasSerberus: Bool { !serberusEvidence.isEmpty }

    public var captures: [FleetUpload] { uploads.filter { $0.kind == .capture } }
    public var intelBundles: [FleetUpload] { uploads.filter { $0.kind == .intel } }

    public init(summary: JamfComputerSummary) {
        id = summary.id
        name = summary.name
        serialNumber = summary.serialNumber
        user = summary.username?.isEmpty == false ? summary.username : nil
        realName = summary.realName
        email = summary.email
        osVersion = summary.osVersion
        osBuild = summary.osBuild
        model = summary.model
        lastContact = summary.lastContactTime
        lastEnrolled = summary.lastEnrolledDate
        managed = summary.managed
        attachmentCount = summary.attachments.count
        uploads = summary.uploads
            .map {
                FleetUpload(id: $0.id, kind: $0.isSerberusCapture ? .capture : .intel,
                            computerID: summary.id, deviceName: summary.name,
                            serialNumber: summary.serialNumber, fileName: $0.name, sizeBytes: $0.sizeBytes,
                            recordedAt: FleetUpload.recordedAt(fromFileName: $0.name))
            }
            .sorted { ($0.recordedAt ?? .distantPast) > ($1.recordedAt ?? .distantPast) }
        posture = summary.extensionAttributes
            .filter { Self.isSerberusEAName($0.name) }
            .map { PostureItem(name: $0.name, value: $0.values.joined(separator: ", ")) }
            .sorted { (Self.postureRank($0.name), $0.name) < (Self.postureRank($1.name), $1.name) }
        serberusEvidence = Self.evidence(posture: posture, receipts: summary.packageReceipts, uploads: uploads)
    }

    /// Values a Serberus EA reports when the daemon is NOT there (the EA
    /// scripts' own vocabulary) — an EA carrying one of these is not evidence.
    static let absentEAValues: Set<String> = ["", "not installed", "unknown", "none", "unknown (state.plist unreadable)"]

    /// An EA belongs to Serberus when its name contains this token, in ANY
    /// naming convention (`EA_Serberus_State`, `Serberus — State`,
    /// `serberus: mode`, `SERBERUS_VERSION`, …). Case-insensitive.
    public static let postureNameToken = "serberus"

    public static func isSerberusEAName(_ name: String) -> Bool {
        name.lowercased().contains(postureNameToken)
    }

    /// The EA name reduced to its meaning: lowercased, every separator
    /// (`_ - — – :`) a space, the `EA` prefix and the `serberus` token dropped —
    /// `EA_Serberus_Last_Upload` → "last upload", `Serberus — State` → "state".
    public static func postureKey(_ name: String) -> String {
        let separators = CharacterSet(charactersIn: "_-—–:()[]/|")
        let words = name.lowercased()
            .components(separatedBy: separators.union(.whitespacesAndNewlines))
            .filter { !$0.isEmpty }
            .filter { $0 != "ea" && $0 != postureNameToken }
        return words.joined(separator: " ")
    }

    /// Title-cased ``postureKey`` ("Last Upload"); the raw name when nothing is left.
    public static func postureLabel(_ name: String) -> String {
        let key = postureKey(name)
        guard !key.isEmpty else { return name }
        return key.split(separator: " ").map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined(separator: " ")
    }

    static func evidence(posture: [PostureItem], receipts: [String], uploads: [FleetUpload]) -> [String] {
        var lines: [String] = []
        for item in posture where !absentEAValues.contains(item.value.lowercased()) {
            lines.append("EA \(item.name) = \(item.value)")
        }
        // A daemon EA (State / Mode / Version) that says "not installed" is the
        // CURRENT truth from the same recon; package receipts are history
        // (Jamf's policy stubs survive the uninstaller) — so the EA vetoes them.
        let eaSaysNotInstalled = posture.contains {
            postureRank($0.name) < preferredPosture.count && $0.value.lowercased() == "not installed"
        }
        if !eaSaysNotInstalled {
            for receipt in receipts where receipt.lowercased().contains("serberus")
                && !receipt.lowercased().contains("uninstall") {   // the uninstaller's own receipt/stub
                lines.append("package \(receipt)")
            }
        }
        if !uploads.isEmpty {
            lines.append("\(uploads.count) Serberus \(uploads.count == 1 ? "upload" : "uploads") on the record")
        }
        return lines
    }

    /// Evidence beyond uploads — an EA value or a package receipt, i.e. the
    /// daemon/app is (or was just) actually on the Mac.
    public var hasInstallEvidence: Bool {
        serberusEvidence.contains { $0.hasPrefix("EA ") || $0.hasPrefix("package ") }
    }

    /// Card order for posture chips: the daemon trio (State / Mode / Version)
    /// ranks first so the ledger EAs (Uploads, Last Upload) never push them off
    /// the card's three chips; anything else follows by name. Matched on the
    /// convention-free ``postureKey``, so `EA_Serberus_State`, `Serberus — State`
    /// and `serberus: state` all rank the same.
    static let preferredPosture = ["state", "mode", "version"]
    static func postureRank(_ name: String) -> Int {
        let key = postureKey(name)
        return preferredPosture.firstIndex { key == $0 || key.hasSuffix(" \($0)") } ?? preferredPosture.count
    }

    public func freshness(now: Date = Date(), thresholds: FreshnessThresholds = .default) -> Freshness {
        guard let lastContact else { return .unknown }
        let t = thresholds.normalized
        let age = now.timeIntervalSince(lastContact)
        if age < Double(t.staleAfterDays) * 86_400 { return .fresh }
        if age < Double(t.offlineAfterDays) * 86_400 { return .stale }
        return .offline
    }

    // MARK: Posture lookups (the daemon trio the EAs publish)

    /// Convention-free posture keys the enforcement telemetry EAs use — surfaced
    /// in Commander's own Enforcement / Recent-events sections and therefore
    /// filtered out of the generic posture chips/rows (no duplication, and never
    /// a raw recent-events JSON blob shown as a chip).
    public static let telemetryPostureKeys: Set<String> = ["denials 24h", "grants active", "prompts 24h", "last decision", "recent events"]

    /// Posture items minus the telemetry EAs above — what a device card's chips
    /// and the detail's posture card show.
    public var displayPosture: [PostureItem] {
        posture.filter { !Self.telemetryPostureKeys.contains(Self.postureKey($0.name)) }
    }

    /// The value of the Serberus EA whose convention-free ``postureKey(_:)``
    /// is `key` (or ends in " key"): `postureValue("state")` reads
    /// `EA_Serberus_State`, `Serberus — State`, `serberus: state` alike.
    /// `nil` when the org has not deployed that EA (or it has no value).
    public func postureValue(_ key: String) -> String? {
        let wanted = key.lowercased()
        // An exact key wins over a suffix match ("version" before "daemon version").
        let item = posture.first { Self.postureKey($0.name) == wanted }
            ?? posture.first { Self.postureKey($0.name).hasSuffix(" \(wanted)") }
        guard let value = item?.value.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
        return value
    }

    /// The integer value of the Serberus EA whose convention-free
    /// ``postureKey(_:)`` is `key` (or ends in " key") — e.g.
    /// `postureInt("denials 24h")` reads `EA_Serberus_Denials_24h`. `nil` when
    /// the EA is absent, empty, or not a clean integer (so a "not installed"
    /// string never poses as 0). Backs the fleet telemetry sums.
    public func postureInt(_ key: String) -> Int? {
        guard let raw = postureValue(key) else { return nil }
        return Int(raw.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Denials, active grants and prompts as the telemetry EAs reported them at
    /// last recon (nil when the org has not deployed that EA / no value yet).
    public var denials24h: Int? { postureInt("denials 24h") }
    public var activeGrants: Int? { postureInt("grants active") }
    public var prompts24h: Int? { postureInt("prompts 24h") }

    /// The individual recent denial/prompt events (last 24h) the debug-telemetry
    /// EA (`EA_Serberus_Recent_Events`) carries — empty unless the debug profile
    /// is on (or the EA is not deployed). Newest first, as the daemon wrote them.
    public var recentDecisionEvents: [FleetDecisionEvent] {
        guard let raw = postureValue("recent events") else { return [] }
        return FleetDecisionEvent.decodeList(from: raw)
    }

    /// The daemon's state as the State EA reported it at last recon
    /// ("healthy", "degraded", "not installed", …), lowercased for grouping.
    public var daemonState: String? { postureValue("state")?.lowercased() }
    /// The enforcement mode as the Mode EA reported it ("enforce", "audit", …).
    public var enforcementMode: String? { postureValue("mode")?.lowercased() }
    /// The daemon version as the Version EA reported it.
    public var daemonVersion: String? { postureValue("version") }

    /// Placeholder the filters use for a Mac whose EA has no value yet.
    public static let postureNotReported = "not reported"

    /// The same device minus one (deleted) upload.
    public func removingUpload(id uploadID: String) -> FleetDevice {
        var copy = self
        copy.uploads.removeAll { $0.id == uploadID }
        copy.attachmentCount = max(0, copy.attachmentCount - 1)
        return copy
    }
}

/// A failure the model noticed on a path that does not throw to a caller
/// (the detail reload). A fresh `id` per event, so two identical messages
/// in a row still register as a change.
public struct FleetError: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let message: String
    public init(id: UUID = UUID(), message: String) {
        self.id = id
        self.message = message
    }
}

/// A downloaded attachment that is not a usable capture.
public enum FleetCaptureError: Error, LocalizedError, Equatable {
    /// Bigger than the kind's size cap — refused before (or after) the bytes
    /// move, exactly like the file importer.
    case tooLarge(fileName: String, bytes: Int, limit: Int)
    /// Downloaded but failed ``RuleCapture/decode(from:)``.
    case invalidCapture(fileName: String, underlying: String)

    public var errorDescription: String? {
        switch self {
        case let .tooLarge(fileName, bytes, limit):
            return "\(fileName) is \(ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)) — larger than the \(limit / (1024 * 1024)) MB limit for this kind of upload, so it was not downloaded."
        case let .invalidCapture(fileName, underlying):
            return "\(fileName) is not a valid capture: \(underlying)"
        }
    }
}

// MARK: - Model

/// Drives the Fleet Observer: Jamf is the fleet data plane,
/// so this reads the computer inventory through ``JamfFleetClient`` with
/// Commander's user-entered MDM connection, keeps the devices + every Sentinel
/// upload attached to them (captures + Intel bundles), downloads an upload on
/// request (Save, or hand a capture to Definitions → Import Capture), and —
/// the one write — deletes a harvested upload from the record.
@MainActor
@Observable
public final class FleetObserverModel {
    public enum State: Equatable, Sendable {
        case idle
        case loading
        case loaded
        case failed(String)
    }

    public private(set) var state: State = .idle
    public private(set) var devices: [FleetDevice] = []
    public private(set) var lastRefreshed: Date?
    /// The connection the current `devices` came from — a changed connection
    /// means a different tenant, so the next visit reloads instead of showing
    /// stale data.
    public private(set) var loadedConnection: MDMConnection?
    /// Jamf's total when the walk hit the page cap — shown as "first N of M".
    public private(set) var truncatedTotal: Int?
    /// Attachment ids being downloaded right now (Save or Import).
    public private(set) var downloading: Set<String> = []
    /// Attachment ids being imported right now (a subset of `downloading`).
    public private(set) var importing: Set<String> = []
    /// Attachment ids being deleted from their record right now.
    public private(set) var deleting: Set<String> = []
    /// Computer ids whose detail is being re-read.
    public private(set) var reloading: Set<String> = []
    /// A detail-reload failure (the one path that does not throw to a caller).
    public var lastError: FleetError?

    /// Check-in windows for ``FleetDevice/Freshness`` — operator-set in
    /// Settings, persisted in `UserDefaults` when one was given. Every
    /// freshness read in Commander goes through ``freshness(of:now:)`` so the
    /// Dashboard, Fleet Observer, menu bar and risk signals agree.
    public var thresholds: FleetDevice.FreshnessThresholds {
        didSet {
            let normalized = thresholds.normalized
            if normalized != thresholds { thresholds = normalized; return }
            guard thresholds != oldValue else { return }
            defaults?.set(thresholds.staleAfterDays, forKey: Self.kStaleAfterDays)
            defaults?.set(thresholds.offlineAfterDays, forKey: Self.kOfflineAfterDays)
        }
    }

    /// Which uploads Commander has already imported / rejected / downloaded —
    /// see ``CaptureReviewLedger``. "Waiting" = on a record and not in here.
    public let reviews: CaptureReviewLedger

    private let transport: HTTPTransport
    @ObservationIgnored private let defaults: UserDefaults?
    private static let kStaleAfterDays = "serberus.fleet.staleAfterDays"
    private static let kOfflineAfterDays = "serberus.fleet.offlineAfterDays"
    /// One client per connection: the client learns which API versions the
    /// instance serves, and that knowledge must outlive a single call.
    private var client: JamfFleetClient?
    private var clientCredentials: JamfCredentials?

    /// - Parameters:
    ///   - defaults: where the check-in thresholds are remembered; `nil`
    ///     keeps the defaults in memory only (tests).
    ///   - reviews: the upload review ledger; the default is in-memory —
    ///     the app passes a file-backed one.
    public init(transport: HTTPTransport = URLSessionTransport(),
                defaults: UserDefaults? = nil,
                reviews: CaptureReviewLedger = CaptureReviewLedger()) {
        self.transport = transport
        self.defaults = defaults
        self.reviews = reviews
        var stored = FleetDevice.FreshnessThresholds.default
        if let defaults {
            let stale = defaults.integer(forKey: Self.kStaleAfterDays)
            let offline = defaults.integer(forKey: Self.kOfflineAfterDays)
            if stale > 0 { stored.staleAfterDays = stale }
            if offline > 0 { stored.offlineAfterDays = offline }
        }
        self.thresholds = stored.normalized
    }

    // MARK: Derived

    /// The Macs Serberus is installed on (inventory evidence — see
    /// ``FleetDevice/serberusEvidence``); the rest of the Jamf fleet is kept
    /// in `devices` for coverage checks but hidden by default.
    public var serberusDevices: [FleetDevice] { devices.filter(\.hasSerberus) }
    public var otherDeviceCount: Int { devices.count - serberusDevices.count }

    /// Every Sentinel upload across the fleet (captures + Intel bundles), newest first.
    public var uploads: [FleetUpload] {
        devices.flatMap(\.uploads).sorted { ($0.recordedAt ?? .distantPast) > ($1.recordedAt ?? .distantPast) }
    }

    /// Uploads still to deal with: on a record AND not yet imported /
    /// rejected / downloaded (``reviews``). This is the Dashboard's "Uploads
    /// waiting" and the menu bar's attention state.
    public var waitingUploads: [FleetUpload] { uploads.filter { !reviews.isReviewed($0) } }
    /// Uploads already reviewed but still on their record (harvest switch off,
    /// or the delete failed) — shown with their decision, not as waiting.
    public var reviewedUploads: [FleetUpload] { uploads.filter { reviews.isReviewed($0) } }

    public func waitingUploads(on deviceID: String) -> [FleetUpload] {
        device(id: deviceID)?.uploads.filter { !reviews.isReviewed($0) } ?? []
    }

    public var devicesWithUploads: Int { devices.filter { !$0.uploads.isEmpty }.count }
    /// Devices with at least one upload waiting, most-waiting first.
    public var devicesWithWaitingUploads: [FleetDevice] {
        devices.filter { !waitingUploads(on: $0.id).isEmpty }
            .sorted { waitingUploads(on: $0.id).count > waitingUploads(on: $1.id).count }
    }

    public func device(id: String) -> FleetDevice? { devices.first { $0.id == id } }

    // MARK: Posture (thresholds-aware)

    /// ``FleetDevice/freshness(now:thresholds:)`` with THIS model's thresholds.
    public func freshness(of device: FleetDevice, now: Date = Date()) -> FleetDevice.Freshness {
        device.freshness(now: now, thresholds: thresholds)
    }

    /// Serberus Macs per check-in state (all four keys always present).
    public func postureCounts(now: Date = Date()) -> [FleetDevice.Freshness: Int] {
        var counts: [FleetDevice.Freshness: Int] = [.fresh: 0, .stale: 0, .offline: 0, .unknown: 0]
        for device in serberusDevices { counts[freshness(of: device, now: now), default: 0] += 1 }
        return counts
    }

    /// Serberus Macs per daemon State EA value (lowercased; Macs without a
    /// value under ``FleetDevice/postureNotReported``), most common first.
    public var stateCounts: [(value: String, count: Int)] { counts(by: \.daemonState) }
    /// Serberus Macs per enforcement Mode EA value, most common first.
    public var modeCounts: [(value: String, count: Int)] { counts(by: \.enforcementMode) }

    private func counts(by key: (FleetDevice) -> String?) -> [(value: String, count: Int)] {
        var counts: [String: Int] = [:]
        for device in serberusDevices { counts[key(device) ?? FleetDevice.postureNotReported, default: 0] += 1 }
        return counts.map { (value: $0.key, count: $0.value) }
            .sorted { $0.count != $1.count ? $0.count > $1.count : $0.value < $1.value }
    }

    // MARK: Telemetry — decision counts summed across the Serberus fleet

    /// The fleet telemetry decision counts summed over every Serberus Mac that reported
    /// them, plus how many Macs actually carry the telemetry EAs (so a tile can
    /// say "12 denials across 4 Macs" and distinguish "0" from "nobody reports").
    public struct FleetTelemetry: Equatable, Sendable {
        public var denials24h: Int
        public var activeGrants: Int
        public var prompts24h: Int
        /// Serberus Macs that reported at least one telemetry EA value.
        public var reportingDevices: Int
        /// Serberus Macs total (the denominator for coverage).
        public var serberusDevices: Int

        public var hasData: Bool { reportingDevices > 0 }
    }

    /// Sums the telemetry EAs across the Serberus fleet. A Mac contributes 0 for
    /// a metric it does not report; it counts as "reporting" if it reports any
    /// of the three.
    public var telemetry: FleetTelemetry {
        var denials = 0, grants = 0, prompts = 0, reporting = 0
        for device in serberusDevices {
            let d = device.denials24h, g = device.activeGrants, p = device.prompts24h
            if d == nil, g == nil, p == nil { continue }
            denials += d ?? 0
            grants += g ?? 0
            prompts += p ?? 0
            reporting += 1
        }
        return FleetTelemetry(
            denials24h: denials, activeGrants: grants, prompts24h: prompts,
            reportingDevices: reporting, serberusDevices: serberusDevices.count
        )
    }

    /// Serberus Macs with the most denials in the last 24h (only those reporting
    /// a nonzero count), most first — the Dashboard's "Top denial sources".
    public func topDenialSources(limit: Int = 5) -> [(device: FleetDevice, denials: Int)] {
        serberusDevices
            .compactMap { device -> (device: FleetDevice, denials: Int)? in
                guard let d = device.denials24h, d > 0 else { return nil }
                return (device, d)
            }
            .sorted { $0.denials != $1.denials ? $0.denials > $1.denials : $0.device.name < $1.device.name }
            .prefix(limit)
            .map { $0 }
    }

    /// The Serberus devices passing `filter` (the Fleet Observer's list; the
    /// menu bar / Dashboard counts use the same predicate).
    public func serberusDevices(matching filter: FleetFilter, now: Date = Date()) -> [FleetDevice] {
        devices(in: serberusDevices, matching: filter, now: now)
    }

    public func devices(in pool: [FleetDevice], matching filter: FleetFilter, now: Date = Date()) -> [FleetDevice] {
        guard filter.isActive else { return pool }
        return pool.filter { filter.matches($0, freshness: freshness(of: $0, now: now), waitingUploads: waitingUploads(on: $0.id).count) }
    }

    /// Whether a visit should (re)load: nothing loaded yet, or the connection
    /// changed since the current devices were fetched.
    public func needsLoad(for connection: MDMConnection) -> Bool {
        if case .loading = state { return false }
        guard case .loaded = state else { return loadedConnection != connection }
        return loadedConnection != connection
    }

    // MARK: Connection

    /// Why this connection can't drive Fleet Observer, or nil when it can.
    public static func connectionProblem(_ connection: MDMConnection) -> String? {
        guard connection.isComplete else {
            return "Connect Jamf in Settings (URL, API client ID and secret) to load the fleet."
        }
        guard connection.vendor.isSupported else {
            return "\(connection.vendor.displayName) fleet support is not implemented — Fleet Observer reads Jamf Pro only. Switch the vendor to Jamf Pro in Settings."
        }
        guard let url = URL(string: connection.instanceURL.trimmingCharacters(in: .whitespaces)),
              url.scheme != nil, url.host != nil else {
            return "Enter the full Jamf Pro URL including https:// (for example https://yourcompany.jamfcloud.com) in Settings."
        }
        return nil
    }

    // MARK: Refresh

    /// Reloads the whole fleet. A failure keeps the previous devices (stale
    /// but visible) and reports why.
    public func refresh(connection: MDMConnection) async {
        if let problem = Self.connectionProblem(connection) {
            state = .failed(problem)
            return
        }
        guard let client = makeClient(connection) else {
            state = .failed("Connect Jamf in Settings (URL, API client ID and secret) to load the fleet.")
            return
        }
        if case .loading = state { return } // one refresh at a time
        state = .loading
        do {
            let inventory = try await client.listComputers()
            await client.invalidateToken()
            devices = inventory.computers.map(FleetDevice.init(summary:))
            truncatedTotal = inventory.truncated ? inventory.totalCount : nil
            loadedConnection = connection
            lastRefreshed = Date()
            state = .loaded
        } catch {
            await client.invalidateToken()
            state = .failed(Self.describe(error))
        }
    }

    /// Re-reads one computer (its detail always carries attachments, even if
    /// the inventory list could not include the `ATTACHMENTS` section).
    public func reloadDevice(id: String, connection: MDMConnection) async {
        guard let client = makeClient(connection), !reloading.contains(id) else { return }
        reloading.insert(id)
        defer { reloading.remove(id) }
        do {
            let summary = try await client.computer(id: id)
            await client.invalidateToken()
            let device = FleetDevice(summary: summary)
            if let index = devices.firstIndex(where: { $0.id == id }) {
                devices[index] = device
            } else {
                devices.append(device)
            }
        } catch {
            await client.invalidateToken()
            lastError = FleetError(message: Self.describe(error))
        }
    }

    // MARK: Uploads (download / import / delete)

    /// Size cap per kind: captures share the importer's 8 MB gate; Intel
    /// bundles (zips with logs) may be larger but are still bounded.
    public static func maxBytes(for kind: FleetUpload.Kind) -> Int {
        switch kind {
        case .capture: return RuleCapture.maxEncodedBytes
        case .intel: return 256 * 1024 * 1024
        }
    }

    /// Downloads an upload's bytes from the device's Jamf record. Refuses an
    /// attachment the inventory already reports as over the kind's size cap
    /// BEFORE a byte moves, and re-checks what actually arrived (Jamf may
    /// omit `sizeBytes`). Throws `CancellationError` when the same upload is
    /// already in flight (callers ignore it).
    public func downloadUpload(_ upload: FleetUpload, connection: MDMConnection) async throws -> Data {
        let cap = Self.maxBytes(for: upload.kind)
        if let size = upload.sizeBytes, size > cap {
            throw FleetCaptureError.tooLarge(fileName: upload.fileName, bytes: size, limit: cap)
        }
        guard let client = makeClient(connection) else {
            throw JamfError.notConfigured(missingKey: "MDM connection")
        }
        guard !downloading.contains(upload.id) else { throw CancellationError() }
        downloading.insert(upload.id)
        defer { downloading.remove(upload.id) }
        do {
            let data = try await client.downloadAttachment(computerID: upload.computerID, attachmentID: upload.id)
            await client.invalidateToken()
            guard data.count <= cap else {
                throw FleetCaptureError.tooLarge(fileName: upload.fileName, bytes: data.count, limit: cap)
            }
            return data
        } catch {
            await client.invalidateToken()
            throw error
        }
    }

    /// Downloads AND validates a capture — the same size/schema checks the
    /// file importer applies (a Jamf attachment is untrusted input too).
    /// Only captures can be imported; an Intel bundle is downloaded as a file.
    public func fetchCapture(_ upload: FleetUpload, connection: MDMConnection) async throws -> RuleCapture {
        guard upload.kind == .capture else {
            throw FleetCaptureError.invalidCapture(fileName: upload.fileName, underlying: "an Intel bundle is not a capture — download it instead")
        }
        importing.insert(upload.id)
        defer { importing.remove(upload.id) }
        let data = try await downloadUpload(upload, connection: connection)
        do {
            return try RuleCapture.decode(from: data)
        } catch {
            throw FleetCaptureError.invalidCapture(fileName: upload.fileName, underlying: error.localizedDescription)
        }
    }

    /// Removes an upload from the device's Jamf record (after Commander has
    /// downloaded or imported it) and drops it from the local fleet so the
    /// record does not accumulate harvested files. Needs the API role
    /// **Update Computers**. Throws `CancellationError` when already in flight.
    public func deleteUpload(_ upload: FleetUpload, connection: MDMConnection) async throws {
        guard let client = makeClient(connection) else {
            throw JamfError.notConfigured(missingKey: "MDM connection")
        }
        guard !deleting.contains(upload.id) else { throw CancellationError() }
        deleting.insert(upload.id)
        defer { deleting.remove(upload.id) }
        do {
            try await client.deleteAttachment(computerID: upload.computerID, attachmentID: upload.id)
            await client.invalidateToken()
        } catch {
            await client.invalidateToken()
            throw error
        }
        if let index = devices.firstIndex(where: { $0.id == upload.computerID }) {
            devices[index] = devices[index].removingUpload(id: upload.id)
        }
    }

    public func clear() {
        devices = []
        state = .idle
        lastRefreshed = nil
        loadedConnection = nil
        truncatedTotal = nil
        lastError = nil
    }

    // MARK: Plumbing

    func makeClient(_ connection: MDMConnection) -> JamfFleetClient? {
        guard Self.connectionProblem(connection) == nil,
              let url = URL(string: connection.instanceURL.trimmingCharacters(in: .whitespaces)) else { return nil }
        let credentials = JamfCredentials(serverURL: url, clientID: connection.clientID, clientSecret: connection.clientSecret)
        if let client, clientCredentials == credentials { return client }
        let fresh = JamfFleetClient(credentialStore: JamfCredentialStore(override: credentials), transport: transport)
        client = fresh
        clientCredentials = credentials
        return fresh
    }

    /// Operator-facing text for a Jamf / capture failure.
    public static func describe(_ error: Error) -> String {
        if let capture = error as? FleetCaptureError { return capture.localizedDescription }
        guard let jamf = error as? JamfError else { return error.localizedDescription }
        switch jamf {
        case .credentialsInvalid:
            return "Jamf rejected the API client credentials — check the client ID and secret in Settings."
        case let .insufficientPermissions(endpoint):
            return "The Jamf API client lacks permission for \(endpoint). Grant the API role “Read Computers” (and “Update Computers” to delete uploads from a record) — see Settings → Required API permissions."
        case let .unreachable(underlying):
            return "Jamf Pro could not be reached: \(underlying)"
        case let .unexpectedStatus(code, endpoint):
            return code == 404
                ? "Jamf no longer has \(endpoint) (HTTP 404) — the computer or attachment may have been removed. Refresh the fleet."
                : "Jamf returned HTTP \(code) for \(endpoint)."
        case let .responseDecodingFailed(endpoint, _):
            return "Jamf's response for \(endpoint) could not be read — the inventory API shape may have changed."
        case let .notConfigured(missingKey):
            return "Jamf connection incomplete: \(missingKey)."
        }
    }
}
