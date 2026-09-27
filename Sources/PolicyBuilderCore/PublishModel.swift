import Foundation
import Observation
import PrivMgrCore

/// Required Jamf API permissions and the features they unlock.
/// Surfaced in Settings as a checklist; `requiredInV1` distinguishes the
/// permissions the Policy Builder needs now from V1.1 fleet features.
public struct JamfPermission: Identifiable, Sendable, Equatable {
    public let id: String
    public let feature: String
    /// Whether a shipped feature needs it today, a shipped feature improves
    /// with it, or it is reserved for a planned feature.
    public let tier: Tier

    public enum Tier: Sendable, Equatable {
        /// A shipped Commander feature does not work without it.
        case required
        /// Optional: a shipped feature shows more when granted.
        case optional
        /// Reserved for a planned (V1.1) feature — not needed yet.
        case planned
    }

    public init(id: String, feature: String, tier: Tier) {
        self.id = id
        self.feature = feature
        self.tier = tier
    }

    /// Backwards-compatible accessor: required today.
    public var requiredInV1: Bool { tier == .required }

    public static let all: [JamfPermission] = [
        .init(id: "Read Configuration Profiles", feature: "Commander — list profiles", tier: .required),
        .init(id: "Create Configuration Profiles", feature: "Commander — publish new", tier: .required),
        .init(id: "Update Configuration Profiles", feature: "Commander — update existing", tier: .required),
        .init(id: "Read Computers", feature: "Fleet Observer — device inventory + capture download", tier: .required),
        .init(id: "Read Computer Extension Attributes", feature: "Fleet Observer — Serberus posture EAs, when deployed", tier: .optional),
        .init(id: "Update Computers", feature: "Fleet Observer — delete harvested uploads from the computer record", tier: .optional),
        .init(id: "Read Jamf Pro Policies", feature: "Emergency revocation (V1.1)", tier: .planned),
        .init(id: "Trigger Jamf Pro Policies", feature: "Emergency revocation (V1.1)", tier: .planned),
    ]

    public static let requiredInV1 = all.filter(\.requiredInV1)
}

/// Drives publishing a profile to Jamf Pro. The Policy Builder
/// stays fully functional offline; publish is the only daemon/Jamf-dependent
/// action. Create-vs-update is decided by matching the profile's name.
@MainActor
@Observable
public final class PublishModel {
    public enum Status: Equatable, Sendable {
        case idle
        case working
        case published(id: Int, updated: Bool)
        case failed(String)
    }

    public private(set) var status: Status = .idle
    private let client: JamfAPIClient

    public init(client: JamfAPIClient = JamfAPIClient()) {
        self.client = client
    }

    public let permissions = JamfPermission.all

    /// Publishes `mobileconfig` under `name`, updating the existing profile if
    /// one already carries that name, else creating a new one.
    public func publish(name: String, mobileconfig: Data) async {
        status = .working
        do {
            let existing = try await client.listConfigurationProfiles()
            if let match = existing.first(where: { JamfAPIClient.profileNamesMatch($0.name, name) }) {
                try await client.updateConfigurationProfile(id: match.id, name: name, mobileconfig: mobileconfig)
                status = .published(id: match.id, updated: true)
            } else {
                let id = try await client.createConfigurationProfile(name: name, mobileconfig: mobileconfig)
                status = .published(id: id, updated: false)
            }
        } catch {
            status = .failed(error.localizedDescription)
        }
    }
}
