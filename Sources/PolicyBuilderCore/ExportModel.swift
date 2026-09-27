import Foundation
import Observation
import PrivMgrCore

/// Drives MobileConfig export. Runs the full pre-export
/// validation pipeline over ALL of a policy's compiled profiles (a policy can
/// compile to both a sudo and an authuri profile — blocking errors in either
/// prevent export) and surfaces cross-profile conflicts against the rest of
/// the compiled library, which require a mandatory acknowledgement before
/// export proceeds.
@MainActor
@Observable
public final class ExportModel {
    public var organization: String = "Serberus"
    /// One report per compiled profile of the policy being exported. Empty
    /// until ``prepare(profiles:library:)`` runs, or when the policy compiled
    /// to nothing.
    public private(set) var reports: [ValidationReport] = []
    public private(set) var conflicts: [ConflictDetector.CrossProfileConflict] = []
    public var conflictsAcknowledged = false
    public private(set) var lastError: String?
    /// The profiles ``prepare(profiles:library:)`` was last given — kept so
    /// the export sheet can render key/version rows without re-compiling.
    public private(set) var preparedProfiles: [RuleProfile] = []

    public init() {}

    /// Refreshes validation + conflict state for a policy's compiled
    /// `profiles` against the rest of the compiled `library`. Call before
    /// presenting the export sheet.
    public func prepare(profiles: [RuleProfile], library: [RuleProfile]) {
        preparedProfiles = profiles
        reports = profiles.map { PolicyValidator().validate($0) }
        conflicts = profiles.flatMap { ConflictDetector().crossProfileConflicts($0, against: library) }
        conflictsAcknowledged = false
        lastError = nil
    }

    /// Blocking errors across every prepared profile.
    public var errorCount: Int { reports.reduce(0) { $0 + $1.errors.count } }

    /// Whether export may proceed: at least one compiled profile, no blocking
    /// errors in any of them, and any cross-profile conflicts acknowledged.
    public func canExport() -> Bool {
        guard !reports.isEmpty, reports.allSatisfy(\.isExportable) else { return false }
        if !conflicts.isEmpty && !conflictsAcknowledged { return false }
        return true
    }

    /// Generates ONE combined `.mobileconfig` delivering every compiled
    /// profile of the policy (N `rules_*` keys in a single payload), or
    /// captures the reason it could not.
    public func export(profiles: [RuleProfile]) -> MobileConfigGenerator.Export? {
        guard canExport() else {
            lastError = blockingReason()
            return nil
        }
        do {
            let export = try MobileConfigGenerator().export(profiles: profiles, organization: organization)
            lastError = nil
            return export
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    /// Generates the flat rules-domain settings `.plist` for the policy's
    /// compiled profiles — the file the operator uploads through Jamf's
    /// "Application & Custom Settings → Upload File" flow — gated by the same
    /// validation and conflict checks as `.mobileconfig` export.
    public func exportSettingsPlist(profiles: [RuleProfile]) -> MobileConfigGenerator.SettingsPlist? {
        guard canExport() else {
            lastError = blockingReason()
            return nil
        }
        do {
            let plist = try MobileConfigGenerator().rulesSettingsPlist(profiles: profiles)
            lastError = nil
            return plist
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    /// Generates the Jamf **Custom Schema** JSON for the policy — the shipped
    /// rules schema, pointed at a per-policy sub-domain and pre-filled with the
    /// compiled rules — for Jamf's "Application & Custom Settings → External
    /// Applications → Custom Schema" flow, where the profile renders as an
    /// editable form in the console. Same validation gate as the other exports.
    public func exportJamfSchema(profiles: [RuleProfile], policyID: String, policyName: String) -> JamfRulesSchema.Export? {
        guard canExport() else {
            lastError = blockingReason()
            return nil
        }
        do {
            let export = try JamfRulesSchema.export(policyID: policyID, policyName: policyName, profiles: profiles)
            lastError = nil
            return export
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    /// Human-readable reason export is blocked, for the UI.
    public func blockingReason() -> String? {
        if reports.isEmpty {
            return "This policy compiles to no profiles — enable at least one rule with a definition."
        }
        if errorCount > 0 {
            return "Fix \(errorCount) validation error(s) before exporting."
        }
        if !conflicts.isEmpty && !conflictsAcknowledged {
            return "Acknowledge \(conflicts.count) cross-profile conflict(s) before exporting."
        }
        return nil
    }
}

/// In-memory version history for a profile key (the profile library's
/// version history). Persistence layers on in a future version; the model
/// keeps the published snapshots so the UI can show and diff versions.
@MainActor
@Observable
public final class ProfileHistory {
    public private(set) var versions: [RuleProfile] = []

    public init(versions: [RuleProfile] = []) {
        self.versions = versions
    }

    /// Records a published snapshot, keeping at most one entry per policy
    /// version (re-publishing a version replaces it).
    public func record(_ profile: RuleProfile) {
        if let index = versions.firstIndex(where: { $0.policyVersion == profile.policyVersion }) {
            versions[index] = profile
        } else {
            versions.append(profile)
        }
        versions.sort { $0.policyVersion < $1.policyVersion }
    }

    public var latest: RuleProfile? { versions.last }
}
