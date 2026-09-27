import Foundation
import PrivMgrCore

/// A mutable, UI-friendly editing model for a single library rule (tier 2).
///
/// The Rules composer edits ``RuleDraft`` values (all fields settable, no
/// optionals, so SwiftUI can bind directly), then converts to the value-type
/// ``PolicyRule`` for the model's `upsertRule(_:)`. Keeping a separate draft
/// type avoids scattering sentinel handling across SwiftUI bindings. No
/// validation happens in either direction — authoring validation runs on the
/// COMPILED profiles (``PolicyBuilderModel/validationReport(forPolicy:)``).
public struct RuleDraft: Identifiable, Sendable, Equatable {
    /// SwiftUI view identity only — never persisted.
    public let id: UUID
    /// The library rule's stable id. Empty for a brand-new draft until the
    /// composer commits (generate via ``AuthoringID`` from the name).
    public var ruleID: String
    public var name: String
    public var detail: String
    /// Ordered references into the definition library (the composer's
    /// multi-select).
    public var definitionIDs: [String]
    public var action: RuleAction
    public var elevationType: ElevationType

    // Advanced
    public var priority: Int
    /// `nil` wire cache (use global) is represented by `useGlobalCache == true`.
    public var useGlobalCache: Bool
    public var cacheSeconds: Int
    public var requireJustification: Bool
    public var maxGrantDurationSeconds: Int
    public var logArguments: Bool

    public init(
        id: UUID = UUID(),
        ruleID: String = "",
        name: String = "",
        detail: String = "",
        definitionIDs: [String] = [],
        action: RuleAction = .allow,
        elevationType: ElevationType = .silent,
        priority: Int = 50,
        useGlobalCache: Bool = true,
        cacheSeconds: Int = 0,
        requireJustification: Bool = false,
        maxGrantDurationSeconds: Int = 0,
        logArguments: Bool = false
    ) {
        self.id = id
        self.ruleID = ruleID
        self.name = name
        self.detail = detail
        self.definitionIDs = definitionIDs
        self.action = action
        self.elevationType = elevationType
        self.priority = priority
        self.useGlobalCache = useGlobalCache
        self.cacheSeconds = cacheSeconds
        self.requireJustification = requireJustification
        self.maxGrantDurationSeconds = maxGrantDurationSeconds
        self.logArguments = logArguments
    }

    /// Converts the draft to a ``PolicyRule`` under `ruleID`. Timestamps are
    /// stamped "now"; ``PolicyBuilderModel/upsertRule(_:)`` preserves the
    /// stored `createdAt` when the id already exists, so drafts never need to
    /// carry dates.
    public func toPolicyRule() -> PolicyRule {
        PolicyRule(
            id: ruleID,
            name: name,
            detail: detail,
            definitionIDs: definitionIDs,
            action: action,
            elevationType: elevationType,
            priority: priority,
            useGlobalCache: useGlobalCache,
            cacheSeconds: cacheSeconds,
            requireJustification: requireJustification,
            maxGrantDurationSeconds: maxGrantDurationSeconds,
            logArguments: logArguments
        )
    }

    /// Builds a draft from an existing library rule (opening the composer to
    /// edit).
    public init(rule: PolicyRule) {
        self.init(
            ruleID: rule.id,
            name: rule.name,
            detail: rule.detail,
            definitionIDs: rule.definitionIDs,
            action: rule.action,
            elevationType: rule.elevationType,
            priority: rule.priority,
            useGlobalCache: rule.useGlobalCache,
            cacheSeconds: rule.cacheSeconds,
            requireJustification: rule.requireJustification,
            maxGrantDurationSeconds: rule.maxGrantDurationSeconds,
            logArguments: rule.logArguments
        )
    }
}

/// A mutable, UI-friendly editing model for a single definition (tier 3).
///
/// Same pattern as ``RuleDraft``: optionals flattened to empty-string
/// bindables, converted to the value-type ``RuleDefinition`` on commit. The
/// conversion is kind-shaped — switching the kind picker mid-edit never leaks
/// the other mechanism's fields into the saved definition.
public struct DefinitionDraft: Identifiable, Sendable, Equatable {
    /// SwiftUI view identity only — never persisted.
    public let id: UUID
    /// The definition's stable id. Empty for a brand-new draft until the
    /// composer commits (generate via ``AuthoringID`` from the name).
    public var definitionID: String
    public var kind: RuleType
    public var name: String
    public var detail: String

    // authuri
    public var authURI: String

    // sudo
    public var commandPattern: String
    /// Second literal path for a symlinked binary (the resolved real path). When
    /// non-empty, the definition compiles to a second `.exact` wire rule so one
    /// authored row covers both the friendly and resolved paths. Empty ⇒ plain
    /// single-path definition.
    public var resolvedCommandPattern: String
    public var argPattern: String
    public var matchType: MatchType

    // identity pins (either kind)
    public var requiredTeamID: String
    public var requiredBinaryHash: String

    // app identity (authoringKind == .appIdentity)
    /// True when the draft is an App Identity definition (kind stays
    /// `.authuri` on the wire).
    public var appIdentity: Bool
    public var appTeamID: String
    public var appBundleID: String

    /// The kind tile the composer shows. Setting it keeps `kind` and
    /// `appIdentity` consistent.
    public var authoringKind: DefinitionKind {
        get { appIdentity && kind == .authuri ? .appIdentity : (kind == .sudo ? .sudo : .authuri) }
        set {
            kind = newValue.wireType
            appIdentity = newValue == .appIdentity
        }
    }

    public init(
        id: UUID = UUID(),
        definitionID: String = "",
        kind: RuleType = .sudo,
        name: String = "",
        detail: String = "",
        authURI: String = "",
        commandPattern: String = "",
        resolvedCommandPattern: String = "",
        argPattern: String = "",
        matchType: MatchType = .exact,
        requiredTeamID: String = "",
        requiredBinaryHash: String = "",
        appIdentity: Bool = false,
        appTeamID: String = "",
        appBundleID: String = ""
    ) {
        self.id = id
        self.definitionID = definitionID
        self.kind = kind
        self.appIdentity = appIdentity
        self.appTeamID = appTeamID
        self.appBundleID = appBundleID
        self.name = name
        self.detail = detail
        self.authURI = authURI
        self.commandPattern = commandPattern
        self.resolvedCommandPattern = resolvedCommandPattern
        self.argPattern = argPattern
        self.matchType = matchType
        self.requiredTeamID = requiredTeamID
        self.requiredBinaryHash = requiredBinaryHash
    }

    /// Converts the draft to a ``RuleDefinition`` under `definitionID`.
    /// Empty fields collapse to `nil`; only the active kind's matcher fields
    /// are emitted. Timestamps are stamped "now" and
    /// ``PolicyBuilderModel/upsertDefinition(_:)`` preserves the stored
    /// `createdAt` on replace.
    public func toDefinition() -> RuleDefinition {
        let trimmedTeam = requiredTeamID.trimmingCharacters(in: .whitespaces)
        let trimmedHash = requiredBinaryHash.trimmingCharacters(in: .whitespaces)
        switch kind {
        case .authuri:
            // App Identity: the app pin IS the identity; the generic pins
            // are not emitted (the requirement already binds team + bundle).
            let team = appTeamID.trimmingCharacters(in: .whitespaces).uppercased()
            let bundle = appBundleID.trimmingCharacters(in: .whitespaces)
            return RuleDefinition(
                id: definitionID,
                name: name,
                detail: detail,
                kind: .authuri,
                authURI: authURI.isEmpty ? nil : authURI,
                requiredTeamID: appIdentity ? nil : (trimmedTeam.isEmpty ? nil : trimmedTeam),
                requiredBinaryHash: appIdentity ? nil : (trimmedHash.isEmpty ? nil : trimmedHash),
                appTeamID: appIdentity ? team : nil,
                // An empty bundle still marks the definition as App Identity
                // (empty string, not nil) so the kind survives a half-filled
                // save and the validator reports the missing pin.
                appBundleID: appIdentity ? bundle : nil
            )
        case .sudo:
            let trimmedResolved = resolvedCommandPattern.trimmingCharacters(in: .whitespaces)
            return RuleDefinition(
                id: definitionID,
                name: name,
                detail: detail,
                kind: .sudo,
                commandPattern: commandPattern.isEmpty ? nil : commandPattern,
                resolvedCommandPattern: trimmedResolved.isEmpty ? nil : trimmedResolved,
                argPattern: argPattern.isEmpty ? nil : argPattern,
                matchType: matchType,
                requiredTeamID: trimmedTeam.isEmpty ? nil : trimmedTeam,
                requiredBinaryHash: trimmedHash.isEmpty ? nil : trimmedHash
            )
        }
    }

    /// Builds a draft from an existing definition (opening the composer to
    /// edit).
    public init(definition: RuleDefinition) {
        self.init(
            definitionID: definition.id,
            kind: definition.kind,
            name: definition.name,
            detail: definition.detail,
            authURI: definition.authURI ?? "",
            commandPattern: definition.commandPattern ?? "",
            resolvedCommandPattern: definition.resolvedCommandPattern ?? "",
            argPattern: definition.argPattern ?? "",
            matchType: definition.matchType ?? .exact,
            requiredTeamID: definition.requiredTeamID ?? "",
            requiredBinaryHash: definition.requiredBinaryHash ?? "",
            appIdentity: definition.isAppIdentity,
            appTeamID: definition.appTeamID ?? "",
            appBundleID: definition.appBundleID ?? ""
        )
    }
}
