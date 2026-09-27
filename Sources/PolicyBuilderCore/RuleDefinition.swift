import Foundation
import PrivMgrCore

/// Tier 3 of the authoring model: a pure matcher for exactly one mechanism.
///
/// A definition describes WHAT is matched — an AuthorizationDB right name or a
/// sudo command pattern, plus optional identity pins — and nothing else. The
/// decision (allow/deny, silent/prompt) and every advanced setting live on the
/// ``PolicyRule`` tier, so one definition can be shared by many rules without
/// duplicating the matcher. Definitions never reach the daemon directly:
/// ``PolicyCompiler`` folds them into wire `Rule`s inside frozen v1.0
/// `RuleProfile` documents.
///
/// `kind` reuses the wire `RuleType` (`.sudo` | `.authuri`) rather than
/// introducing a parallel enum — the semantics are identical, and reuse keeps
/// the compile-time mapping trivially correct.
public struct RuleDefinition: Codable, Sendable, Equatable, Identifiable {
    /// Stable slug (`[a-z0-9_]+` by convention), unique across the definition
    /// library. Ids never change after creation — compiled wire rule ids and
    /// rule references embed them.
    public var id: String
    /// Display name shown in the Definitions screen and rule pickers.
    public var name: String
    /// Free-text description of what the matcher covers.
    public var detail: String
    /// Which mechanism this definition matches: `.sudo` or `.authuri`.
    public var kind: RuleType

    // authuri (kind == .authuri)
    /// AuthorizationDB right name, matched exactly.
    public var authURI: String?

    // sudo (kind == .sudo)
    /// Canonical executable path pattern, interpreted per `matchType`.
    public var commandPattern: String?
    /// Second literal path for a **symlinked binary** — the resolved real path
    /// when `commandPattern` is the friendly symlink (`/usr/local/bin/jamf` →
    /// `/usr/local/jamf/bin/jamf`). When non-empty and distinct, the compiler
    /// emits a SECOND wire rule for it so the coarse (sudoers, keyed on the
    /// friendly path) and fine (daemon, keyed on the canonical path) layers are
    /// both covered from ONE authored definition. Empty/nil ⇒ a plain
    /// single-path definition (unchanged). See
    /// `docs/policy-authoring-symlinked-binaries.md`.
    public var resolvedCommandPattern: String?
    /// Regular expression applied to `argv[0]`.
    public var argPattern: String?
    /// Interpretation of `commandPattern`. `nil` defaults to `.exact` on the wire.
    public var matchType: MatchType?

    // app identity (authoringKind == .appIdentity; kind stays .authuri on the wire)
    /// Apple Team ID of the ONE app this definition pins on `authURI`.
    public var appTeamID: String?
    /// The app's code-signing identifier (bundle ID). Non-nil marks the
    /// definition as an App Identity definition: the compiler emits an
    /// identity-scoped wire rule and the daemon COMPOSES the right per app
    /// instead of rewriting it.
    public var appBundleID: String?

    // identity pins (either kind — they are part of WHAT is matched)
    /// When set, the requesting binary's Team ID must equal this value.
    public var requiredTeamID: String?
    /// When set, the requesting binary's SHA-256 must equal this value.
    public var requiredBinaryHash: String?

    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: String,
        name: String,
        detail: String = "",
        kind: RuleType,
        authURI: String? = nil,
        commandPattern: String? = nil,
        resolvedCommandPattern: String? = nil,
        argPattern: String? = nil,
        matchType: MatchType? = nil,
        requiredTeamID: String? = nil,
        requiredBinaryHash: String? = nil,
        appTeamID: String? = nil,
        appBundleID: String? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.detail = detail
        self.kind = kind
        self.authURI = authURI
        self.appTeamID = appTeamID
        self.appBundleID = appBundleID
        self.commandPattern = commandPattern
        self.resolvedCommandPattern = resolvedCommandPattern
        self.argPattern = argPattern
        self.matchType = matchType
        self.requiredTeamID = requiredTeamID
        self.requiredBinaryHash = requiredBinaryHash
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    /// The authoring-level kind: `.appIdentity` when the definition pins an
    /// app (a `.authuri` wire rule with `appIdentity` set), else the wire kind.
    public var authoringKind: DefinitionKind {
        if kind == .authuri, appBundleID != nil { return .appIdentity }
        return kind == .sudo ? .sudo : .authuri
    }

    public var isAppIdentity: Bool { authoringKind == .appIdentity }

    /// The per-app branch this definition compiles to.
    public func appIdentityBranch() -> AppIdentityBranch? {
        guard isAppIdentity else { return nil }
        return AppIdentityBranch(teamID: appTeamID ?? "", bundleID: appBundleID ?? "")
    }

    /// The definition's **primary** wire ``MatchCriteria`` — the `authURI` (for
    /// authuri) or the friendly `commandPattern` (for sudo). This is the single
    /// matcher the reverse-mapping migration and the composer preview reason
    /// about; the compiler uses ``matchCriteriaList()`` to also emit the
    /// resolved-path twin when one is set.
    ///
    /// The mapping is kind-shaped so compiled rules always pass the
    /// validator's `match-shape` check: an authuri definition never emits
    /// command fields and a sudo definition never emits `authURI`, even if
    /// stale values linger from a kind switch in the editor. Identity pins
    /// are legal on both kinds.
    public func matchCriteria() -> MatchCriteria {
        switch kind {
        case .authuri:
            return MatchCriteria(
                authURI: authURI,
                requiredTeamID: requiredTeamID,
                requiredBinaryHash: requiredBinaryHash
            )
        case .sudo:
            return MatchCriteria(
                commandPattern: commandPattern,
                argPattern: argPattern,
                matchType: matchType,
                requiredTeamID: requiredTeamID,
                requiredBinaryHash: requiredBinaryHash
            )
        }
    }

    /// Every wire ``MatchCriteria`` this definition compiles to.
    ///
    /// One entry for a plain definition; **two** for a symlinked-binary sudo
    /// definition — the friendly `commandPattern` plus a distinct, non-empty
    /// ``resolvedCommandPattern`` — so a single authored row covers both the
    /// coarse (friendly-path) and fine (canonical-path) layers. The resolved
    /// twin inherits the same `argPattern`, `matchType`, and identity pins;
    /// only the path differs. Order is stable (friendly first) so compiled wire
    /// rule ids are deterministic.
    public func matchCriteriaList() -> [MatchCriteria] {
        var list = [matchCriteria()]
        guard kind == .sudo,
              let resolved = resolvedCommandPattern?.trimmingCharacters(in: .whitespaces),
              !resolved.isEmpty,
              resolved != commandPattern
        else { return list }
        list.append(MatchCriteria(
            commandPattern: resolved,
            argPattern: argPattern,
            matchType: matchType,
            requiredTeamID: requiredTeamID,
            requiredBinaryHash: requiredBinaryHash
        ))
        return list
    }
}

// MARK: - Authoring kind

/// The three definition kinds Commander authors. Two are the wire mechanisms;
/// App Identity is an authorization right pinned to ONE app (Team ID + bundle
/// ID), stored as a `.authuri` definition with the app fields set and compiled
/// into an identity-scoped wire rule. Kept separate from the wire `RuleType`
/// so the daemon's vocabulary never grows a third mechanism it does not have.
public enum DefinitionKind: String, CaseIterable, Sendable, Codable, Identifiable {
    case sudo
    case authuri
    case appIdentity = "app-identity"

    public var id: String { rawValue }

    /// The wire mechanism the definition compiles to.
    public var wireType: RuleType {
        switch self {
        case .sudo: return .sudo
        case .authuri, .appIdentity: return .authuri
        }
    }

    public var title: String {
        switch self {
        case .sudo: return "Sudo command"
        case .authuri: return "Authorization right"
        case .appIdentity: return "App Identity"
        }
    }

    public var symbol: String {
        switch self {
        case .sudo: return "terminal.fill"
        case .authuri: return "lock.fill"
        case .appIdentity: return "app.badge.checkmark"
        }
    }
}

