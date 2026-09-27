import Foundation
import PrivMgrCore
import Security

/// Manages dynamic AuthorizationDB interception under the AuthorizationDB
/// guardrails: snapshot (checksummed) every original before modification, diff
/// current vs desired and perform minimal changes, and restore all modified
/// rights on uninstall / upgrade failure. A right a rule names that this macOS
/// doesn't define is created, with a tombstone so restore removes it again (see
/// ``apply(_:compositions:)``). Every modification emits an integrity event
/// (a pass that retries a failed one does not repeat what that pass logged;
/// see ``RetryNoticeFilter``).
///
/// Two shapes of change are supported:
/// - **Projection** (plain authuri rules): the right's definition is REWRITTEN
///   to a static policy (deny / session-owner-or-admin).
/// - **Composition** (identity-scoped authuri rules): the right is never
///   rewritten in place. Its live native definition is captured once and
///   preserved as a named `native-default` branch, one named sub-rule is
///   synthesized per app (code requirement + session-owner-or-admin), and the top-level right
///   becomes `k-of-n: 1` over `[app-1, app-2, …, native-default]`. No other
///   caller's posture changes. See ``compose(_:result:)``.
///
/// The backend and snapshot store are injected so the full lifecycle —
/// discover, snapshot, minimal-diff inject/compose, restore — is unit-tested
/// with an in-memory mock, no root or live authdb required.
public struct AuthorizationDBManager: Sendable {
    private let backend: AuthorizationDBBackend
    private let store: AuthorizationDBSnapshotStore
    private let integrityLogger: IntegrityLogger?
    private let daemonVersion: String
    private let now: @Sendable () -> Date
    /// The verification table consulted (advisory only) before a composition:
    /// it drives the integrity-log warnings, never a refusal. Injected so tests
    /// can drive every state; production uses the shipped table.
    private let scopeRegistry: AuthURIIdentityScopeRegistry
    /// This Mac's macOS major, for the "newer than verified" warning.
    private let osMajor: Int
    /// `enableBiometrics` from the daemon's EFFECTIVE config (the delivered
    /// profile, or the last-known-good snapshot when the profile is absent):
    /// when true an app branch authenticates the session owner ONLY, which is
    /// what lets macOS offer Touch ID. Default false = session-owner-or-admin.
    ///
    /// A CLOSURE, not a stored value: the manager is built once at daemon
    /// start but an MDM push can flip this key at any time. Production wires it
    /// to an ``AuthorizationDBEffectiveSettings`` box the daemon updates each
    /// time it resolves its effective config — never to a fresh read of the
    /// live managed domain, which would diverge from the config the daemon is
    /// actually enforcing when the profile is removed.
    private let sessionOwnerOnly: @Sendable () -> Bool
    /// Checks the SerberusAuth plugin bundle before any composition (see
    /// ``apply(_:compositions:)``). Injected so tests drive both outcomes
    /// without a real bundle in `/Library/Security/SecurityAgentPlugins`.
    private let authPluginVerifier: AuthPluginBundleVerifying
    /// Shared (reference) state: the cached plugin verdict keyed by the
    /// bundle's cheap `lstat` fingerprint, and the last "identity-scoped rules
    /// not enforced" problem, which the daemon surfaces as
    /// `degraded(auth_plugin_unavailable)`.
    private let pluginState = AuthPluginState()
    /// Shared (reference) state: what the last reconcile pass logged, when it
    /// failed. The daemon retries a failed reconcile on every reload tick, and
    /// a retry does not write again what the pass before it already logged
    /// (see ``RetryNoticeFilter``).
    private let retryNotices = RetryNoticeFilter()
    /// Apple's shipped definition of a right (from
    /// `/System/Library/Security/authorization.plist`), or nil when Apple
    /// does not ship that name. Restore writes it when the original is
    /// unrecoverable. Injected so tests never depend on this Mac's plist.
    private let shippedDefinitions: @Sendable (String) -> Data?

    public init(
        backend: AuthorizationDBBackend,
        store: AuthorizationDBSnapshotStore,
        integrityLogger: IntegrityLogger?,
        daemonVersion: String = DaemonVersion.current.daemonVersion,
        now: @escaping @Sendable () -> Date = { Date() },
        scopeRegistry: AuthURIIdentityScopeRegistry = .current,
        osMajor: Int = MacOSVersion.currentMajor,
        sessionOwnerOnly: @escaping @Sendable () -> Bool = { false },
        authPluginVerifier: AuthPluginBundleVerifying = SystemAuthPluginBundleVerifier(),
        shippedDefinitions: @escaping @Sendable (String) -> Data? = { AuthorizationDBManager.shippedDefinition(of: $0) }
    ) {
        self.backend = backend
        self.store = store
        self.integrityLogger = integrityLogger
        self.daemonVersion = daemonVersion
        self.now = now
        self.scopeRegistry = scopeRegistry
        self.osMajor = osMajor
        self.sessionOwnerOnly = sessionOwnerOnly
        self.authPluginVerifier = authPluginVerifier
        self.shippedDefinitions = shippedDefinitions
    }

    /// A right Serberus wants the authdb to reflect.
    public struct DesiredRight: Sendable, Equatable {
        public let name: String
        /// The desired definition (serialized XML plist). When `nil`, the
        /// right is snapshotted and validated but left unmodified — the V1
        /// conservative default (no live modification until the interception
        /// mechanism is defined), which still satisfies guardrails 1–5 & 10.
        public let definition: Data?
        /// True for a plain `allow` projection: it is written only when the
        /// right's native definition is a plain admin gate (see
        /// ``AuthRightNativeGate/plainAllowRefusal(_:lookup:)``), so the rewrite
        /// adds the session owner and nothing else.
        public let requiresNativeAdminGate: Bool

        public init(name: String, definition: Data? = nil, requiresNativeAdminGate: Bool = false) {
            self.name = name
            self.definition = definition
            self.requiresNativeAdminGate = requiresNativeAdminGate
        }

        /// True when the desired definition is a `class=deny`.
        var isDeny: Bool {
            guard let definition else { return false }
            return AuthorizationDBManager.policyFields(definition)["class"] == "deny"
        }
    }

    /// A right Serberus wants COMPOSED from per-app branches.
    public struct DesiredComposition: Sendable, Equatable {
        public let right: String
        /// Sorted by row slug so row names and the top-level array are
        /// deterministic across runs.
        public let branches: [AppIdentityBranch]

        public init(right: String, branches: [AppIdentityBranch]) {
            self.right = right
            self.branches = branches.sorted { $0.rowSlug < $1.rowSlug }
        }
    }

    /// The distinct auth URI right names referenced by allow/prompt authuri
    /// rules across all profiles, sorted (deterministic).
    public static func discoverRightNames(in profiles: [RuleProfile]) -> [String] {
        var names: Set<String> = []
        for profile in profiles {
            for rule in profile.rules where rule.type == .authuri {
                if let uri = rule.match.authURI {
                    names.insert(uri)
                }
            }
        }
        return names.sorted()
    }

    /// The static AuthorizationDB policy an authuri rule projects onto a right.
    ///
    /// macOS AuthorizationDB rewriting is *static*: it cannot route an
    /// authorization through the Serberus Sentinel (that needs an authorization
    /// plugin). So a `.prompt` authuri rule maps to the **native** admin-auth
    /// gate, not the Sentinel prompt; and per-request identity/conditions are not
    /// expressible here (those apply on the sudo/ESF paths).
    ///
    /// There is deliberately no `class=allow` policy: statically stripping
    /// authentication from a right is an auth-bypass (see ``policy(for:)``),
    /// and nothing ever produced one.
    public enum AuthURIPolicy: Sendable, Equatable {
        /// `class=rule → authenticate-session-owner-or-admin` — the logged-in
        /// user authenticates with their OWN password (or any admin with theirs).
        /// This is what an `allow` authuri rule projects to: it lets a standard
        /// user self-serve the right instead of being handed admin credentials.
        case requireSessionOwnerOrAdmin
        /// `class=rule → authenticate-admin` — native admin-only authentication.
        /// Not produced by policy projection any more; retained as the
        /// conservative reset target when an original definition's snapshot is
        /// unrecoverable (see ``restoreAll()``).
        case requireAdmin
        /// `class=deny` — always blocked.
        case deny

        /// Higher = more restrictive; conflicts resolve to the most restrictive.
        /// admin-only is more restrictive than session-owner-or-admin — fewer
        /// principals can satisfy it.
        var restrictiveness: Int {
            switch self {
            case .requireSessionOwnerOrAdmin: return 1
            case .requireAdmin: return 2
            case .deny: return 3
            }
        }

        /// The definition with Serberus's ``managedMarker`` comment, so a
        /// rewritten right is always recognisable as Serberus's own. The
        /// admin-auth stand-in is the exception: it carries
        /// ``AuthorizationDBManager/standInComment`` and no marker, because
        /// it is the terminal state of a restore, and the uninstallers must
        /// not read it as a right Serberus still manages. Serberus
        /// recognises its stand-in by the digest it records
        /// (``AuthorizationDBSnapshotStore/saveStandInDigest(_:rightName:)``).
        var definitionDictionary: [String: Any] {
            var body = policyBody
            switch self {
            case .requireAdmin:
                body["comment"] = AuthorizationDBManager.standInComment
            case .requireSessionOwnerOrAdmin, .deny:
                body["comment"] = "Serberus projection (\(label)). \(AuthorizationDBManager.managedMarker)"
            }
            return body
        }

        private var label: String {
            switch self {
            case .requireSessionOwnerOrAdmin: return "session owner or admin"
            case .requireAdmin: return "admin-auth stand-in"
            case .deny: return "deny"
            }
        }

        private var policyBody: [String: Any] {
            switch self {
            case .deny: return ["class": "deny"]
            case .requireSessionOwnerOrAdmin:
                // A self-contained `class=user` definition — NOT a delegate to the
                // built-in `authenticate-session-owner-or-admin` rule, whose
                // `allow-root=false` is exactly what breaks a non-interactive
                // managed install. The session owner self-serves with their OWN
                // password (`session-owner`) and any admin with theirs (`group`),
                // AND a root/non-interactive caller is authorized WITHOUT
                // authentication (`allow-root=true`).
                //
                // MDM/installer non-interference invariant: this root pass-through
                // is why rewriting an install right (e.g. an authuri allow rule for
                // `system.install.software`, letting standard users self-install)
                // no longer breaks a Jamf/MDM `installer`, which runs as root with
                // no session to authenticate. The right still gates non-root users;
                // root — the only context an MDM policy runs in — passes.
                //
                // No `version`: authd manages it, and a stamped one could hold
                // back Apple's own version-gated update of the right. The
                // native credential `timeout` and `shared` are carried over at
                // apply time (see ``projection(_:native:)``).
                return [
                    "class": "user",
                    "group": "admin",
                    "session-owner": true,
                    "authenticate-user": true,
                    "allow-root": true,
                    "shared": false,
                    "tries": 10000,
                ]
            case .requireAdmin:
                // Admin-only reset target (used only when an original definition's
                // snapshot is unrecoverable). Root-passable for the same invariant:
                // an unrecoverable reset must never block a managed context either.
                return [
                    "class": "user",
                    "group": "admin",
                    "authenticate-user": true,
                    "allow-root": true,
                    "shared": false,
                    "tries": 10000,
                ]
            }
        }
    }

    /// Right-name prefixes Serberus must NEVER modify, even if a rule names
    /// them — see ``AuthRightTargetPolicy/protectedRightPrefixes``, which the
    /// runtime parser and the Commander validator share. A right matching any
    /// of these is left untouched (fail-closed) and logged.
    public static var protectedRightPrefixes: [String] { AuthRightTargetPolicy.protectedRightPrefixes }

    /// Whether `rightName` is on the never-touch deny-list.
    public static func isProtected(_ rightName: String) -> Bool {
        AuthRightTargetPolicy.isProtected(rightName)
    }

    /// Rights a plain `allow` rule must never open (matched as prefixes). An
    /// allow projects to "the session owner's own password", so each of these
    /// would hand every standard user root, or a direct path to it. Deny rules
    /// on them are still honoured, and letting ONE verified app use a right (an
    /// identity-scoped rule) is governed separately by
    /// ``AuthURIIdentityScopeRegistry``.
    public static var rootEquivalentRightPrefixes: [String] { AuthRightTargetPolicy.rootEquivalentRightPrefixes }

    /// Whether a plain `allow` rule may not open `rightName` (prefix entries,
    /// plus the exact-only entries).
    public static func isRootEquivalent(_ rightName: String) -> Bool {
        AuthRightTargetPolicy.isRootEquivalent(rightName)
    }

    /// The marker every definition Serberus WRITES carries in its `comment`
    /// (authd stores and returns `comment` verbatim). It is how a definition
    /// Serberus rewrote is told apart from a native one when the snapshot of
    /// the original has been lost: such a definition is never snapshotted as
    /// the "original" (see ``isSerberusWritten(_:)``). The composer's rows and
    /// top-level carry it too; the preserved `native-default` row does not,
    /// because it IS the native definition, and neither does the admin-auth
    /// stand-in, which Serberus recognises by its recorded digest instead
    /// (``isRecordedStandIn(_:right:)``).
    ///
    /// Anyone who can create a right can copy this string, so it is a hint
    /// for the restore sweep, never proof: the uninstallers gate on
    /// Serberus's records and on live SerberusAuth mechanisms, not on it.
    public static let managedMarker = "Managed by serberusd; do not edit."

    /// The comment of the admin-auth stand-in (see ``AuthURIPolicy/requireAdmin``).
    /// Deliberately without ``managedMarker``.
    public static let standInComment = "Serberus admin-auth stand-in: the original definition could not be recovered."

    /// The comment older daemons wrote into the stand-in, marker included.
    static let legacyStandInLabel = "admin-auth reset"

    /// Whether `definition` was written by Serberus: it carries
    /// ``managedMarker``, or it is a composed top-level referencing owned rows
    /// (the structural guard the composer already used).
    static func isSerberusWritten(_ definition: Data) -> Bool {
        carriesManagedMarker(definition) || referencesOwnedRows(definition)
    }

    static func carriesManagedMarker(_ definition: Data) -> Bool {
        guard let comment = dictionary(definition)?["comment"] as? String else { return false }
        return comment.contains(managedMarker)
    }

    /// Projects one authuri ``Rule`` onto its static authdb policy.
    ///
    /// `allow` never maps to `class=allow`: statically stripping authentication
    /// from a right (which may originally have required admin) is an auth-bypass —
    /// the opposite of what a security tool should do. Instead, both silent and
    /// prompt allow rules map to `authenticate-session-owner-or-admin`: the
    /// logged-in user authenticates with their OWN password (an admin may also
    /// use theirs), so a STANDARD user can self-serve the right — the whole point
    /// of an authuri allow rule — without being handed admin credentials. It
    /// still fails closed for conditional allows whose identity pins /
    /// justification static rewriting cannot replay: an unauthenticated caller is
    /// always challenged. Only `deny` blocks outright.
    static func policy(for rule: Rule) -> AuthURIPolicy {
        switch rule.action {
        case .deny: return .deny
        case .allow: return .requireSessionOwnerOrAdmin
        }
    }

    /// The desired right definitions for every PLAIN authuri right referenced
    /// by policy (identity-scoped rules are composed, not projected — see
    /// ``desiredCompositions(in:perAppPinsEnabled:)``). When a right is governed by multiple rules
    /// the **most restrictive** projection wins (deny > require-admin > allow):
    /// static rewriting fails closed because it cannot replay the engine's
    /// per-request identity/condition checks. Sorted, deterministic.
    public static func desiredRights(in profiles: [RuleProfile]) -> [DesiredRight] {
        var policies: [String: AuthURIPolicy] = [:]
        for profile in profiles {
            for rule in profile.rules where rule.type == .authuri && rule.appIdentity == nil {
                guard let name = rule.match.authURI, !isProtected(name) else { continue }
                // Defense in depth: the runtime parser already drops these
                // (rule-class and wildcard targets, a deny on a login
                // right), but a caller that built profiles itself must not
                // get them projected either. Logged via ``skippedRules(_:perAppPinsEnabled:)``.
                guard rule.runtimeRejectionReason == nil else { continue }
                // An allow on a root-equivalent right is dropped (the right stays
                // native); a deny on one still applies.
                if rule.action == .allow, isRootEquivalent(name) { continue }
                let projected = policy(for: rule)
                if let existing = policies[name], existing.restrictiveness >= projected.restrictiveness {
                    continue
                }
                policies[name] = projected
            }
        }
        return policies
            .map { DesiredRight(name: $0.key, definition: definitionPlist(for: $0.value),
                                requiresNativeAdminGate: $0.value == .requireSessionOwnerOrAdmin) }
            .sorted { $0.name < $1.name }
    }

    /// The desired compositions: one per right that has identity-scoped rules,
    /// carrying every app branch authored for it (across profiles). A right
    /// that ALSO has a plain projection is excluded — the projection wins
    /// (fail-closed: a projection is at least as restrictive as composition)
    /// and the skip is logged at apply time by ``skippedByProjection(_:perAppPinsEnabled:)``.
    /// Protected rights are excluded. Sorted by right.
    ///
    /// This is the single production gate for per-app pins: while
    /// `perAppPinsEnabled` is false (the production default,
    /// ``AuthURIIdentityScope/perAppPinsEnabled``) it returns NO composition,
    /// every pin is reported by ``skippedRules(_:perAppPinsEnabled:)``, and the
    /// differential reconcile restores any right an older build composed. Tests
    /// pass `true` to exercise the composition machinery.
    public static func desiredCompositions(
        in profiles: [RuleProfile],
        perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled
    ) -> [DesiredComposition] {
        guard perAppPinsEnabled else { return [] }
        let projected = Set(desiredRights(in: profiles).map(\.name))
        var branches: [String: [AppIdentityBranch]] = [:]
        for profile in profiles {
            for rule in profile.rules where rule.type == .authuri {
                // Only an ALLOW pin becomes a branch: a branch can only ever
                // widen access for its app, so an identity-scoped deny composed
                // here would be enforced as an allow. The parser drops those;
                // this is the defense-in-depth copy (logged by skippedRules).
                guard rule.action == .allow, rule.runtimeRejectionReason == nil,
                      let branch = rule.appIdentity, let right = rule.match.authURI,
                      !isProtected(right), !projected.contains(right) else { continue }
                // One row per (team, bundle) pair: a duplicate pin from another
                // profile is the same branch, not a second one.
                if !(branches[right] ?? []).contains(where: { $0.rowSlug == branch.rowSlug }) {
                    branches[right, default: []].append(branch)
                }
            }
        }
        return branches
            .map { DesiredComposition(right: $0.key, branches: $0.value) }
            .sorted { $0.right < $1.right }
    }

    /// Root-equivalent rights named by a plain `allow` rule, which is dropped
    /// (see ``isRootEquivalent(_:)``). For the integrity log.
    public static func skippedRootEquivalentAllows(_ profiles: [RuleProfile]) -> [String] {
        Set(profiles.flatMap(\.rules)
            .filter { $0.type == .authuri && $0.appIdentity == nil && $0.action == .allow && $0.runtimeRejectionReason == nil }
            .compactMap(\.match.authURI)
            .filter { !isProtected($0) && isRootEquivalent($0) })
            .sorted()
    }

    /// Every authuri rule the AuthorizationDB layer will NOT enforce, with the
    /// reason — for the integrity log, so no rule is skipped silently. Covers
    /// the runtime gate (``Rule/runtimeRejectionReason``), protected rights,
    /// and plain allows on root-equivalent rights. (Plain-vs-branch overlap is
    /// reported separately by ``skippedByProjection(_:perAppPinsEnabled:)``.)
    /// While per-app pins are disabled, every identity-scoped rule is
    /// reported with ``AuthURIIdentityScope/disabledSkipReason``.
    public static func skippedRules(
        _ profiles: [RuleProfile],
        perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled
    ) -> [(ruleID: String, right: String, reason: String)] {
        var skipped: [(ruleID: String, right: String, reason: String)] = []
        for profile in profiles {
            for rule in profile.rules where rule.type == .authuri {
                let right = rule.match.authURI ?? "<none>"
                if let reason = rule.runtimeRejectionReason {
                    skipped.append((rule.id, right, reason))
                } else if isProtected(right) {
                    skipped.append((rule.id, right, "'\(right)' is protected; Serberus never modifies it"))
                } else if rule.appIdentity != nil, !perAppPinsEnabled {
                    skipped.append((rule.id, right, AuthURIIdentityScope.disabledSkipReason))
                } else if rule.appIdentity == nil, rule.action == .allow, isRootEquivalent(right) {
                    skipped.append((rule.id, right, perAppPinsEnabled
                        ? "an allow on '\(right)' would give every standard user root (use an identity-scoped rule to allow one app)"
                        : "an allow on '\(right)' would give every standard user root; there is no per-app allow in this release"))
                }
            }
        }
        return skipped
    }

    /// ``skippedRules(_:perAppPinsEnabled:)`` plus the rules the LIVE database rules out: any
    /// rule on a right whose native definition runs a mechanism chain (other
    /// than a deny on a right macOS does not ship), and a plain allow on a
    /// right that is not natively a plain admin gate (see
    /// ``AuthRightNativeGate``). For an undefined right the native gate is
    /// the wildcard that governs its name. Reads the live definitions of the
    /// rights the rules name; ``apply(_:compositions:)`` makes the same checks.
    public func skippedRules(
        _ profiles: [RuleProfile],
        perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled
    ) -> [(ruleID: String, right: String, reason: String)] {
        var skipped = Self.skippedRules(profiles, perAppPinsEnabled: perAppPinsEnabled)
        let known = Set(skipped.map { "\($0.ruleID)|\($0.right)" })
        for profile in profiles {
            for rule in profile.rules where rule.type == .authuri {
                guard let right = rule.match.authURI, !known.contains("\(rule.id)|\(right)") else { continue }
                let plainAllow = rule.appIdentity == nil && rule.action == .allow && !Self.isRootEquivalent(right)
                let native: Data?
                let refusal: String?
                var foreign = false
                if backend.rightExists(right) {
                    guard let current = try? backend.definition(of: right) else { continue }
                    let view = nativeView(of: right, current: current, desired: nil)
                    native = view.definition
                    foreign = rule.appIdentity == nil && isForeign(right, current: current)
                    if let definition = view.definition {
                        refusal = plainAllowRefusal(definition, right: right) ?? (foreign ? foreignAllowRefusal(right) : nil)
                    } else {
                        refusal = view.unavailableReason
                    }
                } else {
                    // Composition never creates a right, so only a plain rule
                    // on an undefined name reaches the create path.
                    guard rule.appIdentity == nil else { continue }
                    let governing = governingDefinition(of: right)
                    native = governing?.definition
                    refusal = undefinedRightRefusal(governing)
                }
                if let native, let chain = mechanismChain(of: native),
                   !(rule.action == .deny && (foreign || shippedDefinitions(right) == nil)) {
                    skipped.append((rule.id, right, "'\(right)' natively runs a mechanism chain (\(chain)); Serberus never replaces it with a password rule"))
                } else if plainAllow, let refusal {
                    skipped.append((rule.id, right, "an allow on '\(right)' is refused: \(refusal)"))
                }
            }
        }
        return skipped
    }

    /// Rights whose per-app branches were dropped because a plain authuri rule
    /// also targets them (the projection wins). For the integrity log. Empty
    /// while per-app pins are disabled: every pin is then already reported by
    /// ``skippedRules(_:perAppPinsEnabled:)``.
    public static func skippedByProjection(
        _ profiles: [RuleProfile],
        perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled
    ) -> [String] {
        guard perAppPinsEnabled else { return [] }
        let projected = Set(desiredRights(in: profiles).map(\.name))
        let composed = Set(profiles.flatMap(\.rules)
            .filter { $0.type == .authuri && $0.appIdentity != nil && $0.action == .allow && $0.runtimeRejectionReason == nil }
            .compactMap(\.match.authURI))
        return composed.intersection(projected).sorted()
    }

    /// Serializes a policy to the XML-plist definition the backend writes. The
    /// dictionaries are fixed literals that always serialize; an empty `Data` on
    /// the impossible failure makes the backend write fail → `degraded(authdb)`.
    static func definitionPlist(for policy: AuthURIPolicy) -> Data {
        plist(policy.definitionDictionary)
    }

    static func plist(_ dictionary: [String: Any]) -> Data {
        (try? PropertyListSerialization.data(fromPropertyList: dictionary, format: .xml, options: 0)) ?? Data()
    }

    static func dictionary(_ data: Data) -> [String: Any]? {
        (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }

    /// Result of an apply pass.
    public struct ApplyResult: Sendable, Equatable {
        public var snapshotted: [String] = []
        public var modified: [String] = []
        /// Rights that did not exist and were created by this apply pass.
        public var created: [String] = []
        public var skippedMissing: [String] = []
        public var skippedProtected: [String] = []
        public var unchanged: [String] = []
        // Composition
        /// Rights composed (or re-verified) from per-app branches this pass.
        public var composed: [String] = []
        /// Rights that could not be composed (no native definition to
        /// preserve, unreadable snapshot), with the reason.
        public var compositionRejected: [String: String] = [:]
        /// Verification warnings raised by the advisory table (right → message).
        /// Informational — the right is composed regardless.
        public var verificationWarnings: [String: String] = [:]
        /// App rows whose requirement failed validation (`<right>|<row>` → reason).
        public var branchesRejected: [String: String] = [:]
        /// Owned rows written (created or updated) this pass.
        public var branchRowsWritten: [String] = []
        /// Owned rows removed this pass (retired apps).
        public var branchRowsRemoved: [String] = []
        /// Composed rights whose top-level had drifted from a pure OR and were
        /// rewritten back to `k-of-n: 1` over the owned rows.
        public var compositionDriftRepaired: [String] = []
        /// Loud OS-version warnings raised (right → message).
        public var osVersionWarnings: [String: String] = [:]
        /// Set when identity-scoped compositions were requested but the
        /// SerberusAuth plugin bundle is missing or untrusted: the reason. The
        /// rights in ``compositionSkippedPluginUnavailable`` were left (or put
        /// back) native rather than composed around a mechanism authd cannot
        /// load — which would fail those rights for EVERY caller.
        public var authPluginUnavailable: String?
        /// Rights whose composition was skipped because of
        /// ``authPluginUnavailable``.
        public var compositionSkippedPluginUnavailable: [String] = []
        /// Rights whose live definition was Serberus-written while no snapshot
        /// of the original existed (a lost snapshot store): the definition was
        /// NOT adopted as the "original", the right is tracked as
        /// original-unrecoverable, and restore resets it to Apple's shipped
        /// default (or the admin-auth gate for a name Apple does not ship)
        /// instead of reinstating Serberus's own rewrite.
        public var originalUnrecoverable: [String] = []
        /// Rights whose native definition is, or delegates through `rule`
        /// references to, a mechanism chain (login, smart card, keychain
        /// unlock, Platform SSO, …). Replacing or wrapping that chain with a
        /// password rule would bypass whatever the mechanisms enforce, so such
        /// a right is never projected or composed. The one exception is a deny
        /// on a right macOS does not ship, which is written: it admits nobody.
        public var skippedEvaluateMechanisms: [String] = []
        /// Plain `allow` rules refused because the right's native definition
        /// is not a plain admin gate (right → reason): rewriting it to
        /// "session owner or admin" would widen it beyond the session owner,
        /// or it is already open. The right is left native.
        public var skippedNotAdminGated: [String: String] = [:]
        /// Rights whose live definition was replaced by someone else (an
        /// admin, an app, a macOS update) since Serberus recorded the
        /// original. Each was re-checked: one that still passes is
        /// re-snapshotted as the new original; one that no longer does is
        /// released, with the new definition left in place.
        public var nativeChanged: [String] = []
        /// Rights (projections and compositions) this pass could not apply,
        /// with the reason: the live definition could not be read, the
        /// snapshot of the original could not be saved (the right is then not
        /// written: nothing is modified without a record to restore it from),
        /// a write failed, or a deny could not be created. The pass carries
        /// on with the next right, then throws
        /// ``AuthorizationDBError/applyIncomplete(_:)`` carrying this result.
        public var failed: [String: String] = [:]

        public init() {}
    }

    /// Ensures the authdb reflects `desired` (projections) and `compositions`
    /// (per-app branches), snapshotting originals first.
    ///
    /// - Every deny is applied first (existing rights and creates alike), then
    ///   the other projections, then the compositions; name order within each.
    /// - A right that does not exist is CREATED (unless protected), recording an
    ///   absent tombstone so restore removes it. A failed create of an allow is
    ///   non-fatal (the right stays absent); a deny that could not be created is
    ///   a failure. Its native gate is the wildcard authd answers it from until
    ///   then (``governingDefinition(of:)``), and it gets the same checks.
    /// - Each existing original is snapshotted once (checksummed) before change.
    ///   When the live definition later turns out to be neither Serberus's
    ///   write nor that original, it is the new original: it is re-checked,
    ///   then re-snapshotted, or released if it no longer passes.
    /// - A definition is written only when it differs (minimal diff).
    /// - A right or composition that fails (its live definition unreadable,
    ///   its snapshot not saved, a write refused) is recorded in
    ///   ``ApplyResult/failed`` and logged, and the pass carries on, so one
    ///   failure never keeps a later deny or a composition from landing. A
    ///   projection that fails keeps the definition it had (native, or what
    ///   an earlier pass wrote): its snapshot is saved before the write it
    ///   guards. A composition that fails part-way is completed by a later
    ///   pass. Nothing is denied in place of a failed right. Once everything
    ///   was attempted, the pass throws
    ///   ``AuthorizationDBError/applyIncomplete(_:)``: the daemon reports
    ///   `degraded(authdb_failure)` and retries the reconcile on every reload
    ///   tick until it succeeds.
    @discardableResult
    public func apply(_ desired: [DesiredRight], compositions: [DesiredComposition] = []) async throws -> ApplyResult {
        var result = ApplyResult()

        // Denies first: whatever happens to the rest of the pass (a failure,
        // a pass the reload watchdog abandons), they are written before any
        // other right.
        let ordered = desired.filter(\.isDeny).sorted { $0.name < $1.name }
            + desired.filter { !$0.isDeny }.sorted { $0.name < $1.name }
        for right in ordered {
            do {
                // Defense in depth: never touch a protected right even if a caller
                // (or a future projection bug) puts one in `desired`.
                guard !Self.isProtected(right.name) else {
                    result.skippedProtected.append(right.name)
                    await emit(.authDBModification, "right '\(right.name)' is protected; refusing to modify (guardrail)")
                    continue
                }

                guard backend.rightExists(right.name) else {
                    // Create-if-missing: a rule may name an authorization right that
                    // this macOS does not define (e.g. a granular right Apple never
                    // shipped). Protected rights are already excluded above, so this
                    // only ever creates non-protected rights. An ABSENT tombstone is
                    // recorded first so restore/uninstall REMOVES the right — a
                    // created right never outlives the daemon.
                    //
                    // NOTE: creating a right only has effect if some macOS component
                    // actually queries it; an unqueried right is inert (visible via
                    // `security authorizationdb read`, but never consulted).
                    guard let desiredDefinition = right.definition else {
                        result.skippedMissing.append(right.name)
                        await emit(.authDBModification, "right '\(right.name)' does not exist and has no definition; skipping")
                        continue
                    }
                    // Until it exists, authd answers an undefined right from the
                    // wildcard that governs it (see ``governingDefinition(of:)``);
                    // that is its native gate, and it gets the same checks as the
                    // native definition of an existing right. So a deny on a name
                    // macOS does not ship is created whatever chain that wildcard
                    // runs: a deny admits nobody, so it bypasses nothing the
                    // chain enforced.
                    let governing = governingDefinition(of: right.name)
                    if let governing, let chain = mechanismChain(of: governing.definition),
                       !(right.isDeny && shippedDefinitions(right.name) == nil) {
                        await refuseEvaluateMechanisms(right.name, chain: "through \(governing.label): \(chain)", result: &result)
                        continue
                    }
                    if right.requiresNativeAdminGate, let reason = undefinedRightRefusal(governing) {
                        await refuseNotAdminGated(right.name, reason: reason, current: nil, result: &result)
                        continue
                    }
                    if !store.hasSnapshot(rightName: right.name) {
                        try store.save(AuthorizationDBSnapshot(
                            absentRightName: right.name, timestamp: now(), daemonVersion: daemonVersion))
                    }
                    let definition = governing.map { projectedDefinition(right, native: $0.definition) } ?? desiredDefinition
                    do {
                        try backend.setDefinition(definition, for: right.name)
                        result.created.append(right.name)
                        recordProjectionDigest(of: right.name)
                        await emit(.authDBModification, "created right '\(right.name)' (did not previously exist\(governing.map { "; governed natively by \($0.label)" } ?? ""))")
                    } catch {
                        // The right stays absent (its prior state): drop the
                        // tombstone. For an allow that is no security regression,
                        // so the create failure is non-fatal. A deny that could not
                        // be created did not land: that is a failure (below).
                        try? store.remove(rightName: right.name)
                        if right.isDeny { throw error }
                        result.skippedMissing.append(right.name)
                        await emit(.authDBModification, "could not create right '\(right.name)': \(String(describing: error)); left absent")
                    }
                    continue
                }

                let current = try backend.definition(of: right.name)
                let view = nativeView(of: right.name, current: current, desired: right.definition)
                let native = view.definition
                if native == nil, right.requiresNativeAdminGate {
                    await refuseNotAdminGated(right.name, reason: view.unavailableReason ?? "its native gate cannot be determined",
                                              current: current, result: &result)
                    continue
                }
                // A right macOS does not ship, that Serberus has no record of,
                // holding a definition that is not Serberus's: any user can have
                // created it (`config.add.` is class=allow), so nothing it says
                // is trusted (see ``isForeign(_:current:)``).
                let foreign = isForeign(right.name, current: current)

                // Never rewrite a mechanism chain (checked against the ORIGINAL
                // definition, so an older daemon's projection is put back). A
                // deny on a right macOS does not ship, or whose original was
                // recorded as FOREIGN, is the exception: any user can have
                // created such a right, copying in Serberus's marker or a
                // composition-row reference so it does not count as foreign, and
                // a chain there must not be a way to keep a deny from landing. A
                // deny admits nobody, so it bypasses nothing the chain enforced.
                if let native, let chain = mechanismChain(of: native),
                   !(right.isDeny && (foreign || shippedDefinitions(right.name) == nil)) {
                    if view.changedUnderneath {
                        await releaseChangedRight(right.name, current: current, reason: "it now runs a mechanism chain (\(chain))",
                                                  result: &result)
                        result.skippedEvaluateMechanisms.append(right.name)
                    } else {
                        await refuseEvaluateMechanisms(right.name, chain: chain, result: &result)
                    }
                    continue
                }

                // A plain allow is written only over a native admin gate: on any
                // other gate "session owner or admin, root passes" would widen the
                // right (session owner only, an entitlement, another group) or
                // mean nothing (already open). The deny-list cannot know rights
                // created at runtime, so this reads the live definition.
                if right.requiresNativeAdminGate, let native,
                   let reason = plainAllowRefusal(native, right: right.name) ?? (foreign ? foreignAllowRefusal(right.name) : nil) {
                    if view.changedUnderneath {
                        await releaseChangedRight(right.name, current: current, reason: reason, result: &result)
                        result.skippedNotAdminGated[right.name] = "its native definition changed underneath Serberus: \(reason)"
                    } else {
                        await refuseNotAdminGated(right.name, reason: reason, current: current, result: &result)
                    }
                    continue
                }

                if view.changedUnderneath {
                    // Someone else (an admin, an app, a macOS update) replaced the
                    // definition since it was recorded. It passed the checks above,
                    // so it is the new original: restore puts THIS back, not the
                    // stale one.
                    let snapshot = AuthorizationDBSnapshot(rightName: right.name, originalDefinition: current,
                                                           timestamp: now(), daemonVersion: daemonVersion, foreign: foreign)
                    try store.save(snapshot)
                    result.snapshotted.append(right.name)
                    result.nativeChanged.append(right.name)
                    await emit(.authDBModification, "the native definition of '\(right.name)' changed underneath Serberus; re-checked and re-snapshotted it (checksum \(snapshot.sha256.prefix(12))) as the new original")
                } else if !store.hasSnapshot(rightName: right.name) {
                    // Snapshot the original exactly once — and never Serberus's own
                    // rewrite (see ``adoptOriginal(of:current:foreign:result:)``).
                    _ = try await adoptOriginal(of: right.name, current: current, foreign: foreign, result: &result)
                }

                // A right that was previously COMPOSED and is now projected: the
                // projection rewrites the top-level, and the owned branch rows must
                // not linger referenced by nothing.
                let staleRows = ownedRows(for: right.name, currentDefinition: current)

                // Minimal diff on POLICY content only: AuthorizationRightGet returns
                // system-managed metadata (created/modified/version) that changes every
                // read, so a raw-byte compare would re-write — and log a false
                // "modified right" — on every startup. Compare the policy fields
                // only. A projection written before the marker existed is re-written
                // once to gain it, so a later lost snapshot can still recognise it,
                // and one whose recorded digest no longer matches (edited in place)
                // is re-written as well.
                if right.definition != nil {
                    let desiredDefinition = projectedDefinition(right, native: native)
                    let recorded = store.projectionDigest(rightName: right.name)
                    let drifted = recorded != nil && recorded != Self.canonicalDigest(current)
                    if !Self.semanticallyEqual(desiredDefinition, current) || drifted
                        || (Self.carriesManagedMarker(desiredDefinition) && !Self.carriesManagedMarker(current)) {
                        try await writeOverExisting(desiredDefinition, right: right, foreign: foreign)
                        result.modified.append(right.name)
                        await emit(.authDBModification, "modified right '\(right.name)'\(drifted && Self.semanticallyEqual(desiredDefinition, current) ? " (its written definition had been edited in place)" : "")")
                        recordProjectionDigest(of: right.name)
                    } else {
                        result.unchanged.append(right.name)
                        if recorded == nil { recordProjectionDigest(of: right.name) }
                    }
                } else {
                    result.unchanged.append(right.name)
                }

                if !staleRows.isEmpty {
                    await removeRows(staleRows, right: right.name, result: &result)
                    if store.hasSnapshot(rightName: right.name) {
                        try? store.removeOwnedRows(rightName: right.name)
                    } else {
                        // Original unrecoverable: the (now empty) ownership
                        // record is what keeps the right controlled.
                        try? store.saveOwnedRows([], rightName: right.name)
                    }
                }
            } catch {
                await recordFailure(right.name, error, result: &result)
            }
        }

        if compositions.isEmpty {
            pluginState.setProblem(nil)
        } else if case let .unavailable(reason) = authPluginStatus() {
            // Every composed right references `SerberusAuth:identity`. If authd
            // cannot load that mechanism the whole right fails — for every caller,
            // not just the pinned apps — so the bundle is verified BEFORE any
            // composition, and on failure no right is composed around it.
            await skipCompositions(compositions, pluginProblem: reason, result: &result)
        } else {
            pluginState.setProblem(nil)
            for composition in compositions.sorted(by: { $0.right < $1.right }) {
                do {
                    try await compose(composition, result: &result)
                } catch {
                    await recordFailure(composition.right, error, result: &result)
                }
            }
        }
        guard result.failed.isEmpty else { throw AuthorizationDBError.applyIncomplete(result) }
        return result
    }

    /// Records that `right` (a projection or a composition) could not be
    /// applied this pass, and logs it; the pass carries on with the next one.
    private func recordFailure(_ right: String, _ error: Error, result: inout ApplyResult) async {
        let reason = error.localizedDescription
        result.failed[right] = reason
        await emit(.configurationError, "'\(right)' could not be applied: \(reason). The rest of the policy is still applied; this right is retried on the next pass.")
    }

    /// Records that the enforced policy has NO identity-scoped rules, so a
    /// missing plugin is not a problem (the applier skips ``apply`` entirely
    /// when nothing is desired).
    public func noteNoCompositionsDesired() {
        pluginState.setProblem(nil)
    }

    /// The best knowledge of the definition that was native before Serberus
    /// touched `right` (see ``nativeView(of:current:desired:)``), else `current`.
    private func nativeDefinition(of right: String, current: Data) -> Data {
        nativeView(of: right, current: current, desired: nil).definition ?? current
    }

    /// What Serberus knows about the native gate of an existing right.
    struct NativeView {
        /// The definition to check, or nil when none can be determined.
        var definition: Data?
        /// The live definition is neither Serberus's write nor the recorded
        /// original: someone else replaced it, and `definition` is that
        /// replacement.
        var changedUnderneath = false
        /// Why `definition` is nil.
        var unavailableReason: String?
    }

    /// The native gate of an existing right:
    ///
    /// - With a snapshot and a live definition Serberus wrote: the snapshot's
    ///   original, or, for a right Serberus created, the wildcard that governs
    ///   its name (what authd would answer from if it were removed).
    /// - With a snapshot and a live definition equal to the original: that.
    /// - With a snapshot and anything else: the live definition, flagged as
    ///   changed underneath.
    /// - Without one: the verified native-default row of a composition, else
    ///   — when the live definition is Serberus's own rewrite and the
    ///   original is lost — Apple's shipped default, else `current`.
    func nativeView(of right: String, current: Data, desired: Data?) -> NativeView {
        if store.hasSnapshot(rightName: right), let snapshot = try? store.load(rightName: right) {
            if isOwnWrite(current, right: right, desired: desired) {
                guard snapshot.wasAbsent else { return NativeView(definition: snapshot.originalDefinition) }
                guard let governing = governingDefinition(of: right) else {
                    return NativeView(definition: nil, unavailableReason: "Serberus created it and no wildcard governs its name, so its native gate cannot be checked")
                }
                return NativeView(definition: governing.definition)
            }
            if !snapshot.wasAbsent, Self.semanticallyEqual(current, snapshot.originalDefinition) {
                return NativeView(definition: snapshot.originalDefinition)
            }
            return NativeView(definition: current, changedUnderneath: true)
        }
        if Self.referencesOwnedRows(current), let preserved = verifiedNativeDefault(for: right) {
            return NativeView(definition: preserved)
        }
        if isSerberusWritten(current, right: right), let shipped = shippedDefinitions(right), Self.dictionary(shipped) != nil {
            return NativeView(definition: shipped)
        }
        return NativeView(definition: current)
    }

    /// Whether `current` is what Serberus wrote for `right`: it carries the
    /// marker or references owned rows, matches the digest recorded when it
    /// was written, already equals `desired`, or is a projection written
    /// before the marker existed.
    private func isOwnWrite(_ current: Data, right: String, desired: Data?) -> Bool {
        if isSerberusWritten(current, right: right) { return true }
        if let recorded = store.projectionDigest(rightName: right), recorded == Self.canonicalDigest(current) { return true }
        if let desired, Self.semanticallyEqual(desired, current) { return true }
        return Self.isUnmarkedProjection(current)
    }

    /// Whether `definition` has the policy of one of Serberus's own password
    /// projections, ignoring the credential `timeout` and `shared` carried
    /// over from the native definition.
    static func isUnmarkedProjection(_ definition: Data) -> Bool {
        var fields = policyFields(definition)
        fields["timeout"] = nil
        fields["shared"] = nil
        fields["password-only"] = nil
        return [AuthURIPolicy.requireSessionOwnerOrAdmin, .requireAdmin].contains { policy in
            var projected = policyFields(definitionPlist(for: policy))
            projected["timeout"] = nil
            projected["shared"] = nil
            return projected == fields
        }
    }

    /// The definition authd evaluates an UNDEFINED right against: the
    /// longest trailing-dot ancestor the live database defines (for example
    /// `system.` → `rule = default`, a plain admin gate), else the catch-all
    /// `""` right. Nil when none can be read.
    func governingDefinition(of right: String) -> (name: String, label: String, definition: Data)? {
        for name in AuthRightNativeGate.wildcardCandidates(for: right) where !AuthURICompositionNaming.isOwnedRow(name) {
            guard backend.rightExists(name) else { continue }
            guard let definition = try? backend.definition(of: name) else { return nil }
            return (name, name.isEmpty ? "the catch-all default right" : "the wildcard '\(name)'", definition)
        }
        return nil
    }

    /// Why a plain allow must not create an undefined right governed by
    /// `governing` (see ``governingDefinition(of:)``), or nil when it may.
    private func undefinedRightRefusal(_ governing: (name: String, label: String, definition: Data)?) -> String? {
        guard let governing else {
            return "it is not defined and no wildcard governs its name, so its native gate cannot be checked"
        }
        return nativeAdminGateRefusal(governing.definition).map { "it is not defined, and \(governing.label) that governs it: \($0)" }
    }

    /// Whether the live definition `current` of an existing `right` is
    /// FOREIGN: macOS does not ship the right, Serberus holds no record of it
    /// (snapshot, projection digest, ownership record or stand-in), and the
    /// definition is not Serberus's. Any user can create a right macOS does
    /// not define, so such a definition says only what its creator chose. A
    /// right already snapshotted keeps the verdict recorded then.
    ///
    /// "Not Serberus's" rests on ``managedMarker`` and on references to
    /// composition rows, which anyone who can create a right can copy, so a
    /// deny does not rely on this verdict: one on any right macOS does not
    /// ship is written whatever chain the right runs (see
    /// ``apply(_:compositions:)``).
    func isForeign(_ right: String, current: Data) -> Bool {
        if store.hasSnapshot(rightName: right) {
            return (try? store.load(rightName: right))?.foreign ?? false
        }
        return shippedDefinitions(right) == nil
            && store.ownedRowsRecord(rightName: right) == nil
            && store.projectionDigest(rightName: right) == nil
            && !isSerberusWritten(current, right: right)
    }

    /// Why a plain allow must not rewrite a FOREIGN right (see
    /// ``isForeign(_:current:)``), or nil when it may. Its live definition
    /// proves nothing, so the right must ALSO pass as the undefined right it
    /// would be without it: the wildcard that governs its name must be a
    /// plain admin gate and run no mechanism chain.
    private func foreignAllowRefusal(_ right: String) -> String? {
        let governing = governingDefinition(of: right)
        if let governing, let chain = mechanismChain(of: governing.definition) {
            return "macOS does not ship it and Serberus has no record of it, so it is checked as an undefined right too, and \(governing.label) that governs it runs a mechanism chain (\(chain))"
        }
        return undefinedRightRefusal(governing).map {
            "macOS does not ship it and Serberus has no record of it, so it is checked as an undefined right too: \($0)"
        }
    }

    /// Writes `definition` over the EXISTING right `right`, replacing a right
    /// created outside Serberus when authd refuses the write.
    ///
    /// Any user can create a right macOS does not ship (`config.add.` is
    /// class=allow), and authd then refuses to let anyone else, root
    /// included, overwrite it (`AuthorizationRightSet` -> -60005,
    /// errAuthorizationDenied), while root may still remove it. Without
    /// this, a standard user who pre-creates the right of a deny rule as
    /// `allow` keeps the deny from ever landing. So when the write is
    /// refused and ``mayReplaceForeignRight(_:foreign:)`` allows it, the
    /// right is removed as root and the definition written again: Serberus
    /// then created it, so root can rewrite it on restore, and a standard
    /// user can no longer modify or remove it (`config.modify.<name>` and
    /// `config.remove.<name>` are refused to them).
    ///
    /// The original the user created was snapshotted before this write (as
    /// FOREIGN, never trusted as a native gate), so restore puts it back.
    ///
    /// One attempt per pass: if the user re-creates the right between the
    /// remove and the write, the write is refused again (or, when authd lets
    /// root create over a racing create, simply lands) and the error is
    /// thrown, so the right is reported and retried on the next pass. The
    /// right may be left absent in between; it is not put back.
    private func writeOverExisting(_ definition: Data, right: DesiredRight, foreign: Bool) async throws {
        do {
            try backend.setDefinition(definition, for: right.name)
        } catch let AuthorizationDBError.rightUnwritable(name, status) {
            // Only authd's refusal (errAuthorizationDenied), the signature of a
            // right another creator owns: any other failure stays a reported
            // failure and never removes the right.
            guard status == errAuthorizationDenied, mayReplaceForeignRight(right, foreign: foreign) else {
                throw AuthorizationDBError.rightUnwritable(name: name, status: status)
            }
            try backend.removeRight(right.name)
            do {
                try backend.setDefinition(definition, for: right.name)
            } catch {
                await emit(.configurationError, "removed right '\(right.name)', which was created outside Serberus and refused Serberus's write, but writing Serberus's definition failed too (it may have been re-created in between): \(error.localizedDescription). Retried on the next pass.")
                throw error
            }
            DaemonLog.integrity.error("authdb: replaced right '\(right.name, privacy: .public)', created outside Serberus (a standard user can create new rights)")
            await emit(.authDBModification, "replaced right '\(right.name)', which was created outside Serberus (a standard user can create new rights, and authd refuses anyone else, root included, to overwrite one): removed it as root and wrote Serberus's definition; the definition it had is put back on restore")
        }
    }

    /// Whether a right whose write authd refused may be removed and written
    /// again (see ``writeOverExisting(_:right:foreign:)``). Only a
    /// right created outside Serberus: macOS does not ship it, it is not
    /// protected or a login/unlock right, it is a plain right name (no
    /// wildcard, rule class or composition row), and either its original is
    /// recorded as FOREIGN (``isForeign(_:current:)``), or, for a deny, no
    /// original is recorded at all (its creator copied Serberus's marker, so
    /// it counts as an unrecoverable Serberus write; restore resets it to the
    /// admin-auth stand-in). Never a right with a recorded non-foreign
    /// original, nor one Serberus created (an absent tombstone).
    private func mayReplaceForeignRight(_ right: DesiredRight, foreign: Bool) -> Bool {
        let name = right.name
        guard shippedDefinitions(name) == nil,
              !Self.isProtected(name),
              AuthRightTargetPolicy.targetRejectionReason(name) == nil,
              AuthRightTargetPolicy.denyRejectionReason(name) == nil,
              AuthRightTargetPolicy.allowRejectionReason(name) == nil,
              !AuthURICompositionNaming.isOwnedRow(name) else { return false }
        if store.hasSnapshot(rightName: name) {
            guard let snapshot = try? store.load(rightName: name) else { return false }
            return foreign && snapshot.foreign && !snapshot.wasAbsent
        }
        return right.isDeny
    }

    /// The definition to write for `right`. A plain allow keeps the native
    /// credential `timeout`, `shared` and `password-only` of the gate it
    /// replaces (for an any-of gate, the most restrictive across its admin
    /// branches; see
    /// ``AuthRightNativeGate/credentialSettings(_:lookup:)``), so a credential
    /// macOS lets live for 15 minutes is not reusable for longer after the
    /// rewrite.
    private func projectedDefinition(_ right: DesiredRight, native: Data?) -> Data {
        guard let definition = right.definition else { return Data() }
        guard right.requiresNativeAdminGate, let native, let nativeDict = Self.dictionary(native),
              var dict = Self.dictionary(definition) else { return definition }
        let settings = AuthRightNativeGate.credentialSettings(nativeDict, lookup: liveDefinition)
        if let timeout = settings.timeout { dict["timeout"] = timeout }
        if let shared = settings.shared { dict["shared"] = shared }
        if settings.passwordOnly == true { dict["password-only"] = true }
        return Self.plist(dict)
    }

    /// Records the digest of `right` as authd returns it right after Serberus
    /// wrote it, so a later edit in place is detected. Best-effort.
    private func recordProjectionDigest(of right: String) {
        guard let readBack = try? backend.definition(of: right), let digest = Self.canonicalDigest(readBack) else { return }
        try? store.saveProjectionDigest(digest, rightName: right)
    }

    /// The live definition of `right` changed underneath Serberus and no
    /// longer passes its checks: log it, leave the new definition in place,
    /// and stop managing the right, so restore never writes the stale
    /// original over it.
    private func releaseChangedRight(_ right: String, current: Data, reason: String, result: inout ApplyResult) async {
        result.nativeChanged.append(right)
        DaemonLog.integrity.error("authdb: native definition of '\(right, privacy: .public)' changed underneath; no longer passes: \(reason, privacy: .public)")
        await emit(.configurationError, "The native definition of '\(right)' changed underneath Serberus and no longer passes its checks: \(reason). The rule is not enforced; the new definition is left in place and Serberus stops managing the right.")
        await removeRows(ownedRows(for: right, currentDefinition: current), right: right, result: &result)
        try? store.remove(rightName: right)
    }

    /// A named rule or right from the live database, as a dictionary; the
    /// lookup ``AuthRightNativeGate`` follows `rule` references with.
    /// Serberus's own composition rows are not native definitions and are
    /// never followed.
    private func liveDefinition(_ name: String) -> [String: Any]? {
        guard !AuthURICompositionNaming.isOwnedRow(name), backend.rightExists(name),
              let data = try? backend.definition(of: name) else { return nil }
        return Self.dictionary(data)
    }

    /// Why a plain allow must not be written over a right whose best-known
    /// native definition is `native` (see ``nativeDefinition(of:current:)``),
    /// or nil when it may.
    private func plainAllowRefusal(_ native: Data, right: String) -> String? {
        if isSerberusWritten(native, right: right) {
            return "its original definition cannot be recovered (the live one is Serberus's own rewrite, no snapshot exists and macOS ships no default for it), so its native gate cannot be checked"
        }
        return nativeAdminGateRefusal(native)
    }

    /// The mechanism chain `definition` runs, directly or through the rules
    /// it references (resolved live), or nil.
    func mechanismChain(of definition: Data) -> String? {
        guard let dict = Self.dictionary(definition) else { return nil }
        return AuthRightNativeGate.mechanismChain(dict, lookup: liveDefinition)
    }

    /// Why a plain allow must not rewrite a right whose native definition is
    /// `definition` (resolved against the live database), or nil when the
    /// right is a plain admin gate.
    func nativeAdminGateRefusal(_ definition: Data) -> String? {
        guard let dict = Self.dictionary(definition) else { return "its native definition is unreadable" }
        return AuthRightNativeGate.plainAllowRefusal(dict, lookup: liveDefinition)
    }

    /// Skips (and logs) a right whose native definition is a mechanism chain,
    /// putting it back if an earlier daemon had already rewritten it.
    private func refuseEvaluateMechanisms(_ right: String, chain: String, result: inout ApplyResult) async {
        result.skippedEvaluateMechanisms.append(right)
        DaemonLog.integrity.error("authdb: '\(right, privacy: .public)' natively runs a mechanism chain (\(chain, privacy: .public)); refusing to rewrite it")
        await emit(.configurationError, "'\(right)' natively runs a mechanism chain: \(chain). Serberus never replaces or wraps a mechanism chain (login, smart card, keychain unlock, Platform SSO, …) with a password rule; the rule is not enforced and the right is left native.")
        if controlledRightNames().contains(right) {
            _ = try? await restore(names: [right])
        }
    }

    /// Skips (and logs) a plain allow on a right that is not natively a
    /// plain admin gate, putting the right back if an earlier daemon had
    /// already rewritten it.
    private func refuseNotAdminGated(_ right: String, reason: String, current: Data?,
                                     result: inout ApplyResult) async {
        result.skippedNotAdminGated[right] = reason
        DaemonLog.integrity.error("authdb: allow on '\(right, privacy: .public)' refused: \(reason, privacy: .public)")
        await emit(.configurationError, "The allow rule on '\(right)' is not enforced: \(reason). A plain allow lets the session owner in only where macOS natively asks for an admin password; the right is left native.")
        // Serberus's own rewrite with no record of the original (a lost
        // snapshot store) is taken under control so restore replaces it with
        // the stand-in rather than leaving the rewrite in force.
        if !controlledRightNames().contains(right), let current, isSerberusWritten(current, right: right) {
            try? store.saveOwnedRows([], rightName: right)
        }
        if controlledRightNames().contains(right) {
            _ = try? await restore(names: [right])
        }
    }

    /// The SerberusAuth plugin is missing or untrusted: leave every requested
    /// composition's right NATIVE. A right this daemon composed earlier (while
    /// the plugin was present) is restored now, since its app branches point
    /// at a mechanism authd can no longer load. Logged loudly and recorded in
    /// the result so the daemon can surface it.
    private func skipCompositions(_ compositions: [DesiredComposition], pluginProblem reason: String,
                                  result: inout ApplyResult) async {
        let rights = compositions.map(\.right).sorted()
        pluginState.setProblem(reason)
        result.authPluginUnavailable = reason
        result.compositionSkippedPluginUnavailable = rights
        for right in rights {
            result.compositionRejected[right] = "SerberusAuth plugin unavailable: \(reason)"
        }
        DaemonLog.integrity.error("authdb: SerberusAuth plugin unavailable (\(reason, privacy: .public)); identity-scoped rules NOT enforced on \(rights, privacy: .public) — rights left native")
        await emit(.configurationError, "SerberusAuth authorization plugin unavailable (\(reason)). Identity-scoped rules on \(rights.joined(separator: ", ")) are NOT enforced; the rights are left at their native definitions. Install a root-owned, validly signed \(SystemAuthPluginBundleVerifier.defaultBundlePath) to enable them.")
        let controlled = Set(controlledRightNames())
        let toRestore = Set(rights).intersection(controlled)
        if !toRestore.isEmpty {
            await emit(.authDBModification, "restoring previously composed right(s) \(toRestore.sorted()) to native: their branches reference the unavailable plugin")
            _ = try? await restore(names: toRestore)
        }
    }

    /// Whether the SerberusAuth plugin bundle is installed and trusted right
    /// now — the same check ``apply(_:compositions:)`` makes before composing.
    ///
    /// Cheap enough for every reload tick: the verifier's ``AuthPluginBundleVerifying/fingerprint()``
    /// (a handful of `lstat`s: device, inode, size, mtime, ctime of the bundle
    /// and its signature-relevant files) keys a cached verdict, and the full
    /// ownership + `SecStaticCode` check re-runs only when it changes. A
    /// verifier with no fingerprint is fully checked every time.
    public func authPluginStatus() -> AuthPluginInstallStatus {
        let fingerprint = authPluginVerifier.fingerprint()
        if let fingerprint, let cached = pluginState.cachedStatus(for: fingerprint) {
            return cached
        }
        let status = authPluginVerifier.verify()
        if let fingerprint { pluginState.cache(status, for: fingerprint) }
        return status
    }

    /// Non-nil while identity-scoped rules are in the enforced policy but NOT
    /// enforced because the plugin is unavailable (the reason). Set by the
    /// last ``apply(_:compositions:)``; the daemon reports it as
    /// `degraded(auth_plugin_unavailable)`.
    public var lastAuthPluginProblem: String? {
        pluginState.problem
    }

    /// Records the ORIGINAL definition of `right`, which has no snapshot yet.
    ///
    /// - A definition that is a composition (references owned rows) is not
    ///   the original: the preserved `native-default` row is, and it is
    ///   re-adopted from there — but only when ``verifiedNativeDefault(for:)``
    ///   vouches for that row.
    /// - Any other definition WITHOUT Serberus's ``managedMarker`` is the
    ///   original and is snapshotted.
    /// - A Serberus-written definition with no recoverable original (the
    ///   snapshot store was lost) is NEVER snapshotted as the original —
    ///   restoring it would reinstate Serberus's own rewrite as "native". An
    ///   empty ownership record keeps the right controlled, so restore takes
    ///   the corrupt-snapshot path and resets it to Apple's shipped default,
    ///   or the admin-auth gate for a name Apple does not ship (never a deny).
    ///
    /// - Returns: the snapshot saved, or nil when the original is unrecoverable.
    private func adoptOriginal(of right: String, current: Data, foreign: Bool = false,
                               result: inout ApplyResult) async throws -> AuthorizationDBSnapshot? {
        if Self.referencesOwnedRows(current) {
            if let recovered = verifiedNativeDefault(for: right) {
                let snapshot = AuthorizationDBSnapshot(rightName: right, originalDefinition: recovered,
                                                       timestamp: now(), daemonVersion: daemonVersion)
                try store.save(snapshot)
                result.snapshotted.append(right)
                await emit(.authDBModification, "re-adopted native-default for '\(right)' from its preserved row (snapshot was missing; row verified against its recorded digest)")
                return snapshot
            }
            await emit(.configurationError, "'\(right)' references composition rows but its preserved native-default row is missing or UNVERIFIED (no ownership record naming it, or its digest does not match — any user can create a right, so an unverified row is never trusted as the original)")
        } else if !Self.carriesManagedMarker(current), !isRecordedStandIn(current, right: right) {
            let snapshot = AuthorizationDBSnapshot(rightName: right, originalDefinition: current,
                                                   timestamp: now(), daemonVersion: daemonVersion, foreign: foreign)
            try store.save(snapshot)
            result.snapshotted.append(right)
            await emit(.authDBModification, "snapshotted right '\(right)' (checksum \(snapshot.sha256.prefix(12)))\(foreign ? " as FOREIGN: macOS does not ship it and Serberus has no record of it, so its definition is put back on restore but never trusted as its native gate" : "")")
            return snapshot
        }
        try store.saveOwnedRows(store.ownedRows(rightName: right), rightName: right)
        result.originalUnrecoverable.append(right)
        DaemonLog.integrity.error("authdb: '\(right, privacy: .public)' carries a Serberus-written definition but its snapshot is missing; NOT adopting it as the original (restore will reset it to Apple's shipped default or admin-auth)")
        await emit(.configurationError, "'\(right)' already carries a Serberus-written definition but no snapshot of its original exists (the snapshot store was lost, or a user created the right with a copy of Serberus's marker). It will NOT be recorded as the original; on restore it is reset to Apple's shipped default, or the admin-auth default when Apple does not ship it.")
        return nil
    }

    // MARK: - Composition

    /// Composes one right from its per-app branches — the composer, never a
    /// rewriter of the right's native behaviour:
    ///
    /// 1. **Verification state, logged.** The advisory table says whether
    ///    identity scoping is verified on this right; an unverified,
    ///    ineligible or provisional right is WARNED about in the integrity log
    ///    and composed anyway — a rule that exists is enforced.
    /// 2. **Requirement compiler.** Each branch's Team ID + bundle ID compiles
    ///    to a code requirement validated by `SecRequirementCreateWithString`
    ///    before anything is written; a rejected branch is skipped, the rest
    ///    compose independently.
    /// 3. **Native default captured live, once.** The right's existing
    ///    definition is snapshotted on first touch and written as the
    ///    permanently preserved `native-default` row. Never hardcoded — Apple
    ///    can change a right's default across OS versions.
    /// 4. **One named sub-rule per app**, each independent of every other.
    /// 5. **Top-level = `k-of-n: 1`** over `[app-1, …, app-n, native-default]`.
    ///    authd evaluates the array in order and stops at the first success,
    ///    so the app branches go FIRST (a non-matching caller fails their code
    ///    requirement without a prompt) and the native default stays LAST as
    ///    the fallback every other caller lands on.
    /// 6. **Minimal diff.** Rows and the top-level are written only when their
    ///    policy content differs; a retired app's row is deleted and dropped
    ///    from the array, every other branch untouched.
    /// 7. **Drift check.** A top-level that is no longer a pure OR (an admin
    ///    flipped `k-of-n`, or dropped the native row) would silently turn
    ///    "easier path for approved apps" into a lockout with no live decision
    ///    path to surface it — it is detected, logged loudly, and repaired.
    private func compose(_ composition: DesiredComposition, result: inout ApplyResult) async throws {
        let right = composition.right

        guard !Self.isProtected(right) else {
            result.skippedProtected.append(right)
            await emit(.authDBModification, "right '\(right)' is protected; refusing to compose (guardrail)")
            return
        }

        // 1. Verification state — advisory. Warn, then compose regardless.
        let decision = scopeRegistry.authoringDecision(for: right)
        if let reason = decision.rejectionReason {
            result.verificationWarnings[right] = reason
            DaemonLog.integrity.error("authdb: UNVERIFIED identity scoping on '\(right, privacy: .public)': \(reason, privacy: .public) — composing as authored")
            await emit(.configurationError, "UNVERIFIED identity scoping on '\(right)': \(reason) Composing as authored.")
        } else if decision.state == .provisional {
            result.verificationWarnings[right] = "\(decision.state.label)"
            await emit(.authDBModification, "'\(right)' is \(decision.state.label); composing as authored (under test)")
        }
        if let warning = scopeRegistry.osVersionWarning(for: right, fleetMajor: osMajor) {
            result.osVersionWarnings[right] = warning
            DaemonLog.integrity.error("authdb: UNVERIFIED macOS for identity scoping — \(warning, privacy: .public)")
            await emit(.configurationError, "UNVERIFIED macOS: \(warning)")
        }

        // Composition preserves a native definition; a right that does not
        // exist has none to preserve, so it is never composed (and never created).
        guard backend.rightExists(right) else {
            result.skippedMissing.append(right)
            await emit(.authDBModification, "right '\(right)' does not exist; cannot compose (nothing to preserve as native-default)")
            return
        }
        if let live = try? backend.definition(of: right) {
            let view = nativeView(of: right, current: live, desired: nil)
            if let native = view.definition, let chain = mechanismChain(of: native) {
                result.compositionRejected[right] = "natively runs a mechanism chain (\(chain)); a mechanism chain is never wrapped"
                if view.changedUnderneath {
                    result.skippedEvaluateMechanisms.append(right)
                    await releaseChangedRight(right, current: live, reason: "it now runs a mechanism chain (\(chain))", result: &result)
                } else {
                    await refuseEvaluateMechanisms(right, chain: chain, result: &result)
                }
                return
            }
        }

        // 2. Compile + validate every branch requirement before any write.
        //    Each app becomes THREE rows: the identity check, the
        //    authentication, and a k-of-n 2 composite requiring both. See
        //    ``AppIdentityBranch`` for why one rule cannot do both jobs.
        var appRows: [(name: String, definition: Data)] = []
        var appCompositeRows: [String] = []
        for branch in composition.branches {
            let rowName = AuthURICompositionNaming.appRow(for: right, branch: branch)
            let identityRow = AuthURICompositionNaming.appIdentityRow(for: right, branch: branch)
            let authRow = AuthURICompositionNaming.appAuthRow(for: right, branch: branch)
            do {
                // The requirement is still compiled and validated, but it is
                // no longer written into the rule: authd ignores it. It is
                // the policy the MECHANISM enforces, and compiling it here
                // keeps a malformed pin from ever reaching a deployed rule.
                let requirement = try CodeRequirementCompiler.compileAndValidate(branch)
                let describes = "\(branch.bundleID) (\(branch.teamID)) on '\(right)'"

                var identity = AppIdentityBranch.identityBody
                identity["comment"] = "Serberus identity check for \(describes): allows only \(requirement). Enforced by \(AppIdentityBranch.mechanismName). \(Self.managedMarker)"
                appRows.append((identityRow, Self.plist(identity)))

                let ownerOnly = sessionOwnerOnly()
                var auth = AppIdentityBranch.authBody(sessionOwnerOnly: ownerOnly)
                auth["comment"] = "Serberus authentication for \(describes): \(AppIdentityBranch.postureName(sessionOwnerOnly: ownerOnly)), cached \(AppIdentityBranch.credentialTimeoutSeconds)s so one operation's several authorizations prompt once. \(Self.managedMarker)"
                appRows.append((authRow, Self.plist(auth)))

                var composite = AppIdentityBranch.branchBody(identityRow: identityRow, authRow: authRow)
                composite["comment"] = "Serberus per-app branch for \(describes): BOTH the identity check and the authentication must pass. \(Self.managedMarker)"
                appRows.append((rowName, Self.plist(composite)))
                appCompositeRows.append(rowName)
            } catch {
                result.branchesRejected["\(right)|\(rowName)"] = error.localizedDescription
                await emit(.authDBModification, "REFUSED branch '\(rowName)' on '\(right)': \(error.localizedDescription) (nothing written)")
            }
        }
        guard !appCompositeRows.isEmpty else {
            await emit(.authDBModification, "no valid app branch for '\(right)'; leaving the right uncomposed")
            if store.hasSnapshot(rightName: right) { _ = try? await restore(names: [right]) }
            return
        }

        // 3. Native default: snapshot once, live.
        let current = try backend.definition(of: right)
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: right)
        var snapshot: AuthorizationDBSnapshot
        if store.hasSnapshot(rightName: right) {
            do {
                snapshot = try store.load(rightName: right)
            } catch {
                result.compositionRejected[right] = "snapshot unreadable: \(error.localizedDescription)"
                await emit(.authDBModification, "cannot compose '\(right)': its native-default snapshot is unreadable (\(error.localizedDescription)); left as is")
                return
            }
            if !snapshot.wasAbsent, !Self.isSerberusWritten(current),
               !Self.semanticallyEqual(current, snapshot.originalDefinition) {
                // Replaced by someone else since it was recorded (checked for a
                // mechanism chain above): the replacement is the native
                // definition to preserve now, and the one restore puts back.
                snapshot = AuthorizationDBSnapshot(rightName: right, originalDefinition: current,
                                                   timestamp: now(), daemonVersion: daemonVersion)
                try store.save(snapshot)
                result.snapshotted.append(right)
                result.nativeChanged.append(right)
                await emit(.authDBModification, "the native definition of '\(right)' changed underneath Serberus; re-snapshotted it (checksum \(snapshot.sha256.prefix(12))) as the definition to preserve")
            }
        } else if let adopted = try await adoptOriginal(of: right, current: current, result: &result) {
            // Re-adopted from the preserved native-default row (the snapshot
            // store was lost but the right is already composed), or the live
            // native definition snapshotted on first touch.
            snapshot = adopted
        } else {
            // The live definition is Serberus's own and the original is gone:
            // there is no native definition to preserve as the fallback, and
            // composing around the rewrite would make it the "native" path.
            // Reset to the same stand-in restore uses (Apple's shipped
            // default, else the admin-auth default; never a deny) and leave
            // the right uncomposed.
            result.compositionRejected[right] = "original definition unrecoverable (Serberus-written, snapshot missing)"
            let staleRows = ownedRows(for: right, currentDefinition: current)
            let fallback = try writeFallback(for: right)
            await removeRows(staleRows, right: right, result: &result)
            try? store.saveOwnedRows([], rightName: right)   // still controlled: restore resets it
            await emit(.authDBModification, "cannot compose '\(right)': its original definition is unrecoverable; reset to \(fallback.label) and left uncomposed")
            return
        }
        guard !snapshot.wasAbsent else {
            result.compositionRejected[right] = "right was created by Serberus; no native definition to preserve"
            await emit(.authDBModification, "cannot compose '\(right)': it was created by Serberus (no native default)")
            return
        }

        // 4. Write rows that differ (native-default first so the top-level
        //    never references a missing row).
        //    Every row is additionally re-written whenever it is not the row
        //    Serberus recorded (no sidecar record naming it, no digest yet, or
        //    a different one): any user can CREATE a right, so a row that
        //    already existed under one of these names is never assumed to be
        //    ours, however closely it matches. Each row's digest is taken from
        //    authd's read-back and recorded with the ownership sidecar below.
        var desiredRows: [(name: String, definition: Data)] = [(nativeRow, snapshot.originalDefinition)]
        desiredRows.append(contentsOf: appRows)
        let record = store.ownedRowsRecord(rightName: right)
        for row in desiredRows {
            if backend.rightExists(row.name), let existing = try? backend.definition(of: row.name),
               Self.semanticallyEqual(row.definition, existing),
               let recorded = record?.digest(of: row.name, nativeRow: nativeRow),
               Self.canonicalDigest(existing) == recorded {
                continue
            }
            try backend.setDefinition(row.definition, for: row.name)
            result.branchRowsWritten.append(row.name)
            await emit(.authDBModification, "wrote branch row '\(row.name)'")
        }
        guard let nativeReadBack = try? backend.definition(of: nativeRow),
              Self.semanticallyEqual(snapshot.originalDefinition, nativeReadBack),
              let nativeDigest = Self.canonicalDigest(nativeReadBack) else {
            throw AuthorizationDBError.rightUnreadable(name: nativeRow, status: errAuthorizationInternal)
        }
        // A row whose read-back is missing or unreadable gets no digest, so
        // the next pass writes it again.
        var rowDigests: [String: String] = [:]
        for row in desiredRows {
            if let readBack = try? backend.definition(of: row.name), let digest = Self.canonicalDigest(readBack) {
                rowDigests[row.name] = digest
            }
        }

        // 5. Top-level: apps first, native-default last (see the doc comment).
        //    Only the COMPOSITE rows go in the array; the identity/auth halves
        //    are referenced by the composite, never by the right itself.
        let order = appCompositeRows + [nativeRow]
        let topLevel = Self.plist([
            "class": "rule",
            "k-of-n": 1,
            "rule": order,
            "comment": "Serberus identity-scoped composition of '\(right)': k-of-n 1 over per-app branches with the native definition preserved as '\(nativeRow)'. \(Self.managedMarker)",
            "version": 1,
        ])
        if let drift = Self.compositionDrift(in: current, nativeRow: nativeRow) {
            result.compositionDriftRepaired.append(right)
            DaemonLog.integrity.error("authdb: COMPOSITION DRIFT on '\(right, privacy: .public)': \(drift, privacy: .public) — repairing")
            await emit(.configurationError, "COMPOSITION DRIFT on '\(right)': \(drift). This would have turned the per-app easier path into a lockout with no live decision path to surface it; rewriting the top-level back to k-of-n 1 over the owned branches.")
        }
        if !Self.semanticallyEqual(topLevel, current) {
            try backend.setDefinition(topLevel, for: right)
            result.modified.append(right)
            await emit(.authDBModification, "composed right '\(right)' as k-of-n 1 over \(order)")
        } else {
            result.unchanged.append(right)
        }
        result.composed.append(right)

        // 6. Retire rows no longer desired — after the top-level stopped
        //    referencing them. Every other branch is untouched.
        let previouslyOwned = ownedRows(for: right, currentDefinition: current)
        let keep = Set(desiredRows.map(\.name))
        let stale = previouslyOwned.filter { !keep.contains($0) }
        await removeRows(stale, right: right, result: &result)
        try store.saveOwnedRows(desiredRows.map(\.name), rightName: right, nativeDefaultSHA256: nativeDigest,
                                rowSHA256: rowDigests)
    }

    // MARK: - Native-default row verification

    /// Metadata authd stamps or rewrites on every read/write; excluded from
    /// ``canonicalDigest(_:)`` so a digest taken at write time still matches
    /// a later read-back.
    static let volatileDefinitionKeys: Set<String> = ["created", "modified", "version", "identifier", "comment"]

    /// SHA-256 over a canonical, key-sorted rendering of a definition minus
    /// ``volatileDefinitionKeys`` — every policy-bearing key, including the
    /// ones ``policyFields(_:)`` ignores, so a forged row cannot match by
    /// sharing only the compared subset. Nil when `data` is not a dictionary.
    static func canonicalDigest(_ data: Data) -> String? {
        guard var dict = dictionary(data) else { return nil }
        for key in volatileDefinitionKeys { dict[key] = nil }
        return SHA256Hasher.hexDigest(Data(canonical(dict).utf8))
    }

    private static func canonical(_ value: Any) -> String {
        switch value {
        case let dict as [String: Any]:
            return "{" + dict.keys.sorted().map { "\($0.debugDescription):\(canonical(dict[$0]!))" }.joined(separator: ",") + "}"
        case let array as [Any]:
            return "[" + array.map(canonical).joined(separator: ",") + "]"
        case let string as String:
            return "s" + string.debugDescription
        case let data as Data:
            return "d" + data.base64EncodedString()
        case let date as Date:
            return "t\(date.timeIntervalSinceReferenceDate)"
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
            return "n" + number.stringValue
        default:
            return "?" + String(describing: value)
        }
    }

    /// The preserved `native-default` row of `right`, ONLY when Serberus can
    /// vouch for it: the ownership sidecar exists, is non-empty, names the
    /// row, and carries a digest that matches the row's current definition.
    /// Anything else — no record, a legacy record without a digest, a row
    /// someone else created or changed — is nil, and the caller falls back to
    /// its stand-in (Apple's shipped default, else the admin-auth gate).
    func verifiedNativeDefault(for right: String) -> Data? {
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: right)
        guard let record = store.ownedRowsRecord(rightName: right), !record.rows.isEmpty,
              record.rows.contains(nativeRow), let expected = record.nativeDefaultSHA256,
              backend.rightExists(nativeRow), let definition = try? backend.definition(of: nativeRow),
              Self.canonicalDigest(definition) == expected else { return nil }
        return definition
    }

    /// Describes how a composed top-level has drifted from a pure OR, or nil
    /// when it is intact (or not composed at all — a native definition is not
    /// drift, it is the pre-composition state).
    static func compositionDrift(in definition: Data, nativeRow: String) -> String? {
        guard let dict = dictionary(definition), referencesOwnedRows(definition) else { return nil }
        let rules = AuthURICompositionNaming.ownedRows(referencedBy: dict)
        var problems: [String] = []
        if (dict["class"] as? String) != "rule" {
            problems.append("class is '\(dict["class"] as? String ?? "?")', not 'rule'")
        }
        let kofn = dict["k-of-n"]
        if let k = kofn as? Int {
            if k != 1 { problems.append("k-of-n is \(k), not 1 — the branches became an AND (every branch must pass)") }
        } else if kofn == nil {
            problems.append("k-of-n is missing — authd treats a bare rule array as an AND of every branch")
        } else {
            problems.append("k-of-n is not an integer")
        }
        if !rules.contains(nativeRow) {
            problems.append("native-default branch '\(nativeRow)' is no longer referenced — callers outside the app branches lost their native path")
        }
        return problems.isEmpty ? nil : problems.joined(separator: "; ")
    }

    /// Whether a top-level definition references any Serberus-owned row.
    static func referencesOwnedRows(_ definition: Data) -> Bool {
        guard let dict = dictionary(definition) else { return false }
        return !AuthURICompositionNaming.ownedRows(referencedBy: dict).isEmpty
    }

    /// The rows Serberus owns for `right`: the recorded sidecar ∪ whatever the
    /// current top-level references under our prefix (so a lost sidecar never
    /// strands a row). A referenced row is taken only when it is named for
    /// `right` (``isCompositionRow(_:of:)``): any user can create a right
    /// whose definition references another right's rows, and removing those
    /// would break that right's composition.
    private func ownedRows(for right: String, currentDefinition: Data?) -> [String] {
        var rows = Set(store.ownedRows(rightName: right))
        if let currentDefinition, let dict = Self.dictionary(currentDefinition) {
            // The top-level references the per-app COMPOSITE rows; each
            // composite in turn references its identity/auth halves. Follow one
            // level so a lost sidecar cannot strand the halves as orphans.
            let direct = AuthURICompositionNaming.ownedRows(referencedBy: dict)
                .filter { Self.isCompositionRow($0, of: right) }
            rows.formUnion(direct)
            for row in direct {
                guard backend.rightExists(row), let nested = try? backend.definition(of: row),
                      let nestedDict = Self.dictionary(nested) else { continue }
                rows.formUnion(AuthURICompositionNaming.ownedRows(referencedBy: nestedDict)
                    .filter { Self.isCompositionRow($0, of: right) })
            }
        }
        return rows.filter(AuthURICompositionNaming.isOwnedRow).sorted()
    }

    /// Whether `row` is named for `right` (see ``AuthURICompositionNaming``):
    /// its `native-default` row, or an app row of it (`.app.<slug>`, and that
    /// row's `.identity` and `.auth` halves).
    private static func isCompositionRow(_ row: String, of right: String) -> Bool {
        row == AuthURICompositionNaming.nativeDefaultRow(for: right)
            || row.hasPrefix(AuthURICompositionNaming.rowPrefix + right + ".app.")
    }

    /// Removes owned rows, best-effort: macOS may refuse `AuthorizationRightRemove`
    /// (-60005), in which case an orphaned row — referenced by nothing — is
    /// neutralized to `class=deny` so it can never grant anything.
    ///
    /// - Returns: the rows that could be neither removed nor neutralized. A
    ///   restore counts each as a leftover, since such a row may still name
    ///   SerberusAuth.
    @discardableResult
    private func removeRows(_ rows: [String], right: String, result: inout ApplyResult) async -> [String] {
        var failed: [String] = []
        for row in rows where AuthURICompositionNaming.isOwnedRow(row) {
            guard backend.rightExists(row) else { continue }
            if (try? backend.removeRight(row)) != nil {
                result.branchRowsRemoved.append(row)
                await emit(.authDBModification, "removed retired branch row '\(row)' from '\(right)'")
            } else if (try? backend.setDefinition(Self.definitionPlist(for: .deny), for: row)) != nil {
                result.branchRowsRemoved.append(row)
                await emit(.authDBModification, "branch row '\(row)' could not be removed (macOS denied); neutralized to deny")
            } else {
                failed.append(row)
                DaemonLog.integrity.error("authdb: branch row '\(row, privacy: .public)' could not be removed or neutralized")
                await emit(.authDBModification, "branch row '\(row)' could not be removed or neutralized")
            }
        }
        return failed
    }

    // MARK: - Semantic diff

    /// Compares two right definitions by their policy-relevant fields only,
    /// ignoring system-managed metadata (created/modified/version/comment/etc.).
    static func semanticallyEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        policyFields(lhs) == policyFields(rhs)
    }

    /// The decision-bearing subset of a right definition. Includes
    /// `mechanisms`/`shared`/`timeout` so an evaluate-mechanisms definition
    /// (e.g. an authURI prompt rule wired to the Sentinel authorization
    /// plugin) is detected as a change against a prior `class=allow|deny|rule`
    /// definition — those keys carry the decision for that class the same way
    /// `rule`/`group` do for `class=rule`/`class=user`, so omitting them let
    /// two rights with different mechanism chains compare equal and skip a
    /// needed rewrite. `k-of-n` carries the composition's decision (OR vs
    /// AND) and the `class=user` principal flags carry a branch's posture, so
    /// they are compared too.
    ///
    /// `requirement` is deliberately NOT compared: authd does not decide a
    /// right with it (the SerberusAuth mechanism enforces a branch's app
    /// identity, and Serberus writes no `requirement` into any row), and on
    /// macOS 26 authd stamps the creating process's own code requirement
    /// (with `identifier`) onto every right a signed process writes, so the
    /// read-back of a row Serberus wrote never matches what it wrote. The
    /// key still counts in ``canonicalDigest(_:)``, taken from authd's
    /// read-back, so a planted row must match it too.
    static func policyFields(_ data: Data) -> [String: String] {
        guard let dict = dictionary(data) else { return [:] }
        var fields: [String: String] = [:]
        if let cls = dict["class"] as? String { fields["class"] = cls }
        if let rule = dict["rule"] as? [String] { fields["rule"] = rule.joined(separator: ",") }
        if let rule = dict["rule"] as? String { fields["rule"] = rule }
        if let group = dict["group"] as? String { fields["group"] = group }
        if let mechanisms = dict["mechanisms"] as? [String] { fields["mechanisms"] = mechanisms.joined(separator: ",") }
        if let shared = dict["shared"] as? Bool { fields["shared"] = shared ? "1" : "0" }
        if let timeout = dict["timeout"] as? Int { fields["timeout"] = String(timeout) }
        if let kofn = dict["k-of-n"] as? Int { fields["k-of-n"] = String(kofn) }
        for flag in ["session-owner", "authenticate-user", "allow-root", "password-only"] {
            if let value = dict[flag] as? Bool { fields[flag] = value ? "1" : "0" }
        }
        return fields
    }

    // MARK: - Restore

    /// Restores every snapshotted right (uninstall / upgrade-failure rollback).
    /// **Best-effort and resilient:** each right is
    /// attempted independently so one corrupt snapshot cannot strand the others
    /// (e.g. leave a `deny` blocking a Settings pane after uninstall). An intact
    /// snapshot restores the original; an unreadable/tampered one resets the right
    /// to Apple's shipped default from `authorization.plist`, or the admin gate
    /// for a name Apple does not ship (never leaves a `deny`). Owned
    /// composition rows are swept for every entry.
    ///
    /// The backup directory is NOT the only source: if it is empty or missing
    /// (wiped, never migrated), composed rights would still reference
    /// `SerberusAuth:identity` while the uninstaller deletes the plugin — which
    /// fails those rights for EVERY caller. So the LIVE database is then swept
    /// too (``sweepUnrecordedRights(extraCandidates:)``): every right carrying
    /// ``managedMarker``, referencing a Serberus composition row, or naming a
    /// `SerberusAuth:` mechanism is reset to its verified native-default row
    /// or a stand-in (Apple's shipped default, else the admin-auth gate; never
    /// over a protected right), a foreign chain that merely names SerberusAuth
    /// loses only that entry, and orphaned composition rows are removed.
    ///
    /// Throws an aggregate error only AFTER attempting every right, so the
    /// caller still enters degraded state when any restore failed — and ALSO
    /// when any right still references SerberusAuth afterwards, so
    /// `serberusd --restore-authdb` exits non-zero and the uninstaller knows
    /// the plugin is still load-bearing. A protected right that Apple does not
    /// ship and Serberus never recorded is not counted (see
    /// ``countsAsLeftover(_:recorded:)``): only a user can have created it.
    @discardableResult
    public func restoreAll() async throws -> [String] {
        let entries = allControlledEntries()
        let recorded = Set(entries.map(\.rightName))
        var restored: [String] = []
        var restoreError: Error?
        do {
            restored = try await restore(entries: entries)
        } catch {
            restoreError = error
        }
        let candidates = sweepCandidates(extra: entries.map(\.rightName))
        let sweep = await sweepUnrecordedRights(candidates)
        restored.append(contentsOf: sweep.reset)
        let remaining = Set(rightsReferencingSerberusAuth(candidates)).union(sweep.leftovers).sorted()
        let leftovers = remaining.filter { countsAsLeftover($0, recorded: recorded) }
        let ignored = remaining.filter { !countsAsLeftover($0, recorded: recorded) }
        if !ignored.isEmpty {
            await emit(.authDBRestore, "left as is and not counted as a failed restore: \(ignored) name SerberusAuth or carry Serberus's marker, but each is a protected right macOS does not ship and Serberus never wrote (Serberus never writes a protected right), so it was created by someone else and nothing but its creator uses it. Remove it by hand if it is unwanted (security authorizationdb remove).")
        }
        if !leftovers.isEmpty {
            await emit(.authDBRestore, "RESTORE INCOMPLETE: \(leftovers) still reference SerberusAuth or a Serberus composition row, could not be reset, or are protected rights left Serberus-written")
            throw AuthorizationDBError.restoreFailed(
                name: leftovers.joined(separator: ", "),
                underlying: "\(leftovers.count) right(s) still reference SerberusAuth, could not be reset, or are protected and left Serberus-written after restore; the plugin must not be removed")
        }
        if let restoreError { throw restoreError }
        return restored
    }

    /// The right names the restore sweep examines: the live database's full
    /// list when the backend can enumerate it (``AuthorizationDBBackend/allRightNames()``
    /// — a read-only SQLite read of `/var/db/auth.db`, root only), otherwise
    /// every right the shipped `/System/Library/Security/authorization.plist`
    /// defines plus the names Serberus recorded. Composition rows reached
    /// through a top-level's `rule` array are followed either way.
    private func sweepCandidates(extra: [String]) -> [String] {
        var names = Set(extra)
        if let live = backend.allRightNames() {
            names.formUnion(live)
        } else {
            names.formUnion(Self.shippedRightNames())
        }
        return names.filter { !$0.isEmpty }.sorted()
    }

    /// Apple's shipped authorization database.
    public static let shippedDefaultsPath = "/System/Library/Security/authorization.plist"

    private static func shippedRights(plistPath: String) -> [String: Any]? {
        guard let data = FileManager.default.contents(atPath: plistPath),
              let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
        else { return nil }
        return plist["rights"] as? [String: Any]
    }

    /// Every right `/System/Library/Security/authorization.plist` defines —
    /// the enumeration fallback when auth.db itself cannot be read.
    static func shippedRightNames(plistPath: String = shippedDefaultsPath) -> [String] {
        Array((shippedRights(plistPath: plistPath) ?? [:]).keys)
    }

    /// Apple's shipped definition of `right`, serialized, or nil when the
    /// plist does not define that name.
    public static func shippedDefinition(of right: String, plistPath: String = shippedDefaultsPath) -> Data? {
        guard let definition = shippedRights(plistPath: plistPath)?[right] as? [String: Any] else { return nil }
        return try? PropertyListSerialization.data(fromPropertyList: definition, format: .xml, options: 0)
    }

    /// What restore writes when a right's original definition cannot be
    /// recovered: Apple's shipped default when this macOS ships the right
    /// (so an entitlement-gated right is not weakened and a console-open one
    /// is not locked to admins), else the admin-auth gate. Never a deny.
    private func unrecoverableFallback(for right: String) -> (definition: Data, label: String, isStandIn: Bool) {
        if let shipped = shippedDefinitions(right), Self.dictionary(shipped) != nil {
            return (shipped, "Apple's shipped default", false)
        }
        return (Self.definitionPlist(for: .requireAdmin), "the admin-auth default", true)
    }

    /// Writes ``unrecoverableFallback(for:)`` over `right`. When that is the
    /// admin-auth stand-in, its digest is recorded (see
    /// ``AuthorizationDBSnapshotStore/saveStandInDigest(_:rightName:)``);
    /// Apple's shipped default is not Serberus's and clears any record.
    private func writeFallback(for right: String) throws -> (definition: Data, label: String, isStandIn: Bool) {
        let fallback = unrecoverableFallback(for: right)
        try backend.setDefinition(fallback.definition, for: right)
        if fallback.isStandIn, let readBack = try? backend.definition(of: right),
           let digest = Self.canonicalDigest(readBack) {
            try? store.saveStandInDigest(digest, rightName: right)
        } else if !fallback.isStandIn {
            try? store.removeStandIn(rightName: right)
        }
        return fallback
    }

    /// Whether `definition` is the admin-auth stand-in Serberus recorded for
    /// `right`: the stand-in's policy, and the digest recorded when it was
    /// written. The comment alone proves nothing.
    func isRecordedStandIn(_ definition: Data, right: String) -> Bool {
        guard let recorded = store.standInDigest(rightName: right) else { return false }
        return Self.canonicalDigest(definition) == recorded
            && Self.semanticallyEqual(definition, Self.definitionPlist(for: .requireAdmin))
    }

    /// Whether Serberus wrote `definition` over `right`: it carries the
    /// marker or references owned rows (``isSerberusWritten(_:)``), or it is
    /// the stand-in Serberus recorded for this right.
    func isSerberusWritten(_ definition: Data, right: String) -> Bool {
        Self.isSerberusWritten(definition) || isRecordedStandIn(definition, right: right)
    }

    /// The plugin half of ``AppIdentityBranch/mechanismName`` (`SerberusAuth:`).
    static let serberusAuthMechanismPrefix = "SerberusAuth:"

    /// Whether `mechanism` names the SerberusAuth plugin. The plugin half is
    /// compared ignoring ASCII case, as the uninstallers' SQL `LIKE` does, so
    /// the daemon and the scripts agree on which rights still need it.
    static func isSerberusAuthMechanism(_ mechanism: String) -> Bool {
        mechanism.lowercased().hasPrefix(serberusAuthMechanismPrefix.lowercased())
    }

    /// Whether a definition names a `SerberusAuth:` mechanism (any case).
    static func referencesSerberusAuthMechanism(_ definition: Data) -> Bool {
        guard let mechanisms = dictionary(definition)?["mechanisms"] as? [String] else { return false }
        return mechanisms.contains(where: isSerberusAuthMechanism)
    }

    /// `definition` with every `SerberusAuth:` entry removed from its
    /// `mechanisms`, or nil when nothing would be left (an empty mechanism
    /// list is not a safe definition to write).
    static func strippingSerberusAuth(from definition: Data) -> Data? {
        guard var dict = dictionary(definition), let mechanisms = dict["mechanisms"] as? [String] else { return nil }
        let kept = mechanisms.filter { !isSerberusAuthMechanism($0) }
        guard !kept.isEmpty else { return nil }
        dict["mechanisms"] = kept
        return plist(dict)
    }

    /// Resets every live right among `candidates` that Serberus wrote but no
    /// longer has a record for (see ``restoreAll()``), then removes orphaned
    /// composition rows. Best-effort.
    ///
    /// - A definition someone else wrote that merely NAMES a `SerberusAuth:`
    ///   mechanism (an admin added it to their own chain) keeps that chain:
    ///   only the `SerberusAuth:` entries are removed.
    /// - A protected right is never overwritten with a stand-in definition;
    ///   it is logged and reported as a leftover for an admin to repair.
    /// - A right whose reset fails is a leftover too, and keeps its records.
    ///
    /// - Returns: the rights reset, and the leftovers: the protected rights
    ///   left as they are, the rights whose reset failed, and the rows that
    ///   could be neither removed nor neutralized.
    private func sweepUnrecordedRights(_ candidates: [String]) async -> (reset: [String], leftovers: [String]) {
        var reset: [String] = []
        var leftovers: [String] = []
        var orphanRows: Set<String> = []
        for name in candidates {
            guard backend.rightExists(name), let definition = try? backend.definition(of: name) else { continue }
            if AuthURICompositionNaming.isOwnedRow(name) {
                orphanRows.insert(name)
                continue
            }
            let serberusAuth = Self.referencesSerberusAuthMechanism(definition)
            let serberusWritten = Self.referencesOwnedRows(definition) || Self.carriesManagedMarker(definition)
            if serberusAuth, !serberusWritten, let stripped = Self.strippingSerberusAuth(from: definition) {
                do {
                    try backend.setDefinition(stripped, for: name)
                    reset.append(name)
                    await emit(.authDBRestore, "sweep: '\(name)' names a SerberusAuth mechanism in a chain Serberus did not write; removed only the SerberusAuth entries and kept the rest")
                } catch {
                    await emit(.authDBRestore, "sweep: could not remove the SerberusAuth entries from '\(name)': \(String(describing: error))")
                }
                continue
            }
            // The admin-auth stand-in carries no marker, so it is the
            // terminal state here; one an older daemon wrote with the marker
            // is reset once more and so loses it.
            guard Self.referencesOwnedRows(definition) || serberusAuth
                    || Self.carriesManagedMarker(definition) else { continue }
            let rows = ownedRows(for: name, currentDefinition: definition)
            let preserved = verifiedNativeDefault(for: name)
            if preserved == nil, Self.isProtected(name) {
                leftovers.append(name)
                DaemonLog.integrity.error("authdb: sweep: '\(name, privacy: .public)' is protected and Serberus-written with no recoverable original; NOT overwritten — repair it by hand")
                await emit(.authDBRestore, "sweep: '\(name)' is a protected right carrying a Serberus-written or SerberusAuth definition with no recoverable original. Serberus never writes a stand-in over a protected right; it is left as is and reported as a leftover. Restore it by hand (security authorizationdb write) from /System/Library/Security/authorization.plist.")
                continue
            }
            var resetFailed = false
            do {
                if let preserved {
                    try backend.setDefinition(preserved, for: name)
                    await emit(.authDBRestore, "sweep: '\(name)' was Serberus-written with no snapshot record; restored from its verified native-default row")
                } else {
                    let fallback = try writeFallback(for: name)
                    await emit(.authDBRestore, "sweep: '\(name)' was Serberus-written\(serberusAuth ? " (references SerberusAuth)" : "") with no snapshot record; reset to \(fallback.label)")
                }
                reset.append(name)
            } catch {
                // Still Serberus-written: a leftover, whatever it references,
                // and its records stay so the next restore tries again.
                resetFailed = true
                leftovers.append(name)
                await emit(.authDBRestore, "sweep: RESET FAILED for '\(name)': \(String(describing: error))")
            }
            var scratch = ApplyResult()
            leftovers.append(contentsOf: await removeRows(rows, right: name, result: &scratch))
            if !resetFailed { try? store.remove(rightName: name) }
        }
        // Rows no top-level references any more (their right was restored
        // above or earlier), including a `native-default` row that names no
        // mechanism and carries no marker: every live name under the owned
        // prefix is removed, or neutralized to deny. A row that can be
        // neither is a leftover.
        var scratch = ApplyResult()
        leftovers.append(contentsOf: await removeRows(orphanRows.sorted(), right: "<orphaned>", result: &scratch))
        return (reset, leftovers)
    }

    /// Whether a right that still references SerberusAuth (or is a protected
    /// right left Serberus-written) after restore means authorization breaks
    /// once the plugin is removed. Serberus never writes a protected right,
    /// so one that macOS does not ship and that Serberus never recorded can
    /// only be a NEW right someone created (`config.add.` is `class=allow`,
    /// so any user can) — no macOS component relies on it, and it must not
    /// be able to block restore or uninstall. Every other right counts,
    /// including every non-protected one the sweep could not reset.
    private func countsAsLeftover(_ name: String, recorded: Set<String>) -> Bool {
        guard Self.isProtected(name) else { return true }
        return recorded.contains(name) || shippedDefinitions(name) != nil
    }

    /// Live rights among `candidates` (plus the composition rows their
    /// top-levels reference) that still name a `SerberusAuth:` mechanism or a
    /// Serberus composition row.
    private func rightsReferencingSerberusAuth(_ candidates: [String]) -> [String] {
        var leftovers: Set<String> = []
        var toCheck = Set(candidates)
        for name in candidates where backend.rightExists(name) {
            if let definition = try? backend.definition(of: name) {
                toCheck.formUnion(ownedRows(for: name, currentDefinition: definition))
            }
        }
        for name in toCheck where backend.rightExists(name) {
            guard let definition = try? backend.definition(of: name) else { continue }
            if Self.referencesSerberusAuthMechanism(definition) || Self.referencesOwnedRows(definition) {
                leftovers.insert(name)
            }
        }
        return leftovers.sorted()
    }

    /// The right names Serberus currently controls (i.e. has a snapshot or an
    /// owned-rows record for). A right appears here from the moment `apply`
    /// snapshots it until a restore removes its snapshot. Used by the
    /// differential reconcile to compute which rights were DROPPED from the
    /// policy (controlled minus still-desired).
    public func controlledRightNames() -> [String] {
        allControlledEntries().map(\.rightName)
    }

    /// Snapshot entries plus sidecar-only rights (snapshot lost, rows recorded).
    private func allControlledEntries() -> [(rightName: String, snapshot: AuthorizationDBSnapshot?)] {
        var entries = store.allSnapshotsBestEffort()
        let known = Set(entries.map(\.rightName))
        for right in store.rightsWithOwnedRows() where !known.contains(right) {
            entries.append((right, nil))
        }
        return entries.sorted { $0.rightName < $1.rightName }
    }

    /// Restores ONLY the controlled rights whose name is in `names`, using the
    /// exact per-entry logic of ``restoreAll()`` (created-right rollback / snapshot
    /// restore / corrupt-snapshot reset-to-admin / snapshot removal / failure
    /// aggregation). Names with no snapshot are ignored. This is the targeted
    /// restore the differential reconcile uses so a right that STAYS desired is
    /// never touched. Best-effort and resilient — attempts every named right, then
    /// throws ``AuthorizationDBError/restoreFailed`` if any failed.
    @discardableResult
    public func restore(names: Set<String>) async throws -> [String] {
        try await restore(entries: allControlledEntries().filter { names.contains($0.rightName) })
    }

    /// The shared restore loop for ``restoreAll()`` and ``restore(names:)``. Each
    /// entry is attempted independently (via ``restoreEntry(_:)``) so one corrupt
    /// snapshot cannot strand the others; failures are aggregated and thrown only
    /// after every entry has been attempted, so the caller still enters degraded
    /// state when any restore failed.
    private func restore(entries: [(rightName: String, snapshot: AuthorizationDBSnapshot?)]) async throws -> [String] {
        var restored: [String] = []
        var failures: [String] = []
        for entry in entries {
            do {
                try await restoreEntry(entry)
                restored.append(entry.rightName)
            } catch {
                failures.append(entry.rightName)
                await emit(.authDBRestore, "RESTORE FAILED for '\(entry.rightName)': \(String(describing: error))")
            }
        }
        guard failures.isEmpty else {
            throw AuthorizationDBError.restoreFailed(
                name: failures.joined(separator: ", "),
                underlying: "\(failures.count) right(s) could not be restored"
            )
        }
        return restored
    }

    /// Restores a single controlled right to its pre-Serberus state, sweeps the
    /// composition rows Serberus owns for it, and clears its records. Throws on
    /// backend failure (before the records are removed) so the caller can
    /// aggregate.
    private func restoreEntry(_ entry: (rightName: String, snapshot: AuthorizationDBSnapshot?)) async throws {
        let right = entry.rightName
        let nativeRow = AuthURICompositionNaming.nativeDefaultRow(for: right)
        // Collect owned rows BEFORE the top-level is rewritten (the current
        // definition is one of the two ownership sources).
        let currentDefinition = backend.rightExists(right) ? (try? backend.definition(of: right)) : nil
        let rows = ownedRows(for: right, currentDefinition: currentDefinition)

        if let snapshot = entry.snapshot {
            if snapshot.wasAbsent {
                // Serberus created this right; roll it back so nothing it
                // created outlives the daemon. macOS DENIES removing some
                // rights outright (`AuthorizationRightRemove` → -60005,
                // errAuthorizationDenied — the root daemon isn't authorized
                // for `config.remove.<right>`), so removal is best-effort:
                // if it's refused, neutralize the right to the conservative
                // stand-in (Apple's shipped default, else the admin gate)
                // instead. A created right therefore never outlives Serberus
                // as a gate weaker than macOS's own, and one un-removable
                // right never aborts the whole restore (which would strand
                // every other controlled right — the failure mode that let
                // a stuck reconcile revert real rights every reload).
                if !backend.rightExists(right) {
                    await emit(.authDBRestore, "created right '\(right)' already absent; nothing to remove")
                } else if (try? backend.removeRight(right)) != nil {
                    await emit(.authDBRestore, "removed right '\(right)' (Serberus created it; it did not previously exist)")
                } else {
                    let fallback = try writeFallback(for: right)
                    await emit(.authDBRestore, "created right '\(right)' could not be removed (macOS denied); reset to \(fallback.label)")
                }
            } else {
                try backend.setDefinition(snapshot.originalDefinition, for: right)
                await emit(.authDBRestore, "restored right '\(right)' from snapshot")
            }
        } else if backend.rightExists(right) {
            if let preserved = verifiedNativeDefault(for: right) {
                // Corrupt/missing snapshot, but the composition's preserved
                // native-default row — verified against the digest recorded
                // when Serberus wrote it — still holds the original.
                try backend.setDefinition(preserved, for: right)
                await emit(.authDBRestore, "snapshot for '\(right)' unusable; restored from its verified native-default row")
            } else {
                if backend.rightExists(nativeRow) {
                    await emit(.authDBRestore, "native-default row for '\(right)' exists but is UNVERIFIED (not recorded by Serberus, or its digest does not match); NOT trusted")
                }
                // Corrupt/unreadable snapshot for a right that still exists —
                // we cannot recover the original, so reset to Apple's shipped
                // default, or the admin gate for a name Apple does not ship
                // (never leave a `deny`). Guarded by `rightExists` so a
                // corrupt tombstone for an already-removed right never causes
                // restore to CREATE one.
                let fallback = try writeFallback(for: right)
                await emit(.authDBRestore, "snapshot for '\(right)' unusable; reset to \(fallback.label)")
            }
        } else {
            await emit(.authDBRestore, "snapshot for '\(right)' unusable and right is absent; nothing to restore")
        }

        // Sweep the composition rows now that nothing references them. A row
        // that can be neither removed nor neutralized fails this entry, and
        // its records are kept so the next restore tries again.
        var scratch = ApplyResult()
        let stuck = await removeRows(rows, right: right, result: &scratch)
        guard stuck.isEmpty else {
            throw AuthorizationDBError.restoreFailed(
                name: right, underlying: "branch row(s) \(stuck.joined(separator: ", ")) could not be removed or neutralized")
        }
        try? store.remove(rightName: right)
    }

    /// Brackets one reconcile pass (``AuthorizationDBApplier/reconcile(profiles:)``)
    /// for ``RetryNoticeFilter``.
    func beginReconcilePass() {
        retryNotices.beginPass()
    }

    func endReconcilePass(failed: Bool) {
        retryNotices.endPass(failed: failed)
    }

    private func emit(_ kind: IntegrityEvent.Kind, _ detail: String) async {
        if retryNotices.isRepeat(detail) {
            DaemonLog.integrity.debug("authdb (as on the last, failed, pass): \(detail, privacy: .public)")
            return
        }
        DaemonLog.integrity.notice("authdb: \(detail, privacy: .public)")
        guard let integrityLogger else { return }
        let event = IntegrityEvent(timestamp: now(), kind: kind, detail: detail, daemonVersion: daemonVersion)
        try? await integrityLogger.log(event)
    }
}

/// The daemon's ``AuthorizationDBApplying`` implementation: project each plain
/// authuri rule onto a static AuthorizationDB policy
/// (``AuthorizationDBManager/desiredRights(in:)``) and compose each
/// identity-scoped right from its app branches
/// (``AuthorizationDBManager/desiredCompositions(in:perAppPinsEnabled:)``), then snapshot originals
/// and inject under the AuthorizationDB guardrails (existing rights only, checksummed
/// snapshot, minimal diff, restorable). Rights are restored on uninstall via
/// `serberusd --restore-authdb`.
///
/// Projection is *static* interception (allow / deny / native admin-auth) — true
/// Sentinel-mediated JIT for authorization rights would require an authorization
/// plugin and is out of scope for V1.
public struct AuthorizationDBApplier: AuthorizationDBApplying, AuthPluginHealthReporting,
                                     AuthorizationDBEffectiveConfigReceiving {
    private let manager: AuthorizationDBManager
    private let settings: AuthorizationDBEffectiveSettings?
    /// Whether identity-scoped rules are composed. Production always uses
    /// ``AuthURIIdentityScope/perAppPinsEnabled`` (false in 0.9.0):
    /// pins are then skipped and logged, and composed rights are restored.
    private let perAppPinsEnabled: Bool

    /// - Parameter settings: the box the manager's `sessionOwnerOnly` closure
    ///   reads; ``adoptEffectiveConfig(_:)`` writes into it. Nil when the
    ///   manager was built with some other source (tests).
    /// - Parameter perAppPinsEnabled: injected `true` only by tests that
    ///   exercise the composition machinery.
    public init(manager: AuthorizationDBManager, settings: AuthorizationDBEffectiveSettings? = nil,
                perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled) {
        self.manager = manager
        self.settings = settings
        self.perAppPinsEnabled = perAppPinsEnabled
    }

    public func adoptEffectiveConfig(_ config: SerberusConfig) {
        settings?.adopt(config)
    }

    public func authPluginHealthToken() -> String {
        switch manager.authPluginStatus() {
        case .installed: return "installed"
        case let .unavailable(reason): return "unavailable: \(reason)"
        }
    }

    public func authPluginProblem() -> String? {
        manager.lastAuthPluginProblem
    }

    /// Logs every authuri rule the AuthorizationDB layer will not enforce, one
    /// line per rule, so nothing is dropped silently. Called once per apply /
    /// reconcile pass (so once per reload). Returns the lines it logged (tests).
    @discardableResult
    func logSkippedRules(_ profiles: [RuleProfile]) -> [String] {
        manager.skippedRules(profiles, perAppPinsEnabled: perAppPinsEnabled).map { skipped in
            let line = "authdb: rule '\(skipped.ruleID)' on '\(skipped.right)' skipped: \(skipped.reason)"
            DaemonLog.integrity.notice("\(line, privacy: .public)")
            return line
        }
    }

    /// Whether the SerberusAuth plugin is installed and trusted. When it is
    /// not, identity-scoped rules are left native on every apply (see
    /// ``AuthorizationDBManager/ApplyResult/authPluginUnavailable``); the
    /// daemon can surface this in its health/status report.
    public func authPluginStatus() -> AuthPluginInstallStatus {
        manager.authPluginStatus()
    }

    public func apply(profiles: [RuleProfile]) async throws {
        let desired = AuthorizationDBManager.desiredRights(in: profiles)
        let compositions = AuthorizationDBManager.desiredCompositions(in: profiles, perAppPinsEnabled: perAppPinsEnabled)
        logSkippedRules(profiles)
        if compositions.isEmpty { manager.noteNoCompositionsDesired() }
        guard !desired.isEmpty || !compositions.isEmpty else { return }
        for right in AuthorizationDBManager.skippedByProjection(profiles, perAppPinsEnabled: perAppPinsEnabled) {
            DaemonLog.integrity.notice("authdb: '\(right, privacy: .public)' has both a plain authuri rule and per-app branches; the plain projection wins, branches skipped")
        }
        try await manager.apply(desired, compositions: compositions)
    }

    /// Reconciles a live policy reload DIFFERENTIALLY: a right that stays in the
    /// policy is never reverted, so a standard user never sees a sub-second admin
    /// prompt flicker on a controlled right across a reload.
    ///
    /// Only rights DROPPED from the policy (currently controlled minus still
    /// desired) are restored to their originals. The current desired set is then
    /// applied — and `apply` is idempotent (it snapshots once and writes only when
    /// the definition semantically differs), so an unchanged still-desired right is
    /// a no-op (no revert, no re-write), a changed right updates in place, and a
    /// new right is snapshotted then applied. A composed right that keeps SOME
    /// apps but retires one stays desired: only the retired app's row is deleted
    /// and dropped from the array. Because the dropped and desired sets are
    /// disjoint, a still-desired right is never touched by the restore. An empty
    /// policy drops everything, so every controlled right is restored.
    ///
    /// Restore is best-effort: even if a dropped right cannot be rolled back, the
    /// CURRENT policy must still be enforced, so the desired set is always applied
    /// and the restore error is surfaced only afterwards.
    /// The rule profiles to project into the AuthorizationDB. Rights are
    /// rewritten only in enforce mode: monitor and audit are meant to change
    /// nothing on the Mac, so they (like awaiting-config) reconcile to the
    /// native state, which also undoes rights applied under a previous enforce.
    public static func profilesToApply(_ profiles: [RuleProfile],
                                       mode: EnforcementMode,
                                       awaitingConfig: Bool) -> [RuleProfile] {
        guard !awaitingConfig, mode == .enforce else { return [] }
        return profiles
    }

    public func reconcile(profiles: [RuleProfile]) async throws {
        manager.beginReconcilePass()
        let desired = AuthorizationDBManager.desiredRights(in: profiles)
        let compositions = AuthorizationDBManager.desiredCompositions(in: profiles, perAppPinsEnabled: perAppPinsEnabled)
        let desiredNames = Set(desired.map(\.name)).union(compositions.map(\.right))
        let dropped = Set(manager.controlledRightNames()).subtracting(desiredNames)

        var restoreError: Error?
        do {
            _ = try await manager.restore(names: dropped)
        } catch {
            restoreError = error
        }

        // Always apply the current desired set, even if the drop-restore failed.
        // Capture (rather than immediately propagate) apply's error so a restore
        // failure is never SWALLOWED when apply also throws — either failure
        // drives the daemon to `degraded(authdb_failure)`, and restore()'s own
        // per-right emit already logs the restore failure regardless.
        logSkippedRules(profiles)
        if compositions.isEmpty { manager.noteNoCompositionsDesired() }
        var applyError: Error?
        if !desired.isEmpty || !compositions.isEmpty {
            do {
                for right in AuthorizationDBManager.skippedByProjection(profiles, perAppPinsEnabled: perAppPinsEnabled) {
                    DaemonLog.integrity.notice("authdb: '\(right, privacy: .public)' has both a plain authuri rule and per-app branches; the plain projection wins, branches skipped")
                }
                try await manager.apply(desired, compositions: compositions)
            } catch {
                applyError = error
            }
        }

        manager.endReconcilePass(failed: applyError != nil || restoreError != nil)
        if let applyError { throw applyError }
        if let restoreError { throw restoreError }
    }
}

// MARK: - SerberusAuth plugin install check

/// Whether the SerberusAuth authorization plugin can be referenced from a
/// right. A right that names `SerberusAuth:identity` while authd cannot load
/// the bundle fails for EVERY caller, so the composer checks this first.
public enum AuthPluginInstallStatus: Sendable, Equatable {
    case installed
    case unavailable(reason: String)
}

/// Seam for the plugin install check, so tests can drive both outcomes.
public protocol AuthPluginBundleVerifying: Sendable {
    /// The full check (ownership, mode, code signature).
    func verify() -> AuthPluginInstallStatus
    /// A cheap token that changes whenever anything ``verify()`` depends on
    /// could have changed (`lstat` identity + times of the bundle and its
    /// signature-relevant files). Nil = no cheap check; verify every time.
    func fingerprint() -> String?
}

public extension AuthPluginBundleVerifying {
    func fingerprint() -> String? { nil }
}

/// Reports the SerberusAuth plugin's health to the daemon. The daemon folds
/// ``authPluginHealthToken()`` into its per-tick policy signature — so the
/// plugin disappearing (or coming back) triggers a reconcile, which puts
/// composed rights back to native (or recomposes them) — and surfaces
/// ``authPluginProblem()`` as `degraded(auth_plugin_unavailable)`.
public protocol AuthPluginHealthReporting: Sendable {
    /// Cheap per-tick token: `lstat` fingerprint, full check only on change.
    func authPluginHealthToken() -> String
    /// Non-nil while identity-scoped rules are in the enforced policy but not
    /// enforced because the plugin is unavailable.
    func authPluginProblem() -> String?
}

extension AuthPluginHealthReporting {
    /// Overlays `degraded(auth_plugin_unavailable)` onto an already-resolved
    /// daemon state. Lowest-ranked degraded cause: it only replaces a HEALTHY
    /// state (a pending, awaiting, kill-switch or other degraded state is
    /// already the more urgent report).
    public func overlayAuthPluginHealth(state: DaemonState, reason: DegradedReason?)
        -> (state: DaemonState, reason: DegradedReason?) {
        guard state == .healthy, let problem = authPluginProblem() else { return (state, reason) }
        DaemonLog.integrity.error("authdb: identity-scoped rules NOT enforced — SerberusAuth plugin unavailable (\(problem, privacy: .public)); degraded(auth_plugin_unavailable)")
        return (.degraded, .authPluginUnavailable)
    }
}

/// Receives the daemon's EFFECTIVE config (managed, or last-known-good) each
/// time it is resolved, for the settings the authdb layer consumes.
public protocol AuthorizationDBEffectiveConfigReceiving: Sendable {
    func adoptEffectiveConfig(_ config: SerberusConfig)
}

/// The effective-config values the AuthorizationDB manager reads at compose
/// time (today: `enableBiometrics`). A lock-protected box so the manager's
/// synchronous `sessionOwnerOnly` closure can read what the daemon actor last
/// resolved.
public final class AuthorizationDBEffectiveSettings: @unchecked Sendable {
    private let lock = NSLock()
    private var biometrics: Bool

    public init(enableBiometrics: Bool) {
        biometrics = enableBiometrics
    }

    /// Seeds the box before the daemon's first resolution (the startup apply
    /// runs before the controller adopts its config): the delivered config
    /// when it is usable (present, enabled, enforceable), else the
    /// last-known-good snapshot, else `false` — the same precedence
    /// `EffectiveConfigResolver` applies, without its snapshot side effect.
    public convenience init(reader: ManagedPreferencesReader, lastKnownGood: any LastKnownGoodConfigStoring) {
        let managed = reader.readConfig().value
        if reader.configIsPresent(), managed.daemonEnabled, managed.isEnforceable {
            self.init(enableBiometrics: managed.enableBiometrics)
        } else {
            self.init(enableBiometrics: lastKnownGood.load()?.enableBiometrics ?? false)
        }
    }

    public var enableBiometrics: Bool {
        lock.lock(); defer { lock.unlock() }
        return biometrics
    }

    public func adopt(_ config: SerberusConfig) {
        lock.lock(); defer { lock.unlock() }
        biometrics = config.enableBiometrics
    }
}

/// The manager's shared plugin bookkeeping (the manager is a value type that
/// is copied freely; this reference keeps one cache across copies).
final class AuthPluginState: @unchecked Sendable {
    private let lock = NSLock()
    private var fingerprint: String?
    private var status: AuthPluginInstallStatus?
    private var currentProblem: String?

    func cachedStatus(for fingerprint: String) -> AuthPluginInstallStatus? {
        lock.lock(); defer { lock.unlock() }
        return self.fingerprint == fingerprint ? status : nil
    }

    func cache(_ status: AuthPluginInstallStatus, for fingerprint: String) {
        lock.lock(); defer { lock.unlock() }
        self.fingerprint = fingerprint
        self.status = status
    }

    var problem: String? {
        lock.lock(); defer { lock.unlock() }
        return currentProblem
    }

    func setProblem(_ problem: String?) {
        lock.lock(); defer { lock.unlock() }
        currentProblem = problem
    }
}

/// Keeps a failed reconcile's retries quiet. The daemon re-runs a failed
/// reconcile on every reload tick until it succeeds; each pass would otherwise
/// write the same integrity events again (the failure itself, every refused
/// rule, every composition warning) every 30 seconds. A notice identical to
/// one the last pass logged, when that pass failed, is logged at debug level
/// instead. Only inside a pass (``AuthorizationDBManager/beginReconcilePass()``);
/// after a pass that succeeded, everything is logged again.
final class RetryNoticeFilter: @unchecked Sendable {
    private let lock = NSLock()
    /// What the last pass logged, when it failed; nil after one that did not.
    private var previous: Set<String>?
    /// What the pass in progress has logged; nil outside a pass.
    private var current: Set<String>?

    func beginPass() {
        lock.lock(); defer { lock.unlock() }
        current = []
    }

    /// Records `detail` for the pass in progress. True when the last pass,
    /// which failed, logged it too.
    func isRepeat(_ detail: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard current != nil else { return false }
        current?.insert(detail)
        return previous?.contains(detail) ?? false
    }

    func endPass(failed: Bool) {
        lock.lock(); defer { lock.unlock() }
        previous = failed ? current ?? [] : nil
        current = nil
    }
}

/// The production check: the bundle at
/// `/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle` must be a
/// real directory (not a symlink), owned by root, not group/other-writable,
/// carry a valid code signature — Apple-anchored, with the plugin's
/// identifier and this daemon's own Team ID when the daemon is signed — and
/// its executable must contain a slice for this Mac's CPU. A validly signed
/// bundle without that slice passes every signature check yet cannot be
/// loaded by SecurityAgent, which would fail every composed right for every
/// caller. The bundle is never loaded into the daemon to find out.
public struct SystemAuthPluginBundleVerifier: AuthPluginBundleVerifying {
    public static let defaultBundlePath = "/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
    /// `PRODUCT_BUNDLE_IDENTIFIER` of the SerberusAuth target.
    public static let bundleIdentifier = "com.herojoneslabs.serberus.authplugin"

    private let bundlePath: String
    private let teamID: String
    private let hostCPUType: cpu_type_t

    /// `CPU_TYPE_ARM64` / `CPU_TYPE_X86_64` from `<mach/machine.h>` (function-like
    /// macros Swift does not import).
    public static let cpuTypeARM64: cpu_type_t = 0x0100_000C
    public static let cpuTypeX86_64: cpu_type_t = 0x0100_0007
    private static let fatMagic: UInt32 = 0xCAFE_BABE
    private static let fatMagic64: UInt32 = 0xCAFE_BABF

    /// - Parameter teamID: the team the bundle must be signed by. Defaults to
    ///   the team that signed this daemon; empty (an unsigned development
    ///   build) checks signature validity only.
    /// - Parameter hostCPUType: the CPU the plugin must have a slice for.
    ///   Defaults to this Mac's (SecurityAgent runs natively).
    public init(bundlePath: String = SystemAuthPluginBundleVerifier.defaultBundlePath,
                teamID: String = BundleConfig.teamID,
                hostCPUType: cpu_type_t = SystemAuthPluginBundleVerifier.hostCPUType()) {
        self.bundlePath = bundlePath
        self.teamID = teamID
        self.hostCPUType = hostCPUType
    }

    /// This Mac's native CPU type: arm64 on Apple silicon (also when the
    /// asking process runs translated), else x86_64.
    public static func hostCPUType() -> cpu_type_t {
        var arm64: Int32 = 0
        var size = MemoryLayout<Int32>.size
        if sysctlbyname("hw.optional.arm64", &arm64, &size, nil, 0) == 0, arm64 == 1 {
            return cpuTypeARM64
        }
        return cpuTypeX86_64
    }

    /// Whether the Mach-O file at `path` (thin or universal) contains a slice
    /// for `cpuType`. Nil when the file cannot be read or is not Mach-O.
    /// Reads the headers only; never maps or loads the code.
    public static func machOContainsArchitecture(at path: String, cpuType: cpu_type_t) -> Bool? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var header = [UInt8](repeating: 0, count: 4096)
        let count = header.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard count >= 8 else { return nil }
        func be32(_ offset: Int) -> UInt32? {
            guard offset + 4 <= count else { return nil }
            return header[offset..<offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
        }
        func le32(_ offset: Int) -> UInt32? {
            guard offset + 4 <= count else { return nil }
            return header[offset..<offset + 4].reversed().reduce(0) { $0 << 8 | UInt32($1) }
        }
        let wanted = UInt32(bitPattern: cpuType)
        switch be32(0) {
        case fatMagic, fatMagic64:
            // Universal header: big-endian fat_arch (20 bytes) or fat_arch_64
            // (32 bytes) entries after the 8-byte fat_header.
            let entrySize = be32(0) == fatMagic64 ? 32 : 20
            guard let slices = be32(4), slices > 0, slices <= 64 else { return nil }
            for index in 0..<Int(slices) {
                guard let slice = be32(8 + index * entrySize) else { return nil }
                if slice == wanted { return true }
            }
            return false
        case 0xCFFA_EDFE, 0xCEFA_EDFE:
            // Thin little-endian Mach-O (MH_MAGIC_64 / MH_MAGIC as stored).
            return le32(4) == wanted
        default:
            return nil
        }
    }

    /// The code requirement the bundle is validated against, or nil when no
    /// team is known (validity only).
    static func requirement(teamID: String) -> String? {
        guard CodeRequirementCompiler.isValidTeamID(teamID) else { return nil }
        return "identifier \"\(bundleIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// The files whose identity/times feed ``fingerprint()``: the bundle
    /// directory and everything the signature check reads first.
    private var fingerprintPaths: [String] {
        [bundlePath,
         bundlePath + "/Contents",
         bundlePath + "/Contents/Info.plist",
         bundlePath + "/Contents/MacOS",
         bundlePath + "/Contents/MacOS/SerberusAuth",
         bundlePath + "/Contents/_CodeSignature",
         bundlePath + "/Contents/_CodeSignature/CodeResources"]
    }

    /// `dev:ino:mode:uid:size:mtime:ctime` of each ``fingerprintPaths`` entry
    /// (`-` when absent). Any replacement, rewrite, chmod or chown of those
    /// files moves at least the ctime, so an unchanged fingerprint means the
    /// last full ``verify()`` still holds.
    public func fingerprint() -> String? {
        fingerprintPaths.map { path -> String in
            var info = stat()
            guard lstat(path, &info) == 0 else { return "-" }
            return "\(info.st_dev):\(info.st_ino):\(info.st_mode):\(info.st_uid):\(info.st_size):"
                + "\(info.st_mtimespec.tv_sec).\(info.st_mtimespec.tv_nsec):\(info.st_ctimespec.tv_sec).\(info.st_ctimespec.tv_nsec)"
        }.joined(separator: "|")
    }

    public func verify() -> AuthPluginInstallStatus {
        var info = stat()
        guard lstat(bundlePath, &info) == 0 else {
            return .unavailable(reason: "\(bundlePath) is not installed")
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            return .unavailable(reason: "\(bundlePath) is not a directory (a symlink or file stands in its place)")
        }
        guard info.st_uid == 0 else {
            return .unavailable(reason: "\(bundlePath) is owned by uid \(info.st_uid), not root")
        }
        guard (info.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
            return .unavailable(reason: "\(bundlePath) is group- or other-writable")
        }

        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: bundlePath, isDirectory: true) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess, let staticCode else {
            return .unavailable(reason: "\(bundlePath) has no readable code signature")
        }
        var requirement: SecRequirement?
        if let text = Self.requirement(teamID: teamID) {
            guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else {
                return .unavailable(reason: "could not compile the plugin requirement")
            }
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        let status = SecStaticCodeCheckValidity(staticCode, flags, requirement)
        guard status == errSecSuccess else {
            return .unavailable(reason: "\(bundlePath) fails signature validation (OSStatus \(status))")
        }

        let executable = bundlePath + "/Contents/MacOS/SerberusAuth"
        switch Self.machOContainsArchitecture(at: executable, cpuType: hostCPUType) {
        case true?:
            return .installed
        case false?:
            return .unavailable(reason: "\(executable) has no slice for this Mac's CPU (\(Self.label(hostCPUType))); SecurityAgent cannot load it")
        case nil:
            return .unavailable(reason: "\(executable) is missing or is not a Mach-O executable")
        }
    }

    static func label(_ cpuType: cpu_type_t) -> String {
        switch cpuType {
        case cpuTypeARM64: return "arm64"
        case cpuTypeX86_64: return "x86_64"
        default: return "CPU type \(cpuType)"
        }
    }
}
