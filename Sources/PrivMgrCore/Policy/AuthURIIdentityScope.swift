import Foundation
import Security

// MARK: - Identity-scoped authURI rules
//
// An identity-scoped authURI rule gives ONE app (pinned by Team ID + bundle
// ID) a lighter authentication posture on ONE AuthorizationDB right, without
// loosening that right for every other caller. The daemon composes the right
// as a k-of-n:1 OR over `[app-1, app-2, …, native-default]` where the
// native-default branch is the right's live, snapshotted definition and each
// app branch is an `evaluate-mechanisms` sub-rule that runs Serberus's
// authorization mechanism (`SerberusAuth.bundle`) ahead of the native password
// mechanisms. The mechanism — not the rule — is what checks the caller's code
// signature, because authd's rule schema has no code-requirement key.
// Everything here is the shared vocabulary for that composition: the per-app
// branch, the requirement compiler, the auth.db row naming, and the advisory
// verification table.

// MARK: Release switch

/// The one switch that decides whether identity-scoped (per-app, App
/// Identity) authURI rules do anything at all.
///
/// **Off in Serberus 0.9.0.** The mechanism identifies the app
/// from authd's `creator-audit-token` hint, and a caller can supply its own
/// `creator-audit-token` item in the AuthorizationCreate /
/// AuthorizationCopyRights environment, which authd hands to the mechanism in
/// place of the real one. Any process could therefore borrow the identity of
/// a running pinned app and take its easier path on a root-equivalent right.
/// Until the identity comes from a value the caller cannot write, per-app
/// pins stay disabled everywhere:
///
/// - the daemon composes nothing (SerberusDaemonCore's
///   `AuthorizationDBManager.desiredCompositions(in:perAppPinsEnabled:)`
///   returns no composition, and every pin is logged as
///   skipped with ``disabledSkipReason``), so the right keeps its native
///   definition and a right composed by an older build is restored by the
///   differential reconcile;
/// - the SerberusAuth mechanism denies every request (``SerberusAuthPolicy``),
///   so a stale composed right falls through to its native-default branch;
/// - ``PolicyValidator`` reports a pin as an error, and the engine/simulator
///   never lets one match.
///
/// The composition machinery is kept compiled for a later release. Tests
/// exercise it by injecting `true` where the call sites take a
/// `perAppPinsEnabled` parameter; production always uses this constant.
public enum AuthURIIdentityScope {
    /// Production value. Never flip this until the app's identity comes
    /// from a value the caller cannot forge.
    public static let perAppPinsEnabled = false

    /// Why the daemon skips a per-app rule (integrity log, once per reload).
    public static let disabledSkipReason =
        "per-app (App Identity) rules are disabled in Serberus 0.9.0: the app's identity comes from a value the caller can forge; the right keeps its native definition"

    /// Why the SerberusAuth mechanism denies (its `MechanismInvoke: DENY` line).
    public static let disabledMechanismReason = "per-app rules are disabled in this build"

    /// The validator's error for a per-app rule (Commander / export refuse it).
    public static let disabledValidationMessage =
        "Per-app (App Identity) rules are disabled in Serberus 0.9.0 because the app's identity comes from a value the requesting process can forge, so this rule would never take effect and the right keeps its native definition."
}

// MARK: Branch

/// The identity pin of ONE app branch on ONE right. A wire `Rule` carries at
/// most one of these (`Rule.appIdentity`) — rules are authored and stored
/// individually per app/right pair, never as a shared identity list.
///
/// There is deliberately NO posture on the schema: every app branch grants
/// `authenticate-session-owner-or-admin` (``branchBody``) — the console user
/// authenticates with their own password, or any admin with theirs — and the
/// referencing rule's silent/prompt setting does not change it.
public struct AppIdentityBranch: Codable, Sendable, Equatable, Hashable {
    /// Apple Developer Team ID (10 characters, e.g. `M5RQTPC7A2`).
    public var teamID: String
    /// The app's code-signing identifier (its bundle ID for a bundled app).
    public var bundleID: String

    public init(teamID: String, bundleID: String) {
        self.teamID = teamID
        self.bundleID = bundleID
    }

    /// The mechanism that performs the identity check, as authd names it:
    /// `<bundle name>:<mechanism id>`. Both halves are FROZEN — a right in
    /// auth.db references this string by name, so renaming either would
    /// leave every deployed right pointing at a mechanism that no longer
    /// exists.
    public static let mechanismName = "SerberusAuth:identity"

    /// How long an app's authentication is reused across the several
    /// authorizations one operation produces. Matches the native
    /// `authenticate-admin-nonshared` rule these rights fall through to.
    public static let credentialTimeoutSeconds = 30

    // MARK: The three rows an app branch is made of
    //
    // An app branch CANNOT be a single rule, because the two things it must do
    // live in different authd rule classes and neither class can do both:
    //
    // - Only `evaluate-mechanisms` can run a mechanism, which is the only way
    //   to check the caller's code signature (authd's rule schema has no
    //   code-requirement key — proved live).
    // - Only `class=user` does credential checking, which is what caches an
    //   authentication so the user is asked once. authd NEVER credential-checks
    //   an evaluate-mechanisms rule; it re-runs the whole chain every time, and
    //   it silently DISCARDS a `timeout` key written onto one (verified on
    //   macOS 27: the key is absent when the rule is read back).
    //
    // That mattered because one helper install is not one authorization: a
    // single install produces three (the app asks once directly, then
    // `/usr/libexec/smd` asks twice more on its behalf), so a chain that
    // authenticates inside the mechanism rule prompted the user three times.
    //
    // The branch is therefore a `k-of-n: 2` AND over both: identity is checked
    // on EVERY evaluation (no bypass), while authentication happens in a
    // `class=user` rule where the timeout actually persists and caches.

    /// `evaluate-mechanisms` sub-rule: the identity check alone, no password
    /// mechanisms. Runs on every evaluation.
    public static var identityBody: [String: Any] {
        [
            "class": "evaluate-mechanisms",
            "mechanisms": [mechanismName],
            "shared": false,
            "tries": 1,
            "version": 1,
        ]
    }

    /// `class=user` sub-rule: the authentication, with the credential cache.
    /// Self-contained (never a delegate to the built-in `authenticate-*`
    /// rules) so the `allow-root=true` non-interactive invariant that keeps
    /// MDM/root callers working is explicit. `shared=false` keeps the
    /// credential out of the global pool, where any caller could satisfy from
    /// it; the timeout then scopes reuse to the authorization that created it.
    ///
    /// - Parameter sessionOwnerOnly: drops the `group=admin` clause, leaving
    ///   the console user as the only principal who can satisfy the rule. That
    ///   is what lets macOS offer Touch ID: biometrics cannot stand in for a
    ///   different person, so SecurityAgent falls back to the name-and-password
    ///   form whenever some *other* admin could also approve. Driven by the
    ///   `enableBiometrics` config key; `false` (session-owner-or-admin) is the
    ///   default and the broader principal set.
    public static func authBody(sessionOwnerOnly: Bool) -> [String: Any] {
        var body: [String: Any] = [
            "class": "user",
            "session-owner": true,
            "authenticate-user": true,
            "allow-root": true,
            "shared": false,
            "timeout": credentialTimeoutSeconds,
            "tries": 3,
            "version": 1,
        ]
        if !sessionOwnerOnly { body["group"] = "admin" }
        return body
    }

    /// The posture an app branch grants, for display and for rule comments.
    public static func postureName(sessionOwnerOnly: Bool) -> String {
        sessionOwnerOnly ? "authenticate-session-owner" : "authenticate-session-owner-or-admin"
    }

    /// The app branch itself: BOTH sub-rules must pass.
    public static func branchBody(identityRow: String, authRow: String) -> [String: Any] {
        [
            "class": "rule",
            "k-of-n": 2,
            "rule": [identityRow, authRow],
            "version": 1,
        ]
    }

    /// Stable, filesystem/auth.db-safe token for row naming: `<team>.<bundle>`
    /// with anything outside `[A-Za-z0-9.-]` folded to `_`. Two branches on a
    /// right with the same (team, bundle) would collide — the validator
    /// rejects that pair as a duplicate before it ever reaches the composer.
    public var rowSlug: String {
        let safe = "\(teamID).\(bundleID)".map { ch -> Character in
            ch.isLetter || ch.isNumber || ch == "." || ch == "-" ? ch : "_"
        }
        return String(safe)
    }
}

// MARK: Requirement compiler

public enum CodeRequirementError: Error, Equatable, Sendable, LocalizedError {
    case invalidTeamID(String)
    case invalidBundleID(String)
    /// `SecRequirementCreateWithString` refused the compiled string.
    case requirementRejected(requirement: String, status: OSStatus)

    public var errorDescription: String? {
        switch self {
        case let .invalidTeamID(id):
            return "Team ID '\(id)' is not a 10-character Apple Team ID"
        case let .invalidBundleID(id):
            return "Bundle ID '\(id)' is not a valid code-signing identifier"
        case let .requirementRejected(requirement, status):
            return "macOS rejected the code requirement '\(requirement)' (status \(status))"
        }
    }
}

/// Team ID + bundle ID → a compiled code-signing requirement string, validated
/// through the Security framework BEFORE anything is written to auth.db.
///
/// The requirement shape is the standard Developer ID / App Store designated
/// requirement core: the signing identifier must equal the bundle ID, the
/// chain must anchor at Apple's generic root, and the leaf certificate's OU
/// (the Team ID) must match. Format checks run first so the string can never
/// carry a quote or metacharacter; ``validate(_:)`` then asks
/// `SecRequirementCreateWithString` — the same parser authd uses — to accept it.
public enum CodeRequirementCompiler {
    private static let teamIDPattern = try! NSRegularExpression(pattern: #"^[A-Z0-9]{10}$"#)
    private static let bundleIDPattern = try! NSRegularExpression(pattern: #"^[A-Za-z0-9][A-Za-z0-9.\-]{0,254}$"#)

    public static func isValidTeamID(_ teamID: String) -> Bool {
        teamIDPattern.firstMatch(in: teamID, range: NSRange(teamID.startIndex..., in: teamID)) != nil
    }

    public static func isValidBundleID(_ bundleID: String) -> Bool {
        bundleIDPattern.firstMatch(in: bundleID, range: NSRange(bundleID.startIndex..., in: bundleID)) != nil
    }

    /// Builds the requirement string. Throws on a malformed Team ID / bundle
    /// ID; does NOT touch the Security framework (pure, testable anywhere).
    public static func compile(teamID: String, bundleID: String) throws -> String {
        guard isValidTeamID(teamID) else { throw CodeRequirementError.invalidTeamID(teamID) }
        guard isValidBundleID(bundleID) else { throw CodeRequirementError.invalidBundleID(bundleID) }
        return "identifier \"\(bundleID)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// Asks `SecRequirementCreateWithString` to parse `requirement`. Throws
    /// ``CodeRequirementError/requirementRejected(requirement:status:)`` when
    /// macOS will not accept it — the gate every composer write sits behind.
    public static func validate(_ requirement: String) throws {
        var compiled: SecRequirement?
        let status = SecRequirementCreateWithString(requirement as CFString, [], &compiled)
        guard status == errSecSuccess, compiled != nil else {
            throw CodeRequirementError.requirementRejected(requirement: requirement, status: status)
        }
    }

    /// ``compile(teamID:bundleID:)`` then ``validate(_:)``.
    public static func compileAndValidate(_ branch: AppIdentityBranch) throws -> String {
        let requirement = try compile(teamID: branch.teamID, bundleID: branch.bundleID)
        try validate(requirement)
        return requirement
    }
}

// MARK: auth.db row naming

/// Names of the extra auth.db rows the composer owns for a composed right.
/// Every row Serberus creates for the composition carries ``rowPrefix``, so
/// ownership is recognisable from the name alone (restore uses this to sweep
/// rows even when the on-disk ownership record is unreadable).
public enum AuthURICompositionNaming {
    public static let rowPrefix = "com.herojoneslabs.serberus.branch."

    /// The permanently preserved fallback branch: the right's native
    /// definition, captured live on first touch.
    public static func nativeDefaultRow(for right: String) -> String {
        rowPrefix + right + ".native-default"
    }

    /// The per-app sub-rule row (the `k-of-n: 2` composite).
    public static func appRow(for right: String, branch: AppIdentityBranch) -> String {
        rowPrefix + right + ".app." + branch.rowSlug
    }

    /// The identity half of an app branch (runs the mechanism).
    public static func appIdentityRow(for right: String, branch: AppIdentityBranch) -> String {
        appRow(for: right, branch: branch) + ".identity"
    }

    /// The authentication half of an app branch (holds the credential cache).
    public static func appAuthRow(for right: String, branch: AppIdentityBranch) -> String {
        appRow(for: right, branch: branch) + ".auth"
    }

    public static func isOwnedRow(_ name: String) -> Bool {
        name.hasPrefix(rowPrefix)
    }

    /// The owned rows a composed top-level definition references.
    public static func ownedRows(referencedBy definition: [String: Any]) -> [String] {
        let refs: [String]
        if let list = definition["rule"] as? [String] { refs = list }
        else if let single = definition["rule"] as? String { refs = [single] }
        else { refs = [] }
        return refs.filter(isOwnedRow)
    }
}

// MARK: - Scope guard

/// Whether identity scoping is known to work on a given right — an
/// ENGINEERING fact about how a macOS API resolves its caller, not admin
/// policy. ADVISORY ONLY: the daemon enforces whatever rule exists; this
/// table drives the "not verified" warnings Commander and the Sentinel show.
public enum AuthURIIdentityEligibility: String, Sendable, Codable, Equatable, CaseIterable {
    /// Empirically verified: the right resolves the client identity directly
    /// against the calling app, so a requirement branch can match it.
    case verifiedEligible = "verified-eligible"
    /// Empirically ruled out: the caller is always a mediator (Installer.app,
    /// smd, …) so no requirement can distinguish the real payload.
    case confirmedIneligible = "confirmed-ineligible"
    /// Authoring permitted for TESTING on allow-listed serial numbers only.
    /// Badged "Testing — not verified" everywhere it appears.
    case provisional
    /// Not in the table — blocked.
    case unknown

    public var label: String {
        switch self {
        case .verifiedEligible: return "Verified"
        case .confirmedIneligible: return "Ineligible"
        case .provisional: return "Testing — not verified"
        case .unknown: return "Not verified — blocked"
        }
    }

    /// True when the right has been verified (or is under test) — the
    /// states Commander offers in the App Identity rights browser.
    public var permitsAuthoring: Bool {
        switch self {
        case .verifiedEligible, .provisional: return true
        case .confirmedIneligible, .unknown: return false
        }
    }
}

/// One row of the scope-guard table.
public struct AuthURIIdentityScopeEntry: Sendable, Equatable {
    /// How the entry matches a right name.
    public enum Match: Sendable, Equatable {
        case exact(String)
        case prefix(String)

        public func matches(_ right: String) -> Bool {
            switch self {
            case let .exact(name): return right == name
            case let .prefix(prefix): return right.hasPrefix(prefix)
            }
        }
    }

    public let match: Match
    public let state: AuthURIIdentityEligibility
    /// The macOS MAJOR versions this entry was actually verified against
    /// (inclusive). `nil` = never verified (ineligible entries need none).
    public let verifiedMacOSMajors: ClosedRange<Int>?
    /// Serial numbers of the Mac(s) a `.provisional` right is being tested on.
    /// Informational — the daemon enforces the rule wherever it lands; scope
    /// the profile to these Macs in Jamf while the right is under test.
    public let allowedSerials: Set<String>
    /// What was verified / why it is ineligible — shown in authoring UIs.
    public let notes: String
    /// A verification question still open for this right, if any.
    public let openQuestion: String?
    /// Condition the AUTHOR must confirm about the app (e.g. "does not use
    /// SMJobBless") — eligibility holds only when it is true.
    public let authorMustConfirm: String?

    public init(
        match: Match,
        state: AuthURIIdentityEligibility,
        verifiedMacOSMajors: ClosedRange<Int>?,
        allowedSerials: Set<String> = [],
        notes: String,
        openQuestion: String? = nil,
        authorMustConfirm: String? = nil
    ) {
        self.match = match
        self.state = state
        self.verifiedMacOSMajors = verifiedMacOSMajors
        self.allowedSerials = allowedSerials
        self.notes = notes
        self.openQuestion = openQuestion
        self.authorMustConfirm = authorMustConfirm
    }
}

/// The result of asking the scope guard about one right.
public struct AuthURIIdentityScopeDecision: Sendable, Equatable {
    public let right: String
    public let state: AuthURIIdentityEligibility
    public let entry: AuthURIIdentityScopeEntry?
    /// Nil for a verified or provisional right; otherwise the specific reason
    /// the right is NOT verified for identity scoping — a WARNING surfaced
    /// verbatim in Commander, the simulator and the daemon's integrity log.
    /// Nothing refuses the rule on its account.
    public let rejectionReason: String?

    /// True when the right is verified or under test (no warning).
    public var isPermitted: Bool { rejectionReason == nil }
    /// Badge text for provisional rights; nil otherwise.
    public var badge: String? { state == .provisional ? AuthURIIdentityEligibility.provisional.label : nil }
}

/// The four-state verification table for identity-scoped rights.
///
/// **This table is code, not admin-editable policy.** Each entry records the
/// macOS versions it was verified on; ``AuthURIIdentityScopeRegistry/current``
/// is versioned with the product. It is ADVISORY: Commander's authoring UI
/// and the Decision Simulator show its verdict as warnings, the Sentinel
/// badges provisional rules, and the daemon logs it — but a rule that exists
/// is enforced regardless of the state here.
public struct AuthURIIdentityScopeRegistry: Sendable {
    public let entries: [AuthURIIdentityScopeEntry]

    public init(entries: [AuthURIIdentityScopeEntry]) {
        self.entries = entries
    }

    /// The shipping table. Seeded from empirical testing (2026-09):
    ///
    /// - `com.apple.ServiceManagement.daemons.modify` — VERIFIED, macOS 26–27.
    ///   A pure `SMAppService` app (Postman) resolves this right's client
    ///   identity directly against the app itself, no `smd` mediation (Sentinel
    ///   capture: `clientPath` = the app bundle). On macOS 27 both request
    ///   shapes were verified end to end: an `SMJobBless`-style app (Composer)
    ///   is resolved through `/usr/libexec/smd`, where the client is `smd` and
    ///   the creator is the app, so the mechanism matches the creator first.
    /// - `com.apple.ServiceManagement.blesshelper` — VERIFIED, macOS 27 only.
    ///   Composer was allowed both directly and through `smd`, and a non-pinned
    ///   caller fell through to the preserved native branch and was refused
    ///   for a standard user. That run also answered whether an app needing
    ///   BOTH `blesshelper` and `daemons.modify` is resolved through `smd` on
    ///   the `daemons.modify` leg under the composed rule: it is, by creator.
    /// - `system.install.software` / `com.apple.system.install.software` and
    ///   installer-mediated rights generally (`system.install.`) — INELIGIBLE.
    ///   The caller is always `Installer.app` / the mediator, never the target
    ///   package, so identity scoping cannot distinguish payloads.
    ///
    /// Verified majors are the macOS versions the live tests ran on (26 and
    /// 27 for `daemons.modify`, 27 for `blesshelper`). Bump a range only after
    /// re-verifying on a newer
    /// major; ``osVersionWarning(for:fleetMajor:)`` warns when a fleet runs
    /// ahead of it.
    public static let current = AuthURIIdentityScopeRegistry(entries: [
        AuthURIIdentityScopeEntry(
            match: .exact("com.apple.ServiceManagement.daemons.modify"),
            state: .verifiedEligible,
            verifiedMacOSMajors: 26...27,
            notes: "Verified on macOS 26 and 27. The macOS 26 end rests on the capture of a pure-SMAppService app (Postman) resolving directly; the end-to-end run was on macOS 27 (2026-09-02), for BOTH request shapes: a pure-SMAppService app resolves directly (client == creator), and an SMJobBless-style app (Composer) is resolved through /usr/libexec/smd — where the client is smd but the CREATOR is the app, which is why the mechanism matches on the creator first. Non-pinned callers fall through to the native branch (is-root / is-admin-nonshared), so root, MDM and admins keep native behaviour."
        ),
        AuthURIIdentityScopeEntry(
            match: .exact("com.apple.ServiceManagement.blesshelper"),
            state: .verifiedEligible,
            verifiedMacOSMajors: 27...27,
            notes: "Verified end to end on macOS 27 (2026-09-02): Composer allowed both directly and through smd; a non-pinned caller (/usr/bin/security) was denied by the mechanism and fell through to the preserved native branch, which is a bare class=user group=admin rule — a standard user authenticated there and was correctly refused."
        ),
        AuthURIIdentityScopeEntry(
            match: .exact("com.apple.system.install.software"),
            state: .confirmedIneligible,
            verifiedMacOSMajors: nil,
            notes: "Installer-mediated: the caller is always Installer.app / the mediator, never the target package, so identity scoping cannot distinguish payloads."
        ),
        AuthURIIdentityScopeEntry(
            match: .exact("system.install.software"),
            state: .confirmedIneligible,
            verifiedMacOSMajors: nil,
            notes: "Installer-mediated: the caller is always Installer.app / the mediator, never the target package, so identity scoping cannot distinguish payloads."
        ),
        AuthURIIdentityScopeEntry(
            match: .prefix("system.install."),
            state: .confirmedIneligible,
            verifiedMacOSMajors: nil,
            notes: "Installer-mediated rights generally: the caller is the installer/mediator, not the payload."
        ),
        AuthURIIdentityScopeEntry(
            match: .prefix("com.apple.pkgkit."),
            state: .confirmedIneligible,
            verifiedMacOSMajors: nil,
            notes: "Package-kit rights are exercised by the installer mediator, not the payload."
        ),
    ])

    /// The rights identity scoping may target, by exact name (verified +
    /// provisional). These are IDENTITY-ONLY rights in Commander: the plain
    /// "Authorization right" browser hides them and a plain allow rule on one
    /// is refused, because rewriting such a right for every caller is exactly
    /// what per-app scoping exists to avoid.
    public var identityOnlyRights: [String] {
        entries.compactMap { entry in
            guard entry.state.permitsAuthoring, case let .exact(name) = entry.match else { return nil }
            return name
        }.sorted()
    }

    /// Whether `right` must be authored as an App Identity definition.
    public func isIdentityOnly(_ right: String) -> Bool {
        identityOnlyRights.contains(right)
    }

    /// The first entry matching `right`: exact matches win over prefix matches.
    public func entry(for right: String) -> AuthURIIdentityScopeEntry? {
        if let exact = entries.first(where: {
            if case .exact = $0.match { return $0.match.matches(right) } else { return false }
        }) { return exact }
        return entries.first { $0.match.matches(right) }
    }

    public func state(for right: String) -> AuthURIIdentityEligibility {
        entry(for: right)?.state ?? .unknown
    }

    /// The advisory verdict for `right`: verified and provisional carry no
    /// warning text (provisional is badged instead); ineligible and unknown
    /// carry the specific reason as a WARNING. Nothing is refused.
    public func authoringDecision(for right: String) -> AuthURIIdentityScopeDecision {
        let entry = entry(for: right)
        let state = entry?.state ?? .unknown
        switch state {
        case .verifiedEligible, .provisional:
            return AuthURIIdentityScopeDecision(right: right, state: state, entry: entry, rejectionReason: nil)
        case .confirmedIneligible:
            return AuthURIIdentityScopeDecision(
                right: right, state: state, entry: entry,
                rejectionReason: "'\(right)' is confirmed ineligible for identity scoping: \(entry?.notes ?? "the caller cannot be distinguished by code signature"). The rule is enforced as authored, but the app branch is not expected to match.")
        case .unknown:
            return AuthURIIdentityScopeDecision(
                right: right, state: state, entry: entry,
                rejectionReason: "'\(right)' has not been verified for identity scoping. The rule is enforced as authored; verify with a Sentinel capture before relying on it.")
        }
    }

    /// A loud warning when `fleetMajor` (a Mac's macOS major version) is newer
    /// than anything `right`'s entry was verified on; nil when in range, when
    /// the entry has no verified range, or when the right is not in the table.
    public func osVersionWarning(for right: String, fleetMajor: Int) -> String? {
        guard let entry = entry(for: right), let range = entry.verifiedMacOSMajors else { return nil }
        guard fleetMajor > range.upperBound else { return nil }
        return "macOS \(fleetMajor) is newer than any version '\(right)' identity scoping was verified on (macOS \(range.lowerBound)–\(range.upperBound)). Apple can rewire how this right resolves its caller across majors — re-verify before trusting it."
    }
}

// MARK: - macOS version parsing

public enum MacOSVersion {
    /// The major version at the head of a version string ("27.0", "26.6.2",
    /// "Version 26.6.2 (Build 25G83)"). Nil when no leading integer is found.
    public static func major(from text: String) -> Int? {
        let scanner = Scanner(string: text)
        scanner.charactersToBeSkipped = CharacterSet.decimalDigits.inverted
        var value = 0
        guard scanner.scanInt(&value), value > 0 else { return nil }
        return value
    }

    /// This Mac's macOS major version.
    public static var currentMajor: Int {
        ProcessInfo.processInfo.operatingSystemVersion.majorVersion
    }
}
