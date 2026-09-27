import Foundation
import PrivMgrCore
import Security
import os

// The Swift half of SerberusAuth.bundle — the production authorization
// mechanism behind identity-scoped authURI rules.
//
// Split exactly as docs/authuri-prompt-plugin-design.md
// prescribes: the ObjC shim
// (SerberusAuthShim.m) owns every call into the Authorization Plugin C ABI
// (GetHintValue / SetResult / DidDeactivate); this file only receives plain C
// values, decides, and logs. Reached via @_cdecl rather than the generated
// -Swift.h header (that header comes back empty under -parse-as-library on
// this toolchain).
//
// Contract this file must never break: EVERY path returns a verdict, and an
// unresolvable one is DENY. A mechanism that returns nothing hangs the
// caller's AuthorizationCopyRights forever; nothing in the OS rescues it.

private let log = Logger(subsystem: BundleConfig.logSubsystem + ".authplugin", category: "mechanism")

/// Verdict codes shared with the shim (which maps them to the
/// `AuthorizationResult` constants). Deliberately plain ints — the C ABI
/// boundary carries no Swift types.
private enum Verdict: Int32 {
    case allow = 0
    case deny = 1
}

private func cString(_ pointer: UnsafePointer<CChar>?) -> String? {
    pointer.map { String(cString: $0) }
}

@_cdecl("serberus_auth_plugin_did_load")
func serberusAuthPluginDidLoad() {
    log.notice("AuthorizationPluginCreate: SerberusAuth loaded (pid=\(getpid()), uid=\(getuid()), euid=\(geteuid()))")
}

@_cdecl("serberus_auth_plugin_did_destroy")
func serberusAuthPluginDidDestroy() {
    log.notice("PluginDestroy: SerberusAuth unloading")
}

@_cdecl("serberus_auth_mechanism_will_deactivate")
func serberusAuthMechanismWillDeactivate() {
    // No UI in this mechanism, so the shim acks DidDeactivate immediately.
    log.debug("MechanismDeactivate: no UI, acking immediately")
}

/// The decision entry point. Returns a ``Verdict`` raw value; the shim maps it
/// onto `kAuthorizationResultAllow` / `kAuthorizationResultDeny`.
///
/// - Parameters unchanged from the hints as authd delivered them. These are
///   NOT authd-trusted values: the caller's environment overrides
///   `client-pid` and `creator-audit-token`, which is why per-app rules
///   are disabled. A `-1` length or a nil pointer means the hint was absent,
///   which is treated as a caller we cannot identify, which denies.
@_cdecl("serberus_auth_decide")
func serberusAuthDecide(
    _ right: UnsafePointer<CChar>?,
    _ clientPID: Int32,
    _ creatorAuditToken: UnsafeRawPointer?,
    _ creatorAuditTokenLength: Int32
) -> Int32 {
    guard let rightName = cString(right), !rightName.isEmpty else {
        // SPI drift or a malformed evaluation: we cannot know what is being
        // authorized, so we cannot vouch for it.
        log.fault("MechanismInvoke: 'authorize-right' hint missing — denying (degrade closed, never guess)")
        return Verdict.deny.rawValue
    }

    // Per-app pins are disabled in this build. The creator audit token
    // and client pid below come from hints the caller can override through
    // its authorization environment, so they prove nothing; deny before
    // looking at either. authd then falls through to the
    // right's native-default branch. The verification code stays compiled for
    // the release that fixes the identity source (AuthURIIdentityScope in
    // PrivMgrCore holds the switch the daemon and validator use too).
    guard AuthURIIdentityScope.perAppPinsEnabled else {
        log.notice("""
        MechanismInvoke: DENY right=\(rightName, privacy: .public) \
        reason=\(AuthURIIdentityScope.disabledMechanismReason, privacy: .public) \
        claimed-client-pid(log only)=\(clientPID)
        """)
        return Verdict.deny.rawValue
    }

    // The decision rests on the CREATOR's audit token alone, validated as the
    // live process it names (not its on-disk file). The client PID is looked
    // up for the log line only: a PID can be recycled between authd stamping
    // the hint and this lookup, so it must never decide anything.
    let creatorOutcome = SerberusCodeIdentity.verifyRunning(auditToken: creatorAuditToken,
                                                           length: creatorAuditTokenLength)
    let creator = creatorOutcome.identity
    let clientDescription = clientPID > 0 ? SerberusCodeIdentity.describeForLog(pid: clientPID) : "<none>"

    let caller = SerberusAuthCaller(
        right: rightName,
        creatorIdentifier: creator?.identifier, creatorTeamID: creator?.teamID
    )

    // Read policy per invocation rather than caching it: an MDM push must take
    // effect on the next authorization, and these files are small.
    let decision = SerberusAuthPolicy.live().decide(caller)

    switch decision {
    case let .allow(branch):
        log.notice("""
        MechanismInvoke: ALLOW right=\(rightName, privacy: .public) \
        matched=\(branch.bundleID, privacy: .public) (\(branch.teamID, privacy: .public)) \
        creator=\(creatorOutcome.description, privacy: .public) \
        claimed-client(log only)=\(clientDescription, privacy: .public)
        """)
        return Verdict.allow.rawValue
    case let .deny(reason):
        log.notice("""
        MechanismInvoke: DENY right=\(rightName, privacy: .public) reason=\(reason, privacy: .public) \
        creator=\(creatorOutcome.description, privacy: .public) \
        claimed-client(log only)=\(clientDescription, privacy: .public)
        """)
        return Verdict.deny.rawValue
    }
}

// MARK: - Code identity

/// A verified code-signing identity: the signing identifier plus the team.
/// Produced only for a RUNNING process that passes every check in
/// ``SerberusCodeIdentity/verifyRunning(auditToken:length:)``, so an
/// unsigned, ad-hoc, Apple-platform (no team), non-hardened, or injectable
/// caller never matches a pin and falls through to the native branch.
struct SerberusCodeIdentity: CustomStringConvertible {
    let identifier: String
    let teamID: String

    var description: String { "\(identifier) (\(teamID))" }

    /// The result of verifying the creator, with the reason when it failed
    /// (for the log line; the decision only sees ``identity``).
    enum Outcome: CustomStringConvertible {
        case verified(SerberusCodeIdentity)
        case rejected(String)

        var identity: SerberusCodeIdentity? {
            if case let .verified(identity) = self { return identity }
            return nil
        }

        var description: String {
            switch self {
            case let .verified(identity): return identity.description
            case let .rejected(reason): return "<unverified: \(reason)>"
            }
        }
    }

    /// Verifies the RUNNING process behind `auditToken`:
    ///
    /// 1. `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` — the
    ///    audit token names one process instance, so a recycled PID cannot
    ///    stand in for it.
    /// 2. `SecCodeCopySigningInformation` with dynamic + requirement + signing
    ///    information: identifier, team, flags, live status, entitlements.
    /// 3. `SecCodeCheckValidity` of the LIVE code against
    ///    `identifier <id> and anchor apple generic and <team leaf>`: the
    ///    running image is still valid (not a static check of a file that
    ///    may have been swapped), chains to Apple, and was issued to the team.
    /// 4. ``SerberusRuntimeSigningPolicy/rejectionReason(codeSigningFlags:dynamicStatus:entitlements:)``:
    ///    hardened runtime required; `get-task-allow`,
    ///    `allow-dyld-environment-variables`, `disable-library-validation`,
    ///    `disable-executable-page-protection` and
    ///    `allow-unsigned-executable-memory` refused, since each lets another
    ///    process run or rewrite code as this identity.
    /// 5. ``SerberusBundleWritabilityPolicy``: no file or directory of the
    ///    outermost enclosing app, and no parent directory up to `/`, is
    ///    writable by the requesting uid (owned by it, group-writable by one of
    ///    its groups, world-writable, or opened by an ACL entry); bounded at
    ///    ``SerberusBundleWritabilityPolicy/defaultMaxEntries`` entries, over
    ///    the cap refuses.
    ///
    /// Anything that cannot be verified is `.rejected` — no match, fail closed.
    static func verifyRunning(auditToken: UnsafeRawPointer?, length: Int32) -> Outcome {
        guard let auditToken, length == Int32(MemoryLayout<audit_token_t>.size) else {
            return .rejected("creator-audit-token hint missing or malformed")
        }
        var token = audit_token_t()
        withUnsafeMutableBytes(of: &token) { destination in
            destination.copyMemory(from: UnsafeRawBufferPointer(start: auditToken,
                                                                count: MemoryLayout<audit_token_t>.size))
        }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }

        var guest: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let code = guest else {
            return .rejected("no running code for the audit token")
        }

        // A SecCode is accepted wherever a SecStaticCode is, and passing the
        // LIVE code is what makes kSecCSDynamicInformation report its status.
        let asStatic = unsafeBitCast(code, to: SecStaticCode.self)
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation
                                   | kSecCSDynamicInformation)
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(asStatic, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return .rejected("signing information unavailable")
        }
        guard let identifier = dict[kSecCodeInfoIdentifier as String] as? String,
              let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String,
              let requirementText = SerberusRuntimeSigningPolicy.requirement(identifier: identifier, teamID: teamID)
        else {
            return .rejected("no well-formed identifier and team")
        }

        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            return .rejected("requirement did not compile")
        }
        guard SecCodeCheckValidity(code, [], requirement) == errSecSuccess else {
            return .rejected("\(identifier) (\(teamID)): running code fails validity or the Apple-issued team requirement")
        }

        let signatureFlags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value
        let status = (dict[kSecCodeInfoStatus as String] as? NSNumber)?.uint32Value
        let entitlements = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        if let reason = SerberusRuntimeSigningPolicy.rejectionReason(codeSigningFlags: signatureFlags,
                                                                     dynamicStatus: status,
                                                                     entitlements: entitlements) {
            return .rejected("\(identifier) (\(teamID)): \(reason)")
        }

        // 5. The bundle on disk must not be writable by the requesting user
        //    (see SerberusBundleWritabilityPolicy): a signature says who signed
        //    the app, not who can swap what it loads next. The requester is the
        //    creator's effective uid, straight from its audit token (val[1];
        //    read directly so the bundle needs no libbsm link).
        var codePath: CFURL?
        guard SecCodeCopyPath(asStatic, [], &codePath) == errSecSuccess,
              let bundlePath = (codePath as URL?)?.path, !bundlePath.isEmpty else {
            return .rejected("\(identifier) (\(teamID)): code path unavailable")
        }
        let requester = uid_t(token.val.1)
        let verdict = SerberusBundleWritabilityPolicy.evaluate(
            bundlePath: bundlePath, requester: requester,
            isMember: SerberusBundleWritabilityPolicy.systemMembership(uid: requester))
        if let reason = verdict.refusalReason {
            if let message = verdict.adminMessage(bundle: "\(identifier) (\(teamID)) at \(bundlePath)", requester: requester) {
                log.error("\(message, privacy: .public)")
            }
            return .rejected("\(identifier) (\(teamID)): \(reason)")
        }
        return .verified(SerberusCodeIdentity(identifier: identifier, teamID: teamID))
    }

    /// Best-effort `identifier (team)` of a PID, for the log line ONLY. Never
    /// validated and never consulted by the decision.
    static func describeForLog(pid: Int32) -> String {
        var guest: SecCode?
        let attributes = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let code = guest else {
            return "pid \(pid) <unresolved>"
        }
        var info: CFDictionary?
        SecCodeCopySigningInformation(unsafeBitCast(code, to: SecStaticCode.self),
                                      SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = info as? [String: Any] ?? [:]
        let identifier = dict[kSecCodeInfoIdentifier as String] as? String ?? "?"
        let team = dict[kSecCodeInfoTeamIdentifier as String] as? String ?? "no team"
        return "pid \(pid) \(identifier) (\(team))"
    }
}
