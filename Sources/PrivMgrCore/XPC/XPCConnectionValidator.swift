import Foundation
import Security

// MARK: - Expected caller descriptions

/// What a connecting XPC peer must prove before any message is processed.
///
/// Every caller must pass ALL checks: team ID, bundle ID, Hardened Runtime,
/// valid designated requirement, valid (non-ad-hoc) code signature, the
/// required private entitlement marker when one is defined, and audit-token
/// resolution (never PID — PID validation is TOCTOU-vulnerable).
public struct ExpectedCaller: Sendable, Equatable {
    /// Bundle ID / signing identifier the peer must present.
    public let bundleID: String
    /// Team ID the peer must be signed by.
    public let teamID: String
    /// Private entitlement marker that must be present and `true`,
    /// or `nil` when none is required (PAM module runs as root and is
    /// validated by team ID + bundle ID only).
    public let requiredEntitlement: String?

    public init(bundleID: String, teamID: String, requiredEntitlement: String?) {
        self.bundleID = bundleID
        self.teamID = teamID
        self.requiredEntitlement = requiredEntitlement
    }

    // There is deliberately NO `pamModule` preset. `pam_serberus.so` runs
    // in-process inside `/usr/bin/sudo`, so the connection's audit token is
    // sudo's; the PAM interface is reachable ONLY through the sudo-host path
    // (`validatePAMHost`: euid 0 + `anchor apple` + sudo identifier/path pin).
    // A team-signed peer presenting the module's identifier
    // (`BundleConfig.pamBundleID`, e.g. a dev test client) is not
    // a daemon principal and falls through to "unknown caller".

    /// The menu bar Sentinel caller.
    ///
    /// The private entitlement is defense-in-depth on top of the bundle ID, Team
    /// ID, Hardened Runtime, and designated-requirement checks. A locally
    /// Apple-Development-signed Sentinel cannot embed a custom entitlement without a
    /// provisioning profile, so a **default-secure** dev escape hatch drops only
    /// this one check when the daemon is started with
    /// `SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT=1` in its environment. Production
    /// leaves it unset, so the entitlement remains required.
    public static let sentinel = ExpectedCaller(
        bundleID: BundleConfig.sentinelBundleID,
        teamID: BundleConfig.teamID,
        requiredEntitlement: ProcessInfo.processInfo.environment["SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT"] == "1"
            ? nil
            : BundleConfig.sentinelEntitlement
    )

    /// The Serberus Intel caller (standard-user diagnostics app).
    ///
    /// **No private entitlement, by design.** The remaining checks already pin
    /// the caller to a binary only this team can produce: signature valid,
    /// non-ad-hoc, Hardened Runtime, Team ID, bundle ID, and the designated
    /// requirement (`identifier` + `anchor apple generic` + leaf OU). Adding a
    /// custom entitlement would buy no security here but would drag Intel
    /// into the Sentinel's signing problem — an Apple-Development-signed app
    /// cannot carry a custom entitlement without a provisioning profile, which
    /// is why the Sentinel needs `SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT`. Intel
    /// ships in the same Apple-Dev-signed test pkg, so it must stay clean.
    ///
    /// The `.intel` interface it maps to is read-only.
    public static let intelApp = ExpectedCaller(
        bundleID: BundleConfig.intelBundleID,
        teamID: BundleConfig.teamID,
        requiredEntitlement: nil
    )

    /// The Finder Sync extension caller — used ONLY by the agent's Finder-bridge
    /// listener, never by the daemon.
    ///
    /// **No private entitlement, by design** — the same reasoning as
    /// ``intelApp``: an Apple-Development-signed *sandboxed* app extension cannot
    /// carry a custom entitlement without a provisioning profile, and the five
    /// identity pins (valid non-ad-hoc signature, Hardened Runtime, Team ID,
    /// bundle ID, and the designated requirement) already restrict the caller to
    /// a binary only this team can produce.
    ///
    /// Deliberately **absent** from ``forBundleID(_:)`` and ``interface`` — those
    /// are the *daemon's* dispatch tables. The extension talks only to the
    /// agent's bridge (which forwards to the daemon as the `.sentinel` peer); if
    /// this bundle ID ever connected to the daemon directly it would fall through
    /// to "unknown caller" and be rejected, which is exactly what we want.
    public static let finderExtension = ExpectedCaller(
        bundleID: BundleConfig.finderExtensionBundleID,
        teamID: BundleConfig.teamID,
        requiredEntitlement: nil
    )

    /// Code-signing designated requirement enforcing identifier, team ID,
    /// Apple-anchored chain, and (via flag checks at validation time)
    /// non-ad-hoc signing.
    public var designatedRequirement: String {
        """
        identifier "\(bundleID)" and anchor apple generic and \
        certificate leaf[subject.OU] = "\(teamID)"
        """
    }

    /// The expected ``XPCInterface`` for this caller, or nil for a caller the
    /// daemon serves no interface to.
    ///
    /// Every known bundle ID is matched explicitly and anything else is nil, so
    /// a caller added to ``forBundleID(_:)`` but forgotten here is refused
    /// rather than handed some interface by default. `.pam` is never produced
    /// here — it is granted only by the listener's sudo-host branch.
    public var interface: XPCInterface? {
        switch bundleID {
        case BundleConfig.sentinelBundleID: return .sentinel
        case BundleConfig.intelBundleID: return .intel
        default: return nil
        }
    }

    /// Matches a connecting peer's signing identifier to a known caller, or
    /// `nil` when it is not one of the expected Serberus components.
    public static func forBundleID(_ bundleID: String?) -> ExpectedCaller? {
        switch bundleID {
        case BundleConfig.sentinelBundleID: return .sentinel
        case BundleConfig.intelBundleID: return .intelApp
        default: return nil
        }
    }
}

// MARK: - Peer identity abstraction

/// Identity evidence extracted from a connecting peer. Production fills this
/// from the connection's audit token via `SecTask`/`SecCode`; tests construct
/// it directly to exercise the decision table.
public struct PeerIdentity: Sendable, Equatable {
    public let bundleID: String?
    public let teamID: String?
    public let signatureValid: Bool
    public let adHocSigned: Bool
    public let hardenedRuntime: Bool
    public let satisfiesDesignatedRequirement: Bool
    /// Entitlement names present with boolean `true` values.
    public let trueEntitlements: Set<String>

    public init(
        bundleID: String?,
        teamID: String?,
        signatureValid: Bool,
        adHocSigned: Bool,
        hardenedRuntime: Bool,
        satisfiesDesignatedRequirement: Bool,
        trueEntitlements: Set<String>
    ) {
        self.bundleID = bundleID
        self.teamID = teamID
        self.signatureValid = signatureValid
        self.adHocSigned = adHocSigned
        self.hardenedRuntime = hardenedRuntime
        self.satisfiesDesignatedRequirement = satisfiesDesignatedRequirement
        self.trueEntitlements = trueEntitlements
    }
}

// MARK: - PAM host identity (sudo)

/// Identity evidence for a PAM-interface *host* process — the setuid-root
/// `sudo` binary that loads `pam_serberus.so` in-process.
///
/// An in-process dylib cannot present its own SecCode identity over XPC: the
/// connection's audit token always belongs to the host executable. So the
/// daemon cannot recognize the PAM module by a Serberus bundle ID (that path
/// yields "unknown caller" for a real `sudo` call). Instead it authenticates
/// the *host* from facts in that same token. Production fills this from the
/// audit token; tests construct it directly to exercise the decision table.
public struct PAMHostIdentity: Sendable, Equatable {
    /// Effective UID from the connection's audit token. The setuid-root PAM
    /// auth phase runs as root, so a genuine host presents `0`. The kernel
    /// stamps this per connection — a non-root process cannot forge it.
    public let euid: uid_t
    public let signatureValid: Bool
    public let adHocSigned: Bool
    /// Satisfies `anchor apple` — a genuine Apple OS binary. NOT `anchor apple
    /// generic`, which any Developer-ID / Apple-Development / ad-hoc binary
    /// satisfies.
    public let isApplePlatformBinary: Bool
    public let signingIdentifier: String?
    public let executablePath: String?

    public init(
        euid: uid_t,
        signatureValid: Bool,
        adHocSigned: Bool,
        isApplePlatformBinary: Bool,
        signingIdentifier: String?,
        executablePath: String?
    ) {
        self.euid = euid
        self.signatureValid = signatureValid
        self.adHocSigned = adHocSigned
        self.isApplePlatformBinary = isApplePlatformBinary
        self.signingIdentifier = signingIdentifier
        self.executablePath = executablePath
    }
}

// MARK: - Validator

/// Validates XPC peers against ``ExpectedCaller`` descriptions.
///
/// The decision logic (`validate(identity:against:)`) is pure and fully
/// unit-tested; audit-token extraction (`identity(forAuditToken:)`) is the
/// only platform-bound part and is exercised in daemon integration tests.
public struct XPCConnectionValidator: Sendable {
    public init() {}

    /// Pure decision: does `identity` satisfy `expected`?
    ///
    /// - Throws: The first failing ``XPCValidationError``. Callers reject
    ///   the connection (`shouldAcceptNewConnection → false`) on any throw.
    public func validate(identity: PeerIdentity, against expected: ExpectedCaller) throws {
        // Without a team of our own there is nothing to pin peers to. An empty
        // expectation must never match a peer whose team is also empty.
        guard !expected.teamID.isEmpty else {
            throw XPCValidationError.expectedTeamIDUnavailable
        }
        guard identity.signatureValid else {
            throw XPCValidationError.signatureInvalid(reason: "code signature missing or invalid")
        }
        guard !identity.adHocSigned else {
            throw XPCValidationError.signatureInvalid(reason: "ad-hoc signatures are rejected")
        }
        guard identity.hardenedRuntime else {
            throw XPCValidationError.hardenedRuntimeDisabled
        }
        guard identity.teamID == expected.teamID else {
            throw XPCValidationError.teamIDMismatch(found: identity.teamID)
        }
        guard identity.bundleID == expected.bundleID else {
            throw XPCValidationError.unknownBundleID(found: identity.bundleID)
        }
        guard identity.satisfiesDesignatedRequirement else {
            throw XPCValidationError.signatureInvalid(reason: "designated requirement not satisfied")
        }
        if let entitlement = expected.requiredEntitlement {
            guard identity.trueEntitlements.contains(entitlement) else {
                throw XPCValidationError.missingEntitlement(name: entitlement)
            }
        }
    }

    /// Pure decision: may this PAM *host* speak on the PAM interface?
    ///
    /// The keystone is `euid == 0` — a kernel-stamped, per-connection,
    /// unforgeable fact a non-root standard user cannot present. `anchor apple`
    /// plus the `sudo` identifier/path pin are layered defense that also
    /// exclude third-party root binaries and other Apple platform hosts
    /// (`su`/`login`/`sshd`). Hardened Runtime, Team ID, and entitlement are
    /// deliberately NOT required: `sudo` is a setuid platform binary that
    /// structurally lacks all three, and requiring any of them is exactly what
    /// rejects the real caller today. The policy engine remains the
    /// authorization gate — accepting the host only lets its request reach rule
    /// evaluation.
    ///
    /// - Throws: the first failing ``XPCValidationError``.
    public func validatePAMHost(_ identity: PAMHostIdentity) throws {
        guard identity.euid == 0 else {
            throw XPCValidationError.pamHostNotRoot(found: identity.euid)
        }
        guard identity.signatureValid else {
            throw XPCValidationError.signatureInvalid(reason: "code signature missing or invalid")
        }
        guard !identity.adHocSigned else {
            throw XPCValidationError.signatureInvalid(reason: "ad-hoc signatures are rejected")
        }
        guard identity.isApplePlatformBinary else {
            throw XPCValidationError.pamHostNotApplePlatform
        }
        guard identity.signingIdentifier == BundleConfig.sudoSigningIdentifier else {
            throw XPCValidationError.pamHostNotSudo(found: identity.signingIdentifier)
        }
        guard identity.executablePath == BundleConfig.sudoExecutablePath else {
            throw XPCValidationError.pamHostNotSudo(found: identity.executablePath)
        }
    }

    /// Reads only the signing identifier of an audit-token peer, so the
    /// listener can pick the right ``ExpectedCaller`` before running the full
    /// identity check against that caller's designated requirement.
    public func bundleID(forAuditToken auditToken: audit_token_t) -> String? {
        guard let task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, auditToken) else {
            return nil
        }
        return SecTaskCopySigningIdentifier(task, nil) as String?
    }

    /// Extracts ``PeerIdentity`` from a connection's audit token.
    ///
    /// Audit-token validation only — PID-based lookups are deliberately not
    /// implemented anywhere in this type.
    public func identity(
        forAuditToken auditToken: audit_token_t,
        expected: ExpectedCaller
    ) throws -> PeerIdentity {
        guard let task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, auditToken) else {
            throw XPCValidationError.auditTokenUnresolvable
        }

        let bundleID = SecTaskCopySigningIdentifier(task, nil) as String?
        let entitlements = Self.trueEntitlements(of: task)

        // Resolve the audit token to a SecCode guest for signature checks.
        var tokenData = auditToken
        let tokenCFData = withUnsafeBytes(of: &tokenData) { Data($0) } as CFData
        let attributes = [kSecGuestAttributeAudit: tokenCFData] as CFDictionary

        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else {
            throw XPCValidationError.auditTokenUnresolvable
        }

        let signatureValid = SecCodeCheckValidity(code, [], nil) == errSecSuccess

        var requirement: SecRequirement?
        var satisfiesDR = false
        if SecRequirementCreateWithString(
            expected.designatedRequirement as CFString, [], &requirement
        ) == errSecSuccess, let requirement {
            satisfiesDR = SecCodeCheckValidity(code, [], requirement) == errSecSuccess
        }

        // Static code info for signing flags (ad-hoc + Hardened Runtime) and the
        // signing Team ID. The Team ID is read from the signature itself
        // (`kSecCodeInfoTeamIdentifier`, the leaf cert's OU), which is present on
        // any team-signed binary. The `com.apple.developer.team-identifier`
        // entitlement is only a fallback: Apple's provisioning flow stamps it,
        // but a locally Apple-Development-signed binary (no provisioning profile)
        // does not carry it, so relying on the entitlement alone would reject
        // every locally signed peer with "Team ID mismatch (found: none)".
        var staticCode: SecStaticCode?
        var flags: UInt32 = 0
        var signatureTeamID: String?
        if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode {
            var info: CFDictionary?
            if SecCodeCopySigningInformation(
                staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info
            ) == errSecSuccess,
                let info = info as? [String: Any] {
                if let rawFlags = info[kSecCodeInfoFlags as String] as? UInt32 {
                    flags = rawFlags
                }
                signatureTeamID = info[kSecCodeInfoTeamIdentifier as String] as? String
            }
        }
        let teamID = signatureTeamID ?? SecTaskCopyTeamIdentifier(task)
        let adHoc = (flags & SecCodeSignatureFlags.adhoc.rawValue) != 0
        let hardened = (flags & SecCodeSignatureFlags.runtime.rawValue) != 0

        return PeerIdentity(
            bundleID: bundleID,
            teamID: teamID,
            signatureValid: signatureValid,
            adHocSigned: adHoc,
            hardenedRuntime: hardened,
            satisfiesDesignatedRequirement: satisfiesDR,
            trueEntitlements: entitlements
        )
    }

    /// Extracts ``PAMHostIdentity`` from a connection's audit token. `euid` is
    /// supplied by the caller (read from the same token via the XPC shim's
    /// `serberus_audit_token_euid`) so this module needs no BSM dependency.
    ///
    /// Audit-token validation only — never PID (PID lookups are TOCTOU-prone).
    public func pamHostIdentity(forAuditToken auditToken: audit_token_t, euid: uid_t) throws -> PAMHostIdentity {
        var tokenData = auditToken
        let tokenCFData = withUnsafeBytes(of: &tokenData) { Data($0) } as CFData
        let attributes = [kSecGuestAttributeAudit: tokenCFData] as CFDictionary

        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else {
            throw XPCValidationError.auditTokenUnresolvable
        }

        let signatureValid = SecCodeCheckValidity(code, [], nil) == errSecSuccess

        // `anchor apple` (NOT `anchor apple generic`) — satisfiable only by
        // Apple's own OS-component signing chain, so no Developer-ID,
        // Apple-Development, self-signed, or ad-hoc binary can pass.
        var appleRequirement: SecRequirement?
        var isApplePlatformBinary = false
        if SecRequirementCreateWithString("anchor apple" as CFString, [], &appleRequirement) == errSecSuccess,
           let appleRequirement {
            isApplePlatformBinary = SecCodeCheckValidity(code, [], appleRequirement) == errSecSuccess
        }

        var adHoc = false
        var signingIdentifier: String?
        var executablePath: String?
        var staticCode: SecStaticCode?
        if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode {
            var info: CFDictionary?
            if SecCodeCopySigningInformation(
                staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info
            ) == errSecSuccess, let info = info as? [String: Any] {
                if let rawFlags = info[kSecCodeInfoFlags as String] as? UInt32 {
                    adHoc = (rawFlags & SecCodeSignatureFlags.adhoc.rawValue) != 0
                }
                signingIdentifier = info[kSecCodeInfoIdentifier as String] as? String
                let mainExec = info[kSecCodeInfoMainExecutable as String]
                executablePath = (mainExec as? URL)?.path
                    ?? (mainExec as? NSURL)?.path
                    ?? (mainExec as? String)
            }
        }

        return PAMHostIdentity(
            euid: euid,
            signatureValid: signatureValid,
            adHocSigned: adHoc,
            isApplePlatformBinary: isApplePlatformBinary,
            signingIdentifier: signingIdentifier,
            executablePath: executablePath
        )
    }

    private static func trueEntitlements(of task: SecTask) -> Set<String> {
        var names: Set<String> = []
        for name in [BundleConfig.sentinelEntitlement] {
            if let value = SecTaskCopyValueForEntitlement(task, name as CFString, nil),
               let boolValue = value as? Bool, boolValue {
                names.insert(name)
            }
        }
        return names
    }
}

private func SecTaskCopyTeamIdentifier(_ task: SecTask) -> String? {
    // Fallback only — the primary Team ID source is the signature's
    // `kSecCodeInfoTeamIdentifier` (the leaf cert OU). This entitlement is
    // stamped by Apple's provisioning flow and cannot be self-asserted in a
    // distributable binary, but it is absent on locally Apple-Development-signed
    // binaries that have no provisioning profile.
    SecTaskCopyValueForEntitlement(task, "com.apple.developer.team-identifier" as CFString, nil) as? String
}
