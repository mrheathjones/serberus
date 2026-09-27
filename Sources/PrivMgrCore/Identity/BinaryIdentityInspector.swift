import Foundation
import Security

/// Collects validated binary identity at decision time: canonical
/// path, Team ID, signing status, and SHA-256. Injected into the daemon's
/// `PAMEvaluator` so its decision logic is testable without signed fixtures.
///
/// Lives in PrivMgrCore (not SerberusDaemonCore) because the
/// Sentinel's Capture session pins the SAME identity (Team ID / SHA-256) on the
/// binaries it observes, so a captured attempt carries exactly what a
/// Definition's `requiredTeamID` / `requiredBinaryHash` would be checked
/// against. One implementation, both sides.
public protocol BinaryIdentityInspecting: Sendable {
    /// Inspects the binary at `canonicalPath`. Never throws — a missing or
    /// unreadable binary yields an `unsigned`, empty-hash identity, which
    /// fails identity-pinned rules closed.
    func inspect(canonicalPath: String) -> BinaryIdentity
}

/// Production inspector using CryptoKit (hash) and the Security framework
/// (Team ID + signing posture).
public struct BinaryIdentityInspector: BinaryIdentityInspecting {
    public init() {}

    public func inspect(canonicalPath: String) -> BinaryIdentity {
        let url = URL(fileURLWithPath: canonicalPath)
        let hash = (try? SHA256Hasher.hexDigest(fileAt: url)) ?? ""

        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return BinaryIdentity(canonicalPath: canonicalPath, teamID: nil, sha256: hash, signingStatus: .unsigned)
        }

        let validity = SecStaticCodeCheckValidity(staticCode, [], nil)
        var info: CFDictionary?
        SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = info as? [String: Any]

        let teamID = dict?[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = (dict?[kSecCodeInfoFlags as String] as? UInt32) ?? 0
        let adHoc = (flags & SecCodeSignatureFlags.adhoc.rawValue) != 0

        let signing: SigningStatus
        if dict?[kSecCodeInfoIdentifier as String] == nil {
            signing = .unsigned
        } else if adHoc {
            signing = .adhoc
        } else if validity == errSecSuccess {
            signing = .valid
        } else {
            signing = .invalid
        }

        return BinaryIdentity(
            canonicalPath: canonicalPath,
            teamID: (teamID?.isEmpty == false) ? teamID : nil,
            sha256: hash,
            signingStatus: signing
        )
    }
}

/// Fixed-answer inspector for tests.
public struct StaticBinaryIdentityInspector: BinaryIdentityInspecting {
    private let identity: BinaryIdentity
    public init(identity: BinaryIdentity) { self.identity = identity }
    public func inspect(canonicalPath: String) -> BinaryIdentity {
        BinaryIdentity(
            canonicalPath: canonicalPath,
            teamID: identity.teamID,
            sha256: identity.sha256,
            signingStatus: identity.signingStatus
        )
    }
}
