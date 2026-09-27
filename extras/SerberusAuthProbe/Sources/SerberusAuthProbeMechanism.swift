import Foundation
import Security
import os

// All decision/logging logic for the SerberusAuthProbe spike (chunk 2 of
// docs/authuri-prompt-plugin-design.md). The Objective-C shim
// (SerberusAuthProbeShim.m) owns every direct call into the Authorization
// Plugin C ABI (GetHintValue/SetResult/DidDeactivate); these functions only
// receive plain C values and decide/log — they never touch
// AuthorizationEngineRef/AuthorizationCallbacks directly.
//
// Exposed to the .m file via @_cdecl, NOT the Xcode-generated
// <Target>-Swift.h header: on this toolchain (Swift 6.3.3 /
// swiftlang-6.3.3.1.3), `-parse-as-library` — which Xcode always passes for
// a non-`main.swift` library-shaped target, i.e. every target in this repo,
// including a `type: bundle` product — makes the generated header come back
// completely empty (no @interface at all) despite the class compiling and
// linking correctly; confirmed with a minimal repro before writing this.
// @_cdecl sidesteps that: it's a much narrower, longstanding FFI mechanism
// (unaffected by -parse-as-library) that exports a plain C symbol per
// function, hand-declared as `extern` in the .m file — same "thin ObjC shim,
// real logic in Swift" split docs/authuri-prompt-plugin-design.md calls for, just without the
// generated-header step this toolchain currently breaks.
//
// mechanismId selects the verdict this instance tests (wired to a right's
// `mechanisms` array as `SerberusAuthProbe:allow` / `:deny` / `:undefined` —
// see extras/SerberusAuthProbe/authprobe-spike.sh): this answers Open
// Questions 3 and 4 (does SetResult(deny) behave sanely on a prefs right,
// what does kAuthorizationResultUndefined actually do) without any daemon.

// Deliberately OUTSIDE the com.herojoneslabs.serberus.* hierarchy (a sibling,
// not a child): Serberus Intel's log-capture predicate is
// `subsystem == "com.herojoneslabs.serberus" OR subsystem BEGINSWITH
// "com.herojoneslabs.serberus."` (Sources/SerberusIntelCore/LogQuery.swift),
// deliberately built to sweep up every child subsystem so real diagnostics
// captures don't miss a component. This spike's throwaway logs must NOT be
// swept into that real production diagnostics/Jamf-upload path.
private let log = Logger(subsystem: "com.herojoneslabs.spike.authprobe", category: "mechanism")

private func cString(_ s: UnsafePointer<CChar>?) -> String? {
    s.map { String(cString: $0) }
}

/// Called once from `AuthorizationPluginCreate`. This log line is the
/// "load-success signal" the bundle-load question in
/// docs/authuri-prompt-plugin-design.md needs — if it never appears on the
/// test Mac, the bundle didn't load into SecurityAgentHelper at all.
@_cdecl("serberus_probe_plugin_did_load")
func serberusProbePluginDidLoad() {
    log.notice("AuthorizationPluginCreate: SerberusAuthProbe loaded (pid=\(getpid()), uid=\(getuid()), euid=\(geteuid()))")
}

@_cdecl("serberus_probe_plugin_did_destroy")
func serberusProbePluginDidDestroy() {
    log.notice("PluginDestroy: SerberusAuthProbe unloading")
}

@_cdecl("serberus_probe_mechanism_created")
func serberusProbeMechanismCreated(_ mechanismId: UnsafePointer<CChar>?) {
    log.notice("MechanismCreate: mechanismId=\(cString(mechanismId) ?? "<null>", privacy: .public)")
}

@_cdecl("serberus_probe_mechanism_destroyed")
func serberusProbeMechanismDestroyed(_ mechanismId: UnsafePointer<CChar>?) {
    log.notice("MechanismDestroy: mechanismId=\(cString(mechanismId) ?? "<null>", privacy: .public)")
}

@_cdecl("serberus_probe_mechanism_will_deactivate")
func serberusProbeMechanismWillDeactivate(_ mechanismId: UnsafePointer<CChar>?) {
    log.notice("MechanismDeactivate: mechanismId=\(cString(mechanismId) ?? "<null>", privacy: .public) — no UI, calling DidDeactivate immediately")
}

/// Logs every hint the engine handed us (answers the hint-availability
/// question in docs/authuri-prompt-plugin-design.md), RESOLVES
/// THE CALLER'S CODE-SIGNING IDENTITY from both the `client-pid` hint and the
/// `creator-audit-token` hint, and returns the verdict this mechanismId is
/// wired to test: 0=allow, 1=deny, 2=undefined.
///
/// The identity resolution is the point of the extended probe. Serberus's
/// per-app authURI feature needs a mechanism to answer "which app is behind
/// this request?", and the live captures show the two hints can disagree: on
/// an `SMJobBless`-style call the CLIENT is `/usr/libexec/smd` while the
/// authorization's CREATOR is the real app. If the creator token resolves to
/// the app's own signature here, per-app scoping is implementable; if it
/// resolves to smd (or to nothing), it is not.
///
/// Sentinel `-1` on `clientUID`/`clientPID`/`creatorAuditTokenLength` means
/// the shim could not read that hint at all (also worth knowing — Open
/// Question 5 is "does this hint arrive," not just "what's its value").
///
/// An unrecognized mechanismId fails closed to `undefined` and logs a fault —
/// mirrors the real plugin's "missing authorize-right -> deny and log,
/// degrade closed, never guess" posture from
/// docs/authuri-prompt-plugin-design.md.
@_cdecl("serberus_probe_decide")
func serberusProbeDecide(
    _ mechanismId: UnsafePointer<CChar>?,
    _ right: UnsafePointer<CChar>?,
    _ clientUID: Int32,
    _ clientPID: Int32,
    _ clientPath: UnsafePointer<CChar>?,
    _ creatorAuditToken: UnsafeRawPointer?,
    _ creatorAuditTokenLength: Int32
) -> Int32 {
    let mechanismIdString = cString(mechanismId) ?? "<null>"
    log.notice("""
    MechanismInvoke[\(mechanismIdString, privacy: .public)]: \
    authorize-right=\(cString(right) ?? "<missing>", privacy: .public) \
    client-uid=\(clientUID >= 0 ? String(clientUID) : "<missing>", privacy: .public) \
    client-pid=\(clientPID >= 0 ? String(clientPID) : "<missing>", privacy: .public) \
    client-path=\(cString(clientPath) ?? "<missing>", privacy: .public) \
    creator-audit-token=\(creatorAuditTokenLength >= 0 ? "\(creatorAuditTokenLength) bytes" : "<missing>", privacy: .public)
    """)

    // IDENTITY: the client pid's signature, and the creator token's signature.
    if clientPID >= 0 {
        log.notice("  client-pid identity: \(describeIdentity(ofPID: clientPID), privacy: .public)")
    }
    if let creatorAuditToken, creatorAuditTokenLength == Int32(MemoryLayout<audit_token_t>.size) {
        var token = audit_token_t()
        withUnsafeMutableBytes(of: &token) { destination in
            destination.copyMemory(from: UnsafeRawBufferPointer(start: creatorAuditToken,
                                                                count: MemoryLayout<audit_token_t>.size))
        }
        // The audit token's 6th word is the pid (stable layout; what
        // audit_token_to_pid() reads).
        let creatorPID = Int32(bitPattern: token.val.5)
        log.notice("  creator pid (from audit token): \(creatorPID, privacy: .public)")
        log.notice("  creator identity (by audit token): \(describeIdentity(ofAuditToken: token), privacy: .public)")
        log.notice("  creator identity (by pid): \(describeIdentity(ofPID: creatorPID), privacy: .public)")
    } else if creatorAuditTokenLength >= 0 {
        log.error("  creator-audit-token is \(creatorAuditTokenLength, privacy: .public) bytes, expected \(MemoryLayout<audit_token_t>.size, privacy: .public) — cannot resolve creator identity")
    }

    let verdict: Int32
    switch mechanismIdString {
    case "allow": verdict = 0
    case "deny": verdict = 1
    case "undefined": verdict = 2
    // The identity probe: log who the caller is, then ALLOW so the chain
    // continues to the native password mechanisms. Safe to attach to a real
    // right — it never blocks anything that would otherwise succeed.
    case "identity": verdict = 0
    default:
        log.fault("MechanismInvoke: unrecognized mechanismId '\(mechanismIdString, privacy: .public)' — failing closed to undefined")
        verdict = 2
    }
    log.notice("MechanismInvoke[\(mechanismIdString, privacy: .public)]: returning verdict \(verdict, privacy: .public) (0=allow 1=deny 2=undefined)")
    return verdict
}

// MARK: - Identity resolution

/// `identifier=… team=… signed=…` for a running process, or why it could not
/// be resolved. Never throws and never blocks — a probe must not wedge the
/// authorization it is inspecting.
private func describeIdentity(ofPID pid: Int32) -> String {
    let attributes = [kSecGuestAttributePid as String: pid] as CFDictionary
    return describeIdentity(attributes: attributes, label: "pid \(pid)")
}

private func describeIdentity(ofAuditToken token: audit_token_t) -> String {
    var token = token
    let data = withUnsafeBytes(of: &token) { Data($0) }
    let attributes = [kSecGuestAttributeAudit as String: data] as CFDictionary
    return describeIdentity(attributes: attributes, label: "audit token")
}

private func describeIdentity(attributes: CFDictionary, label: String) -> String {
    var code: SecCode?
    let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
    guard status == errSecSuccess, let code else {
        return "<unresolvable via \(label): SecCodeCopyGuestWithAttributes status \(status)>"
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
        return "<no static code via \(label)>"
    }
    var info: CFDictionary?
    SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
    let dict = info as? [String: Any] ?? [:]
    let identifier = dict[kSecCodeInfoIdentifier as String] as? String ?? "<none>"
    let team = dict[kSecCodeInfoTeamIdentifier as String] as? String ?? "<none>"
    let valid = SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess
    return "identifier=\(identifier) team=\(team) signatureValid=\(valid)"
}
