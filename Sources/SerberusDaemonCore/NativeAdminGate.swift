import Foundation
import PrivMgrCore

/// Decides whether a sudo request comes from a JIT admin inside their window,
/// who gets sudo exactly as native macOS gives it (the `native` PAM reply)
/// instead of Serberus's rules.
///
/// Both must hold, checked at the moment of the request:
/// 1. an elevation SOURCE of the live JIT provider: an active Serberus JIT
///    grant for this user and uid (provider `serberus`), or an open Jamf
///    Connect elevation window the daemon observed in the log (provider
///    `jamf_connect`);
/// 2. the user is in the local `admin` group RIGHT NOW (a live directory
///    check, never a cached answer).
///
/// The Jamf Connect window is a hint read from the unified log and can be
/// forged by anyone able to write there as Jamf; it only ever counts together
/// with (2), which it cannot forge. A user who is already an admin gains
/// nothing from native: macOS would let them sudo anyway.
public enum NativeAdminGate {
    /// Why a request qualifies.
    public enum Source: Sendable, Equatable {
        case serberusJIT(grantID: UUID)
        case jamfConnect(JamfConnectElevationWindow)

        /// Rule ID recorded on the decision-log event.
        public var ruleID: String {
            switch self {
            case .serberusJIT: return "jit-native"
            case .jamfConnect: return "jit-native-jamf-connect"
            }
        }

        var grantID: UUID? {
            if case let .serberusJIT(grantID) = self { return grantID }
            return nil
        }
    }

    /// Step 1: the elevation source for `user` / `uid` under the live JIT
    /// `provider`, if any. A Serberus JIT grant counts only while the provider
    /// is `serberus`, and a Jamf Connect window only while it is
    /// `jamf_connect`: once the policy moves off `serberus`, an open Serberus
    /// window stops answering `native` at once, before the reload tick's sweep
    /// demotes it. `activeGrants` must already be filtered to grants active
    /// now; `jamfConnectWindow` is the observer's open window for `user` (nil
    /// when the observer is not running).
    public static func source(
        user: String,
        uid: uid_t,
        provider: JITAdminProvider,
        activeGrants: [Grant],
        jamfConnectWindow: JamfConnectElevationWindow?
    ) -> Source? {
        if provider == .serberus, let grant = activeGrants.first(where: {
            JITAdmin.isJITGrant($0) && $0.revokedAt == nil && $0.uid == uid
                && LocalAccounts.namesMatchExactly($0.user, user)
        }) {
            return .serberusJIT(grantID: grant.grantID)
        }
        if provider == .jamfConnect, let window = jamfConnectWindow,
           LocalAccounts.namesMatchExactly(window.user, user) {
            return .jamfConnect(window)
        }
        return nil
    }

    /// Step 2 on top of step 1: the source, only when `membership` answers a
    /// definite "member of admin". Unknown membership is not native.
    public static func evaluate(
        user: String,
        uid: uid_t,
        provider: JITAdminProvider,
        activeGrants: [Grant],
        jamfConnectWindow: JamfConnectElevationWindow?,
        membership: GroupMembershipControlling
    ) async -> Source? {
        guard let source = source(user: user, uid: uid, provider: provider, activeGrants: activeGrants,
                                  jamfConnectWindow: jamfConnectWindow) else { return nil }
        guard (try? await membership.isMember(user: user, group: JITAdmin.adminGroup)) == true else { return nil }
        return source
    }
}
