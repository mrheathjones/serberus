import Foundation

/// Where Serberus reads a console user's IdP (e.g. Entra) group membership when
/// resolving curated-sudo enrollment for standard users (IdP-group enrollment).
///
/// # Trust posture
/// This selects a *source of self-asserted membership hints*, never an
/// authorization oracle. The resolver's only output is the daemon-supplied
/// verified console-user name — the source content selects **whether** that one
/// verified name is enrolled, never **which** name. The default is ``disabled``
/// so the whole feature is inert until an admin opts in via MDM, and the parse
/// is fail-closed (an unknown raw value falls back to ``disabled``, mirroring
/// ``JITAdminProvider``).
public enum IDPGroupSource: String, Codable, Sendable, Equatable, CaseIterable {
    /// The default — the IdP-group resolver never runs and no console user is
    /// ever enrolled from an IdP hint. Opt-in off.
    case disabled
    /// Read the console user's Jamf Connect state cache
    /// (`com.jamf.connect.state`, key `UserGroups`) as the membership hint. The
    /// file is user-owned and user-writable, so this is an advisory hint gated
    /// by the full trust-mitigation stack in the resolver and daemon source —
    /// never an attestation of real IdP membership.
    case jamfConnectState = "jamf_connect_state"
}
