import Foundation

// MARK: - Value types (daemon-supplied inputs)

/// The **verified** current console user, resolved by the daemon from
/// `SCDynamicStoreCopyConsoleUser` + `getpwuid` (`ConsoleUserResolver`).
///
/// This is the single trust anchor of IdP-group enrollment: the resolver's only possible
/// output is this user's ``name``. The membership hint (an IdP-group claim read
/// from a user-writable file) selects **whether** this one verified name is
/// enrolled — it can never substitute a different name. `name`/`homeDir` come
/// from `getpwuid(uid)`, never from a plist or a computed `/Users/<name>` path.
public struct ConsoleUser: Sendable, Equatable {
    /// The console user's numeric uid from `SCDynamicStoreCopyConsoleUser`.
    public let uid: uid_t
    /// `getpwuid(uid)->pw_name`, cross-checked against the SC name string.
    public let name: String
    /// `getpwuid(uid)->pw_dir` — the trust anchor the state path is joined onto.
    public let homeDir: String

    public init(uid: uid_t, name: String, homeDir: String) {
        self.uid = uid
        self.name = name
        self.homeDir = homeDir
    }
}

/// A file-verified IdP-group membership hint for a specific ``ConsoleUser``.
///
/// Constructed by an ``IDPGroupSourceProviding`` **after** the source has
/// already passed its TOCTOU-safe ownership/symlink checks. The
/// ``groups`` array is still *self-asserted* content the owner could write —
/// the checks scope it to the verified console user's own file, they do not
/// make its contents an attestation of real IdP membership.
public struct IDPGroupClaim: Sendable, Equatable {
    /// The raw `idpGroupsKey` array from the state file (names or GUIDs).
    public let groups: [String]
    /// True when the source file was owner-writable (the expected default,
    /// Tier-C advisory mode); false when it was root-owned / not owner-writable
    /// (`requireRootOwnedState`). Advisory only — surfaced for logging.
    public let ownerWritable: Bool

    public init(groups: [String], ownerWritable: Bool) {
        self.groups = groups
        self.ownerWritable = ownerWritable
    }
}

// MARK: - Source protocol + refusal errors

/// Why a source refused to produce a claim. Thrown by an
/// ``IDPGroupSourceProviding`` and mapped by the resolver to the matching
/// ``IDPResolveEvent`` for loud audit logging. Every refusal is fail-safe: the
/// resolver returns no enrolled users.
public enum IDPSourceRefusal: Error, Sendable, Equatable {
    /// The state file failed an ownership/mode check (wrong owner, or
    /// group/other-writable). `mode` is `st_mode & 0o7777`.
    case ownership(uid: uid_t, mode: UInt16)
    /// The path resolved through a symlink (`O_NOFOLLOW` / non-regular file).
    case symlink
    /// `requireRootOwnedState` was set but the file was not root-owned.
    case strictReject
}

/// A pluggable source of a console user's IdP-group membership hint.
///
/// The Jamf Connect state reader (`JamfConnectStateSource`) is the initial
/// conformer; a future PSSO / root-owned source can slot in without touching
/// ``IDPGroupResolver`` or the sudoers generator. Implementations perform the
/// trust-boundary I/O; the resolver stays pure and I/O-free.
///
/// - Returns: `nil` when there is no readable/valid source for this user
///   (stale/missing — fail-safe, no enrollment).
/// - Throws: ``IDPSourceRefusal`` on an ownership/symlink/strict violation.
public protocol IDPGroupSourceProviding: Sendable {
    func readClaim(
        for user: ConsoleUser,
        config: SerberusConfig.SudoEnrollment
    ) throws -> IDPGroupClaim?
}

// MARK: - Outcome + audit events

/// A single, loggable reason the resolver reached its result. Drives the
/// `idp-resolve.*` audit trail an admin monitors. Exactly one is produced per
/// ``IDPGroupResolver/resolve(consoleUser:config:)`` call.
public enum IDPResolveEvent: Sendable, Equatable {
    /// `idpSource == .disabled` — the feature is opt-in/off; resolver no-op.
    case disabled
    /// No verified console user (nil / loginwindow / root / uid < 501 upstream).
    case noConsoleUser
    /// `idpGroups` is empty — nothing to match, so no one is ever enrolled.
    case noConfiguredGroups
    /// The source returned `nil`: the state file is missing, unreadable, or
    /// carries no group array (e.g. Jamf Connect never signed in).
    case staleOrMissingSource
    /// The source refused on an ownership/mode check. `mode` is `st_mode & 0o7777`.
    case refusedOwnership(uid: uid_t, mode: UInt16)
    /// The source refused because the path went through a symlink.
    case refusedSymlink
    /// `requireRootOwnedState` rejected a non-root-owned file.
    case strictReject
    /// A valid claim was read but no configured group matched.
    case noMatch
    /// A configured group matched; `user` is the enrolled console-user name and
    /// `matched` the configured group values (original form) that intersected.
    case granted(user: String, matched: [String])
}

/// The result of one resolve pass. ``resolvedUsers`` is the only value that
/// flows onward into `enrollmentUsers`; it is always either `[]` or exactly
/// `[consoleUser.name]`.
public struct IDPResolveOutcome: Sendable, Equatable {
    /// `[]` or `[consoleUser.name]` — never any other name.
    public let resolvedUsers: [String]
    /// The configured group values (original form) that matched, sorted/deduped.
    public let matchedGroups: [String]
    /// The single audit event describing how this outcome was reached.
    public let event: IDPResolveEvent

    public init(resolvedUsers: [String], matchedGroups: [String], event: IDPResolveEvent) {
        self.resolvedUsers = resolvedUsers
        self.matchedGroups = matchedGroups
        self.event = event
    }
}

// MARK: - Resolver

/// The pure, I/O-free heart of IdP-group enrollment (Entra-group curated-sudo enrollment).
///
/// # Containment invariant
/// The only value ``resolve(consoleUser:config:)`` can put into
/// ``IDPResolveOutcome/resolvedUsers`` is the daemon-supplied
/// ``ConsoleUser/name``. The claim's group content selects **whether** that one
/// verified name is enrolled, never **which** name — a fully attacker-controlled
/// claim can at most add the attacker's *own* current console username to an
/// already-curated, per-command, `pam_serberus`-gated ALLOW set.
///
/// # Fail-safe direction
/// Every off-path (disabled, no configured groups, no console user, missing
/// source, any source refusal, or no match) returns `[]` — the drop-in opens
/// for no one. Enrollment happens on exactly one path: a non-empty intersection
/// of the configured groups with the claim's groups after normalization.
public struct IDPGroupResolver: Sendable {
    private let source: IDPGroupSourceProviding

    public init(source: IDPGroupSourceProviding) {
        self.source = source
    }

    /// Resolve whether the verified console user should be enrolled from an IdP
    /// membership hint. Pure orchestration — no `getpwuid`, `SCDynamicStore`, or
    /// file I/O happens here (that is the daemon's state source, behind the protocol).
    public func resolve(
        consoleUser: ConsoleUser?,
        config: SerberusConfig.SudoEnrollment
    ) -> IDPResolveOutcome {
        // Gate 1: feature opt-in. Off by default.
        guard config.idpSource != .disabled else {
            return .init(resolvedUsers: [], matchedGroups: [], event: .disabled)
        }
        // Gate 2: nothing configured to match -> no one is ever enrolled.
        guard !config.idpGroups.isEmpty else {
            return .init(resolvedUsers: [], matchedGroups: [], event: .noConfiguredGroups)
        }
        // Gate 3: no verified console user -> no possible output name.
        guard let consoleUser else {
            return .init(resolvedUsers: [], matchedGroups: [], event: .noConsoleUser)
        }

        // Read the (already file-verified) claim from the pluggable source.
        let claim: IDPGroupClaim?
        do {
            claim = try source.readClaim(for: consoleUser, config: config)
        } catch let refusal as IDPSourceRefusal {
            return .init(resolvedUsers: [], matchedGroups: [], event: refusal.event)
        } catch {
            // Any other read failure is treated as a missing/stale source —
            // fail-safe, no enrollment.
            return .init(resolvedUsers: [], matchedGroups: [], event: .staleOrMissingSource)
        }
        guard let claim else {
            return .init(resolvedUsers: [], matchedGroups: [], event: .staleOrMissingSource)
        }

        // Normalize the claim side into a fast lookup set.
        var claimNormalized = Set<String>()
        for group in claim.groups {
            let normalized = Self.normalize(group)
            if !normalized.isEmpty { claimNormalized.insert(normalized) }
        }

        // Intersect: keep the configured values (original form) whose normalized
        // form appears in the claim. De-dupe on original value, sorted stable.
        var matched: [String] = []
        var seen = Set<String>()
        for configured in config.idpGroups {
            let normalized = Self.normalize(configured)
            guard !normalized.isEmpty, claimNormalized.contains(normalized) else { continue }
            guard seen.insert(configured).inserted else { continue }
            matched.append(configured)
        }
        matched.sort()

        guard !matched.isEmpty else {
            return .init(resolvedUsers: [], matchedGroups: [], event: .noMatch)
        }

        // The ONE enrollment path: emit only the verified console-user name.
        return .init(
            resolvedUsers: [consoleUser.name],
            matchedGroups: matched,
            event: .granted(user: consoleUser.name, matched: matched)
        )
    }

    /// Normalize an IdP-group token for matching: trim surrounding whitespace,
    /// strip a single surrounding pair of GUID braces (`{…}`), then case-fold.
    /// Entra emits group GUIDs both as `{guid}` and `guid` and names in varying
    /// case; normalization makes the intersection robust to those forms without
    /// altering which name the resolver can output.
    static func normalize(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.count >= 2, value.hasPrefix("{"), value.hasSuffix("}") {
            value = String(value.dropFirst().dropLast())
            value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return value.lowercased()
    }
}

private extension IDPSourceRefusal {
    /// Map a source refusal to its audit event 1:1.
    var event: IDPResolveEvent {
        switch self {
        case let .ownership(uid, mode): return .refusedOwnership(uid: uid, mode: mode)
        case .symlink: return .refusedSymlink
        case .strictReject: return .strictReject
        }
    }
}
