import Foundation
import Security

/// The identity decision an authorization mechanism makes for one request.
///
/// This is the whole policy brain of `SerberusAuth.bundle`, kept as a pure,
/// injectable type so every branch is unit-tested in `SerberusAuthTests`
/// without a plugin host, a signed fixture app, or a live authdb.
///
/// ## Why the decision is local
///
/// A per-app identity check needs no user interaction and no privileged
/// state: it is a pure function of (right, caller signature, policy). The
/// policy is the same MDM-delivered rules profile the daemon reads, which is
/// root-owned and world-readable under `/Library/Managed Preferences`, so the
/// mechanism reads it directly instead of asking the daemon over XPC. That
/// removes the entire weak-peer XPC surface the prompt design had to defend
/// (the mechanism host is Apple's shared SecurityAgentHelper, which cannot be
/// cryptographically distinguished from any other plugin loaded into it).
public enum SerberusAuthDecision: Equatable, Sendable {
    /// The caller satisfies a pinned app branch for this right. The chain
    /// continues to the native password mechanisms.
    case allow(matched: AppIdentityBranch)
    /// No pinned app matches this caller.
    case deny(reason: String)

    public var isAllow: Bool { if case .allow = self { return true }; return false }
}

/// What the mechanism learned about the caller.
///
/// Only the authorization's CREATOR counts, identified by the audit token in
/// the `creator-audit-token` hint and validated as a RUNNING process (see
/// ``SerberusRuntimeSigningPolicy``).
///
/// That hint is NOT authd-trusted. authd merges the caller's
/// authorization environment into the hints after setting `client-pid`,
/// `creator-pid`, `creator-audit-token` and the other client hints, so the
/// caller can override every one of them and borrow a running pinned app's
/// identity. This is why per-app rules are disabled
/// (``AuthURIIdentityScope/perAppPinsEnabled``). The immediate
/// client (`client-pid`) is deliberately not part of the decision: a PID can
/// be recycled between the hint and the lookup, and on an `SMJobBless`-style
/// call the client is Apple's `/usr/libexec/smd` anyway — the creator is the
/// real app in both the direct and the mediated shape.
public struct SerberusAuthCaller: Equatable, Sendable {
    /// The right being authorized (`authorize-right`).
    public let right: String
    /// Code-signing identifier of the verified creator process, or nil when
    /// the creator could not be verified (which never matches).
    public let creatorIdentifier: String?
    /// Team ID of the verified creator process.
    public let creatorTeamID: String?

    public init(right: String, creatorIdentifier: String?, creatorTeamID: String?) {
        self.right = right
        self.creatorIdentifier = creatorIdentifier
        self.creatorTeamID = creatorTeamID
    }
}

/// What a RUNNING creator process must look like before its identity is
/// trusted for an identity-scoped branch. Pure, so every rule is unit-tested;
/// `SerberusAuth.bundle` feeds it the values it reads from
/// `SecCodeCopySigningInformation` on the live `SecCode`.
public enum SerberusRuntimeSigningPolicy {
    /// `kSecCodeSignatureRuntime` — the hardened runtime.
    public static let hardenedRuntimeFlag: UInt32 = 0x0001_0000
    /// `CS_VALID` in the dynamic status word.
    public static let dynamicValidFlag: UInt32 = 0x0000_0001

    /// Entitlements that let another process inject code into, or take over,
    /// the caller — any of them means the verified identity can be borrowed.
    /// `disable-executable-page-protection` switches off code-signing
    /// enforcement of the process's pages and `allow-unsigned-executable-memory`
    /// lets it run code that was never signed, so either lets a same-user
    /// attacker rewrite the running code behind a valid identity.
    public static let forbiddenEntitlements: [String] = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.allow-unsigned-executable-memory",
    ]

    /// The code requirement the running creator must satisfy: its own
    /// identifier, an Apple-anchored chain, and a leaf issued to its team (or
    /// Apple's Mac App Store signing, whose leaf carries the store marker
    /// 1.2.840.113635.100.6.1.9 instead of the developer's team). `nil` when
    /// the identifier or team is malformed — both are interpolated into the
    /// requirement string, so a quote or space must never reach it.
    public static func requirement(identifier: String, teamID: String) -> String? {
        guard CodeRequirementCompiler.isValidTeamID(teamID),
              CodeRequirementCompiler.isValidBundleID(identifier) else { return nil }
        return """
        identifier "\(identifier)" and anchor apple generic and \
        (certificate leaf[subject.OU] = "\(teamID)" or \
        certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */)
        """
    }

    /// Why a running process's signing state disqualifies it, or nil when it
    /// is acceptable. Anything missing is a rejection (fail closed).
    ///
    /// - Parameters:
    ///   - codeSigningFlags: `kSecCodeInfoFlags` (the signature's flags).
    ///   - dynamicStatus: `kSecCodeInfoStatus` (the live status word), when
    ///     reported.
    ///   - entitlements: `kSecCodeInfoEntitlementsDict`, when present.
    public static func rejectionReason(codeSigningFlags: UInt32?,
                                       dynamicStatus: UInt32?,
                                       entitlements: [String: Any]?) -> String? {
        guard let codeSigningFlags else { return "code-signing flags unavailable" }
        guard codeSigningFlags & hardenedRuntimeFlag != 0 else {
            return "not signed with the hardened runtime"
        }
        if let dynamicStatus, dynamicStatus & dynamicValidFlag == 0 {
            return "running code is no longer valid"
        }
        for key in forbiddenEntitlements {
            guard let value = entitlements?[key] else { continue }
            // Only an explicit `false` is harmless; `true` or any other type
            // is treated as granting the capability.
            if (value as? Bool) != false || CFGetTypeID(value as CFTypeRef) != CFBooleanGetTypeID() {
                return "carries the entitlement \(key)"
            }
        }
        return nil
    }
}

/// Matches a caller against the identity-scoped rules in the delivered policy.
public struct SerberusAuthPolicy: Sendable {
    /// Every identity-scoped branch, keyed by the right it applies to.
    private let branchesByRight: [String: [AppIdentityBranch]]
    /// ``AuthURIIdentityScope/perAppPinsEnabled`` in production (false in
    /// 0.9.0): every request is then denied. Tests inject `true` to
    /// exercise the matching logic kept for a later release.
    private let perAppPinsEnabled: Bool

    public init(profiles: [RuleProfile],
                perAppPinsEnabled: Bool = AuthURIIdentityScope.perAppPinsEnabled) {
        self.perAppPinsEnabled = perAppPinsEnabled
        var branches: [String: [AppIdentityBranch]] = [:]
        for profile in profiles {
            for rule in profile.rules where rule.type == .authuri {
                // Only an ALLOW pin opens a branch. A deny (or any other rule
                // the runtime gate refuses) never becomes an allow for the app,
                // even if a reader that skipped the gate handed it over.
                guard rule.action == .allow, rule.runtimeRejectionReason == nil,
                      let branch = rule.appIdentity, let right = rule.match.authURI else { continue }
                if !(branches[right] ?? []).contains(branch) {
                    branches[right, default: []].append(branch)
                }
            }
        }
        branchesByRight = branches
    }

    /// Reads the live MDM-delivered policy. Same reader, same parsing, and
    /// the same multi-domain scan the daemon uses, so the mechanism can never
    /// disagree with the daemon about what the policy says. The reader takes
    /// only the root-owned computer-level plist: the mechanism runs inside
    /// SecurityAgentHelper in the console user's context, where a user-scoped
    /// profile would otherwise be visible and could inject an app branch.
    public static func live(reader: ManagedPreferencesReader = ManagedPreferencesReader()) -> SerberusAuthPolicy {
        SerberusAuthPolicy(profiles: reader.readRuleProfiles().value)
    }

    public func branches(forRight right: String) -> [AppIdentityBranch] {
        branchesByRight[right] ?? []
    }

    /// The decision for one caller.
    ///
    /// Fails CLOSED in every ambiguous case: an unknown right, a right with
    /// no pinned apps, a caller whose signature could not be resolved, and a
    /// caller that matches nothing all deny. A deny here does not necessarily
    /// deny the request — when the right is composed as `k-of-n`, authd falls
    /// through to the preserved native branch — but nothing in this type ever
    /// widens access on uncertainty.
    ///
    /// While per-app pins are disabled (the creator identity comes from
    /// a hint the caller can forge), EVERY request is denied, so a composed
    /// right left behind by any path falls through to its native-default
    /// branch.
    public func decide(_ caller: SerberusAuthCaller) -> SerberusAuthDecision {
        guard perAppPinsEnabled else {
            return .deny(reason: AuthURIIdentityScope.disabledMechanismReason)
        }
        let branches = branches(forRight: caller.right)
        guard !branches.isEmpty else {
            return .deny(reason: "no identity-scoped rule targets '\(caller.right)'")
        }
        guard let identifier = caller.creatorIdentifier, let teamID = caller.creatorTeamID else {
            return .deny(reason: "caller identity unresolvable (creator unverified: unsigned, ad-hoc, no team, not hardened, or injectable)")
        }
        if let branch = branches.first(where: { $0.bundleID == identifier && $0.teamID == teamID }) {
            return .allow(matched: branch)
        }
        return .deny(reason: "caller [\(identifier) (\(teamID))] matches no pinned app on '\(caller.right)'")
    }
}

// MARK: - Bundle writability

/// Whether the requesting user could have altered the pinned app's code on
/// disk. A code signature proves who SIGNED the bundle, not who can change
/// what is loaded next: an app the requester can write (one they own — the
/// owner can always `chmod` — or that is group-writable by a group they are
/// in, world-writable, or opened up by an ACL entry) can have its helpers,
/// frameworks or resources swapped, and anything reached through a writable
/// parent directory can be renamed away and replaced. Such an app never
/// matches a pin; the caller falls through to the right's native branch.
///
/// When the code is a helper or XPC service inside an app, the walk starts at
/// the OUTERMOST enclosing `.app`, so the frameworks and resources beside the
/// helper are covered too.
///
/// Pure except for the injected filesystem and membership lookups, so it is
/// unit-tested on temp trees; `SerberusAuth.bundle` runs it on the running
/// creator's bundle path with the creator's audit-token uid.
public enum SerberusBundleWritabilityPolicy {
    /// Upper bound on the entries walked (bundle tree + parents). Large
    /// enough for the largest apps a fleet pins (Xcode is about 170,000
    /// entries); a bundle larger than this is refused rather than
    /// half-checked.
    public static let defaultMaxEntries = 400_000

    /// What one `lstat` (or one bulk directory read) returned.
    public struct FileInfo: Sendable, Equatable {
        public let uid: uid_t
        public let gid: gid_t
        public let mode: mode_t
        /// The entry carries an extended ACL, which ``aclGrant(path:requester:isMember:)``
        /// must examine.
        public let hasACL: Bool

        public init(uid: uid_t, gid: gid_t, mode: mode_t, hasACL: Bool = false) {
            self.uid = uid
            self.gid = gid
            self.mode = mode
            self.hasACL = hasACL
        }

        public var isDirectory: Bool { (mode & S_IFMT) == S_IFDIR }
        public var isSymlink: Bool { (mode & S_IFMT) == S_IFLNK }
    }

    /// One entry of a directory listing, with its metadata.
    public struct DirectoryEntry: Sendable, Equatable {
        public let name: String
        public let info: FileInfo

        public init(name: String, info: FileInfo) {
            self.name = name
            self.info = info
        }
    }

    /// What an entry's ACL grants the requester.
    public enum ACLGrant: Sendable, Equatable {
        /// No ACL, or no entry that lets the requester write.
        case none
        /// An entry lets the requester write (the reason says which).
        case write(String)
        /// The ACL could not be read or an entry could not be resolved.
        case unreadable(String)
    }

    public enum Verdict: Sendable, Equatable {
        /// Nothing in the bundle or above it is writable by the requester.
        case notWritable
        /// `path` is writable by the requester (the reason says how).
        case writable(path: String, reason: String)
        /// The walk could not be completed (unreadable entry or ACL, over the
        /// cap, a symlink leaving the bundle). Refused: fail closed.
        case unverifiable(String)

        public var refusalReason: String? {
            switch self {
            case .notWritable: return nil
            case let .writable(path, reason): return "\(path) is writable by the requesting user (\(reason))"
            case let .unverifiable(reason): return "bundle writability could not be verified: \(reason)"
            }
        }

        /// A log line an administrator can act on: what was found, what it
        /// means for the rule, and how to fix it.
        public func adminMessage(bundle: String, requester: uid_t) -> String? {
            switch self {
            case .notWritable:
                return nil
            case let .writable(path, reason):
                return "Identity-scoped rule not applied for \(bundle): \(path) can be modified by uid \(requester) (\(reason)), "
                    + "so that user could change the app's code. The request falls back to the right's normal authentication. "
                    + "Fix: install the app so it and every folder above it are owned by root and not writable by this user "
                    + "(for example deploy it with MDM or the App Store instead of dragging it in)."
            case let .unverifiable(reason):
                return "Identity-scoped rule not applied for \(bundle): Serberus could not confirm uid \(requester) cannot modify it (\(reason)). "
                    + "The request falls back to the right's normal authentication. "
                    + "Fix: install it on the startup disk, and check the app's ownership, permissions and ACLs (ls -leO@) "
                    + "and that its symlinks stay inside the bundle."
            }
        }
    }

    /// Whether a single entry's owner and mode let `requester` write it.
    public static func writableReason(_ info: FileInfo, requester: uid_t, isMember: (gid_t) -> Bool) -> String? {
        if info.uid == requester { return "owned by uid \(requester)" }
        if info.mode & S_IWOTH != 0 { return "other-writable" }
        if info.mode & S_IWGRP != 0, isMember(info.gid) { return "group-writable by gid \(info.gid), which the requester is in" }
        return nil
    }

    /// Bundle extensions the walk widens to (compared case-insensitively):
    /// code in any of them loads the rest of the bundle it sits in.
    public static let bundleExtensions: Set<String> = ["app", "xpc", "bundle", "framework", "appex"]

    /// The outermost bundle (``bundleExtensions``) enclosing `path` — the
    /// app around a helper, XPC service or nested app, or a framework or
    /// bundle not inside any app — or `path` itself when none encloses it.
    public static func outermostBundle(of path: String) -> String {
        let components = (path as NSString).pathComponents
        guard let index = components.firstIndex(where: {
            $0 != "/" && bundleExtensions.contains(($0 as NSString).pathExtension.lowercased())
        }) else { return path }
        return NSString.path(withComponents: Array(components[...index]))
    }

    /// The mount a path lives on, as `statfs(2)` reports it.
    public struct VolumeInfo: Sendable, Equatable {
        /// `f_flags` (`MNT_*`).
        public let flags: UInt32
        /// `f_owner`: the uid that mounted it.
        public let owner: uid_t
        public let mountPoint: String

        public init(flags: UInt32, owner: uid_t, mountPoint: String) {
            self.flags = flags
            self.owner = owner
            self.mountPoint = mountPoint
        }
    }

    /// Why ownership and mode on `volume` do not say who can write, or nil
    /// when they do: ownership ignored (`noowners`, the default for a disk
    /// image a user attaches), a volume that is not local (the server decides
    /// who writes), or one a non-root user mounted (and can swap for another
    /// image at the same path).
    public static func volumeRefusal(_ volume: VolumeInfo) -> String? {
        if volume.flags & UInt32(MNT_IGNORE_OWNERSHIP) != 0 {
            return "it is on \(volume.mountPoint), which ignores file ownership"
        }
        if volume.flags & UInt32(MNT_LOCAL) == 0 {
            return "it is on \(volume.mountPoint), which is not a local volume"
        }
        if volume.owner != 0 {
            return "it is on \(volume.mountPoint), which uid \(volume.owner) mounted"
        }
        return nil
    }

    /// `statfs(2)` of `path`, or nil when it fails.
    public static func volumeInfo(_ path: String) -> VolumeInfo? {
        var info = statfs()
        guard statfs(path, &info) == 0 else { return nil }
        let mountPoint = withUnsafeBytes(of: info.f_mntonname) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        return VolumeInfo(flags: info.f_flags, owner: info.f_owner, mountPoint: mountPoint)
    }

    /// Walks the bundle (every regular file, directory and symlink inside,
    /// never following a symlink, owner, mode and ACL of each) and each
    /// parent directory up to `/`. The bundle must sit on a local volume
    /// that honours ownership and that root mounted (see
    /// ``volumeRefusal(_:)``); elsewhere owner and mode prove nothing.
    ///
    /// - Parameters:
    ///   - bundlePath: the code's path — a bundle directory or a bare
    ///     executable. Resolved with `realpath` first, so the parents walked
    ///     are the ones the kernel actually traverses, then widened to the
    ///     outermost enclosing bundle (see ``outermostBundle(of:)``).
    ///   - requester: the uid whose write access matters.
    ///   - isMember: whether `requester` is in a group. Should answer `true`
    ///     when membership cannot be determined (fail closed).
    ///   - lstatInfo / listEntries / aclGrant / readLink / resolvePath /
    ///     volumeInfo: filesystem seams. `listEntries` returns a directory's entries with
    ///     their metadata (one bulk read per directory instead of one `lstat`
    ///     per entry).
    public static func evaluate(
        bundlePath: String,
        requester: uid_t,
        isMember: (gid_t) -> Bool,
        maxEntries: Int = defaultMaxEntries,
        lstatInfo: (String) -> FileInfo? = SerberusBundleWritabilityPolicy.lstatInfo,
        listEntries: (String) -> [DirectoryEntry]? = SerberusBundleWritabilityPolicy.bulkEntries,
        aclGrant: (String, uid_t, (gid_t) -> Bool) -> ACLGrant = SerberusBundleWritabilityPolicy.aclGrant,
        readLink: (String) -> String? = SerberusBundleWritabilityPolicy.readLink,
        resolvePath: (String) -> String? = SerberusBundleWritabilityPolicy.realPath,
        volumeInfo: (String) -> VolumeInfo? = SerberusBundleWritabilityPolicy.volumeInfo
    ) -> Verdict {
        guard let resolved = resolvePath(bundlePath), resolved.hasPrefix("/") else {
            return .unverifiable("cannot resolve \(bundlePath)")
        }
        let root = outermostBundle(of: resolved)
        var visited = 0

        guard let volume = volumeInfo(root) else { return .unverifiable("cannot read the volume of \(root)") }
        if let reason = volumeRefusal(volume) {
            return .unverifiable("\(root): \(reason), so its owner and mode do not say who can write it")
        }

        func check(_ path: String, _ info: FileInfo, alwaysCheckACL: Bool) -> Verdict? {
            if let reason = writableReason(info, requester: requester, isMember: isMember) {
                return .writable(path: path, reason: reason)
            }
            guard info.hasACL || alwaysCheckACL else { return nil }
            let grant = withoutActuallyEscaping(isMember) { member in aclGrant(path, requester, member) }
            switch grant {
            case .none: return nil
            case let .write(reason): return .writable(path: path, reason: reason)
            case let .unreadable(reason): return .unverifiable("ACL of \(path): \(reason)")
            }
        }

        // Parents first (cheap, and the likeliest to be writable). A plain
        // lstat cannot say whether an ACL is present, so each parent's ACL is
        // read directly.
        var parent = (root as NSString).deletingLastPathComponent
        while true {
            visited += 1
            guard let info = lstatInfo(parent) else { return .unverifiable("cannot stat \(parent)") }
            if let verdict = check(parent, info, alwaysCheckACL: true) { return verdict }
            if parent == "/" || parent.isEmpty { break }
            parent = (parent as NSString).deletingLastPathComponent
        }

        visited += 1
        guard let rootInfo = lstatInfo(root) else { return .unverifiable("cannot stat \(root)") }
        if let verdict = check(root, rootInfo, alwaysCheckACL: true) { return verdict }
        guard rootInfo.isDirectory else { return .notWritable }   // a bare executable

        // The bundle itself, depth-first, never following symlinks.
        var stack = [root]
        while let directory = stack.popLast() {
            guard let entries = listEntries(directory) else { return .unverifiable("cannot list \(directory)") }
            visited += entries.count
            if visited > maxEntries {
                return .unverifiable("the bundle has more than \(maxEntries) entries")
            }
            for entry in entries {
                // Most entries are plain files that pass on owner and mode
                // alone; their path is never built.
                let info = entry.info
                guard info.isSymlink || info.isDirectory || info.hasACL
                        || writableReason(info, requester: requester, isMember: isMember) != nil else { continue }
                let path = directory + "/" + entry.name
                if let verdict = check(path, info, alwaysCheckACL: false) { return verdict }
                if info.isSymlink {
                    // A link's own mode is irrelevant, but its TARGET is what
                    // gets loaded: it must stay inside the bundle (walked).
                    // A relative target with no `..` stays below the link's
                    // own directory (any link it passes through is itself an
                    // entry of the bundle and checked here), so only other
                    // targets need a full `realpath`.
                    if let target = readLink(path), staysBelowLink(target) { continue }
                    guard let target = resolvePath(path), target == root || target.hasPrefix(root + "/") else {
                        return .unverifiable("symlink \(path) resolves outside the bundle")
                    }
                } else if info.isDirectory {
                    stack.append(path)
                }
            }
        }
        return .notWritable
    }

    /// Whether a symlink target is relative and never climbs (`..`).
    static func staysBelowLink(_ target: String) -> Bool {
        !target.isEmpty && !target.hasPrefix("/") && !target.split(separator: "/").contains("..")
    }

    /// `readlink(2)`: the link's stored target, or nil.
    public static func readLink(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let count = readlink(path, &buffer, Int(PATH_MAX))
        guard count > 0 else { return nil }
        return String(decoding: buffer[..<count].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    // MARK: ACLs

    /// ACL permissions that let a principal change what the bundle loads:
    /// write or append to a file, add, remove or replace entries in a
    /// directory, delete the entry, or change its ACL or owner.
    static let writePermissions: [(acl_perm_t, String)] = [
        (ACL_WRITE_DATA, "write/add_file"),
        (ACL_APPEND_DATA, "append/add_subdirectory"),
        (ACL_DELETE, "delete"),
        (ACL_DELETE_CHILD, "delete_child"),
        (ACL_WRITE_SECURITY, "writesecurity"),
        (ACL_CHANGE_OWNER, "chown"),
    ]

    /// Reads `path`'s extended ACL (without following a symlink) and reports
    /// whether an allow entry grants `requester` — directly, or through a
    /// group it is in, including `everyone` — any of ``writePermissions``.
    /// Deny entries are not credited (fail closed). An ACL that cannot be read,
    /// or an entry whose principal cannot be resolved, is `.unreadable`.
    public static func aclGrant(path: String, requester: uid_t, isMember: (gid_t) -> Bool) -> ACLGrant {
        errno = 0
        guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT ? .none : .unreadable("acl_get_link_np failed (errno \(errno))")
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        var which = ACL_FIRST_ENTRY.rawValue
        while acl_get_entry(acl, which, &entry) == 0, let current = entry {
            which = ACL_NEXT_ENTRY.rawValue
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(current, &tag) == 0 else { return .unreadable("unreadable ACL entry") }
            guard tag == ACL_EXTENDED_ALLOW else { continue }
            var permset: acl_permset_t?
            guard acl_get_permset(current, &permset) == 0, let permset else { return .unreadable("unreadable ACL permissions") }
            let granted = writePermissions.filter { acl_get_perm_np(permset, $0.0) == 1 }.map(\.1)
            guard !granted.isEmpty else { continue }
            guard let qualifier = acl_get_qualifier(current) else { return .unreadable("unreadable ACL principal") }
            let principal = principalID(qualifier)
            acl_free(qualifier)
            switch principal {
            case let (id, isGroup)?:
                if isGroup ? isMember(gid_t(id)) : uid_t(id) == requester {
                    let who = isGroup ? "group \(id), which the requester is in" : "uid \(id)"
                    return .write("ACL allows \(granted.joined(separator: ", ")) to \(who)")
                }
            case nil:
                return .unreadable("an ACL entry names a principal that cannot be resolved")
            }
        }
        return .none
    }

    /// The uid or gid an ACL qualifier (a 16-byte UUID) names, via
    /// `mbr_uuid_to_id` (bound with `dlsym` for the same reason as
    /// ``systemMembership(uid:)``). Nil when it cannot be resolved.
    static func principalID(_ qualifier: UnsafeMutableRawPointer) -> (id: UInt32, isGroup: Bool)? {
        typealias UUIDToID = @convention(c) (UnsafePointer<UInt8>, UnsafeMutablePointer<id_t>, UnsafeMutablePointer<Int32>) -> Int32
        let handle = UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT
        guard let symbol = dlsym(handle, "mbr_uuid_to_id") else { return nil }
        let uuidToID = unsafeBitCast(symbol, to: UUIDToID.self)
        var id: id_t = 0
        var type: Int32 = -1
        let status = uuidToID(qualifier.assumingMemoryBound(to: UInt8.self), &id, &type)
        guard status == 0 else { return nil }
        switch type {
        case 0: return (id, false)   // ID_TYPE_UID
        case 1: return (id, true)    // ID_TYPE_GID
        default: return nil
        }
    }

    // MARK: Bulk directory reads

    /// Every entry of `directory` with its owner, group, mode and whether it
    /// carries an ACL, read with `getattrlistbulk(2)` (one call returns many
    /// entries; no per-entry `lstat`). Symlinks are described, never
    /// followed. Nil when the directory cannot be opened or an entry reports
    /// an error.
    public static func bulkEntries(_ directory: String) -> [DirectoryEntry]? {
        let fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var request = attrlist()
        request.bitmapcount = u_short(BulkAttribute.bitmapCount)
        request.commonattr = BulkAttribute.returnedAttrs | BulkAttribute.error | BulkAttribute.name
            | BulkAttribute.objectType | BulkAttribute.ownerID | BulkAttribute.groupID
            | BulkAttribute.accessMask | BulkAttribute.extendedSecurity
        let capacity = 128 * 1024
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: capacity, alignment: 8)
        defer { buffer.deallocate() }
        var entries: [DirectoryEntry] = []
        while true {
            let count = getattrlistbulk(fd, &request, buffer, capacity, 0)
            if count < 0 { return nil }
            if count == 0 { break }
            var record = buffer
            for _ in 0..<count {
                let length = Int(record.load(as: UInt32.self))
                guard let entry = parseBulkRecord(record) else { return nil }
                entries.append(entry)
                record += length
            }
        }
        return entries
    }

    /// The `ATTR_CMN_*` bits of `<sys/attr.h>` the walk requests (spelled
    /// out: the header's values do not all import as one integer type).
    private enum BulkAttribute {
        static let bitmapCount = 5
        static let name: attrgroup_t = 0x0000_0001
        static let objectType: attrgroup_t = 0x0000_0008
        static let ownerID: attrgroup_t = 0x0000_8000
        static let groupID: attrgroup_t = 0x0001_0000
        static let accessMask: attrgroup_t = 0x0002_0000
        static let extendedSecurity: attrgroup_t = 0x0040_0000
        static let error: attrgroup_t = 0x2000_0000
        static let returnedAttrs: attrgroup_t = 0x8000_0000
    }

    /// Decodes one `getattrlistbulk` record: the length, the returned-attrs
    /// set, then each returned attribute in bit order (the error first).
    private static func parseBulkRecord(_ record: UnsafeMutableRawPointer) -> DirectoryEntry? {
        var field = record + MemoryLayout<UInt32>.size
        let returned = field.loadUnaligned(as: attribute_set_t.self)
        field += MemoryLayout<attribute_set_t>.size
        let common = returned.commonattr
        func has(_ attribute: attrgroup_t) -> Bool { common & attribute != 0 }

        if has(BulkAttribute.error) {
            guard field.loadUnaligned(as: UInt32.self) == 0 else { return nil }
            field += MemoryLayout<UInt32>.size
        }
        guard has(BulkAttribute.name) else { return nil }
        let nameReference = field.loadUnaligned(as: attrreference_t.self)
        let name = String(cString: (field + Int(nameReference.attr_dataoffset)).assumingMemoryBound(to: CChar.self))
        field += MemoryLayout<attrreference_t>.size
        guard has(BulkAttribute.objectType) else { return nil }
        let objectType = field.loadUnaligned(as: UInt32.self)
        field += MemoryLayout<UInt32>.size
        guard has(BulkAttribute.ownerID) else { return nil }
        let uid = field.loadUnaligned(as: uid_t.self)
        field += MemoryLayout<uid_t>.size
        guard has(BulkAttribute.groupID) else { return nil }
        let gid = field.loadUnaligned(as: gid_t.self)
        field += MemoryLayout<gid_t>.size
        guard has(BulkAttribute.accessMask) else { return nil }
        let access = field.loadUnaligned(as: UInt32.self)
        field += MemoryLayout<UInt32>.size
        var hasACL = false
        if has(BulkAttribute.extendedSecurity) {
            hasACL = field.loadUnaligned(as: attrreference_t.self).attr_length > 0
        }
        let typeBits: mode_t
        switch objectType {
        case 1: typeBits = S_IFREG   // VREG
        case 2: typeBits = S_IFDIR   // VDIR
        case 5: typeBits = S_IFLNK   // VLNK
        case 3: typeBits = S_IFBLK
        case 4: typeBits = S_IFCHR
        case 6: typeBits = S_IFSOCK
        case 7: typeBits = S_IFIFO
        default: return nil
        }
        let mode = typeBits | mode_t(access & 0o7777)
        return DirectoryEntry(name: name, info: FileInfo(uid: uid, gid: gid, mode: mode, hasACL: hasACL))
    }

    /// Directory Services group membership for `uid` (nested groups
    /// included), via `mbr_check_membership` — the same answer the kernel's
    /// permission check gets. `<membership.h>` is not in Swift's Darwin
    /// module, so the three C functions are bound with `dlsym`. Any lookup
    /// failure answers `true` (member), which refuses the pin: fail closed.
    public static func systemMembership(uid: uid_t) -> (gid_t) -> Bool {
        typealias UIDToUUID = @convention(c) (uid_t, UnsafeMutablePointer<UInt8>) -> Int32
        typealias GIDToUUID = @convention(c) (gid_t, UnsafeMutablePointer<UInt8>) -> Int32
        typealias CheckMembership = @convention(c) (UnsafePointer<UInt8>, UnsafePointer<UInt8>,
                                                    UnsafeMutablePointer<Int32>) -> Int32
        let handle = UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT
        guard let uidSymbol = dlsym(handle, "mbr_uid_to_uuid"),
              let gidSymbol = dlsym(handle, "mbr_gid_to_uuid"),
              let checkSymbol = dlsym(handle, "mbr_check_membership") else {
            return { _ in true }
        }
        let uidToUUID = unsafeBitCast(uidSymbol, to: UIDToUUID.self)
        let gidToUUID = unsafeBitCast(gidSymbol, to: GIDToUUID.self)
        let check = unsafeBitCast(checkSymbol, to: CheckMembership.self)
        var userUUID = [UInt8](repeating: 0, count: 16)
        guard uidToUUID(uid, &userUUID) == 0 else { return { _ in true } }
        var cache: [gid_t: Bool] = [:]
        return { gid in
            if let known = cache[gid] { return known }
            var groupUUID = [UInt8](repeating: 0, count: 16)
            var isMember: Int32 = 0
            let answer = gidToUUID(gid, &groupUUID) != 0 || check(userUUID, groupUUID, &isMember) != 0
                ? true
                : isMember != 0
            cache[gid] = answer
            return answer
        }
    }

    /// `lstat(2)`: never follows a symlink. Does not report ACLs; the walk
    /// reads the ACL of every entry it stats this way.
    public static func lstatInfo(_ path: String) -> FileInfo? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        return FileInfo(uid: info.st_uid, gid: info.st_gid, mode: info.st_mode)
    }

    /// `realpath(3)`, or nil when the path does not resolve.
    public static func realPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}
