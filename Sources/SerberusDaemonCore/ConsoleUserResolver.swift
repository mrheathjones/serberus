import Foundation
import PrivMgrCore
import SystemConfiguration

// MARK: - Passwd lookup

/// The only fields IdP-group enrollment may ever take from the passwd database: the
/// canonical short name and the home directory for a uid.
///
/// # Trust posture
/// ``ConsoleUser/name`` and ``ConsoleUser/homeDir`` must originate **here** —
/// from `getpwuid(uid)` — and nowhere else. They are never read from a plist,
/// an XPC message, or a computed `/Users/<name>` path. This keeps the resolved
/// enrollment name pinned to the OS account record for the verified uid.
public struct PasswdEntry: Sendable, Equatable {
    /// `getpwuid(uid)->pw_name` — the canonical short name.
    public let name: String
    /// `getpwuid(uid)->pw_dir` — the home directory the state path joins onto.
    public let homeDir: String

    public init(name: String, homeDir: String) {
        self.name = name
        self.homeDir = homeDir
    }
}

// MARK: - Rejection / resolution

/// Why the console user was refused. Every case is fail-safe: the daemon treats
/// a rejection as "no verified console user", so the IdP resolver produces no
/// enrollment (`IDPResolveEvent.noConsoleUser`).
public enum ConsoleUserRejection: Sendable, Equatable {
    /// `SCDynamicStoreCopyConsoleUser` returned nil / an empty name — no one is
    /// at the console (fast-user-switching gap, screen locked to no session).
    case noConsoleUser
    /// The console name is `loginwindow` — the login window owns the session.
    case loginWindow
    /// The console uid is root (0) or below `minimumUID` (a service/system
    /// account, not a real interactive standard user).
    case systemUser(uid: uid_t)
    /// `getpwuid(uid)` returned nothing — no local account record for the uid,
    /// so no trustworthy name / home directory exists.
    case unknownUID(uid: uid_t)
    /// The passwd short name disagreed with the `SCDynamicStore` console name,
    /// or the passwd home directory was not an absolute path. The identity is
    /// inconsistent, so it is refused rather than guessed.
    case nameMismatch(scName: String, pwName: String)
}

/// The pure result of evaluating a `(name, uid)` console pair against the passwd
/// database. Exactly one console user (or one rejection) per evaluation.
public enum ConsoleUserResolution: Sendable, Equatable {
    case resolved(ConsoleUser)
    case rejected(ConsoleUserRejection)
}

// MARK: - Resolver

/// Resolves the **verified** current console user — the single trust anchor of
/// IdP-group (e.g. Entra) curated-sudo enrollment.
///
/// # What it guarantees
/// The daemon calls ``resolve()``; the returned ``ConsoleUser`` (or `nil`) is
/// the *only* possible source of an enrolled username downstream. The name and
/// home directory come exclusively from `getpwuid`, and the name is
/// cross-checked against the `SCDynamicStore` console name. Any inconsistency,
/// or a system/login-window/sub-standard uid, yields `nil` — the fail-safe
/// direction where no one is enrolled.
///
/// The syscall-touching entry point (``resolve()``) is a thin shell over the
/// pure ``evaluate(scName:scUID:minimumUID:passwd:)``, which is fully unit
/// testable by injecting a passwd-lookup closure.
public struct ConsoleUserResolver: Sendable {
    /// Standard interactive accounts start at uid 501 on macOS; anything below
    /// is a system/service account and is never a curated-sudo enrollee.
    public static let defaultMinimumUID: uid_t = 501

    private let minimumUID: uid_t
    private let warn: @Sendable (String) -> Void

    public init(
        minimumUID: uid_t = ConsoleUserResolver.defaultMinimumUID,
        warn: @escaping @Sendable (String) -> Void = ConsoleUserResolver.defaultWarn
    ) {
        self.minimumUID = minimumUID
        self.warn = warn
    }

    /// Default audit sink: the daemon's integrity `os.Logger` stream.
    public static let defaultWarn: @Sendable (String) -> Void = { message in
        DaemonLog.integrity.notice("console-user: \(message, privacy: .public)")
    }

    /// Resolve the verified console user via `SCDynamicStoreCopyConsoleUser` +
    /// `getpwuid`. Returns `nil` (and logs the reason) on every refusal so the
    /// caller's fail-safe path enrolls no one.
    public func resolve() -> ConsoleUser? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        let scName = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) as String?

        switch Self.evaluate(scName: scName, scUID: uid, minimumUID: minimumUID, passwd: Self.livePasswd) {
        case let .resolved(user):
            return user
        case let .rejected(reason):
            warn("no verified console user (\(reason))")
            return nil
        }
    }

    /// Live `getpwuid` lookup. Isolated so ``evaluate(scName:scUID:minimumUID:passwd:)``
    /// stays syscall-free and testable.
    static func livePasswd(_ uid: uid_t) -> PasswdEntry? {
        guard let entry = getpwuid(uid) else { return nil }
        return PasswdEntry(
            name: String(cString: entry.pointee.pw_name),
            homeDir: String(cString: entry.pointee.pw_dir)
        )
    }

    /// The pure trust core: validate a console `(name, uid)` pair and produce a
    /// ``ConsoleUser`` only when every check passes.
    ///
    /// Order (each gate is fail-safe):
    /// 1. non-empty console name, else ``ConsoleUserRejection/noConsoleUser``;
    /// 2. not `loginwindow`;
    /// 3. uid is neither root nor below `minimumUID`;
    /// 4. `passwd(uid)` exists;
    /// 5. passwd short name equals the console name **and** the home directory
    ///    is absolute — otherwise the identity is inconsistent and refused.
    ///
    /// The emitted ``ConsoleUser/name`` and ``ConsoleUser/homeDir`` are taken
    /// only from the passwd entry, never from `scName`.
    static func evaluate(
        scName: String?,
        scUID: uid_t,
        minimumUID: uid_t,
        passwd: (uid_t) -> PasswdEntry?
    ) -> ConsoleUserResolution {
        guard let scName, !scName.isEmpty else {
            return .rejected(.noConsoleUser)
        }
        if scName == "loginwindow" {
            return .rejected(.loginWindow)
        }
        if scUID == 0 || scUID < minimumUID {
            return .rejected(.systemUser(uid: scUID))
        }
        guard let entry = passwd(scUID) else {
            return .rejected(.unknownUID(uid: scUID))
        }
        // The console name and passwd short name must agree; the passwd name is
        // the authoritative output. A mismatch is a refusal, never a guess.
        guard entry.name == scName else {
            return .rejected(.nameMismatch(scName: scName, pwName: entry.name))
        }
        // The home directory is the trust anchor the state-file path is joined
        // onto; it must be an absolute path.
        guard entry.homeDir.hasPrefix("/") else {
            return .rejected(.nameMismatch(scName: scName, pwName: entry.name))
        }
        return .resolved(ConsoleUser(uid: scUID, name: entry.name, homeDir: entry.homeDir))
    }
}
