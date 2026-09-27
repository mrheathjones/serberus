import Darwin
import Foundation

/// Deletes sudo's cached-credential tickets under `/var/db/sudo/ts`.
///
/// sudo 1.9.15 and later name a ticket after the invoking user's numeric uid
/// (`/var/db/sudo/ts/501`; see `sudoers_timestamp(5)`), and earlier releases
/// after the user name. Both files are deleted, so either sudo is covered.
///
/// A ticket lets sudo skip authentication — and with it `pam_serberus` — for
/// the rest of its lifetime. So a ticket obtained while a user was an admin
/// outside Serberus's gate (a JIT window) or while the daemon was not gating at
/// all must not outlive that state:
/// - when a Serberus JIT grant ends (demotion, expiry, kill-switch demote-all,
///   the teardown sweep) or an observed Jamf Connect elevation ends, that
///   user's ticket is deleted (``clearTicket(uid:user:)``);
/// - when the daemon moves into enforce from any other state, every ticket is
///   deleted (``clearAllTickets()``).
public protocol SudoTicketClearing: Sendable {
    /// Deletes the ticket of the account with `uid` (the file sudo 1.9.15+
    /// uses) and, when `user` is given, the one named after `user` (older
    /// sudo). Returns whether a file was removed.
    @discardableResult func clearTicket(uid: uid_t, user: String?) -> Bool
    /// Deletes the tickets of the account named `user`: the name file, and the
    /// uid file when `user` resolves to an account whose name is exactly
    /// `user`. Prefer ``clearTicket(uid:user:)`` when the uid is known — it
    /// also covers an account renamed or deleted since.
    @discardableResult func clearTicket(user: String) -> Bool
    /// Deletes every ticket in the directory. Returns the number removed.
    @discardableResult func clearAllTickets() -> Int
}

public extension SudoTicketClearing {
    /// ``clearTicket(uid:user:)`` for the uid file alone.
    @discardableResult func clearTicket(uid: uid_t) -> Bool {
        clearTicket(uid: uid, user: nil)
    }
}

/// Production ``SudoTicketClearing`` over sudo's timestamp directory. The
/// directory and the name-to-uid lookup are injectable so tests never touch
/// the real ones.
///
/// A name is used only when it is safe as a single path component under the
/// directory — the rule `pam_serberus` applies (`serberus_timestamp_user_is_safe`):
/// not empty, not `.` or `..`, and no `/`. Only the entry itself is unlinked
/// (never followed), and sub-directories are left alone.
public struct SudoTimestampDirectory: SudoTicketClearing {
    /// sudo 1.9's `timestampdir` on macOS (matches `SERBERUS_SUDO_TIMESTAMP_DIR`).
    public static let defaultPath = "/var/db/sudo/ts"

    public let path: String
    private let uidForName: @Sendable (String) -> uid_t?

    /// - Parameter uidForName: the uid of the account named EXACTLY the given
    ///   name, or nil. Production: `getpwnam_r`, requiring the returned
    ///   `pw_name` to equal the name byte for byte (the rule `pam_serberus`
    ///   applies to `PAM_RUSER`).
    public init(
        path: String = SudoTimestampDirectory.defaultPath,
        uidForName: @escaping @Sendable (String) -> uid_t? = SudoTimestampDirectory.exactUID
    ) {
        self.path = path
        self.uidForName = uidForName
    }

    /// The same rule as `serberus_timestamp_user_is_safe` in `pam_decisions.h`.
    public static func isSafeName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\0")
    }

    /// The ticket file name sudo 1.9.15+ uses for `uid`: its decimal value.
    public static func ticketName(uid: uid_t) -> String { String(uid) }

    /// The uid of the account whose canonical name is exactly `name`, or nil.
    public static func exactUID(_ name: String) -> uid_t? {
        guard !name.isEmpty, !name.contains("\0") else { return nil }
        var pwd = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var size = 4096
        while size <= 1 << 20 {
            var buffer = [CChar](repeating: 0, count: size)
            let status = getpwnam_r(name, &pwd, &buffer, size, &result)
            if status == ERANGE { size *= 4; continue }
            guard status == 0, result != nil, let canonical = pwd.pw_name else { return nil }
            return LocalAccounts.namesMatchExactly(String(cString: canonical), name) ? pwd.pw_uid : nil
        }
        return nil
    }

    @discardableResult
    public func clearTicket(uid: uid_t, user: String?) -> Bool {
        var removed = unlinkEntry(named: Self.ticketName(uid: uid))
        if let user, Self.isSafeName(user) {
            removed = unlinkEntry(named: user) || removed
        }
        return removed
    }

    @discardableResult
    public func clearTicket(user: String) -> Bool {
        guard Self.isSafeName(user) else { return false }
        if let uid = uidForName(user) {
            return clearTicket(uid: uid, user: user)
        }
        return unlinkEntry(named: user)
    }

    @discardableResult
    public func clearAllTickets() -> Int {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: path) else { return 0 }
        return names.filter(Self.isSafeName).reduce(0) { $0 + (unlinkEntry(named: $1) ? 1 : 0) }
    }

    /// Unlinks `path/name` relative to an open descriptor of the directory, so a
    /// directory swapped for a symlink mid-way cannot redirect the removal.
    private func unlinkEntry(named name: String) -> Bool {
        let dirFD = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else { return false }
        defer { close(dirFD) }
        var info = stat()
        guard fstatat(dirFD, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
        guard (info.st_mode & S_IFMT) != S_IFDIR else { return false }
        return unlinkat(dirFD, name, 0) == 0
    }
}

/// Clears nothing. The default for components constructed in unit tests.
public struct NoopSudoTicketClearer: SudoTicketClearing {
    public init() {}
    public func clearTicket(uid: uid_t, user: String?) -> Bool { false }
    public func clearTicket(user: String) -> Bool { false }
    public func clearAllTickets() -> Int { 0 }
}
