import Darwin
import Foundation
import PrivMgrCore

// MARK: - Verdict

/// Whether sudo authentication is actually routed through `pam_serberus`.
///
/// The coarse `/etc/sudoers.d/serberus` drop-in is a GRANT: it lets enrolled
/// standard users reach the curated command paths through sudo at all, with
/// `pam_serberus` + the daemon as the only thing that can still deny (argv
/// patterns, deny rules, prompts). Without the PAM gate the drop-in is plain
/// sudoers — any arguments, no Serberus decision — so the daemon only writes it
/// once this verifies.
public enum PAMGateStatus: Sendable, Equatable {
    case wired
    case notWired(reason: String)

    public var isWired: Bool { self == .wired }
}

/// Verifies the PAM gate. Injectable so ``DaemonController`` is unit-testable
/// without reading the host's `/etc/pam.d`.
public protocol PAMGateVerifying: Sendable {
    func verify() -> PAMGateStatus
}

/// Always reports the gate as wired. The ``DaemonController`` default, so unit
/// tests are independent of the host's PAM configuration; production wires
/// ``FilesystemPAMGateVerifier`` in ``DaemonController/makeProduction()``.
public struct AssumeWiredPAMGate: PAMGateVerifying {
    public init() {}
    public func verify() -> PAMGateStatus { .wired }
}

/// A fixed verdict (tests).
public struct StaticPAMGate: PAMGateVerifying {
    public let status: PAMGateStatus
    public init(_ status: PAMGateStatus) { self.status = status }
    public func verify() -> PAMGateStatus { status }
}

// MARK: - OpenPAM tokenizer

/// Splits PAM policy bytes into lines of words the way the OpenPAM macOS ships
/// (2007 "Hydrangea": `openpam_readline` + the word helpers in
/// `openpam_configure.c`) does, so the gate reads EXACTLY what `pam_start`
/// will:
///
/// - `#` starts a comment ANYWHERE on a line, even inside a word; the comment
///   runs to the end of the physical line (a `\` inside it is swallowed with it).
/// - Every `isspace()` byte (space, `\t`, `\n`, `\v`, `\f`, `\r`) separates
///   words; runs of it collapse.
/// - `\` is special only as the last non-blank byte of a line, where it joins
///   the next line (continuation). Anywhere else it is an ordinary byte.
/// - Quotes are ordinary bytes: `"x"` is a three-byte word.
///
/// Works on bytes, not `Character`s: Swift reads `"\r\n"` as ONE character,
/// which would hide the `\n` that ends a comment.
public enum OpenPAMTokenizer {
    /// C-locale `isspace()`.
    static func isSpace(_ byte: UInt8) -> Bool {
        byte == 0x20 || (0x09...0x0D).contains(byte)
    }

    /// Logical lines as word byte-arrays.
    static func lineWords(_ bytes: [UInt8]) -> [[[UInt8]]] {
        let space = UInt8(ascii: " ")
        let backslash = UInt8(ascii: "\\")
        let newline = UInt8(ascii: "\n")
        var lines: [[UInt8]] = []
        var line: [UInt8] = []
        var index = 0

        func trimTrailingSpace() {
            while let last = line.last, isSpace(last) { line.removeLast() }
        }

        while true {
            var ch: UInt8? = index < bytes.count ? bytes[index] : nil
            index += 1
            if ch == UInt8(ascii: "#") {
                repeat {
                    ch = index < bytes.count ? bytes[index] : nil
                    index += 1
                } while ch != nil && ch != newline
            }
            guard let byte = ch else {
                trimTrailingSpace()
                if !line.isEmpty { lines.append(line) }
                break
            }
            if byte == newline {
                trimTrailingSpace()
                if line.isEmpty { continue }
                if line.last == backslash {
                    // Continuation: drop the `\` and treat the newline as
                    // whitespace between words.
                    line.removeLast()
                } else {
                    lines.append(line)
                    line = []
                    continue
                }
            }
            if isSpace(byte) {
                if let last = line.last, last != space { line.append(space) }
                continue
            }
            line.append(byte)
        }
        return lines.map { $0.split(separator: space, omittingEmptySubsequences: true).map(Array.init) }
    }

    /// Logical lines as words (diagnostics and tests).
    public static func lines(_ bytes: [UInt8]) -> [[String]] {
        lineWords(bytes).map { $0.map { String(decoding: $0, as: UTF8.self) } }
    }

    public static func lines(_ text: String) -> [[String]] {
        lines(Array(text.utf8))
    }
}

// MARK: - Shared policy-file reading

/// What the two parsers share: the fail-closed byte screen, and splitting a
/// policy into lines with OpenPAM's case-insensitive facility match.
enum PAMPolicyText {
    /// The facilities OpenPAM knows. A line whose first word is none of these
    /// (case-insensitively) makes OpenPAM reject the whole file, so `pam_start`
    /// fails.
    static let facilities: Set<String> = ["auth", "account", "password", "session"]

    struct Line {
        /// Lower-cased ASCII.
        let facility: String
        let words: [[UInt8]]

        /// The word at `index`, lower-cased ASCII (OpenPAM matches control
        /// flags and `include` with `tolower`).
        func lowercased(_ index: Int) -> String? {
            guard index < words.count else { return nil }
            return String(decoding: words[index], as: UTF8.self).lowercased()
        }

        var text: String {
            words.map { String(decoding: $0, as: UTF8.self) }.joined(separator: " ")
        }
    }

    /// Why `bytes` can't be read unambiguously, or nil. Anything whose meaning
    /// depends on parser details this check would have to get exactly right —
    /// a CR, a backslash, a NUL or other control byte — is refused wherever it
    /// appears: a backslash ending a line continues it, even the line of a
    /// comment, and a CR changes where that line ends. A quote or a non-ASCII
    /// byte is refused outside a comment only: OpenPAM discards everything from
    /// `#` to the end of the line byte for byte, so text there can't change
    /// what the file means (an apostrophe in an admin's note is harmless).
    static func ambiguity(in bytes: [UInt8], path: String) -> String? {
        var inComment = false
        for (offset, byte) in bytes.enumerated() {
            if byte == 0x0A { inComment = false }
            if byte == UInt8(ascii: "#") { inComment = true }
            let what: String?
            switch byte {
            case 0x0D: what = "a carriage return"
            case UInt8(ascii: "\""), UInt8(ascii: "'"): what = inComment ? nil : "a quote character outside a comment"
            case UInt8(ascii: "\\"): what = "a backslash"
            case 0x09, 0x0A, 0x0B, 0x0C: what = nil
            case 0x00...0x1F, 0x7F: what = "a control byte (0x\(String(byte, radix: 16)))"
            case 0x80...: what = inComment ? nil : "a non-ASCII byte outside a comment"
            default: what = nil
            }
            if let what {
                return "\(path) contains \(what) at offset \(offset); it is not read as wired "
                    + "because it can't be parsed unambiguously"
            }
        }
        return nil
    }

    /// The control flags OpenPAM accepts (matched case-insensitively). The
    /// only other form it takes is `include <policy>`.
    static let controlFlags: Set<String> = ["binding", "required", "requisite", "sufficient", "optional"]

    /// Every active line, or the reason the file is not usable. EVERY line is
    /// checked, not just the ones the gate decision reads: `pam_start` loads
    /// all four facility chains, and one bad line anywhere fails the whole
    /// file, so sudo would deny everyone (pamBypass included) while the daemon
    /// believed the gate was wired.
    static func lines(_ bytes: [UInt8], path: String) -> Result<[Line], PAMGateError> {
        if let reason = ambiguity(in: bytes, path: path) { return .failure(PAMGateError(reason)) }
        var result: [Line] = []
        for words in OpenPAMTokenizer.lineWords(bytes) {
            let line = Line(facility: String(decoding: words[0], as: UTF8.self).lowercased(), words: words)
            if let problem = problem(with: line) {
                return .failure(PAMGateError("\(path): '\(line.text)' \(problem) — "
                    + "OpenPAM rejects the whole file, so sudo's PAM stack would fail to load"))
            }
            result.append(line)
        }
        return .success(result)
    }

    /// Why OpenPAM would reject `line`, or nil when it is well formed:
    /// `facility control module [args]`, or `facility include <policy>` with
    /// exactly one word after `include`.
    private static func problem(with line: Line) -> String? {
        // OpenPAM needs a word after the facility for it to match at all.
        guard line.words.count >= 2, facilities.contains(line.facility) else {
            return "has no valid facility"
        }
        let control = line.lowercased(1) ?? ""
        if control == "include" {
            return line.words.count == 3 ? nil : "needs exactly one policy name after 'include'"
        }
        guard controlFlags.contains(control) else {
            return "has no valid control flag"
        }
        return line.words.count >= 3 ? nil : "names no module"
    }
}

struct PAMGateError: Error {
    let reason: String
    init(_ reason: String) { self.reason = reason }
}

// MARK: - Pure sudo_local parser

/// Parses `/etc/pam.d/sudo_local` (OpenPAM syntax: `facility control
/// module-path [args]`; see ``OpenPAMTokenizer`` for comments and
/// continuations).
///
/// Wired means: the FIRST active `auth` line (facility matched
/// case-insensitively, as OpenPAM does) is `auth requisite
/// /usr/local/lib/pam/pam_serberus.so …`. First matters — an `auth sufficient
/// pam_tid.so` above it lets Touch ID satisfy sudo without Serberus ever being
/// consulted. `requisite` (any case) matters — it is the control the installer
/// writes; anything else (`required`, `optional`, `sufficient`, an `include`)
/// is treated as not wired rather than reasoned about. The module path must be
/// the exact absolute path, byte for byte: a bare name is ambiguous (libpam
/// searches `/usr/lib/pam/` and then `/usr/local/lib/pam/`) and a relative
/// path resolves against the process CWD, so neither is reasoned about. Every
/// other active line must also be one OpenPAM accepts
/// (``PAMPolicyText/lines(_:path:)``). A file with a backslash or CR anywhere,
/// or a quote or non-ASCII byte outside a comment, is not wired
/// (``PAMPolicyText/ambiguity(in:path:)``). ``FilesystemPAMGateVerifier``,
/// which calls this in production, also judges the other lines: each module
/// must sit on a root-only path, and any `include` is not wired.
public enum SudoLocalParser {
    public static func verify(_ text: String,
                              modulePath: String = FilesystemPAMGateVerifier.defaultModulePath) -> PAMGateStatus {
        verify(Array(text.utf8), modulePath: modulePath)
    }

    public static func verify(_ bytes: [UInt8],
                              modulePath: String = FilesystemPAMGateVerifier.defaultModulePath,
                              path: String = FilesystemPAMGateVerifier.defaultSudoLocalPath) -> PAMGateStatus {
        let lines: [PAMPolicyText.Line]
        switch PAMPolicyText.lines(bytes, path: path) {
        case let .success(parsed): lines = parsed
        case let .failure(error): return .notWired(reason: error.reason)
        }
        // The first active auth line decides.
        guard let line = lines.first(where: { $0.facility == "auth" }) else {
            return .notWired(reason: "no active 'auth requisite \(modulePath)' line")
        }
        guard line.words.count >= 3, let control = line.lowercased(1) else {
            return .notWired(reason: "first active auth line is malformed: '\(line.text)'")
        }
        let module = line.words[2]
        guard module == Array(modulePath.utf8) else {
            let name = String(decoding: module, as: UTF8.self)
            if name.hasSuffix("pam_serberus.so") {
                return .notWired(reason: "pam_serberus is referenced as '\(name)', not by its exact path \(modulePath)")
            }
            return .notWired(reason: "first active auth line is '\(line.text)', not pam_serberus — it runs before Serberus")
        }
        guard control == "requisite" else {
            return .notWired(reason: "pam_serberus auth control is '\(control)', expected 'requisite'")
        }
        return .wired
    }

    /// Comment-stripped, continuation-joined, non-empty lines (words joined by
    /// a single space). Kept for diagnostics/tests.
    static func activeLines(_ text: String) -> [String] {
        OpenPAMTokenizer.lines(text).map { $0.joined(separator: " ") }
    }
}

// MARK: - Pure /etc/pam.d/sudo parser

/// Parses `/etc/pam.d/sudo`. `sudo_local` only gates sudo if the main policy
/// actually pulls it in FIRST: its first active `auth` line must be `auth
/// include sudo_local` (facility and `include` in any case, as OpenPAM matches
/// them; the target exactly the bytes `sudo_local`, since OpenPAM silently
/// skips an include whose file doesn't exist). Anything before it —
/// `sufficient` (Touch ID / smart card satisfies sudo on its own), `binding`,
/// another `include`, or any other auth module — runs before Serberus, and a
/// missing include means `sudo_local` is never consulted at all. Every other
/// active line must also be one OpenPAM accepts, and the include line must
/// name exactly one policy (``PAMPolicyText/lines(_:path:)``).
public enum SudoPolicyParser {
    public static let includeTarget = "sudo_local"

    public static func verify(_ text: String) -> PAMGateStatus {
        verify(Array(text.utf8))
    }

    public static func verify(_ bytes: [UInt8],
                              path: String = FilesystemPAMGateVerifier.defaultSudoPolicyPath) -> PAMGateStatus {
        let lines: [PAMPolicyText.Line]
        switch PAMPolicyText.lines(bytes, path: path) {
        case let .success(parsed): lines = parsed
        case let .failure(error): return .notWired(reason: error.reason)
        }
        guard let line = lines.first(where: { $0.facility == "auth" }) else {
            return .notWired(reason: "\(path) has no active 'auth include \(includeTarget)' line — "
                + "sudo_local (and pam_serberus) is never consulted")
        }
        guard line.words.count >= 3, line.lowercased(1) == "include",
              line.words[2] == Array(includeTarget.utf8) else {
            return .notWired(reason: "\(path): first active auth line is '\(line.text)', "
                + "not 'auth include \(includeTarget)' — it runs before Serberus")
        }
        return .wired
    }
}

// MARK: - Filesystem seam

/// `lstat` result reduced to what the gate check needs.
public struct PAMGateFileInfo: Sendable, Equatable {
    public enum Kind: Sendable, Equatable { case regular, directory, symlink, other }
    public let kind: Kind
    public let uid: uid_t
    public let mode: mode_t
    /// Whether the entry's access control list lets anyone but root write it
    /// (``PAMGateACL/grantsNonRootWrite(_:)``). The mode bits alone miss this.
    public let aclGrantsNonRootWrite: Bool

    public init(kind: Kind, uid: uid_t, mode: mode_t, aclGrantsNonRootWrite: Bool = false) {
        self.kind = kind
        self.uid = uid
        self.mode = mode
        self.aclGrantsNonRootWrite = aclGrantsNonRootWrite
    }

    /// Group- or other-writable, by its mode bits or by its ACL.
    var isLooselyWritable: Bool { mode & 0o022 != 0 || aclGrantsNonRootWrite }

    /// "mode 755", plus the ACL when it is what makes the entry writable.
    var writability: String {
        "mode \(String(mode, radix: 8))" + (aclGrantsNonRootWrite ? ", and an ACL entry lets a non-root account write it" : "")
    }
}

/// Reads access control lists for the gate's root-only checks.
public enum PAMGateACL {
    /// The permissions that let a holder change what an entry is or holds:
    /// write or append data (add a file or sub-directory to a directory),
    /// delete it or a child, or rewrite its ACL or owner.
    static let writePermissions: [acl_perm_t] = [
        ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
        ACL_WRITE_SECURITY, ACL_CHANGE_OWNER,
    ]

    /// Whether any ALLOW entry of `path`'s extended ACL (never following a
    /// final symlink) grants one of ``writePermissions`` to anyone but the
    /// root user: another user, or any group (the mode check allows no group
    /// write either). A DENY entry grants nothing. Inherit-only entries count
    /// too, so a check never depends on how an entry would be inherited. An
    /// ACL that can't be read, or an entry whose owner can't be resolved,
    /// counts as granting write.
    public static func grantsNonRootWrite(_ path: String) -> Bool {
        guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else {
            // No extended ACL at all is the common case.
            return errno != ENOENT
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        var which = ACL_FIRST_ENTRY.rawValue
        while acl_get_entry(acl, which, &entry) == 0, let current = entry {
            which = ACL_NEXT_ENTRY.rawValue
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(current, &tag) == 0 else { return true }
            guard tag == ACL_EXTENDED_ALLOW else { continue }
            var permset: acl_permset_t?
            guard acl_get_permset(current, &permset) == 0, let permset else { return true }
            guard writePermissions.contains(where: { acl_get_perm_np(permset, $0) == 1 }) else { continue }
            guard let qualifier = acl_get_qualifier(current) else { return true }
            let isRoot = LocalAccounts.isRootUser(uuid: qualifier.assumingMemoryBound(to: UInt8.self))
            acl_free(qualifier)
            if !isRoot { return true }
        }
        return false
    }
}

/// The filesystem reads the verifier makes. Production uses
/// ``SystemPAMGateFileSystem``; tests inject a dictionary.
public protocol PAMGateFileSystem: Sendable {
    /// `lstat` of `path` (never follows a final symlink), nil when absent.
    func info(_ path: String) -> PAMGateFileInfo?
    /// The file's raw bytes, refusing to follow a final symlink. At most
    /// ``FilesystemPAMGateVerifier/maxPolicyBytes`` + 1 bytes need be returned:
    /// anything longer than the cap is reported as not wired, never parsed as
    /// a truncated prefix.
    func read(_ path: String) -> [UInt8]?
    /// Whether anything might be at `path`. Only a definite "no such file"
    /// counts as absent; any other `lstat` failure counts as present.
    func exists(_ path: String) -> Bool
}

public extension PAMGateFileSystem {
    func exists(_ path: String) -> Bool { info(path) != nil }
}

public struct SystemPAMGateFileSystem: PAMGateFileSystem {
    public init() {}

    public func info(_ path: String) -> PAMGateFileInfo? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        let kind: PAMGateFileInfo.Kind
        switch st.st_mode & S_IFMT {
        case S_IFREG: kind = .regular
        case S_IFDIR: kind = .directory
        case S_IFLNK: kind = .symlink
        default: kind = .other
        }
        return PAMGateFileInfo(kind: kind, uid: st.st_uid, mode: st.st_mode & 0o7777,
                               aclGrantsNonRootWrite: kind != .symlink && PAMGateACL.grantsNonRootWrite(path))
    }

    public func read(_ path: String) -> [UInt8]? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        // sudo_local is a few hundred bytes; bound the read regardless. One
        // byte past the cap is enough to tell the verifier the file is longer.
        guard let data = try? handle.read(upToCount: FilesystemPAMGateVerifier.maxPolicyBytes + 1) else {
            return nil
        }
        return [UInt8](data)
    }

    public func exists(_ path: String) -> Bool {
        var st = stat()
        if lstat(path, &st) == 0 { return true }
        return errno != ENOENT && errno != ENOTDIR
    }
}

// MARK: - Production verifier

/// Verifies, on every call, that:
/// -1. no other file OpenPAM could load sudo's policy from exists
///    (``defaultShadowingPolicyPaths``), and no versioned `<module>.2`, which
///    OpenPAM loads in preference to the module path it was given;
/// 0. `/etc/pam.d/sudo` is a root-owned regular file (lstat), not
///    group/other-writable, whose first active `auth` line is
///    `auth include sudo_local` (``SudoPolicyParser``), no longer than
///    ``maxPolicyBytes``;
/// 1. `/etc/pam.d/sudo_local` is a root-owned regular file (lstat — not a
///    symlink), not group/other-writable, whose first active `auth` line is
///    `auth requisite /usr/local/lib/pam/pam_serberus.so` (``SudoLocalParser``),
///    no longer than ``maxPolicyBytes``;
/// 2. the module is a root-owned regular file with no group/other write bit;
/// 3. every parent directory of the module (`/usr`, `/usr/local`,
///    `/usr/local/lib`, `/usr/local/lib/pam`) is a real, root-owned directory
///    that is not group/other-writable — otherwise a non-root user could swap
///    the module out from under the gate;
/// 4. every OTHER module either policy names sits on a root-only path the same
///    way (``modulePathProblem(_:policy:)``): sudo loads each of them as root
///    on every authentication, so one a user can replace (Homebrew's
///    `pam_reattach` under a user-owned `/opt/homebrew`) runs that user's code
///    as root around the gate. Bare names that resolve in the sealed
///    `/usr/lib/pam` are exempt;
/// 5. neither policy has an `include` line other than the `auth include
///    sudo_local` of 0: OpenPAM loads the modules an included policy names
///    into sudo as root at `pam_start`, and the verifier doesn't follow
///    includes (OpenPAM can find the target outside `/etc/pam.d`), so any
///    other include is not wired rather than reasoned about.
///
/// "Not writable" counts ACLs as well as mode bits: an ALLOW entry granting
/// write to anyone but root fails the check (``PAMGateACL``).
public struct FilesystemPAMGateVerifier: PAMGateVerifying {
    public static let defaultSudoPolicyPath = "/etc/pam.d/sudo"
    public static let defaultSudoLocalPath = "/etc/pam.d/sudo_local"
    public static let defaultModulePath = "/usr/local/lib/pam/pam_serberus.so"

    /// The most policy-file bytes the verifier parses. OpenPAM reads the whole
    /// file, so a longer file is not wired rather than judged on a prefix that
    /// could end mid-word.
    public static let maxPolicyBytes = 256 * 1024

    /// Where else macOS's OpenPAM looks for the `sudo` and `sudo_local`
    /// policies. It tries, in order: the MDM-managed
    /// `/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d/`
    /// and its `pam.conf`, then `/etc/pam.d/`, `/etc/pam.conf`,
    /// `/usr/local/etc/pam.d/`, `/usr/local/etc/pam.conf` (and the sealed
    /// `/usr/share/pam.d/`), stopping at the first file that yields any entry.
    /// A managed file replaces the `/etc/pam.d` one outright; the later ones
    /// take over when an earlier file yields nothing. The verifier reads only
    /// `/etc/pam.d`, so any of these existing is reported as not wired rather
    /// than reasoned about. None exists on a stock Mac.
    public static let defaultShadowingPolicyPaths = [
        "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d/sudo",
        "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d/sudo_local",
        "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.conf",
        "/etc/pam.conf",
        "/usr/local/etc/pam.d/sudo",
        "/usr/local/etc/pam.d/sudo_local",
        "/usr/local/etc/pam.conf",
    ]

    /// Where OpenPAM looks for a module named without a path, in order. For
    /// each directory it tries `<name>.2`, then `<name>`.
    public static let moduleSearchDirectories = ["/usr/lib/pam", "/usr/local/lib/pam"]

    /// The directory on the sealed system volume: nobody can replace a module
    /// found there, so its modules are not checked further.
    public static let sealedModuleDirectory = "/usr/lib/pam"

    private let sudoPolicyPath: String
    private let sudoLocalPath: String
    private let modulePath: String
    private let shadowingPolicyPaths: [String]
    private let fileSystem: PAMGateFileSystem

    public init(
        sudoPolicyPath: String = FilesystemPAMGateVerifier.defaultSudoPolicyPath,
        sudoLocalPath: String = FilesystemPAMGateVerifier.defaultSudoLocalPath,
        modulePath: String = FilesystemPAMGateVerifier.defaultModulePath,
        shadowingPolicyPaths: [String] = FilesystemPAMGateVerifier.defaultShadowingPolicyPaths,
        fileSystem: PAMGateFileSystem = SystemPAMGateFileSystem()
    ) {
        self.sudoPolicyPath = sudoPolicyPath
        self.sudoLocalPath = sudoLocalPath
        self.modulePath = modulePath
        self.shadowingPolicyPaths = shadowingPolicyPaths
        self.fileSystem = fileSystem
    }

    public func verify() -> PAMGateStatus {
        for path in shadowingPolicyPaths where fileSystem.exists(path) {
            return .notWired(reason: "\(path) exists; OpenPAM can load sudo's policy from it instead of "
                + "the verified \(sudoPolicyPath) / \(sudoLocalPath)")
        }

        let policyBytes: [UInt8]
        switch verifyPolicyFile() {
        case let .success(bytes): policyBytes = bytes
        case let .failure(error): return .notWired(reason: error.reason)
        }

        guard let local = fileSystem.info(sudoLocalPath) else {
            return .notWired(reason: "\(sudoLocalPath) is missing")
        }
        guard local.kind == .regular else {
            return .notWired(reason: "\(sudoLocalPath) is not a regular file (\(local.kind))")
        }
        guard local.uid == 0 else {
            return .notWired(reason: "\(sudoLocalPath) is owned by uid \(local.uid), not root")
        }
        guard !local.isLooselyWritable else {
            return .notWired(reason: "\(sudoLocalPath) is group/other-writable (\(local.writability))")
        }
        let text: [UInt8]
        switch readPolicy(sudoLocalPath) {
        case let .success(bytes): text = bytes
        case let .failure(error): return .notWired(reason: error.reason)
        }
        let parsed = SudoLocalParser.verify(text, modulePath: modulePath, path: sudoLocalPath)
        guard parsed.isWired else { return parsed }

        // OpenPAM tries "<path>.2" before "<path>", even for an absolute path,
        // so a versioned file beside the module is what sudo would really run.
        let versioned = modulePath + ".2"
        if fileSystem.exists(versioned) {
            return .notWired(reason: "\(versioned) exists; OpenPAM loads it in preference to \(modulePath)")
        }

        if let problem = rootOnlyProblem(modulePath) {
            return .notWired(reason: "PAM module \(modulePath): \(problem)")
        }

        // Every other module either policy names is loaded into sudo as root,
        // and so are the modules of any policy either one includes. Includes
        // aren't followed: the one allowed is /etc/pam.d/sudo's first auth
        // line, the `auth include sudo_local` SudoPolicyParser verified.
        for (policy, bytes) in [(sudoPolicyPath, policyBytes), (sudoLocalPath, text)] {
            guard case let .success(lines) = PAMPolicyText.lines(bytes, path: policy) else { continue }
            let verifiedInclude = policy == sudoPolicyPath ? lines.firstIndex(where: { $0.facility == "auth" }) : nil
            for (index, line) in lines.enumerated() where line.words.count >= 3 {
                if line.lowercased(1) == "include" {
                    if index == verifiedInclude { continue }
                    return .notWired(reason: "\(policy): '\(line.text)' includes another policy — Serberus doesn't "
                        + "check the modules an included policy loads into sudo as root, so it is not read as wired")
                }
                let module = line.words[2]
                if module == Array(modulePath.utf8) { continue }
                if let problem = modulePathProblem(module, policy: policy) {
                    return .notWired(reason: problem)
                }
            }
        }
        return .wired
    }

    /// Why a module `policy` names could be replaced by someone other than
    /// root, or nil when it can't. OpenPAM loads a bare name from the first of
    /// ``moduleSearchDirectories`` holding `<name>.2` or `<name>`, and an
    /// absolute path as `<path>.2` if that exists, else `<path>`. A bare name
    /// found in the sealed ``sealedModuleDirectory`` is safe; anything else must
    /// pass ``rootOnlyProblem(_:)``. A relative path (resolved against sudo's
    /// working directory) is never safe.
    func modulePathProblem(_ word: [UInt8], policy: String) -> String? {
        let name = String(decoding: word, as: UTF8.self)
        let loaded: String
        if !name.contains("/") {
            var found: (directory: String, path: String)?
            for directory in Self.moduleSearchDirectories {
                if let path = ["\(directory)/\(name).2", "\(directory)/\(name)"].first(where: fileSystem.exists) {
                    found = (directory, path)
                    break
                }
            }
            guard let found else {
                return "\(policy) names PAM module \(name), which is in neither "
                    + Self.moduleSearchDirectories.joined(separator: " nor ")
            }
            if found.directory == Self.sealedModuleDirectory { return nil }
            loaded = found.path
        } else if name.hasPrefix("/") {
            loaded = [name + ".2", name].first(where: fileSystem.exists) ?? name
        } else {
            return "\(policy) names PAM module \(name) by a relative path, which sudo resolves against its "
                + "working directory"
        }
        guard let problem = rootOnlyProblem(loaded) else { return nil }
        return "\(policy) names PAM module \(name), and \(problem) — whoever can write there can replace "
            + "code sudo loads as root"
    }

    /// Why `path` is not a root-only regular file, or nil: it and every parent
    /// directory must exist, be real (not symlinks), be owned by root, and not
    /// be group/other-writable by mode or ACL.
    func rootOnlyProblem(_ path: String) -> String? {
        for directory in Self.parentDirectories(of: path) {
            guard let info = fileSystem.info(directory) else {
                return "\(directory) is missing"
            }
            guard info.kind == .directory else {
                return "\(directory) is not a real directory (\(info.kind))"
            }
            guard info.uid == 0 else {
                return "\(directory) is owned by uid \(info.uid), not root"
            }
            guard !info.isLooselyWritable else {
                return "\(directory) is group/other-writable (\(info.writability))"
            }
        }
        guard let info = fileSystem.info(path) else {
            return "\(path) is missing"
        }
        guard info.kind == .regular else {
            return "\(path) is not a regular file (\(info.kind))"
        }
        guard info.uid == 0 else {
            return "\(path) is owned by uid \(info.uid), not root"
        }
        guard !info.isLooselyWritable else {
            return "\(path) is group/other-writable (\(info.writability))"
        }
        return nil
    }

    /// `/etc/pam.d/sudo`: root-owned regular file (lstat), not group/other-
    /// writable, first active auth line `auth include sudo_local`. Its bytes
    /// when it verifies.
    private func verifyPolicyFile() -> Result<[UInt8], PAMGateError> {
        guard let info = fileSystem.info(sudoPolicyPath) else {
            return .failure(PAMGateError("\(sudoPolicyPath) is missing"))
        }
        guard info.kind == .regular else {
            return .failure(PAMGateError("\(sudoPolicyPath) is not a regular file (\(info.kind))"))
        }
        guard info.uid == 0 else {
            return .failure(PAMGateError("\(sudoPolicyPath) is owned by uid \(info.uid), not root"))
        }
        guard !info.isLooselyWritable else {
            return .failure(PAMGateError("\(sudoPolicyPath) is group/other-writable (\(info.writability))"))
        }
        let bytes: [UInt8]
        switch readPolicy(sudoPolicyPath) {
        case let .success(read): bytes = read
        case let .failure(error): return .failure(error)
        }
        if case let .notWired(reason) = SudoPolicyParser.verify(bytes, path: sudoPolicyPath) {
            return .failure(PAMGateError(reason))
        }
        return .success(bytes)
    }

    /// The whole policy file, or why it can't be judged: unreadable, or longer
    /// than ``maxPolicyBytes``.
    private func readPolicy(_ path: String) -> Result<[UInt8], PAMGateError> {
        guard let bytes = fileSystem.read(path) else {
            return .failure(PAMGateError("\(path) could not be read"))
        }
        guard bytes.count <= Self.maxPolicyBytes else {
            return .failure(PAMGateError("\(path) is longer than \(Self.maxPolicyBytes) bytes; "
                + "it is not read as wired because only part of it would be checked"))
        }
        return .success(bytes)
    }

    /// `/usr/local/lib/pam/x.so` → `["/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/pam"]`.
    static func parentDirectories(of path: String) -> [String] {
        let parts = path.split(separator: "/").dropLast()
        var result: [String] = []
        var current = ""
        for part in parts {
            current += "/" + part
            result.append(current)
        }
        return result
    }
}
