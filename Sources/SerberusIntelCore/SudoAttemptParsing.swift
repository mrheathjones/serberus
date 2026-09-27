import Foundation
import PrivMgrCore

/// What one `sudo(8)` unified-log line says about an attempt.
///
/// sudo logs every invocation itself, as `/usr/bin/sudo`, Default level, EMPTY
/// subsystem/category. The shapes, all grounded in
/// real output:
///
///     tuser : TTY=ttys001 ; PWD=/Users/tuser ; USER=root ; COMMAND=/usr/bin/true
///     tuser : a password is required ; PWD=/Users/tuser ; USER=root ; COMMAND=/usr/bin/true
///     tuser : 3 incorrect password attempts ; TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id
///     tuser : command not allowed ; TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/jamf policy
///     tuser : user NOT in sudoers ; TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/bin/ls
///
/// i.e. `<user> : [<status> ; ][TTY=<tty> ; ]PWD=<pwd> ; USER=<runas> ; [GROUP=<g> ; ]COMMAND=<path> [<args>]`.
/// A line with no status means sudo went on to run the command. The same
/// process also emits `libsystem_info.dylib` Activity lines (`Retrieve Group by
/// ID`) — those carry no ` ; COMMAND=` and are not attempts.
///
/// Escaping (sudo ≥ 1.9.13): a space or control character INSIDE the command
/// path is written as a `#ooo` octal escape (`/Library/Application#040Support/…`),
/// and an argument containing spaces or quotes is wrapped in single quotes with
/// `\'` and `\\` escapes inside. Both are decoded here so the command can be
/// realpath'd / identity-pinned and `argv[0]` is the real first argument.
public struct SudoAttemptInfo: Sendable, Equatable {
    /// The invoking user.
    public let user: String
    /// Free-text status sudo stated, when it stated one (`a password is
    /// required`, `command not allowed`, `3 incorrect password attempts`, …).
    /// `nil` on a success line.
    public let status: String?
    public let tty: String?
    public let pwd: String?
    /// `USER=` — the target user (almost always `root`).
    public let runAsUser: String?
    /// `COMMAND=`'s first token, `#ooo` escapes decoded — the command path as
    /// sudo resolved it.
    public let command: String
    /// Everything after the command, one element per argument (sudo's
    /// single-quote wrapping decoded). This is the argv the daemon's
    /// `argPattern` (a regex over `argv[0]`) is matched against.
    public let arguments: [String]

    public init(user: String, status: String?, tty: String?, pwd: String?, runAsUser: String?,
                command: String, arguments: [String]) {
        self.user = user
        self.status = status
        self.tty = tty
        self.pwd = pwd
        self.runAsUser = runAsUser
        self.command = command
        self.arguments = arguments
    }

    /// Coarse outcome for the capture, from the status prose. Never guessed:
    /// an unrecognised status is `.unknown`, with the prose kept alongside.
    ///
    /// `.granted` means **sudo went on to run the command** — whether because
    /// pam_serberus allowed it, the user approved a prompt, or Serberus was in
    /// monitor mode and never consulted. The capture's enrichment
    /// (`serberusOutcome`, matched rule) is what says which.
    public var outcome: CapturedOutcome {
        guard let status else { return .granted }
        let lower = status.lowercased()
        // "denied" also covers Serberus's OWN deny text, which sudo logs as the
        // status when pam_serberus refuses (the configurable `sudoDenyMessage`
        // / sudoers `authfail_message` — e.g. "denied by Serberus - see the
        // message above").
        if lower.contains("command not allowed")
            || lower.contains("not in sudoers")
            || lower.contains("not allowed to execute")
            || lower.contains("not authorized")
            || lower.contains("denied") {
            return .denied
        }
        if lower.contains("incorrect password")
            || lower.contains("password is required")
            || lower.contains("authentication failure")
            || lower.contains("no tty present") {
            return .failed
        }
        return .unknown
    }
}

/// Extracts ``SudoAttemptInfo`` from one sudo `eventMessage`. Pure and
/// deterministic.
public enum SudoAttemptParser {
    /// The field separator sudo uses between every segment.
    private static let separator = " ; "
    private static let commandKey = "COMMAND="

    /// Parses one message. `nil` for anything that is not an attempt line
    /// (no ` ; COMMAND=` segment — the `libsystem_info` activity noise, or a
    /// line in a shape this parser does not understand).
    public static func info(from message: String) -> SudoAttemptInfo? {
        let text = message.trimmingCharacters(in: .whitespaces)
        // COMMAND= is always the LAST segment; everything after it is the
        // command line (which may itself contain ` ; `, so it is not split).
        guard let commandRange = text.range(of: separator + commandKey) else { return nil }
        let commandText = String(text[commandRange.upperBound...])
        let head = String(text[..<commandRange.lowerBound])

        // `<user> : <first segment>` then ` ; `-separated key/value segments.
        guard let userSeparator = head.range(of: " : ") else { return nil }
        let user = String(head[..<userSeparator.lowerBound]).trimmingCharacters(in: .whitespaces)
        guard !user.isEmpty else { return nil }
        let rest = String(head[userSeparator.upperBound...])
        let segments = rest.components(separatedBy: separator)

        var status: String?
        var tty: String?
        var pwd: String?
        var runAs: String?
        for segment in segments {
            if segment.hasPrefix("TTY=") {
                tty = String(segment.dropFirst(4))
            } else if segment.hasPrefix("PWD=") {
                pwd = String(segment.dropFirst(4))
            } else if segment.hasPrefix("USER=") {
                runAs = String(segment.dropFirst(5))
            } else if segment.hasPrefix("GROUP=") {
                continue
            } else if !segment.isEmpty, status == nil {
                // The one free-text segment sudo emits is the failure status,
                // always first. Anything else unrecognised is left alone.
                status = segment
            }
        }

        // The command is everything up to the first LITERAL space (sudo never
        // writes a literal space inside the path — it escapes them), decoded.
        let (commandToken, remainder) = splitAtFirstSpace(commandText)
        let command = decodeOctalEscapes(commandToken)
        guard !command.isEmpty else { return nil }
        return SudoAttemptInfo(
            user: user,
            status: status,
            tty: tty,
            pwd: pwd,
            runAsUser: runAs,
            command: command,
            arguments: tokenizeArguments(remainder)
        )
    }

    /// Whether a unified-log entry is a sudo attempt line at all — the gate a
    /// Capture session applies before parsing (drops the per-invocation
    /// `libsystem_info` activity records that share the `sudo` process).
    public static func isAttemptLine(_ entry: LogEntry) -> Bool {
        entry.message.contains(separator + commandKey)
    }

    // MARK: Escapes

    static func splitAtFirstSpace(_ text: String) -> (String, String) {
        guard let space = text.firstIndex(of: " ") else { return (text, "") }
        return (String(text[..<space]), String(text[text.index(after: space)...]))
    }

    /// Decodes sudo's `#ooo` octal escapes (`#040` → space, `#011` → tab) in
    /// a command path. Anything that is not exactly `#` + three octal digits is
    /// left verbatim, so a literal `#` in a path survives.
    static func decodeOctalEscapes(_ text: String) -> String {
        guard text.contains("#") else { return text }
        var bytes: [UInt8] = []
        let scalars = Array(text.unicodeScalars)
        var index = 0
        while index < scalars.count {
            let scalar = scalars[index]
            if scalar == "#", index + 3 < scalars.count {
                let digits = scalars[(index + 1)...(index + 3)]
                if digits.allSatisfy({ ("0"..."7").contains($0) }),
                   let value = UInt8(String(digits.map { Character($0) }), radix: 8) {
                    bytes.append(value)
                    index += 4
                    continue
                }
            }
            bytes.append(contentsOf: Array(String(scalar).utf8))
            index += 1
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Splits sudo's logged argument text into argv: space-separated, with
    /// single-quoted arguments (which may contain spaces, `\'` and `\\`)
    /// returned unquoted and unescaped.
    static func tokenizeArguments(_ text: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var hasToken = false
        var inQuotes = false
        var iterator = text.makeIterator()
        while let character = iterator.next() {
            if inQuotes {
                if character == "\\" {
                    if let escaped = iterator.next() { current.append(escaped) }
                    continue
                }
                if character == "'" { inQuotes = false; continue }
                current.append(character)
            } else {
                if character == " " {
                    if hasToken { tokens.append(current); current = ""; hasToken = false }
                    continue
                }
                if character == "'" { inQuotes = true; hasToken = true; continue }
                current.append(character)
                hasToken = true
            }
        }
        if hasToken { tokens.append(current) }
        return tokens
    }
}
