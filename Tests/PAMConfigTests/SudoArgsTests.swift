import Foundation
import Testing

/// Exercises `serberus_find_sudo_command` (`sudo_args.c`), which tells
/// `pam_serberus` which command sudo is about to run. Any disagreement with
/// sudo's own parser is a policy bypass, so each case pins one sudo parsing
/// rule, and every form Serberus can't evaluate must come back unsupported.
@Suite("sudo command-line parser")
struct SudoArgsTests {

    private enum Outcome: Equatable {
        case command(at: Int)
        case noCommand
        case unsupported
    }

    private func parse(_ arguments: [String]) -> Outcome {
        let cStrings = arguments.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }
        let pointers = cStrings.map { UnsafePointer<CChar>($0) }
        var index: Int32 = -1
        let result = pointers.withUnsafeBufferPointer {
            serberus_find_sudo_command(Int32(arguments.count), $0.baseAddress, &index)
        }
        switch result {
        case SERBERUS_SUDO_ARGS_COMMAND: return .command(at: Int(index))
        case SERBERUS_SUDO_ARGS_NO_COMMAND: return .noCommand
        default: return .unsupported
        }
    }

    // MARK: - The command is found where sudo finds it

    @Test("a long option is never mistaken for one that takes a value")
    func longOptionEndingInValueLetter() {
        // The old parser read the LAST letter of "--reset-timestamp" ("p") as the
        // short -p, skipped the next token, and evaluated `jamf recon` while
        // sudo ran jamf with `/usr/local/bin/jamf recon`.
        #expect(parse(["sudo", "--reset-timestamp", "/usr/local/bin/jamf", "/usr/local/bin/jamf", "recon"])
                == .command(at: 2))
    }

    @Test("options that take a value", arguments: [
        (["sudo", "/usr/local/bin/jamf", "recon"], 1),
        (["sudo", "-u", "root", "/bin/ls"], 3),
        (["sudo", "-uroot", "/bin/ls"], 2),
        (["sudo", "-Hu", "root", "/bin/ls"], 3),
        (["sudo", "-nk", "/bin/ls"], 2),
        (["sudo", "-u", "-x", "/bin/ls"], 3),          // a required value is taken even if it looks like an option
        (["sudo", "--user=root", "/bin/ls"], 2),
        (["sudo", "--user", "root", "/bin/ls"], 3),
        (["sudo", "--us", "root", "/bin/ls"], 3),       // unique prefix of --user
        (["sudo", "--close-from", "5", "/bin/ls"], 3),
        (["sudo", "-C5", "/bin/ls"], 2),
        (["sudo", "-p", "Password:", "--", "/bin/ls"], 4),
        (["sudo", "--preserve-env=PATH", "/bin/ls"], 2),
    ])
    func valueOptions(arguments: [String], commandIndex: Int) {
        #expect(parse(arguments) == .command(at: commandIndex))
    }

    @Test("--preserve-env takes a value only when attached, like sudo")
    func preserveEnvOptionalValue() {
        // sudo runs `PATH` as the command here; so must Serberus evaluate it.
        #expect(parse(["sudo", "--preserve-env", "PATH", "/bin/ls"]) == .command(at: 2))
    }

    @Test("end of options and non-options", arguments: [
        (["sudo", "--", "/bin/ls"], 2),
        (["sudo", "--", "FOO=bar"], 2),                 // after --, even NAME=value is the command
        (["sudo", "/opt/x=y/tool"], 1),                 // starts with '/', so not an assignment
        (["sudo", "-"], 1),                             // a lone dash is not an option
    ])
    func endOfOptions(arguments: [String], commandIndex: Int) {
        #expect(parse(arguments) == .command(at: commandIndex))
    }

    // MARK: - Invocations that don't run the named command are refused

    @Test("modes and options that change what runs are unsupported", arguments: [
        ["sudo", "-s"], ["sudo", "-s", "/bin/ls"], ["sudo", "--shell", "/bin/ls"],
        ["sudo", "-i"], ["sudo", "--login", "/bin/ls"],
        ["sudo", "-e", "/etc/hosts"], ["sudo", "--edit", "/etc/hosts"],
        ["sudo", "-l"], ["sudo", "--list", "/bin/ls"],
        ["sudo", "-v"], ["sudo", "--validate"], ["sudo", "-V"], ["sudo", "--version"],
        ["sudo", "-K"], ["sudo", "--remove-timestamp"],
        ["sudo", "-h"], ["sudo", "-hhost", "/bin/ls"], ["sudo", "--help"],
        ["sudo", "--host=h", "/bin/ls"], ["sudo", "--host", "h", "/bin/ls"],
        ["sudo", "-D", "/tmp", "/bin/ls"], ["sudo", "--chdir=/tmp", "/bin/ls"],
        ["sudo", "-R", "/", "/bin/ls"], ["sudo", "--chroot", "/", "/bin/ls"],
        ["sudo", "-U", "bob", "-l"], ["sudo", "--other-user", "bob"],
        ["sudo", "-a", "x", "/bin/ls"], ["sudo", "-c", "x", "/bin/ls"],
        ["sudo", "-r", "x", "/bin/ls"], ["sudo", "-t", "x", "/bin/ls"],
        ["sudo", "-ns", "/bin/ls"],                     // a refused letter inside a cluster
        ["sudoedit", "/etc/hosts"], ["/usr/bin/sudoedit", "/etc/hosts"],
    ])
    func refusedModes(arguments: [String]) {
        #expect(parse(arguments) == .unsupported)
    }

    @Test("malformed, unknown, or ambiguous options are unsupported", arguments: [
        ["sudo", "-x", "/bin/ls"],
        ["sudo", "--bogus", "/bin/ls"],
        ["sudo", "--pre", "/bin/ls"],                   // preserve-env or preserve-groups
        ["sudo", "--v", "/bin/ls"],                     // validate or version
        ["sudo", "-u"],                                 // value missing
        ["sudo", "--user"],
        ["sudo", "--askpass=yes", "/bin/ls"],           // takes no value
        ["sudo", "--=x", "/bin/ls"],
    ])
    func malformedOptions(arguments: [String]) {
        #expect(parse(arguments) == .unsupported)
    }

    @Test("NAME=value assignments before the command are unsupported", arguments: [
        ["sudo", "FOO=bar", "/bin/ls"],
        ["sudo", "-u", "root", "FOO=bar", "/bin/ls"],
    ])
    func environmentAssignments(arguments: [String]) {
        #expect(parse(arguments) == .unsupported)
    }

    @Test("no command at all", arguments: [["sudo"], ["sudo", "-n"], ["sudo", "--"]])
    func noCommand(arguments: [String]) {
        #expect(parse(arguments) == .noCommand)
    }

    // MARK: - argv[0]

    @Test("an empty argv[0] is unsupported")
    func emptyArgv0() {
        // execve("/usr/bin/sudo", ["", jamf, -u, root, jamf, recon]): the old
        // KERN_PROCARGS2 reader swallowed the empty argv[0] into the exec-path
        // padding and evaluated `jamf recon FIRSTENV=1` while sudo ran jamf
        // with `-u root /usr/local/bin/jamf recon`.
        #expect(parse(["", "/usr/local/bin/jamf", "-u", "root", "/usr/local/bin/jamf", "recon"])
                == .unsupported)
        #expect(parse([""]) == .unsupported)
    }

    @Test("argv[0] must name sudo, after sudo's own lt- stripping", arguments: [
        (["sudo", "/bin/ls"], true),
        (["/usr/bin/sudo", "/bin/ls"], true),
        (["lt-sudo", "/bin/ls"], true),                 // sudo strips a libtool "lt-" prefix
        (["/opt/x/lt-sudo", "/bin/ls"], true),
        (["lt-sudoedit", "/etc/hosts"], false),
        (["/tmp/x/lt-sudoedit", "/etc/hosts"], false),
        (["xsudo", "/bin/ls"], false),
        (["sudo2", "/bin/ls"], false),
        (["lt-", "/bin/ls"], false),
        (["/usr/bin/", "/bin/ls"], false),
    ])
    func argv0Names(arguments: [String], accepted: Bool) {
        #expect(parse(arguments) == (accepted ? .command(at: 1) : .unsupported))
    }
}

/// Exercises `serberus_sudo_invocation_name_ok`: sudo picks sudoedit mode from
/// getprogname(), which on macOS follows argv[0] as the process was started
/// (`exec -a sudoedit /usr/bin/sudo`, or a symlink `~/x/sudoedit ->
/// /usr/bin/sudo`). The program name, the exec path, and argv[0] must all say
/// "sudo".
@Suite("sudo invocation name")
struct SudoInvocationNameTests {

    @Test("plain sudo is accepted", arguments: [
        ("sudo", "/usr/bin/sudo", "sudo"),
        ("sudo", "/usr/bin/sudo", "/usr/bin/sudo"),
        ("sudo", "sudo", "sudo"),
        ("sudo", "/usr/bin/sudo", "lt-sudo"),
        ("lt-sudo", "/opt/lt-sudo", "sudo"),
    ])
    func accepted(progname: String, execPath: String, argv0: String) {
        #expect(serberus_sudo_invocation_name_ok(progname, execPath, argv0))
    }

    @Test("sudoedit by program name, exec path, or argv[0] is rejected", arguments: [
        ("sudoedit", "/usr/bin/sudo", "sudo"),          // progname alone decides edit mode
        ("lt-sudoedit", "/usr/bin/sudo", "sudo"),
        ("sudo", "/Users/u/x/sudoedit", "sudo"),        // symlink named sudoedit
        ("sudo", "/Users/u/x/lt-sudoedit", "sudo"),
        ("sudo", "/usr/bin/sudo", "sudoedit"),
        ("sudo", "/usr/bin/sudo", "/usr/bin/sudoedit"),
        ("sudo", "/usr/bin/sudo", "lt-sudoedit"),
    ])
    func sudoeditRejected(progname: String, execPath: String, argv0: String) {
        #expect(!serberus_sudo_invocation_name_ok(progname, execPath, argv0))
    }

    @Test("any other or missing name is rejected", arguments: [
        ("sudo", "/usr/bin/sudo", ""),                  // empty argv[0]
        ("", "/usr/bin/sudo", "sudo"),
        ("sudo", "", "sudo"),
        ("pn", "/usr/bin/sudo", "sudo"),
        ("sudo", "/tmp/notsudo", "sudo"),
        ("sudo", "/usr/bin/sudo/", "sudo"),
        ("sudo", "/usr/bin/sudo", "SUDO"),
    ])
    func otherNamesRejected(progname: String, execPath: String, argv0: String) {
        #expect(!serberus_sudo_invocation_name_ok(progname, execPath, argv0))
    }

    @Test("NULL names are rejected")
    func nullNames() {
        #expect(!serberus_sudo_invocation_name_ok(nil, "/usr/bin/sudo", "sudo"))
        #expect(!serberus_sudo_invocation_name_ok("sudo", nil, "sudo"))
        #expect(!serberus_sudo_invocation_name_ok("sudo", "/usr/bin/sudo", nil))
    }
}

/// Exercises `serberus_find_in_path`, which resolves a bare command name the
/// way sudoers' find_path() does, so Serberus evaluates the binary sudo runs.
@Suite("sudo PATH lookup")
struct SudoFindInPathTests {

    /// A temp tree: <root>/a/tool and <root>/b/tool are executables,
    /// <root>/a/plain is not executable, <root>/a/dir is a directory named
    /// like a command, <root>/b/plain and <root>/b/dir are executables.
    private struct Fixture {
        let root: URL
        var a: String { root.appendingPathComponent("a").path }
        var b: String { root.appendingPathComponent("b").path }

        init() throws {
            let fm = FileManager.default
            let raw = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("serberus-path-\(UUID().uuidString)")
            try fm.createDirectory(at: raw, withIntermediateDirectories: true)
            // realpath, not resolvingSymlinksInPath (which drops /private):
            // results are compared with what the C side's realpath() returns.
            guard let canonical = realpath(raw.path, nil) else {
                throw CocoaError(.fileNoSuchFile)
            }
            root = URL(fileURLWithPath: String(cString: canonical))
            free(canonical)
            let a = root.appendingPathComponent("a")
            let b = root.appendingPathComponent("b")
            try fm.createDirectory(at: a, withIntermediateDirectories: true)
            try fm.createDirectory(at: b, withIntermediateDirectories: true)
            try Self.file(a.appendingPathComponent("tool"), mode: 0o755)
            try Self.file(b.appendingPathComponent("tool"), mode: 0o755)
            try Self.file(a.appendingPathComponent("plain"), mode: 0o644)
            try Self.file(b.appendingPathComponent("plain"), mode: 0o755)
            try Self.file(a.appendingPathComponent("rootonly"), mode: 0o100)  // owner-exec only
            try fm.createDirectory(at: a.appendingPathComponent("dir"), withIntermediateDirectories: true)
            try Self.file(b.appendingPathComponent("dir"), mode: 0o755)
        }

        private static func file(_ url: URL, mode: Int) throws {
            try Data("#!/bin/sh\n".utf8).write(to: url)
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        }

        func remove() { try? FileManager.default.removeItem(at: root) }

        /// `absolute` as a path RELATIVE to the current directory, whatever
        /// that is: enough "../" to reach "/" (extra ones stay at "/").
        static func relative(_ absolute: String) -> String {
            String(repeating: "../", count: 64) + absolute.drop(while: { $0 == "/" })
        }
    }

    private func find(_ command: String, path: String?) -> String? {
        var out = [CChar](repeating: 0, count: Int(PATH_MAX))
        let found = serberus_find_in_path(command, path, &out, out.count)
        return found ? out.withUnsafeBufferPointer { String(cString: $0.baseAddress!) } : nil
    }

    @Test("first PATH match wins, canonicalized")
    func firstMatch() throws {
        let fx = try Fixture(); defer { fx.remove() }
        #expect(find("tool", path: "\(fx.a):\(fx.b)") == "\(fx.a)/tool")
        #expect(find("tool", path: "\(fx.b):\(fx.a)") == "\(fx.b)/tool")
        #expect(find("missing", path: "\(fx.a):\(fx.b)") == nil)
    }

    @Test("a relative PATH entry is searched in order, as sudo does")
    func relativeEntrySearchedInOrder() throws {
        // Skipping it would let Serberus evaluate b/tool while sudo runs a/tool.
        let fx = try Fixture(); defer { fx.remove() }
        #expect(find("tool", path: "\(Fixture.relative(fx.a)):\(fx.b)") == "\(fx.a)/tool")
    }

    @Test("empty PATH entries are skipped, never the current directory")
    func emptyEntries() throws {
        let fx = try Fixture(); defer { fx.remove() }
        #expect(find("tool", path: "::\(fx.b):") == "\(fx.b)/tool")
    }

    @Test("\".\" is searched after every other entry")
    func dotSearchedLast() throws {
        let fx = try Fixture(); defer { fx.remove() }
        #expect(find("tool", path: ".:\(fx.b)") == "\(fx.b)/tool")
    }

    @Test("only regular files with an execute bit qualify (stat, like sudo_goodpath)")
    func executableRegularFilesOnly() throws {
        let fx = try Fixture(); defer { fx.remove() }
        #expect(find("plain", path: "\(fx.a):\(fx.b)") == "\(fx.b)/plain")
        #expect(find("dir", path: "\(fx.a):\(fx.b)") == "\(fx.b)/dir")
        // Any execute bit counts, not just one the caller holds.
        #expect(find("rootonly", path: fx.a) == "\(fx.a)/rootonly")
    }

    @Test("names with a slash and empty names are not looked up")
    func notBareNames() {
        #expect(find("bin/ls", path: "/") == nil)
        #expect(find("", path: "/bin") == nil)
    }

    @Test("unset or empty PATH searches the fixed system default")
    func defaultPath() {
        #expect(find("ls", path: nil) == "/bin/ls")
        #expect(find("ls", path: "") == "/bin/ls")
    }
}
