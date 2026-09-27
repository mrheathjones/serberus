import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

// MARK: - Pure sudo_local parser

@Suite("SudoLocalParser — sudo_local PAM gate")
struct SudoLocalParserTests {
    private let module = FilesystemPAMGateVerifier.defaultModulePath

    @Test("the installer's canonical line (with its managed-tag comment) is wired")
    func wiredCorrect() {
        let text = """
        # sudo_local: local config file which survives system update and is included for sudo
        auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
        auth       sufficient     pam_tid.so
        """
        #expect(SudoLocalParser.verify(text) == .wired)
    }

    @Test("`required` instead of `requisite` is NOT wired")
    func requiredControl() {
        let text = "auth       required       \(module)\n"
        let status = SudoLocalParser.verify(text)
        #expect(!status.isWired)
        #expect(status.reasonText.contains("required"))
    }

    @Test("a commented-out line is NOT wired — `#` starts a comment anywhere on the line")
    func commentedLine() {
        #expect(!SudoLocalParser.verify("#auth requisite \(module)\n").isWired)
        #expect(!SudoLocalParser.verify("   # auth requisite \(module)\n").isWired)
        // A `#` mid-line comments out the rest, leaving a malformed auth line.
        #expect(!SudoLocalParser.verify("auth requisite #\(module)\n").isWired)
    }

    @Test("pam_tid.so above Serberus is NOT wired — Touch ID would satisfy sudo first")
    func pamTidAbove() {
        let text = """
        auth       sufficient     pam_tid.so
        auth       requisite      \(module)
        """
        let status = SudoLocalParser.verify(text)
        #expect(!status.isWired)
        #expect(status.reasonText.contains("pam_tid.so"))
    }

    @Test("a commented-out pam_tid.so above Serberus does not count")
    func commentedPamTidAbove() {
        let text = """
        #auth       sufficient     pam_tid.so
        auth       requisite      \(module)
        """
        #expect(SudoLocalParser.verify(text) == .wired)
    }

    @Test("non-auth lines above the Serberus line are fine")
    func otherFacilitiesAbove() {
        let text = """
        account    required       pam_permit.so
        auth       requisite      \(module)
        """
        #expect(SudoLocalParser.verify(text) == .wired)
    }

    @Test("empty / missing content is NOT wired")
    func emptyFile() {
        #expect(!SudoLocalParser.verify("").isWired)
        #expect(!SudoLocalParser.verify("# only comments\n\n").isWired)
    }

    @Test("a bare or relative module name is NOT wired — only the exact absolute path counts")
    func relativeOrBareModule() {
        #expect(!SudoLocalParser.verify("auth requisite pam_serberus.so\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite lib/pam/pam_serberus.so\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite /usr/lib/pam/pam_serberus.so\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite /usr/local/lib/pam/../pam/pam_serberus.so\n").isWired)
    }

    @Test("an `include` as the first auth line is NOT wired")
    func includeFirst() {
        let text = """
        auth       include        sudo_other
        auth       requisite      \(module)
        """
        #expect(!SudoLocalParser.verify(text).isWired)
    }

    @Test("tabs as separators and trailing module args are accepted")
    func tabsAndArgs() {
        #expect(SudoLocalParser.verify("auth\trequisite\t\(module) debug\n") == .wired)
    }

    @Test("facility and control flag match case-insensitively, as OpenPAM does")
    func caseInsensitiveFacilityAndControl() {
        let status = SudoLocalParser.verify("Auth sufficient pam_tid.so\nauth requisite \(module)\n")
        #expect(!status.isWired)
        #expect(status.reasonText.contains("pam_tid.so"))
        #expect(!SudoLocalParser.verify("AUTH sufficient pam_tid.so\nauth requisite \(module)\n").isWired)
        #expect(SudoLocalParser.verify("AUTH Requisite \(module)\n") == .wired)
        #expect(!SudoLocalParser.verify("auth REQUIRED \(module)\n").isWired)
    }

    @Test("a CRLF comment line does not run on into the next line; any CR is not wired")
    func crlf() {
        #expect(!SudoLocalParser.verify("# managed by IT\r\nauth sufficient pam_tid.so\nauth requisite \(module)\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite \(module)\r\n").isWired)
        #expect(!SudoLocalParser.verify("# managed by IT\r\nauth requisite \(module)\n").isWired)
    }

    @Test("\\v and \\f separate words like any other isspace() byte")
    func verticalTabAndFormFeed() {
        #expect(!SudoLocalParser.verify("auth\u{0B}sufficient\u{0B}pam_tid.so\nauth requisite \(module)\n").isWired)
        #expect(!SudoLocalParser.verify("auth\u{0C}sufficient\u{0C}pam_tid.so\nauth requisite \(module)\n").isWired)
        #expect(SudoLocalParser.verify("auth\u{0B}requisite\u{0C}\(module)\n") == .wired)
    }

    @Test("a quoted module path is NOT wired — OpenPAM would try to load a file whose name includes the quotes")
    func quotedModulePath() {
        #expect(!SudoLocalParser.verify("auth requisite \"\(module)\"\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite '\(module)'\n").isWired)
        // A quote anywhere outside a comment, even on a later line.
        #expect(!SudoLocalParser.verify("auth requisite \(module)\nauth optional pam_x.so 'a'\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite \(module) a\"b\n").isWired)
    }

    @Test("a quote inside a comment is read as OpenPAM reads it: discarded with the comment")
    func quotesInComments() {
        let line = "auth requisite \(module)"
        #expect(SudoLocalParser.verify("# don't edit: IT's \"managed\" file\n\(line)\n") == .wired)
        #expect(SudoLocalParser.verify("\(line) # \"x\" and 'y'\n") == .wired)
        #expect(SudoLocalParser.verify("\(line)#'glued'\n") == .wired)
        // The comment ends at the newline: a quote on the next line is outside it.
        #expect(!SudoLocalParser.verify("# note\n'\(line)'\n").isWired)
    }

    @Test("a backslash anywhere is NOT wired, even a valid continuation")
    func backslash() {
        #expect(!SudoLocalParser.verify("auth \\\n requisite \(module)\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite \(module) arg\\x\n").isWired)
    }

    @Test("a non-ASCII byte outside a comment, or a NUL or other control byte anywhere, is NOT wired")
    func nonASCII() {
        let line = Array("auth requisite \(module)\n".utf8)
        #expect(SudoLocalParser.verify(line) == .wired)
        #expect(!SudoLocalParser.verify([0xC2, 0xA0] + line).isWired)           // NBSP
        #expect(!SudoLocalParser.verify(Array("auth requisite \(module) caf\u{E9}\n".utf8)).isWired)
        #expect(!SudoLocalParser.verify(line + Array("# caf\u{E9}\n\u{E9}\n".utf8)).isWired) // comment ends at LF
        #expect(!SudoLocalParser.verify(line + [0xFF, 0x0A]).isWired)             // not even UTF-8
        #expect(!SudoLocalParser.verify(line + [0x00]).isWired)
        #expect(!SudoLocalParser.verify([0x1B] + line).isWired)
    }

    @Test("non-ASCII text inside a comment is read as OpenPAM reads it: ignored")
    func nonASCIIInComment() {
        let line = "auth requisite \(module)"
        #expect(SudoLocalParser.verify("# managed by IT \u{2014} do not edit\n\(line)\n") == .wired)
        #expect(SudoLocalParser.verify("\(line) # caf\u{E9}\n") == .wired)
        #expect(SudoLocalParser.verify("\(line)#\u{2014}tag\n") == .wired)
        #expect(SudoLocalParser.verify("# it\u{2019}s \"quoted\"\n\(line)\n") == .wired)
        // CR and backslashes stay refused even inside a comment: a backslash
        // ending a comment line continues it, and a CR moves where it ends.
        #expect(!SudoLocalParser.verify("# note\r\n\(line)\n").isWired)
        #expect(!SudoLocalParser.verify("# note \\\n\(line)\n").isWired)
        #expect(!SudoLocalParser.verify("# C:\\path\n\(line)\n").isWired)
    }

    /// The header `serberus_pam_merge_sudo_local` writes above a sudo_local it
    /// creates: `SERBERUS_PAM_CREATED_HEADER` with `SERBERUS_PAM_CREATED_TAG`
    /// expanded. test-pam-lib.sh checks this literal against pam-lib.sh.
    static let installerCreatedHeader = "# sudo_local: created by com.herojoneslabs.serberus # serberus-created"

    private static let repositoryRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private static let pamLibPath = repositoryRoot.appendingPathComponent("PKG/Scripts/pam-lib.sh").path
    private static let templatePath = repositoryRoot.appendingPathComponent("Support/sudo_local").path

    /// Runs `serberus_pam_merge_sudo_local` from the real pam-lib.sh on
    /// `sudoLocal` (with the shipped template), returning what it printed.
    private func installerMerge(_ sudoLocal: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", "source \"$1\" && serberus_pam_merge_sudo_local \"$2\" \"$3\"",
                             "merge", Self.pamLibPath, sudoLocal, Self.templatePath]
        let out = Pipe()
        process.standardOutput = out
        try process.run()
        let printed = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: printed, as: UTF8.self)
    }

    private func scratchDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-sudo-local-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test("the header literal is the one pam-lib.sh defines")
    func installerHeaderMatchesPamLib() throws {
        let lib = try String(contentsOfFile: Self.pamLibPath, encoding: .utf8)
        func value(_ name: String) -> String? {
            lib.split(separator: "\n").first { $0.hasPrefix("\(name)=\"") }
                .map { String($0.dropFirst(name.count + 2).dropLast()) }
        }
        let tag = try #require(value("SERBERUS_PAM_CREATED_TAG"))
        let header = try #require(value("SERBERUS_PAM_CREATED_HEADER"))
        #expect(header.replacingOccurrences(of: "${SERBERUS_PAM_CREATED_TAG}", with: tag)
                == Self.installerCreatedHeader)
    }

    @Test("the shipped Support/sudo_local template, as the installer writes it, reads as wired")
    func shippedTemplate() throws {
        let body = try Data(contentsOf: URL(fileURLWithPath: Self.templatePath))
        let written = Array((Self.installerCreatedHeader + "\n").utf8) + Array(body)
        #expect(SudoLocalParser.verify(written) == .wired)
        // The template itself stays plain ASCII.
        #expect(body.allSatisfy { $0 < 0x80 })

        // And the file the installer's own create path writes.
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sudoLocal = dir.appendingPathComponent("sudo_local").path
        #expect(try installerMerge(sudoLocal) == "created")
        let created = try Data(contentsOf: URL(fileURLWithPath: sudoLocal))
        #expect(Array(created) == written)
        #expect(SudoLocalParser.verify(Array(created)) == .wired)
    }

    @Test("an existing Touch ID sudo_local, merged by the installer, reads as wired",
          arguments: ["auth       sufficient     pam_tid.so\n",
                      "# sudo_local: local config file which survives system update\nauth sufficient pam_tid.so\n",
                      "AUTH sufficient pam_tid.so\n",
                      "Auth sufficient pam_tid.so # Touch ID\nauth requisite pam_serberus.so\n"])
    func mergedTouchID(existing: String) throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sudoLocal = dir.appendingPathComponent("sudo_local").path
        try Data(existing.utf8).write(to: URL(fileURLWithPath: sudoLocal))
        #expect(!SudoLocalParser.verify(existing).isWired)
        #expect(try installerMerge(sudoLocal) == "merged")
        let merged = try Data(contentsOf: URL(fileURLWithPath: sudoLocal))
        #expect(SudoLocalParser.verify(Array(merged)) == .wired)
        // The user's Touch ID line is kept, below Serberus.
        #expect(String(decoding: merged, as: UTF8.self).contains("pam_tid.so"))
        // A second merge finds it canonical.
        #expect(try installerMerge(sudoLocal) == "present")
    }

    @Test("`#` glued to the module path starts a comment, leaving the exact path")
    func hashGluedToPath() {
        #expect(SudoLocalParser.verify("auth requisite \(module)#x\n") == .wired)
        #expect(SudoLocalParser.verify("auth requisite \(module)# serberus-managed\n") == .wired)
    }

    @Test("a line with no valid facility anywhere is NOT wired (OpenPAM rejects the whole file)")
    func invalidFacility() {
        #expect(!SudoLocalParser.verify("auth requisite \(module)\nbogus required pam_permit.so\n").isWired)
        #expect(!SudoLocalParser.verify("auth requisite \(module)\nauth\n").isWired)
    }

    @Test("every active line is validated, not just the first auth line")
    func everyLineValidated() {
        for line in ["account bogus pam_permit.so", "session required", "password include",
                     "account include sudo_other extra", "auth substack sudo_other"] {
            let status = SudoLocalParser.verify("auth requisite \(module)\n\(line)\n")
            #expect(!status.isWired, "\(line) accepted")
            #expect(status.reasonText.contains("would fail to load"), "\(line): \(status.reasonText)")
        }
    }

    @Test("well-formed later lines stay wired, control flags in any case")
    func wellFormedLaterLines() {
        let text = """
        auth       requisite      \(module)
        auth       sufficient     pam_tid.so
        account    OPTIONAL       pam_permit.so debug
        password   Binding        pam_deny.so
        session    Required       pam_permit.so
        """
        #expect(SudoLocalParser.verify(text) == .wired)
    }
}

@Suite("SudoPolicyParser — /etc/pam.d/sudo includes sudo_local first")
struct SudoPolicyParserTests {
    @Test("the stock macOS policy is wired")
    func stock() {
        #expect(SudoPolicyParser.verify(FakePAMFileSystem.stockSudoPolicy) == .wired)
    }

    @Test("any auth line before the include is NOT wired (sufficient / binding / include / substack / required)")
    func anythingBeforeInclude() {
        for line in ["auth sufficient pam_tid.so", "auth binding pam_krb5.so", "auth include sudo_other",
                     "auth substack sudo_other", "auth required pam_opendirectory.so"] {
            let text = "\(line)\nauth include sudo_local\n"
            #expect(!SudoPolicyParser.verify(text).isWired, "\(line) accepted above the include")
        }
    }

    @Test("a missing include is NOT wired; a commented-out include does not count")
    func missingInclude() {
        #expect(!SudoPolicyParser.verify("auth required pam_opendirectory.so\n").isWired)
        #expect(!SudoPolicyParser.verify("# auth include sudo_local\nauth required pam_opendirectory.so\n").isWired)
        #expect(!SudoPolicyParser.verify("").isWired)
    }

    @Test("non-auth lines and comments above the include are fine")
    func nonAuthAbove() {
        #expect(SudoPolicyParser.verify("account required pam_permit.so\n# note\nauth include sudo_local\n") == .wired)
    }

    @Test("a capitalised auth line above the include is NOT wired")
    func capitalisedAuthAbove() {
        let status = SudoPolicyParser.verify("Auth sufficient pam_tid.so\nauth include sudo_local\n")
        #expect(!status.isWired)
        #expect(status.reasonText.contains("pam_tid.so"))
    }

    @Test("facility and `include` match in any case; the target must be exactly `sudo_local`")
    func includeCase() {
        #expect(SudoPolicyParser.verify("AUTH Include sudo_local\n") == .wired)
        #expect(!SudoPolicyParser.verify("auth include SUDO_LOCAL\n").isWired)
        #expect(!SudoPolicyParser.verify("auth include sudo_local.\n").isWired)
    }

    @Test("an include with words after its target is NOT wired — OpenPAM rejects the file")
    func includeTrailingWords() {
        let status = SudoPolicyParser.verify("auth include sudo_local extra\n")
        #expect(!status.isWired)
        #expect(status.reasonText.contains("would fail to load"))
        #expect(!SudoPolicyParser.verify("auth include sudo_local # note\nauth include\n").isWired)
    }

    @Test("a malformed line anywhere after the include is NOT wired")
    func malformedLaterLine() {
        let text = FakePAMFileSystem.stockSudoPolicy + "\naccount bogus pam_permit.so\n"
        let status = SudoPolicyParser.verify(text)
        #expect(!status.isWired)
        #expect(status.reasonText.contains("account bogus pam_permit.so"))
    }

    @Test("a quoted include target is NOT wired — OpenPAM looks for a file named with the quotes and skips it")
    func quotedInclude() {
        #expect(!SudoPolicyParser.verify("auth include \"sudo_local\"\n").isWired)
        #expect(!SudoPolicyParser.verify("auth include 'sudo_local'\n").isWired)
    }

    @Test("CR line endings, backslashes and non-ASCII bytes are NOT wired; \\v separators are read as whitespace")
    func unusualBytes() {
        #expect(!SudoPolicyParser.verify(FakePAMFileSystem.stockSudoPolicy.replacingOccurrences(of: "\n", with: "\r\n")).isWired)
        #expect(!SudoPolicyParser.verify("auth include \\\n sudo_local\n").isWired)
        #expect(!SudoPolicyParser.verify(Array("auth include sudo_local\n".utf8) + [0xE2, 0x80, 0x8B]).isWired)
        #expect(SudoPolicyParser.verify("auth\u{0B}include\u{0B}sudo_local\n") == .wired)
        #expect(!SudoPolicyParser.verify("auth\u{0B}sufficient\u{0B}pam_tid.so\nauth include sudo_local\n").isWired)
    }
}

@Suite("OpenPAMTokenizer — macOS (Hydrangea) OpenPAM word/comment rules")
struct OpenPAMTokenizerTests {
    @Test("`#` starts a comment anywhere, even inside a word")
    func hashAnywhere() {
        #expect(OpenPAMTokenizer.lines("auth requisite /x/pam_serberus.so#tag\n")
                == [["auth", "requisite", "/x/pam_serberus.so"]])
        #expect(OpenPAMTokenizer.lines("auth requisite /x.so #comment here\n") == [["auth", "requisite", "/x.so"]])
        #expect(OpenPAMTokenizer.lines("# whole line\n   #indented\n").isEmpty)
    }

    @Test("quotes are ordinary bytes: they neither group words nor get removed")
    func quotes() {
        #expect(OpenPAMTokenizer.lines("auth required /x.so \"arg with spaces\" 'single'\n")
                == [["auth", "required", "/x.so", "\"arg", "with", "spaces\"", "'single'"]])
    }

    @Test("backslash-newline continues the logical line; a comment swallows its backslash; elsewhere `\\` is literal")
    func continuations() {
        #expect(OpenPAMTokenizer.lines("auth \\\n  requisite \\\n /x.so\n") == [["auth", "requisite", "/x.so"]])
        #expect(OpenPAMTokenizer.lines("# comment \\\nauth requisite /x.so\n") == [["auth", "requisite", "/x.so"]])
        #expect(OpenPAMTokenizer.lines("auth requisite /x\\ y.so\n") == [["auth", "requisite", "/x\\", "y.so"]])
        // Trailing blanks after the backslash are trimmed first, so it still continues.
        #expect(OpenPAMTokenizer.lines("auth \\  \nrequisite /x.so\n") == [["auth", "requisite", "/x.so"]])
    }

    @Test("a CRLF comment ends at the LF (bytes, not Characters); CR, VT and FF are whitespace")
    func byteLevelWhitespace() {
        #expect(OpenPAMTokenizer.lines("# c\r\nauth x y\r\n") == [["auth", "x", "y"]])
        #expect(OpenPAMTokenizer.lines("auth\u{0B}x\u{0C}y\n") == [["auth", "x", "y"]])
        #expect(OpenPAMTokenizer.lines("  auth   x\t\ty  \n\n\nnext line") == [["auth", "x", "y"], ["next", "line"]])
    }
}

private extension PAMGateStatus {
    var reasonText: String {
        if case let .notWired(reason) = self { return reason }
        return ""
    }
}

// MARK: - Filesystem verifier (injected filesystem)

/// Dictionary-backed ``PAMGateFileSystem``.
private struct FakePAMFileSystem: PAMGateFileSystem {
    var infos: [String: PAMGateFileInfo]
    var contents: [String: String]

    /// Raw bytes that override `contents` (non-UTF-8 content).
    var bytes: [String: [UInt8]] = [:]

    func info(_ path: String) -> PAMGateFileInfo? { infos[path] }
    func read(_ path: String) -> [UInt8]? { bytes[path] ?? contents[path].map { Array($0.utf8) } }

    static let sudoPolicy = FilesystemPAMGateVerifier.defaultSudoPolicyPath
    static let sudoLocal = FilesystemPAMGateVerifier.defaultSudoLocalPath
    static let module = FilesystemPAMGateVerifier.defaultModulePath
    /// The stock macOS `/etc/pam.d/sudo`.
    static let stockSudoPolicy = """
        # sudo: auth account password session
        auth       include        sudo_local
        auth       sufficient     pam_smartcard.so
        auth       required       pam_opendirectory.so
        account    required       pam_permit.so
        password   required       pam_deny.so
        session    required       pam_permit.so
        """

    /// The modules the stock policy names, as they ship in the sealed
    /// `/usr/lib/pam` (versioned `.2` files).
    static let sealedModules = ["pam_smartcard.so", "pam_opendirectory.so", "pam_permit.so",
                                "pam_deny.so", "pam_tid.so"]

    /// A correctly wired, root-owned installation.
    static func wired() -> FakePAMFileSystem {
        let dir = PAMGateFileInfo(kind: .directory, uid: 0, mode: 0o755)
        var infos: [String: PAMGateFileInfo] = [
            sudoPolicy: PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444),
            sudoLocal: PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o644),
            module: PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o644),
            "/usr": dir, "/usr/local": dir, "/usr/local/lib": dir, "/usr/local/lib/pam": dir,
            "/usr/lib": dir, "/usr/lib/pam": dir,
        ]
        for name in sealedModules {
            infos["/usr/lib/pam/\(name).2"] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        }
        return FakePAMFileSystem(
            infos: infos,
            contents: [sudoLocal: "auth       requisite      \(module) # serberus-managed\n",
                       sudoPolicy: stockSudoPolicy]
        )
    }
}

@Suite("FilesystemPAMGateVerifier")
struct FilesystemPAMGateVerifierTests {
    private func verify(_ fs: FakePAMFileSystem) -> PAMGateStatus {
        FilesystemPAMGateVerifier(fileSystem: fs).verify()
    }

    @Test("a correctly wired, root-owned install verifies")
    func wired() {
        #expect(verify(.wired()) == .wired)
    }

    @Test("missing sudo_local is NOT wired")
    func missingFile() {
        var fs = FakePAMFileSystem.wired()
        fs.infos[FakePAMFileSystem.sudoLocal] = nil
        fs.contents[FakePAMFileSystem.sudoLocal] = nil
        #expect(!verify(fs).isWired)
    }

    @Test("sudo_local as a symlink is NOT wired (lstat, never followed)")
    func symlinkedSudoLocal() {
        var fs = FakePAMFileSystem.wired()
        fs.infos[FakePAMFileSystem.sudoLocal] = PAMGateFileInfo(kind: .symlink, uid: 0, mode: 0o755)
        #expect(!verify(fs).isWired)
    }

    @Test("sudo_local not owned by root, or group/other-writable, is NOT wired")
    func sudoLocalOwnership() {
        var fs = FakePAMFileSystem.wired()
        fs.infos[FakePAMFileSystem.sudoLocal] = PAMGateFileInfo(kind: .regular, uid: 501, mode: 0o644)
        #expect(!verify(fs).isWired)
        fs.infos[FakePAMFileSystem.sudoLocal] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o666)
        #expect(!verify(fs).isWired)
    }

    @Test("a missing, non-root, or group-writable module is NOT wired")
    func moduleChecks() {
        var fs = FakePAMFileSystem.wired()
        fs.infos[FakePAMFileSystem.module] = nil
        #expect(!verify(fs).isWired)
        fs.infos[FakePAMFileSystem.module] = PAMGateFileInfo(kind: .regular, uid: 501, mode: 0o644)
        #expect(!verify(fs).isWired)
        fs.infos[FakePAMFileSystem.module] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o664)
        #expect(!verify(fs).isWired)
        fs.infos[FakePAMFileSystem.module] = PAMGateFileInfo(kind: .symlink, uid: 0, mode: 0o755)
        #expect(!verify(fs).isWired)
    }

    @Test("a user-owned or group-writable parent directory is NOT wired (module swappable)")
    func parentDirectoryChecks() {
        for parent in ["/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/pam"] {
            var fs = FakePAMFileSystem.wired()
            fs.infos[parent] = PAMGateFileInfo(kind: .directory, uid: 501, mode: 0o755)
            #expect(!verify(fs).isWired, "user-owned \(parent) accepted")
            fs.infos[parent] = PAMGateFileInfo(kind: .directory, uid: 0, mode: 0o775)
            #expect(!verify(fs).isWired, "group-writable \(parent) accepted")
            fs.infos[parent] = PAMGateFileInfo(kind: .symlink, uid: 0, mode: 0o755)
            #expect(!verify(fs).isWired, "symlinked \(parent) accepted")
        }
    }

    @Test("/etc/pam.d/sudo must exist, be a root-owned regular file, not group/other-writable")
    func sudoPolicyFileChecks() {
        var fs = FakePAMFileSystem.wired()
        fs.infos[FakePAMFileSystem.sudoPolicy] = nil
        #expect(!verify(fs).isWired)
        fs = .wired()
        fs.infos[FakePAMFileSystem.sudoPolicy] = PAMGateFileInfo(kind: .symlink, uid: 0, mode: 0o755)
        #expect(!verify(fs).isWired)
        fs.infos[FakePAMFileSystem.sudoPolicy] = PAMGateFileInfo(kind: .regular, uid: 501, mode: 0o444)
        #expect(!verify(fs).isWired)
        fs.infos[FakePAMFileSystem.sudoPolicy] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o664)
        #expect(!verify(fs).isWired)
    }

    @Test("/etc/pam.d/sudo with Touch ID above the include, or no include, is NOT wired")
    func sudoPolicyContent() {
        var fs = FakePAMFileSystem.wired()
        fs.contents[FakePAMFileSystem.sudoPolicy] = """
            auth       sufficient     pam_tid.so
            auth       include        sudo_local
            auth       required       pam_opendirectory.so
            """
        let above = verify(fs)
        #expect(!above.isWired)
        #expect(above.reasonText.contains("pam_tid.so"))

        fs.contents[FakePAMFileSystem.sudoPolicy] = """
            auth       sufficient     pam_smartcard.so
            auth       required       pam_opendirectory.so
            """
        #expect(!verify(fs).isWired)
    }

    @Test("any other file OpenPAM could load sudo's policy from is NOT wired",
          arguments: FilesystemPAMGateVerifier.defaultShadowingPolicyPaths)
    func shadowingPolicyFile(path: String) {
        var fs = FakePAMFileSystem.wired()
        fs.infos[path] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o644)
        let status = verify(fs)
        #expect(!status.isWired)
        #expect(status.reasonText.contains(path))
        // A symlink there (even a dangling one) counts too.
        fs.infos[path] = PAMGateFileInfo(kind: .symlink, uid: 0, mode: 0o755)
        #expect(!verify(fs).isWired)
    }

    @Test("the shadowing paths cover the managed, /etc and /usr/local locations for sudo and sudo_local")
    func shadowingPathList() {
        let paths = Set(FilesystemPAMGateVerifier.defaultShadowingPolicyPaths)
        let managed = "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc"
        for path in ["\(managed)/pam.d/sudo", "\(managed)/pam.d/sudo_local", "\(managed)/pam.conf",
                     "/etc/pam.conf", "/usr/local/etc/pam.d/sudo", "/usr/local/etc/pam.d/sudo_local",
                     "/usr/local/etc/pam.conf"] {
            #expect(paths.contains(path), "\(path) not checked")
        }
        #expect(!paths.contains(FilesystemPAMGateVerifier.defaultSudoPolicyPath))
        #expect(!paths.contains(FilesystemPAMGateVerifier.defaultSudoLocalPath))
    }

    @Test("the shadowing paths are injectable")
    func shadowingPathsInjectable() {
        var fs = FakePAMFileSystem.wired()
        fs.infos["/custom/pam.d/sudo"] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o644)
        #expect(FilesystemPAMGateVerifier(shadowingPolicyPaths: [], fileSystem: fs).verify() == .wired)
        #expect(!FilesystemPAMGateVerifier(shadowingPolicyPaths: ["/custom/pam.d/sudo"], fileSystem: fs)
            .verify().isWired)
    }

    @Test("non-UTF-8 or CRLF content in either file is NOT wired")
    func unusualFileBytes() {
        var fs = FakePAMFileSystem.wired()
        fs.bytes[FakePAMFileSystem.sudoLocal] = Array("auth requisite \(FakePAMFileSystem.module)\n".utf8) + [0xFF]
        #expect(!verify(fs).isWired)
        fs = .wired()
        fs.contents[FakePAMFileSystem.sudoPolicy] = "auth include sudo_local\r\n"
        #expect(!verify(fs).isWired)
    }

    @Test("a versioned module beside the real one is NOT wired — OpenPAM loads <path>.2 first")
    func versionedModule() {
        var fs = FakePAMFileSystem.wired()
        let versioned = FakePAMFileSystem.module + ".2"
        fs.infos[versioned] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        let status = verify(fs)
        #expect(!status.isWired)
        #expect(status.reasonText.contains(versioned))
    }

    @Test("a policy file longer than the cap is NOT wired, never judged on its prefix")
    func oversizedPolicyFiles() {
        let cap = FilesystemPAMGateVerifier.maxPolicyBytes
        let line = Array("auth requisite \(FakePAMFileSystem.module)\n".utf8)
        // Exactly the cap (padded with a comment) is still read.
        let padding = [UInt8(ascii: "#")] + [UInt8](repeating: UInt8(ascii: "x"), count: cap - line.count - 2)
            + [UInt8(ascii: "\n")]
        var fs = FakePAMFileSystem.wired()
        fs.bytes[FakePAMFileSystem.sudoLocal] = line + padding
        #expect(fs.bytes[FakePAMFileSystem.sudoLocal]?.count == cap)
        #expect(verify(fs) == .wired)

        fs.bytes[FakePAMFileSystem.sudoLocal] = line + padding + [UInt8(ascii: "x")]
        let local = verify(fs)
        #expect(!local.isWired)
        #expect(local.reasonText.contains("longer than"))

        fs = .wired()
        fs.bytes[FakePAMFileSystem.sudoPolicy] = Array(FakePAMFileSystem.stockSudoPolicy.utf8)
            + [UInt8](repeating: UInt8(ascii: "\n"), count: cap)
        #expect(!verify(fs).isWired)
    }

    @Test("the system filesystem reads one byte past the cap, so a longer file is detectable")
    func systemReadCap() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("big").path
        let cap = FilesystemPAMGateVerifier.maxPolicyBytes
        try Data(repeating: UInt8(ascii: "\n"), count: cap + 100).write(to: URL(fileURLWithPath: file))
        #expect(SystemPAMGateFileSystem().read(file)?.count == cap + 1)
    }

    @Test("the system filesystem treats only a definite ENOENT/ENOTDIR as absent")
    func systemExists() throws {
        let system = SystemPAMGateFileSystem()
        #expect(system.exists("/"))
        #expect(!system.exists("/no-such-dir-\(UUID().uuidString)/sudo"))
        #expect(!system.exists("/etc/hosts/sudo")) // ENOTDIR
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let link = dir.appendingPathComponent("dangling").path
        #expect(symlink("/no-such-target-\(UUID().uuidString)", link) == 0)
        #expect(system.exists(link))
        let file = dir.appendingPathComponent("f").path
        try Data([0x61, 0xFF, 0x0A]).write(to: URL(fileURLWithPath: file))
        #expect(system.read(file) == [0x61, 0xFF, 0x0A])
    }

    @Test("modules the policies name by bare name in the sealed /usr/lib/pam are accepted")
    func sealedBareModules() {
        var fs = FakePAMFileSystem.wired()
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module) # serberus-managed
            auth       sufficient     pam_tid.so
            """
        #expect(verify(fs) == .wired)
        // Even with the sealed directory itself not root-only in the fixture:
        // nothing there can be replaced.
        fs.infos["/usr/lib/pam"] = PAMGateFileInfo(kind: .directory, uid: 501, mode: 0o777)
        #expect(verify(fs) == .wired)
    }

    @Test("Homebrew's pam_reattach under a user-owned /opt/homebrew is NOT wired, with the reason")
    func userOwnedHomebrewModule() {
        var fs = FakePAMFileSystem.wired()
        let reattach = "/opt/homebrew/lib/pam/pam_reattach.so"
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module) # serberus-managed
            auth       optional       \(reattach) ignore_ssh
            auth       sufficient     pam_tid.so
            """
        fs.infos["/opt"] = PAMGateFileInfo(kind: .directory, uid: 0, mode: 0o755)
        fs.infos["/opt/homebrew"] = PAMGateFileInfo(kind: .directory, uid: 501, mode: 0o755)
        fs.infos["/opt/homebrew/lib"] = PAMGateFileInfo(kind: .directory, uid: 501, mode: 0o755)
        fs.infos["/opt/homebrew/lib/pam"] = PAMGateFileInfo(kind: .directory, uid: 501, mode: 0o755)
        fs.infos[reattach] = PAMGateFileInfo(kind: .regular, uid: 501, mode: 0o644)
        let status = verify(fs)
        #expect(!status.isWired)
        #expect(status.reasonText.contains(reattach))
        #expect(status.reasonText.contains("/opt/homebrew is owned by uid 501, not root"))

        // The same module on a root-only path is fine.
        for path in ["/opt/homebrew", "/opt/homebrew/lib", "/opt/homebrew/lib/pam"] {
            fs.infos[path] = PAMGateFileInfo(kind: .directory, uid: 0, mode: 0o755)
        }
        fs.infos[reattach] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        #expect(verify(fs) == .wired)
        // ...until the module itself is a symlink, as a Homebrew keg link is.
        fs.infos[reattach] = PAMGateFileInfo(kind: .symlink, uid: 0, mode: 0o755)
        #expect(!verify(fs).isWired)
    }

    @Test("a module in /etc/pam.d/sudo is checked too")
    func moduleInSudoPolicy() {
        var fs = FakePAMFileSystem.wired()
        fs.contents[FakePAMFileSystem.sudoPolicy] = FakePAMFileSystem.stockSudoPolicy
            + "\nsession    optional       /Users/Shared/pam_x.so\n"
        fs.infos["/Users"] = PAMGateFileInfo(kind: .directory, uid: 0, mode: 0o755)
        fs.infos["/Users/Shared"] = PAMGateFileInfo(kind: .directory, uid: 0, mode: 0o1777)
        fs.infos["/Users/Shared/pam_x.so"] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o644)
        let status = verify(fs)
        #expect(!status.isWired)
        #expect(status.reasonText.contains(FakePAMFileSystem.sudoPolicy))
        #expect(status.reasonText.contains("/Users/Shared is group/other-writable"))
    }

    @Test("a bare name not in /usr/lib/pam is judged where OpenPAM finds it, in /usr/local/lib/pam")
    func bareModuleInLocalDirectory() {
        var fs = FakePAMFileSystem.wired()
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module)
            auth       optional       pam_local_extra.so
            """
        // Nowhere at all: sudo could not load it.
        let missing = verify(fs)
        #expect(!missing.isWired)
        #expect(missing.reasonText.contains("in neither /usr/lib/pam nor /usr/local/lib/pam"))

        let local = "/usr/local/lib/pam/pam_local_extra.so"
        fs.infos[local] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        #expect(verify(fs) == .wired)
        fs.infos[local] = PAMGateFileInfo(kind: .regular, uid: 501, mode: 0o444)
        #expect(!verify(fs).isWired)
        // A versioned file wins over the plain one, so it is the one judged.
        fs.infos[local] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        fs.infos[local + ".2"] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o666)
        #expect(!verify(fs).isWired)
        // A copy in the sealed directory takes precedence over /usr/local.
        fs.infos["/usr/lib/pam/pam_local_extra.so.2"] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        #expect(verify(fs) == .wired)
    }

    @Test("an absolute module path is judged as OpenPAM loads it: <path>.2 first")
    func absoluteModuleVersioned() {
        var fs = FakePAMFileSystem.wired()
        let extra = "/usr/local/lib/pam/pam_extra.so"
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module)
            account    required       \(extra)
            """
        fs.infos[extra] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        #expect(verify(fs) == .wired)
        fs.infos[extra + ".2"] = PAMGateFileInfo(kind: .regular, uid: 501, mode: 0o444)
        let status = verify(fs)
        #expect(!status.isWired)
        #expect(status.reasonText.contains(extra + ".2"))
    }

    @Test("a relative module path is NOT wired")
    func relativeModulePath() {
        var fs = FakePAMFileSystem.wired()
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module)
            auth       optional       lib/pam_x.so
            """
        let status = verify(fs)
        #expect(!status.isWired)
        #expect(status.reasonText.contains("relative path"))
    }

    @Test("the stock /etc/pam.d/sudo plus a normal sudo_local is still wired: its include is the one allowed")
    func stockSudoLocalInclude() {
        var fs = FakePAMFileSystem.wired()
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module) # serberus-managed
            auth       sufficient     pam_tid.so
            """
        #expect(verify(fs) == .wired)
        // Found as SudoPolicyParser finds it: the first auth line, in any case.
        fs.contents[FakePAMFileSystem.sudoPolicy] = """
            account    required       pam_permit.so
            AUTH       Include        sudo_local
            auth       required       pam_opendirectory.so
            """
        #expect(verify(fs) == .wired)
    }

    @Test("sudo_local pulling pam_reattach in with `auth include` is NOT wired, with the reason")
    func includedHomebrewModule() {
        var fs = FakePAMFileSystem.wired()
        // The admin keeps pam_reattach, under a user-owned /opt/homebrew, in a
        // policy of its own…
        let reattach = "/opt/homebrew/lib/pam/pam_reattach.so"
        let included = "/etc/pam.d/sudo_reattach"
        fs.infos[included] = PAMGateFileInfo(kind: .regular, uid: 0, mode: 0o444)
        fs.contents[included] = "auth       optional       \(reattach) ignore_ssh\n"
        fs.infos["/opt"] = PAMGateFileInfo(kind: .directory, uid: 0, mode: 0o755)
        for path in ["/opt/homebrew", "/opt/homebrew/lib", "/opt/homebrew/lib/pam"] {
            fs.infos[path] = PAMGateFileInfo(kind: .directory, uid: 501, mode: 0o755)
        }
        fs.infos[reattach] = PAMGateFileInfo(kind: .regular, uid: 501, mode: 0o644)
        // …and pulls it in from sudo_local, below Serberus's line.
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module) # serberus-managed
            auth       include        sudo_reattach
            auth       sufficient     pam_tid.so
            """
        let status = verify(fs)
        #expect(!status.isWired)
        let reason = status.reasonText
        #expect(reason.hasPrefix(
            "\(FakePAMFileSystem.sudoLocal): 'auth include sudo_reattach' includes another policy"))
        #expect(reason.contains("doesn't check the modules an included policy loads into sudo as root"))

        // Includes aren't followed: what the target holds doesn't matter, nor
        // whether /etc/pam.d has it at all (OpenPAM looks in other policy
        // directories too).
        fs.contents[included] = "auth       sufficient     pam_tid.so\n"
        #expect(!verify(fs).isWired)
        fs.infos[included] = nil
        fs.contents[included] = nil
        #expect(!verify(fs).isWired)

        // Without the include, sudo loads nothing from /opt/homebrew.
        fs.contents[FakePAMFileSystem.sudoLocal] = """
            auth       requisite      \(FakePAMFileSystem.module) # serberus-managed
            auth       sufficient     pam_tid.so
            """
        #expect(verify(fs) == .wired)
    }

    @Test("any include in sudo_local is NOT wired, whatever its facility or case")
    func includeInSudoLocal() {
        let serberus = "auth requisite \(FakePAMFileSystem.module)"
        for line in ["session include sudo_other", "ACCOUNT INCLUDE x", "password Include sudo_other"] {
            var fs = FakePAMFileSystem.wired()
            fs.contents[FakePAMFileSystem.sudoLocal] = "\(serberus)\n\(line)\n"
            let status = verify(fs)
            #expect(!status.isWired, "\(line) accepted")
            #expect(status.reasonText.hasPrefix("\(FakePAMFileSystem.sudoLocal): '\(line)' includes another policy"),
                    "\(line): \(status.reasonText)")
            // Above Serberus's line too, where lines of other facilities are otherwise fine.
            fs.contents[FakePAMFileSystem.sudoLocal] = "\(line)\n\(serberus)\n"
            #expect(!verify(fs).isWired, "\(line) accepted above Serberus")
        }
    }

    @Test("a second include in /etc/pam.d/sudo is NOT wired; only its first auth line may include sudo_local")
    func secondIncludeInSudoPolicy() {
        let stock = FakePAMFileSystem.stockSudoPolicy
        for line in ["account include sudo_account", "auth include sudo_local", "SESSION Include sudo_other"] {
            var fs = FakePAMFileSystem.wired()
            fs.contents[FakePAMFileSystem.sudoPolicy] = "\(stock)\n\(line)\n"
            let status = verify(fs)
            #expect(!status.isWired, "\(line) accepted")
            #expect(status.reasonText.hasPrefix("\(FakePAMFileSystem.sudoPolicy): '\(line)' includes another policy"),
                    "\(line): \(status.reasonText)")
            // Above the stock include too.
            fs.contents[FakePAMFileSystem.sudoPolicy] = "\(line)\n\(stock)\n"
            #expect(!verify(fs).isWired, "\(line) accepted above the stock include")
        }
    }

    @Test("an ACL granting write to a non-root account fails every root-only check")
    func aclWritability() {
        let aclWritable = { (kind: PAMGateFileInfo.Kind, mode: mode_t) in
            PAMGateFileInfo(kind: kind, uid: 0, mode: mode, aclGrantsNonRootWrite: true)
        }
        for parent in ["/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/pam"] {
            var fs = FakePAMFileSystem.wired()
            fs.infos[parent] = aclWritable(.directory, 0o755)
            let status = verify(fs)
            #expect(!status.isWired, "ACL-writable \(parent) accepted")
            #expect(status.reasonText.contains("ACL"), "\(parent): \(status.reasonText)")
        }
        for file in [FakePAMFileSystem.module, FakePAMFileSystem.sudoLocal, FakePAMFileSystem.sudoPolicy] {
            var fs = FakePAMFileSystem.wired()
            fs.infos[file] = aclWritable(.regular, 0o444)
            let status = verify(fs)
            #expect(!status.isWired, "ACL-writable \(file) accepted")
            #expect(status.reasonText.contains("ACL"), "\(file): \(status.reasonText)")
        }
    }

    @Test("the system filesystem reads ACLs: allow-write for others counts, deny and root don't")
    func systemACLs() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        func chmodACL(_ entry: String, _ path: String) throws -> Bool {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", entry, path]
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        }
        func fresh(_ name: String, directory: Bool = true) throws -> String {
            let path = dir.appendingPathComponent(name).path
            if directory {
                try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
            } else {
                FileManager.default.createFile(atPath: path, contents: Data("x".utf8))
            }
            return path
        }
        let system = SystemPAMGateFileSystem()

        let plain = try fresh("plain")
        #expect(system.info(plain)?.aclGrantsNonRootWrite == false)
        #expect(!PAMGateACL.grantsNonRootWrite(plain))

        let userWrite = try fresh("user-write")
        guard try chmodACL("user:nobody allow add_file,delete_child", userWrite) else { return }
        #expect(PAMGateACL.grantsNonRootWrite(userWrite))
        #expect(system.info(userWrite)?.isLooselyWritable == true)

        let groupWrite = try fresh("group-write")
        #expect(try chmodACL("group:staff allow add_subdirectory", groupWrite))
        #expect(PAMGateACL.grantsNonRootWrite(groupWrite))

        let everyoneWrite = try fresh("everyone-file", directory: false)
        #expect(try chmodACL("everyone allow write", everyoneWrite))
        #expect(PAMGateACL.grantsNonRootWrite(everyoneWrite))

        let denyOnly = try fresh("deny-only")
        #expect(try chmodACL("user:nobody deny add_file,delete_child", denyOnly))
        #expect(!PAMGateACL.grantsNonRootWrite(denyOnly))

        let readOnly = try fresh("read-only")
        #expect(try chmodACL("user:nobody allow list,search,readattr", readOnly))
        #expect(!PAMGateACL.grantsNonRootWrite(readOnly))

        let rootWrite = try fresh("root-write")
        #expect(try chmodACL("user:root allow add_file,delete_child", rootWrite))
        #expect(!PAMGateACL.grantsNonRootWrite(rootWrite))

        let inheritOnly = try fresh("inherit-only")
        #expect(try chmodACL("user:nobody allow add_file,file_inherit,only_inherit", inheritOnly))
        #expect(PAMGateACL.grantsNonRootWrite(inheritOnly))
    }

    @Test("parentDirectories enumerates every ancestor of the module")
    func parents() {
        #expect(FilesystemPAMGateVerifier.parentDirectories(of: "/usr/local/lib/pam/pam_serberus.so")
                == ["/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/pam"])
    }
}

// MARK: - Daemon wiring: withheld drop-in, degraded(pam_not_wired), recovery

/// A PAM gate whose verdict a test can flip between reload ticks.
final class MutablePAMGate: PAMGateVerifying, @unchecked Sendable {
    private let lock = NSLock()
    private var status: PAMGateStatus
    init(_ status: PAMGateStatus) { self.status = status }
    func set(_ status: PAMGateStatus) {
        lock.lock(); defer { lock.unlock() }
        self.status = status
    }
    func verify() -> PAMGateStatus {
        lock.lock(); defer { lock.unlock() }
        return status
    }
}

/// An authdb whose reconcile fails the first `failures` times.
actor FlakyAuthDB: AuthorizationDBApplying {
    private var failuresRemaining: Int
    private(set) var reconcileCount = 0
    init(failures: Int) { failuresRemaining = failures }
    func apply(profiles: [RuleProfile]) async throws {}
    func reconcile(profiles: [RuleProfile]) async throws {
        reconcileCount += 1
        if failuresRemaining > 0 {
            failuresRemaining -= 1
            throw GrantStoreError.openFailed(path: "authdb", code: 1, message: "mock restore failure")
        }
    }
}

@Suite("DaemonController — PAM gate + kill-switch authdb retry", .serialized)
struct DaemonPAMGateTests {
    private func enrolledEnforceConfig() -> [String: any Sendable] {
        var config = CoordinatorFixtures.enforceableConfig
        config["sudoEnrollment"] = ["users": ["standarduser"]] as [String: any Sendable]
        return config
    }

    private func makeController(
        config: [String: any Sendable],
        paths: DaemonPaths,
        sudoers: SudoersProvisioning,
        pamGate: PAMGateVerifying,
        authDB: AuthorizationDBApplying = NoopAuthorizationDBApplier()
    ) -> DaemonController {
        let source = DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: config,
            BundleConfig.rulesDomain: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()],
        ])
        return DaemonController(
            paths: paths,
            machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: source),
            grantStore: NullGrantStore(),
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil,
            decisionLogger: nil,
            pppc: StaticPPPCStatus(ready: true),
            authDB: authDB,
            sudoers: sudoers,
            pamGate: pamGate,
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            deviceSerial: "TESTSERIAL",
            now: { CoordinatorFixtures.now }
        )
    }

    @Test("gate NOT wired: drop-in removed (never applied), degraded(pam_not_wired); wiring it brings the drop-in back")
    func unwiredGateWithholdsDropInThenRecovers() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let sudoers = DaemonSudoersReconcileTests.ReconcileSpyProvisioner()
        let gate = MutablePAMGate(.notWired(reason: "test: pam_tid above serberus"))
        let controller = makeController(config: enrolledEnforceConfig(), paths: paths,
                                        sudoers: sudoers, pamGate: gate)

        await controller.reloadPolicyIfChanged()

        #expect(sudoers.applyCount == 0)          // the grant is never written…
        #expect(sudoers.removeCount == 1)         // …and any existing one is actively removed
        let degraded = await controller.healthReport()
        #expect(degraded.state == .degraded)
        #expect(degraded.degradedReason == .pamNotWired)

        // Nothing changed: the next tick is a no-op (signature unchanged).
        await controller.reloadPolicyIfChanged()
        #expect(sudoers.applyCount == 0)

        // The admin fixes sudo_local. No policy changed, but the gate verdict is
        // part of the signature, so the very next tick re-provisions.
        gate.set(.wired)
        await controller.reloadPolicyIfChanged()
        #expect(sudoers.applyCount == 1)
        #expect(await controller.healthReport().degradedReason != .pamNotWired)

        // …and a later UN-wiring removes it again.
        gate.set(.notWired(reason: "test: sudo_local rewritten"))
        await controller.reloadPolicyIfChanged()
        #expect(sudoers.removeCount == 2)
        #expect(await controller.healthReport().degradedReason == .pamNotWired)
    }

    @Test("gate NOT wired in monitor mode: no pam_not_wired (the drop-in is not wanted anyway)")
    func unwiredGateInMonitorModeIsNotDegraded() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        var config = enrolledEnforceConfig()
        config["enforcementMode"] = "monitor"
        let controller = makeController(config: config, paths: paths,
                                        sudoers: DaemonSudoersReconcileTests.ReconcileSpyProvisioner(),
                                        pamGate: StaticPAMGate(.notWired(reason: "test")))

        await controller.reloadPolicyIfChanged()

        #expect(await controller.healthReport().degradedReason != .pamNotWired)
    }

    @Test("kill switch whose authdb restore FAILS: degraded(authdb_failure), signature not committed, retried next tick")
    func killSwitchAuthDBRestoreRetried() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let authDB = FlakyAuthDB(failures: 1)
        let controller = makeController(config: ["daemonEnabled": false], paths: paths,
                                        sudoers: DaemonSudoersReconcileTests.ReconcileSpyProvisioner(),
                                        pamGate: AssumeWiredPAMGate(), authDB: authDB)

        await controller.reloadPolicyIfChanged()
        let failed = await controller.healthReport()
        #expect(failed.state == .degraded)
        #expect(failed.degradedReason == .authDBFailure)
        #expect(await authDB.reconcileCount == 1)

        // Same policy, but the failure left the signature uncommitted: retried.
        await controller.reloadPolicyIfChanged()
        #expect(await authDB.reconcileCount == 2)
        #expect(await controller.currentDaemonState() == .killSwitch)

        // Now committed: an unchanged policy no longer re-runs the teardown.
        await controller.reloadPolicyIfChanged()
        #expect(await authDB.reconcileCount == 2)
    }
}

// MARK: - State resolution

@Suite("StartupCoordinator — pam_not_wired + kill-switch restore failure")
struct PAMGateStateResolutionTests {
    @Test("pam_not_wired ranks below authdb_failure and above rule_parse_error / pending / healthy")
    func resolvePrecedence() {
        #expect(StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: true, rulesError: false,
            fdaReady: true, hasProfiles: true, pamNotWired: true).reason == .authDBFailure)
        #expect(StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false, rulesError: true,
            fdaReady: true, hasProfiles: true, pamNotWired: true).reason == .pamNotWired)
        #expect(StartupCoordinator.resolveState(
            configInvalid: false, grantsError: false, authDBError: false, rulesError: false,
            fdaReady: false, hasProfiles: false, pamNotWired: true).reason == .pamNotWired)
    }

    @Test("overlayPAMGate keeps higher-ranked states and overrides the rest")
    func overlay() {
        typealias C = StartupCoordinator
        #expect(C.overlayPAMGate(state: .healthy, reason: nil, pamNotWired: false) == (.healthy, nil))
        #expect(C.overlayPAMGate(state: .healthy, reason: nil, pamNotWired: true) == (.degraded, .pamNotWired))
        #expect(C.overlayPAMGate(state: .pendingPPPC, reason: nil, pamNotWired: true) == (.degraded, .pamNotWired))
        #expect(C.overlayPAMGate(state: .degraded, reason: .ruleParseError, pamNotWired: true) == (.degraded, .pamNotWired))
        #expect(C.overlayPAMGate(state: .degraded, reason: .configMissing, pamNotWired: true) == (.degraded, .configMissing))
        #expect(C.overlayPAMGate(state: .degraded, reason: .authDBFailure, pamNotWired: true) == (.degraded, .authDBFailure))
        #expect(C.overlayPAMGate(state: .killSwitch, reason: nil, pamNotWired: true) == (.killSwitch, nil))
        #expect(C.overlayPAMGate(state: .awaitingConfig, reason: nil, pamNotWired: true) == (.awaitingConfig, nil))
    }

    @Test("a startup kill switch whose authdb restore fails reports degraded(authdb_failure), not kill_switch")
    func startupKillSwitchRestoreFailure() async {
        let coordinator = StartupCoordinator(
            prefsReader: CoordinatorFixtures.prefs(config: ["daemonEnabled": false]),
            grantStore: MockGrantStore(), pppc: StaticPPPCStatus(ready: true),
            authDB: FailingAuthDB(), lastKnownGood: InMemoryLastKnownGoodConfigStore(),
            now: { CoordinatorFixtures.now }
        )
        let outcome = await coordinator.run()
        #expect(outcome.state == .degraded)
        #expect(outcome.degradedReason == .authDBFailure)
        #expect(outcome.profiles.isEmpty)
        #expect(!outcome.config.daemonEnabled) // still a kill switch: nothing is enforced
    }
}

// MARK: - Leaving enforce removes the drop-in first; managed-config watch

/// Records the order of sudoers + authdb side effects across both fakes.
final class SideEffectLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String] = []
    func append(_ entry: String) { lock.lock(); entries.append(entry); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return entries }
}

final class OrderedSudoers: SudoersProvisioning, @unchecked Sendable {
    let log: SideEffectLog
    init(log: SideEffectLog) { self.log = log }
    func apply(profiles: [RuleProfile], enrollment: SerberusConfig.SudoEnrollment) async -> Bool {
        log.append("sudoers.apply"); return true
    }
    func remove() async -> Bool { log.append("sudoers.remove"); return true }
}

struct OrderedAuthDB: AuthorizationDBApplying {
    let log: SideEffectLog
    func apply(profiles: [RuleProfile]) async throws { log.append("authdb.apply") }
    func reconcile(profiles: [RuleProfile]) async throws { log.append("authdb.reconcile") }
}

/// A break-glass resolver whose answer a test can flip.
final class MutableBypassResolver: BypassResolving, @unchecked Sendable {
    private let lock = NSLock()
    private var resolves: Bool
    init(resolves: Bool) { self.resolves = resolves }
    func set(_ value: Bool) { lock.lock(); resolves = value; lock.unlock() }
    func userResolves(_ name: String) -> Bool { lock.lock(); defer { lock.unlock() }; return resolves }
    func groupResolves(_ name: String) -> Bool { lock.lock(); defer { lock.unlock() }; return resolves }
}

@Suite("DaemonController — early drop-in removal + bypass_unresolvable", .serialized)
struct DaemonModeSwitchTests {
    private func enrolledConfig(mode: String = "enforce", bypassUsers: [String] = [],
                                bypassGroups: [String] = ["admin"]) -> [String: any Sendable] {
        [
            "daemonEnabled": true,
            "enforcementMode": mode,
            "pamBypass": ["groups": bypassGroups, "users": bypassUsers] as [String: any Sendable],
            "sudoEnrollment": ["users": ["standarduser"]] as [String: any Sendable],
        ]
    }

    private func makeController(source: MutablePreferencesSource, paths: DaemonPaths,
                                sudoers: SudoersProvisioning, authDB: AuthorizationDBApplying,
                                bypassResolver: BypassResolving = AssumeResolvableBypass()) -> DaemonController {
        DaemonController(
            paths: paths,
            machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: source),
            grantStore: NullGrantStore(),
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil,
            decisionLogger: nil,
            pppc: StaticPPPCStatus(ready: true),
            authDB: authDB,
            sudoers: sudoers,
            bypassResolver: bypassResolver,
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            deviceSerial: "TESTSERIAL",
            now: { CoordinatorFixtures.now }
        )
    }

    @Test("enforce → monitor: the drop-in is removed FIRST in that pass (before the authdb reconcile), exactly once")
    func leavingEnforceRemovesFirst() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SideEffectLog()
        let rules: [String: any Sendable] = ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()]
        let source = MutablePreferencesSource(domains: [
            BundleConfig.configDomain: enrolledConfig(), BundleConfig.rulesDomain: rules,
        ])
        let controller = makeController(source: source, paths: DaemonPaths.ephemeral(in: dir),
                                        sudoers: OrderedSudoers(log: log), authDB: OrderedAuthDB(log: log))
        await controller.reloadPolicyIfChanged()
        #expect(log.all.contains("sudoers.apply"))
        let before = log.all.count

        source.set([BundleConfig.configDomain: enrolledConfig(mode: "monitor"), BundleConfig.rulesDomain: rules])
        await controller.reloadPolicyIfChanged()
        let pass = Array(log.all.dropFirst(before))
        #expect(pass.first == "sudoers.remove")
        #expect(pass.filter { $0 == "sudoers.remove" }.count == 1)
        #expect(!pass.contains("sudoers.apply"))
    }

    @Test("enforce → kill switch: the drop-in is removed first, exactly once")
    func killSwitchRemovesFirst() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SideEffectLog()
        let source = MutablePreferencesSource(domains: [BundleConfig.configDomain: enrolledConfig()])
        let controller = makeController(source: source, paths: DaemonPaths.ephemeral(in: dir),
                                        sudoers: OrderedSudoers(log: log), authDB: OrderedAuthDB(log: log))
        await controller.reloadPolicyIfChanged()
        let before = log.all.count
        source.set([BundleConfig.configDomain: ["daemonEnabled": false]])
        await controller.reloadPolicyIfChanged()
        let pass = Array(log.all.dropFirst(before))
        #expect(pass.first == "sudoers.remove")
        #expect(pass.filter { $0 == "sudoers.remove" }.count == 1)
    }

    @Test("enforcing with a pamBypass none of whose entries resolves → degraded(bypass_unresolvable); fixed → clears")
    func bypassUnresolvableReported() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SideEffectLog()
        let resolver = MutableBypassResolver(resolves: false)
        let source = MutablePreferencesSource(domains: [
            BundleConfig.configDomain: enrolledConfig(bypassUsers: ["breakglsas"], bypassGroups: []),
            BundleConfig.rulesDomain: ["rules_sudo_test": CoordinatorFixtures.validProfileJSON()],
        ])
        let controller = makeController(source: source, paths: DaemonPaths.ephemeral(in: dir),
                                        sudoers: OrderedSudoers(log: log), authDB: OrderedAuthDB(log: log),
                                        bypassResolver: resolver)
        await controller.reloadPolicyIfChanged()
        let degraded = await controller.healthReport()
        #expect(degraded.state == .degraded)
        #expect(degraded.degradedReason == .bypassUnresolvable)
        #expect(degraded.enforcementMode == .enforce) // enforcement continues

        // The account appears — no policy key changed, but the next tick re-resolves.
        resolver.set(true)
        await controller.reloadPolicyIfChanged()
        #expect(await controller.healthReport().degradedReason != .bypassUnresolvable)
    }

    @Test("the managed-config watch fires (debounced) when the plist is atomically replaced")
    func managedConfigWatchFires() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let counter = SideEffectLog()
        let watch = ManagedConfigWatch(directory: dir.path, fileName: "x.plist", debounce: .milliseconds(100)) {
            counter.append("fired")
        }
        watch.start()
        defer { watch.stop() }
        try await Task.sleep(for: .milliseconds(200))
        try Data("a".utf8).write(to: dir.appendingPathComponent("x.plist"), options: .atomic)
        try Data("b".utf8).write(to: dir.appendingPathComponent("x.plist"), options: .atomic)
        var waited = 0
        while counter.all.isEmpty && waited < 50 {
            try await Task.sleep(for: .milliseconds(100))
            waited += 1
        }
        try await Task.sleep(for: .milliseconds(300))
        #expect(counter.all.count == 1) // two writes, one debounced reload
    }
}

@Suite("Break-glass resolvability")
struct BypassResolutionTests {
    private struct Table: BypassResolving {
        let users: Set<String>
        let groups: Set<String>
        func userResolves(_ name: String) -> Bool { users.contains(name) }
        func groupResolves(_ name: String) -> Bool { groups.contains(name) }
    }

    private func config(_ mode: EnforcementMode, users: [String] = [], groups: [String] = [],
                        enabled: Bool = true) -> SerberusConfig {
        SerberusConfig(jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
                       daemonEnabled: enabled, enforcementMode: mode, sudoCacheSeconds: 0,
                       promptTimeoutSeconds: 60, pamBypass: PAMBypass(groups: groups, users: users))
    }

    @Test("unresolvable only when enforcing with entries of which NONE resolves")
    func decision() {
        let table = Table(users: ["itadmin"], groups: ["admin"])
        #expect(BypassResolution.isUnresolvable(config(.enforce, users: ["itadmn"], groups: ["admn"]), resolver: table))
        #expect(!BypassResolution.isUnresolvable(config(.enforce, users: ["itadmn"], groups: ["admin"]), resolver: table))
        #expect(!BypassResolution.isUnresolvable(config(.enforce, users: ["itadmin"]), resolver: table))
        #expect(!BypassResolution.isUnresolvable(config(.monitor, users: ["nope"]), resolver: table))
        #expect(!BypassResolution.isUnresolvable(config(.enforce, users: ["nope"], enabled: false), resolver: table))
        // Empty bypass is the fail-closed config's shape → config_missing, not this.
        #expect(!BypassResolution.isUnresolvable(config(.enforce), resolver: table))
    }

    @Test("bypass_unresolvable ranks just below config_invalid")
    func ranking() {
        typealias C = StartupCoordinator
        #expect(C.resolveState(configInvalid: true, grantsError: false, authDBError: false, rulesError: false,
                               fdaReady: true, hasProfiles: true, bypassUnresolvable: true).reason == .configInvalid)
        #expect(C.resolveState(configInvalid: false, grantsError: true, authDBError: true, rulesError: true,
                               fdaReady: true, hasProfiles: true, configMissing: true, pamNotWired: true,
                               bypassUnresolvable: true).reason == .bypassUnresolvable)
        #expect(C.overlayPAMGate(state: .degraded, reason: .bypassUnresolvable, pamNotWired: true)
                == (.degraded, .bypassUnresolvable))
        #expect(DegradedReason.bypassUnresolvable.rawValue == "bypass_unresolvable")
    }

    @Test("the production resolver uses the local directory")
    func production() {
        let resolver = LocalBypassResolver()
        #expect(resolver.userResolves("root"))
        #expect(resolver.groupResolves("wheel"))
        #expect(!resolver.userResolves("no-such-user-\(UUID().uuidString.prefix(8))"))
        #expect(!resolver.groupResolves("no-such-group-\(UUID().uuidString.prefix(8))"))
    }
}
