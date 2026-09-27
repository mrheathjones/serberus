import Foundation

/// Sensitive-argument redaction.
///
/// No log entry may contain passwords, tokens, secrets, API keys, or
/// authorization credentials. Arguments are only logged at all when the
/// matched rule sets `logArguments = true` (or debug telemetry is on), and even
/// then every sensitive value is replaced before the event is encoded.
///
/// # What is redacted
/// - **Sensitive flags**, case-insensitively, single- or double-dash, in both
///   `--flag value` (next token) and `--flag=value` forms, whenever the flag
///   NAME looks secret-bearing (see ``isSensitiveName(_:)``): it contains
///   `passw`, `passphrase`, `passhash`, `secret`, `token`, `credential`,
///   `apikey` / `api-key` / `api_key`, `privatekey`; or one of its word
///   components (split on `-`, `_`, `.` and camelCase) is `pass`, `passwd`,
///   `password`, `pw`, `pwd`, `passcode`, `auth`, `authorization`, `key`,
///   `secret`, `token`, `bearer`, `apikey`, `credential(s)`. Matching `key` /
///   `auth` / `pass` / `pw` only as WHOLE components is deliberate:
///   `--keychain`, `--author`, `--bypass`, `--pwrite` and `-k` are harmless and
///   stay readable. The shell's own `PWD` / `OLDPWD` (the working directory)
///   are not secrets and are exempt.
/// - **`NAME=value` tokens** (environment-style assignments) whose `NAME` is
///   sensitive by the same rule, e.g. `API_TOKEN=…` → `API_TOKEN=<redacted>`,
///   `MYSQL_PWD=…`, `pw=…`.
/// - **URL credentials** in ANY token: the password of `scheme://user:pass@host`
///   (and scheme-less `//user:pass@host`) → `user:<redacted>`; a userinfo with
///   no colon (`https://TOKEN@host`, how tokens ride in git remotes) is
///   redacted whole, except for ssh-style schemes where it can only be a user
///   name; and sensitive query / fragment parameters (`access_token`, `token`,
///   `password`, `secret`, `key`, `sig`, `signature`, … —
///   ``isSensitiveParameter(_:)``).
/// - **Tool-specific flags**, applied only when the program is that tool
///   (``redact(_:program:)``'s `program`, else `argv[0]`):
///   - `security -w/-p/-P/-o` (separate or attached value) — except that in
///     `find-generic-password` / `find-internet-password` `-w` only asks for
///     the password to be printed and takes no value;
///   - `curl`: short-option bundles (`-sSfu user:pass`, `-uUSER:PASS`,
///     `-HAuthorization:…`), `-u/-U/--user/--proxy-user` (`user:<redacted>`),
///     `-H/--header` with a credential-bearing name, `-d/--data*/--json`
///     bodies that name a sensitive field (whole body), `-F name=value`,
///     `-E/--cert file:pass`, `--pass`, `-b/--cookie` strings;
///   - `dscl . -passwd <path> …` / `-authonly <user> …` (every token after the
///     path/user), `dscl . -create|-append|-merge|-change <path> <attr> …` when
///     the attribute is password-like (every value after it), and
///     `dscl -P <password>`;
///   - `openssl -passin/-passout/-pass pass:x` (`pass:<redacted>`), `-k/-K`;
///   - `mysql`-family `-pPASSWORD`; `ldap*` `-w` (and `ldappasswd -a/-s`);
///     `sshpass -p`; `docker|podman login -p`;
///   - `git -c <name>=<value>`: the value of an `*.extraheader` whose header
///     carries a credential, or of any sensitive config name;
///   - `ssh-keygen -N/-P` (new / old passphrase); `zip`/`unzip -P`;
///     `7z`-family `-pPASSWORD`; `htpasswd -b … <password>` (the last
///     argument); `sqlcmd -P`;
///   - `networksetup -setairportnetwork <dev> <ssid> <password>`,
///     `-setairportpassword …`, `-addpreferredwirelessnetworkatindex`, and the
///     `-set*proxy … <user> <password>` family;
///   - `security set-*-partition-list -k <password>` (elsewhere `-k` names a
///     keychain and is kept);
///   - `wget --header` (like curl's `-H`); its `--password` / `--http-password`
///     are covered by the generic rule;
///   - `keytool` `-storepass` / `-keypass` / `-srcstorepass` / … (any option
///     ending in `pass`) and `-new`; `redis-cli -a`; `smbclient` / `rpcclient`
///     `-U user%password` (`user%<redacted>`); `vault login <token>`;
///     `dsconfigad -p` / `-lp`; `pwpolicy -p`; `createmobileaccount -p`;
///     `openssl passwd … <plaintext>`;
///   - `launchctl setenv <NAME> <value>` and `defaults write <domain> <key>
///     <value…>` when the name / key is sensitive (every value token after a
///     sensitive `defaults` key; a plist-literal value naming a sensitive field
///     is redacted whole).
///   `jamf -password` is covered by the generic rule.
/// - **Header-shaped tokens** in any argv: `Authorization:…`,
///   `Proxy-Authorization:…`, `Cookie:…`, or a dashed header name that is
///   sensitive (`X-Api-Key:…`, `Private-Token:…`) → `Name: <redacted>`.
/// - **Wrapped commands**: the command that `sh` / `bash` / `zsh` / `dash` /
///   `ksh -c "<cmd>"`, `env [VAR=…] cmd …`, `xargs [opts] cmd …` and
///   `launchctl asuser <uid> cmd …` run is redacted with the same rules as if
///   it had been run directly. A `-c` string is split into shell words
///   (quotes and `;` / `&&` / `||` / `|` / `&` respected); only the words that
///   change are rewritten, so the rest of the string stays as typed.
/// - **Free text** (justifications) is split on ALL whitespace and screened
///   like argv, with the original separators preserved.
///
/// `-p` / `-pVALUE` is deliberately NOT redacted globally: it is too
/// ambiguous (for `sudo -p` it is the prompt), and over-redaction erases the
/// audit value of the argv.
public enum ArgumentRedactor {
    /// Replacement for redacted values.
    public static let placeholder = "<redacted>"

    /// Canonical examples of sensitive flag names (all matched by
    /// ``isSensitiveName(_:)``; kept for API compatibility).
    public static let sensitiveFlags: Set<String> = [
        "--password",
        "--token",
        "--secret",
        "--apikey",
        "--api-key",
        "--client-secret",
    ]

    /// Substrings that mark a name as secret-bearing wherever they occur.
    static let sensitiveSubstrings: [String] = [
        "passw", "passphrase", "passhash", "secret", "token", "credential",
        "apikey", "api-key", "api_key", "privatekey", "private-key", "private_key",
    ]

    /// Words that mark a name as secret-bearing only as a WHOLE component.
    /// `sshpass` is `SSHPASS`, the variable `sshpass -e` reads; `pat` is a
    /// personal access token (`GITHUB_PAT`).
    static let sensitiveComponents: Set<String> = [
        "pass", "passwd", "password", "pw", "pwd", "passcode", "auth", "authorization", "key", "secret",
        "token", "bearer", "apikey", "credential", "credentials", "sshpass", "pat",
    ]

    /// Exact names that match a sensitive component but are not secrets: the
    /// shell's working-directory variables.
    static let nonSensitiveExactNames: Set<String> = ["PWD", "OLDPWD"]

    /// Query / form parameter names that carry secrets beyond what
    /// ``isSensitiveName(_:)`` already catches (signed-URL signatures).
    static let sensitiveParameterNames: Set<String> = [
        "sig", "signature", "x-amz-signature", "x-goog-signature", "x-amz-credential", "x-goog-credential",
    ]

    /// Whether a URL query / form / JSON parameter NAME is secret-bearing.
    public static func isSensitiveParameter(_ name: String) -> Bool {
        isSensitiveName(name) || sensitiveParameterNames.contains(name.lowercased())
    }

    /// Returns `argv` with every sensitive value replaced.
    ///
    /// Argv stays `[String]` throughout — it is never flattened.
    /// - Parameters:
    ///   - argv: the argument vector. May or may not include the program as
    ///     element 0; every element is screened either way.
    ///   - program: the program the arguments belong to (a path or name), used
    ///     for the tool-specific rules. When nil, `argv[0]` is used.
    public static func redact(_ argv: [String], program: String?) -> [String] {
        redact(argv, program: program, depth: 0)
    }

    /// How deeply wrapped commands are unwrapped (`sh -c "env … xargs …"`).
    /// Anything nested deeper still gets the generic and URL rules.
    static let maxWrapperDepth = 6

    private static func redact(_ argv: [String], program: String?, depth: Int) -> [String] {
        let tool = basename(program ?? argv.first ?? "")
        var output = argv
        // Tokens a tool rule already parsed (flag + value) are final for the
        // generic pass; the URL pass below still screens every token.
        var handled = [Bool](repeating: false, count: argv.count)
        applyToolRules(tool: tool, argv: argv, output: &output, handled: &handled)
        if depth < maxWrapperDepth {
            // Where the tool's own arguments begin: after `argv[0]` when it is
            // the program, else at 0 (the caller passed the program separately).
            let start = program == nil || basename(argv.first ?? "") == tool ? 1 : 0
            applyWrapperRules(tool: tool, argv: argv, start: start, depth: depth,
                              output: &output, handled: &handled)
        }

        var redactNext = false
        for index in argv.indices {
            if handled[index] {
                redactNext = false
                continue
            }
            if redactNext {
                output[index] = placeholder
                redactNext = false
                continue
            }
            output[index] = redactGeneric(argv[index], redactNext: &redactNext)
        }
        // URL userinfo + sensitive query/fragment parameters, in ANY token
        // (bare URL, `--url=…`, `DATABASE_URL=…`, a tool-rule value).
        return output.map(redactURLCredentials)
    }

    /// Returns `argv` with every sensitive value replaced, taking `argv[0]` as
    /// the program for the tool-specific rules. (A separate overload, not a
    /// defaulted parameter, so `.map(ArgumentRedactor.redact)` keeps working.)
    public static func redact(_ argv: [String]) -> [String] {
        redact(argv, program: nil)
    }

    /// Redacts free text (justifications) that quotes a sensitive flag and
    /// its value, e.g. "needed --password hunter2". Split on ALL whitespace
    /// (tabs, newlines, …) — a secret after a tab or line break is still a
    /// token — while every original separator is preserved in the output.
    public static func redact(text: String) -> String {
        var words: [String] = []
        var separators: [String] = [""]   // separators[i] precedes words[i]; last is trailing
        var current = ""
        var inWord = false
        for character in text {
            if character.isWhitespace {
                if inWord {
                    words.append(current)
                    current = ""
                    separators.append("")
                    inWord = false
                }
                separators[separators.count - 1].append(character)
            } else {
                current.append(character)
                inWord = true
            }
        }
        if inWord {
            words.append(current)
            separators.append("")
        }
        let redacted = redact(words)
        var result = ""
        for (index, word) in redacted.enumerated() {
            result += separators[index] + word
        }
        return result + (separators.last ?? "")
    }

    // MARK: Generic rules

    private static func redactGeneric(_ argument: String, redactNext: inout Bool) -> String {
        if argument.hasPrefix("-"), argument.count > 1, argument != "--" {
            let dashes = argument.hasPrefix("--") ? 2 : 1
            let body = argument.dropFirst(dashes)
            if let equals = body.firstIndex(of: "=") {
                let name = String(body[..<equals])
                if isSensitiveName(name) {
                    return String(argument.prefix(dashes)) + name + "=" + placeholder
                }
                return argument
            }
            if isSensitiveName(String(body)) {
                redactNext = true
            }
            return argument
        }
        // Environment-style `NAME=value`.
        if let equals = argument.firstIndex(of: "=") {
            let name = String(argument[..<equals])
            if isIdentifier(name), isSensitiveName(name) {
                return name + "=" + placeholder
            }
        }
        // A header given as one token (`Authorization:Bearer x`, httpie style).
        if isCredentialHeaderToken(argument) {
            return redactHeader(argument)
        }
        return argument
    }

    /// Whether `token` is `Name:value` with a header name that carries a
    /// credential: `Authorization` / `Proxy-Authorization` / `Cookie`, or a
    /// DASHED sensitive name (`X-Api-Key`, `Private-Token`). Undashed names
    /// (`key:value`, `token:x`) are too common in ordinary arguments to judge.
    static func isCredentialHeaderToken(_ token: String) -> Bool {
        guard let colon = token.firstIndex(of: ":"), colon != token.startIndex else { return false }
        let name = token[..<colon]
        guard name.unicodeScalars.allSatisfy({
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_")
        }) else { return false }
        let lowered = name.lowercased()
        if lowered == "cookie" || lowered.hasSuffix("authorization") { return true }
        return name.contains("-") && isSensitiveName(String(name))
    }

    /// Whether a flag / variable NAME (without dashes) is secret-bearing.
    public static func isSensitiveName(_ name: String) -> Bool {
        guard !name.isEmpty, !nonSensitiveExactNames.contains(name) else { return false }
        let lowered = name.lowercased()
        if sensitiveSubstrings.contains(where: { lowered.contains($0) }) { return true }
        return components(of: name).contains { sensitiveComponents.contains($0) }
    }

    /// Lowercased word components: split on `-`, `_`, `.` and camelCase humps.
    static func components(of name: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var previousWasLower = false
        for character in name {
            if character == "-" || character == "_" || character == "." {
                if !current.isEmpty { parts.append(current.lowercased()) }
                current = ""
                previousWasLower = false
                continue
            }
            if character.isUppercase, previousWasLower, !current.isEmpty {
                parts.append(current.lowercased())
                current = ""
            }
            current.append(character)
            previousWasLower = character.isLowercase || character.isNumber
        }
        if !current.isEmpty { parts.append(current.lowercased()) }
        return parts
    }

    private static func isIdentifier(_ name: String) -> Bool {
        guard let first = name.unicodeScalars.first,
              first.isASCII, CharacterSet.letters.contains(first) || first == "_" else { return false }
        return name.unicodeScalars.allSatisfy {
            ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || $0 == "_" || $0 == "-" || $0 == "."
        }
    }

    private static func basename(_ path: String) -> String {
        (path.split(separator: "/").last.map(String.init) ?? path).lowercased()
    }

    // MARK: Tool-specific rules

    /// A value transform for a flag's argument.
    typealias Transform = @Sendable (String) -> String

    /// Applies the rules of `tool` (a lowercased basename) to `argv`, writing
    /// into `output` and marking every token it parsed in `handled`.
    private static func applyToolRules(tool: String, argv: [String], output: inout [String], handled: inout [Bool]) {
        var rules = ToolScan(argv: argv, output: output, handled: handled)
        switch tool {
        case "security":
            // `add-generic-password -w`, `unlock-keychain -p`, `create-keychain -p`,
            // `set-keychain-password -o old -p new`, `import/export -P` (getopt:
            // value separate or attached). In `find-*-password`, `-w` is the
            // "print only the password" switch and takes no value.
            let finding = argv.contains { $0.hasPrefix("find-") && $0.hasSuffix("-password") }
            rules.valueFlags(finding ? ["-p", "-P", "-o"] : ["-w", "-p", "-P", "-o"],
                             attached: true, transform: redactWhole)
            // `set-key-partition-list` / `set-*-password-partition-list -k
            // <keychain password>`. Elsewhere (`import`, `export`, …) `-k`
            // names a keychain and is kept.
            if argv.contains(where: { $0.hasPrefix("set-") && $0.hasSuffix("partition-list") }) {
                rules.valueFlags(["-k"], attached: true, transform: redactWhole)
            }

        case "curl":
            rules.curl()

        case "dscl":
            rules.dscl()

        case "openssl":
            rules.valueFlags(["-passin", "-passout", "-pass"], attached: false, transform: redactOpenSSLPassphrase)
            rules.valueFlags(["-k", "-K"], attached: false, transform: redactWhole)
            rules.opensslPasswd(tool: tool)

        case "mysql", "mysqldump", "mysqladmin", "mysqlimport", "mysqlshow", "mysqlcheck", "mariadb":
            // `-pPASSWORD` (attached only — a bare `-p` prompts, and the next
            // token is the database name).
            rules.attachedOnly("-p", transform: redactWhole)

        case "sshpass":
            rules.valueFlags(["-p"], attached: true, transform: redactWhole)

        case "docker", "podman":
            if argv.contains("login") {
                rules.markNoValue(["--password-stdin"])
                rules.valueFlags(["-p"], attached: true, transform: redactWhole)
            }

        case "networksetup":
            rules.networksetup()

        case "git":
            rules.git()

        case "ssh-keygen":
            rules.valueFlags(["-N", "-P"], attached: true, transform: redactWhole)

        case "zip", "unzip", "zipcloak":
            rules.valueFlags(["-P"], attached: true, transform: redactWhole)

        case "7z", "7za", "7zr", "7zz":
            // `-pPASSWORD` only; a bare `-p` prompts.
            rules.attachedOnly("-p", transform: redactWhole)

        case "htpasswd":
            rules.htpasswd()

        case "sqlcmd":
            rules.valueFlags(["-P"], attached: true, transform: redactWhole)

        case "wget":
            // `--password` / `--http-password` are caught by the generic rule.
            rules.longFlags(["--header": redactHeader])

        case "keytool":
            rules.keytool()

        case "redis-cli":
            rules.valueFlags(["-a"], attached: false, transform: redactWhole)

        case "smbclient", "rpcclient":
            // `-U user%password` / `--user=user%password`.
            rules.valueFlags(["-U"], attached: true, transform: redactAfterPercent)
            rules.longFlags(["--user": redactAfterPercent])

        case "vault":
            rules.vaultLogin(tool: tool)

        case "dsconfigad":
            // `-u <admin> -p <password>`, `-lu <local admin> -lp <password>`.
            rules.valueFlags(["-p", "-lp"], attached: false, transform: redactWhole)

        case "pwpolicy", "createmobileaccount":
            rules.valueFlags(["-p"], attached: false, transform: redactWhole)

        case "launchctl":
            rules.launchctlSetenv(tool: tool)

        case "defaults":
            rules.defaultsWrite()

        default:
            if tool.hasPrefix("ldap") {
                // ldapsearch/ldapmodify/ldapadd/…: `-w bindpw`; ldappasswd also
                // `-a oldpw` and `-s newpw`.
                let flags: Set<String> = tool == "ldappasswd" ? ["-w", "-a", "-s"] : ["-w"]
                rules.valueFlags(flags, attached: true, transform: redactWhole)
            }
        }
        output = rules.output
        handled = rules.handled
    }

    /// Index-based scanner the tool rules share.
    private struct ToolScan {
        let argv: [String]
        var output: [String]
        var handled: [Bool]

        /// Redacts the value of each flag in `flags` — the next token, or
        /// (with `attached`) the rest of the same token (`-wVALUE`).
        mutating func valueFlags(_ flags: Set<String>, attached: Bool, transform: Transform) {
            var index = 0
            while index < argv.count {
                defer { index += 1 }
                guard !handled[index] else { continue }
                let argument = argv[index]
                if flags.contains(argument) {
                    handled[index] = true
                    if index + 1 < argv.count {
                        output[index + 1] = transform(argv[index + 1])
                        handled[index + 1] = true
                        index += 1
                    }
                    continue
                }
                if attached, argument.count > 2, argument.hasPrefix("-"), !argument.hasPrefix("--"),
                   flags.contains(String(argument.prefix(2))) {
                    output[index] = String(argument.prefix(2)) + transform(String(argument.dropFirst(2)))
                    handled[index] = true
                }
            }
        }

        /// Redacts only the attached form `<flag>VALUE`.
        mutating func attachedOnly(_ flag: String, transform: Transform) {
            for index in argv.indices where !handled[index] {
                let argument = argv[index]
                if argument.count > flag.count, argument.hasPrefix(flag), !argument.hasPrefix("--") {
                    output[index] = flag + transform(String(argument.dropFirst(flag.count)))
                    handled[index] = true
                }
            }
        }

        /// Marks value-less flags whose NAME looks sensitive so the generic
        /// pass does not redact the token after them.
        mutating func markNoValue(_ flags: Set<String>) {
            for index in argv.indices where flags.contains(argv[index]) { handled[index] = true }
        }

        /// Redacts every token from `start` to the end.
        mutating func redactRest(from start: Int) {
            guard start < argv.count else { return }
            for index in start..<argv.count {
                output[index] = ArgumentRedactor.placeholder
                handled[index] = true
            }
        }

        /// Redacts one positional token, if present.
        mutating func redactPositional(_ index: Int) {
            guard index < argv.count else { return }
            output[index] = ArgumentRedactor.placeholder
            handled[index] = true
        }

        /// Redacts the value of each long flag in `transforms`, given as
        /// `--flag value` or `--flag=value`.
        mutating func longFlags(_ transforms: [String: Transform]) {
            var index = 0
            while index < argv.count {
                defer { index += 1 }
                guard !handled[index] else { continue }
                let argument = argv[index]
                if let equals = argument.firstIndex(of: "="),
                   let transform = transforms[String(argument[..<equals])] {
                    output[index] = String(argument[...equals]) + transform(String(argument[argument.index(after: equals)...]))
                    handled[index] = true
                } else if let transform = transforms[argument] {
                    handled[index] = true
                    if index + 1 < argv.count {
                        output[index + 1] = transform(argv[index + 1])
                        handled[index + 1] = true
                        index += 1
                    }
                }
            }
        }

        /// The index of the tool's subcommand: the first token that is not an
        /// option and not the program itself.
        func subcommand(of tool: String) -> Int? {
            argv.firstIndex { !$0.hasPrefix("-") && ArgumentRedactor.basename($0) != tool }
        }

        // MARK: keytool

        /// Every `-…pass` option (`-storepass`, `-keypass`, `-srcstorepass`,
        /// `-destkeypass`, …) and `-new` take a password as the next token.
        /// `-storepass:env NAME` / `:file PATH` name a source and are kept.
        mutating func keytool() {
            var index = 0
            while index < argv.count {
                defer { index += 1 }
                let lowered = argv[index].lowercased()
                guard lowered.hasPrefix("-"), lowered.hasSuffix("pass") || lowered == "-new" else { continue }
                handled[index] = true
                redactPositional(index + 1)
                index += 1
            }
        }

        // MARK: vault

        /// `vault login <token>`: the first operand after `login` that is not
        /// an option or a `key=value` pair (those go through the generic rule;
        /// `-` reads the token from stdin and is kept).
        mutating func vaultLogin(tool: String) {
            guard let login = subcommand(of: tool), argv[login] == "login" else { return }
            for index in argv.indices where index > login {
                let argument = argv[index]
                if argument.hasPrefix("-") || argument.contains("=") { continue }
                redactPositional(index)
                return
            }
        }

        // MARK: openssl passwd

        /// `openssl passwd [-1|-5|-6|…] [-salt s] [-in file] <password…>`:
        /// every operand is a plaintext password.
        mutating func opensslPasswd(tool: String) {
            guard let passwd = subcommand(of: tool), argv[passwd] == "passwd" else { return }
            var index = passwd + 1
            while index < argv.count {
                defer { index += 1 }
                let argument = argv[index]
                if argument == "-salt" || argument == "-in" {
                    handled[index] = true
                    if index + 1 < argv.count { handled[index + 1] = true }
                    index += 1
                } else if !argument.hasPrefix("-") {
                    redactPositional(index)
                }
            }
        }

        // MARK: launchctl setenv

        /// `launchctl setenv <NAME> <value> [<NAME> <value> …]`: the value of a
        /// sensitive name.
        mutating func launchctlSetenv(tool: String) {
            guard let setenv = subcommand(of: tool), argv[setenv] == "setenv" else { return }
            var index = setenv + 1
            while index + 1 < argv.count {
                if ArgumentRedactor.isSensitiveName(argv[index]) {
                    handled[index] = true
                    redactPositional(index + 1)
                }
                index += 2
            }
        }

        // MARK: defaults write

        /// `defaults [-currentHost] write <domain> <key> <value…>` (the domain
        /// is two tokens for `-app <name>`): every token after a sensitive key.
        /// A plist-literal value in the key's place (`write <domain> '{ … }'`)
        /// is redacted whole when it names a sensitive field.
        mutating func defaultsWrite() {
            guard let write = argv.firstIndex(of: "write") else { return }
            let keyIndex = write + (argv.indices.contains(write + 1) && argv[write + 1] == "-app" ? 3 : 2)
            guard keyIndex < argv.count else { return }
            let key = argv[keyIndex]
            if key.hasPrefix("{") || key.hasPrefix("(") {
                if ArgumentRedactor.namesSensitiveField(key) { redactPositional(keyIndex) }
                return
            }
            guard ArgumentRedactor.isSensitiveName(key) else { return }
            handled[keyIndex] = true
            redactRest(from: keyIndex + 1)
        }

        // MARK: curl

        /// Short options that take an argument (`curl --help all`).
        static let curlShortWithArgument: Set<Character> = Set("AbcCdDeEFHKmoPQrtTuUwxXyYz")

        static func curlShortTransform(_ option: Character) -> Transform? {
            switch option {
            case "u", "U": return ArgumentRedactor.redactUserPass
            case "H": return ArgumentRedactor.redactHeader
            case "d": return ArgumentRedactor.redactBody
            case "F": return ArgumentRedactor.redactFormField
            case "E": return ArgumentRedactor.redactCertPassphrase
            case "b": return ArgumentRedactor.redactCookie
            default: return nil
            }
        }

        static let curlLongTransforms: [String: Transform] = {
            typealias R = ArgumentRedactor
            var map: [String: Transform] = [:]
            for flag in ["--user", "--proxy-user"] { map[flag] = R.redactUserPass }
            for flag in ["--header", "--proxy-header"] { map[flag] = R.redactHeader }
            for flag in ["--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json"] {
                map[flag] = R.redactBody
            }
            for flag in ["--form", "--form-string"] { map[flag] = R.redactFormField }
            for flag in ["--cert", "--proxy-cert"] { map[flag] = R.redactCertPassphrase }
            for flag in ["--pass", "--proxy-pass"] { map[flag] = R.redactWhole }
            map["--cookie"] = R.redactCookie
            return map
        }()

        mutating func curl() {
            var index = 0
            while index < argv.count {
                defer { index += 1 }
                let argument = argv[index]
                if argument.hasPrefix("--") {
                    if let equals = argument.firstIndex(of: "=") {
                        let flag = String(argument[..<equals])
                        if let transform = Self.curlLongTransforms[flag] {
                            output[index] = flag + "=" + transform(String(argument[argument.index(after: equals)...]))
                            handled[index] = true
                        }
                    } else if let transform = Self.curlLongTransforms[argument] {
                        handled[index] = true
                        if index + 1 < argv.count {
                            output[index + 1] = transform(argv[index + 1])
                            handled[index + 1] = true
                            index += 1
                        }
                    }
                    continue
                }
                guard argument.hasPrefix("-"), argument.count > 1 else { continue }
                // Short-option bundle: `-sSfu user:pass`, `-uUSER:PASS`,
                // `-HAuthorization: …`, `-kd body`. The first option that takes
                // an argument consumes the rest of the token, else the next one.
                let letters = Array(argument.dropFirst())
                for (offset, option) in letters.enumerated() where Self.curlShortWithArgument.contains(option) {
                    let transform = Self.curlShortTransform(option)
                    let rest = String(letters[(offset + 1)...])
                    if !rest.isEmpty {
                        if let transform {
                            output[index] = "-" + String(letters[...offset]) + transform(rest)
                            handled[index] = true
                        }
                    } else if index + 1 < argv.count {
                        if let transform {
                            handled[index] = true
                            output[index + 1] = transform(argv[index + 1])
                            handled[index + 1] = true
                        }
                        index += 1
                    }
                    break
                }
            }
        }

        // MARK: dscl

        mutating func dscl() {
            var index = 0
            while index < argv.count {
                defer { index += 1 }
                let lowered = argv[index].lowercased()
                switch lowered {
                case "-passwd", "passwd", "-authonly", "authonly":
                    // `-passwd <path> [old] <new>` / `-authonly <user> <password>`:
                    // keep the record path / user, redact EVERY token after it.
                    handled[index] = true
                    if index + 1 < argv.count { handled[index + 1] = true }
                    redactRest(from: index + 2)
                    return
                case "-create", "create", "-append", "append", "-merge", "merge", "-change", "change":
                    // `-create <path> <attribute> <value…>` / `-change <path>
                    // <attribute> <old> <new>`: when the attribute is
                    // password-like, keep the record path and attribute name
                    // and redact every value after them.
                    guard index + 2 < argv.count, Self.isPasswordAttribute(argv[index + 2]) else { break }
                    for part in index...(index + 2) { handled[part] = true }
                    redactRest(from: index + 3)
                    return
                case "-p" where argv[index] == "-P":
                    // `dscl -u admin -P password …`
                    handled[index] = true
                    redactPositional(index + 1)
                    index += 1
                default:
                    break
                }
            }
        }

        /// A dscl attribute that holds a password: `Password`,
        /// `dsAttrTypeStandard:Password`, `dsAttrTypeNative:passwd`, … (the
        /// part after the last `:` is judged by ``ArgumentRedactor/isSensitiveName(_:)``).
        static func isPasswordAttribute(_ attribute: String) -> Bool {
            let name = attribute.split(separator: ":").last.map(String.init) ?? attribute
            return ArgumentRedactor.isSensitiveName(name)
        }

        // MARK: git

        /// `git -c <name>=<value>` (separate or attached `-c`): an
        /// `http.extraheader` / `http.<url>.extraheader` value is a header, and
        /// its credential is redacted like curl's `-H`; any other config name
        /// that looks secret-bearing has its whole value redacted.
        mutating func git() {
            let transform: Transform = { value in
                guard let equals = value.firstIndex(of: "=") else { return value }
                let name = String(value[..<equals])
                let rest = String(value[value.index(after: equals)...])
                if name.lowercased().hasSuffix("extraheader") {
                    return name + "=" + ArgumentRedactor.redactHeader(rest)
                }
                return ArgumentRedactor.isSensitiveName(name) ? name + "=" + ArgumentRedactor.placeholder : value
            }
            valueFlags(["-c"], attached: true, transform: transform)
        }

        // MARK: htpasswd

        /// `htpasswd -b[…] [file] <user> <password>`: with `-b` (batch, alone
        /// or in a bundle such as `-cb` / `-nbB`) the password is the LAST
        /// argument.
        mutating func htpasswd() {
            let batch = argv.contains { argument in
                argument.hasPrefix("-") && !argument.hasPrefix("--") && argument.dropFirst().contains("b")
            }
            guard batch, let last = argv.indices.last, !argv[last].hasPrefix("-") else { return }
            redactPositional(last)
        }

        // MARK: networksetup

        /// Flags whose password is the Nth operand after the flag.
        static let networksetupPasswordOperand: [String: Int] = [
            "-setairportnetwork": 3,                      // <device> <network> [password]
            "-addpreferredwirelessnetworkatindex": 5,     // <device> <network> <index> <security> [password]
            "-setwebproxy": 6, "-setsecurewebproxy": 6,  // <svc> <domain> <port> <on|off> <user> <password>
            "-setftpproxy": 6, "-setsocksfirewallproxy": 6,
            "-setstreamingproxy": 6, "-setgopherproxy": 6,
        ]

        mutating func networksetup() {
            for index in argv.indices {
                let lowered = argv[index].lowercased()
                if lowered == "-setairportpassword" {
                    handled[index] = true
                    redactRest(from: index + 1)
                    return
                }
                if let operand = Self.networksetupPasswordOperand[lowered] {
                    redactPositional(index + operand)
                }
            }
        }
    }

    // MARK: Value transforms

    private static let redactWhole: Transform = { _ in placeholder }

    /// Samba `user%password` → `user%<redacted>`; a bare user is kept.
    private static let redactAfterPercent: Transform = { value in
        guard let percent = value.firstIndex(of: "%") else { return value }
        return String(value[...percent]) + placeholder
    }

    /// `user:password` → `user:<redacted>`; a bare user (curl prompts for the
    /// password) carries no secret and is kept.
    private static let redactUserPass: Transform = { value in
        guard let colon = value.firstIndex(of: ":") else { return value }
        return String(value[...colon]) + placeholder
    }

    /// `Authorization: Bearer x` → `Authorization: <redacted>` for
    /// credential-bearing header names; other headers are kept.
    static let redactHeader: Transform = { value in
        guard let colon = value.firstIndex(of: ":") else { return value }
        let name = value[..<colon].trimmingCharacters(in: .whitespaces)
        let lowered = name.lowercased()
        guard lowered == "cookie" || lowered.hasSuffix("authorization") || isSensitiveName(name) else {
            return value
        }
        return String(value[...colon]) + " " + placeholder
    }

    /// A request body (`-d`, `--data*`, `--json`): `@file` is kept; any body that
    /// NAMES a sensitive field (form `password=…`, JSON `"token": …`) is redacted
    /// whole — a body's structure is too varied to excise values reliably.
    private static let redactBody: Transform = { value in
        if value.hasPrefix("@") { return value }
        return namesSensitiveField(value) ? placeholder : value
    }

    /// `-F name=value`: redact the value when the field name is sensitive.
    private static let redactFormField: Transform = { value in
        guard let equals = value.firstIndex(of: "=") else { return value }
        let name = String(value[..<equals])
        return isSensitiveParameter(name) ? name + "=" + placeholder : value
    }

    /// `--cert file:passphrase` → `file:<redacted>`.
    private static let redactCertPassphrase: Transform = { value in
        guard let colon = value.firstIndex(of: ":") else { return value }
        return String(value[...colon]) + placeholder
    }

    /// `-b 'session=abc'` is a cookie string (secret); `-b jar.txt` a file.
    private static let redactCookie: Transform = { value in
        value.contains("=") ? placeholder : value
    }

    /// openssl `-passin pass:x` → `pass:<redacted>`; `env:`/`file:`/`fd:`/`stdin`
    /// name a source, not the secret, and are kept. Anything else is redacted.
    private static let redactOpenSSLPassphrase: Transform = { value in
        let lowered = value.lowercased()
        if lowered.hasPrefix("pass:") { return String(value.prefix(5)) + placeholder }
        if lowered.hasPrefix("env:") || lowered.hasPrefix("file:") || lowered.hasPrefix("fd:") || lowered == "stdin" {
            return value
        }
        return placeholder
    }

    /// Whether free-form text names a sensitive field (identifier-like words).
    static func namesSensitiveField(_ text: String) -> Bool {
        var word = ""
        for scalar in text.unicodeScalars {
            if scalar.isASCII, CharacterSet.alphanumerics.contains(scalar) || scalar == "_" || scalar == "-" || scalar == "." {
                word.unicodeScalars.append(scalar)
                continue
            }
            if !word.isEmpty, isSensitiveParameter(word) { return true }
            word = ""
        }
        return !word.isEmpty && isSensitiveParameter(word)
    }

    // MARK: URLs

    /// Redacts URL credentials anywhere in `token`: the password of a
    /// `scheme://user:pass@host` (or scheme-less `//user:pass@host`) userinfo,
    /// and the values of sensitive query / fragment parameters
    /// (`?access_token=…`, `&sig=…`, `#token=…`).
    static func redactURLCredentials(_ token: String) -> String {
        let authorityStart: String.Index
        if let scheme = token.range(of: "://") {
            authorityStart = scheme.upperBound
        } else if token.hasPrefix("//") {
            authorityStart = token.index(token.startIndex, offsetBy: 2)
        } else {
            return token
        }
        var result = token
        let authorityEnd = token[authorityStart...].firstIndex(where: { "/?#".contains($0) }) ?? token.endIndex
        let authority = token[authorityStart..<authorityEnd]
        if let at = authority.lastIndex(of: "@") {
            let userinfo = authority[..<at]
            if let colon = userinfo.firstIndex(of: ":") {
                result = String(token[..<authorityStart]) + String(userinfo[...colon]) + placeholder
                    + String(token[at...])
            } else if !userinfo.isEmpty, !isUserNameOnlyScheme(token[..<authorityStart]) {
                // `https://TOKEN@host`: a lone userinfo is how access tokens ride
                // in git remotes and many APIs, so it is redacted whole.
                result = String(token[..<authorityStart]) + placeholder + String(token[at...])
            }
        }
        return redactURLParameters(result)
    }

    /// Schemes whose userinfo can only be a user name (key-based ssh
    /// transports), so `ssh://git@host` stays readable.
    /// `prefix` is everything before the authority (`…ssh://`); the scheme is
    /// the run of scheme characters right before `://`.
    private static func isUserNameOnlyScheme(_ prefix: Substring) -> Bool {
        guard prefix.hasSuffix("://") else { return false }
        let beforeSeparator = prefix.dropLast(3)
        let scheme = beforeSeparator.reversed()
            .prefix { $0.isASCII && ($0.isLetter || $0.isNumber || "+-.".contains($0)) }
        return ["ssh", "git+ssh", "ssh+git", "sftp", "scp"].contains(String(scheme.reversed()).lowercased())
    }

    /// `name=value` pairs after the first `?` and after `#`, split on `&`/`;`.
    private static func redactURLParameters(_ url: String) -> String {
        guard let start = url.firstIndex(where: { $0 == "?" || $0 == "#" }) else { return url }
        var output = String(url[..<start])
        var segment = ""
        func flush() {
            if let equals = segment.firstIndex(of: "="),
               isSensitiveParameter(String(segment[..<equals])) {
                output += String(segment[...equals]) + placeholder
            } else {
                output += segment
            }
            segment = ""
        }
        for character in url[start...] {
            if character == "?" || character == "#" || character == "&" || character == ";" {
                flush()
                output.append(character)
            } else {
                segment.append(character)
            }
        }
        flush()
        return output
    }
}

// MARK: - Wrapped commands

extension ArgumentRedactor {
    /// Shells whose `-c` string is a command line.
    static let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh"]

    /// Programs (and shell reserved words) that run the rest of their argv as a
    /// command after some options of their own, and how to skip those options:
    /// `valueLetters` are getopt letters that take a value (attached or next),
    /// `valueWords` whole options that take the next token, and `operands` how
    /// many operands of the wrapper's own come before the command (`timeout`'s
    /// duration, `chroot`'s directory, `script`'s file).
    struct PrefixWrapper: Sendable {
        var valueLetters: Set<Character> = []
        var valueWords: Set<String> = []
        var operands = 0
        /// Whether `NAME=value` words may come before the command (`sudo`).
        var allowsAssignments = false
        /// Whether options are whole words, not getopt bundles (`arch -arm64`).
        var wordOptions = false
    }

    static let prefixWrappers: [String: PrefixWrapper] = {
        var table: [String: PrefixWrapper] = [
            "nohup": PrefixWrapper(),
            "nice": PrefixWrapper(valueLetters: ["n"], valueWords: ["--adjustment"]),
            "caffeinate": PrefixWrapper(valueLetters: ["t", "w"]),
            "timeout": PrefixWrapper(valueLetters: ["k", "s"], valueWords: ["--kill-after", "--signal"], operands: 1),
            "gtimeout": PrefixWrapper(valueLetters: ["k", "s"], valueWords: ["--kill-after", "--signal"], operands: 1),
            "time": PrefixWrapper(),
            "arch": PrefixWrapper(valueWords: ["-arch", "-e", "-d"], wordOptions: true),
            "command": PrefixWrapper(),
            "builtin": PrefixWrapper(),
            "exec": PrefixWrapper(valueLetters: ["a"]),
            "doas": PrefixWrapper(valueLetters: ["a", "C", "u"]),
            "sudo": PrefixWrapper(
                valueLetters: ["u", "g", "C", "D", "h", "p", "r", "t", "T", "U", "R"],
                valueWords: ["--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role",
                             "--type", "--command-timeout", "--other-user", "--chroot"],
                allowsAssignments: true),
            "chroot": PrefixWrapper(valueLetters: ["u", "g", "G"], operands: 1),
            "script": PrefixWrapper(valueLetters: ["t", "T"], operands: 1),
        ]
        // Shell reserved words that can precede a command in a `-c` string.
        for word in ["!", "{", "if", "then", "elif", "else", "while", "until", "do"] {
            table[word] = PrefixWrapper()
        }
        return table
    }()

    /// Interpreters whose `-e` / `-c` value is a program that may run commands
    /// (`system("…")`, `do shell script "…"`).
    static func scriptOptions(forTool tool: String) -> Set<String>? {
        if tool == "osascript" { return ["-e"] }
        if tool.hasPrefix("perl") { return ["-e", "-E"] }
        if tool == "ruby" || tool.hasPrefix("ruby") { return ["-e"] }
        if tool.hasPrefix("python") { return ["-c"] }
        if tool == "node" || tool == "nodejs" { return ["-e", "--eval", "-p", "--print"] }
        return nil
    }

    /// Redacts the command a wrapper program runs (`env`, `xargs`,
    /// `launchctl asuser`, a shell's `-c` string) with the full rule set, as if
    /// it had been run directly. `start` is where the wrapper's own arguments
    /// begin in `argv`.
    fileprivate static func applyWrapperRules(tool: String, argv: [String], start: Int, depth: Int,
                                              output: inout [String], handled: inout [Bool]) {
        guard start <= argv.count else { return }
        func redactInner(from index: Int) {
            guard index < argv.count else { return }
            let inner = redact(Array(argv[index...]), program: nil, depth: depth + 1)
            for (offset, value) in inner.enumerated() {
                output[index + offset] = value
                handled[index + offset] = true
            }
        }

        if shells.contains(tool) {
            guard let payload = shellCommandIndex(argv: argv, start: start) else { return }
            output[payload] = redact(shellCommand: argv[payload], depth: depth + 1)
            handled[payload] = true
            return
        }
        if let wrapper = prefixWrappers[tool] {
            if let inner = innerCommandIndex(argv: argv, start: start, wrapper: wrapper) {
                redactInner(from: inner)
            }
            // `script -c "command"` (util-linux form): a command string.
            if tool == "script" {
                redactShellStringOptions(["-c", "--command"], argv: argv, start: start, depth: depth,
                                         output: &output, handled: &handled)
            }
            return
        }
        if let options = scriptOptions(forTool: tool) {
            var index = start
            while index < argv.count {
                let argument = argv[index]
                if argument == "--" { break }
                if options.contains(argument), index + 1 < argv.count {
                    output[index + 1] = redact(script: argv[index + 1], depth: depth + 1)
                    handled[index + 1] = true
                    index += 2
                    continue
                }
                // Attached forms: `-e…`, `-c…`, `--eval=…`.
                for option in options.sorted(by: { $0.count > $1.count }) {
                    let prefix = option.hasPrefix("--") ? option + "=" : option
                    guard argument.hasPrefix(prefix), argument.count > prefix.count else { continue }
                    output[index] = prefix + redact(script: String(argument.dropFirst(prefix.count)), depth: depth + 1)
                    handled[index] = true
                    break
                }
                index += 1
            }
            return
        }
        switch tool {
        case "env":
            var index = start
            while index < argv.count {
                let argument = argv[index]
                if argument == "--" { index += 1; break }
                if argument == "-S" || argument == "--split-string" {
                    // `-S "string"`: env splits the string into the command.
                    if index + 1 < argv.count {
                        output[index + 1] = redact(shellCommand: argv[index + 1], depth: depth + 1)
                        handled[index + 1] = true
                    }
                    return
                }
                if ["-u", "-P", "-C", "--unset", "--chdir"].contains(argument) { index += 2; continue }
                if argument.hasPrefix("-") { index += 1; continue }
                if isAssignment(argument) { index += 1; continue }   // the generic rule screens it
                break
            }
            redactInner(from: index)

        case "xargs":
            let withValue: Set<String> = ["-E", "-I", "-J", "-L", "-n", "-P", "-R", "-S", "-s", "-a", "-d"]
            var index = start
            while index < argv.count {
                let argument = argv[index]
                if argument == "--" { index += 1; break }
                guard argument.hasPrefix("-"), argument.count > 1 else { break }
                index += withValue.contains(argument) ? 2 : 1
            }
            redactInner(from: index)

        case "launchctl":
            // `launchctl asuser <uid> <command…>`.
            if start + 1 < argv.count, argv[start] == "asuser" {
                redactInner(from: start + 2)
            }

        case "su":
            // `su [flags] [login [args]]`: the args go to the login shell, so a
            // `-c` among them (or `--command`) is a command string.
            redactShellStringOptions(["-c", "--command"], argv: argv, start: start, depth: depth,
                                     output: &output, handled: &handled)

        default:
            break
        }
    }

    /// Where the command a prefix wrapper runs begins, or nil when there is
    /// none. `--` ends the wrapper's options.
    private static func innerCommandIndex(argv: [String], start: Int, wrapper: PrefixWrapper) -> Int? {
        var index = start
        while index < argv.count {
            let argument = argv[index]
            if argument == "--" { index += 1; break }
            if wrapper.allowsAssignments, isAssignment(argument) { index += 1; continue }
            guard argument.hasPrefix("-"), argument.count > 1 else { break }
            if wrapper.valueWords.contains(argument) { index += 2; continue }
            if argument.hasPrefix("--") || wrapper.wordOptions { index += 1; continue }
            // A getopt bundle: the first letter that takes a value consumes the
            // rest of the token, or the next token when it is the last letter.
            var takesNext = false
            for (offset, letter) in argument.dropFirst().enumerated() where wrapper.valueLetters.contains(letter) {
                takesNext = offset == argument.count - 2
                break
            }
            index += takesNext ? 2 : 1
        }
        index += wrapper.operands
        return index < argv.count ? index : nil
    }

    /// Redacts, as a shell command line, the value of each of `options`
    /// (`-c string`, `--command string`, `--command=string`) and of a short
    /// option bundle ending in the first option's letter (`-lc string`).
    private static func redactShellStringOptions(_ options: [String], argv: [String], start: Int, depth: Int,
                                                 output: inout [String], handled: inout [Bool]) {
        let letter = options.first.flatMap { $0.count == 2 ? $0.last : nil }
        var index = start
        while index < argv.count {
            let argument = argv[index]
            let isBundle = letter.map { argument.hasPrefix("-") && !argument.hasPrefix("--")
                && argument.count > 2 && argument.last == $0 } ?? false
            if (options.contains(argument) || isBundle), index + 1 < argv.count {
                output[index + 1] = redact(shellCommand: argv[index + 1], depth: depth + 1)
                handled[index + 1] = true
                index += 2
                continue
            }
            if let long = options.first(where: { $0.hasPrefix("--") && argument.hasPrefix($0 + "=") }) {
                let value = String(argument.dropFirst(long.count + 1))
                output[index] = long + "=" + redact(shellCommand: value, depth: depth + 1)
                handled[index] = true
            }
            index += 1
        }
    }

    /// Redacts an interpreter's program text (`osascript -e`, `perl -e`,
    /// `python -c`, …): each quoted string literal in it is redacted as a
    /// shell command line (the usual way such a program runs a command:
    /// `do shell script "…"`, `system("…")`), then the whole text is too.
    static func redact(script: String) -> String {
        redact(script: script, depth: 0)
    }

    fileprivate static func redact(script: String, depth: Int) -> String {
        guard depth < maxWrapperDepth else { return redact(text: script) }
        var result = ""
        var index = script.startIndex
        while index < script.endIndex {
            let character = script[index]
            guard character == "\"" || character == "'" else {
                result.append(character)
                index = script.index(after: index)
                continue
            }
            // A string literal: up to the matching unescaped quote.
            var end = script.index(after: index)
            while end < script.endIndex, script[end] != character {
                if script[end] == "\\", script.index(after: end) < script.endIndex {
                    end = script.index(after: end)
                }
                end = script.index(after: end)
            }
            let body = String(script[script.index(after: index)..<end])
            let redacted = redact(shellCommand: body, depth: depth + 1)
            result.append(character)
            result += redacted == body ? body : redacted.replacingOccurrences(of: String(character), with: "")
            if end < script.endIndex {
                result.append(character)
                end = script.index(after: end)
            }
            index = end
        }
        return redact(shellCommand: result, depth: depth + 1)
    }

    /// The index of a shell's `-c` command string: the first operand after an
    /// option bundle containing `c` (`-c`, `-lc`, `-ec`), skipping `-o` / `-O`
    /// option values. nil when the shell was not given `-c`.
    private static func shellCommandIndex(argv: [String], start: Int) -> Int? {
        var index = start
        var sawC = false
        while index < argv.count {
            let argument = argv[index]
            if argument == "--" {
                index += 1
                break
            }
            let isOption = (argument.hasPrefix("-") || argument.hasPrefix("+")) && argument.count > 1
                && !argument.hasPrefix("--")
            if argument.hasPrefix("--") { index += 1; continue }
            guard isOption else { break }
            let letters = argument.dropFirst()
            if letters.contains("c") { sawC = true }
            index += (letters.last == "o" || letters.last == "O") ? 2 : 1
        }
        return sawC && index < argv.count ? index : nil
    }

    private static func isAssignment(_ token: String) -> Bool {
        guard let equals = token.firstIndex(of: "="), equals != token.startIndex else { return false }
        return isIdentifier(String(token[..<equals]))
    }

    /// Redacts a shell command line (`sh -c` string) with the argv rules.
    ///
    /// The string is split into words the way the shell would (single and
    /// double quotes, backslash escapes) and into simple commands at unquoted
    /// `;` `&&` `||` `|` `&`, newlines and parentheses. Each command's leading
    /// `NAME=value` assignments are screened by the generic rule and the rest
    /// by the full rule set, with its first word as the program. Only words
    /// whose redacted form differs are rewritten (unquoted) in place; the rest
    /// of the string is kept byte for byte.
    static func redact(shellCommand: String) -> String {
        redact(shellCommand: shellCommand, depth: 0)
    }

    fileprivate static func redact(shellCommand: String, depth: Int) -> String {
        let commands = shellWords(shellCommand)
        var replacements: [(range: Range<String.Index>, text: String)] = []
        for command in commands where !command.isEmpty {
            let words = command.map(\.value)
            let programIndex = words.firstIndex { !isAssignment($0) } ?? words.count
            var redacted = words
            for index in 0..<programIndex {
                var ignored = false
                redacted[index] = redactGeneric(words[index], redactNext: &ignored)
            }
            if programIndex < words.count {
                let inner = depth < maxWrapperDepth
                    ? redact(Array(words[programIndex...]), program: nil, depth: depth)
                    : Array(words[programIndex...]).map { word in
                        var ignored = false
                        return redactGeneric(word, redactNext: &ignored)
                    }
                redacted.replaceSubrange(programIndex..., with: inner)
            }
            for (index, word) in command.enumerated() where redacted[index] != word.value {
                replacements.append((word.range, shellQuotedIfNeeded(redacted[index])))
            }
        }
        guard !replacements.isEmpty else { return shellCommand }
        var result = ""
        var cursor = shellCommand.startIndex
        for replacement in replacements.sorted(by: { $0.range.lowerBound < $1.range.lowerBound }) {
            result += shellCommand[cursor..<replacement.range.lowerBound]
            result += replacement.text
            cursor = replacement.range.upperBound
        }
        return result + shellCommand[cursor...]
    }

    /// `word` as the shell would need it to stay one word: unchanged when it
    /// has no whitespace, quotes or operators, else single-quoted. Keeps a
    /// rewritten string splitting the same way, so redaction stays idempotent.
    private static func shellQuotedIfNeeded(_ word: String) -> String {
        let special: Set<Character> = ["'", "\"", "\\", ";", "&", "|", "(", ")"]
        guard word.contains(where: { $0.isWhitespace || special.contains($0) }) else { return word }
        return "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// One shell word: its unquoted value and where it sits in the source.
    struct ShellWord {
        var value: String
        var range: Range<String.Index>
    }

    /// Splits `text` into simple commands of shell words. Quotes are removed
    /// from the values; an unterminated quote runs to the end of the text.
    static func shellWords(_ text: String) -> [[ShellWord]] {
        var commands: [[ShellWord]] = [[]]
        var value = ""
        var wordStart: String.Index?
        var index = text.startIndex
        func endWord(at end: String.Index) {
            if let start = wordStart {
                commands[commands.count - 1].append(ShellWord(value: value, range: start..<end))
            }
            value = ""
            wordStart = nil
        }
        while index < text.endIndex {
            let character = text[index]
            switch character {
            case "'":
                if wordStart == nil { wordStart = index }
                index = text.index(after: index)
                while index < text.endIndex, text[index] != "'" {
                    value.append(text[index])
                    index = text.index(after: index)
                }
                if index < text.endIndex { index = text.index(after: index) }
            case "\"":
                if wordStart == nil { wordStart = index }
                index = text.index(after: index)
                while index < text.endIndex, text[index] != "\"" {
                    if text[index] == "\\", text.index(after: index) < text.endIndex,
                       "\"\\$`".contains(text[text.index(after: index)]) {
                        index = text.index(after: index)
                    }
                    value.append(text[index])
                    index = text.index(after: index)
                }
                if index < text.endIndex { index = text.index(after: index) }
            case "\\":
                if wordStart == nil { wordStart = index }
                index = text.index(after: index)
                if index < text.endIndex {
                    if text[index] != "\n" { value.append(text[index]) }
                    index = text.index(after: index)
                }
            case ";", "&", "|", "\n", "(", ")":
                endWord(at: index)
                if !commands[commands.count - 1].isEmpty { commands.append([]) }
                index = text.index(after: index)
            default:
                if character.isWhitespace {
                    endWord(at: index)
                } else {
                    if wordStart == nil { wordStart = index }
                    value.append(character)
                }
                index = text.index(after: index)
            }
        }
        endWord(at: text.endIndex)
        return commands
    }
}
