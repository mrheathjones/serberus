import Foundation

/// Pure translator from Serberus sudo *allow* rules + enrollment principals to a
/// validated `/etc/sudoers.d/serberus` body string.
///
/// # Security model
/// The generated drop-in is the **coarse** outer allowlist that bounds an enrolled
/// standard user to the curated command *paths*. `pam_serberus` + the daemon remain
/// the **authoritative fine policy** (argv, prompt, deny, identity pins, caching).
/// Because `pam_serberus` passes the sudo authentication through to that fine policy,
/// this file is the *only* thing keeping an enrolled standard user bounded to curated
/// paths. Therefore this generator:
///
/// - emits **only** `rule.type == .sudo && rule.action == .allow` (the union of silent
///   and prompt elevation — a "prompt rule" is an allow with `elevation.type == .prompt`),
///   and **never** a `.deny` rule;
/// - **never** emits a `NOPASSWD:` tag (that would skip PAM entirely) and **never** an
///   `ALL` commands token (`.any` and nil-pattern rules are *excluded*, not translated);
/// - rejects any resolved path containing newline / CR / NUL / control characters and
///   backslash-escapes sudoers command metacharacters — `visudo` (in the daemon layer)
///   is the backstop, not the only guard;
/// - **excludes** regex / any / unrepresentable rules and records them for loud logging
///   (excluding = fail-safe: the command stays denied at the sudoers gate);
/// - emits, for `.exact` and `.prefix-regex`, BOTH the **authored** (as-written) command
///   path and its **canonical** (symlink-resolved) form when they differ, so a binary
///   reached through a symlink (`/usr/local/bin/jamf` → `/usr/local/jamf/bin/jamf`) is
///   authorized under the path `sudo` actually matches — `sudo` matches the typed path
///   while the daemon canonicalizes, so a resolved-only spec denied `sudo jamf …`;
/// - is **path-only**: it never pins `argPattern` into the drop-in. `sudo` requires an
///   EXACT full-argument match, so a `<path> <subcommand>` spec would deny
///   `sudo jamf recon -verbose` (any recon-with-flags) even though the fine gate allows
///   it (the daemon matches `argPattern` against `argv[0]` only). Argument enforcement is
///   therefore the daemon's job alone; the coarse layer ignores `argPattern`;
/// - returns an **empty** body when enrollment is empty OR every command was excluded,
///   so the caller *removes* the file rather than installing a header-only, invalid
///   sudoers file.
///
/// # Purity
/// This function performs no filesystem writes, no `visudo`, no `chown`/`chmod`, and holds
/// no daemon state. It *may* invoke ``PathCanonicalizer`` which resolves symlinks under
/// ``PathCanonicalizer/ExistencePolicy/allowMissing`` — the same trade-off `ESFMonitor`
/// makes when building its controlled-path set (an absent or symlinked binary must not
/// silently drop the rule).
public struct SudoersGenerator {

    /// A single rule — or a single enrollment principal — that could not be
    /// represented safely and was therefore left out of the body (fail-safe: the
    /// command stays denied / the principal gets no grant at the sudoers gate).
    public struct Exclusion: Sendable, Equatable {
        /// The rule's original `commandPattern` (may be `nil`; always `nil` for a
        /// principal exclusion).
        public let commandPattern: String?
        /// The offending enrollment principal (user or group), or `nil` for a
        /// command exclusion. Carried typed so callers can log/test it directly.
        public let principal: String?
        /// The effective match type raw value (`"exact"` when unset, `"principal"`
        /// for a principal exclusion).
        public let matchType: String
        /// Human-readable reason the rule/principal was excluded, for loud logging.
        public let reason: String

        public init(
            commandPattern: String? = nil,
            principal: String? = nil,
            matchType: String,
            reason: String
        ) {
            self.commandPattern = commandPattern
            self.principal = principal
            self.matchType = matchType
            self.reason = reason
        }
    }

    /// The result of translation: the sudoers body plus the list of excluded rules.
    public struct Result: Sendable, Equatable {
        /// The complete sudoers file body (header + principal lines + trailing newline),
        /// or `""` when the caller should remove the drop-in.
        public let body: String
        /// Rules that were not representable and were left out, for logging.
        public let excluded: [Exclusion]

        public init(body: String, excluded: [Exclusion]) {
            self.body = body
            self.excluded = excluded
        }
    }

    /// The default managed-marker header. The daemon-side removal helper greps for this
    /// exact string before deleting, so a same-named admin file is never destroyed.
    public static let defaultHeader =
        "# /etc/sudoers.d/serberus: managed by com.herojoneslabs.serberus \u{2014} DO NOT EDIT"

    /// Replaces sudo's `"%d incorrect password attempt(s)"` summary on a Serberus
    /// deny. With `passwd_tries=1` (below) this is the ONLY line sudo forces after
    /// a deny — there is no way to make sudo print zero lines on an auth failure
    /// without triggering its `AUTH_FATAL` path, which prints two worse lines
    /// ("PAM authentication error" + "a password is required"). So this line is
    /// made verdict-neutral and points at the module's own message printed just
    /// above it (which names the actual reason: declined / timed out / policy deny
    /// / service outage). ASCII only — it is a parsed sudoers string value, and a
    /// visudo parse failure would fail the whole drop-in.
    public static let authFailMessage = "denied by Serberus - see the message above"

    /// Replaces sudo's `"Sorry, try again."` between-attempts warning. With
    /// `passwd_tries=1` this never prints (sudo guards it on `tries != 0`); kept as
    /// belt-and-suspenders for any principal whose `passwd_tries` is raised
    /// elsewhere, so even then the terminal never says "Sorry, try again".
    public static let badPassMessage = "denied by Serberus"

    /// Translates the `.sudo`/`.allow` rules of `profiles` into a sudoers body for the
    /// given enrollment principals.
    ///
    /// - Parameters:
    ///   - profiles: The rule profiles to scan. Only `type == .sudo && action == .allow`
    ///     rules are considered; every other rule is ignored entirely (not even logged as
    ///     an exclusion — exclusions are reserved for *sudo allow* rules that cannot be
    ///     represented).
    ///   - enrollmentGroup: The optional local group whose members get the grant. A `nil`
    ///     or blank value means "no group principal".
    ///   - enrollmentUsers: The literal user names that get the grant. Blank entries are
    ///     dropped; duplicates are de-duplicated.
    ///   - header: The first line of the body. Defaults to ``defaultHeader``.
    ///   - canonicalizer: Path canonicalizer used for `.exact` (and metachar-free
    ///     `.prefix-regex`) patterns under `.allowMissing`.
    /// - Returns: A ``Result`` whose `body` is `""` when enrollment is empty or every
    ///   command was excluded (caller removes the file), and whose `excluded` always
    ///   lists the unrepresentable *sudo allow* rules.
    public static func generate(
        profiles: [RuleProfile],
        enrollmentGroup: String?,
        enrollmentUsers: [String],
        header: String = SudoersGenerator.defaultHeader,
        canonicalizer: PathCanonicalizer = PathCanonicalizer()
    ) -> Result {
        var commandSpecs = Set<String>()
        var excluded: [Exclusion] = []

        for profile in profiles {
            for rule in profile.rules {
                // Only sudo *allow* rules (silent + prompt) participate. Never deny,
                // never authuri.
                guard rule.type == .sudo, rule.action == .allow else { continue }

                let pattern = rule.match.commandPattern
                let matchType = rule.match.matchType ?? .exact
                let matchTypeRaw = matchType.rawValue

                switch matchType {
                case .regex:
                    excluded.append(Exclusion(
                        commandPattern: pattern,
                        matchType: matchTypeRaw,
                        reason: "regex match type not representable in sudoers"
                    ))
                    continue

                case .any:
                    excluded.append(Exclusion(
                        commandPattern: pattern,
                        matchType: matchTypeRaw,
                        reason: "'any' would be an ALL-commands grant \u{2014} forbidden"
                    ))
                    continue

                case .exact, .glob, .prefixRegex:
                    // Path-based match types require a non-empty command pattern.
                    guard let rawPattern = pattern,
                          !rawPattern.trimmingCharacters(in: .whitespaces).isEmpty else {
                        excluded.append(Exclusion(
                            commandPattern: pattern,
                            matchType: matchTypeRaw,
                            reason: "command pattern is missing"
                        ))
                        continue
                    }

                    // The rule's `argPattern` is deliberately IGNORED here: the coarse
                    // sudoers layer is path-only. `sudo` requires an EXACT full-argument
                    // match, so pinning `<path> <subcommand>` would deny
                    // `sudo <cmd> <subcommand> <flags…>` that the fine gate allows. The
                    // daemon is the sole enforcer of `argPattern`.
                    switch matchType {
                    case .exact:
                        appendExactSpec(
                            rawPattern,
                            matchTypeRaw: matchTypeRaw,
                            canonicalizer: canonicalizer,
                            into: &commandSpecs,
                            excluded: &excluded
                        )
                    case .glob:
                        appendGlobSpec(
                            rawPattern,
                            matchTypeRaw: matchTypeRaw,
                            into: &commandSpecs,
                            excluded: &excluded
                        )
                    case .prefixRegex:
                        appendPrefixRegexSpecs(
                            rawPattern,
                            matchTypeRaw: matchTypeRaw,
                            canonicalizer: canonicalizer,
                            into: &commandSpecs,
                            excluded: &excluded
                        )
                    case .regex, .any:
                        // Unreachable — handled by the outer switch.
                        break
                    }
                }
            }
        }

        // Fail-safe: enrollment empty OR every command excluded OR every principal
        // invalid -> empty body (remove). Principal validation is authoritative
        // here: the daemon reads `sudoEnrollment` straight from managed prefs, so a
        // hand-crafted MDM profile bypasses the admin-app UI entirely.
        let principals = orderedPrincipals(
            group: enrollmentGroup,
            users: enrollmentUsers,
            excluded: &excluded
        )
        guard !principals.isEmpty, !commandSpecs.isEmpty else {
            return Result(body: "", excluded: excluded)
        }

        let commandList = commandSpecs.sorted().joined(separator: ", ")
        var lines = [header]
        // Defeat sudo's per-tty credential timestamp cache for enrolled principals.
        // `pam_serberus` is (structurally) an `auth`-phase module — macOS includes
        // `sudo_local` only in the auth stack — and sudo skips the auth stack while a
        // tty's timestamp is valid (~5 min). Without `timestamp_timeout=0`, one
        // approved `sudo jamf recon` would open a window in which ANY other curated
        // command (`sudo jamf removeFramework`) runs WITHOUT the fine gate being
        // consulted. Setting it to 0 forces every curated invocation back through
        // auth → pam_serberus → daemon, so per-command policy is actually enforced.
        // The daemon's own per-command grant cache still provides re-approval grace;
        // only sudo's coarse tty-wide cache is disabled, and only for these
        // principals (reusing the same validated ``principals`` as the command lines).
        // Per-principal presentation hardening (scoped to the enrolled principals,
        // so an admin's normal 3-try sudo is untouched):
        //   - timestamp_timeout=0 forces every curated invocation back through
        //     pam_serberus (per-command policy actually enforced; see above);
        //   - passwd_tries=1 collapses sudo's auth-retry loop to one iteration, so on
        //     a Serberus deny sudo never prints "Sorry, try again." (guarded on
        //     tries != 0) and never runs up a "3 incorrect password attempts" count —
        //     the requisite control already suppressed the password prompt itself, so
        //     the deny reads as a single clean line, not a failed-login loop;
        //   - authfail_message / badpass_message replace sudo's built-in failure text
        //     with a Serberus-branded, verdict-neutral line.
        // TRADE-OFF (intended): passwd_tries=1 also gives these principals a single
        // password attempt on the ALLOW path (the drop-in never grants NOPASSWD).
        // That is consistent with the timestamp_timeout=0 hardening already applied to
        // the same principals, and a mistyped password just means re-running sudo.
        //
        // SECURITY: `!env_keep` empties the kept-variable list for these principals.
        // macOS's /etc/sudoers adds `env_keep += "HOME MAIL"` and `"EDITOR VISUAL"`,
        // and sudo's built-in keep list includes PATH. Harmless when only admins can
        // sudo; here a standard user runs curated commands as root, and each kept
        // variable points root at user-controlled code: HOME (~/.zshenv, Python user
        // site-packages, ~/.gitconfig, ~/.curlrc), PATH (a curated script's bare
        // `ls` resolves to ~/bin/ls), EDITOR/VISUAL (any tool that opens an editor).
        // With the list empty, env_reset gives the command the target user's HOME
        // and sudo's standard PATH; env_check variables (TERM, LANG, LC_*, TZ) still
        // pass. sudo still FINDS the command along the caller's PATH (lookup doesn't
        // use env_keep), so this doesn't change what pam_serberus resolves.
        for principal in principals {
            lines.append("Defaults:\(principal) timestamp_timeout=0")
            lines.append("Defaults:\(principal) !env_keep")
            lines.append("Defaults:\(principal) passwd_tries=1")
            lines.append("Defaults:\(principal) authfail_message=\"\(authFailMessage)\"")
            lines.append("Defaults:\(principal) badpass_message=\"\(badPassMessage)\"")
        }
        for principal in principals {
            lines.append("\(principal) ALL = \(commandList)")
        }
        let body = lines.joined(separator: "\n") + "\n"
        return Result(body: body, excluded: excluded)
    }

    // MARK: - Match-type translation

    /// Emits the sudoers command spec(s) for an `.exact` rule.
    ///
    /// FIX 1 (dual-path): a curated binary is frequently reached through a symlink
    /// (`/usr/local/bin/jamf` → `/usr/local/jamf/bin/jamf`). `sudo` matches the path
    /// the user *typed*, but the daemon canonicalizes before matching, so a
    /// resolved-only spec denied `sudo jamf …` at the sudoers gate. We therefore emit
    /// BOTH the authored (as-written) and the canonical (symlink-resolved) path when
    /// they differ, each independently guarded and escaped.
    private static func appendExactSpec(
        _ rawPattern: String,
        matchTypeRaw: String,
        canonicalizer: PathCanonicalizer,
        into specs: inout Set<String>,
        excluded: inout [Exclusion]
    ) {
        appendDualPathSpecs(
            rawPattern: rawPattern,
            matchTypeRaw: matchTypeRaw,
            canonicalize: true,
            // `.exact` is matched LITERALLY by the fine gate (`pattern == command`).
            // A path containing an fnmatch metacharacter (`* ? [ ]`) would become a
            // LIVE wildcard in sudoers — a coarse grant far broader than the literal
            // fine-gate rule (directory-wide over-auth). The backslash-literal forms
            // `\* \? \[ \]` are REJECTED by visudo (verified on sudo 1.9.17p2), so
            // there is no safe literal escape. Fail safe: EXCLUDE (command stays
            // denied at the coarse gate) rather than over-authorize or brick the file.
            rejectGlobMetacharacter: true,
            prefixSuffixWildcard: false,
            canonicalizer: canonicalizer,
            into: &specs,
            excluded: &excluded
        )
    }

    private static func appendGlobSpec(
        _ rawPattern: String,
        matchTypeRaw: String,
        into specs: inout Set<String>,
        excluded: inout [Exclusion]
    ) {
        // Best-effort wildcard spec: never canonicalized (metachars break
        // standardizing/symlink resolution), never dual-path (there is no single
        // canonical form to resolve to). Keep `* ? [ ]` live; escape only the
        // non-wildcard unsafe chars (wildcard-preserving mode).
        switch guardAndEscapePath(rawPattern, rejectGlobMetacharacter: false) {
        case .ok(let escaped):
            appendSpecs(
                base: escaped,
                prefixSuffixWildcard: false,
                into: &specs
            )
        case .failed(let reason):
            excluded.append(Exclusion(
                commandPattern: rawPattern,
                matchType: matchTypeRaw,
                reason: reason
            ))
        }
    }

    private static func appendPrefixRegexSpecs(
        _ rawPattern: String,
        matchTypeRaw: String,
        canonicalizer: PathCanonicalizer,
        into specs: inout Set<String>,
        excluded: inout [Exclusion]
    ) {
        // Component-boundary prefix semantics: emit the bare `<prefix>` AND
        // `<prefix>/*` (see ``appendSpecs``). Canonicalize the prefix (for the dual
        // authored/canonical forms) only when it has no metachars; otherwise treat it
        // literally.
        appendDualPathSpecs(
            rawPattern: rawPattern,
            matchTypeRaw: matchTypeRaw,
            canonicalize: !containsGlobMetacharacter(rawPattern),
            // prefix-regex wildcards are valid, intentionally live fnmatch wildcards.
            rejectGlobMetacharacter: false,
            prefixSuffixWildcard: true,
            canonicalizer: canonicalizer,
            into: &specs,
            excluded: &excluded
        )
    }

    // MARK: - Dual-path core

    /// Shared FIX 1 dual-path emitter for `.exact` and `.prefix-regex`. Builds the
    /// authored (raw) and canonical (symlink-resolved) path forms, guards + escapes
    /// each identically, and appends the resulting spec(s) via ``appendSpecs``.
    ///
    /// Canonicalization failure is **non-fatal** — the authored form is still
    /// attempted, so a path whose symlinks cannot be resolved is not silently dropped.
    /// Only when EVERY form fails its guards is the rule recorded as an ``Exclusion``
    /// (fail-safe: the command stays denied at the coarse gate). At most one exclusion
    /// is logged per rule, carrying the authored form's rejection reason.
    private static func appendDualPathSpecs(
        rawPattern: String,
        matchTypeRaw: String,
        canonicalize shouldCanonicalize: Bool,
        rejectGlobMetacharacter: Bool,
        prefixSuffixWildcard: Bool,
        canonicalizer: PathCanonicalizer,
        into specs: inout Set<String>,
        excluded: inout [Exclusion]
    ) {
        // Authored form first (its guard failure is the most meaningful reason to
        // report), then the canonical form when it differs. Canonicalization never
        // introduces control chars, backslashes, wildcards, or a relative path, so
        // the canonical form cannot fail a guard that the authored form passes.
        var forms = [rawPattern]
        if shouldCanonicalize,
           let canonical = try? canonicalizer.canonicalize(rawPattern, existence: .allowMissing),
           canonical != rawPattern {
            forms.append(canonical)
        }

        var escapedBases: [String] = []
        var seen = Set<String>()
        var firstFailure: String?
        for form in forms {
            switch guardAndEscapePath(form, rejectGlobMetacharacter: rejectGlobMetacharacter) {
            case .ok(let escaped):
                if seen.insert(escaped).inserted { escapedBases.append(escaped) }
            case .failed(let reason):
                if firstFailure == nil { firstFailure = reason }
            }
        }

        guard !escapedBases.isEmpty else {
            excluded.append(Exclusion(
                commandPattern: rawPattern,
                matchType: matchTypeRaw,
                reason: firstFailure ?? "path could not be represented in sudoers"
            ))
            return
        }

        for base in escapedBases {
            appendSpecs(
                base: base,
                prefixSuffixWildcard: prefixSuffixWildcard,
                into: &specs
            )
        }
    }

    /// Appends the path-only spec(s) for a single already-guarded+escaped base path:
    /// emits `"<base>"`, plus `"<base>/*"` for prefix-regex. `argPattern` is never
    /// pinned here — the coarse sudoers layer is path-only and the daemon is the sole
    /// enforcer of arguments (see the type-level docs).
    private static func appendSpecs(
        base: String,
        prefixSuffixWildcard: Bool,
        into specs: inout Set<String>
    ) {
        specs.insert(base)
        if prefixSuffixWildcard {
            // `/*` is a live fnmatch suffix wildcard (`escapeSpec` never touches `*`).
            specs.insert(base + "/*")
        }
    }

    /// Outcome of guarding + escaping one candidate path form.
    private enum GuardedPath {
        /// Escaped spec, ready to emit.
        case ok(String)
        /// Human-readable reason the form was rejected.
        case failed(String)
    }

    /// Applies every path guard — control-char reject, backslash exclusion,
    /// non-absolute exclusion, and (for `.exact`) fnmatch-metacharacter exclusion —
    /// to one candidate form and returns the escaped spec or the rejection reason.
    ///
    /// FIX 1: this runs identically over the authored AND the canonical form. The
    /// authored path is admin/attacker-authored too, so it gets the same guards
    /// before it can reach the body.
    private static func guardAndEscapePath(
        _ path: String,
        rejectGlobMetacharacter: Bool
    ) -> GuardedPath {
        // A newline/NUL/control char is rejected outright (not escaped).
        guard !containsUnsafeControlCharacter(path) else {
            return .failed("path contains a newline, NUL, or control character")
        }
        // A backslash has no accepted literal form in a sudoers Cmnd (`\\` is rejected
        // by visudo) — exclude rather than emit an invalid spec.
        guard !containsBackslash(path) else {
            return .failed("path contains a backslash, which has no valid sudoers Cmnd form")
        }
        // A non-fully-qualified Cmnd is rejected by visudo and would brick the file.
        guard isFullyQualified(path) else {
            return .failed("path is not fully qualified (must start with '/')")
        }
        if rejectGlobMetacharacter, containsGlobMetacharacter(path) {
            return .failed(
                "exact path contains an fnmatch wildcard (* ? [ ]) that cannot be "
                    + "represented literally in sudoers without becoming a live wildcard"
            )
        }
        return .ok(escapeSpec(path))
    }

    // MARK: - Principals

    /// Users (blank-dropped, validated, de-duplicated, sorted) followed by the
    /// group (`%<group>`), appended last. Every principal is interpolated raw into
    /// a `"<principal> ALL = ..."` User_Spec, so a principal that isn't a strict,
    /// safe local account/group name could inject an arbitrary sudoers spec
    /// (e.g. `NOPASSWD: ALL`). This is the authoritative guard — the daemon reads
    /// `sudoEnrollment` straight from managed prefs, bypassing the admin-app UI.
    /// Invalid principals are recorded as ``Exclusion``s and dropped; if that
    /// leaves no principals the caller emits an empty (remove) body.
    private static func orderedPrincipals(
        group: String?,
        users: [String],
        excluded: inout [Exclusion]
    ) -> [String] {
        var seen = Set<String>()
        var uniqueUsers: [String] = []
        for user in users {
            let trimmed = user.trimmingCharacters(in: .whitespaces)
            // Blank entries are dropped silently (not an injection, just noise).
            guard !trimmed.isEmpty else { continue }
            guard isSafePrincipalName(trimmed) else {
                excluded.append(Exclusion(
                    principal: trimmed,
                    matchType: "principal",
                    reason: "user principal \u{201C}\(trimmed)\u{201D} is not a safe local "
                        + "account name (or is the reserved ALL token) \u{2014} dropped"
                ))
                continue
            }
            if seen.insert(trimmed).inserted {
                uniqueUsers.append(trimmed)
            }
        }
        var principals = uniqueUsers.sorted()

        if let group {
            let trimmedGroup = group.trimmingCharacters(in: .whitespaces)
            if !trimmedGroup.isEmpty {
                // We own the `%` prefix; an admin-supplied `%` is invalid. The
                // name before our `%` must be a strict, non-reserved group name.
                if trimmedGroup.hasPrefix("%") || !isSafePrincipalName(trimmedGroup) {
                    excluded.append(Exclusion(
                        principal: trimmedGroup,
                        matchType: "principal",
                        reason: "group principal \u{201C}\(trimmedGroup)\u{201D} is not a safe "
                            + "local group name (reserved ALL, an already-%-prefixed name, or "
                            + "contains disallowed characters) \u{2014} dropped"
                    ))
                } else {
                    principals.append("%\(trimmedGroup)")
                }
            }
        }
        return principals
    }

    /// True when `name` is a strict, safe local account/group name: it matches
    /// `^[A-Za-z0-9_][A-Za-z0-9_.-]*$` (no whitespace, `=`, `,`, `:`, `#`, `!`,
    /// `%`, `+`, `(`, `)`, `*`, or control chars) and is not the reserved sudoers
    /// token `ALL`.
    private static func isSafePrincipalName(_ name: String) -> Bool {
        guard name != "ALL" else { return false }
        func isWordScalar(_ scalar: Unicode.Scalar) -> Bool {
            (scalar >= "A" && scalar <= "Z")
                || (scalar >= "a" && scalar <= "z")
                || (scalar >= "0" && scalar <= "9")
                || scalar == "_"
        }
        let scalars = name.unicodeScalars
        guard let first = scalars.first, isWordScalar(first) else { return false }
        for scalar in scalars.dropFirst() where !(isWordScalar(scalar) || scalar == "." || scalar == "-") {
            return false
        }
        return true
    }

    // MARK: - Escaping & rejection

    /// Backslash-escapes sudoers command-spec metacharacters by prefixing a
    /// single backslash to each. Callers MUST have already excluded any path
    /// containing a literal backslash (`\\` is rejected by visudo and there is no
    /// accepted literal-backslash Cmnd form), so this never escapes `\` itself.
    ///
    /// Always escaped: `#` (comment start), space, `,` `:` `=` (separators/special).
    ///
    /// Deliberately NOT escaped:
    /// - `!` — `\!` is REJECTED by visudo ("expected a fully-qualified path name");
    ///   a bare `!` is literal mid-path.
    /// - `* ? [ ]` — the fnmatch wildcards. On this sudo (1.9.17p2) the escaped
    ///   forms `\* \? \[ \]` are ALL **rejected** by visudo, so there is no
    ///   backslash-literal form. For `.glob` / `.prefixRegex` the wildcards are
    ///   meant to stay live anyway; for `.exact` a path containing a wildcard is
    ///   *excluded upstream* (it cannot be represented literally without changing
    ///   fnmatch semantics), so no wildcard ever reaches this function for exact.
    ///
    /// The only character this inserts is `\`, which no subsequent replacement
    /// targets, so replacement order among the metacharacters is irrelevant.
    private static func escapeSpec(_ path: String) -> String {
        var result = path
        result = result.replacingOccurrences(of: "#", with: "\\#")
        result = result.replacingOccurrences(of: " ", with: "\\ ")
        result = result.replacingOccurrences(of: ",", with: "\\,")
        result = result.replacingOccurrences(of: ":", with: "\\:")
        result = result.replacingOccurrences(of: "=", with: "\\=")
        return result
    }

    /// True when the path contains a literal backslash. Such a path has no valid
    /// sudoers Cmnd form (`\\` is rejected) and is excluded rather than emitted.
    private static func containsBackslash(_ string: String) -> Bool {
        string.contains("\\")
    }

    /// True when the path is a fully-qualified (absolute) path. A Cmnd that does
    /// not start with `/` is rejected by visudo and would brick the whole drop-in.
    private static func isFullyQualified(_ path: String) -> Bool {
        path.hasPrefix("/")
    }

    /// True when the string contains a newline, CR, NUL, DEL, or any C0/C1 control
    /// character — such a path is rejected outright (not escaped).
    private static func containsUnsafeControlCharacter(_ string: String) -> Bool {
        for scalar in string.unicodeScalars {
            let value = scalar.value
            if value < 0x20 || value == 0x7F || (value >= 0x80 && value <= 0x9F) {
                return true
            }
        }
        return false
    }

    /// True when the string contains an fnmatch glob metacharacter (`* ? [ ]`).
    private static func containsGlobMetacharacter(_ string: String) -> Bool {
        for character in string {
            switch character {
            case "*", "?", "[", "]":
                return true
            default:
                continue
            }
        }
        return false
    }
}
