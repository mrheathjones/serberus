import Foundation
import PrivMgrCore

/// Commander's side of Capture (Rule Recorder): load + validate a
/// `.serberuscapture` recorded in Sentinel, and turn captured attempts into
/// pre-filled ``DefinitionDraft``s for the composer — the admin authors from
/// what the user actually did instead of guessing.
///
/// A capture is **untrusted input** (a user-supplied file, or a Jamf
/// attachment any local user on the recording Mac could have written): it is
/// size-capped before it is read, schema-validated on decode, and nothing is
/// applied automatically — every draft still goes through the composer or an
/// explicit "Create" click.
public enum CaptureImporter {
    /// Reads and validates a capture file.
    ///
    /// The size cap is checked from the file's attributes BEFORE the bytes are
    /// read, so an oversize file never lands in memory; the decoder applies the
    /// same cap again on the data it sees.
    public static func load(url: URL) throws -> RuleCapture {
        // Attributes of the TARGET (a symlink's own attributes would pass a
        // multi-GB target through to the read).
        let target = url.resolvingSymlinksInPath()
        if let size = (try? FileManager.default.attributesOfItem(atPath: target.path))?[.size] as? Int,
           size > RuleCapture.maxEncodedBytes {
            throw CaptureDecodeError.tooLarge(bytes: size)
        }
        let data: Data
        do {
            data = try Data(contentsOf: target)
        } catch {
            throw CaptureDecodeError.malformed("could not read \(url.lastPathComponent): \(error.localizedDescription)")
        }
        return try RuleCapture.decode(from: data)
    }

    /// A composer-ready draft for one captured attempt.
    ///
    /// - sudo: `commandPattern` = the logged path (`.exact`), `resolvedCommandPattern`
    ///   = its realpath when the binary was a symlink, `argPattern` = an
    ///   anchored, escaped literal of `argv[0]` (the engine applies `argPattern`
    ///   to `argv[0]` only), `requiredTeamID` = the captured Team ID — the
    ///   DEFAULT pin. The binary hash is NOT pre-filled: it changes on every
    ///   update of the binary, so pinning it is an explicit choice.
    /// - authuri: `authURI` = the right (exact match). The client's Team ID is
    ///   deliberately NOT pre-filled as a pin: the live authuri layer is an
    ///   AuthorizationDB projection that cannot enforce identity pins (the
    ///   Intel tag says "binary-gated" for exactly this reason), so a
    ///   pre-filled pin would read as protection that never applies. The
    ///   captured Team ID stays on the attempt for the admin to see.
    ///
    /// `existingIDs` keeps the generated slug unique across the library (and
    /// across a batch import — pass the ids already produced).
    public static func draft(
        for attempt: CapturedAttempt,
        capture: RuleCapture? = nil,
        existingIDs: Set<String>
    ) -> DefinitionDraft {
        switch attempt.kind {
        case .sudo:
            let command = attempt.sudoCommand ?? ""
            let binary = (command as NSString).lastPathComponent
            let firstArgument = attempt.argv?.first
            let name = "sudo " + (firstArgument.map { "\(binary) \($0)" } ?? binary)
            return DefinitionDraft(
                definitionID: uniqueSlug(for: name, existing: existingIDs),
                kind: .sudo,
                name: name,
                detail: detail(for: attempt, capture: capture),
                commandPattern: command,
                resolvedCommandPattern: attempt.resolvedCommand ?? "",
                argPattern: firstArgument.map(anchoredLiteral) ?? "",
                matchType: .exact,
                requiredTeamID: attempt.teamID ?? "",
                requiredBinaryHash: ""
            )
        case .authuri:
            let right = attempt.authURI ?? ""
            // An identity-only right (verified table) can only be allowed per
            // app: draft an App Identity definition with the captured Team ID
            // pre-filled; the bundle ID (not on the authd line) is left for
            // the admin, and the validator reports it until filled.
            let identityOnly = AuthURIIdentityScopeRegistry.current.isIdentityOnly(right)
            return DefinitionDraft(
                definitionID: uniqueSlug(for: right, existing: existingIDs),
                kind: .authuri,
                name: right,
                detail: detail(for: attempt, capture: capture),
                authURI: right,
                requiredTeamID: "",
                requiredBinaryHash: "",
                appIdentity: identityOnly,
                appTeamID: identityOnly ? (attempt.teamID ?? "") : "",
                appBundleID: ""
            )
        }
    }

    /// Drafts for a batch of attempts, each slug unique against the library
    /// AND the drafts before it.
    public static func drafts(
        for attempts: [CapturedAttempt],
        capture: RuleCapture? = nil,
        existingIDs: Set<String>
    ) -> [DefinitionDraft] {
        var taken = existingIDs
        return attempts.map { attempt in
            let draft = draft(for: attempt, capture: capture, existingIDs: taken)
            taken.insert(draft.definitionID)
            return draft
        }
    }

    /// `^<escaped literal>$` — matches exactly this argument and nothing else.
    /// `argPattern` is a regular expression over `argv[0]`, so a bare literal
    /// would treat `.`/`+`/`*` as metacharacters and match more than the admin
    /// saw.
    public static func anchoredLiteral(_ argument: String) -> String {
        "^" + NSRegularExpression.escapedPattern(for: argument) + "$"
    }

    // MARK: Helpers

    static func uniqueSlug(for name: String, existing: Set<String>) -> String {
        var base = AuthoringID.slugify(name)
        if base.isEmpty { base = "captured_attempt" }
        return AuthoringID.uniqueID(base: base, existing: existing)
    }

    private static let detailFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    /// Provenance for the definition's description: when, where, who, and
    /// how it ended — the evidence the rule is based on. Names only what the
    /// definition MATCHES (the command and `argv[0]`, or the right) — never
    /// the full argument line, which can carry secrets and would otherwise be
    /// persisted into the policy library forever.
    static func detail(for attempt: CapturedAttempt, capture: RuleCapture?) -> String {
        var parts: [String] = ["Captured \(detailFormatter.string(from: attempt.timestamp))"]
        if let capture {
            parts.append("on \(capture.host.computerName)")
        }
        if let user = attempt.user { parts.append("by \(user)") }
        let matched: String
        switch attempt.kind {
        case .sudo:
            let command = attempt.sudoCommand ?? "(unknown command)"
            matched = attempt.argv?.first.map { "\(command) \($0)" } ?? command
        case .authuri:
            matched = attempt.authURI ?? "(unknown right)"
        }
        var text = parts.joined(separator: " ") + " — \(matched)"
        switch attempt.outcome {
        case .granted: text += " (granted)"
        case .denied: text += " (denied)"
        case .failed: text += " (failed" + (attempt.sudoStatus.map { ": \($0)" } ?? "") + ")"
        case .requested, .unknown: break
        }
        if let rule = attempt.matchedRuleID {
            text += " · Serberus rule \(rule)"
        } else if let verdict = attempt.serberusOutcome {
            // The daemon saw it and decided without a matching rule (the
            // default posture) — the reason the admin is authoring one.
            text += " · Serberus \(verdict) (no rule matched)"
        }
        return text
    }
}
