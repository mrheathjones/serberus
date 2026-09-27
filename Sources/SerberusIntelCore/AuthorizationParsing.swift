import Foundation

/// Verdict a single authd line carries about a right, when it carries one.
public enum AuthorizationOutcome: String, Sendable, Equatable {
    /// `Succeeded authorizing right 'X'`.
    case granted
    /// `denied` / `Sandbox denied authorizing right 'X'`.
    case denied
    /// `Failed … authorizing right 'X'`.
    case failed
    /// The right is named (`… for right 'X'`) but this line states no verdict —
    /// the outcome is on a neighbouring line (authd splits a decision across
    /// several lines by engine). Neutral rather than guessed.
    case requested
}

/// What one authd message says about an authorization right.
///
/// Two extraction forms, both grounded in real authd output:
///
/// 1. **Quoted** — `authorizing right 'X'` and `for right 'X'`. Verified over
///    24h of live authd as the only two phrases that quote a right.
/// 2. **Unquoted** — `Validating {credential|session owner|shared credential}
///    user (uid) for X`, where `X` is a **dotted** token.
///
/// Form 2 is essential, not optional: measured over 24h, **four rights appeared
/// ONLY in the unquoted form** — including `system.preferences.datetime`, a
/// right Serberus ships rules for. Parsing quoted forms alone silently hid
/// them, which for a rule-authoring tool is the worst kind of failure.
///
/// The dot is what makes form 2 safe. In that position authd emits either a
/// right (reverse-DNS, always dotted: `system.install.software`,
/// `system.preferences.datetime`) or one of its rule names (hyphenated, never
/// dotted: `is-root`, `is-admin`, `is-appstore`, `use-login-window-ui`,
/// `authenticate-session-owner-or-admin`). Measured across 24h the two sets do
/// not overlap, so requiring a dot admits every right and excludes every rule.
public struct AuthorizationInfo: Sendable, Equatable {
    /// The right this line names, or `nil` if it names none (the credential /
    /// mechanism / sheet noise that surrounds every real decision).
    public let right: String?
    /// The verdict this line states, when it names a right.
    public let outcome: AuthorizationOutcome?
    /// authd's `(engine N)` id — the correlation key that ties the several
    /// lines of one authorization attempt together. Present on ~96% of
    /// right-naming lines (measured over 24h).
    public let engine: String?
    /// Requesting process from `by client '/path'`, when stated.
    public let client: String?
    /// This line reports the attempt FAILING, without naming a right —
    /// `copy_rights: authorization failed`, `Evaluate denied`,
    /// `User credential for rule failed (-60005)`, `Authorization result :-N`.
    /// A right in the same engine that never got its own success line inherits
    /// this, which is how a failed authorization gets a real verdict instead of
    /// a neutral one.
    public let statesEngineFailure: Bool

    public init(
        right: String?,
        outcome: AuthorizationOutcome?,
        engine: String? = nil,
        client: String? = nil,
        statesEngineFailure: Bool = false
    ) {
        self.right = right
        self.outcome = outcome
        self.engine = engine
        self.client = client
        self.statesEngineFailure = statesEngineFailure
    }

    /// Whether this line is about a right at all — the signal the
    /// "Rights only" filter keys on.
    public var namesRight: Bool { right != nil }
}

/// Extracts the authorization right (and its stated verdict) from one authd
/// `eventMessage`. Pure and deterministic.
public enum AuthorizationParser {
    // First `right 'X'` occurrence. `authorizing right 'X'` and `for right 'X'`
    // both end in `right 'X'`, so one pattern covers both.
    private static let rightPattern = try! NSRegularExpression(pattern: #"right '([^']+)'"#)

    /// Unquoted right after `for`, required to be dotted so authd's hyphenated
    /// rule names (`is-admin`, `authenticate-session-owner-or-admin`) can never
    /// match. Anchored to start with a letter so paths (`/System/…`) and
    /// version numbers are excluded too.
    private static let unquotedRightPattern = try! NSRegularExpression(
        pattern: #"\bfor ([A-Za-z][\w-]*(?:\.[\w-]+)+)"#
    )

    private static let enginePattern = try! NSRegularExpression(pattern: #"\(engine (\d+)\)"#)
    private static let clientPattern = try! NSRegularExpression(pattern: #"by client '([^']+)'"#)

    public static func info(from message: String) -> AuthorizationInfo {
        let engine = firstMatch(enginePattern, in: message)
        let client = firstMatch(clientPattern, in: message)
        let failure = statesFailure(message)

        // A quoted right always wins — it is the definitive form, and on lines
        // that have one the trailing `for authorization created by …` clause
        // must not be re-scanned.
        if let right = firstMatch(rightPattern, in: message) {
            return AuthorizationInfo(
                right: right, outcome: outcome(in: message),
                engine: engine, client: client, statesEngineFailure: failure
            )
        }
        // Otherwise fall back to the unquoted `… for <dotted right>` form. These
        // lines state no verdict, so the outcome is neutral.
        if let right = firstMatch(unquotedRightPattern, in: message) {
            return AuthorizationInfo(
                right: right, outcome: .requested,
                engine: engine, client: client, statesEngineFailure: failure
            )
        }
        return AuthorizationInfo(
            right: nil, outcome: nil,
            engine: engine, client: client, statesEngineFailure: failure
        )
    }

    /// Engine-level failure signals, observed verbatim in live authd output.
    /// Deliberately failure-only: an engine-level *success* is not attributed
    /// to a right that lacks its own `Succeeded authorizing right` line,
    /// because an engine can satisfy one right and fail another — inferring
    /// success would manufacture an approval that never happened.
    private static func statesFailure(_ message: String) -> Bool {
        if message.contains("copy_rights: authorization failed") { return true }
        if message.contains("Evaluate denied") { return true }
        if message.contains("credential for rule failed") { return true }
        // "Authorization result :-60005" — negative result codes only; ":0" is success.
        if let range = message.range(of: "Authorization result :") {
            return message[range.upperBound...].hasPrefix("-")
        }
        return false
    }

    private static func firstMatch(_ pattern: NSRegularExpression, in message: String) -> String? {
        let range = NSRange(message.startIndex..., in: message)
        guard let match = pattern.firstMatch(in: message, range: range),
              let captured = Range(match.range(at: 1), in: message) else {
            return nil
        }
        return String(message[captured])
    }

    /// The verdict, from the verb immediately before `authorizing right`.
    /// A line that only *mentions* a right (`for right 'X'`) has no verb and is
    /// reported as ``AuthorizationOutcome/requested``.
    private static func outcome(in message: String) -> AuthorizationOutcome {
        guard let head = message.range(of: "authorizing right") else {
            return .requested
        }
        let prefix = message[message.startIndex..<head.lowerBound].lowercased()
        if prefix.contains("succeeded") { return .granted }
        if prefix.contains("denied") { return .denied }   // covers "Sandbox denied"
        if prefix.contains("failed") { return .failed }
        return .requested
    }
}
