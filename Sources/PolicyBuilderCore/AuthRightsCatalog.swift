import Foundation
import Observation
import PrivMgrCore

/// One authorization right discovered from the running Mac's authorization
/// database.
public struct AuthorizationRight: Identifiable, Sendable, Hashable {
    public var id: String { name }
    public var name: String
    /// `class` of the rule: user, rule, evaluate-mechanisms, allow, deny.
    public var ruleClass: String?
    /// Required group for `class == user` rights (e.g. "admin").
    public var group: String?
    public var comment: String?
    /// `right` (matchable) or `rule` (a named rule template).
    public var kind: Kind
    /// Why the daemon refuses a plain (not identity-scoped) `allow` rule on
    /// this right, judged against this Mac's shipped database, or nil when
    /// it accepts one: a rule class or wildcard, a protected or
    /// root-equivalent right, a mechanism chain, or a definition that is not
    /// a plain admin-password gate. Each Mac still checks its own live
    /// definition.
    public var allowRefusal: String?
    /// Why the daemon refuses a `deny` rule on this right, or nil when it
    /// accepts one.
    public var denyRefusal: String?

    public enum Kind: String, Sendable { case right, rule }

    public init(name: String, ruleClass: String?, group: String?, comment: String?, kind: Kind,
                allowRefusal: String? = nil, denyRefusal: String? = nil) {
        self.name = name
        self.ruleClass = ruleClass
        self.group = group
        self.comment = comment
        self.kind = kind
        self.allowRefusal = allowRefusal
        self.denyRefusal = denyRefusal
    }

    /// Whether the daemon refuses every plain rule on this right.
    public var refusedForEveryRule: Bool { allowRefusal != nil && denyRefusal != nil }

    /// Why the daemon refuses a plain `allow` and a `deny` on `name`, judged
    /// against `rights` and `rules` of a shipped database. Mirrors the
    /// daemon's checks (``AuthRightTargetPolicy`` and ``AuthRightNativeGate``).
    public static func refusals(for name: String, rights: [String: Any], rules: [String: Any])
        -> (allow: String?, deny: String?) {
        if let reason = AuthRightTargetPolicy.targetRejectionReason(name) { return (reason, reason) }
        if AuthRightTargetPolicy.isProtected(name) {
            let reason = "'\(name)' is protected; Serberus never modifies it"
            return (reason, reason)
        }
        if let chain = AuthRightNativeGate.mechanismChain(name, rights: rights, rules: rules) {
            let reason = "it runs a mechanism chain (\(chain)), which Serberus never replaces with a password rule"
            return (reason, reason)
        }
        let deny = AuthRightTargetPolicy.denyRejectionReason(name)
        if let reason = AuthRightTargetPolicy.allowRejectionReason(name) { return (reason, deny) }
        if AuthRightTargetPolicy.isRootEquivalent(name) {
            return ("an allow would give every standard user root; allow one app with an identity-scoped rule instead", deny)
        }
        return (AuthRightNativeGate.plainAllowRefusal(name, rights: rights, rules: rules), deny)
    }

    public var isWildcard: Bool { name.hasSuffix(".") }

    /// Coarse category from the name prefix, for grouping/filtering.
    public var category: String {
        if name.hasPrefix("com.apple.") { return "com.apple" }
        let head = name.split(separator: ".").first.map(String.init) ?? name
        return head.isEmpty ? "other" : head
    }
}

/// Enumerates **all** authorization rights from the live macOS authorization
/// database, so the rule builder offers real right URIs rather than a hardcoded
/// list.
///
/// Source: `/System/Library/Security/authorization.plist` — the system's
/// authorization-rights database, world-readable, no root and no entitlement
/// required from the Commander app. (The mutable copy at `/var/db/auth.db` is
/// root-only and is read by the daemon in a later tier.) Individual live
/// definitions can be confirmed with `security authorizationdb read <right>`.
@MainActor
@Observable
public final class AuthRightsCatalog {
    public private(set) var rights: [AuthorizationRight] = []
    public private(set) var loaded = false
    public private(set) var loadError: String?
    public let sourcePath: String

    public init(sourcePath: String = "/System/Library/Security/authorization.plist") {
        self.sourcePath = sourcePath
    }

    /// Loads once; safe to call repeatedly (e.g. on sheet appear).
    public func loadIfNeeded() {
        guard !loaded else { return }
        reload()
    }

    /// (Re)parses the authorization database template.
    public func reload() {
        loaded = true
        loadError = nil
        guard let data = FileManager.default.contents(atPath: sourcePath) else {
            loadError = "Couldn’t read \(sourcePath)"
            return
        }
        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let root = plist as? [String: Any] else {
            loadError = "Couldn’t parse the authorization database"
            return
        }

        let shippedRights = root["rights"] as? [String: Any] ?? [:]
        let shippedRules = root["rules"] as? [String: Any] ?? [:]
        var parsed: [AuthorizationRight] = []
        func ingest(_ dict: [String: Any], kind: AuthorizationRight.Kind) {
            for (name, value) in dict {
                guard !name.isEmpty, let entry = value as? [String: Any] else { continue }
                let refusals: (allow: String?, deny: String?)
                if kind == .rule {
                    let reason = "'\(name)' is a rule class, not a right a rule can target"
                    refusals = (reason, reason)
                } else {
                    refusals = AuthorizationRight.refusals(for: name, rights: shippedRights, rules: shippedRules)
                }
                parsed.append(AuthorizationRight(
                    name: name,
                    ruleClass: entry["class"] as? String,
                    group: entry["group"] as? String,
                    comment: (entry["comment"] as? String)?
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                        .replacingOccurrences(of: "\n", with: " "),
                    kind: kind,
                    allowRefusal: refusals.allow,
                    denyRefusal: refusals.deny))
            }
        }
        ingest(shippedRights, kind: .right)
        ingest(shippedRules, kind: .rule)
        rights = parsed.sorted { $0.name < $1.name }
    }

    public var rightsCount: Int { rights.filter { $0.kind == .right }.count }
    public var rulesCount: Int { rights.filter { $0.kind == .rule }.count }

    /// Fast membership set of every known right/rule name on this Mac.
    private var nameSet: Set<String> { Set(rights.map(\.name)) }

    /// Whether `name` is a known authorization right or rule in this Mac's
    /// authorization database. Returns `nil` when the catalog hasn't loaded or
    /// failed to load (existence can't be determined — callers should not warn).
    public func existence(of name: String) -> Bool? {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard loaded, loadError == nil, !trimmed.isEmpty else { return nil }
        return nameSet.contains(trimmed)
    }

    /// Case-insensitive search across name and comment, optionally including
    /// the named rule templates.
    public func search(_ query: String, includeRules: Bool = false) -> [AuthorizationRight] {
        let pool = includeRules ? rights : rights.filter { $0.kind == .right }
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return pool }
        return pool.filter {
            $0.name.lowercased().contains(q) || ($0.comment?.lowercased().contains(q) ?? false)
        }
    }
}
