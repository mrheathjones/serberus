import Foundation

/// A typed, Sendable view of one authorization-database entry (a right or a
/// named rule) as stored in `/System/Library/Security/authorization.plist` or as
/// returned live by `AuthorizationRightGet`.
struct RuleDefinition: Hashable, Sendable {
    struct Field: Hashable, Sendable, Identifiable {
        let key: String
        let value: String
        var id: String { key }
    }

    var ruleClass: String?
    var comment: String?
    var group: String?
    var allowRoot: Bool?
    var authenticateUser: Bool?
    var sessionOwner: Bool?
    var shared: Bool?
    var timeout: Int?
    var tries: Int?
    var version: Int?
    var kOfN: Int?
    /// Contents of the `rule` key — a single name or a list of names.
    var delegates: [String] = []
    var mechanisms: [String] = []
    var entitled: Bool?
    var entitledGroup: Bool?
    var vpnEntitledGroup: Bool?
    var passwordOnly: Bool?
    var extractPassword: Bool?
    var requireAppleSigned: Bool?
    var identifier: String?
    var requirement: String?
    var created: Date?
    var modified: Date?
    /// Every key/value pair, stringified and sorted, for the raw table.
    var fields: [Field] = []
    /// The definition re-serialised as an XML plist.
    var xml: String = ""

    /// The class the daemon will actually apply: an entry that has a `rule`
    /// key but no `class` behaves as `class = rule`.
    var effectiveClass: String {
        if let ruleClass, !ruleClass.isEmpty { return ruleClass }
        if !delegates.isEmpty { return "rule" }
        if !mechanisms.isEmpty { return "evaluate-mechanisms" }
        return "unknown"
    }

    init(plist: [String: Any]) {
        ruleClass = plist["class"] as? String
        comment = (plist["comment"] as? String).map(Self.cleaned)
        group = plist["group"] as? String
        allowRoot = Self.bool(plist["allow-root"])
        authenticateUser = Self.bool(plist["authenticate-user"])
        sessionOwner = Self.bool(plist["session-owner"])
        shared = Self.bool(plist["shared"])
        timeout = Self.int(plist["timeout"])
        tries = Self.int(plist["tries"])
        version = Self.int(plist["version"])
        kOfN = Self.int(plist["k-of-n"])
        if let single = plist["rule"] as? String {
            delegates = [single]
        } else if let many = plist["rule"] as? [String] {
            delegates = many
        }
        mechanisms = plist["mechanisms"] as? [String] ?? []
        entitled = Self.bool(plist["entitled"])
        entitledGroup = Self.bool(plist["entitled-group"])
        vpnEntitledGroup = Self.bool(plist["vpn-entitled-group"])
        passwordOnly = Self.bool(plist["password-only"])
        extractPassword = Self.bool(plist["extract-password"])
        requireAppleSigned = Self.bool(plist["require-apple-signed"])
        identifier = plist["identifier"] as? String
        requirement = plist["requirement"] as? String
        created = Self.date(plist["created"])
        modified = Self.date(plist["modified"])
        fields = plist.keys.sorted().map { Field(key: $0, value: Self.describe(plist[$0] as Any)) }
        if let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
            xml = String(decoding: data, as: UTF8.self)
        }
    }

    // MARK: - Value helpers

    private static func cleaned(_ text: String) -> String {
        text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }

    private static func isBoolean(_ value: Any) -> Bool {
        CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID()
    }

    static func bool(_ value: Any?) -> Bool? {
        guard let value, isBoolean(value) else { return nil }
        return value as? Bool
    }

    static func int(_ value: Any?) -> Int? {
        guard let value, !isBoolean(value), let number = value as? NSNumber else { return nil }
        return number.intValue
    }

    static func date(_ value: Any?) -> Date? {
        if let date = value as? Date { return date }
        guard let value, !isBoolean(value), let number = value as? NSNumber else { return nil }
        return Date(timeIntervalSinceReferenceDate: number.doubleValue)
    }

    static func describe(_ value: Any) -> String {
        if isBoolean(value) { return (value as? Bool) == true ? "true" : "false" }
        switch value {
        case let text as String: return text
        case let number as NSNumber:
            let double = number.doubleValue
            if double == double.rounded() && abs(double) < 1e15 { return String(number.int64Value) }
            return String(double)
        case let date as Date: return date.formatted(date: .abbreviated, time: .shortened)
        case let data as Data: return "<\(data.count) bytes>"
        case let list as [Any]: return list.map(describe).joined(separator: ", ")
        case let dict as [String: Any]:
            return dict.keys.sorted().map { "\($0) = \(describe(dict[$0] as Any))" }.joined(separator: "; ")
        default: return String(describing: value)
        }
    }
}

// MARK: - Human-readable helpers

extension RuleDefinition {
    var timeoutDescription: String? {
        guard let timeout else { return nil }
        switch timeout {
        case 0: return "not cached (prompts every time)"
        case Int(Int32.max)...: return "never expires"
        default:
            if timeout % 3600 == 0 { return "\(timeout / 3600) h" }
            if timeout % 60 == 0 { return "\(timeout / 60) min" }
            return "\(timeout) s"
        }
    }

    var classDescription: String {
        switch effectiveClass {
        case "user": return "user — a user must satisfy the group / owner / root checks"
        case "rule": return "rule — delegates to other named rules"
        case "evaluate-mechanisms": return "evaluate-mechanisms — runs authorization plug-in mechanisms"
        case "allow": return "allow — always granted"
        case "deny": return "deny — always refused"
        default: return effectiveClass
        }
    }
}
