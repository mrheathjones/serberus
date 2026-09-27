import Foundation
import SwiftUI

/// Who can ultimately satisfy a right, once every `rule` delegation has been
/// followed to a leaf.
enum Principal: Hashable, Sendable {
    case anyone
    case root
    case admin
    case sessionOwner
    case anyUser
    case group(String)
    case mechanisms
    case denied
    case unresolved(String)

    /// Ordering used when an AND-composition has to pick the stricter side.
    var strictness: Int {
        switch self {
        case .denied: return 9
        case .unresolved: return 8
        case .root: return 7
        case .admin: return 6
        case .group: return 5
        case .sessionOwner: return 4
        case .anyUser: return 3
        case .mechanisms: return 2
        case .anyone: return 0
        }
    }
}

/// Extra conditions layered on top of a principal.
enum Constraint: String, Hashable, Sendable, Comparable {
    case entitled = "calling app must hold the matching entitlement"
    case entitledGroup = "calling app must hold the group entitlement"
    case vpnEntitledGroup = "calling app must hold the VPN group entitlement"
    case onConsole = "only from the console (GUI) session"
    case appleSigned = "caller must be Apple-signed"
    case codeRequirement = "caller must match a code-signing requirement"
    case passwordOnly = "password only (no Touch ID / Apple Watch)"

    static func < (lhs: Constraint, rhs: Constraint) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// One way a right can be granted.
struct AccessPath: Hashable, Sendable {
    var principal: Principal
    var password: Bool
    var constraints: Set<Constraint> = []
    /// Delegate chain that led here (outermost first), for explanation.
    var via: [String] = []
    var note: String?

    var badge: AccessBadge {
        switch principal {
        case .anyone: return constraints.contains(.entitled) || constraints.contains(.entitledGroup) ? .entitled : .anyone
        case .root: return .root
        case .admin: return .admin
        case .sessionOwner, .anyUser: return .standardUser
        case .group: return .group
        case .mechanisms: return .mechanisms
        case .denied: return .denied
        case .unresolved: return .unresolved
        }
    }

    /// Plain-English sentence for the detail view.
    var explanation: String {
        var text: String
        switch principal {
        case .anyone:
            text = "Anyone — granted without authentication"
        case .root:
            text = "A process already running as root passes without a prompt"
        case .admin:
            text = password
                ? "An administrator, after entering an admin name and password"
                : "Any member of the admin group, with no password prompt"
        case .sessionOwner:
            text = password
                ? "The user who owns the login session, after entering their own password"
                : "The user who owns the login session, with no password prompt"
        case .anyUser:
            text = password ? "Any local user, after authenticating" : "Any local user, with no password prompt"
        case let .group(name):
            text = password
                ? "A member of the ‘\(name)’ group, after authenticating"
                : "Any member of the ‘\(name)’ group, with no password prompt"
        case .mechanisms:
            text = "Decided by authorization plug-in mechanisms (see the mechanism list)"
        case .denied:
            text = "Nobody — the right is always denied"
        case let .unresolved(name):
            text = "Delegates to ‘\(name)’, which is not defined on this Mac"
        }
        if !constraints.isEmpty {
            text += "; " + constraints.sorted().map(\.rawValue).joined(separator: "; ")
        }
        if let note { text += " (\(note))" }
        if !via.isEmpty { text += " — via " + via.joined(separator: " → ") }
        return text
    }
}

/// The coarse badge shown in the list and used for sidebar filtering.
enum AccessBadge: String, CaseIterable, Identifiable, Sendable {
    case root = "Root"
    case admin = "Admin"
    case group = "Group"
    case standardUser = "Standard user"
    case entitled = "Entitled app"
    case anyone = "Anyone"
    case mechanisms = "Mechanisms"
    case denied = "Denied"
    case unresolved = "Unresolved"

    var id: String { rawValue }

    var systemImage: String {
        switch self {
        case .root: return "terminal.fill"
        case .admin: return "person.badge.key.fill"
        case .group: return "person.3.fill"
        case .standardUser: return "person.fill"
        case .entitled: return "checkmark.seal.fill"
        case .anyone: return "lock.open.fill"
        case .mechanisms: return "gearshape.2.fill"
        case .denied: return "nosign"
        case .unresolved: return "questionmark.circle"
        }
    }

    /// Serberus semantic palette: red = root, amber = admin, blue = standard
    /// user, emerald = open to anyone; the two extra hues cover group and
    /// entitlement, and the neutral greys cover the non-user outcomes.
    var tint: Color {
        switch self {
        case .root: return Theme.critical
        case .admin: return Theme.warning
        case .group: return Theme.violet
        case .standardUser: return Theme.info
        case .entitled: return Theme.cyan
        case .anyone: return Theme.success
        case .mechanisms: return Theme.textSecondary
        case .denied: return Theme.textMuted
        case .unresolved: return Theme.textMuted
        }
    }

    var filterDescription: String {
        switch self {
        case .root: return "Root processes pass silently"
        case .admin: return "Needs an administrator"
        case .group: return "Needs a specific group"
        case .standardUser: return "Session owner or any user can satisfy"
        case .entitled: return "Gated by an app entitlement"
        case .anyone: return "Granted to everyone"
        case .mechanisms: return "Plug-in mechanisms decide"
        case .denied: return "Always refused"
        case .unresolved: return "Delegates to a missing rule"
        }
    }
}

/// One concrete badge instance: the category plus a label that can carry the
/// group name or the password/no-password distinction.
struct BadgeInstance: Hashable, Identifiable, Sendable {
    let badge: AccessBadge
    private(set) var label: String
    let password: Bool
    var id: String { "\(badge.rawValue)|\(label)|\(password)" }

    init(path: AccessPath) {
        badge = path.badge
        password = path.password
        switch path.principal {
        case let .group(name): label = name
        case .sessionOwner: label = "Session owner"
        case .anyUser: label = "Any user"
        case .admin: label = path.password ? "Admin" : "Admin (member)"
        case .anyone where path.badge == .entitled: label = "Entitled app"
        default: label = path.badge.rawValue
        }
        if path.principal != .anyone {
            if !path.constraints.isDisjoint(with: [.entitled, .entitledGroup, .vpnEntitledGroup]) { label += " · entitled" }
        }
        if path.constraints.contains(.onConsole) { label += " · console" }
        if path.constraints.contains(.codeRequirement) { label += " · signed app" }
    }

    static func ordered(from paths: [AccessPath]) -> [BadgeInstance] {
        let order = AccessBadge.allCases
        var seen = Set<BadgeInstance>()
        var result: [BadgeInstance] = []
        for path in paths {
            let instance = BadgeInstance(path: path)
            if seen.insert(instance).inserted { result.append(instance) }
        }
        return result.sorted { lhs, rhs in
            let li = order.firstIndex(of: lhs.badge) ?? 0
            let ri = order.firstIndex(of: rhs.badge) ?? 0
            if li != ri { return li < ri }
            return lhs.label < rhs.label
        }
    }
}

/// A node in the delegate chain, for the "Resolution" outline.
struct ResolutionNode: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let summary: String
    let exists: Bool
    var children: [ResolutionNode]?
}

/// Follows `rule` delegations and mechanism lists down to the set of
/// principals that can satisfy a definition.
struct AccessResolver: Sendable {
    /// Looks up a named rule (or right) by name.
    let lookup: @Sendable (String) -> RuleDefinition?
    private let maxDepth = 12

    func paths(for definition: RuleDefinition) -> [AccessPath] {
        paths(for: definition, visited: [], depth: 0)
    }

    func resolutionTree(name: String, definition: RuleDefinition) -> ResolutionNode {
        node(name: name, definition: definition, visited: [name], depth: 0)
    }

    private func node(name: String, definition: RuleDefinition?, visited: Set<String>, depth: Int) -> ResolutionNode {
        guard let definition else {
            return ResolutionNode(id: visited.sorted().joined() + name, name: name, summary: "not defined on this Mac", exists: false, children: nil)
        }
        let children: [ResolutionNode]? = definition.delegates.isEmpty || depth >= maxDepth
            ? nil
            : definition.delegates.map { child in
                if visited.contains(child) {
                    return ResolutionNode(id: name + "/" + child + "/cycle", name: child, summary: "cycle", exists: true, children: nil)
                }
                return node(name: child, definition: lookup(child), visited: visited.union([child]), depth: depth + 1)
            }
        return ResolutionNode(id: visited.sorted().joined() + "/" + name, name: name, summary: Self.summary(of: definition), exists: true, children: children)
    }

    static func summary(of definition: RuleDefinition) -> String {
        switch definition.effectiveClass {
        case "user":
            var parts: [String] = []
            if let group = definition.group, !group.isEmpty { parts.append("group \(group)") }
            if definition.sessionOwner == true { parts.append("session owner") }
            if definition.allowRoot == true { parts.append("root ok") }
            parts.append(definition.authenticateUser == false ? "no password" : "password")
            return "user · " + parts.joined(separator: " · ")
        case "rule":
            let n = definition.delegates.count
            let k = definition.kOfN ?? n
            let mode = n <= 1 ? "delegates" : (k <= 1 ? "any of" : (k >= n ? "all of" : "\(k) of \(n)"))
            return "rule · \(mode) \(definition.delegates.joined(separator: ", "))"
        case "evaluate-mechanisms":
            return "mechanisms · " + definition.mechanisms.joined(separator: ", ")
        case "allow": return "allow"
        case "deny": return "deny"
        default: return definition.effectiveClass
        }
    }

    private func paths(for definition: RuleDefinition, visited: Set<String>, depth: Int) -> [AccessPath] {
        var constraints = Set<Constraint>()
        if definition.entitled == true { constraints.insert(.entitled) }
        if definition.entitledGroup == true { constraints.insert(.entitledGroup) }
        if definition.vpnEntitledGroup == true { constraints.insert(.vpnEntitledGroup) }
        if definition.requireAppleSigned == true { constraints.insert(.appleSigned) }
        if definition.requirement != nil { constraints.insert(.codeRequirement) }
        if definition.passwordOnly == true { constraints.insert(.passwordOnly) }

        var result: [AccessPath]
        switch definition.effectiveClass {
        case "allow":
            result = [AccessPath(principal: .anyone, password: false)]
        case "deny":
            result = [AccessPath(principal: .denied, password: false)]
        case "user":
            result = userPaths(definition)
        case "evaluate-mechanisms":
            result = mechanismPaths(definition)
        case "rule":
            result = rulePaths(definition, visited: visited, depth: depth)
        default:
            result = [AccessPath(principal: .unresolved("class \(definition.effectiveClass)"), password: false)]
        }
        guard !constraints.isEmpty else { return result }
        return result.map { path in
            var copy = path
            // Root and denial are unaffected by entitlement gating.
            if copy.principal != .root && copy.principal != .denied {
                copy.constraints.formUnion(constraints)
            }
            return copy
        }
    }

    private func userPaths(_ definition: RuleDefinition) -> [AccessPath] {
        let password = definition.authenticateUser ?? true
        var paths: [AccessPath] = []
        if definition.allowRoot == true {
            paths.append(AccessPath(principal: .root, password: false))
        }
        if let group = definition.group, !group.isEmpty {
            paths.append(AccessPath(principal: group == "admin" ? .admin : .group(group), password: password))
        }
        if definition.sessionOwner == true {
            paths.append(AccessPath(principal: .sessionOwner, password: password))
        }
        let hasEntitlementGate = definition.entitled == true || definition.entitledGroup == true || definition.vpnEntitledGroup == true
        if definition.group == nil && definition.sessionOwner != true {
            if hasEntitlementGate {
                // No user check at all: the calling process's entitlement is the credential.
                paths.append(AccessPath(principal: .anyone, password: false, constraints: [.entitled]))
            } else if password {
                paths.append(AccessPath(principal: .anyUser, password: true))
            } else if paths.isEmpty {
                paths.append(AccessPath(principal: .denied, password: false, note: "no group, no owner check, no authentication"))
            }
        }
        return paths
    }

    private func mechanismPaths(_ definition: RuleDefinition) -> [AccessPath] {
        let names = definition.mechanisms
        var constraints = Set<Constraint>()
        var authenticates = false
        var other = false
        for name in names {
            let base = name.split(separator: ",").first.map(String.init) ?? name
            switch base {
            case "builtin:entitled": constraints.insert(.entitled)
            case "builtin:on-console": constraints.insert(.onConsole)
            case "builtin:authenticate", "loginwindow:login": authenticates = true
            default: other = true
            }
        }
        if authenticates {
            return [AccessPath(principal: .anyUser, password: true, constraints: constraints, note: "mechanism login")]
        }
        if other || names.isEmpty {
            return [AccessPath(principal: .mechanisms, password: false, constraints: constraints)]
        }
        return [AccessPath(principal: .anyone, password: false, constraints: constraints)]
    }

    private func rulePaths(_ definition: RuleDefinition, visited: Set<String>, depth: Int) -> [AccessPath] {
        guard depth < maxDepth else {
            return [AccessPath(principal: .unresolved("depth limit"), password: false)]
        }
        let branches: [[AccessPath]] = definition.delegates.map { name in
            guard !visited.contains(name) else {
                return [AccessPath(principal: .unresolved("\(name) (cycle)"), password: false)]
            }
            guard let child = lookup(name) else {
                return [AccessPath(principal: .unresolved(name), password: false)]
            }
            return paths(for: child, visited: visited.union([name]), depth: depth + 1).map { path in
                var copy = path
                copy.via.insert(name, at: 0)
                return copy
            }
        }
        guard !branches.isEmpty else {
            return [AccessPath(principal: .unresolved("empty rule list"), password: false)]
        }
        let n = branches.count
        let k = definition.kOfN ?? n
        if n == 1 || k <= 1 {
            return branches.flatMap { $0 }
        }
        if k >= n {
            return branches.dropFirst().reduce(branches[0]) { acc, next in
                acc.flatMap { a in next.map { b in Self.combine(a, b) } }
            }
        }
        return branches.flatMap { $0 }.map { path in
            var copy = path
            copy.note = "\(k) of \(n) branches must pass"
            return copy
        }
    }

    /// AND-composition of two paths (both must pass).
    private static func combine(_ a: AccessPath, _ b: AccessPath) -> AccessPath {
        if a.principal == .denied { return a }
        if b.principal == .denied { return b }
        var merged = a
        merged.constraints.formUnion(b.constraints)
        merged.password = a.password || b.password
        merged.via = a.via + b.via
        switch (a.principal, b.principal) {
        case (.anyone, _): merged.principal = b.principal
        case (_, .anyone): merged.principal = a.principal
        case let (x, y) where x == y: break
        default:
            let stricter = a.principal.strictness >= b.principal.strictness ? a : b
            let looser = stricter.principal == a.principal ? b : a
            merged.principal = stricter.principal
            merged.note = "also requires \(BadgeInstance(path: looser).label.lowercased())"
        }
        if case .mechanisms = merged.principal, a.principal != b.principal {
            merged.note = merged.note ?? "plus mechanism evaluation"
        }
        return merged
    }
}
