import Foundation
import Observation

/// One right or named rule, merged from the system template and the live
/// database.
struct AuthEntry: Identifiable, Hashable, Sendable {
    enum Kind: String, Sendable { case right, rule }
    enum Source: String, Sendable {
        /// Listed in `/System/Library/Security/authorization.plist`.
        case template
        /// Found only in the live `/var/db/auth.db` (third-party or MDM-added).
        case discovered
    }

    let name: String
    var kind: Kind
    var source: Source
    var template: RuleDefinition?
    var live: RuleDefinition?
    var liveStatus: String?
    var paths: [AccessPath] = []
    var badges: [BadgeInstance] = []

    var id: String { name }
    var isWildcard: Bool { name.hasSuffix(".") }
    var isCustom: Bool { source == .discovered }

    /// The definition authd will actually evaluate.
    var effective: RuleDefinition? { live ?? template }

    /// Human description: the template comment reads best, the live comment
    /// covers rights that only exist in the live database.
    var summary: String? {
        if let comment = template?.comment, !comment.isEmpty { return comment }
        if let comment = live?.comment, !comment.isEmpty { return comment }
        return nil
    }

    /// True when the live row has been rewritten since it was created — the
    /// signature of a local override (MDM, Serberus, `security authorizationdb write`).
    var isModified: Bool {
        guard let live, let created = live.created, let modified = live.modified else { return false }
        return modified.timeIntervalSince(created) > 1
    }

    /// True when the live definition disagrees with the system template on
    /// at least one key — the strongest sign of a local override.
    var isDrifted: Bool { !driftedFields.isEmpty }

    /// Differs from the template AND was rewritten after creation: a local
    /// override. (Apple ships a few rows that differ from the plist as-is.)
    var isOverridden: Bool { isDrifted && isModified }

    /// Keys whose live value differs from the template value.
    var driftedFields: [(key: String, template: String, live: String)] {
        guard let template, let live else { return [] }
        let liveByKey = Dictionary(uniqueKeysWithValues: live.fields.map { ($0.key, $0.value) })
        return template.fields.compactMap { field in
            guard field.key != "comment", let liveValue = liveByKey[field.key], liveValue != field.value else { return nil }
            return (field.key, field.value, liveValue)
        }
    }

    var namespace: String {
        let parts = name.split(separator: ".", omittingEmptySubsequences: true)
        if parts.count >= 2 { return parts[0...1].joined(separator: ".") }
        return parts.first.map(String.init) ?? "other"
    }
}

enum SidebarFilter: Hashable {
    case all
    case rights
    case rules
    case modified
    case drifted
    case custom
    case wildcards
    case badge(AccessBadge)
    case namespace(String)
}

@MainActor
@Observable
final class Catalog {
    private(set) var entries: [AuthEntry] = []
    private(set) var isLoading = false
    private(set) var isDiscovering = false
    private(set) var loadError: String?
    private(set) var discoveryMessage: String?
    private(set) var liveOverlayCount = 0
    private(set) var discoveredCount = 0
    private(set) var hasDiscovered = false

    var searchText = ""
    var filter: SidebarFilter = .rights
    var selectedID: String?

    var selectedEntry: AuthEntry? {
        guard let selectedID else { return nil }
        return entries.first { $0.id == selectedID }
    }

    var rightsCount: Int { entries.filter { $0.kind == .right }.count }
    var rulesCount: Int { entries.filter { $0.kind == .rule }.count }
    var modifiedCount: Int { entries.filter(\.isModified).count }
    var driftedCount: Int { entries.filter(\.isDrifted).count }
    var wildcardCount: Int { entries.filter(\.isWildcard).count }

    func count(for badge: AccessBadge) -> Int {
        entries.filter { $0.kind == .right && $0.badges.contains { $0.badge == badge } }.count
    }

    var namespaces: [(name: String, count: Int)] {
        Dictionary(grouping: entries.filter { $0.kind == .right }, by: \.namespace)
            .map { (name: $0.key, count: $0.value.count) }
            .sorted { $0.name < $1.name }
    }

    var visibleEntries: [AuthEntry] {
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        return entries.filter { entry in
            guard matches(filter: filter, entry: entry) else { return false }
            guard !query.isEmpty else { return true }
            if entry.name.lowercased().contains(query) { return true }
            if let summary = entry.summary, summary.lowercased().contains(query) { return true }
            return entry.badges.contains { $0.label.lowercased().contains(query) }
        }
    }

    private func matches(filter: SidebarFilter, entry: AuthEntry) -> Bool {
        switch filter {
        case .all: return true
        case .rights: return entry.kind == .right
        case .rules: return entry.kind == .rule
        case .modified: return entry.isModified
        case .drifted: return entry.isDrifted
        case .custom: return entry.isCustom
        case .wildcards: return entry.isWildcard
        case let .badge(badge): return entry.kind == .right && entry.badges.contains { $0.badge == badge }
        case let .namespace(name): return entry.kind == .right && entry.namespace == name
        }
    }

    func entry(named name: String) -> AuthEntry? {
        entries.first { $0.name == name }
    }

    // MARK: - Loading

    func load() async {
        guard !isLoading else { return }
        isLoading = true
        loadError = nil
        defer { isLoading = false }

        let previouslyDiscovered = entries.filter(\.isCustom).map { LiveDatabaseDiscovery.Row(name: $0.name, kind: $0.kind) }
        let result = await Task.detached(priority: .userInitiated) { () -> Result<[AuthEntry], Error> in
            do {
                return .success(try Self.loadEntries(extra: previouslyDiscovered))
            } catch {
                return .failure(error)
            }
        }.value

        switch result {
        case let .success(list):
            entries = list
            liveOverlayCount = list.filter { $0.live != nil }.count
            discoveredCount = list.filter(\.isCustom).count
            if let selectedID, !list.contains(where: { $0.id == selectedID }) { self.selectedID = nil }
        case let .failure(error):
            loadError = error.localizedDescription
        }
    }

    /// Asks for admin credentials, lists every row in the live database, and
    /// merges rows that the template does not know about.
    func discoverCustomRights() async {
        guard !isDiscovering else { return }
        isDiscovering = true
        discoveryMessage = nil
        defer { isDiscovering = false }

        let existing = entries
        let result = await Task.detached(priority: .userInitiated) { () -> Result<([AuthEntry], Int), Error> in
            do {
                let rows = try LiveDatabaseDiscovery.discover()
                let known = Set(existing.map(\.name))
                let additions = rows.filter { !known.contains($0.name) }.map {
                    AuthEntry(name: $0.name, kind: $0.kind, source: .discovered)
                }
                return .success((Self.overlayLive(existing + additions), rows.count))
            } catch {
                return .failure(error)
            }
        }.value

        switch result {
        case let .success((list, total)):
            entries = list
            hasDiscovered = true
            liveOverlayCount = list.filter { $0.live != nil }.count
            discoveredCount = list.filter(\.isCustom).count
            discoveryMessage = "Live database holds \(total) rows; \(discoveredCount) not in the system template."
        case let .failure(error):
            if case CatalogError.cancelled = error { return }
            discoveryMessage = "Discovery failed: \(error.localizedDescription)"
        }
    }

    /// Template entries plus any extra live-only rows, with the live overlay
    /// and badges applied. Synchronous; used by `load()` and by `--dump`.
    nonisolated static func loadEntries(extra: [LiveDatabaseDiscovery.Row]) throws -> [AuthEntry] {
        let template = try AuthorizationTemplate.load()
        var merged: [AuthEntry] = template.map {
            AuthEntry(name: $0.name, kind: $0.kind, source: .template, template: $0.definition)
        }
        let known = Set(merged.map(\.name))
        for row in extra where !known.contains(row.name) {
            merged.append(AuthEntry(name: row.name, kind: row.kind, source: .discovered))
        }
        return overlayLive(merged)
    }

    /// Reads every entry's live definition, then resolves badges against the
    /// live-or-template lookup table.
    nonisolated private static func overlayLive(_ input: [AuthEntry]) -> [AuthEntry] {
        var list = input
        for index in list.indices {
            let outcome = LiveAuthorizationReader.read(list[index].name)
            list[index].live = outcome.definition
            list[index].liveStatus = outcome.definition == nil ? LiveAuthorizationReader.describe(status: outcome.status) : nil
        }
        let table = Dictionary(list.map { ($0.name, $0.effective) }, uniquingKeysWith: { first, _ in first })
        let resolver = AccessResolver { name in table[name] ?? nil }
        for index in list.indices {
            guard let definition = list[index].effective else {
                list[index].paths = [AccessPath(principal: .unresolved("no definition"), password: false)]
                list[index].badges = BadgeInstance.ordered(from: list[index].paths)
                continue
            }
            let paths = resolver.paths(for: definition)
            list[index].paths = paths
            list[index].badges = BadgeInstance.ordered(from: paths)
        }
        return list.sorted { $0.name < $1.name }
    }

    nonisolated static func resolver(for entries: [AuthEntry]) -> AccessResolver {
        let table = Dictionary(entries.map { ($0.name, $0.effective) }, uniquingKeysWith: { first, _ in first })
        return AccessResolver { name in table[name] ?? nil }
    }
}
