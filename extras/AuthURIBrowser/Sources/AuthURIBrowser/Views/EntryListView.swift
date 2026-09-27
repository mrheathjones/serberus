import SwiftUI

/// The rights list: a screen header with the filter bar, then card rows. The
/// selected row takes the accent-dim fill + emerald hairline; hover lifts a
/// row to `Theme.elevated`. ↑/↓ move the selection when the list has focus.
struct EntryListView: View {
    @Bindable var catalog: Catalog

    var body: some View {
        let entries = catalog.visibleEntries
        VStack(alignment: .leading, spacing: 0) {
            header(count: entries.count)
                .padding(.horizontal, Spacing.lg)
                .padding(.top, Spacing.md)
                .padding(.bottom, Spacing.md)
            if entries.isEmpty && !catalog.isLoading {
                emptyState
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 6) {
                            ForEach(entries) { entry in
                                EntryRow(entry: entry, selected: catalog.selectedID == entry.id) {
                                    catalog.selectedID = entry.id
                                }
                                .id(entry.id)
                            }
                        }
                        .padding(.horizontal, Spacing.lg)
                        .padding(.bottom, Spacing.lg)
                    }
                    .scrollIndicators(.automatic)
                    .focusable()
                    .focusEffectDisabled()
                    .onMoveCommand { direction in
                        move(direction, in: entries)
                        if let id = catalog.selectedID { withAnimation(.easeOut(duration: 0.15)) { proxy.scrollTo(id, anchor: .center) } }
                    }
                    .onChange(of: catalog.selectedID) { _, id in
                        if let id { proxy.scrollTo(id, anchor: .center) }
                    }
                }
            }
        }
        .navigationTitle("")
    }

    private func header(count: Int) -> some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 22, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("\(count) shown · \(subtitle)")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.textSecondary)
                }
                Spacer(minLength: Spacing.md)
                Button {
                    Task { await catalog.load() }
                } label: {
                    Image(systemName: "arrow.clockwise").frame(width: 14, height: 14)
                }
                .buttonStyle(.ghost)
                .help("Re-read the template and the live database")
                .disabled(catalog.isLoading)
                Button {
                    Task { await catalog.discoverCustomRights() }
                } label: {
                    Label(catalog.hasDiscovered ? "Rediscover" : "Discover custom rights", systemImage: "lock.shield")
                }
                .buttonStyle(.tinted)
                .help("Authenticate as an administrator to list every row in /var/db/auth.db, including third-party and MDM-added rights")
                .disabled(catalog.isDiscovering)
            }
            SearchField(text: $catalog.searchText, prompt: "Search rights, descriptions, badges…")
        }
    }

    private var emptyState: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 26))
                .foregroundStyle(Theme.textMuted)
            Text(catalog.searchText.isEmpty ? "Nothing in this view" : "No matches for “\(catalog.searchText)”")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(Theme.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func move(_ direction: MoveCommandDirection, in entries: [AuthEntry]) {
        guard !entries.isEmpty else { return }
        let index = entries.firstIndex { $0.id == catalog.selectedID }
        switch direction {
        case .up: catalog.selectedID = entries[max((index ?? 0) - 1, 0)].id
        case .down: catalog.selectedID = entries[min((index ?? -1) + 1, entries.count - 1)].id
        default: break
        }
    }

    private var title: String {
        switch catalog.filter {
        case .all: return "Everything"
        case .rights: return "Rights"
        case .rules: return "Named rules"
        case .modified: return "Modified after creation"
        case .drifted: return "Differs from template"
        case .custom: return "Not in template"
        case .wildcards: return "Wildcards"
        case let .badge(badge): return badge.rawValue
        case let .namespace(name): return name
        }
    }

    private var subtitle: String {
        switch catalog.filter {
        case .all: return "rights and named rules"
        case .rights: return "matchable authorization rights"
        case .rules: return "rule templates other rights delegate to"
        case .modified: return "live row rewritten since creation"
        case .drifted: return "live value differs from the system template"
        case .custom: return "present only in the live database"
        case .wildcards: return "prefix rules ending in a dot"
        case let .badge(badge): return badge.filterDescription.lowercased()
        case .namespace: return "rights in this namespace"
        }
    }
}

struct EntryRow: View {
    let entry: AuthEntry
    let selected: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(entry.name)
                        .font(.mono(12.5, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 4)
                    if entry.kind == .rule { TagChip("rule") }
                    if entry.isWildcard { TagChip("wildcard") }
                    if entry.isCustom { TagChip("custom", color: Theme.info) }
                    if entry.isOverridden { TagChip("overridden", color: Theme.warning) }
                    else if entry.isDrifted { TagChip("differs", color: Theme.warning) }
                    else if entry.isModified { TagChip("modified") }
                }
                BadgeRow(badges: entry.badges)
                Text(entry.summary ?? "No description in the authorization database.")
                    .font(.system(size: 12))
                    .foregroundStyle(entry.summary == nil ? Theme.textMuted : Theme.textSecondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Spacing.md)
            .padding(.vertical, Spacing.sm + 2)
            .background(
                selected ? Theme.accentDim : (hovering ? Theme.elevated : Theme.surface),
                in: RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
                    .strokeBorder(selected ? Theme.emerald.opacity(0.55) : Theme.hairline, lineWidth: 1)
            )
            .contentShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityAddTraits(selected ? [.isSelected] : [])
        .animation(.easeOut(duration: 0.12), value: selected)
    }
}

struct BadgeRow: View {
    let badges: [BadgeInstance]

    var body: some View {
        FlowLayout(spacing: 5) {
            ForEach(badges) { badge in
                PillBadge(text: badge.label, color: badge.badge.tint,
                          symbol: badge.badge.systemImage,
                          trailingSymbol: badge.password ? "key.horizontal.fill" : nil)
                    .help(badge.password ? "\(badge.badge.filterDescription) — password prompt" : badge.badge.filterDescription)
            }
        }
    }
}

/// Wraps subviews onto new lines when they do not fit.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(subviews: subviews, width: proposal.width ?? .infinity).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let placement = arrange(subviews: subviews, width: bounds.width)
        for (index, origin) in placement.origins.enumerated() {
            subviews[index].place(at: CGPoint(x: bounds.minX + origin.x, y: bounds.minY + origin.y), proposal: .unspecified)
        }
    }

    private func arrange(subviews: Subviews, width: CGFloat) -> (size: CGSize, origins: [CGPoint]) {
        var origins: [CGPoint] = []
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, maxX: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            origins.append(CGPoint(x: x, y: y))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
            maxX = max(maxX, x - spacing)
        }
        return (CGSize(width: maxX, height: y + rowHeight), origins)
    }
}
