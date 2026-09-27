import SwiftUI

/// Grouped navigation on the lifted ground with a brand header and a status
/// footer. Rows are custom buttons so the selected row takes the accent
/// gradient (Sentinel's selected-tab treatment) instead of the system
/// highlight.
struct SidebarView: View {
    @Bindable var catalog: Catalog

    private struct Item: Identifiable {
        let filter: SidebarFilter
        let title: String
        let symbol: String
        let count: Int
        var tint: Color = Theme.emerald
        var mono = false
        var id: SidebarFilter { filter }
    }

    private var browseItems: [Item] {
        [
            Item(filter: .rights, title: "Rights", symbol: "key.fill", count: catalog.rightsCount),
            Item(filter: .rules, title: "Named rules", symbol: "list.bullet.indent", count: catalog.rulesCount),
            Item(filter: .all, title: "Everything", symbol: "tray.full.fill", count: catalog.entries.count),
            Item(filter: .wildcards, title: "Wildcards", symbol: "asterisk", count: catalog.wildcardCount),
            Item(filter: .drifted, title: "Differs from template", symbol: "exclamationmark.triangle.fill", count: catalog.driftedCount, tint: Theme.warning),
            Item(filter: .modified, title: "Modified after creation", symbol: "pencil.line", count: catalog.modifiedCount),
            Item(filter: .custom, title: "Not in template", symbol: "plus.square.dashed", count: catalog.discoveredCount),
        ]
    }

    private var badgeItems: [Item] {
        AccessBadge.allCases.map {
            Item(filter: .badge($0), title: $0.rawValue, symbol: $0.systemImage, count: catalog.count(for: $0), tint: $0.tint)
        }
    }

    private var namespaceItems: [Item] {
        catalog.namespaces.map {
            Item(filter: .namespace($0.name), title: $0.name, symbol: "point.3.connected.trianglepath.dotted", count: $0.count, mono: true)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                group("Browse", browseItems)
                group("Who can satisfy", badgeItems)
                group("Namespace", namespaceItems)
            }
            .padding(.horizontal, Spacing.sm)
            .padding(.vertical, Spacing.sm)
        }
        .scrollIndicators(.never)
        .navigationSplitViewColumnWidth(min: 236, ideal: 260, max: 320)
        .safeAreaInset(edge: .top, spacing: 0) { brandHeader }
        .safeAreaInset(edge: .bottom, spacing: 0) { statusFooter }
        .background(Theme.backgroundDeep.ignoresSafeArea())
    }

    private func group(_ title: String, _ items: [Item]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            SectionLabel(title)
                .padding(.horizontal, Spacing.md)
                .padding(.bottom, Spacing.xs)
                .accessibilityAddTraits(.isHeader)
            ForEach(items) { item in
                SidebarRow(item: item, selected: catalog.filter == item.filter) {
                    catalog.filter = item.filter
                }
            }
        }
    }

    private var brandHeader: some View {
        HStack(spacing: 11) {
            BrandChip(size: 34)
            VStack(alignment: .leading, spacing: 1) {
                Text("SERBERUS")
                    .font(.system(size: 14, weight: .bold)).tracking(2)
                    .foregroundStyle(Theme.textPrimary)
                Text("Auth URI Browser")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(Theme.emerald.opacity(0.85))
            }
            Spacer()
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.top, Spacing.sm)
        .padding(.bottom, Spacing.md)
    }

    private var statusFooter: some View {
        VStack(spacing: Spacing.sm) {
            Divider().overlay(Theme.glassBorder)
            HStack(alignment: .top, spacing: Spacing.sm) {
                StatusDot(color: footerColor, size: 7)
                    .padding(.top, 3)
                VStack(alignment: .leading, spacing: 1) {
                    Text(footerHeadline)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    Text(footerDetail)
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.textMuted)
                        .lineLimit(2)
                }
                Spacer()
            }
            .padding(.horizontal, Spacing.lg)
            .padding(.bottom, Spacing.sm)
        }
        // Opaque ground so scrolled rows never show through the footer.
        .background(Theme.backgroundDeep)
    }

    private var footerColor: Color {
        if catalog.loadError != nil { return Theme.critical }
        if catalog.isLoading || catalog.isDiscovering { return Theme.warning }
        return Theme.success
    }

    private var footerHeadline: String {
        if let error = catalog.loadError { return error }
        if catalog.isDiscovering { return "Waiting for administrator approval…" }
        if catalog.isLoading { return "Reading authorization database…" }
        return "\(catalog.liveOverlayCount) of \(catalog.entries.count) read live"
    }

    private var footerDetail: String {
        if let message = catalog.discoveryMessage { return message }
        return catalog.hasDiscovered ? "Template + full live database" : "Template + live overlay · Discover for custom rights"
    }

    private struct SidebarRow: View {
        let item: Item
        let selected: Bool
        let action: () -> Void
        @State private var hovering = false

        var body: some View {
            Button(action: action) {
                HStack(spacing: 10) {
                    Image(systemName: item.symbol)
                        .font(.system(size: 12, weight: .semibold))
                        .frame(width: 17, height: 17)
                        .foregroundStyle(selected ? Theme.onEmerald : item.tint)
                    Text(item.title)
                        .font(item.mono ? .mono(12, weight: selected ? .semibold : .medium)
                                        : .system(size: 13, weight: selected ? .semibold : .medium))
                        .foregroundStyle(selected ? Theme.onEmerald : Theme.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 4)
                    Text("\(item.count)")
                        .font(.mono(11))
                        .foregroundStyle(selected ? Theme.onEmerald.opacity(0.8) : Theme.textMuted)
                }
                .padding(.horizontal, Spacing.md)
                .padding(.vertical, 6)
                .background {
                    if selected {
                        RoundedRectangle(cornerRadius: Radius.md, style: .continuous).fill(Theme.accentGradient)
                    } else if hovering {
                        RoundedRectangle(cornerRadius: Radius.md, style: .continuous).fill(Theme.elevated)
                    }
                }
                .contentShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            }
            .buttonStyle(.plain)
            .onHover { hovering = $0 }
            .accessibilityAddTraits(selected ? [.isSelected] : [])
            .animation(.easeOut(duration: 0.12), value: selected)
        }
    }
}
