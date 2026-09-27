import AppKit
import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// The single "Serberus" window opened from the menubar. A branded header with
/// tab buttons over the current tab's content: My Activity, My Rules, and Intel
/// (diagnostics). The popover deep-links here by setting
/// ``SerberusWindowModel/tab`` before opening the window.
struct SerberusMainView: View {
    @Bindable var nav: SerberusWindowModel
    let rules: SentinelRulesStore
    let history: ElevationHistoryStore
    /// App-lifetime Intel model — a Capture in progress survives tab switches.
    let intel: IntelModel

    var body: some View {
        VStack(spacing: 0) {
            tabHeader
            Divider().overlay(Theme.glassBorder)
            content
        }
        // maxWidth/maxHeight .infinity so the tabbed content FILLS the window
        // instead of sizing to its own ideal. On some macOS versions a
        // minWidth-only frame lets the content settle at its ideal width and
        // left-align in a wider window — which left the Intel controls bar laid
        // out narrower than the window (leading padding gone, feed-dependent).
        // Filling makes the bar span the window on every version.
        .frame(minWidth: 640, maxWidth: .infinity, minHeight: 460, maxHeight: .infinity)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.accent)
    }

    // MARK: Header + tabs

    private var tabHeader: some View {
        HStack(spacing: Spacing.lg) {
            HStack(spacing: Spacing.sm) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Theme.iconChipGradient)
                    SentinelSigilView().foregroundStyle(Theme.accent).frame(width: 17, height: 17)
                }
                .frame(width: 26, height: 26)
                Text("Sentinel").font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            }
            Spacer()
            HStack(spacing: Spacing.xs) {
                ForEach(SerberusTab.allCases) { tab in
                    tabButton(tab)
                }
            }
        }
        .padding(.horizontal, Spacing.xl)
        .padding(.vertical, Spacing.md)
        .sentinelGlass(Theme.glass2)
    }

    private func tabButton(_ tab: SerberusTab) -> some View {
        let selected = nav.tab == tab
        return Button {
            withAnimation(.easeOut(duration: 0.12)) { nav.tab = tab }
        } label: {
            Label(tab.title, systemImage: tab.symbol)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(selected ? Theme.accentInk : Theme.textSecondary)
                .padding(.horizontal, Spacing.md).padding(.vertical, 6)
                .background {
                    if selected {
                        Capsule().fill(Theme.accentGradient)
                    } else {
                        Capsule().fill(Theme.surface2)
                    }
                }
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }

    // MARK: Content

    @ViewBuilder
    private var content: some View {
        switch nav.tab {
        case .activity:
            HistoryView(history: history, todayOnly: $nav.activityTodayOnly)
        case .rules:
            MyRulesView(rules: rules, history: history)
        case .intel:
            // The former standalone Serberus Intel app, embedded.
            IntelTabView(model: intel)
        }
    }
}
