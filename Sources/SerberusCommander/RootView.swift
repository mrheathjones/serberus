import PolicyBuilderCore
import PrivMgrCore
import SerberusUI
import SwiftUI

/// The Serberus shell: a grouped sidebar over the ambient near-black backdrop,
/// with a branded header and a live daemon-status footer. Navigation rows are
/// custom (not `List` selection) so the selected row takes the accent
/// gradient — Sentinel's selected-tab treatment — instead of the system
/// accent highlight.
struct RootView: View {
    @Bindable var model: PolicyBuilderModel
    /// Owned by the app so a window re-open never re-shows the launch page.
    @Binding var launchComplete: Bool
    /// Real local-daemon posture for the sidebar footer (from state.plist).
    @State private var daemonStatus = DaemonStatusReader()

    /// Show the launch/loading page only when there is a Jamf fetch to wait
    /// for (a usable connection) and the app hasn't been revealed yet. With no
    /// Jamf connection there is nothing to front-load, so it never appears —
    /// authoring-only use never sees a splash.
    private var showLanding: Bool {
        !launchComplete && FleetObserverModel.connectionProblem(model.effectiveJamfConnection) == nil
    }

    var body: some View {
        ZStack {
            NavigationSplitView {
                sidebar
                    // The launch splash is a full-window overlay, but the split
                    // view's own titlebar "Sidebar" toggle keeps showing through
                    // it. Remove that toggle while the splash is up (it returns
                    // for normal use once the app is revealed).
                    .toolbar(removing: showLanding ? .sidebarToggle : nil)
            } detail: {
                ZStack {
                    AppBackground()
                    detail
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                }
            }

            if showLanding {
                LaunchLandingView(model: model) {
                    withAnimation(.easeOut(duration: 0.4)) { launchComplete = true }
                }
                .transition(.opacity)
                .zIndex(1)
            }
        }
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
    }

    // MARK: Sidebar

    private var sidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                ForEach(SidebarGroup.allCases) { group in
                    VStack(alignment: .leading, spacing: 2) {
                        SectionLabel(group.title)
                            .padding(.horizontal, Spacing.md)
                            .padding(.bottom, Spacing.xs)
                            .accessibilityAddTraits(.isHeader)
                        ForEach(group.sections) { section in
                            SidebarRow(title: section.title,
                                       glyph: glyph(for: section),
                                       index: SidebarSection.allCases.firstIndex(of: section) ?? 0,
                                       selected: model.selectedSection == section) {
                                model.selectedSection = section
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, Spacing.sm)
            .padding(.vertical, Spacing.sm)
        }
        .scrollIndicators(.never)
        // Keyboard path the old `List` gave for free: ↑/↓ move the selection
        // when the sidebar has focus (rows also carry ⌘1…⌘7).
        .focusable()
        .focusEffectDisabled()
        .onMoveCommand(perform: moveSelection)
        .navigationSplitViewColumnWidth(min: 224, ideal: 248)
        .safeAreaInset(edge: .top, spacing: 0) { brandHeader }
        .safeAreaInset(edge: .bottom, spacing: 0) { statusFooter }
        // Opaque lifted ground (Sentinel's --bg-2) instead of the stock sidebar
        // vibrancy, so the column reads as part of the same near-black window.
        .background(Theme.backgroundDeep.ignoresSafeArea())
    }

    private func moveSelection(_ direction: MoveCommandDirection) {
        let all = SidebarSection.allCases
        guard let index = all.firstIndex(of: model.selectedSection) else { return }
        switch direction {
        case .up: model.selectedSection = all[max(index - 1, 0)]
        case .down: model.selectedSection = all[min(index + 1, all.count - 1)]
        default: break
        }
    }

    private var brandHeader: some View {
        HStack(spacing: 11) {
            // Icon chip + the Serberus sigil (three chevrons) — a miniature of
            // the app icon: same tile gradient, glyph at the handoff's 72%
            // optical box, accent-tinted. 34pt chip spec (radius 10, no stroke).
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Theme.iconChipGradient)
                SerberusSigilView()
                    .foregroundStyle(Theme.emerald)
                    .frame(width: 24, height: 24)
            }
            .frame(width: 34, height: 34)
            VStack(alignment: .leading, spacing: 1) {
                Text("SERBERUS")
                    .font(.system(size: 14, weight: .bold)).tracking(2)
                    .foregroundStyle(Theme.textPrimary)
                Text("Privilege. Controlled.")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(Theme.emerald.opacity(0.85))
            }
            Spacer()
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.top, Spacing.sm)
        .padding(.bottom, Spacing.md)
    }

    /// Maps a sidebar destination to its custom Serberus glyph.
    /// (`.ruleLibrary` is the historical name of the stacked-rows glyph;
    /// it now fronts the flat "Rules" screen.)
    private func glyph(for section: SidebarSection) -> SerberusGlyph {
        switch section {
        case .dashboard:         .dashboard
        case .policies:          .policies
        case .rules:             .ruleLibrary
        case .definitions:       .definitions
        case .decisionSimulator: .decisionSimulator
        case .fleetObserver:     .fleetObserver
        case .settings:          .settings
        }
    }

    private var statusFooter: some View {
        VStack(spacing: Spacing.sm) {
            Divider().overlay(Theme.glassBorder)
            HStack(spacing: Spacing.sm) {
                StatusDot(tone: daemonStatus.tone, size: 7)
                VStack(alignment: .leading, spacing: 1) {
                    Text(daemonStatus.headline).font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    Text(daemonStatus.detail).font(.system(size: 10))
                        .foregroundStyle(Theme.textMuted)
                }
                Spacer()
            }
            .padding(.horizontal, Spacing.lg)
            .padding(.bottom, Spacing.sm)
        }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                daemonStatus.refresh()
            }
        }
    }

    // MARK: Detail

    @ViewBuilder
    private var detail: some View {
        switch model.selectedSection {
        case .dashboard:
            DashboardView(model: model)
        case .policies:
            PolicyLibraryView(model: model)
        case .rules:
            RulesView(model: model)
        case .definitions:
            DefinitionsView(model: model)
        case .decisionSimulator:
            DecisionSimulatorView(model: model)
        case .fleetObserver:
            FleetObserverView(model: model)
        case .settings:
            SettingsView(model: model)
        }
    }
}

// MARK: - Sidebar row

/// One navigation row. The selected row takes the accent gradient with ink
/// text and glyph (Sentinel's selected-tab treatment); idle rows keep an
/// accent-tinted glyph and lift to `Theme.elevated` on hover. Rows 1–9 answer
/// to ⌘1…⌘9 so the screens stay reachable from the keyboard.
private struct SidebarRow: View {
    let title: String
    let glyph: SerberusGlyph
    /// Position in `SidebarSection.allCases` — drives the ⌘-digit shortcut.
    let index: Int
    let selected: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        row
            .accessibilityAddTraits(selected ? [.isSelected] : [])
            .animation(.easeOut(duration: 0.12), value: selected)
    }

    @ViewBuilder
    private var row: some View {
        if index < 9 {
            button.keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
        } else {
            button
        }
    }

    private var button: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                glyph.shape
                    .frame(width: 17, height: 17)
                    .foregroundStyle(selected ? Theme.onEmerald : Theme.emerald)
                Text(title)
                    .font(.system(size: 13, weight: selected ? .semibold : .medium))
                    .foregroundStyle(selected ? Theme.onEmerald : Theme.textSecondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Spacing.md)
            .padding(.vertical, 7)
            .background {
                if selected {
                    RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                        .fill(Theme.accentGradient)
                } else if hovering {
                    RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                        .fill(Theme.elevated)
                }
            }
            .contentShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
