import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// The Serberus Sentinel popover (design: "Menu bar popover — My rules"):
/// the user checks what they are and are not allowed to do on this Mac, and
/// can request more access. Everything shown is real state — the rule list
/// and daemon state come over XPC (cached on disk for offline), the
/// audited-today counter from the Sentinel's own prompt history.
struct MenubarContentView: View {
    let model: MenubarStateModel
    let rules: SentinelRulesStore
    let history: ElevationHistoryStore
    let jit: JITAdminViewModel
    /// How many "most-used rules" to list (managed `menuBarTopRulesCount`, 0 hides).
    var topRulesCount: Int = 3
    /// Pulls fresh daemon state; run when the popover opens so it never shows
    /// stale state, even between poll ticks.
    var refresh: (() async -> Void)? = nil

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var showAdminRequest = false
    /// Live clock driving the grant/admin countdowns. Ticked once a second while
    /// the popover is open (see the `.task` in `body`) so "12m remaining" counts
    /// down in place instead of freezing at its open-time value. A manual
    /// cancellation-guarded loop, not `TimelineView` — the same discipline the
    /// menu-bar icon uses to stay off the main-thread-spin path.
    @State private var clock = Date()

    /// Closes the menubar popover, then opens (launching if needed) the separate
    /// full Serberus Sentinel app at `route`. The two are distinct processes, so
    /// this crosses the boundary with a custom-scheme URL (``SentinelFullApp``)
    /// rather than SwiftUI's in-process `openWindow`.
    ///
    /// Closing the popover first is why a deep link no longer leaves the popover
    /// hanging over the window (#1); it also works from the gear `Menu` (#2)
    /// because launching another app does not depend on this app's scene state.
    private func openFullApp(_ route: SentinelDeepLink) {
        SentinelPopover.dismiss()
        SentinelFullApp.open(route)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            rulesSection
            adminSection
            activeElevations
            footer
        }
        .frame(width: 380)
        .background(
            LinearGradient(colors: [Theme.popoverTop, Theme.popoverBottom],
                           startPoint: .top, endPoint: .bottom)
        )
        .preferredColorScheme(.dark)
        .tint(Theme.accent)
        .task { await refresh?() }
        .task {
            // Tick the countdown clock every second while the popover is open.
            // The task is cancelled when the popover closes; the guard after the
            // sleep prevents a cancelled `Task.sleep` (which returns immediately)
            // from spinning.
            while !Task.isCancelled {
                clock = Date()
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled else { break }
            }
        }
    }

    // MARK: Header (glass chrome)

    private var header: some View {
        VStack(spacing: 12) {
            HStack(spacing: Spacing.md) {
                appIconChip
                VStack(alignment: .leading, spacing: 3) {
                    Text("Serberus Sentinel")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                    statusLine
                }
                Spacer()
                gearMenu
            }
            counterPair
        }
        .padding(.top, Spacing.lg)
        .padding(.horizontal, Spacing.xl)
        .padding(.bottom, Spacing.lg)
        .sentinelGlass(Theme.glass2)
        .overlay(alignment: .bottom) { Theme.glassBorder.frame(height: 1) }
    }

    private var appIconChip: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Theme.iconChipGradient)
            SentinelSigilView()
                .foregroundStyle(Theme.accent)
                .frame(width: 21, height: 21)
        }
        .frame(width: 34, height: 34)
        .accessibilityHidden(true)
    }

    // Both halves of the status line derive from the same steady daemon
    // state (`model.icon`) — the prompt pulse and post-denial flash are
    // menubar-sigil-only presentations, so the popover header can never
    // contradict itself (red dot next to "Protected").
    private var statusTone: SentinelTone {
        switch model.icon {
        case .healthy: return .healthy
        case .pending: return .pending
        case .degraded: return .degraded
        case .killSwitch, .offline: return .offline
        }
    }

    private var statusText: String {
        switch model.icon {
        case .healthy:
            if let synced = rules.lastSyncedAt {
                return "Protected · synced \(relativeAgo(synced))"
            }
            // Daemon reachable but the rule list didn't come from it this
            // session (older daemon, or a failing userRules query) — never
            // present cached rules as live policy.
            return rules.isFromCache ? "Protected · cached rules" : "Protected"
        case .pending:
            // The three setup states are distinct, actionable conditions —
            // name the missing piece so IT knows what to deliver.
            switch model.daemonState {
            case .awaitingConfig: return "Waiting for configuration"
            case .pendingPPPC: return "Setup pending · disk access"
            case .pendingProfiles: return "Setup pending · awaiting policy"
            default: return "Setup pending"
            }
        case .degraded: return "Degraded · enforcement issue"
        case .killSwitch: return "Disabled by IT"
        case .offline: return rules.snapshot == nil ? "Offline" : "Offline · cached rules"
        }
    }

    private var statusLine: some View {
        HStack(spacing: 6) {
            PulsingDot(color: statusTone.color, animated: model.icon == .healthy && !reduceMotion)
            Text(statusText)
                .font(.system(size: 11.5))
                .foregroundStyle(Theme.textSecondary)
                .lineLimit(1)
        }
    }

    private var gearMenu: some View {
        Menu {
            Button("Open Sentinel") { openFullApp(.home) }
            #if DEBUG
            Button("Demo Prompt") { SentinelPopover.openPromptDemo() }
            #endif
            Divider()
            Button("Quit Serberus Sentinel") { NSApplication.shared.terminate(nil) }
        } label: {
            Image(systemName: "gearshape")
                .font(.system(size: 14))
                .foregroundStyle(Theme.textMuted)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel("Sentinel settings")
    }

    private var counterPair: some View {
        HStack(spacing: Spacing.sm) {
            // Tapping a counter deep-links into the Serberus window.
            counterCard(value: "\(rules.snapshot?.rules.count ?? 0)", label: "My rules",
                        valueColor: Theme.textPrimary, hint: "View all rules") {
                openFullApp(.rules)
            }
            counterCard(value: "\(history.auditedTodayCount())", label: "Audited today",
                        valueColor: Theme.silent, hint: "View today's activity") {
                openFullApp(.activityToday)
            }
        }
    }

    private func counterCard(value: String, label: String, valueColor: Color,
                             hint: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 0) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(value)
                        .font(.system(size: 17, weight: .semibold, design: .monospaced))
                        .foregroundStyle(valueColor)
                    Text(label.uppercased())
                        .font(.system(size: 10.5))
                        .tracking(0.4)
                        .foregroundStyle(Theme.textMuted)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(Theme.textMuted)
                    .padding(.top, 2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 9).padding(.horizontal, 11)
            .background(Theme.surface2, in: RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous).strokeBorder(Theme.stroke, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
        .accessibilityHint(hint)
    }

    // MARK: Rules (most-used)

    private func ruleName(for rule: SentinelRuleSummary) -> String {
        "\(rule.profileKey) · \(rule.ruleID)"
    }

    /// The `topRulesCount` rules with the most prompts, most-hit first. Only
    /// prompted rules qualify (see ``ElevationHistoryStore/ruleHitCounts()``);
    /// the full list lives in the Serberus window.
    private var topRules: [(rule: SentinelRuleSummary, count: Int)] {
        guard topRulesCount > 0, let all = rules.snapshot?.rules else { return [] }
        let counts = history.ruleHitCounts()
        return all
            .compactMap { rule -> (rule: SentinelRuleSummary, count: Int)? in
                let count = counts[ruleName(for: rule)] ?? 0
                return count > 0 ? (rule, count) : nil
            }
            .sorted { $0.count > $1.count }
            .prefix(topRulesCount)
            .map { $0 }
    }

    /// The rule the user was most recently prompted for (drives the
    /// highlighted row).
    private var lastPromptedRuleName: String? {
        history.entries.first(where: { $0.ruleName != nil })?.ruleName
    }

    @ViewBuilder
    private var rulesSection: some View {
        if topRulesCount > 0 {
            VStack(spacing: 0) {
                HStack {
                    SectionLabel(text: "Most used rules")
                    Spacer()
                    Button {
                        openFullApp(.rules)
                    } label: {
                        HStack(spacing: 3) {
                            Text("See all")
                            Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold))
                        }
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundStyle(Theme.textSecondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, Spacing.xl)
                .padding(.top, Spacing.lg)
                .padding(.bottom, Spacing.sm)

                let top = topRules
                if top.isEmpty {
                    emptyTopRules
                } else {
                    let highlighted = lastPromptedRuleName
                    VStack(spacing: 0) {
                        ForEach(top, id: \.rule.id) { entry in
                            SentinelRuleRow(
                                rule: entry.rule,
                                hitCount: entry.count,
                                isHighlighted: ruleName(for: entry.rule) == highlighted,
                                lastUsed: history.lastEntry(forRuleNamed: ruleName(for: entry.rule))?.date
                            )
                        }
                    }
                    .padding(.bottom, Spacing.xxs)
                }
            }
        }
    }

    private var emptyTopRules: some View {
        VStack(spacing: 5) {
            let ruleCount = rules.snapshot?.rules.count ?? 0
            Text(ruleCount == 0 ? "No rules assigned yet" : "No rules used yet")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Theme.textSecondary)
            if ruleCount > 0 {
                Button { openFullApp(.rules) } label: {
                    Text("See all \(ruleCount) rules")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Theme.accent)
                }
                .buttonStyle(.plain)
            } else {
                Text(model.icon == .offline && rules.snapshot == nil
                     ? "Rules will appear when the daemon is back."
                     : "Rules arrive with your Mac's policy profile.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textMuted)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Spacing.xl)
        .padding(.horizontal, Spacing.xl)
    }

    // MARK: JIT local-admin

    @ViewBuilder
    private var adminSection: some View {
        if jit.info.available {
            // The active window is always visible; the request card only
            // after "Request access…" (footer) is pressed.
            switch jit.phase {
            case .active(let expiresAt):
                sectionBlock(label: "Admin access") { activeAdminCard(expiresAt: expiresAt) }
            case .requesting:
                sectionBlock(label: "Admin access") {
                    HStack(spacing: Spacing.sm) {
                        ProgressView().controlSize(.small)
                        Text("Requesting…").font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .sentinelCard()
                }
            default:
                if showAdminRequest {
                    sectionBlock(label: "Admin access") { requestAdminCard }
                }
            }
        }
    }

    private func sectionBlock(label: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            SectionLabel(text: label)
            content()
        }
        .padding(.horizontal, Spacing.xl)
        .padding(.top, Spacing.md)
    }

    private func activeAdminCard(expiresAt: Date) -> some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: "person.badge.key.fill").font(.system(size: 15))
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 1) {
                Text("Admin access active").font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text("\(relativeRemaining(expiresAt)) remaining").font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.accent)
            }
            Spacer()
            Button("End now") { Task { await jit.end() } }
                .buttonStyle(.plain)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Theme.deny)
        }
        .sentinelCard()
    }

    private var requestAdminCard: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            if jit.needsJustification {
                TextField("Reason for admin access…", text: Binding(
                    get: { jit.justification }, set: { jit.justification = $0 }
                ), axis: .vertical)
                    .textFieldStyle(.plain).font(.system(size: 12)).foregroundStyle(Theme.textPrimary)
                    .lineLimit(1...3)
                    .padding(Spacing.sm)
                    .background(Theme.backgroundDeep.opacity(0.6), in: RoundedRectangle(cornerRadius: Radius.chip, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: Radius.chip, style: .continuous).strokeBorder(Theme.stroke, lineWidth: 1))
            }
            if case .message(let text) = jit.phase {
                Text(text).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // Jamf Connect missing or not signed by Jamf: the item stays visible
            // but disabled, with the reason, instead of failing silently.
            if let reason = jit.unavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button {
                Task { await jit.submit() }
            } label: {
                Label(jit.info.provider == .jamfConnect ? "Request admin (Jamf Connect)" : "Request admin access",
                      systemImage: "key.horizontal.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(SentinelEmeraldButton())
            .disabled(!jit.canSubmit)
            .opacity(jit.canSubmit ? 1 : 0.5)
        }
        .sentinelCard()
    }

    // MARK: Active elevations

    @ViewBuilder
    private var activeElevations: some View {
        // JIT admin grants are surfaced by the Admin Access section above.
        let grants = model.displayGrants().filter { !JITAdminGrant.isJITGrant($0) }
        if !grants.isEmpty {
            sectionBlock(label: "Active elevations") {
                VStack(spacing: Spacing.xs) {
                    ForEach(grants) { grant in
                        HStack(spacing: Spacing.sm) {
                            SentinelStatusDot(tone: .healthy, size: 6)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(grant.canonicalPath)
                                    .font(.system(size: 11.5, design: .monospaced))
                                    .foregroundStyle(Theme.textPrimary)
                                    .lineLimit(1).truncationMode(.middle)
                                Text(grant.ruleID).font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(Theme.textMuted)
                            }
                            Spacer()
                            if let expires = grant.expiresAt {
                                Text(relativeRemaining(expires))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(Theme.accent)
                            }
                        }
                        .sentinelCard(padding: Spacing.sm)
                    }
                }
            }
        }
    }

    // MARK: Footer (glass chrome)

    private var footer: some View {
        HStack(spacing: Spacing.sm) {
            if jit.info.available, !jitWindowActive {
                Button {
                    withAnimation(reduceMotion ? nil : .easeOut(duration: 0.15)) {
                        showAdminRequest.toggle()
                    }
                } label: {
                    Label("Request access…", systemImage: "hand.raised")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(SentinelEmeraldButton())
                Button {
                    openFullApp(.home)
                } label: {
                    Label("Open Sentinel", systemImage: "square.grid.2x2")
                }
                .buttonStyle(SentinelGhostButton())
            } else {
                Button {
                    openFullApp(.home)
                } label: {
                    Label("Open Sentinel", systemImage: "square.grid.2x2")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(SentinelGhostButton())
            }
        }
        .padding(.vertical, Spacing.md)
        .padding(.horizontal, Spacing.lg)
        .padding(.top, 1)
        .sentinelGlass(Theme.glass)
        .overlay(alignment: .top) { Theme.glassBorder.frame(height: 1) }
        .padding(.top, Spacing.md)
    }

    private var jitWindowActive: Bool {
        if case .active = jit.phase { return true }
        return false
    }

    // MARK: Formatting

    private func relativeAgo(_ date: Date) -> String {
        let secs = max(0, Int(Date().timeIntervalSince(date)))
        if secs < 60 { return "just now" }
        if secs < 3600 { return "\(secs / 60)m ago" }
        return "\(secs / 3600)h ago"
    }

    /// Exact remaining time as a zero-padded clock: `MM:SS`, or `HH:MM:SS` once
    /// an hour or more is left (e.g. 4 minutes → `04:00`, 90 minutes → `01:30:00`).
    /// Measured against the ticking `clock` (not `Date()`), so reading it from
    /// the view body re-renders the countdown each second while the popover is
    /// open.
    private func relativeRemaining(_ date: Date) -> String {
        let total = max(0, Int(date.timeIntervalSince(clock)))
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let seconds = total % 60
        if hours > 0 {
            return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
        }
        return String(format: "%02d:%02d", minutes, seconds)
    }
}

/// The pulsing status dot (design: 6×6 --allow dot, 2.6s ease-in-out,
/// opacity 1 → 0.35). Static when Reduce Motion is on or the state is not
/// healthy.
///
/// ⚠️ The pulse MUST stay a view-scoped `.animation(_:value:)` on the dot's own
/// opacity — NEVER a `withAnimation { … }` (transaction-level) call from
/// `.task`/`onAppear`. This view first renders in the same update as the
/// `MenuBarExtra` popover's initial layout, and a transaction-level
/// `repeatForever(autoreverses:)` animation leaks into every layout change in
/// that transaction — including the host window's own frame fix-up. On a
/// built-in MacBook display (notch menu bar → the popover is placed, then
/// nudged into its final frame) that produced the reported "slides out from the
/// icon and back in" bounce, forever, while the popover was open; external
/// displays land the frame in one pass and never showed it.
private struct PulsingDot: View {
    let color: Color
    let animated: Bool
    @State private var dimmed = false

    private var pulse: Animation? {
        animated ? .easeInOut(duration: 1.3).repeatForever(autoreverses: true) : nil
    }

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 6, height: 6)
            .opacity(dimmed ? 0.35 : 1)
            // Scoped: applies only to the `.opacity` above, not the transaction.
            .animation(pulse, value: dimmed)
            .task(id: animated) { dimmed = animated }
            .accessibilityHidden(true)
    }
}
