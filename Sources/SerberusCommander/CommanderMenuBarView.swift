import AppKit
import PolicyBuilderCore
import PrivMgrCore
import SerberusUI
import SwiftUI

/// Dismisses Commander's `MenuBarExtra` popover. SwiftUI exposes no public
/// dismiss for it, so its host window (a private `…MenuBarExtra…` class) is
/// closed directly — the same approach as the Sentinel agent's popover.
/// A no-match is a harmless no-op.
enum CommanderPopover {
    @MainActor static func dismiss() {
        for window in NSApplication.shared.windows
        where "\(type(of: window))".contains("MenuBarExtra") {
            window.close()
        }
    }
}

/// The status-item glyph: the Serberus sigil as a template image, amber
/// while uploads wait for review (the same attention hue the Sentinel agent
/// uses while a prompt waits), dimmed when the last Jamf refresh failed.
struct CommanderStatusItemLabel: View {
    let model: PolicyBuilderModel

    private var fleet: FleetObserverModel { model.fleet }

    private var variant: SerberusStatusIcon.Variant {
        switch fleet.state {
        case .loaded:
            return fleet.waitingUploads.isEmpty ? .template : .tinted(SerberusStatusIcon.amber)
        case .failed:
            return fleet.devices.isEmpty ? .dimmed : (fleet.waitingUploads.isEmpty ? .template : .tinted(SerberusStatusIcon.amber))
        case .idle, .loading:
            return .template
        }
    }

    private var tooltip: String {
        switch fleet.state {
        case .loaded:
            let waiting = fleet.waitingUploads.count
            return "Serberus Commander — \(fleet.serberusDevices.count) Serberus \(fleet.serberusDevices.count == 1 ? "Mac" : "Macs")"
                + (waiting > 0 ? " · \(waiting) \(waiting == 1 ? "upload" : "uploads") waiting" : "")
        case .failed: return "Serberus Commander — last Jamf refresh failed"
        case .loading: return "Serberus Commander — loading the fleet…"
        case .idle: return "Serberus Commander"
        }
    }

    var body: some View {
        Image(nsImage: SerberusStatusIcon.image(variant))
            .help(tooltip)
            .accessibilityLabel(tooltip)
    }
}

/// The Commander popover (design language: the Sentinel agent's "My rules"
/// popover — glass header with the icon chip + status line, counter cards,
/// tappable rows, glass footer). Everything shown is the real Jamf-backed
/// fleet (`model.fleet`); nothing is invented. Every row is a deep link into
/// the Fleet Observer at the matching filter.
struct CommanderMenuBarView: View {
    @Bindable var model: PolicyBuilderModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var fleet: FleetObserverModel { model.fleet }
    private var connection: MDMConnection { model.effectiveJamfConnection }
    private var connectionProblem: String? { FleetObserverModel.connectionProblem(connection) }
    private var loaded: Bool { if case .loaded = fleet.state { return true }; return false }
    private var loading: Bool { fleet.state == .loading }
    /// Loaded, or failed-but-showing the previous devices.
    private var hasDevices: Bool { !fleet.devices.isEmpty }

    /// Rows the uploads section lists before "See all".
    private static let maxUploadRows = 5
    private static let maxStateRows = 4

    var body: some View {
        VStack(spacing: 0) {
            header
            if let problem = connectionProblem {
                message(symbol: "antenna.radiowaves.left.and.right.slash", title: "Connect Jamf to see your fleet", detail: problem) {
                    Button("Open Settings") { go(section: .settings) }.buttonStyle(.ghost)
                }
            } else if !hasDevices {
                notLoadedBody
            } else {
                checkInSection
                stateSection
                uploadsSection
            }
            footer
        }
        .frame(width: 380)
        .background(LinearGradient(colors: [Theme.popoverTop, Theme.popoverBottom], startPoint: .top, endPoint: .bottom))
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .task {
            // Opening the popover loads the fleet once (a Jamf read), never
            // on a timer — every refresh is fleet-wide.
            if connectionProblem == nil, fleet.needsLoad(for: connection) {
                await fleet.refresh(connection: connection)
            }
        }
    }

    // MARK: Navigation

    /// Close the popover, route, and bring the Commander window forward
    /// (re-opening it if the operator closed it — the app keeps running for
    /// the status item).
    private func go(_ route: FleetRoute) {
        CommanderPopover.dismiss()
        model.openFleetObserver(route)
        showWindow()
    }

    private func go(section: SidebarSection) {
        CommanderPopover.dismiss()
        model.selectedSection = section
        showWindow()
    }

    private func showWindow() {
        openWindow(id: "serberus")
        NSApplication.shared.activate()
    }

    // MARK: Header

    private var header: some View {
        VStack(spacing: Spacing.md) {
            HStack(spacing: Spacing.md) {
                appIconChip
                VStack(alignment: .leading, spacing: 3) {
                    Text("Serberus Commander")
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
        .glassChrome(Theme.glass2)
        .overlay(alignment: .bottom) { Theme.glassBorder.frame(height: 1) }
    }

    private var appIconChip: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.iconChipGradient)
            SerberusSigilView().foregroundStyle(Theme.emerald).frame(width: 22, height: 22)
        }
        .frame(width: 34, height: 34)
        .accessibilityHidden(true)
    }

    private var statusTone: StatusTone {
        if connectionProblem != nil { return .offline }
        switch fleet.state {
        case .loaded: return fleet.waitingUploads.isEmpty ? .healthy : .pending
        case .loading: return .neutral
        case .failed: return .degraded
        case .idle: return .offline
        }
    }

    private var statusText: String {
        if connectionProblem != nil { return "Jamf not connected" }
        switch fleet.state {
        case .loading where !hasDevices: return "Loading the fleet from Jamf…"
        case .loading: return "Refreshing…"
        case .idle: return "Fleet not loaded"
        // Neutral wording: the popover body carries the specific reason
        // (credentials / permission / unreachable) so the header must not
        // pin every failure on the network.
        case .failed where !hasDevices: return "Couldn't load the fleet"
        case .failed: return "Last refresh failed · showing \(relative(fleet.lastRefreshed))"
        case .loaded where fleet.devices.isEmpty: return "No computers in Jamf · refreshed \(relative(fleet.lastRefreshed))"
        case .loaded:
            let count = fleet.serberusDevices.count
            return "\(count) Serberus \(count == 1 ? "Mac" : "Macs") · refreshed \(relative(fleet.lastRefreshed))"
        }
    }

    private var statusLine: some View {
        HStack(spacing: 6) {
            if loading {
                ProgressView().controlSize(.mini).frame(width: 8, height: 8)
            } else {
                StatusDot(tone: statusTone, size: 6)
            }
            Text(statusText).font(.system(size: 11.5)).foregroundStyle(Theme.textSecondary).lineLimit(1)
        }
    }

    private var gearMenu: some View {
        Menu {
            Button("Open Commander") { go(section: .dashboard) }
            Button("Refresh Fleet") { Task { await fleet.refresh(connection: connection) } }
                .disabled(loading || connectionProblem != nil)
            Divider()
            Button("Quit Serberus Commander") { NSApplication.shared.terminate(nil) }
        } label: {
            Image(systemName: "gearshape").font(.system(size: 14)).foregroundStyle(Theme.textMuted)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel("Commander menu")
    }

    private var counterPair: some View {
        let waiting = fleet.waitingUploads.count
        return HStack(spacing: Spacing.sm) {
            counterCard(value: hasDevices ? "\(fleet.serberusDevices.count)" : "—", label: "Serberus devices",
                        valueColor: Theme.textPrimary, hint: "Open Fleet Observer") { go(.allDevices) }
            counterCard(value: hasDevices ? "\(waiting)" : "—", label: "Uploads waiting",
                        valueColor: waiting > 0 ? Theme.warning : Theme.textPrimary,
                        hint: "Open the uploads waiting for review") { go(.allUploads) }
        }
    }

    private func counterCard(value: String, label: String, valueColor: Color, hint: String,
                             action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 0) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(value).font(.system(size: 17, weight: .semibold, design: .monospaced)).foregroundStyle(valueColor)
                    Text(label.uppercased()).font(.system(size: 10.5)).tracking(0.4).foregroundStyle(Theme.textMuted)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(Theme.textMuted).padding(.top, 2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 9).padding(.horizontal, 11)
            .background(Theme.elevated, in: RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous).strokeBorder(Theme.border, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
        .accessibilityHint(hint)
    }

    // MARK: Body sections

    private var notLoadedBody: some View {
        Group {
            switch fleet.state {
            case .loading:
                HStack(spacing: Spacing.sm) {
                    ProgressView().controlSize(.small)
                    Text("Reading the computer inventory…").font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                }
                .frame(maxWidth: .infinity).padding(.vertical, Spacing.xl)
            case let .failed(reason):
                message(symbol: "exclamationmark.triangle", title: "Couldn't load the fleet", detail: reason) {
                    Button("Try Again") { Task { await fleet.refresh(connection: connection) } }.buttonStyle(.ghost)
                }
            case .loaded:
                // Loaded, but Jamf returned no computers at all (empty instance,
                // or an API client scoped to an empty site) — NOT "not loaded".
                message(symbol: "laptopcomputer.slash", title: "No computers in Jamf",
                        detail: "The inventory loaded but returned no computers. Enroll a Mac and run inventory, then Refresh.") {
                    Button("Refresh") { Task { await fleet.refresh(connection: connection) } }.buttonStyle(.ghost)
                }
            case .idle:
                message(symbol: "laptopcomputer.and.arrow.down", title: "Fleet not loaded",
                        detail: "Refresh reads every computer from Jamf (API role Read Computers).") {
                    Button("Load Fleet") { Task { await fleet.refresh(connection: connection) } }.buttonStyle(.ghost)
                }
            }
        }
    }

    private func message<Action: View>(symbol: String, title: String, detail: String,
                                       @ViewBuilder action: () -> Action) -> some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: symbol).font(.system(size: 26)).foregroundStyle(Theme.textMuted)
            Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text(detail).font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            action().padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, Spacing.xl).padding(.vertical, Spacing.lg)
    }

    /// Checked in / Stale / Offline (/ Unknown) → each its filtered device list.
    private var checkInSection: some View {
        let counts = fleet.postureCounts()
        let thresholds = fleet.thresholds
        return section("Check-in", trailing: { seeAll("See all") { go(.allDevices) } }) {
            ForEach([FleetDevice.Freshness.fresh, .stale, .offline, .unknown], id: \.self) { freshness in
                let count = counts[freshness] ?? 0
                if freshness != .unknown || count > 0 {
                    row(tone: FleetFormat.tone(for: freshness), title: freshness.label(thresholds: thresholds),
                        count: count, hint: "Open Fleet Observer filtered to \(freshness.label)") {
                        go(.devices(FleetFilter(freshness: freshness)))
                    }
                }
            }
        }
    }

    /// Daemon State EA values (healthy / degraded / not reported …) → filtered list.
    @ViewBuilder
    private var stateSection: some View {
        let states = fleet.stateCounts
        if !states.isEmpty {
            section("Serberus state") {
                ForEach(states.prefix(Self.maxStateRows), id: \.value) { entry in
                    row(tone: Self.tone(forState: entry.value), title: Self.humanState(entry.value), count: entry.count,
                        hint: "Open Fleet Observer filtered to state “\(entry.value)”") {
                        go(.devices(FleetFilter(state: entry.value)))
                    }
                }
                if states.count > Self.maxStateRows {
                    seeAll("\(states.count - Self.maxStateRows) more in Fleet Observer") { go(.allDevices) }
                        .padding(.leading, Spacing.xl).padding(.top, Spacing.xxs)
                }
            }
        }
    }

    /// The shipped State EA emits values like "degraded (pam missing)",
    /// "unknown (state.plist unreadable)", and underscored states
    /// (kill_switch / awaiting_config), so match on the head word by prefix,
    /// not equality — otherwise a degraded Mac falls through to amber.
    private static func tone(forState state: String) -> StatusTone {
        let head = state.split(whereSeparator: { $0 == " " || $0 == "_" || $0 == "(" }).first.map(String.init) ?? state
        switch head {
        case "healthy": return .healthy
        case "degraded", "kill": return .degraded          // "kill_switch" → head "kill"
        case "unknown", "not": return .offline             // "not installed", "not reported"
        default: return .pending                            // awaiting_config, pending_*, …
        }
    }

    /// "kill_switch" → "Kill Switch", "degraded (pam missing)" → "Degraded
    /// (pam missing)" — underscores to spaces, first letter up, parenthetical
    /// reason left as the daemon wrote it.
    private static func humanState(_ state: String) -> String {
        let spaced = state.replacingOccurrences(of: "_", with: " ")
        guard let first = spaced.first else { return spaced }
        return first.uppercased() + spaced.dropFirst()
    }

    /// Macs with uploads waiting for review → that device's uploads.
    private var uploadsSection: some View {
        let devices = fleet.devicesWithWaitingUploads
        return section("Uploads to review", trailing: {
            if !devices.isEmpty { seeAll("See all") { go(.allUploads) } }
        }) {
            if devices.isEmpty {
                Text(fleet.reviewedUploads.isEmpty ? "Nothing waiting — captures and Intel bundles users upload from Sentinel appear here."
                                                   : "Nothing waiting — every upload on the records has been reviewed.")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, Spacing.xl).padding(.vertical, Spacing.sm)
            } else {
                ForEach(devices.prefix(Self.maxUploadRows)) { device in
                    uploadRow(device)
                }
                if devices.count > Self.maxUploadRows {
                    seeAll("\(devices.count - Self.maxUploadRows) more \(devices.count - Self.maxUploadRows == 1 ? "device" : "devices")") { go(.allUploads) }
                        .padding(.leading, Spacing.xl).padding(.top, Spacing.xxs)
                }
            }
        }
    }

    private func uploadRow(_ device: FleetDevice) -> some View {
        let waiting = fleet.waitingUploads(on: device.id)
        let captures = waiting.filter { $0.kind == .capture }.count
        let bundles = waiting.filter { $0.kind == .intel }.count
        var parts: [String] = []
        if captures > 0 { parts.append("\(captures) \(captures == 1 ? "capture" : "captures")") }
        if bundles > 0 { parts.append("\(bundles) Intel \(bundles == 1 ? "bundle" : "bundles")") }
        let detail = [device.user ?? device.serialNumber, parts.joined(separator: " · ")].compactMap { $0 }.joined(separator: " · ")
        return HoverRow(action: { go(.uploads(deviceID: device.id)) }) {
            HStack(spacing: Spacing.md) {
                Image(systemName: "tray.and.arrow.down").font(.system(size: 12)).foregroundStyle(Theme.warning)
                    .frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text(device.name).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                    Text(detail).font(.system(size: 10.5)).foregroundStyle(Theme.textMuted).lineLimit(1)
                }
                Spacer()
                Text("\(waiting.count)").font(.system(size: 12.5, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.warning)
                Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.textMuted)
            }
        }
        .help("Open \(device.name)'s uploads in Fleet Observer")
        .accessibilityLabel("\(device.name), \(waiting.count) \(waiting.count == 1 ? "upload" : "uploads") waiting")
    }

    // MARK: Row / section scaffolding

    private func section<Trailing: View, Content: View>(_ title: String,
                                                        @ViewBuilder trailing: () -> Trailing = { EmptyView() },
                                                        @ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: 0) {
            HStack {
                SectionLabel(title)
                Spacer()
                trailing()
            }
            .padding(.horizontal, Spacing.xl)
            .padding(.top, Spacing.lg)
            .padding(.bottom, Spacing.xs)
            content()
        }
    }

    private func seeAll(_ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 3) {
                Text(title)
                Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold))
            }
            .font(.system(size: 10.5, weight: .medium))
            .foregroundStyle(Theme.textSecondary)
        }
        .buttonStyle(.plain)
    }

    /// "● Checked in …… 1 ›" — a count row that routes to its filtered list.
    private func row(tone: StatusTone, title: String, count: Int, hint: String, action: @escaping () -> Void) -> some View {
        HoverRow(action: action) {
            HStack(spacing: Spacing.md) {
                StatusDot(tone: tone, size: 7).frame(width: 16)
                Text(title).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                Spacer()
                Text("\(count)").font(.system(size: 12.5, weight: .semibold, design: .monospaced))
                    .foregroundStyle(count > 0 ? Theme.textPrimary : Theme.textMuted)
                Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.textMuted)
            }
        }
        .help(hint)
        .accessibilityLabel("\(count) \(title)")
        .accessibilityHint(hint)
    }

    // MARK: Footer

    private var footer: some View {
        HStack(spacing: Spacing.sm) {
            Button {
                Task { await fleet.refresh(connection: connection) }
            } label: {
                if loading {
                    HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Refreshing…") }
                } else {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
            .buttonStyle(.ghost)
            .disabled(loading || connectionProblem != nil)
            .help(connectionProblem ?? "Reload the computer inventory from Jamf")
            Button { go(section: .dashboard) } label: {
                Label("Open Commander", systemImage: "square.grid.2x2").frame(maxWidth: .infinity)
            }
            .buttonStyle(.emerald)
        }
        .padding(.vertical, Spacing.md)
        .padding(.horizontal, Spacing.lg)
        .padding(.top, 1)
        .glassChrome(Theme.glass)
        .overlay(alignment: .top) { Theme.glassBorder.frame(height: 1) }
        .padding(.top, Spacing.md)
    }

    // MARK: Formatting

    private func relative(_ date: Date?) -> String {
        guard let date else { return "—" }
        let secs = max(0, Int(Date().timeIntervalSince(date)))
        if secs < 60 { return "just now" }
        if secs < 3600 { return "\(secs / 60)m ago" }
        if secs < 86_400 { return "\(secs / 3600)h ago" }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

/// A full-width popover row that lifts on hover (Sentinel's rule-row
/// treatment) and acts as one button.
private struct HoverRow<Content: View>: View {
    let action: () -> Void
    @ViewBuilder let content: () -> Content
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            content()
                .padding(.horizontal, Spacing.xl)
                .padding(.vertical, 7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(hovering ? Theme.elevated : Color.clear)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
