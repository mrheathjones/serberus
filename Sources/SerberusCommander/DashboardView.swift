import PolicyBuilderCore
import SwiftUI

/// Dashboard — the authoring library and the live fleet at a glance. Every
/// number here is real: policy/rule/definition counts from the persisted
/// library, device / upload counts from the Jamf-backed Fleet Observer (when
/// loaded), and risk signals computed from the compiled rules. There is no
/// sample data — per-decision activity and grant telemetry need the Serberus
/// collector (not in this build), so they are called out rather than faked.
struct DashboardView: View {
    @Bindable var model: PolicyBuilderModel

    private let metricColumns = [GridItem(.adaptive(minimum: 190), spacing: Spacing.lg)]
    private var fleet: FleetObserverModel { model.fleet }
    private var fleetLoaded: Bool { if case .loaded = fleet.state { return true }; return false }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                metrics
                HStack(alignment: .top, spacing: Spacing.lg) {
                    fleetPostureCard.frame(maxWidth: .infinity)
                    riskCard.frame(width: 340)
                }
                telemetrySection
            }
            .padding(Spacing.xl)
        }
        .scrollIndicators(.never)
        .onAppear { model.refreshDirectPublishGate() }
    }

    // MARK: Header

    private var header: some View {
        ScreenHeader("Dashboard", subtitle: "Policy library & fleet posture") {
            Button {
                // Reload BOTH sources the Dashboard shows: the on-disk policy
                // library and the Jamf-backed fleet (every tile below the
                // library counts comes from `model.fleet`, which only updates
                // on an explicit fleet refresh).
                model.reloadLibrary()
                let connection = model.effectiveJamfConnection
                if FleetObserverModel.connectionProblem(connection) == nil {
                    Task { await model.fleet.refresh(connection: connection) }
                }
            } label: {
                if fleet.state == .loading {
                    HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Refreshing…") }
                } else {
                    Label("Reload", systemImage: "arrow.clockwise")
                }
            }
            .buttonStyle(.ghost)
            .disabled(fleet.state == .loading)
            .help("Re-read the policy library from disk and reload the Jamf fleet (devices, uploads, and enforcement counts)")
        }
    }

    // MARK: Metrics (all real)

    /// Every tile routes to the screen its number comes from.
    private var metrics: some View {
        LazyVGrid(columns: metricColumns, spacing: Spacing.lg) {
            MetricTile(label: "Serberus devices",
                       value: fleetLoaded ? "\(fleet.serberusDevices.count)" : "—",
                       symbol: "laptopcomputer", tone: fleetLoaded ? .healthy : .neutral,
                       help: fleetLoaded ? "Macs with inventory evidence of Serberus — open Fleet Observer"
                                         : "The fleet loads from Jamf on demand — open Fleet Observer") {
                model.openFleetObserver(.allDevices)
            }
            MetricTile(label: "Policies", value: "\(model.policies.count)", symbol: "square.stack.3d.up.fill", tone: .neutral,
                       help: "Policies in the library — open Policies") { model.selectedSection = .policies }
            MetricTile(label: "Rules", value: "\(model.rules.count)", symbol: "list.bullet.rectangle.fill", tone: .neutral,
                       help: "Rules in the library — open Rules") { model.openRuleEditor(ruleID: nil) }
            MetricTile(label: "Definitions", value: "\(model.definitions.count)", symbol: "curlybraces", tone: .neutral,
                       help: "Definitions in the library — open Definitions") { model.openDefinitionEditor(definitionID: nil) }
            MetricTile(label: "Uploads waiting",
                       value: fleetLoaded ? "\(fleet.waitingUploads.count)" : "—",
                       symbol: "tray.and.arrow.down.fill",
                       tone: fleetLoaded && !fleet.waitingUploads.isEmpty ? .pending : .neutral,
                       help: uploadsHelp) {
                model.openFleetObserver(.allUploads)
            }
        }
    }

    private var uploadsHelp: String {
        guard fleetLoaded else { return "Captures and Intel bundles on Jamf records that nobody has imported, rejected, or downloaded yet — open Fleet Observer → Uploads" }
        let reviewed = fleet.reviewedUploads.count
        var text = "\(fleet.waitingUploads.count) on Jamf records, not yet imported, rejected, or downloaded"
        if reviewed > 0 { text += " (\(reviewed) reviewed, still on the record)" }
        return text + " — open Fleet Observer → Uploads"
    }

    // MARK: Fleet posture

    @ViewBuilder
    private var fleetPostureCard: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            HStack {
                SectionLabel("Fleet posture")
                Spacer()
                if let refreshed = fleet.lastRefreshed {
                    Text("as of \(refreshed.formatted(date: .omitted, time: .shortened))")
                        .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                }
            }
            if fleetLoaded {
                let devices = fleet.serberusDevices
                let counts = fleet.postureCounts()
                let fresh = counts[.fresh] ?? 0
                let thresholds = fleet.thresholds
                HStack(spacing: Spacing.lg) {
                    Button { model.openFleetObserver(.allDevices) } label: {
                        EnforcementRing(fraction: devices.isEmpty ? 0 : Double(fresh) / Double(devices.count))
                    }
                    .buttonStyle(.plain)
                    .help("Share of Serberus Macs that contacted Jamf within \(thresholds.staleAfterDays == 1 ? "the last day" : "\(thresholds.staleAfterDays) days") — open Fleet Observer")
                    VStack(alignment: .leading, spacing: Spacing.sm) {
                        // Each line opens the Fleet Observer filtered to that
                        // check-in state (the menu bar offers the same rows).
                        postureLine(.fresh, counts[.fresh] ?? 0, thresholds)
                        postureLine(.stale, counts[.stale] ?? 0, thresholds)
                        postureLine(.offline, counts[.offline] ?? 0, thresholds)
                        if (counts[.unknown] ?? 0) > 0 { postureLine(.unknown, counts[.unknown] ?? 0, thresholds) }
                    }
                    Spacer()
                }
                if devices.isEmpty {
                    Text("No Serberus Macs in Jamf yet. Deploy the pkgs and the EAs (Support/jamf-extension-attributes), then Refresh in Fleet Observer.")
                        .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                VStack(alignment: .leading, spacing: Spacing.md) {
                    Text("The fleet loads from Jamf on demand — device check-ins, uploads, and posture live in Fleet Observer.")
                        .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                    Button { model.selectedSection = .fleetObserver } label: { Label("Open Fleet Observer", systemImage: "arrow.up.forward") }
                        .buttonStyle(.ghost)
                }
            }
        }
        .card()
    }

    private func postureLine(_ freshness: FleetDevice.Freshness, _ count: Int,
                             _ thresholds: FleetDevice.FreshnessThresholds) -> some View {
        let tone = FleetFormat.tone(for: freshness)
        return PostureLineButton(label: freshness.label(thresholds: thresholds), count: count, tone: tone) {
            model.openFleetObserver(.devices(FleetFilter(freshness: freshness)))
        }
    }

    // MARK: Risk (from the compiled library)

    /// Each row is a link: a fleet-derived signal opens the Fleet Observer
    /// filtered to those Macs; a library signal opens Rules. The score is a
    /// 0–100 severity heuristic — spelled out in the tooltip and the legend,
    /// with the on/off switches and check-in windows in Settings.
    private var riskCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack {
                SectionLabel("Top risk signals")
                Spacer()
                Button { model.selectedSection = .settings } label: {
                    HStack(spacing: 3) {
                        Text("Configure")
                        Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold))
                    }
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(Theme.textSecondary)
                }
                .buttonStyle(.plain)
                .help("Switch signals on or off and set the check-in windows (Settings → Dashboard & fleet posture)")
            }
            ForEach(model.riskSignals().prefix(5)) { signal in
                RiskSignalRow(signal: signal, tone: Self.tone(signal.level)) {
                    switch signal.kind {
                    case .offline:
                        model.openFleetObserver(.devices(FleetFilter(freshness: .offline)))
                    case .nominal:
                        break
                    default:
                        model.openRuleEditor(ruleID: nil)
                    }
                }
            }
            Text("Score = 0–100 severity heuristic per signal (base weight + a step per affected rule or Mac, capped); Low < 35 ≤ Medium < 65 ≤ High. Hover a signal for its formula.")
                .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .card()
    }

    private static func tone(_ level: RiskSignal.Level) -> StatusTone {
        switch level {
        case .low: return .healthy
        case .medium: return .pending
        case .high: return .degraded
        }
    }

    // MARK: Enforcement telemetry (Jamf EA counts summed over the fleet)

    private let telemetryColumns = [GridItem(.adaptive(minimum: 190), spacing: Spacing.lg)]

    @ViewBuilder
    private var telemetrySection: some View {
        // Only meaningful once the fleet has loaded; before that the note below
        // explains where the numbers come from.
        if fleetLoaded {
            let telemetry = fleet.telemetry
            VStack(alignment: .leading, spacing: Spacing.md) {
                SectionLabel("Enforcement · last 24h")
                if telemetry.hasData {
                    LazyVGrid(columns: telemetryColumns, spacing: Spacing.lg) {
                        MetricTile(label: "Denials · 24h", value: "\(telemetry.denials24h)",
                                   symbol: "hand.raised.fill",
                                   tone: telemetry.denials24h > 0 ? .degraded : .neutral,
                                   help: "Elevation decisions Serberus denied fleet-wide in the last 24h (EA_Serberus_Denials_24h, summed) — open the Macs with denials in Fleet Observer") {
                            model.openFleetObserver(.devices(FleetFilter(denials24hOnly: true)))
                        }
                        MetricTile(label: "Active grants", value: "\(telemetry.activeGrants)",
                                   symbol: "checkmark.seal.fill",
                                   tone: telemetry.activeGrants > 0 ? .pending : .neutral,
                                   help: "Elevation grants currently live across the fleet (EA_Serberus_Grants_Active, summed) — open Fleet Observer") {
                            model.openFleetObserver(.allDevices)
                        }
                        MetricTile(label: "Prompts · 24h", value: "\(telemetry.prompts24h)",
                                   symbol: "bell.badge.fill",
                                   tone: telemetry.prompts24h > 0 ? .pending : .neutral,
                                   help: "Decisions that raised an interactive prompt fleet-wide in the last 24h (EA_Serberus_Prompts_24h, summed) — open Fleet Observer") {
                            model.openFleetObserver(.allDevices)
                        }
                    }
                    topDenialSources
                } else {
                    Text("No Serberus Mac is reporting the telemetry EAs yet. Deploy EA_Serberus_Denials_24h / _Grants_Active / _Prompts_24h / _Last_Decision (Support/jamf-extension-attributes) and run recon; the daemon writes fleet-summary.plist each 30s.")
                        .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(Spacing.md)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .card()
                }
            }
        }
    }

    @ViewBuilder
    private var topDenialSources: some View {
        let sources = fleet.topDenialSources()
        if !sources.isEmpty {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                SectionLabel("Top denial sources")
                ForEach(sources, id: \.device.id) { entry in
                    Button { model.openFleetObserver(.devices(FleetFilter(denials24hOnly: true))) } label: {
                        HStack(spacing: Spacing.sm) {
                            Text(entry.device.name)
                                .font(.system(size: 12)).foregroundStyle(Theme.textPrimary)
                                .lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: Spacing.md)
                            Text("\(entry.denials)")
                                .font(.metric(13)).foregroundStyle(Theme.critical)
                        }
                    }
                    .buttonStyle(.plain)
                    .help("\(entry.denials) denied in the last 24h on \(entry.device.name) — open Fleet Observer")
                }
            }
            .padding(Spacing.md)
            .frame(maxWidth: .infinity, alignment: .leading)
            .card()
        }
    }

}

// MARK: - Pieces

/// One Fleet-posture line ("● 2  Offline (> 7 days)") as a link into the
/// Fleet Observer filtered to that state.
private struct PostureLineButton: View {
    let label: String
    let count: Int
    let tone: StatusTone
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Circle().fill(tone.color).frame(width: 8, height: 8)
                Text("\(count)").font(.system(size: 14, weight: .semibold).monospacedDigit()).foregroundStyle(Theme.textPrimary)
                Text(label).font(.system(size: 11)).foregroundStyle(hovering ? Theme.textPrimary : Theme.textSecondary)
                Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold))
                    .foregroundStyle(Theme.textMuted).opacity(hovering ? 1 : 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help("Open Fleet Observer filtered to “\(label)”")
        .accessibilityLabel("\(count) \(label)")
        .accessibilityHint("Open Fleet Observer filtered to this check-in state")
    }
}

/// One risk signal: title, score out of 100 with its level, detail, bar —
/// the whole row is a link (hover reveals the chevron), the tooltip is the
/// signal's formula.
private struct RiskSignalRow: View {
    let signal: RiskSignal
    let tone: StatusTone
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Text(signal.title).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textPrimary)
                    Spacer()
                    RuleDecisionBadge(signal.level.label, color: tone.color)
                    HStack(alignment: .firstTextBaseline, spacing: 1) {
                        Text("\(signal.score)").font(.system(size: 12, weight: .semibold).monospacedDigit())
                            .foregroundStyle(tone.color)
                        Text("/100").font(.system(size: 9.5, weight: .medium).monospacedDigit())
                            .foregroundStyle(Theme.textMuted)
                    }
                    if signal.kind != .nominal {
                        Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold))
                            .foregroundStyle(Theme.textMuted).opacity(hovering ? 1 : 0)
                    }
                }
                Text(signal.detail).font(.system(size: 10.5)).foregroundStyle(Theme.textMuted).lineLimit(2)
                ScoreBar(score: signal.score, tone: tone)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(signal.kind == .nominal)
        .onHover { hovering = $0 }
        .help("\(signal.title) — \(signal.level.label) (\(signal.score)/100). \(signal.explanation)\(signal.kind == .offline ? " Click to open the offline Macs in Fleet Observer." : (signal.kind == .nominal ? "" : " Click to open Rules."))")
        .accessibilityLabel("\(signal.title), \(signal.level.label), \(signal.score) out of 100")
    }
}

struct ScoreBar: View {
    let score: Int
    let tone: StatusTone

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.elevated)
                Capsule()
                    .fill(LinearGradient(colors: [tone.color.opacity(0.7), tone.color],
                                         startPoint: .leading, endPoint: .trailing))
                    .frame(width: geo.size.width * CGFloat(score) / 100)
                    .shadow(color: tone.color.opacity(0.5), radius: 4)
            }
        }
        .frame(height: 6)
    }
}

struct EnforcementRing: View {
    let fraction: Double

    var body: some View {
        ZStack {
            Circle().stroke(Theme.elevated, lineWidth: 9)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(
                    AngularGradient(colors: [Theme.emeraldDeep, Theme.emerald, Theme.emeraldGlow], center: .center),
                    style: StrokeStyle(lineWidth: 9, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .shadow(color: Theme.emerald.opacity(0.5), radius: 6)
            VStack(spacing: 0) {
                Text("\(Int((fraction * 100).rounded()))%").font(.metric(22)).foregroundStyle(Theme.textPrimary)
                Text("checked in").font(.system(size: 9)).foregroundStyle(Theme.textMuted)
            }
        }
        .frame(width: 92, height: 92)
    }
}
