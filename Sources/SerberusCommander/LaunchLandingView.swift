import PolicyBuilderCore
import PrivMgrCore
import SerberusUI
import SwiftUI

/// The launch / loading page. Commander's fleet posture (Dashboard ring, risk
/// signals, device & upload counts) all come from the Jamf inventory, which
/// used to load lazily — so the Dashboard opened showing "—" until the
/// operator visited a fleet screen. This page **front-loads** that Jamf read
/// the moment Commander launches, behind a branded splash, and reveals the
/// app when the fetch settles. Shown only when a Jamf connection is
/// configured (nothing to wait for otherwise — the caller hides it) and only
/// on the first launch (the window's later re-opens skip it).
struct LaunchLandingView: View {
    @Bindable var model: PolicyBuilderModel
    /// Called once, to fade the splash away and reveal Commander.
    let onFinish: () -> Void

    @State private var minTimeElapsed = false
    @State private var started = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var fleet: FleetObserverModel { model.fleet }
    private var connection: MDMConnection { model.effectiveJamfConnection }

    var body: some View {
        ZStack {
            AppBackground()
            VStack(spacing: Spacing.section) {
                brand
                statusArea
            }
            .padding(Spacing.xl)
            VStack {
                Spacer()
                skip
            }
            .padding(Spacing.xl)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task {
            // A short minimum so a fast/cached load doesn't flash the splash.
            if !started {
                started = true
                Task { try? await Task.sleep(for: .milliseconds(650)); minTimeElapsed = true; advanceIfReady() }
                if fleet.needsLoad(for: connection) {
                    await fleet.refresh(connection: connection)
                }
                advanceIfReady()
            }
        }
        .onChange(of: fleet.state) { _, _ in advanceIfReady() }
    }

    /// Reveal Commander once the fleet has loaded AND the splash has shown for
    /// its minimum. A failed load stays here with Retry / Continue — the
    /// operator decides — rather than dropping them onto an empty Dashboard.
    private func advanceIfReady() {
        guard minTimeElapsed else { return }
        if case .loaded = fleet.state { onFinish() }
    }

    // MARK: Brand

    private var brand: some View {
        VStack(spacing: Spacing.lg) {
            ZStack {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(Theme.iconChipGradient)
                    .frame(width: 84, height: 84)
                    .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(Theme.glassBorder, lineWidth: 1))
                    .shadow(color: Theme.emerald.opacity(0.28), radius: 24, y: 8)
                SerberusSigilView()
                    .foregroundStyle(Theme.emerald)
                    .frame(width: 54, height: 54)
            }
            VStack(spacing: 5) {
                Text("SERBERUS")
                    .font(.system(size: 26, weight: .bold)).tracking(5)
                    .foregroundStyle(Theme.textPrimary)
                Text("Privilege. Controlled.")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.emerald.opacity(0.85))
            }
        }
    }

    // MARK: Status

    @ViewBuilder
    private var statusArea: some View {
        switch fleet.state {
        case .failed(let reason):
            failed(reason)
        default:
            loading
        }
    }

    private var loadingText: String {
        switch fleet.state {
        case .loaded: return "Fleet loaded"
        default: return "Loading fleet inventory from \(model.mdm.vendor.displayName)…"
        }
    }

    private var loading: some View {
        VStack(spacing: Spacing.md) {
            ProgressView()
                .controlSize(.small)
                .tint(Theme.emerald)
            Text(loadingText)
                .font(.system(size: 12.5))
                .foregroundStyle(Theme.textSecondary)
        }
    }

    private func failed(_ reason: String) -> some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 26))
                .foregroundStyle(Theme.warning)
            Text("Couldn't load the fleet")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
            Text(reason)
                .font(.system(size: 11.5))
                .foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: Spacing.sm) {
                Button {
                    Task { await fleet.refresh(connection: connection) }
                } label: {
                    if fleet.state == .loading {
                        HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Retrying…") }
                    } else {
                        Label("Retry", systemImage: "arrow.clockwise")
                    }
                }
                .buttonStyle(.tinted)
                .disabled(fleet.state == .loading)
                Button("Continue to Commander") { onFinish() }
                    .buttonStyle(.ghost)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, Spacing.xs)
        }
    }

    // MARK: Skip

    @ViewBuilder
    private var skip: some View {
        if fleet.state == .loading || fleet.state == .idle {
            Button("Skip") { onFinish() }
                .buttonStyle(.plain)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(Theme.textMuted)
                .help("Open Commander now — the fleet keeps loading in the background")
                .keyboardShortcut(.cancelAction)
        }
    }
}
