import SerberusIntelCore
import SerberusUI
import SwiftUI

/// Serberus Intel — live authorization diagnostics, decision history, and
/// support-bundle export. Formerly the standalone `SerberusIntel.app`; now the
/// **Intel tab** of the unified Sentinel window. Its daemon reads
/// (`pollAuthorizations`, privileged export) go over the `.intel` XPC
/// interface, which the daemon now lets the Sentinel bundle reach.
struct IntelTabView: View {
    /// App-lifetime model (owned by `SerberusSentinelApp`), so a Capture in
    /// progress survives tab switches and window close/reopen.
    @Bindable var model: IntelModel
    @State private var showingExport = false
    @State private var showingCapture = false

    var body: some View {
        VStack(spacing: 0) {
            controls
            Divider()
            // A greedy always-present filler behind the content gives this region
            // the SAME firm full size whether the feed is empty (a compact
            // VStack) or populated (a filling List). Without it, macOS 27's
            // empty-feed FIRST layout under-sizes the column and cramps the bar,
            // and only a later content change (a log line arriving) fixed it.
            ZStack {
                Color.clear
                content
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            statusBar
        }
        // Embedded in a tab, so it fills the window rather than forcing a fixed
        // window size (the standalone app used minWidth 900 × 560).
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .sheet(isPresented: $showingExport) {
            ExportSheet(model: model)
        }
        .sheet(isPresented: $showingCapture) {
            CaptureReviewSheet(model: model)
        }
        .task {
            // Live is the default mode, so start the tail when the tab appears.
            model.startStreaming()
        }
        .onDisappear {
            model.stopStreaming()
            model.stopAuthorizations()
            // A recording deliberately SURVIVES leaving the tab (the user may
            // switch to My Activity mid-capture); only the feeds stop.
        }
    }

    /// Capture (Rule Recorder): idle → "Capture" starts; recording → a red
    /// dot with elapsed time + attempts seen, click to stop and review; after
    /// a stop the button re-opens the review until it is discarded/finished.
    @ViewBuilder
    private var captureButton: some View {
        switch model.capturePhase {
        case .idle:
            Button {
                model.startCapture()
            } label: {
                Label("Capture", systemImage: "record.circle")
            }
            .buttonStyle(.bordered)
            .help("Record every sudo and authorization attempt on this Mac until you stop, then save or upload the capture for Commander's Import Capture")
        case .recording:
            Button {
                model.stopCapture()
                showingCapture = true
            } label: {
                HStack(spacing: 6) {
                    Circle().fill(SerberusBrand.critical).frame(width: 8, height: 8)
                    Text("Stop · \(Self.elapsed(model.captureElapsedSeconds)) · \(model.captureAttemptCount)")
                        .monospacedDigit()
                }
            }
            .buttonStyle(.bordered)
            .tint(SerberusBrand.critical)
            .help("Stop recording and review the capture")
            .accessibilityLabel("Stop capture, \(Self.elapsed(model.captureElapsedSeconds)) elapsed, \(model.captureAttemptCount) attempts recorded")
        case .building:
            Button {
                showingCapture = true
            } label: {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Assembling…")
                }
            }
            .buttonStyle(.bordered)
            .help("Building the capture from what was recorded")
        case .uploading:
            Button {
                showingCapture = true
            } label: {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Uploading…")
                }
            }
            .buttonStyle(.bordered)
            .help("Uploading the capture to this Mac's Jamf record")
        case .review, .uploaded, .failed:
            Button {
                showingCapture = true
            } label: {
                Label("Review Capture · \(model.captureAttemptCount)", systemImage: "doc.text.magnifyingglass")
            }
            .buttonStyle(.bordered)
            .help("Open the recorded capture to save it, upload it, or discard it")
            .accessibilityLabel("Review capture, \(model.captureAttemptCount) attempts")
        }
    }

    private static func elapsed(_ seconds: Int) -> String {
        String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    /// Custom segmented mode control. The native `.pickerStyle(.segmented)` Picker
    /// pins itself to the container's leading edge on macOS 27, swallowing the
    /// bar's leading padding (a plain view in the same slot is inset correctly).
    /// This equivalent built from Buttons lays out like any other view.
    private var modeControl: some View {
        HStack(spacing: 2) {
            ForEach(ViewMode.allCases) { mode in
                Button {
                    model.mode = mode
                } label: {
                    Text(mode.rawValue)
                        .font(.system(size: 12, weight: .medium))
                        .lineLimit(1)
                        .padding(.vertical, 4)
                        // Equal-width segments: each label fills its share of the
                        // fixed control width below.
                        .frame(maxWidth: .infinity)
                        .background(
                            model.mode == mode ? SerberusBrand.emerald : Color.clear,
                            in: RoundedRectangle(cornerRadius: 5, style: .continuous)
                        )
                        .foregroundStyle(model.mode == mode ? Color.black : Color.primary)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(2)
        .frame(width: 360)
        .background(Color.primary.opacity(0.08), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
    }

    /// Pause/Resume for the active live source. In Live it toggles the log
    /// stream; in Authorizations it toggles authd polling; History has nothing
    /// to pause, so nothing shows.
    @ViewBuilder
    private var pauseResumeButton: some View {
        switch model.mode {
        case .live:
            Button {
                if model.isStreaming { model.stopStreaming() } else { model.startStreaming() }
            } label: {
                Label(model.isStreaming ? "Pause" : "Resume",
                      systemImage: model.isStreaming ? "pause.fill" : "play.fill")
            }
            .buttonStyle(.bordered)
        case .authorizations:
            Button {
                model.toggleAuthorizationsPaused()
            } label: {
                Label(model.authorizationPaused ? "Resume" : "Pause",
                      systemImage: model.authorizationPaused ? "play.fill" : "pause.fill")
            }
            .buttonStyle(.bordered)
        case .history:
            EmptyView()
        }
    }

    /// Minimum-severity filter for the log feeds. A menu picker over
    /// `LogLevel.filterLabel` — "All levels" / "<Level> and above" — because
    /// the filter is a FLOOR (`entry.level.severity >= minimumLevel.severity`),
    /// not an exact-level match; a bare "Notice" read as "only Notice lines".
    private var levelFilter: some View {
        Picker("Level", selection: $model.minimumLevel) {
            ForEach(LogLevel.allCases, id: \.self) { level in
                Text(level.filterLabel).tag(level)
            }
        }
        .pickerStyle(.menu)
        .labelsHidden()
        .frame(width: 150)
    }

    /// Free-text filter over the visible feed, with an inline clear affordance.
    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            TextField("Filter", text: $model.searchText)
                .textFieldStyle(.plain)
            if !model.searchText.isEmpty {
                Button {
                    model.searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        .frame(maxWidth: 260)
    }

    private var controls: some View {
        HStack(spacing: 12) {
            modeControl

            pauseResumeButton

            if model.mode != .history {
                Button {
                    model.clearLive()
                } label: {
                    Label("Clear", systemImage: "trash")
                }
                .buttonStyle(.bordered)
            }

            levelFilter

            searchField

            Spacer()

            captureButton

            Button {
                model.resetExport()
                showingExport = true
            } label: {
                Label("Export…", systemImage: "square.and.arrow.up")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!model.canExport)
        }
        // Inset the bar with padding, and DO NOT add `.frame(maxWidth: .infinity)`
        // — on macOS 27 that frame pins the HStack's first child to x=0 and
        // swallows the leading inset (verified with red/blue marker builds). The
        // HStack's trailing `Spacer()` already stretches the bar across the
        // GeometryReader-forced full-width column, so the bar fills AND keeps
        // symmetric leading/trailing insets on 26 and 27.
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private var content: some View {
        if let error = model.loadError {
            emptyState(
                title: "Could not read the log",
                message: error,
                symbol: "exclamationmark.triangle"
            )
        } else if model.isLoadingHistory {
            ProgressView("Reading the last \(model.window.rawValue)…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if model.mode == .authorizations, let reason = model.authorizationUnavailable,
                  model.visibleRowCount == 0 {
            emptyState(
                title: "Authorizations unavailable",
                message: reason,
                symbol: "lock.slash"
            )
        } else if model.entriesHiddenByFilter {
            // Captured entries exist but the filters hid them all — never let
            // this read as "nothing happened".
            emptyState(
                title: "\(model.hiddenEntryCount) hidden by filters",
                message: filteredEmptyMessage,
                symbol: "line.3.horizontal.decrease.circle"
            )
        } else if model.visibleRowCount == 0 {
            emptyState(title: emptyTitle, message: emptyMessage, symbol: "text.magnifyingglass")
        } else if model.mode == .authorizations {
            // Follow only while actively polling — a paused feed stays put so
            // the user can read what just fired.
            if model.authorizationGrouped {
                AuthorizationAttemptTableView(
                    attempts: model.visibleAttempts,
                    follow: !model.authorizationPaused,
                    ruleTag: { model.ruleTag(forRight: $0) }
                )
            } else {
                AuthorizationTableView(
                    entries: model.visibleEntries,
                    follow: !model.authorizationPaused,
                    ruleTag: { model.ruleTag(forRight: $0) }
                )
            }
        } else {
            LogTableView(entries: model.visibleEntries, follow: model.mode == .live && model.isStreaming)
        }
    }

    private var emptyTitle: String {
        switch model.mode {
        case .live: return "Waiting for Serberus activity"
        case .authorizations: return "Waiting for authorization attempts"
        case .history: return "No matching entries"
        }
    }

    /// Shown when captured entries were all hidden by the active filters.
    /// Names the specific filter(s) in play so the fix is one obvious click.
    private var filteredEmptyMessage: String {
        var hints: [String] = []
        if model.mode == .authorizations && model.authorizationRightsOnly {
            hints.append("These lines don't name a right — turn off “Rights only” to see the raw authd events.")
        }
        if !model.searchText.trimmingCharacters(in: .whitespaces).isEmpty {
            hints.append("Clear the filter text.")
        }
        if model.minimumLevel != .debug {
            hints.append("Lower the level filter (authorization events are Notice level).")
        }
        if hints.isEmpty {
            hints.append("Adjust the filters to see them.")
        }
        return hints.joined(separator: " ")
    }

    private var emptyMessage: String {
        switch model.mode {
        case .live:
            return "Every allow and deny decision appears here as it happens. Try running the command that failed."
        case .authorizations:
            return "Every macOS authorization right requested on this Mac appears here, live. Try opening a locked System Settings pane — the right it asks for shows up, ready to author a rule from."
        case .history:
            return "Nothing in the last \(model.window.rawValue) matches your filter. Try a longer range."
        }
    }

    private func emptyState(title: String, message: String, symbol: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 30))
                .foregroundStyle(.tertiary)
            Text(title).font(.headline)
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var authorizationDotColor: Color {
        if model.authorizationPaused { return .secondary }
        return model.authorizationUnavailable == nil ? SerberusBrand.emerald : SerberusBrand.amber
    }

    private var authorizationStatusText: String {
        if model.authorizationPaused { return "Paused" }
        return model.authorizationUnavailable == nil ? "Polling authd" : "Daemon unavailable"
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            if model.mode == .live {
                Circle()
                    .fill(model.isStreaming ? SerberusBrand.emerald : Color.secondary)
                    .frame(width: 7, height: 7)
                Text(model.isStreaming ? "Streaming" : "Paused")
            } else if model.mode == .authorizations {
                Circle()
                    .fill(authorizationDotColor)
                    .frame(width: 7, height: 7)
                Text(authorizationStatusText)
            }
            Text("\(model.visibleRowCount) shown")
                .foregroundStyle(.secondary)

            Spacer()

            // Never let a permission boundary look like an empty log: say which
            // source is actually feeding this view.
            switch model.mode {
            case .authorizations:
                Label("System authorizations (via daemon)", systemImage: "person.badge.key")
                    .foregroundStyle(.tertiary)
                    .help("macOS authorization-right attempts, collected by the Serberus daemon (a standard user cannot read these directly).")
            case .live, .history:
                if model.unifiedLogAvailable {
                    Label("Serberus records + system log", systemImage: "checkmark.seal")
                        .foregroundStyle(.tertiary)
                        .help(LogQuery.predicate)
                } else {
                    Label("Serberus records", systemImage: "info.circle")
                        .foregroundStyle(.tertiary)
                        .help(UnifiedLogAccess.unavailableReason)
                }
            }
        }
        .font(.caption)
        // Match the controls bar's leading edge (20) so the top and bottom
        // chrome align. No `.frame(maxWidth: .infinity)` — same macOS 27 reason
        // as the controls bar (the Spacer already fills the width).
        .padding(.horizontal, 20)
        .padding(.vertical, 6)
    }
}
