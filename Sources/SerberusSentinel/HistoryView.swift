import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// Local elevation history: every prompt this Sentinel presented and
/// how it resolved, searchable and filterable by outcome. Data comes from the
/// Sentinel's own ``ElevationHistoryStore`` — real decisions, persisted per-user.
struct HistoryView: View {
    let history: ElevationHistoryStore
    /// When bound and true, the list is scoped to today — the deep link from
    /// the popover's "Audited today" counter. A `.constant(false)` default keeps
    /// the standalone/all-time use unchanged.
    var todayOnly: Binding<Bool> = .constant(false)

    @State private var query = ""
    @State private var filter: Filter = .all

    private enum Filter: String, CaseIterable, Identifiable {
        case all = "All"
        case approved = "Approved"
        case denied = "Denied"
        case timedOut = "Timed out"
        var id: String { rawValue }

        func matches(_ verdict: PromptResponse.Verdict) -> Bool {
            switch self {
            case .all: return true
            case .approved: return verdict == .approved
            case .denied: return verdict == .denied
            case .timedOut: return verdict == .timedOut
            }
        }
    }

    private var source: [ElevationHistoryEntry] {
        todayOnly.wrappedValue ? history.entriesToday() : history.entries
    }

    private var filtered: [ElevationHistoryEntry] {
        source.filter { entry in
            guard filter.matches(entry.verdict) else { return false }
            guard !query.isEmpty else { return true }
            let haystack = "\(entry.processName) \(entry.canonicalPath) \(entry.humanReadableRequest)"
            return haystack.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            header
            controls
            if source.isEmpty {
                emptyState
            } else if filtered.isEmpty {
                noMatches
            } else {
                entriesList
            }
        }
        .padding(Spacing.lg)
        .frame(minWidth: 560, minHeight: 400)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
    }

    private var header: some View {
        HStack(spacing: Spacing.sm) {
            SentinelSigilView()
                .foregroundStyle(Theme.accent)
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text("My Activity").font(.system(size: 16, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Text("Decisions on prompts shown to you on this Mac")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
            if !history.entries.isEmpty {
                Button("Clear") { history.clear() }
                    .buttonStyle(.plain)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Theme.textMuted)
            }
        }
    }

    private var controls: some View {
        HStack(spacing: Spacing.sm) {
            HStack(spacing: Spacing.xs) {
                Image(systemName: "magnifyingglass").font(.system(size: 11))
                    .foregroundStyle(Theme.textMuted)
                TextField("Search command or path…", text: $query)
                    .textFieldStyle(.plain).font(.system(size: 12))
                    .foregroundStyle(Theme.textPrimary)
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
                }
            }
            .padding(.horizontal, Spacing.md).padding(.vertical, 7)
            .background(Theme.elevated.opacity(0.7), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))

            Picker("", selection: Binding(
                get: { todayOnly.wrappedValue ? "Today" : "All time" },
                set: { todayOnly.wrappedValue = ($0 == "Today") }
            )) {
                Text("Today").tag("Today")
                Text("All time").tag("All time")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()

            Picker("", selection: $filter) {
                ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
        }
    }

    private var entriesList: some View {
        ScrollView {
            LazyVStack(spacing: Spacing.xs) {
                ForEach(filtered) { entry in
                    entryRow(entry)
                }
            }
            .padding(.vertical, 2)
        }
        .scrollIndicators(.automatic)
    }

    private func entryRow(_ entry: ElevationHistoryEntry) -> some View {
        HStack(alignment: .top, spacing: Spacing.md) {
            SentinelStatusDot(tone: tone(entry.verdict), size: 7)
                .padding(.top, 4)
            VStack(alignment: .leading, spacing: 2) {
                // The whole request, wrapped and never cut off, with hidden
                // characters shown as escapes.
                Text(entry.displayRequest)
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(Theme.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(DisplayText.escapingInvisibles(entry.canonicalPath))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.textMuted)
                    .lineLimit(1)
                if let justification = entry.justificationText, !justification.isEmpty {
                    Text("“\(justification)”")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                        .lineLimit(2)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                SentinelBadge(text: label(entry.verdict), tone: tone(entry.verdict))
                Text(entry.date, format: .dateTime.day().month(.abbreviated).hour().minute())
                    .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
            }
        }
        .sentinelCard(padding: Spacing.md)
    }

    private var emptyState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "clock.arrow.circlepath")
                .font(.system(size: 34)).foregroundStyle(Theme.textMuted)
            Text(todayOnly.wrappedValue ? "Nothing audited today" : "No activity yet")
                .font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text(todayOnly.wrappedValue
                 ? "Prompts you respond to today will appear here."
                 : "Decisions on elevation prompts will appear here.")
                .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var noMatches: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 24)).foregroundStyle(Theme.textMuted)
            Text("No matching entries").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func tone(_ verdict: PromptResponse.Verdict) -> SentinelTone {
        switch verdict {
        case .approved: return .healthy
        case .denied: return .degraded
        case .timedOut: return .pending
        }
    }

    private func label(_ verdict: PromptResponse.Verdict) -> String {
        switch verdict {
        case .approved: return "Approved"
        case .denied: return "Denied"
        case .timedOut: return "Timed out"
        }
    }
}
