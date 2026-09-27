import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// The full assigned-rules list — every rule the daemon delivered, searchable,
/// each with its prompt count. The menubar popover shows only the top few; this
/// is the complete picture (Serberus window → My Rules tab).
struct MyRulesView: View {
    let rules: SentinelRulesStore
    let history: ElevationHistoryStore

    @State private var query = ""

    private var allRules: [SentinelRuleSummary] { rules.snapshot?.rules ?? [] }
    private var hitCounts: [String: Int] { history.ruleHitCounts() }

    private var filtered: [SentinelRuleSummary] {
        guard !query.isEmpty else { return allRules }
        return allRules.filter {
            "\($0.title) \($0.detail) \($0.profileKey)".localizedCaseInsensitiveContains(query)
        }
    }

    private func ruleName(_ rule: SentinelRuleSummary) -> String { "\(rule.profileKey) · \(rule.ruleID)" }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            header
            if allRules.isEmpty {
                emptyState
            } else {
                searchField
                if filtered.isEmpty {
                    noMatches
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(filtered) { rule in
                                SentinelRuleRow(
                                    rule: rule,
                                    hitCount: hitCounts[ruleName(rule)].flatMap { $0 > 0 ? $0 : nil },
                                    lastUsed: history.lastEntry(forRuleNamed: ruleName(rule))?.date
                                )
                                Divider().overlay(Theme.stroke)
                            }
                        }
                    }
                    .background(Theme.surface1, in: RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous).strokeBorder(Theme.stroke, lineWidth: 1))
                }
            }
        }
        .padding(Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Rules assigned to you")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text("\(allRules.count) \(allRules.count == 1 ? "rule" : "rules")\(policySuffix)")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
        }
    }

    private var policySuffix: String {
        guard let snapshot = rules.snapshot, !snapshot.profileKeys.isEmpty else { return "" }
        if snapshot.profileKeys.count == 1 { return " · \(snapshot.profileKeys[0])" }
        return " · \(snapshot.profileKeys.count) profiles"
    }

    private var searchField: some View {
        HStack(spacing: Spacing.xs) {
            Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            TextField("Search rules…", text: $query)
                .textFieldStyle(.plain).font(.system(size: 12)).foregroundStyle(Theme.textPrimary)
            if !query.isEmpty {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
            }
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, 7)
        .background(Theme.surface2, in: RoundedRectangle(cornerRadius: Radius.chip, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.chip, style: .continuous).strokeBorder(Theme.stroke, lineWidth: 1))
    }

    private var emptyState: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "checklist").font(.system(size: 30)).foregroundStyle(Theme.textMuted)
            Text("No rules assigned yet").font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.textSecondary)
            Text("Rules arrive with your Mac's policy profile.").font(.system(size: 11)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var noMatches: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "magnifyingglass").font(.system(size: 22)).foregroundStyle(Theme.textMuted)
            Text("No matching rules").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
