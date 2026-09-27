import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// One rule row (design: decision glyph chip + name + machine-readable detail +
/// decision badge), tappable to disclose the rule's right/source/last-used.
/// Shared by the menubar popover's "most-used rules" and the Serberus window's
/// full My Rules list. Self-contained: it owns its own hover/expand state so
/// both hosts can just list them.
struct SentinelRuleRow: View {
    let rule: SentinelRuleSummary
    /// Prompt count for this rule, shown as a `×N` chip. `nil` hides it.
    var hitCount: Int? = nil
    /// The most-recently-prompted rule gets a 2px accent left border.
    var isHighlighted: Bool = false
    /// Last time this rule prompted, for the disclosed "Last used" line.
    var lastUsed: Date? = nil

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var expanded = false
    @State private var hovering = false

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(reduceMotion ? nil : .easeOut(duration: 0.15)) {
                    expanded.toggle()
                }
            } label: {
                HStack(spacing: Spacing.md) {
                    ZStack {
                        RoundedRectangle(cornerRadius: Radius.chip, style: .continuous)
                            .fill(rule.decision.dimColor)
                        Image(systemName: RuleSymbolMapper.symbol(for: rule))
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(rule.decision.color)
                    }
                    .frame(width: 26, height: 26)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(rule.title)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(Theme.textPrimary)
                            .lineLimit(1)
                        Text(rule.detail)
                            .font(.system(size: 10.5, design: .monospaced))
                            .foregroundStyle(Theme.textMuted)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                    Spacer(minLength: Spacing.sm)
                    if let hitCount {
                        Text("×\(hitCount)")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Theme.textSecondary)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Theme.surface2, in: Capsule())
                            .accessibilityLabel("prompted \(hitCount) times")
                    }
                    DecisionBadge(decision: rule.decision)
                }
                .padding(.vertical, 9)
                .padding(.horizontal, Spacing.xl)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .background(hovering ? Theme.surface2 : (isHighlighted ? Theme.surface1 : .clear))
            .overlay(alignment: .leading) {
                if isHighlighted { rule.decision.color.frame(width: 2) }
            }
            .onHover { hovering = $0 }
            .accessibilityLabel("\(rule.title), \(rule.decision.badgeText)\(hitCount.map { ", prompted \($0) times" } ?? "")")
            .accessibilityHint("Shows rule details")

            if expanded {
                detail
            }
        }
    }

    private var detail: some View {
        VStack(alignment: .leading, spacing: 5) {
            detailLine(label: "Right", value: rule.detail)
            detailLine(label: "Source", value: rule.profileKey + (rule.policyVersion.map { " · v\($0)" } ?? ""))
            if let lastUsed {
                detailLine(label: "Last used",
                           value: lastUsed.formatted(.dateTime.day().month(.abbreviated).hour().minute()))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, Spacing.sm)
        .padding(.horizontal, Spacing.xl + 26 + Spacing.md)
        .background(Theme.backgroundDeep.opacity(0.5))
        .transition(.opacity)
    }

    private func detailLine(label: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.sm) {
            Text(label.uppercased())
                .font(.system(size: 9.5, weight: .semibold))
                .tracking(0.5)
                .foregroundStyle(Theme.textMuted)
                .frame(width: 58, alignment: .leading)
            Text(value)
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
                .textSelection(.enabled)
        }
    }
}
