import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

// MARK: - Rule row

/// Compact library-rule row: the one-line representation of a ``PolicyRule``
/// used by policy editors' rule-assignment pickers (and anywhere outside the
/// Rules screen that lists rules). Rules no longer carry a mechanism of their
/// own — sudo/authuri lives on their definitions — so the icon reads the
/// decision (allow/deny) instead of the old type glyph.
struct RuleRow: View {
    let rule: PolicyRule
    let selected: Bool

    private var allow: Bool { rule.action == .allow }
    private var tone: StatusTone { allow ? .healthy : .degraded }

    var body: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: allow ? "checkmark.shield.fill" : "xmark.shield.fill")
                .font(.system(size: 13))
                .foregroundStyle(allow ? Theme.emerald : Theme.critical)
                .frame(width: 30, height: 30)
                .background((allow ? Theme.emerald : Theme.critical).opacity(0.12),
                           in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                Text(rule.name.isEmpty ? rule.id : rule.name)
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                    .lineLimit(1)
            }
            Spacer()
            StatusDot(tone: tone, size: 6)
        }
        .padding(.horizontal, Spacing.sm)
        .padding(.vertical, Spacing.sm)
        .background(selected ? Theme.accentDim : Color.clear,
                    in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Radius.sm, style: .continuous)
                .strokeBorder(selected ? Theme.emerald.opacity(0.4) : Color.clear, lineWidth: 1)
        )
    }

    /// "allow · silent · 2 definitions · priority 10" — enough to pick a rule
    /// out of a list without opening it.
    private var subtitle: String {
        var parts = [rule.action.rawValue]
        if allow {
            parts.append(rule.elevationType == .silent ? "silent" : "prompt")
        }
        let count = rule.definitionIDs.count
        parts.append("\(count) \(count == 1 ? "definition" : "definitions")")
        parts.append("priority \(rule.priority)")
        return parts.joined(separator: " · ")
    }
}

// MARK: - Duration formatting

/// Human-readable rendering of second counts ("15 min", "2 hr", "90 sec").
/// Stored values stay in seconds — this is display-only.
enum DurationFormat {
    static func humanize(_ seconds: Int, zero: String) -> String {
        guard seconds > 0 else { return zero }
        if seconds % 3600 == 0 { return "\(seconds / 3600) hr" }
        if seconds % 60 == 0 { return "\(seconds / 60) min" }
        if seconds > 60 { return "\(seconds / 60) min \(seconds % 60) sec" }
        return "\(seconds) sec"
    }
}

// MARK: - Shared form styling

/// Styling helpers shared by the rule composer's cards and the decision
/// groups below, so captions, field labels, and toggles render identically
/// across every section of the form.
enum RuleFormStyle {
    static func eyebrow(_ title: String, _ symbol: String) -> some View {
        Label(title, systemImage: symbol)
            .font(.eyebrow).tracking(0.8).foregroundStyle(Theme.textMuted)
    }

    // Captions and field labels are primary text for the form, not tertiary —
    // textSecondary (60%) keeps them ≥4.5:1 on a card; textMuted (36%) is ~3:1.
    static func caption(_ text: String) -> some View {
        Text(text).font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    static func labeled(_ label: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
            content()
        }
    }

    static func toggle(_ label: String, _ binding: Binding<Bool>) -> some View {
        Toggle(isOn: binding) {
            Text(label).font(.system(size: 13)).foregroundStyle(Theme.textSecondary)
        }
    }
}

// MARK: - When matched

/// The rule-tier decision group: silent grant vs. approval prompt (allow
/// only — deny rules have no elevation to pick), plus the plain-language
/// consequence line so the author always reads what saving actually does.
/// Matcher fields are gone from the rule form — they live on definitions,
/// edited in the Definitions screen.
///
/// An allow on an authorization right has no elevation choice: the daemon
/// rewrites the right so the user authenticates with their own password, and
/// no Serberus prompt is shown. So the picker is hidden when the rule matches
/// only authorization rights, and a mixed rule says the choice applies to its
/// sudo commands only.
struct RuleWhenMatchedGroup: View {
    @Binding var draft: RuleDraft
    /// The kinds of the definitions the rule matches (empty while none is
    /// picked).
    var definitionKinds: Set<RuleType> = []

    private var authorizationRightsOnly: Bool { definitionKinds == [.authuri] }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            RuleFormStyle.eyebrow("When matched", "bolt.shield")
            if draft.action == .allow, !authorizationRightsOnly {
                SegmentedControl(selection: $draft.elevationType,
                                 options: [.silent: "Allow silently", .prompt: "Ask first"],
                                 label: "When matched")
                if definitionKinds.contains(.authuri) {
                    RuleFormStyle.caption("Applies to the sudo commands only. For the authorization rights, the user authenticates with their own password; no Serberus prompt.")
                }
            }
            consequenceLine
        }
    }

    /// Plain-language statement of what saving this rule actually does —
    /// warning-tinted for the silent-admin case.
    @ViewBuilder
    private var consequenceLine: some View {
        if draft.action == .deny {
            Label("Matching requests are refused outright.", systemImage: "hand.raised.fill")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
        } else if authorizationRightsOnly {
            Label("The user authenticates with their own password; no Serberus prompt.",
                  systemImage: "person.badge.key.fill")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        } else if draft.elevationType == .silent {
            Label("Anyone this rule covers can do this with admin rights and no password prompt.",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.system(size: 11)).foregroundStyle(Theme.warning)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Label("The user sees a Serberus approval prompt before anything runs.",
                  systemImage: "person.fill.questionmark")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
        }
    }
}

// MARK: - Advanced settings

/// Expert knobs behind a collapsed disclosure with safe defaults, so skipping
/// it is always fine: priority, justification, grant duration, approval
/// memory, audit logging. The identity pins (Team ID, binary
/// hash) that used to live here are gone — they are part of WHAT is matched,
/// so they moved to the definition tier (Definitions screen).
struct RuleAdvancedSettingsGroup: View {
    @Binding var draft: RuleDraft

    /// The three meanings of a rule's `maxGrantDurationSeconds`: -1, 0, or
    /// a number of seconds.
    enum GrantMode: String, CaseIterable, Identifiable {
        case oneTimeOnly, orgDefault, custom

        var id: String { rawValue }

        init(seconds: Int) {
            switch seconds {
            case ..<0: self = .oneTimeOnly
            case 0: self = .orgDefault
            default: self = .custom
            }
        }

        var title: String {
            switch self {
            case .oneTimeOnly: return "One time only"
            case .orgDefault: return "Use org default"
            case .custom: return "Set a time limit"
            }
        }

        var caption: String {
            switch self {
            case .oneTimeOnly: return "Every use is checked again; no admin time is granted, whatever the org default."
            case .orgDefault: return "Admin access lasts as long as the org default grant duration in Settings."
            case .custom: return "How long admin access lasts before it's automatically taken back."
            }
        }
    }

    private var grantMode: Binding<GrantMode> {
        Binding(
            get: { GrantMode(seconds: draft.maxGrantDurationSeconds) },
            set: { mode in
                switch mode {
                case .oneTimeOnly: draft.maxGrantDurationSeconds = RuleSchemaConstants.neverGrantSeconds
                case .orgDefault: draft.maxGrantDurationSeconds = 0
                case .custom where draft.maxGrantDurationSeconds <= 0: draft.maxGrantDurationSeconds = 900
                case .custom: break
                }
            }
        )
    }

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                VStack(alignment: .leading, spacing: 5) {
                    RuleFormStyle.labeled("Priority") {
                        Stepper("\(draft.priority)", value: $draft.priority, in: 0...1000)
                            .font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                    }
                    RuleFormStyle.caption("Lower number = checked first when several rules match.")
                }
                RuleFormStyle.toggle("Ask the user to give a reason", $draft.requireJustification)
                VStack(alignment: .leading, spacing: 5) {
                    RuleFormStyle.labeled("Elevated time limit") {
                        Picker("Elevated time limit", selection: grantMode) {
                            ForEach(GrantMode.allCases) { mode in
                                Text(mode.title).tag(mode)
                            }
                        }
                        .labelsHidden()
                        .font(.system(size: 13))
                    }
                    if GrantMode(seconds: draft.maxGrantDurationSeconds) == .custom {
                        Stepper(DurationFormat.humanize(draft.maxGrantDurationSeconds, zero: ""),
                                value: $draft.maxGrantDurationSeconds, in: 60...RuleSchemaConstants.maxGrantSeconds, step: 60)
                            .font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                    }
                    RuleFormStyle.caption(GrantMode(seconds: draft.maxGrantDurationSeconds).caption)
                }
                RuleFormStyle.toggle("Use the default approval memory", $draft.useGlobalCache)
                if !draft.useGlobalCache {
                    VStack(alignment: .leading, spacing: 5) {
                        RuleFormStyle.labeled("Remember approval for") {
                            Stepper(DurationFormat.humanize(draft.cacheSeconds, zero: "Ask every time"),
                                    value: $draft.cacheSeconds, in: 0...86_400, step: 30)
                                .font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                        }
                        RuleFormStyle.caption("How long an approval is reused before the user is asked again.")
                    }
                }
                RuleFormStyle.toggle("Record the full command in the audit log", $draft.logArguments)
            }
            .padding(.top, Spacing.md)
        } label: {
            Label("Advanced", systemImage: "slider.horizontal.3")
                .font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textSecondary)
        }
        .tint(Theme.textMuted)
    }
}
