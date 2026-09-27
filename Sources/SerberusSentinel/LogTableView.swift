import SerberusIntelCore
import SerberusUI
import SwiftUI

extension LogLevel {
    /// Brand colour for a severity, using the shared Serberus ramps so the
    /// tool reads as part of the same product.
    var tint: Color {
        switch self {
        case .debug, .info: return .secondary
        case .default: return SerberusBrand.emerald
        case .error: return SerberusBrand.amber
        case .fault: return SerberusBrand.critical
        }
    }
}

/// The scrolling log table shared by the live and history modes.
struct LogTableView: View {
    let entries: [LogEntry]
    /// Pin to the newest row as entries arrive (live mode only).
    let follow: Bool

    var body: some View {
        ScrollViewReader { proxy in
            List(entries) { entry in
                LogRow(entry: entry)
                    .listRowInsets(EdgeInsets(top: 4, leading: 8, bottom: 4, trailing: 8))
                    .id(entry.id)
            }
            .listStyle(.inset)
            .font(.system(.caption, design: .monospaced))
            .onChange(of: entries.last?.id) { _, newValue in
                guard follow, let newValue else { return }
                withAnimation(.easeOut(duration: 0.15)) {
                    proxy.scrollTo(newValue, anchor: .bottom)
                }
            }
        }
    }
}

extension AuthorizationOutcome {
    var tint: Color {
        switch self {
        case .granted: return SerberusBrand.emerald
        case .denied, .failed: return SerberusBrand.critical
        case .requested: return SerberusBrand.amber
        }
    }

    var label: String {
        switch self {
        case .granted: return "GRANTED"
        case .denied: return "DENIED"
        case .failed: return "FAILED"
        case .requested: return "REQUESTED"
        }
    }
}

/// The scrolling authorizations table — surfaces the right name up front so a
/// triggered authURI is readable at a glance, not buried in authd prose.
struct AuthorizationTableView: View {
    let entries: [LogEntry]
    let follow: Bool
    /// Serberus rule (if any) governing a given right — drives the per-row tag.
    let ruleTag: (String) -> AuthorizationRuleTag?

    var body: some View {
        ScrollViewReader { proxy in
            List(entries) { entry in
                AuthorizationRow(entry: entry, ruleTag: ruleTag)
                    .listRowInsets(EdgeInsets(top: 4, leading: 8, bottom: 4, trailing: 8))
                    .id(entry.id)
            }
            .listStyle(.inset)
            .font(.system(.caption, design: .monospaced))
            .onChange(of: entries.last?.id) { _, newValue in
                guard follow, let newValue else { return }
                withAnimation(.easeOut(duration: 0.15)) {
                    proxy.scrollTo(newValue, anchor: .bottom)
                }
            }
        }
    }
}

/// Grouped view — one row per authorization attempt rather than per authd line.
struct AuthorizationAttemptTableView: View {
    let attempts: [AuthorizationAttempt]
    let follow: Bool
    let ruleTag: (String) -> AuthorizationRuleTag?

    var body: some View {
        ScrollViewReader { proxy in
            List(attempts) { attempt in
                AuthorizationAttemptRow(attempt: attempt, ruleTag: ruleTag)
                    .listRowInsets(EdgeInsets(top: 4, leading: 8, bottom: 4, trailing: 8))
                    .id(attempt.id)
            }
            .listStyle(.inset)
            .font(.system(.caption, design: .monospaced))
            .onChange(of: attempts.last?.id) { _, newValue in
                guard follow, let newValue else { return }
                withAnimation(.easeOut(duration: 0.15)) {
                    proxy.scrollTo(newValue, anchor: .bottom)
                }
            }
        }
    }
}

private struct AuthorizationAttemptRow: View {
    let attempt: AuthorizationAttempt
    let ruleTag: (String) -> AuthorizationRuleTag?
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text(attempt.outcome.label)
                    .font(.system(.caption2, design: .rounded).weight(.semibold))
                    .foregroundStyle(attempt.outcome.tint)
                    .frame(width: 74, alignment: .leading)
                Text(attempt.timestamp)
                    .foregroundStyle(.secondary)
                if let tag = ruleTag(attempt.right) {
                    RuleBadge(tag: tag)
                }
                Spacer(minLength: 0)
            }

            Text(attempt.right)
                .font(.system(.body, design: .monospaced).weight(.medium))
                .foregroundStyle(attempt.outcome.tint)
                .textSelection(.enabled)

            HStack(spacing: 6) {
                if let client = attempt.client {
                    Text((client as NSString).lastPathComponent)
                        .foregroundStyle(.secondary)
                }
                if attempt.verdictInherited {
                    // Never present an inferred verdict as authd's own words.
                    Text("verdict inferred from the attempt's failure")
                        .foregroundStyle(SerberusBrand.amber)
                }
                Button(expanded ? "hide \(attempt.lines.count) log lines"
                                : "show \(attempt.lines.count) log lines") {
                    expanded.toggle()
                }
                .buttonStyle(.link)
                .font(.system(.caption2, design: .rounded))
            }
            .font(.system(.caption2, design: .monospaced))

            if expanded {
                // The raw authd lines, verbatim — the message is Apple-internal
                // prose, so the source is always one click away.
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(attempt.lines) { line in
                        Text(line.message)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.leading, 8)
            }
        }
        .padding(.vertical, 2)
        // Pin the row to the list width so a long monospace right/log line wraps
        // instead of forcing the row (and, through the shared VStack, the Intel
        // controls bar) wider than the window. See LogRow.
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Shared "matches a Serberus rule" badge.
private struct RuleBadge: View {
    let tag: AuthorizationRuleTag

    var body: some View {
        let tint = tag.action == .deny ? SerberusBrand.critical : SerberusBrand.emerald
        let verb = tag.action == .deny ? "DENY" : "ALLOW"
        return HStack(spacing: 3) {
            Image(systemName: "shield.lefthalf.filled")
            Text("Serberus \(verb)\(tag.identityGated ? " (binary-gated)" : "")")
            Text("· \(tag.ruleID)").foregroundStyle(.secondary)
        }
        .font(.system(.caption2, design: .rounded).weight(.medium))
        .padding(.horizontal, 6)
        .padding(.vertical, 1)
        .background(tint.opacity(0.15), in: Capsule())
        .foregroundStyle(tint)
        .help(tag.identityGated
              ? "A Serberus rule (\(tag.ruleID)) targets this right, but also pins the requesting app's identity — the live match is necessary but not sufficient."
              : "This right is governed by Serberus rule \(tag.ruleID) (\(verb)).")
    }
}

private struct AuthorizationRow: View {
    let entry: LogEntry
    let ruleTag: (String) -> AuthorizationRuleTag?

    private var info: AuthorizationInfo { AuthorizationParser.info(from: entry.message) }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                if let outcome = info.outcome {
                    Text(outcome.label)
                        .font(.system(.caption2, design: .rounded).weight(.semibold))
                        .foregroundStyle(outcome.tint)
                        .frame(width: 74, alignment: .leading)
                }
                Text(entry.timestamp)
                    .foregroundStyle(.secondary)

                // "Serberus rule" tag — is this right already governed by a
                // Serberus authURI rule? The whole point of the tab for rule
                // authoring: covered vs. worth a new rule.
                if let right = info.right, let tag = ruleTag(right) {
                    RuleBadge(tag: tag)
                }

                Spacer(minLength: 0)
            }

            // The right itself — big, monospace, selectable. This is the thing
            // the user came to read and copy into a rule.
            if let right = info.right {
                Text(right)
                    .font(.system(.body, design: .monospaced).weight(.medium))
                    .foregroundStyle(info.outcome?.tint ?? .primary)
                    .textSelection(.enabled)
            }

            // The raw authd line, kept verbatim underneath — the message is
            // Apple-internal prose, not a contract, so we never hide the source.
            Text(entry.message)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
        // See LogRow — pin to the list width so a wide right/authd line can't
        // stretch the shared VStack (and the controls bar) past the window.
        .frame(maxWidth: .infinity, alignment: .leading)
    }

}

private struct LogRow: View {
    let entry: LogEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                Text(entry.level.label)
                    .font(.system(.caption2, design: .rounded).weight(.semibold))
                    .foregroundStyle(entry.level.tint)
                    .frame(width: 48, alignment: .leading)

                Text(entry.timestamp)
                    .foregroundStyle(.secondary)

                // The category is how a reader tells a policy decision from an
                // integrity event, so it earns a badge rather than blending in.
                Text(entry.category)
                    .font(.system(.caption2, design: .rounded))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(entry.level.tint.opacity(0.15), in: Capsule())
                    .foregroundStyle(entry.level.tint)

                Text("\(entry.processName)[\(entry.processID)]")
                    .foregroundStyle(.tertiary)

                Spacer(minLength: 0)
            }

            Text(entry.message)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
        // A List row reports its child's intrinsic width up to the enclosing
        // VStack; an unconstrained long monospace message therefore stretched
        // the whole Intel column — and the controls bar with it — past the
        // window (leading padding collapsed, "Export" truncated) whenever the
        // daemon fed real log data. Pinning the row to the available width makes
        // wide text wrap within the row instead.
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
