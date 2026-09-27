import PrivMgrCore
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// The audit prompt (design: "Screen 2 — Audit prompt"): the escalation
/// moment. The user learns the action is audited and chooses to proceed or
/// cancel. Timeout and Escape always deny; **Return also cancels** — only
/// ⌘↩ approves, so a stray keystroke can never grant elevation. Approve (⌘↩
/// included) stays disabled until the prompt has been focused, visible and
/// uncovered for a second (``PromptArming``), so a click or keystroke timed
/// with its appearance, or one landing through another app's window, can't
/// approve either.
///
/// Accessibility: every control carries a VoiceOver label, the countdown
/// respects Reduce Motion, and full keyboard navigation is supported.
struct PromptWindow: View {
    @Bindable var model: PromptViewModel
    let allowLabel: String
    let denyLabel: String
    /// Org branding from the managed prompts profile (`brandTitle` /
    /// `brandSubtitle`); nil falls back to the product name.
    var brandTitle: String? = nil
    var brandSubtitle: String? = nil
    /// Called AFTER the rule disclosure toggles so the window controller can
    /// remeasure and resize the floating window once (top-anchored → grows
    /// downward). Fired once per toggle — deliberately NOT a continuous height
    /// stream, which re-enters a blocking window resize and hangs the app.
    var onDisclosureToggled: (() -> Void)? = nil
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Entrance animation state (design: 160ms scale 0.96 → 1 + fade).
    @State private var appeared = false
    /// Focuses the justification field on appear so the user can type
    /// immediately — the field is the one thing they must act on, and a
    /// borderless window doesn't route the first keystrokes anywhere until
    /// something is first responder.
    @FocusState private var justificationFocused: Bool
    /// Whether the matched-rule line is disclosed (hidden by default —
    /// operators need it, end users rarely do).
    @State private var ruleDisclosed = false
    /// The request row's scroll position. The entrance scale leaves a scrolling
    /// row a few points down, clipping the top of the command's first line, so
    /// it's put back at the top once the entrance animation ends.
    @State private var requestScroll = ScrollPosition(edge: .top)

    private var signingTone: SentinelTone {
        switch model.context.signingStatus {
        case .valid: return .healthy
        case .adhoc, .invalid: return .pending
        case .unsigned: return .degraded
        }
    }

    private var urgent: Bool { model.remainingSeconds <= 10 }

    var body: some View {
        VStack(spacing: 0) {
            head
            divider
            details
            if model.context.requireJustification {
                divider
                justificationField
            }
            divider
            actions
        }
        .frame(width: 470)
        .background {
            ZStack {
                GlassBackground()
                Theme.glass2
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: Radius.sheet, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: Radius.sheet, style: .continuous)
                .strokeBorder(Theme.glassBorder, lineWidth: 1)
        }
        .overlay(alignment: .top) {
            // 1px specular top edge, inset from the rounded corners.
            Theme.glassHighlight.frame(height: 1).padding(.horizontal, Radius.sheet)
        }
        .preferredColorScheme(.dark)
        .tint(Theme.accent)
        .scaleEffect(appeared || reduceMotion ? 1 : 0.96)
        .opacity(appeared || reduceMotion ? 1 : 0)
        .onAppear {
            withAnimation(.easeOut(duration: 0.16)) { appeared = true } completion: {
                requestScroll.scrollTo(edge: .top)
            }
            // Put the cursor in the justification field so the user can type
            // straight away (the button enables on the first real character).
            if model.context.requireJustification { justificationFocused = true }
        }
        .onExitCommand { model.deny() }
    }

    private var divider: some View {
        Theme.stroke.frame(height: 1)
    }

    // MARK: Head

    private var head: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Brand row — org identity, left aligned (managed prompts profile
            // keys `brandTitle`/`brandSubtitle`; unbranded = product name).
            HStack(spacing: Spacing.md) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Theme.iconChipGradient)
                    SentinelSigilView()
                        .foregroundStyle(Theme.accent)
                        .frame(width: 22, height: 22)
                }
                .frame(width: 36, height: 36)
                .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(brandTitle ?? "Serberus Sentinel")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                    if let brandSubtitle {
                        Text(brandSubtitle)
                            .font(.system(size: 11.5))
                            .foregroundStyle(Theme.textSecondary)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.bottom, 18)

            VStack(spacing: 8) {
                Text("This action is being audited")
                    .font(.system(size: 21, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text("Elevated privileges are needed for this action. Serberus will record and log your choice.")
                    .font(.system(size: 13.5))
                    .lineSpacing(4)
                    .foregroundStyle(Theme.textSecondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 340)
            }
            .frame(maxWidth: .infinity)
        }
        .padding(.top, 20)
        .padding(.horizontal, Spacing.xxl)
        .padding(.bottom, 20)
    }

    // MARK: Details

    private var details: some View {
        VStack(spacing: Spacing.md) {
            // The APP row shows the requesting app for authorization prompts.
            // Sudo prompts omit it: the elevated binary's canonical path is
            // already the command line's first element, and the terminal that
            // hosted the sudo is deliberately NOT shown — approval is about
            // the binary being elevated, not the window it was typed in. Hidden
            // characters in the path show as escapes, as in the request row.
            if model.context.isAuthURIRequest {
                detailRow("App", value: DisplayText.escapingInvisibles(model.context.canonicalPath),
                          valueColor: Theme.textPrimary)
            }
            requestRow
            HStack(alignment: .center, spacing: 12) {
                detailLabel("Signing")
                HStack(spacing: Spacing.sm) {
                    SentinelBadge(text: model.context.signingStatus.rawValue, tone: signingTone)
                    if let teamID = model.context.teamID {
                        Text(teamID)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.textMuted)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            // Time-bound rules: tell the user, before they approve, how long the
            // access will last. Absent for indefinite grants and rules that
            // issue no grant (nothing to count down).
            if let seconds = model.context.grantDurationSeconds, seconds > 0 {
                detailRow("Grant", value: "Active \(Self.humanizeDuration(seconds)) after approval",
                          valueColor: Theme.accent)
            }
            ruleDisclosure
        }
        .padding(.vertical, Spacing.xl)
        .padding(.horizontal, Spacing.xxl)
    }

    /// Compact duration for the Grant row: `45 sec`, `15 min`, `1 hr`, `1 hr 30 min`.
    static func humanizeDuration(_ seconds: Int) -> String {
        if seconds < 60 { return "\(seconds) sec" }
        let minutes = seconds / 60
        if minutes < 60 { return "\(minutes) min" }
        let hours = minutes / 60
        let remainder = minutes % 60
        return remainder == 0 ? "\(hours) hr" : "\(hours) hr \(remainder) min"
    }

    /// The matched rule, behind a show/hide disclosure (end users rarely need
    /// it; IT does when a user calls). Collapsed by default; toggling grows the
    /// sheet DOWNWARD (the window controller re-anchors the top edge on the
    /// reported height change) so nothing above is clipped.
    private var ruleDisclosure: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button {
                // Instant state change (no withAnimation): the visible motion is
                // the window growing downward, driven ONCE by the controller via
                // onDisclosureToggled. Animating the SwiftUI height here would
                // make the sheet's ideal size change every frame — the storm that
                // re-entered the window resize and crashed the app.
                ruleDisclosed.toggle()
                onDisclosureToggled?()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 8, weight: .bold))
                        .rotationEffect(.degrees(ruleDisclosed ? 90 : 0))
                    Text(ruleDisclosed ? "Hide rule" : "Show rule")
                }
                .font(.system(size: 11))
                .foregroundStyle(Theme.textMuted)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(ruleDisclosed ? "Hide the policy rule" : "Show the policy rule that triggered this prompt")

            if ruleDisclosed {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    detailLabel("Rule")
                    Text(model.context.ruleDisplayName)
                        .font(.system(size: 12.5))
                        .foregroundStyle(Theme.textSecondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func detailLabel(_ label: String) -> some View {
        Text(label.uppercased())
            .font(.system(size: 11.5))
            .tracking(0.7)
            .foregroundStyle(Theme.textMuted)
            .frame(width: 74, alignment: .leading)
    }

    private func detailRow(_ label: String, value: String, valueColor: Color) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            detailLabel(label)
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(valueColor)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// Tallest the request row grows before it scrolls.
    private static let requestRowMaxHeight: CGFloat = 140
    /// First-line baseline of the request value (12pt monospaced), from its top.
    private static let requestValueAscender = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular).ascender

    /// The request row (COMMAND / ITEM / RIGHT) always holds the whole value —
    /// never truncated — and scrolls once it's taller than
    /// ``requestRowMaxHeight``, so a very long command can't push the window off
    /// screen or hide its tail. The controller sizes the window from the ideal
    /// height, so the row reports a bounded one: `fixedSize` asks the scroll
    /// view for its content's height and the frame caps it.
    private var requestRow: some View {
        let ascender = Self.requestValueAscender
        return HStack(alignment: .firstTextBaseline, spacing: 12) {
            detailLabel(model.context.requestRowLabel)
            ScrollView(.vertical) {
                Text(model.context.requestRowValue)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(Theme.prompt)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .scrollPosition($requestScroll)
            .scrollIndicatorsFlash(onAppear: true)
            .frame(maxHeight: Self.requestRowMaxHeight)
            .fixedSize(horizontal: false, vertical: true)
            // A scroll view has no text baseline (the label would line up with
            // its bottom edge), so align on the value's first line.
            .alignmentGuide(.firstTextBaseline) { $0[.top] + ascender }
        }
    }

    // MARK: Justification

    private var justificationField: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("JUSTIFICATION (REQUIRED)")
                .font(.system(size: 11.5))
                .tracking(0.7)
                .foregroundStyle(Theme.textMuted)
            TextField("Why do you need this?", text: $model.justificationText, axis: .vertical)
                .textFieldStyle(.plain).font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                .lineLimit(2...4)
                .focused($justificationFocused)
                .padding(Spacing.sm)
                .background(Theme.backgroundDeep.opacity(0.6), in: RoundedRectangle(cornerRadius: Radius.chip, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: Radius.chip, style: .continuous).strokeBorder(Theme.stroke, lineWidth: 1))
                .accessibilityLabel(minLengthHint ?? "Justification")
            // Only when an admin sets a floor above the "any non-empty text"
            // default: a live reason the button is still disabled, so a short
            // reason never dead-ends silently the way it used to.
            if let hint = minLengthHint {
                Text(hint)
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textMuted)
            }
        }
        .padding(.vertical, Spacing.lg)
        .padding(.horizontal, Spacing.xxl)
    }

    /// "Minimum N characters" while the trimmed justification is below an
    /// admin-configured floor greater than 1; `nil` once satisfied, or when the
    /// floor is the default 1 (any non-empty text — no counter needed).
    private var minLengthHint: String? {
        let minLen = model.context.justificationMinLength
        guard minLen > 1 else { return nil }
        let typed = model.justificationText.trimmingCharacters(in: .whitespacesAndNewlines).count
        guard typed < minLen else { return nil }
        return "Minimum \(minLen) characters"
    }

    // MARK: Actions

    private var actions: some View {
        VStack(spacing: 0) {
            countdownLine
                .padding(.bottom, 14)
            HStack(spacing: 10) {
                denyButton
                approveButton
            }
            // The arming hint takes the provenance line's place while it shows
            // (an overlay, so the window never changes size under the pointer).
            provenanceLine
                .opacity(model.disarmedReason == nil ? 1 : 0)
                .accessibilityHidden(model.disarmedReason != nil)
                .overlay {
                    if let reason = model.disarmedReason {
                        armingHint(reason)
                    }
                }
                .padding(.top, 13)
        }
        .padding(.top, 16)
        .padding(.horizontal, Spacing.xxl)
        .padding(.bottom, 22)
    }

    private var countdownLine: some View {
        HStack(spacing: 7) {
            Image(systemName: "timer")
                .font(.system(size: 12))
            Text("Denies automatically in")
            Text(countdownText)
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(urgent ? Theme.deny : Theme.textSecondary)
                .contentTransition(reduceMotion ? .identity : .numericText(countsDown: true))
                .animation(reduceMotion ? nil : .linear(duration: 0.2), value: model.remainingSeconds)
        }
        .font(.system(size: 11.5))
        .foregroundStyle(Theme.textMuted)
        .frame(maxWidth: .infinity)
        .accessibilityLabel("Denies automatically in \(model.remainingSeconds) seconds")
    }

    private var countdownText: String {
        let secs = max(0, model.remainingSeconds)
        return "\(secs / 60):" + String(format: "%02d", secs % 60)
    }

    private var denyButton: some View {
        Button { model.deny() } label: {
            HStack(spacing: 8) {
                Image(systemName: "xmark").font(.system(size: 13, weight: .semibold))
                Text(denyLabel)
            }
            .font(.system(size: 14, weight: .semibold))
            .foregroundStyle(Theme.deny)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(Theme.denyDim, in: RoundedRectangle(cornerRadius: Radius.button, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.button, style: .continuous)
                .strokeBorder(Theme.deny.opacity(0.30), lineWidth: 1))
        }
        .buttonStyle(.plain)
        // Escape cancels (root `onExitCommand`), and bare Return cancels too —
        // approval must be deliberate (⌘↩). Return is left unbound while a
        // justification field is present so typing can't trigger a deny.
        .keyboardShortcut(model.context.requireJustification ? nil : .defaultAction)
        .accessibilityLabel("\(denyLabel) — deny this request")
    }

    private var approveButton: some View {
        Button { model.approve() } label: {
            HStack(spacing: 8) {
                Image(systemName: "checkmark").font(.system(size: 13, weight: .semibold))
                Text(allowLabel)
            }
            .font(.system(size: 14, weight: .semibold))
            .foregroundStyle(Theme.accentInk)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(Theme.accentGradient, in: RoundedRectangle(cornerRadius: Radius.button, style: .continuous))
            .shadow(color: Theme.accentGlow, radius: 13, y: 6)
        }
        .buttonStyle(.plain)
        .keyboardShortcut(.return, modifiers: .command)
        .disabled(!model.canApprove)
        .opacity(model.canApprove ? 1 : 0.5)
        .accessibilityLabel("\(allowLabel) — approve this request (Command Return)")
    }

    /// Why Approve is still disabled once the prompt has been up for a second:
    /// it arms only while this window has the focus and nothing covers it.
    private func armingHint(_ reason: PromptViewModel.DisarmedReason) -> some View {
        let text: String
        switch reason {
        case .covered: text = "Move this window so nothing covers it to approve"
        case .notFocused: text = "Click this window to approve"
        }
        return Text(text)
            .font(.system(size: 11))
            .foregroundStyle(Theme.textSecondary)
            .lineLimit(1)
            .minimumScaleFactor(0.8)
            .frame(maxWidth: .infinity)
            .accessibilityLabel("Approve is unavailable. \(text).")
    }

    private var provenanceLine: some View {
        HStack(spacing: 7) {
            SerberusChevronsView()
                .frame(width: 12, height: 12)
            Text("Recorded by Serberus Sentinel · request \(shortRequestID)")
        }
        .font(.system(size: 11))
        .foregroundStyle(Theme.textMuted)
        .frame(maxWidth: .infinity)
    }

    private var shortRequestID: String {
        String(model.context.requestID.uuidString.prefix(8)).lowercased()
    }
}
