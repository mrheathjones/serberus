import AppKit
import SwiftUI

// MARK: - Surfaces

/// Flat surface-1 card — the default content surface (used for the dense
/// 85–90% of the UI). Translucent fill + hairline, no shadow — Sentinel's
/// `sentinelCard` (a drop shadow under a 2.8%-white fill would only halo the
/// card's opaque children).
struct CardModifier: ViewModifier {
    var padding: CGFloat = Spacing.lg
    var radius: CGFloat = Radius.card
    var elevated = false

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(
                (elevated ? Theme.elevated : Theme.surface),
                in: RoundedRectangle(cornerRadius: radius, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Theme.hairline, lineWidth: 1)
            )
    }
}

extension View {
    func card(padding: CGFloat = Spacing.lg, radius: CGFloat = Radius.card, elevated: Bool = false) -> some View {
        modifier(CardModifier(padding: padding, radius: radius, elevated: elevated))
    }
}

// MARK: - Status

/// A small, softly-glowing status dot.
struct StatusDot: View {
    let tone: StatusTone
    var size: CGFloat = 8

    var body: some View {
        Circle()
            .fill(tone.color)
            .frame(width: size, height: size)
            .shadow(color: tone.color.opacity(0.8), radius: size * 0.7)
            .accessibilityHidden(true)
    }
}

/// Pill badge with thin tinted border — never a solid fill.
struct StatusBadge: View {
    let text: String
    let tone: StatusTone
    var symbol: String?

    init(_ text: String, tone: StatusTone, symbol: String? = nil) {
        self.text = text
        self.tone = tone
        self.symbol = symbol
    }

    var body: some View {
        HStack(spacing: 5) {
            if let symbol {
                Image(systemName: symbol).font(.system(size: 9, weight: .bold))
            } else {
                StatusDot(tone: tone, size: 6)
            }
            Text(text).font(.system(size: 11, weight: .semibold))
        }
        .foregroundStyle(tone.color)
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(tone.color.opacity(0.12), in: Capsule())
        .overlay(Capsule().strokeBorder(tone.color.opacity(0.30), lineWidth: 1))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}

/// Rule-decision badge — Sentinel's `DecisionBadge` spec (10.5/700, 0.06em,
/// uppercase, 3×8 padding, radius 6, dim fill, decision-colour text) so the
/// same rule reads identically in Commander and in the user's Sentinel.
/// Decision colours: allow `Theme.success`, deny `Theme.critical`,
/// prompt `Theme.info`, silent `Theme.warning`. Keep `StatusBadge` for
/// health/status; this is for allow/deny/prompt/silent only.
struct RuleDecisionBadge: View {
    let text: String
    let color: Color

    init(_ text: String, color: Color) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 10.5, weight: .bold))
            .tracking(0.6)
            .foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.14), in: RoundedRectangle(cornerRadius: Radius.badge, style: .continuous))
            .accessibilityLabel(text)
    }
}

// MARK: - Labels

/// Uppercase muted eyebrow used above sections (design: 11px/700, 0.12em,
/// uppercase, --text-3 — identical to Sentinel's `SectionLabel`).
struct SectionLabel: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased())
            .font(.eyebrow)
            .tracking(1.3)
            .foregroundStyle(Theme.textMuted)
    }
}

// MARK: - Segmented control

/// Custom segmented control, built from Buttons instead of
/// `.pickerStyle(.segmented)`: the native picker pins itself to the
/// container's leading edge on macOS 27 (swallowing the bar's leading padding)
/// and cannot take
/// the accent-gradient selected state. It mirrors the Button-built
/// `modeControl` in Sentinel's Intel tab (same 7/5 radii and 2pt inset) with
/// Sentinel's accent tokens; the two are not yet one shared type — hoisting
/// this into `SerberusUI` for both apps is the natural follow-up. Options are
/// ordered `KeyValuePairs` so call sites read `[.enforce: "Enforce", …]`.
struct SegmentedControl<Value: Hashable>: View {
    @Binding var selection: Value
    let options: KeyValuePairs<Value, String>
    /// Accessibility label for the whole group (e.g. "Enforcement mode") —
    /// the native picker exposed one element; without this VoiceOver reads N
    /// unrelated buttons.
    var label: String?
    /// Fixed overall width → equal-width segments; `nil` sizes each segment to
    /// its own label (the `.fixedSize()` look).
    var width: CGFloat?

    init(selection: Binding<Value>, options: KeyValuePairs<Value, String>,
         label: String? = nil, width: CGFloat? = nil) {
        _selection = selection
        self.options = options
        self.label = label
        self.width = width
    }

    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(options), id: \.key) { option in
                let selected = option.key == selection
                Button {
                    selection = option.key
                } label: {
                    Text(option.value)
                        .font(.system(size: 12, weight: .medium))
                        .lineLimit(1)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .frame(maxWidth: width == nil ? nil : .infinity)
                        .background {
                            if selected {
                                RoundedRectangle(cornerRadius: 5, style: .continuous)
                                    .fill(Theme.accentGradient)
                            }
                        }
                        .foregroundStyle(selected ? Theme.onEmerald : Theme.textSecondary)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selected ? [.isSelected] : [])
            }
        }
        .padding(2)
        .frame(width: width)
        .background(Theme.elevated, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
        // Scoped to the control: only the highlight animates, never the
        // dependent layout at the call site (Settings sub-forms etc.).
        .animation(.easeOut(duration: 0.12), value: selection)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(label ?? "")
    }
}

/// A standard screen header: title, optional subtitle, trailing accessory.
struct ScreenHeader<Trailing: View>: View {
    let title: String
    var subtitle: String?
    @ViewBuilder var trailing: Trailing

    init(_ title: String, subtitle: String? = nil, @ViewBuilder trailing: () -> Trailing = { EmptyView() }) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 22, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                if let subtitle {
                    Text(subtitle).font(.system(size: 13))
                        .foregroundStyle(Theme.textSecondary)
                }
            }
            Spacer(minLength: Spacing.lg)
            trailing
        }
    }
}

// MARK: - Wizard stepper

/// Horizontal numbered step indicator for multi-step flows (Create Policy).
struct StepperHeader: View {
    let steps: [String]
    let current: Int

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(steps.enumerated()), id: \.offset) { index, title in
                let done = index < current
                let active = index == current
                HStack(spacing: 8) {
                    ZStack {
                        Circle()
                            .fill(done || active ? Theme.emerald.opacity(done ? 1 : 0.18) : Theme.elevated)
                            .frame(width: 26, height: 26)
                            .overlay(Circle().strokeBorder(active ? Theme.emerald : Theme.border, lineWidth: 1))
                        if done {
                            Image(systemName: "checkmark").font(.system(size: 11, weight: .bold))
                                .foregroundStyle(Theme.onEmerald)
                        } else {
                            Text("\(index + 1)").font(.system(size: 12, weight: .bold))
                                .foregroundStyle(active ? Theme.emerald : Theme.textMuted)
                        }
                    }
                    Text(title)
                        .font(.system(size: 12, weight: active ? .semibold : .medium))
                        .foregroundStyle(active ? Theme.textPrimary : Theme.textMuted)
                        .fixedSize()
                }
                if index < steps.count - 1 {
                    Rectangle()
                        .fill(done ? Theme.emerald.opacity(0.6) : Theme.border)
                        .frame(height: 1)
                        .frame(maxWidth: .infinity)
                        .padding(.horizontal, Spacing.sm)
                }
            }
        }
    }
}

// MARK: - Metric tile

/// Dashboard metric: glyph, large value, label, optional delta. With an
/// `action` the whole tile is a button (hover lifts it, a chevron marks it as
/// a link) that routes to the screen the number comes from — the same
/// counter-card affordance as the Sentinel popover.
struct MetricTile: View {
    let label: String
    let value: String
    var symbol: String
    var tone: StatusTone = .neutral
    var delta: String?
    var deltaUp = true
    /// Tooltip (what the number counts / where the tile goes).
    var help: String? = nil
    var action: (() -> Void)? = nil
    @State private var hovering = false

    var body: some View {
        if let action {
            Button(action: action) { content }
                .buttonStyle(.plain)
                .onHover { hovering = $0 }
                .help(help ?? "")
                .accessibilityLabel("\(value) \(label)")
                .accessibilityHint("Open")
                .animation(.easeOut(duration: 0.12), value: hovering)
        } else {
            content.help(help ?? "")
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack {
                Image(systemName: symbol)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(tone.color)
                    .frame(width: 30, height: 30)
                    .background(tone.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Spacer()
                if let delta {
                    Label(delta, systemImage: deltaUp ? "arrow.up.right" : "arrow.down.right")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(deltaUp ? Theme.success : Theme.textMuted)
                        .labelStyle(.titleAndIcon)
                } else if action != nil {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(hovering ? Theme.textSecondary : Theme.textMuted)
                }
            }
            Text(value)
                .font(.metric(28))
                .foregroundStyle(Theme.textPrimary)
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(Theme.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(elevated: hovering && action != nil)
        .contentShape(RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
    }
}

// MARK: - Key/value detail row

struct DetailRow: View {
    let label: String
    let value: String
    var mono = false
    var valueColor: Color = Theme.textPrimary

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(Theme.textSecondary)
                .frame(width: 120, alignment: .leading)
            Text(value)
                .font(mono ? .mono(11) : .system(size: 12, weight: .medium))
                .foregroundStyle(valueColor)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Control chrome & buttons

/// Primary-action chrome — Sentinel's primary button (accent gradient, ink
/// text, 12.5/600, radius 9, 12×9 insets, accent glow) expressed as a
/// modifier so `Button`s (via `EmeraldButtonStyle`) and `Menu` labels share
/// ONE recipe instead of hand-rolled copies that drift.
struct PrimaryControlChrome: ViewModifier {
    var pressed = false
    func body(content: Content) -> some View {
        content
            .font(.system(size: 12.5, weight: .semibold))
            .foregroundStyle(Theme.onEmerald)
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(Theme.accentGradient, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .shadow(color: Theme.accentGlow.opacity(pressed ? 0.4 : 1), radius: 10, y: 4)
            .opacity(pressed ? 0.85 : 1)
    }
}

/// Secondary chrome — Sentinel's ghost button (surface-2 fill, hairline
/// stroke, secondary text). `active` tints text + stroke accent, for a filter
/// menu whose selection is not the default.
struct GhostControlChrome: ViewModifier {
    var pressed = false
    var active = false
    func body(content: Content) -> some View {
        content
            .font(.system(size: 12.5, weight: .semibold))
            .foregroundStyle(active ? Theme.emerald : Theme.textSecondary)
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(Theme.elevated, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                .strokeBorder(active ? Theme.emerald.opacity(0.5) : Theme.hairline, lineWidth: 1))
            .opacity(pressed ? 0.85 : 1)
    }
}

/// Tinted chrome — the quiet accent for PAGE-LEVEL actions ("New Rule",
/// "New Policy", "New Definition"): accent-dim fill, accent text, a faint
/// accent stroke. Sits between ghost and primary so a toolbar does not carry a
/// full-gradient block on every screen; the full primary gradient is reserved
/// for the single commit action of a sheet ("Create Definition", "Publish").
struct TintedControlChrome: ViewModifier {
    var pressed = false
    func body(content: Content) -> some View {
        content
            .font(.system(size: 12.5, weight: .semibold))
            .foregroundStyle(Theme.emerald)
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(Theme.accentDim, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                .strokeBorder(Theme.emerald.opacity(0.35), lineWidth: 1))
            .opacity(pressed ? 0.8 : 1)
    }
}

extension View {
    /// Primary-action chrome for non-`Button` controls (a `Menu` label).
    func primaryControlChrome(pressed: Bool = false) -> some View {
        modifier(PrimaryControlChrome(pressed: pressed))
    }
    /// Secondary chrome for non-`Button` controls (a `Menu` label).
    func ghostControlChrome(pressed: Bool = false, active: Bool = false) -> some View {
        modifier(GhostControlChrome(pressed: pressed, active: active))
    }
    /// Tinted chrome for non-`Button` controls (a page-level `Menu` label).
    func tintedControlChrome(pressed: Bool = false) -> some View {
        modifier(TintedControlChrome(pressed: pressed))
    }
}

/// Page-level accent action button (see ``TintedControlChrome``).
struct TintedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.tintedControlChrome(pressed: configuration.isPressed)
    }
}

extension ButtonStyle where Self == TintedButtonStyle {
    static var tinted: TintedButtonStyle { TintedButtonStyle() }
}

// MARK: - Segmented action bar

/// A grouped row of ACTION buttons in the Intel-bar segmented idiom — one
/// track, equal-height segments with 12pt labels, the primary segment
/// accent-filled. Used for sheet footers that offer several sibling actions
/// ("Save Jamf Schema" / "Save .plist" / "Save .mobileconfig" / "Publish"),
/// the policy card's action row, and the Definitions batch-selection bar.
/// Segments size to their full titles, so nothing truncates; icon-only
/// segments (`iconOnly`) carry their title as the tooltip.
struct SegmentedActionBar: View {
    struct Action: Identifiable {
        let id: String
        let title: String
        /// Optional SF Symbol shown before the title (or alone — see `iconOnly`).
        var systemImage: String? = nil
        /// Icon-only segment: the title becomes the tooltip / accessibility
        /// label. For the secondary tail of a card's action row.
        var iconOnly = false
        var isPrimary = false
        /// Destructive tone: the label turns critical-red on hover.
        var isDestructive = false
        var isDisabled = false
        /// Replaces the icon with a small spinner (an in-flight publish).
        var isBusy = false
        var help: String? = nil
        let perform: () -> Void
    }

    let actions: [Action]

    var body: some View {
        HStack(spacing: 2) {
            ForEach(actions) { action in
                Segment(action: action)
            }
        }
        .padding(2)
        .background(Theme.elevated, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    private struct Segment: View {
        let action: Action
        @State private var hovering = false

        private var foreground: Color {
            if action.isPrimary { return Theme.onEmerald }
            if action.isDestructive, hovering, !action.isDisabled { return Theme.critical }
            return Theme.textSecondary
        }

        var body: some View {
            Button(action: action.perform) {
                HStack(spacing: 5) {
                    if action.isBusy {
                        ProgressView().controlSize(.mini).frame(width: 12, height: 12)
                    } else if let symbol = action.systemImage {
                        Image(systemName: symbol)
                            .font(.system(size: 11, weight: .semibold))
                            .frame(width: 12, height: 12)
                    }
                    if !action.iconOnly {
                        Text(action.title)
                            .font(.system(size: 12, weight: .medium))
                            .lineLimit(1)
                            .fixedSize()
                    }
                }
                .padding(.horizontal, action.iconOnly ? 9 : 12)
                .padding(.vertical, 5)
                .frame(minHeight: 24)
                .background {
                    if action.isPrimary {
                        RoundedRectangle(cornerRadius: 5, style: .continuous).fill(Theme.accentGradient)
                    } else if hovering, !action.isDisabled {
                        RoundedRectangle(cornerRadius: 5, style: .continuous)
                            .fill((action.isDestructive ? Theme.critical : Color.white).opacity(action.isDestructive ? 0.10 : 0.06))
                    }
                }
                .foregroundStyle(foreground)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(action.isDisabled)
            // A busy segment is disabled too (no double-fire) but must not
            // look "unavailable" — the spinner is the state.
            .opacity(action.isDisabled && !action.isBusy ? 0.45 : 1)
            .onHover { hovering = $0 }
            .help(action.help ?? (action.iconOnly ? action.title : ""))
            .accessibilityLabel(action.title)
        }
    }
}

/// Primary accent action button (the one place a solid brand fill is allowed).
struct EmeraldButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .primaryControlChrome(pressed: configuration.isPressed)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

/// Subtle bordered "ghost" button for secondary actions.
struct GhostButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.ghostControlChrome(pressed: configuration.isPressed)
    }
}

extension ButtonStyle where Self == EmeraldButtonStyle {
    static var emerald: EmeraldButtonStyle { EmeraldButtonStyle() }
}
extension ButtonStyle where Self == GhostButtonStyle {
    static var ghost: GhostButtonStyle { GhostButtonStyle() }
}

// MARK: - Form field

/// A labelled input wrapper that gives plain controls a dark, bordered field
/// look consistent with the rest of the UI.
struct LabeledField<Content: View>: View {
    let label: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            // Field labels are primary text for the form, not tertiary — 60%
            // keeps them ≥4.5:1 on a card; 36% (textMuted) drops to ~3:1.
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Theme.textSecondary)
            content
                .font(.system(size: 13))
                .foregroundStyle(Theme.textPrimary)
                .textFieldStyle(.plain)
                .padding(.horizontal, Spacing.md)
                .padding(.vertical, Spacing.sm)
                .background(Theme.background.opacity(0.55), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
        }
    }
}

/// Code-block style container for commands, hashes, and evaluation traces.
struct CodeBlock<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(Spacing.md)
            // A genuine well: the page ground (darker than any surface) at 70%.
            .background(Theme.background.opacity(0.7), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

// MARK: - Glass chrome (menu-bar popover)

/// Native stand-in for the design's CSS glass (`backdrop-filter: blur +
/// saturate` with a 1px specular top edge): an `NSVisualEffectView` behind a
/// tinted wash — Sentinel's `GlassBackground`. Chrome only (the menu-bar
/// popover header / footer), never list content.
struct GlassBackground: NSViewRepresentable {
    var material: NSVisualEffectView.Material = .hudWindow

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }

    func updateNSView(_ view: NSVisualEffectView, context: Context) {
        view.material = material
    }
}

extension View {
    /// Chrome glass: material + tint wash + 1px specular top edge (Sentinel's
    /// `sentinelGlass`).
    func glassChrome(_ tint: Color = Theme.glass2) -> some View {
        self.background {
            ZStack {
                GlassBackground()
                tint
                VStack(spacing: 0) {
                    Theme.glassHighlight.frame(height: 1)
                    Spacer(minLength: 0)
                }
            }
        }
    }
}
