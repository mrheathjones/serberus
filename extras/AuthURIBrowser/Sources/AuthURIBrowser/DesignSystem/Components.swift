import AppKit
import SwiftUI

// Serberus UI components, ported from Commander's DesignSystem/Components.swift
// and SerberusUI (sigil). Same recipes, trimmed to what this tool uses.

// MARK: - Backdrop

/// Sentinel's near-black canvas plus a barely-there lift and one faint accent
/// bloom in the top-leading corner (Commander's `AppBackground`).
struct AppBackground: View {
    var body: some View {
        ZStack {
            Theme.background
            LinearGradient(colors: [Theme.backgroundDeep, Theme.background], startPoint: .top, endPoint: .bottom)
                .opacity(0.9)
            RadialGradient(
                colors: [Theme.emerald.opacity(0.07), .clear],
                center: .init(x: 0.04, y: -0.02),
                startRadius: 0,
                endRadius: 560
            )
        }
        .ignoresSafeArea()
    }
}

// MARK: - Surfaces

/// Flat surface-1 card: translucent fill + hairline, no shadow.
struct CardModifier: ViewModifier {
    var padding: CGFloat = Spacing.lg
    var radius: CGFloat = Radius.card
    var elevated = false
    var stroke: Color = Theme.hairline

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(elevated ? Theme.elevated : Theme.surface,
                        in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous).strokeBorder(stroke, lineWidth: 1))
    }
}

extension View {
    func card(padding: CGFloat = Spacing.lg, radius: CGFloat = Radius.card, elevated: Bool = false,
              stroke: Color = Theme.hairline) -> some View {
        modifier(CardModifier(padding: padding, radius: radius, elevated: elevated, stroke: stroke))
    }
}

/// Code-block well for the raw plist: the page ground at 70% under a hairline.
struct CodeBlock<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(Spacing.md)
            .background(Theme.background.opacity(0.7), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

// MARK: - Labels & status

/// Uppercase muted eyebrow above sections (11/700, 0.12em).
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

/// Softly-glowing status dot.
struct StatusDot: View {
    var color: Color = Theme.success
    var size: CGFloat = 8
    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .shadow(color: color.opacity(0.8), radius: size * 0.7)
            .accessibilityHidden(true)
    }
}

/// Pill badge with a thin tinted border — never a solid fill (Commander's
/// `StatusBadge`).
struct PillBadge: View {
    let text: String
    let color: Color
    var symbol: String?
    var trailingSymbol: String?

    var body: some View {
        HStack(spacing: 5) {
            if let symbol {
                Image(systemName: symbol).font(.system(size: 9, weight: .bold))
            }
            Text(text).font(.system(size: 11, weight: .semibold))
            if let trailingSymbol {
                Image(systemName: trailingSymbol).font(.system(size: 9, weight: .bold)).opacity(0.85)
            }
        }
        .foregroundStyle(color)
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(color.opacity(0.12), in: Capsule())
        .overlay(Capsule().strokeBorder(color.opacity(0.30), lineWidth: 1))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}

/// Small uppercase tag (Sentinel's `DecisionBadge` spec: 10.5/700, tracked,
/// 3×8 padding, radius 6, dim fill).
struct TagChip: View {
    let text: String
    let color: Color
    init(_ text: String, color: Color = Theme.textSecondary) {
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

/// Key/value detail row (label column 150pt, value selectable).
struct DetailRow: View {
    let label: String
    let value: String
    var mono = false
    var valueColor: Color = Theme.textPrimary

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.mono(11))
                .foregroundStyle(Theme.textSecondary)
                .frame(width: 150, alignment: .leading)
            Text(value)
                .font(mono ? .mono(11) : .system(size: 12, weight: .medium))
                .foregroundStyle(valueColor)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Controls

struct GhostControlChrome: ViewModifier {
    var pressed = false
    var active = false
    func body(content: Content) -> some View {
        content
            .font(.system(size: 12.5, weight: .semibold))
            .foregroundStyle(active ? Theme.emerald : Theme.textSecondary)
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(Theme.elevated, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                .strokeBorder(active ? Theme.emerald.opacity(0.5) : Theme.hairline, lineWidth: 1))
            .opacity(pressed ? 0.85 : 1)
    }
}

struct TintedControlChrome: ViewModifier {
    var pressed = false
    func body(content: Content) -> some View {
        content
            .font(.system(size: 12.5, weight: .semibold))
            .foregroundStyle(Theme.emerald)
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(Theme.accentDim, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                .strokeBorder(Theme.emerald.opacity(0.35), lineWidth: 1))
            .opacity(pressed ? 0.8 : 1)
    }
}

struct GhostButtonStyle: ButtonStyle {
    var active = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.modifier(GhostControlChrome(pressed: configuration.isPressed, active: active))
    }
}

struct TintedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.modifier(TintedControlChrome(pressed: configuration.isPressed))
    }
}

extension ButtonStyle where Self == GhostButtonStyle {
    static var ghost: GhostButtonStyle { GhostButtonStyle() }
    static func ghost(active: Bool) -> GhostButtonStyle { GhostButtonStyle(active: active) }
}

extension ButtonStyle where Self == TintedButtonStyle {
    static var tinted: TintedButtonStyle { TintedButtonStyle() }
}

/// Dark bordered search field (Commander's filter-bar idiom).
struct SearchField: View {
    @Binding var text: String
    var prompt: String

    var body: some View {
        HStack(spacing: Spacing.sm) {
            Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            TextField(prompt, text: $text)
                .textFieldStyle(.plain)
                .font(.system(size: 13))
                .foregroundStyle(Theme.textPrimary)
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(Theme.textMuted)
                    .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.elevated.opacity(0.7), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

// MARK: - Brand

/// The Serberus sigil — three stacked chevrons, rising — from the design
/// handoff geometry (40×40 box, stroke 3.4, round caps). Strokes with the
/// current `foregroundStyle`. Mirrors `SerberusUI.SerberusSigilView`.
struct SerberusSigilView: View {
    var body: some View {
        Canvas { ctx, size in
            let side = min(size.width, size.height)
            let scale = side / 40
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                CGPoint(x: size.width / 2 + (x - 20) * scale, y: size.height / 2 + (y - 20) * scale)
            }
            let stroke: CGFloat = side < 20 ? 2.4 : (side > 200 ? 4.4 : 3.4)
            for (fromY, apexY) in [(CGFloat(17), CGFloat(7)), (25, 15), (33, 23)] {
                var path = Path()
                path.move(to: p(9, fromY))
                path.addLine(to: p(20, apexY))
                path.addLine(to: p(31, fromY))
                ctx.stroke(path, with: .style(.foreground),
                           style: StrokeStyle(lineWidth: stroke * scale, lineCap: .round, lineJoin: .round))
            }
        }
        .accessibilityHidden(true)
    }
}

/// Icon chip: the app-icon tile gradient with the sigil at the handoff's 72%
/// optical box (Commander's 34pt brand-header chip).
struct BrandChip: View {
    var size: CGFloat = 34
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.29, style: .continuous)
                .fill(Theme.iconChipGradient)
            SerberusSigilView()
                .foregroundStyle(Theme.emerald)
                .frame(width: size * 0.7, height: size * 0.7)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

// MARK: - Clipboard

enum Clipboard {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
