import AppKit
import PrivMgrCore
import SerberusSentinelCore
import SwiftUI

// Serberus Sentinel design tokens — the dark-canonical set from the design
// handoff (`design_handoff_sentinel/README.md`). Colors, type sizes, spacing,
// radii, and shadows are final; native materials substitute for CSS glass.

extension Color {
    init(hex: UInt, opacity: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: opacity)
    }
}

enum Theme {
    // Backgrounds
    static let background = Color(hex: 0x06090A)          // --bg
    static let backgroundDeep = Color(hex: 0x0A0F10)      // --bg-2 (recessed)
    /// Popover body gradient endpoints (design: `linear-gradient(180deg,#0e1413,#0a100f)`).
    static let popoverTop = Color(hex: 0x0E1413)
    static let popoverBottom = Color(hex: 0x0A100F)

    // Surfaces & strokes
    static let surface1 = Color.white.opacity(0.028)      // --surface-1 (card fill)
    static let surface2 = Color.white.opacity(0.05)       // --surface-2 (control fill)
    static let glass = Color(.sRGB, red: 18 / 255, green: 26 / 255, blue: 24 / 255, opacity: 0.55)
    static let glass2 = Color(.sRGB, red: 24 / 255, green: 32 / 255, blue: 30 / 255, opacity: 0.70)
    static let glassBorder = Color.white.opacity(0.09)    // --glass-brd
    static let glassHighlight = Color.white.opacity(0.14) // --glass-hi (specular top edge)
    static let stroke = Color.white.opacity(0.08)
    static let stroke2 = Color.white.opacity(0.14)
    static let hairline = stroke

    // Text
    static let textPrimary = Color(hex: 0xEDF4F1, opacity: 0.96)
    static let textSecondary = Color(hex: 0xEDF4F1, opacity: 0.60)
    static let textMuted = Color(hex: 0xEDF4F1, opacity: 0.36)

    // Accent (Serberus green)
    static let accent = Color(hex: 0x3EE0A1)
    static let accentStrong = Color(hex: 0x58ECB2)
    static let accentDim = Color(hex: 0x3EE0A1, opacity: 0.14)
    static let accentInk = Color(hex: 0x04140D)
    static let accentGlow = Color(hex: 0x3EE0A1, opacity: 0.30)

    // Decision colors
    static let allow = Color(hex: 0x3EE0A1)
    static let allowDim = Color(hex: 0x3EE0A1, opacity: 0.14)
    static let deny = Color(hex: 0xFF6672)
    static let denyDim = Color(hex: 0xFF6672, opacity: 0.14)
    static let prompt = Color(hex: 0x64A6FF)
    static let promptDim = Color(hex: 0x64A6FF, opacity: 0.14)
    static let silent = Color(hex: 0xF5B13D)
    static let silentDim = Color(hex: 0xF5B13D, opacity: 0.14)

    // Legacy aliases still used by secondary surfaces (History window).
    static let emerald = accent
    static let emeraldGlow = accentStrong
    static let onEmerald = accentInk
    static let surface = surface1
    static let elevated = surface2
    static let border = stroke
    static let borderStrong = stroke2
    static let success = allow
    static let warning = silent
    static let critical = deny
    static let info = prompt

    /// App-icon chip fill (design: `radial-gradient(130% 130% at 30% 12%, #12563f, #081c18 72%)`).
    static let iconChipGradient = RadialGradient(
        colors: [Color(hex: 0x12563F), Color(hex: 0x081C18)],
        center: UnitPoint(x: 0.30, y: 0.12),
        startRadius: 0,
        endRadius: 46
    )

    /// Primary accent gradient (design: `linear-gradient(160deg, --accent, --accent-strong)`).
    static let accentGradient = LinearGradient(
        colors: [accent, accentStrong],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
}

enum Spacing {
    static let xxs: CGFloat = 4
    static let xs: CGFloat = 6
    static let sm: CGFloat = 8
    static let md: CGFloat = 11
    static let lg: CGFloat = 14
    static let xl: CGFloat = 18
    static let xxl: CGFloat = 26
}

enum Radius {
    static let badge: CGFloat = 6
    static let chip: CGFloat = 8
    static let control: CGFloat = 9
    static let card: CGFloat = 10
    static let button: CGFloat = 11
    static let toast: CGFloat = 14
    static let popover: CGFloat = 16
    static let sheet: CGFloat = 18
    // Legacy aliases.
    static let sm: CGFloat = 8
    static let md: CGFloat = 10
    static let lg: CGFloat = 16
}

// MARK: - Decision presentation

extension SentinelRuleDecision {
    var color: Color {
        switch self {
        case .allow: return Theme.allow
        case .deny: return Theme.deny
        case .prompt: return Theme.prompt
        case .silent: return Theme.silent
        }
    }

    var dimColor: Color {
        switch self {
        case .allow: return Theme.allowDim
        case .deny: return Theme.denyDim
        case .prompt: return Theme.promptDim
        case .silent: return Theme.silentDim
        }
    }

    var badgeText: String { rawValue.uppercased() }
}

// MARK: - Tones (status dot / badges on secondary surfaces)

enum SentinelTone {
    case healthy, pending, degraded, offline, neutral
    var color: Color {
        switch self {
        case .healthy: return Theme.allow
        case .pending: return Theme.silent
        case .degraded: return Theme.deny
        case .offline: return Theme.textMuted
        case .neutral: return Theme.prompt
        }
    }
}

struct SentinelStatusDot: View {
    let tone: SentinelTone
    var size: CGFloat = 8
    var body: some View {
        Circle().fill(tone.color).frame(width: size, height: size)
            .shadow(color: tone.color.opacity(0.8), radius: size * 0.7)
    }
}

struct SentinelBadge: View {
    let text: String
    let tone: SentinelTone
    var symbol: String?
    var body: some View {
        HStack(spacing: 5) {
            if let symbol { Image(systemName: symbol).font(.system(size: 9, weight: .bold)) }
            else { SentinelStatusDot(tone: tone, size: 6) }
            Text(text).font(.system(size: 11, weight: .semibold))
        }
        .foregroundStyle(tone.color)
        .padding(.horizontal, 9).padding(.vertical, 4)
        .background(tone.color.opacity(0.12), in: Capsule())
        .overlay(Capsule().strokeBorder(tone.color.opacity(0.30), lineWidth: 1))
    }
}

/// Decision badge (design: 10.5/700, 0.06em tracking, 3×8 padding, radius 6,
/// tint fill, decision-colour text).
struct DecisionBadge: View {
    let decision: SentinelRuleDecision
    var body: some View {
        Text(decision.badgeText)
            .font(.system(size: 10.5, weight: .bold))
            .tracking(0.6)
            .foregroundStyle(decision.color)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(decision.dimColor, in: RoundedRectangle(cornerRadius: Radius.badge, style: .continuous))
    }
}

/// Section label (design: 11px/700, 0.12em, uppercase, --text-3).
struct SectionLabel: View {
    let text: String
    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 11, weight: .bold))
            .tracking(1.3)
            .foregroundStyle(Theme.textMuted)
    }
}

// MARK: - Cards & buttons

extension View {
    func sentinelCard(padding: CGFloat = Spacing.md, radius: CGFloat = Radius.card) -> some View {
        self.padding(padding)
            .background(Theme.surface1, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous).strokeBorder(Theme.stroke, lineWidth: 1))
    }
}

/// Primary accent button (design: accent gradient, --accent-ink text,
/// 12.5/600, radius 9, accent glow shadow).
struct SentinelEmeraldButton: ButtonStyle {
    var fontSize: CGFloat = 12.5
    var radius: CGFloat = Radius.control
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: fontSize, weight: .semibold))
            .foregroundStyle(Theme.accentInk)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 9).padding(.horizontal, 12)
            .background(Theme.accentGradient, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .shadow(color: Theme.accentGlow.opacity(configuration.isPressed ? 0.4 : 1), radius: 10, y: 4)
            .opacity(configuration.isPressed ? 0.85 : 1)
    }
}

/// Secondary button (design: --surface-2 fill, 1px --stroke, --text-2 text).
struct SentinelGhostButton: ButtonStyle {
    var fontSize: CGFloat = 12.5
    var radius: CGFloat = Radius.control
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: fontSize, weight: .semibold))
            .foregroundStyle(Theme.textSecondary)
            .padding(.vertical, 9).padding(.horizontal, 12)
            .background(Theme.surface2, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous).strokeBorder(Theme.stroke, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.85 : 1)
    }
}

// MARK: - Glass material

/// Native stand-in for the design's CSS glass (`backdrop-filter: blur +
/// saturate` with a 1px specular top edge): an `NSVisualEffectView` behind a
/// tinted wash. Used only for chrome — the popover header/footer and the
/// floating prompt sheet — never for list content (per the handoff).
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
    /// Chrome glass: material + tint wash + 1px specular top edge.
    func sentinelGlass(_ tint: Color = Theme.glass2) -> some View {
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
