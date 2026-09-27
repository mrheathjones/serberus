import SwiftUI

// MARK: - Color from hex

extension Color {
    /// Creates a color from a 24-bit RGB hex value (e.g. `0x2BBF9C`).
    init(hex: UInt, opacity: Double = 1) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: opacity
        )
    }
}

// MARK: - Serberus design tokens
//
// "Privilege. Controlled." — shares its palette 1:1 with Serberus Sentinel
// (`SerberusSentinelShared/SentinelTheme.swift`) so Commander and Sentinel
// read as one product. 85–90% of the UI is near-black graphite/glass; the
// accent green is reserved for actions, trust, approvals, active states, and
// focus. Thin borders and subtle glows over large colored fills.
//
// Colours, radii, and type are shared 1:1. SPACING IS DELIBERATELY NOT:
// Commander's console canvas uses wider gutters (md 12 / lg 16 / xl 24) than
// Sentinel's popover scale (11 / 14 / 18).

enum Theme {

    // Brand — accent (== Sentinel's --accent / --accent-strong). The SerberusUI
    // `SerberusBrand` ramp behind the shared mark is rebased on the same values,
    // so the brand mark and the UI are one green in both apps.
    static let emerald = Color(hex: 0x3EE0A1)
    /// Console-only (EnforcementRing gradient); == `SerberusBrand.emeraldDeep`.
    static let emeraldDeep = Color(hex: 0x227B59)
    static let emeraldGlow = Color(hex: 0x58ECB2)
    /// Ink for text/glyphs sitting on an accent fill (buttons, badges).
    static let onEmerald = Color(hex: 0x04140D)

    // Graphite surfaces
    /// Sentinel's `--bg-2`: the slightly LIFTED ground (sidebar column, top of
    /// the AppBackground gradient). It is lighter than `background` — NOT a
    /// well. Inset wells (fields, code blocks) use `background` over a surface.
    static let backgroundDeep = Color(hex: 0x0A0F10)
    static let background = Color(hex: 0x06090A)
    static let surface = Color.white.opacity(0.028)
    static let elevated = Color.white.opacity(0.05)
    static let border = Color.white.opacity(0.08)
    static let borderStrong = Color.white.opacity(0.14)

    // Text
    static let textPrimary = Color(hex: 0xEDF4F1, opacity: 0.96)
    static let textSecondary = Color(hex: 0xEDF4F1, opacity: 0.60)
    static let textMuted = Color(hex: 0xEDF4F1, opacity: 0.36)

    // Semantic
    static let success = Color(hex: 0x3EE0A1)
    static let warning = Color(hex: 0xF5B13D)
    static let critical = Color(hex: 0xFF6672)
    static let info = Color(hex: 0x64A6FF)

    /// Hairline border used on cards and dividers.
    static let hairline = border

    /// Soft glow cast under the primary accent button (design: --accent-glow).
    static let accentGlow = Color(hex: 0x3EE0A1, opacity: 0.30)

    /// Primary accent gradient (design: `linear-gradient(160deg, --accent, --accent-strong)`).
    static let accentGradient = LinearGradient(
        colors: [emerald, emeraldGlow],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    /// Soft accent tint for selected / hover fills (design: --accent-dim).
    static let accentDim = Color(hex: 0x3EE0A1, opacity: 0.14)

    /// Glass-chrome stroke, shared with Sentinel's header/footer chrome.
    static let glassBorder = Color.white.opacity(0.09)
    /// Glass-chrome tint washes + specular top edge (Sentinel's `--glass`,
    /// `--glass-2`, `--glass-hi`) — the menu-bar popover's header and footer.
    static let glass = Color(.sRGB, red: 18 / 255, green: 26 / 255, blue: 24 / 255, opacity: 0.55)
    static let glass2 = Color(.sRGB, red: 24 / 255, green: 32 / 255, blue: 30 / 255, opacity: 0.70)
    static let glassHighlight = Color.white.opacity(0.14)
    /// Menu-bar popover body gradient endpoints (design:
    /// `linear-gradient(180deg,#0e1413,#0a100f)`, same as Sentinel's popover).
    static let popoverTop = Color(hex: 0x0E1413)
    static let popoverBottom = Color(hex: 0x0A100F)

    /// App-icon chip fill behind the brand mark
    /// (design: `radial-gradient(130% 130% at 30% 12%, #12563f, #081c18 72%)`).
    static let iconChipGradient = RadialGradient(
        colors: [Color(hex: 0x12563F), Color(hex: 0x081C18)],
        center: UnitPoint(x: 0.30, y: 0.12),
        startRadius: 0,
        endRadius: 46
    )
}

// MARK: - Spacing & radius

enum Spacing {
    static let xxs: CGFloat = 4
    static let xs: CGFloat = 6
    static let sm: CGFloat = 8
    static let md: CGFloat = 12
    static let lg: CGFloat = 16
    static let xl: CGFloat = 24
    static let xxl: CGFloat = 32
    static let section: CGFloat = 40
}

enum Radius {
    // Use-named radii shared with Sentinel (`Radius.badge / chip / card`).
    static let badge: CGFloat = 6
    static let chip: CGFloat = 8
    static let card: CGFloat = 10
    // Generic scale: sm = chip, md = control (buttons, segmented), lg = panel, xl = sheet.
    static let sm: CGFloat = 8
    static let md: CGFloat = 9
    static let lg: CGFloat = 12
    static let xl: CGFloat = 18
    static let pill: CGFloat = 999
}

// MARK: - Typography

extension Font {
    /// Large numeric/metric display — SF Mono, like Sentinel's counter cards.
    static func metric(_ size: CGFloat = 30) -> Font {
        .system(size: size, weight: .semibold, design: .monospaced)
    }

    /// Uppercase section eyebrow label (design: 11px/700, tracked, --text-3 —
    /// the same eyebrow Sentinel's section labels use).
    static let eyebrow = Font.system(size: 11, weight: .bold)

    /// Monospaced detail text (paths, hashes, traces).
    static func mono(_ size: CGFloat = 11) -> Font {
        .system(size: size, weight: .regular, design: .monospaced)
    }
}

// MARK: - Status semantics

/// The four daemon/sentinel states share one color + glyph vocabulary across the
/// whole UI so operators read status the same way everywhere.
enum StatusTone {
    case healthy
    case pending
    case degraded
    case offline
    case neutral

    var color: Color {
        switch self {
        case .healthy: return Theme.success
        case .pending: return Theme.warning
        case .degraded: return Theme.critical
        case .offline: return Theme.textMuted
        case .neutral: return Theme.info
        }
    }

    var symbol: String {
        switch self {
        case .healthy: return "checkmark.shield.fill"
        case .pending: return "clock.badge.fill"
        case .degraded: return "exclamationmark.shield.fill"
        case .offline: return "shield.slash.fill"
        case .neutral: return "shield.lefthalf.filled"
        }
    }
}
