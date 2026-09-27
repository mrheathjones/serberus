import SwiftUI

// Serberus design tokens, mirrored 1:1 from the Commander console
// (`Sources/SerberusCommander/DesignSystem/Theme.swift`) and Sentinel
// (`Sources/SerberusSentinelShared/SentinelTheme.swift`). Copied rather than
// imported so this tool stays a single portable SwiftPM target; if the shared
// palette changes, re-sync this file. "Privilege. Controlled." — 85–90% of the
// UI is near-black graphite/glass; emerald is reserved for actions, trust,
// active states, and focus.

extension Color {
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

enum Theme {
    // Brand accent
    static let emerald = Color(hex: 0x3EE0A1)
    static let emeraldDeep = Color(hex: 0x227B59)
    static let emeraldGlow = Color(hex: 0x58ECB2)
    /// Ink for text/glyphs sitting on an accent fill.
    static let onEmerald = Color(hex: 0x04140D)

    // Graphite surfaces
    static let backgroundDeep = Color(hex: 0x0A0F10)   // lifted ground (sidebar)
    static let background = Color(hex: 0x06090A)       // page ground
    static let surface = Color.white.opacity(0.028)    // card fill
    static let elevated = Color.white.opacity(0.05)    // control fill / hover
    static let border = Color.white.opacity(0.08)
    static let borderStrong = Color.white.opacity(0.14)
    static let hairline = border

    // Text
    static let textPrimary = Color(hex: 0xEDF4F1, opacity: 0.96)
    static let textSecondary = Color(hex: 0xEDF4F1, opacity: 0.60)
    static let textMuted = Color(hex: 0xEDF4F1, opacity: 0.36)

    // Semantic
    static let success = Color(hex: 0x3EE0A1)
    static let warning = Color(hex: 0xF5B13D)
    static let critical = Color(hex: 0xFF6672)
    static let info = Color(hex: 0x64A6FF)
    /// Two extra hues this tool needs for its nine badge kinds; chosen to sit
    /// beside the four semantics at the same lightness.
    static let violet = Color(hex: 0xB99CFF)
    static let cyan = Color(hex: 0x5FD7E6)

    static let accentGlow = Color(hex: 0x3EE0A1, opacity: 0.30)
    static let accentDim = Color(hex: 0x3EE0A1, opacity: 0.14)
    static let accentGradient = LinearGradient(
        colors: [emerald, emeraldGlow],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let glassBorder = Color.white.opacity(0.09)

    /// App-icon chip fill behind the sigil
    /// (design: `radial-gradient(130% 130% at 30% 12%, #12563f, #081c18 72%)`).
    static let iconChipGradient = RadialGradient(
        colors: [Color(hex: 0x12563F), Color(hex: 0x081C18)],
        center: UnitPoint(x: 0.30, y: 0.12),
        startRadius: 0,
        endRadius: 46
    )
}

/// Commander's console spacing scale (wider gutters than Sentinel's popover).
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
    static let badge: CGFloat = 6
    static let chip: CGFloat = 8
    static let card: CGFloat = 10
    static let sm: CGFloat = 8
    static let md: CGFloat = 9
    static let lg: CGFloat = 12
    static let xl: CGFloat = 18
}

extension Font {
    /// Uppercase section eyebrow (11/700, tracked).
    static let eyebrow = Font.system(size: 11, weight: .bold)
    /// Monospaced detail text (right names, plist keys).
    static func mono(_ size: CGFloat = 11, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}
