import SwiftUI

/// Brand palette for the Serberus identity system.
///
/// Self-contained on purpose: the icon library has no dependency on either
/// app's local `Theme`, so the Commander app and the menu-bar sentinel draw the exact
/// same mark from one source. The emerald ramp is rebased on the Sentinel
/// design accent (`--accent` 0x3EE0A1 / `--accent-strong` 0x58ECB2, see
/// `SerberusSentinelShared/SentinelTheme.swift`, mirrored by Commander's
/// `Theme`) so the shared mark is the SAME green as the UI around it in both
/// apps — previously the mark carried an older 0x2BBF9C ramp and read as a
/// duller teal beside the accent.
public enum SerberusBrand {

    /// Builds a color from a 24-bit RGB hex literal. Kept internal so it never
    /// collides with each app's own `Color(hex:)` convenience initializer.
    static func rgb(_ hex: UInt) -> Color {
        Color(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }

    // Emerald ramp (light → dark), anchored on the shared accent
    public static let emeraldBright = rgb(0x58ECB2)   // --accent-strong
    public static let emeraldMid    = rgb(0x4BE6AA)
    public static let emerald       = rgb(0x3EE0A1)   // --accent
    public static let emeraldDeep   = rgb(0x227B59)
    public static let emeraldShadow = rgb(0x195A40)

    // State ramps (== Sentinel's silent / deny)
    public static let amber        = rgb(0xF5B13D)
    public static let amberDeep    = rgb(0xB47B12)
    public static let critical     = rgb(0xFF6672)
    public static let criticalDeep = rgb(0xB23445)

    // Graphite / structure (== Sentinel's --bg / --bg-2)
    public static let graphite     = rgb(0x06090A)
    public static let graphiteTile = rgb(0x0A0F10)
    public static let nodeGlow     = rgb(0x8AF2CF)
}
