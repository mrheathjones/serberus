import AppKit
import SwiftUI

/// A local copy of the handful of design tokens the Guardian's one panel needs.
/// Copied — NOT imported — so this lean watch-only agent doesn't drag in the
/// full theme stack (the real `Theme`/`Radius`/`GlassBackground` live in
/// `SerberusSentinelShared` behind `PrivMgrCore`/`SerberusSentinelCore` imports).
/// Keep these visually in step with the toast/prompt.
enum GuardianTheme {
    static let glass = Color(red: 18 / 255, green: 26 / 255, blue: 24 / 255).opacity(0.55)
    static let glassBorder = Color.white.opacity(0.09)
    static let glassHighlight = Color.white.opacity(0.14)
    static let accent = Color(red: 0x3E / 255, green: 0xE0 / 255, blue: 0xA1 / 255)
    static let accentInk = Color(red: 0x04 / 255, green: 0x14 / 255, blue: 0x0D / 255)
    static let silent = Color(red: 0xF5 / 255, green: 0xB1 / 255, blue: 0x3D / 255)  // amber = attention
    static let silentDim = Color(red: 0xF5 / 255, green: 0xB1 / 255, blue: 0x3D / 255).opacity(0.14)
    static let textPrimary = Color(red: 0xED / 255, green: 0xF4 / 255, blue: 0xF1 / 255).opacity(0.96)
    static let textSecondary = Color(red: 0xED / 255, green: 0xF4 / 255, blue: 0xF1 / 255).opacity(0.60)
    static let accentGradient = LinearGradient(
        colors: [accent, Color(red: 0x4F / 255, green: 0xE4 / 255, blue: 0xAB / 255)],
        startPoint: .top, endPoint: .bottom)

    enum Radius {
        static let button: CGFloat = 11
        static let toast: CGFloat = 14
    }
}

/// Frosted-glass backdrop (matches the toast's GlassBackground).
struct GuardianGlassBackground: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .hudWindow
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }
    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {}
}
