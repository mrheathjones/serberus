import AppKit

/// Renders the **Serberus sigil** (three rising chevrons — the Commander app
/// icon's glyph, see ``SerberusSigilView``) as menu-bar status images for
/// Serberus Commander, the same way ``SentinelStatusIcon`` renders the
/// Sentinel sigil for the user's agent. Idle is a template image so macOS
/// tints it like a native status item; `attention` (uploads waiting for
/// review) is deliberately amber — the same "something needs you" hue the
/// Sentinel agent uses while a prompt waits — and `dimmed` (fleet not loaded
/// / Jamf unreachable) is a muted gray, like Sentinel's offline state.
public enum SerberusStatusIcon {

    /// Standard menu-bar glyph size in points (18pt canvas).
    public static let pointSize: CGFloat = 18

    /// Design colours (dark canonical) — shared with ``SentinelStatusIcon``.
    public static let amber = SentinelStatusIcon.amber
    public static let gray = SentinelStatusIcon.gray

    public enum Variant: Equatable {
        /// Monochrome template — follows the menu bar tint.
        case template
        /// Solid colour (amber = uploads waiting).
        case tinted(NSColor)
        /// Muted gray — fleet not loaded / Jamf unreachable.
        case dimmed
    }

    private static let templateImage = render(.template)
    private static let amberImage = render(.tinted(amber))
    private static let dimmedImage = render(.dimmed)

    /// Returns the cached image for a variant (tints other than amber render uncached).
    public static func image(_ variant: Variant) -> NSImage {
        switch variant {
        case .template: return templateImage
        case .tinted(let color) where color == amber: return amberImage
        case .tinted(let color): return render(.tinted(color))
        case .dimmed: return dimmedImage
        }
    }

    private static func render(_ variant: Variant) -> NSImage {
        let side = pointSize
        let image = NSImage(size: NSSize(width: side, height: side), flipped: true) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            draw(variant, in: rect, context: ctx)
            return true
        }
        image.isTemplate = (variant == .template)
        image.accessibilityDescription = "Serberus Commander"
        return image
    }

    private static func draw(_ variant: Variant, in rect: CGRect, context ctx: CGContext) {
        // The sigil's ink spans x 9…31 (22 units) and y 7…33 (26 units) of its
        // 40-unit box (handoff README: `M9 17 L20 7 L31 17` ×3 at pitch 8,
        // stroke 2.4 under 20px). Scale the INK, not the box, so the glyph
        // fills ~17pt of the 18pt canvas like the Sentinel status icon.
        let inkHeight: CGFloat = 26 + 2.4
        let scale = min(rect.width, rect.height) * (17.0 / 18.0) / inkHeight
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.midX + (x - 20) * scale, y: rect.midY + (y - 20) * scale)
        }
        let color: CGColor
        switch variant {
        case .template: color = .black  // template: only alpha matters
        case .tinted(let tint): color = tint.cgColor
        case .dimmed: color = gray.cgColor
        }
        ctx.setStrokeColor(color)
        ctx.setLineCap(.round)
        ctx.setLineJoin(.round)
        ctx.setLineWidth(2.4 * scale * 1.15)   // a hair heavier than the vector: 18pt raster legibility
        for (fromY, apexY) in [(CGFloat(17), CGFloat(7)), (25, 15), (33, 23)] {
            ctx.move(to: p(9, fromY))
            ctx.addLine(to: p(20, apexY))
            ctx.addLine(to: p(31, fromY))
            ctx.strokePath()
        }
    }
}
