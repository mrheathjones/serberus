import AppKit

/// Renders the Serberus mark as a crisp **template** menu-bar image.
///
/// Template images are alpha masks: macOS tints them to match the menu bar
/// (black in light mode, white in dark mode, dimmed when the session is
/// inactive), which is what makes an icon read as native up there. The old
/// full-color raster `BrandMark` PNG could not do any of that.
///
/// The silhouette follows the brand render (`extras/design/icons/`): a triradiate
/// claw — three arms for the three heads of Cerberus — with the detached
/// chevron echo under the lower arms. Drawn as thick rounded strokes so it
/// stays legible at 18pt where filled blade shapes turn to mush.
///
/// State is carried two ways:
/// - `slashed` knocks a slash through the mark (kill switch), staying template.
/// - `badgeCutout` erases a notch at the top-trailing corner (the mark's open
///   quadrant) so the caller can overlay a small *colored* status dot with
///   native-looking breathing room (pending = amber, degraded = red,
///   offline = gray). Healthy needs no badge at all.
public enum SerberusMenubarIcon {

    /// Standard menu-bar glyph size in points. The status item gives ~22pt of
    /// height; 18pt of content is the conventional template-icon size.
    public static let pointSize: CGFloat = 18

    /// Diameter (in points) of the badge dot that fits the cutout notch.
    public static let badgeDiameter: CGFloat = 6.5

    // Cached variants — NSImage drawing handlers re-render per backing scale,
    // so one instance serves 1x/2x/3x crisply.
    private static let plain = render(slashed: false, badgeCutout: false)
    private static let badged = render(slashed: false, badgeCutout: true)
    private static let slashed = render(slashed: true, badgeCutout: false)

    /// Returns the cached template image for a menu-bar state.
    public static func image(slashed: Bool = false, badgeCutout: Bool = false) -> NSImage {
        if slashed { return Self.slashed }
        return badgeCutout ? badged : plain
    }

    private static func render(slashed: Bool, badgeCutout: Bool) -> NSImage {
        let side = pointSize
        let image = NSImage(size: NSSize(width: side, height: side), flipped: true) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            draw(in: rect, context: ctx, slashed: slashed, badgeCutout: badgeCutout)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Serberus"
        return image
    }

    private static func draw(in rect: CGRect, context ctx: CGContext, slashed: Bool, badgeCutout: Bool) {
        let s = min(rect.width, rect.height)
        let r = s * 0.5 * 0.98
        let center = CGPoint(x: rect.midX, y: rect.midY)
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: center.x + x * r, y: center.y + y * r)
        }

        ctx.setStrokeColor(.black)  // template: only alpha matters
        ctx.setLineCap(.round)
        ctx.setLineJoin(.round)

        // Three arms radiating from the hub — the triradiate claw.
        let hub = (x: CGFloat(0), y: CGFloat(-0.15))
        ctx.setLineWidth(r * 0.26)
        for tip in [(CGFloat(0), CGFloat(-0.82)), (-0.68, 0.42), (0.68, 0.42)] {
            ctx.move(to: p(hub.x, hub.y))
            ctx.addLine(to: p(tip.0, tip.1))
            ctx.strokePath()
        }

        // Detached chevron echo nested under the lower arms.
        ctx.setLineWidth(r * 0.22)
        ctx.move(to: p(-0.72, 0.86))
        ctx.addLine(to: p(0, 0.42))
        ctx.addLine(to: p(0.72, 0.86))
        ctx.strokePath()

        if badgeCutout {
            // Erase a notch slightly larger than the badge dot so the colored
            // overlay sits in clear space instead of on top of the silhouette.
            // Top-trailing: the open quadrant between the up and right arms.
            let notch = (badgeDiameter + 2.5) / 2
            let badgeCenter = badgeCenter(in: rect)
            ctx.setBlendMode(.clear)
            ctx.fillEllipse(in: CGRect(x: badgeCenter.x - notch, y: badgeCenter.y - notch,
                                       width: notch * 2, height: notch * 2))
            ctx.setBlendMode(.normal)
        }

        if slashed {
            // Slash with an eraser halo so it separates from the mark in any tint.
            let start = CGPoint(x: rect.minX + s * 0.14, y: rect.minY + s * 0.14)
            let end = CGPoint(x: rect.minX + s * 0.86, y: rect.minY + s * 0.86)
            ctx.setBlendMode(.clear)
            ctx.setLineWidth(s * 0.22)
            ctx.move(to: start); ctx.addLine(to: end)
            ctx.strokePath()
            ctx.setBlendMode(.normal)
            ctx.setStrokeColor(.black)
            ctx.setLineWidth(s * 0.09)
            ctx.move(to: start); ctx.addLine(to: end)
            ctx.strokePath()
        }
    }

    /// Center (in the icon's coordinate space) of the badge dot / cutout notch —
    /// the top-trailing corner, where the mark leaves open space.
    public static func badgeCenter(in rect: CGRect) -> CGPoint {
        let inset = badgeDiameter / 2 + 0.5
        return CGPoint(x: rect.maxX - inset, y: rect.minY + inset)
    }
}
