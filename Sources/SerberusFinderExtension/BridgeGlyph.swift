import AppKit

/// The image shown next to the Finder menu items. Per design, this is the actual
/// **Serberus Sentinel app icon** (the colored artwork users recognize), bundled
/// into the extension's own asset catalog as `SentinelAppIcon` and loaded from
/// the appex bundle (sandbox-safe: it reads only its own resources — no
/// NSWorkspace.icon(forFile:) call and no dependency on SerberusUI).
///
/// If the asset ever fails to load, it falls back to the monochrome Sentinel
/// sigil drawn inline, so a menu item is never icon-less.
enum BridgeGlyph {
    /// A menu image at `pointSize` pt — the colored app icon, sized down crisply
    /// from the 128/256px renditions in the asset catalog. NOT a template, so the
    /// icon keeps its colors (it is not tinted to the row like a symbol).
    static func image(pointSize: CGFloat) -> NSImage {
        if let named = NSImage(named: "SentinelAppIcon"),
           let icon = named.copy() as? NSImage {
            icon.size = NSSize(width: pointSize, height: pointSize)
            icon.isTemplate = false
            icon.accessibilityDescription = "Serberus Sentinel"
            return icon
        }
        return sigil(pointSize: pointSize)
    }

    /// Fallback: the compact Sentinel sigil (ring + upward chevron) as a template
    /// image, mirroring SerberusUI.SentinelStatusIcon's geometry.
    private static func sigil(pointSize: CGFloat) -> NSImage {
        let image = NSImage(size: NSSize(width: pointSize, height: pointSize), flipped: true) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            let scale = min(rect.width, rect.height) / 21.5
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                CGPoint(x: rect.midX + (x - 20) * scale, y: rect.midY + (y - 21) * scale)
            }
            ctx.setStrokeColor(.black)
            ctx.setLineCap(.round); ctx.setLineJoin(.round)
            ctx.setLineWidth(2.4 * scale)
            let center = p(20, 21), radius = 9 * scale
            ctx.strokeEllipse(in: CGRect(x: center.x - radius, y: center.y - radius,
                                         width: radius * 2, height: radius * 2))
            ctx.setLineWidth(3.2 * scale)
            ctx.move(to: p(14, 23)); ctx.addLine(to: p(20, 16)); ctx.addLine(to: p(26, 23))
            ctx.strokePath()
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Serberus"
        return image
    }
}
