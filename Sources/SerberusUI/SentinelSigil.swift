import AppKit
import SwiftUI

// MARK: - Geometry

/// The Sentinel sigil geometry from the design handoff, in a normalized 40×40
/// box: concentric ring(s) + an upward chevron + a center dot. The menu bar
/// uses the compact single-ring variant; the popover header and prompt use the
/// full two-ring glyph. One geometry source so every rendering agrees.
enum SentinelSigilGeometry {
    /// Compact status-item variant (design: `circle r9 sw2.4` +
    /// `M14 23 L20 16 L26 23 sw3.2` in a 40 box).
    static let compactRing = (center: CGPoint(x: 20, y: 21), radius: CGFloat(9), width: CGFloat(2.4))
    static let compactChevron = (from: CGPoint(x: 14, y: 23), apex: CGPoint(x: 20, y: 16),
                                 to: CGPoint(x: 26, y: 23), width: CGFloat(3.2))

    /// Full glyph variant (design: outer `r13.5 sw1.5 op0.4`, inner
    /// `r8.5 sw1.6 op0.68`, chevron `M13.5 23 L20 16 L26.5 23 sw2.8`,
    /// center dot `r1.7`).
    static let outerRing = (center: CGPoint(x: 20, y: 21), radius: CGFloat(13.5), width: CGFloat(1.5))
    static let innerRing = (center: CGPoint(x: 20, y: 21), radius: CGFloat(8.5), width: CGFloat(1.6))
    static let fullChevron = (from: CGPoint(x: 13.5, y: 23), apex: CGPoint(x: 20, y: 16),
                              to: CGPoint(x: 26.5, y: 23), width: CGFloat(2.8))
    static let dotRadius: CGFloat = 1.7
}

// MARK: - Menu bar status images

/// Renders the Sentinel sigil as menu-bar status images (design: menu bar
/// icon states). Idle and kill switch are template images so macOS tints them
/// like a native status item; the attention states are colored deliberately —
/// amber while a prompt waits, red after a blocked action, dashed gray when
/// running on cached policy.
public enum SentinelStatusIcon {

    /// Standard menu-bar glyph size in points (18pt canvas, ~17pt of content).
    public static let pointSize: CGFloat = 18

    /// Design decision colors (dark canonical). The menu bar is the one place
    /// these are baked into raster output, so they live here with the renderer.
    public static let amber = NSColor(srgbRed: 0xF5 / 255, green: 0xB1 / 255, blue: 0x3D / 255, alpha: 1)
    public static let red = NSColor(srgbRed: 0xFF / 255, green: 0x66 / 255, blue: 0x72 / 255, alpha: 1)
    public static let gray = NSColor(white: 0.62, alpha: 1)
    /// Active timed-grant indicator — the Serberus accent green. Signals that an
    /// approved elevation is currently in effect (`#3EE0A1`).
    public static let green = NSColor(srgbRed: 0x3E / 255, green: 0xE0 / 255, blue: 0xA1 / 255, alpha: 1)

    /// One rendering of the sigil for the status item.
    public enum Variant: Equatable {
        /// Monochrome template — follows the menu bar tint.
        case template
        /// Template with a kill-switch slash.
        case slashed
        /// Solid color (amber = prompt waiting/pending, red = blocked).
        case tinted(NSColor)
        /// Dashed ring in gray — offline, cached policy.
        case dashed
    }

    // Cached variants: NSImage drawing handlers re-render per backing scale,
    // so one instance serves 1x/2x/3x crisply.
    private static let templateImage = render(.template)
    private static let slashedImage = render(.slashed)
    private static let amberImage = render(.tinted(amber))
    private static let redImage = render(.tinted(red))
    private static let greenImage = render(.tinted(green))
    private static let dashedImage = render(.dashed)

    /// Returns the cached image for a variant (tints other than the two
    /// design states render uncached).
    public static func image(_ variant: Variant) -> NSImage {
        switch variant {
        case .template: return templateImage
        case .slashed: return slashedImage
        case .tinted(let color) where color == amber: return amberImage
        case .tinted(let color) where color == red: return redImage
        case .tinted(let color) where color == green: return greenImage
        case .tinted(let color): return render(.tinted(color))
        case .dashed: return dashedImage
        }
    }

    private static func render(_ variant: Variant) -> NSImage {
        let side = pointSize
        let image = NSImage(size: NSSize(width: side, height: side), flipped: true) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            draw(variant, in: rect, context: ctx)
            return true
        }
        switch variant {
        case .template, .slashed: image.isTemplate = true
        case .tinted, .dashed: image.isTemplate = false
        }
        image.accessibilityDescription = "Serberus Sentinel"
        return image
    }

    private static func draw(_ variant: Variant, in rect: CGRect, context ctx: CGContext) {
        // The compact sigil's INK spans ~20.4 units of the 40-unit design box
        // (ring Ø18 + stroke, chevron tucked inside): scaling the box itself
        // into the canvas would render an ~8pt glyph in an 18pt status item.
        // Scale the ink instead so the sigil fills ~17pt of the 18pt canvas
        // (design: "the Sentinel sigil … at 17×17 in an 18pt template image").
        // Ink = ring Ø18 + 2.4 stroke = 20.4 units; 20.4 × (18 / 21.5) ≈ 17pt.
        let scale = min(rect.width, rect.height) / 21.5
        func p(_ point: CGPoint) -> CGPoint {
            // Ink bounding-box center in the 40-box: (20, 21) — the ring center.
            CGPoint(x: rect.midX + (point.x - 20) * scale,
                    y: rect.midY + (point.y - 21) * scale)
        }

        let color: CGColor
        switch variant {
        case .template, .slashed: color = .black  // template: only alpha matters
        case .tinted(let tint): color = tint.cgColor
        case .dashed: color = gray.cgColor
        }
        ctx.setStrokeColor(color)
        ctx.setLineCap(.round)
        ctx.setLineJoin(.round)

        // Ring — dashed in the offline variant (design: stroke-dash 3 3).
        let ring = SentinelSigilGeometry.compactRing
        ctx.setLineWidth(ring.width * scale)
        if case .dashed = variant {
            ctx.setLineDash(phase: 0, lengths: [3 * scale, 3 * scale])
        }
        ctx.strokeEllipse(in: CGRect(
            x: p(ring.center).x - ring.radius * scale,
            y: p(ring.center).y - ring.radius * scale,
            width: ring.radius * 2 * scale,
            height: ring.radius * 2 * scale
        ))
        ctx.setLineDash(phase: 0, lengths: [])

        // Chevron.
        let chevron = SentinelSigilGeometry.compactChevron
        ctx.setLineWidth(chevron.width * scale)
        ctx.move(to: p(chevron.from))
        ctx.addLine(to: p(chevron.apex))
        ctx.addLine(to: p(chevron.to))
        ctx.strokePath()

        if case .slashed = variant {
            // Slash with an eraser halo so it separates from the sigil in any
            // tint (same treatment as the previous mark).
            let s = min(rect.width, rect.height)
            let start = CGPoint(x: rect.minX + s * 0.14, y: rect.minY + s * 0.14)
            let end = CGPoint(x: rect.minX + s * 0.86, y: rect.minY + s * 0.86)
            ctx.setBlendMode(.clear)
            ctx.setLineWidth(s * 0.22)
            ctx.move(to: start); ctx.addLine(to: end)
            ctx.strokePath()
            ctx.setBlendMode(.normal)
            ctx.setStrokeColor(color)
            ctx.setLineWidth(s * 0.09)
            ctx.move(to: start); ctx.addLine(to: end)
            ctx.strokePath()
        }
    }
}

// MARK: - SwiftUI vector views

/// The full Sentinel glyph (two rings + chevron + center dot) as a
/// tint-following vector view — the popover header's app-icon chip and any
/// other in-app use. Colors with the current `foregroundStyle`.
public struct SentinelSigilView: View {
    public init() {}

    public var body: some View {
        Canvas { ctx, size in
            let scale = min(size.width, size.height) / 40
            func p(_ point: CGPoint) -> CGPoint {
                CGPoint(x: size.width / 2 + (point.x - 20) * scale,
                        y: size.height / 2 + (point.y - 20.5) * scale)
            }
            func ring(_ spec: (center: CGPoint, radius: CGFloat, width: CGFloat), opacity: Double) {
                let rect = CGRect(
                    x: p(spec.center).x - spec.radius * scale,
                    y: p(spec.center).y - spec.radius * scale,
                    width: spec.radius * 2 * scale,
                    height: spec.radius * 2 * scale
                )
                ctx.opacity = opacity
                ctx.stroke(Path(ellipseIn: rect), with: .style(.foreground),
                           style: StrokeStyle(lineWidth: spec.width * scale, lineCap: .round))
            }
            ring(SentinelSigilGeometry.outerRing, opacity: 0.4)
            ring(SentinelSigilGeometry.innerRing, opacity: 0.68)
            ctx.opacity = 1
            let chevron = SentinelSigilGeometry.fullChevron
            var path = Path()
            path.move(to: p(chevron.from))
            path.addLine(to: p(chevron.apex))
            path.addLine(to: p(chevron.to))
            ctx.stroke(path, with: .style(.foreground),
                       style: StrokeStyle(lineWidth: chevron.width * scale, lineCap: .round, lineJoin: .round))
            let dot = SentinelSigilGeometry.dotRadius * scale
            let center = p(CGPoint(x: 20, y: 21))
            ctx.fill(Path(ellipseIn: CGRect(x: center.x - dot, y: center.y - dot,
                                            width: dot * 2, height: dot * 2)),
                     with: .style(.foreground))
        }
        .accessibilityHidden(true)
    }
}

/// The Serberus provenance chevrons (design: the two stacked chevrons in the
/// prompt's "Recorded by Serberus Sentinel" line). Strokes with the current
/// `foregroundStyle`.
public struct SerberusChevronsView: View {
    public init() {}

    public var body: some View {
        Canvas { ctx, size in
            let scale = min(size.width, size.height) / 40
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                CGPoint(x: size.width / 2 + (x - 20) * scale,
                        y: size.height / 2 + (y - 18.5) * scale)
            }
            for (fromY, apexY) in [(CGFloat(19), CGFloat(9)), (28, 18)] {
                var path = Path()
                path.move(to: p(9, fromY))
                path.addLine(to: p(20, apexY))
                path.addLine(to: p(31, fromY))
                ctx.stroke(path, with: .style(.foreground),
                           style: StrokeStyle(lineWidth: 3.4 * scale, lineCap: .round, lineJoin: .round))
            }
        }
        .accessibilityHidden(true)
    }
}

/// The **Serberus sigil** — three stacked chevrons, rising — exactly the
/// handoff geometry (`extras/design/icons/serberus-sigil/README.md`):
/// in a 40×40 box `M9 17 L20 7 L31 17` / `M9 25 L20 15 L31 25` /
/// `M9 33 L20 23 L31 33`, round caps + joins, stroke 3.4 (2.4 under 20px,
/// 4.4 over 200px). One geometry at every size; only the stroke weight
/// changes. This is the Commander app icon's glyph and Commander's in-app
/// brand mark; it strokes with the current `foregroundStyle` (accent
/// `#3ee0a1` in dark UI, `#4fe4ab` on the icon tile).
public struct SerberusSigilView: View {
    public init() {}

    public var body: some View {
        Canvas { ctx, size in
            let side = min(size.width, size.height)
            let scale = side / 40
            // The geometry is already centred on (20, 20) in its box.
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                CGPoint(x: size.width / 2 + (x - 20) * scale,
                        y: size.height / 2 + (y - 20) * scale)
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
