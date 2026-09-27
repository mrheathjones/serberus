import SwiftUI

/// The Serberus feature-glyph set: custom vector icons drawn in the same
/// angular chevron + HUD-ring language as the brand mark, replacing generic SF
/// Symbols across the navigation surfaces.
///
/// Each glyph is a `Shape` (``SerberusGlyphShape``) so it fills with the
/// surrounding `foregroundStyle` — sidebar rows tint it exactly like a native
/// template symbol would. `fallbackSymbol` is the closest SF Symbol, kept for
/// any context that needs a system image.
public enum SerberusGlyph: String, CaseIterable, Sendable {
    case dashboard
    case policies
    case ruleLibrary
    case policyBuilder
    case definitions
    case decisionSimulator
    case fleetObserver
    case settings

    public var fallbackSymbol: String {
        switch self {
        case .dashboard:         "gauge.with.dots.needle.50percent"
        case .policies:          "square.stack.3d.up"
        case .ruleLibrary:       "list.bullet.rectangle"
        case .policyBuilder:     "slider.horizontal.3"
        case .definitions:       "curlybraces"
        case .decisionSimulator: "play.circle"
        case .fleetObserver:     "macwindow.on.rectangle"
        case .settings:          "gearshape"
        }
    }

    /// A tint-following vector glyph view. Fills with the current foreground style.
    public var shape: SerberusGlyphShape { SerberusGlyphShape(glyph: self) }
}

/// Resolution-independent vector shape for a ``SerberusGlyph``. Returns filled
/// outlines (line work is converted to stroked outlines) so a single
/// `foregroundStyle` colors the whole glyph.
public struct SerberusGlyphShape: Shape {
    public var glyph: SerberusGlyph
    public init(glyph: SerberusGlyph) { self.glyph = glyph }

    public func path(in rect: CGRect) -> Path {
        let s = min(rect.width, rect.height)
        let ox = rect.midX - s / 2, oy = rect.midY - s / 2
        func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: ox + x * s, y: oy + y * s) }
        let lineWidth = s * 0.085

        var line = Path()   // stroked centerlines
        var solid = Path()  // filled shapes (dots, play head)

        func dot(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat) {
            let c = pt(x, y); let rr = r * s
            solid.addEllipse(in: CGRect(x: c.x - rr, y: c.y - rr, width: rr * 2, height: rr * 2))
        }
        func ring(_ cx: CGFloat, _ cy: CGFloat, _ r: CGFloat) {
            let c = pt(cx, cy); let rr = r * s
            line.addEllipse(in: CGRect(x: c.x - rr, y: c.y - rr, width: rr * 2, height: rr * 2))
        }
        func poly(_ points: [(CGFloat, CGFloat)], close: Bool = false) {
            guard let first = points.first else { return }
            line.move(to: pt(first.0, first.1))
            for p in points.dropFirst() { line.addLine(to: pt(p.0, p.1)) }
            if close { line.closeSubpath() }
        }

        switch glyph {
        case .dashboard:
            // HUD dial: ring + needle + hub
            ring(0.5, 0.5, 0.34)
            poly([(0.5, 0.5), (0.68, 0.32)])
            dot(0.5, 0.5, 0.055)

        case .policies:
            // stacked policy cards
            let back = CGRect(x: pt(0.34, 0.22).x, y: pt(0.34, 0.22).y, width: 0.40 * s, height: 0.30 * s)
            let front = CGRect(x: pt(0.22, 0.42).x, y: pt(0.22, 0.42).y, width: 0.40 * s, height: 0.30 * s)
            line.addRoundedRect(in: back, cornerSize: CGSize(width: s * 0.05, height: s * 0.05))
            line.addRoundedRect(in: front, cornerSize: CGSize(width: s * 0.05, height: s * 0.05))

        case .ruleLibrary:
            // stacked rule rows, each with a leading marker dot
            dot(0.28, 0.32, 0.045); poly([(0.42, 0.32), (0.77, 0.32)])
            dot(0.28, 0.50, 0.045); poly([(0.42, 0.50), (0.77, 0.50)])
            dot(0.28, 0.68, 0.045); poly([(0.42, 0.68), (0.69, 0.68)])

        case .policyBuilder:
            // chevron blade authoring rule lines
            poly([(0.24, 0.30), (0.37, 0.45), (0.24, 0.60)])
            poly([(0.47, 0.41), (0.77, 0.41)])
            poly([(0.47, 0.57), (0.69, 0.57)])

        case .definitions:
            // atomic matcher token: angle brackets framing a single matched value
            poly([(0.36, 0.30), (0.20, 0.50), (0.36, 0.70)])
            poly([(0.64, 0.30), (0.80, 0.50), (0.64, 0.70)])
            dot(0.5, 0.5, 0.06)

        case .decisionSimulator:
            ring(0.5, 0.5, 0.34)
            solid.move(to: pt(0.43, 0.37))
            solid.addLine(to: pt(0.43, 0.63))
            solid.addLine(to: pt(0.65, 0.50))
            solid.closeSubpath()

        case .fleetObserver:
            // central console with three orbiting endpoint nodes
            ring(0.5, 0.5, 0.16)
            poly([(0.5, 0.34), (0.5, 0.21)])
            poly([(0.38, 0.59), (0.28, 0.70)])
            poly([(0.62, 0.59), (0.72, 0.70)])
            dot(0.5, 0.17, 0.058)
            dot(0.25, 0.74, 0.058)
            dot(0.75, 0.74, 0.058)

        case .settings:
            // gear-ring: ring + radial teeth + hub
            ring(0.5, 0.5, 0.20)
            dot(0.5, 0.5, 0.06)
            for k in 0..<6 {
                let a = Double(k) * 60.0 * .pi / 180
                let inner = (0.5 + 0.20 * CGFloat(cos(a)), 0.5 + 0.20 * CGFloat(sin(a)))
                let outer = (0.5 + 0.31 * CGFloat(cos(a)), 0.5 + 0.31 * CGFloat(sin(a)))
                poly([inner, outer])
            }
        }

        var result = line.strokedPath(StrokeStyle(lineWidth: lineWidth, lineCap: .round, lineJoin: .round))
        result.addPath(solid)
        return result
    }
}
