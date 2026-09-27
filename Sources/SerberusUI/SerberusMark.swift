import SwiftUI

/// The Serberus triradiate mark — three beveled emerald chevron-blades in
/// 120° rotational symmetry. Drawn as resolution-independent vector art so it
/// renders crisp from a 16pt menu-bar glyph to a 1024px app icon.
///
/// The bare mark is the **Sentinel** identity; wrap it in ``SerberusMarkRing`` for
/// the **Commander** console identity (the segmented HUD control ring).
public struct SerberusMark: View {

    /// Color treatment. The mark is emerald by default; the amber/critical
    /// tones let the menu-bar glyph carry daemon state in the same shape.
    public enum Tone: Equatable, Sendable {
        case emerald, amber, critical

        /// Gradient for the brighter (upper-left) bevel face.
        var leftFace: [Color] {
            switch self {
            case .emerald:  [SerberusBrand.emeraldBright, SerberusBrand.emerald]
            case .amber:    [SerberusBrand.rgb(0xFFDF9E), SerberusBrand.amber]
            case .critical: [SerberusBrand.rgb(0xFF9AA6), SerberusBrand.critical]
            }
        }
        /// Gradient for the deeper (lower-right) bevel face.
        var rightFace: [Color] {
            switch self {
            case .emerald:  [SerberusBrand.emerald, SerberusBrand.emeraldDeep]
            case .amber:    [SerberusBrand.amber, SerberusBrand.amberDeep]
            case .critical: [SerberusBrand.critical, SerberusBrand.criticalDeep]
            }
        }
        var edge: Color {
            switch self {
            case .emerald:  SerberusBrand.emeraldBright
            case .amber:    SerberusBrand.rgb(0xFFE7B0)
            case .critical: SerberusBrand.rgb(0xFFC2C9)
            }
        }
        var glow: Color {
            switch self {
            case .emerald:  SerberusBrand.emerald
            case .amber:    SerberusBrand.amber
            case .critical: SerberusBrand.critical
            }
        }
    }

    var tone: Tone
    var glow: Bool

    public init(tone: Tone = .emerald, glow: Bool = false) {
        self.tone = tone
        self.glow = glow
    }

    public var body: some View {
        Canvas { ctx, size in
            Self.draw(into: &ctx, size: size, tone: tone, glow: glow)
        }
        .accessibilityHidden(true)
    }

    // Claw geometry (matches the brand render in `extras/design/icons/` and the
    // template menu-bar icon): hub, three arm tips, and the chevron echo.
    // Normalized units, origin = mark center, y-down.
    private static let hub = CGPoint(x: 0, y: -0.15)
    private static let tips = [
        CGPoint(x: 0, y: -0.82),      // up
        CGPoint(x: -0.68, y: 0.42),   // down-left
        CGPoint(x: 0.68, y: 0.42),    // down-right
    ]
    private static let chevron = (
        left: CGPoint(x: -0.72, y: 0.86),
        apex: CGPoint(x: 0, y: 0.42),
        right: CGPoint(x: 0.72, y: 0.86)
    )
    private static let armHalfWidth: CGFloat = 0.14
    /// Vertical half-thickness that keeps the chevron band's perpendicular
    /// width equal to the arms' (wing slope ≈ 31°, 0.14 / cos ≈ 0.165).
    private static let chevronHalfHeight: CGFloat = 0.165

    /// Renders the mark into an existing graphics context. Exposed so the
    /// menu-bar variant and the app-icon renderer can compose it.
    static func draw(into ctx: inout GraphicsContext, size: CGSize, tone: Tone, glow: Bool) {
        let r = min(size.width, size.height) * 0.5 * 0.92
        let center = CGPoint(x: size.width / 2, y: size.height / 2)
        func p(_ q: CGPoint) -> CGPoint { CGPoint(x: center.x + q.x * r, y: center.y + q.y * r) }

        // Beveled arm: the quad split lengthwise at its centerline; the half
        // whose outward normal faces the upper-left key light gets the bright
        // face, the other the deep face.
        func armFaces(to tip: CGPoint) -> (lit: Path, dark: Path, litEdge: Path) {
            let dx = tip.x - hub.x, dy = tip.y - hub.y
            let len = (dx * dx + dy * dy).squareRoot()
            var n = CGPoint(x: -dy / len, y: dx / len)
            if n.x * -0.7 + n.y * -0.7 < 0 { n = CGPoint(x: -n.x, y: -n.y) }
            let off = CGPoint(x: n.x * armHalfWidth, y: n.y * armHalfWidth)

            var lit = Path()
            lit.move(to: p(CGPoint(x: hub.x + off.x, y: hub.y + off.y)))
            lit.addLine(to: p(CGPoint(x: tip.x + off.x, y: tip.y + off.y)))
            lit.addLine(to: p(tip)); lit.addLine(to: p(hub)); lit.closeSubpath()

            var dark = Path()
            dark.move(to: p(hub)); dark.addLine(to: p(tip))
            dark.addLine(to: p(CGPoint(x: tip.x - off.x, y: tip.y - off.y)))
            dark.addLine(to: p(CGPoint(x: hub.x - off.x, y: hub.y - off.y)))
            dark.closeSubpath()

            var edge = Path()
            edge.move(to: p(CGPoint(x: hub.x + off.x, y: hub.y + off.y)))
            edge.addLine(to: p(CGPoint(x: tip.x + off.x, y: tip.y + off.y)))
            return (lit, dark, edge)
        }

        // Chevron echo band, mitred at the apex by the uniform vertical offset.
        func chevronWing(_ from: CGPoint, _ to: CGPoint) -> Path {
            let h = chevronHalfHeight
            var path = Path()
            path.move(to: p(CGPoint(x: from.x, y: from.y - h)))
            path.addLine(to: p(CGPoint(x: to.x, y: to.y - h)))
            path.addLine(to: p(CGPoint(x: to.x, y: to.y + h)))
            path.addLine(to: p(CGPoint(x: from.x, y: from.y + h)))
            path.closeSubpath()
            return path
        }

        func allShapes() -> Path {
            var all = Path()
            for tip in tips {
                let faces = armFaces(to: tip)
                all.addPath(faces.lit); all.addPath(faces.dark)
            }
            all.addPath(chevronWing(chevron.left, chevron.apex))
            all.addPath(chevronWing(chevron.apex, chevron.right))
            return all
        }

        if glow {
            ctx.drawLayer { layer in
                layer.addFilter(.blur(radius: r * 0.17))
                layer.fill(allShapes(), with: .color(tone.glow.opacity(0.55)))
            }
        }

        // Arms — draw the down arms first so the up arm caps the hub knot.
        for tip in [tips[1], tips[2], tips[0]] {
            let faces = armFaces(to: tip)
            ctx.fill(faces.lit, with: .linearGradient(
                Gradient(colors: tone.leftFace), startPoint: p(hub), endPoint: p(tip)))
            ctx.fill(faces.dark, with: .linearGradient(
                Gradient(colors: tone.rightFace), startPoint: p(hub), endPoint: p(tip)))
            ctx.stroke(faces.litEdge, with: .color(tone.edge),
                       style: StrokeStyle(lineWidth: r * 0.03, lineCap: .round))
        }

        // Chevron echo: bright left wing, deep right wing, lit top edge.
        ctx.fill(chevronWing(chevron.left, chevron.apex), with: .linearGradient(
            Gradient(colors: tone.leftFace), startPoint: p(chevron.apex), endPoint: p(chevron.left)))
        ctx.fill(chevronWing(chevron.apex, chevron.right), with: .linearGradient(
            Gradient(colors: tone.rightFace), startPoint: p(chevron.apex), endPoint: p(chevron.right)))
        var chevronEdge = Path()
        chevronEdge.move(to: p(CGPoint(x: chevron.left.x, y: chevron.left.y - chevronHalfHeight)))
        chevronEdge.addLine(to: p(CGPoint(x: chevron.apex.x, y: chevron.apex.y - chevronHalfHeight)))
        chevronEdge.addLine(to: p(CGPoint(x: chevron.right.x, y: chevron.right.y - chevronHalfHeight)))
        ctx.stroke(chevronEdge, with: .color(tone.edge),
                   style: StrokeStyle(lineWidth: r * 0.03, lineCap: .round, lineJoin: .round))
    }
}

/// The Commander-console identity: the mark inside a segmented HUD control ring with
/// four glowing nodes. The node color can carry overall fleet/console state.
public struct SerberusMarkRing: View {
    var nodeTone: Color
    var glowMark: Bool

    public init(nodeTone: Color = SerberusBrand.nodeGlow, glowMark: Bool = true) {
        self.nodeTone = nodeTone
        self.glowMark = glowMark
    }

    public var body: some View {
        GeometryReader { geo in
            let s = min(geo.size.width, geo.size.height)
            ZStack {
                Canvas { ctx, size in Self.drawRing(into: &ctx, size: size, nodeTone: nodeTone) }
                SerberusMark(tone: .emerald, glow: glowMark)
                    .frame(width: s * 0.52, height: s * 0.52)
            }
            .frame(width: s, height: s)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .accessibilityHidden(true)
    }

    static func drawRing(into ctx: inout GraphicsContext, size: CGSize, nodeTone: Color) {
        let s = min(size.width, size.height)
        let center = CGPoint(x: size.width / 2, y: size.height / 2)

        func arcBand(radius: CGFloat, half: Double, width: CGFloat, color: Color) {
            for k in 0..<4 {
                let mid = Double(k) * 90.0
                var path = Path()
                path.addArc(center: center, radius: radius,
                            startAngle: .degrees(mid - half), endAngle: .degrees(mid + half),
                            clockwise: false)
                ctx.stroke(path, with: .color(color), style: StrokeStyle(lineWidth: width, lineCap: .round))
            }
        }

        arcBand(radius: s * 0.45, half: 36, width: s * 0.028, color: SerberusBrand.emeraldShadow)
        arcBand(radius: s * 0.37, half: 32, width: s * 0.045, color: SerberusBrand.emerald.opacity(0.92))

        // Four nodes on the diagonals.
        let nr = s * 0.42
        for k in 0..<4 {
            let a = (45.0 + Double(k) * 90.0) * .pi / 180
            let c = CGPoint(x: center.x + nr * cos(a), y: center.y + nr * sin(a))
            let halo = s * 0.07, dotR = s * 0.032
            ctx.fill(Path(ellipseIn: CGRect(x: c.x - halo, y: c.y - halo, width: halo * 2, height: halo * 2)),
                     with: .color(nodeTone.opacity(0.22)))
            ctx.fill(Path(ellipseIn: CGRect(x: c.x - dotR, y: c.y - dotR, width: dotR * 2, height: dotR * 2)),
                     with: .color(nodeTone))
        }
    }
}

/// The menu-bar presentation of the mark: the bare triradiate tinted by daemon
/// state, with a slash overlay for the kill-switch state.
public struct MenubarMark: View {
    var tone: SerberusMark.Tone
    var slashed: Bool

    public init(tone: SerberusMark.Tone = .emerald, slashed: Bool = false) {
        self.tone = tone
        self.slashed = slashed
    }

    public var body: some View {
        Canvas { ctx, size in
            SerberusMark.draw(into: &ctx, size: size, tone: tone, glow: false)
            if slashed {
                let s = min(size.width, size.height)
                var slash = Path()
                slash.move(to: CGPoint(x: size.width * 0.16, y: size.height * 0.16))
                slash.addLine(to: CGPoint(x: size.width * 0.84, y: size.height * 0.84))
                ctx.stroke(slash, with: .color(SerberusBrand.graphite),
                           style: StrokeStyle(lineWidth: s * 0.17, lineCap: .round))
                ctx.stroke(slash, with: .color(tone.edge),
                           style: StrokeStyle(lineWidth: s * 0.08, lineCap: .round))
            }
        }
        .accessibilityHidden(true)
    }
}
