// icongen.swift — headless CoreGraphics renderer for the Serberus identity.
//
// Generates the macOS AppIcon raster sets for the Admin (mark + HUD ring) and
// Agent (bare mark) apps from the exact triradiate geometry used in SerberusUI,
// plus a contact sheet for visual review. Run with the Xcode toolchain:
//   DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift extras/icon-tools/icongen.swift
//
// Pure CoreGraphics/ImageIO — no SwiftUI, no window, no run loop.

import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

// MARK: - Palette

func cg(_ hex: UInt, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: a)
}
let emeraldBright = cg(0x4EF5C6), emeraldMid = cg(0x33D4AC), emerald = cg(0x2BBF9C)
let emeraldDeep = cg(0x1D8B73), emeraldShadow = cg(0x14705B)
let graphite = cg(0x0E1114), tileTop = cg(0x171B20), tileBot = cg(0x0C0E11)
let tileBorder = cg(0x2B343D), nodeGlow = cg(0x7CF7D8)
let rgbSpace = CGColorSpaceCreateDeviceRGB()

// MARK: - Context / IO

func makeContext(_ size: Int) -> CGContext {
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                        bytesPerRow: 0, space: rgbSpace,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.translateBy(x: 0, y: CGFloat(size))   // flip to y-down (screen space)
    ctx.scaleBy(x: 1, y: -1)
    ctx.setAllowsAntialiasing(true)
    ctx.interpolationQuality = .high
    return ctx
}

func savePNG(_ ctx: CGContext, _ path: String) {
    guard let img = ctx.makeImage() else { fatalError("makeImage failed") }
    let url = URL(fileURLWithPath: path)
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                             withIntermediateDirectories: true)
    let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, img, nil)
    CGImageDestinationFinalize(dest)
}

func vGrad(_ ctx: CGContext, _ colors: [CGColor], _ from: CGPoint, _ to: CGPoint) {
    let grad = CGGradient(colorsSpace: rgbSpace, colors: colors as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(grad, start: from, end: to, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
}

// MARK: - Triradiate mark (normalized, unit = radius, apex up)

let pA = CGPoint(x: 0.00, y: -1.00), pB = CGPoint(x: 0.46, y: -0.52)
let pC = CGPoint(x: 0.17, y: -0.18), pD = CGPoint(x: 0.00, y: -0.28)
let pE = CGPoint(x: -0.17, y: -0.18), pF = CGPoint(x: -0.46, y: -0.52)

func path(_ pts: [CGPoint], _ r: CGFloat) -> CGMutablePath {
    let p = CGMutablePath()
    p.move(to: CGPoint(x: pts[0].x * r, y: pts[0].y * r))
    for q in pts.dropFirst() { p.addLine(to: CGPoint(x: q.x * r, y: q.y * r)) }
    p.closeSubpath()
    return p
}

func drawMark(_ ctx: CGContext, center: CGPoint, r: CGFloat, glow: Bool) {
    if glow {
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: r * 0.30, color: emerald.copy(alpha: 0.85))
        for i in 0..<3 {
            ctx.saveGState()
            ctx.translateBy(x: center.x, y: center.y)
            ctx.rotate(by: CGFloat(i) * 2 * .pi / 3)
            ctx.addPath(path([pA, pB, pC, pD, pE, pF], r))
            ctx.setFillColor(emerald); ctx.fillPath()
            ctx.restoreGState()
        }
        ctx.restoreGState()
    }
    for i in 0..<3 {
        ctx.saveGState()
        ctx.translateBy(x: center.x, y: center.y)
        ctx.rotate(by: CGFloat(i) * 2 * .pi / 3)
        let apex = CGPoint(x: 0, y: -r), valley = CGPoint(x: 0, y: -0.28 * r)

        ctx.saveGState(); ctx.addPath(path([pA, pF, pE, pD], r)); ctx.clip()
        vGrad(ctx, [emeraldBright, emerald], apex, valley); ctx.restoreGState()

        ctx.saveGState(); ctx.addPath(path([pA, pB, pC, pD], r)); ctx.clip()
        vGrad(ctx, [emerald, emeraldDeep], apex, valley); ctx.restoreGState()

        let e = CGMutablePath()
        e.move(to: CGPoint(x: pA.x * r, y: pA.y * r))
        e.addLine(to: CGPoint(x: pF.x * r, y: pF.y * r))
        ctx.addPath(e); ctx.setStrokeColor(emeraldBright)
        ctx.setLineWidth(r * 0.035); ctx.setLineCap(.round); ctx.strokePath()
        ctx.restoreGState()
    }
    ctx.setFillColor(graphite)
    ctx.fillEllipse(in: CGRect(x: center.x - r * 0.17, y: center.y - r * 0.17, width: r * 0.34, height: r * 0.34))
    ctx.setFillColor(emeraldBright)
    ctx.fillEllipse(in: CGRect(x: center.x - r * 0.085, y: center.y - r * 0.085, width: r * 0.17, height: r * 0.17))
}

func drawRing(_ ctx: CGContext, center: CGPoint, s: CGFloat) {
    func band(_ radius: CGFloat, _ half: CGFloat, _ width: CGFloat, _ color: CGColor) {
        for k in 0..<4 {
            let mid = CGFloat(k) * .pi / 2
            let p = CGMutablePath()
            p.addArc(center: center, radius: radius, startAngle: mid - half, endAngle: mid + half, clockwise: false)
            ctx.addPath(p); ctx.setStrokeColor(color); ctx.setLineWidth(width); ctx.setLineCap(.round); ctx.strokePath()
        }
    }
    band(s * 0.45, 36 * .pi / 180, s * 0.026, emeraldShadow)
    band(s * 0.37, 32 * .pi / 180, s * 0.044, emerald)
    let nr = s * 0.42
    for k in 0..<4 {
        let a = (45 + CGFloat(k) * 90) * .pi / 180
        let c = CGPoint(x: center.x + nr * cos(a), y: center.y + nr * sin(a))
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: s * 0.045, color: nodeGlow.copy(alpha: 0.9))
        ctx.setFillColor(nodeGlow)
        ctx.fillEllipse(in: CGRect(x: c.x - s * 0.030, y: c.y - s * 0.030, width: s * 0.060, height: s * 0.060))
        ctx.restoreGState()
    }
}

func drawTile(_ ctx: CGContext, _ n: CGFloat) {
    let inset = n * 0.085
    let rect = CGRect(x: inset, y: inset, width: n - 2 * inset, height: n - 2 * inset)
    let radius = rect.width * 0.224
    let p = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)
    ctx.saveGState(); ctx.addPath(p); ctx.clip()
    vGrad(ctx, [tileTop, tileBot], CGPoint(x: 0, y: inset), CGPoint(x: 0, y: n - inset))
    ctx.restoreGState()
    ctx.addPath(p); ctx.setStrokeColor(tileBorder); ctx.setLineWidth(max(1, n * 0.004)); ctx.strokePath()
}

// MARK: - Compositions

func agentIcon(_ n: Int) -> CGContext {
    let ctx = makeContext(n); let f = CGFloat(n)
    drawTile(ctx, f)
    drawMark(ctx, center: CGPoint(x: f / 2, y: f / 2), r: f * 0.295, glow: true)
    return ctx
}

func adminIcon(_ n: Int) -> CGContext {
    let ctx = makeContext(n); let f = CGFloat(n)
    drawTile(ctx, f)
    let c = CGPoint(x: f / 2, y: f / 2)
    drawRing(ctx, center: c, s: f * 0.74)
    drawMark(ctx, center: c, r: f * 0.175, glow: true)
    return ctx
}

// MARK: - Asset catalog writers

let entries: [(name: String, px: Int, size: String, scale: String)] = [
    ("appicon-16",    16,  "16x16",   "1x"),
    ("appicon-16@2x", 32,  "16x16",   "2x"),
    ("appicon-32",    32,  "32x32",   "1x"),
    ("appicon-32@2x", 64,  "32x32",   "2x"),
    ("appicon-128",   128, "128x128", "1x"),
    ("appicon-128@2x",256, "128x128", "2x"),
    ("appicon-256",   256, "256x256", "1x"),
    ("appicon-256@2x",512, "256x256", "2x"),
    ("appicon-512",   512, "512x512", "1x"),
    ("appicon-512@2x",1024,"512x512", "2x"),
]

func contentsJSON() -> String {
    var imgs = [String]()
    for e in entries {
        imgs.append("""
            {
              "idiom" : "mac",
              "scale" : "\(e.scale)",
              "size" : "\(e.size)",
              "filename" : "\(e.name).png"
            }
        """)
    }
    return "{\n  \"images\" : [\n" + imgs.joined(separator: ",\n")
        + "\n  ],\n  \"info\" : {\n    \"author\" : \"serberus-icongen\",\n    \"version\" : 1\n  }\n}\n"
}

func writeIconSet(dir: String, render: (Int) -> CGContext) {
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    for e in entries { savePNG(render(e.px), "\(dir)/\(e.name).png") }
    try? contentsJSON().write(toFile: "\(dir)/Contents.json", atomically: true, encoding: .utf8)
}

// MARK: - Run

let root = FileManager.default.currentDirectoryPath
writeIconSet(dir: "\(root)/Sources/SerberusCommander/Assets.xcassets/AppIcon.appiconset", render: adminIcon)
writeIconSet(dir: "\(root)/Sources/SerberusSentinel/Assets.xcassets/AppIcon.appiconset", render: agentIcon)

// Contact sheet for review
do {
    let n = 1100, ctx = makeContext(n); let f = CGFloat(n)
    ctx.setFillColor(cg(0x07090B)); ctx.fill(CGRect(x: 0, y: 0, width: f, height: f))
    savePNG(agentIcon(420), "/tmp/serberus_icons/_agent.png")  // warm caches; ignore
    // top row: two app icons at 360
    func blit(_ src: CGContext, _ x: CGFloat, _ y: CGFloat) {
        if let im = src.makeImage() {
            ctx.saveGState(); ctx.translateBy(x: x, y: y + CGFloat(src.height))
            ctx.scaleBy(x: 1, y: -1)
            ctx.draw(im, in: CGRect(x: 0, y: 0, width: CGFloat(src.width), height: CGFloat(src.height)))
            ctx.restoreGState()
        }
    }
    blit(agentIcon(420), 90, 90)
    blit(adminIcon(420), 590, 90)
    // bottom row: bare marks at small scale on tiles
    for (i, scale) in [64, 32, 18].enumerated() {
        let s = scale
        let c = makeContext(s)
        c.setFillColor(cg(0x111316)); c.fill(CGRect(x: 0, y: 0, width: CGFloat(s), height: CGFloat(s)))
        drawMark(c, center: CGPoint(x: CGFloat(s) / 2, y: CGFloat(s) / 2), r: CGFloat(s) * 0.40, glow: false)
        blit(c, 120 + CGFloat(i) * 260, 640)
    }
    savePNG(ctx, "/tmp/serberus_icons/contact.png")
}

print("done: wrote admin + agent AppIcon sets and /tmp/serberus_icons/contact.png")
