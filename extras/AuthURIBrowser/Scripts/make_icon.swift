// Renders the Auth URI Browser app icon as a sibling of the Serberus icons:
// the handoff tile (superellipse, radial #12563f → #081c18) with the flat
// #4fe4ab three-chevron sigil, plus a key badge in the lower-right so it is
// distinguishable from Commander/Sentinel in the Dock. Writes an .iconset and
// builds Icon.icns next to Package.swift.
//
//   swift Scripts/make_icon.swift
import AppKit

let root = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
let iconset = root.appendingPathComponent("build/AuthURIBrowser.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

func srgb(_ hex: UInt, _ alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}

/// Superellipse (n = 5) path, the shape used by the shipped Serberus.iconset.
func superellipse(in rect: CGRect, n: CGFloat = 5) -> CGPath {
    let path = CGMutablePath()
    let a = rect.width / 2, b = rect.height / 2
    let cx = rect.midX, cy = rect.midY
    let steps = 360
    for i in 0...steps {
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
        let ct = cos(t), st = sin(t)
        let x = cx + a * (ct < 0 ? -1 : 1) * pow(abs(ct), 2 / n)
        let y = cy + b * (st < 0 ? -1 : 1) * pow(abs(st), 2 / n)
        if i == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
    }
    path.closeSubpath()
    return path
}

func render(pixels: Int) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: pixels, height: pixels)
    NSGraphicsContext.saveGraphicsState()
    let gctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = gctx
    let ctx = gctx.cgContext
    let s = CGFloat(pixels)

    // Apple icon grid: the tile fills ~80% of the canvas.
    let tileSide = s * 0.80
    let tile = CGRect(x: (s - tileSide) / 2, y: (s - tileSide) / 2, width: tileSide, height: tileSide)
    let shape = superellipse(in: tile)

    // Drop shadow under the tile.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.01), blur: s * 0.03, color: NSColor.black.withAlphaComponent(0.55).cgColor)
    ctx.addPath(shape)
    ctx.setFillColor(srgb(0x081C18).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    // Tile: radial gradient (130% at 30%/12% from top → in CG coords 30%/88%).
    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    let colors = [srgb(0x12563F).cgColor, srgb(0x081C18).cgColor] as CFArray
    let gradient = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: colors, locations: [0, 0.72])!
    let center = CGPoint(x: tile.minX + tile.width * 0.30, y: tile.minY + tile.height * 0.88)
    ctx.drawRadialGradient(gradient, startCenter: center, startRadius: 0, endCenter: center,
                           endRadius: tile.width * 1.3, options: [.drawsAfterEndLocation])
    // Faint specular rim at the top edge.
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.07).cgColor)
    ctx.setLineWidth(max(1, s * 0.004))
    ctx.addPath(shape)
    ctx.strokePath()
    ctx.restoreGState()

    // Sigil at the 72% optical box, nudged up-left to leave room for the badge.
    let box = tile.width * 0.72
    let origin = CGPoint(x: tile.midX - box / 2 - tile.width * 0.03, y: tile.midY - box / 2 + tile.height * 0.03)
    let scale = box / 40
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
        // Design geometry is y-down in a 40 box.
        CGPoint(x: origin.x + x * scale, y: origin.y + (40 - y) * scale)
    }
    ctx.saveGState()
    ctx.setStrokeColor(srgb(0x4FE4AB).cgColor)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.setLineWidth((box > 200 ? 4.4 : (box < 20 ? 2.4 : 3.4)) * scale)
    for (fromY, apexY) in [(CGFloat(17), CGFloat(7)), (25, 15), (33, 23)] {
        ctx.move(to: p(9, fromY))
        ctx.addLine(to: p(20, apexY))
        ctx.addLine(to: p(31, fromY))
        ctx.strokePath()
    }
    ctx.restoreGState()

    // Key badge: accent-gradient disc with an ink key, lower-right.
    let badgeD = tile.width * 0.30
    let badgeRect = CGRect(x: tile.maxX - badgeD - tile.width * 0.07, y: tile.minY + tile.height * 0.07, width: badgeD, height: badgeD)
    ctx.saveGState()
    ctx.setShadow(offset: .zero, blur: badgeD * 0.35, color: srgb(0x3EE0A1, 0.45).cgColor)
    ctx.addEllipse(in: badgeRect)
    ctx.setFillColor(srgb(0x3EE0A1).cgColor)
    ctx.fillPath()
    ctx.restoreGState()
    ctx.saveGState()
    ctx.addEllipse(in: badgeRect)
    ctx.clip()
    let badgeGradient = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
                                   colors: [srgb(0x58ECB2).cgColor, srgb(0x3EE0A1).cgColor] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(badgeGradient, start: CGPoint(x: badgeRect.minX, y: badgeRect.maxY),
                           end: CGPoint(x: badgeRect.maxX, y: badgeRect.minY), options: [])
    ctx.restoreGState()
    // Tile-coloured ring separates the badge from the sigil.
    ctx.setStrokeColor(srgb(0x081C18).cgColor)
    ctx.setLineWidth(badgeD * 0.075)
    ctx.addEllipse(in: badgeRect.insetBy(dx: -badgeD * 0.0375, dy: -badgeD * 0.0375))
    ctx.strokePath()

    if pixels >= 32 {
        let config = NSImage.SymbolConfiguration(pointSize: badgeD * 0.5, weight: .bold)
        if let key = NSImage(systemSymbolName: "key.fill", accessibilityDescription: nil)?
            .withSymbolConfiguration(config) {
            let tinted = NSImage(size: key.size, flipped: false) { rect in
                key.draw(in: rect)
                srgb(0x04140D).set()
                rect.fill(using: .sourceAtop)
                return true
            }
            let ks = tinted.size
            let fit = badgeD * 0.56 / max(ks.width, ks.height)
            let drawSize = NSSize(width: ks.width * fit, height: ks.height * fit)
            let at = NSRect(x: badgeRect.midX - drawSize.width / 2, y: badgeRect.midY - drawSize.height / 2,
                            width: drawSize.width, height: drawSize.height)
            tinted.draw(in: at, from: .zero, operation: .sourceOver, fraction: 1)
        }
    }

    NSGraphicsContext.restoreGraphicsState()
    return rep
}

let entries: [(String, Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
for (name, px) in entries {
    let rep = render(pixels: px)
    let data = rep.representation(using: .png, properties: [:])!
    try data.write(to: iconset.appendingPathComponent(name + ".png"))
}
// Preview for review.
try render(pixels: 512).representation(using: .png, properties: [:])!.write(to: root.appendingPathComponent("build/icon-preview.png"))

let task = Process()
task.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
task.arguments = ["-c", "icns", iconset.path, "-o", root.appendingPathComponent("Icon.icns").path]
try task.run()
task.waitUntilExit()
print(task.terminationStatus == 0 ? "wrote \(root.appendingPathComponent("Icon.icns").path)" : "iconutil failed")
exit(task.terminationStatus)
