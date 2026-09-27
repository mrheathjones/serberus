import SwiftUI
import AppKit
import ImageIO
import UniformTypeIdentifiers
import SerberusUI

@MainActor
func sheet() -> some View {
    let glyphs = SerberusGlyph.allCases
    return ZStack {
        Color(red: 0.03, green: 0.035, blue: 0.04)
        VStack(spacing: 26) {
            HStack(spacing: 18) {
                ForEach(glyphs, id: \.self) { g in
                    VStack(spacing: 6) {
                        g.shape
                            .frame(width: 34, height: 34)
                            .foregroundStyle(Color(red: 0.17, green: 0.75, blue: 0.61))
                        Text(g.rawValue)
                            .font(.system(size: 8))
                            .foregroundStyle(Color(white: 0.5))
                    }
                }
            }
            HStack(spacing: 34) {
                SerberusMark(tone: .emerald, glow: true).frame(width: 60, height: 60)
                SerberusMark(tone: .amber).frame(width: 42, height: 42)
                SerberusMark(tone: .critical).frame(width: 42, height: 42)
                MenubarMark(tone: .critical, slashed: true).frame(width: 42, height: 42)
                SerberusMarkRing().frame(width: 92, height: 92)
            }
        }
        .padding(34)
    }
    .frame(width: 820, height: 280)
}

func savePNG(_ img: CGImage, _ path: String) {
    let url = URL(fileURLWithPath: path)
    let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, img, nil)
    CGImageDestinationFinalize(dest)
}

MainActor.assumeIsolated {
    _ = NSApplication.shared
    let renderer = ImageRenderer(content: sheet())
    renderer.scale = 2
    guard let img = renderer.cgImage else {
        FileHandle.standardError.write(Data("render failed\n".utf8)); exit(1)
    }
    savePNG(img, "/tmp/serberus_icons/glyphs.png")
    print("wrote /tmp/serberus_icons/glyphs.png")
}
