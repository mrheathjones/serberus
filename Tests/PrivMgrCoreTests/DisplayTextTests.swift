import Foundation
import Testing
@testable import PrivMgrCore

@Suite("DisplayText.escapingInvisibles")
struct DisplayTextEscapingTests {
    private func escaped(_ text: String) -> String {
        DisplayText.escapingInvisibles(text)
    }

    @Test("bidi overrides, embeddings, isolates and marks show as escapes")
    func bidi() {
        // Rendered raw, this reads "IT-approved-evil.pkg".
        #expect(escaped("IT-approved-\u{202E}gkp.live\u{202C}") == #"IT-approved-\u{202E}gkp.live\u{202C}"#)
        #expect(escaped("a\u{202A}b\u{202B}c\u{202D}") == #"a\u{202A}b\u{202B}c\u{202D}"#)
        #expect(escaped("a\u{2066}b\u{2067}c\u{2068}d\u{2069}") == #"a\u{2066}b\u{2067}c\u{2068}d\u{2069}"#)
        #expect(escaped("\u{200E}x\u{200F}y\u{061C}") == #"\u{200E}x\u{200F}y\u{061C}"#)
    }

    @Test("zero-width characters show as escapes, so a path can't pass for another")
    func zeroWidth() {
        #expect(escaped("/etc/pass\u{200B}wd") == #"/etc/pass\u{200B}wd"#)
        #expect(escaped("a\u{200C}b\u{200D}c\u{2060}d\u{FEFF}e") == #"a\u{200C}b\u{200D}c\u{2060}d\u{FEFF}e"#)
    }

    @Test("newline, carriage return and tab use their short escapes")
    func lineBreaksAndTabs() {
        #expect(escaped("rm -rf /tmp/x\nreboot") == #"rm -rf /tmp/x\nreboot"#)
        #expect(escaped("a\r\nb\tc") == #"a\r\nb\tc"#)
    }

    @Test("other C0 controls, DEL and C1 controls show as four-digit escapes")
    func controls() {
        #expect(escaped("\u{0000}") == #"\u{0000}"#)
        #expect(escaped("\u{001B}[31mred") == #"\u{001B}[31mred"#)
        #expect(escaped("x\u{007F}y") == #"x\u{007F}y"#)
        #expect(escaped("\u{0085}\u{009B}") == #"\u{0085}\u{009B}"#)
    }

    @Test("spaces other than U+0020, and line and paragraph separators, show as escapes")
    func spaces() {
        #expect(escaped("a\u{00A0}b") == #"a\u{00A0}b"#)
        #expect(escaped("a\u{3000}b") == #"a\u{3000}b"#)
        #expect(escaped("\u{1680}\u{2000}\u{200A}\u{202F}\u{205F}") == #"\u{1680}\u{2000}\u{200A}\u{202F}\u{205F}"#)
        #expect(escaped("a\u{2028}b\u{2029}c") == #"a\u{2028}b\u{2029}c"#)
        #expect(escaped("a b") == "a b")
    }

    @Test("default-ignorable code points show as escapes, with more than four digits when needed")
    func defaultIgnorables() {
        #expect(escaped("pass\u{00AD}wd") == #"pass\u{00AD}wd"#)
        #expect(escaped("\u{3164}\u{FFA0}\u{115F}") == #"\u{3164}\u{FFA0}\u{115F}"#)
        #expect(escaped("x\u{FE0F}\u{034F}") == #"x\u{FE0F}\u{034F}"#)
        #expect(escaped("tag\u{E0041}\u{E007F}\u{E0100}") == #"tag\u{E0041}\u{E007F}\u{E0100}"#)
    }

    @Test("printable ASCII, non-Latin text, combining marks and emoji are unchanged")
    func visibleTextUnchanged() {
        let ascii = String((0x20...0x7E).map { Character(Unicode.Scalar(UInt8($0))) })
        #expect(escaped(ascii) == ascii)
        let visible = [
            "sudo /opt/homebrew/bin/brew install wget",
            "Привет мир", "日本語のファイル", "עברית", "مرحبا", "नमस्ते",
            "e\u{0301}", "café 🍺 🔥 🚀", "Install “Foo” 1.2 — done…",
        ]
        for text in visible {
            #expect(escaped(text) == text)
        }
    }

    @Test("escaping twice changes nothing more, and backslashes are left alone")
    func idempotent() {
        let raw = "sudo /bin/echo IT-approved-\u{202E}gkp.live\u{202C} /etc/pass\u{200B}wd a\nb\tc"
            + "\u{0000}\u{0085}\u{00A0}\u{3000}\u{00AD}\u{3164}\u{E0041} 日本 🍺"
        let once = escaped(raw)
        #expect(escaped(once) == once)
        // Text that already looks like an escape is shown as it is.
        #expect(escaped(#"C:\new\u{202E}"#) == #"C:\new\u{202E}"#)
    }

    @Test("every scalar is kept or escaped for good, and all that sanitized strips is escaped")
    func everyScalar() {
        var unstable: [UInt32] = []
        var strippedButKept: [UInt32] = []
        // Planes 0, 1 and 14 hold every control, format, space-separator and
        // default-ignorable code point; the other planes have none.
        let planes: [ClosedRange<UInt32>] = [0...0x1FFFF, 0xE0000...0xEFFFF]
        for value in planes.joined() {
            guard let scalar = Unicode.Scalar(value) else { continue }
            let text = String(Character(scalar))
            let once = escaped(text)
            if once == text {
                if DisplayText.isControlScalar(scalar) || DisplayText.isFormatScalar(scalar) {
                    strippedButKept.append(value)
                }
            } else if !once.hasPrefix("\\") || escaped(once) != once {
                unstable.append(value)
            }
        }
        #expect(unstable.isEmpty)
        #expect(strippedButKept.isEmpty)
    }

    @Test("a long command is shown whole: nothing trimmed or capped")
    func longCommandWhole() {
        let long = String(repeating: "x", count: 5_000)
        let raw = "  sudo /bin/echo \(long)\u{202E}end  "
        let shown = escaped(raw)
        #expect(shown == "  sudo /bin/echo \(long)" + #"\u{202E}"# + "end  ")
        #expect(shown.count == raw.count + 7)
    }
}
