import Foundation

/// Cleans names that come from the filesystem or a bundle before they are
/// shown to a person, and makes hidden characters in a command line visible.
/// Shared by the daemon (prompt text, messages) and the Sentinel (toasts,
/// prompt rows, history), so both strip or escape exactly the same characters.
public enum DisplayText {
    /// Whether `scalar` is a control character: C0 (U+0000–U+001F), DEL, or C1
    /// (U+0080–U+009F) — every Unicode `Cc` scalar.
    public static func isControlScalar(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x20 || (0x7F...0x9F).contains(scalar.value) || scalar.properties.generalCategory == .control
    }

    /// Whether `scalar` is an invisible formatting character: any Unicode `Cf`
    /// scalar (which covers U+061C, U+200B–U+200F, U+202A–U+202E, U+2066–U+2069,
    /// U+FEFF) or a line/paragraph separator.
    public static func isFormatScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069, 0x2028, 0x2029: return true
        default: return scalar.properties.generalCategory == .format
        }
    }

    /// `text` with control and format characters (including bidi overrides,
    /// isolates and marks, and zero-width characters) removed, trimmed, and
    /// capped at `maxLength` characters — safe to show in a prompt or message.
    public static func sanitized(_ text: String, maxLength: Int = 80) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in text.unicodeScalars where !isControlScalar(scalar) && !isFormatScalar(scalar) {
            scalars.append(scalar)
        }
        let cleaned = String(scalars).trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.count <= maxLength ? cleaned : String(cleaned.prefix(maxLength)) + "…"
    }

    /// `text` with every hidden character written as a visible escape: `\n`,
    /// `\r` and `\t` for those three, and `\u{XXXX}` (uppercase hex, at least
    /// four digits) for any other control or format character, line or
    /// paragraph separator, space other than U+0020, or default-ignorable
    /// code point (soft hyphen, variation selectors, Hangul fillers, tag
    /// characters…). For a command line, where ``sanitized(_:maxLength:)``
    /// would mislead: removing the zero-width space from `/etc/pass\u{200B}wd`
    /// shows `/etc/passwd`, which isn't what runs. Nothing is removed, trimmed
    /// or capped, and backslashes are left alone, so applying it twice changes
    /// nothing more.
    public static func escapingInvisibles(_ text: String) -> String {
        var escaped = ""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\n": escaped += "\\n"
            case "\r": escaped += "\\r"
            case "\t": escaped += "\\t"
            case _ where isHiddenScalar(scalar):
                let hex = String(scalar.value, radix: 16, uppercase: true)
                escaped += "\\u{" + String(repeating: "0", count: max(0, 4 - hex.count)) + hex + "}"
            default:
                escaped.unicodeScalars.append(scalar)
            }
        }
        return escaped
    }

    /// Whether `scalar` shows as nothing, or as something it isn't: a control
    /// or format character, a space other than U+0020 (NBSP, U+1680,
    /// U+2000–U+200A, U+202F, U+205F, U+3000), or a default-ignorable code
    /// point.
    private static func isHiddenScalar(_ scalar: Unicode.Scalar) -> Bool {
        if isControlScalar(scalar) || isFormatScalar(scalar) { return true }
        let properties = scalar.properties
        return (properties.generalCategory == .spaceSeparator && scalar != " ")
            || properties.isDefaultIgnorableCodePoint
    }
}
