import Foundation
import PrivMgrCore

/// Picks the SF Symbol for a rule row's glyph chip. Pure keyword mapping over
/// the rule's machine-readable detail — the design seeds specific icons per
/// right (`printer`, `wifi`, `shippingbox`, …) and this generalizes that to
/// whatever rights and commands a policy actually contains.
public enum RuleSymbolMapper {

    /// SF Symbol name for a rule summary.
    public static func symbol(for rule: SentinelRuleSummary) -> String {
        if rule.type == .sudo { return "terminal" }
        return symbol(forAuthURI: rule.detail)
    }

    /// SF Symbol for an authorization right, by keyword. Checks the most
    /// specific keywords first so e.g. `system.preferences.network` lands on
    /// wifi, not the generic preferences lock.
    static func symbol(forAuthURI right: String) -> String {
        let lowered = right.lowercased()
        let keywordSymbols: [(keyword: String, symbol: String)] = [
            ("print", "printer"),
            ("network", "wifi"),
            ("wifi", "wifi"),
            ("airport", "wifi"),
            ("install", "shippingbox"),
            ("software", "shippingbox"),
            ("app-store", "shippingbox"),
            ("timemachine", "clock"),
            ("datetime", "clock"),
            ("dateandtime", "clock"),
            ("kext", "cpu"),
            ("extension", "cpu"),
            ("energysaver", "bolt"),
            ("battery", "bolt"),
            ("sharing", "person.2"),
            ("accounts", "person.crop.circle"),
            ("users", "person.crop.circle"),
            ("security", "lock.shield"),
            ("privacy", "hand.raised"),
            ("startupdisk", "internaldrive"),
            ("diskmanagement", "internaldrive"),
            ("accessibility", "figure.arms.open"),
        ]
        for entry in keywordSymbols where lowered.contains(entry.keyword) {
            return entry.symbol
        }
        // The bare settings-unlock right and its children.
        if lowered.hasPrefix("system.preferences") { return "lock.open" }
        return "key.horizontal"
    }
}
