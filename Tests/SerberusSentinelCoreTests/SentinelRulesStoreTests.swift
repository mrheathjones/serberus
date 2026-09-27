import Foundation
import Testing
import PrivMgrCore
@testable import SerberusSentinelCore

@MainActor
@Suite("SentinelRulesStore")
struct SentinelRulesStoreTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func snapshot(ruleID: String = "net") -> SentinelRulesSnapshot {
        SentinelRulesSnapshot(
            rules: [SentinelRuleSummary(
                ruleID: ruleID, profileKey: "rules_authuri_standard",
                title: "Change network settings", detail: "system.preferences.network",
                type: .authuri, decision: .prompt
            )],
            profileKeys: ["rules_authuri_standard"],
            policyVersion: "1.2.0",
            enforcementMode: .enforce,
            generatedAt: now
        )
    }

    private func tempFileURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-rules-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("rules-cache.json")
    }

    @Test("adopt marks the snapshot live and persists it for the next launch")
    func adoptPersists() {
        let url = tempFileURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let store = SentinelRulesStore(fileURL: url, now: { self.now })
        #expect(store.snapshot == nil)
        store.adopt(snapshot())
        #expect(store.lastSyncedAt == now)
        #expect(!store.isFromCache)

        // A fresh store (next launch, daemon not yet reached) reads the cache.
        let relaunched = SentinelRulesStore(fileURL: url, now: { self.now })
        #expect(relaunched.snapshot == snapshot())
        #expect(relaunched.isFromCache)
        #expect(relaunched.lastSyncedAt == nil)
    }

    @Test("markOffline keeps the rules but drops the live claim")
    func offlineKeepsRules() {
        let store = SentinelRulesStore(fileURL: nil, now: { self.now })
        store.adopt(snapshot())
        store.markOffline()
        #expect(store.snapshot != nil)
        #expect(store.isFromCache)
    }

    @Test("a corrupt cache file starts empty instead of failing")
    func corruptCache() throws {
        let url = tempFileURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not json".utf8).write(to: url)

        let store = SentinelRulesStore(fileURL: url, now: { self.now })
        #expect(store.snapshot == nil)
    }

    @Test("nil fileURL keeps the snapshot in memory only")
    func inMemory() {
        let store = SentinelRulesStore(fileURL: nil, now: { self.now })
        store.adopt(snapshot())
        #expect(store.snapshot != nil)
    }
}

@Suite("RuleSymbolMapper")
struct RuleSymbolMapperTests {
    private func summary(type: RuleType, detail: String) -> SentinelRuleSummary {
        SentinelRuleSummary(ruleID: "r", profileKey: "p", title: "t", detail: detail,
                            type: type, decision: .allow)
    }

    @Test("sudo rules always get the terminal glyph")
    func sudo() {
        #expect(RuleSymbolMapper.symbol(for: summary(type: .sudo, detail: "sudo · all commands")) == "terminal")
    }

    @Test("rights map by keyword, most specific first")
    func rights() {
        #expect(RuleSymbolMapper.symbol(forAuthURI: "system.print.admin") == "printer")
        #expect(RuleSymbolMapper.symbol(forAuthURI: "system.preferences.network") == "wifi")
        #expect(RuleSymbolMapper.symbol(forAuthURI: "system.install.app-store.software") == "shippingbox")
        #expect(RuleSymbolMapper.symbol(forAuthURI: "system.preferences.timemachine") == "clock")
        #expect(RuleSymbolMapper.symbol(forAuthURI: "system.kext.load") == "cpu")
        #expect(RuleSymbolMapper.symbol(forAuthURI: "system.preferences") == "lock.open")
        #expect(RuleSymbolMapper.symbol(forAuthURI: "com.example.unknown.right") == "key.horizontal")
    }
}
