import Foundation
import Testing
@testable import PrivMgrCore

@Suite("AppSupportMigration — user folder rename")
struct AppSupportMigrationTests {
    private let fm = FileManager.default

    /// A throwaway "Application Support" base directory.
    private func makeBase() throws -> URL {
        let base = fm.temporaryDirectory.appendingPathComponent("appsupport-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    private func writeFile(_ text: String, at url: URL) throws {
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.data(using: .utf8)!.write(to: url)
    }

    private func read(_ url: URL) -> String? {
        (try? Data(contentsOf: url)).flatMap { String(data: $0, encoding: .utf8) }
    }

    @Test("a legacy folder is renamed to Serberus, preserving its files")
    func renamesWhenDestinationAbsent() throws {
        let base = try makeBase()
        defer { try? fm.removeItem(at: base) }
        let legacy = base.appendingPathComponent("com.herojoneslabs.serberus.sentinel", isDirectory: true)
        try writeFile("history", at: legacy.appendingPathComponent("elevation-history.json"))

        AppSupportMigration.migrate(inBase: base, fileManager: fm)

        let dest = base.appendingPathComponent("Serberus", isDirectory: true)
        #expect(fm.fileExists(atPath: dest.path))
        #expect(!fm.fileExists(atPath: legacy.path))
        #expect(read(dest.appendingPathComponent("elevation-history.json")) == "history")
    }

    @Test("both legacy folders merge into Serberus")
    func mergesBothLegacyFolders() throws {
        let base = try makeBase()
        defer { try? fm.removeItem(at: base) }
        let sentinel = base.appendingPathComponent("com.herojoneslabs.serberus.sentinel", isDirectory: true)
        let commander = base.appendingPathComponent("com.herojoneslabs.serberus", isDirectory: true)
        try writeFile("history", at: sentinel.appendingPathComponent("elevation-history.json"))
        try writeFile("policies", at: commander.appendingPathComponent("policies.json"))

        AppSupportMigration.migrate(inBase: base, fileManager: fm)

        let dest = base.appendingPathComponent("Serberus", isDirectory: true)
        #expect(read(dest.appendingPathComponent("elevation-history.json")) == "history")
        #expect(read(dest.appendingPathComponent("policies.json")) == "policies")
        #expect(!fm.fileExists(atPath: sentinel.path))
        #expect(!fm.fileExists(atPath: commander.path))
    }

    @Test("merge keeps the newer file already in the destination")
    func mergeDoesNotClobberNewer() throws {
        let base = try makeBase()
        defer { try? fm.removeItem(at: base) }
        let dest = base.appendingPathComponent("Serberus", isDirectory: true)
        let legacy = base.appendingPathComponent("com.herojoneslabs.serberus.sentinel", isDirectory: true)
        try writeFile("NEW", at: dest.appendingPathComponent("rules-cache.json"))
        try writeFile("OLD", at: legacy.appendingPathComponent("rules-cache.json"))

        AppSupportMigration.migrate(inBase: base, fileManager: fm)

        #expect(read(dest.appendingPathComponent("rules-cache.json")) == "NEW")
        #expect(!fm.fileExists(atPath: legacy.path))
    }

    @Test("no legacy folder is a no-op (does not create Serberus)")
    func noOpWhenNothingToMigrate() throws {
        let base = try makeBase()
        defer { try? fm.removeItem(at: base) }

        AppSupportMigration.migrate(inBase: base, fileManager: fm)

        // The rename path is only taken when a legacy folder exists; the app's
        // stores create the Serberus folder lazily on first write.
        #expect(!fm.fileExists(atPath: base.appendingPathComponent("Serberus").path))
    }
}
