import Foundation
import PrivMgrCore

/// Persists the policy library as JSON under Application Support so authored
/// policies survive app restarts.
///
/// Location: `~/Library/Application Support/Serberus/policies.json`.
/// The Commander app is not sandboxed, so this is a plain file write. This is the
/// local authoring copy in three-tier form (schema v2, see
/// ``PolicyLibraryFile``); publishing to Jamf delivers the COMPILED
/// `RuleProfile`s as `.mobileconfig` (see ``PolicyCompiler`` /
/// ``MobileConfigGenerator``). v1 files at the same path decode through the
/// in-place migration in ``PolicyLibraryFile/init(from:)``.
public struct ProfileLibraryStore: Sendable {
    public let url: URL

    public init(url: URL? = nil) {
        self.url = url ?? Self.defaultURL()
    }

    public static func defaultURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("Serberus", isDirectory: true)
            .appendingPathComponent("policies.json")
    }

    public func exists() -> Bool {
        FileManager.default.fileExists(atPath: url.path)
    }

    public func load() -> PolicyLibraryFile? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? Self.decoder.decode(PolicyLibraryFile.self, from: data)
    }

    @discardableResult
    public func save(_ file: PolicyLibraryFile) -> Bool {
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try Self.encoder.encode(file)
            try data.write(to: url, options: .atomic)
            return true
        } catch {
            return false
        }
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}
