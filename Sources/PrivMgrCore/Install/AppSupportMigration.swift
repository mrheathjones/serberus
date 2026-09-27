import Foundation

/// One-time migration of the per-user Application Support folder from the old
/// reverse-DNS names to the new `Serberus` folder.
///
/// The Sentinel agent, the full Sentinel app, and Commander all persist per-user
/// data under `~/Library/Application Support/`. That folder was renamed
/// `com.herojoneslabs.serberus[.sentinel]` → `Serberus`; every store now reads
/// and writes the new path, so each app calls ``migrateUserSupportDirectory()``
/// once at launch to move any pre-rename data across (elevation history, the
/// Jamf upload ledger, the rules cache, the policy library, capture reviews) so
/// nothing is orphaned. The system daemon's `/Library/Application Support`
/// folder is migrated separately by the pkg preinstall (which runs as root).
public enum AppSupportMigration {
    /// The current, post-rename per-user folder name.
    public static let currentFolderName = "Serberus"
    /// Pre-rename folder names, most-specific first. `.sentinel` is migrated
    /// before the bare domain so that, when both exist, the Sentinel data seeds
    /// the new folder and the Commander data (bare domain) merges in after.
    static let legacyFolderNames = [
        "com.herojoneslabs.serberus.sentinel",
        "com.herojoneslabs.serberus",
    ]

    /// Renames the pre-rename user support folder(s) to `Serberus`, preserving
    /// their contents. Idempotent and safe: a no-op when no legacy folder exists;
    /// a plain rename when the new folder does not yet exist; a non-clobbering
    /// merge (keeping newer files already in the new folder) when both exist.
    /// All failures are swallowed — a migration that cannot complete must never
    /// block app launch; the app simply starts against the new (possibly empty)
    /// folder.
    public static func migrateUserSupportDirectory(fileManager: FileManager = .default) {
        guard let base = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return
        }
        migrate(inBase: base, fileManager: fileManager)
    }

    /// The rename/merge core, with an explicit Application Support base so it can
    /// be exercised against a temp directory in tests.
    static func migrate(inBase base: URL, fileManager: FileManager) {
        let destination = base.appendingPathComponent(currentFolderName, isDirectory: true)

        for name in legacyFolderNames {
            let legacy = base.appendingPathComponent(name, isDirectory: true)
            guard fileManager.fileExists(atPath: legacy.path) else { continue }

            if fileManager.fileExists(atPath: destination.path) {
                mergeContents(of: legacy, into: destination, fileManager: fileManager)
                try? fileManager.removeItem(at: legacy)
            } else {
                do {
                    try fileManager.moveItem(at: legacy, to: destination)
                } catch {
                    // A move can fail if the parent is missing; fall back to a
                    // create-then-merge so the data is still preserved.
                    try? fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
                    mergeContents(of: legacy, into: destination, fileManager: fileManager)
                    try? fileManager.removeItem(at: legacy)
                }
            }
        }
    }

    /// Moves each entry from `source` into `destination`, skipping any name that
    /// already exists in `destination` (newer data wins).
    private static func mergeContents(of source: URL, into destination: URL, fileManager: FileManager) {
        guard let items = try? fileManager.contentsOfDirectory(atPath: source.path) else { return }
        for item in items {
            let from = source.appendingPathComponent(item)
            let to = destination.appendingPathComponent(item)
            if !fileManager.fileExists(atPath: to.path) {
                try? fileManager.moveItem(at: from, to: to)
            }
        }
    }
}
