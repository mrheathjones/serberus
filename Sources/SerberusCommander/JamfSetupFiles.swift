import Foundation

/// The Jamf setup files Commander ships as bundled resources so an admin can
/// hand them out for a new deployment: the extension-attribute scripts, the
/// Application & Custom Settings JSON schemas, and sample rule sets. Settings
/// lists each one with its own download button (no single bundle).
///
/// The three folders are added to the app as folder references (see
/// `project.yml`), so each lands whole under `Contents/Resources/<folder>/` and
/// is enumerated here at runtime — no file list to keep in sync.
enum JamfSetupFiles {
    enum Category: String, CaseIterable, Identifiable {
        case extensionAttributes = "Extension Attributes"
        case schemas = "Application & Custom Settings schemas"
        case sampleRules = "Sample rule sets"

        var id: String { rawValue }

        /// The bundled folder name (folder reference) this category reads.
        var folder: String {
            switch self {
            case .extensionAttributes: return "jamf-extension-attributes"
            case .schemas: return "jamf-schemas"
            case .sampleRules: return "sample-rules"
            }
        }

        var blurb: String {
            switch self {
            case .extensionAttributes:
                return "Create each as a Script extension attribute in Jamf (name it anything containing “Serberus”)."
            case .schemas:
                return "Paste into an Application & Custom Settings profile payload to build the Serberus config UI in Jamf."
            case .sampleRules:
                return "Example rule sets to adapt for your fleet."
            }
        }

        /// The file extension a downloadable in this category must have (so a
        /// generator script or stray file in the folder isn't offered), or nil
        /// to accept any content file.
        var fileExtension: String? {
            switch self {
            case .extensionAttributes: return "sh"
            case .schemas: return "json"
            case .sampleRules: return nil
            }
        }
    }

    struct SetupFile: Identifiable, Hashable {
        let category: Category
        let name: String
        let url: URL
        var id: String { "\(category.folder)/\(name)" }
    }

    /// Files in one category, sorted by name. Empty if the folder is missing
    /// from the bundle (e.g. a stripped build).
    static func files(in category: Category) -> [SetupFile] {
        guard let root = Bundle.main.resourceURL?.appendingPathComponent(category.folder, isDirectory: true),
              let names = try? FileManager.default.contentsOfDirectory(atPath: root.path) else {
            return []
        }
        return names
            .filter { !$0.hasPrefix(".") }
            // Only offer the content type each category is about — the schemas
            // folder also holds a generator script (make-rules-subdomain-schema.sh)
            // that must not appear as a downloadable "schema".
            .filter { category.fileExtension == nil || ($0 as NSString).pathExtension == category.fileExtension }
            .sorted()
            .map { SetupFile(category: category, name: $0, url: root.appendingPathComponent($0)) }
    }

    /// Whether any setup files are bundled at all (the Settings card hides itself
    /// when nothing shipped).
    static var isAvailable: Bool {
        Category.allCases.contains { !files(in: $0).isEmpty }
    }
}
