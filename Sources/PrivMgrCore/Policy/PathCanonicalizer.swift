import Foundation

/// Canonicalizes executable paths before rule evaluation.
///
/// All executable paths must have symlinks resolved, relative
/// paths rejected, and representation normalized before any pattern is
/// applied. Missing executables are rejected except in audit/monitor mode
/// or when evaluating simulation input.
public struct PathCanonicalizer: Sendable {
    /// Whether the canonical path must exist on disk.
    public enum ExistencePolicy: Sendable {
        /// Enforce mode: the executable must exist.
        case requireExists
        /// Audit/monitor mode or simulation input: existence is not required.
        case allowMissing
    }

    public init() {}

    /// Returns the canonical form of `path`.
    ///
    /// - Resolves all symlinks (e.g. `/usr/local/bin/brew` → `/opt/homebrew/bin/brew`)
    /// - Normalizes the path representation
    /// - Rejects empty, relative, and ambiguous paths
    /// - Rejects any path — as given or after symlink resolution — containing a
    ///   control character (U+0000–U+001F, U+007F). No legitimate executable or
    ///   installer path needs one, and a newline in a path lets it forge extra
    ///   lines in tool output (`spctl`, logs) that is later read back.
    /// - Rejects missing executables under ``ExistencePolicy/requireExists``
    /// - Throws: ``PathError``
    public func canonicalize(_ path: String, existence: ExistencePolicy) throws -> String {
        guard !path.isEmpty else { throw PathError.emptyPath }
        guard !Self.containsControlCharacter(path) else { throw PathError.ambiguousPath(Self.escaped(path)) }
        guard path.hasPrefix("/") else { throw PathError.relativePath(path) }

        let standardized = (path as NSString).standardizingPath
        // standardizingPath leaves ".." intact when the referenced parent does
        // not exist; any remaining traversal component is ambiguous.
        let components = (standardized as NSString).pathComponents
        if components.contains("..") || components.contains(".") {
            throw PathError.ambiguousPath(path)
        }

        let resolved = (standardized as NSString).resolvingSymlinksInPath
        // A clean path can still resolve through a symlink to a hostile name.
        guard !Self.containsControlCharacter(resolved) else { throw PathError.ambiguousPath(Self.escaped(resolved)) }

        if case .requireExists = existence {
            guard FileManager.default.fileExists(atPath: resolved) else {
                throw PathError.missingExecutable(resolved)
            }
        }
        return resolved
    }

    /// Whether `path` contains a C0 or C1 control character, or DEL.
    public static func containsControlCharacter(_ path: String) -> Bool {
        path.unicodeScalars.contains { $0.value < 0x20 || (0x7F...0x9F).contains($0.value) }
    }

    /// `path` with control characters escaped, so a rejected path can be
    /// reported in an error/log line without injecting into it.
    private static func escaped(_ path: String) -> String {
        var out = ""
        for scalar in path.unicodeScalars {
            if scalar.value < 0x20 || scalar.value == 0x7F {
                out += "\\u{" + String(scalar.value, radix: 16) + "}"
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }
}
