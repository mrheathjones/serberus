import Foundation
import Security

/// Reads a single right or rule definition from the live authorization
/// database through the Security framework. Works for any user — this is the
/// same call `security authorizationdb read <name>` makes.
enum LiveAuthorizationReader {
    struct Outcome: Sendable {
        let definition: RuleDefinition?
        let status: OSStatus
    }

    static func read(_ name: String) -> Outcome {
        var raw: CFDictionary?
        let status = AuthorizationRightGet(name, &raw)
        guard status == errAuthorizationSuccess, let dict = raw as? [String: Any] else {
            return Outcome(definition: nil, status: status)
        }
        return Outcome(definition: RuleDefinition(plist: dict), status: status)
    }

    static func describe(status: OSStatus) -> String {
        switch status {
        case errAuthorizationDenied: return "not present in the live database (\(status))"
        case errAuthorizationSuccess: return "ok"
        default:
            if let message = SecCopyErrorMessageString(status, nil) as String? {
                return "\(message) (\(status))"
            }
            return "OSStatus \(status)"
        }
    }
}

/// Parses the world-readable system template that seeds the live database.
enum AuthorizationTemplate {
    static let path = "/System/Library/Security/authorization.plist"

    struct Entry: Sendable {
        let name: String
        let kind: AuthEntry.Kind
        let definition: RuleDefinition
    }

    static func load() throws -> [Entry] {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let root = plist as? [String: Any] else {
            throw CatalogError.message("The authorization template is not a dictionary")
        }
        var entries: [Entry] = []
        func ingest(_ key: String, kind: AuthEntry.Kind) {
            guard let table = root[key] as? [String: Any] else { return }
            for (name, value) in table {
                guard !name.isEmpty, let dict = value as? [String: Any] else { continue }
                entries.append(Entry(name: name, kind: kind, definition: RuleDefinition(plist: dict)))
            }
        }
        ingest("rights", kind: .right)
        ingest("rules", kind: .rule)
        return entries
    }
}

/// Enumerates every row name in `/var/db/auth.db`, which is root-only, by
/// asking for administrator credentials once through the system prompt.
/// Only the names come back — each definition is then read with
/// `LiveAuthorizationReader` as the current user.
enum LiveDatabaseDiscovery {
    struct Row: Sendable, Hashable {
        let name: String
        let kind: AuthEntry.Kind
    }

    static func discover() throws -> [Row] {
        let shell = "/usr/bin/sqlite3 -separator '|' /var/db/auth.db 'select name,type from rules order by name'"
        let escaped = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let outData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errData = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let errText = String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationStatus == 0 else {
            if errText.contains("-128") || errText.localizedCaseInsensitiveContains("cancel") {
                throw CatalogError.cancelled
            }
            throw CatalogError.message(errText.isEmpty ? "osascript exited \(process.terminationStatus)" : errText)
        }

        // osascript renders the shell's newlines as carriage returns.
        let text = String(decoding: outData, as: UTF8.self)
        return text.split(whereSeparator: { $0 == "\r" || $0 == "\n" }).compactMap { line in
            let parts = line.split(separator: "|", omittingEmptySubsequences: false)
            guard let name = parts.first, !name.isEmpty else { return nil }
            let type = parts.count > 1 ? Int(parts[1]) ?? 1 : 1
            return Row(name: String(name), kind: type == 2 ? .rule : .right)
        }
    }
}

enum CatalogError: Error, LocalizedError, Sendable {
    case cancelled
    case message(String)

    var errorDescription: String? {
        switch self {
        case .cancelled: return "Cancelled"
        case let .message(text): return text
        }
    }
}
