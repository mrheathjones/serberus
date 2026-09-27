import Foundation

// MARK: - Policy errors

/// Errors raised while loading, decoding, or evaluating policy.
public enum PolicyError: Error, LocalizedError, Equatable, Sendable {
    /// A `rules_*` key contained a value that could not be decoded.
    case profileDecodingFailed(profileKey: String, underlying: String)
    /// A profile declared a schema version this build does not recognize.
    case unrecognizedSchemaVersion(profileKey: String, version: String)
    /// A regular expression in a rule failed to compile.
    case invalidRegex(ruleID: String, pattern: String, underlying: String)
    /// The evaluation context was malformed (e.g. missing required fields).
    case invalidEvaluationContext(reason: String)

    public var errorDescription: String? {
        switch self {
        case let .profileDecodingFailed(profileKey, underlying):
            return "Failed to decode rule profile '\(profileKey)': \(underlying)"
        case let .unrecognizedSchemaVersion(profileKey, version):
            return "Rule profile '\(profileKey)' declares unrecognized schema version '\(version)'"
        case let .invalidRegex(ruleID, pattern, underlying):
            return "Rule '\(ruleID)' has invalid regex '\(pattern)': \(underlying)"
        case let .invalidEvaluationContext(reason):
            return "Invalid evaluation context: \(reason)"
        }
    }
}

// MARK: - Path errors

/// Errors raised during executable path canonicalization.
public enum PathError: Error, LocalizedError, Equatable, Sendable {
    /// The path is relative; only absolute paths are accepted.
    case relativePath(String)
    /// The path is ambiguous (contains `..` or `.` components after normalization).
    case ambiguousPath(String)
    /// The executable does not exist on disk (enforce-mode evaluation only).
    case missingExecutable(String)
    /// The path is empty.
    case emptyPath

    public var errorDescription: String? {
        switch self {
        case let .relativePath(path):
            return "Relative path rejected: '\(path)'"
        case let .ambiguousPath(path):
            return "Ambiguous path rejected: '\(path)'"
        case let .missingExecutable(path):
            return "Executable does not exist: '\(path)'"
        case .emptyPath:
            return "Empty executable path rejected"
        }
    }
}

// MARK: - Configuration errors

/// Errors raised while reading managed preference domains.
public enum ConfigError: Error, LocalizedError, Equatable, Sendable {
    /// A required key is absent from the domain.
    case missingKey(domain: String, key: String)
    /// A key is present but its value has the wrong type or an invalid value.
    case invalidValue(domain: String, key: String, reason: String)

    public var errorDescription: String? {
        switch self {
        case let .missingKey(domain, key):
            return "'\(key)' not found in \(domain)"
        case let .invalidValue(domain, key, reason):
            return "Invalid value for '\(key)' in \(domain): \(reason)"
        }
    }
}

// MARK: - Grant store errors

/// Errors raised by the persisted grant database.
public enum GrantStoreError: Error, LocalizedError, Equatable, Sendable {
    /// SQLite could not open the database file.
    case openFailed(path: String, code: Int32, message: String)
    /// A SQL statement failed to prepare or execute.
    case statementFailed(sql: String, code: Int32, message: String)
    /// Schema migration failed; the daemon must enter degraded state.
    case migrationFailed(from: Int, to: Int, underlying: String)
    /// The database schema version is newer than this build understands.
    case schemaTooNew(found: Int, supported: Int)
    /// A stored row failed HMAC integrity verification.
    case integrityViolation(grantID: String)
    /// A stored row could not be decoded into a ``Grant``.
    case rowDecodingFailed(grantID: String, reason: String)

    public var errorDescription: String? {
        switch self {
        case let .openFailed(path, code, message):
            return "Failed to open grant database at '\(path)' (sqlite \(code)): \(message)"
        case let .statementFailed(sql, code, message):
            return "Grant database statement failed (sqlite \(code)): \(message) [\(sql)]"
        case let .migrationFailed(from, to, underlying):
            return "Grant database migration \(from)→\(to) failed: \(underlying)"
        case let .schemaTooNew(found, supported):
            return "Grant database schema \(found) is newer than supported \(supported)"
        case let .integrityViolation(grantID):
            return "Grant \(grantID) failed HMAC integrity verification"
        case let .rowDecodingFailed(grantID, reason):
            return "Grant \(grantID) row could not be decoded: \(reason)"
        }
    }
}

// MARK: - Logging errors

/// Errors raised by the decision and integrity loggers.
public enum LoggingError: Error, LocalizedError, Equatable, Sendable {
    /// The log directory could not be created or written.
    case directoryUnavailable(path: String, underlying: String)
    /// An event failed to encode as JSON.
    case encodingFailed(reason: String)
    /// The signing key could not be obtained from the key provider.
    case signingKeyUnavailable(reason: String)

    public var errorDescription: String? {
        switch self {
        case let .directoryUnavailable(path, underlying):
            return "Log directory unavailable at '\(path)': \(underlying)"
        case let .encodingFailed(reason):
            return "Log event encoding failed: \(reason)"
        case let .signingKeyUnavailable(reason):
            return "Log signing key unavailable: \(reason)"
        }
    }
}

// MARK: - Jamf errors

/// Errors raised by the Jamf Pro API client and token manager.
public enum JamfError: Error, LocalizedError, Equatable, Sendable {
    /// Jamf connection settings are absent from the config domain.
    case notConfigured(missingKey: String)
    /// The token endpoint rejected the client credentials (HTTP 401).
    case credentialsInvalid
    /// A specific API permission is missing (HTTP 403).
    case insufficientPermissions(endpoint: String)
    /// Jamf Pro could not be reached or timed out.
    case unreachable(underlying: String)
    /// Jamf returned an unexpected status code.
    case unexpectedStatus(code: Int, endpoint: String)
    /// A Jamf response failed to decode.
    case responseDecodingFailed(endpoint: String, reason: String)

    public var errorDescription: String? {
        switch self {
        case let .notConfigured(missingKey):
            return "Jamf connection not configured: '\(missingKey)' not found in \(BundleConfig.configDomain)"
        case .credentialsInvalid:
            return "Jamf credentials invalid or expired"
        case let .insufficientPermissions(endpoint):
            return "Insufficient Jamf API permissions for \(endpoint)"
        case let .unreachable(underlying):
            return "Jamf Pro unreachable: \(underlying)"
        case let .unexpectedStatus(code, endpoint):
            return "Jamf Pro returned HTTP \(code) for \(endpoint)"
        case let .responseDecodingFailed(endpoint, reason):
            return "Failed to decode Jamf response from \(endpoint): \(reason)"
        }
    }
}

// MARK: - Export errors

/// Errors raised by the MobileConfig generator.
public enum ExportError: Error, LocalizedError, Equatable, Sendable {
    /// The profile failed pre-export validation; export is blocked.
    case validationFailed(issues: [String])
    /// Plist serialization failed.
    case serializationFailed(reason: String)

    public var errorDescription: String? {
        switch self {
        case let .validationFailed(issues):
            return "Profile failed pre-export validation: \(issues.joined(separator: "; "))"
        case let .serializationFailed(reason):
            return "MobileConfig serialization failed: \(reason)"
        }
    }
}

// MARK: - XPC errors

/// Errors raised while validating XPC peers.
public enum XPCValidationError: Error, LocalizedError, Equatable, Sendable {
    /// The peer's code signature is invalid, ad-hoc, or absent.
    case signatureInvalid(reason: String)
    /// The peer's Team ID does not match ``BundleConfig/teamID``.
    case teamIDMismatch(found: String?)
    /// This process has no signing Team ID (unsigned, ad-hoc, or an invalid
    /// signature), so it cannot tell a genuine Serberus peer from any other
    /// and rejects them all.
    case expectedTeamIDUnavailable
    /// The peer's bundle identifier is not an expected caller.
    case unknownBundleID(found: String?)
    /// The peer lacks the required private entitlement marker.
    case missingEntitlement(name: String)
    /// The peer does not have Hardened Runtime enabled.
    case hardenedRuntimeDisabled
    /// The audit token could not be resolved to a code object.
    case auditTokenUnresolvable
    /// The PAM-host caller is not running as root (euid != 0).
    case pamHostNotRoot(found: uid_t)
    /// The PAM-host caller is not an Apple platform binary (`anchor apple`).
    case pamHostNotApplePlatform
    /// The PAM-host caller is not the pinned platform `sudo` binary.
    case pamHostNotSudo(found: String?)

    public var errorDescription: String? {
        switch self {
        case let .signatureInvalid(reason):
            return "XPC peer code signature invalid: \(reason)"
        case let .teamIDMismatch(found):
            return "XPC peer Team ID mismatch (found: \(found ?? "none"))"
        case .expectedTeamIDUnavailable:
            return "XPC peer rejected: this process has no signing Team ID to trust peers against (unsigned or ad-hoc build)"
        case let .unknownBundleID(found):
            return "XPC peer bundle ID not recognized (found: \(found ?? "none"))"
        case let .missingEntitlement(name):
            return "XPC peer missing required entitlement '\(name)'"
        case .hardenedRuntimeDisabled:
            return "XPC peer does not have Hardened Runtime enabled"
        case .auditTokenUnresolvable:
            return "XPC peer audit token could not be resolved"
        case let .pamHostNotRoot(found):
            return "PAM host not running as root (euid: \(found))"
        case .pamHostNotApplePlatform:
            return "PAM host is not an Apple platform binary"
        case let .pamHostNotSudo(found):
            return "PAM host is not the platform sudo binary (found: \(found ?? "none"))"
        }
    }
}
