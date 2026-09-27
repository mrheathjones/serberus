import CryptoKit
import Foundation

/// Thin wrappers over CryptoKit so call sites stay framework-agnostic.
public enum SHA256Hasher {
    /// SHA-256 digest as raw bytes.
    public static func hash(_ data: Data) -> [UInt8] {
        Array(SHA256.hash(data: data))
    }

    /// SHA-256 digest as a lowercase hex string.
    public static func hexDigest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// SHA-256 of a file's contents as a lowercase hex string.
    /// - Throws: Any file-read error.
    public static func hexDigest(fileAt url: URL) throws -> String {
        hexDigest(try Data(contentsOf: url))
    }
}

/// HMAC-SHA256 signing used by log sidecars and grant-row integrity markers.
public enum HMACSHA256 {
    /// HMAC-SHA256 of `message` under `key`, as a lowercase hex string.
    public static func hexSignature(message: Data, key: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    /// Constant-time comparison of an expected hex signature against a
    /// computed one.
    public static func verify(message: Data, key: Data, expectedHex: String) -> Bool {
        let computed = hexSignature(message: message, key: key)
        // Hex strings are fixed-width; compare byte-wise without early exit.
        guard computed.utf8.count == expectedHex.utf8.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(computed.utf8, expectedHex.utf8) {
            difference |= a ^ b
        }
        return difference == 0
    }

    /// Generates a random 256-bit key.
    public static func generateKey() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }
}

/// Source of HMAC signing keys.
///
/// The daemon supplies a System-Keychain-backed provider;
/// tests supply ``InMemoryKeyProvider``. Keys never appear in logs or on
/// disk outside the Keychain.
public protocol SigningKeyProvider: Sendable {
    /// Returns the key for `account`, creating it when absent.
    /// - Throws: ``LoggingError/signingKeyUnavailable(reason:)``
    func key(account: String) throws -> Data
}

/// Test/process-local key provider. Not persisted.
public struct InMemoryKeyProvider: SigningKeyProvider {
    private let keys: [String: Data]

    public init(keys: [String: Data]) {
        self.keys = keys
    }

    /// Convenience: a provider with fresh random keys for the daemon's two
    /// well-known accounts.
    public static func random() -> InMemoryKeyProvider {
        InMemoryKeyProvider(keys: [
            BundleConfig.logHMACKeyAccount: HMACSHA256.generateKey(),
            BundleConfig.grantsHMACKeyAccount: HMACSHA256.generateKey(),
        ])
    }

    public func key(account: String) throws -> Data {
        guard let key = keys[account] else {
            throw LoggingError.signingKeyUnavailable(reason: "no in-memory key for account '\(account)'")
        }
        return key
    }
}

/// Whether a key provider may MINT a key that is absent.
///
/// Minting is not harmless: a fresh key silently orphans every row signed with
/// the old one (the grant store then fails every HMAC). So read-only callers
/// (the `serberusd --demote-jit` teardown) never mint, and the daemon mints the
/// grants key only while the grant database holds no rows.
public enum KeyCreationPolicy: Sendable {
    /// Mint a fresh key when none exists (historical behavior).
    case createIfMissing
    /// Never mint; an absent key throws ``LoggingError/signingKeyUnavailable(reason:)``.
    case readOnly
    /// Mint only when the closure (given the account) returns true.
    case createIf(@Sendable (String) -> Bool)

    /// Whether minting `account` is permitted right now.
    public func mayCreate(account: String) -> Bool {
        switch self {
        case .createIfMissing: return true
        case .readOnly: return false
        case let .createIf(allow): return allow(account)
        }
    }
}

/// System-Keychain-backed key provider used by the root daemon.
///
/// Keys live in the System Keychain under service
/// ``BundleConfig/keychainService`` and are generated on first use — subject
/// to ``KeyCreationPolicy``. Runtime-only — unit tests use ``InMemoryKeyProvider``.
public struct SystemKeychainKeyProvider: SigningKeyProvider {
    private let service: String
    private let creation: KeyCreationPolicy

    public init(service: String = BundleConfig.keychainService,
                creation: KeyCreationPolicy = .createIfMissing) {
        self.service = service
        self.creation = creation
    }

    public func key(account: String) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw LoggingError.signingKeyUnavailable(reason: "keychain returned non-data item for '\(account)'")
            }
            return data
        case errSecItemNotFound:
            guard creation.mayCreate(account: account) else {
                throw LoggingError.signingKeyUnavailable(
                    reason: "keychain key '\(account)' is absent and minting a new one is refused "
                        + "(read-only, or existing data is signed with the missing key)")
            }
            let key = HMACSHA256.generateKey()
            query.removeValue(forKey: kSecReturnData as String)
            query.removeValue(forKey: kSecMatchLimit as String)
            query[kSecValueData as String] = key
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw LoggingError.signingKeyUnavailable(reason: "keychain add failed for '\(account)' (status \(addStatus))")
            }
            return key
        default:
            throw LoggingError.signingKeyUnavailable(reason: "keychain read failed for '\(account)' (status \(status))")
        }
    }
}

/// **Dev-only** fallback: a key file readable only by its owner (mode 600) under
/// a directory, created on first use. Less private than the System Keychain — an offline
/// attacker who copies the grant DB can copy the adjacent key too — so it is
/// gated behind an explicit dev opt-in and never used in production (where a
/// keychain failure must fail closed to `degraded(grants_db_error)` instead of
/// silently downgrading key storage).
public struct FileKeyProvider: SigningKeyProvider {
    private let directory: URL
    private let creation: KeyCreationPolicy

    public init(directory: URL, creation: KeyCreationPolicy = .createIfMissing) {
        self.directory = directory
        self.creation = creation
    }

    /// Where the key for `account` lives under `directory`
    /// (e.g. `<support>/.grants-hmac-key.key`).
    public static func keyURL(directory: URL, account: String) -> URL {
        directory.appendingPathComponent(".\(account).key")
    }

    public func key(account: String) throws -> Data {
        let url = Self.keyURL(directory: directory, account: account)
        if let existing = try Self.readOwnerOnlyKey(at: url) {
            return existing
        }
        guard creation.mayCreate(account: account) else {
            throw LoggingError.signingKeyUnavailable(
                reason: "file key '\(account)' is absent (or unusable) and minting a new one is refused")
        }
        let key = HMACSHA256.generateKey()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Self.writeOwnerOnly(key, to: url)
        } catch {
            throw LoggingError.signingKeyUnavailable(reason: "file key write failed for '\(account)': \(error)")
        }
        return key
    }

    /// The existing 32-byte key, or nil when there's none (or it's the wrong
    /// size, and is regenerated). Throws when the file isn't private to this
    /// user: a key others could read may already have leaked, so logs signed
    /// with it can't be trusted.
    static func readOwnerOnlyKey(at url: URL) throws -> Data? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw LoggingError.signingKeyUnavailable(reason: "can't open key file \(url.lastPathComponent) (errno \(errno))")
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            throw LoggingError.signingKeyUnavailable(
                reason: "key file \(url.lastPathComponent) isn't a regular file readable only by its owner")
        }
        var buffer = [UInt8](repeating: 0, count: 33)
        let count = read(fd, &buffer, buffer.count)
        return count == 32 ? Data(buffer.prefix(32)) : nil
    }

    /// Writes `data` so the file is 0600 from the moment it exists: created with
    /// O_EXCL under a temporary name, then renamed into place atomically.
    static func writeOwnerOnly(_ data: Data, to url: URL) throws {
        let temp = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var failure: Int32 = 0
        if fchmod(fd, 0o600) != 0 { failure = errno }
        if failure == 0 {
            let written = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if written != data.count { failure = errno == 0 ? EIO : errno }
        }
        if failure == 0, fsync(fd) != 0 { failure = errno }
        close(fd)
        if failure == 0, rename(temp.path, url.path) != 0 { failure = errno }
        if failure != 0 {
            unlink(temp.path)
            throw POSIXError(POSIXErrorCode(rawValue: failure) ?? .EIO)
        }
    }
}

/// Tries `primary`; on any failure, reports it via `onFallback` and uses
/// `secondary`. Lets the daemon prefer the System Keychain but fall back to a
/// dev file key when the keychain is unavailable — without silently hiding that
/// the downgrade happened.
public struct FallbackKeyProvider: SigningKeyProvider {
    private let primary: SigningKeyProvider
    private let secondary: SigningKeyProvider
    private let onFallback: @Sendable (String, Error) -> Void

    public init(
        primary: SigningKeyProvider,
        secondary: SigningKeyProvider,
        onFallback: @escaping @Sendable (String, Error) -> Void = { _, _ in }
    ) {
        self.primary = primary
        self.secondary = secondary
        self.onFallback = onFallback
    }

    public func key(account: String) throws -> Data {
        do {
            return try primary.key(account: account)
        } catch {
            onFallback(account, error)
            return try secondary.key(account: account)
        }
    }
}
