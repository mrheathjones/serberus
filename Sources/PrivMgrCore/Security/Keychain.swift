import Foundation
import Security

/// Minimal generic-password Keychain wrapper for storing the Commander app's
/// user-entered MDM client secret. Unlike the endpoint daemon (which never
/// puts Jamf credentials in the Keychain), the *Commander* app is operator-driven
/// and stores its own connection secret here rather than on disk in plaintext.
public enum Keychain {
    public static let defaultService = "com.herojoneslabs.serberus.commander.mdm"

    @discardableResult
    public static func set(_ value: String, account: String, service: String = defaultService) -> Bool {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        guard !value.isEmpty else { return true }  // empty = clear
        var attrs = query
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
    }

    public static func get(account: String, service: String = defaultService) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    public static func delete(account: String, service: String = defaultService) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
}
