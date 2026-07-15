// SPDX-License-Identifier: Apache-2.0
import Foundation
import Security

struct SecureSessionStore: Sendable {
    struct Session: Codable, Sendable {
        let accessToken: String
        let approverID: String
        let profileID: String
        let expiresAt: String
        let deviceKeyID: String?
        let appAttestKeyID: String?
    }

    private let service = "ai.emiliaprotocol.approver.session"
    private let account = "mobile-access-token"

    func load() throws -> Session? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess,
              let data = item as? Data
        else { throw StoreError.keychain(status) }
        do {
            return try JSONDecoder().decode(Session.self, from: data)
        } catch {
            try? clear()
            throw StoreError.invalidValue
        }
    }

    func save(_ value: Session) throws {
        let data = try JSONEncoder().encode(value)
        guard !data.isEmpty else { throw StoreError.invalidValue }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw StoreError.keychain(update) }
        let insert = query.merging(attributes) { _, replacement in replacement }
        let status = SecItemAdd(insert as CFDictionary, nil)
        guard status == errSecSuccess else { throw StoreError.keychain(status) }
    }

    func clear() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw StoreError.keychain(status) }
    }

    enum StoreError: Error {
        case invalidValue
        case keychain(OSStatus)
    }
}
