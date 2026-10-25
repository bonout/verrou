import Foundation
import Security

/// The login filled last, for 90 seconds: a two-step form (username, then
/// password on the next page) asks the extension twice for the same login.
/// The second time, the tapped suggestion fills right away, without Face ID
/// or an interface (`provideCredentialWithoutUserInteraction`).
///
/// Only this login, and only if the suggestion designates it: never the vault
/// key, never another item, never a protected one ("re-ask for the master
/// password"). In the keychain of this device, readable while it is
/// unlocked, never synced.
enum RecentFill {
    static let lifetime: TimeInterval = 90

    private struct Entry: Codable {
        let itemID: String
        let user: String
        let password: String
        let expires: Date
    }

    private static var base: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app.verrou.autofill.recent-fill",
            kSecAttrAccount: "last",
            kSecUseDataProtectionKeychain: true,
        ]
    }

    static func remember(itemID: String, user: String, password: String) {
        let entry = Entry(itemID: itemID, user: user, password: password, expires: Date().addingTimeInterval(lifetime))
        guard let data = try? JSONEncoder().encode(entry) else { return }
        forget()
        var query = base
        query[kSecValueData] = data
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecAttrSynchronizable] = false
        SecItemAdd(query as CFDictionary, nil)
    }

    /// The login if it is the one filled less than 90 seconds ago.
    static func credential(for itemID: String) -> (user: String, password: String)? {
        var query = base
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let entry = try? JSONDecoder().decode(Entry.self, from: data) else { return nil }
        guard entry.expires > Date() else {
            forget()
            return nil
        }
        return entry.itemID == itemID ? (entry.user, entry.password) : nil
    }

    static func forget() {
        SecItemDelete(base as CFDictionary)
    }
}
