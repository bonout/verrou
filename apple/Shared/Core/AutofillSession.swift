import Foundation
import Security

/// iPhone AutoFill: after Face ID (or the master password) in the
/// extension, the next fills on any site skip Face ID for 5 minutes, as
/// in other password managers. A tapped suggestion then fills without an
/// interface (`provideCredentialWithoutUserInteraction`), and the list
/// opens at once.
///
/// The user's key (what Face ID unseals) is kept in this device's keychain,
/// readable only while the iPhone is unlocked, never synced, and erased
/// when the 5 minutes are up, when Verrou locks in the app, or when the
/// setting is turned off. Protected items ("re-ask for the master
/// password") and passkeys still ask every time.
enum AutofillSession {
    static let lifetime: TimeInterval = 5 * 60
    /// Setting (app group), on by default.
    static let enabledKey = "autofillWithoutFaceID"

    private struct Entry: Codable {
        let userKey: String
        let expires: Date
    }

    private static var base: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app.verrou.autofill.session",
            kSecAttrAccount: "user-key",
            kSecUseDataProtectionKeychain: true,
        ]
    }

    private static var defaults: UserDefaults {
        VerrouStorage.appGroupID.flatMap(UserDefaults.init(suiteName:)) ?? .standard
    }

    static var isEnabled: Bool {
        get { defaults.object(forKey: enabledKey) as? Bool ?? true }
        set {
            defaults.set(newValue, forKey: enabledKey)
            if !newValue { forget() }
        }
    }

    /// Starts the 5 minutes (not extended by the fills that follow).
    static func remember(userKey: String) {
        guard isEnabled,
              let data = try? JSONEncoder().encode(Entry(userKey: userKey, expires: Date().addingTimeInterval(lifetime)))
        else { return }
        forget()
        var query = base
        query[kSecValueData] = data
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecAttrSynchronizable] = false
        SecItemAdd(query as CFDictionary, nil)
    }

    /// The user's key while the 5 minutes last.
    static func userKey() -> String? {
        guard isEnabled else { return nil }
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
        return entry.userKey
    }

    static func forget() {
        SecItemDelete(base as CFDictionary)
    }
}
