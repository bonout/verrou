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
///
/// One keychain item per account (`user-key.<tag>`): an account's key never
/// opens another account's vault. The single item older versions kept
/// (`user-key`) is deleted the first time anything here runs.
enum AutofillSession {
    static let lifetime: TimeInterval = 5 * 60
    /// Setting (app group), on by default.
    static let enabledKey = "autofillWithoutFaceID"

    private struct Entry: Codable {
        let userKey: String
        let expires: Date
    }

    private static let service = "app.verrou.autofill.session"
    /// The account of the one item older versions kept.
    private static let legacyAccount = "user-key"

    private static func base(tag: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: "\(legacyAccount).\(tag)",
            kSecUseDataProtectionKeychain: true,
        ]
    }

    /// Deletes the single, account-less item of earlier versions: its key
    /// belongs to the account of the time, which is no longer named.
    private static func removeLegacy() {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: legacyAccount,
            kSecUseDataProtectionKeychain: true,
        ] as CFDictionary)
    }

    private static var defaults: UserDefaults {
        VerrouStorage.appGroupID.flatMap(UserDefaults.init(suiteName:)) ?? .standard
    }

    static var isEnabled: Bool {
        get { defaults.object(forKey: enabledKey) as? Bool ?? true }
        set {
            defaults.set(newValue, forKey: enabledKey)
            if !newValue { forgetAll() }
        }
    }

    /// Starts the 5 minutes (not extended by the fills that follow).
    static func remember(userKey: String, tag: String) {
        guard isEnabled,
              let data = try? JSONEncoder().encode(Entry(userKey: userKey, expires: Date().addingTimeInterval(lifetime)))
        else { return }
        forget(tag: tag)
        var query = base(tag: tag)
        query[kSecValueData] = data
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecAttrSynchronizable] = false
        SecItemAdd(query as CFDictionary, nil)
    }

    /// The account's user key while the 5 minutes last.
    static func userKey(tag: String) -> String? {
        guard isEnabled else { return nil }
        removeLegacy()
        var query = base(tag: tag)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let entry = try? JSONDecoder().decode(Entry.self, from: data) else { return nil }
        guard entry.expires > Date() else {
            forget(tag: tag)
            return nil
        }
        return entry.userKey
    }

    static func forget(tag: String) {
        removeLegacy()
        SecItemDelete(base(tag: tag) as CFDictionary)
    }

    /// Every account's key (the app locks, the setting is turned off), and
    /// the legacy one.
    static func forgetAll() {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecUseDataProtectionKeychain: true,
        ] as CFDictionary)
    }
}
