import Foundation
import Security

/// The login filled last, for 90 seconds: a two-step form (username, then
/// password on the next page) asks the extension twice for the same login.
/// The second time, the tapped suggestion fills right away, without Face ID
/// or an interface (`provideCredentialWithoutUserInteraction`); a list
/// opened for the same site (key icon) offers it at the top of the lock
/// screen ("Continue as…", `AutoFillModel.recentLogin`).
///
/// Only this login, and only if the suggestion designates it or the list is
/// for its site: never the vault key, never another item, never a protected
/// one ("re-ask for the master password"). In the keychain of this device,
/// readable while it is unlocked, never synced.
enum RecentFill {
    static let lifetime: TimeInterval = 90

    private struct Entry: Codable {
        let itemID: String
        let user: String
        let password: String
        let expires: Date
        /// Hosts where it was filled and of its own site; nil for an entry
        /// written by an earlier version (no list offer).
        var sites: [String]?
    }

    private static var base: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app.verrou.autofill.recent-fill",
            kSecAttrAccount: "last",
            kSecUseDataProtectionKeychain: true,
        ]
    }

    static func remember(itemID: String, user: String, password: String, sites: [String]) {
        let entry = Entry(itemID: itemID, user: user, password: password, expires: Date().addingTimeInterval(lifetime),
                          sites: sites.map { $0.lowercased() })
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
        guard let entry = current(), entry.itemID == itemID else { return nil }
        return (entry.user, entry.password)
    }

    static func isLogin(user: String, password: String, site: String) -> Bool {
        guard let entry = current(), let sites = entry.sites else { return false }
        return entry.user == user && entry.password == password && sites.contains { sameSite(site, $0) }
    }

    /// The login filled less than 90 seconds ago on one of these sites (a
    /// list request's): its identifier and user, not its password, read
    /// again when the user chooses it.
    static func login(forSites hosts: [String]) -> (itemID: String, user: String)? {
        guard let entry = current(), let sites = entry.sites,
              hosts.contains(where: { host in sites.contains { sameSite(host, $0) } }) else { return nil }
        return (entry.itemID, entry.user)
    }

    /// The same host, "www." aside: the two pages of a sign-in. Not a parent
    /// or a subdomain ("example.com" and "pages.example.com" may have
    /// different owners: shared hosting, user pages).
    static func sameSite(_ first: String, _ second: String) -> Bool {
        func bare(_ host: String) -> String {
            let host = host.lowercased()
            return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
        }
        let a = bare(first), b = bare(second)
        return !a.isEmpty && a == b
    }

    /// The entry while it is valid; erased once expired.
    private static func current() -> Entry? {
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
        return entry
    }

    static func forget() {
        SecItemDelete(base as CFDictionary)
    }
}
