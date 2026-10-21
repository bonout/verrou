import Foundation
import SwiftUI

// Removal from sharing, sorting, default filter and match rules: labels
// and settings shared by the Mac and iPhone apps. The work (re-encrypted
// copy, matching, usage log) is in the Rust core.

// MARK: Sorting

extension ResultOrder {
    /// Orders offered, in menu order.
    static let menu: [ResultOrder] = [.relevance, .title, .recentlyModified, .created, .lastUsed]

    var label: String {
        switch self {
        case .relevance: String(localized: "Relevance")
        case .title: String(localized: "Title")
        case .recentlyModified: String(localized: "Recently modified")
        case .created: String(localized: "Date created")
        case .lastUsed: String(localized: "Last used")
        }
    }

    /// Key saved in the device's preferences.
    var storageKey: String {
        switch self {
        case .relevance: "relevance"
        case .title: "title"
        case .recentlyModified: "modified"
        case .created: "created"
        case .lastUsed: "lastUsed"
        }
    }

    init?(storageKey: String) {
        guard let order = Self.menu.first(where: { $0.storageKey == storageKey }) else { return nil }
        self = order
    }
}

/// Device preferences (never synced): chosen sort and filter opened on
/// unlock.
enum DevicePreferences {
    private static let sortKey = "verrou.sort"
    private static let defaultFilterKey = "verrou.defaultFilter"

    static var sort: ResultOrder {
        get { UserDefaults.standard.string(forKey: sortKey).flatMap(ResultOrder.init(storageKey:)) ?? .relevance }
        set { UserDefaults.standard.set(newValue.storageKey, forKey: sortKey) }
    }

    static var defaultFilter: DefaultFilter {
        get { UserDefaults.standard.string(forKey: defaultFilterKey).flatMap(DefaultFilter.init(rawValue:)) ?? .all }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: defaultFilterKey) }
    }
}

/// The filter opened on unlock (device setting).
enum DefaultFilter: String, CaseIterable, Identifiable {
    case all, favorites, withTotp, passkeys

    var id: String { rawValue }

    var label: String {
        switch self {
        case .all: String(localized: "All items")
        case .favorites: String(localized: "Favorites")
        case .withTotp: String(localized: "One-time codes")
        case .passkeys: String(localized: "Passkeys")
        }
    }

    var filter: SidebarFilter {
        switch self {
        case .all: .all
        case .favorites: .favorites
        case .withTotp: .withTotp
        case .passkeys: .passkeys
        }
    }
}

// MARK: Passkeys

extension ItemSummary {
    /// "github.com · camille": the passkey's site and user.
    var passkeyLine: String? {
        guard let rpId = passkeyRpId else { return nil }
        guard let user = passkeyUserName, !user.isEmpty else { return rpId }
        return "\(rpId) · \(user)"
    }

    /// Last use on this device, in words ("3 days ago").
    var lastUsedLabel: String? {
        guard let lastUsed else { return nil }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: Date(timeIntervalSince1970: TimeInterval(lastUsed)), relativeTo: .now)
    }
}

// MARK: Removal from sharing

extension ItemSummary {
    /// Can leave its organization: shared, editable, passwords visible, not
    /// in the trash (the server checks too).
    var canUnshare: Bool {
        guard let sharing else { return false }
        return !sharing.readOnly && !sharing.hidePasswords && state != .trashed
    }
}

/// Request to remove from sharing, awaiting confirmation.
struct UnshareRequest: Identifiable {
    let id = UUID()
    let itemIDs: [String]
    /// The item's title, or "3 items".
    let title: String
    /// Organizations concerned, for the message.
    let organizations: [String]

    var question: String {
        itemIDs.count == 1 ? String(localized: "Remove “\(title)” from sharing?") : String(localized: "Remove \(title) from sharing?")
    }

    var message: String {
        let from = organizations.count == 1 ? String(localized: "from “\(organizations[0])”") : String(localized: "from their organizations")
        let what = itemIDs.count == 1 ? String(localized: "A personal copy is created (history, passkeys, codes, fields and attachments included), then the item is permanently deleted \(from): its members will no longer see it.")
            : String(localized: "Personal copies are created (history, passkeys, codes, fields and attachments included), then the items are permanently deleted \(from): their members will no longer see them.")
        return what + " " + String(localized: "Requires a connection to the server.")
    }
}

extension UnshareResult {
    /// "2 items moved back to your vault, 1 skipped (read-only)".
    var toast: Toast {
        let n = moved.count
        var message = n == 1 ? String(localized: "Item moved back to your vault") : String(localized: "\(n) items moved back to your vault")
        if n == 0 { message = String(localized: "No item removed from sharing") }
        var ignored: [String] = []
        if notShared > 0 { ignored.append(notShared > 1 ? String(localized: "\(notShared) skipped items (already personal)") : String(localized: "\(notShared) skipped item (already personal)")) }
        if readOnly > 0 { ignored.append(readOnly > 1 ? String(localized: "\(readOnly) skipped items (edit permission required)") : String(localized: "\(readOnly) skipped item (edit permission required)")) }
        if passwordsHidden > 0 { ignored.append(passwordsHidden > 1 ? String(localized: "\(passwordsHidden) skipped items (passwords hidden)") : String(localized: "\(passwordsHidden) skipped item (passwords hidden)")) }
        if inTrash > 0 { ignored.append(inTrash > 1 ? String(localized: "\(inTrash) skipped items (in the trash)") : String(localized: "\(inTrash) skipped item (in the trash)")) }
        if notFound > 0 { ignored.append(notFound > 1 ? String(localized: "\(notFound) items not found") : String(localized: "\(notFound) item not found")) }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !failures.isEmpty {
            return Toast(message: message + ", " + (failures.count > 1 ? String(localized: "\(failures.count) refused items") : String(localized: "\(failures.count) refused item")),
                         detail: failures.joined(separator: "\n"), failure: true, seconds: 6)
        }
        return Toast(message: message, detail: nil, failure: n == 0, seconds: ignored.isEmpty ? 2.5 : 4)
    }
}

// MARK: Match rules

extension UriMatchRule: Identifiable {
    public var id: String { uriMatchLabel(rule: self) }

    /// "Base domain", "Host"… (labels from the Rust core, translated).
    var label: String { CoreText.localized(uriMatchLabel(rule: self)) }

    /// What the rule does, in one sentence.
    var explanation: String {
        switch self {
        case .domain: String(localized: "The site and all its subdomains (and equivalent domains).")
        case .host: String(localized: "The same host, port included: not the subdomains.")
        case .startsWith: String(localized: "Addresses that start with the site's.")
        case .exact: String(localized: "Only this exact address.")
        case .regularExpression: String(localized: "Addresses that match the regular expression.")
        case .never: String(localized: "Never offered for filling.")
        }
    }

    static var all: [UriMatchRule] { uriMatchRules() }
}

extension LoginFields {
    /// Rules aligned with `urls` (one per site, `nil`: default).
    private var alignedMatches: [UriMatchRule?] {
        let current = urlMatches ?? []
        return urls.indices.map { current.indices.contains($0) ? current[$0] : nil }
    }

    func matchRule(at index: Int) -> UriMatchRule? {
        alignedMatches.indices.contains(index) ? alignedMatches[index] : nil
    }

    mutating func setMatchRule(_ rule: UriMatchRule?, at index: Int) {
        var list = alignedMatches
        guard list.indices.contains(index) else { return }
        list[index] = rule
        urlMatches = list
    }

    mutating func appendURL(_ url: String = "") {
        var list = alignedMatches
        urls.append(url)
        list.append(nil)
        urlMatches = list
    }

    mutating func removeURL(at index: Int) {
        var list = alignedMatches
        guard urls.indices.contains(index) else { return }
        urls.remove(at: index)
        list.remove(at: index)
        urlMatches = list
    }

    /// Removes the sites left empty, with their rule.
    mutating func dropEmptyURLs() {
        let kept = zip(urls, alignedMatches).filter { !$0.0.trimmingCharacters(in: .whitespaces).isEmpty }
        urls = kept.map(\.0)
        urlMatches = kept.map(\.1)
    }
}

extension MatchSettingsView {
    /// Rule that applies to sites without a rule of an item in the folder.
    func fallback(folderID: String?) -> UriMatchRule {
        folderRules.first { $0.folderId == folderID }?.rule ?? defaultRule
    }
}
