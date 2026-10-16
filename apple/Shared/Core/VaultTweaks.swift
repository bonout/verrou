import Foundation
import SwiftUI

// Retrait du partage, tri, filtre par défaut et règles de correspondance :
// libellés et réglages communs aux apps Mac et iPhone. Le travail (copie
// rechiffrée, correspondance, registre d'utilisation) est dans le cœur Rust.

// MARK: Tri

extension ResultOrder {
    /// Ordres proposés, dans l'ordre du menu.
    static let menu: [ResultOrder] = [.relevance, .title, .recentlyModified, .created, .lastUsed]

    var label: String {
        switch self {
        case .relevance: "Pertinence"
        case .title: "Titre"
        case .recentlyModified: "Modifiés récemment"
        case .created: "Date de création"
        case .lastUsed: "Dernière utilisation"
        }
    }

    /// Clé enregistrée dans les préférences de l'appareil.
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

/// Préférences de l'appareil (jamais synchronisées) : tri choisi et filtre
/// ouvert au déverrouillage.
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

/// Le filtre ouvert au déverrouillage (réglage de l'appareil).
enum DefaultFilter: String, CaseIterable, Identifiable {
    case all, favorites, withTotp, passkeys

    var id: String { rawValue }

    var label: String {
        switch self {
        case .all: "Tous les éléments"
        case .favorites: "Favoris"
        case .withTotp: "Codes à usage unique"
        case .passkeys: "Passkeys"
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
    /// « github.com · camille » : le site et l'utilisateur de la passkey.
    var passkeyLine: String? {
        guard let rpId = passkeyRpId else { return nil }
        guard let user = passkeyUserName, !user.isEmpty else { return rpId }
        return "\(rpId) · \(user)"
    }

    /// Dernière utilisation sur cet appareil, en clair (« il y a 3 jours »).
    var lastUsedLabel: String? {
        guard let lastUsed else { return nil }
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "fr_FR")
        formatter.unitsStyle = .full
        return formatter.localizedString(for: Date(timeIntervalSince1970: TimeInterval(lastUsed)), relativeTo: .now)
    }
}

// MARK: Retrait du partage

extension ItemSummary {
    /// Peut quitter son organisation : partagé, modifiable, mots de passe
    /// visibles, hors de la corbeille (le serveur vérifie aussi).
    var canUnshare: Bool {
        guard let sharing else { return false }
        return !sharing.readOnly && !sharing.hidePasswords && state != .trashed
    }
}

/// Demande de retrait du partage, en attente de confirmation.
struct UnshareRequest: Identifiable {
    let id = UUID()
    let itemIDs: [String]
    /// Titre de l'élément, ou « 3 éléments ».
    let title: String
    /// Organisations concernées, pour le message.
    let organizations: [String]

    var question: String {
        itemIDs.count == 1 ? "Retirer « \(title) » du partage ?" : "Retirer \(title) du partage ?"
    }

    var message: String {
        let from = organizations.count == 1 ? "de « \(organizations[0]) »" : "de leurs organisations"
        let what = itemIDs.count == 1 ? "Une copie personnelle est créée (historique, passkeys, codes, champs et pièces jointes compris), puis l'élément est supprimé définitivement \(from) : ses membres ne le verront plus."
            : "Des copies personnelles sont créées (historique, passkeys, codes, champs et pièces jointes compris), puis les éléments sont supprimés définitivement \(from) : leurs membres ne les verront plus."
        return what + " Demande une connexion au serveur."
    }
}

extension UnshareResult {
    /// « 2 éléments ramenés dans votre coffre, 1 ignoré (lecture seule) ».
    var toast: Toast {
        let n = moved.count
        var message = n == 1 ? "Élément ramené dans votre coffre" : "\(n) éléments ramenés dans votre coffre"
        if n == 0 { message = "Aucun élément retiré du partage" }
        var ignored: [String] = []
        let plural = { (count: UInt32) in count > 1 ? "s" : "" }
        if notShared > 0 { ignored.append("\(notShared) ignoré\(plural(notShared)) (déjà personnel\(plural(notShared)))") }
        if readOnly > 0 { ignored.append("\(readOnly) ignoré\(plural(readOnly)) (droit de modifier requis)") }
        if passwordsHidden > 0 { ignored.append("\(passwordsHidden) ignoré\(plural(passwordsHidden)) (mots de passe masqués)") }
        if inTrash > 0 { ignored.append("\(inTrash) ignoré\(plural(inTrash)) (dans la corbeille)") }
        if notFound > 0 { ignored.append("\(notFound) introuvable\(plural(notFound))") }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !failures.isEmpty {
            return Toast(message: message + ", \(failures.count) refusé\(failures.count > 1 ? "s" : "")",
                         detail: failures.joined(separator: "\n"), failure: true, seconds: 6)
        }
        return Toast(message: message, detail: nil, failure: n == 0, seconds: ignored.isEmpty ? 2.5 : 4)
    }
}

// MARK: Règles de correspondance

extension UriMatchRule: Identifiable {
    public var id: String { label }

    /// « Domaine de base », « Hôte »… (libellés du cœur Rust).
    var label: String { uriMatchLabel(rule: self) }

    /// Ce que fait la règle, en une phrase.
    var explanation: String {
        switch self {
        case .domain: "Le site et tous ses sous-domaines (et les domaines équivalents)."
        case .host: "Le même hôte, port compris : pas les sous-domaines."
        case .startsWith: "Les adresses qui commencent par celle du site."
        case .exact: "Seulement cette adresse exacte."
        case .regularExpression: "Les adresses qui vérifient l'expression régulière."
        case .never: "Jamais proposé au remplissage."
        }
    }

    static var all: [UriMatchRule] { uriMatchRules() }
}

extension LoginFields {
    /// Règles alignées sur `urls` (une par site, `nil` : par défaut).
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

    /// Retire les sites laissés vides, avec leur règle.
    mutating func dropEmptyURLs() {
        let kept = zip(urls, alignedMatches).filter { !$0.0.trimmingCharacters(in: .whitespaces).isEmpty }
        urls = kept.map(\.0)
        urlMatches = kept.map(\.1)
    }
}

extension MatchSettingsView {
    /// Règle qui s'applique aux sites sans règle d'un élément du dossier.
    func fallback(folderID: String?) -> UriMatchRule {
        folderRules.first { $0.folderId == folderID }?.rule ?? defaultRule
    }
}
