import Observation
import SwiftUI
#if canImport(AppKit)
import AppKit

/// Image du système : `NSImage` sur le Mac, `UIImage` sur l'iPhone.
typealias PlatformImage = NSImage

extension Image {
    init(platformImage: PlatformImage) { self.init(nsImage: platformImage) }
}
#else
import UIKit

/// Image du système : `NSImage` sur le Mac, `UIImage` sur l'iPhone.
typealias PlatformImage = UIImage

extension Image {
    init(platformImage: PlatformImage) { self.init(uiImage: platformImage) }
}
#endif

/// Icônes des sites, servies par le Vaultwarden du compte (`/icons/<site>/icon.png`).
///
/// Seul le nom du site part, vers son propre serveur, qui les récupère pour
/// nous ; rien ne touche le disque (session réseau éphémère, cache en
/// mémoire vidé au verrouillage) : la liste des sites ne reste pas en clair
/// sur l'appareil.
@MainActor
@Observable
final class SiteIcons {
    /// L'icône d'un site : observée séparément, pour qu'une icône arrivée ne
    /// redessine que les vues qui la montrent (pas toutes les lignes).
    @MainActor
    @Observable
    final class Entry {
        /// `nil` : téléchargement en cours, ou pas d'icône (on garde l'initiale).
        fileprivate(set) var image: PlatformImage?
    }

    /// Sites demandés. Hors observation : en ajouter un pendant le calcul
    /// d'une vue n'invalide aucune autre vue.
    @ObservationIgnored private var entries: [String: Entry] = [:]
    /// L'image générique que Vaultwarden renvoie quand il ne trouve rien.
    @ObservationIgnored private var fallback: Task<Data?, Never>?
    @ObservationIgnored private let urlSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.httpMaximumConnectionsPerHost = 4
        return URLSession(configuration: configuration)
    }()

    /// Adresse du serveur ; `nil` (coffre fictif, réglage désactivé) : aucune icône.
    var server: String? {
        didSet { if oldValue != server { clear() } }
    }

    /// Icônes déjà arrivées, par site (mesures, tests).
    var images: [String: PlatformImage] {
        entries.compactMapValues(\.image)
    }

    /// L'icône si elle est déjà là ; sinon la demande, et la vue se mettra à jour.
    func image(for host: String) -> PlatformImage? {
        let site = Self.site(of: host)
        if let entry = entries[site] { return entry.image }
        guard let server, !site.isEmpty else { return nil }
        let entry = Entry()
        entries[site] = entry
        Task { await load(site, into: entry, from: server) }
        return entry.image
    }

    /// Sites déjà demandés (mesures).
    var requestedCount: Int { entries.count }

    func clear() {
        // Les vues qui montrent une icône la perdent tout de suite.
        for entry in entries.values { entry.image = nil }
        entries.removeAll()
        fallback?.cancel()
        fallback = nil
    }

    private func load(_ site: String, into entry: Entry, from server: String) async {
        guard let data = await fetch(server: server, site: site),
              data != (await fallbackIcon(server: server)),
              self.server == server else { return }
        // Décodée hors du fil principal : le défilement n'a plus qu'à l'afficher.
        let image = await Task.detached(priority: .utility) { Self.decoded(data) }.value
        guard let image, self.server == server, entries[site] === entry else { return }
        entry.image = image
    }

    nonisolated private static func decoded(_ data: Data) -> PlatformImage? {
        #if canImport(UIKit)
        guard let image = UIImage(data: data) else { return nil }
        return image.preparingForDisplay() ?? image
        #else
        return NSImage(data: data)
        #endif
    }

    private func fallbackIcon(server: String) async -> Data? {
        if let fallback { return await fallback.value }
        let task = Task { await fetch(server: server, site: "verrou-sans-icone.invalid") }
        fallback = task
        return await task.value
    }

    private func fetch(server: String, site: String) async -> Data? {
        guard let url = URL(string: "\(server)/icons/\(site)/icon.png"),
              let (data, response) = try? await urlSession.data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return data
    }

    /// Le nom de domaine seul : ni port, ni majuscules.
    static func site(of host: String) -> String {
        let name = host.split(separator: ":").first.map(String.init) ?? host
        return name.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
    }
}
