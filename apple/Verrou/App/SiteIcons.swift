import AppKit
import Observation

/// Icônes des sites, servies par le Vaultwarden du compte (`/icons/<site>/icon.png`).
///
/// Seul le nom du site part, vers son propre serveur, qui les récupère pour
/// nous ; rien ne touche le disque (session réseau éphémère, cache en
/// mémoire vidé au verrouillage) : la liste des sites ne reste pas en clair
/// sur le Mac.
@MainActor
@Observable
final class SiteIcons {
    /// `nil` : téléchargement en cours, ou pas d'icône (on garde l'initiale).
    private(set) var images: [String: NSImage] = [:]
    @ObservationIgnored private var requested: Set<String> = []
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

    /// L'icône si elle est déjà là ; sinon la demande, et la vue se mettra à jour.
    func image(for host: String) -> NSImage? {
        let site = Self.site(of: host)
        if let image = images[site] { return image }
        guard let server, !site.isEmpty, !requested.contains(site) else { return nil }
        requested.insert(site)
        Task { await load(site, from: server) }
        return nil
    }

    /// Sites déjà demandés (mesures).
    var requestedCount: Int { requested.count }

    func clear() {
        images.removeAll()
        requested.removeAll()
        fallback?.cancel()
        fallback = nil
    }

    private func load(_ site: String, from server: String) async {
        guard let data = await fetch(server: server, site: site),
              data != (await fallbackIcon(server: server)),
              self.server == server,
              let image = NSImage(data: data) else { return }
        images[site] = image
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
