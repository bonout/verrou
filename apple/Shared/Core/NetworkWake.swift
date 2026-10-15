import Foundation

/// Réveil du réseau avant la première synchronisation.
///
/// Le cœur Rust se connecte par des sockets BSD : sur iPhone, elles ne
/// déclenchent ni le VPN à la demande ni la mise en route de la radio
/// cellulaire (TN3151). Un serveur joignable seulement à la maison ou par
/// le VPN pouvait ainsi retenir la première synchronisation jusqu'au délai
/// de connexion. Une requête `URLSession` vers le serveur du compte, lancée
/// dès l'ouverture de l'app (pendant Face ID), fait monter le réseau : la
/// synchronisation qui suit le trouve prêt. Aucun identifiant n'est envoyé,
/// la réponse est ignorée.
enum NetworkWake {
    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 6
        configuration.waitsForConnectivity = false
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        return URLSession(configuration: configuration)
    }()

    static func nudge(server: String) {
        guard let url = URL(string: server)?.appending(path: "alive") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        let start = ContinuousClock.now
        Task.detached(priority: .userInitiated) {
            let outcome: String
            do {
                _ = try await session.data(for: request)
                outcome = "serveur joint"
            } catch {
                outcome = "sans réponse"
            }
            Perf.mark("réveil du réseau (\(outcome)) : \(Perf.ms(since: start)) ms")
        }
    }
}
