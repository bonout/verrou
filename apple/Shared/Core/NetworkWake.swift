import Foundation

/// Wakes the network up before the first sync.
///
/// The Rust core connects through BSD sockets: on iPhone, they trigger
/// neither VPN On Demand nor powering up the cellular radio (TN3151). A
/// server reachable only at home or through the VPN could thus hold the
/// first sync until the connection timeout. A `URLSession` request to the
/// account's server, started as soon as the app opens (during Face ID),
/// brings the network up: the sync that follows finds it ready. No
/// credential is sent, the response is ignored.
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
                outcome = "server reached"
            } catch {
                outcome = "no response"
            }
            Perf.mark("network wake (\(outcome)): \(Perf.ms(since: start)) ms")
        }
    }
}
