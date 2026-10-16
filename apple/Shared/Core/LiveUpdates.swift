import Foundation

/// Mises à jour en direct, coffre ouvert : le canal de notifications de
/// Vaultwarden (`/notifications/hub`, tenu par le cœur Rust, qui garde le
/// jeton d'accès). Un changement annoncé déclenche une synchronisation
/// (regroupée sur une seconde et demie), donc les notifications du partage
/// en quelques secondes.
///
/// Canal perdu : nouvel essai après 2 s, puis 4, 8… jusqu'à 5 minutes, avec
/// un peu de hasard (plusieurs appareils ne reviennent pas ensemble).
/// Serveur sans canal (`ENABLE_WEBSOCKET=false`) : on s'arrête, la
/// synchronisation périodique reste.
@MainActor
final class LiveUpdates {
    /// Canal ouvert en ce moment.
    private(set) var connected = false
    /// Le serveur n'a pas le canal.
    private(set) var unsupported = false

    private var task: Task<Void, Never>?
    private var pendingSync: Task<Void, Never>?

    var isRunning: Bool { task != nil }

    /// `sync` : synchroniser (puis examiner les nouveautés). `expired` :
    /// la session n'est plus valable.
    func start(session: VaultSession, sync: @escaping @MainActor () async -> Void,
               expired: @escaping @MainActor () -> Void) {
        guard task == nil, !unsupported else { return }
        task = Task { [weak self] in
            var delay = 2.0
            while !Task.isCancelled {
                do {
                    let change = try await session.waitForServerChange()
                    delay = 2
                    guard let self else { return }
                    self.connected = true
                    if change.fromThisDevice { continue }
                    switch change.kind {
                    // Ni le coffre ni le partage : rien à relire.
                    case .sends, .authRequest, .other: continue
                    default: self.scheduleSync(sync)
                    }
                } catch VerrouError.Locked {
                    break
                } catch VerrouError.NotFound {
                    self?.unsupported = true
                    break
                } catch VerrouError.SessionExpired {
                    expired()
                    break
                } catch {
                    self?.connected = false
                    let wait = delay * Double.random(in: 0.8...1.2)
                    delay = min(delay * 2, 300)
                    try? await Task.sleep(for: .seconds(wait))
                }
            }
            self?.connected = false
            self?.task = nil
        }
    }

    func stop(session: VaultSession) {
        task?.cancel()
        task = nil
        pendingSync?.cancel()
        pendingSync = nil
        connected = false
        session.stopServerChanges()
    }

    /// Une seule synchronisation pour une rafale de changements.
    private func scheduleSync(_ sync: @escaping @MainActor () async -> Void) {
        guard pendingSync == nil else { return }
        pendingSync = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(1500))
            self?.pendingSync = nil
            guard !Task.isCancelled else { return }
            await sync()
        }
    }
}
