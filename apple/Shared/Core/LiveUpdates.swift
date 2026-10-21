import Foundation

/// Live updates, vault open: Vaultwarden's notification channel
/// (`/notifications/hub`, held by the Rust core, which keeps the access
/// token). An announced change triggers a sync (batched over a second and a
/// half), hence sharing notifications within a few seconds.
///
/// Channel lost: retry after 2 s, then 4, 8… up to 5 minutes, with a bit of
/// randomness (several devices don't come back together).
/// Server without the channel (`ENABLE_WEBSOCKET=false`): we stop, the
/// periodic sync remains.
@MainActor
final class LiveUpdates {
    /// Channel open right now.
    private(set) var connected = false
    /// The server doesn't have the channel.
    private(set) var unsupported = false

    private var task: Task<Void, Never>?
    private var pendingSync: Task<Void, Never>?

    var isRunning: Bool { task != nil }

    /// `sync`: sync (then examine what's new). `expired`: the session is no
    /// longer valid.
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
                    // Neither the vault nor sharing: nothing to reload.
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

    /// A single sync for a burst of changes.
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
