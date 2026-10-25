import Foundation
import WatchConnectivity

/// Hands the pinned one-time codes (`PinnedCodes`) to the Apple Watch app.
///
/// The only thing that goes to the Watch: the list the user pinned ("Show in
/// widgets and on Apple Watch"), never the vault, a password or a key. It
/// travels as the session's application context: the system keeps the latest
/// state and delivers it when the Watch app wakes (no need for both apps to
/// run), encrypted between the paired devices. The full list is sent each
/// time, so an unpinned code or a sign-out (an empty list) also reaches the
/// Watch, which then removes it from its own keychain. See SECURITY.md,
/// "Pinned one-time codes".
@MainActor
final class WatchSync: NSObject {
    /// Not in the demo vault: its items are never pinned.
    private var sendsCodes = false

    private var session: WCSession? {
        WCSession.isSupported() ? WCSession.default : nil
    }

    /// Starts the session at launch; the codes follow once it is active.
    func activate(sendsCodes: Bool) {
        self.sendsCodes = sendsCodes
        guard let session else { return }
        session.delegate = self
        session.activate()
    }

    /// Sends the codes as they are now, if a Watch with Verrou is there.
    func send() {
        guard sendsCodes, let session, session.activationState == .activated,
              session.isPaired, session.isWatchAppInstalled else { return }
        // An unreadable keychain (before the first unlock after a restart)
        // says nothing about the codes: the Watch keeps what it has.
        guard case .codes(let codes) = PinnedCodes.read(), let context = PinnedCodes.transferContext(codes) else { return }
        try? session.updateApplicationContext(context)
    }
}

extension WatchSync: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState,
                             error: Error?) {
        Task { @MainActor in send() }
    }

    /// The Watch app was installed or the Watch paired: it has no codes yet.
    nonisolated func sessionWatchStateDidChange(_ session: WCSession) {
        Task { @MainActor in send() }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    /// Another Watch was selected: the session starts again for it.
    nonisolated func sessionDidDeactivate(_ session: WCSession) {
        session.activate()
    }
}
