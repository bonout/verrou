import Foundation
import Observation
import WatchConnectivity
import WidgetKit

/// The pinned codes on the wrist: what the iPhone sends (`WatchSync`) is
/// kept in the Watch's own keychain (`PinnedCodes`, group `app.verrou.watch`,
/// this device only, after the first unlock), where the complications read
/// it too.
///
/// No network, no vault, no Face ID: the Watch has nothing but the codes the
/// user pinned, and its own passcode and wrist detection protect them (the
/// codes are `privacySensitive`, hidden when the wrist is down). Pinning
/// something else, or unpinning, happens on the iPhone.
@MainActor
@Observable
final class WatchModel: NSObject {
    private(set) var codes: [PinnedCode] = PinnedCodes.all

    private var session: WCSession? {
        WCSession.isSupported() ? WCSession.default : nil
    }

    /// Starts the session at launch. The last context the iPhone sent is
    /// kept by the system: it is applied once the session is active, even if
    /// the app wasn't running when it arrived.
    func activate() {
        guard let session else { return }
        session.delegate = self
        session.activate()
    }

    /// Reads again what the iPhone last sent: a write that failed (keychain
    /// not readable yet) or a message that arrived in the background.
    func refresh() {
        guard let session, session.activationState == .activated else { return }
        let context = session.receivedApplicationContext
        guard !context.isEmpty, let received = PinnedCodes.codes(fromTransferContext: context) else { return }
        apply(received)
    }

    private func apply(_ received: [PinnedCode]) {
        // Shown even if the keychain refuses the write (before the first
        // unlock): the complications catch up at the next refresh.
        if received != codes { codes = received }
        guard PinnedCodes.read() != .codes(received) else { return }
        PinnedCodes.replace(with: received)
        WidgetCenter.shared.reloadAllTimelines()
    }
}

extension WatchModel: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState,
                             error: Error?) {
        Task { @MainActor in refresh() }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        // Decoded here: only the codes cross to the main actor, and a
        // message this version doesn't understand changes nothing.
        guard let received = PinnedCodes.codes(fromTransferContext: applicationContext) else { return }
        Task { @MainActor in apply(received) }
    }
}
