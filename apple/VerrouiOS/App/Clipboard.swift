import UIKit
import UniformTypeIdentifiers

/// The secrets' clipboard on the iPhone.
///
/// - `localOnly`: never sent to the other devices (Universal Clipboard).
/// - `expirationDate`: iOS itself erases the secret after the chosen delay
///   (90 s by default), even if Verrou was closed in the meantime.
/// - On lock, Verrou erases it if it still holds what Verrou put there
///   (`changeCount`), without reading its content or triggering the paste alert.
@MainActor
final class Clipboard {
    private var ownedChangeCount: Int?

    /// `expiresIn`: `nil` for a value that isn't secret.
    func copy(_ value: String, expiresIn seconds: TimeInterval?) {
        var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
        if let seconds { options[.expirationDate] = Date().addingTimeInterval(seconds) }
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: value]], options: options)
        ownedChangeCount = seconds == nil ? nil : UIPasteboard.general.changeCount
    }

    func clearIfOurs() {
        if let owned = ownedChangeCount, UIPasteboard.general.changeCount == owned {
            UIPasteboard.general.items = []
        }
        ownedChangeCount = nil
    }
}
