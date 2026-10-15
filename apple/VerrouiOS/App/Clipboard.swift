import UIKit
import UniformTypeIdentifiers

/// Presse-papiers des secrets sur l'iPhone.
///
/// - `localOnly` : jamais envoyé aux autres appareils (presse-papiers
///   universel).
/// - `expirationDate` : iOS efface lui-même le secret après le délai choisi
///   (90 s par défaut), même si Verrou a été fermé entre-temps.
/// - Au verrouillage, Verrou l'efface s'il contient encore ce qu'il y a mis
///   (`changeCount`), sans lire son contenu ni déclencher l'alerte de collage.
@MainActor
final class Clipboard {
    private var ownedChangeCount: Int?

    /// `expiresIn` : `nil` pour une valeur qui n'est pas secrète.
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
