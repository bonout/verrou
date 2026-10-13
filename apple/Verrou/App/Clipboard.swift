import AppKit

/// Presse-papiers des secrets.
///
/// - Marqué « dissimulé » et « transitoire » (conventions nspasteboard.org) :
///   les gestionnaires d'historique du presse-papiers ne l'enregistrent pas.
/// - Effacé après 90 s, mais seulement s'il contient encore ce que Verrou y a
///   mis : on ne détruit pas ce que l'utilisateur a copié entre-temps.
@MainActor
final class Clipboard {
    static let clearDelay: TimeInterval = 90
    private var ownedChangeCount: Int?
    private var clearTask: Task<Void, Never>?

    func copy(_ value: String, concealed: Bool) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
        if concealed {
            pasteboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            pasteboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
        }
        ownedChangeCount = pasteboard.changeCount
        clearTask?.cancel()
        guard concealed else { return }
        clearTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.clearDelay))
            guard !Task.isCancelled else { return }
            self?.clearIfOurs()
        }
    }

    func clearIfOurs() {
        if let owned = ownedChangeCount, NSPasteboard.general.changeCount == owned {
            NSPasteboard.general.clearContents()
        }
        ownedChangeCount = nil
    }
}
