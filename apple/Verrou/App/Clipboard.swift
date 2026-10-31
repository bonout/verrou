import AppKit

/// Clipboard for secrets.
///
/// - Marked "concealed" and "transient" (nspasteboard.org conventions):
///   clipboard history managers don't record it.
/// - Cleared after the chosen delay (90 s by default), but only if it still
///   holds what Verrou put there: we don't destroy what the user copied in
///   the meantime.
@MainActor
final class Clipboard {
    static let delayKey = "clipboardSeconds"
    static var clearDelay: Int {
        UserDefaults.standard.object(forKey: delayKey) as? Int ?? 90
    }
    static var clearedLabel: String {
        String(localized: "Cleared from the clipboard in \(DurationLabel.short(clearDelay))")
    }
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
        let delay = Self.clearDelay
        clearTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
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
