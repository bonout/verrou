import AppKit

/// Clipboard for secrets.
///
/// - Marked "concealed" and "transient" (nspasteboard.org conventions):
///   clipboard history managers don't record it.
/// - Cleared after 90 s, but only if it still holds what Verrou put there:
///   we don't destroy what the user copied in the meantime.
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
