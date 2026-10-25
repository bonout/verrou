import AppIntents
import Foundation
import WidgetKit

/// The codes pinned for the widgets, Shortcuts and the Apple Watch
/// (`PinnedCodes`): the app is the only one that writes them, vault open.
///
/// Pinning reads the item's TOTP field (the same `reveal` as showing it)
/// and checks that Swift computes the Rust core's code; afterwards, each
/// list reload (unlock, sync, write) brings the store in line with the
/// vault: titles and sites follow, a changed item's seed is read again
/// (only when its revision changes, so that "last used" isn't touched at
/// each sync), and an item deleted, archived, trashed, made protected or
/// whose organization now hides passwords leaves the store.
extension PhoneModel {
    /// The item's code can be shown outside the vault: a code, active,
    /// neither protected nor hidden by its organization. An account's
    /// vault only (not the demo vault).
    func canPinCode(_ summary: ItemSummary) -> Bool {
        mode == .vaultwarden && summary.hasTotp && !summary.reprompt && summary.state == .active
            && summary.sharing?.hidePasswords != true
    }

    func setCodePinned(_ pinned: Bool, itemID: String) {
        guard pinned else {
            PinnedCodes.remove(id: itemID)
            pinnedCodeIDs.remove(itemID)
            pinnedCodesChanged()
            return
        }
        guard let summary = summary(id: itemID), canPinCode(summary) else { return }
        guard let code = readPinnedCode(summary) else {
            toast = Toast(message: String(localized: "This code can't be shown in widgets"),
                          detail: String(localized: "Verrou can't compute it outside the vault (Steam or unusual settings)."),
                          failure: true, seconds: 4)
            return
        }
        guard PinnedCodes.save(code) else {
            toast = Toast(message: String(localized: "Could not pin the code"),
                          detail: String(localized: "This iPhone's keychain refused it."), failure: true)
            return
        }
        pinnedCodeIDs.insert(itemID)
        pinnedCodesChanged()
        toast = Toast(message: String(localized: "Code pinned"),
                      detail: String(localized: "Add the One-time code widget to your Home Screen or Lock Screen."), seconds: 3.5)
    }

    /// Sign-out: nothing of the account stays outside the vault.
    func unpinAllCodes() {
        PinnedCodes.removeAll()
        pinnedCodeIDs = []
        pinnedCodesChanged()
    }

    /// Brings the store in line with the vault just reloaded.
    func refreshPinnedCodes() {
        guard mode == .vaultwarden, session.isUnlocked() else { return }
        guard case .codes(let stored) = PinnedCodes.read() else { return }
        // An unreadable list (an error, not an empty vault) mustn't unpin
        // everything.
        guard !stored.isEmpty, !summaries.isEmpty else {
            pinnedCodeIDs = Set(stored.map(\.id))
            return
        }
        var updated: [PinnedCode] = []
        for var code in stored {
            // An item created offline gets its final identifier at sending.
            let id = session.resolveItemId(id: code.id)
            guard let summary = summary(id: id), canPinCode(summary) else { continue }
            if summary.modified != code.revision || id != code.id {
                guard let fresh = readPinnedCode(summary) else { continue }
                code = fresh
            }
            code.title = summary.title
            code.host = summary.host
            updated.append(code)
        }
        pinnedCodeIDs = Set(updated.map(\.id))
        guard updated != stored else { return }
        PinnedCodes.replace(with: updated)
        pinnedCodesChanged()
    }

    /// The item's code parameters, if Swift computes the same code as the
    /// Rust core right now.
    private func readPinnedCode(_ summary: ItemSummary) -> PinnedCode? {
        guard let field = detail(id: summary.id)?.fields.first(where: { $0.fieldType == .totp }), !field.hidden,
              let value = try? session.reveal(id: summary.id, fieldId: field.id) else { return nil }
        let now = Date()
        guard let code = PinnedCode(id: summary.id, title: summary.title, host: summary.host,
                                    revision: summary.modified, totp: value),
              let reference = vault.currentCode(of: summary.id, at: now),
              reference.code == code.code(at: now).value else { return nil }
        return code
    }

    /// The widgets redraw, the Apple Watch gets the new list, Siri learns
    /// the new names.
    private func pinnedCodesChanged() {
        WidgetCenter.shared.reloadAllTimelines()
        watchSync.send()
        VerrouShortcuts.updateAppShortcutParameters()
    }
}
