import Foundation

/// Destinations from the widgets and the control (`verrou://` links) and Shortcuts (`VerrouLinkCenter`).
extension PhoneModel {
    /// A destination given with the vault locked waits this long for the
    /// unlock: unlocking much later doesn't copy or open something
    /// unexpected.
    static let pendingLinkLifetime: TimeInterval = 120

    func open(_ link: VerrouLink) {
        // The Mac's request shows above everything, vault open or not.
        if link == .approval {
            Task { await remote.refresh() }
            return
        }
        guard lockState == .unlocked else {
            // Kept in memory only; the vault's Face ID comes up on its own.
            pendingLink = (link, Date())
            return
        }
        switch link {
        case .search(let query):
            searchPath = []
            if let query { searchQuery = query }
            tab = .search
        case .generator:
            tab = .generator
        case .scanCode:
            guard canEdit else {
                toast = Toast(message: String(localized: "Sign in to your Vaultwarden server to save one-time codes."),
                              detail: nil, failure: true)
                return
            }
            // The edit screen presents its own sheets: its draft is not
            // thrown away.
            guard editor == nil else {
                toast = Toast(message: String(localized: "Close the edit screen first."), detail: nil, failure: true)
                return
            }
            qrSheet = nil
            moveRequest = nil
            startOTPScan(.scan)
        case .item(let id):
            let id = session.resolveItemId(id: id)
            guard summary(id: id) != nil else {
                toast = Toast(message: String(localized: "Item not found"), detail: nil, failure: true)
                return
            }
            tab = .vault
            vaultPath = [.item(id)]
        case .copyPassword(let id):
            let id = session.resolveItemId(id: id)
            guard summary(id: id) != nil else {
                toast = Toast(message: String(localized: "Item not found"), detail: nil, failure: true)
                return
            }
            // The usual confirmations (protected item, hidden password)
            // and clipboard expiry.
            copyPassword(of: id)
        case .approval:
            break
        }
    }
}
