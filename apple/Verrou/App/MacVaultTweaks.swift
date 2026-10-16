import AppKit
import SwiftUI

// Retrait du partage et règles de correspondance (voir
// `Shared/Core/VaultTweaks.swift` pour les libellés communs).

extension AppModel {
    // MARK: Retrait du partage

    /// Les éléments qui peuvent quitter leur organisation.
    func unshareableIDs(_ ids: [String]) -> [String] {
        ids.filter { summary(id: $0)?.canUnshare == true }
    }

    /// « Retirer du partage… » : demande confirmation (la copie de
    /// l'organisation est supprimée définitivement).
    func requestUnshare(_ ids: [String]) {
        let candidates = unshareableIDs(ids)
        guard canEdit, !candidates.isEmpty else {
            toast = Toast(message: "Rien à retirer du partage",
                          detail: "Il faut pouvoir modifier l'élément et en voir le mot de passe", failure: true)
            return
        }
        let summaries = candidates.compactMap { summary(id: $0) }
        let title = summaries.count == 1 ? summaries[0].title : "\(summaries.count) éléments"
        var organizations: [String] = []
        for name in summaries.compactMap(\.sharing?.organization) where !organizations.contains(name) {
            organizations.append(name)
        }
        unshareError = nil
        unshareRequest = UnshareRequest(itemIDs: candidates, title: title, organizations: organizations)
    }

    /// Ramène les éléments dans le coffre personnel (en ligne seulement).
    func performUnshare(_ request: UnshareRequest) async {
        guard !unshareBusy else { return }
        let protected = request.itemIDs.filter { session.needsConfirmation(id: $0) }
        if let first = protected.first {
            let title = protected.count == 1 ? summary(id: first)?.title ?? request.title
                                             : "\(protected.count) éléments protégés"
            guard await confirmAccess(itemID: first, title: title) else { return }
            protected.forEach { session.authorizeItem(id: $0) }
        }
        unshareBusy = true
        unshareError = nil
        bulkProgress = (0, request.itemIDs.count)
        defer {
            unshareBusy = false
            bulkProgress = nil
        }
        do {
            let result = try await session.unshareItems(ids: request.itemIDs,
                                                        progress: UnshareProgressRelay(model: self))
            let moved = result.moved.count == 1 ? result.moved.first?.server : nil
            afterWrite(select: moved)
            pruneSelection()
            unshareRequest = nil
            toast = result.toast
        } catch {
            unshareError = Self.describe(error)
        }
    }

    /// La liste montre le site et l'utilisateur des passkeys : filtre
    /// « Passkeys », ou recherche `passkey:` / `has:passkey`.
    var showsPasskeyLines: Bool {
        if filter == .passkeys { return true }
        let words = query.lowercased().split(separator: " ")
        return words.contains { $0.hasPrefix("passkey:") || $0.hasPrefix("passkeys:") || $0 == "has:passkey" }
    }

    // MARK: Règles de correspondance

    func setDefaultMatchRule(_ rule: UriMatchRule) {
        try? session.setDefaultMatchRule(rule: rule)
        matchSettings = session.matchSettings()
    }

    func setFolderMatchRule(_ folderID: String, _ rule: UriMatchRule?) {
        try? session.setFolderMatchRule(folderId: folderID, rule: rule)
        matchSettings = session.matchSettings()
    }
}

/// Avancement du retrait du partage, relayé sur le fil principal.
final class UnshareProgressRelay: BulkProgress, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) { self.model = model }

    func progress(done: UInt32, total: UInt32) {
        Task { @MainActor [weak model] in model?.bulkProgress = (Int(done), Int(total)) }
    }
}
