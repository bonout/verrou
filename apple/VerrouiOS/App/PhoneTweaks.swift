import SwiftUI

// Retrait du partage et règles de correspondance sur l'iPhone (libellés
// communs : `Shared/Core/VaultTweaks.swift`).

extension PhoneModel {
    // MARK: Retrait du partage

    func unshareableIDs(_ ids: [String]) -> [String] {
        ids.filter { summary(id: $0)?.canUnshare == true }
    }

    /// « Retirer du partage… » : demande confirmation.
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
        unshareRequest = UnshareRequest(itemIDs: candidates, title: title, organizations: organizations)
    }

    /// Ramène les éléments dans le coffre personnel (en ligne seulement).
    func performUnshare(_ request: UnshareRequest) async {
        unshareRequest = nil
        guard canEdit, !unshareBusy else { return }
        let protected = request.itemIDs.filter { session.needsConfirmation(id: $0) }
        if let first = protected.first {
            let title = protected.count == 1 ? summary(id: first)?.title ?? request.title
                                             : "\(protected.count) éléments protégés"
            guard await confirmAccess(itemID: first, title: title) else { return }
            protected.forEach { session.authorizeItem(id: $0) }
        }
        unshareBusy = true
        defer { unshareBusy = false }
        do {
            let result = try await session.unshareItems(ids: request.itemIDs, progress: NoBulkProgress())
            // La fiche ouverte suit l'élément vers sa copie personnelle.
            let moved = Dictionary(result.moved.map { ($0.temporary, $0.server) }, uniquingKeysWith: { a, _ in a })
            let follow = { (path: [Route]) in
                path.map { route -> Route in
                    if case .item(let id) = route, let new = moved[id] { return .item(new) }
                    return route
                }
            }
            vaultPath = follow(vaultPath)
            searchPath = follow(searchPath)
            afterWrite()
            toast = result.toast
        } catch {
            toast = Toast(message: "Retrait du partage impossible", detail: ErrorText.describe(error), failure: true,
                          seconds: 5)
        }
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

/// Confirmation de « Retirer du partage… », posée sur les onglets.
struct UnsharePresentation: ViewModifier {
    @Environment(PhoneModel.self) private var model

    func body(content: Content) -> some View {
        content
            .confirmationDialog(model.unshareRequest?.question ?? "",
                                isPresented: Binding(get: { model.unshareRequest != nil },
                                                     set: { if !$0 { model.unshareRequest = nil } }),
                                titleVisibility: .visible,
                                presenting: model.unshareRequest) { request in
                Button(request.itemIDs.count == 1 ? "Retirer du partage" : "Retirer \(request.itemIDs.count) éléments",
                       role: .destructive) {
                    Task { await model.performUnshare(request) }
                }
                Button("Annuler", role: .cancel) { model.unshareRequest = nil }
            } message: { request in
                Text(request.message)
            }
            .overlay {
                if model.unshareBusy {
                    ProgressView("Retrait du partage…")
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .accessibilityIdentifier("unshare-progress")
                }
            }
    }
}
