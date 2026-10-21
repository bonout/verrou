import SwiftUI

// Removal from sharing and match rules on the iPhone (shared labels:
// `Shared/Core/VaultTweaks.swift`).

extension PhoneModel {
    // MARK: Removal from sharing

    func unshareableIDs(_ ids: [String]) -> [String] {
        ids.filter { summary(id: $0)?.canUnshare == true }
    }

    /// "Remove from sharing…": asks for confirmation.
    func requestUnshare(_ ids: [String]) {
        let candidates = unshareableIDs(ids)
        guard canEdit, !candidates.isEmpty else {
            toast = Toast(message: String(localized: "Nothing to remove from sharing"),
                          detail: String(localized: "You must be able to edit the item and see its password"), failure: true)
            return
        }
        let summaries = candidates.compactMap { summary(id: $0) }
        let title = summaries.count == 1 ? summaries[0].title : String(localized: "\(summaries.count) items")
        var organizations: [String] = []
        for name in summaries.compactMap(\.sharing?.organization) where !organizations.contains(name) {
            organizations.append(name)
        }
        unshareRequest = UnshareRequest(itemIDs: candidates, title: title, organizations: organizations)
    }

    /// Brings the items back into the personal vault (online only).
    func performUnshare(_ request: UnshareRequest) async {
        unshareRequest = nil
        guard canEdit, !unshareBusy else { return }
        let protected = request.itemIDs.filter { session.needsConfirmation(id: $0) }
        if let first = protected.first {
            let title = protected.count == 1 ? summary(id: first)?.title ?? request.title
                                             : String(localized: "\(protected.count) protected items")
            guard await confirmAccess(itemID: first, title: title) else { return }
            protected.forEach { session.authorizeItem(id: $0) }
        }
        unshareBusy = true
        defer { unshareBusy = false }
        do {
            let result = try await session.unshareItems(ids: request.itemIDs, progress: NoBulkProgress())
            // The open item page follows the item to its personal copy.
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
            toast = Toast(message: String(localized: "Could not remove from sharing"), detail: ErrorText.describe(error), failure: true,
                          seconds: 5)
        }
    }

    // MARK: Match rules

    func setDefaultMatchRule(_ rule: UriMatchRule) {
        try? session.setDefaultMatchRule(rule: rule)
        matchSettings = session.matchSettings()
    }

    func setFolderMatchRule(_ folderID: String, _ rule: UriMatchRule?) {
        try? session.setFolderMatchRule(folderId: folderID, rule: rule)
        matchSettings = session.matchSettings()
    }
}

/// Confirmation of "Remove from sharing…", placed on the tabs.
struct UnsharePresentation: ViewModifier {
    @Environment(PhoneModel.self) private var model

    func body(content: Content) -> some View {
        content
            .confirmationDialog(model.unshareRequest?.question ?? "",
                                isPresented: Binding(get: { model.unshareRequest != nil },
                                                     set: { if !$0 { model.unshareRequest = nil } }),
                                titleVisibility: .visible,
                                presenting: model.unshareRequest) { request in
                Button(request.itemIDs.count == 1 ? "Remove from sharing" : "Remove \(request.itemIDs.count) items",
                       role: .destructive) {
                    Task { await model.performUnshare(request) }
                }
                Button("Cancel", role: .cancel) { model.unshareRequest = nil }
            } message: { request in
                Text(request.message)
            }
            .overlay {
                if model.unshareBusy {
                    ProgressView("Removing from sharing…")
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .accessibilityIdentifier("unshare-progress")
                }
            }
    }
}
