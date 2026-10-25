import AppKit
import SwiftUI

// Removal from sharing and match rules (see
// `Shared/Core/VaultTweaks.swift` for the shared labels).

extension AppModel {
    // MARK: Removal from sharing

    /// The items that can leave their organization.
    func unshareableIDs(_ ids: [String]) -> [String] {
        ids.filter { summary(id: $0)?.canUnshare == true }
    }

    /// "Remove from sharing…": asks for confirmation (the organization's
    /// copy is permanently deleted).
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
        unshareError = nil
        unshareRequest = UnshareRequest(itemIDs: candidates, title: title, organizations: organizations)
    }

    /// Brings the items back into the personal vault (online only).
    func performUnshare(_ request: UnshareRequest) async {
        guard !unshareBusy else { return }
        let protected = request.itemIDs.filter { session.needsConfirmation(id: $0) }
        if let first = protected.first {
            let title = protected.count == 1 ? summary(id: first)?.title ?? request.title
                                             : String(localized: "\(protected.count) protected items")
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

    /// The list shows the site and user of passkeys: "Passkeys" filter, or
    /// `passkey:` / `has:passkey` search.
    var showsPasskeyLines: Bool {
        if filter == .passkeys { return true }
        let words = query.lowercased().split(separator: " ")
        return words.contains { $0.hasPrefix("passkey:") || $0.hasPrefix("passkeys:") || $0 == "has:passkey" }
    }

    // MARK: Terminal approval of SSH keys

    /// How long the terminal's approval of an SSH key holds, on this Mac.
    func setSshApprovalScope(_ itemID: String, _ scope: SshApprovalScope) {
        try? session.setSshApprovalScope(id: itemID, scope: scope)
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

/// Progress of the removal from sharing, relayed to the main thread.
final class UnshareProgressRelay: BulkProgress, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) { self.model = model }

    func progress(done: UInt32, total: UInt32) {
        Task { @MainActor [weak model] in model?.bulkProgress = (Int(done), Int(total)) }
    }
}
