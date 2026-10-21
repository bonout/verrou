import AppKit
import Observation
import SwiftUI

/// Where to put a shared item: an organization and one or more of its
/// collections.
struct SharedDestination: Equatable, Hashable {
    var organizationID: String
    var collectionIDs: [String]
}

extension AppModel {
    /// Can the item be edited (Vaultwarden vault open, and not a read-only
    /// collection)?
    func canModify(_ summary: ItemSummary?) -> Bool {
        canEdit && summary?.sharing?.readOnly != true
    }

    /// Organizations where the account can put an item.
    var writableOrganizations: [OrganizationView] {
        organizations.filter(\.writable)
    }

    /// Destination suggested for a new item: the organization or the
    /// collection displayed in the sidebar, if it can be written to.
    var destinationFromFilter: SharedDestination? {
        switch filter {
        case .organization(let id):
            guard let org = writableOrganizations.first(where: { $0.id == id }),
                  let collection = org.collections.first(where: { !$0.readOnly }) else { return nil }
            return SharedDestination(organizationID: org.id, collectionIDs: [collection.id])
        case .collection(let id):
            guard let org = writableOrganizations.first(where: { $0.collections.contains { $0.id == id && !$0.readOnly } })
            else { return nil }
            return SharedDestination(organizationID: org.id, collectionIDs: [id])
        default:
            return nil
        }
    }

    /// Opens "Share…" or "Collections…" for the item.
    func openSharing(_ itemID: String) {
        guard canEdit, let summary = summaries.first(where: { $0.id == itemID }), canModify(summary) else { return }
        if let sharing = summary.sharing {
            sharingFlow = SharingFlow(itemIDs: [itemID], title: summary.title, current: sharing,
                                      organizationID: sharing.organizationId,
                                      collectionIDs: Set(sharing.collectionIds))
        } else {
            openSharing(items: [itemID], title: summary.title)
        }
    }

    /// "Share…" on several items: only personal items that can be edited and
    /// are not in the trash go; the others are counted.
    func openSharing(items ids: [String]) {
        let personal = shareableIDs(ids)
        guard canEdit, !personal.isEmpty else { return }
        let title = personal.count == 1 ? summary(id: personal[0])?.title ?? "" : String(localized: "\(personal.count) items")
        openSharing(items: personal, title: title)
    }

    private func openSharing(items ids: [String], title: String) {
        guard let org = writableOrganizations.first else {
            toast = Toast(message: String(localized: "No shared vault"),
                          detail: String(localized: "Create an organization (Shared Vaults → New Organization…)"), failure: true)
            return
        }
        let first = org.collections.first { !$0.readOnly }
        sharingFlow = SharingFlow(itemIDs: ids, title: title, current: nil,
                                  organizationID: org.id, collectionIDs: Set(first.map { [$0.id] } ?? []))
    }

    /// The items a share can move: personal, editable, not in the trash.
    func shareableIDs(_ ids: [String]) -> [String] {
        ids.filter { id in
            guard let summary = summary(id: id) else { return false }
            return summary.sharing == nil && canModify(summary) && summary.state != .trashed
        }
    }

    /// Runs the sheet: share (one or several items), or new collections.
    func applySharing(_ flow: SharingFlow) async {
        guard !flow.busy else { return }
        if flow.current == nil {
            let protected = flow.itemIDs.filter { session.needsConfirmation(id: $0) }
            if let first = protected.first {
                let title = protected.count == 1 ? summary(id: first)?.title ?? flow.title
                                                 : String(localized: "\(protected.count) protected items")
                guard await confirmAccess(itemID: first, title: title) else { return }
                protected.forEach { session.authorizeItem(id: $0) }
            }
        }
        flow.busy = true
        flow.error = nil
        defer {
            flow.busy = false
            flow.progress = nil
        }
        // The order of the organization's collections, for a stable upload.
        let ordered = organizations.first { $0.id == flow.organizationID }?
            .collections.map(\.id).filter(flow.collectionIDs.contains) ?? Array(flow.collectionIDs)
        let name = organizations.first { $0.id == flow.organizationID }?.name
        do {
            if flow.current != nil {
                try await session.setItemCollections(id: flow.itemID, collectionIds: ordered)
                afterWrite(select: flow.itemID)
                toast = Toast(message: String(localized: "Collections saved"), detail: name)
            } else if !flow.isBulk {
                try await session.shareItem(id: flow.itemID, organizationId: flow.organizationID, collectionIds: ordered)
                afterWrite(select: flow.itemID)
                toast = Toast(message: String(localized: "Item shared"), detail: name)
            } else {
                flow.progress = (0, flow.itemIDs.count)
                let result = try await session.shareItems(ids: flow.itemIDs, organizationId: flow.organizationID,
                                                          collectionIds: ordered,
                                                          progress: ShareProgressRelay(flow: flow))
                afterWrite(select: nil)
                pruneSelection()
                toast = result.toast(organization: name)
            }
            sharingFlow = nil
        } catch {
            flow.error = Self.describe(error)
        }
    }

    /// The organization's page in the web vault (members, collections, rights).
    func openWebVault(organizationID: String?) {
        let org = organizations.first { $0.id == organizationID } ?? organizations.first
        guard let link = org?.manageUrl, let url = URL(string: link) else { return }
        NSWorkspace.shared.open(url)
    }
}
