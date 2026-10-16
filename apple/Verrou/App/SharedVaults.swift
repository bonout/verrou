import AppKit
import Observation
import SwiftUI

/// Où ranger un élément partagé : une organisation et une ou plusieurs de
/// ses collections.
struct SharedDestination: Equatable, Hashable {
    var organizationID: String
    var collectionIDs: [String]
}

extension AppModel {
    /// L'élément peut-il être modifié (coffre Vaultwarden ouvert, et pas une
    /// collection en lecture seule) ?
    func canModify(_ summary: ItemSummary?) -> Bool {
        canEdit && summary?.sharing?.readOnly != true
    }

    /// Organisations où le compte peut ranger un élément.
    var writableOrganizations: [OrganizationView] {
        organizations.filter(\.writable)
    }

    /// Destination proposée pour un nouvel élément : l'organisation ou la
    /// collection affichée dans la barre latérale, si on peut y écrire.
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

    /// Ouvre « Partager… » ou « Collections… » pour l'élément.
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

    /// « Partager… » sur plusieurs éléments : seuls les éléments personnels
    /// modifiables et hors de la corbeille partent ; les autres sont comptés.
    func openSharing(items ids: [String]) {
        let personal = shareableIDs(ids)
        guard canEdit, !personal.isEmpty else { return }
        let title = personal.count == 1 ? summary(id: personal[0])?.title ?? "" : "\(personal.count) éléments"
        openSharing(items: personal, title: title)
    }

    private func openSharing(items ids: [String], title: String) {
        guard let org = writableOrganizations.first else {
            toast = Toast(message: "Aucun coffre partagé",
                          detail: "Créez une organisation (Coffres partagés → Nouvelle organisation…)", failure: true)
            return
        }
        let first = org.collections.first { !$0.readOnly }
        sharingFlow = SharingFlow(itemIDs: ids, title: title, current: nil,
                                  organizationID: org.id, collectionIDs: Set(first.map { [$0.id] } ?? []))
    }

    /// Les éléments qu'un partage peut déplacer : personnels, modifiables,
    /// hors de la corbeille.
    func shareableIDs(_ ids: [String]) -> [String] {
        ids.filter { id in
            guard let summary = summary(id: id) else { return false }
            return summary.sharing == nil && canModify(summary) && summary.state != .trashed
        }
    }

    /// Exécute la feuille : partage (un ou plusieurs éléments), ou nouvelles
    /// collections.
    func applySharing(_ flow: SharingFlow) async {
        guard !flow.busy else { return }
        if flow.current == nil {
            let protected = flow.itemIDs.filter { session.needsConfirmation(id: $0) }
            if let first = protected.first {
                let title = protected.count == 1 ? summary(id: first)?.title ?? flow.title
                                                 : "\(protected.count) éléments protégés"
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
        // L'ordre des collections de l'organisation, pour un envoi stable.
        let ordered = organizations.first { $0.id == flow.organizationID }?
            .collections.map(\.id).filter(flow.collectionIDs.contains) ?? Array(flow.collectionIDs)
        let name = organizations.first { $0.id == flow.organizationID }?.name
        do {
            if flow.current != nil {
                try await session.setItemCollections(id: flow.itemID, collectionIds: ordered)
                afterWrite(select: flow.itemID)
                toast = Toast(message: "Collections enregistrées", detail: name)
            } else if !flow.isBulk {
                try await session.shareItem(id: flow.itemID, organizationId: flow.organizationID, collectionIds: ordered)
                afterWrite(select: flow.itemID)
                toast = Toast(message: "Élément partagé", detail: name)
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

    /// Page de l'organisation dans le coffre web (membres, collections, droits).
    func openWebVault(organizationID: String?) {
        let org = organizations.first { $0.id == organizationID } ?? organizations.first
        guard let link = org?.manageUrl, let url = URL(string: link) else { return }
        NSWorkspace.shared.open(url)
    }
}
