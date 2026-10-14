import AppKit
import Observation
import SwiftUI

/// Où ranger un élément partagé : une organisation et une ou plusieurs de
/// ses collections.
struct SharedDestination: Equatable, Hashable {
    var organizationID: String
    var collectionIDs: [String]
}

/// « Partager… » (élément personnel) ou « Collections… » (élément déjà
/// partagé) : la feuille garde son état, le modèle l'exécute.
@MainActor
@Observable
final class SharingFlow: Identifiable {
    let id = UUID()
    let itemID: String
    let title: String
    /// Déjà dans une organisation : on ne change que ses collections.
    let current: ItemSharing?
    var organizationID: String
    var collectionIDs: Set<String>
    var busy = false
    var error: String?

    init(itemID: String, title: String, current: ItemSharing?, organizationID: String, collectionIDs: Set<String>) {
        self.itemID = itemID
        self.title = title
        self.current = current
        self.organizationID = organizationID
        self.collectionIDs = collectionIDs
    }
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
            sharingFlow = SharingFlow(itemID: itemID, title: summary.title, current: sharing,
                                      organizationID: sharing.organizationId,
                                      collectionIDs: Set(sharing.collectionIds))
        } else {
            guard let org = writableOrganizations.first else {
                toast = Toast(message: "Aucun coffre partagé", detail: "Créez une organisation dans le coffre web", failure: true)
                return
            }
            let first = org.collections.first { !$0.readOnly }
            sharingFlow = SharingFlow(itemID: itemID, title: summary.title, current: nil,
                                      organizationID: org.id, collectionIDs: Set(first.map { [$0.id] } ?? []))
        }
    }

    /// Exécute la feuille : partage, ou nouvelles collections.
    func applySharing(_ flow: SharingFlow) async {
        guard !flow.busy else { return }
        if flow.current == nil, session.needsConfirmation(id: flow.itemID) {
            guard await confirmAccess(itemID: flow.itemID, title: flow.title) else { return }
        }
        flow.busy = true
        flow.error = nil
        defer { flow.busy = false }
        // L'ordre des collections de l'organisation, pour un envoi stable.
        let ordered = organizations.first { $0.id == flow.organizationID }?
            .collections.map(\.id).filter(flow.collectionIDs.contains) ?? Array(flow.collectionIDs)
        do {
            if flow.current == nil {
                try await session.shareItem(id: flow.itemID, organizationId: flow.organizationID, collectionIds: ordered)
            } else {
                try await session.setItemCollections(id: flow.itemID, collectionIds: ordered)
            }
            afterWrite(select: flow.itemID)
            sharingFlow = nil
            let name = organizations.first { $0.id == flow.organizationID }?.name
            toast = Toast(message: flow.current == nil ? "Élément partagé" : "Collections enregistrées", detail: name)
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

extension ItemSharing {
    /// « Organisation › Collection, Collection ».
    var label: String {
        collections.isEmpty ? organization : "\(organization) › \(collections.joined(separator: ", "))"
    }
}
