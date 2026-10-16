import AppKit
import Observation
import SwiftUI

/// Où ranger un élément partagé : une organisation et une ou plusieurs de
/// ses collections.
struct SharedDestination: Equatable, Hashable {
    var organizationID: String
    var collectionIDs: [String]
}

/// « Partager… » (un ou plusieurs éléments personnels) ou « Collections… »
/// (élément déjà partagé) : la feuille garde son état, le modèle l'exécute.
@MainActor
@Observable
final class SharingFlow: Identifiable {
    let id = UUID()
    /// Éléments à partager (un seul pour « Collections… »).
    let itemIDs: [String]
    let title: String
    /// Déjà dans une organisation : on ne change que ses collections.
    let current: ItemSharing?
    var organizationID: String
    var collectionIDs: Set<String>
    var busy = false
    var error: String?
    /// Avancement d'un partage groupé.
    var progress: (done: Int, total: Int)?

    var itemID: String { itemIDs.first ?? "" }
    var isBulk: Bool { itemIDs.count > 1 }

    init(itemIDs: [String], title: String, current: ItemSharing?, organizationID: String, collectionIDs: Set<String>) {
        self.itemIDs = itemIDs
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
                toast = shareToast(result, organization: name)
            }
            sharingFlow = nil
        } catch {
            flow.error = Self.describe(error)
        }
    }

    /// « 12 éléments partagés dans Famille, 2 ignorés (déjà partagés) ».
    func shareToast(_ result: ShareResult, organization: String?) -> Toast {
        let n = Int(result.shared)
        var message = "\(n) élément\(n > 1 ? "s" : "") partagé\(n > 1 ? "s" : "")"
        if let organization { message += " dans \(organization)" }
        var ignored: [String] = []
        let plural = { (count: UInt32) in count > 1 ? "s" : "" }
        if result.alreadyShared > 0 { ignored.append("\(result.alreadyShared) ignoré\(plural(result.alreadyShared)) (déjà partagé\(plural(result.alreadyShared)))") }
        if result.readOnly > 0 { ignored.append("\(result.readOnly) ignoré\(plural(result.readOnly)) (lecture seule)") }
        if result.inTrash > 0 { ignored.append("\(result.inTrash) ignoré\(plural(result.inTrash)) (dans la corbeille)") }
        if result.notFound > 0 { ignored.append("\(result.notFound) introuvable\(plural(result.notFound))") }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !result.failures.isEmpty {
            return Toast(message: message + ", \(result.failures.count) refusé\(result.failures.count > 1 ? "s" : "")",
                         detail: result.failures.joined(separator: "\n"), failure: true, seconds: 6)
        }
        return Toast(message: message, detail: nil, seconds: ignored.isEmpty ? 2.5 : 4)
    }

    /// Page de l'organisation dans le coffre web (membres, collections, droits).
    func openWebVault(organizationID: String?) {
        let org = organizations.first { $0.id == organizationID } ?? organizations.first
        guard let link = org?.manageUrl, let url = URL(string: link) else { return }
        NSWorkspace.shared.open(url)
    }
}

/// Avancement d'un partage groupé, envoyé par Rust depuis son fil.
private final class ShareProgressRelay: BulkProgress, @unchecked Sendable {
    private weak var flow: SharingFlow?

    init(flow: SharingFlow) {
        self.flow = flow
    }

    func progress(done: UInt32, total: UInt32) {
        DispatchQueue.main.async { [weak flow] in
            MainActor.assumeIsolated {
                guard let flow, flow.busy else { return }
                flow.progress = (Int(done), Int(total))
            }
        }
    }
}
