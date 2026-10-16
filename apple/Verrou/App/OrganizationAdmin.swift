import AppKit
import Observation
import SwiftUI

/// Gestion des coffres partagés depuis l'app : créer, renommer ou quitter
/// une organisation, créer et modifier ses collections (qui y accède, avec
/// quels droits), ses groupes, et rejoindre une organisation avec le lien
/// d'invitation reçu par courriel. Tout passe par le cœur Rust, qui chiffre
/// les noms avec la clé de l'organisation et vérifie les droits avant
/// d'envoyer ; le serveur les vérifie de toute façon.
@MainActor
@Observable
final class OrganizationAdminModel {
    var sheet: OrganizationSheet?
    var confirmLeave: OrganizationView?
    var confirmDelete: CollectionTarget?
    var busy = false
    var error: String?
    /// Organisations rejointes, en attente de la confirmation d'un
    /// administrateur.
    var pending: [PendingMembershipView] = []
    /// Membres à confirmer, par organisation administrée.
    var toConfirm: [String: Int] = [:]
    /// Revue visuelle : données fictives, aucun serveur.
    var preview = false

    var totalToConfirm: Int { toConfirm.values.reduce(0, +) }

    func clear() {
        sheet = nil
        confirmLeave = nil
        confirmDelete = nil
        busy = false
        error = nil
        pending = []
        toConfirm = [:]
        preview = false
    }
}

/// Une collection visée par une action (suppression).
struct CollectionTarget: Identifiable {
    let organization: OrganizationView
    let collection: CollectionView
    var id: String { collection.id }
}

/// Les feuilles de la gestion des coffres partagés.
enum OrganizationSheet: Identifiable {
    case newOrganization
    case rename(OrganizationView)
    case collection(CollectionDraft)
    case groups(GroupsDraft)
    case join

    var id: String {
        switch self {
        case .newOrganization: "new"
        case .rename(let org): "rename-\(org.id)"
        case .collection(let draft): "collection-\(draft.collectionID ?? "new")"
        case .groups(let draft): "groups-\(draft.organizationID)"
        case .join: "join"
        }
    }
}

extension AppModel {
    // MARK: État des invitations

    /// Après une synchronisation : ce qui est nouveau pour le compte (cœur
    /// Rust, une seule fois chaque chose), posté en notifications locales ;
    /// organisations en attente de confirmation (sans réseau) et membres à
    /// confirmer dans celles qu'on administre (réseau), pour les bandeaux.
    /// `notify` faux : tout est marqué vu sans notification (juste après
    /// une action de ce compte, qui ne doit pas lui être annoncée).
    func refreshSharingStatus(notify: Bool = true) async {
        guard mode == .vaultwarden, lockState == .unlocked, !organizationAdmin.preview else { return }
        let network = organizations.contains(where: \.canManageMembers) || emergencyAvailable
        guard let report = try? await session.checkActivity(network: network, emergency: emergencyAvailable,
                                                            notify: notify && ActivityNotifier.enabled),
              lockState == .unlocked else { return }
        // Assignés seulement s'ils changent : l'accueil ne se redessine pas
        // à chaque synchronisation pour rien.
        if organizationAdmin.pending != report.pending { organizationAdmin.pending = report.pending }
        if !organizations.contains(where: \.canManageMembers) {
            if !organizationAdmin.toConfirm.isEmpty { organizationAdmin.toConfirm = [:] }
        } else if report.toConfirmChecked {
            let toConfirm = Dictionary(report.toConfirm.map { ($0.organizationId, Int($0.count)) },
                                       uniquingKeysWith: { first, _ in first })
            if organizationAdmin.toConfirm != toConfirm { organizationAdmin.toConfirm = toConfirm }
        }
        ActivityNotifier.shared.post(report.notices)
        // L'autorisation se demande quand le partage concerne ce compte,
        // jamais au premier lancement.
        if report.organizations > 0 || !report.pending.isEmpty {
            await ActivityNotifier.shared.requestAuthorizationIfNeeded()
        }
    }

    /// Le toucher d'une notification du partage : l'écran qui en parle.
    func openActivity(_ route: ActivityRoute) {
        showMainWindow()
        guard lockState == .unlocked else {
            pendingActivityRoute = route
            return
        }
        switch route {
        case .members(let id): openMembers(id)
        case .organization(let id):
            pane = nil
            filter = .organization(id: id)
        case .pendingMemberships:
            pane = nil
        case .emergency: openEmergency()
        }
    }

    /// « N membres à confirmer » : le volet des membres de la première
    /// organisation qui en a.
    func openFirstMembersToConfirm() {
        guard let id = organizations.first(where: { (organizationAdmin.toConfirm[$0.id] ?? 0) > 0 })?.id else { return }
        openMembers(id)
    }

    // MARK: Organisations

    func openNewOrganization() {
        guard canEdit || organizationAdmin.preview else { return }
        organizationAdmin.error = nil
        organizationAdmin.sheet = .newOrganization
    }

    func createOrganization(name: String, collection: String) async {
        await organizationAction {
            let id = try await self.session.createOrganization(name: name, collectionName: collection)
            self.afterWrite(select: nil)
            self.organizationAdmin.sheet = nil
            self.filter = .organization(id: id)
            self.toast = Toast(message: "Organisation créée",
                               detail: "Invitez ses membres depuis « Membres », sous ses collections")
        }
    }

    func openRename(_ organization: OrganizationView) {
        organizationAdmin.error = nil
        organizationAdmin.sheet = .rename(organization)
    }

    func renameOrganization(_ organization: OrganizationView, to name: String) async {
        await organizationAction {
            try await self.session.renameOrganization(organizationId: organization.id, name: name)
            self.afterWrite(select: nil)
            self.organizationAdmin.sheet = nil
            self.toast = Toast(message: "Organisation renommée", detail: name.trimmingCharacters(in: .whitespaces))
        }
    }

    func leaveOrganization(_ organization: OrganizationView) async {
        organizationAdmin.confirmLeave = nil
        await organizationAction {
            try await self.session.leaveOrganization(organizationId: organization.id)
            if case .organization(organization.id) = self.filter { self.filter = .all }
            if organization.collections.contains(where: { self.filter == .collection(id: $0.id) }) { self.filter = .all }
            self.afterWrite(select: nil)
            self.toast = Toast(message: "Vous avez quitté \(organization.name)",
                               detail: "Ses éléments ne sont plus dans votre coffre")
        } failed: { message in
            self.toast = Toast(message: "Impossible de quitter \(organization.name)", detail: message, failure: true)
        }
    }

    // MARK: Collections

    /// Ouvre l'éditeur d'une collection (`nil` : nouvelle) ; la feuille lit
    /// elle-même membres, groupes et accès (`loadCollectionDraft`).
    func openCollectionEditor(_ organization: OrganizationView, collection: CollectionView?) {
        organizationAdmin.error = nil
        var draft = CollectionDraft(organizationID: organization.id, collectionID: collection?.id,
                                    name: collection?.name ?? "")
        // Revue visuelle : rien à lire.
        if organizationAdmin.preview { draft.loading = false }
        organizationAdmin.sheet = .collection(draft)
    }

    func saveCollection(_ draft: CollectionDraft) async {
        await organizationAction {
            if let id = draft.collectionID {
                if draft.accessUnavailable == nil {
                    try await self.session.updateCollection(organizationId: draft.organizationID, collectionId: id,
                                                            name: draft.name, access: draft.accessList)
                } else {
                    // Accès illisibles : on relit ceux du serveur pour ne pas les effacer.
                    let current = try await self.session.collectionAccess(organizationId: draft.organizationID,
                                                                          collectionId: id)
                    try await self.session.updateCollection(organizationId: draft.organizationID, collectionId: id,
                                                            name: draft.name, access: current)
                }
                self.toast = Toast(message: "Collection enregistrée", detail: draft.name)
            } else {
                let id = try await self.session.createCollection(organizationId: draft.organizationID,
                                                                 name: draft.name, access: draft.accessList)
                self.filter = .collection(id: id)
                self.toast = Toast(message: "Collection créée", detail: draft.name)
            }
            self.afterWrite(select: nil)
            self.organizationAdmin.sheet = nil
        }
    }

    func deleteCollection(_ target: CollectionTarget) async {
        organizationAdmin.confirmDelete = nil
        await organizationAction {
            try await self.session.deleteCollection(organizationId: target.organization.id,
                                                    collectionId: target.collection.id)
            if self.filter == .collection(id: target.collection.id) { self.filter = .organization(id: target.organization.id) }
            self.afterWrite(select: nil)
            self.toast = Toast(message: "Collection « \(target.collection.name) » supprimée",
                               detail: "Ses éléments restent dans l'organisation")
        } failed: { message in
            self.toast = Toast(message: "Suppression impossible", detail: message, failure: true)
        }
    }

    // MARK: Groupes

    func openGroups(_ organization: OrganizationView) async {
        organizationAdmin.error = nil
        var draft = GroupsDraft(organizationID: organization.id)
        organizationAdmin.sheet = .groups(draft)
        guard !organizationAdmin.preview else { return }
        do {
            draft.groups = try await session.organizationGroups(organizationId: organization.id)
            draft.members = try await session.organizationMembers(organizationId: organization.id)
        } catch {
            organizationAdmin.error = Self.describe(error)
        }
        draft.loading = false
        if case .groups = organizationAdmin.sheet { organizationAdmin.sheet = .groups(draft) }
    }

    func saveGroup(_ group: GroupDraft, in organizationID: String) async {
        await organizationAction {
            _ = try await self.session.saveOrganizationGroup(
                organizationId: organizationID, id: group.id, name: group.name,
                members: group.members.sorted(), collections: group.collections)
            try await self.reloadGroups(organizationID)
            self.toast = Toast(message: group.id == nil ? "Groupe créé" : "Groupe enregistré", detail: group.name)
        }
    }

    func deleteGroup(_ group: OrganizationGroup, in organizationID: String) async {
        await organizationAction {
            try await self.session.deleteOrganizationGroup(organizationId: organizationID, id: group.id)
            try await self.reloadGroups(organizationID)
            self.toast = Toast(message: "Groupe « \(group.name) » supprimé", detail: nil)
        }
    }

    private func reloadGroups(_ organizationID: String) async throws {
        guard case .groups(var draft) = organizationAdmin.sheet else { return }
        draft.groups = try await session.organizationGroups(organizationId: organizationID)
        draft.editing = nil
        organizationAdmin.sheet = .groups(draft)
    }

    // MARK: Invitations reçues

    func openJoin() {
        Task { await ActivityNotifier.shared.requestAuthorizationIfNeeded() }
        guard canEdit || organizationAdmin.preview else { return }
        organizationAdmin.error = nil
        organizationAdmin.sheet = .join
    }

    func joinOrganization(link: String) async {
        await organizationAction {
            let name = try await self.session.joinOrganization(link: link)
            self.afterWrite(select: nil)
            self.organizationAdmin.sheet = nil
            await self.refreshSharingStatus()
            self.toast = Toast(message: "Invitation acceptée",
                               detail: "Un administrateur de \(name) doit maintenant vous confirmer : lisez-lui votre phrase d'empreinte",
                               seconds: 8)
        }
    }

    // MARK: Commun

    private func organizationAction(_ action: @escaping () async throws -> Void,
                                    failed: ((String) -> Void)? = nil) async {
        guard !organizationAdmin.busy, !organizationAdmin.preview else { return }
        organizationAdmin.busy = true
        organizationAdmin.error = nil
        defer { organizationAdmin.busy = false }
        do {
            try await action()
        } catch {
            let message = Self.describe(error)
            if let failed { failed(message) } else { organizationAdmin.error = message }
        }
    }
}
