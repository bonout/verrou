import Observation
import SwiftUI
import UIKit

/// Partage avec les autres comptes du serveur, sur l'iPhone : partager des
/// éléments dans un coffre partagé, gérer les organisations, leurs
/// collections, leurs membres et leurs groupes, rejoindre une organisation
/// avec le lien d'invitation. Même cœur Rust que le Mac : il vérifie les
/// droits avant d'envoyer, chiffre avec la clé de l'organisation (qui ne
/// quitte jamais le SDK) et refuse clairement hors ligne.
@MainActor
@Observable
final class PhoneSharingModel {
    /// « Partager… » ou « Collections… » ouvert.
    var shareFlow: SharingFlow?
    var sheet: PhoneSharingSheet?
    /// Organisations rejointes, en attente de la confirmation d'un
    /// administrateur.
    var pending: [PendingMembershipView] = []
    /// Membres à confirmer, par organisation administrée.
    var toConfirm: [String: Int] = [:]
    /// Membres et groupes lus, par organisation.
    var members: [String: [OrganizationMember]] = [:]
    var groups: [String: [OrganizationGroup]] = [:]
    var loading: Set<String> = []
    var busy = false
    /// Erreur affichée dans la feuille ouverte.
    var error: String?
    /// Empreinte d'un membre à vérifier avant de le confirmer.
    var confirmation: MemberConfirmation?
    var confirmLeave: OrganizationView?
    var confirmDelete: CollectionTarget?
    var confirmRemove: MemberTarget?
    var confirmRevoke: MemberTarget?
    /// Envois (Bitwarden Send) du compte ; `nil` : pas encore lus.
    var sends: [SendSummary]?
    var sendComposer: SendComposer?
    /// Lien de l'envoi qui vient d'être créé (il porte sa clé).
    var createdLink: String?

    var totalToConfirm: Int { toConfirm.values.reduce(0, +) }

    func clear() {
        shareFlow = nil
        sheet = nil
        pending = []
        toConfirm = [:]
        members = [:]
        groups = [:]
        loading = []
        busy = false
        error = nil
        confirmation = nil
        confirmLeave = nil
        confirmDelete = nil
        confirmRemove = nil
        confirmRevoke = nil
        sends = nil
        sendComposer = nil
        createdLink = nil
    }
}

/// Les feuilles de la gestion des coffres partagés.
enum PhoneSharingSheet: Identifiable {
    case newOrganization
    case rename(OrganizationView)
    case collection(CollectionDraft)
    case member(MemberDraft, organizationID: String)
    case group(GroupDraft, organizationID: String)
    /// Lien déjà connu (collé ou reçu), sinon vide.
    case join(String)
    case fingerprint(PendingMembershipView?)

    var id: String {
        switch self {
        case .newOrganization: "new"
        case .rename(let org): "rename-\(org.id)"
        case .collection(let draft): "collection-\(draft.collectionID ?? "new")"
        case .member(let draft, _): "member-\(draft.id)"
        case .group(let draft, _): "group-\(draft.id ?? "new")"
        case .join: "join"
        case .fingerprint(let pending): "fingerprint-\(pending?.organizationId ?? "")"
        }
    }
}

struct MemberConfirmation: Identifiable {
    let id = UUID()
    let organizationID: String
    let member: OrganizationMember
    let fingerprint: String
}

struct MemberTarget: Identifiable {
    let organizationID: String
    let member: OrganizationMember
    var id: String { member.id }
}

struct CollectionTarget: Identifiable {
    let organization: OrganizationView
    let collection: CollectionView
    var id: String { collection.id }
}

extension PhoneModel {
    func organization(_ id: String) -> OrganizationView? {
        organizations.first { $0.id == id }
    }

    // MARK: Partager des éléments

    /// Les éléments qu'un partage peut déplacer : personnels, modifiables,
    /// hors de la corbeille.
    func shareableIDs(_ ids: [String]) -> [String] {
        ids.filter { id in
            guard let summary = summary(id: id) else { return false }
            return summary.sharing == nil && canModify(summary) && summary.state != .trashed
        }
    }

    /// « Partager… » (élément personnel) ou « Collections… » (déjà partagé).
    func openSharing(_ itemID: String) {
        guard canEdit, let summary = summary(id: itemID), canModify(summary) else { return }
        if let sharing = summary.sharing {
            openShareFlow(SharingFlow(itemIDs: [itemID], title: summary.title, current: sharing,
                                     organizationID: sharing.organizationId,
                                     collectionIDs: Set(sharing.collectionIds)))
        } else {
            openSharing(items: [itemID])
        }
    }

    /// « Partager… » sur une sélection : seuls les éléments personnels
    /// modifiables partent, les autres sont comptés.
    func openSharing(items ids: [String]) {
        let personal = shareableIDs(ids)
        guard canEdit, !personal.isEmpty else { return }
        guard let org = writableOrganizations.first else {
            toast = Toast(message: "Aucun coffre partagé",
                          detail: "Créez une organisation depuis l'accueil (Coffres partagés)", failure: true)
            return
        }
        let title = personal.count == 1 ? summary(id: personal[0])?.title ?? "" : "\(personal.count) éléments"
        let first = org.collections.first { !$0.readOnly }
        openShareFlow(SharingFlow(itemIDs: personal, title: title, current: nil, organizationID: org.id,
                                 collectionIDs: Set(first.map { [$0.id] } ?? [])))
    }

    private func openShareFlow(_ flow: SharingFlow) {
        sharing.error = nil
        sharing.shareFlow = flow
    }

    /// Exécute la feuille : partage (un ou plusieurs éléments), ou nouvelles
    /// collections. Rend `true` si la feuille peut se fermer.
    @discardableResult
    func applySharing(_ flow: SharingFlow) async -> Bool {
        guard !flow.busy else { return false }
        if flow.current == nil {
            let protected = flow.itemIDs.filter { session.needsConfirmation(id: $0) }
            if let first = protected.first {
                let title = protected.count == 1 ? summary(id: first)?.title ?? flow.title
                                                 : "\(protected.count) éléments protégés"
                guard await confirmAccess(itemID: first, title: title) else { return false }
                protected.forEach { session.authorizeItem(id: $0) }
            }
        }
        flow.busy = true
        flow.error = nil
        defer {
            flow.busy = false
            flow.progress = nil
        }
        let org = organization(flow.organizationID)
        let ordered = org?.collections.map(\.id).filter(flow.collectionIDs.contains) ?? Array(flow.collectionIDs)
        do {
            if flow.current != nil {
                try await session.setItemCollections(id: flow.itemID, collectionIds: ordered)
                afterWrite()
                toast = Toast(message: "Collections enregistrées", detail: org?.name)
            } else if !flow.isBulk {
                try await session.shareItem(id: flow.itemID, organizationId: flow.organizationID, collectionIds: ordered)
                afterWrite()
                toast = Toast(message: "Élément partagé", detail: org?.name)
            } else {
                flow.progress = (0, flow.itemIDs.count)
                let result = try await session.shareItems(ids: flow.itemIDs, organizationId: flow.organizationID,
                                                          collectionIds: ordered, progress: ShareProgressRelay(flow: flow))
                afterWrite()
                toast = result.toast(organization: org?.name)
            }
            sharing.shareFlow = nil
            return true
        } catch {
            flow.error = ErrorText.describe(error)
            return false
        }
    }

    // MARK: Invitations et confirmations

    /// Après une synchronisation : ce qui est nouveau pour le compte (cœur
    /// Rust, une seule fois chaque chose), posté en notifications locales ;
    /// organisations en attente de confirmation (sans réseau) et membres à
    /// confirmer dans celles qu'on administre (réseau), pour les bandeaux.
    /// `notify` faux : tout est marqué vu sans notification (juste après
    /// une action de ce compte).
    func refreshSharingStatus(notify: Bool = true) async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        let manages = organizations.contains(where: \.canManageMembers)
        guard let report = try? await session.checkActivity(network: manages, emergency: false,
                                                            notify: notify && ActivityNotifier.enabled),
              lockState == .unlocked else { return }
        // Assignés seulement s'ils changent : l'accueil ne se redessine pas
        // à chaque synchronisation pour rien.
        if sharing.pending != report.pending { sharing.pending = report.pending }
        if !manages {
            if !sharing.toConfirm.isEmpty { sharing.toConfirm = [:] }
        } else if report.toConfirmChecked {
            let toConfirm = Dictionary(report.toConfirm.map { ($0.organizationId, Int($0.count)) },
                                       uniquingKeysWith: { first, _ in first })
            if sharing.toConfirm != toConfirm { sharing.toConfirm = toConfirm }
        }
        ActivityNotifier.shared.post(report.notices)
        // Pastille : ce qui attend une action.
        ActivityNotifier.shared.setBadge(sharing.totalToConfirm + sharing.pending.count)
        // L'autorisation se demande quand le partage concerne ce compte,
        // jamais au premier lancement.
        if report.organizations > 0 || !report.pending.isEmpty {
            await ActivityNotifier.shared.requestAuthorizationIfNeeded()
        }
    }

    /// Le toucher d'une notification du partage : l'écran qui en parle.
    func openActivity(_ route: ActivityRoute) {
        guard lockState == .unlocked else {
            pendingActivityRoute = route
            return
        }
        tab = .vault
        switch route {
        case .members(let id): vaultPath = [.organization(id), .members(id)]
        case .organization(let id): vaultPath = [.organization(id)]
        case .pendingMemberships, .emergency: vaultPath = []
        }
    }

    /// « N membres à confirmer » : les membres de la première organisation
    /// qui en a.
    func openFirstMembersToConfirm() {
        guard let id = organizations.first(where: { (sharing.toConfirm[$0.id] ?? 0) > 0 })?.id else { return }
        tab = .vault
        vaultPath = [.organization(id), .members(id)]
    }

    func joinOrganization(link: String) async -> Bool {
        await sharingAction {
            let name = try await self.session.joinOrganization(link: link)
            self.afterWrite()
            await self.refreshSharingStatus()
            self.toast = Toast(message: "Invitation acceptée",
                               detail: "Un administrateur de \(name) doit vous confirmer : lisez-lui votre phrase d'empreinte",
                               seconds: 8)
        }
    }

    // MARK: Organisations

    func createOrganization(name: String, collection: String) async -> Bool {
        await sharingAction {
            let id = try await self.session.createOrganization(name: name, collectionName: collection)
            self.afterWrite()
            self.tab = .vault
            self.vaultPath = [.organization(id)]
            self.toast = Toast(message: "Organisation créée", detail: "Invitez ses membres depuis « Membres »")
        }
    }

    func renameOrganization(_ organization: OrganizationView, to name: String) async -> Bool {
        await sharingAction {
            try await self.session.renameOrganization(organizationId: organization.id, name: name)
            self.afterWrite()
            self.toast = Toast(message: "Organisation renommée", detail: name.trimmingCharacters(in: .whitespaces))
        }
    }

    func leaveOrganization(_ organization: OrganizationView) async {
        sharing.confirmLeave = nil
        let left = await sharingAction {
            try await self.session.leaveOrganization(organizationId: organization.id)
            self.vaultPath = []
            self.afterWrite()
            self.toast = Toast(message: "Vous avez quitté \(organization.name)",
                               detail: "Ses éléments ne sont plus dans votre coffre")
        }
        if !left, let error = sharing.error {
            sharing.error = nil
            toast = Toast(message: "Impossible de quitter \(organization.name)", detail: error, failure: true)
        }
    }

    // MARK: Collections

    /// L'éditeur d'une collection (`nil` : nouvelle) ; la feuille lit
    /// elle-même membres, groupes et accès (`loadCollectionDraft`).
    func openCollectionEditor(_ organization: OrganizationView, collection: CollectionView?) {
        sharing.error = nil
        sharing.sheet = .collection(CollectionDraft(organizationID: organization.id, collectionID: collection?.id,
                                                    name: collection?.name ?? ""))
    }

    func saveCollection(_ draft: CollectionDraft) async -> Bool {
        await sharingAction {
            if let id = draft.collectionID {
                let access = draft.accessUnavailable == nil
                    ? draft.accessList
                    : try await self.session.collectionAccess(organizationId: draft.organizationID, collectionId: id)
                try await self.session.updateCollection(organizationId: draft.organizationID, collectionId: id,
                                                        name: draft.name, access: access)
                self.toast = Toast(message: "Collection enregistrée", detail: draft.name)
            } else {
                _ = try await self.session.createCollection(organizationId: draft.organizationID,
                                                            name: draft.name, access: draft.accessList)
                self.toast = Toast(message: "Collection créée", detail: draft.name)
            }
            self.afterWrite()
        }
    }

    func deleteCollection(_ target: CollectionTarget) async {
        sharing.confirmDelete = nil
        do {
            try await session.deleteCollection(organizationId: target.organization.id, collectionId: target.collection.id)
            vaultPath.removeAll { $0 == .list(.collection(id: target.collection.id)) }
            afterWrite()
            toast = Toast(message: "Collection « \(target.collection.name) » supprimée",
                          detail: "Ses éléments restent dans l'organisation")
        } catch {
            toast = Toast(message: "Suppression impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    // MARK: Membres

    func loadMembers(_ organizationID: String) async {
        guard mode == .vaultwarden, lockState == .unlocked, !sharing.loading.contains(organizationID) else { return }
        sharing.loading.insert(organizationID)
        defer { sharing.loading.remove(organizationID) }
        do {
            let list = try await session.organizationMembers(organizationId: organizationID)
            sharing.members[organizationID] = list
            let accepted = list.filter { $0.status == .accepted }.count
            sharing.toConfirm[organizationID] = accepted > 0 ? accepted : nil
            if organization(organizationID)?.useGroups == true {
                sharing.groups[organizationID] = try await session.organizationGroups(organizationId: organizationID)
            }
        } catch {
            toast = Toast(message: "Membres illisibles", detail: ErrorText.describe(error), failure: true)
        }
    }

    func inviteMembers(_ organizationID: String) {
        let first = organization(organizationID)?.collections.first { !$0.readOnly }
        sharing.error = nil
        sharing.sheet = .member(MemberDraft(member: nil, emails: "", role: .user,
                                            access: first.map { [$0.id: .edit] } ?? [:]),
                                organizationID: organizationID)
    }

    func editMember(_ member: OrganizationMember, in organizationID: String) {
        var access: [String: CollectionPermission] = [:]
        for collection in member.collections { access[collection.collectionId] = CollectionPermission(collection) }
        sharing.error = nil
        sharing.sheet = .member(MemberDraft(member: member, emails: member.email, role: member.role, access: access),
                                organizationID: organizationID)
    }

    func saveMember(_ draft: MemberDraft, in organizationID: String) async -> Bool {
        await sharingAction {
            if let member = draft.member {
                try await self.session.editOrganizationMember(organizationId: organizationID, memberId: member.id,
                                                             role: draft.role, collections: draft.collections)
                self.toast = Toast(message: "Accès de \(member.displayName) enregistrés", detail: nil)
            } else {
                let invited = try await self.session.inviteOrganizationMembers(
                    organizationId: organizationID, emails: draft.emails, role: draft.role, collections: draft.collections)
                self.toast = Toast(message: invited.count == 1 ? "Invitation envoyée" : "\(invited.count) invitations envoyées",
                                   detail: "\(invited.joined(separator: ", ")) : voir « Et ensuite ? » sous les invitations")
                // Sans courriel, le serveur accepte d'office un compte
                // existant : ce membre à confirmer n'est pas une nouvelle
                // pour qui l'invite.
                await self.refreshSharingStatus(notify: false)
            }
            await self.loadMembers(organizationID)
        }
    }

    func memberAction(_ done: String, in organizationID: String,
                      _ action: @escaping () async throws -> Void) async {
        sharing.confirmRemove = nil
        sharing.confirmRevoke = nil
        do {
            try await action()
            toast = Toast(message: done, detail: nil)
            await loadMembers(organizationID)
        } catch {
            toast = Toast(message: "Action impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Avant de confirmer : l'empreinte de la clé publique du membre, relue
    /// sur le serveur, à comparer de vive voix avec la sienne.
    func prepareConfirmation(_ member: OrganizationMember, in organizationID: String) async {
        do {
            let fingerprint = try await session.organizationMemberFingerprint(organizationId: organizationID,
                                                                               memberId: member.id)
            sharing.confirmation = MemberConfirmation(organizationID: organizationID, member: member,
                                                      fingerprint: fingerprint)
        } catch {
            toast = Toast(message: "Empreinte illisible", detail: ErrorText.describe(error), failure: true)
        }
    }

    func confirmMember(_ confirmation: MemberConfirmation) async {
        sharing.confirmation = nil
        await memberAction("\(confirmation.member.displayName) est confirmé", in: confirmation.organizationID) {
            try await self.session.confirmOrganizationMember(organizationId: confirmation.organizationID,
                                                             memberId: confirmation.member.id,
                                                             fingerprint: confirmation.fingerprint)
        }
    }

    // MARK: Groupes

    func saveGroup(_ group: GroupDraft, in organizationID: String) async -> Bool {
        await sharingAction {
            _ = try await self.session.saveOrganizationGroup(
                organizationId: organizationID, id: group.id, name: group.name,
                members: group.members.sorted(), collections: group.collections)
            self.sharing.groups[organizationID] = try await self.session.organizationGroups(organizationId: organizationID)
            self.toast = Toast(message: group.id == nil ? "Groupe créé" : "Groupe enregistré", detail: group.name)
        }
    }

    func deleteGroup(_ group: OrganizationGroup, in organizationID: String) async {
        do {
            try await session.deleteOrganizationGroup(organizationId: organizationID, id: group.id)
            sharing.groups[organizationID] = try await session.organizationGroups(organizationId: organizationID)
            toast = Toast(message: "Groupe « \(group.name) » supprimé", detail: nil)
        } catch {
            toast = Toast(message: "Suppression impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    // MARK: Commun

    /// Action d'une feuille : rend `true` si elle a réussi (la feuille se
    /// ferme), sinon l'erreur s'affiche dans la feuille.
    @discardableResult
    func sharingAction(_ action: @escaping () async throws -> Void) async -> Bool {
        guard !sharing.busy else { return false }
        sharing.busy = true
        sharing.error = nil
        defer { sharing.busy = false }
        do {
            try await action()
            return true
        } catch {
            sharing.error = ErrorText.describe(error)
            return false
        }
    }
}
