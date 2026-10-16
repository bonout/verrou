import Observation
import SwiftUI

// Partage avec d'autres comptes : les brouillons et les libellés communs aux
// apps Mac et iPhone (droits sur une collection, invitation, collection,
// groupe). Les actions passent par le cœur Rust (`VaultSession`), qui
// vérifie les droits et chiffre avec la clé de l'organisation.

/// Droits sur une collection, comme dans le coffre web.
enum CollectionPermission: String, CaseIterable, Identifiable {
    case view, viewExceptPasswords, edit, editExceptPasswords, manage

    var id: String { rawValue }

    var label: String {
        switch self {
        case .view: "Voir"
        case .viewExceptPasswords: "Voir, sans les mots de passe"
        case .edit: "Modifier"
        case .editExceptPasswords: "Modifier, sans les mots de passe"
        case .manage: "Gérer"
        }
    }

    init(_ access: MemberCollectionAccess) {
        switch (access.manage, access.readOnly, access.hidePasswords) {
        case (true, _, _): self = .manage
        case (false, true, true): self = .viewExceptPasswords
        case (false, true, false): self = .view
        case (false, false, true): self = .editExceptPasswords
        case (false, false, false): self = .edit
        }
    }

    func access(_ collectionID: String) -> MemberCollectionAccess {
        MemberCollectionAccess(collectionId: collectionID,
                               readOnly: self == .view || self == .viewExceptPasswords,
                               hidePasswords: self == .viewExceptPasswords || self == .editExceptPasswords,
                               manage: self == .manage)
    }
}

/// Invitation (une ou plusieurs adresses) ou modification d'un membre.
struct MemberDraft: Identifiable {
    let id = UUID()
    /// `nil` : nouvelle invitation.
    let member: OrganizationMember?
    var emails: String
    var role: OrganizationMemberRole
    /// Collections accordées, et le droit sur chacune.
    var access: [String: CollectionPermission]

    var isNew: Bool { member == nil }

    /// Propriétaires et administrateurs voient toutes les collections.
    var seesAll: Bool { role == .owner || role == .admin }

    var collections: [MemberCollectionAccess] {
        seesAll ? [] : access.map { $1.access($0) }.sorted { $0.collectionId < $1.collectionId }
    }
}

/// Création ou modification d'une collection : son nom, et qui y accède.
struct CollectionDraft {
    let organizationID: String
    /// `nil` : nouvelle collection.
    let collectionID: String?
    var name: String
    /// Membres de l'organisation (si le compte peut les voir).
    var members: [OrganizationMember] = []
    /// Groupes de l'organisation (si le serveur les active).
    var groups: [OrganizationGroup] = []
    /// Accès accordés : identifiant d'adhésion → droit.
    var memberAccess: [String: CollectionPermission] = [:]
    /// Accès accordés : identifiant de groupe → droit.
    var groupAccess: [String: CollectionPermission] = [:]
    var loading = true
    /// Les membres n'ont pas pu être lus : seul le nom est modifiable, les
    /// accès restent comme ils sont.
    var accessUnavailable: String?

    var isNew: Bool { collectionID == nil }

    var accessList: CollectionAccessList {
        CollectionAccessList(
            members: memberAccess.map { $1.grant($0) }.sorted { $0.id < $1.id },
            groups: groupAccess.map { $1.grant($0) }.sorted { $0.id < $1.id })
    }
}

/// Les groupes d'une organisation, et celui en cours de modification.
struct GroupsDraft {
    let organizationID: String
    var groups: [OrganizationGroup] = []
    var members: [OrganizationMember] = []
    var editing: GroupDraft?
    var loading = true
}

struct GroupDraft {
    /// `nil` : nouveau groupe.
    let id: String?
    var name: String
    var members: Set<String>
    var access: [String: CollectionPermission]

    var collections: [MemberCollectionAccess] {
        access.map { $1.access($0) }.sorted { $0.collectionId < $1.collectionId }
    }
}

extension CollectionPermission {
    init(_ grant: AccessGrant) {
        self.init(MemberCollectionAccess(collectionId: grant.id, readOnly: grant.readOnly,
                                         hidePasswords: grant.hidePasswords, manage: grant.manage))
    }

    func grant(_ id: String) -> AccessGrant {
        let access = access(id)
        return AccessGrant(id: id, readOnly: access.readOnly, hidePasswords: access.hidePasswords,
                           manage: access.manage)
    }
}

extension GroupDraft {
    init(_ group: OrganizationGroup) {
        var access: [String: CollectionPermission] = [:]
        for collection in group.collections { access[collection.collectionId] = CollectionPermission(collection) }
        self.init(id: group.id, name: group.name, members: Set(group.members), access: access)
    }
}

/// Bilan d'un partage de plusieurs éléments, pour le message affiché :
/// « 12 éléments partagés dans Famille, 2 ignorés (déjà partagés) ».
extension ShareResult {
    func toast(organization: String?) -> Toast {
        let n = Int(shared)
        var message = "\(n) élément\(n > 1 ? "s" : "") partagé\(n > 1 ? "s" : "")"
        if let organization { message += " dans \(organization)" }
        var ignored: [String] = []
        let plural = { (count: UInt32) in count > 1 ? "s" : "" }
        if alreadyShared > 0 { ignored.append("\(alreadyShared) ignoré\(plural(alreadyShared)) (déjà partagé\(plural(alreadyShared)))") }
        if readOnly > 0 { ignored.append("\(readOnly) ignoré\(plural(readOnly)) (lecture seule)") }
        if inTrash > 0 { ignored.append("\(inTrash) ignoré\(plural(inTrash)) (dans la corbeille)") }
        if notFound > 0 { ignored.append("\(notFound) introuvable\(plural(notFound))") }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !failures.isEmpty {
            return Toast(message: message + ", \(failures.count) refusé\(failures.count > 1 ? "s" : "")",
                         detail: failures.joined(separator: "\n"), failure: true, seconds: 6)
        }
        return Toast(message: message, detail: nil, seconds: ignored.isEmpty ? 2.5 : 4)
    }
}

extension OrganizationMember {
    var displayName: String { name ?? email }
}

extension OrganizationMemberRole {
    var label: String {
        switch self {
        case .owner: "Propriétaire"
        case .admin: "Administrateur"
        case .user: "Utilisateur"
        case .manager: "Gestionnaire"
        }
    }

    var symbol: String {
        switch self {
        case .owner: "crown"
        case .admin: "person.badge.key"
        case .user: "person"
        case .manager: "person.badge.shield.checkmark"
        }
    }

    var explanation: String {
        switch self {
        case .owner: "Tous les droits, y compris sur les autres propriétaires et administrateurs."
        case .admin: "Voit toutes les collections, invite, confirme et gère les utilisateurs."
        case .user: "Accède aux collections qui lui sont attribuées."
        case .manager: "Gère les collections qui lui sont attribuées (et leurs accès)."
        }
    }
}

extension OrganizationMemberStatus {
    var label: String {
        switch self {
        case .invited: "Invité"
        case .accepted: "Accepté — à confirmer"
        case .confirmed: "Confirmé"
        case .revoked: "Révoqué"
        }
    }

    var tint: Color {
        switch self {
        case .invited: .secondary
        case .accepted: .orange
        case .confirmed: .green
        case .revoked: .red
        }
    }
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

/// Avancement d'un partage groupé, envoyé par Rust depuis son fil.
final class ShareProgressRelay: BulkProgress, @unchecked Sendable {
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

extension VaultSession {
    /// Le brouillon d'une collection, complété sur le serveur : membres de
    /// l'organisation (si le rôle permet de les voir), groupes (si le
    /// serveur les active), accès actuels de la collection (nouvelle :
    /// celui qui la crée y a accès, sauf s'il voit déjà tout). En cas
    /// d'échec, `accessUnavailable` dit pourquoi : seul le nom reste
    /// modifiable, et les accès du serveur sont gardés tels quels.
    func loadCollectionDraft(_ draft: CollectionDraft, organization: OrganizationView,
                             accountEmail: String?) async -> CollectionDraft {
        var draft = draft
        do {
            if organization.canViewMembers {
                draft.members = try await organizationMembers(organizationId: organization.id)
            } else {
                draft.accessUnavailable = "Votre rôle ne permet pas de voir les membres : seul le nom se modifie ici."
            }
            if organization.useGroups {
                draft.groups = try await organizationGroups(organizationId: organization.id)
            }
            if let collectionID = draft.collectionID, draft.accessUnavailable == nil {
                let access = try await collectionAccess(organizationId: organization.id, collectionId: collectionID)
                // Propriétaires et administrateurs voient tout de toute façon.
                let seesAll = Set(draft.members.filter(\.accessAll).map(\.id))
                for grant in access.members where !seesAll.contains(grant.id) {
                    draft.memberAccess[grant.id] = CollectionPermission(grant)
                }
                for grant in access.groups { draft.groupAccess[grant.id] = CollectionPermission(grant) }
            } else if draft.collectionID == nil,
                      let me = draft.members.first(where: { $0.email.caseInsensitiveCompare(accountEmail ?? "") == .orderedSame }),
                      !me.accessAll {
                draft.memberAccess[me.id] = .manage
            }
        } catch {
            draft.accessUnavailable = ErrorText.describe(error)
        }
        draft.loading = false
        return draft
    }
}
