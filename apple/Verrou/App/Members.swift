import Observation
import SwiftUI

/// Membres d'une organisation (volet « Membres » de la barre latérale) :
/// liste, invitation, confirmation après vérification de l'empreinte,
/// rôles et collections. Tout passe par le cœur Rust, qui vérifie les
/// droits et relit chaque membre sur le serveur avant d'agir.
@MainActor
@Observable
final class MembersModel {
    /// Organisation affichée.
    private(set) var organizationID: String?
    private(set) var members: [OrganizationMember] = []
    private(set) var loaded = false
    var busy = false
    var error: String?
    var notice: String?
    /// Membre affiché dans la colonne de droite.
    var selection: String?
    /// Invitation, ou modification du rôle et des collections d'un membre.
    var draft: MemberDraft?
    /// Confirmation d'un membre : l'empreinte de sa clé, à vérifier avec lui.
    var confirmation: Confirmation?
    var confirmRemove: OrganizationMember?
    var confirmRevoke: OrganizationMember?
    /// Revue visuelle : membres fictifs, aucun serveur.
    var preview = false

    struct Confirmation: Identifiable {
        let id = UUID()
        let member: OrganizationMember
        let fingerprint: String
    }

    var selected: OrganizationMember? {
        selection.flatMap { id in members.first { $0.id == id } }
    }

    /// Membres qui ont accepté l'invitation : à confirmer.
    var pendingConfirmation: Int {
        members.filter { $0.status == .accepted }.count
    }

    func show(_ organizationID: String) {
        guard organizationID != self.organizationID else { return }
        self.organizationID = organizationID
        members = []
        loaded = false
        selection = nil
        error = nil
        notice = nil
    }

    func set(_ members: [OrganizationMember], organizationID: String) {
        guard organizationID == self.organizationID else { return }
        self.members = members
        loaded = true
        if selected == nil {
            // À confirmer d'abord : c'est ce qui attend.
            selection = (members.first { $0.status == .accepted } ?? members.first)?.id
        }
    }

    /// Au verrouillage : liste et brouillons oubliés.
    func clear() {
        organizationID = nil
        members = []
        loaded = false
        busy = false
        error = nil
        notice = nil
        selection = nil
        draft = nil
        confirmation = nil
        confirmRemove = nil
        confirmRevoke = nil
        preview = false
    }
}

extension AppModel {
    /// L'organisation du volet « Membres ».
    var membersOrganization: OrganizationView? {
        organizations.first { $0.id == members.organizationID }
    }

    /// Barre latérale : le volet des membres de l'organisation.
    func openMembers(_ organizationID: String) {
        guard showsAccountPanes || members.preview else { return }
        showMainWindow()
        members.show(organizationID)
        pane = .members
    }

    func reloadMembers() async {
        guard let organizationID = members.organizationID, !members.preview, lockState == .unlocked else { return }
        do {
            let list = try await session.organizationMembers(organizationId: organizationID)
            members.set(list, organizationID: organizationID)
            members.error = nil
        } catch {
            members.error = Self.describe(error)
        }
    }

    func inviteMembers() {
        let first = membersOrganization?.collections.first { !$0.readOnly }
        members.draft = MemberDraft(member: nil, emails: "", role: .user,
                                    access: first.map { [$0.id: .edit] } ?? [:])
    }

    func editMember(_ member: OrganizationMember) {
        var access: [String: CollectionPermission] = [:]
        for collection in member.collections {
            access[collection.collectionId] = CollectionPermission(collection)
        }
        members.draft = MemberDraft(member: member, emails: member.email, role: member.role, access: access)
    }

    func saveMemberDraft(_ draft: MemberDraft) async {
        guard let organizationID = members.organizationID else { return }
        if let member = draft.member {
            await membersAction("Accès de \(member.displayName) enregistrés.") {
                try await self.session.editOrganizationMember(organizationId: organizationID, memberId: member.id,
                                                             role: draft.role, collections: draft.collections)
                self.members.draft = nil
            }
        } else {
            await membersAction(nil) {
                let invited = try await self.session.inviteOrganizationMembers(
                    organizationId: organizationID, emails: draft.emails, role: draft.role,
                    collections: draft.collections)
                self.members.draft = nil
                self.members.notice = invited.count == 1
                    ? "Invitation envoyée à \(invited[0])."
                    : "\(invited.count) invitations envoyées."
            }
        }
    }

    func reinviteMember(_ member: OrganizationMember) async {
        await membersAction("Invitation renvoyée à \(member.email).") {
            try await self.session.reinviteOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                              memberId: member.id)
        }
    }

    func revokeMember(_ member: OrganizationMember) async {
        await membersAction("Accès de \(member.displayName) révoqué.") {
            try await self.session.revokeOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                            memberId: member.id)
        }
    }

    func restoreMember(_ member: OrganizationMember) async {
        await membersAction("Accès de \(member.displayName) restauré.") {
            try await self.session.restoreOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                             memberId: member.id)
        }
    }

    func removeMember(_ member: OrganizationMember) async {
        await membersAction("\(member.displayName) ne fait plus partie de l'organisation.") {
            try await self.session.removeOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                            memberId: member.id)
            if self.members.selection == member.id { self.members.selection = nil }
        }
    }

    /// Avant de confirmer : l'empreinte de la clé publique du membre, relue
    /// sur le serveur.
    func prepareMemberConfirmation(_ member: OrganizationMember) async {
        guard let organizationID = members.organizationID, !members.busy else { return }
        members.busy = true
        defer { members.busy = false }
        do {
            let fingerprint = try await session.organizationMemberFingerprint(organizationId: organizationID,
                                                                               memberId: member.id)
            members.confirmation = .init(member: member, fingerprint: fingerprint)
            members.error = nil
        } catch {
            members.error = Self.describe(error)
        }
    }

    func confirmMember(_ confirmation: MembersModel.Confirmation) async {
        members.confirmation = nil
        await membersAction("\(confirmation.member.displayName) est confirmé : il a accès aux collections partagées.") {
            try await self.session.confirmOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                             memberId: confirmation.member.id,
                                                             fingerprint: confirmation.fingerprint)
        }
    }

    /// Après la création d'un compte avec un lien d'invitation : l'accepter,
    /// une fois connecté (second facteur compris).
    func acceptPendingInvitation() async {
        guard mode == .vaultwarden else { return }
        do {
            if let organization = try await session.acceptPendingInvitation() {
                toast = Toast(message: "Invitation acceptée",
                              detail: "Un administrateur de \(organization) doit maintenant vous confirmer (Réglages → Compte : votre phrase d'empreinte)",
                              seconds: 8)
            }
        } catch {
            toast = Toast(message: "Invitation non acceptée", detail: Self.describe(error), failure: true)
        }
    }

    private func membersAction(_ done: String?, _ action: @escaping () async throws -> Void) async {
        guard !members.busy, !members.preview else { return }
        members.busy = true
        defer { members.busy = false }
        do {
            try await action()
            if let done { members.notice = done }
            members.error = nil
            await reloadMembers()
        } catch {
            members.error = Self.describe(error)
        }
    }
}
