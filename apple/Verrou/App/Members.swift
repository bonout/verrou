import Observation
import SwiftUI

/// Members of an organization ("Members" pane of the sidebar): list,
/// invitation, confirmation after checking the fingerprint, roles and
/// collections. Everything goes through the Rust core, which checks the
/// rights and reads each member again on the server before acting.
@MainActor
@Observable
final class MembersModel {
    /// Displayed organization.
    private(set) var organizationID: String?
    private(set) var members: [OrganizationMember] = []
    private(set) var loaded = false
    var busy = false
    var error: String?
    var notice: String?
    /// Member displayed in the right column.
    var selection: String?
    /// Invitation, or edit of a member's role and collections.
    var draft: MemberDraft?
    /// Confirmation of a member: their key's fingerprint, to check with them.
    var confirmation: Confirmation?
    var confirmRemove: OrganizationMember?
    var confirmRevoke: OrganizationMember?
    /// Address just invited: its detail opens on "What's next?".
    var justInvited: String?
    /// Visual review: mock members, no server.
    var preview = false

    struct Confirmation: Identifiable {
        let id = UUID()
        let member: OrganizationMember
        let fingerprint: String
    }

    var selected: OrganizationMember? {
        selection.flatMap { id in members.first { $0.id == id } }
    }

    /// Members who accepted the invitation: to confirm.
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
            // To confirm first: that's what is waiting.
            selection = (members.first { $0.status == .accepted } ?? members.first)?.id
        }
    }

    /// On lock: list and drafts forgotten.
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
        justInvited = nil
        preview = false
    }
}

extension AppModel {
    /// The organization of the "Members" pane.
    var membersOrganization: OrganizationView? {
        organizations.first { $0.id == members.organizationID }
    }

    /// Sidebar: the organization's members pane.
    func openMembers(_ organizationID: String) {
        guard showsAccountPanes || members.preview else { return }
        showMainWindow()
        members.show(organizationID)
        pane = .members
        Task { await ActivityNotifier.shared.requestAuthorizationIfNeeded() }
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
            await membersAction(String(localized: "Access of \(member.displayName) saved.")) {
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
                    ? String(localized: "Invitation sent to \(invited[0]): see “What's next?”.")
                    : String(localized: "\(invited.count) invitations sent: see “What's next?”.")
                self.members.justInvited = invited.first
            }
            // Without email, the server automatically accepts an existing
            // account: this member to confirm is no news to whoever invites them.
            await refreshSharingStatus(notify: false)
            if let email = members.justInvited,
               let invited = members.members.first(where: { $0.email.caseInsensitiveCompare(email) == .orderedSame }) {
                members.selection = invited.id
            }
        }
    }

    func reinviteMember(_ member: OrganizationMember) async {
        await membersAction(String(localized: "Invitation sent again to \(member.email).")) {
            try await self.session.reinviteOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                              memberId: member.id)
        }
    }

    func revokeMember(_ member: OrganizationMember) async {
        await membersAction(String(localized: "Access of \(member.displayName) revoked.")) {
            try await self.session.revokeOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                            memberId: member.id)
        }
    }

    func restoreMember(_ member: OrganizationMember) async {
        await membersAction(String(localized: "Access of \(member.displayName) restored.")) {
            try await self.session.restoreOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                             memberId: member.id)
        }
    }

    func removeMember(_ member: OrganizationMember) async {
        await membersAction(String(localized: "\(member.displayName) is no longer part of the organization.")) {
            try await self.session.removeOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                            memberId: member.id)
            if self.members.selection == member.id { self.members.selection = nil }
        }
    }

    /// Before confirming: the fingerprint of the member's public key, read
    /// again on the server.
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
        await membersAction(String(localized: "\(confirmation.member.displayName) is confirmed: they have access to the shared collections.")) {
            try await self.session.confirmOrganizationMember(organizationId: self.members.organizationID ?? "",
                                                             memberId: confirmation.member.id,
                                                             fingerprint: confirmation.fingerprint)
        }
    }

    /// After creating an account with an invitation link: accept it, once
    /// logged in (second factor included).
    func acceptPendingInvitation() async {
        guard mode == .vaultwarden else { return }
        do {
            if let organization = try await session.acceptPendingInvitation() {
                toast = Toast(message: String(localized: "Invitation accepted"),
                              detail: String(localized: "An administrator of \(CoreText.organization(organization)) must now confirm you (Settings → Account: your fingerprint phrase)"),
                              seconds: 8)
            }
        } catch {
            toast = Toast(message: String(localized: "Invitation not accepted"), detail: Self.describe(error), failure: true)
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
