import Observation
import SwiftUI
import UIKit

/// Sharing with the server's other accounts, on the iPhone: sharing items
/// into a shared vault, managing organizations, their collections, their
/// members and their groups, joining an organization with the invitation
/// link. Same Rust core as the Mac: it checks permissions before sending,
/// encrypts with the organization's key (which never leaves the SDK) and
/// clearly refuses offline.
@MainActor
@Observable
final class PhoneSharingModel {
    /// "Share…" or "Collections…" open.
    var shareFlow: SharingFlow?
    var sheet: PhoneSharingSheet?
    /// Joined organizations, awaiting an administrator's confirmation.
    var pending: [PendingMembershipView] = []
    /// Members to confirm, per administered organization.
    var toConfirm: [String: Int] = [:]
    /// Members and groups read, per organization.
    var members: [String: [OrganizationMember]] = [:]
    var groups: [String: [OrganizationGroup]] = [:]
    var loading: Set<String> = []
    var busy = false
    /// Error shown in the open sheet.
    var error: String?
    /// A member's fingerprint to verify before confirming them.
    var confirmation: MemberConfirmation?
    var confirmLeave: OrganizationView?
    var confirmDelete: CollectionTarget?
    var confirmRemove: MemberTarget?
    var confirmRevoke: MemberTarget?
    /// The account's Sends (Bitwarden Send); `nil`: not read yet.
    var sends: [SendSummary]?
    var sendComposer: SendComposer?
    /// Link of the Send just created (it carries its key).
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

/// The sheets of shared vault management.
enum PhoneSharingSheet: Identifiable {
    case newOrganization
    case rename(OrganizationView)
    case collection(CollectionDraft)
    case member(MemberDraft, organizationID: String)
    case group(GroupDraft, organizationID: String)
    /// Link already known (pasted or received), otherwise empty.
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

    // MARK: Sharing items

    /// The items a share can move: personal, editable, not in the trash.
    func shareableIDs(_ ids: [String]) -> [String] {
        ids.filter { id in
            guard let summary = summary(id: id) else { return false }
            return summary.sharing == nil && canModify(summary) && summary.state != .trashed
        }
    }

    /// "Share…" (personal item) or "Collections…" (already shared).
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

    /// "Share…" on a selection: only the editable personal items go, the
    /// others are counted.
    func openSharing(items ids: [String]) {
        let personal = shareableIDs(ids)
        guard canEdit, !personal.isEmpty else { return }
        guard let org = writableOrganizations.first else {
            toast = Toast(message: String(localized: "No shared vault"),
                          detail: String(localized: "Create an organization from the home screen (Shared vaults)"), failure: true)
            return
        }
        let title = personal.count == 1 ? summary(id: personal[0])?.title ?? "" : String(localized: "\(personal.count) items")
        let first = org.collections.first { !$0.readOnly }
        openShareFlow(SharingFlow(itemIDs: personal, title: title, current: nil, organizationID: org.id,
                                 collectionIDs: Set(first.map { [$0.id] } ?? [])))
    }

    private func openShareFlow(_ flow: SharingFlow) {
        sharing.error = nil
        sharing.shareFlow = flow
    }

    /// Runs the sheet: share (one or more items), or new collections.
    /// Returns `true` if the sheet can close.
    @discardableResult
    func applySharing(_ flow: SharingFlow) async -> Bool {
        guard !flow.busy else { return false }
        if flow.current == nil {
            let protected = flow.itemIDs.filter { session.needsConfirmation(id: $0) }
            if let first = protected.first {
                let title = protected.count == 1 ? summary(id: first)?.title ?? flow.title
                                                 : String(localized: "\(protected.count) protected items")
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
                toast = Toast(message: String(localized: "Collections saved"), detail: org?.name)
            } else if !flow.isBulk {
                try await session.shareItem(id: flow.itemID, organizationId: flow.organizationID, collectionIds: ordered)
                afterWrite()
                toast = Toast(message: String(localized: "Item shared"), detail: org?.name)
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

    // MARK: Invitations and confirmations

    /// After a sync: what is new for the account (Rust core, each thing only
    /// once), posted as local notifications; organizations awaiting
    /// confirmation (no network) and members to confirm in the ones we
    /// administer (network), for the banners. `notify` false: everything is
    /// marked seen without notification (right after an action of this
    /// account).
    func refreshSharingStatus(notify: Bool = true) async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        let manages = organizations.contains(where: \.canManageMembers)
        guard let report = try? await session.checkActivity(network: manages, emergency: false,
                                                            notify: notify && ActivityNotifier.enabled),
              lockState == .unlocked else { return }
        // Assigned only if they change: the home screen isn't redrawn for
        // nothing at each sync.
        if sharing.pending != report.pending { sharing.pending = report.pending }
        if !manages {
            if !sharing.toConfirm.isEmpty { sharing.toConfirm = [:] }
        } else if report.toConfirmChecked {
            let toConfirm = Dictionary(report.toConfirm.map { ($0.organizationId, Int($0.count)) },
                                       uniquingKeysWith: { first, _ in first })
            if sharing.toConfirm != toConfirm { sharing.toConfirm = toConfirm }
        }
        ActivityNotifier.shared.post(report.notices)
        // Badge: what awaits an action.
        ActivityNotifier.shared.setBadge(sharing.totalToConfirm + sharing.pending.count)
        // Authorization is requested when sharing concerns this account,
        // never on first launch.
        if report.organizations > 0 || !report.pending.isEmpty {
            await ActivityNotifier.shared.requestAuthorizationIfNeeded()
        }
    }

    /// Tapping a sharing notification: the screen that talks about it.
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

    /// "N members to confirm": the members of the first organization that
    /// has some.
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
            self.toast = Toast(message: String(localized: "Invitation accepted"),
                               detail: String(localized: "An administrator of \(CoreText.organization(name)) must confirm you: read them your fingerprint phrase"),
                               seconds: 8)
        }
    }

    // MARK: Organizations

    func createOrganization(name: String, collection: String) async -> Bool {
        await sharingAction {
            // Without a name, the core would name the first collection "General" in English.
            let collection = collection.trimmingCharacters(in: .whitespaces).isEmpty ? String(localized: "General") : collection
            let id = try await self.session.createOrganization(name: name, collectionName: collection)
            self.afterWrite()
            self.tab = .vault
            self.vaultPath = [.organization(id)]
            self.toast = Toast(message: String(localized: "Organization created"), detail: String(localized: "Invite its members from “Members”"))
        }
    }

    func renameOrganization(_ organization: OrganizationView, to name: String) async -> Bool {
        await sharingAction {
            try await self.session.renameOrganization(organizationId: organization.id, name: name)
            self.afterWrite()
            self.toast = Toast(message: String(localized: "Organization renamed"), detail: name.trimmingCharacters(in: .whitespaces))
        }
    }

    func leaveOrganization(_ organization: OrganizationView) async {
        sharing.confirmLeave = nil
        let left = await sharingAction {
            try await self.session.leaveOrganization(organizationId: organization.id)
            self.vaultPath = []
            self.afterWrite()
            self.toast = Toast(message: String(localized: "You left \(organization.name)"),
                               detail: String(localized: "Its items are no longer in your vault"))
        }
        if !left, let error = sharing.error {
            sharing.error = nil
            toast = Toast(message: String(localized: "Could not leave \(organization.name)"), detail: error, failure: true)
        }
    }

    // MARK: Collections

    /// A collection's editor (`nil`: new); the sheet itself reads members,
    /// groups and access (`loadCollectionDraft`).
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
                self.toast = Toast(message: String(localized: "Collection saved"), detail: draft.name)
            } else {
                _ = try await self.session.createCollection(organizationId: draft.organizationID,
                                                            name: draft.name, access: draft.accessList)
                self.toast = Toast(message: String(localized: "Collection created"), detail: draft.name)
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
            toast = Toast(message: String(localized: "Collection “\(target.collection.name)” deleted"),
                          detail: String(localized: "Its items stay in the organization"))
        } catch {
            toast = Toast(message: String(localized: "Could not delete"), detail: ErrorText.describe(error), failure: true)
        }
    }

    // MARK: Members

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
            toast = Toast(message: String(localized: "Could not read members"), detail: ErrorText.describe(error), failure: true)
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
                self.toast = Toast(message: String(localized: "Access for \(member.displayName) saved"), detail: nil)
            } else {
                let invited = try await self.session.inviteOrganizationMembers(
                    organizationId: organizationID, emails: draft.emails, role: draft.role, collections: draft.collections)
                self.toast = Toast(message: invited.count == 1 ? String(localized: "Invitation sent") : String(localized: "\(invited.count) invitations sent"),
                                   detail: String(localized: "\(invited.joined(separator: ", ")): see “What's next?” under the invitations"))
                // Without email, the server automatically accepts an existing
                // account: this member to confirm is not news for the one who
                // invites.
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
            toast = Toast(message: String(localized: "Action failed"), detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Before confirming: the fingerprint of the member's public key, read
    /// again from the server, to compare out loud with theirs.
    func prepareConfirmation(_ member: OrganizationMember, in organizationID: String) async {
        do {
            let fingerprint = try await session.organizationMemberFingerprint(organizationId: organizationID,
                                                                               memberId: member.id)
            sharing.confirmation = MemberConfirmation(organizationID: organizationID, member: member,
                                                      fingerprint: fingerprint)
        } catch {
            toast = Toast(message: String(localized: "Could not read fingerprint"), detail: ErrorText.describe(error), failure: true)
        }
    }

    func confirmMember(_ confirmation: MemberConfirmation) async {
        sharing.confirmation = nil
        await memberAction(String(localized: "\(confirmation.member.displayName) is confirmed"), in: confirmation.organizationID) {
            try await self.session.confirmOrganizationMember(organizationId: confirmation.organizationID,
                                                             memberId: confirmation.member.id,
                                                             fingerprint: confirmation.fingerprint)
        }
    }

    // MARK: Groups

    func saveGroup(_ group: GroupDraft, in organizationID: String) async -> Bool {
        await sharingAction {
            _ = try await self.session.saveOrganizationGroup(
                organizationId: organizationID, id: group.id, name: group.name,
                members: group.members.sorted(), collections: group.collections)
            self.sharing.groups[organizationID] = try await self.session.organizationGroups(organizationId: organizationID)
            self.toast = Toast(message: group.id == nil ? String(localized: "Group created") : String(localized: "Group saved"), detail: group.name)
        }
    }

    func deleteGroup(_ group: OrganizationGroup, in organizationID: String) async {
        do {
            try await session.deleteOrganizationGroup(organizationId: organizationID, id: group.id)
            sharing.groups[organizationID] = try await session.organizationGroups(organizationId: organizationID)
            toast = Toast(message: String(localized: "Group “\(group.name)” deleted"), detail: nil)
        } catch {
            toast = Toast(message: String(localized: "Could not delete"), detail: ErrorText.describe(error), failure: true)
        }
    }

    // MARK: Common

    /// A sheet's action: returns `true` if it succeeded (the sheet closes),
    /// otherwise the error is shown in the sheet.
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
