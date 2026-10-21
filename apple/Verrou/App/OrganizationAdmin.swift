import AppKit
import Observation
import SwiftUI

/// Management of shared vaults from the app: create, rename or leave an
/// organization, create and edit its collections (who accesses them, with
/// which rights), its groups, and join an organization with the invitation
/// link received by email. Everything goes through the Rust core, which
/// encrypts the names with the organization's key and checks the rights
/// before sending; the server checks them anyway.
@MainActor
@Observable
final class OrganizationAdminModel {
    var sheet: OrganizationSheet?
    var confirmLeave: OrganizationView?
    var confirmDelete: CollectionTarget?
    var busy = false
    var error: String?
    /// Organizations joined, waiting for an administrator's confirmation.
    var pending: [PendingMembershipView] = []
    /// Members to confirm, per administered organization.
    var toConfirm: [String: Int] = [:]
    /// Visual review: mock data, no server.
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

/// A collection targeted by an action (deletion).
struct CollectionTarget: Identifiable {
    let organization: OrganizationView
    let collection: CollectionView
    var id: String { collection.id }
}

/// The sheets of shared vault management.
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
    // MARK: Invitation status

    /// After a sync: what is new for the account (Rust core, each thing only
    /// once), posted as local notifications; organizations waiting for
    /// confirmation (without network) and members to confirm in those we
    /// administer (network), for the banners. `notify` false: everything is
    /// marked seen without notification (right after an action of this
    /// account, which must not be announced to it).
    func refreshSharingStatus(notify: Bool = true) async {
        guard mode == .vaultwarden, lockState == .unlocked, !organizationAdmin.preview else { return }
        let network = organizations.contains(where: \.canManageMembers) || emergencyAvailable
        guard let report = try? await session.checkActivity(network: network, emergency: emergencyAvailable,
                                                            notify: notify && ActivityNotifier.enabled),
              lockState == .unlocked else { return }
        // Assigned only if they change: the home screen doesn't redraw on
        // every sync for nothing.
        if organizationAdmin.pending != report.pending { organizationAdmin.pending = report.pending }
        if !organizations.contains(where: \.canManageMembers) {
            if !organizationAdmin.toConfirm.isEmpty { organizationAdmin.toConfirm = [:] }
        } else if report.toConfirmChecked {
            let toConfirm = Dictionary(report.toConfirm.map { ($0.organizationId, Int($0.count)) },
                                       uniquingKeysWith: { first, _ in first })
            if organizationAdmin.toConfirm != toConfirm { organizationAdmin.toConfirm = toConfirm }
        }
        ActivityNotifier.shared.post(report.notices)
        // Permission is requested when sharing concerns this account, never
        // at first launch.
        if report.organizations > 0 || !report.pending.isEmpty {
            await ActivityNotifier.shared.requestAuthorizationIfNeeded()
        }
    }

    /// The tap on a sharing notification: the screen that talks about it.
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

    /// "N members to confirm": the members pane of the first organization
    /// that has some.
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
            // Without a name, the core would name the first collection "General" in English.
            let collection = collection.trimmingCharacters(in: .whitespaces).isEmpty ? String(localized: "General") : collection
            let id = try await self.session.createOrganization(name: name, collectionName: collection)
            self.afterWrite(select: nil)
            self.organizationAdmin.sheet = nil
            self.filter = .organization(id: id)
            self.toast = Toast(message: String(localized: "Organization created"),
                               detail: String(localized: "Invite its members from “Members”, under its collections"))
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
            self.toast = Toast(message: String(localized: "Organization renamed"), detail: name.trimmingCharacters(in: .whitespaces))
        }
    }

    func leaveOrganization(_ organization: OrganizationView) async {
        organizationAdmin.confirmLeave = nil
        await organizationAction {
            try await self.session.leaveOrganization(organizationId: organization.id)
            if case .organization(organization.id) = self.filter { self.filter = .all }
            if organization.collections.contains(where: { self.filter == .collection(id: $0.id) }) { self.filter = .all }
            self.afterWrite(select: nil)
            self.toast = Toast(message: String(localized: "You left \(organization.name)"),
                               detail: String(localized: "Its items are no longer in your vault"))
        } failed: { message in
            self.toast = Toast(message: String(localized: "Couldn't leave \(organization.name)"), detail: message, failure: true)
        }
    }

    // MARK: Collections

    /// Opens the editor of a collection (`nil`: new); the sheet reads members,
    /// groups and access itself (`loadCollectionDraft`).
    func openCollectionEditor(_ organization: OrganizationView, collection: CollectionView?) {
        organizationAdmin.error = nil
        var draft = CollectionDraft(organizationID: organization.id, collectionID: collection?.id,
                                    name: collection?.name ?? "")
        // Visual review: nothing to read.
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
                    // Unreadable access: read the server's again so as not to erase them.
                    let current = try await self.session.collectionAccess(organizationId: draft.organizationID,
                                                                          collectionId: id)
                    try await self.session.updateCollection(organizationId: draft.organizationID, collectionId: id,
                                                            name: draft.name, access: current)
                }
                self.toast = Toast(message: String(localized: "Collection saved"), detail: draft.name)
            } else {
                let id = try await self.session.createCollection(organizationId: draft.organizationID,
                                                                 name: draft.name, access: draft.accessList)
                self.filter = .collection(id: id)
                self.toast = Toast(message: String(localized: "Collection created"), detail: draft.name)
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
            self.toast = Toast(message: String(localized: "Collection “\(target.collection.name)” deleted"),
                               detail: String(localized: "Its items stay in the organization"))
        } failed: { message in
            self.toast = Toast(message: String(localized: "Couldn't delete"), detail: message, failure: true)
        }
    }

    // MARK: Groups

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
            self.toast = Toast(message: group.id == nil ? String(localized: "Group created") : String(localized: "Group saved"), detail: group.name)
        }
    }

    func deleteGroup(_ group: OrganizationGroup, in organizationID: String) async {
        await organizationAction {
            try await self.session.deleteOrganizationGroup(organizationId: organizationID, id: group.id)
            try await self.reloadGroups(organizationID)
            self.toast = Toast(message: String(localized: "Group “\(group.name)” deleted"), detail: nil)
        }
    }

    private func reloadGroups(_ organizationID: String) async throws {
        guard case .groups(var draft) = organizationAdmin.sheet else { return }
        draft.groups = try await session.organizationGroups(organizationId: organizationID)
        draft.editing = nil
        organizationAdmin.sheet = .groups(draft)
    }

    // MARK: Received invitations

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
            self.toast = Toast(message: String(localized: "Invitation accepted"),
                               detail: String(localized: "An administrator of \(CoreText.organization(name)) must now confirm you: read them your fingerprint phrase"),
                               seconds: 8)
        }
    }

    // MARK: Common

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
