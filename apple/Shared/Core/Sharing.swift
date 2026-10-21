import Observation
import SwiftUI

// Sharing with other accounts: the drafts and labels shared by the Mac and
// iPhone apps (permissions on a collection, invitation, collection, group).
// Actions go through the Rust core (`VaultSession`), which checks the
// permissions and encrypts with the organization's key.

/// Permissions on a collection, as in the web vault.
enum CollectionPermission: String, CaseIterable, Identifiable {
    case view, viewExceptPasswords, edit, editExceptPasswords, manage

    var id: String { rawValue }

    var label: String {
        switch self {
        case .view: String(localized: "View")
        case .viewExceptPasswords: String(localized: "View, without passwords")
        case .edit: String(localized: "Edit")
        case .editExceptPasswords: String(localized: "Edit, without passwords")
        case .manage: String(localized: "Manage")
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

/// Invitation (one or more addresses) or edit of a member.
struct MemberDraft: Identifiable {
    let id = UUID()
    /// `nil`: new invitation.
    let member: OrganizationMember?
    var emails: String
    var role: OrganizationMemberRole
    /// Granted collections, and the permission on each.
    var access: [String: CollectionPermission]

    var isNew: Bool { member == nil }

    /// Owners and administrators see all collections.
    var seesAll: Bool { role == .owner || role == .admin }

    var collections: [MemberCollectionAccess] {
        seesAll ? [] : access.map { $1.access($0) }.sorted { $0.collectionId < $1.collectionId }
    }
}

/// Creating or editing a collection: its name, and who has access.
struct CollectionDraft {
    let organizationID: String
    /// `nil`: new collection.
    let collectionID: String?
    var name: String
    /// The organization's members (if the account can see them).
    var members: [OrganizationMember] = []
    /// The organization's groups (if the server enables them).
    var groups: [OrganizationGroup] = []
    /// Granted access: membership ID → permission.
    var memberAccess: [String: CollectionPermission] = [:]
    /// Granted access: group ID → permission.
    var groupAccess: [String: CollectionPermission] = [:]
    var loading = true
    /// The members could not be read: only the name can be edited, access
    /// stays as it is.
    var accessUnavailable: String?

    var isNew: Bool { collectionID == nil }

    var accessList: CollectionAccessList {
        CollectionAccessList(
            members: memberAccess.map { $1.grant($0) }.sorted { $0.id < $1.id },
            groups: groupAccess.map { $1.grant($0) }.sorted { $0.id < $1.id })
    }
}

/// An organization's groups, and the one being edited.
struct GroupsDraft {
    let organizationID: String
    var groups: [OrganizationGroup] = []
    var members: [OrganizationMember] = []
    var editing: GroupDraft?
    var loading = true
}

struct GroupDraft {
    /// `nil`: new group.
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

/// Outcome of sharing several items, for the message shown:
/// "12 items shared in Family, 2 skipped (already shared)".
extension ShareResult {
    func toast(organization: String?) -> Toast {
        let n = Int(shared)
        var message = n > 1 ? String(localized: "\(n) items shared") : String(localized: "\(n) item shared")
        if let organization { message += " " + String(localized: "in \(organization)") }
        var ignored: [String] = []
        if alreadyShared > 0 { ignored.append(alreadyShared > 1 ? String(localized: "\(alreadyShared) skipped items (already shared)") : String(localized: "\(alreadyShared) skipped item (already shared)")) }
        if readOnly > 0 { ignored.append(readOnly > 1 ? String(localized: "\(readOnly) skipped items (read-only)") : String(localized: "\(readOnly) skipped item (read-only)")) }
        if inTrash > 0 { ignored.append(inTrash > 1 ? String(localized: "\(inTrash) skipped items (in the trash)") : String(localized: "\(inTrash) skipped item (in the trash)")) }
        if notFound > 0 { ignored.append(notFound > 1 ? String(localized: "\(notFound) items not found") : String(localized: "\(notFound) item not found")) }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !failures.isEmpty {
            return Toast(message: message + ", " + (failures.count > 1 ? String(localized: "\(failures.count) refused items") : String(localized: "\(failures.count) refused item")),
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
        case .owner: String(localized: "Owner")
        case .admin: String(localized: "Administrator")
        case .user: String(localized: "User")
        case .manager: String(localized: "Manager")
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
        case .owner: String(localized: "All rights, including over the other owners and administrators.")
        case .admin: String(localized: "Sees all collections, invites, confirms and manages users.")
        case .user: String(localized: "Accesses the collections assigned to them.")
        case .manager: String(localized: "Manages the collections assigned to them (and their access).")
        }
    }
}

extension OrganizationMemberStatus {
    var label: String {
        switch self {
        case .invited: String(localized: "Invited")
        case .accepted: String(localized: "Accepted — to confirm")
        case .confirmed: String(localized: "Confirmed")
        case .revoked: String(localized: "Revoked")
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

/// "Share…" (one or more personal items) or "Collections…" (item already
/// shared): the sheet keeps its state, the model runs it.
@MainActor
@Observable
final class SharingFlow: Identifiable {
    let id = UUID()
    /// Items to share (only one for "Collections…").
    let itemIDs: [String]
    let title: String
    /// Already in an organization: only its collections change.
    let current: ItemSharing?
    var organizationID: String
    var collectionIDs: Set<String>
    var busy = false
    var error: String?
    /// Progress of a bulk share.
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

/// Progress of a bulk share, sent by Rust from its thread.
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
    /// A collection's draft, completed from the server: the organization's
    /// members (if the role allows seeing them), groups (if the server
    /// enables them), the collection's current access (new: whoever creates
    /// it has access, unless they already see everything). On failure,
    /// `accessUnavailable` says why: only the name stays editable, and the
    /// server's access is kept as is.
    func loadCollectionDraft(_ draft: CollectionDraft, organization: OrganizationView,
                             accountEmail: String?) async -> CollectionDraft {
        var draft = draft
        do {
            if organization.canViewMembers {
                draft.members = try await organizationMembers(organizationId: organization.id)
            } else {
                draft.accessUnavailable = String(localized: "Your role doesn't allow seeing the members: only the name can be edited here.")
            }
            if organization.useGroups {
                draft.groups = try await organizationGroups(organizationId: organization.id)
            }
            if let collectionID = draft.collectionID, draft.accessUnavailable == nil {
                let access = try await collectionAccess(organizationId: organization.id, collectionId: collectionID)
                // Owners and administrators see everything anyway.
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
