import SwiftUI

// MARK: Home

/// The home screen's "Shared vaults" section: members to confirm, pending
/// invitations, each organization (to its screen) and its collections
/// (create or join: the home screen's "+" menu).
struct SharedVaultsHomeSection: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        let sharing = model.sharing
        // Without a shared vault, nothing to build: creating or joining an
        // organization goes through the home screen's "+" menu. Only the
        // organizations: their collections are on the organization's page.
        if !model.organizations.isEmpty {
            Section {
                ForEach(model.organizations, id: \.id) { org in
                    NavigationLink(value: PhoneModel.Route.organization(org.id)) {
                        HStack(spacing: 12) {
                            TintedSymbol(symbol: "person.2.fill", tint: .indigo)
                            Text(org.name)
                            Spacer()
                            if let pending = sharing.toConfirm[org.id], pending > 0 {
                                Badge(text: "\(pending)", tint: .orange)
                            }
                            Text("\(org.count)").foregroundStyle(.secondary).monospacedDigit()
                        }
                    }
                }
            } header: {
                SectionHeader("Shared vaults")
            }
        }
    }
}

/// At the top of the home screen, like the pending changes: the members to
/// confirm (administrators) and the accepted invitations awaiting their
/// confirmation.
struct SharingBanners: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        let sharing = model.sharing
        if sharing.totalToConfirm > 0 || !sharing.pending.isEmpty {
            Section {
                if sharing.totalToConfirm > 0 {
                    Button {
                        model.openFirstMembersToConfirm()
                    } label: {
                        HStack(spacing: 12) {
                            TintedSymbol(symbol: "person.badge.clock.fill", tint: .orange)
                            let n = sharing.totalToConfirm
                            Text(n > 1 ? "\(n) members to confirm" : "\(n) member to confirm").foregroundStyle(.primary)
                            Spacer()
                            Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
                        }
                    }
                    .tint(.primary)
                    .accessibilityIdentifier("members-to-confirm")
                }
                ForEach(sharing.pending, id: \.organizationId) { pending in
                    Button {
                        model.sharing.sheet = .fingerprint(pending)
                    } label: {
                        HStack(spacing: 12) {
                            TintedSymbol(symbol: "hourglass", tint: .orange)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(pending.name).foregroundStyle(.primary)
                                Text("Awaiting confirmation").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "info.circle").foregroundStyle(.secondary)
                        }
                    }
                    .tint(.primary)
                    .accessibilityIdentifier("pending-\(pending.name)")
                }
            }
        }
    }
}

// MARK: Organization

/// A shared vault: its items, its collections (managed according to the
/// permissions), its members, its groups, and a way to rename or leave it.
struct OrganizationScreen: View {
    @Environment(PhoneModel.self) private var model
    let organizationID: String

    var body: some View {
        if let org = model.organization(organizationID) {
            content(org)
        } else {
            ContentUnavailableView("Organization unavailable", systemImage: "person.2.slash",
                                   description: Text("You are no longer part of this shared vault."))
        }
    }

    private func content(_ org: OrganizationView) -> some View {
        List {
            Section {
                NavigationLink(value: PhoneModel.Route.list(.organization(id: org.id))) {
                    HStack(spacing: 12) {
                        TintedSymbol(symbol: "square.grid.2x2.fill", tint: .indigo)
                        Text("All its items")
                        Spacer()
                        Text("\(org.count)").foregroundStyle(.secondary).monospacedDigit()
                    }
                }
            } footer: {
                Text(roleLine(org))
            }
            Section {
                ForEach(org.collections, id: \.id) { collection in
                    NavigationLink(value: PhoneModel.Route.list(.collection(id: collection.id))) {
                        HStack(spacing: 12) {
                            TintedSymbol(symbol: collection.readOnly ? "eye.fill" : "tray.full.fill",
                                         tint: .indigo.opacity(0.7))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(collection.name)
                                if let rights = rights(collection) {
                                    Text(rights).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            Text("\(collection.count)").foregroundStyle(.secondary).monospacedDigit()
                        }
                    }
                    .swipeActions(edge: .trailing) {
                        if model.canEdit && collection.canManage {
                            Button(role: .destructive) {
                                model.sharing.confirmDelete = CollectionTarget(organization: org, collection: collection)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                            Button {
                                model.openCollectionEditor(org, collection: collection)
                            } label: {
                                Label("Edit", systemImage: "slider.horizontal.3")
                            }
                            .tint(.indigo)
                        }
                    }
                    .contextMenu {
                        if model.canEdit && collection.canManage {
                            Button("Edit collection…", systemImage: "slider.horizontal.3") {
                                model.openCollectionEditor(org, collection: collection)
                            }
                            Button("Delete collection…", systemImage: "trash", role: .destructive) {
                                model.sharing.confirmDelete = CollectionTarget(organization: org, collection: collection)
                            }
                        }
                    }
                }
                if model.canEdit && org.canCreateCollections {
                    Button {
                        model.openCollectionEditor(org, collection: nil)
                    } label: {
                        Label("New collection…", systemImage: "plus.circle.fill")
                    }
                    .accessibilityIdentifier("new-collection")
                }
            } header: {
                SectionHeader("Collections")
            } footer: {
                if org.hasManagedCollections {
                    Text("Swipe a collection to the left to edit or delete it.")
                }
            }
            if org.canViewMembers || org.canManageGroups {
                Section {
                    if org.canViewMembers {
                        NavigationLink(value: PhoneModel.Route.members(org.id)) {
                            HStack(spacing: 12) {
                                TintedSymbol(symbol: "person.3.fill", tint: .teal)
                                Text("Members")
                                Spacer()
                                if let pending = model.sharing.toConfirm[org.id], pending > 0 {
                                    Badge(text: String(localized: "\(pending) to confirm"), tint: .orange)
                                }
                            }
                        }
                        .accessibilityIdentifier("members-link")
                    }
                    if org.canManageGroups {
                        NavigationLink(value: PhoneModel.Route.groups(org.id)) {
                            HStack(spacing: 12) {
                                TintedSymbol(symbol: "person.2.circle.fill", tint: .mint)
                                Text("Groups")
                            }
                        }
                    }
                } header: {
                    SectionHeader("People")
                }
            }
            if model.canEdit {
                Section {
                    if org.canRename {
                        Button("Rename organization…", systemImage: "pencil") { model.sharing.sheet = .rename(org) }
                    }
                    Button("Leave organization…", systemImage: "rectangle.portrait.and.arrow.right",
                           role: .destructive) {
                        model.sharing.confirmLeave = org
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(org.name)
        .navigationBarTitleDisplayMode(.large)
        .refreshable { await model.syncNow() }
    }

    private func roleLine(_ org: OrganizationView) -> String {
        let role = org.role?.label ?? String(localized: "Member")
        return String(localized: "Your role: \(role). The items shared here are encrypted with the organization's key.")
    }

    private func rights(_ collection: CollectionView) -> String? {
        var rights: [String] = []
        if collection.readOnly { rights.append(String(localized: "read-only")) }
        if collection.hidePasswords { rights.append(String(localized: "passwords hidden")) }
        if collection.canManage { rights.append(String(localized: "you manage it")) }
        return rights.isEmpty ? nil : rights.joined(separator: " · ")
    }
}

private extension OrganizationView {
    var hasManagedCollections: Bool { collections.contains(where: \.canManage) }
}

// MARK: Members

/// An organization's members, grouped by state; a tap opens their actions
/// (confirm after verifying the fingerprint, edit, revoke, remove).
struct MembersScreen: View {
    @Environment(PhoneModel.self) private var model
    let organizationID: String
    @State private var chosen: OrganizationMember?

    var body: some View {
        let org = model.organization(organizationID)
        let members = model.sharing.members[organizationID]
        List {
            if let members {
                section("To confirm", members.filter { $0.status == .accepted },
                        footer: "They accepted the invitation: verify their fingerprint phrase with them to give them the organization's key.")
                let invited = members.filter { $0.status == .invited }
                section("Pending invitations", invited)
                if !invited.isEmpty, org?.canManageMembers == true {
                    Section {
                        InvitationNextSteps(email: invited.count == 1 ? invited[0].email : nil,
                                            server: model.account?.server,
                                            hasAccount: invited.count == 1 ? invited[0].hasAccount : nil)
                            .accessibilityIdentifier("invitation-next-steps")
                    }
                }
                section("Members", members.filter { $0.status == .confirmed })
                section("Revoked members", members.filter { $0.status == .revoked })
            } else {
                ProgressView().frame(maxWidth: .infinity).listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Members")
        .navigationSubtitleIfAvailable(org?.name ?? "")
        .toolbar {
            if org?.canManageMembers == true, model.canEdit {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        model.inviteMembers(organizationID)
                    } label: {
                        Image(systemName: "person.badge.plus")
                    }
                    .accessibilityLabel("Invite")
                    .accessibilityIdentifier("invite-members")
                }
            }
        }
        .refreshable { await model.loadMembers(organizationID) }
        .task { await model.loadMembers(organizationID) }
        .confirmationDialog(chosen?.displayName ?? "", isPresented: Binding(get: { chosen != nil },
                                                                            set: { if !$0 { chosen = nil } }),
                            titleVisibility: .visible, presenting: chosen) { member in
            actions(member, org: org)
        } message: { member in
            Text("\(member.email) · \(member.role.label) · \(member.status.label)")
        }
    }

    @ViewBuilder
    private func section(_ title: LocalizedStringKey, _ members: [OrganizationMember], footer: LocalizedStringKey? = nil) -> some View {
        if !members.isEmpty {
            Section {
                ForEach(members, id: \.id) { member in
                    Button {
                        chosen = member
                    } label: {
                        MemberRow(member: member)
                    }
                    .tint(.primary)
                    .accessibilityIdentifier("member-\(member.email)")
                }
            } header: {
                SectionHeader(title)
            } footer: {
                if let footer { Text(footer) }
            }
        }
    }

    @ViewBuilder
    private func actions(_ member: OrganizationMember, org: OrganizationView?) -> some View {
        if org?.canManageMembers == true, model.canEdit {
            switch member.status {
            case .accepted:
                Button("Verify fingerprint and confirm…") {
                    Task { await model.prepareConfirmation(member, in: organizationID) }
                }
            case .invited:
                Button("Resend invitation") {
                    Task {
                        await model.memberAction(String(localized: "Invitation resent to \(member.email)"), in: organizationID) {
                            try await model.session.reinviteOrganizationMember(organizationId: organizationID,
                                                                               memberId: member.id)
                        }
                    }
                }
            case .revoked:
                Button("Restore access") {
                    Task {
                        await model.memberAction(String(localized: "Access for \(member.displayName) restored"), in: organizationID) {
                            try await model.session.restoreOrganizationMember(organizationId: organizationID,
                                                                              memberId: member.id)
                        }
                    }
                }
            case .confirmed:
                EmptyView()
            }
            Button("Edit role and collections…") { model.editMember(member, in: organizationID) }
            if member.status != .revoked {
                Button("Revoke access…", role: .destructive) {
                    model.sharing.confirmRevoke = MemberTarget(organizationID: organizationID, member: member)
                }
            }
            Button("Remove from organization…", role: .destructive) {
                model.sharing.confirmRemove = MemberTarget(organizationID: organizationID, member: member)
            }
        }
        Button("Copy address") { model.copy(member.email, label: String(localized: "Address"), secret: false) }
    }
}

private struct MemberRow: View {
    let member: OrganizationMember

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: member.role.symbol)
                .font(.body.weight(.semibold))
                .foregroundStyle(member.status.tint)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(member.displayName).foregroundStyle(.primary).lineLimit(1)
                Text(member.name == nil ? member.role.label : "\(member.email) · \(member.role.label)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if member.status == .accepted {
                Badge(text: String(localized: "To confirm"), tint: .orange)
            } else if member.twoFactorEnabled {
                Image(systemName: "lock.shield").foregroundStyle(.green).accessibilityLabel("Two-factor authentication")
            }
        }
        .contentShape(Rectangle())
    }
}

// MARK: Groups

struct GroupsScreen: View {
    @Environment(PhoneModel.self) private var model
    let organizationID: String

    var body: some View {
        let groups = model.sharing.groups[organizationID] ?? []
        List {
            Section {
                if groups.isEmpty {
                    Text("No groups yet.").foregroundStyle(.secondary)
                }
                ForEach(groups, id: \.id) { group in
                    Button {
                        model.sharing.error = nil
                        model.sharing.sheet = .group(GroupDraft(group), organizationID: organizationID)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(group.name).foregroundStyle(.primary)
                            Text((group.members.count > 1 ? String(localized: "\(group.members.count) members") : String(localized: "\(group.members.count) member")) + ", " + (group.collections.count > 1 ? String(localized: "\(group.collections.count) collections") : String(localized: "\(group.collections.count) collection")))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .swipeActions {
                        Button(role: .destructive) {
                            Task { await model.deleteGroup(group, in: organizationID) }
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            } footer: {
                Text("A group gives the same access to several members. Its collections add to each member's.")
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Groups")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    model.sharing.error = nil
                    model.sharing.sheet = .group(GroupDraft(id: nil, name: "", members: [], access: [:]),
                                                 organizationID: organizationID)
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("New group")
                .disabled(!model.canEdit)
            }
        }
        .task { await model.loadMembers(organizationID) }
    }
}

// MARK: Presentations

/// Sharing sheets, confirmations and alerts, placed on the tabs.
struct SharingPresentations: ViewModifier {
    @Environment(PhoneModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var sharing = model.sharing
        content
            .sheet(item: $sharing.shareFlow) { flow in
                ShareToVaultSheet(flow: flow)
                    .interactiveDismissDisabled(flow.busy)
            }
            .sheet(item: $sharing.sendComposer) { composer in
                NewSendSheet(composer: composer)
            }
            .sheet(item: $sharing.sheet) { sheet in
                Group {
                    switch sheet {
                    case .newOrganization: NewOrganizationSheet()
                    case .rename(let org): RenameOrganizationSheet(organization: org)
                    case .collection(let draft): CollectionEditorSheet(draft: draft)
                    case .member(let draft, let organizationID): MemberEditorSheet(draft: draft, organizationID: organizationID)
                    case .group(let draft, let organizationID): GroupEditorSheet(draft: draft, organizationID: organizationID)
                    case .join(let link): JoinOrganizationSheet(link: link)
                    case .fingerprint(let pending): FingerprintSheet(pending: pending)
                    }
                }
                .interactiveDismissDisabled(model.sharing.busy)
            }
            .alert("Verify \(sharing.confirmation?.member.displayName ?? "")'s fingerprint",
                   isPresented: Binding(get: { sharing.confirmation != nil },
                                        set: { if !$0 { sharing.confirmation = nil } }),
                   presenting: sharing.confirmation) { confirmation in
                Button("Confirm") { Task { await model.confirmMember(confirmation) } }
                Button("Cancel", role: .cancel) { sharing.confirmation = nil }
            } message: { confirmation in
                Text("“\(confirmation.fingerprint)”\n\nAsk \(confirmation.member.displayName) for their account's fingerprint phrase (Verrou: Settings → Account; web vault: Settings → My account). Confirm only if it is identical: the organization's key will be encrypted for this person.")
            }
            .confirmationDialog("Leave \(sharing.confirmLeave?.name ?? String(localized: "the organization"))?",
                                isPresented: Binding(get: { sharing.confirmLeave != nil },
                                                     set: { if !$0 { sharing.confirmLeave = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmLeave) { org in
                Button("Leave", role: .destructive) { Task { await model.leaveOrganization(org) } }
            } message: { _ in
                Text("Its items will disappear from your vault (they stay in the organization). To come back, a new invitation will be needed.")
            }
            .confirmationDialog("Delete the collection “\(sharing.confirmDelete?.collection.name ?? "")”?",
                                isPresented: Binding(get: { sharing.confirmDelete != nil },
                                                     set: { if !$0 { sharing.confirmDelete = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmDelete) { target in
                Button("Delete", role: .destructive) { Task { await model.deleteCollection(target) } }
            } message: { _ in
                Text("Its items stay in the organization: the administrators still see them.")
            }
            .confirmationDialog("Revoke access for \(sharing.confirmRevoke?.member.displayName ?? "")?",
                                isPresented: Binding(get: { sharing.confirmRevoke != nil },
                                                     set: { if !$0 { sharing.confirmRevoke = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmRevoke) { target in
                Button("Revoke", role: .destructive) {
                    Task {
                        await model.memberAction(String(localized: "Access for \(target.member.displayName) revoked"), in: target.organizationID) {
                            try await model.session.revokeOrganizationMember(organizationId: target.organizationID,
                                                                             memberId: target.member.id)
                        }
                    }
                }
            } message: { _ in
                Text("They no longer see anything of the organization; you can restore their access.")
            }
            .confirmationDialog("Remove \(sharing.confirmRemove?.member.displayName ?? "") from the organization?",
                                isPresented: Binding(get: { sharing.confirmRemove != nil },
                                                     set: { if !$0 { sharing.confirmRemove = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmRemove) { target in
                Button("Remove", role: .destructive) {
                    Task {
                        await model.memberAction(String(localized: "\(target.member.displayName) is no longer part of the organization"),
                                                 in: target.organizationID) {
                            try await model.session.removeOrganizationMember(organizationId: target.organizationID,
                                                                             memberId: target.member.id)
                        }
                    }
                }
            } message: { _ in
                Text("Their account stays on the server. To come back, they will need a new invitation.")
            }
    }
}

// MARK: Sheets

/// A sheet's bar: Cancel, and the action (pending while sending).
private struct SheetToolbar: ToolbarContent {
    let action: LocalizedStringKey
    let enabled: Bool
    let busy: Bool
    let cancel: () -> Void
    let perform: () -> Void

    var body: some ToolbarContent {
        ToolbarItem(placement: .cancellationAction) {
            Button("Cancel", action: cancel).disabled(busy)
        }
        ToolbarItem(placement: .confirmationAction) {
            if busy {
                ProgressView()
            } else {
                Button(action, action: perform)
                    .fontWeight(.semibold)
                    .disabled(!enabled)
                    .accessibilityIdentifier("sheet-primary")
            }
        }
    }
}

private struct ErrorRow: View {
    let error: String?

    var body: some View {
        if let error {
            Section {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
        }
    }
}

/// Permissions on a collection, chosen in a menu, or no access.
private struct PermissionPicker: View {
    let title: String
    var subtitle: String?
    var symbol: String?
    @Binding var permission: CollectionPermission?

    var body: some View {
        Picker(selection: $permission) {
            Text("No access").tag(CollectionPermission?.none)
            ForEach(CollectionPermission.allCases) { level in
                Text(level.label).tag(Optional(level))
            }
        } label: {
            HStack(spacing: 10) {
                if let symbol {
                    Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 22)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).lineLimit(1)
                    if let subtitle {
                        Text(subtitle).font(.caption).foregroundStyle(Color.warningText)
                    }
                }
            }
        }
        .pickerStyle(.menu)
    }
}

/// "Share…": one or more items to an organization's collections;
/// "Collections…" for an item already shared.
struct ShareToVaultSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Bindable var flow: SharingFlow

    private var organization: OrganizationView? { model.organization(flow.organizationID) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if flow.current == nil {
                        Picker("Organization", selection: $flow.organizationID) {
                            ForEach(model.writableOrganizations, id: \.id) { org in
                                Text(org.name).tag(org.id)
                            }
                        }
                        .onChange(of: flow.organizationID) { _, _ in
                            let first = organization?.collections.first { !$0.readOnly }
                            flow.collectionIDs = Set(first.map { [$0.id] } ?? [])
                        }
                    } else {
                        LabeledContent("Organization", value: flow.current?.organization ?? "")
                    }
                } footer: {
                    Text(flow.current != nil
                         ? "The members of each checked collection see the item."
                         : flow.isBulk
                         ? "These items leave your personal vault: each one is re-encrypted with the organization's key (attachments included)."
                         : "The item leaves your personal vault: it is re-encrypted with the organization's key, and its members see it according to their permissions.")
                }
                Section {
                    ForEach(organization?.collections ?? [], id: \.id) { collection in
                        Toggle(isOn: binding(collection.id)) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(collection.name)
                                if collection.readOnly {
                                    Text("read-only").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(collection.readOnly)
                    }
                } header: {
                    SectionHeader("Collections")
                }
                if let progress = flow.progress {
                    Section {
                        ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1))) {
                            Text("\(progress.done) of \(progress.total)").font(.caption).monospacedDigit()
                        }
                    }
                }
                ErrorRow(error: flow.error)
            }
            .navigationTitle(heading)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: flow.current == nil ? "Share" : "Save",
                             enabled: !flow.collectionIDs.isEmpty, busy: flow.busy,
                             cancel: { dismiss() },
                             perform: { Task { await model.applySharing(flow) } })
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var heading: String {
        if flow.current != nil { return String(localized: "Collections") }
        return flow.isBulk ? String(localized: "Share (\(flow.itemIDs.count))") : String(localized: "Share")
    }

    private func binding(_ id: String) -> Binding<Bool> {
        Binding(get: { flow.collectionIDs.contains(id) },
                set: { on in if on { flow.collectionIDs.insert(id) } else { flow.collectionIDs.remove(id) } })
    }
}

struct NewOrganizationSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var collection = String(localized: "General")

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name, prompt: Text("Smith family"))
                        .accessibilityIdentifier("organization-name")
                    TextField("First collection", text: $collection, prompt: Text("General"))
                } footer: {
                    Text("A shared vault you own. Its key is created on this iPhone and encrypted for your account: the server never sees it. The server may restrict creating organizations to some accounts.")
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle("New organization")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: "Create", enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.createOrganization(name: name, collection: collection) { dismiss() } }
                }
            }
        }
    }
}

struct RenameOrganizationSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let organization: OrganizationView
    @State private var name: String

    init(organization: OrganizationView) {
        self.organization = organization
        _name = State(initialValue: organization.name)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name)
                } footer: {
                    Text("The new name shows for all members at their next sync.")
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle("Rename")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: "Rename",
                             enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty && name != organization.name,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.renameOrganization(organization, to: name) { dismiss() } }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

/// Creating or editing a collection: name, and the permissions of each
/// member and each group.
struct CollectionEditorSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var draft: CollectionDraft

    init(draft: CollectionDraft) {
        _draft = State(initialValue: draft)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $draft.name, prompt: Text("Bank"))
                        .accessibilityIdentifier("collection-name")
                } footer: {
                    Text("Its name is encrypted with the organization's key. Owners and administrators see all collections.")
                }
                if draft.loading {
                    Section { ProgressView().frame(maxWidth: .infinity) }
                } else if let unavailable = draft.accessUnavailable {
                    Section {
                        Label(unavailable, systemImage: "info.circle").foregroundStyle(.secondary)
                    } header: {
                        SectionHeader("Access")
                    }
                } else {
                    Section {
                        ForEach(draft.members.filter { $0.status != .revoked }, id: \.id) { member in
                            if member.accessAll {
                                LabeledContent {
                                    Text("all").foregroundStyle(.secondary)
                                } label: {
                                    Label(member.displayName, systemImage: member.role.symbol)
                                }
                            } else {
                                PermissionPicker(title: member.displayName,
                                                 subtitle: member.status == .confirmed ? nil : member.status.label,
                                                 symbol: member.role.symbol,
                                                 permission: $draft.memberAccess[member.id])
                            }
                        }
                    } header: {
                        SectionHeader("Members")
                    }
                    if model.organization(draft.organizationID)?.useGroups == true {
                        Section {
                            if draft.groups.isEmpty {
                                Text("No groups.").foregroundStyle(.secondary)
                            }
                            ForEach(draft.groups, id: \.id) { group in
                                PermissionPicker(title: group.name, symbol: "person.3",
                                                 permission: $draft.groupAccess[group.id])
                            }
                        } header: {
                            SectionHeader("Groups")
                        }
                    }
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle(draft.isNew ? "New collection" : "Collection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: draft.isNew ? "Create" : "Save",
                             enabled: !draft.name.trimmingCharacters(in: .whitespaces).isEmpty && !draft.loading,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.saveCollection(draft) { dismiss() } }
                }
            }
        }
        .task {
            // Members, groups and access read here, once the sheet is open;
            // the name already typed is kept. A failure shows in place of
            // the access (the name stays editable).
            guard draft.loading, let org = model.organization(draft.organizationID) else { return }
            var loaded = await model.session.loadCollectionDraft(draft, organization: org,
                                                                 accountEmail: model.account?.email)
            loaded.name = draft.name
            draft = loaded
        }
    }
}

/// Invitation (one or more addresses) or edit of a member.
struct MemberEditorSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var draft: MemberDraft
    let organizationID: String

    init(draft: MemberDraft, organizationID: String) {
        _draft = State(initialValue: draft)
        self.organizationID = organizationID
    }

    private var organization: OrganizationView? { model.organization(organizationID) }

    private var roles: [OrganizationMemberRole] {
        organization?.isOwner == true ? [.user, .manager, .admin, .owner] : [.user]
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if draft.isNew {
                        TextField("Email addresses", text: $draft.emails,
                                  prompt: Text("lea@example.com, tom@example.com"), axis: .vertical)
                            .keyboardType(.emailAddress)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(1...4)
                            .accessibilityIdentifier("invite-emails")
                    } else {
                        LabeledContent("Email", value: draft.emails)
                    }
                    Picker("Role", selection: $draft.role) {
                        ForEach(roles, id: \.self) { role in
                            Text(role.label).tag(role)
                        }
                    }
                    .disabled(roles.count == 1)
                } footer: {
                    Text(draft.role.explanation + (organization?.isOwner == true ? ""
                         : " " + String(localized: "Only an owner gives the manager, administrator or owner roles.")))
                }
                Section {
                    if draft.seesAll {
                        Text("All collections, with all permissions.").foregroundStyle(.secondary)
                    } else {
                        ForEach(organization?.collections ?? [], id: \.id) { collection in
                            PermissionPicker(title: collection.name, symbol: "tray.full",
                                             permission: $draft.access[collection.id])
                        }
                    }
                } header: {
                    SectionHeader("Collections")
                } footer: {
                    if draft.isNew {
                        Text("Without an account, the person creates one with the link received, in the web vault or in Verrou on a Mac (“Create an account” at sign-in). With an account, they paste the link into “Join an organization”. You will then confirm them by verifying their fingerprint.")
                    }
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle(draft.isNew ? String(localized: "Invite") : draft.member?.displayName ?? String(localized: "Member"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: draft.isNew ? "Invite" : "Save", enabled: draft.emails.contains("@"),
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.saveMember(draft, in: organizationID) { dismiss() } }
                }
            }
        }
    }
}

struct GroupEditorSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var draft: GroupDraft
    let organizationID: String

    init(draft: GroupDraft, organizationID: String) {
        _draft = State(initialValue: draft)
        self.organizationID = organizationID
    }

    var body: some View {
        let members = (model.sharing.members[organizationID] ?? []).filter { $0.status != .revoked }
        NavigationStack {
            Form {
                Section {
                    TextField("Group name", text: $draft.name, prompt: Text("Parents"))
                }
                Section {
                    ForEach(members, id: \.id) { member in
                        Toggle(isOn: Binding(
                            get: { draft.members.contains(member.id) },
                            set: { if $0 { draft.members.insert(member.id) } else { draft.members.remove(member.id) } })) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(member.displayName)
                                Text(member.role.label).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    SectionHeader("Members")
                }
                Section {
                    ForEach(model.organization(organizationID)?.collections ?? [], id: \.id) { collection in
                        PermissionPicker(title: collection.name, symbol: "tray.full",
                                         permission: $draft.access[collection.id])
                    }
                } header: {
                    SectionHeader("Collections")
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle(draft.id == nil ? String(localized: "New group") : draft.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: draft.id == nil ? "Create" : "Save",
                             enabled: !draft.name.trimmingCharacters(in: .whitespaces).isEmpty,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.saveGroup(draft, in: organizationID) { dismiss() } }
                }
            }
        }
    }
}

/// "Join an organization": the link from the invitation email, pasted here,
/// with an account that already exists.
struct JoinOrganizationSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var link: String

    init(link: String = "") {
        _link = State(initialValue: link)
    }

    private var trimmed: String { link.trimmingCharacters(in: .whitespacesAndNewlines) }

    private var info: Result<InvitationInfo, Error>? {
        guard !trimmed.isEmpty else { return nil }
        return Result { try model.session.invitationInfo(link: trimmed) }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Invitation link", text: $link,
                              prompt: Text("https://…/#/accept-organization/?…"), axis: .vertical)
                        .lineLimit(2...5)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .accessibilityIdentifier("invite-link")
                    PasteButton(payloadType: String.self) { strings in
                        if let first = strings.first { link = first }
                    }
                    .labelStyle(.titleAndIcon)
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(InvitationHelp.join(server: model.account?.server))
                        if info == nil { Text(InvitationHelp.notListed) }
                    }
                }
                if let info {
                    Section {
                        switch info {
                        case .success(let invitation):
                            LabeledContent("Invitation from", value: invitation.organizationName ?? String(localized: "an organization"))
                            LabeledContent("For", value: invitation.email)
                            if !invitation.forThisAccount && model.mode == .vaultwarden {
                                Label("This invitation is for an address other than this account's.",
                                      systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(Color.warningText)
                            }
                        case .failure(let error):
                            Label(ErrorText.describe(error), systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(Color.warningText)
                        }
                    } footer: {
                        Text("Once the invitation is accepted, an administrator confirms you by comparing your fingerprint phrase: the organization's key is then encrypted for your account.")
                    }
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle("Join")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: "Join", enabled: (try? info?.get())?.forThisAccount == true,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.joinOrganization(link: trimmed) { dismiss() } }
                }
            }
        }
    }
}

/// My fingerprint phrase, to read to the administrator who confirms me (or
/// to the emergency contact).
struct FingerprintSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var typeSize
    let pending: PendingMembershipView?
    @State private var fingerprint: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    if !typeSize.isAccessibilitySize {
                        Image(systemName: "person.badge.key.fill")
                            .font(.system(size: 44))
                            .foregroundStyle(.indigo)
                            .accessibilityHidden(true)
                    }
                    Text(pending.map { String(localized: "Waiting for \($0.name)") } ?? String(localized: "Fingerprint phrase"))
                        .font(.title3.weight(.semibold))
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    FingerprintText(phrase: fingerprint)
                        .padding(16)
                        .frame(maxWidth: .infinity)
                        .glassSurface(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
                        .accessibilityIdentifier("own-fingerprint")
                    Text("Read this phrase to the person who confirms you: they must see the same one, word for word. It guarantees that the organization's key will be encrypted for you, and for no one else.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(24)
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("OK") { dismiss() } }
            }
            .task { fingerprint = try? await model.session.ownFingerprint() }
        }
        // Large text sizes: the full sheet, the phrase visible without
        // scrolling.
        .presentationDetents(typeSize.isAccessibilitySize ? [.large] : [.medium, .large])
    }
}
