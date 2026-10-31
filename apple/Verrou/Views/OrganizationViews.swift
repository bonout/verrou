import SwiftUI

/// Sheets and confirmations of shared vault management, attached to the main
/// window.
struct OrganizationPresentations: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var admin = model.organizationAdmin
        content
            .sheet(item: $admin.sheet) { sheet in
                Group {
                    switch sheet {
                    case .newOrganization: NewOrganizationView()
                    case .rename(let organization): RenameOrganizationView(organization: organization)
                    case .collection(let draft): CollectionEditorView(draft: draft)
                    case .groups(let draft): GroupsView(draft: draft)
                    case .join: JoinOrganizationView()
                    }
                }
                .environment(model)
            }
            .confirmationDialog("Leave \(admin.confirmLeave?.name ?? String(localized: "the organization"))?",
                                isPresented: Binding(get: { admin.confirmLeave != nil },
                                                     set: { if !$0 { admin.confirmLeave = nil } }),
                                presenting: admin.confirmLeave) { organization in
                Button("Leave", role: .destructive) { Task { await model.leaveOrganization(organization) } }
                Button("Cancel", role: .cancel) { admin.confirmLeave = nil }
            } message: { _ in
                Text("Its items will disappear from your vault (they stay in the organization). To come back, a new invitation will be needed.")
            }
            .confirmationDialog("Delete the collection “\(admin.confirmDelete?.collection.name ?? "")”?",
                                isPresented: Binding(get: { admin.confirmDelete != nil },
                                                     set: { if !$0 { admin.confirmDelete = nil } }),
                                presenting: admin.confirmDelete) { target in
                Button("Delete", role: .destructive) { Task { await model.deleteCollection(target) } }
                Button("Cancel", role: .cancel) { admin.confirmDelete = nil }
            } message: { _ in
                Text("Its items stay in the organization: administrators still see them, the other members only through their other collections.")
            }
    }
}

/// Common header of the sheets: symbol, title, explanation.
private struct SheetHeader: View {
    let symbol: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .accessibilityHidden(true)
                .font(.system(size: 22))
                .foregroundStyle(.indigo)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                    .layoutMark("sheet-title")
                Text(subtitle)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(16)
    }
}

/// Bottom of a sheet: possible error, waiting, Cancel and the action.
private struct SheetFooter: View {
    @Environment(AppModel.self) private var model
    let action: LocalizedStringKey
    var enabled = true
    var destructive = false
    let perform: () -> Void

    var body: some View {
        HStack {
            Spacer()
            if model.organizationAdmin.busy { ProgressView().controlSize(.small) }
            Button("Cancel") { model.organizationAdmin.sheet = nil }
                .keyboardShortcut(.cancelAction)
            Button(action, role: destructive ? .destructive : nil, action: perform)
                .keyboardShortcut(.defaultAction)
                .disabled(!enabled || model.organizationAdmin.busy)
                .layoutMark("sheet-primary")
        }
        .padding(16)
    }
}

private struct ErrorSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let error = model.organizationAdmin.error {
            Section {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
        }
    }
}

/// "New Organization…": a shared vault you own.
struct NewOrganizationView: View {
    @Environment(AppModel.self) private var model
    @State private var name = ""
    @State private var collection = String(localized: "General")

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "person.2.badge.plus", title: String(localized: "New Shared Vault"),
                        subtitle: String(localized: "A shared vault (an organization, in Bitwarden) that you own. Its key is created here and encrypted for your account: the server never sees it."))
            Divider()
            Form {
                Section {
                    TextField("Name", text: $name, prompt: Text("Martin Family"))
                    TextField("First collection", text: $collection, prompt: Text("General"))
                } footer: {
                    Text("Collections organize the shared items; each member accesses the ones you open to them. The server can restrict the creation of shared vaults to some accounts (ORG_CREATION_USERS).")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ErrorSection()
            }
            .formStyle(.grouped)
            Divider()
            SheetFooter(action: "Create", enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty) {
                Task { await model.createOrganization(name: name, collection: collection) }
            }
        }
        .frame(width: 480)
        .frame(minHeight: 330)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Rename the organization (owner).
struct RenameOrganizationView: View {
    @Environment(AppModel.self) private var model
    let organization: OrganizationView
    @State private var name: String

    init(organization: OrganizationView) {
        self.organization = organization
        _name = State(initialValue: organization.name)
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "pencil", title: String(localized: "Rename “\(organization.name)”"),
                        subtitle: String(localized: "The new name shows for all members at their next sync."))
            Divider()
            Form {
                TextField("Name", text: $name)
                ErrorSection()
            }
            .formStyle(.grouped)
            Divider()
            SheetFooter(action: "Rename",
                        enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty && name != organization.name) {
                Task { await model.renameOrganization(organization, to: name) }
            }
        }
        .frame(width: 440)
        .frame(minHeight: 240)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Creation or edit of a collection: name, members and groups who access
/// it, with their rights.
struct CollectionEditorView: View {
    @Environment(AppModel.self) private var model
    @State private var draft: CollectionDraft

    init(draft: CollectionDraft) {
        _draft = State(initialValue: draft)
    }

    private var organization: OrganizationView? {
        model.organizations.first { $0.id == draft.organizationID }
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: draft.isNew ? "folder.badge.plus" : "square.stack",
                        title: draft.isNew
                            ? String(localized: "New collection in \(organization?.name ?? String(localized: "the organization"))")
                            : String(localized: "Collection “\(draft.name)”"),
                        subtitle: String(localized: "Its name is encrypted with the organization's key. Owners and administrators see all collections."))
            Divider()
            Form {
                Section {
                    TextField("Name", text: $draft.name, prompt: Text("Bank"))
                }
                if draft.loading {
                    Section { ProgressView().frame(maxWidth: .infinity) }
                } else if let unavailable = draft.accessUnavailable {
                    Section("Access") {
                        Label(unavailable, systemImage: "info.circle").foregroundStyle(.secondary)
                    }
                } else {
                    Section("Members") {
                        if draft.members.isEmpty {
                            Text("No members.").foregroundStyle(.secondary)
                        }
                        ForEach(draft.members.filter { $0.status != .revoked }, id: \.id) { member in
                            memberRow(member)
                        }
                    }
                    if organization?.useGroups == true {
                        Section("Groups") {
                            if draft.groups.isEmpty {
                                Text("No groups.").foregroundStyle(.secondary)
                            }
                            ForEach(draft.groups, id: \.id) { group in
                                accessRow(group.name, systemImage: "person.3",
                                          binding: \.groupAccess, id: group.id)
                            }
                        }
                    }
                }
                ErrorSection()
            }
            .formStyle(.grouped)
            Divider()
            SheetFooter(action: draft.isNew ? "Create" : "Save",
                        enabled: !draft.name.trimmingCharacters(in: .whitespaces).isEmpty && !draft.loading) {
                Task { await model.saveCollection(draft) }
            }
        }
        .frame(width: 560)
        .frame(minHeight: 420, maxHeight: 660)
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            // Members, groups and access read here, once the sheet is open;
            // the name already entered is kept.
            guard draft.loading, let org = organization else { return }
            var loaded = await model.session.loadCollectionDraft(draft, organization: org,
                                                                 accountEmail: model.account?.email)
            loaded.name = draft.name
            draft = loaded
        }
    }

    @ViewBuilder
    private func memberRow(_ member: OrganizationMember) -> some View {
        if member.accessAll {
            HStack {
                Label(member.displayName, systemImage: member.role.symbol)
                Spacer()
                Text("\(member.role.label): all collections")
                    .font(.caption).foregroundStyle(.secondary)
            }
        } else {
            accessRow(member.displayName, systemImage: member.role.symbol, binding: \.memberAccess, id: member.id,
                      note: member.status == .confirmed ? nil : member.status.label)
        }
    }

    private func accessRow(_ title: String, systemImage: String,
                           binding path: WritableKeyPath<CollectionDraft, [String: CollectionPermission]>,
                           id: String, note: String? = nil) -> some View {
        let granted = Binding(
            get: { draft[keyPath: path][id] != nil },
            set: { draft[keyPath: path][id] = $0 ? (draft[keyPath: path][id] ?? .edit) : nil })
        let permission = Binding(
            get: { draft[keyPath: path][id] ?? .edit },
            set: { draft[keyPath: path][id] = $0 })
        return HStack {
            Toggle(isOn: granted) {
                HStack(spacing: 6) {
                    Image(systemName: systemImage).foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text(title).lineLimit(1)
                    if let note {
                        Text(note).font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            .toggleStyle(.checkbox)
            Spacer()
            Picker("Rights", selection: permission) {
                ForEach(CollectionPermission.allCases) { level in
                    Text(level.label).tag(level)
                }
            }
            .labelsHidden()
            .frame(width: 230)
            .disabled(draft[keyPath: path][id] == nil)
        }
    }
}

/// Member groups (if the server turns them on): list, creation, edit,
/// deletion.
struct GroupsView: View {
    @Environment(AppModel.self) private var model
    let draft: GroupsDraft
    @State private var editing: GroupDraft?
    @State private var deleting: OrganizationGroup?

    init(draft: GroupsDraft, editing: GroupDraft? = nil) {
        self.draft = draft
        _editing = State(initialValue: editing)
    }

    private var organization: OrganizationView? {
        model.organizations.first { $0.id == draft.organizationID }
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "person.3", title: String(localized: "Groups of \(organization?.name ?? String(localized: "the organization"))"),
                        subtitle: String(localized: "A group gives the same access to several members. Its collections and their rights add to those of each member."))
            Divider()
            if let group = Binding($editing) {
                GroupEditorForm(group: group, members: draft.members, collections: organization?.collections ?? [])
                Divider()
                HStack {
                    Spacer()
                    if model.organizationAdmin.busy { ProgressView().controlSize(.small) }
                    Button("Back") { editing = nil }
                        .keyboardShortcut(.cancelAction)
                    Button(group.wrappedValue.id == nil ? "Create Group" : "Save") {
                        let saved = group.wrappedValue
                        Task {
                            await model.saveGroup(saved, in: draft.organizationID)
                            if model.organizationAdmin.error == nil { editing = nil }
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(group.wrappedValue.name.trimmingCharacters(in: .whitespaces).isEmpty
                              || model.organizationAdmin.busy)
                    .layoutMark("sheet-primary")
                }
                .padding(16)
            } else {
                Form {
                    Section {
                        if draft.loading {
                            ProgressView().frame(maxWidth: .infinity)
                        } else if draft.groups.isEmpty {
                            Text("No groups yet.").foregroundStyle(.secondary)
                        }
                        ForEach(draft.groups, id: \.id) { group in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(group.name)
                                    Text(memberCount(group.members.count) + ", " + collectionCount(group.collections.count))
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Edit…") { editing = GroupDraft(group) }
                                Button(role: .destructive) {
                                    deleting = group
                                } label: {
                                    Image(systemName: "trash")
                                        .accessibilityLabel("Delete the group")
                                }
                                .help("Delete the group (its members keep their direct access)")
                            }
                        }
                    }
                    ErrorSection()
                }
                .formStyle(.grouped)
                Divider()
                HStack {
                    Button("New Group…", systemImage: "plus") {
                        editing = GroupDraft(id: nil, name: "", members: [], access: [:])
                    }
                    .disabled(draft.loading)
                    Spacer()
                    if model.organizationAdmin.busy { ProgressView().controlSize(.small) }
                    Button("Close") { model.organizationAdmin.sheet = nil }
                        .keyboardShortcut(.defaultAction)
                        .layoutMark("sheet-primary")
                }
                .padding(16)
            }
        }
        .frame(width: 560)
        .frame(minHeight: 400, maxHeight: 660)
        .background(Color(nsColor: .windowBackgroundColor))
        .confirmationDialog("Delete the group “\(deleting?.name ?? "")”?",
                            isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button("Delete Group", role: .destructive) {
                if let group = deleting {
                    Task { await model.deleteGroup(group, in: draft.organizationID) }
                }
                deleting = nil
            }
        } message: {
            Text("Its members keep their direct access to the collections. This can't be undone.")
        }
    }

    private func memberCount(_ count: Int) -> String {
        count > 1 ? String(localized: "\(count) members") : String(localized: "\(count) member")
    }

    private func collectionCount(_ count: Int) -> String {
        count > 1 ? String(localized: "\(count) collections") : String(localized: "\(count) collection")
    }
}

private struct GroupEditorForm: View {
    @Binding var group: GroupDraft
    let members: [OrganizationMember]
    let collections: [CollectionView]

    var body: some View {
        Form {
            Section {
                TextField("Group name", text: $group.name, prompt: Text("Parents"))
            }
            Section("Members") {
                ForEach(members.filter { $0.status != .revoked }, id: \.id) { member in
                    Toggle(isOn: Binding(
                        get: { group.members.contains(member.id) },
                        set: { if $0 { group.members.insert(member.id) } else { group.members.remove(member.id) } })) {
                        HStack {
                            Text(member.displayName)
                            Text(member.role.label).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .toggleStyle(.checkbox)
                }
            }
            Section("Collections") {
                ForEach(collections, id: \.id) { collection in
                    let granted = Binding(
                        get: { group.access[collection.id] != nil },
                        set: { group.access[collection.id] = $0 ? (group.access[collection.id] ?? .edit) : nil })
                    HStack {
                        Toggle(collection.name, isOn: granted).toggleStyle(.checkbox)
                        Spacer()
                        Picker("Rights", selection: Binding(
                            get: { group.access[collection.id] ?? .edit },
                            set: { group.access[collection.id] = $0 })) {
                            ForEach(CollectionPermission.allCases) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .frame(width: 230)
                        .disabled(group.access[collection.id] == nil)
                    }
                }
            }
            ErrorSection()
        }
        .formStyle(.grouped)
    }
}

/// "Join an Organization…": the invitation link received by email, pasted
/// here, with an account that already exists.
struct JoinOrganizationView: View {
    @Environment(AppModel.self) private var model
    @State private var link: String

    init(link: String = "") {
        _link = State(initialValue: link)
    }

    private var info: Result<InvitationInfo, Error>? {
        let text = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        return Result { try model.session.invitationInfo(link: text) }
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "envelope.open", title: String(localized: "Join a Shared Vault"),
                        subtitle: InvitationHelp.join(server: model.account?.server))
            Divider()
            Form {
                Section {
                    TextField("Invitation link", text: $link,
                              prompt: Text("https://…/#/accept-organization/?…"), axis: .vertical)
                        .lineLimit(2...4)
                } footer: {
                    if info == nil {
                        Text(InvitationHelp.notListed)
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let info {
                    Section {
                        switch info {
                        case .success(let invitation):
                            LabeledContent("Invitation from", value: invitation.organizationName ?? String(localized: "an organization"))
                            LabeledContent("For", value: invitation.email)
                            if !invitation.forThisAccount && !model.organizationAdmin.preview {
                                Label("This invitation is meant for another address than this account's.",
                                      systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                            }
                        case .failure(let error):
                            Label(AppModel.describe(error), systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                    } footer: {
                        Text("Once the invitation is accepted, an administrator confirms you by comparing your fingerprint phrase: the organization's key is then encrypted for your account.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                ErrorSection()
            }
            .formStyle(.grouped)
            Divider()
            SheetFooter(action: "Join",
                        enabled: (try? info?.get())?.forThisAccount == true || model.organizationAdmin.preview) {
                Task { await model.joinOrganization(link: link.trimmingCharacters(in: .whitespacesAndNewlines)) }
            }
        }
        .frame(width: 520)
        .frame(minHeight: 340)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Sidebar: an organization joined, waiting for an administrator's
/// confirmation. The fingerprint phrase, to read to them, is one click away.
struct PendingMembershipRow: View {
    @Environment(AppModel.self) private var model
    let pending: PendingMembershipView
    @State private var showFingerprint = false

    var body: some View {
        Button {
            showFingerprint = true
        } label: {
            Label {
                VStack(alignment: .leading, spacing: 1) {
                    Text(pending.name).lineLimit(1)
                    Text("Waiting for confirmation").font(.caption).foregroundStyle(.orange)
                }
            } icon: {
                Image(systemName: "hourglass").foregroundStyle(.orange)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Invitation accepted: an administrator of \(pending.name) must confirm you")
        .popover(isPresented: $showFingerprint, arrowEdge: .trailing) {
            PendingFingerprintView(pending: pending)
                .environment(model)
        }
    }
}

struct PendingFingerprintView: View {
    @Environment(AppModel.self) private var model
    let pending: PendingMembershipView
    @State private var fingerprint: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Waiting for \(pending.name)").font(.headline)
            Text("Read this fingerprint phrase to the administrator who confirms you: they must see the same one. It guarantees that the organization's key will be encrypted for you, and for nobody else.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            FingerprintText(phrase: fingerprint, alignment: .leading)
        }
        .padding(16)
        .frame(width: 340)
        .task { fingerprint = try? await model.session.ownFingerprint() }
    }
}

/// Sidebar: "N members to confirm" (administrators).
struct MembersToConfirmRow: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let total = model.organizationAdmin.totalToConfirm
        Button {
            model.openFirstMembersToConfirm()
        } label: {
            Label {
                Text(total > 1 ? "\(total) members to confirm" : "\(total) member to confirm").lineLimit(1)
            } icon: {
                Image(systemName: "person.badge.clock").foregroundStyle(.orange)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("They accepted the invitation: check their fingerprint phrase to give them access")
    }
}
