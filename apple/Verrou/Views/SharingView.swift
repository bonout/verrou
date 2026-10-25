import SwiftUI

/// "Shared Vaults" section of the sidebar: each organization, then its
/// collections, with their counts; pending invitations and members to
/// confirm; what's needed to create or join an organization.
struct SharedVaultsSection: View {
    @Environment(AppModel.self) private var model
    /// Organizations folded in the sidebar (their collections and members
    /// hidden), by identifier: a choice of this Mac, never synced.
    @AppStorage("collapsedOrganizations") private var collapsedIDs = ""

    var body: some View {
        let admin = model.organizationAdmin
        if !model.organizations.isEmpty || model.showsAccountPanes {
            Section {
                if admin.totalToConfirm > 0 {
                    MembersToConfirmRow()
                }
                ForEach(admin.pending, id: \.organizationId) { pending in
                    PendingMembershipRow(pending: pending)
                }
                ForEach(model.organizations, id: \.id) { org in
                    DisclosureGroup(isExpanded: expanded(org.id)) {
                        ForEach(org.collections, id: \.id) { collection in
                            row(.collection(id: collection.id), collection.name,
                                collection.readOnly ? "eye" : "square.stack",
                                count: collection.count, tint: .secondary)
                                .help(help(for: collection))
                                .contextMenu { collectionMenu(org, collection) }
                        }
                        if org.canViewMembers && model.showsAccountPanes {
                            MembersSidebarRow(organization: org)
                        }
                    } label: {
                        row(.organization(id: org.id), org.name, "person.2.fill", count: org.count, tint: .indigo)
                            .contextMenu { organizationMenu(org) }
                    }
                }
                if model.organizations.isEmpty && admin.pending.isEmpty && model.canEdit {
                    Button {
                        model.openNewOrganization()
                    } label: {
                        Label("New Organization…", systemImage: "plus")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Create a shared vault, then invite other accounts of your server to it")
                    Button {
                        model.openJoin()
                    } label: {
                        Label("Join with a Link…", systemImage: "envelope.open")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Invited by email? Paste the invitation link")
                }
            } header: {
                HStack {
                    Text("Shared Vaults")
                    Spacer()
                    if model.canEdit || admin.preview {
                        Menu {
                            Button("New Organization…") { model.openNewOrganization() }
                            Button("Join an Organization…") { model.openJoin() }
                            if model.organizations.contains(where: { $0.manageUrl != nil }) {
                                Divider()
                                Button("Open the Web Vault") { model.openWebVault(organizationID: currentOrganization) }
                            }
                        } label: {
                            Image(systemName: "plus")
                                .accessibilityLabel("Add")
                        }
                        .menuStyle(.borderlessButton)
                        .menuIndicator(.hidden)
                        .fixedSize()
                        .help("New organization, or join an organization with an invitation link")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func organizationMenu(_ org: OrganizationView) -> some View {
        if model.canEdit {
            if org.canCreateCollections {
                Button("New Collection…") { model.openCollectionEditor(org, collection: nil) }
            }
            if org.canManageGroups {
                Button("Groups…") { Task { await model.openGroups(org) } }
            }
            if org.canViewMembers {
                Button("Members") { model.openMembers(org.id) }
            }
            if org.canRename {
                Button("Rename…") { model.openRename(org) }
            }
            Divider()
            Button("Leave Organization…", role: .destructive) { model.organizationAdmin.confirmLeave = org }
        }
        if org.manageUrl != nil {
            Divider()
            Button("Manage in the Web Vault") { model.openWebVault(organizationID: org.id) }
        }
    }

    @ViewBuilder
    private func collectionMenu(_ org: OrganizationView, _ collection: CollectionView) -> some View {
        if model.canEdit && collection.canManage {
            Button("Edit Collection…") { model.openCollectionEditor(org, collection: collection) }
            Button("Delete Collection…", role: .destructive) {
                model.organizationAdmin.confirmDelete = CollectionTarget(organization: org, collection: collection)
            }
        } else {
            Text(collection.readOnly ? "Read-only" : "You don't manage this collection")
        }
    }

    /// Unfolded unless the user folded it on this Mac.
    private func expanded(_ id: String) -> Binding<Bool> {
        Binding {
            !collapsed.contains(id)
        } set: { open in
            var ids = collapsed
            if open { ids.remove(id) } else { ids.insert(id) }
            collapsedIDs = ids.sorted().joined(separator: ",")
        }
    }

    private var collapsed: Set<String> {
        Set(collapsedIDs.split(separator: ",").map(String.init))
    }

    /// The displayed organization (itself or one of its collections).
    private var currentOrganization: String? {
        switch model.filter {
        case .organization(let id): return id
        case .collection(let id): return model.organizations.first { $0.collections.contains { $0.id == id } }?.id
        default: return model.organizations.first?.id
        }
    }

    private func help(for collection: CollectionView) -> String {
        var rights: [String] = []
        if collection.readOnly { rights.append(String(localized: "read-only")) }
        if collection.hidePasswords { rights.append(String(localized: "passwords hidden")) }
        return rights.isEmpty ? collection.name
                              : String(localized: "\(collection.name): \(rights.joined(separator: ", "))")
    }

    private func row(_ filter: SidebarFilter, _ title: String, _ symbol: String, count: UInt32, tint: Color) -> some View {
        Label {
            HStack {
                Text(title).lineLimit(1)
                Spacer()
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary).font(.callout)
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .tag(filter)
    }
}

/// "Share…": moves a personal item into an organization's collections. For
/// an already shared item: "Collections…".
struct SharingView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: SharingFlow

    private var organization: OrganizationView? {
        model.organizations.first { $0.id == flow.organizationID }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "person.2.fill")
                    .accessibilityHidden(true)
                    .font(.system(size: 24))
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 2) {
                    Text(heading)
                        .font(.title3.weight(.semibold))
                        .layoutMark("sheet-title")
                    Text(flow.current != nil
                         ? "The members of each checked collection see the item."
                         : flow.isBulk
                         ? "These items leave your personal vault: each one is re-encrypted with the organization's key (attachments included), and its members see them according to their rights."
                         : "The item leaves your personal vault: it is re-encrypted with the organization's key, and its members see it according to their rights.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
            }
            .padding(16)
            Divider()

            Form {
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
                Section("Collections") {
                    ForEach(organization?.collections ?? [], id: \.id) { collection in
                        Toggle(isOn: binding(collection.id)) {
                            HStack {
                                Text(collection.name)
                                if collection.readOnly {
                                    Text("read-only").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(collection.readOnly)
                    }
                }
                if let error = flow.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack(spacing: 10) {
                if organization?.manageUrl != nil {
                    Button("Manage in the Web Vault") { model.openWebVault(organizationID: flow.organizationID) }
                        .buttonStyle(.link)
                }
                Spacer()
                if let progress = flow.progress {
                    ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1)))
                        .frame(width: 120)
                    Text("\(progress.done) of \(progress.total)").font(.caption).monospacedDigit()
                } else if flow.busy {
                    ProgressView().controlSize(.small)
                }
                Button("Cancel") { model.sharingFlow = nil }
                    .keyboardShortcut(.cancelAction)
                Button(flow.current == nil
                       ? (flow.isBulk ? String(localized: "Share \(flow.itemIDs.count) Items") : String(localized: "Share"))
                       : String(localized: "Save")) {
                    Task { await model.applySharing(flow) }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .layoutMark("sheet-primary")
                .disabled(flow.collectionIDs.isEmpty || flow.busy)
            }
            .padding(16)
        }
        .frame(width: 480)
        .frame(minHeight: 380)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var heading: String {
        if flow.current != nil { return String(localized: "Collections of “\(flow.title)”") }
        return flow.isBulk ? String(localized: "Share \(flow.itemIDs.count) items") : String(localized: "Share “\(flow.title)”")
    }

    private func binding(_ id: String) -> Binding<Bool> {
        Binding(
            get: { flow.collectionIDs.contains(id) },
            set: { on in
                if on { flow.collectionIDs.insert(id) } else { flow.collectionIDs.remove(id) }
            })
    }
}

/// A field the organization hides from this account: no display, no copy.
struct HiddenFieldRow: View {
    let field: FieldView

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    MaskedText(count: 8)
                    Text("hidden by the organization").font(.caption).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            Image(systemName: "eye.slash").foregroundStyle(.tertiary)
                .accessibilityLabel("Hidden by the organization")
                .help("The organization hides this field for your account. Filling in the browser is still possible.")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}
