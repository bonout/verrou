import SwiftUI

/// Feuilles et confirmations de la gestion des coffres partagés, posées sur
/// la fenêtre principale.
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
            .confirmationDialog("Quitter \(admin.confirmLeave?.name ?? "l'organisation") ?",
                                isPresented: Binding(get: { admin.confirmLeave != nil },
                                                     set: { if !$0 { admin.confirmLeave = nil } }),
                                presenting: admin.confirmLeave) { organization in
                Button("Quitter", role: .destructive) { Task { await model.leaveOrganization(organization) } }
                Button("Annuler", role: .cancel) { admin.confirmLeave = nil }
            } message: { _ in
                Text("Ses éléments disparaîtront de votre coffre (ils restent dans l'organisation). Pour revenir, il faudra une nouvelle invitation.")
            }
            .confirmationDialog("Supprimer la collection « \(admin.confirmDelete?.collection.name ?? "") » ?",
                                isPresented: Binding(get: { admin.confirmDelete != nil },
                                                     set: { if !$0 { admin.confirmDelete = nil } }),
                                presenting: admin.confirmDelete) { target in
                Button("Supprimer", role: .destructive) { Task { await model.deleteCollection(target) } }
                Button("Annuler", role: .cancel) { admin.confirmDelete = nil }
            } message: { _ in
                Text("Ses éléments restent dans l'organisation : les administrateurs les voient toujours, les autres membres seulement par leurs autres collections.")
            }
    }
}

/// En-tête commun des feuilles : symbole, titre, explication.
private struct SheetHeader: View {
    let symbol: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
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

/// Bas de feuille : erreur éventuelle, attente, Annuler et l'action.
private struct SheetFooter: View {
    @Environment(AppModel.self) private var model
    let action: String
    var enabled = true
    var destructive = false
    let perform: () -> Void

    var body: some View {
        HStack {
            Spacer()
            if model.organizationAdmin.busy { ProgressView().controlSize(.small) }
            Button("Annuler") { model.organizationAdmin.sheet = nil }
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

/// « Nouvelle organisation… » : un coffre partagé dont on est propriétaire.
struct NewOrganizationView: View {
    @Environment(AppModel.self) private var model
    @State private var name = ""
    @State private var collection = "Général"

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "person.2.badge.plus", title: "Nouvelle organisation",
                        subtitle: "Un coffre partagé dont vous êtes propriétaire. Sa clé est créée ici et chiffrée pour votre compte : le serveur ne la voit jamais.")
            Divider()
            Form {
                Section {
                    TextField("Nom", text: $name, prompt: Text("Famille Martin"))
                    TextField("Première collection", text: $collection, prompt: Text("Général"))
                } footer: {
                    Text("Les collections rangent les éléments partagés ; chaque membre accède à celles que vous lui ouvrez. Le serveur peut réserver la création d'organisations à certains comptes (ORG_CREATION_USERS).")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ErrorSection()
            }
            .formStyle(.grouped)
            Divider()
            SheetFooter(action: "Créer", enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty) {
                Task { await model.createOrganization(name: name, collection: collection) }
            }
        }
        .frame(width: 480)
        .frame(minHeight: 330)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Renommer l'organisation (propriétaire).
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
            SheetHeader(symbol: "pencil", title: "Renommer « \(organization.name) »",
                        subtitle: "Le nouveau nom s'affiche chez tous les membres à leur prochaine synchronisation.")
            Divider()
            Form {
                TextField("Nom", text: $name)
                ErrorSection()
            }
            .formStyle(.grouped)
            Divider()
            SheetFooter(action: "Renommer",
                        enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty && name != organization.name) {
                Task { await model.renameOrganization(organization, to: name) }
            }
        }
        .frame(width: 440)
        .frame(minHeight: 240)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Création ou modification d'une collection : nom, membres et groupes qui
/// y accèdent, avec leurs droits.
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
                        title: draft.isNew ? "Nouvelle collection dans \(organization?.name ?? "l'organisation")"
                                           : "Collection « \(draft.name) »",
                        subtitle: "Son nom est chiffré avec la clé de l'organisation. Propriétaires et administrateurs voient toutes les collections.")
            Divider()
            Form {
                Section {
                    TextField("Nom", text: $draft.name, prompt: Text("Banque"))
                }
                if draft.loading {
                    Section { ProgressView().frame(maxWidth: .infinity) }
                } else if let unavailable = draft.accessUnavailable {
                    Section("Accès") {
                        Label(unavailable, systemImage: "info.circle").foregroundStyle(.secondary)
                    }
                } else {
                    Section("Membres") {
                        if draft.members.isEmpty {
                            Text("Aucun membre.").foregroundStyle(.secondary)
                        }
                        ForEach(draft.members.filter { $0.status != .revoked }, id: \.id) { member in
                            memberRow(member)
                        }
                    }
                    if organization?.useGroups == true {
                        Section("Groupes") {
                            if draft.groups.isEmpty {
                                Text("Aucun groupe.").foregroundStyle(.secondary)
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
            SheetFooter(action: draft.isNew ? "Créer" : "Enregistrer",
                        enabled: !draft.name.trimmingCharacters(in: .whitespaces).isEmpty && !draft.loading) {
                Task { await model.saveCollection(draft) }
            }
        }
        .frame(width: 560)
        .frame(minHeight: 420, maxHeight: 660)
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            // Membres, groupes et accès lus ici, une fois la feuille ouverte ;
            // le nom déjà saisi est gardé.
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
                Text("\(member.role.label) : toutes les collections")
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
                    Text(title).lineLimit(1)
                    if let note {
                        Text(note).font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            .toggleStyle(.checkbox)
            Spacer()
            Picker("Droits", selection: permission) {
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

/// Groupes de membres (si le serveur les active) : liste, création,
/// modification, suppression.
struct GroupsView: View {
    @Environment(AppModel.self) private var model
    let draft: GroupsDraft
    @State private var editing: GroupDraft?

    init(draft: GroupsDraft, editing: GroupDraft? = nil) {
        self.draft = draft
        _editing = State(initialValue: editing)
    }

    private var organization: OrganizationView? {
        model.organizations.first { $0.id == draft.organizationID }
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "person.3", title: "Groupes de \(organization?.name ?? "l'organisation")",
                        subtitle: "Un groupe donne les mêmes accès à plusieurs membres. Ses collections et leurs droits s'ajoutent à ceux de chaque membre.")
            Divider()
            if let group = Binding($editing) {
                GroupEditorForm(group: group, members: draft.members, collections: organization?.collections ?? [])
                Divider()
                HStack {
                    Spacer()
                    if model.organizationAdmin.busy { ProgressView().controlSize(.small) }
                    Button("Retour") { editing = nil }
                        .keyboardShortcut(.cancelAction)
                    Button(group.wrappedValue.id == nil ? "Créer le groupe" : "Enregistrer") {
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
                            Text("Aucun groupe pour l'instant.").foregroundStyle(.secondary)
                        }
                        ForEach(draft.groups, id: \.id) { group in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(group.name)
                                    Text("\(group.members.count) membre\(group.members.count > 1 ? "s" : ""), \(group.collections.count) collection\(group.collections.count > 1 ? "s" : "")")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Modifier…") { editing = GroupDraft(group) }
                                Button(role: .destructive) {
                                    Task { await model.deleteGroup(group, in: draft.organizationID) }
                                } label: {
                                    Image(systemName: "trash")
                                }
                                .help("Supprimer le groupe (ses membres gardent leurs accès directs)")
                            }
                        }
                    }
                    ErrorSection()
                }
                .formStyle(.grouped)
                Divider()
                HStack {
                    Button("Nouveau groupe…", systemImage: "plus") {
                        editing = GroupDraft(id: nil, name: "", members: [], access: [:])
                    }
                    .disabled(draft.loading)
                    Spacer()
                    if model.organizationAdmin.busy { ProgressView().controlSize(.small) }
                    Button("Fermer") { model.organizationAdmin.sheet = nil }
                        .keyboardShortcut(.defaultAction)
                        .layoutMark("sheet-primary")
                }
                .padding(16)
            }
        }
        .frame(width: 560)
        .frame(minHeight: 400, maxHeight: 660)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

private struct GroupEditorForm: View {
    @Binding var group: GroupDraft
    let members: [OrganizationMember]
    let collections: [CollectionView]

    var body: some View {
        Form {
            Section {
                TextField("Nom du groupe", text: $group.name, prompt: Text("Parents"))
            }
            Section("Membres") {
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
                        Picker("Droits", selection: Binding(
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

/// « Rejoindre une organisation… » : le lien d'invitation reçu par courriel,
/// collé ici, avec un compte qui existe déjà.
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
            SheetHeader(symbol: "envelope.open", title: "Rejoindre une organisation",
                        subtitle: InvitationHelp.join(server: model.account?.server))
            Divider()
            Form {
                Section {
                    TextField("Lien d'invitation", text: $link,
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
                            LabeledContent("Invitation de", value: invitation.organizationName ?? "une organisation")
                            LabeledContent("Pour", value: invitation.email)
                            if !invitation.forThisAccount && !model.organizationAdmin.preview {
                                Label("Cette invitation est destinée à une autre adresse que celle de ce compte.",
                                      systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                            }
                        case .failure(let error):
                            Label(AppModel.describe(error), systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                    } footer: {
                        Text("Une fois l'invitation acceptée, un administrateur vous confirme en comparant votre phrase d'empreinte : la clé de l'organisation est alors chiffrée pour votre compte.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                ErrorSection()
            }
            .formStyle(.grouped)
            Divider()
            SheetFooter(action: "Rejoindre",
                        enabled: (try? info?.get())?.forThisAccount == true || model.organizationAdmin.preview) {
                Task { await model.joinOrganization(link: link.trimmingCharacters(in: .whitespacesAndNewlines)) }
            }
        }
        .frame(width: 520)
        .frame(minHeight: 340)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Barre latérale : une organisation rejointe, qui attend la confirmation
/// d'un administrateur. La phrase d'empreinte, à lui lire, est à un clic.
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
                    Text("En attente de confirmation").font(.caption).foregroundStyle(.orange)
                }
            } icon: {
                Image(systemName: "hourglass").foregroundStyle(.orange)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Invitation acceptée : un administrateur de \(pending.name) doit vous confirmer")
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
            Text("En attente de \(pending.name)").font(.headline)
            Text("Lisez cette phrase d'empreinte à l'administrateur qui vous confirme : il doit voir la même. Elle garantit que la clé de l'organisation sera chiffrée pour vous, et pour personne d'autre.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            FingerprintText(phrase: fingerprint, alignment: .leading)
        }
        .padding(16)
        .frame(width: 340)
        .task { fingerprint = try? await model.session.ownFingerprint() }
    }
}

/// Barre latérale : « N membres à confirmer » (administrateurs).
struct MembersToConfirmRow: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let total = model.organizationAdmin.totalToConfirm
        Button {
            model.openFirstMembersToConfirm()
        } label: {
            Label {
                Text("\(total) membre\(total > 1 ? "s" : "") à confirmer").lineLimit(1)
            } icon: {
                Image(systemName: "person.badge.clock").foregroundStyle(.orange)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Ils ont accepté l'invitation : vérifiez leur phrase d'empreinte pour leur donner accès")
    }
}
