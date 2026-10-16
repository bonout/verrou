import SwiftUI

// MARK: Accueil

/// Section « Coffres partagés » de l'accueil : membres à confirmer,
/// invitations en attente, chaque organisation (vers son écran) et ses
/// collections (créer ou rejoindre : menu « + » de l'accueil).
struct SharedVaultsHomeSection: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        let sharing = model.sharing
        // Sans coffre partagé, rien à construire : créer ou rejoindre une
        // organisation passe par le menu « + » de l'accueil.
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
                    ForEach(org.collections, id: \.id) { collection in
                        NavigationLink(value: PhoneModel.Route.list(.collection(id: collection.id))) {
                            HStack(spacing: 12) {
                                TintedSymbol(symbol: collection.readOnly ? "eye.fill" : "tray.full.fill",
                                             tint: .indigo.opacity(0.7))
                                Text(collection.name)
                                Spacer()
                                Text("\(collection.count)").foregroundStyle(.secondary).monospacedDigit()
                            }
                        }
                        .padding(.leading, 18)
                    }
                }
            } header: {
                SectionHeader("Coffres partagés")
            }
        }
    }
}

/// En tête de l'accueil, comme les modifications en attente : les membres
/// à confirmer (administrateurs) et les invitations acceptées qui attendent
/// leur confirmation.
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
                            Text("\(n) membre\(n > 1 ? "s" : "") à confirmer").foregroundStyle(.primary)
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
                                Text("En attente de confirmation").font(.caption).foregroundStyle(.orange)
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

// MARK: Organisation

/// Un coffre partagé : ses éléments, ses collections (gérées selon les
/// droits), ses membres, ses groupes, et de quoi le renommer ou le quitter.
struct OrganizationScreen: View {
    @Environment(PhoneModel.self) private var model
    let organizationID: String

    var body: some View {
        if let org = model.organization(organizationID) {
            content(org)
        } else {
            ContentUnavailableView("Organisation indisponible", systemImage: "person.2.slash",
                                   description: Text("Vous ne faites plus partie de ce coffre partagé."))
        }
    }

    private func content(_ org: OrganizationView) -> some View {
        List {
            Section {
                NavigationLink(value: PhoneModel.Route.list(.organization(id: org.id))) {
                    HStack(spacing: 12) {
                        TintedSymbol(symbol: "square.grid.2x2.fill", tint: .indigo)
                        Text("Tous ses éléments")
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
                                Label("Supprimer", systemImage: "trash")
                            }
                            Button {
                                model.openCollectionEditor(org, collection: collection)
                            } label: {
                                Label("Modifier", systemImage: "slider.horizontal.3")
                            }
                            .tint(.indigo)
                        }
                    }
                    .contextMenu {
                        if model.canEdit && collection.canManage {
                            Button("Modifier la collection…", systemImage: "slider.horizontal.3") {
                                model.openCollectionEditor(org, collection: collection)
                            }
                            Button("Supprimer la collection…", systemImage: "trash", role: .destructive) {
                                model.sharing.confirmDelete = CollectionTarget(organization: org, collection: collection)
                            }
                        }
                    }
                }
                if model.canEdit && org.canCreateCollections {
                    Button {
                        model.openCollectionEditor(org, collection: nil)
                    } label: {
                        Label("Nouvelle collection…", systemImage: "plus.circle.fill")
                    }
                    .accessibilityIdentifier("new-collection")
                }
            } header: {
                SectionHeader("Collections")
            } footer: {
                if org.hasManagedCollections {
                    Text("Balayez une collection vers la gauche pour la modifier ou la supprimer.")
                }
            }
            if org.canViewMembers || org.canManageGroups {
                Section {
                    if org.canViewMembers {
                        NavigationLink(value: PhoneModel.Route.members(org.id)) {
                            HStack(spacing: 12) {
                                TintedSymbol(symbol: "person.3.fill", tint: .teal)
                                Text("Membres")
                                Spacer()
                                if let pending = model.sharing.toConfirm[org.id], pending > 0 {
                                    Badge(text: "\(pending) à confirmer", tint: .orange)
                                }
                            }
                        }
                        .accessibilityIdentifier("members-link")
                    }
                    if org.canManageGroups {
                        NavigationLink(value: PhoneModel.Route.groups(org.id)) {
                            HStack(spacing: 12) {
                                TintedSymbol(symbol: "person.2.circle.fill", tint: .mint)
                                Text("Groupes")
                            }
                        }
                    }
                } header: {
                    SectionHeader("Personnes")
                }
            }
            if model.canEdit {
                Section {
                    if org.canRename {
                        Button("Renommer l'organisation…", systemImage: "pencil") { model.sharing.sheet = .rename(org) }
                    }
                    Button("Quitter l'organisation…", systemImage: "rectangle.portrait.and.arrow.right",
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
        let role = org.role?.label ?? "Membre"
        return "Votre rôle : \(role). Les éléments partagés ici sont chiffrés avec la clé de l'organisation."
    }

    private func rights(_ collection: CollectionView) -> String? {
        var rights: [String] = []
        if collection.readOnly { rights.append("lecture seule") }
        if collection.hidePasswords { rights.append("mots de passe masqués") }
        if collection.canManage { rights.append("vous la gérez") }
        return rights.isEmpty ? nil : rights.joined(separator: " · ")
    }
}

private extension OrganizationView {
    var hasManagedCollections: Bool { collections.contains(where: \.canManage) }
}

// MARK: Membres

/// Les membres d'une organisation, groupés par état ; un appui ouvre leurs
/// actions (confirmer après vérification de l'empreinte, modifier,
/// révoquer, retirer).
struct MembersScreen: View {
    @Environment(PhoneModel.self) private var model
    let organizationID: String
    @State private var chosen: OrganizationMember?

    var body: some View {
        let org = model.organization(organizationID)
        let members = model.sharing.members[organizationID]
        List {
            if let members {
                section("À confirmer", members.filter { $0.status == .accepted },
                        footer: "Ils ont accepté l'invitation : vérifiez leur phrase d'empreinte avec eux pour leur donner la clé de l'organisation.")
                let invited = members.filter { $0.status == .invited }
                section("Invitations en attente", invited)
                if !invited.isEmpty, org?.canManageMembers == true {
                    Section {
                        InvitationNextSteps(email: invited.count == 1 ? invited[0].email : nil,
                                            server: model.account?.server,
                                            hasAccount: invited.count == 1 ? invited[0].hasAccount : nil)
                            .accessibilityIdentifier("invitation-next-steps")
                    }
                }
                section("Membres", members.filter { $0.status == .confirmed })
                section("Révoqués", members.filter { $0.status == .revoked })
            } else {
                ProgressView().frame(maxWidth: .infinity).listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Membres")
        .navigationSubtitleIfAvailable(org?.name ?? "")
        .toolbar {
            if org?.canManageMembers == true, model.canEdit {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        model.inviteMembers(organizationID)
                    } label: {
                        Image(systemName: "person.badge.plus")
                    }
                    .accessibilityLabel("Inviter")
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
    private func section(_ title: String, _ members: [OrganizationMember], footer: String? = nil) -> some View {
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
                Button("Vérifier l'empreinte et confirmer…") {
                    Task { await model.prepareConfirmation(member, in: organizationID) }
                }
            case .invited:
                Button("Renvoyer l'invitation") {
                    Task {
                        await model.memberAction("Invitation renvoyée à \(member.email)", in: organizationID) {
                            try await model.session.reinviteOrganizationMember(organizationId: organizationID,
                                                                               memberId: member.id)
                        }
                    }
                }
            case .revoked:
                Button("Restaurer l'accès") {
                    Task {
                        await model.memberAction("Accès de \(member.displayName) restauré", in: organizationID) {
                            try await model.session.restoreOrganizationMember(organizationId: organizationID,
                                                                              memberId: member.id)
                        }
                    }
                }
            case .confirmed:
                EmptyView()
            }
            Button("Modifier le rôle et les collections…") { model.editMember(member, in: organizationID) }
            if member.status != .revoked {
                Button("Révoquer l'accès…", role: .destructive) {
                    model.sharing.confirmRevoke = MemberTarget(organizationID: organizationID, member: member)
                }
            }
            Button("Retirer de l'organisation…", role: .destructive) {
                model.sharing.confirmRemove = MemberTarget(organizationID: organizationID, member: member)
            }
        }
        Button("Copier l'adresse") { model.copy(member.email, label: "Adresse", secret: false) }
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
                Badge(text: "À confirmer", tint: .orange)
            } else if member.twoFactorEnabled {
                Image(systemName: "lock.shield").foregroundStyle(.green).accessibilityLabel("Double authentification")
            }
        }
        .contentShape(Rectangle())
    }
}

// MARK: Groupes

struct GroupsScreen: View {
    @Environment(PhoneModel.self) private var model
    let organizationID: String

    var body: some View {
        let groups = model.sharing.groups[organizationID] ?? []
        List {
            Section {
                if groups.isEmpty {
                    Text("Aucun groupe pour l'instant.").foregroundStyle(.secondary)
                }
                ForEach(groups, id: \.id) { group in
                    Button {
                        model.sharing.error = nil
                        model.sharing.sheet = .group(GroupDraft(group), organizationID: organizationID)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(group.name).foregroundStyle(.primary)
                            Text("\(group.members.count) membre\(group.members.count > 1 ? "s" : ""), \(group.collections.count) collection\(group.collections.count > 1 ? "s" : "")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .swipeActions {
                        Button(role: .destructive) {
                            Task { await model.deleteGroup(group, in: organizationID) }
                        } label: {
                            Label("Supprimer", systemImage: "trash")
                        }
                    }
                }
            } footer: {
                Text("Un groupe donne les mêmes accès à plusieurs membres. Ses collections s'ajoutent à celles de chaque membre.")
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Groupes")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    model.sharing.error = nil
                    model.sharing.sheet = .group(GroupDraft(id: nil, name: "", members: [], access: [:]),
                                                 organizationID: organizationID)
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Nouveau groupe")
                .disabled(!model.canEdit)
            }
        }
        .task { await model.loadMembers(organizationID) }
    }
}

// MARK: Présentations

/// Feuilles, confirmations et alertes du partage, posées sur les onglets.
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
                    .interactiveDismissDisabled(model.sharing.busy)
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
            .alert("Vérifier l'empreinte de \(sharing.confirmation?.member.displayName ?? "")",
                   isPresented: Binding(get: { sharing.confirmation != nil },
                                        set: { if !$0 { sharing.confirmation = nil } }),
                   presenting: sharing.confirmation) { confirmation in
                Button("Confirmer") { Task { await model.confirmMember(confirmation) } }
                Button("Annuler", role: .cancel) { sharing.confirmation = nil }
            } message: { confirmation in
                Text("« \(confirmation.fingerprint) »\n\nDemandez à \(confirmation.member.displayName) la phrase d'empreinte de son compte (Verrou : Réglages → Compte ; coffre web : Paramètres → Mon compte). Confirmez seulement si elle est identique : la clé de l'organisation sera chiffrée pour cette personne.")
            }
            .confirmationDialog("Quitter \(sharing.confirmLeave?.name ?? "l'organisation") ?",
                                isPresented: Binding(get: { sharing.confirmLeave != nil },
                                                     set: { if !$0 { sharing.confirmLeave = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmLeave) { org in
                Button("Quitter", role: .destructive) { Task { await model.leaveOrganization(org) } }
            } message: { _ in
                Text("Ses éléments disparaîtront de votre coffre (ils restent dans l'organisation). Pour revenir, il faudra une nouvelle invitation.")
            }
            .confirmationDialog("Supprimer la collection « \(sharing.confirmDelete?.collection.name ?? "") » ?",
                                isPresented: Binding(get: { sharing.confirmDelete != nil },
                                                     set: { if !$0 { sharing.confirmDelete = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmDelete) { target in
                Button("Supprimer", role: .destructive) { Task { await model.deleteCollection(target) } }
            } message: { _ in
                Text("Ses éléments restent dans l'organisation : les administrateurs les voient toujours.")
            }
            .confirmationDialog("Révoquer l'accès de \(sharing.confirmRevoke?.member.displayName ?? "") ?",
                                isPresented: Binding(get: { sharing.confirmRevoke != nil },
                                                     set: { if !$0 { sharing.confirmRevoke = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmRevoke) { target in
                Button("Révoquer", role: .destructive) {
                    Task {
                        await model.memberAction("Accès de \(target.member.displayName) révoqué", in: target.organizationID) {
                            try await model.session.revokeOrganizationMember(organizationId: target.organizationID,
                                                                             memberId: target.member.id)
                        }
                    }
                }
            } message: { _ in
                Text("Il ne voit plus rien de l'organisation ; vous pourrez restaurer son accès.")
            }
            .confirmationDialog("Retirer \(sharing.confirmRemove?.member.displayName ?? "") de l'organisation ?",
                                isPresented: Binding(get: { sharing.confirmRemove != nil },
                                                     set: { if !$0 { sharing.confirmRemove = nil } }),
                                titleVisibility: .visible, presenting: sharing.confirmRemove) { target in
                Button("Retirer", role: .destructive) {
                    Task {
                        await model.memberAction("\(target.member.displayName) ne fait plus partie de l'organisation",
                                                 in: target.organizationID) {
                            try await model.session.removeOrganizationMember(organizationId: target.organizationID,
                                                                             memberId: target.member.id)
                        }
                    }
                }
            } message: { _ in
                Text("Son compte reste sur le serveur. Pour revenir, il lui faudra une nouvelle invitation.")
            }
    }
}

// MARK: Feuilles

/// Barre d'une feuille : Annuler, et l'action (en attente pendant l'envoi).
private struct SheetToolbar: ToolbarContent {
    let action: String
    let enabled: Bool
    let busy: Bool
    let cancel: () -> Void
    let perform: () -> Void

    var body: some ToolbarContent {
        ToolbarItem(placement: .cancellationAction) {
            Button("Annuler", action: cancel).disabled(busy)
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

/// Droits sur une collection, au choix dans un menu, ou pas d'accès.
private struct PermissionPicker: View {
    let title: String
    var subtitle: String?
    var symbol: String?
    @Binding var permission: CollectionPermission?

    var body: some View {
        Picker(selection: $permission) {
            Text("Aucun accès").tag(CollectionPermission?.none)
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
                        Text(subtitle).font(.caption).foregroundStyle(.orange)
                    }
                }
            }
        }
        .pickerStyle(.menu)
    }
}

/// « Partager… » : un ou plusieurs éléments vers les collections d'une
/// organisation ; « Collections… » pour un élément déjà partagé.
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
                        Picker("Organisation", selection: $flow.organizationID) {
                            ForEach(model.writableOrganizations, id: \.id) { org in
                                Text(org.name).tag(org.id)
                            }
                        }
                        .onChange(of: flow.organizationID) { _, _ in
                            let first = organization?.collections.first { !$0.readOnly }
                            flow.collectionIDs = Set(first.map { [$0.id] } ?? [])
                        }
                    } else {
                        LabeledContent("Organisation", value: flow.current?.organization ?? "")
                    }
                } footer: {
                    Text(flow.current != nil
                         ? "Les membres de chaque collection cochée voient l'élément."
                         : flow.isBulk
                         ? "Ces éléments quittent votre coffre personnel : chacun est rechiffré avec la clé de l'organisation (pièces jointes comprises)."
                         : "L'élément quitte votre coffre personnel : il est rechiffré avec la clé de l'organisation, et ses membres le voient selon leurs droits.")
                }
                Section {
                    ForEach(organization?.collections ?? [], id: \.id) { collection in
                        Toggle(isOn: binding(collection.id)) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(collection.name)
                                if collection.readOnly {
                                    Text("lecture seule").font(.caption).foregroundStyle(.secondary)
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
                            Text("\(progress.done) sur \(progress.total)").font(.caption).monospacedDigit()
                        }
                    }
                }
                ErrorRow(error: flow.error)
            }
            .navigationTitle(heading)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: flow.current == nil ? "Partager" : "Enregistrer",
                             enabled: !flow.collectionIDs.isEmpty, busy: flow.busy,
                             cancel: { dismiss() },
                             perform: { Task { await model.applySharing(flow) } })
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var heading: String {
        if flow.current != nil { return "Collections" }
        return flow.isBulk ? "Partager (\(flow.itemIDs.count))" : "Partager"
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
    @State private var collection = "Général"

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Nom", text: $name, prompt: Text("Famille Martin"))
                        .accessibilityIdentifier("organization-name")
                    TextField("Première collection", text: $collection, prompt: Text("Général"))
                } footer: {
                    Text("Un coffre partagé dont vous êtes propriétaire. Sa clé est créée sur cet iPhone et chiffrée pour votre compte : le serveur ne la voit jamais. Le serveur peut réserver la création d'organisations à certains comptes.")
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle("Nouvelle organisation")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: "Créer", enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty,
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
                    TextField("Nom", text: $name)
                } footer: {
                    Text("Le nouveau nom s'affiche chez tous les membres à leur prochaine synchronisation.")
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle("Renommer")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: "Renommer",
                             enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty && name != organization.name,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.renameOrganization(organization, to: name) { dismiss() } }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

/// Création ou modification d'une collection : nom, et droits de chaque
/// membre et de chaque groupe.
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
                    TextField("Nom", text: $draft.name, prompt: Text("Banque"))
                        .accessibilityIdentifier("collection-name")
                } footer: {
                    Text("Son nom est chiffré avec la clé de l'organisation. Propriétaires et administrateurs voient toutes les collections.")
                }
                if draft.loading {
                    Section { ProgressView().frame(maxWidth: .infinity) }
                } else if let unavailable = draft.accessUnavailable {
                    Section {
                        Label(unavailable, systemImage: "info.circle").foregroundStyle(.secondary)
                    } header: {
                        SectionHeader("Accès")
                    }
                } else {
                    Section {
                        ForEach(draft.members.filter { $0.status != .revoked }, id: \.id) { member in
                            if member.accessAll {
                                LabeledContent {
                                    Text("toutes").foregroundStyle(.secondary)
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
                        SectionHeader("Membres")
                    }
                    if model.organization(draft.organizationID)?.useGroups == true {
                        Section {
                            if draft.groups.isEmpty {
                                Text("Aucun groupe.").foregroundStyle(.secondary)
                            }
                            ForEach(draft.groups, id: \.id) { group in
                                PermissionPicker(title: group.name, symbol: "person.3",
                                                 permission: $draft.groupAccess[group.id])
                            }
                        } header: {
                            SectionHeader("Groupes")
                        }
                    }
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle(draft.isNew ? "Nouvelle collection" : "Collection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: draft.isNew ? "Créer" : "Enregistrer",
                             enabled: !draft.name.trimmingCharacters(in: .whitespaces).isEmpty && !draft.loading,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.saveCollection(draft) { dismiss() } }
                }
            }
        }
        .task {
            // Membres, groupes et accès lus ici, une fois la feuille ouverte ;
            // le nom déjà saisi est gardé. Un échec s'affiche à la place des
            // accès (le nom reste modifiable).
            guard draft.loading, let org = model.organization(draft.organizationID) else { return }
            var loaded = await model.session.loadCollectionDraft(draft, organization: org,
                                                                 accountEmail: model.account?.email)
            loaded.name = draft.name
            draft = loaded
        }
    }
}

/// Invitation (une ou plusieurs adresses) ou modification d'un membre.
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
                        TextField("Adresses e-mail", text: $draft.emails,
                                  prompt: Text("lea@exemple.fr, tom@exemple.fr"), axis: .vertical)
                            .keyboardType(.emailAddress)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(1...4)
                            .accessibilityIdentifier("invite-emails")
                    } else {
                        LabeledContent("E-mail", value: draft.emails)
                    }
                    Picker("Rôle", selection: $draft.role) {
                        ForEach(roles, id: \.self) { role in
                            Text(role.label).tag(role)
                        }
                    }
                    .disabled(roles.count == 1)
                } footer: {
                    Text(draft.role.explanation + (organization?.isOwner == true ? ""
                         : " Seul un propriétaire donne les rôles de gestionnaire, d'administrateur ou de propriétaire."))
                }
                Section {
                    if draft.seesAll {
                        Text("Toutes les collections, avec tous les droits.").foregroundStyle(.secondary)
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
                        Text("Sans compte, la personne le crée avec le lien reçu (Verrou : « Créer un compte » à la connexion). Avec un compte, elle colle le lien dans « Rejoindre une organisation ». Vous la confirmerez ensuite en vérifiant son empreinte.")
                    }
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle(draft.isNew ? "Inviter" : draft.member?.displayName ?? "Membre")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: draft.isNew ? "Inviter" : "Enregistrer", enabled: draft.emails.contains("@"),
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
                    TextField("Nom du groupe", text: $draft.name, prompt: Text("Parents"))
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
                    SectionHeader("Membres")
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
            .navigationTitle(draft.id == nil ? "Nouveau groupe" : draft.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: draft.id == nil ? "Créer" : "Enregistrer",
                             enabled: !draft.name.trimmingCharacters(in: .whitespaces).isEmpty,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.saveGroup(draft, in: organizationID) { dismiss() } }
                }
            }
        }
    }
}

/// « Rejoindre une organisation » : le lien du courriel d'invitation, collé
/// ici, avec un compte qui existe déjà.
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
                    TextField("Lien d'invitation", text: $link,
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
                            LabeledContent("Invitation de", value: invitation.organizationName ?? "une organisation")
                            LabeledContent("Pour", value: invitation.email)
                            if !invitation.forThisAccount && model.mode == .vaultwarden {
                                Label("Cette invitation vise une autre adresse que celle de ce compte.",
                                      systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                            }
                        case .failure(let error):
                            Label(ErrorText.describe(error), systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                    } footer: {
                        Text("Une fois l'invitation acceptée, un administrateur vous confirme en comparant votre phrase d'empreinte : la clé de l'organisation est alors chiffrée pour votre compte.")
                    }
                }
                ErrorRow(error: model.sharing.error)
            }
            .navigationTitle("Rejoindre")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                SheetToolbar(action: "Rejoindre", enabled: (try? info?.get())?.forThisAccount == true,
                             busy: model.sharing.busy, cancel: { dismiss() }) {
                    Task { if await model.joinOrganization(link: trimmed) { dismiss() } }
                }
            }
        }
    }
}

/// Ma phrase d'empreinte, à lire à l'administrateur qui me confirme (ou au
/// contact d'urgence).
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
                    Text(pending.map { "En attente de \($0.name)" } ?? "Phrase d'empreinte")
                        .font(.title3.weight(.semibold))
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    FingerprintText(phrase: fingerprint)
                        .padding(16)
                        .frame(maxWidth: .infinity)
                        .glassSurface(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
                        .accessibilityIdentifier("own-fingerprint")
                    Text("Lisez cette phrase à la personne qui vous confirme : elle doit voir la même, mot pour mot. Elle garantit que la clé de l'organisation sera chiffrée pour vous, et pour personne d'autre.")
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
        // Grandes tailles de texte : la feuille entière, la phrase visible
        // sans défiler.
        .presentationDetents(typeSize.isAccessibilitySize ? [.large] : [.medium, .large])
    }
}
