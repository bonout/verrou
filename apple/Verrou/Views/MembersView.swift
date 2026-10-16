import SwiftUI

/// Entrée « Membres » d'une organisation, sous ses collections dans la
/// barre latérale « Coffres partagés ».
struct MembersSidebarRow: View {
    @Environment(AppModel.self) private var model
    let organization: OrganizationView

    private var active: Bool {
        model.pane == .members && model.members.organizationID == organization.id
    }

    /// Membres à confirmer : la liste ouverte, sinon le dernier décompte.
    private var pending: Int {
        active && model.members.loaded ? model.members.pendingConfirmation
                                       : model.organizationAdmin.toConfirm[organization.id] ?? 0
    }

    var body: some View {
        Button {
            model.openMembers(organization.id)
        } label: {
            Label {
                HStack {
                    Text("Membres").lineLimit(1)
                    Spacer()
                    if pending > 0 {
                        Text("\(pending)")
                            .monospacedDigit().foregroundStyle(.orange).font(.callout)
                            .help("Membres à confirmer")
                    }
                }
            } icon: {
                Image(systemName: "person.3").foregroundStyle(.indigo)
            }
            .padding(.vertical, 2)
            .padding(.horizontal, 4)
            .background(active ? Color.primary.opacity(0.08) : .clear,
                        in: RoundedRectangle(cornerRadius: 5, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.leading, 14)
        .help(organization.canManageMembers
              ? "Inviter, confirmer et gérer les membres de \(organization.name)"
              : "Membres de \(organization.name)")
    }
}

/// Volet « Membres », dans la colonne centrale : les membres d'une
/// organisation, groupés par état. Le membre sélectionné s'affiche à droite.
struct MembersListView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var members = model.members
        let organization = model.membersOrganization
        VStack(spacing: 0) {
            PaneHeader(title: "Membres · \(organization?.name ?? "")",
                       caption: organization?.canManageMembers == true
                           ? "Invitez une adresse : la personne crée son compte (Verrou ou coffre web), accepte, puis vous la confirmez en vérifiant son empreinte."
                           : "Votre rôle permet de voir les membres, pas de les gérer.",
                       busy: members.busy, notice: members.notice, error: members.error) {
                if organization?.canManageMembers == true {
                    Button("Inviter", systemImage: "plus") { model.inviteMembers() }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .help("Inviter des personnes dans \(organization?.name ?? "l'organisation")")
                }
            }
            Divider()
            List(selection: $members.selection) {
                if members.members.isEmpty {
                    Text(members.loaded ? "Aucun membre." : "Chargement…")
                        .foregroundStyle(.secondary)
                }
                section("À confirmer", .accepted)
                section("Invitations en attente", .invited)
                section("Membres", .confirmed)
                section("Révoqués", .revoked)
            }
            .listStyle(.inset)
            .contextMenu(forSelectionType: String.self) { ids in
                if let member = ids.first.flatMap({ id in members.members.first { $0.id == id } }),
                   organization?.canManageMembers == true {
                    MemberActionsMenu(member: member)
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .task(id: members.organizationID) { await model.reloadMembers() }
    }

    @ViewBuilder
    private func section(_ title: String, _ status: OrganizationMemberStatus) -> some View {
        let rows = model.members.members.filter { $0.status == status }
        if !rows.isEmpty {
            Section(title) {
                ForEach(rows, id: \.id) { member in
                    MemberRow(member: member).tag(member.id)
                }
            }
        }
    }
}

private struct MemberRow: View {
    let member: OrganizationMember

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: member.role.symbol)
                .font(.system(size: 15))
                .foregroundStyle(member.status == .revoked ? Color.secondary : Theme.accent)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(member.displayName).lineLimit(1)
                Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if member.status == .accepted {
                Circle().fill(.orange).frame(width: 7, height: 7)
                    .help("À confirmer : vérifiez son empreinte")
            }
        }
        .padding(.vertical, 4)
    }

    private var subtitle: String {
        var parts = [member.role.label]
        if member.name != nil { parts.insert(member.email, at: 0) }
        if member.status == .invited, !member.hasAccount { parts.append("pas encore de compte") }
        return parts.joined(separator: " · ")
    }
}

/// Actions possibles sur un membre selon son état (menu contextuel).
private struct MemberActionsMenu: View {
    @Environment(AppModel.self) private var model
    let member: OrganizationMember

    var body: some View {
        switch member.status {
        case .accepted:
            Button("Confirmer…") { Task { await model.prepareMemberConfirmation(member) } }
        case .invited:
            Button("Renvoyer l'invitation") { Task { await model.reinviteMember(member) } }
        case .revoked:
            Button("Restaurer l'accès") { Task { await model.restoreMember(member) } }
        case .confirmed:
            EmptyView()
        }
        Button("Modifier le rôle et les collections…") { model.editMember(member) }
        Divider()
        if member.status != .revoked {
            Button("Révoquer l'accès…") { model.members.confirmRevoke = member }
        }
        Button("Retirer de l'organisation…", role: .destructive) { model.members.confirmRemove = member }
    }
}

/// Colonne de droite du volet « Membres » : le membre sélectionné, ses
/// accès, et ce qu'on peut en faire selon son état.
struct MemberDetailView: View {
    @Environment(AppModel.self) private var model
    let member: OrganizationMember

    private var organization: OrganizationView? { model.membersOrganization }
    private var canManage: Bool { organization?.canManageMembers == true }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Text(statusText)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if canManage {
                    HStack(spacing: 10) {
                        primaryAction
                        Button("Modifier…", systemImage: "pencil") { model.editMember(member) }
                        Spacer()
                        if member.status == .revoked {
                            Button("Restaurer", systemImage: "arrow.uturn.backward") {
                                Task { await model.restoreMember(member) }
                            }
                        } else {
                            Button("Révoquer…", systemImage: "hand.raised") { model.members.confirmRevoke = member }
                                .help("Retirer son accès sans le supprimer (restaurable)")
                        }
                        Button("Retirer…", systemImage: "person.badge.minus", role: .destructive) {
                            model.members.confirmRemove = member
                        }
                    }
                    .disabled(model.members.busy)
                }

                SectionTitle("Accès")
                FieldCard {
                    line("Rôle", member.role.label)
                    Divider().padding(.leading, 14)
                    if member.accessAll {
                        line("Collections", "Toutes")
                    } else if member.collections.isEmpty {
                        line("Collections", "Aucune")
                    } else {
                        ForEach(Array(member.collections.enumerated()), id: \.element.collectionId) { index, access in
                            if index > 0 { Divider().padding(.leading, 14) }
                            line(collectionName(access.collectionId), CollectionPermission(access).label)
                        }
                    }
                }
                Text(member.role.explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                SectionTitle("Compte")
                FieldCard {
                    line("E-mail", member.email)
                    Divider().padding(.leading, 14)
                    line("Compte sur le serveur", member.hasAccount ? "Créé" : "Pas encore créé")
                    Divider().padding(.leading, 14)
                    line("Double authentification", member.twoFactorEnabled ? "Activée" : "Désactivée")
                }
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    @ViewBuilder
    private var primaryAction: some View {
        switch member.status {
        case .accepted:
            Button("Confirmer…") { Task { await model.prepareMemberConfirmation(member) } }
                .buttonStyle(.borderedProminent)
                .help("Vérifier son empreinte, puis lui confier la clé de l'organisation")
        case .invited:
            Button("Renvoyer l'invitation") { Task { await model.reinviteMember(member) } }
        case .confirmed, .revoked:
            EmptyView()
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: member.role.symbol)
                .font(.system(size: 28))
                .foregroundStyle(Theme.accent)
                .frame(width: 64, height: 64)
                .background(Theme.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 5) {
                Text(member.displayName)
                    .font(.system(size: 24, weight: .bold))
                    .textSelection(.enabled)
                    .layoutMark("detail-title")
                HStack(spacing: 8) {
                    Chip(text: member.role.label, symbol: member.role.symbol, tint: Theme.accent)
                    Chip(text: member.status.label, symbol: "circle.fill", tint: member.status.tint)
                    if member.twoFactorEnabled {
                        Chip(text: "2FA", symbol: "lock.shield", tint: .secondary)
                            .help("Double authentification activée")
                    }
                }
            }
            Spacer()
        }
        .padding(.bottom, 4)
    }

    private var statusText: String {
        switch member.status {
        case .invited:
            member.hasAccount
                ? "Invitation envoyée : en attente de son acceptation."
                : "Invitation envoyée. La personne crée son compte avec le lien reçu par e-mail (dans Verrou : « Créer un compte » sur l'écran de connexion), puis l'accepte."
        case .accepted:
            "Invitation acceptée. Confirmez-la après avoir comparé l'empreinte de sa clé avec la phrase que la personne lit dans son compte : la clé de l'organisation sera chiffrée pour elle."
        case .confirmed:
            "Membre confirmé : il accède aux collections ci-dessous."
        case .revoked:
            "Accès révoqué : il ne voit plus rien de l'organisation. Restaurer lui rend son accès d'avant."
        }
    }

    private func collectionName(_ id: String) -> String {
        organization?.collections.first { $0.id == id }?.name ?? "Collection"
    }

    private func line(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

/// Feuilles et confirmations du volet « Membres », posées sur la fenêtre
/// principale.
struct MembersPresentations: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var members = model.members
        content
            .sheet(item: $members.draft) { draft in
                MemberEditorView(draft: draft).environment(model)
            }
            .alert("Vérifier l'empreinte de \(members.confirmation?.member.displayName ?? "")",
                   isPresented: Binding(get: { members.confirmation != nil },
                                        set: { if !$0 { members.confirmation = nil } }),
                   presenting: members.confirmation) { confirmation in
                Button("Confirmer") { Task { await model.confirmMember(confirmation) } }
                Button("Annuler", role: .cancel) { members.confirmation = nil }
            } message: { confirmation in
                Text("« \(confirmation.fingerprint) »\n\nDemandez à \(confirmation.member.displayName) la phrase d'empreinte de son compte (Verrou : Réglages → Compte ; coffre web : Paramètres → Mon compte). Confirmez seulement si elle est identique : la clé de l'organisation sera chiffrée pour cette personne.")
            }
            .confirmationDialog("Révoquer l'accès de \(members.confirmRevoke?.displayName ?? "") ?",
                                isPresented: Binding(get: { members.confirmRevoke != nil },
                                                     set: { if !$0 { members.confirmRevoke = nil } }),
                                presenting: members.confirmRevoke) { member in
                Button("Révoquer", role: .destructive) { Task { await model.revokeMember(member) } }
            } message: { _ in
                Text("Il ne verra plus les éléments de l'organisation. Vous pourrez restaurer son accès.")
            }
            .confirmationDialog("Retirer \(members.confirmRemove?.displayName ?? "") de l'organisation ?",
                                isPresented: Binding(get: { members.confirmRemove != nil },
                                                     set: { if !$0 { members.confirmRemove = nil } }),
                                presenting: members.confirmRemove) { member in
                Button("Retirer", role: .destructive) { Task { await model.removeMember(member) } }
            } message: { _ in
                Text("Son compte reste sur le serveur ; pour le faire revenir, il faudra l'inviter de nouveau.")
            }
    }
}

/// Invitation de nouvelles adresses, ou modification du rôle et des
/// collections d'un membre.
struct MemberEditorView: View {
    @Environment(AppModel.self) private var model
    @State private var draft: MemberDraft

    init(draft: MemberDraft) {
        _draft = State(initialValue: draft)
    }

    private var organization: OrganizationView? { model.membersOrganization }

    /// Rôles proposés : au-dessus d'« utilisateur », seulement par un
    /// propriétaire (règle de Vaultwarden).
    private var roles: [OrganizationMemberRole] {
        organization?.isOwner == true ? [.user, .manager, .admin, .owner] : [.user]
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: draft.isNew ? "person.badge.plus" : "person.crop.circle.badge.checkmark")
                    .font(.system(size: 22))
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 2) {
                    Text(draft.isNew ? "Inviter dans \(organization?.name ?? "l'organisation")"
                                     : "Accès de \(draft.member?.displayName ?? "")")
                        .font(.headline)
                        .layoutMark("sheet-title")
                    Text(draft.isNew ? "Le serveur envoie un lien d'invitation à chaque adresse."
                                     : "Le rôle et les collections remplacent les précédents.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(16)
            Divider()
            Form {
                Section {
                    if draft.isNew {
                        TextField("Adresses e-mail", text: $draft.emails,
                                  prompt: Text("lea@exemple.fr, tom@exemple.fr"), axis: .vertical)
                            .lineLimit(1...4)
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
                    VStack(alignment: .leading, spacing: 4) {
                        Text(draft.role.explanation)
                        if organization?.isOwner != true {
                            Text("Seul un propriétaire peut donner les rôles de gestionnaire, d'administrateur ou de propriétaire.")
                        }
                    }
                    .font(.caption).foregroundStyle(.secondary)
                }
                Section("Collections") {
                    if draft.seesAll {
                        Text("Toutes les collections, avec tous les droits.")
                            .foregroundStyle(.secondary)
                    } else if let collections = organization?.collections, !collections.isEmpty {
                        ForEach(collections, id: \.id) { collection in
                            collectionRow(collection)
                        }
                    } else {
                        Text("Aucune collection dans cette organisation.").foregroundStyle(.secondary)
                    }
                }
                if draft.isNew {
                    Section {
                        Text("Sans compte sur le serveur, la personne le crée avec le lien reçu (dans Verrou : « Créer un compte » sur l'écran de connexion, en collant le lien). Une fois l'invitation acceptée, vous la confirmerez en vérifiant l'empreinte de sa clé.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                if let error = model.members.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                if model.members.busy { ProgressView().controlSize(.small) }
                Button("Annuler") { model.members.draft = nil }
                    .keyboardShortcut(.cancelAction)
                Button(draft.isNew ? "Inviter" : "Enregistrer") { Task { await model.saveMemberDraft(draft) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!draft.emails.contains("@") || model.members.busy)
                    .layoutMark("sheet-primary")
            }
            .padding(16)
        }
        .frame(width: 520)
        .frame(minHeight: 420, maxHeight: 640)
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear { model.members.error = nil }
    }

    private func collectionRow(_ collection: CollectionView) -> some View {
        let granted = Binding(
            get: { draft.access[collection.id] != nil },
            set: { draft.access[collection.id] = $0 ? (draft.access[collection.id] ?? .edit) : nil })
        let permission = Binding(
            get: { draft.access[collection.id] ?? .edit },
            set: { draft.access[collection.id] = $0 })
        return HStack {
            Toggle(collection.name, isOn: granted)
                .toggleStyle(.checkbox)
            Spacer()
            Picker("Droits", selection: permission) {
                ForEach(CollectionPermission.allCases) { level in
                    Text(level.label).tag(level)
                }
            }
            .labelsHidden()
            .frame(width: 230)
            .disabled(draft.access[collection.id] == nil)
        }
    }
}

/// Réglages → Compte : la phrase d'empreinte de ma clé publique, à lire à
/// l'administrateur qui me confirme dans une organisation (ou à un contact
/// d'urgence).
struct OwnFingerprintRow: View {
    @Environment(AppModel.self) private var model
    @State private var phrase: String?
    @State private var failed = false

    var body: some View {
        LabeledContent("Phrase d'empreinte") {
            if let phrase {
                FingerprintText(phrase: phrase, font: .body.monospaced(), alignment: .trailing)
            } else if model.lockState != .unlocked {
                Text("coffre verrouillé").foregroundStyle(.secondary)
            } else if failed {
                Text("indisponible").foregroundStyle(.secondary)
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .help("À comparer avec celle que voit la personne qui vous confirme (organisation ou accès d'urgence)")
        .task(id: model.lockState) {
            phrase = nil
            failed = false
            guard model.lockState == .unlocked else { return }
            if model.members.preview {
                phrase = "turban-deftly-anime-chatroom-unselfish"
                return
            }
            do {
                phrase = try await model.session.ownFingerprint()
            } catch {
                failed = true
            }
        }
    }
}
