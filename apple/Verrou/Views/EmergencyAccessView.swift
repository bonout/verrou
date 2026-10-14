import SwiftUI

/// Entrée de la barre latérale : le volet des accès d'urgence remplace la liste.
struct EmergencySidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        SidebarPaneButton(title: "Accès d'urgence", symbol: "person.2.badge.key", active: model.pane == .emergency,
                          badge: pending > 0 ? pending : nil, badgeTint: .orange,
                          help: "Confier son coffre à un proche, ou ouvrir celui qu'un proche vous a confié") {
            model.openEmergency()
        }
    }

    /// Ce qui attend une action de ma part : contact à confirmer, demande à traiter.
    private var pending: Int {
        model.emergency.trusted.filter { $0.state == .accepted || $0.state == .recoveryInitiated }.count
    }
}

/// Volet « Accès d'urgence », dans la colonne centrale : mes contacts de
/// confiance et ceux qui m'ont choisi. L'accès sélectionné s'affiche à droite.
struct EmergencyListView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var emergency = model.emergency
        VStack(spacing: 0) {
            PaneHeader(title: "Accès d'urgence",
                       caption: "Un proche de confiance peut demander l'accès à votre coffre ; sans refus de votre part, il l'obtient après le délai choisi.",
                       busy: emergency.busy, notice: emergency.notice, error: emergency.error) {
                Button("Inviter un contact", systemImage: "plus") { emergency.inviteNew() }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .help("Désigner un proche comme contact d'urgence")
            }
            Divider()
            List(selection: $emergency.selection) {
                Section("Mes contacts de confiance") {
                    if emergency.trusted.isEmpty {
                        Text(emergency.loaded ? "Aucun contact pour l'instant." : "Chargement…")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(emergency.trusted, id: \.id) { contact in
                        ContactRow(contact: contact, trusted: true)
                            .tag(contact.id)
                    }
                }
                Section("Ils vous ont choisi") {
                    if emergency.granted.isEmpty {
                        Text(emergency.loaded ? "Personne ne vous a désigné comme contact d'urgence." : "Chargement…")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(emergency.granted, id: \.id) { contact in
                        ContactRow(contact: contact, trusted: false)
                            .tag(contact.id)
                    }
                }
            }
            .listStyle(.inset)
            .contextMenu(forSelectionType: String.self) { ids in
                if let id = ids.first {
                    if let contact = emergency.trusted.first(where: { $0.id == id }) {
                        Button("Modifier…") { emergency.edit(contact) }
                        Divider()
                        Button("Supprimer…", role: .destructive) { emergency.confirmDelete = contact }
                    } else if let contact = emergency.granted.first(where: { $0.id == id }) {
                        Button("Renoncer à cet accès…", role: .destructive) { emergency.confirmDelete = contact }
                    }
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .task { await model.reloadEmergency() }
    }
}

private struct ContactRow: View {
    let contact: EmergencyContact
    let trusted: Bool

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: contact.accessType == .view ? "eye" : "key")
                .font(.system(size: 16))
                .foregroundStyle(Theme.accent)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(contact.displayName).lineLimit(1)
                Text(contact.status(trusted: trusted)).font(.callout).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            if trusted, contact.state == .accepted || contact.state == .recoveryInitiated {
                Circle().fill(.orange).frame(width: 7, height: 7)
                    .help("En attente de votre réponse")
            }
        }
        .padding(.vertical, 4)
    }
}

/// Colonne de droite du volet « Accès d'urgence » : l'accès sélectionné et
/// ce qu'on peut en faire selon son état.
struct EmergencyDetailView: View {
    @Environment(AppModel.self) private var model
    let contact: EmergencyContact
    /// Un de mes contacts (je suis le concédant) ; sinon, quelqu'un qui m'a choisi.
    let trusted: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Text(contact.status(trusted: trusted))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    if trusted { trustedActions } else { grantedActions }
                    Spacer()
                    if trusted {
                        Button("Modifier…", systemImage: "pencil") { model.emergency.edit(contact) }
                        Button("Supprimer…", systemImage: "trash", role: .destructive) {
                            model.emergency.confirmDelete = contact
                        }
                    } else {
                        Button("Renoncer…", systemImage: "trash", role: .destructive) {
                            model.emergency.confirmDelete = contact
                        }
                        .help("Renoncer à cet accès d'urgence")
                    }
                }
                .disabled(model.emergency.busy)

                SectionTitle(trusted ? "Ce que ce contact peut faire" : "Ce qui vous est confié")
                FieldCard {
                    line("Accès", contact.accessType.label)
                    Divider().padding(.leading, 14)
                    line("Délai d'attente", days(contact.waitTimeDays))
                    if let email = contact.email {
                        Divider().padding(.leading, 14)
                        line("E-mail", email)
                    }
                }
                Text(contact.accessType == .view
                     ? (trusted ? "Il pourra voir les éléments de votre coffre, sans les modifier."
                                : "Vous pourrez voir les éléments de son coffre, sans les modifier.")
                     : (trusted ? "Il pourra choisir un nouveau mot de passe principal pour votre compte (depuis le coffre web)."
                                : "Vous pourrez choisir un nouveau mot de passe principal pour son compte (depuis le coffre web)."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: contact.accessType == .view ? "eye" : "key")
                .font(.system(size: 28))
                .foregroundStyle(Theme.accent)
                .frame(width: 64, height: 64)
                .background(Theme.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 5) {
                Text(contact.displayName)
                    .font(.system(size: 24, weight: .bold))
                    .textSelection(.enabled)
                HStack(spacing: 8) {
                    Chip(text: trusted ? "Mon contact" : "M'a choisi", symbol: "person.2.badge.key", tint: Theme.accent)
                    Chip(text: contact.accessType.label, symbol: contact.accessType == .view ? "eye" : "key",
                         tint: .secondary)
                }
            }
            Spacer()
        }
        .padding(.bottom, 4)
    }

    // MARK: Mes contacts (je suis le concédant)

    @ViewBuilder
    private var trustedActions: some View {
        switch contact.state {
        case .accepted:
            Button("Confirmer…") { Task { await model.prepareConfirmation(contact) } }
                .buttonStyle(.borderedProminent)
                .disabled(contact.userId == nil)
        case .recoveryInitiated:
            Button("Approuver") { Task { await model.approveEmergency(contact) } }
                .buttonStyle(.borderedProminent)
            Button("Refuser") { Task { await model.rejectEmergency(contact) } }
        case .recoveryApproved:
            Button("Retirer l'accès") { Task { await model.rejectEmergency(contact) } }
        case .invited, .confirmed:
            EmptyView()
        }
    }

    // MARK: Ceux qui m'ont choisi (je suis le contact)

    @ViewBuilder
    private var grantedActions: some View {
        switch contact.state {
        case .confirmed:
            Button("Demander l'accès…") { model.emergency.confirmRequest = contact }
                .buttonStyle(.borderedProminent)
        case .recoveryApproved where contact.accessType == .view:
            Button("Ouvrir le coffre") { Task { await model.openGrantorVault(contact) } }
                .buttonStyle(.borderedProminent)
        case .recoveryApproved:
            if let server = model.account?.server, let url = URL(string: server) {
                Button("Ouvrir le coffre web") { NSWorkspace.shared.open(url) }
                    .help("La prise de contrôle (nouveau mot de passe principal) est à faire depuis le coffre web")
            }
        case .invited, .accepted, .recoveryInitiated:
            EmptyView()
        }
    }

    private func line(_ label: String, _ value: String) -> some View {
        LabeledContent(label) {
            Text(value).textSelection(.enabled)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

/// Feuilles, alertes et confirmations des accès d'urgence, posées sur la
/// fenêtre principale. Le coffre d'un concédant reste une feuille.
struct EmergencyPresentations: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var emergency = model.emergency
        content
            .sheet(item: $emergency.invite) { draft in
                InviteContactView(draft: draft).environment(model)
            }
            .sheet(item: Binding(get: { emergency.grantorVault },
                                 set: { if $0 == nil { emergency.closeGrantorVault() } })) { vault in
                GrantorVaultView(vault: vault).environment(model)
            }
            .alert("Vérifier l'empreinte de \(emergency.confirmation?.contact.displayName ?? "")",
                   isPresented: Binding(get: { emergency.confirmation != nil },
                                        set: { if !$0 { emergency.confirmation = nil } }),
                   presenting: emergency.confirmation) { confirmation in
                Button("Confirmer") { Task { await model.confirmContact(confirmation) } }
                Button("Annuler", role: .cancel) { emergency.confirmation = nil }
            } message: { confirmation in
                Text("« \(confirmation.fingerprint) »\n\nDemandez à \(confirmation.contact.displayName) la phrase d'empreinte de son compte (coffre web : Réglages → Mon compte). Confirmez seulement si elle est identique : la clé de votre coffre sera chiffrée pour lui.")
            }
            .confirmationDialog("Demander l'accès au coffre de \(emergency.confirmRequest?.displayName ?? "") ?",
                                isPresented: Binding(get: { emergency.confirmRequest != nil },
                                                     set: { if !$0 { emergency.confirmRequest = nil } }),
                                presenting: emergency.confirmRequest) { contact in
                Button("Demander l'accès") { Task { await model.requestEmergency(contact) } }
            } message: { contact in
                Text("\(contact.displayName) sera prévenu. Sans refus de sa part, l'accès vous sera accordé dans \(days(contact.waitTimeDays)).")
            }
            .confirmationDialog("Supprimer cet accès d'urgence ?",
                                isPresented: Binding(get: { emergency.confirmDelete != nil },
                                                     set: { if !$0 { emergency.confirmDelete = nil } }),
                                presenting: emergency.confirmDelete) { contact in
                Button("Supprimer", role: .destructive) { Task { await model.deleteEmergency(contact) } }
            } message: { contact in
                Text("L'accès entre vous et \(contact.displayName) sera retiré.")
            }
    }
}

private func days(_ count: UInt32) -> String {
    count > 1 ? "\(count) jours" : "\(count) jour"
}

private extension EmergencyContact {
    /// État de l'accès, vu de mon côté : concédant (`trusted`) ou contact.
    func status(trusted: Bool) -> String {
        let base = "\(accessType.label) · délai \(days(waitTimeDays))"
        if trusted {
            switch state {
            case .invited: return base + " · invitation envoyée, en attente d'acceptation"
            case .accepted: return base + " · invitation acceptée : à confirmer"
            case .confirmed: return base + " · confirmé"
            case .recoveryInitiated: return base + " · demande d'accès en cours"
            case .recoveryApproved: return base + " · accès accordé"
            }
        }
        switch state {
        case .invited: return base + " · acceptez l'invitation depuis le lien reçu par e-mail"
        case .accepted: return base + " · en attente de sa confirmation"
        case .confirmed: return base + " · vous pouvez demander l'accès"
        case .recoveryInitiated: return base + " · demande envoyée, accès à la fin du délai sauf refus"
        case .recoveryApproved:
            return accessType == .takeover
                ? base + " · accès accordé : la prise de contrôle se fait depuis le coffre web"
                : base + " · accès accordé"
        }
    }
}

/// Invitation d'un contact, ou modification de son type d'accès et de son délai.
struct InviteContactView: View {
    @Environment(AppModel.self) private var model
    @State private var draft: EmergencyModel.InviteDraft

    init(draft: EmergencyModel.InviteDraft) {
        _draft = State(initialValue: draft)
    }

    private var isNew: Bool { draft.contactID == nil }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Adresse e-mail", text: $draft.email, prompt: Text("proche@exemple.fr"))
                        .disabled(!isNew)
                    Picker("Accès", selection: $draft.type) {
                        Text("Lecture seule").tag(EmergencyType.view)
                        Text("Prise de contrôle").tag(EmergencyType.takeover)
                    }
                    Stepper(value: $draft.waitDays, in: 1...90) {
                        Text("Délai d'attente : \(draft.waitDays) jour\(draft.waitDays > 1 ? "s" : "")")
                    }
                } footer: {
                    Text(draft.type == .view
                         ? "Le contact pourra voir les éléments de votre coffre, sans les modifier."
                         : "Le contact pourra choisir un nouveau mot de passe principal pour votre compte (depuis le coffre web).")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if isNew {
                    Section {
                        Text("Le contact doit avoir un compte sur ce serveur. Une fois l'invitation acceptée, vous la confirmerez en vérifiant l'empreinte de sa clé.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                if let error = model.emergency.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                if model.emergency.busy { ProgressView().controlSize(.small) }
                Button("Annuler") { model.emergency.invite = nil }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Inviter" : "Enregistrer") { Task { await model.saveInvite(draft) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!draft.email.contains("@") || model.emergency.busy)
            }
            .padding(16)
        }
        .frame(width: 460)
        .onAppear { model.emergency.error = nil }
    }
}

/// Coffre d'un concédant, en lecture seule.
struct GrantorVaultView: View {
    @Environment(AppModel.self) private var model
    @Bindable var vault: GrantorVault

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "eye").foregroundStyle(Theme.accent)
                Text("Coffre de \(vault.grantor)").font(.headline)
                Text("lecture seule").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Fermer") { model.emergency.closeGrantorVault() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
            Divider()
            HStack(spacing: 0) {
                VStack(spacing: 0) {
                    TextField("Rechercher", text: $vault.query)
                        .textFieldStyle(.roundedBorder)
                        .padding(8)
                    List(vault.rows, id: \.id, selection: $vault.selection) { summary in
                        HStack(spacing: 9) {
                            ItemIcon(summary: summary, size: 26)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(summary.title).lineLimit(1)
                                Text(summary.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                        .tag(summary.id)
                    }
                    .listStyle(.sidebar)
                }
                .frame(width: 260)
                Divider()
                Group {
                    if let detail = vault.detail {
                        GrantorItemView(vault: vault, detail: detail)
                            .id(detail.summary.id)
                    } else {
                        ContentUnavailableView("Aucun élément", systemImage: "tray")
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(width: 820, height: 560)
        .onChange(of: vault.selection) { vault.revealed.removeAll() }
    }
}

private struct GrantorItemView: View {
    @Environment(AppModel.self) private var model
    let vault: GrantorVault
    let detail: ItemDetail

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 12) {
                    ItemIcon(summary: detail.summary, size: 40)
                    VStack(alignment: .leading) {
                        Text(detail.summary.title).font(.title3.weight(.semibold))
                        Text(detail.summary.subtitle).foregroundStyle(.secondary)
                    }
                }
                ForEach(detail.fields, id: \.id) { field in
                    row(field)
                }
                ForEach(detail.urls, id: \.self) { url in
                    LabeledContent("Site") { Text(url).textSelection(.enabled) }
                }
                if detail.hasNotes {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("Notes").font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Button(vault.revealed["notes"] == nil ? "Afficher" : "Masquer") { toggle("notes") }
                                .buttonStyle(.borderless)
                        }
                        if let notes = vault.revealed["notes"] {
                            Text(notes).textSelection(.enabled)
                        } else {
                            MaskedText()
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func row(_ field: FieldView) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                if field.fieldType == .totp {
                    Text((try? vault.vault.totp(id: detail.summary.id, unixTime: UInt64(Date().timeIntervalSince1970)))?.code ?? "—")
                        .font(.body.monospaced())
                } else if !field.secret {
                    Text(field.value ?? "").textSelection(.enabled)
                } else if let value = vault.revealed[field.id] {
                    Text(value).font(.body.monospaced()).textSelection(.enabled)
                } else {
                    MaskedText()
                }
            }
            Spacer()
            if field.secret, field.fieldType != .totp {
                Button(vault.revealed[field.id] == nil ? "Afficher" : "Masquer") { toggle(field.id) }
                    .buttonStyle(.borderless)
            }
            Button {
                model.copyGrantorField(field, itemID: detail.summary.id, in: vault)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copier")
        }
    }

    private func toggle(_ fieldID: String) {
        if vault.revealed[fieldID] != nil {
            vault.revealed[fieldID] = nil
        } else {
            vault.revealed[fieldID] = try? vault.vault.reveal(id: detail.summary.id, fieldId: fieldID)
        }
    }
}
