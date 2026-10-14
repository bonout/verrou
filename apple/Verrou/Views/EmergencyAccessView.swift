import SwiftUI

/// Entrée de la barre latérale : ouvre la fenêtre des accès d'urgence.
struct EmergencySidebarButton: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            openWindow(id: "emergency")
        } label: {
            Label {
                HStack {
                    Text("Accès d'urgence")
                    Spacer()
                    if pending > 0 {
                        Text("\(pending)").monospacedDigit().foregroundStyle(.orange).font(.callout)
                    }
                }
            } icon: {
                Image(systemName: "person.2.badge.key").foregroundStyle(Theme.accent)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 10)
        .padding(.bottom, 6)
        .help("Confier son coffre à un proche, ou ouvrir celui qu'un proche vous a confié")
    }

    /// Ce qui attend une action de ma part : contact à confirmer, demande à traiter.
    private var pending: Int {
        model.emergency.trusted.filter { $0.state == .accepted || $0.state == .recoveryInitiated }.count
    }
}

/// Fenêtre « Accès d'urgence ».
struct EmergencyWindow: View {
    @Environment(AppModel.self) private var model
    @State private var confirmRequest: EmergencyContact?
    @State private var confirmDelete: EmergencyContact?

    var body: some View {
        Group {
            if model.emergencyAvailable {
                content
            } else {
                ContentUnavailableView(
                    model.mode == .demo ? "Coffre fictif" : "Coffre verrouillé",
                    systemImage: model.mode == .demo ? "person.2" : "lock",
                    description: Text(model.mode == .demo
                                      ? "L'accès d'urgence demande un compte Vaultwarden."
                                      : "Déverrouillez Verrou pour gérer vos accès d'urgence."))
            }
        }
        .frame(minWidth: 620, minHeight: 460)
        .task(id: model.lockState) { await model.reloadEmergency() }
        .sheet(item: Binding(get: { model.emergency.invite }, set: { model.emergency.invite = $0 })) { draft in
            InviteContactView(draft: draft).environment(model)
        }
        .sheet(item: Binding(get: { model.emergency.grantorVault }, set: { if $0 == nil { model.emergency.closeGrantorVault() } })) { vault in
            GrantorVaultView(vault: vault).environment(model)
        }
        .alert("Vérifier l'empreinte de \(model.emergency.confirmation?.contact.displayName ?? "")",
               isPresented: Binding(get: { model.emergency.confirmation != nil },
                                    set: { if !$0 { model.emergency.confirmation = nil } }),
               presenting: model.emergency.confirmation) { confirmation in
            Button("Confirmer") { Task { await model.confirmContact(confirmation) } }
            Button("Annuler", role: .cancel) { model.emergency.confirmation = nil }
        } message: { confirmation in
            Text("« \(confirmation.fingerprint) »\n\nDemandez à \(confirmation.contact.displayName) la phrase d'empreinte de son compte (coffre web : Réglages → Mon compte). Confirmez seulement si elle est identique : la clé de votre coffre sera chiffrée pour lui.")
        }
        .confirmationDialog("Demander l'accès au coffre de \(confirmRequest?.displayName ?? "") ?",
                            isPresented: Binding(get: { confirmRequest != nil }, set: { if !$0 { confirmRequest = nil } }),
                            presenting: confirmRequest) { contact in
            Button("Demander l'accès") { Task { await model.requestEmergency(contact) } }
        } message: { contact in
            Text("\(contact.displayName) sera prévenu. Sans refus de sa part, l'accès vous sera accordé dans \(days(contact.waitTimeDays)).")
        }
        .confirmationDialog("Supprimer cet accès d'urgence ?",
                            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                            presenting: confirmDelete) { contact in
            Button("Supprimer", role: .destructive) { Task { await model.deleteEmergency(contact) } }
        } message: { contact in
            Text("L'accès entre vous et \(contact.displayName) sera retiré.")
        }
    }

    private var content: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "person.2.badge.key")
                    .font(.system(size: 26))
                    .foregroundStyle(Theme.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Accès d'urgence").font(.title3.weight(.semibold))
                    Text("Un proche de confiance peut demander l'accès à votre coffre ; sans refus de votre part, il l'obtient après le délai choisi.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if model.emergency.busy { ProgressView().controlSize(.small) }
                Button {
                    model.emergency.invite = .init(contactID: nil, email: "", type: .view, waitDays: 7)
                } label: {
                    Label("Inviter un contact", systemImage: "plus")
                }
            }
            .padding(16)
            if let notice = model.emergency.notice {
                banner(notice, symbol: "checkmark.circle.fill", tint: .green)
            }
            if let error = model.emergency.error {
                banner(error, symbol: "exclamationmark.triangle.fill", tint: .red)
            }
            Divider()
            List {
                Section("Mes contacts de confiance") {
                    if model.emergency.trusted.isEmpty {
                        Text(model.emergency.loaded ? "Aucun contact pour l'instant." : "Chargement…")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.emergency.trusted, id: \.id) { contact in
                        ContactRow(contact: contact, subtitle: trustedStatus(contact)) {
                            trustedActions(contact)
                        }
                        .contextMenu {
                            Button("Modifier…") {
                                model.emergency.invite = .init(contactID: contact.id, email: contact.email ?? "",
                                                               type: contact.accessType, waitDays: Int(contact.waitTimeDays))
                            }
                            Divider()
                            Button("Supprimer…", role: .destructive) { confirmDelete = contact }
                        }
                    }
                }
                Section("Ils vous ont choisi") {
                    if model.emergency.granted.isEmpty {
                        Text(model.emergency.loaded ? "Personne ne vous a désigné comme contact d'urgence." : "Chargement…")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.emergency.granted, id: \.id) { contact in
                        ContactRow(contact: contact, subtitle: grantedStatus(contact)) {
                            grantedActions(contact)
                        }
                        .contextMenu {
                            Button("Renoncer à cet accès…", role: .destructive) { confirmDelete = contact }
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    // MARK: Mes contacts (je suis le concédant)

    private func trustedStatus(_ contact: EmergencyContact) -> String {
        let base = "\(contact.accessType.label) · délai \(days(contact.waitTimeDays))"
        switch contact.state {
        case .invited: return base + " · invitation envoyée, en attente d'acceptation"
        case .accepted: return base + " · invitation acceptée : à confirmer"
        case .confirmed: return base + " · confirmé"
        case .recoveryInitiated: return base + " · demande d'accès en cours"
        case .recoveryApproved: return base + " · accès accordé"
        }
    }

    @ViewBuilder
    private func trustedActions(_ contact: EmergencyContact) -> some View {
        switch contact.state {
        case .accepted:
            Button("Confirmer…") { Task { await model.prepareConfirmation(contact) } }
                .disabled(contact.userId == nil)
        case .recoveryInitiated:
            Button("Refuser") { Task { await model.rejectEmergency(contact) } }
            Button("Approuver") { Task { await model.approveEmergency(contact) } }
                .buttonStyle(.borderedProminent)
        case .recoveryApproved:
            Button("Retirer l'accès") { Task { await model.rejectEmergency(contact) } }
        case .invited, .confirmed:
            EmptyView()
        }
    }

    // MARK: Ceux qui m'ont choisi (je suis le contact)

    private func grantedStatus(_ contact: EmergencyContact) -> String {
        let base = "\(contact.accessType.label) · délai \(days(contact.waitTimeDays))"
        switch contact.state {
        case .invited: return base + " · acceptez l'invitation depuis le lien reçu par e-mail"
        case .accepted: return base + " · en attente de sa confirmation"
        case .confirmed: return base + " · vous pouvez demander l'accès"
        case .recoveryInitiated: return base + " · demande envoyée, accès à la fin du délai sauf refus"
        case .recoveryApproved:
            return contact.accessType == .takeover
                ? base + " · accès accordé : la prise de contrôle se fait depuis le coffre web"
                : base + " · accès accordé"
        }
    }

    @ViewBuilder
    private func grantedActions(_ contact: EmergencyContact) -> some View {
        switch contact.state {
        case .confirmed:
            Button("Demander l'accès…") { confirmRequest = contact }
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

    private func days(_ count: UInt32) -> String {
        count > 1 ? "\(count) jours" : "\(count) jour"
    }

    private func banner(_ text: String, symbol: String, tint: Color) -> some View {
        Label(text, systemImage: symbol)
            .font(.callout)
            .foregroundStyle(tint)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.bottom, 10)
    }
}

private struct ContactRow<Actions: View>: View {
    let contact: EmergencyContact
    let subtitle: String
    @ViewBuilder let actions: () -> Actions

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: contact.accessType == .view ? "eye" : "key")
                .font(.system(size: 16))
                .foregroundStyle(Theme.accent)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(contact.displayName).lineLimit(1)
                if let email = contact.email, contact.name != nil {
                    Text(email).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            actions()
        }
        .padding(.vertical, 4)
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
