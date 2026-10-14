import SwiftUI

/// Entrée de la barre latérale : ouvre la fenêtre des envois.
struct SendsSidebarButton: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            openWindow(id: "sends")
        } label: {
            Label {
                HStack {
                    Text("Envois")
                    Spacer()
                    if model.sends.loaded, !model.sends.items.isEmpty {
                        Text("\(model.sends.items.count)").monospacedDigit().foregroundStyle(.secondary).font(.callout)
                    }
                }
            } icon: {
                Image(systemName: "paperplane").foregroundStyle(Theme.accent)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 10)
        .padding(.bottom, 6)
        .help("Partager un texte par un lien chiffré (Bitwarden Send)")
    }
}

/// Fenêtre « Envois » : les envois du compte, avec leurs accès et leur
/// échéance ; copier le lien, modifier, supprimer.
struct SendsWindow: View {
    @Environment(AppModel.self) private var model
    @State private var confirmDelete: SendSummary?

    var body: some View {
        Group {
            if model.sendsAvailable {
                content
            } else {
                ContentUnavailableView(
                    model.mode == .demo ? "Coffre fictif" : "Coffre verrouillé",
                    systemImage: model.mode == .demo ? "paperplane" : "lock",
                    description: Text(model.mode == .demo
                                      ? "Les envois demandent un compte Vaultwarden."
                                      : "Déverrouillez Verrou pour voir vos envois."))
            }
        }
        .frame(minWidth: 560, minHeight: 380)
        .task(id: model.lockState) { await model.reloadSends() }
        .sheet(item: Binding(get: { model.sends.composer }, set: { model.sends.composer = $0 })) { composer in
            SendEditorView(composer: composer)
                .environment(model)
        }
        .confirmationDialog("Supprimer « \(confirmDelete?.name ?? "") » ?",
                            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                            presenting: confirmDelete) { send in
            Button("Supprimer", role: .destructive) { Task { await model.deleteSend(send) } }
        } message: { _ in
            Text("Le lien ne mènera plus à rien. Cette suppression est définitive.")
        }
    }

    private var content: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "paperplane")
                    .font(.system(size: 26))
                    .foregroundStyle(Theme.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Envois").font(.title3.weight(.semibold))
                    Text("Un texte partagé par un lien, chiffré de bout en bout : la clé est dans le lien, jamais sur le serveur.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if model.sends.busy { ProgressView().controlSize(.small) }
                Button {
                    model.newSend()
                } label: {
                    Label("Nouvel envoi", systemImage: "plus")
                }
            }
            .padding(16)
            if let notice = model.sends.notice {
                banner(notice, symbol: "checkmark.circle.fill", tint: .green)
            }
            if let error = model.sends.error {
                banner(error, symbol: "exclamationmark.triangle.fill", tint: .red)
            }
            Divider()
            if model.sends.items.isEmpty {
                ContentUnavailableView {
                    Label(model.sends.loaded ? "Aucun envoi" : "Chargement…", systemImage: "paperplane")
                } description: {
                    Text("Créez un envoi ici, ou depuis un élément : clic droit → « Envoyer de façon sécurisée… ».")
                }
                .frame(maxHeight: .infinity)
            } else {
                List(model.sends.items, id: \.id) { send in
                    SendRow(send: send)
                        .contextMenu { menu(send) }
                        .onTapGesture(count: 2) { Task { await model.editSend(send) } }
                }
                .listStyle(.inset)
            }
        }
    }

    @ViewBuilder
    private func menu(_ send: SendSummary) -> some View {
        Button("Copier le lien") { Task { await model.copySendLink(send) } }
        if send.content == .text {
            Button("Modifier…") { Task { await model.editSend(send) } }
        }
        if send.hasPassword {
            Button("Retirer le mot de passe") { Task { await model.removeSendPassword(send) } }
        }
        Divider()
        Button("Supprimer…", role: .destructive) { confirmDelete = send }
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

struct SendRow: View {
    @Environment(AppModel.self) private var model
    let send: SendSummary

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: send.content == .file ? "doc" : "text.alignleft")
                .font(.system(size: 18))
                .foregroundStyle(send.available ? Theme.accent : .secondary)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(send.name).lineLimit(1)
                    if send.hasPassword {
                        Image(systemName: "key.fill").font(.caption).foregroundStyle(.secondary)
                            .help("Protégé par un mot de passe")
                    }
                    if send.hideEmail {
                        Image(systemName: "eye.slash").font(.caption).foregroundStyle(.secondary)
                            .help("Adresse e-mail masquée")
                    }
                }
                Text(status)
                    .font(.callout)
                    .foregroundStyle(send.available ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
                    .lineLimit(1)
            }
            Spacer()
            Button {
                Task { await model.copySendLink(send) }
            } label: {
                Image(systemName: "link")
            }
            .buttonStyle(.borderless)
            .help("Copier le lien")
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    private var status: String {
        var parts: [String] = []
        if send.disabled {
            parts.append("Désactivé")
        }
        let accesses = send.maxAccessCount.map { "\(send.accessCount)/\($0) accès" }
            ?? "\(send.accessCount) accès"
        parts.append(accesses)
        let now = Date()
        if let expiry = send.expirationDate.map(date) {
            parts.append(expiry < now ? "expiré" : "expire \(expiry.formatted(.relative(presentation: .named)))")
        }
        parts.append("supprimé \(date(send.deletionDate).formatted(.relative(presentation: .named)))")
        return parts.joined(separator: " · ")
    }

    private func date(_ timestamp: Int64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(timestamp))
    }
}

/// Création ou modification d'un envoi de texte.
struct SendEditorView: View {
    @Environment(AppModel.self) private var model
    let composer: SendsModel.Composer
    @State private var fields: SendFields
    @State private var showText: Bool
    @State private var expires: Bool
    @State private var limited: Bool
    @State private var password = ""

    init(composer: SendsModel.Composer) {
        self.composer = composer
        _fields = State(initialValue: composer.fields)
        // Prérempli depuis un élément : le secret reste masqué jusqu'à ce
        // qu'on demande à le voir.
        _showText = State(initialValue: composer.source == nil)
        _expires = State(initialValue: composer.fields.expirationDate != nil)
        _limited = State(initialValue: composer.fields.maxAccessCount != nil)
    }

    private var isNew: Bool { composer.sendID == nil }
    private static let maxDays = 31

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if let source = composer.source {
                    Section {
                        Label("Prérempli depuis « \(source) ». Vérifiez les réglages, puis créez l'envoi : le lien sera copié.",
                              systemImage: "info.circle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                Section {
                    TextField("Nom", text: $fields.name, prompt: Text("Wi-Fi du chalet, code de la porte…"))
                    if showText {
                        TextEditor(text: $fields.text)
                            .font(.body.monospaced())
                            .frame(minHeight: 90)
                            .scrollContentBackground(.hidden)
                    } else {
                        HStack {
                            Text("Texte").foregroundStyle(.secondary)
                            Spacer()
                            MaskedText()
                            Button("Afficher") { showText = true }
                                .buttonStyle(.borderless)
                        }
                    }
                    Toggle("Masquer le texte chez le destinataire", isOn: $fields.hidden)
                }

                Section("Durée de vie") {
                    DatePicker("Suppression", selection: dateBinding(\.deletionDate), in: dateRange,
                               displayedComponents: [.date, .hourAndMinute])
                    Toggle("Expire avant la suppression", isOn: $expires.animation())
                    if expires {
                        DatePicker("Expiration", selection: expiryBinding, in: Date()...date(fields.deletionDate),
                                   displayedComponents: [.date, .hourAndMinute])
                    }
                    Toggle("Limiter le nombre d'accès", isOn: $limited.animation())
                    if limited {
                        Stepper(value: accessBinding, in: 1...1000) {
                            Text("\(fields.maxAccessCount ?? 1) accès au plus")
                        }
                    }
                }

                Section("Protection") {
                    SecureField(isNew || !composer.hasPassword ? "Mot de passe" : "Nouveau mot de passe",
                                text: $password,
                                prompt: Text(isNew || !composer.hasPassword ? "facultatif" : "laisser vide pour garder l'actuel"))
                    if !isNew, composer.hasPassword {
                        Text("Pour retirer le mot de passe : clic droit sur l'envoi → « Retirer le mot de passe ».")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Toggle("Masquer mon adresse e-mail", isOn: $fields.hideEmail)
                    if !isNew {
                        Toggle("Désactiver cet envoi", isOn: $fields.disabled)
                    }
                }

                Section("Notes privées") {
                    TextField("Notes", text: notesBinding, prompt: Text("visibles de vous seul"), axis: .vertical)
                        .labelsHidden()
                }

                if let error = model.sends.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack(spacing: 10) {
                Spacer()
                if model.sends.busy { ProgressView().controlSize(.small) }
                Button("Annuler") { model.sends.composer = nil }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Créer et copier le lien" : "Enregistrer") { save() }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave)
            }
            .padding(16)
        }
        .frame(width: 520)
        .frame(minHeight: 560)
        .navigationTitle(isNew ? "Nouvel envoi" : "Modifier l'envoi")
        .onAppear { model.sends.error = nil }
    }

    private var canSave: Bool {
        !fields.name.trimmingCharacters(in: .whitespaces).isEmpty
            && !fields.text.isEmpty
            && !model.sends.busy
    }

    private var dateRange: ClosedRange<Date> {
        Date()...Date().addingTimeInterval(TimeInterval(Self.maxDays * 86_400 - 60))
    }

    private func date(_ timestamp: Int64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(timestamp))
    }

    private func dateBinding(_ path: WritableKeyPath<SendFields, Int64>) -> Binding<Date> {
        Binding(get: { date(fields[keyPath: path]) },
                set: { fields[keyPath: path] = Int64($0.timeIntervalSince1970) })
    }

    private var expiryBinding: Binding<Date> {
        Binding(get: { date(fields.expirationDate ?? fields.deletionDate) },
                set: { fields.expirationDate = Int64($0.timeIntervalSince1970) })
    }

    private var accessBinding: Binding<UInt32> {
        Binding(get: { fields.maxAccessCount ?? 1 }, set: { fields.maxAccessCount = $0 })
    }

    private var notesBinding: Binding<String> {
        Binding(get: { fields.notes ?? "" }, set: { fields.notes = $0.isEmpty ? nil : $0 })
    }

    private func save() {
        var final = fields
        final.expirationDate = expires ? (fields.expirationDate ?? fields.deletionDate) : nil
        final.maxAccessCount = limited ? (fields.maxAccessCount ?? 1) : nil
        final.password = password.isEmpty ? nil : password
        Task {
            await model.saveSend(final, id: composer.sendID)
            if model.sends.composer == nil { password = "" }
        }
    }
}
