import SwiftUI

/// Entrée de la barre latérale : le volet des envois remplace la liste.
struct SendsSidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        SidebarPaneButton(title: "Envois", symbol: "paperplane", active: model.pane == .sends,
                          badge: model.sends.loaded && !model.sends.items.isEmpty ? model.sends.items.count : nil,
                          help: "Partager un texte par un lien chiffré (Bitwarden Send)") {
            model.openSends()
        }
    }
}

/// Volet « Envois », dans la colonne centrale : les envois du compte, avec
/// leurs accès et leur échéance. L'envoi sélectionné s'affiche à droite.
struct SendsListView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var sends = model.sends
        VStack(spacing: 0) {
            PaneHeader(title: "Envois",
                       caption: "Un texte partagé par un lien, chiffré de bout en bout : la clé est dans le lien, jamais sur le serveur.",
                       busy: sends.busy, notice: sends.notice, error: sends.error) {
                Button("Nouvel envoi", systemImage: "plus") { model.newSend() }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .help("Créer un envoi de texte")
            }
            Divider()
            if sends.items.isEmpty {
                ContentUnavailableView {
                    Label(sends.loaded ? "Aucun envoi" : "Chargement…", systemImage: "paperplane")
                } description: {
                    Text("Créez un envoi ici, ou depuis un élément : clic droit → « Envoyer de façon sécurisée… ».")
                }
                .frame(maxHeight: .infinity)
            } else {
                List(sends.items, id: \.id, selection: $sends.selection) { send in
                    SendRow(send: send)
                        .tag(send.id)
                }
                .listStyle(.inset)
                .contextMenu(forSelectionType: String.self) { ids in
                    if let send = sends.items.first(where: { ids.contains($0.id) }) {
                        SendMenu(send: send)
                    }
                } primaryAction: { ids in
                    // Double clic : modifier l'envoi.
                    if let send = sends.items.first(where: { ids.contains($0.id) }), send.content == .text {
                        Task { await model.editSend(send) }
                    }
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .task { await model.reloadSends() }
    }
}

/// Actions d'un envoi, pour le menu contextuel de la liste.
private struct SendMenu: View {
    @Environment(AppModel.self) private var model
    let send: SendSummary

    var body: some View {
        Button("Copier le lien") { Task { await model.copySendLink(send) } }
        if send.content == .text {
            Button("Modifier…") { Task { await model.editSend(send) } }
        }
        if send.hasPassword {
            Button("Retirer le mot de passe") { Task { await model.removeSendPassword(send) } }
        }
        Divider()
        Button("Supprimer…", role: .destructive) { model.sends.confirmDelete = send }
    }
}

/// Colonne de droite du volet « Envois » : l'envoi sélectionné.
struct SendDetailView: View {
    @Environment(AppModel.self) private var model
    let send: SendSummary

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                HStack(spacing: 10) {
                    Button("Copier le lien", systemImage: "link") { Task { await model.copySendLink(send) } }
                        .buttonStyle(.borderedProminent)
                    if send.content == .text {
                        Button("Modifier…", systemImage: "pencil") { Task { await model.editSend(send) } }
                    }
                    if send.hasPassword {
                        Button("Retirer le mot de passe", systemImage: "lock.open") {
                            Task { await model.removeSendPassword(send) }
                        }
                    }
                    Spacer()
                    Button("Supprimer…", systemImage: "trash", role: .destructive) {
                        model.sends.confirmDelete = send
                    }
                }
                .disabled(model.sends.busy)

                SectionTitle("Accès")
                FieldCard {
                    line("Ouvertures", send.maxAccessCount.map { "\(send.accessCount) sur \($0) au plus" }
                        ?? "\(send.accessCount)")
                    if let expiry = send.expirationDate {
                        Divider().padding(.leading, 14)
                        line(date(expiry) < Date() ? "Expiré" : "Expiration", formatted(expiry))
                    }
                    Divider().padding(.leading, 14)
                    line("Suppression", formatted(send.deletionDate))
                    if let file = send.fileName {
                        Divider().padding(.leading, 14)
                        line("Fichier", file)
                    }
                }
                Text("Modifié \(date(send.revisionDate).formatted(.relative(presentation: .named))).")
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
            Image(systemName: send.content == .file ? "doc" : "text.alignleft")
                .font(.system(size: 28))
                .foregroundStyle(send.available ? Theme.accent : .secondary)
                .frame(width: 64, height: 64)
                .background(Theme.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 5) {
                Text(send.name)
                    .font(.system(size: 24, weight: .bold))
                    .textSelection(.enabled)
                HStack(spacing: 8) {
                    Chip(text: send.content == .file ? "Fichier" : "Texte", symbol: "paperplane", tint: Theme.accent)
                    if !send.available {
                        Chip(text: send.disabled ? "Désactivé" : "Lien inactif", symbol: "exclamationmark.circle",
                             tint: .orange)
                            .help("Le lien ne mène plus au contenu : désactivé, expiré ou nombre d'accès atteint")
                    }
                    if send.hasPassword {
                        Chip(text: "Mot de passe", symbol: "key.fill", tint: .secondary)
                    }
                    if send.hideEmail {
                        Chip(text: "E-mail masqué", symbol: "eye.slash", tint: .secondary)
                    }
                }
            }
            Spacer()
        }
        .padding(.bottom, 4)
    }

    private func line(_ label: String, _ value: String) -> some View {
        LabeledContent(label) {
            Text(value).monospacedDigit().textSelection(.enabled)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private func formatted(_ timestamp: Int64) -> String {
        let value = date(timestamp)
        return "\(value.formatted(date: .abbreviated, time: .shortened)) · \(value.formatted(.relative(presentation: .named)))"
    }

    private func date(_ timestamp: Int64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(timestamp))
    }
}

/// Feuilles et confirmations des envois, posées sur la fenêtre principale :
/// « Envoyer de façon sécurisée… » les ouvre aussi depuis la liste des éléments.
struct SendsPresentations: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var sends = model.sends
        content
            .sheet(item: $sends.composer) { composer in
                SendEditorView(composer: composer)
                    .environment(model)
            }
            .confirmationDialog("Supprimer « \(sends.confirmDelete?.name ?? "") » ?",
                                isPresented: Binding(get: { sends.confirmDelete != nil },
                                                     set: { if !$0 { sends.confirmDelete = nil } }),
                                presenting: sends.confirmDelete) { send in
                Button("Supprimer", role: .destructive) { Task { await model.deleteSend(send) } }
            } message: { _ in
                Text("Le lien ne mènera plus à rien. Cette suppression est définitive.")
            }
    }
}

struct SendRow: View {
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
                        Text("Pour retirer le mot de passe : « Retirer le mot de passe » sur la fiche de l'envoi.")
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
