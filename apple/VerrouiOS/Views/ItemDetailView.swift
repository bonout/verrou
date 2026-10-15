import SwiftUI

/// La fiche d'un élément : un appui copie un champ, l'œil révèle un secret
/// (après confirmation pour un élément protégé), les codes à usage unique
/// défilent avec leur compte à rebours.
struct ItemDetailView: View {
    @Environment(PhoneModel.self) private var model
    let itemID: String
    @State private var confirmTrash = false
    @State private var importingFile = false
    @State private var deletingAttachment: AttachmentEntry?
    @State private var deletingPasskey: PasskeyInfo?

    var body: some View {
        Group {
            if let detail = model.detail(id: itemID) {
                content(detail)
            } else {
                ContentUnavailableView("Élément introuvable", systemImage: "questionmark.folder",
                                       description: Text("Il a peut-être été supprimé ailleurs."))
            }
        }
        .task(id: itemID) { await model.loadAttachments(of: itemID) }
        .onDisappear { model.forgetRevealed(of: itemID) }
    }

    @ViewBuilder
    private func content(_ detail: ItemDetail) -> some View {
        let summary = detail.summary
        let fields = detail.fields.filter { !$0.id.hasPrefix("history-") }
        let history = detail.fields.filter { $0.id.hasPrefix("history-") }
        List {
            Section {
                DetailHeader(summary: summary)
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))

            stateBanner(summary)

            if !fields.isEmpty {
                Section {
                    ForEach(fields, id: \.id) { field in
                        FieldRow(itemID: itemID, field: field)
                    }
                    if summary.category == .sshKey, fields.contains(where: { $0.id == "public_key" }),
                       let key = fields.first(where: { $0.id == "public_key" }) {
                        Button("Copier la clé publique", systemImage: "doc.on.doc") {
                            model.copyField(key, of: itemID)
                        }
                    }
                }
            }

            if summary.template == .wifi {
                Section {
                    Button("Afficher le QR code", systemImage: "qrcode") { model.showWifiQRCode(of: itemID) }
                } footer: {
                    Text("Un autre téléphone le scanne avec l'appareil photo pour rejoindre le réseau.")
                }
            }

            if !detail.urls.isEmpty {
                Section("Sites") {
                    ForEach(Array(detail.urls.enumerated()), id: \.offset) { index, url in
                        WebsiteRow(url: url, primary: index == 0)
                    }
                }
            }

            let passkeys = model.passkeys(of: itemID)
            if !passkeys.isEmpty {
                Section {
                    ForEach(passkeys, id: \.credentialId) { passkey in
                        PasskeyRow(passkey: passkey)
                            .swipeActions {
                                if model.canModify(summary) {
                                    Button("Supprimer", systemImage: "trash", role: .destructive) {
                                        deletingPasskey = passkey
                                    }
                                }
                            }
                    }
                } header: {
                    Text("Passkeys")
                } footer: {
                    Text("Utilisables dans Brave et Firefox avec Verrou sur le Mac, et par les apps Bitwarden.")
                }
            }

            if detail.hasNotes {
                Section("Notes") { NotesRow(itemID: itemID) }
            }

            if !history.isEmpty {
                Section("Anciens mots de passe") {
                    ForEach(history, id: \.id) { field in
                        FieldRow(itemID: itemID, field: field)
                    }
                }
            }

            attachmentsSection(summary)

            if !summary.tags.isEmpty {
                Section("Étiquettes") {
                    Text(summary.tags.map { "#\($0)" }.joined(separator: "  "))
                        .foregroundStyle(.secondary)
                }
            }

            Section {
            } footer: {
                metadata(detail)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(summary.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { toolbar(summary) }
        .fileImporter(isPresented: $importingFile, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result {
                Task { await model.addAttachment(from: url, to: itemID) }
            }
        }
        .confirmationDialog("Mettre « \(summary.title) » à la corbeille ?", isPresented: $confirmTrash,
                            titleVisibility: .visible) {
            Button("Mettre à la corbeille", role: .destructive) { Task { await model.trash(itemID) } }
        } message: {
            Text("L'élément reste restaurable depuis la corbeille pendant 30 jours.")
        }
        .confirmationDialog("Supprimer « \(deletingAttachment?.fileName ?? "") » ?",
                            isPresented: Binding(get: { deletingAttachment != nil }, set: { if !$0 { deletingAttachment = nil } }),
                            titleVisibility: .visible) {
            Button("Supprimer la pièce jointe", role: .destructive) {
                if let entry = deletingAttachment { Task { await model.deleteAttachment(entry, of: itemID) } }
                deletingAttachment = nil
            }
        } message: {
            Text("Le fichier est supprimé du serveur. Cette action est définitive.")
        }
        .confirmationDialog("Supprimer cette passkey ?",
                            isPresented: Binding(get: { deletingPasskey != nil }, set: { if !$0 { deletingPasskey = nil } }),
                            titleVisibility: .visible) {
            Button("Supprimer la passkey", role: .destructive) {
                if let passkey = deletingPasskey {
                    Task { await model.deletePasskey(itemID: itemID, credentialID: passkey.credentialId) }
                }
                deletingPasskey = nil
            }
        } message: {
            Text("Le site ne vous reconnaîtra plus avec elle.")
        }
    }

    @ToolbarContentBuilder
    private func toolbar(_ summary: ItemSummary) -> some ToolbarContent {
        ToolbarItemGroup(placement: .topBarTrailing) {
            if model.canModify(summary), summary.state == .active {
                Button("Modifier") { Task { await model.edit(itemID) } }
                    .disabled(model.editorBusy)
            }
            Menu {
                if summary.category == .login {
                    Button("Copier l'identifiant", systemImage: "person") { model.copyUsername(of: itemID) }
                    Button("Copier le mot de passe", systemImage: "key") { model.copyPassword(of: itemID) }
                }
                if summary.hasTotp {
                    Button("Copier le code", systemImage: "clock") { model.copyCode(of: itemID) }
                }
                if model.canModify(summary) {
                    Divider()
                    switch summary.state {
                    case .active:
                        Button(summary.favorite ? "Retirer des favoris" : "Ajouter aux favoris",
                               systemImage: summary.favorite ? "star.slash" : "star") {
                            Task { await model.setFavorite(itemID, !summary.favorite) }
                        }
                        Button("Déplacer vers un dossier…", systemImage: "folder") {
                            model.moveRequest = PhoneModel.MoveRequest(itemIDs: [itemID])
                        }
                        Button("Ajouter une pièce jointe…", systemImage: "paperclip") { importingFile = true }
                        Button("Archiver", systemImage: "archivebox") { Task { await model.setArchived(itemID, true) } }
                        Button("Mettre à la corbeille", systemImage: "trash", role: .destructive) { confirmTrash = true }
                    case .archived:
                        Button("Sortir des archives", systemImage: "tray.and.arrow.up") {
                            Task { await model.setArchived(itemID, false) }
                        }
                        Button("Mettre à la corbeille", systemImage: "trash", role: .destructive) { confirmTrash = true }
                    case .trashed:
                        Button("Restaurer", systemImage: "arrow.uturn.backward") { Task { await model.restore(itemID) } }
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .accessibilityLabel("Actions")
        }
    }

    @ViewBuilder
    private func stateBanner(_ summary: ItemSummary) -> some View {
        switch summary.state {
        case .active:
            EmptyView()
        case .archived:
            banner("Archivé : hors de la liste, de la recherche et du remplissage.", symbol: "archivebox",
                   action: "Sortir des archives", summary: summary) { await model.setArchived(itemID, false) }
        case .trashed:
            banner("À la corbeille : supprimé définitivement par le serveur après 30 jours.", symbol: "trash",
                   action: "Restaurer", summary: summary) { await model.restore(itemID) }
        }
    }

    private func banner(_ text: String, symbol: String, action: String, summary: ItemSummary,
                        perform: @escaping () async -> Void) -> some View {
        Section {
            Label(text, systemImage: symbol)
                .font(.callout)
                .foregroundStyle(.secondary)
            if model.canModify(summary) {
                Button(action) { Task { await perform() } }
                    .disabled(model.editorBusy)
            }
        }
    }

    @ViewBuilder
    private func attachmentsSection(_ summary: ItemSummary) -> some View {
        let entries = model.attachments[itemID] ?? []
        if !entries.isEmpty || model.attachmentActivity != nil {
            Section {
                ForEach(entries, id: \.id) { entry in
                    Button {
                        model.openAttachment(entry, of: itemID)
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "doc.fill")
                                .foregroundStyle(Theme.accent)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.readable ? entry.fileName : "Fichier illisible")
                                    .foregroundStyle(.primary)
                                    .lineLimit(1)
                                Text(ByteCountFormatter.string(fromByteCount: Int64(entry.size), countStyle: .file))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                    }
                    .disabled(!entry.readable || model.attachmentActivity != nil)
                    .contextMenu {
                        Button("Aperçu", systemImage: "eye") { model.openAttachment(entry, of: itemID) }
                        Button("Partager…", systemImage: "square.and.arrow.up") { model.shareAttachment(entry, of: itemID) }
                        if model.canModify(summary) {
                            Button("Supprimer", systemImage: "trash", role: .destructive) { deletingAttachment = entry }
                        }
                    }
                    .swipeActions {
                        if model.canModify(summary) {
                            Button("Supprimer", systemImage: "trash", role: .destructive) { deletingAttachment = entry }
                        }
                        Button("Partager", systemImage: "square.and.arrow.up") { model.shareAttachment(entry, of: itemID) }
                            .tint(.blue)
                    }
                }
                if let activity = model.attachmentActivity {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text(activity).font(.callout).foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Pièces jointes")
            } footer: {
                Text("Téléchargées et déchiffrées à chaque ouverture : il faut le réseau.")
            }
        }
    }

    private func metadata(_ detail: ItemDetail) -> some View {
        let format = Date.FormatStyle(date: .long, time: .shortened).locale(Locale(identifier: "fr_FR"))
        return VStack(alignment: .leading, spacing: 3) {
            Text("Modifié le \(Date(timeIntervalSince1970: TimeInterval(detail.summary.modified)).formatted(format))")
            Text("Créé le \(Date(timeIntervalSince1970: TimeInterval(detail.created)).formatted(format))")
        }
        .font(.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Icône, titre et pastilles (type, dossier, partage, protection).
private struct DetailHeader: View {
    @Environment(PhoneModel.self) private var model
    let summary: ItemSummary

    var body: some View {
        VStack(spacing: 10) {
            ItemIcon(summary: summary, size: 64)
            Text(summary.title)
                .font(.title2.weight(.bold))
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
            FlowChips(chips: chips)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
    }

    private var chips: [Chip] {
        var chips = [Chip(text: summary.kindLabel, symbol: summary.symbol, tint: summary.tint)]
        if let folder = summary.folder { chips.append(Chip(text: folder, symbol: "folder", tint: .secondary)) }
        if summary.favorite { chips.append(Chip(text: "Favori", symbol: "star.fill", tint: .yellow)) }
        if summary.pendingSync {
            chips.append(Chip(text: "En attente de synchronisation", symbol: "arrow.triangle.2.circlepath", tint: .orange))
        }
        if summary.reprompt { chips.append(Chip(text: "Protégé", symbol: "lock.shield", tint: .orange)) }
        if let sharing = summary.sharing {
            chips.append(Chip(text: sharing.organization, symbol: "person.2.fill", tint: .indigo))
            if sharing.readOnly { chips.append(Chip(text: "Lecture seule", symbol: "eye", tint: .secondary)) }
            if sharing.hidePasswords { chips.append(Chip(text: "Mot de passe masqué", symbol: "eye.slash", tint: .secondary)) }
        }
        return chips
    }
}

private struct Chip: Hashable {
    let text: String
    let symbol: String
    let tint: Color
}

/// Pastilles centrées ; trop nombreuses pour la largeur, elles défilent.
private struct FlowChips: View {
    let chips: [Chip]

    var body: some View {
        ViewThatFits(in: .horizontal) {
            row
            ScrollView(.horizontal, showsIndicators: false) { row.padding(.horizontal, 4) }
        }
    }

    private var row: some View {
        HStack(spacing: 6) {
            ForEach(chips, id: \.self) { chip in
                Label(chip.text, systemImage: chip.symbol)
                    .labelStyle(.titleAndIcon)
                    .font(.caption.weight(.medium))
                    .lineLimit(1)
                    .fixedSize()
                    .foregroundStyle(chip.tint == .secondary ? Color.secondary : chip.tint)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 4)
                    .background((chip.tint == .secondary ? Color.secondary : chip.tint).opacity(0.14), in: Capsule())
            }
        }
    }
}

/// Une ligne de champ : un appui copie, l'œil révèle.
struct FieldRow: View {
    @Environment(PhoneModel.self) private var model
    let itemID: String
    let field: FieldView

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(field.label)
                    .font(.caption)
                    .foregroundStyle(field.fieldType == .password || field.fieldType == .totp ? Theme.accent : Color.secondary)
                FieldValue(itemID: itemID, field: field)
            }
            Spacer(minLength: 8)
            if field.secret && field.fieldType != .totp && !field.hidden {
                let shown = model.revealedValue(field.id, of: itemID) != nil
                Button {
                    withAnimation(.snappy(duration: 0.18)) { model.toggleReveal(field.id, of: itemID) }
                } label: {
                    Image(systemName: shown ? "eye.slash" : "eye")
                        .font(.body)
                        .frame(width: 34, height: 34)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(shown ? "Masquer" : "Afficher")
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { model.copyField(field, of: itemID) }
        .accessibilityElement(children: .combine)
        .accessibilityHint("Touchez deux fois pour copier")
        .accessibilityAction(named: "Copier") { model.copyField(field, of: itemID) }
        .contextMenu {
            Button("Copier", systemImage: "doc.on.doc") { model.copyField(field, of: itemID) }
            if field.secret && field.fieldType != .totp && !field.hidden {
                Button(model.revealedValue(field.id, of: itemID) == nil ? "Afficher" : "Masquer", systemImage: "eye") {
                    model.toggleReveal(field.id, of: itemID)
                }
            }
        }
    }
}

/// La valeur d'un champ (masquée, révélée, code à usage unique…).
private struct FieldValue: View {
    @Environment(PhoneModel.self) private var model
    let itemID: String
    let field: FieldView

    var body: some View {
        switch field.fieldType {
        case .totp:
            TimelineView(.periodic(from: .now, by: 1)) { context in
                if let code = model.totpCode(of: itemID, at: context.date) {
                    TotpCodeView(code: code, size: 24)
                } else {
                    // Élément protégé : le code n'apparaît qu'après confirmation.
                    MaskedText(count: 6)
                }
            }
        case .password, .concealed, .pin, .cardNumber:
            if field.hidden {
                Text("Masqué par l'organisation").foregroundStyle(.secondary)
            } else if let revealed = model.revealedValue(field.id, of: itemID) {
                if field.fieldType == .password || field.fieldType == .pin {
                    PasswordText(value: revealed, size: 17)
                } else {
                    Text(revealed).font(.system(size: 17, design: .monospaced))
                }
            } else if field.fieldType == .cardNumber {
                Text("•••• •••• •••• ••••").font(.system(size: 17, design: .monospaced)).foregroundStyle(.secondary)
            } else {
                MaskedText(count: field.fieldType == .pin ? 4 : 12)
            }
        case .address, .multiline:
            Text(field.value ?? "")
                .font(field.fieldType == .multiline ? .system(size: 13, design: .monospaced) : .body)
                .lineLimit(field.fieldType == .multiline ? 4 : nil)
        case .email, .phone, .url:
            Text(field.value ?? "").foregroundStyle(Theme.accent)
        default:
            Text(field.value ?? "")
        }
    }
}

private struct WebsiteRow: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.openURL) private var openURL
    let url: String
    let primary: Bool

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(primary ? "Site principal" : "Site").font(.caption).foregroundStyle(.secondary)
                Text(url).foregroundStyle(Theme.accent).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            if let link = URL(string: url), link.scheme == "https" || link.scheme == "http" {
                Button {
                    openURL(link)
                } label: {
                    Image(systemName: "safari")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Ouvrir dans Safari")
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { model.copy(url, label: "Site", secret: false) }
    }
}

private struct PasskeyRow: View {
    let passkey: PasskeyInfo

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.badge.key.fill")
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(passkey.rpName ?? passkey.rpId)
                Text([passkey.userName, created].compactMap { $0 }.joined(separator: " · "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var created: String {
        let format = Date.FormatStyle(date: .abbreviated, time: .omitted).locale(Locale(identifier: "fr_FR"))
        return "créée le \(Date(timeIntervalSince1970: TimeInterval(passkey.created)).formatted(format))"
    }
}

private struct NotesRow: View {
    @Environment(PhoneModel.self) private var model
    let itemID: String

    var body: some View {
        HStack(alignment: .top) {
            if let notes = model.revealedValue("notes", of: itemID) {
                Text(notes)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Contenu masqué").foregroundStyle(.secondary)
                    Text("Touchez l'œil pour afficher la note.").font(.caption).foregroundStyle(.tertiary)
                }
                Spacer()
            }
            Button {
                withAnimation(.snappy(duration: 0.18)) { model.toggleReveal("notes", of: itemID) }
            } label: {
                Image(systemName: model.revealedValue("notes", of: itemID) == nil ? "eye" : "eye.slash")
                    .frame(width: 34, height: 34)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Afficher la note")
        }
    }
}

/// QR code d'un réseau Wi-Fi, à scanner par un autre appareil.
struct WifiQRSheet: View {
    @Environment(\.dismiss) private var dismiss
    let sheet: PhoneModel.QRSheet

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(decorative: sheet.image, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 260)
                    .padding(16)
                    .background(.white, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                    .accessibilityLabel("QR code du réseau « \(sheet.title) »")
                Text("Scannez avec l'appareil photo d'un autre téléphone pour rejoindre « \(sheet.title) ».")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(.systemGroupedBackground))
            .navigationTitle(sheet.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("OK") { dismiss() } }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

/// « Déplacer vers un dossier » : un dossier existant, aucun, ou un nouveau.
struct MoveToFolderSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: PhoneModel.MoveRequest
    @State private var newFolder = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button("Aucun dossier", systemImage: "folder.badge.minus") { move(to: nil) }
                    ForEach(model.folders, id: \.id) { folder in
                        Button(folder.name, systemImage: "folder") { move(to: folder) }
                    }
                }
                Section("Nouveau dossier") {
                    TextField("Nom du dossier", text: $newFolder)
                    Button("Créer et déplacer") {
                        let name = newFolder
                        dismiss()
                        Task { await model.moveToNewFolder(name, ids: request.itemIDs) }
                    }
                    .disabled(newFolder.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .navigationTitle(request.itemIDs.count == 1 ? "Déplacer" : "Déplacer \(request.itemIDs.count) éléments")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Annuler") { dismiss() } }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func move(to folder: FolderOption?) {
        dismiss()
        Task { await model.performBulk(.moveToFolder(folderId: folder?.id), on: request.itemIDs, folderName: folder?.name) }
    }
}

/// Feuille de partage du système (Fichiers, AirDrop, autre app).
struct ShareSheet: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
