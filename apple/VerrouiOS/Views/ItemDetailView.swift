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
    @Environment(\.dynamicTypeSize) private var typeSize

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
                // Très grand texte : les lignes des champs suffisent (elles copient aussi).
                if summary.state == .active, !typeSize.isAccessibilitySize,
                   summary.category == .login || summary.hasTotp {
                    QuickCopyBar(summary: summary, fields: fields)
                        .padding(.top, 4)
                }
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: 4, leading: 4, bottom: 8, trailing: 4))
            .listRowSeparator(.hidden)

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
                Section {
                    ForEach(Array(detail.urls.enumerated()), id: \.offset) { index, url in
                        WebsiteRow(url: url, primary: index == 0)
                    }
                } header: {
                    SectionHeader("Sites")
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
                    SectionHeader("Passkeys")
                } footer: {
                    Text("Utilisables dans Brave et Firefox avec Verrou sur le Mac, et par les apps Bitwarden.")
                }
            }

            if detail.hasNotes {
                Section { NotesRow(itemID: itemID) } header: { SectionHeader("Notes") }
            }

            if !history.isEmpty {
                Section {
                    ForEach(history, id: \.id) { field in
                        FieldRow(itemID: itemID, field: field)
                    }
                } header: {
                    SectionHeader("Anciens mots de passe")
                }
            }

            attachmentsSection(summary)

            if !summary.tags.isEmpty {
                Section {
                    TagsRow(tags: summary.tags)
                        .padding(.vertical, 2)
                } header: {
                    SectionHeader("Étiquettes")
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
                            TintedSymbol(symbol: "doc.fill", tint: Theme.accent, size: 32)
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
                SectionHeader("Pièces jointes")
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

/// Icône, titre et pastilles (type, dossier, partage, protection), étoile
/// des favoris : l'en-tête de la fiche du Mac.
private struct DetailHeader: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dynamicTypeSize) private var typeSize
    let summary: ItemSummary

    var body: some View {
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 12))
            : AnyLayout(HStackLayout(alignment: .center, spacing: 16))
        layout {
            ItemIcon(summary: summary, size: 68)
            VStack(alignment: .leading, spacing: 6) {
                Text(summary.title)
                    .font(.title2.weight(.bold))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                // Les pastilles passent à la ligne, sans jamais couper leur texte.
                FlowLayout(spacing: 6, lineSpacing: 6) {
                    ForEach(chips, id: \.text) { chip in
                        Chip(text: chip.text, symbol: chip.symbol, tint: chip.tint)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            FavoriteButton(summary: summary)
        }
        .padding(.vertical, 4)
    }

    private var chips: [(text: String, symbol: String, tint: Color)] {
        var chips: [(text: String, symbol: String, tint: Color)] = [(summary.kindLabel, summary.symbol, summary.tint)]
        if let folder = summary.folder { chips.append((folder, "folder", .secondary)) }
        if summary.pendingSync { chips.append(("En attente de synchronisation", "arrow.triangle.2.circlepath", .orange)) }
        if summary.reprompt { chips.append(("Protégé", "lock.shield", .orange)) }
        if let sharing = summary.sharing {
            chips.append((sharing.organization, "person.2.fill", .indigo))
            if sharing.readOnly { chips.append(("Lecture seule", "eye", .secondary)) }
            if sharing.hidePasswords { chips.append(("Mot de passe masqué", "eye.slash", .secondary)) }
        }
        return chips
    }
}

/// L'étoile des favoris, qui rebondit quand on la touche.
private struct FavoriteButton: View {
    @Environment(PhoneModel.self) private var model
    let summary: ItemSummary

    var body: some View {
        Button {
            Task { await model.setFavorite(summary.id, !summary.favorite) }
        } label: {
            Image(systemName: summary.favorite ? "star.fill" : "star")
                .font(.title2)
                .foregroundStyle(summary.favorite ? Color.yellow : Color.secondary)
                .symbolReplaceTransition()
                .bounceOnChange(of: summary.favorite)
                .animation(.snappy, value: summary.favorite)
                .frame(width: 44, height: 44)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .disabled(!model.canModify(summary) || summary.state != .active || model.editorBusy)
        .accessibilityLabel(summary.favorite ? "Retirer des favoris" : "Ajouter aux favoris")
    }
}

/// Copie en un geste : identifiant, mot de passe, code. Boutons de verre
/// fondus ensemble sur iOS 26, en capsules teintées avant.
private struct QuickCopyBar: View {
    @Environment(PhoneModel.self) private var model
    let summary: ItemSummary
    let fields: [FieldView]
    /// Le bouton qui vient de copier : sa coche s'affiche 1,5 s.
    @State private var copied: String?
    @State private var copyToken = 0

    var body: some View {
        GlassGroup(spacing: 10) {
            HStack(spacing: 10) {
                if summary.category == .login, fields.contains(where: { $0.fieldType == .username || $0.id == "username" }) {
                    action("Identifiant", symbol: "person.fill") { model.copyUsername(of: summary.id) }
                }
                if summary.category == .login, fields.contains(where: { $0.id == "password" }) {
                    action("Mot de passe", symbol: "key.fill") { model.copyPassword(of: summary.id) }
                }
                if summary.hasTotp {
                    action("Code", symbol: "clock.fill") { model.copyCode(of: summary.id) }
                }
            }
        }
    }

    private func action(_ title: String, symbol: String, perform: @escaping () -> Void) -> some View {
        Button {
            let before = model.copies
            perform()
            guard model.copies != before else { return }
            copied = title
            // Échéance plutôt que tâche de la vue (voir CopiedFlag).
            copyToken += 1
            let mine = copyToken
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                if copyToken == mine { copied = nil }
            }
        } label: {
            Label {
                Text(title)
            } icon: {
                CopySymbol(symbol: symbol, copied: copied == title)
            }
            .labelStyle(StackedLabelStyle())
            .frame(maxWidth: .infinity)
        }
        .glassButton()
        .accessibilityLabel("Copier : \(title.lowercased())")
        .accessibilityIdentifier("quick-copy-\(title)")
    }
}

/// Symbole au-dessus du texte, dans les boutons de copie rapide.
private struct StackedLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        VStack(spacing: 4) {
            configuration.icon
                .font(.system(size: 17, weight: .semibold))
                .frame(height: 22)
            configuration.title
                .font(.caption.weight(.semibold))
                .lineLimit(2)
                .minimumScaleFactor(0.8)
                .multilineTextAlignment(.center)
        }
        .padding(.vertical, 4)
    }
}

/// Une ligne de champ : un appui copie (le bouton passe à la coche), l'œil révèle.
struct FieldRow: View {
    @Environment(PhoneModel.self) private var model
    let itemID: String
    let field: FieldView
    @State private var copied = false

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                Text(field.label)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(field.fieldType == .password || field.fieldType == .totp ? Theme.accent : Color.secondary)
                FieldValue(itemID: itemID, field: field)
            }
            Spacer(minLength: 8)
            if field.secret && field.fieldType != .totp && !field.hidden {
                let shown = model.revealedValue(field.id, of: itemID) != nil
                RowIconButton(symbol: shown ? "eye.slash" : "eye", label: shown ? "Masquer" : "Afficher") {
                    model.toggleReveal(field.id, of: itemID)
                }
                .animation(.snappy(duration: 0.25), value: shown)
            }
            if !field.hidden {
                RowIconButton(symbol: copied ? "checkmark" : "doc.on.doc", label: "Copier",
                              tint: copied ? .green : Theme.accent, action: copy)
                    .animation(.snappy(duration: 0.3), value: copied)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture(perform: copy)
        .accessibilityElement(children: .combine)
        .accessibilityHint("Touchez deux fois pour copier")
        .accessibilityAction(named: "Copier", copy)
        .contextMenu {
            Button("Copier", systemImage: "doc.on.doc", action: copy)
            if field.secret && field.fieldType != .totp && !field.hidden {
                Button(model.revealedValue(field.id, of: itemID) == nil ? "Afficher" : "Masquer", systemImage: "eye") {
                    model.toggleReveal(field.id, of: itemID)
                }
            }
        }
        .modifier(CopiedFlag(copied: $copied))
    }

    private func copy() {
        let before = model.copies
        model.copyField(field, of: itemID)
        // La coche seulement si la copie a eu lieu (pas d'attente de Face ID) ;
        // le retour haptique de réussite suit chaque copie (RootView).
        if model.copies != before {
            copied = true
        }
    }
}

/// Petit bouton rond d'une ligne (afficher, copier) : un fond discret, pas
/// de verre dans une liste.
private struct RowIconButton: View {
    let symbol: String
    let label: String
    var tint: Color = Theme.accent
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(tint)
                .symbolReplaceTransition()
                .frame(width: 36, height: 36)
                .background(tint.opacity(0.12), in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(.borderless)
        .accessibilityLabel(label)
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
            TotpFieldValue(itemID: itemID)
        case .password, .concealed, .pin, .cardNumber:
            if field.hidden {
                Text("Masqué par l'organisation").foregroundStyle(.secondary)
            } else {
                // Révélé : brouillé puis déchiffré caractère par caractère.
                DecryptReveal(value: model.revealedValue(field.id, of: itemID), fontSize: 17) { revealed in
                    if field.fieldType == .password || field.fieldType == .pin {
                        // Copié d'un toucher sur la ligne : pas de sélection.
                        PasswordText(value: revealed, size: 17, selectable: false)
                    } else {
                        Text(revealed).font(.system(size: 17, design: .monospaced))
                    }
                } masked: {
                    if field.fieldType == .cardNumber {
                        Text("•••• •••• •••• ••••").font(.system(size: 17, design: .monospaced)).foregroundStyle(.secondary)
                    } else {
                        MaskedText(count: field.fieldType == .pin ? 4 : 12)
                    }
                }
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

/// Le code à usage unique de la fiche : ses chiffres roulent, et un léger
/// retour haptique marque chaque nouveau code, seulement quand la fiche est
/// à l'écran et l'app au premier plan.
private struct TotpFieldValue: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    let itemID: String
    @State private var onScreen = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = model.totpCode(of: itemID, at: context.date)
            Group {
                if let code {
                    TotpCodeView(code: code, size: 28)
                } else {
                    // Élément protégé : le code n'apparaît qu'après confirmation.
                    MaskedText(count: 6)
                }
            }
            .sensoryFeedback(.impact(weight: .light), trigger: code?.code) { old, new in
                onScreen && scenePhase == .active && old != nil && new != nil && old != new
            }
        }
        .onAppear { onScreen = true }
        .onDisappear { onScreen = false }
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
                Text(primary ? "Site principal" : "Site").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                Text(url).foregroundStyle(Theme.accent).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            if let link = URL(string: url), link.scheme == "https" || link.scheme == "http" {
                RowIconButton(symbol: "safari", label: "Ouvrir dans Safari") { openURL(link) }
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
            TintedSymbol(symbol: "person.badge.key.fill", tint: Theme.accent, size: 32)
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
        let notes = model.revealedValue("notes", of: itemID)
        HStack(alignment: .top) {
            if let notes {
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
            RowIconButton(symbol: notes == nil ? "eye" : "eye.slash",
                          label: "Afficher la note") {
                model.toggleReveal("notes", of: itemID)
            }
        }
        .animation(.snappy(duration: 0.2), value: notes)
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
