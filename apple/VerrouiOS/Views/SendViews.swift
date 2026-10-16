import SwiftUI
import UniformTypeIdentifiers

/// Un envoi en cours de composition : texte, ou fichier choisi.
struct SendComposer: Identifiable {
    let id = UUID()
    var fields: SendFields
    /// Fichier à chiffrer et envoyer (`nil` : envoi de texte).
    var file: URL?
}

extension PhoneModel {
    /// Les envois du compte, d'après la dernière synchronisation.
    func reloadSends() async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        do {
            sharing.sends = try await session.sends()
        } catch {
            toast = Toast(message: "Envois illisibles", detail: ErrorText.describe(error), failure: true)
        }
    }

    func newSend(file: URL? = nil) {
        guard canEdit else { return }
        var fields = session.newSendFields()
        if let file { fields.name = file.lastPathComponent }
        sharing.error = nil
        sharing.sendComposer = SendComposer(fields: fields, file: file)
    }

    /// Crée l'envoi (chiffré dans le cœur Rust) ; le lien, qui porte la
    /// clé, va dans le presse-papiers (effacé après le délai réglé).
    func createSend(_ composer: SendComposer) async -> Bool {
        await sharingAction {
            let created: CreatedSend
            if let url = composer.file {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(UInt64.init) ?? 0
                guard size <= self.session.maxSendFileSize() else {
                    throw VerrouError.Invalid(message: "fichier trop gros pour un envoi (100 Mo au plus)")
                }
                let data = try Data(contentsOf: url)
                created = try await self.session.createFileSend(fields: composer.fields,
                                                                fileName: url.lastPathComponent, data: data)
            } else {
                created = try await self.session.createSend(fields: composer.fields)
            }
            self.copy(created.link, label: "Lien de l'envoi", secret: true)
            self.sharing.createdLink = created.link
            await self.reloadSends()
        }
    }

    func copySendLink(_ send: SendSummary) async {
        do {
            copy(try await session.sendLink(id: send.id), label: "Lien de l'envoi", secret: true)
        } catch {
            toast = Toast(message: "Lien indisponible", detail: ErrorText.describe(error), failure: true)
        }
    }

    func deleteSend(_ send: SendSummary) async {
        do {
            try await session.deleteSend(id: send.id)
            toast = Toast(message: "Envoi « \(send.name) » supprimé", detail: nil)
            await reloadSends()
        } catch {
            toast = Toast(message: "Suppression impossible", detail: ErrorText.describe(error), failure: true)
        }
    }
}

/// Les envois (Bitwarden Send) : un texte ou un fichier chiffré, ouvert par
/// un lien qui expire. Le serveur ne voit ni le contenu ni la clé.
struct SendsScreen: View {
    @Environment(PhoneModel.self) private var model
    @State private var importing = false
    @State private var deleting: SendSummary?

    var body: some View {
        List {
            if let sends = model.sharing.sends {
                if sends.isEmpty {
                    ContentUnavailableView("Aucun envoi", systemImage: "paperplane",
                                           description: Text("Partagez un texte ou un fichier par un lien chiffré qui expire."))
                        .listRowBackground(Color.clear)
                }
                Section {
                    ForEach(sends, id: \.id) { send in
                        SendRow(send: send)
                            .contextMenu {
                                Button("Copier le lien", systemImage: "link") { Task { await model.copySendLink(send) } }
                                Button("Supprimer", systemImage: "trash", role: .destructive) { deleting = send }
                            }
                            .swipeActions {
                                Button(role: .destructive) { deleting = send } label: {
                                    Label("Supprimer", systemImage: "trash")
                                }
                                Button { Task { await model.copySendLink(send) } } label: {
                                    Label("Lien", systemImage: "link")
                                }
                                .tint(.indigo)
                            }
                    }
                } footer: {
                    if !sends.isEmpty {
                        Text("Touchez longuement un envoi pour copier son lien. Le lien porte la clé : ne le donnez qu'à son destinataire.")
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity).listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Envois")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("Texte", systemImage: "text.alignleft") { model.newSend() }
                    Button("Fichier…", systemImage: "doc") { importing = true }
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Nouvel envoi")
                .disabled(!model.canEdit)
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result { model.newSend(file: url) }
        }
        .refreshable {
            await model.syncNow()
            await model.reloadSends()
        }
        .task { await model.reloadSends() }
        .confirmationDialog("Supprimer « \(deleting?.name ?? "") » ?",
                            isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
                            titleVisibility: .visible, presenting: deleting) { send in
            Button("Supprimer", role: .destructive) { Task { await model.deleteSend(send) } }
        } message: { _ in
            Text("Le lien ne fonctionnera plus.")
        }
    }
}

private struct SendRow: View {
    let send: SendSummary

    var body: some View {
        HStack(spacing: 12) {
            TintedSymbol(symbol: send.content == .file ? "doc.fill" : "text.alignleft",
                         tint: send.available ? .indigo : .gray)
            VStack(alignment: .leading, spacing: 2) {
                Text(send.name).lineLimit(1)
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if send.hasPassword { Image(systemName: "key.fill").foregroundStyle(.secondary) }
            if !send.available { Badge(text: "Inactif", tint: nil) }
        }
    }

    private var detail: String {
        var parts: [String] = []
        let deletion = Date(timeIntervalSince1970: TimeInterval(send.deletionDate))
        parts.append("supprimé \(deletion.formatted(.relative(presentation: .named)))")
        if let max = send.maxAccessCount {
            parts.append("\(send.accessCount)/\(max) accès")
        } else if send.accessCount > 0 {
            parts.append("\(send.accessCount) accès")
        }
        return parts.joined(separator: " · ")
    }
}

/// Composition d'un envoi : contenu, durée de vie, nombre d'accès, mot de
/// passe. À la création, le lien est copié et peut être partagé.
struct NewSendSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var composer: SendComposer
    @State private var days = 7
    @State private var limitAccess = false
    @State private var maxAccess = 1
    @State private var password = ""

    init(composer: SendComposer) {
        _composer = State(initialValue: composer)
    }

    var body: some View {
        NavigationStack {
            Form {
                if let link = model.sharing.createdLink {
                    Section {
                        Label("Envoi créé : lien copié", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                        ShareLink(item: link) { Label("Partager le lien", systemImage: "square.and.arrow.up") }
                    } footer: {
                        Text("Le lien porte la clé de l'envoi : ne le donnez qu'à son destinataire. Il est effacé du presse-papiers après le délai réglé.")
                    }
                } else {
                    Section {
                        TextField("Nom", text: $composer.fields.name, prompt: Text("Code du portail"))
                        if let file = composer.file {
                            LabeledContent("Fichier", value: file.lastPathComponent)
                        } else {
                            TextField("Texte", text: $composer.fields.text, axis: .vertical)
                                .lineLimit(3...8)
                                .accessibilityIdentifier("send-text")
                            Toggle("Masquer le texte à l'ouverture", isOn: $composer.fields.hidden)
                        }
                    }
                    Section {
                        Picker("Supprimé après", selection: $days) {
                            Text("1 jour").tag(1)
                            Text("2 jours").tag(2)
                            Text("3 jours").tag(3)
                            Text("7 jours").tag(7)
                            Text("14 jours").tag(14)
                            Text("30 jours").tag(30)
                        }
                        Toggle("Limiter le nombre d'accès", isOn: $limitAccess)
                        if limitAccess {
                            Stepper("\(maxAccess) accès au plus", value: $maxAccess, in: 1...100)
                        }
                        SecureField("Mot de passe (facultatif)", text: $password)
                        Toggle("Cacher mon adresse", isOn: $composer.fields.hideEmail)
                    } header: {
                        SectionHeader("Accès")
                    } footer: {
                        Text("Chiffré sur cet iPhone avant l'envoi : le serveur ne voit ni le contenu ni la clé.")
                    }
                }
                if let error = model.sharing.error {
                    Section { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red) }
                }
            }
            .navigationTitle(composer.file == nil ? "Envoi de texte" : "Envoi de fichier")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if model.sharing.createdLink != nil {
                    ToolbarItem(placement: .confirmationAction) { Button("OK") { dismiss() } }
                } else {
                    ToolbarItem(placement: .cancellationAction) { Button("Annuler") { dismiss() } }
                    ToolbarItem(placement: .confirmationAction) {
                        if model.sharing.busy {
                            ProgressView()
                        } else {
                            Button("Créer") { create() }
                                .fontWeight(.semibold)
                                .disabled(composer.fields.name.trimmingCharacters(in: .whitespaces).isEmpty
                                          || (composer.file == nil && composer.fields.text.isEmpty))
                        }
                    }
                }
            }
        }
        .onDisappear { model.sharing.createdLink = nil }
    }

    private func create() {
        var ready = composer
        ready.fields.deletionDate = Int64(Date().addingTimeInterval(TimeInterval(days) * 86_400).timeIntervalSince1970)
        ready.fields.maxAccessCount = limitAccess ? UInt32(maxAccess) : nil
        ready.fields.password = password.isEmpty ? nil : password
        Task { _ = await model.createSend(ready) }
    }
}
