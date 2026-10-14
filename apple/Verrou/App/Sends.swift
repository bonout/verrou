import AppKit
import Observation
import SwiftUI

/// Envois (Bitwarden Send) : la liste du volet « Envois » de la fenêtre
/// principale, l'envoi sélectionné et l'écran de création ou de modification.
/// Le texte et le lien (qui porte la clé) ne viennent de Rust qu'à la
/// demande : copie du lien, ouverture de l'écran. Un fichier n'est lu qu'à
/// la création, puis chiffré dans Rust ; une pièce jointe ne passe même pas
/// par Swift.
@MainActor
@Observable
final class SendsModel {
    private(set) var items: [SendSummary] = []
    private(set) var loaded = false
    var busy = false
    var error: String?
    /// Écran de création ou de modification ouvert.
    var composer: Composer?
    /// Dernier envoi créé ou lien copié, pour le signaler dans le volet.
    var notice: String?
    /// Envoi affiché dans la colonne de droite.
    var selection: String?
    /// Suppression à confirmer.
    var confirmDelete: SendSummary?
    /// Envoi d'un fichier en cours : ce qu'on montre à l'utilisateur.
    var activity: String?

    struct Composer: Identifiable {
        let id = UUID()
        /// `nil` : création.
        let sendID: String?
        let fields: SendFields
        let hasPassword: Bool
        /// Prérempli depuis un élément du coffre (titre de l'élément).
        let source: String?
        /// Envoi de fichier : le fichier à envoyer (création) ou celui de
        /// l'envoi (modification, il ne change pas).
        var file: SendFile?

        init(sendID: String?, fields: SendFields, hasPassword: Bool, source: String?, file: SendFile? = nil) {
            self.sendID = sendID
            self.fields = fields
            self.hasPassword = hasPassword
            self.source = source
            self.file = file
        }
    }

    /// Le fichier d'un envoi de fichier.
    struct SendFile {
        enum Origin {
            /// Choisi dans le Finder ou déposé : lu à la création.
            case local(URL)
            /// Pièce jointe d'un élément : déchiffrée puis chiffrée de nouveau dans Rust.
            case attachment(itemID: String, attachmentID: String)
            /// Fichier d'un envoi existant.
            case existing
        }

        let name: String
        /// En octets (taille chiffrée pour une pièce jointe ou un envoi existant).
        let size: Int64?
        let origin: Origin
    }

    var selected: SendSummary? {
        selection.flatMap { id in items.first { $0.id == id } }
    }

    func set(_ items: [SendSummary]) {
        self.items = items
        loaded = true
        if selection.map({ id in !items.contains { $0.id == id } }) ?? true {
            selection = items.first?.id
        }
    }

    /// Au verrouillage : rien ne doit survivre, brouillon compris.
    func clear() {
        items = []
        loaded = false
        busy = false
        error = nil
        composer = nil
        notice = nil
        selection = nil
        confirmDelete = nil
        activity = nil
    }
}

extension AppModel {
    var sendsAvailable: Bool { mode == .vaultwarden && lockState == .unlocked }

    func reloadSends() async {
        guard sendsAvailable else { return }
        do {
            sends.set(try await session.sends())
            sends.error = nil
        } catch {
            sends.error = Self.describe(error)
        }
    }

    /// Barre latérale ou menu Coffre : le volet des envois dans la fenêtre principale.
    func openSends() {
        guard sendsAvailable else { return }
        showMainWindow()
        pane = .sends
    }

    func newSend() {
        guard sendsAvailable else { return }
        pane = .sends
        sends.notice = nil
        sends.composer = .init(sendID: nil, fields: session.newSendFields(), hasPassword: false, source: nil)
    }

    /// « Nouvel envoi » → « Fichier… » : choix dans le Finder.
    func newFileSend() {
        guard sendsAvailable else { return }
        pane = .sends
        let panel = NSOpenPanel()
        panel.title = "Nouvel envoi de fichier"
        panel.message = "Le fichier est chiffré avant d'être envoyé ; seul le lien permet de l'ouvrir (100 Mo au plus)."
        panel.prompt = "Choisir"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        composeFileSend(url)
    }

    /// Un fichier choisi ou déposé sur la liste des envois : l'écran de
    /// création, prérempli à son nom. Le fichier n'est lu qu'à la création.
    func composeFileSend(_ url: URL) {
        guard sendsAvailable else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        let problem: AttachmentFileError? = if values?.isRegularFile != true {
            .notAFile
        } else if let size = values?.fileSize, Int64(size) > Int64(session.maxSendFileSize()) {
            .tooLarge
        } else {
            nil
        }
        if let problem {
            sends.error = problem.message
            return
        }
        var fields = session.newSendFields()
        fields.name = url.lastPathComponent
        sends.notice = nil
        sends.error = nil
        sends.composer = .init(sendID: nil, fields: fields, hasPassword: false, source: nil,
                               file: .init(name: url.lastPathComponent, size: values?.fileSize.map(Int64.init),
                                           origin: .local(url)))
        openSends()
    }

    /// « Envoyer de façon sécurisée… » sur une pièce jointe : un envoi de
    /// fichier prérempli, à confirmer dans le volet des envois.
    func composeSend(fromAttachment entry: AttachmentEntry, of itemID: String) {
        guard sendsAvailable else { return }
        if awaitsConfirmation(itemID, retry: { [weak self] in
            self?.composeSend(fromAttachment: entry, of: itemID)
        }) { return }
        Task {
            do {
                let prefilled = try await session.sendFieldsForAttachment(itemId: itemID, attachmentId: entry.id)
                sends.notice = nil
                sends.error = nil
                sends.composer = .init(sendID: nil, fields: prefilled.fields, hasPassword: false,
                                       source: summaries.first { $0.id == itemID }?.title ?? prefilled.fileName,
                                       file: .init(name: prefilled.fileName, size: Int64(prefilled.size),
                                                   origin: .attachment(itemID: itemID, attachmentID: entry.id)))
                openSends()
            } catch {
                toast = Toast(message: "Envoi impossible", detail: Self.describe(error), failure: true)
            }
        }
    }

    func editSend(_ send: SendSummary) async {
        do {
            let fields = try await session.sendFields(id: send.id)
            let file = send.content == .file
                ? SendsModel.SendFile(name: send.fileName ?? "", size: send.fileSize.map(Int64.init), origin: .existing)
                : nil
            sends.composer = .init(sendID: send.id, fields: fields, hasPassword: send.hasPassword, source: nil,
                                   file: file)
        } catch {
            sends.error = Self.describe(error)
        }
    }

    /// « Envoyer de façon sécurisée… » depuis un élément : un envoi prérempli
    /// avec son mot de passe (ou ses notes), à confirmer dans le volet des envois.
    func composeSend(from summary: ItemSummary) {
        if awaitsConfirmation(summary.id, retry: { [weak self] in
            self?.composeSend(from: summary)
        }) { return }
        let field = summary.category == .login ? "password" : "notes"
        do {
            let fields = try session.sendFieldsForField(itemId: summary.id, fieldId: field)
            sends.notice = nil
            sends.composer = .init(sendID: nil, fields: fields, hasPassword: false, source: summary.title)
            openSends()
        } catch {
            toast = Toast(message: "Envoi impossible", detail: Self.describe(error), failure: true)
        }
    }

    /// Crée ou modifie l'envoi ; à la création, le lien est copié. Un
    /// fichier est lu ici, puis chiffré et envoyé par Rust.
    func saveSend(_ fields: SendFields, id: String?, file: SendsModel.SendFile? = nil) async {
        guard !sends.busy else { return }
        sends.busy = true
        defer {
            sends.busy = false
            sends.activity = nil
        }
        do {
            if let id {
                try await session.updateSend(id: id, fields: fields)
                sends.notice = "Envoi « \(fields.name) » enregistré."
            } else {
                let created: CreatedSend
                switch file?.origin {
                case .local(let url):
                    sends.activity = "Chiffrement et envoi de « \(url.lastPathComponent) »…"
                    let data = try Self.readFile(url, limit: Int64(session.maxSendFileSize()))
                    created = try await session.createFileSend(fields: fields, fileName: url.lastPathComponent,
                                                               data: data)
                case .attachment(let itemID, let attachmentID):
                    sends.activity = "Chiffrement et envoi de « \(file?.name ?? "") »…"
                    created = try await session.createSendFromAttachment(fields: fields, itemId: itemID,
                                                                         attachmentId: attachmentID)
                case .existing, nil:
                    created = try await session.createSend(fields: fields)
                }
                guard lockState == .unlocked else { return }
                copy(created.link, label: "Lien de l'envoi", secret: true)
                sends.selection = created.id
                sends.notice = "Envoi « \(fields.name) » créé : lien copié (effacé du presse-papiers dans 90 s)."
            }
            sends.composer = nil
            sends.error = nil
            afterWrite(select: selection)
            await reloadSends()
        } catch {
            sends.error = Self.describeFile(error)
        }
    }

    func copySendLink(_ send: SendSummary) async {
        do {
            let link = try await session.sendLink(id: send.id)
            copy(link, label: "Lien de l'envoi", secret: true)
            sends.notice = "Lien de « \(send.name) » copié (effacé du presse-papiers dans 90 s)."
        } catch {
            sends.error = Self.describe(error)
        }
    }

    func deleteSend(_ send: SendSummary) async {
        await sendAction("Envoi « \(send.name) » supprimé.") { try await self.session.deleteSend(id: send.id) }
    }

    func removeSendPassword(_ send: SendSummary) async {
        await sendAction("Mot de passe retiré de « \(send.name) ».") {
            try await self.session.removeSendPassword(id: send.id)
        }
    }

    private func sendAction(_ done: String, _ action: @escaping () async throws -> Void) async {
        guard !sends.busy else { return }
        sends.busy = true
        defer { sends.busy = false }
        do {
            try await action()
            sends.notice = done
            sends.error = nil
            afterWrite(select: selection)
            await reloadSends()
        } catch {
            sends.error = Self.describe(error)
        }
    }
}
