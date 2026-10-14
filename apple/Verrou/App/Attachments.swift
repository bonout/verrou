import AppKit
import Observation
import SwiftUI
import UniformTypeIdentifiers

/// Pièces jointes de l'élément affiché, et ce qui est en cours : envoi,
/// téléchargement, aperçu.
///
/// Rien n'est gardé hors ligne : un fichier se télécharge (et se déchiffre,
/// dans Rust) à chaque ouverture. Pour Quick Look, il passe par un fichier
/// temporaire du conteneur de l'app, effacé dès la fermeture de l'aperçu, au
/// changement d'élément, au verrouillage et au lancement suivant.
@MainActor
@Observable
final class AttachmentsModel {
    /// Taille maximale d'un fichier (comme le cœur Rust).
    static let maxSize: Int64 = 100 * 1024 * 1024

    private(set) var itemID: String?
    private(set) var entries: [AttachmentEntry] = []
    /// Envoi ou téléchargement en cours : ce qu'on montre à l'utilisateur.
    var activity: String?
    /// Fichier déchiffré montré par Quick Look ; effacé à la fermeture.
    var preview: URL? {
        didSet { if let oldValue, oldValue != preview { Self.discard(oldValue) } }
    }

    func show(_ entries: [AttachmentEntry], for itemID: String) {
        if self.itemID != itemID { preview = nil }
        self.itemID = itemID
        self.entries = entries
    }

    func clear() {
        preview = nil
        itemID = nil
        entries = []
        activity = nil
        Self.purge()
    }

    // MARK: Fichiers temporaires

    private static var directory: URL {
        FileManager.default.temporaryDirectory.appending(path: "pieces-jointes", directoryHint: .isDirectory)
    }

    /// Écrit le fichier déchiffré pour Quick Look, lisible par l'utilisateur
    /// seul, sous son vrai nom (Quick Look s'en sert pour le reconnaître).
    static func temporaryFile(named name: String, data: Data) throws -> URL {
        let folder = directory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let url = folder.appending(path: safeName(name))
        guard FileManager.default.createFile(atPath: url.path, contents: data,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        return url
    }

    private static func discard(_ url: URL) {
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }

    /// Efface tous les fichiers temporaires (verrouillage, lancement, fin).
    static func purge() {
        try? FileManager.default.removeItem(at: directory)
    }

    /// Un nom de fichier sans chemin.
    static func safeName(_ name: String) -> String {
        let cleaned = name.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty || cleaned.hasPrefix(".") ? "fichier\(cleaned)" : cleaned
    }
}

extension AppModel {
    // MARK: Pièces jointes

    /// Recharge la liste de l'élément affiché (depuis le cache, sans réseau).
    func loadAttachments(of itemID: String) async {
        let entries = (try? await session.attachments(itemId: itemID)) ?? []
        guard selection == itemID else { return }
        attachments.show(entries, for: itemID)
    }

    /// Peut-on ajouter ou retirer un fichier à cet élément ?
    func canEditAttachments(of summary: ItemSummary) -> Bool {
        canEdit && summary.state == .active && attachments.activity == nil && !editorBusy
    }

    /// Ouvre la pièce jointe dans Quick Look (téléchargée et déchiffrée).
    func openAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.openAttachment(entry, of: itemID) }) { return }
        Task {
            guard let content = await download(entry, of: itemID) else { return }
            do {
                attachments.preview = try AttachmentsModel.temporaryFile(named: content.fileName, data: content.data)
            } catch {
                toast = Toast(message: "Ouverture impossible", detail: error.localizedDescription, failure: true)
            }
        }
    }

    /// Enregistre une copie déchiffrée, là où l'utilisateur le choisit.
    func saveAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.saveAttachment(entry, of: itemID) }) { return }
        let panel = NSSavePanel()
        panel.title = "Enregistrer la pièce jointe"
        panel.message = "La copie enregistrée ne sera pas chiffrée."
        panel.nameFieldStringValue = AttachmentsModel.safeName(entry.fileName)
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            guard let content = await download(entry, of: itemID) else { return }
            do {
                try content.data.write(to: url, options: .atomic)
                toast = Toast(message: "Pièce jointe enregistrée", detail: url.lastPathComponent)
            } catch {
                toast = Toast(message: "Enregistrement impossible", detail: error.localizedDescription, failure: true)
            }
        }
    }

    private func download(_ entry: AttachmentEntry, of itemID: String) async -> AttachmentContent? {
        guard attachments.activity == nil else { return nil }
        attachments.activity = "Téléchargement de « \(entry.fileName) »…"
        defer { attachments.activity = nil }
        do {
            let content = try await session.downloadAttachment(itemId: itemID, attachmentId: entry.id)
            // Verrouillé ou autre élément entre-temps : on n'ouvre rien.
            guard lockState == .unlocked, selection == itemID else { return nil }
            return content
        } catch {
            toast = Toast(message: "Pièce jointe illisible", detail: Self.describe(error), failure: true)
            return nil
        }
    }

    /// Supprime définitivement la pièce jointe (après confirmation dans la vue).
    func deleteAttachment(_ entry: AttachmentEntry, of itemID: String) async {
        guard canEdit, attachments.activity == nil else { return }
        attachments.activity = "Suppression de « \(entry.fileName) »…"
        defer { attachments.activity = nil }
        do {
            try await session.deleteAttachment(itemId: itemID, attachmentId: entry.id)
            afterWrite(select: itemID)
            await loadAttachments(of: itemID)
            toast = Toast(message: "Pièce jointe supprimée", detail: entry.fileName)
        } catch {
            toast = Toast(message: "Suppression impossible", detail: Self.describe(error), failure: true)
        }
    }

    /// « Ajouter un fichier… » : choix dans le Finder.
    func chooseAttachments(for itemID: String) {
        guard canEdit else { return }
        let panel = NSOpenPanel()
        panel.title = "Ajouter des pièces jointes"
        panel.message = "Les fichiers sont chiffrés avant d'être envoyés (100 Mo au plus chacun)."
        panel.prompt = "Ajouter"
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK else { return }
        let urls = panel.urls
        Task { await addAttachments(urls, to: itemID) }
    }

    /// Ajoute des fichiers (choisis ou déposés) à l'élément, un par un.
    func addAttachments(_ urls: [URL], to itemID: String) async {
        guard canEdit, attachments.activity == nil else { return }
        var added = 0
        for url in urls {
            attachments.activity = "Envoi de « \(url.lastPathComponent) »…"
            do {
                let data = try Self.readFile(url, limit: AttachmentsModel.maxSize)
                try await session.addAttachment(itemId: itemID, fileName: url.lastPathComponent, data: data)
                added += 1
            } catch {
                toast = Toast(message: "« \(url.lastPathComponent) » non ajouté", detail: Self.describeFile(error), failure: true)
                break
            }
        }
        attachments.activity = nil
        guard added > 0, lockState == .unlocked else { return }
        afterWrite(select: itemID)
        await loadAttachments(of: itemID)
        toast = Toast(message: added == 1 ? "Pièce jointe ajoutée" : "\(added) pièces jointes ajoutées",
                      detail: "Chiffrée avant l'envoi")
    }

    /// Fichier → Nouveau document… : une note sécurisée au nom du fichier,
    /// le fichier en pièce jointe.
    func newDocument() {
        guard canEdit, attachments.activity == nil else { return }
        showMainWindow()
        let panel = NSOpenPanel()
        panel.title = "Nouveau document"
        panel.message = "Le fichier est chiffré et rangé dans une note sécurisée à son nom (100 Mo au plus)."
        panel.prompt = "Créer"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var folderID: String?
        if case .folder(let name) = filter {
            folderID = folders.first { $0.name == name }?.id
        }
        Task {
            attachments.activity = "Envoi de « \(url.lastPathComponent) »…"
            defer { attachments.activity = nil }
            do {
                let data = try Self.readFile(url, limit: AttachmentsModel.maxSize)
                let id = try await session.createDocument(fileName: url.lastPathComponent, data: data, folderId: folderID)
                afterWrite(select: id)
                toast = Toast(message: "Document créé", detail: url.lastPathComponent)
            } catch {
                toast = Toast(message: "Document non créé", detail: Self.describeFile(error), failure: true)
            }
        }
    }

    /// Lit un fichier choisi par l'utilisateur (droit du sandbox accordé par
    /// le panneau ou le glisser-déposer), dans la limite de taille.
    static func readFile(_ url: URL, limit: Int64) throws -> Data {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true else { throw AttachmentFileError.notAFile }
        if let size = values.fileSize, Int64(size) > limit { throw AttachmentFileError.tooLarge }
        return try Data(contentsOf: url, options: .mappedIfSafe)
    }

    static func describeFile(_ error: Error) -> String {
        if let error = error as? AttachmentFileError { return error.message }
        if error is VerrouError { return describe(error) }
        return error.localizedDescription
    }
}

enum AttachmentFileError: Error {
    case notAFile
    case tooLarge

    var message: String {
        switch self {
        case .notAFile: "Seuls les fichiers peuvent être joints ou envoyés (pas les dossiers)."
        case .tooLarge: "Le fichier dépasse 100 Mo, la taille maximale d'une pièce jointe ou d'un envoi."
        }
    }
}
