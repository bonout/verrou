import AppKit
import Observation
import SwiftUI
import UniformTypeIdentifiers

/// Attachments of the displayed item, and what is in progress: upload,
/// download, preview.
///
/// Nothing is kept offline: a file is downloaded (and decrypted, in Rust) on
/// each opening. For Quick Look, it goes through a temporary file in the
/// app's container, deleted as soon as the preview closes, when the item
/// changes, on lock and at the next launch.
@MainActor
@Observable
final class AttachmentsModel {
    /// Maximum size of a file (like the Rust core).
    static let maxSize: Int64 = 100 * 1024 * 1024

    private(set) var itemID: String?
    private(set) var entries: [AttachmentEntry] = []
    /// Upload or download in progress: what is shown to the user.
    var activity: String?
    /// Decrypted file shown by Quick Look; deleted when closed.
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

    // MARK: Temporary files

    private static var directory: URL {
        FileManager.default.temporaryDirectory.appending(path: "pieces-jointes", directoryHint: .isDirectory)
    }

    /// Writes the decrypted file for Quick Look, readable by the user only,
    /// under its real name (Quick Look uses it to recognize it).
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

    /// Deletes all the temporary files (lock, launch, quit).
    static func purge() {
        try? FileManager.default.removeItem(at: directory)
    }

    /// A file name without a path.
    static func safeName(_ name: String) -> String {
        let cleaned = name.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty || cleaned.hasPrefix(".") ? String(localized: "file") + cleaned : cleaned
    }
}

extension AppModel {
    // MARK: Attachments

    /// Reloads the list of the displayed item (from the cache, without network).
    func loadAttachments(of itemID: String) async {
        let entries = (try? await session.attachments(itemId: itemID)) ?? []
        guard selection == itemID else { return }
        attachments.show(entries, for: itemID)
    }

    /// Can a file be added to or removed from this item?
    func canEditAttachments(of summary: ItemSummary) -> Bool {
        canEdit && summary.state == .active && attachments.activity == nil && !editorBusy
    }

    /// Opens the attachment in Quick Look (downloaded and decrypted).
    func openAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.openAttachment(entry, of: itemID) }) { return }
        Task {
            guard let content = await download(entry, of: itemID) else { return }
            do {
                attachments.preview = try AttachmentsModel.temporaryFile(named: content.fileName, data: content.data)
            } catch {
                toast = Toast(message: String(localized: "Couldn't open"), detail: error.localizedDescription, failure: true)
            }
        }
    }

    /// Saves a decrypted copy, where the user chooses.
    func saveAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.saveAttachment(entry, of: itemID) }) { return }
        let panel = NSSavePanel()
        panel.title = String(localized: "Save Attachment")
        panel.message = String(localized: "The saved copy will not be encrypted.")
        panel.nameFieldStringValue = AttachmentsModel.safeName(entry.fileName)
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            guard let content = await download(entry, of: itemID) else { return }
            do {
                try content.data.write(to: url, options: .atomic)
                toast = Toast(message: String(localized: "Attachment saved"), detail: url.lastPathComponent)
            } catch {
                toast = Toast(message: String(localized: "Couldn't save"), detail: error.localizedDescription, failure: true)
            }
        }
    }

    private func download(_ entry: AttachmentEntry, of itemID: String) async -> AttachmentContent? {
        guard attachments.activity == nil else { return nil }
        attachments.activity = String(localized: "Downloading “\(entry.fileName)”…")
        defer { attachments.activity = nil }
        do {
            let content = try await session.downloadAttachment(itemId: itemID, attachmentId: entry.id)
            // Locked or another item in the meantime: open nothing.
            guard lockState == .unlocked, selection == itemID else { return nil }
            return content
        } catch {
            toast = Toast(message: String(localized: "Unreadable attachment"), detail: Self.describe(error), failure: true)
            return nil
        }
    }

    /// Permanently deletes the attachment (after confirmation in the view).
    func deleteAttachment(_ entry: AttachmentEntry, of itemID: String) async {
        guard canEdit, attachments.activity == nil else { return }
        attachments.activity = String(localized: "Deleting “\(entry.fileName)”…")
        defer { attachments.activity = nil }
        do {
            try await session.deleteAttachment(itemId: itemID, attachmentId: entry.id)
            afterWrite(select: itemID)
            await loadAttachments(of: itemID)
            toast = Toast(message: String(localized: "Attachment deleted"), detail: entry.fileName)
        } catch {
            toast = Toast(message: String(localized: "Couldn't delete"), detail: Self.describe(error), failure: true)
        }
    }

    /// "Add File…": choice in the Finder.
    func chooseAttachments(for itemID: String) {
        guard canEdit else { return }
        let panel = NSOpenPanel()
        panel.title = String(localized: "Add Attachments")
        panel.message = String(localized: "Files are encrypted before being uploaded (100 MB at most each).")
        panel.prompt = String(localized: "Add")
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK else { return }
        let urls = panel.urls
        Task { await addAttachments(urls, to: itemID) }
    }

    /// Adds files (chosen or dropped) to the item, one by one.
    func addAttachments(_ urls: [URL], to itemID: String) async {
        guard canEdit, attachments.activity == nil else { return }
        var added = 0
        for url in urls {
            attachments.activity = String(localized: "Uploading “\(url.lastPathComponent)”…")
            do {
                let data = try Self.readFile(url, limit: AttachmentsModel.maxSize)
                try await session.addAttachment(itemId: itemID, fileName: url.lastPathComponent, data: data)
                added += 1
            } catch {
                toast = Toast(message: String(localized: "“\(url.lastPathComponent)” not added"), detail: Self.describeFile(error), failure: true)
                break
            }
        }
        attachments.activity = nil
        guard added > 0, lockState == .unlocked else { return }
        afterWrite(select: itemID)
        await loadAttachments(of: itemID)
        toast = Toast(message: added == 1 ? String(localized: "Attachment added") : String(localized: "\(added) attachments added"),
                      detail: String(localized: "Encrypted before upload"))
    }

    /// File → New Document…: a secure note named after the file, with the
    /// file attached.
    func newDocument() {
        guard canEdit, attachments.activity == nil else { return }
        showMainWindow()
        let panel = NSOpenPanel()
        panel.title = String(localized: "New Document")
        panel.message = String(localized: "The file is encrypted and stored in a secure note named after it (100 MB at most).")
        panel.prompt = String(localized: "Create")
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var folderID: String?
        if case .folder(let name) = filter {
            folderID = folders.first { $0.name == name }?.id
        }
        Task {
            attachments.activity = String(localized: "Uploading “\(url.lastPathComponent)”…")
            defer { attachments.activity = nil }
            do {
                let data = try Self.readFile(url, limit: AttachmentsModel.maxSize)
                let id = try await session.createDocument(fileName: url.lastPathComponent, data: data, folderId: folderID)
                afterWrite(select: id)
                toast = Toast(message: String(localized: "Document created"), detail: url.lastPathComponent)
            } catch {
                toast = Toast(message: String(localized: "Document not created"), detail: Self.describeFile(error), failure: true)
            }
        }
    }

    /// Reads a file chosen by the user (sandbox right granted by the panel
    /// or the drag and drop), within the size limit.
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
        case .notAFile: String(localized: "Only files can be attached or sent (not folders).")
        case .tooLarge: String(localized: "The file exceeds 100 MB, the maximum size of an attachment or a send.")
        }
    }
}
