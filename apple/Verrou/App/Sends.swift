import AppKit
import Observation
import SwiftUI

/// Sends (Bitwarden Send): the list of the "Sends" pane of the main window,
/// the selected send and the creation or edit screen. The text and the link
/// (which carries the key) only come from Rust on request: copying the link,
/// opening the screen. A file is only read at creation, then encrypted in
/// Rust; an attachment doesn't even go through Swift.
@MainActor
@Observable
final class SendsModel {
    private(set) var items: [SendSummary] = []
    private(set) var loaded = false
    var busy = false
    var error: String?
    /// Creation or edit screen open.
    var composer: Composer?
    /// Last send created or link copied, to report it in the pane.
    var notice: String?
    /// Send displayed in the right column.
    var selection: String?
    /// Deletion to confirm.
    var confirmDelete: SendSummary?
    /// File upload in progress: what is shown to the user.
    var activity: String?

    struct Composer: Identifiable {
        let id = UUID()
        /// `nil`: creation.
        let sendID: String?
        let fields: SendFields
        let hasPassword: Bool
        /// Prefilled from a vault item (the item's title).
        let source: String?
        /// File send: the file to send (creation) or the send's file (edit,
        /// it doesn't change).
        var file: SendFile?
        var password = ""
        var original: SendFields?

        var baseline: SendFields { original ?? fields }

        init(sendID: String?, fields: SendFields, hasPassword: Bool, source: String?, file: SendFile? = nil) {
            self.sendID = sendID
            self.fields = fields
            self.hasPassword = hasPassword
            self.source = source
            self.file = file
        }
    }

    @ObservationIgnored var liveFields: SendFields?
    @ObservationIgnored var livePassword = ""

    func parked(_ composer: Composer) -> Composer {
        var parked = Composer(sendID: composer.sendID, fields: liveFields ?? composer.fields,
                              hasPassword: composer.hasPassword, source: composer.source, file: composer.file)
        parked.password = livePassword
        parked.original = composer.baseline
        return parked
    }

    /// The file of a file send.
    struct SendFile {
        enum Origin {
            /// Chosen in the Finder or dropped: read at creation.
            case local(URL)
            /// Attachment of an item: decrypted then encrypted again in Rust.
            case attachment(itemID: String, attachmentID: String)
            /// File of an existing send.
            case existing
        }

        let name: String
        /// In bytes (encrypted size for an attachment or an existing send).
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

    /// On lock: nothing must survive, draft included.
    func clear() {
        items = []
        loaded = false
        busy = false
        error = nil
        composer = nil
        liveFields = nil
        livePassword = ""
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

    /// Sidebar or Vault menu: the sends pane in the main window.
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

    /// "New Send" → "File…": choice in the Finder.
    func newFileSend() {
        guard sendsAvailable else { return }
        pane = .sends
        let panel = NSOpenPanel()
        panel.title = String(localized: "New File Send")
        panel.message = String(localized: "The file is encrypted before being sent; only the link can open it (100 MB at most).")
        panel.prompt = String(localized: "Choose")
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        composeFileSend(url)
    }

    /// A file chosen or dropped on the sends list: the creation screen,
    /// prefilled with its name. The file is only read at creation.
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

    /// "Send Securely…" on an attachment: a prefilled file send, to confirm
    /// in the sends pane.
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
                toast = Toast(message: String(localized: "Couldn't create the send"), detail: Self.describe(error), failure: true)
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

    /// "Send Securely…" from an item: a send prefilled with its password (or
    /// its notes), to confirm in the sends pane.
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
            toast = Toast(message: String(localized: "Couldn't create the send"), detail: Self.describe(error), failure: true)
        }
    }

    /// Creates or edits the send; at creation, the link is copied. A file is
    /// read here, then encrypted and sent by Rust.
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
                sends.notice = String(localized: "Send “\(fields.name)” saved.")
            } else {
                let created: CreatedSend
                switch file?.origin {
                case .local(let url):
                    sends.activity = String(localized: "Encrypting and uploading “\(url.lastPathComponent)”…")
                    let data = try Self.readFile(url, limit: Int64(session.maxSendFileSize()))
                    created = try await session.createFileSend(fields: fields, fileName: url.lastPathComponent,
                                                               data: data)
                case .attachment(let itemID, let attachmentID):
                    sends.activity = String(localized: "Encrypting and uploading “\(file?.name ?? "")”…")
                    created = try await session.createSendFromAttachment(fields: fields, itemId: itemID,
                                                                         attachmentId: attachmentID)
                case .existing, nil:
                    created = try await session.createSend(fields: fields)
                }
                guard lockState == .unlocked else { return }
                copy(created.link, label: String(localized: "Send link"), secret: true)
                sends.selection = created.id
                let delay = DurationLabel.short(Clipboard.clearDelay)
                sends.notice = String(localized: "Send “\(fields.name)” created: link copied (cleared from the clipboard in \(delay)).")
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
            copy(link, label: String(localized: "Send link"), secret: true)
            let delay = DurationLabel.short(Clipboard.clearDelay)
            sends.notice = String(localized: "Link of “\(send.name)” copied (cleared from the clipboard in \(delay)).")
        } catch {
            sends.error = Self.describe(error)
        }
    }

    func deleteSend(_ send: SendSummary) async {
        await sendAction(String(localized: "Send “\(send.name)” deleted.")) { try await self.session.deleteSend(id: send.id) }
    }

    func removeSendPassword(_ send: SendSummary) async {
        await sendAction(String(localized: "Password removed from “\(send.name)”.")) {
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
