import SwiftUI
import UniformTypeIdentifiers

/// A Send being composed: text, or a chosen file.
struct SendComposer: Identifiable {
    let id = UUID()
    var fields: SendFields
    /// File to encrypt and send (`nil`: text Send).
    var file: URL?
}

extension PhoneModel {
    /// The account's Sends, from the last sync.
    func reloadSends() async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        do {
            sharing.sends = try await session.sends()
        } catch {
            toast = Toast(message: String(localized: "Could not read Sends"), detail: ErrorText.describe(error), failure: true)
        }
    }

    func newSend(file: URL? = nil) {
        guard canEdit else { return }
        var fields = session.newSendFields()
        if let file { fields.name = file.lastPathComponent }
        sharing.error = nil
        sharing.sendComposer = SendComposer(fields: fields, file: file)
    }

    /// Creates the Send (encrypted in the Rust core); the link, which carries
    /// the key, goes to the clipboard (cleared after the set delay).
    func createSend(_ composer: SendComposer) async -> Bool {
        await sharingAction {
            let created: CreatedSend
            if let url = composer.file {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(UInt64.init) ?? 0
                guard size <= self.session.maxSendFileSize() else {
                    throw VerrouError.Invalid(message: String(localized: "file too big for a Send (100 MB at most)"))
                }
                let data = try Data(contentsOf: url)
                created = try await self.session.createFileSend(fields: composer.fields,
                                                                fileName: url.lastPathComponent, data: data)
            } else {
                created = try await self.session.createSend(fields: composer.fields)
            }
            self.copy(created.link, label: String(localized: "Send link"), secret: true)
            self.sharing.createdLink = created.link
            await self.reloadSends()
        }
    }

    func copySendLink(_ send: SendSummary) async {
        do {
            copy(try await session.sendLink(id: send.id), label: String(localized: "Send link"), secret: true)
        } catch {
            toast = Toast(message: String(localized: "Link unavailable"), detail: ErrorText.describe(error), failure: true)
        }
    }

    func deleteSend(_ send: SendSummary) async {
        do {
            try await session.deleteSend(id: send.id)
            toast = Toast(message: String(localized: "Send “\(send.name)” deleted"), detail: nil)
            await reloadSends()
        } catch {
            toast = Toast(message: String(localized: "Could not delete"), detail: ErrorText.describe(error), failure: true)
        }
    }
}

/// Sends (Bitwarden Send): a text or an encrypted file, opened by a link
/// that expires. The server sees neither the content nor the key.
struct SendsScreen: View {
    @Environment(PhoneModel.self) private var model
    @State private var importing = false
    @State private var deleting: SendSummary?

    var body: some View {
        List {
            if let sends = model.sharing.sends {
                if sends.isEmpty {
                    ContentUnavailableView("No Sends", systemImage: "paperplane",
                                           description: Text("Share a text or a file through an encrypted link that expires."))
                        .listRowBackground(Color.clear)
                }
                Section {
                    ForEach(sends, id: \.id) { send in
                        SendRow(send: send)
                            .contextMenu {
                                Button("Copy link", systemImage: "link") { Task { await model.copySendLink(send) } }
                                Button("Delete", systemImage: "trash", role: .destructive) { deleting = send }
                            }
                            .swipeActions {
                                Button(role: .destructive) { deleting = send } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                                Button { Task { await model.copySendLink(send) } } label: {
                                    Label("Link", systemImage: "link")
                                }
                                .tint(.indigo)
                            }
                    }
                } footer: {
                    if !sends.isEmpty {
                        Text("Touch and hold a Send to copy its link. The link carries the key: only give it to its recipient.")
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity).listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Sends")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("Text", systemImage: "text.alignleft") { model.newSend() }
                    Button("File…", systemImage: "doc") { importing = true }
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("New Send")
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
        .confirmationDialog("Delete “\(deleting?.name ?? "")”?",
                            isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
                            titleVisibility: .visible, presenting: deleting) { send in
            Button("Delete", role: .destructive) { Task { await model.deleteSend(send) } }
        } message: { _ in
            Text("The link will stop working.")
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
            if !send.available { Badge(text: String(localized: "Inactive"), tint: nil) }
        }
    }

    private var detail: String {
        var parts: [String] = []
        let deletion = Date(timeIntervalSince1970: TimeInterval(send.deletionDate))
        parts.append(String(localized: "deleted \(deletion.formatted(.relative(presentation: .named)))"))
        if let max = send.maxAccessCount {
            parts.append(String(localized: "\(send.accessCount)/\(max) accesses"))
        } else if send.accessCount > 0 {
            parts.append(String(localized: "\(send.accessCount) accesses"))
        }
        return parts.joined(separator: " · ")
    }
}

/// Composing a Send: content, lifetime, number of accesses, password. On
/// creation, the link is copied and can be shared.
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
                        Label("Send created: link copied", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                        ShareLink(item: link) { Label("Share link", systemImage: "square.and.arrow.up") }
                    } footer: {
                        Text("The link carries the Send's key: only give it to its recipient. It is cleared from the clipboard after the set delay.")
                    }
                } else {
                    Section {
                        TextField("Name", text: $composer.fields.name, prompt: Text("Gate code"))
                        if let file = composer.file {
                            LabeledContent("File", value: file.lastPathComponent)
                        } else {
                            TextField("Text", text: $composer.fields.text, axis: .vertical)
                                .lineLimit(3...8)
                                .accessibilityIdentifier("send-text")
                            Toggle("Hide the text when opened", isOn: $composer.fields.hidden)
                        }
                    }
                    Section {
                        Picker("Deleted after", selection: $days) {
                            Text("1 day").tag(1)
                            Text("2 days").tag(2)
                            Text("3 days").tag(3)
                            Text("7 days").tag(7)
                            Text("14 days").tag(14)
                            Text("30 days").tag(30)
                        }
                        Toggle("Limit the number of accesses", isOn: $limitAccess)
                        if limitAccess {
                            Stepper("\(maxAccess) accesses at most", value: $maxAccess, in: 1...100)
                        }
                        SecureField("Password (optional)", text: $password)
                        Toggle("Hide my email address", isOn: $composer.fields.hideEmail)
                    } header: {
                        SectionHeader("Access")
                    } footer: {
                        Text("Encrypted on this iPhone before sending: the server sees neither the content nor the key.")
                    }
                }
                if let error = model.sharing.error {
                    Section { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red) }
                }
            }
            .navigationTitle(composer.file == nil ? "Text Send" : "File Send")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if model.sharing.createdLink != nil {
                    ToolbarItem(placement: .confirmationAction) { Button("OK") { dismiss() } }
                } else {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                    ToolbarItem(placement: .confirmationAction) {
                        if model.sharing.busy {
                            ProgressView()
                        } else {
                            Button("Create") { create() }
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
