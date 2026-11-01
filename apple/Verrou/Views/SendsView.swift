import SwiftUI
import UniformTypeIdentifiers

/// Sidebar entry: the sends pane replaces the list.
struct SendsSidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        SidebarPaneButton(title: String(localized: "Sends"), symbol: "paperplane", active: model.pane == .sends,
                          badge: model.sends.loaded && !model.sends.items.isEmpty ? model.sends.items.count : nil,
                          help: String(localized: "Share a text or a file through an encrypted link (Bitwarden Send)")) {
            model.openSends()
        }
    }
}

/// "Sends" pane, in the middle column: the account's sends, with their
/// accesses and their expiry. The selected send shows on the right. A file
/// dropped on the list opens the screen of a new file send.
struct SendsListView: View {
    @Environment(AppModel.self) private var model
    @State private var targeted = false

    var body: some View {
        @Bindable var sends = model.sends
        VStack(spacing: 0) {
            PaneHeader(title: String(localized: "Sends"),
                       caption: String(localized: "A text or a file shared through a link, end-to-end encrypted: the key is in the link, never on the server."),
                       busy: sends.busy, notice: sends.activity ?? sends.notice, error: sends.error) {
                NewSendMenu()
                    .font(.caption)
            }
            Divider()
            if sends.items.isEmpty {
                ContentUnavailableView {
                    Label(sends.loaded ? "No sends" : "Loading…", systemImage: "paperplane")
                } description: {
                    Text("Create a Send here, drop a file on this list, or start from an item or an attachment: right-click → “Send Securely…”.")
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
                    // Double-click: edit the send (the settings, for a file).
                    if let send = sends.items.first(where: { ids.contains($0.id) }) {
                        Task { await model.editSend(send) }
                    }
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first(where: \.isFileURL), !sends.busy else { return false }
            model.composeFileSend(url)
            return true
        } isTargeted: { targeted = $0 && !sends.busy }
        .overlay {
            if targeted {
                RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous)
                    .strokeBorder(Theme.accent, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                    .background(Theme.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: Theme.cornerRadius))
                    .overlay(Label("Drop to create a file Send", systemImage: "doc.badge.arrow.up")
                        .font(.headline).foregroundStyle(Theme.accent))
                    .padding(8)
                    .allowsHitTesting(false)
            }
        }
        .task { await model.reloadSends() }
    }
}

/// "New Send": a text, or a file chosen in the Finder.
struct NewSendMenu: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Menu {
            Button("Text", systemImage: "text.alignleft") { model.newSend() }
            Button("File…", systemImage: "doc") { model.newFileSend() }
        } label: {
            Label("New Send", systemImage: "plus")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(model.sends.busy)
        .help("Create a text or file Send")
    }
}

/// Actions of a send, for the list's context menu.
private struct SendMenu: View {
    @Environment(AppModel.self) private var model
    let send: SendSummary

    var body: some View {
        Button("Copy Link") { Task { await model.copySendLink(send) } }
        Button("Edit…") { Task { await model.editSend(send) } }
        if send.hasPassword {
            Button("Remove Password") { Task { await model.removeSendPassword(send) } }
        }
        Divider()
        Button("Delete…", role: .destructive) { model.sends.confirmDelete = send }
    }
}

/// Right column of the "Sends" pane: the selected send.
struct SendDetailView: View {
    @Environment(AppModel.self) private var model
    let send: SendSummary

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                HStack(spacing: 8) {
                    Button("Copy Link", systemImage: "link") { Task { await model.copySendLink(send) } }
                        .buttonStyle(.borderedProminent)
                    Button("Edit…", systemImage: "pencil") { Task { await model.editSend(send) } }
                    if send.hasPassword {
                        Button("Remove Password", systemImage: "lock.open") {
                            Task { await model.removeSendPassword(send) }
                        }
                    }
                    Spacer()
                    Button("Delete…", systemImage: "trash", role: .destructive) {
                        model.sends.confirmDelete = send
                    }
                }
                .disabled(model.sends.busy)

                SectionTitle(String(localized: "Access"))
                FieldCard {
                    line("Opens", send.maxAccessCount.map { String(localized: "\(Int(send.accessCount)) of \(Int($0)) at most") }
                        ?? "\(send.accessCount)")
                    if let expiry = send.expirationDate {
                        Divider().padding(.leading, 16)
                        line(date(expiry) < Date() ? "Expired" : "Expiration", formatted(expiry))
                    }
                    Divider().padding(.leading, 16)
                    line("Deletion", formatted(send.deletionDate))
                    if let file = send.fileName {
                        Divider().padding(.leading, 16)
                        line("File", send.fileSize.map { "\(file) · \(SendFileSize.text($0))" } ?? file)
                    }
                }
                Text("Modified \(date(send.revisionDate).formatted(.relative(presentation: .named))).")
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
                .accessibilityHidden(true)
                .font(.system(size: 28))
                .foregroundStyle(send.available ? Theme.accent : .secondary)
                .frame(width: 64, height: 64)
                .background(Theme.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
            VStack(alignment: .leading, spacing: 4) {
                Text(send.name)
                    .font(.title.bold())
                    .textSelection(.enabled)
                    .layoutMark("detail-title")
                HStack(spacing: 8) {
                    Chip(text: send.content == .file ? String(localized: "File") : String(localized: "Text"), symbol: "paperplane", tint: Theme.accent)
                    if !send.available {
                        Chip(text: send.disabled ? String(localized: "Disabled") : String(localized: "Inactive link"), symbol: "exclamationmark.circle",
                             tint: .orange)
                            .help("The link no longer leads to the content: disabled, expired or access count reached")
                    }
                    if send.hasPassword {
                        Chip(text: String(localized: "Password"), symbol: "key.fill", tint: .secondary)
                    }
                    if send.hideEmail {
                        Chip(text: String(localized: "Email hidden"), symbol: "eye.slash", tint: .secondary)
                    }
                }
            }
            Spacer()
        }
        .padding(.bottom, 4)
    }

    private func line(_ label: LocalizedStringKey, _ value: String) -> some View {
        // Label on the left, value on the right: outside a `Form`, `LabeledContent`
        // stuck them to each other in the middle of the card.
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).monospacedDigit().textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private func formatted(_ timestamp: Int64) -> String {
        let value = date(timestamp)
        return "\(value.formatted(date: .abbreviated, time: .shortened)) · \(value.formatted(.relative(presentation: .named)))"
    }

    private func date(_ timestamp: Int64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(timestamp))
    }
}

/// Sheets and confirmations of sends, attached to the main window: "Send
/// Securely…" also opens them from the item list.
struct SendsPresentations: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var sends = model.sends
        content
            .sheet(item: $sends.composer) { composer in
                SendEditorView(composer: composer)
                    .environment(model)
            }
            .confirmationDialog("Delete “\(sends.confirmDelete?.name ?? "")”?",
                                isPresented: Binding(get: { sends.confirmDelete != nil },
                                                     set: { if !$0 { sends.confirmDelete = nil } }),
                                presenting: sends.confirmDelete) { send in
                Button("Delete", role: .destructive) { Task { await model.deleteSend(send) } }
            } message: { _ in
                Text("The link will no longer lead anywhere. This deletion is permanent.")
            }
    }
}

/// Readable size of a file ("1.4 MB").
enum SendFileSize {
    static func text(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

struct SendRow: View {
    let send: SendSummary

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: send.content == .file ? "doc" : "text.alignleft")
                .accessibilityLabel(send.content == .file ? "File" : "Text")
                .font(.system(size: 18))
                .foregroundStyle(send.available ? Theme.accent : .secondary)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(send.name).lineLimit(1)
                    if send.hasPassword {
                        Image(systemName: "key.fill").font(.caption).foregroundStyle(.secondary)
                            .accessibilityLabel("Protected by a password")
                            .help("Protected by a password")
                    }
                    if send.hideEmail {
                        Image(systemName: "eye.slash").font(.caption).foregroundStyle(.secondary)
                            .accessibilityLabel("Email address hidden")
                            .help("Email address hidden")
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
            parts.append(String(localized: "Disabled"))
        }
        if let file = send.fileName {
            parts.append(send.fileSize.map { "\(file) (\(SendFileSize.text($0)))" } ?? file)
        }
        let accesses = send.maxAccessCount.map { String(localized: "\(Int(send.accessCount))/\(Int($0)) accesses") }
            ?? String(localized: "\(Int(send.accessCount)) accesses")
        parts.append(accesses)
        let now = Date()
        if let expiry = send.expirationDate.map(date) {
            parts.append(expiry < now ? String(localized: "expired")
                                        : String(localized: "expires \(expiry.formatted(.relative(presentation: .named)))"))
        }
        parts.append(String(localized: "deleted \(date(send.deletionDate).formatted(.relative(presentation: .named)))"))
        return parts.joined(separator: " · ")
    }

    private func date(_ timestamp: Int64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(timestamp))
    }
}

/// Creation or edit of a text or file send. The file of an existing send
/// can't be replaced (as in Bitwarden): only the settings change.
struct SendEditorView: View {
    @Environment(AppModel.self) private var model
    let composer: SendsModel.Composer
    @State private var fields: SendFields
    @State private var showText: Bool
    @State private var expires: Bool
    @State private var limited: Bool
    @State private var password: String
    @State private var confirmDiscard = false

    init(composer: SendsModel.Composer) {
        self.composer = composer
        _fields = State(initialValue: composer.fields)
        _password = State(initialValue: composer.password)
        // Prefilled from an item: the secret stays hidden until asked to see
        // it.
        _showText = State(initialValue: composer.source == nil)
        _expires = State(initialValue: composer.fields.expirationDate != nil)
        _limited = State(initialValue: composer.fields.maxAccessCount != nil)
    }

    private var isNew: Bool { composer.sendID == nil }
    private var isFile: Bool { composer.file != nil }
    private static let maxDays = 31

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if let source = composer.source {
                    Section {
                        Label("Prefilled from “\(source)”. Check the settings, then create the Send: the link will be copied.",
                              systemImage: "info.circle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                Section {
                    TextField("Name", text: $fields.name,
                              prompt: Text(isFile ? "Name seen by the recipient" : "Cabin Wi-Fi, door code…"))
                    if let file = composer.file {
                        fileRow(file)
                    } else if showText {
                        TextEditor(text: $fields.text)
                            .font(.body.monospaced())
                            .frame(minHeight: 90)
                            .scrollContentBackground(.hidden)
                    } else {
                        HStack {
                            Text("Text").foregroundStyle(.secondary)
                            Spacer()
                            MaskedText()
                            Button("Show") { showText = true }
                                .buttonStyle(.borderless)
                        }
                    }
                    if !isFile {
                        Toggle("Hide the text until the recipient reveals it", isOn: $fields.hidden)
                    }
                }

                Section("Lifetime") {
                    DatePicker("Deletion", selection: dateBinding(\.deletionDate), in: dateRange,
                               displayedComponents: [.date, .hourAndMinute])
                    Toggle("Expires before deletion", isOn: $expires.animation())
                    if expires {
                        DatePicker("Expiration", selection: expiryBinding, in: Date()...date(fields.deletionDate),
                                   displayedComponents: [.date, .hourAndMinute])
                    }
                    Toggle("Limit the number of accesses", isOn: $limited.animation())
                    if limited {
                        Stepper(value: accessBinding, in: 1...1000) {
                            Text("\(Int(fields.maxAccessCount ?? 1)) accesses at most")
                        }
                    }
                }

                Section("Protection") {
                    SecureField(isNew || !composer.hasPassword ? "Password" : "New password",
                                text: $password,
                                prompt: Text(isNew || !composer.hasPassword ? "optional" : "leave empty to keep the current one"))
                    if !isNew, composer.hasPassword {
                        Text("To remove the password: “Remove Password” on the Send's detail.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Toggle("Hide my email address", isOn: $fields.hideEmail)
                    if !isNew {
                        Toggle("Disable this Send", isOn: $fields.disabled)
                    }
                }

                Section("Private notes") {
                    TextField("Notes", text: notesBinding, prompt: Text("visible to you only"), axis: .vertical)
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
            HStack(spacing: 8) {
                if model.sends.busy {
                    ProgressView().controlSize(.small)
                    if let activity = model.sends.activity {
                        Text(activity).font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                }
                Spacer()
                Button("Cancel") { cancel() }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Create and Copy Link" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave)
                    .background(
                        Button("") { save() }
                            .keyboardShortcut("s", modifiers: .command)
                            .disabled(!canSave)
                            .opacity(0)
                            .accessibilityHidden(true)
                    )
            }
            .padding(16)
        }
        .frame(width: 520)
        .frame(minHeight: 560)
        .navigationTitle(isNew ? (isFile ? "New File Send" : "New Send") : "Edit Send")
        .onAppear { model.sends.error = nil }
        .onChange(of: normalized, initial: true) { _, value in model.sends.liveFields = value }
        .onChange(of: password, initial: true) { _, value in model.sends.livePassword = value }
        .onDisappear {
            model.sends.liveFields = nil
            model.sends.livePassword = ""
        }
        .interactiveDismissDisabled(changed)
        .confirmationDialog("Discard your changes?", isPresented: $confirmDiscard) {
            Button("Discard Changes", role: .destructive) { model.sends.composer = nil }
            Button("Keep Editing", role: .cancel) {}
        } message: {
            Text(isNew ? "This Send hasn't been created yet." : "Your changes to this Send will be lost.")
        }
        .announcing(model.sends.error)
    }

    private var normalized: SendFields {
        var final = fields
        final.expirationDate = expires ? (fields.expirationDate ?? fields.deletionDate) : nil
        final.maxAccessCount = limited ? (fields.maxAccessCount ?? 1) : nil
        return final
    }

    private var changed: Bool {
        normalized != composer.baseline || !password.isEmpty
    }

    private func cancel() {
        if changed {
            confirmDiscard = true
        } else {
            model.sends.composer = nil
        }
    }

    private var canSave: Bool {
        !fields.name.trimmingCharacters(in: .whitespaces).isEmpty
            && (isFile || !fields.text.isEmpty)
            && !model.sends.busy
    }

    private func fileRow(_ file: SendsModel.SendFile) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(nsImage: NSWorkspace.shared.icon(
                    for: .init(filenameExtension: (file.name as NSString).pathExtension) ?? .data))
                    .resizable()
                    .frame(width: 28, height: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text(file.name).lineLimit(1).truncationMode(.middle)
                    if let size = file.size {
                        Text(ByteCountFormatter.string(fromByteCount: size, countStyle: .file))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
            }
            Text(isNew
                 ? "The file and its name are encrypted before upload; only the link can open them."
                 : "The file of a Send can't be replaced: create a new Send for another file.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
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
        guard canSave else { return }
        var final = normalized
        final.password = password.isEmpty ? nil : password
        Task {
            await model.saveSend(final, id: composer.sendID, file: composer.file)
            if model.sends.composer == nil { password = "" }
        }
    }
}
