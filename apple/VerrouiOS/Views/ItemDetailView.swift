import SwiftUI

/// An item's page: a tap copies a field, the eye reveals a secret (after
/// confirmation for a protected item), the one-time codes scroll with
/// their countdown.
struct ItemDetailView: View {
    @Environment(PhoneModel.self) private var model
    let itemID: String
    @State private var confirmTrash = false
    @State private var importingFile = false
    @State private var deletingAttachment: AttachmentEntry?
    @State private var deletingPasskey: PasskeyInfo?
    @Environment(\.dynamicTypeSize) private var typeSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dismiss) private var dismiss
    /// The page's area (global points): what turns to dust when the item
    /// is archived (the bars stay drawn above their copy).
    @State private var visibleFrame: CGRect = .zero
    @State private var dust: UIImage?
    @State private var archivedTick = 0

    var body: some View {
        Group {
            if let detail = model.detail(id: itemID) {
                content(detail)
            } else {
                ContentUnavailableView("Item not found", systemImage: "questionmark.folder",
                                       description: Text("It may have been deleted elsewhere."))
            }
        }
        .task(id: itemID) { await model.loadAttachments(of: itemID) }
        .onAppear { if !reduceMotion { DustView.prewarm() } }
        .onDisappear { model.forgetRevealed(of: itemID) }
    }

    @ViewBuilder
    private func content(_ detail: ItemDetail) -> some View {
        let summary = detail.summary
        let fields = detail.displayFields.filter { !$0.id.hasPrefix("history-") }
        let history = detail.displayFields.filter { $0.id.hasPrefix("history-") }
        List {
            Section {
                DetailHeader(summary: summary)
                // Very large text: the field rows are enough (they copy too).
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
                        Button("Copy public key", systemImage: "doc.on.doc") {
                            model.copyField(key, of: itemID)
                        }
                    }
                }
            }

            if summary.template == .wifi {
                Section {
                    Button("Show QR code", systemImage: "qrcode") { model.showWifiQRCode(of: itemID) }
                } footer: {
                    Text("Another phone scans it with the camera to join the network.")
                }
            }

            if !detail.urls.isEmpty {
                Section {
                    ForEach(Array(detail.urls.enumerated()), id: \.offset) { index, url in
                        WebsiteRow(url: url, primary: index == 0,
                                   rule: detail.urlMatches.indices.contains(index) ? detail.urlMatches[index] : nil)
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
                                    Button("Delete", systemImage: "trash", role: .destructive) {
                                        deletingPasskey = passkey
                                    }
                                }
                            }
                    }
                } header: {
                    SectionHeader("Passkeys")
                } footer: {
                    Text("Usable in Brave and Firefox with Verrou on the Mac, and by the Bitwarden apps.")
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
                    SectionHeader("Previous passwords")
                }
            }

            attachmentsSection(summary)

            if !summary.tags.isEmpty {
                Section {
                    TagsRow(tags: summary.tags)
                        .padding(.vertical, 2)
                } header: {
                    SectionHeader("Tags")
                }
            }

            Section {
            } footer: {
                metadata(detail)
            }
        }
        .listStyle(.insetGrouped)
        .opacity(dust == nil ? 1 : 0)
        .overlay(alignment: .topLeading) { dustOverlay }
        .background {
            GeometryReader { proxy in
                let visible = proxy.frame(in: .global)
                Color.clear
                    .onAppear { visibleFrame = visible }
                    .onChange(of: visible) { _, new in visibleFrame = new }
            }
        }
        .sensoryFeedback(.impact(flexibility: .soft, intensity: 0.8), trigger: archivedTick)
        .navigationTitle(summary.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { toolbar(summary) }
        .fileImporter(isPresented: $importingFile, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result {
                Task { await model.addAttachment(from: url, to: itemID) }
            }
        }
        .confirmationDialog("Move “\(summary.title)” to the trash?", isPresented: $confirmTrash,
                            titleVisibility: .visible) {
            Button("Move to Trash", role: .destructive) { Task { await model.trash(itemID) } }
        } message: {
            Text("The item can be restored from the trash for 30 days.")
        }
        .confirmationDialog("Delete “\(deletingAttachment?.fileName ?? "")”?",
                            isPresented: Binding(get: { deletingAttachment != nil }, set: { if !$0 { deletingAttachment = nil } }),
                            titleVisibility: .visible) {
            Button("Delete attachment", role: .destructive) {
                if let entry = deletingAttachment { Task { await model.deleteAttachment(entry, of: itemID) } }
                deletingAttachment = nil
            }
        } message: {
            Text("The file is deleted from the server. This action is permanent.")
        }
        .confirmationDialog("Delete this passkey?",
                            isPresented: Binding(get: { deletingPasskey != nil }, set: { if !$0 { deletingPasskey = nil } }),
                            titleVisibility: .visible) {
            Button("Delete passkey", role: .destructive) {
                if let passkey = deletingPasskey {
                    Task { await model.deletePasskey(itemID: itemID, credentialID: passkey.credentialId) }
                }
                deletingPasskey = nil
            }
        } message: {
            Text("The site will no longer recognize you with it.")
        }
    }

    @ToolbarContentBuilder
    private func toolbar(_ summary: ItemSummary) -> some ToolbarContent {
        ToolbarItemGroup(placement: .topBarTrailing) {
            if model.canModify(summary), summary.state == .active {
                Button("Edit") { Task { await model.edit(itemID) } }
                    .disabled(model.editorBusy)
            }
            Menu {
                if summary.category == .login {
                    Button("Copy username", systemImage: "person") { model.copyUsername(of: itemID) }
                    Button("Copy password", systemImage: "key") { model.copyPassword(of: itemID) }
                }
                if summary.hasTotp {
                    Button("Copy code", systemImage: "clock") { model.copyCode(of: itemID) }
                }
                if model.canModify(summary) {
                    Divider()
                    switch summary.state {
                    case .active:
                        Button(summary.favorite ? "Remove from favorites" : "Add to favorites",
                               systemImage: summary.favorite ? "star.slash" : "star") {
                            Task { await model.setFavorite(itemID, !summary.favorite) }
                        }
                        Button("Move to folder…", systemImage: "folder") {
                            model.moveRequest = PhoneModel.MoveRequest(itemIDs: [itemID])
                        }
                        if summary.sharing != nil {
                            Button("Collections…", systemImage: "tray.2") { model.openSharing(itemID) }
                            if summary.canUnshare {
                                Button("Remove from sharing…", systemImage: "person.2.slash") {
                                    model.requestUnshare([itemID])
                                }
                            }
                        } else if !model.writableOrganizations.isEmpty {
                            Button("Share…", systemImage: "person.2") { model.openSharing(itemID) }
                        }
                        if summary.category == .login, !summary.hasTotp {
                            Button("Add a code (QR)", systemImage: "qrcode.viewfinder") {
                                model.startOTPScan(.item(id: itemID, title: summary.title))
                            }
                        }
                        Button("Add an attachment…", systemImage: "paperclip") { importingFile = true }
                        Button("Archive", systemImage: "archivebox") { Task { await archive() } }
                        Button("Move to Trash", systemImage: "trash", role: .destructive) { confirmTrash = true }
                    case .archived:
                        Button("Unarchive", systemImage: "tray.and.arrow.up") {
                            Task { await model.setArchived(itemID, false) }
                        }
                        Button("Move to Trash", systemImage: "trash", role: .destructive) { confirmTrash = true }
                    case .trashed:
                        Button("Restore", systemImage: "arrow.uturn.backward") { Task { await model.restore(itemID) } }
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .accessibilityLabel("Actions")
        }
    }

    // MARK: Archiving

    /// The page turns to dust while the item is archived, then the list
    /// comes back without it. Reduce Motion: a plain fade.
    private func archive() async {
        archivedTick += 1
        // The Actions menu closes first: it mustn't be in the snapshot.
        try? await Task.sleep(for: .milliseconds(300))
        let image = reduceMotion ? nil : DustView.snapshot(visibleFrame)
        if let image {
            dust = image
        } else {
            withAnimation(.easeOut(duration: 0.25)) { dust = UIImage() }
        }
        async let archived: Void = model.setArchived(itemID, true)
        // The way back to the list starts while the last grains leave.
        try? await Task.sleep(for: .seconds(image == nil ? 0.25 : DustView.duration * 0.65))
        dismiss()
        await archived
    }

    @ViewBuilder
    private var dustOverlay: some View {
        if let dust, dust.size != .zero {
            // Exactly over the page, under the bars.
            GeometryReader { proxy in
                let origin = proxy.frame(in: .global).origin
                DustView(image: dust)
                    .frame(width: visibleFrame.width, height: visibleFrame.height)
                    .offset(x: visibleFrame.minX - origin.x, y: visibleFrame.minY - origin.y)
            }
            .ignoresSafeArea()
        }
    }

    @ViewBuilder
    private func stateBanner(_ summary: ItemSummary) -> some View {
        switch summary.state {
        case .active:
            EmptyView()
        case .archived:
            banner("Archived: out of the list, search and filling.", symbol: "archivebox",
                   action: "Unarchive", summary: summary) { await model.setArchived(itemID, false) }
        case .trashed:
            banner("In the trash: permanently deleted by the server after 30 days.", symbol: "trash",
                   action: "Restore", summary: summary) { await model.restore(itemID) }
        }
    }

    private func banner(_ text: LocalizedStringKey, symbol: String, action: LocalizedStringKey, summary: ItemSummary,
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
                                Text(entry.readable ? entry.fileName : String(localized: "Unreadable file"))
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
                        Button("Preview", systemImage: "eye") { model.openAttachment(entry, of: itemID) }
                        Button("Share…", systemImage: "square.and.arrow.up") { model.shareAttachment(entry, of: itemID) }
                        if model.canModify(summary) {
                            Button("Delete", systemImage: "trash", role: .destructive) { deletingAttachment = entry }
                        }
                    }
                    .swipeActions {
                        if model.canModify(summary) {
                            Button("Delete", systemImage: "trash", role: .destructive) { deletingAttachment = entry }
                        }
                        Button("Share", systemImage: "square.and.arrow.up") { model.shareAttachment(entry, of: itemID) }
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
                SectionHeader("Attachments")
            } footer: {
                Text("Downloaded and decrypted on each opening: the network is needed.")
            }
        }
    }

    private func metadata(_ detail: ItemDetail) -> some View {
        let format = Date.FormatStyle(date: .long, time: .shortened)
        return VStack(alignment: .leading, spacing: 3) {
            Text("Modified \(Date(timeIntervalSince1970: TimeInterval(detail.summary.modified)).formatted(format))")
            Text("Created \(Date(timeIntervalSince1970: TimeInterval(detail.created)).formatted(format))")
            if let used = detail.summary.lastUsedLabel {
                Text("Used on this iPhone \(used)")
            }
        }
        .font(.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Icon, title and chips (type, folder, sharing, protection), favorites
/// star: the Mac item page's header.
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
                // The chips wrap, without ever cutting their text.
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
        if summary.pendingSync { chips.append((String(localized: "Pending sync"), "arrow.triangle.2.circlepath", .orange)) }
        if summary.reprompt { chips.append((String(localized: "Protected"), "lock.shield", .orange)) }
        if let sharing = summary.sharing {
            chips.append((sharing.organization, "person.2.fill", .indigo))
            if sharing.readOnly { chips.append((String(localized: "Read-only"), "eye", .secondary)) }
            if sharing.hidePasswords { chips.append((String(localized: "Hidden password"), "eye.slash", .secondary)) }
        }
        return chips
    }
}

/// The favorites star, which bounces when tapped.
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
        .accessibilityLabel(summary.favorite ? "Remove from favorites" : "Add to favorites")
    }
}

/// One-gesture copy: username, password, code. Glass buttons blended
/// together on iOS 26, tinted capsules before.
private struct QuickCopyBar: View {
    @Environment(PhoneModel.self) private var model
    let summary: ItemSummary
    let fields: [FieldView]
    /// The button that just copied: its checkmark shows for 1.5 s.
    @State private var copied: String?
    @State private var copyToken = 0

    var body: some View {
        GlassGroup(spacing: 10) {
            HStack(spacing: 10) {
                if summary.category == .login, fields.contains(where: { $0.fieldType == .username || $0.id == "username" }) {
                    action(String(localized: "Username"), id: "username", symbol: "person.fill") { model.copyUsername(of: summary.id) }
                }
                if summary.category == .login, fields.contains(where: { $0.id == "password" }) {
                    action(String(localized: "Password"), id: "password", symbol: "key.fill") { model.copyPassword(of: summary.id) }
                }
                if summary.hasTotp {
                    action(String(localized: "Code"), id: "code", symbol: "clock.fill") { model.copyCode(of: summary.id) }
                }
            }
        }
    }

    private func action(_ title: String, id: String, symbol: String, perform: @escaping () -> Void) -> some View {
        Button {
            let before = model.copies
            perform()
            guard model.copies != before else { return }
            copied = title
            // Deadline rather than a view task (see CopiedFlag).
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
        .accessibilityLabel("Copy \(title.lowercased())")
        .accessibilityIdentifier("quick-copy-\(id)")
    }
}

/// Symbol above the text, in the quick copy buttons.
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

/// A field row: a tap copies (the button turns into a checkmark), the eye reveals.
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
                RowIconButton(symbol: shown ? "eye.slash" : "eye", label: shown ? "Hide" : "Show") {
                    model.toggleReveal(field.id, of: itemID)
                }
                .animation(.snappy(duration: 0.25), value: shown)
            }
            if !field.hidden {
                RowIconButton(symbol: copied ? "checkmark" : "doc.on.doc", label: "Copy",
                              tint: copied ? .green : Theme.accent, action: copy)
                    .animation(.snappy(duration: 0.3), value: copied)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture(perform: copy)
        .accessibilityElement(children: .combine)
        .accessibilityHint("Double-tap to copy")
        .accessibilityAction(named: "Copy", copy)
        .contextMenu {
            Button("Copy", systemImage: "doc.on.doc", action: copy)
            if field.secret && field.fieldType != .totp && !field.hidden {
                Button(model.revealedValue(field.id, of: itemID) == nil ? "Show" : "Hide", systemImage: "eye") {
                    model.toggleReveal(field.id, of: itemID)
                }
            }
        }
        .modifier(CopiedFlag(copied: $copied))
    }

    private func copy() {
        let before = model.copies
        model.copyField(field, of: itemID)
        // The checkmark only if the copy happened (no wait for Face ID); the
        // success haptic follows each copy (RootView).
        if model.copies != before {
            copied = true
        }
    }
}

/// Small round button of a row (show, copy): a discreet background, no
/// glass in a list.
private struct RowIconButton: View {
    let symbol: String
    let label: LocalizedStringKey
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

/// A field's value (hidden, revealed, one-time code…).
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
                Text("Hidden by the organization").foregroundStyle(.secondary)
            } else {
                // Revealed: scrambled then decrypted character by character.
                DecryptReveal(value: model.revealedValue(field.id, of: itemID), fontSize: 17) { revealed in
                    if field.fieldType == .password || field.fieldType == .pin {
                        // Copied with a tap on the row: no selection.
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

/// The item page's one-time code: its digits roll, and a light haptic marks
/// each new code, only when the page is on screen and the app in the
/// foreground.
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
                    // Protected item: the code only appears after confirmation.
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
    /// The site's own match rule (`nil`: the default one).
    var rule: UriMatchRule?

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(primary ? "Main site" : "Site").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                    if let rule {
                        Text(rule.label)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background((rule == .never ? Color.orange : Color.secondary).opacity(0.15), in: Capsule())
                            .foregroundStyle(rule == .never ? Color.orange : Color.secondary)
                            .accessibilityLabel("Match: \(rule.label)")
                    }
                }
                Text(url).foregroundStyle(Theme.accent).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            if let link = URL(string: url), link.scheme == "https" || link.scheme == "http" {
                RowIconButton(symbol: "safari", label: "Open in Safari") { openURL(link) }
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { model.copy(url, label: String(localized: "Site"), secret: false) }
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
        let format = Date.FormatStyle(date: .abbreviated, time: .omitted)
        return String(localized: "created \(Date(timeIntervalSince1970: TimeInterval(passkey.created)).formatted(format))")
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
                    Text("Hidden content").foregroundStyle(.secondary)
                    Text("Tap the eye to show the note.").font(.caption).foregroundStyle(.tertiary)
                }
                Spacer()
            }
            RowIconButton(symbol: notes == nil ? "eye" : "eye.slash",
                          label: "Show note") {
                model.toggleReveal("notes", of: itemID)
            }
        }
        .animation(.snappy(duration: 0.2), value: notes)
    }
}

/// QR code of a Wi-Fi network, for another device to scan.
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
                    .accessibilityLabel("QR code of the “\(sheet.title)” network")
                Text("Scan with another phone's camera to join “\(sheet.title)”.")
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

/// "Move to folder": an existing folder, none, or a new one.
struct MoveToFolderSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: PhoneModel.MoveRequest
    @State private var newFolder = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button("No folder", systemImage: "folder.badge.minus") { move(to: nil) }
                    // Full names ("Work/Clients"), in order: a subfolder
                    // follows its parent.
                    ForEach(model.folders.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending },
                            id: \.id) { folder in
                        Button(folder.name, systemImage: "folder") { move(to: folder) }
                    }
                }
                Section("New folder") {
                    TextField("Folder name", text: $newFolder)
                    Button("Create and move") {
                        let name = newFolder
                        dismiss()
                        Task { await model.moveToNewFolder(name, ids: request.itemIDs) }
                    }
                    .disabled(newFolder.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .navigationTitle(request.itemIDs.count == 1 ? "Move" : "Move \(request.itemIDs.count) items")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func move(to folder: FolderOption?) {
        dismiss()
        Task { await model.performBulk(.moveToFolder(folderId: folder?.id), on: request.itemIDs, folderName: folder?.name) }
    }
}

/// System share sheet (Files, AirDrop, another app).
struct ShareSheet: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
