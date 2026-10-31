import SwiftUI

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let detail: ItemDetail

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                stateBanner
                if detail.summary.category == .sshKey, fields.contains(where: { $0.id == "public_key" }) {
                    HStack {
                        Button("Copy Public Key", systemImage: "doc.on.doc") {
                            model.copyPublicKey(of: detail.summary.id)
                        }
                        .help("For ~/.ssh/authorized_keys, GitHub, GitLab…")
                        Spacer()
                    }
                    SshApprovalSection(itemID: detail.summary.id, protected: detail.summary.reprompt)
                }
                if !detail.urls.isEmpty || !fields.isEmpty {
                    FieldCard {
                        ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                            if index > 0 { Divider().padding(.leading, 14) }
                            if field.hidden && field.fieldType != .totp {
                                HiddenFieldRow(field: field)
                            } else {
                                FieldRow(itemID: detail.summary.id, field: field)
                            }
                        }
                    }
                }
                if detail.summary.canChangePassword {
                    HStack {
                        ChangePasswordButton(summary: detail.summary, bordered: true)
                        Spacer()
                    }
                }
                if detail.summary.template == .wifi {
                    WifiQRButton(itemID: detail.summary.id, title: detail.summary.title)
                }
                if !detail.urls.isEmpty {
                    SectionTitle(String(localized: "Websites"))
                    FieldCard {
                        ForEach(Array(detail.urls.enumerated()), id: \.offset) { index, url in
                            if index > 0 { Divider().padding(.leading, 14) }
                            WebsiteRow(url: url, primary: index == 0,
                                       rule: detail.urlMatches.indices.contains(index) ? detail.urlMatches[index] : nil)
                        }
                    }
                }
                PasskeysSection(itemID: detail.summary.id, passkeys: model.session.passkeys(id: detail.summary.id))
                if detail.hasNotes {
                    SectionTitle(String(localized: "Notes"))
                    FieldCard { NotesRow(itemID: detail.summary.id) }
                }
                if !history.isEmpty {
                    SectionTitle(String(localized: "Old passwords"))
                    FieldCard {
                        ForEach(Array(history.enumerated()), id: \.element.id) { index, field in
                            if index > 0 { Divider().padding(.leading, 14) }
                            if field.hidden {
                                HiddenFieldRow(field: field)
                            } else {
                                FieldRow(itemID: detail.summary.id, field: field)
                            }
                        }
                    }
                }
                AttachmentsSection(summary: detail.summary)
                if !detail.summary.tags.isEmpty {
                    TagsRow(tags: detail.summary.tags)
                }
                metadata
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .modifier(AttachmentDropModifier(summary: detail.summary))
        .modifier(OptionPeek(itemID: detail.summary.id, fieldIDs: peekable))
    }

    /// Hidden values ⌥ shows: the secret fields (not the one-time code,
    /// always visible) and the notes.
    private var peekable: [String] {
        let secrets = fields.filter { $0.secret && !$0.hidden && $0.fieldType != .totp }.map(\.id)
        return detail.hasNotes ? secrets + ["notes"] : secrets
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            ItemIcon(summary: detail.summary, size: 64)
            VStack(alignment: .leading, spacing: 5) {
                Text(detail.summary.title)
                    .font(.system(size: 24, weight: .bold))
                    .textSelection(.enabled)
                    .layoutMark("detail-title")
                // The chips wrap to the next line when the column is narrow,
                // without ever cutting their text.
                FlowLayout(spacing: 8, lineSpacing: 6) {
                    Chip(text: detail.summary.kindLabel, symbol: detail.summary.symbol, tint: detail.summary.tint)
                    if let folder = detail.summary.folder {
                        Chip(text: folder, symbol: "folder", tint: .secondary)
                    }
                    if detail.summary.pendingSync {
                        Chip(text: String(localized: "Waiting for sync"), symbol: "arrow.triangle.2.circlepath", tint: .orange)
                            .help("Not confirmed by the server yet: sent in the background, or as soon as it responds")
                    }
                    if detail.summary.reprompt {
                        Chip(text: String(localized: "Protected"), symbol: "lock.shield", tint: .orange)
                            .help("Its secrets require a confirmation (Touch ID or master password)")
                    }
                    if let sharing = detail.summary.sharing {
                        Chip(text: sharing.label, symbol: "person.2.fill", tint: .indigo)
                            .help("Shared vault: the members of these collections see it")
                            .contextMenu {
                                Button("Manage in the Web Vault") {
                                    model.openWebVault(organizationID: sharing.organizationId)
                                }
                                if model.canEdit, detail.summary.canUnshare {
                                    Button("Remove from Sharing…") { model.requestUnshare([detail.summary.id]) }
                                }
                            }
                        if sharing.readOnly {
                            Chip(text: String(localized: "Read-only"), symbol: "eye", tint: .secondary)
                        }
                        if sharing.hidePasswords {
                            Chip(text: String(localized: "Password hidden"), symbol: "eye.slash", tint: .secondary)
                                .help("The organization hides the password from your account; filling is still possible")
                        }
                    }
                }
            }
            Spacer()
            Button {
                Task { await model.setFavorite(detail.summary.id, !detail.summary.favorite) }
            } label: {
                Image(systemName: detail.summary.favorite ? "star.fill" : "star")
                    .accessibilityLabel(detail.summary.favorite ? "Remove from Favorites" : "Add to Favorites")
                    .font(.title2)
                    .foregroundStyle(detail.summary.favorite ? Color.yellow : Color.secondary)
            }
            .buttonStyle(.plain)
            .disabled(!model.canModify(detail.summary) || detail.summary.state != .active || model.editorBusy)
            .help(detail.summary.favorite ? "Remove from Favorites" : "Add to Favorites")
        }
        .padding(.bottom, 4)
    }

    /// The item's fields, except old passwords (`history-N`).
    private var fields: [FieldView] { detail.displayFields.filter { !$0.id.hasPrefix("history-") } }
    private var history: [FieldView] { detail.displayFields.filter { $0.id.hasPrefix("history-") } }

    @ViewBuilder private var stateBanner: some View {
        switch detail.summary.state {
        case .active:
            EmptyView()
        case .archived:
            banner("Archived: out of the list, the search and autofill.", symbol: "archivebox",
                   action: "Unarchive") { await model.setArchived(detail.summary.id, false) }
        case .trashed:
            banner("In the Trash: restore it to use it again. The server may delete it permanently after a while.",
                   symbol: "trash",
                   action: "Restore") { await model.restore(detail.summary.id) }
        }
    }

    private func banner(_ text: LocalizedStringKey, symbol: String, action: LocalizedStringKey,
                        perform: @escaping () async -> Void) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(text).font(.callout).foregroundStyle(.secondary)
            Spacer()
            if model.canModify(detail.summary) {
                Button(action) { Task { await perform() } }
                    .disabled(model.editorBusy)
            }
        }
        .padding(12)
        .background(Theme.wash(0.05), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var metadata: some View {
        let format = Date.FormatStyle(date: .long, time: .shortened)
        return VStack(alignment: .leading, spacing: 3) {
            Text("Modified on \(Date(timeIntervalSince1970: TimeInterval(detail.summary.modified)).formatted(format))")
            Text("Created on \(Date(timeIntervalSince1970: TimeInterval(detail.created)).formatted(format))")
            if let used = detail.summary.lastUsedLabel {
                Text("Used on this Mac \(used)")
                    .help("Fill, copy or secret shown: recorded on this Mac only")
            }
        }
        .font(.caption)
        .foregroundStyle(.tertiary)
        .padding(.top, 6)
    }
}

// MARK: Building blocks

/// "Terminal approval" of an SSH key: how long a Touch ID covers the
/// terminal's use of it (ssh, git signing). A device setting, kept by the
/// Rust core; a protected key always asks at least every five minutes, so it
/// only gets a note.
private struct SshApprovalSection: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let protected: Bool
    @State private var scope = SshApprovalScope.fiveMinutes

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if protected {
                Label("Protected keys ask for approval at least every 5 minutes.", systemImage: "lock.shield")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                Picker("Terminal approval", selection: $scope) {
                    Text("Every time").tag(SshApprovalScope.everyTime)
                    Text("For 5 minutes").tag(SshApprovalScope.fiveMinutes)
                    Text("Until Verrou locks").tag(SshApprovalScope.untilLocked)
                }
                .accessibilityIdentifier("ssh-approval-scope")
                Text("""
                    How often the terminal (ssh, git signing) asks for Touch ID to use this key. \
                    “Until Verrou locks” asks once; locking Verrou, sleep or the screen lock end it.
                    """)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .task(id: itemID) { scope = model.session.sshApprovalScope(id: itemID) }
        .onChange(of: scope) { _, new in
            if new != model.session.sshApprovalScope(id: itemID) { model.setSshApprovalScope(itemID, new) }
        }
    }
}

struct FieldCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
            .shadow(color: .black.opacity(0.04), radius: 2, y: 1)
    }
}

struct SectionTitle: View {
    let title: String
    init(_ title: String) { self.title = title }

    var body: some View {
        Text(title.uppercased())
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .tracking(0.6)
            .padding(.leading, 4)
            .padding(.bottom, -10)
    }
}

/// A field row: a click copies, hovering shows the actions.
struct FieldRow: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let field: FieldView
    @State private var hovering = false
    @State private var now = Date()

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(field.label)
                    .font(.caption)
                    .foregroundStyle(field.fieldType == .password || field.fieldType == .totp ? Theme.accent : Color.secondary)
                // Separate view: hovering the row doesn't redraw it (nor
                // recompute the one-time code).
                FieldValue(itemID: itemID, field: field)
            }
            Spacer(minLength: 8)
            if field.secret && field.fieldType != .totp {
                IconButton(symbol: model.revealed[field.id] == nil ? "eye" : "eye.slash",
                           help: model.revealed[field.id] == nil ? "Show" : "Hide") {
                    withAnimation(.snappy(duration: 0.18)) { model.toggleReveal(field.id, of: itemID) }
                }
                .opacity(hovering || model.revealed[field.id] != nil ? 1 : 0)
            }
            IconButton(symbol: "doc.on.doc", help: "Copy") {
                model.copyField(field, of: itemID)
            }
            .opacity(hovering ? 1 : 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .background(hovering ? Theme.wash(0.035) : ContrastStyle(Color.clear))
        .onHover { hovering = $0 }
        .onTapGesture { model.copyField(field, of: itemID) }
        .accessibilityElement(children: .combine)
        .accessibilityAction(named: "Copy") { model.copyField(field, of: itemID) }
    }
}

/// A field's value (hidden, revealed, one-time code…).
private struct FieldValue: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let field: FieldView

    var body: some View {
        switch field.fieldType {
        case .totp:
            TimelineView(.periodic(from: .now, by: 1)) { context in
                if let code = model.totpCode(of: itemID, at: context.date) {
                    TotpCodeView(code: code)
                } else {
                    // Protected item: the code only appears after confirmation.
                    MaskedText(count: 6)
                }
            }
        case .password, .concealed, .pin, .cardNumber:
            if let revealed = model.revealed[field.id] {
                if field.fieldType == .password || field.fieldType == .pin {
                    PasswordText(value: revealed)
                } else {
                    Text(revealed).font(.system(size: 15, design: .monospaced)).textSelection(.enabled)
                }
            } else if field.fieldType == .cardNumber {
                Text("•••• •••• •••• ••••").font(.system(size: 15, design: .monospaced)).foregroundStyle(.secondary)
            } else {
                MaskedText(count: field.fieldType == .pin ? 4 : 12)
            }
        case .address, .multiline:
            Text(field.value ?? "").font(field.fieldType == .multiline ? .system(size: 12, design: .monospaced) : .body)
                .textSelection(.enabled)
                .lineLimit(field.fieldType == .multiline ? 3 : nil)
        case .email, .phone:
            Text(field.value ?? "").foregroundStyle(Theme.accent).textSelection(.enabled)
        default:
            Text(field.value ?? "").textSelection(.enabled)
        }
    }
}

struct IconButton: View {
    let symbol: String
    let help: LocalizedStringKey
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .medium))
                .frame(width: 26, height: 24)
                .background(Theme.faintFill(0.6), in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
    }
}

struct WebsiteRow: View {
    let url: String
    let primary: Bool
    /// The site's own match rule (`nil`: the default one).
    var rule: UriMatchRule?
    @State private var hovering = false

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(primary ? "Main website" : "Website").font(.caption).foregroundStyle(.secondary)
                Text(url).foregroundStyle(Theme.accent).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            if let rule {
                Chip(text: rule.label, symbol: "scope", tint: rule == .never ? .orange : .secondary)
                    .help("Matching: \(rule.explanation)")
            }
            if let link = URL(string: url) {
                Button("Open") { NSWorkspace.shared.open(link) }
                    .controlSize(.small)
                    .opacity(hovering ? 1 : 0.0001)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
    }
}

struct NotesRow: View {
    @Environment(AppModel.self) private var model
    let itemID: String

    var body: some View {
        HStack(alignment: .top) {
            if let notes = model.revealed["notes"] {
                Text(notes).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Content hidden").foregroundStyle(.secondary)
                    Text("Click the eye to show the note.").font(.caption).foregroundStyle(.tertiary)
                }
                Spacer()
            }
            IconButton(symbol: model.revealed["notes"] == nil ? "eye" : "eye.slash", help: "Show the note") {
                withAnimation(.snappy(duration: 0.18)) { model.toggleReveal("notes", of: itemID) }
            }
        }
        .padding(14)
    }
}

/// Holding ⌥ shows the item's hidden fields, released hides them again. An
/// item that asks for a confirmation (protected, or the vault's session
/// password) isn't shown this way: its eye button asks first.
private struct OptionPeek: ViewModifier {
    @Environment(AppModel.self) private var model
    let itemID: String
    let fieldIDs: [String]
    @State private var monitor: Any?
    /// The fields ⌥ revealed, to hide only those on release.
    @State private var shown: [String] = []
    /// What the monitor, created once, acts on: the item shown now.
    @State private var current = Current()

    private final class Current {
        var itemID = ""
        var fieldIDs: [String] = []
    }

    func body(content: Content) -> some View {
        content
            .onChange(of: itemID, initial: true) { current.itemID = itemID }
            .onChange(of: fieldIDs, initial: true) { current.fieldIDs = fieldIDs }
            .onAppear {
                monitor = NSEvent.addLocalMonitorForEvents(matching: .flagsChanged) { event in
                    let option = event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .option
                    option ? show() : hide()
                    return event
                }
            }
            .onDisappear {
                if let monitor { NSEvent.removeMonitor(monitor) }
                monitor = nil
                hide()
            }
            .onChange(of: itemID) { hide() }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in hide() }
    }

    private func show() {
        let itemID = current.itemID
        guard shown.isEmpty, !itemID.isEmpty, model.lockState == .unlocked,
              !model.session.needsConfirmation(id: itemID) else { return }
        let hidden = current.fieldIDs.filter { model.revealed[$0] == nil }
        withAnimation(.snappy(duration: 0.15)) {
            shown = hidden.filter { model.reveal($0, of: itemID) != nil }
        }
    }

    private func hide() {
        guard !shown.isEmpty else { return }
        withAnimation(.snappy(duration: 0.15)) {
            for id in shown { model.revealed[id] = nil }
        }
        shown = []
    }
}
