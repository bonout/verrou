import SwiftUI

/// Sidebar entry: the emergency access pane replaces the list.
struct EmergencySidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        SidebarPaneButton(title: String(localized: "Emergency Access"), symbol: "person.2.badge.key",
                          active: model.pane == .emergency,
                          badge: pending > 0 ? pending : nil, badgeTint: .orange,
                          help: String(localized: "Entrust your vault to someone close, or open the one someone close entrusted to you")) {
            model.openEmergency()
        }
    }

    /// What is waiting for an action from me: contact to confirm, request to handle.
    private var pending: Int {
        model.emergency.trusted.filter { $0.state == .accepted || $0.state == .recoveryInitiated }.count
    }
}

/// "Emergency Access" pane, in the middle column: my trusted contacts and
/// those who chose me. The selected access shows on the right.
struct EmergencyListView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var emergency = model.emergency
        VStack(spacing: 0) {
            PaneHeader(title: String(localized: "Emergency Access"),
                       caption: String(localized: "A trusted person close to you can request access to your vault; unless you decline, they get it after the chosen wait period."),
                       busy: emergency.busy, notice: emergency.notice, error: emergency.error) {
                Button("Invite a Contact", systemImage: "plus") { emergency.inviteNew() }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .help("Choose someone close as an emergency contact")
            }
            Divider()
            List(selection: $emergency.selection) {
                Section("My trusted contacts") {
                    if emergency.trusted.isEmpty {
                        Text(emergency.loaded ? "No contacts yet." : "Loading…")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(emergency.trusted, id: \.id) { contact in
                        ContactRow(contact: contact, trusted: true)
                            .tag(contact.id)
                    }
                }
                Section("They chose you") {
                    if emergency.granted.isEmpty {
                        Text(emergency.loaded ? "Nobody has chosen you as an emergency contact." : "Loading…")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(emergency.granted, id: \.id) { contact in
                        ContactRow(contact: contact, trusted: false)
                            .tag(contact.id)
                    }
                }
            }
            .listStyle(.inset)
            .contextMenu(forSelectionType: String.self) { ids in
                if let id = ids.first {
                    if let contact = emergency.trusted.first(where: { $0.id == id }) {
                        Button("Edit…") { emergency.edit(contact) }
                        Divider()
                        Button("Delete…", role: .destructive) { emergency.confirmDelete = contact }
                    } else if let contact = emergency.granted.first(where: { $0.id == id }) {
                        Button("Give Up This Access…", role: .destructive) { emergency.confirmDelete = contact }
                    }
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .task { await model.reloadEmergency() }
    }
}

private struct ContactRow: View {
    let contact: EmergencyContact
    let trusted: Bool

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: contact.accessType == .view ? "eye" : "key")
                .accessibilityHidden(true)
                .font(.system(size: 16))
                .foregroundStyle(Theme.accent)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(contact.displayName).lineLimit(1)
                Text(contact.status(trusted: trusted)).font(.callout).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            if trusted, contact.state == .accepted || contact.state == .recoveryInitiated {
                Circle().fill(.orange).frame(width: 7, height: 7)
                    .help("Waiting for your answer")
            }
        }
        .padding(.vertical, 4)
    }
}

/// Right column of the "Emergency Access" pane: the selected access and what
/// can be done with it depending on its state.
struct EmergencyDetailView: View {
    @Environment(AppModel.self) private var model
    let contact: EmergencyContact
    /// One of my contacts (I am the grantor); otherwise, someone who chose me.
    let trusted: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Text(contact.status(trusted: trusted))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    if trusted { trustedActions } else { grantedActions }
                    Spacer()
                    if trusted {
                        Button("Edit…", systemImage: "pencil") { model.emergency.edit(contact) }
                        Button("Delete…", systemImage: "trash", role: .destructive) {
                            model.emergency.confirmDelete = contact
                        }
                    } else {
                        Button("Give Up…", systemImage: "trash", role: .destructive) {
                            model.emergency.confirmDelete = contact
                        }
                        .help("Give up this emergency access")
                    }
                }
                .disabled(model.emergency.busy)

                SectionTitle(trusted ? String(localized: "What this contact can do") : String(localized: "What is entrusted to you"))
                FieldCard {
                    line("Access", contact.accessType.label)
                    Divider().padding(.leading, 14)
                    line("Wait period", days(contact.waitTimeDays))
                    if let email = contact.email {
                        Divider().padding(.leading, 14)
                        line("Email", email)
                    }
                }
                Text(contact.accessType == .view
                     ? (trusted ? "They will be able to see the items of your vault, without changing them."
                                : "You will be able to see the items of their vault, without changing them.")
                     : (trusted ? "They will be able to choose a new master password for your account (from the web vault)."
                                : "You will be able to choose a new master password for their account (from the web vault)."))
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
            Image(systemName: contact.accessType == .view ? "eye" : "key")
                .accessibilityHidden(true)
                .font(.system(size: 28))
                .foregroundStyle(Theme.accent)
                .frame(width: 64, height: 64)
                .background(Theme.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 5) {
                Text(contact.displayName)
                    .font(.system(size: 24, weight: .bold))
                    .textSelection(.enabled)
                    .layoutMark("detail-title")
                HStack(spacing: 8) {
                    Chip(text: trusted ? String(localized: "My contact") : String(localized: "Chose me"), symbol: "person.2.badge.key", tint: Theme.accent)
                    Chip(text: contact.accessType.label, symbol: contact.accessType == .view ? "eye" : "key",
                         tint: .secondary)
                }
            }
            Spacer()
        }
        .padding(.bottom, 4)
    }

    // MARK: My contacts (I am the grantor)

    @ViewBuilder
    private var trustedActions: some View {
        switch contact.state {
        case .accepted:
            Button("Confirm…") { Task { await model.prepareConfirmation(contact) } }
                .buttonStyle(.borderedProminent)
                .disabled(contact.userId == nil)
        case .recoveryInitiated:
            Button("Approve") { Task { await model.approveEmergency(contact) } }
                .buttonStyle(.borderedProminent)
            Button("Decline") { Task { await model.rejectEmergency(contact) } }
        case .recoveryApproved:
            Button("Remove Access") { Task { await model.rejectEmergency(contact) } }
        case .invited, .confirmed:
            EmptyView()
        }
    }

    // MARK: Those who chose me (I am the contact)

    @ViewBuilder
    private var grantedActions: some View {
        switch contact.state {
        case .confirmed:
            Button("Request Access…") { model.emergency.confirmRequest = contact }
                .buttonStyle(.borderedProminent)
        case .recoveryApproved where contact.accessType == .view:
            Button("Open the Vault") { Task { await model.openGrantorVault(contact) } }
                .buttonStyle(.borderedProminent)
        case .recoveryApproved:
            if let server = model.account?.server, let url = URL(string: server) {
                Button("Open the Web Vault") { NSWorkspace.shared.open(url) }
                    .help("The takeover (new master password) is done from the web vault")
            }
        case .invited, .accepted, .recoveryInitiated:
            EmptyView()
        }
    }

    private func line(_ label: LocalizedStringKey, _ value: String) -> some View {
        // Label on the left, value on the right: outside a `Form`, `LabeledContent`
        // stuck them to each other in the middle of the card.
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

/// Sheets, alerts and confirmations of emergency access, attached to the
/// main window. A grantor's vault stays a sheet.
struct EmergencyPresentations: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var emergency = model.emergency
        content
            .sheet(item: $emergency.invite) { draft in
                InviteContactView(draft: draft).environment(model)
            }
            .sheet(item: Binding(get: { emergency.grantorVault },
                                 set: { if $0 == nil { emergency.closeGrantorVault() } })) { vault in
                GrantorVaultView(vault: vault).environment(model)
            }
            .alert("Check the fingerprint of \(emergency.confirmation?.contact.displayName ?? "")",
                   isPresented: Binding(get: { emergency.confirmation != nil },
                                        set: { if !$0 { emergency.confirmation = nil } }),
                   presenting: emergency.confirmation) { confirmation in
                Button("Confirm") { Task { await model.confirmContact(confirmation) } }
                Button("Cancel", role: .cancel) { emergency.confirmation = nil }
            } message: { confirmation in
                Text("“\(confirmation.fingerprint)”\n\nAsk \(confirmation.contact.displayName) for their account's fingerprint phrase (web vault: Settings → My account). Only confirm if it is identical: your vault's key will be encrypted for them.")
            }
            .confirmationDialog("Request access to the vault of \(emergency.confirmRequest?.displayName ?? "")?",
                                isPresented: Binding(get: { emergency.confirmRequest != nil },
                                                     set: { if !$0 { emergency.confirmRequest = nil } }),
                                presenting: emergency.confirmRequest) { contact in
                Button("Request Access") { Task { await model.requestEmergency(contact) } }
            } message: { contact in
                Text("\(contact.displayName) will be notified. Unless they decline, access will be granted to you in \(days(contact.waitTimeDays)).")
            }
            .confirmationDialog("Delete this emergency access?",
                                isPresented: Binding(get: { emergency.confirmDelete != nil },
                                                     set: { if !$0 { emergency.confirmDelete = nil } }),
                                presenting: emergency.confirmDelete) { contact in
                Button("Delete", role: .destructive) { Task { await model.deleteEmergency(contact) } }
            } message: { contact in
                Text("The access between you and \(contact.displayName) will be removed.")
            }
    }
}

private func days(_ count: UInt32) -> String {
    count > 1 ? String(localized: "\(Int(count)) days") : String(localized: "\(Int(count)) day")
}

private extension EmergencyContact {
    /// State of the access, seen from my side: grantor (`trusted`) or contact.
    func status(trusted: Bool) -> String {
        let base = String(localized: "\(accessType.label) · wait \(days(waitTimeDays))") + " · "
        if trusted {
            switch state {
            case .invited: return base + String(localized: "invitation sent, waiting for acceptance")
            case .accepted: return base + String(localized: "invitation accepted: to confirm")
            case .confirmed: return base + String(localized: "confirmed")
            case .recoveryInitiated: return base + String(localized: "access request in progress")
            case .recoveryApproved: return base + String(localized: "access granted")
            }
        }
        switch state {
        case .invited: return base + String(localized: "accept the invitation from the link received by email")
        case .accepted: return base + String(localized: "waiting for their confirmation")
        case .confirmed: return base + String(localized: "you can request access")
        case .recoveryInitiated: return base + String(localized: "request sent, access at the end of the wait period unless declined")
        case .recoveryApproved:
            return accessType == .takeover
                ? base + String(localized: "access granted: the takeover is done from the web vault")
                : base + String(localized: "access granted")
        }
    }
}

/// Invitation of a contact, or edit of their access type and wait period.
struct InviteContactView: View {
    @Environment(AppModel.self) private var model
    @State private var draft: EmergencyModel.InviteDraft

    init(draft: EmergencyModel.InviteDraft) {
        _draft = State(initialValue: draft)
    }

    private var isNew: Bool { draft.contactID == nil }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Email address", text: $draft.email, prompt: Text("someone@example.com"))
                        .disabled(!isNew)
                    Picker("Access", selection: $draft.type) {
                        Text("View only").tag(EmergencyType.view)
                        Text("Takeover").tag(EmergencyType.takeover)
                    }
                    Stepper(value: $draft.waitDays, in: 1...90) {
                        Text(draft.waitDays > 1 ? "Wait period: \(draft.waitDays) days" : "Wait period: \(draft.waitDays) day")
                    }
                } footer: {
                    Text(draft.type == .view
                         ? "The contact will be able to see the items of your vault, without changing them."
                         : "The contact will be able to choose a new master password for your account (from the web vault).")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if isNew {
                    Section {
                        Text("The contact must have an account on this server. Once the invitation is accepted, you will confirm it by checking their key's fingerprint.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                if let error = model.emergency.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                if model.emergency.busy { ProgressView().controlSize(.small) }
                Button("Cancel") { model.emergency.invite = nil }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Invite" : "Save") { Task { await model.saveInvite(draft) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!draft.email.contains("@") || model.emergency.busy)
            }
            .padding(16)
        }
        .frame(width: 460)
        .onAppear { model.emergency.error = nil }
    }
}

/// A grantor's vault, read-only.
struct GrantorVaultView: View {
    @Environment(AppModel.self) private var model
    @Bindable var vault: GrantorVault

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "eye").foregroundStyle(Theme.accent)
                    .accessibilityHidden(true)
                Text("Vault of \(vault.grantor)").font(.headline)
                Text("read-only").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Close") { model.emergency.closeGrantorVault() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
            Divider()
            HStack(spacing: 0) {
                VStack(spacing: 0) {
                    TextField("Search", text: $vault.query)
                        .textFieldStyle(.roundedBorder)
                        .padding(8)
                    List(vault.rows, id: \.id, selection: $vault.selection) { summary in
                        HStack(spacing: 9) {
                            ItemIcon(summary: summary, size: 26)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(summary.title).lineLimit(1)
                                Text(summary.displaySubtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                        .tag(summary.id)
                    }
                    .listStyle(.sidebar)
                }
                .frame(width: 260)
                Divider()
                Group {
                    if let detail = vault.detail {
                        GrantorItemView(vault: vault, detail: detail)
                            .id(detail.summary.id)
                    } else {
                        ContentUnavailableView("No items", systemImage: "tray")
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(width: 820, height: 560)
        .onChange(of: vault.selection) { vault.revealed.removeAll() }
    }
}

private struct GrantorItemView: View {
    @Environment(AppModel.self) private var model
    let vault: GrantorVault
    let detail: ItemDetail

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 12) {
                    ItemIcon(summary: detail.summary, size: 40)
                    VStack(alignment: .leading) {
                        Text(detail.summary.title).font(.title3.weight(.semibold))
                        Text(detail.summary.displaySubtitle).foregroundStyle(.secondary)
                    }
                }
                ForEach(detail.displayFields, id: \.id) { field in
                    row(field)
                }
                ForEach(detail.urls, id: \.self) { url in
                    LabeledContent("Website") { Text(url).textSelection(.enabled) }
                }
                if detail.hasNotes {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("Notes").font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Button(vault.revealed["notes"] == nil ? "Show" : "Hide") { toggle("notes") }
                                .buttonStyle(.borderless)
                        }
                        if let notes = vault.revealed["notes"] {
                            Text(notes).textSelection(.enabled)
                        } else {
                            MaskedText()
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func row(_ field: FieldView) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                if field.fieldType == .totp {
                    Text((try? vault.vault.totp(id: detail.summary.id, unixTime: UInt64(Date().timeIntervalSince1970)))?.code ?? "—")
                        .font(.body.monospaced())
                } else if !field.secret {
                    Text(field.value ?? "").textSelection(.enabled)
                } else if let value = vault.revealed[field.id] {
                    Text(value).font(.body.monospaced()).textSelection(.enabled)
                } else {
                    MaskedText()
                }
            }
            Spacer()
            if field.secret, field.fieldType != .totp {
                Button(vault.revealed[field.id] == nil ? "Show" : "Hide") { toggle(field.id) }
                    .buttonStyle(.borderless)
            }
            Button {
                model.copyGrantorField(field, itemID: detail.summary.id, in: vault)
            } label: {
                Image(systemName: "doc.on.doc")
                    .accessibilityLabel("Copy")
            }
            .buttonStyle(.borderless)
            .help("Copy")
        }
    }

    private func toggle(_ fieldID: String) {
        if vault.revealed[fieldID] != nil {
            vault.revealed[fieldID] = nil
        } else {
            vault.revealed[fieldID] = try? vault.vault.reveal(id: detail.summary.id, fieldId: fieldID)
        }
    }
}
