import SwiftUI

/// Creating or editing an item: login (with the generator), note, card,
/// identity, template; for all: custom fields, folder, favorite and notes.
/// The rest of the item (passkeys, attachments, fields reserved for Verrou)
/// goes back as is.
struct EditItemView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let editor: PhoneModel.Editor
    @State private var draft: ItemDraft
    @State private var destination: SharedDestination?
    @State private var showPassword = false
    @State private var showGenerator = false
    /// Exact entropy of the last generated passphrase.
    @State private var generated: (value: String, bits: Double)?
    @State private var confirmTrash = false
    @State private var confirmDiscard = false
    @FocusState private var titleFocused: Bool

    init(editor: PhoneModel.Editor) {
        self.editor = editor
        _draft = State(initialValue: editor.draft)
        _destination = State(initialValue: editor.destination)
    }

    private var isNew: Bool { editor.itemID == nil }

    private var siteURL: String? {
        draft.login?.urls.first { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    private var hasChanges: Bool {
        draft != editor.original || destination != editor.originalDestination
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 14) {
                        TintedSymbol(symbol: kindSymbol.symbol, tint: kindSymbol.tint, size: 44)
                        TextField("Title", text: $draft.name, prompt: Text(titlePrompt))
                            .font(.title3.weight(.semibold))
                            .focused($titleFocused)
                            .accessibilityIdentifier("edit-title")
                    }
                    .padding(.vertical, 4)
                }
                if draft.login != nil { loginSections }
                if draft.card != nil { cardSection }
                if draft.identity != nil { identitySections }
                vaultSection
                PhoneCustomFieldsSection(fields: $draft.fields, template: draft.template)
                Section {
                    Picker("Folder", selection: $draft.folderId) {
                        Text("None").tag(String?.none)
                        ForEach(model.folders, id: \.id) { folder in
                            Text(folder.name).tag(Optional(folder.id))
                        }
                    }
                    Toggle("Favorite", isOn: $draft.favorite)
                }
                Section(header: SectionHeader("Notes")) {
                    TextField("Notes", text: optionalText(\.notes), axis: .vertical)
                        .lineLimit(3...12)
                }
                if let error = model.editorError {
                    Section { ErrorLabel(text: error) }
                }
                if !isNew {
                    Section {
                        Button("Move to Trash…", role: .destructive) { confirmTrash = true }
                            .disabled(model.editorBusy)
                    }
                }
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle(windowTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        if hasChanges { confirmDiscard = true } else { model.editor = nil }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if model.editorBusy {
                        ProgressView()
                    } else {
                        Button(isNew ? "Create" : "Save") { save() }
                            .fontWeight(.semibold)
                            .disabled(draft.name.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            }
            .sheet(isPresented: $showGenerator) {
                GeneratorView(purpose: .use { value, bits in
                    draft.login?.password = value
                    generated = bits.map { (value, $0) }
                    showPassword = true
                    showGenerator = false
                }, uri: siteURL, useAlias: { alias in
                    draft.login?.username = alias
                    showGenerator = false
                })
                .presentationDetents([.medium, .large])
            }
            .confirmationDialog("Move “\(draft.name)” to the trash?", isPresented: $confirmTrash,
                                titleVisibility: .visible) {
                Button("Move to Trash", role: .destructive) {
                    if let id = editor.itemID { Task { await model.trash(id) } }
                }
            } message: {
                Text("Can be restored from the trash")
            }
            .confirmationDialog("Discard changes?", isPresented: $confirmDiscard, titleVisibility: .visible) {
                Button("Discard Changes", role: .destructive) { model.editor = nil }
                Button("Keep Editing", role: .cancel) {}
            }
            .interactiveDismissDisabled(model.editorBusy || hasChanges)
            .onChange(of: draft, initial: true) { keepProgress() }
            .onChange(of: destination) { keepProgress() }
            .sheet(item: scanBinding) { flow in
                OTPScanSheet(flow: flow)
            }
            .onChange(of: model.otpFormFill) { _, fill in
                guard let fill else { return }
                applyScanned(fill.account)
                model.otpFormFill = nil
            }
            #if DEBUG
            .onChange(of: model.e2eSaveEditor) { save() }
            #endif
            .onAppear { titleFocused = isNew }
        }
    }

    // MARK: Login

    @ViewBuilder private var loginSections: some View {
        Section {
            CaptionedField("Username") {
                HStack(spacing: 2) {
                    TextField("Username", text: loginText(\.username), prompt: Text("email or user name"))
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if model.aliasEnabled {
                        FieldIconButton(symbol: "at", label: "Generate email alias") {
                            if let alias = model.emailAlias(for: siteURL) { draft.login?.username = alias }
                        }
                    }
                }
            }
            CaptionedField("Password") {
                HStack(spacing: 2) {
                    Group {
                        if showPassword {
                            TextField("Password", text: loginText(\.password))
                                .font(.system(.body, design: .monospaced))
                        } else {
                            SecureField("Password", text: loginText(\.password))
                        }
                    }
                    .textContentType(.newPassword)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    FieldIconButton(symbol: showPassword ? "eye.slash" : "eye", label: showPassword ? "Hide" : "Show") {
                        showPassword.toggle()
                    }
                    FieldIconButton(symbol: "doc.on.doc", label: "Copy password") {
                        if let password = draft.login?.password, !password.isEmpty {
                            model.copy(password, label: String(localized: "Password"), secret: true)
                        }
                    }
                    .disabled((draft.login?.password ?? "").isEmpty)
                    .accessibilityIdentifier("edit-copy-password")
                    FieldIconButton(symbol: "wand.and.stars", label: "Generate a password") {
                        showGenerator = true
                    }
                }
            }
            if let password = draft.login?.password, !password.isEmpty {
                StrengthMeter(password: password, bits: generated?.value == password ? generated?.bits : nil)
            }
            CaptionedField("One-time code") {
                TextField("One-time code", text: loginText(\.totp), prompt: Text("setup key or otpauth:// link"))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("edit-totp")
            }
            // Code preview: the entered or scanned seed is readable.
            if let value = draft.login?.totp, !value.isEmpty {
                if (try? totpPreview(value: value, unixTime: 0)) != nil {
                    LabeledContent("Current code") {
                        LiveCode(value: value, size: 17)
                    }
                    .font(.callout)
                } else {
                    Label {
                        Text("Unreadable setup key (Base32 or otpauth:// link expected)")
                            .foregroundStyle(.secondary)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    .font(.footnote)
                }
            }
            Button("Scan a QR code", systemImage: "qrcode.viewfinder") {
                model.startOTPScan(.editor(isNew: isNew))
            }
            .accessibilityIdentifier("edit-scan-qr")
        } header: {
            SectionHeader("Login")
        }
        Section {
            ForEach(Array((draft.login?.urls ?? []).indices), id: \.self) { index in
                VStack(alignment: .leading, spacing: 6) {
                    TextField("https://example.com", text: urlBinding(index))
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Picker(selection: matchBinding(index)) {
                        Text("Default (\(fallbackRule.label))").tag(UriMatchRule?.none)
                        ForEach(UriMatchRule.all) { rule in
                            Text(rule.label).tag(Optional(rule))
                        }
                    } label: {
                        Label("Match", systemImage: "scope")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .pickerStyle(.menu)
                    .accessibilityIdentifier("match-picker-\(index)")
                }
            }
            .onDelete { offsets in
                for index in offsets.sorted(by: >) { draft.login?.removeURL(at: index) }
            }
            Button("Add a site", systemImage: "plus.circle.fill") { draft.login?.appendURL() }
        } header: {
            SectionHeader("Sites")
        } footer: {
            Text("Matching decides the pages where the login is offered; it is saved with the item, as in Bitwarden.")
        }
    }

    // MARK: Card

    @ViewBuilder private var cardSection: some View {
        Section(header: SectionHeader("Card")) {
            TextField("Cardholder", text: cardText(\.cardholderName))
                .textContentType(.name)
                .textInputAutocapitalization(.characters)
            Picker("Network", selection: cardText(\.brand)) {
                Text("Other").tag("")
                ForEach(brands, id: \.self) { brand in
                    Text(brand).tag(brand)
                }
            }
            TextField("Number", text: cardText(\.number))
                .keyboardType(.numberPad)
                .textContentType(.creditCardNumber)
                .font(.system(.body, design: .monospaced))
            LabeledContent("Expiration") {
                HStack(spacing: 6) {
                    Picker("Month", selection: cardText(\.expMonth)) {
                        Text("Month").tag("")
                        ForEach(1...12, id: \.self) { month in Text(String(format: "%02d", month)).tag("\(month)") }
                    }
                    .labelsHidden()
                    .fixedSize()
                    Text("/").foregroundStyle(.secondary)
                    TextField("Year", text: cardText(\.expYear))
                        .keyboardType(.numberPad)
                        .frame(width: 60)
                }
            }
            SecureField("Security code", text: cardText(\.code))
                .keyboardType(.numberPad)
        }
    }

    /// Networks offered, plus the card's if it isn't among them.
    private var brands: [String] {
        let known = ["Visa", "Mastercard", "Amex", "Discover", "Diners Club", "JCB", "Maestro", "UnionPay", "RuPay"]
        guard let current = draft.card?.brand, !current.isEmpty, !known.contains(current) else { return known }
        return known + [current]
    }

    // MARK: Identity

    @ViewBuilder private var identitySections: some View {
        Section(header: SectionHeader("Identity")) {
            TextField("Honorific", text: identityText(\.title))
            TextField("First name", text: identityText(\.firstName)).textContentType(.givenName)
            TextField("Middle name", text: identityText(\.middleName)).textContentType(.middleName)
            TextField("Last name", text: identityText(\.lastName)).textContentType(.familyName)
            TextField("Company", text: identityText(\.company)).textContentType(.organizationName)
        }
        Section(header: SectionHeader("Contact")) {
            TextField("Email", text: identityText(\.email))
                .keyboardType(.emailAddress).textContentType(.emailAddress).textInputAutocapitalization(.never)
            TextField("Phone", text: identityText(\.phone)).keyboardType(.phonePad).textContentType(.telephoneNumber)
            TextField("User name", text: identityText(\.username)).textInputAutocapitalization(.never)
        }
        Section(header: SectionHeader("Address")) {
            TextField("Address", text: identityText(\.address1)).textContentType(.streetAddressLine1)
            TextField("Address line 2", text: identityText(\.address2)).textContentType(.streetAddressLine2)
            TextField("Address line 3", text: identityText(\.address3))
            TextField("Postal code", text: identityText(\.postalCode)).textContentType(.postalCode)
            TextField("City", text: identityText(\.city)).textContentType(.addressCity)
            TextField("State", text: identityText(\.state)).textContentType(.addressState)
            TextField("Country", text: identityText(\.country)).textContentType(.countryName)
        }
        Section(header: SectionHeader("Documents")) {
            SecureField("Social security number", text: identityText(\.ssn))
            SecureField("Passport number", text: identityText(\.passportNumber))
            SecureField("Driver's license number", text: identityText(\.licenseNumber))
        }
    }

    // MARK: Vault

    /// The item's vault: chosen on creation, shown afterwards.
    @ViewBuilder private var vaultSection: some View {
        if isNew, !model.writableOrganizations.isEmpty {
            Section {
                Picker("Vault", selection: $destination) {
                    Text("Personal").tag(SharedDestination?.none)
                    ForEach(model.writableOrganizations, id: \.id) { org in
                        ForEach(org.collections.filter { !$0.readOnly }, id: \.id) { collection in
                            Text("\(org.name) › \(collection.name)")
                                .tag(Optional(SharedDestination(organizationID: org.id, collectionIDs: [collection.id])))
                        }
                    }
                }
            } footer: {
                if destination != nil {
                    Text("Encrypted with the organization's key: the collection's members will see it.")
                }
            }
        } else if let id = editor.itemID, let sharing = model.summary(id: id)?.sharing {
            Section {
                LabeledContent("Shared vault", value: sharing.organization)
            }
        }
    }

    private var titlePrompt: String {
        if let template = draft.template { return template.titlePrompt }
        if draft.login != nil { return String(localized: "GitHub, Bank…") }
        if draft.card != nil { return String(localized: "Personal Visa") }
        if draft.identity != nil { return String(localized: "Me") }
        return String(localized: "Door code, gate code…")
    }

    /// Icon symbol and tint of the item type, at the top of the screen.
    private var kindSymbol: (symbol: String, tint: Color) {
        if let template = draft.template { return (template.symbol, template.tint) }
        if draft.login != nil { return (ItemCategory.login.symbol, ItemCategory.login.tint) }
        if draft.card != nil { return (ItemCategory.card.symbol, ItemCategory.card.tint) }
        if draft.identity != nil { return (ItemCategory.identity.symbol, ItemCategory.identity.tint) }
        return (ItemCategory.secureNote.symbol, ItemCategory.secureNote.tint)
    }

    private var windowTitle: String {
        guard isNew else { return String(localized: "Edit") }
        if let template = draft.template { return template.singular }
        if draft.login != nil { return String(localized: "New login") }
        if draft.card != nil { return String(localized: "New card") }
        if draft.identity != nil { return String(localized: "New identity") }
        return String(localized: "New note")
    }

    /// QR code sheet opened from this screen.
    private var scanBinding: Binding<OTPScanFlow?> {
        Binding(get: { model.otpScan?.purpose.isEditor == true ? model.otpScan : nil },
                set: { if $0 == nil { model.otpScan = nil } })
    }

    /// Scanned account: the canonical link (seed included) goes into the
    /// draft; title and username fill in the empty fields.
    private func applyScanned(_ account: ScannedOtp) {
        guard draft.login != nil else { return }
        draft.login?.totp = account.uri
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty, account.issuer != nil || account.account != nil {
            draft.name = account.title
        }
        if (draft.login?.username ?? "").isEmpty, let user = account.account {
            draft.login?.username = user
        }
    }

    private func keepProgress() {
        model.editorProgress = PhoneModel.EditorProgress(editorID: editor.id, draft: draft, destination: destination)
    }

    private func save() {
        // Sites left empty don't go, nor fields with neither name nor value.
        draft.login?.dropEmptyURLs()
        draft.fields.removeAll { $0.name.trimmingCharacters(in: .whitespaces).isEmpty && ($0.value ?? "").isEmpty
            && $0.fieldType != .linked }
        // The card number is saved without spaces.
        if let number = draft.card?.number {
            draft.card?.number = number.filter { !$0.isWhitespace }
        }
        let toSave = draft
        Task { await model.saveEditor(toSave, destination: isNew ? destination : nil) }
    }

    // MARK: Bindings

    private func loginText(_ path: WritableKeyPath<LoginFields, String?>) -> Binding<String> {
        Binding(get: { draft.login?[keyPath: path] ?? "" },
                set: { draft.login?[keyPath: path] = $0.isEmpty ? nil : $0 })
    }

    private func cardText(_ path: WritableKeyPath<CardFields, String?>) -> Binding<String> {
        Binding(get: { draft.card?[keyPath: path] ?? "" },
                set: { draft.card?[keyPath: path] = $0.isEmpty ? nil : $0 })
    }

    private func identityText(_ path: WritableKeyPath<IdentityFields, String?>) -> Binding<String> {
        Binding(get: { draft.identity?[keyPath: path] ?? "" },
                set: { draft.identity?[keyPath: path] = $0.isEmpty ? nil : $0 })
    }

    private func optionalText(_ path: WritableKeyPath<ItemDraft, String?>) -> Binding<String> {
        Binding(get: { draft[keyPath: path] ?? "" },
                set: { draft[keyPath: path] = $0.isEmpty ? nil : $0 })
    }

    /// Rule for sites without their own rule: the folder's, otherwise the
    /// iPhone's.
    private var fallbackRule: UriMatchRule {
        model.matchSettings?.fallback(folderID: draft.folderId) ?? .domain
    }

    private func matchBinding(_ index: Int) -> Binding<UriMatchRule?> {
        Binding(get: { draft.login?.matchRule(at: index) },
                set: { draft.login?.setMatchRule($0, at: index) })
    }

    private func urlBinding(_ index: Int) -> Binding<String> {
        Binding(get: { draft.login?.urls.indices.contains(index) == true ? draft.login!.urls[index] : "" },
                set: { if draft.login?.urls.indices.contains(index) == true { draft.login?.urls[index] = $0 } })
    }
}

/// Custom fields: text, hidden, checkbox; a linked field is shown and moved
/// without being edited. The fields reserved for Verrou never get here (the
/// Rust core keeps them aside).
private struct PhoneCustomFieldsSection: View {
    @Binding var fields: [CustomField]
    /// The item's template: its fields' names are shown translated.
    var template: ItemTemplate?
    @State private var shown: Set<Int> = []

    var body: some View {
        Section {
            ForEach(Array(fields.indices), id: \.self) { index in
                row(index)
            }
            .onDelete { offsets in
                fields.remove(atOffsets: offsets)
                shown.removeAll()
            }
            Menu {
                Button("Text", systemImage: "textformat") { add(.text) }
                Button("Hidden", systemImage: "eye.slash") { add(.hidden) }
                Button("Checkbox", systemImage: "checkmark.square") { add(.boolean) }
            } label: {
                Label("Add a field", systemImage: "plus.circle.fill")
            }
        } header: {
            SectionHeader("Custom fields")
        } footer: {
            if !fields.isEmpty {
                Text("Swipe a field to the left to delete it.")
            }
        }
    }

    @ViewBuilder private func row(_ index: Int) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("Field name", text: nameBinding(index))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Menu {
                    Button("Move up", systemImage: "arrow.up") { move(index, by: -1) }
                        .disabled(index == 0)
                    Button("Move down", systemImage: "arrow.down") { move(index, by: 1) }
                        .disabled(index == fields.count - 1)
                    Button("Delete", systemImage: "trash", role: .destructive) {
                        fields.remove(at: index)
                        shown.removeAll()
                    }
                } label: {
                    Image(systemName: "ellipsis.circle").foregroundStyle(.secondary)
                }
                .accessibilityLabel("Field actions")
            }
            value(index)
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder private func value(_ index: Int) -> some View {
        switch fields[index].fieldType {
        case .text:
            TextField("Value", text: valueBinding(index))
        case .hidden:
            HStack {
                if shown.contains(index) {
                    TextField("Value", text: valueBinding(index)).font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Value", text: valueBinding(index))
                }
                FieldIconButton(symbol: shown.contains(index) ? "eye.slash" : "eye",
                                label: shown.contains(index) ? "Hide" : "Show") {
                    if shown.contains(index) { shown.remove(index) } else { shown.insert(index) }
                }
            }
        case .boolean:
            Toggle("Checked", isOn: Binding(
                get: { fields.indices.contains(index) && fields[index].value == "true" },
                set: { if fields.indices.contains(index) { fields[index].value = $0 ? "true" : "false" } }))
        case .linked:
            Text("Linked field (editable in the web vault)").foregroundStyle(.secondary)
        }
    }

    private func add(_ type: CustomFieldType) {
        fields.append(CustomField(name: "", value: type == .boolean ? "false" : nil, fieldType: type, linkedId: nil))
    }

    private func move(_ index: Int, by offset: Int) {
        let target = index + offset
        guard fields.indices.contains(index), fields.indices.contains(target) else { return }
        fields.swapAt(index, target)
        shown.removeAll()
    }

    private func nameBinding(_ index: Int) -> Binding<String> {
        Binding(get: {
            guard fields.indices.contains(index) else { return "" }
            let name = fields[index].name
            return CoreText.isTemplateField(name, template: template) ? CoreText.localized(name) : name
        }, set: {
            guard fields.indices.contains(index) else { return }
            // A template field keeps the core's label as long as its translation is not edited.
            let name = fields[index].name
            if CoreText.isTemplateField(name, template: template), $0 == CoreText.localized(name) { return }
            fields[index].name = $0
        })
    }

    private func valueBinding(_ index: Int) -> Binding<String> {
        Binding(get: { fields.indices.contains(index) ? fields[index].value ?? "" : "" },
                set: { if fields.indices.contains(index) { fields[index].value = $0.isEmpty ? nil : $0 } })
    }
}

private struct CaptionedField<Field: View>: View {
    let title: LocalizedStringKey
    let field: Field

    init(_ title: LocalizedStringKey, @ViewBuilder field: () -> Field) {
        self.title = title
        self.field = field()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            field
        }
    }
}

private struct FieldIconButton: View {
    let symbol: String
    let label: LocalizedStringKey
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .frame(width: 44, height: 44)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .accessibilityLabel(label)
    }
}
