import SwiftUI

/// Creation or edit of an item. For a login: title, username, password
/// (with the generator), one-time code, sites. For all types: title, custom
/// fields, folder, favorite and notes; the rest of the item (card, identity,
/// fields reserved for Verrou…) goes back as is. A template (Wi-Fi,
/// passport…) comes with its predefined fields.
struct EditItemView: View {
    @Environment(AppModel.self) private var model
    let editor: AppModel.Editor
    @State private var draft: ItemDraft
    /// Creation: personal vault (`nil`) or an organization's collection.
    @State private var destination: SharedDestination?
    @State private var showPassword = false
    @State private var showGenerator = false
    /// Exact entropy of the last generated passphrase: the characters would
    /// overestimate it by a lot.
    @State private var generated: (value: String, bits: Double)?
    @State private var confirmTrash = false
    @FocusState private var titleFocused: Bool

    init(editor: AppModel.Editor) {
        self.editor = editor
        _draft = State(initialValue: editor.draft)
        _destination = State(initialValue: editor.destination)
    }

    private var isNew: Bool { editor.itemID == nil }
    private var isLogin: Bool { draft.login != nil }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Title", text: $draft.name, prompt: Text(titlePrompt))
                        .focused($titleFocused)
                        .layoutMark("edit-title")
                    if isLogin {
                        usernameRow
                        passwordRow
                        if let password = draft.login?.password, !password.isEmpty {
                            StrengthMeter(password: password, bits: generated?.value == password ? generated?.bits : nil)
                        }
                        TextField("One-time code", text: loginText(\.totp), prompt: Text("seed or otpauth:// link"))
                    }
                }

                if isLogin {
                    Section {
                        ForEach(Array((draft.login?.urls ?? []).indices), id: \.self) { index in
                            HStack {
                                TextField("Website", text: urlBinding(index), prompt: Text("https://example.com"))
                                    .labelsHidden()
                                Picker("Matching", selection: matchBinding(index)) {
                                    Text("Default (\(fallbackRule.label))").tag(UriMatchRule?.none)
                                    Divider()
                                    ForEach(UriMatchRule.all) { rule in
                                        Text(rule.label).tag(Optional(rule))
                                    }
                                }
                                .labelsHidden()
                                .fixedSize()
                                .help(draft.login?.matchRule(at: index)?.explanation
                                      ?? String(localized: "This Mac's rule: \(fallbackRule.explanation)"))
                                .layoutMark("match-picker-\(index)")
                                Button {
                                    draft.login?.removeURL(at: index)
                                } label: {
                                    Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                                        .accessibilityLabel("Remove this website")
                                }
                                .buttonStyle(.plain)
                                .help("Remove this website")
                            }
                        }
                        Button {
                            draft.login?.appendURL()
                        } label: {
                            Label("Add a Website", systemImage: "plus.circle.fill")
                        }
                        .buttonStyle(.borderless)
                    } header: {
                        Text("Websites")
                    } footer: {
                        Text("Matching decides on which pages Verrou offers the login; it is saved with the item, as in Bitwarden.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                vaultSection
                CustomFieldsSection(fields: $draft.fields, template: draft.template)

                Section {
                    Picker("Folder", selection: $draft.folderId) {
                        Text("No folder").tag(String?.none)
                        ForEach(model.folders, id: \.id) { folder in
                            Text(folder.name).tag(Optional(folder.id))
                        }
                    }
                    Toggle("Favorite", isOn: $draft.favorite)
                }

                Section("Notes") {
                    TextEditor(text: notesBinding)
                        .font(.body)
                        .frame(minHeight: 70)
                        .scrollContentBackground(.hidden)
                }

                if let error = model.editorError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack(spacing: 10) {
                if !isNew {
                    Button("Move to Trash…", role: .destructive) { confirmTrash = true }
                        .disabled(model.editorBusy)
                }
                Spacer()
                if model.editorBusy {
                    ProgressView().controlSize(.small)
                }
                Button("Cancel") { model.editor = nil }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Create" : "Save") { save() }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
                    .layoutMark("sheet-primary")
                    .disabled(draft.name.trimmingCharacters(in: .whitespaces).isEmpty || model.editorBusy)
            }
            .padding(16)
        }
        .frame(width: 540)
        .frame(minHeight: isLogin ? 640 : 520, maxHeight: 700)
        .navigationTitle(windowTitle)
        .onAppear { titleFocused = isNew }
        .confirmationDialog("Move “\(draft.name)” to the trash?", isPresented: $confirmTrash) {
            Button("Move to Trash", role: .destructive) {
                if let id = editor.itemID { Task { await model.trash(id) } }
            }
        } message: {
            Text("You can restore it from the Trash.")
        }
    }

    /// The item's vault: chosen at creation, recalled afterwards (the
    /// collections are changed through "Collections…").
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
                    Text("Encrypted with the organization's key: the members of the collection will see it.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        } else if let id = editor.itemID, let sharing = model.summaries.first(where: { $0.id == id })?.sharing {
            Section {
                LabeledContent("Shared vault", value: sharing.label)
            }
        }
    }

    private var titlePrompt: String {
        if let template = draft.template { return template.titlePrompt }
        return isLogin ? String(localized: "GitHub, Bank…") : String(localized: "Door code, Wi-Fi…")
    }

    private var windowTitle: String {
        guard isNew else { return String(localized: "Edit") }
        if let template = draft.template { return String(localized: "New: \(template.singular)") }
        return isLogin ? String(localized: "New Login") : String(localized: "New Secure Note")
    }

    private var usernameRow: some View {
        HStack(spacing: 8) {
            TextField("Username", text: loginText(\.username), prompt: Text("email or username"))
                .textContentType(.username)
            if model.aliasEnabled {
                Button {
                    if let alias = model.emailAlias(for: siteURL) { draft.login?.username = alias }
                } label: {
                    Image(systemName: "at")
                        .accessibilityLabel("Generate email alias")
                }
                .buttonStyle(.borderless)
                .help("Generate email alias")
            }
        }
    }

    private var siteURL: String? {
        draft.login?.urls.first { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    private var passwordRow: some View {
        HStack(spacing: 8) {
            Group {
                if showPassword {
                    TextField("Password", text: loginText(\.password))
                        .font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Password", text: loginText(\.password))
                }
            }
            .textContentType(.password)
            Button {
                showPassword.toggle()
            } label: {
                Image(systemName: showPassword ? "eye.slash" : "eye")
                    .accessibilityLabel(showPassword ? "Hide" : "Show")
            }
            .buttonStyle(.borderless)
            .help(showPassword ? "Hide" : "Show")
            Button {
                showGenerator = true
            } label: {
                Image(systemName: "wand.and.stars")
                    .accessibilityLabel("Generate a password or a passphrase")
            }
            .buttonStyle(.borderless)
            .help("Generate a password or a passphrase")
            .popover(isPresented: $showGenerator, arrowEdge: .trailing) {
                GeneratorView(uri: siteURL, useAlias: { alias in
                    draft.login?.username = alias
                    showGenerator = false
                }) { password, bits in
                    draft.login?.password = password
                    generated = bits.map { (password, $0) }
                    showPassword = true
                    showGenerator = false
                }
            }
        }
    }

    private func save() {
        // Sites left empty are not sent.
        draft.login?.dropEmptyURLs()
        // A field added then left without name or value is not sent.
        draft.fields.removeAll { $0.name.trimmingCharacters(in: .whitespaces).isEmpty && ($0.value ?? "").isEmpty
            && $0.fieldType != .linked }
        Task { await model.saveEditor(draft, destination: isNew ? destination : nil) }
    }

    private func loginText(_ path: WritableKeyPath<LoginFields, String?>) -> Binding<String> {
        Binding(
            get: { draft.login?[keyPath: path] ?? "" },
            set: { draft.login?[keyPath: path] = $0.isEmpty ? nil : $0 })
    }

    private func urlBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: { draft.login?.urls.indices.contains(index) == true ? draft.login!.urls[index] : "" },
            set: { if draft.login?.urls.indices.contains(index) == true { draft.login?.urls[index] = $0 } })
    }

    /// Rule of the sites without their own rule: the chosen folder's,
    /// otherwise this Mac's.
    private var fallbackRule: UriMatchRule {
        model.matchSettings?.fallback(folderID: draft.folderId) ?? .domain
    }

    private func matchBinding(_ index: Int) -> Binding<UriMatchRule?> {
        Binding(
            get: { draft.login?.matchRule(at: index) },
            set: { draft.login?.setMatchRule($0, at: index) })
    }

    private var notesBinding: Binding<String> {
        Binding(
            get: { draft.notes ?? "" },
            set: { draft.notes = $0.isEmpty ? nil : $0 })
    }
}

/// Generator: password (length, digits, symbols) or passphrase (words drawn
/// from a list of 7,776, separator, capitals, digit); colored preview and
/// strength. `use` receives the value and, for a passphrase, its exact
/// entropy.
struct GeneratorView: View {
    @Environment(AppModel.self) private var model
    var uri: String?
    var useAlias: ((String) -> Void)?
    let use: (String, Double?) -> Void
    @AppStorage("generatorMode") private var mode = GeneratorMode.password
    @AppStorage("generatorLength") private var length = 20.0
    @AppStorage("generatorDigits") private var digits = true
    @AppStorage("generatorSymbols") private var symbols = true
    @AppStorage("generatorWords") private var words = 5.0
    @AppStorage("generatorSeparator") private var separator = PassphraseSeparatorChoice.hyphen
    @AppStorage("generatorCapitalize") private var capitalize = false
    @AppStorage("generatorNumber") private var number = false
    @AppStorage("generatorLanguage") private var language = PassphraseLanguageChoice.french
    @State private var password = ""
    @State private var bits: Double?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Generator").font(.headline)
            Picker("Type", selection: shownMode) {
                ForEach(GeneratorMode.available(alias: aliasAvailable), id: \.self) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            PasswordText(value: password, size: 14)
                .lineLimit(6)
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            switch shownMode.wrappedValue {
            case .password:
                StrengthMeter(password: password, bits: bits)
                passwordOptions
            case .passphrase:
                StrengthMeter(password: password, bits: bits)
                passphraseOptions
            case .alias: aliasOptions
            }
            HStack {
                Button {
                    regenerate()
                } label: {
                    Label("Another", systemImage: "arrow.clockwise")
                }
                Spacer()
                Button(shownMode.wrappedValue == .alias ? LocalizedStringKey("Use as Username") : LocalizedStringKey("Use")) {
                    if shownMode.wrappedValue == .alias {
                        useAlias?(password)
                    } else {
                        use(password, bits)
                    }
                }
                .disabled(password.isEmpty)
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(16)
        .frame(width: 360)
        .onAppear(perform: regenerate)
        .onChange(of: mode) { regenerate() }
        .onChange(of: length) { regenerate() }
        .onChange(of: digits) { regenerate() }
        .onChange(of: symbols) { regenerate() }
        .onChange(of: words) { regenerate() }
        .onChange(of: separator) { regenerate() }
        .onChange(of: capitalize) { regenerate() }
        .onChange(of: number) { regenerate() }
        .onChange(of: language) { regenerate() }
        .onChange(of: model.aliasSettings?.includeSite) { regenerate() }
    }

    private var aliasAvailable: Bool { useAlias != nil && model.aliasEnabled }

    private var shownMode: Binding<GeneratorMode> {
        Binding(get: { mode == .alias && !aliasAvailable ? .password : mode },
                set: { mode = $0 })
    }

    @ViewBuilder private var aliasOptions: some View {
        Toggle("Start with the site's name", isOn: Binding(
            get: { model.aliasSettings?.includeSite ?? true },
            set: { try? model.setAliasSettings(domain: model.aliasSettings?.domain, includeSite: $0) }))
        LabeledContent("Alias domain", value: model.aliasSettings?.domain ?? "")
    }

    @ViewBuilder private var passwordOptions: some View {
        HStack {
            Text("Length")
            Slider(value: $length, in: 8...64, step: 1)
            Text("\(Int(length))").monospacedDigit().frame(width: 24, alignment: .trailing)
        }
        Toggle("Digits", isOn: $digits)
        Toggle("Symbols", isOn: $symbols)
    }

    @ViewBuilder private var passphraseOptions: some View {
        HStack {
            Text("Words")
            Slider(value: $words, in: 3...20, step: 1)
            Text("\(Int(words))").monospacedDigit().frame(width: 24, alignment: .trailing)
        }
        Picker("Separator", selection: $separator) {
            ForEach(PassphraseSeparatorChoice.allCases, id: \.self) { Text($0.label).tag($0) }
        }
        Picker("Language", selection: $language) {
            ForEach(PassphraseLanguageChoice.allCases, id: \.self) { Text($0.label).tag($0) }
        }
        Toggle("Capitals", isOn: $capitalize)
        Toggle("Add a digit", isOn: $number)
    }

    private func regenerate() {
        switch shownMode.wrappedValue {
        case .password:
            password = generatePassword(length: UInt32(length), digits: digits, symbols: symbols)
            bits = nil
        case .passphrase:
            let phrase = generatePassphrase(settings: PassphraseSettings(
                words: UInt32(words), separator: separator.ffi, capitalize: capitalize,
                includeNumber: number, language: language.ffi))
            password = phrase.value
            bits = phrase.entropyBits
        case .alias:
            password = model.emailAlias(for: uri) ?? ""
            bits = nil
        }
    }
}
