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
    @State private var confirmDiscard = false
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
                        TextField("Username", text: loginText(\.username), prompt: Text("email or username"))
                            .textContentType(.username)
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
                Button("Cancel") { cancel() }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Create" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .layoutMark("sheet-primary")
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
        .frame(width: 540)
        .frame(minHeight: isLogin ? 640 : 520, maxHeight: 700)
        .navigationTitle(windowTitle)
        .onAppear { titleFocused = isNew }
        .onChange(of: draft, initial: true) { _, value in model.editorDraft = value }
        .onChange(of: destination, initial: true) { _, value in model.editorDestination = value }
        .onChange(of: showPassword) { _, shown in model.setSecretShown("editor", shown) }
        .onDisappear {
            model.editorDraft = nil
            model.editorDestination = nil
            model.setSecretShown("editor", false)
        }
        .interactiveDismissDisabled(changed)
        .announcing(model.editorError)
        .confirmationDialog("Discard your changes?", isPresented: $confirmDiscard) {
            Button("Discard Changes", role: .destructive) { model.editor = nil }
            Button("Keep Editing", role: .cancel) {}
        } message: {
            Text(isNew ? "This item hasn't been created yet." : "Your changes to this item will be lost.")
        }
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
                GeneratorView { password, bits in
                    draft.login?.password = password
                    generated = bits.map { (password, $0) }
                    showPassword = true
                    showGenerator = false
                }
            }
        }
    }

    private var canSave: Bool {
        !draft.name.trimmingCharacters(in: .whitespaces).isEmpty && !model.editorBusy
    }

    private var changed: Bool {
        draft != editor.baseline || destination != editor.destination
    }

    private func cancel() {
        if changed {
            confirmDiscard = true
        } else {
            model.editor = nil
        }
    }

    private func save() {
        guard canSave else { return }
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
    var use: ((String, Double?) -> Void)?
    var copy: ((String) -> Void)?
    var showsTitle = true
    @AppStorage("generatorMode") private var mode = GeneratorMode.password
    @AppStorage("generatorLength") private var length = 20.0
    @AppStorage("generatorDigits") private var digits = true
    @AppStorage("generatorSymbols") private var symbols = true
    @AppStorage("generatorWords") private var words = 5.0
    @AppStorage("generatorSeparator") private var separator = PassphraseSeparatorChoice.hyphen
    @AppStorage("generatorCapitalize") private var capitalize = false
    @AppStorage("generatorNumber") private var number = false
    @AppStorage("generatorLanguage") private var language = PassphraseLanguageChoice.preferred
    @State private var password = ""
    @State private var bits: Double?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if showsTitle {
                Text("Generator").font(.headline)
            }
            Picker("Type", selection: $mode) {
                ForEach(GeneratorMode.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            PasswordText(value: password, size: 14)
                .lineLimit(6)
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            StrengthMeter(password: password, bits: bits)
            switch mode {
            case .password: passwordOptions
            case .passphrase: passphraseOptions
            }
            HStack {
                Button {
                    regenerate()
                } label: {
                    Label("Regenerate", systemImage: "arrow.clockwise")
                }
                Spacer()
                if let copy {
                    if use == nil {
                        Button("Copy") { copy(password) }
                            .keyboardShortcut(.defaultAction)
                            .buttonStyle(.borderedProminent)
                    } else {
                        Button("Copy") { copy(password) }
                    }
                }
                if let use {
                    Button("Use") { use(password, bits) }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                }
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
        let settings = GeneratorSettings(mode: mode, length: length, digits: digits, symbols: symbols, words: words,
                                         separator: separator, capitalize: capitalize, number: number,
                                         language: language)
        (password, bits) = settings.generate()
    }
}
