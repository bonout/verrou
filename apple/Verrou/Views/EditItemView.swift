import SwiftUI

/// Création ou modification d'un élément. Pour un identifiant : titre,
/// identifiant, mot de passe (avec le générateur), code à usage unique,
/// sites. Pour tous les types : titre, champs personnalisés, dossier, favori
/// et notes ; le reste de l'élément (carte, identité, champs réservés à
/// Verrou…) repart tel quel. Un modèle (Wi-Fi, passeport…) arrive avec ses
/// champs prédéfinis.
struct EditItemView: View {
    @Environment(AppModel.self) private var model
    let editor: AppModel.Editor
    @State private var draft: ItemDraft
    /// Création : coffre personnel (`nil`) ou collection d'une organisation.
    @State private var destination: SharedDestination?
    @State private var showPassword = false
    @State private var showGenerator = false
    /// Entropie exacte de la dernière phrase de passe générée : les
    /// caractères la surestimeraient de beaucoup.
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
                    TextField("Titre", text: $draft.name, prompt: Text(titlePrompt))
                        .focused($titleFocused)
                        .layoutMark("edit-title")
                    if isLogin {
                        TextField("Identifiant", text: loginText(\.username), prompt: Text("e-mail ou nom d'utilisateur"))
                            .textContentType(.username)
                        passwordRow
                        if let password = draft.login?.password, !password.isEmpty {
                            StrengthMeter(password: password, bits: generated?.value == password ? generated?.bits : nil)
                        }
                        TextField("Code à usage unique", text: loginText(\.totp), prompt: Text("graine ou lien otpauth://"))
                    }
                }

                if isLogin {
                    Section("Sites") {
                        ForEach(Array((draft.login?.urls ?? []).indices), id: \.self) { index in
                            HStack {
                                TextField("Site", text: urlBinding(index), prompt: Text("https://exemple.fr"))
                                    .labelsHidden()
                                Button {
                                    draft.login?.urls.remove(at: index)
                                } label: {
                                    Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                                }
                                .buttonStyle(.plain)
                                .help("Retirer ce site")
                            }
                        }
                        Button {
                            draft.login?.urls.append("")
                        } label: {
                            Label("Ajouter un site", systemImage: "plus.circle.fill")
                        }
                        .buttonStyle(.borderless)
                    }
                }

                vaultSection
                CustomFieldsSection(fields: $draft.fields)

                Section {
                    Picker("Dossier", selection: $draft.folderId) {
                        Text("Aucun").tag(String?.none)
                        ForEach(model.folders, id: \.id) { folder in
                            Text(folder.name).tag(Optional(folder.id))
                        }
                    }
                    Toggle("Favori", isOn: $draft.favorite)
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
                    Button("Mettre à la corbeille…", role: .destructive) { confirmTrash = true }
                        .disabled(model.editorBusy)
                }
                Spacer()
                if model.editorBusy {
                    ProgressView().controlSize(.small)
                }
                Button("Annuler") { model.editor = nil }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Créer" : "Enregistrer") { save() }
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
        .confirmationDialog("Mettre « \(draft.name) » à la corbeille ?", isPresented: $confirmTrash) {
            Button("Mettre à la corbeille", role: .destructive) {
                if let id = editor.itemID { Task { await model.trash(id) } }
            }
        } message: {
            Text("L'élément reste restaurable depuis le coffre web pendant 30 jours.")
        }
    }

    /// Coffre de l'élément : choisi à la création, rappelé ensuite (les
    /// collections se changent par « Collections… »).
    @ViewBuilder private var vaultSection: some View {
        if isNew, !model.writableOrganizations.isEmpty {
            Section {
                Picker("Coffre", selection: $destination) {
                    Text("Personnel").tag(SharedDestination?.none)
                    ForEach(model.writableOrganizations, id: \.id) { org in
                        ForEach(org.collections.filter { !$0.readOnly }, id: \.id) { collection in
                            Text("\(org.name) › \(collection.name)")
                                .tag(Optional(SharedDestination(organizationID: org.id, collectionIDs: [collection.id])))
                        }
                    }
                }
            } footer: {
                if destination != nil {
                    Text("Chiffré avec la clé de l'organisation : les membres de la collection le verront.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        } else if let id = editor.itemID, let sharing = model.summaries.first(where: { $0.id == id })?.sharing {
            Section {
                LabeledContent("Coffre partagé", value: sharing.label)
            }
        }
    }

    private var titlePrompt: String {
        if let template = draft.template { return template.titlePrompt }
        return isLogin ? "GitHub, Banque…" : "Digicode, Wi-Fi…"
    }

    private var windowTitle: String {
        guard isNew else { return "Modifier" }
        if let template = draft.template { return "Nouveau : \(template.singular)" }
        return isLogin ? "Nouvel identifiant" : "Nouvelle note sécurisée"
    }

    private var passwordRow: some View {
        HStack(spacing: 8) {
            Group {
                if showPassword {
                    TextField("Mot de passe", text: loginText(\.password))
                        .font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Mot de passe", text: loginText(\.password))
                }
            }
            .textContentType(.password)
            Button {
                showPassword.toggle()
            } label: {
                Image(systemName: showPassword ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(showPassword ? "Masquer" : "Afficher")
            Button {
                showGenerator = true
            } label: {
                Image(systemName: "wand.and.stars")
            }
            .buttonStyle(.borderless)
            .help("Générer un mot de passe ou une phrase de passe")
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

    private func save() {
        // Les sites laissés vides ne partent pas.
        draft.login?.urls.removeAll { $0.trimmingCharacters(in: .whitespaces).isEmpty }
        // Un champ ajouté puis laissé sans nom ni valeur ne part pas.
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

    private var notesBinding: Binding<String> {
        Binding(
            get: { draft.notes ?? "" },
            set: { draft.notes = $0.isEmpty ? nil : $0 })
    }
}

/// Générateur : mot de passe (longueur, chiffres, symboles) ou phrase de
/// passe (mots tirés dans une liste de 7 776, séparateur, majuscules,
/// chiffre) ; aperçu coloré et robustesse. `use` reçoit la valeur et, pour
/// une phrase de passe, son entropie exacte.
struct GeneratorView: View {
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
            Text("Générateur").font(.headline)
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
                    Label("Autre", systemImage: "arrow.clockwise")
                }
                Spacer()
                Button("Utiliser") { use(password, bits) }
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
    }

    @ViewBuilder private var passwordOptions: some View {
        HStack {
            Text("Longueur")
            Slider(value: $length, in: 8...64, step: 1)
            Text("\(Int(length))").monospacedDigit().frame(width: 24, alignment: .trailing)
        }
        Toggle("Chiffres", isOn: $digits)
        Toggle("Symboles", isOn: $symbols)
    }

    @ViewBuilder private var passphraseOptions: some View {
        HStack {
            Text("Mots")
            Slider(value: $words, in: 3...20, step: 1)
            Text("\(Int(words))").monospacedDigit().frame(width: 24, alignment: .trailing)
        }
        Picker("Séparateur", selection: $separator) {
            ForEach(PassphraseSeparatorChoice.allCases, id: \.self) { Text($0.label).tag($0) }
        }
        Picker("Langue", selection: $language) {
            ForEach(PassphraseLanguageChoice.allCases, id: \.self) { Text($0.label).tag($0) }
        }
        Toggle("Majuscules", isOn: $capitalize)
        Toggle("Ajouter un chiffre", isOn: $number)
    }

    private func regenerate() {
        switch mode {
        case .password:
            password = generatePassword(length: UInt32(length), digits: digits, symbols: symbols)
            bits = nil
        case .passphrase:
            let phrase = generatePassphrase(settings: PassphraseSettings(
                words: UInt32(words), separator: separator.ffi, capitalize: capitalize,
                includeNumber: number, language: language.ffi))
            password = phrase.value
            bits = phrase.entropyBits
        }
    }
}
