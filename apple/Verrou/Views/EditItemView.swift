import SwiftUI

/// Création ou modification d'un élément. Pour un identifiant : titre,
/// identifiant, mot de passe (avec le générateur), code à usage unique,
/// sites. Pour les autres types, seuls le titre, le dossier, le favori et les
/// notes se modifient ici ; le reste de l'élément repart tel quel.
struct EditItemView: View {
    @Environment(AppModel.self) private var model
    let editor: AppModel.Editor
    @State private var draft: ItemDraft
    @State private var showPassword = false
    @State private var showGenerator = false
    @State private var confirmTrash = false
    @FocusState private var titleFocused: Bool

    init(editor: AppModel.Editor) {
        self.editor = editor
        _draft = State(initialValue: editor.draft)
    }

    private var isNew: Bool { editor.itemID == nil }
    private var isLogin: Bool { draft.login != nil }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Titre", text: $draft.name, prompt: Text(isLogin ? "GitHub, Banque…" : "Digicode, Wi-Fi…"))
                        .focused($titleFocused)
                        .accessibilityIdentifier("edit-title")
                    if isLogin {
                        TextField("Identifiant", text: loginText(\.username), prompt: Text("e-mail ou nom d'utilisateur"))
                            .textContentType(.username)
                        passwordRow
                        if let password = draft.login?.password, !password.isEmpty {
                            StrengthMeter(password: password)
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
                    .disabled(draft.name.trimmingCharacters(in: .whitespaces).isEmpty || model.editorBusy)
            }
            .padding(16)
        }
        .frame(width: 540)
        .frame(minHeight: isLogin ? 600 : 420)
        .navigationTitle(isNew ? (isLogin ? "Nouvel identifiant" : "Nouvelle note sécurisée") : "Modifier")
        .onAppear { titleFocused = isNew }
        .confirmationDialog("Mettre « \(draft.name) » à la corbeille ?", isPresented: $confirmTrash) {
            Button("Mettre à la corbeille", role: .destructive) {
                if let id = editor.itemID { Task { await model.trash(id) } }
            }
        } message: {
            Text("L'élément reste restaurable depuis le coffre web pendant 30 jours.")
        }
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
            .help("Générer un mot de passe")
            .popover(isPresented: $showGenerator, arrowEdge: .trailing) {
                GeneratorView { password in
                    draft.login?.password = password
                    showPassword = true
                    showGenerator = false
                }
            }
        }
    }

    private func save() {
        // Les sites laissés vides ne partent pas.
        draft.login?.urls.removeAll { $0.trimmingCharacters(in: .whitespaces).isEmpty }
        Task { await model.saveEditor(draft) }
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

/// Générateur de mots de passe : longueur, chiffres, symboles ; aperçu coloré.
struct GeneratorView: View {
    let use: (String) -> Void
    @AppStorage("generatorLength") private var length = 20.0
    @AppStorage("generatorDigits") private var digits = true
    @AppStorage("generatorSymbols") private var symbols = true
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Générateur").font(.headline)
            PasswordText(value: password, size: 14)
                .lineLimit(3)
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            StrengthMeter(password: password)
            HStack {
                Text("Longueur")
                Slider(value: $length, in: 8...64, step: 1)
                Text("\(Int(length))").monospacedDigit().frame(width: 24, alignment: .trailing)
            }
            Toggle("Chiffres", isOn: $digits)
            Toggle("Symboles", isOn: $symbols)
            HStack {
                Button {
                    regenerate()
                } label: {
                    Label("Autre", systemImage: "arrow.clockwise")
                }
                Spacer()
                Button("Utiliser") { use(password) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(16)
        .frame(width: 340)
        .onAppear(perform: regenerate)
        .onChange(of: length) { regenerate() }
        .onChange(of: digits) { regenerate() }
        .onChange(of: symbols) { regenerate() }
    }

    private func regenerate() {
        password = generatePassword(length: UInt32(length), digits: digits, symbols: symbols)
    }
}

/// Robustesse estimée (entropie) : barre et mot.
struct StrengthMeter: View {
    let password: String

    var body: some View {
        let bits = passwordStrength(password: password)
        let (label, color, fraction) = Self.grade(bits)
        HStack(spacing: 10) {
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(.quaternary)
                    Capsule().fill(color).frame(width: proxy.size.width * fraction)
                }
            }
            .frame(height: 5)
            Text("\(label) · \(Int(bits)) bits")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
                .fixedSize()
        }
        .animation(.snappy, value: fraction)
    }

    static func grade(_ bits: Double) -> (String, Color, Double) {
        switch bits {
        case ..<40: ("Faible", .red, 0.2)
        case ..<60: ("Moyen", .orange, 0.45)
        case ..<80: ("Bon", .yellow, 0.7)
        case ..<100: ("Fort", .green, 0.88)
        default: ("Excellent", .green, 1)
        }
    }
}
