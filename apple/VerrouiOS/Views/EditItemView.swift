import SwiftUI

/// Création ou modification d'un élément : identifiant (avec le
/// générateur), note, carte, identité, modèle ; pour tous : champs
/// personnalisés, dossier, favori et notes. Le reste de l'élément (passkeys,
/// pièces jointes, champs réservés à Verrou) repart tel quel.
struct EditItemView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let editor: PhoneModel.Editor
    @State private var draft: ItemDraft
    @State private var destination: SharedDestination?
    @State private var showPassword = false
    @State private var showGenerator = false
    /// Entropie exacte de la dernière phrase de passe générée.
    @State private var generated: (value: String, bits: Double)?
    @State private var confirmTrash = false
    @FocusState private var titleFocused: Bool

    init(editor: PhoneModel.Editor) {
        self.editor = editor
        _draft = State(initialValue: editor.draft)
        _destination = State(initialValue: editor.destination)
    }

    private var isNew: Bool { editor.itemID == nil }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Titre", text: $draft.name, prompt: Text(titlePrompt))
                        .font(.headline)
                        .focused($titleFocused)
                        .accessibilityIdentifier("edit-title")
                }
                if draft.login != nil { loginSections }
                if draft.card != nil { cardSection }
                if draft.identity != nil { identitySections }
                vaultSection
                PhoneCustomFieldsSection(fields: $draft.fields)
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
                    TextField("Notes", text: optionalText(\.notes), axis: .vertical)
                        .lineLimit(3...12)
                }
                if let error = model.editorError {
                    Section { ErrorLabel(text: error) }
                }
                if !isNew {
                    Section {
                        Button("Mettre à la corbeille…", role: .destructive) { confirmTrash = true }
                            .disabled(model.editorBusy)
                    }
                }
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle(windowTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { model.editor = nil }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if model.editorBusy {
                        ProgressView()
                    } else {
                        Button(isNew ? "Créer" : "Enregistrer") { save() }
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
                })
                .presentationDetents([.medium, .large])
            }
            .confirmationDialog("Mettre « \(draft.name) » à la corbeille ?", isPresented: $confirmTrash,
                                titleVisibility: .visible) {
                Button("Mettre à la corbeille", role: .destructive) {
                    if let id = editor.itemID { Task { await model.trash(id) } }
                }
            } message: {
                Text("L'élément reste restaurable depuis la corbeille pendant 30 jours.")
            }
            .onAppear { titleFocused = isNew }
        }
    }

    // MARK: Identifiant

    @ViewBuilder private var loginSections: some View {
        Section {
            TextField("Identifiant", text: loginText(\.username), prompt: Text("e-mail ou nom d'utilisateur"))
                .textContentType(.username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            HStack(spacing: 10) {
                Group {
                    if showPassword {
                        TextField("Mot de passe", text: loginText(\.password))
                            .font(.system(.body, design: .monospaced))
                    } else {
                        SecureField("Mot de passe", text: loginText(\.password))
                    }
                }
                .textContentType(.newPassword)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                Button {
                    showPassword.toggle()
                } label: {
                    Image(systemName: showPassword ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(showPassword ? "Masquer" : "Afficher")
                Button {
                    showGenerator = true
                } label: {
                    Image(systemName: "wand.and.stars")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Générer un mot de passe")
            }
            if let password = draft.login?.password, !password.isEmpty {
                StrengthMeter(password: password, bits: generated?.value == password ? generated?.bits : nil)
            }
            TextField("Code à usage unique", text: loginText(\.totp), prompt: Text("graine ou lien otpauth://"))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        } header: {
            Text("Identifiant")
        }
        Section("Sites") {
            ForEach(Array((draft.login?.urls ?? []).indices), id: \.self) { index in
                TextField("https://exemple.fr", text: urlBinding(index))
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            .onDelete { draft.login?.urls.remove(atOffsets: $0) }
            Button("Ajouter un site", systemImage: "plus.circle.fill") { draft.login?.urls.append("") }
        }
    }

    // MARK: Carte

    @ViewBuilder private var cardSection: some View {
        Section("Carte") {
            TextField("Titulaire", text: cardText(\.cardholderName))
                .textContentType(.name)
                .textInputAutocapitalization(.characters)
            Picker("Réseau", selection: cardText(\.brand)) {
                Text("Autre").tag("")
                ForEach(brands, id: \.self) { brand in
                    Text(brand).tag(brand)
                }
            }
            TextField("Numéro", text: cardText(\.number))
                .keyboardType(.numberPad)
                .textContentType(.creditCardNumber)
                .font(.system(.body, design: .monospaced))
            LabeledContent("Expiration") {
                HStack(spacing: 6) {
                    Picker("Mois", selection: cardText(\.expMonth)) {
                        Text("Mois").tag("")
                        ForEach(1...12, id: \.self) { month in Text(String(format: "%02d", month)).tag("\(month)") }
                    }
                    .labelsHidden()
                    .fixedSize()
                    Text("/").foregroundStyle(.secondary)
                    TextField("Année", text: cardText(\.expYear))
                        .keyboardType(.numberPad)
                        .frame(width: 60)
                }
            }
            SecureField("Cryptogramme", text: cardText(\.code))
                .keyboardType(.numberPad)
        }
    }

    /// Réseaux proposés, plus celui de la carte s'il n'y figure pas.
    private var brands: [String] {
        let known = ["Visa", "Mastercard", "Amex", "Discover", "Diners Club", "JCB", "Maestro", "UnionPay", "RuPay"]
        guard let current = draft.card?.brand, !current.isEmpty, !known.contains(current) else { return known }
        return known + [current]
    }

    // MARK: Identité

    @ViewBuilder private var identitySections: some View {
        Section("Identité") {
            TextField("Civilité", text: identityText(\.title))
            TextField("Prénom", text: identityText(\.firstName)).textContentType(.givenName)
            TextField("Deuxième prénom", text: identityText(\.middleName)).textContentType(.middleName)
            TextField("Nom", text: identityText(\.lastName)).textContentType(.familyName)
            TextField("Société", text: identityText(\.company)).textContentType(.organizationName)
        }
        Section("Contact") {
            TextField("E-mail", text: identityText(\.email))
                .keyboardType(.emailAddress).textContentType(.emailAddress).textInputAutocapitalization(.never)
            TextField("Téléphone", text: identityText(\.phone)).keyboardType(.phonePad).textContentType(.telephoneNumber)
            TextField("Nom d'utilisateur", text: identityText(\.username)).textInputAutocapitalization(.never)
        }
        Section("Adresse") {
            TextField("Adresse", text: identityText(\.address1)).textContentType(.streetAddressLine1)
            TextField("Complément", text: identityText(\.address2)).textContentType(.streetAddressLine2)
            TextField("Complément (suite)", text: identityText(\.address3))
            TextField("Code postal", text: identityText(\.postalCode)).textContentType(.postalCode)
            TextField("Ville", text: identityText(\.city)).textContentType(.addressCity)
            TextField("Région", text: identityText(\.state)).textContentType(.addressState)
            TextField("Pays", text: identityText(\.country)).textContentType(.countryName)
        }
        Section("Documents") {
            SecureField("N° de sécurité sociale", text: identityText(\.ssn))
            SecureField("N° de passeport", text: identityText(\.passportNumber))
            SecureField("N° de permis de conduire", text: identityText(\.licenseNumber))
        }
    }

    // MARK: Coffre

    /// Coffre de l'élément : choisi à la création, rappelé ensuite.
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
                }
            }
        } else if let id = editor.itemID, let sharing = model.summary(id: id)?.sharing {
            Section {
                LabeledContent("Coffre partagé", value: sharing.organization)
            }
        }
    }

    private var titlePrompt: String {
        if let template = draft.template { return template.titlePrompt }
        if draft.login != nil { return "GitHub, Banque…" }
        if draft.card != nil { return "Visa perso" }
        if draft.identity != nil { return "Moi" }
        return "Digicode, code du portail…"
    }

    private var windowTitle: String {
        guard isNew else { return "Modifier" }
        if let template = draft.template { return template.singular }
        if draft.login != nil { return "Nouvel identifiant" }
        if draft.card != nil { return "Nouvelle carte" }
        if draft.identity != nil { return "Nouvelle identité" }
        return "Nouvelle note"
    }

    private func save() {
        // Les sites laissés vides ne partent pas, ni les champs sans nom ni valeur.
        draft.login?.urls.removeAll { $0.trimmingCharacters(in: .whitespaces).isEmpty }
        draft.fields.removeAll { $0.name.trimmingCharacters(in: .whitespaces).isEmpty && ($0.value ?? "").isEmpty
            && $0.fieldType != .linked }
        // Le numéro de carte s'enregistre sans espaces.
        if let number = draft.card?.number {
            draft.card?.number = number.filter { !$0.isWhitespace }
        }
        let toSave = draft
        Task { await model.saveEditor(toSave, destination: isNew ? destination : nil) }
    }

    // MARK: Liaisons

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

    private func urlBinding(_ index: Int) -> Binding<String> {
        Binding(get: { draft.login?.urls.indices.contains(index) == true ? draft.login!.urls[index] : "" },
                set: { if draft.login?.urls.indices.contains(index) == true { draft.login?.urls[index] = $0 } })
    }
}

/// Champs personnalisés : texte, masqué, case à cocher ; un champ lié se
/// montre et se déplace sans se modifier. Les champs réservés à Verrou
/// n'arrivent jamais ici (le cœur Rust les garde de côté).
private struct PhoneCustomFieldsSection: View {
    @Binding var fields: [CustomField]
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
                Button("Texte", systemImage: "textformat") { add(.text) }
                Button("Masqué", systemImage: "eye.slash") { add(.hidden) }
                Button("Case à cocher", systemImage: "checkmark.square") { add(.boolean) }
            } label: {
                Label("Ajouter un champ", systemImage: "plus.circle.fill")
            }
        } header: {
            Text("Champs personnalisés")
        } footer: {
            if !fields.isEmpty {
                Text("Balayez un champ vers la gauche pour le supprimer.")
            }
        }
    }

    @ViewBuilder private func row(_ index: Int) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("Nom du champ", text: nameBinding(index))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Menu {
                    Button("Monter", systemImage: "arrow.up") { move(index, by: -1) }
                        .disabled(index == 0)
                    Button("Descendre", systemImage: "arrow.down") { move(index, by: 1) }
                        .disabled(index == fields.count - 1)
                    Button("Supprimer", systemImage: "trash", role: .destructive) {
                        fields.remove(at: index)
                        shown.removeAll()
                    }
                } label: {
                    Image(systemName: "ellipsis.circle").foregroundStyle(.secondary)
                }
                .accessibilityLabel("Actions du champ")
            }
            value(index)
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder private func value(_ index: Int) -> some View {
        switch fields[index].fieldType {
        case .text:
            TextField("Valeur", text: valueBinding(index))
        case .hidden:
            HStack {
                if shown.contains(index) {
                    TextField("Valeur", text: valueBinding(index)).font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Valeur", text: valueBinding(index))
                }
                Button {
                    if shown.contains(index) { shown.remove(index) } else { shown.insert(index) }
                } label: {
                    Image(systemName: shown.contains(index) ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
            }
        case .boolean:
            Toggle("Coché", isOn: Binding(
                get: { fields.indices.contains(index) && fields[index].value == "true" },
                set: { if fields.indices.contains(index) { fields[index].value = $0 ? "true" : "false" } }))
        case .linked:
            Text("Champ lié (modifiable dans le coffre web)").foregroundStyle(.secondary)
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
        Binding(get: { fields.indices.contains(index) ? fields[index].name : "" },
                set: { if fields.indices.contains(index) { fields[index].name = $0 } })
    }

    private func valueBinding(_ index: Int) -> Binding<String> {
        Binding(get: { fields.indices.contains(index) ? fields[index].value ?? "" : "" },
                set: { if fields.indices.contains(index) { fields[index].value = $0.isEmpty ? nil : $0 } })
    }
}
