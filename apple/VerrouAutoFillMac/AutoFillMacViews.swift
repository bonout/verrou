import SwiftUI

/// L'interface de l'extension sur le Mac : la feuille que macOS ouvre
/// au-dessus de Safari ou de l'app (440 × 540). Même modèle que l'iPhone
/// (`AutoFillModel`) : déverrouillage (Touch ID, sinon mot de passe
/// principal), puis la liste ou la création de passkey.
struct AutoFillRootView: View {
    @Environment(AutoFillModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            header
            Divider()
            Group {
                switch model.phase {
                case .noAccount:
                    MacNoAccountView()
                case .locked, .unlocking:
                    MacLockView()
                case .ready, .working:
                    content
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 400, minHeight: 460)
        .tint(Theme.accent)
        .sheet(item: $model.confirmation) { _ in
            MacConfirmationSheet()
        }
        .alert("Verrou", isPresented: Binding(get: { model.actionError != nil },
                                              set: { if !$0 { model.actionError = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.actionError ?? "")
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            AppMark(size: 28, glow: false)
            VStack(alignment: .leading, spacing: 1) {
                Text(model.title).font(.headline)
                if let site = model.site {
                    Text(site).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button("Annuler") { model.cancel() }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    @ViewBuilder private var content: some View {
        switch model.request {
        case .register:
            MacPasskeyRegistrationView()
        case .provide:
            MacWorkingView(label: "Remplissage…")
        case .list, .oneTimeCodes:
            if model.phase == .working {
                MacWorkingView(label: "Signature…")
            } else {
                MacCredentialListView()
            }
        case .none:
            VStack(spacing: 12) {
                AppMark(size: 56, glow: false)
                Text("Verrou remplit vos identifiants, codes et passkeys dans Safari et les apps du Mac.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            .padding(24)
        }
    }
}

private struct MacWorkingView: View {
    let label: String

    var body: some View {
        VStack(spacing: 12) {
            ProgressView().controlSize(.small)
            Text(label).foregroundStyle(.secondary)
        }
    }
}

private struct MacNoAccountView: View {
    var body: some View {
        VStack(spacing: 14) {
            AppMark(size: 56)
            Text("Aucun coffre partagé sur ce Mac")
                .font(.title3.weight(.semibold))
            Text("Ouvrez Verrou et connectez-vous à votre serveur Vaultwarden : vos identifiants seront alors proposés ici. L'app doit être un build signé par votre équipe de développeur (voir le guide).")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(28)
    }
}

// MARK: Déverrouillage

private struct MacLockView: View {
    @Environment(AutoFillModel.self) private var model
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        ZStack {
            LockBackground()
            VStack(spacing: 18) {
                AppMark(size: 64)
                VStack(spacing: 4) {
                    Text("Déverrouiller Verrou")
                        .font(.system(.title3, design: .rounded, weight: .bold))
                    if let account = model.account {
                        Text(account.email).font(.callout).foregroundStyle(.secondary)
                    }
                }
                if model.canUseBiometrics {
                    Button {
                        Task { await model.unlockWithBiometrics() }
                    } label: {
                        Label("Déverrouiller avec \(Biometrics.name)", systemImage: Biometrics.symbolName)
                            .frame(maxWidth: 260)
                    }
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .disabled(model.phase == .unlocking)
                }
                HStack(spacing: 8) {
                    SecureField("Mot de passe principal", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .focused($focused)
                        .onSubmit(submit)
                        .frame(maxWidth: 260)
                    if model.phase == .unlocking {
                        ProgressView().controlSize(.small)
                    }
                }
                .disabled(model.phase == .unlocking)
                if let error = model.unlockError {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 320)
                }
            }
            .padding(24)
        }
        .task {
            if !model.canUseBiometrics { focused = true }
            await model.autoUnlock()
        }
    }

    private func submit() {
        let typed = password
        password = ""
        Task { await model.unlock(masterPassword: typed) }
    }
}

// MARK: Liste

private struct MacCredentialListView: View {
    @Environment(AutoFillModel.self) private var model
    @FocusState private var searching: Bool

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            TextField("Rechercher dans le coffre", text: $model.query)
                .textFieldStyle(.roundedBorder)
                .focused($searching)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
            List {
                if model.query.isEmpty {
                    if !model.passkeys.isEmpty {
                        Section("Passkeys") {
                            ForEach(model.passkeys, id: \.credentialId) { passkey in
                                Button { model.choose(passkey) } label: {
                                    MacSymbolRow(title: passkey.userName, subtitle: "Passkey · \(passkey.rpId)",
                                                 symbol: "person.badge.key.fill", protected: passkey.reprompt)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    Section(model.site.map { "Pour \($0)" } ?? "Suggestions") {
                        if model.matches.isEmpty {
                            Text("Aucun identifiant pour ce site : cherchez dans le coffre.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(model.matches, id: \.id) { item in itemButton(item) }
                    }
                    Section("Tout le coffre") {
                        ForEach(model.everything.prefix(100), id: \.id) { item in itemButton(item) }
                    }
                } else {
                    Section("Résultats") {
                        let results = model.searchResults
                        if results.isEmpty {
                            Text("Aucun résultat").foregroundStyle(.secondary)
                        }
                        ForEach(results, id: \.id) { item in itemButton(item) }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    private func itemButton(_ item: ItemSummary) -> some View {
        Button { model.choose(item) } label: {
            ItemRowContent(summary: item, highlights: [], spacing: 10, subtitleFont: .caption,
                           showsProtection: true) {
                ItemIconContent(summary: item, image: nil, size: 28)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

private struct MacSymbolRow: View {
    let title: String
    let subtitle: String
    let symbol: String
    var protected = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 28, height: 28)
                .background(Theme.accent.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(title)
                    if protected {
                        Image(systemName: "lock.shield").font(.caption).foregroundStyle(.orange)
                    }
                }
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .contentShape(Rectangle())
    }
}

// MARK: Création de passkey

private struct MacPasskeyRegistrationView: View {
    @Environment(AutoFillModel.self) private var model

    var body: some View {
        VStack(spacing: 16) {
            VStack(spacing: 8) {
                Image(systemName: model.passkeyCreated ? "checkmark" : "person.badge.key.fill")
                    .font(.system(size: 26, weight: .semibold))
                    .foregroundStyle(.white)
                    .contentTransition(.symbolEffect(.replace))
                    .frame(width: 56, height: 56)
                    .background((model.passkeyCreated ? Color.green : Theme.accent).gradient,
                                in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                    .animation(.snappy(duration: 0.3), value: model.passkeyCreated)
                Text(model.passkeyCreated ? "Passkey enregistrée" : "Nouvelle passkey pour \(model.site ?? "ce site")")
                    .font(.headline)
                Text("Elle est enregistrée dans votre coffre Vaultwarden, au format de Bitwarden : vos autres appareils la retrouvent.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 16)
            .padding(.horizontal, 24)
            List {
                Section {
                    Button { model.register(into: nil) } label: {
                        Label("Nouvel identifiant", systemImage: "plus.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .disabled(model.phase == .working)
                }
                if !model.targets.isEmpty {
                    Section {
                        ForEach(model.targets, id: \.id) { item in
                            Button { model.register(into: item) } label: {
                                ItemRowContent(summary: item, highlights: [], spacing: 10, subtitleFont: .caption) {
                                    ItemIconContent(summary: item, image: nil, size: 28)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .disabled(model.phase == .working)
                        }
                    } header: {
                        Text("Ajouter à un identifiant")
                    } footer: {
                        Text("Un identifiant porte une passkey : celle qu'il avait est remplacée.")
                    }
                }
            }
            .listStyle(.inset)
            if model.phase == .working, !model.passkeyCreated {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Enregistrement sur le serveur…").foregroundStyle(.secondary)
                }
                .padding(.bottom, 12)
            }
        }
    }
}

// MARK: Élément protégé

private struct MacConfirmationSheet: View {
    @Environment(AutoFillModel.self) private var model
    @State private var password = ""

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 30))
                .foregroundStyle(.orange)
            Text("« \(model.confirmation?.title ?? "") » est protégé")
                .font(.headline)
                .multilineTextAlignment(.center)
            Text("Confirmez avec \(Biometrics.name) ou votre mot de passe principal.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if Biometrics.isAvailable {
                Button {
                    Task { await model.confirmWithBiometrics() }
                } label: {
                    Label("Confirmer avec \(Biometrics.name)", systemImage: Biometrics.symbolName)
                }
                .buttonStyle(.borderedProminent)
            }
            SecureField("Mot de passe principal", text: $password)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    let typed = password
                    password = ""
                    Task { await model.confirm(masterPassword: typed) }
                }
            Button("Annuler", role: .cancel) { model.confirmation = nil }
                .keyboardShortcut(.cancelAction)
        }
        .padding(24)
        .frame(width: 340)
    }
}
