import SwiftUI

/// L'interface de l'extension : déverrouillage, puis la liste (ou la
/// création de passkey) ; une suggestion touchée n'affiche que le
/// déverrouillage avant de remplir.
struct AutoFillRootView: View {
    @Environment(AutoFillModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            Group {
                switch model.phase {
                case .noAccount:
                    NoAccountView()
                case .locked, .unlocking:
                    AutoFillLockView()
                case .ready, .working:
                    content
                }
            }
            .navigationTitle(model.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { model.cancel() }
                }
            }
        }
        .tint(Theme.accent)
        .sheet(item: $model.confirmation) { _ in
            ConfirmationSheet()
                .presentationDetents([.medium])
        }
        .alert("Verrou", isPresented: Binding(get: { model.actionError != nil }, set: { if !$0 { model.actionError = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.actionError ?? "")
        }
    }

    @ViewBuilder private var content: some View {
        switch model.request {
        case .register:
            PasskeyRegistrationView()
        case .provide:
            WorkingView(label: "Remplissage…")
        case .list, .oneTimeCodes:
            if model.phase == .working {
                WorkingView(label: "Signature…")
            } else {
                CredentialListView()
            }
        case .none:
            VStack(spacing: 12) {
                AppMark(size: 64)
                Text("Verrou remplit vos identifiants, codes et passkeys.")
                    .multilineTextAlignment(.center)
            }
            .padding()
        }
    }
}

private struct WorkingView: View {
    let label: String

    var body: some View {
        VStack(spacing: 14) {
            ProgressView()
            Text(label).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct NoAccountView: View {
    var body: some View {
        VStack(spacing: 16) {
            AppMark(size: 72)
            Text("Aucun coffre sur cet iPhone")
                .font(.title3.weight(.semibold))
            Text("Ouvrez l'app Verrou et connectez-vous à votre serveur Vaultwarden : vos identifiants seront alors proposés ici.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: Déverrouillage

private struct AutoFillLockView: View {
    @Environment(AutoFillModel.self) private var model
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 22) {
            Spacer(minLength: 12)
            AppMark(size: 72)
            VStack(spacing: 6) {
                Text("Déverrouiller Verrou")
                    .font(.title2.weight(.bold))
                if let site = model.site {
                    Text("pour \(site)").foregroundStyle(.secondary)
                }
                if let account = model.account {
                    Text(account.email).font(.footnote).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 12)
            VStack(spacing: 14) {
                if model.canUseBiometrics {
                    Button {
                        Task { await model.unlockWithBiometrics() }
                    } label: {
                        Label("Déverrouiller avec \(Biometrics.name)", systemImage: Biometrics.symbolName)
                            .font(.body.weight(.semibold))
                            .frame(maxWidth: .infinity, minHeight: 34)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(model.phase == .unlocking)
                }
                HStack(spacing: 8) {
                    SecureField("Mot de passe principal", text: $password)
                        .textContentType(.password)
                        .submitLabel(.go)
                        .focused($focused)
                        .onSubmit(submit)
                        .disabled(model.phase == .unlocking)
                    Button(action: submit) {
                        if model.phase == .unlocking {
                            ProgressView()
                        } else {
                            Image(systemName: "arrow.right.circle.fill")
                                .font(.title2)
                                .foregroundStyle(password.isEmpty ? Color.secondary : Theme.accent)
                        }
                    }
                    .disabled(password.isEmpty)
                    .accessibilityLabel("Déverrouiller")
                }
                .padding(.horizontal, 16)
                .frame(height: 52)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                if let error = model.unlockError {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                }
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 24)
        }
        .task { await model.autoUnlock() }
    }

    private func submit() {
        let typed = password
        password = ""
        focused = false
        Task { await model.unlock(masterPassword: typed) }
    }
}

// MARK: Liste

private struct CredentialListView: View {
    @Environment(AutoFillModel.self) private var model

    var body: some View {
        @Bindable var model = model
        List {
            if model.query.isEmpty {
                if !model.passkeys.isEmpty {
                    Section("Passkeys") {
                        ForEach(model.passkeys, id: \.credentialId) { passkey in
                            Button { model.choose(passkey) } label: {
                                Row(title: passkey.userName, subtitle: "Passkey · \(passkey.rpId)",
                                    symbol: "person.badge.key.fill", protected: passkey.reprompt)
                            }
                            .accessibilityIdentifier("autofill-passkey-\(passkey.userName)")
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
        .searchable(text: $model.query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Rechercher dans le coffre")
    }

    private func itemButton(_ item: ItemSummary) -> some View {
        Button { model.choose(item) } label: {
            HStack(spacing: 12) {
                ItemIconContent(summary: item, image: nil, size: 34)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 4) {
                        Text(item.title).foregroundStyle(.primary)
                        if item.reprompt {
                            Image(systemName: "lock.shield").font(.caption).foregroundStyle(.secondary)
                                .accessibilityLabel("protégé")
                        }
                    }
                    Text(item.subtitle.isEmpty ? (item.host ?? "") : item.subtitle)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityIdentifier("autofill-item-\(item.title)")
    }
}

private struct Row: View {
    let title: String
    let subtitle: String
    let symbol: String
    var protected = false

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 34, height: 34)
                .background(Theme.accent.gradient, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(title).foregroundStyle(.primary)
                    if protected {
                        Image(systemName: "lock.shield").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text(subtitle).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: Création de passkey

private struct PasskeyRegistrationView: View {
    @Environment(AutoFillModel.self) private var model

    var body: some View {
        List {
            Section {
                VStack(spacing: 10) {
                    Image(systemName: "person.badge.key.fill")
                        .font(.system(size: 40))
                        .foregroundStyle(Theme.accent)
                    Text("Nouvelle passkey pour \(model.site ?? "ce site")")
                        .font(.headline)
                        .multilineTextAlignment(.center)
                    Text("Elle est enregistrée dans votre coffre Vaultwarden, au format de Bitwarden : vos autres appareils la retrouvent.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
            Section {
                Button {
                    model.register(into: nil)
                } label: {
                    Label("Nouvel identifiant", systemImage: "plus.circle.fill")
                        .font(.body.weight(.semibold))
                }
                .disabled(model.phase == .working)
                .accessibilityIdentifier("autofill-passkey-new")
            }
            if !model.targets.isEmpty {
                Section {
                    ForEach(model.targets, id: \.id) { item in
                        Button { model.register(into: item) } label: {
                            HStack(spacing: 12) {
                                ItemIconContent(summary: item, image: nil, size: 34)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.title).foregroundStyle(.primary)
                                    Text(item.subtitle).font(.footnote).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(model.phase == .working)
                    }
                } header: {
                    Text("Ajouter à un identifiant")
                } footer: {
                    Text("Un identifiant porte une passkey : celle qu'il avait est remplacée.")
                }
            }
            if model.phase == .working {
                Section {
                    HStack {
                        ProgressView()
                        Text("Enregistrement sur le serveur…").foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

// MARK: Élément protégé

private struct ConfirmationSheet: View {
    @Environment(AutoFillModel.self) private var model
    @State private var password = ""

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 40))
                .foregroundStyle(Theme.accent)
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
                        .frame(maxWidth: .infinity, minHeight: 30)
                }
                .buttonStyle(.borderedProminent)
            }
            SecureField("Mot de passe principal", text: $password)
                .textContentType(.password)
                .padding(12)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .onSubmit {
                    let typed = password
                    password = ""
                    Task { await model.confirm(masterPassword: typed) }
                }
            Button("Annuler", role: .cancel) { model.confirmation = nil }
        }
        .padding(24)
    }
}
