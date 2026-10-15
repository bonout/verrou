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
                AppMark(size: 64, glow: false)
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
        ZStack {
            LockBackground()
            VStack(spacing: 22) {
                Spacer(minLength: 12)
                AppMark(size: 76)
                VStack(spacing: 6) {
                    Text("Déverrouiller Verrou")
                        .font(.system(.title2, design: .rounded, weight: .bold))
                    if let site = model.site {
                        Text("pour \(site)").foregroundStyle(.secondary)
                    }
                    if let account = model.account {
                        Text(account.email).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                .multilineTextAlignment(.center)
                Spacer(minLength: 12)
                GlassGroup(spacing: 14) {
                    VStack(spacing: 14) {
                        if model.canUseBiometrics {
                            BiometricUnlockButton(title: "Déverrouiller avec \(Biometrics.name)",
                                                  symbol: Biometrics.symbolName,
                                                  busy: model.phase == .unlocking) {
                                Task { await model.unlockWithBiometrics() }
                            }
                        }
                        MasterPasswordField(password: $password, busy: model.phase == .unlocking,
                                            focused: $focused, submit: submit)
                    }
                }
                if let error = model.unlockError {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                }
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 24)
        }
        .sensoryFeedback(.error, trigger: model.unlockError) { _, new in new != nil }
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
                    Section(header: SectionHeader("Passkeys")) {
                        ForEach(model.passkeys, id: \.credentialId) { passkey in
                            Button { model.choose(passkey) } label: {
                                Row(title: passkey.userName, subtitle: "Passkey · \(passkey.rpId)",
                                    symbol: "person.badge.key.fill", protected: passkey.reprompt)
                            }
                            .accessibilityIdentifier("autofill-passkey-\(passkey.userName)")
                        }
                    }
                }
                Section {
                    if model.matches.isEmpty {
                        Text("Aucun identifiant pour ce site : cherchez dans le coffre.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.matches, id: \.id) { item in itemButton(item) }
                } header: {
                    SectionHeader(model.site.map { "Pour \($0)" } ?? "Suggestions")
                }
                Section {
                    ForEach(model.everything.prefix(100), id: \.id) { item in itemButton(item) }
                } header: {
                    SectionHeader("Tout le coffre")
                }
            } else {
                Section(header: SectionHeader("Résultats")) {
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
        // La ligne de l'app (sans icône de site : rien à télécharger ici).
        Button { model.choose(item) } label: {
            ItemRowContent(summary: item, highlights: [], spacing: 12, subtitleFont: .subheadline,
                           showsProtection: true) {
                ItemIconContent(summary: item, image: nil, size: 38, initialShadow: false)
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
            TintedSymbol(symbol: symbol, tint: Theme.accent, size: 38)
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
                    TintedSymbol(symbol: "person.badge.key.fill", tint: Theme.accent, size: 64)
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
                                ItemIconContent(summary: item, image: nil, size: 38, initialShadow: false)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.title).foregroundStyle(.primary)
                                    Text(item.subtitle).font(.footnote).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(model.phase == .working)
                    }
                } header: {
                    SectionHeader("Ajouter à un identifiant")
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
            TintedSymbol(symbol: "lock.shield.fill", tint: .orange, size: 60)
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
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity, minHeight: 34)
                }
                .controlSize(.large)
                .glassButton(prominent: true)
            }
            SecureField("Mot de passe principal", text: $password)
                .textContentType(.password)
                .padding(.horizontal, 16)
                .frame(minHeight: 48)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
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
