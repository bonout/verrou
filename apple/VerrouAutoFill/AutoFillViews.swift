import SwiftUI

/// The extension's interface: unlock, then the list (or the passkey
/// creation); a tapped suggestion only shows the unlock before filling.
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
                    if case .alias = model.request {
                        AliasInsertView()
                    } else {
                        AutoFillLockView()
                    }
                case .ready, .working:
                    content
                }
            }
            .navigationTitle(model.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { model.cancel() }
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
            WorkingView(label: "Filling…")
        case .alias:
            AliasInsertView()
        case .save:
            SaveLoginView()
        case .list, .oneTimeCodes:
            if model.phase == .working {
                WorkingView(label: model.matches.isEmpty && model.passkeys.isEmpty ? "Saving to the server…" : "Signing…")
            } else {
                CredentialListView()
            }
        case .none:
            VStack(spacing: 12) {
                AppMark(size: 64, glow: false)
                Text("Verrou fills your logins, codes and passkeys.")
                    .multilineTextAlignment(.center)
            }
            .padding()
        }
    }
}

private struct WorkingView: View {
    let label: LocalizedStringKey

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
            Text("No vault on this iPhone")
                .font(.title3.weight(.semibold))
            Text("Open the Verrou app and sign in to your Vaultwarden server: your logins will then be offered here.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: Email alias

private struct AliasInsertView: View {
    @Environment(AutoFillModel.self) private var model

    var body: some View {
        @Bindable var model = model
        List {
            if model.aliasSettings?.domain == nil {
                Section {
                    VStack(spacing: 10) {
                        TintedSymbol(symbol: "at", tint: Theme.accent, size: 64)
                        Text("No alias domain")
                            .font(.headline)
                        Text("In the Verrou app, enter your catch-all domain in Settings → Vault and filling → Email aliases.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
            } else {
                Section {
                    VStack(spacing: 10) {
                        TintedSymbol(symbol: "at", tint: Theme.accent, size: 64)
                        Text(verbatim: model.alias)
                            .font(.system(.body, design: .monospaced).weight(.semibold))
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .contentTransition(.numericText())
                            .animation(.snappy, value: model.alias)
                            .accessibilityIdentifier("autofill-alias")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                Section {
                    TextField("Site", text: $model.aliasSite, prompt: Text(verbatim: "netflix.com"))
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.done)
                        .accessibilityIdentifier("autofill-alias-site")
                } footer: {
                    if model.aliasUsesSite {
                        Text("The alias starts with the site's name. Without a site, it is random.")
                    }
                }
                Section {
                    Button {
                        model.signUpWithInsertedAlias()
                    } label: {
                        Label("Sign Up with This Alias", systemImage: "person.crop.circle.badge.plus")
                            .font(.body.weight(.semibold))
                    }
                    .disabled(!model.canSignUpWithInsertedAlias || model.phase == .working)
                    .accessibilityIdentifier("autofill-alias-signup")
                } footer: {
                    Text("Saves a login for the site with this alias and a strong password, then inserts the alias. In the password field, the strong password iOS suggests is that one.")
                }
                Section {
                    Button {
                        model.insertAlias()
                    } label: {
                        Label("Insert Alias", systemImage: "text.insert")
                    }
                    .disabled(model.alias.isEmpty)
                    .accessibilityIdentifier("autofill-alias-insert")
                    Button {
                        model.generateAlias()
                    } label: {
                        Label("Another Alias", systemImage: "arrow.clockwise")
                    }
                } footer: {
                    Text("Mail sent to it reaches you through your domain's catch-all. Save the login in Verrou once signed up: the alias is its username.")
                }
            }
        }
        .onChange(of: model.aliasSite) { model.generateAlias() }
    }
}

// MARK: Unlocking

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
                    Text("Unlock Verrou")
                        .font(.system(.title2, design: .rounded, weight: .bold))
                    if let site = model.site {
                        Text("for \(site)").foregroundStyle(.secondary)
                    }
                    if let account = model.account {
                        Text(account.email).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                .multilineTextAlignment(.center)
                Spacer(minLength: 12)
                GlassGroup(spacing: 14) {
                    VStack(spacing: 14) {
                        // The login just filled on this site (the form's
                        // second page): one tap, no Face ID, which stays
                        // offered below to choose another one.
                        if let recent = model.recentLogin {
                            Button {
                                model.continueWithRecentLogin()
                            } label: {
                                Label("Continue as \(recent.user)", systemImage: "person.crop.circle.badge.checkmark")
                                    .font(.body.weight(.semibold))
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .frame(maxWidth: .infinity, minHeight: 36)
                            }
                            .controlSize(.large)
                            .glassButton(prominent: true)
                            .disabled(model.phase == .unlocking)
                            .accessibilityIdentifier("autofill-continue-recent")
                        }
                        if model.canUseBiometrics {
                            BiometricUnlockButton(title: "Unlock with \(Biometrics.name)",
                                                  symbol: Biometrics.symbolName,
                                                  busy: model.phase == .unlocking,
                                                  prominent: model.recentLogin == nil) {
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
        .onChange(of: model.unlockError) { _, error in
            if let error, !error.isEmpty { AccessibilityNotification.Announcement(error).post() }
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

// MARK: List

private struct CredentialListView: View {
    @Environment(AutoFillModel.self) private var model
    private static let listLimit = 100
    private static let searchLimit = 50

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
                        if model.canSignUpWithAlias {
                            Button { model.signUpWithAlias() } label: {
                                Label("Sign Up with an Email Alias", systemImage: "at.badge.plus")
                                    .font(.body.weight(.semibold))
                            }
                            .accessibilityIdentifier("autofill-signup-alias")
                        } else {
                            Text("No login for this site: search the vault.")
                                .foregroundStyle(.secondary)
                        }
                    }
                    ForEach(model.matches, id: \.id) { item in itemButton(item) }
                } header: {
                    SectionHeader(model.site.map { String(localized: "For \($0)") } ?? String(localized: "Suggestions"))
                } footer: {
                    if model.matches.isEmpty, model.canSignUpWithAlias {
                        Text("A new address at your alias domain and a strong password, saved in Verrou, then filled.")
                    }
                }
                Section {
                    ForEach(model.everything.prefix(Self.listLimit), id: \.id) { item in itemButton(item) }
                } header: {
                    SectionHeader("Entire vault")
                } footer: {
                    if model.everything.count > Self.listLimit {
                        Text("Showing \(Self.listLimit) of \(model.everything.count) items: search to find the others.")
                    }
                }
            } else {
                let results = model.allSearchResults
                Section {
                    if results.isEmpty {
                        Text("No results").foregroundStyle(.secondary)
                    }
                    ForEach(results.prefix(Self.searchLimit), id: \.id) { item in itemButton(item) }
                } header: {
                    SectionHeader("Results")
                } footer: {
                    if results.count > Self.searchLimit {
                        Text("Showing the first \(Self.searchLimit) of \(results.count) results: refine the search.")
                    }
                }
            }
        }
        .searchable(text: $model.query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search the vault")
    }

    private func itemButton(_ item: ItemSummary) -> some View {
        // The app's row (without a site icon: nothing to download here).
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
                            .accessibilityLabel("Protected")
                    }
                }
                Text(subtitle).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: Login to save

private struct SaveLoginView: View {
    @Environment(AutoFillModel.self) private var model

    var body: some View {
        List {
            Section {
                VStack(spacing: 8) {
                    TintedSymbol(symbol: model.loginSaved ? "checkmark" : "key.fill",
                                 tint: model.loginSaved ? .green : Theme.accent, size: 64)
                        .contentTransition(.symbolEffect(.replace))
                    Text(headline)
                        .font(.headline)
                        .multilineTextAlignment(.center)
                    Text("It is saved in your Vaultwarden vault: your other devices find it.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
            if case .save(let login) = model.request {
                Section {
                    LabeledContent("Site", value: login.site)
                    if !login.user.isEmpty {
                        LabeledContent("Username", value: login.user)
                    }
                    LabeledContent("Password", value: String(repeating: "•", count: min(login.password.count, 12)))
                }
            }
            Section {
                Button {
                    model.saveLogin()
                } label: {
                    Label(model.saveCheck?.action == .update ? "Update Password" : "Save Login",
                          systemImage: "square.and.arrow.down.fill")
                        .font(.body.weight(.semibold))
                }
                .disabled(model.phase == .working || model.saveCheck == nil)
                .accessibilityIdentifier("autofill-save-login")
                Button("Not Now", role: .cancel) { model.cancel() }
                    .disabled(model.phase == .working)
            }
            if model.phase == .working, !model.loginSaved {
                Section {
                    HStack {
                        ProgressView()
                        Text("Saving to the server…").foregroundStyle(.secondary)
                    }
                }
            }
        }
        .sensoryFeedback(.success, trigger: model.loginSaved) { _, saved in saved }
    }

    private var headline: String {
        if model.loginSaved { return String(localized: "Login saved") }
        if model.saveCheck?.action == .update, let title = model.saveCheck?.title {
            return String(localized: "New password for “\(title)”")
        }
        return String(localized: "New login for \(model.site ?? String(localized: "this site"))")
    }
}

// MARK: Passkey creation

private struct PasskeyRegistrationView: View {
    @Environment(AutoFillModel.self) private var model
    @State private var replacing: ItemSummary?

    var body: some View {
        List {
            Section {
                VStack(spacing: 10) {
                    PasskeySymbol(created: model.passkeyCreated)
                    Text(model.passkeyCreated ? "Passkey saved" : "New passkey for \(model.site ?? String(localized: "this site"))")
                        .font(.headline)
                        .multilineTextAlignment(.center)
                    Text("It is saved in your Vaultwarden vault, in Bitwarden's format: your other devices find it.")
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
                    Label("New login", systemImage: "plus.circle.fill")
                        .font(.body.weight(.semibold))
                }
                .disabled(model.phase == .working)
                .accessibilityIdentifier("autofill-passkey-new")
            }
            if !model.targets.isEmpty {
                Section {
                    ForEach(model.targets, id: \.id) { item in
                        Button {
                            if item.passkeyRpId != nil { replacing = item } else { model.register(into: item) }
                        } label: {
                            HStack(spacing: 12) {
                                ItemIconContent(summary: item, image: nil, size: 38, initialShadow: false)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.title).foregroundStyle(.primary)
                                    Text(item.displaySubtitle).font(.footnote).foregroundStyle(.secondary)
                                    if let passkey = item.passkeyLine {
                                        Label("Has a passkey: \(passkey)", systemImage: "person.badge.key.fill")
                                            .font(.footnote)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                        .disabled(model.phase == .working)
                        .accessibilityIdentifier("autofill-passkey-target-\(item.title)")
                    }
                } header: {
                    SectionHeader("Add to a login")
                } footer: {
                    Text("A login holds one passkey: choosing one that already has a passkey replaces it, after confirmation.")
                }
            }
            if model.phase == .working, !model.passkeyCreated {
                Section {
                    HStack {
                        ProgressView()
                        Text("Saving to the server…").foregroundStyle(.secondary)
                    }
                }
            }
        }
        .sensoryFeedback(.success, trigger: model.passkeyCreated) { _, created in created }
        .confirmationDialog("Replace the passkey of “\(replacing?.title ?? "")”?",
                            isPresented: Binding(get: { replacing != nil }, set: { if !$0 { replacing = nil } }),
                            titleVisibility: .visible, presenting: replacing) { item in
            Button("Replace Passkey", role: .destructive) { model.register(into: item) }
        } message: { item in
            Text("Its current passkey (\(item.passkeyLine ?? "")) is deleted: the site will no longer accept it. To keep it, choose “New login”.")
        }
    }
}

/// The creation sheet's key: it bounces and becomes a checkmark once the
/// passkey is saved. Symbol effects only (nothing heavy in the extension);
/// a fade with "Reduce Motion".
private struct PasskeySymbol: View {
    let created: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Image(systemName: created ? "checkmark" : "person.badge.key.fill")
            .font(.system(size: 30, weight: .semibold))
            .foregroundStyle(.white)
            .modifier(Replace(reduceMotion: reduceMotion))
            .symbolEffect(.bounce, value: created)
            .symbolEffectsRemoved(reduceMotion)
            .frame(width: 64, height: 64)
            .background((created ? Color.green : Theme.accent).gradient,
                        in: RoundedRectangle(cornerRadius: 64 * 0.27, style: .continuous))
            .animation(.snappy(duration: 0.35), value: created)
            .accessibilityHidden(true)
    }

    private struct Replace: ViewModifier {
        let reduceMotion: Bool

        func body(content: Content) -> some View {
            if reduceMotion {
                content.contentTransition(.opacity)
            } else if #available(iOS 18, *), !LiquidGlass.forcedFallback {
                content.contentTransition(.symbolEffect(.replace.magic(fallback: .replace)))
            } else {
                content.contentTransition(.symbolEffect(.replace))
            }
        }
    }
}

// MARK: Protected item

private struct ConfirmationSheet: View {
    @Environment(AutoFillModel.self) private var model
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 18) {
            TintedSymbol(symbol: "lock.shield.fill", tint: .orange, size: 60)
            Text("“\(model.confirmation?.title ?? "")” is protected")
                .font(.headline)
                .multilineTextAlignment(.center)
            Text("Confirm with \(Biometrics.name) or your master password.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if Biometrics.isAvailable {
                Button {
                    Task { await model.confirmWithBiometrics() }
                } label: {
                    Label("Confirm with \(Biometrics.name)", systemImage: Biometrics.symbolName)
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity, minHeight: 34)
                }
                .controlSize(.large)
                .glassButton(prominent: true)
            }
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .submitLabel(.done)
                .focused($focused)
                .padding(.horizontal, 16)
                .frame(minHeight: 48)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).strokeBorder(Theme.cardBorder))
                .onSubmit(submit)
            HStack(spacing: 12) {
                Button(role: .cancel) {
                    model.confirmation = nil
                } label: {
                    Text("Cancel").frame(maxWidth: .infinity, minHeight: 34)
                }
                .glassButton(prominent: false)
                Button(action: submit) {
                    Text("Confirm").frame(maxWidth: .infinity, minHeight: 34)
                }
                .glassButton(prominent: !Biometrics.isAvailable)
                .disabled(password.isEmpty)
                .accessibilityIdentifier("autofill-confirm-password")
            }
            .controlSize(.large)
        }
        .padding(24)
        .onAppear { if !Biometrics.isAvailable { focused = true } }
    }

    private func submit() {
        guard !password.isEmpty else { return }
        let typed = password
        password = ""
        Task { await model.confirm(masterPassword: typed) }
    }
}
