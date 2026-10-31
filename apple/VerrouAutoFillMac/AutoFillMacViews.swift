import SwiftUI

/// The extension's interface on the Mac: the sheet macOS opens above Safari
/// or the app (440 × 540). Same model as the iPhone (`AutoFillModel`):
/// unlock (Touch ID, otherwise master password), then the list or the
/// passkey creation.
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
            Button("Cancel") { model.cancel() }
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
            MacWorkingView(label: "Filling…")
        case .list, .oneTimeCodes:
            if model.phase == .working {
                MacWorkingView(label: "Signing…")
            } else {
                MacCredentialListView()
            }
        case .none, .alias:
            VStack(spacing: 12) {
                AppMark(size: 56, glow: false)
                Text("Verrou fills your logins, codes and passkeys in Safari and the Mac's apps.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            .padding(24)
        }
    }
}

private struct MacWorkingView: View {
    let label: LocalizedStringKey

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
            Text("No shared vault on this Mac")
                .font(.title3.weight(.semibold))
            Text("Open Verrou and sign in to your Vaultwarden server: your logins will then be offered here. The app must be a build signed by your developer team (see the guide).")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(28)
    }
}

// MARK: Unlocking

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
                    Text("Unlock Verrou")
                        .font(.system(.title3, design: .rounded, weight: .bold))
                    if let account = model.account {
                        Text(account.email).font(.callout).foregroundStyle(.secondary)
                    }
                }
                if model.canUseBiometrics {
                    Button {
                        Task { await model.unlockWithBiometrics() }
                    } label: {
                        Label("Unlock with \(Biometrics.name)", systemImage: Biometrics.symbolName)
                            .frame(maxWidth: 260)
                    }
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .disabled(model.phase == .unlocking)
                }
                HStack(spacing: 8) {
                    SecureField("Master password", text: $password)
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

// MARK: List

private struct MacCredentialListView: View {
    @Environment(AutoFillModel.self) private var model
    @FocusState private var searching: Bool

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            TextField("Search the vault", text: $model.query)
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
                    Section(model.site.map { String(localized: "For \($0)") } ?? String(localized: "Suggestions")) {
                        if model.matches.isEmpty {
                            Text("No login for this site: search the vault.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(model.matches, id: \.id) { item in itemButton(item) }
                    }
                    Section("Entire vault") {
                        ForEach(model.everything.prefix(100), id: \.id) { item in itemButton(item) }
                    }
                } else {
                    Section("Results") {
                        let results = model.searchResults
                        if results.isEmpty {
                            Text("No results").foregroundStyle(.secondary)
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

// MARK: Passkey creation

private struct MacPasskeyRegistrationView: View {
    @Environment(AutoFillModel.self) private var model
    @State private var replacing: ItemSummary?

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
                Text(model.passkeyCreated ? "Passkey saved" : "New passkey for \(model.site ?? String(localized: "this site"))")
                    .font(.headline)
                Text("It is saved in your Vaultwarden vault, in Bitwarden's format: your other devices find it.")
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
                        Label("New login", systemImage: "plus.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .disabled(model.phase == .working)
                }
                if !model.targets.isEmpty {
                    Section {
                        ForEach(model.targets, id: \.id) { item in
                            Button {
                                if item.passkeyRpId != nil { replacing = item } else { model.register(into: item) }
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    ItemRowContent(summary: item, highlights: [], spacing: 10, subtitleFont: .caption) {
                                        ItemIconContent(summary: item, image: nil, size: 28)
                                    }
                                    if let passkey = item.passkeyLine {
                                        Label("Has a passkey: \(passkey)", systemImage: "person.badge.key.fill")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .padding(.leading, 38)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .disabled(model.phase == .working)
                        }
                    } header: {
                        Text("Add to a login")
                    } footer: {
                        Text("A login holds one passkey: choosing one that already has a passkey replaces it, after confirmation.")
                    }
                }
            }
            .listStyle(.inset)
            .confirmationDialog("Replace the passkey of “\(replacing?.title ?? "")”?",
                                isPresented: Binding(get: { replacing != nil }, set: { if !$0 { replacing = nil } }),
                                titleVisibility: .visible, presenting: replacing) { item in
                Button("Replace Passkey", role: .destructive) { model.register(into: item) }
            } message: { item in
                Text("Its current passkey (\(item.passkeyLine ?? "")) is deleted: the site will no longer accept it. To keep it, choose “New login”.")
            }
            if model.phase == .working, !model.passkeyCreated {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Saving to the server…").foregroundStyle(.secondary)
                }
                .padding(.bottom, 12)
            }
        }
    }
}

// MARK: Protected item

private struct MacConfirmationSheet: View {
    @Environment(AutoFillModel.self) private var model
    @State private var password = ""

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 30))
                .foregroundStyle(.orange)
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
                }
                .buttonStyle(.borderedProminent)
            }
            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    let typed = password
                    password = ""
                    Task { await model.confirm(masterPassword: typed) }
                }
            Button("Cancel", role: .cancel) { model.confirmation = nil }
                .keyboardShortcut(.cancelAction)
        }
        .padding(24)
        .frame(width: 340)
    }
}
