import SwiftUI

/// Sign-in to Vaultwarden: credentials, then second factor if the server
/// asks for it. Also used to sign in again when the session has expired.
struct LoginView: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        NavigationStack {
            Group {
                if let options = model.twoFactorOptions {
                    TwoFactorStep(options: options)
                } else {
                    CredentialsStep()
                }
            }
            .animation(.smooth, value: model.twoFactorOptions)
        }
    }
}

/// Header of the sign-in and unlock screens.
struct BrandHeader: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 12) {
            AppMark(size: 80)
                .padding(.bottom, 4)
            Text(title)
                .font(.system(.largeTitle, design: .rounded, weight: .bold))
            Text(subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }
}

private struct CredentialsStep: View {
    @Environment(PhoneModel.self) private var model
    @State private var password = ""
    @FocusState private var focus: Field?

    enum Field { case server, email, password }

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                BrandHeader(
                    title: model.reloginRequired ? String(localized: "Session expired") : "Verrou",
                    subtitle: model.reloginRequired
                        ? String(localized: "Sign in again to resume syncing.")
                        : String(localized: "Your Vaultwarden vault, on your iPhone."))
            }
            .listRowBackground(Color.clear)

            Section {
                TextField("https://vault.example.com", text: $model.loginServer)
                    .keyboardType(.URL)
                    .textContentType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focus, equals: .server)
                    .submitLabel(.next)
                    .onSubmit { focus = .email }
                    .accessibilityIdentifier("login-server")
            } header: {
                SectionHeader("Server")
            }

            Section {
                TextField("you@example.com", text: $model.loginEmail)
                    .keyboardType(.emailAddress)
                    .textContentType(.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focus, equals: .email)
                    .submitLabel(.next)
                    .onSubmit { focus = .password }
                SecureField("Master password", text: $password)
                    .textContentType(.password)
                    .focused($focus, equals: .password)
                    .submitLabel(.go)
                    .onSubmit(submit)
            } header: {
                SectionHeader("Account")
            } footer: {
                Text("The master password never leaves the iPhone: only a derived hash is sent to the server.")
            }

            Section {
                GlassGroup {
                    VStack(spacing: 12) {
                        Button(action: submit) {
                            HStack(spacing: 8) {
                                if model.loginBusy { ProgressView() }
                                Text(model.loginBusy ? "Signing in…" : "Sign in").fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity, minHeight: 36)
                        }
                        .controlSize(.large)
                        .glassButton(prominent: true)
                        .disabled(!canSubmit)
                        if model.reloginRequired {
                            Button("Continue offline") { model.continueOffline() }
                                .frame(maxWidth: .infinity)
                                .controlSize(.large)
                                .glassButton()
                        }
                    }
                }
                if let error = model.loginError {
                    ErrorLabel(text: error)
                }
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets())
        }
        .scrollContentBackground(.hidden)
        .background { LockBackground() }
        .disabled(model.loginBusy)
        .navigationTitle("Sign-in")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var canSubmit: Bool {
        !model.loginBusy && !password.isEmpty && model.loginEmail.contains("@")
            && model.loginServer.trimmingCharacters(in: .whitespaces).count > "https://".count
    }

    private func submit() {
        guard canSubmit else { return }
        let typed = password
        focus = nil
        Task {
            await model.signIn(password: typed)
            // The password doesn't stay in the interface once sent.
            password = ""
        }
    }
}

private struct TwoFactorStep: View {
    @Environment(PhoneModel.self) private var model
    let options: [TwoFactorOption]
    @State private var chosen = 0
    @State private var code = ""
    @FocusState private var codeFocused: Bool

    var body: some View {
        Form {
            Section {
                BrandHeader(title: String(localized: "Second factor"), subtitle: model.loginEmail)
            }
            .listRowBackground(Color.clear)
            .listRowSeparator(.hidden)

            if options.count > 1 {
                Section {
                    Picker("Method", selection: $chosen) {
                        ForEach(options.indices, id: \.self) { index in
                            Text(Self.title(options[index])).tag(index)
                        }
                    }
                }
            }

            switch current {
            case .securityKey(let challenge):
                Section {
                    Button {
                        Task { await model.useSecurityKey(challenge: challenge) }
                    } label: {
                        HStack {
                            Spacer()
                            if model.loginBusy { ProgressView().padding(.trailing, 6) }
                            Label("Use my security key", systemImage: "key.horizontal.fill")
                                .fontWeight(.semibold)
                            Spacer()
                        }
                    }
                    .accessibilityIdentifier("security-key")
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Your server's sign-in page opens: hold the YubiKey near the top of the iPhone, or plug it in, then touch it.")
                        if let error = model.loginError {
                            ErrorLabel(text: error)
                        }
                    }
                }
            case .authenticator:
                codeSection(prompt: "6-digit code from your app", option: .authenticator)
            case .yubiKeyOtp:
                codeSection(prompt: "Code from your YubiKey (OTP)", option: .yubiKeyOtp)
            case .email:
                Section {
                    Button("Send the code by email") { Task { await model.sendEmailCode() } }
                }
                codeSection(prompt: "Code received by email", option: .email)
            }

            Section {
                Button("Cancel", role: .cancel) { model.cancelTwoFactor() }
                    .frame(maxWidth: .infinity)
            }
        }
        .scrollContentBackground(.hidden)
        .background { LockBackground() }
        .disabled(model.loginBusy)
        .navigationTitle("Verification")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: chosen) { code = "" }
    }

    private var current: TwoFactorOption {
        options[min(chosen, options.count - 1)]
    }

    @ViewBuilder
    private func codeSection(prompt: LocalizedStringKey, option: TwoFactorOption) -> some View {
        Section {
            TextField("Code", text: $code)
                .font(.system(.title3, design: .monospaced))
                .keyboardType(option == .yubiKeyOtp ? .asciiCapable : .numberPad)
                .textContentType(.oneTimeCode)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($codeFocused)
                .onSubmit { submit(option) }
            Button {
                submit(option)
            } label: {
                HStack {
                    Spacer()
                    if model.loginBusy { ProgressView().padding(.trailing, 6) }
                    Text("Submit").fontWeight(.semibold)
                    Spacer()
                }
            }
            .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty)
        } header: {
            Text(prompt)
        } footer: {
            if let error = model.loginError {
                ErrorLabel(text: error)
            }
        }
        .onAppear { codeFocused = true }
    }

    private func submit(_ option: TwoFactorOption) {
        let token = code.trimmingCharacters(in: .whitespaces)
        guard !token.isEmpty else { return }
        Task {
            await model.answerTwoFactor(option, token: token)
            code = ""
        }
    }

    static func title(_ option: TwoFactorOption) -> String {
        switch option {
        case .securityKey: String(localized: "Security key")
        case .authenticator: String(localized: "Authenticator app")
        case .yubiKeyOtp: "YubiKey OTP"
        case .email: String(localized: "Email")
        }
    }
}

/// Error message under a form.
struct ErrorLabel: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.callout)
            .foregroundStyle(.red)
            .padding(.top, 4)
    }
}
