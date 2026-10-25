import SwiftUI

/// Login to Vaultwarden: credentials, then second factor if the server asks
/// for it. Also used to log in again when the session expired.
struct LoginView: View {
    @Environment(AppModel.self) private var model
    /// "Create an Account" open (`RegisterView.swift`).
    @State private var registration: RegistrationFlow?

    init(registration: RegistrationFlow? = nil) {
        _registration = State(initialValue: registration)
    }

    var body: some View {
        ZStack {
            LockBackground()
            ScrollView {
                VStack(spacing: 22) {
                    if registration == nil || model.twoFactorOptions != nil {
                        AppMark(size: 72)
                    }
                    if let options = model.twoFactorOptions {
                        TwoFactorStep(options: options)
                    } else if let registration {
                        RegisterStep(flow: registration) { self.registration = nil }
                    } else {
                        CredentialsStep {
                            registration = RegistrationFlow(server: model.loginServer, email: model.loginEmail)
                        }
                    }
                    if let error = model.loginError {
                        Text(error)
                            .font(.callout)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 340)
                            .transition(.opacity)
                    }
                }
                .padding(48)
                .frame(maxWidth: .infinity)
            }
            .scrollBounceBehavior(.basedOnSize)
        }
        .frame(minWidth: 520, minHeight: 560)
        .animation(.smooth, value: model.twoFactorOptions)
        .animation(.smooth, value: model.loginError)
        .animation(.smooth, value: registration == nil)
    }
}

private struct CredentialsStep: View {
    @Environment(AppModel.self) private var model
    /// "Create an Account": for a person invited to the server.
    let createAccount: () -> Void
    @State private var password = ""
    @FocusState private var focus: Field?

    enum Field { case server, email, password }

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 18) {
            VStack(spacing: 6) {
                Text(model.reloginRequired ? "Session expired" : "Log in to Vaultwarden")
                    .font(.system(size: 26, weight: .bold, design: .rounded))
                    .layoutMark("login-title")
                Text(model.reloginRequired
                     ? "Log in again to resume syncing."
                     : "Your vault is decrypted on this Mac; the master password is never sent to the server.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: 10) {
                LabeledField(label: "Server") {
                    TextField("https://vault.example.com", text: $model.loginServer)
                        .textContentType(.URL)
                        .focused($focus, equals: .server)
                        .onSubmit { focus = .email }
                }
                LabeledField(label: "Email") {
                    TextField("you@example.com", text: $model.loginEmail)
                        .textContentType(.username)
                        .focused($focus, equals: .email)
                        .onSubmit { focus = .password }
                }
                LabeledField(label: "Master password") {
                    SecureField("", text: $password)
                        .textContentType(.password)
                        .focused($focus, equals: .password)
                        .onSubmit(submit)
                }
            }
            .frame(width: 340)
            .disabled(model.loginBusy)

            Button(action: submit) {
                HStack(spacing: 8) {
                    if model.loginBusy { ProgressView().controlSize(.small) }
                    Text(model.loginBusy ? "Logging in…" : "Log In")
                }
                .font(.body.weight(.semibold))
                .frame(width: 316, height: 30)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(!canSubmit)

            if model.reloginRequired {
                Button("Continue Offline") { model.continueOffline() }
                    .buttonStyle(.link)
            } else {
                Button("Create an Account (Invitation Received)", action: createAccount)
                    .buttonStyle(.link)
                    .help("Join this server with the invitation link received by email")
            }
        }
        .onAppear { focus = model.loginEmail.isEmpty ? .email : .password }
    }

    private var canSubmit: Bool {
        !model.loginBusy && !password.isEmpty && model.loginEmail.contains("@") && !model.loginServer.isEmpty
    }

    private func submit() {
        guard canSubmit else { return }
        let typed = password
        Task {
            await model.signIn(password: typed)
            // The password doesn't stay in the interface once sent.
            password = ""
        }
    }
}

private struct TwoFactorStep: View {
    @Environment(AppModel.self) private var model
    let options: [TwoFactorOption]
    @State private var chosen = 0
    @State private var code = ""
    @FocusState private var codeFocused: Bool

    var body: some View {
        VStack(spacing: 18) {
            VStack(spacing: 6) {
                Text("Second factor")
                    .font(.system(size: 26, weight: .bold, design: .rounded))
                    .layoutMark("login-title")
                Text(model.loginEmail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if options.count > 1 {
                Picker("Method", selection: $chosen) {
                    ForEach(options.indices, id: \.self) { index in
                        Text(Self.title(options[index])).tag(index)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 340)
            }

            Group {
                switch current {
                case .securityKey(let challenge):
                    securityKey(challenge: challenge)
                case .authenticator:
                    codeEntry(prompt: "6-digit code from your app", option: .authenticator)
                case .yubiKeyOtp:
                    codeEntry(prompt: "Touch your YubiKey", option: .yubiKeyOtp)
                case .email:
                    VStack(spacing: 10) {
                        Button("Send the Code by Email") { Task { await model.sendEmailCode() } }
                        codeEntry(prompt: "Code received by email", option: .email)
                    }
                }
            }
            .frame(width: 340)
            .disabled(model.loginBusy)

            Button("Cancel") { model.cancelTwoFactor() }
                .buttonStyle(.link)
        }
        .onChange(of: chosen) { code = "" }
    }

    private var current: TwoFactorOption {
        options[min(chosen, options.count - 1)]
    }

    /// The key signs over USB, without a browser; the wait starts as soon as
    /// the screen shows. The server's page in Safari stays as a fallback.
    private func securityKey(challenge: String) -> some View {
        VStack(spacing: 14) {
            ZStack {
                Image(systemName: "key.horizontal.fill")
                    .accessibilityHidden(true)
                    .font(.system(size: 34))
                    .foregroundStyle(Theme.accent)
                    .symbolEffect(.pulse, isActive: model.securityKeyWaiting)
            }
            .frame(height: 44)
            Text(model.securityKeyWaiting
                 ? "Plug in your YubiKey, then touch it."
                 : "Security key")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if model.securityKeyWaiting || model.loginBusy {
                ProgressView().controlSize(.small)
            } else {
                Button {
                    Task { await model.useSecurityKeyNatively(challenge: challenge) }
                } label: {
                    Text("Try Again with My YubiKey")
                        .font(.body.weight(.semibold))
                        .frame(width: 316, height: 30)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
            }
            Button("Use the Browser") {
                model.cancelSecurityKey()
                Task { await model.useSecurityKey(challenge: challenge) }
            }
            .buttonStyle(.link)
            .font(.callout)
        }
        // A new challenge (after a rejection) restarts the wait.
        .task(id: challenge) { await model.useSecurityKeyNatively(challenge: challenge) }
        .onDisappear { model.cancelSecurityKey() }
    }

    private func codeEntry(prompt: LocalizedStringKey, option: TwoFactorOption) -> some View {
        VStack(spacing: 10) {
            LabeledField(label: prompt) {
                TextField("", text: $code)
                    .font(.system(.title3, design: .monospaced))
                    .textContentType(.oneTimeCode)
                    .focused($codeFocused)
                    .onSubmit { submit(option) }
            }
            Button {
                submit(option)
            } label: {
                HStack(spacing: 8) {
                    if model.loginBusy { ProgressView().controlSize(.small) }
                    Text("Submit")
                }
                .font(.body.weight(.semibold))
                .frame(width: 316, height: 30)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty)
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

/// Field with its label above, in the lock screen's style.
struct LabeledField<Content: View>: View {
    let label: LocalizedStringKey
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            content
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .frame(height: 36)
                .background(.background.opacity(0.7), in: RoundedRectangle(cornerRadius: 9))
                .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Theme.border(0.25)))
        }
    }
}
