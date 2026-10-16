import SwiftUI

/// Connexion à Vaultwarden : identifiants, puis second facteur si le serveur
/// le demande. Sert aussi à se reconnecter quand la session a expiré.
struct LoginView: View {
    @Environment(AppModel.self) private var model
    /// « Créer un compte » ouvert (`RegisterView.swift`).
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
    /// « Créer un compte » : pour une personne invitée sur le serveur.
    let createAccount: () -> Void
    @State private var password = ""
    @FocusState private var focus: Field?

    enum Field { case server, email, password }

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 18) {
            VStack(spacing: 6) {
                Text(model.reloginRequired ? "Session expirée" : "Connexion à Vaultwarden")
                    .font(.system(size: 26, weight: .bold, design: .rounded))
                    .layoutMark("login-title")
                Text(model.reloginRequired
                     ? "Reconnectez-vous pour reprendre la synchronisation."
                     : "Votre coffre est déchiffré sur ce Mac ; le mot de passe principal n'est jamais envoyé au serveur.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: 10) {
                LabeledField(label: "Serveur") {
                    TextField("https://vault.exemple.fr", text: $model.loginServer)
                        .textContentType(.URL)
                        .focused($focus, equals: .server)
                        .onSubmit { focus = .email }
                }
                LabeledField(label: "E-mail") {
                    TextField("vous@exemple.fr", text: $model.loginEmail)
                        .textContentType(.username)
                        .focused($focus, equals: .email)
                        .onSubmit { focus = .password }
                }
                LabeledField(label: "Mot de passe principal") {
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
                    Text(model.loginBusy ? "Connexion…" : "Se connecter")
                }
                .font(.body.weight(.semibold))
                .frame(width: 316, height: 30)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(!canSubmit)

            if model.reloginRequired {
                Button("Continuer hors ligne") { model.continueOffline() }
                    .buttonStyle(.link)
            } else {
                Button("Créer un compte (invitation reçue)", action: createAccount)
                    .buttonStyle(.link)
                    .help("Rejoindre ce serveur avec le lien d'invitation reçu par e-mail")
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
            // Le mot de passe ne reste pas dans l'interface une fois envoyé.
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
                Text("Second facteur")
                    .font(.system(size: 26, weight: .bold, design: .rounded))
                    .layoutMark("login-title")
                Text(model.loginEmail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if options.count > 1 {
                Picker("Méthode", selection: $chosen) {
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
                    codeEntry(prompt: "Code à 6 chiffres de votre application", option: .authenticator)
                case .yubiKeyOtp:
                    codeEntry(prompt: "Touchez votre YubiKey", option: .yubiKeyOtp)
                case .email:
                    VStack(spacing: 10) {
                        Button("Envoyer le code par e-mail") { Task { await model.sendEmailCode() } }
                        codeEntry(prompt: "Code reçu par e-mail", option: .email)
                    }
                }
            }
            .frame(width: 340)
            .disabled(model.loginBusy)

            Button("Annuler") { model.cancelTwoFactor() }
                .buttonStyle(.link)
        }
        .onChange(of: chosen) { code = "" }
    }

    private var current: TwoFactorOption {
        options[min(chosen, options.count - 1)]
    }

    /// La clé se signe en USB, sans navigateur ; l'attente démarre dès que
    /// l'écran s'affiche. La page du serveur dans Safari reste en repli.
    private func securityKey(challenge: String) -> some View {
        VStack(spacing: 14) {
            ZStack {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 34))
                    .foregroundStyle(Theme.accent)
                    .symbolEffect(.pulse, isActive: model.securityKeyWaiting)
            }
            .frame(height: 44)
            Text(model.securityKeyWaiting
                 ? "Branchez votre YubiKey, puis touchez-la."
                 : "Clé de sécurité")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if model.securityKeyWaiting || model.loginBusy {
                ProgressView().controlSize(.small)
            } else {
                Button {
                    Task { await model.useSecurityKeyNatively(challenge: challenge) }
                } label: {
                    Text("Réessayer avec ma YubiKey")
                        .font(.body.weight(.semibold))
                        .frame(width: 316, height: 30)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
            }
            Button("Passer par le navigateur") {
                model.cancelSecurityKey()
                Task { await model.useSecurityKey(challenge: challenge) }
            }
            .buttonStyle(.link)
            .font(.callout)
        }
        // Un nouveau défi (après un refus) relance l'attente.
        .task(id: challenge) { await model.useSecurityKeyNatively(challenge: challenge) }
        .onDisappear { model.cancelSecurityKey() }
    }

    private func codeEntry(prompt: String, option: TwoFactorOption) -> some View {
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
                    Text("Valider")
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
        case .securityKey: "Clé de sécurité"
        case .authenticator: "Application"
        case .yubiKeyOtp: "YubiKey OTP"
        case .email: "E-mail"
        }
    }
}

/// Champ avec son libellé au-dessus, dans le style de l'écran verrouillé.
struct LabeledField<Content: View>: View {
    let label: String
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
                .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Color.secondary.opacity(0.25)))
        }
    }
}
