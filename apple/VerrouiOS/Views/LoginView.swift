import SwiftUI

/// Connexion à Vaultwarden : identifiants, puis second facteur si le
/// serveur le demande. Sert aussi à se reconnecter quand la session a expiré.
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

/// En-tête des écrans de connexion et de déverrouillage.
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
                    title: model.reloginRequired ? "Session expirée" : "Verrou",
                    subtitle: model.reloginRequired
                        ? "Reconnectez-vous pour reprendre la synchronisation."
                        : "Votre coffre Vaultwarden, sur votre iPhone.")
            }
            .listRowBackground(Color.clear)

            Section {
                TextField("https://vault.exemple.fr", text: $model.loginServer)
                    .keyboardType(.URL)
                    .textContentType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focus, equals: .server)
                    .submitLabel(.next)
                    .onSubmit { focus = .email }
                    .accessibilityIdentifier("login-server")
            } header: {
                SectionHeader("Serveur")
            }

            Section {
                TextField("vous@exemple.fr", text: $model.loginEmail)
                    .keyboardType(.emailAddress)
                    .textContentType(.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focus, equals: .email)
                    .submitLabel(.next)
                    .onSubmit { focus = .password }
                SecureField("Mot de passe principal", text: $password)
                    .textContentType(.password)
                    .focused($focus, equals: .password)
                    .submitLabel(.go)
                    .onSubmit(submit)
            } header: {
                SectionHeader("Compte")
            } footer: {
                Text("Le mot de passe principal ne quitte jamais l'iPhone : seule une empreinte dérivée est envoyée au serveur.")
            }

            Section {
                GlassGroup {
                    VStack(spacing: 12) {
                        Button(action: submit) {
                            HStack(spacing: 8) {
                                if model.loginBusy { ProgressView() }
                                Text(model.loginBusy ? "Connexion…" : "Se connecter").fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity, minHeight: 36)
                        }
                        .controlSize(.large)
                        .glassButton(prominent: true)
                        .disabled(!canSubmit)
                        if model.reloginRequired {
                            Button("Continuer hors ligne") { model.continueOffline() }
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
        .navigationTitle("Connexion")
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
            // Le mot de passe ne reste pas dans l'interface une fois envoyé.
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
                BrandHeader(title: "Second facteur", subtitle: model.loginEmail)
            }
            .listRowBackground(Color.clear)
            .listRowSeparator(.hidden)

            if options.count > 1 {
                Section {
                    Picker("Méthode", selection: $chosen) {
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
                            Label("Utiliser ma clé de sécurité", systemImage: "key.horizontal.fill")
                                .fontWeight(.semibold)
                            Spacer()
                        }
                    }
                    .accessibilityIdentifier("security-key")
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("La page de connexion de votre serveur s'ouvre : approchez la YubiKey du haut de l'iPhone, ou branchez-la, puis touchez-la.")
                        if let error = model.loginError {
                            ErrorLabel(text: error)
                        }
                    }
                }
            case .authenticator:
                codeSection(prompt: "Code à 6 chiffres de votre application", option: .authenticator)
            case .yubiKeyOtp:
                codeSection(prompt: "Code de votre YubiKey (OTP)", option: .yubiKeyOtp)
            case .email:
                Section {
                    Button("Envoyer le code par e-mail") { Task { await model.sendEmailCode() } }
                }
                codeSection(prompt: "Code reçu par e-mail", option: .email)
            }

            Section {
                Button("Annuler", role: .cancel) { model.cancelTwoFactor() }
                    .frame(maxWidth: .infinity)
            }
        }
        .scrollContentBackground(.hidden)
        .background { LockBackground() }
        .disabled(model.loginBusy)
        .navigationTitle("Vérification")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: chosen) { code = "" }
    }

    private var current: TwoFactorOption {
        options[min(chosen, options.count - 1)]
    }

    @ViewBuilder
    private func codeSection(prompt: String, option: TwoFactorOption) -> some View {
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
                    Text("Valider").fontWeight(.semibold)
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
        case .securityKey: "Clé de sécurité"
        case .authenticator: "Application"
        case .yubiKeyOtp: "YubiKey OTP"
        case .email: "E-mail"
        }
    }
}

/// Message d'erreur sous un formulaire.
struct ErrorLabel: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.callout)
            .foregroundStyle(.red)
            .padding(.top, 4)
    }
}
