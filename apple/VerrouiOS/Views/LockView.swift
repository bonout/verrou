import SwiftUI

/// Coffre verrouillé : Face ID (ou Touch ID), sinon le mot de passe principal.
struct LockView: View {
    @Environment(PhoneModel.self) private var model
    @State private var password = ""
    @FocusState private var passwordFocused: Bool

    var body: some View {
        ZStack {
            LinearGradient(colors: [Theme.accent.opacity(0.22), Color(.systemBackground)],
                           startPoint: .top, endPoint: .center)
                .ignoresSafeArea()
            VStack(spacing: 28) {
                Spacer()
                VStack(spacing: 12) {
                    AppMark(size: 92)
                    Text("Verrou")
                        .font(.system(.largeTitle, design: .rounded, weight: .bold))
                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                Spacer()
                VStack(spacing: 14) {
                    if model.canUseBiometrics {
                        biometricButton
                    }
                    passwordField
                    if let error = model.unlockError, !error.isEmpty {
                        Text(error)
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                            .transition(.opacity)
                    }
                }
                .padding(.horizontal, 28)
                .padding(.bottom, 24)
            }
        }
        .animation(.snappy, value: model.unlockError)
        .onAppear {
            Perf.log.notice("écran verrouillé affiché à +\(Perf.msSinceLaunch) ms du lancement")
            if model.canUseBiometrics {
                Task { await model.promptBiometricsIfPossible() }
            }
        }
    }

    @ViewBuilder private var biometricButton: some View {
        let button = Button {
            Task { await model.unlockWithBiometrics() }
        } label: {
            Label("Déverrouiller avec \(Biometrics.name)", systemImage: Biometrics.symbolName)
                .font(.body.weight(.semibold))
                .frame(maxWidth: .infinity, minHeight: 34)
        }
        .controlSize(.large)
        .disabled(model.lockState == .unlocking)
        #if compiler(>=6.2)
        if #available(iOS 26, *) {
            button.buttonStyle(.glassProminent)
        } else {
            button.buttonStyle(.borderedProminent)
        }
        #else
        button.buttonStyle(.borderedProminent)
        #endif
    }

    private var passwordField: some View {
        HStack(spacing: 8) {
            SecureField("Mot de passe principal", text: $password)
                .textContentType(.password)
                .submitLabel(.go)
                .focused($passwordFocused)
                .onSubmit(submit)
                .disabled(model.lockState == .unlocking)
            Button(action: submit) {
                if model.lockState == .unlocking {
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
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous)
            .strokeBorder(passwordFocused ? Theme.accent : Color.clear, lineWidth: 1.5))
    }

    private var subtitle: String {
        guard model.mode == .vaultwarden, let account = model.account else {
            return "Coffre fictif · données de démonstration"
        }
        let host = URL(string: account.server)?.host() ?? account.server
        return "\(account.email)\n\(host)"
    }

    private func submit() {
        let typed = password
        password = ""
        passwordFocused = false
        Task { await model.unlock(masterPassword: typed) }
    }
}
