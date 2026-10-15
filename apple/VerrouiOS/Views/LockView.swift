import SwiftUI

/// Coffre verrouillé : Face ID (ou Touch ID), sinon le mot de passe principal.
/// Même composition que l'écran verrouillé du Mac : halo d'accent, logo,
/// titre arrondi ; les commandes en verre au bas de l'écran (iOS 26).
struct LockView: View {
    @Environment(PhoneModel.self) private var model
    @State private var password = ""
    @FocusState private var passwordFocused: Bool

    var body: some View {
        ZStack {
            LockBackground()
            VStack(spacing: 28) {
                Spacer()
                VStack(spacing: 14) {
                    AppMark(size: 96)
                        .padding(.bottom, 6)
                    Text("Verrou")
                        .font(.system(size: 36, weight: .bold, design: .rounded))
                        .accessibilityAddTraits(.isHeader)
                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                Spacer()
                GlassGroup(spacing: 14) {
                    VStack(spacing: 14) {
                        if model.canUseBiometrics {
                            BiometricUnlockButton(title: "Déverrouiller avec \(Biometrics.name)",
                                                  symbol: Biometrics.symbolName,
                                                  busy: model.lockState == .unlocking) {
                                Task { await model.unlockWithBiometrics() }
                            }
                        }
                        MasterPasswordField(password: $password, busy: model.lockState == .unlocking,
                                            focused: $passwordFocused, submit: submit)
                    }
                }
                if let error = model.unlockError, !error.isEmpty {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                }
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 20)
            .frame(maxWidth: 520)
        }
        .animation(.snappy, value: model.unlockError)
        .sensoryFeedback(.error, trigger: model.unlockError) { _, new in new != nil }
        .onAppear {
            Perf.log.notice("écran verrouillé affiché à +\(Perf.msSinceLaunch) ms du lancement")
            if model.canUseBiometrics {
                Task { await model.promptBiometricsIfPossible() }
            }
        }
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
