import SwiftUI

/// Échange avec une clé de sécurité (déverrouillage ou enrôlement) : ce que
/// la clé attend, le champ du code PIN, et « Annuler ».
struct SecurityKeyPanel: View {
    @Environment(AppModel.self) private var model
    @State private var pin = ""
    @FocusState private var pinFocused: Bool

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "key.horizontal.fill")
                .font(.system(size: 30))
                .foregroundStyle(Theme.accent)
                .symbolEffect(.pulse, isActive: model.keyPrompt != nil)
                .frame(height: 38)
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            if case .pin(let retry, let attemptsLeft) = model.keyPrompt {
                if retry {
                    Text(attemptsLeft.map { "Code PIN incorrect : \($0) essai\($0 > 1 ? "s" : "") restant\($0 > 1 ? "s" : "")." }
                         ?? "Code PIN incorrect.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                HStack(spacing: 8) {
                    SecureField("Code PIN de la clé", text: $pin)
                        .textFieldStyle(.roundedBorder)
                        .focused($pinFocused)
                        .onSubmit(submit)
                    Button("Valider", action: submit)
                        .keyboardShortcut(.defaultAction)
                        .disabled(pin.isEmpty)
                }
                .frame(width: 280)
                .onAppear { pinFocused = true }
            } else {
                ProgressView().controlSize(.small)
            }

            Button("Annuler") { model.cancelKeyExchange() }
                .buttonStyle(.link)
                .keyboardShortcut(.cancelAction)
        }
        .onDisappear { pin = "" }
    }

    private var message: String {
        switch model.keyPrompt {
        case .touch?: "Touchez votre clé de sécurité."
        case .pin?: "Saisissez le code PIN de votre clé de sécurité."
        case nil:
            model.keyExchange == .enroll
                ? "Branchez la clé de sécurité à ajouter."
                : "Branchez votre clé de sécurité."
        }
    }

    private func submit() {
        guard !pin.isEmpty else { return }
        let typed = pin
        pin = ""
        model.submitSecurityKeyPin(typed)
    }
}
