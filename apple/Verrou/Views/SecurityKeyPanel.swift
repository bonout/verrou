import SwiftUI

/// Exchange with a security key (unlock or enrollment): what the key is
/// waiting for, the PIN field, and "Cancel".
struct SecurityKeyPanel: View {
    @Environment(AppModel.self) private var model
    @State private var pin = ""
    @FocusState private var pinFocused: Bool

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "key.horizontal.fill")
                .accessibilityHidden(true)
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
                    Text(attemptsLeft.map { left in
                        left > 1 ? String(localized: "Incorrect PIN: \(Int(left)) attempts left.")
                                 : String(localized: "Incorrect PIN: \(Int(left)) attempt left.")
                    } ?? String(localized: "Incorrect PIN."))
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                HStack(spacing: 8) {
                    SecureField("Key PIN", text: $pin)
                        .textFieldStyle(.roundedBorder)
                        .focused($pinFocused)
                        .onSubmit(submit)
                    Button("Submit", action: submit)
                        .keyboardShortcut(.defaultAction)
                        .disabled(pin.isEmpty)
                }
                .frame(width: 280)
                .onAppear { pinFocused = true }
            } else {
                ProgressView().controlSize(.small)
            }

            Button("Cancel") { model.cancelKeyExchange() }
                .buttonStyle(.link)
                .keyboardShortcut(.cancelAction)
        }
        .onDisappear { pin = "" }
    }

    private var message: LocalizedStringKey {
        switch model.keyPrompt {
        case .touch?: "Touch your security key."
        case .pin?: "Enter your security key's PIN."
        case nil:
            model.keyExchange == .enroll
                ? "Plug in the security key to add."
                : "Plug in your security key."
        }
    }

    private func submit() {
        guard !pin.isEmpty else { return }
        let typed = pin
        pin = ""
        model.submitSecurityKeyPin(typed)
    }
}
