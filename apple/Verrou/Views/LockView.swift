import SwiftUI

struct LockView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @FocusState private var passwordFocused: Bool

    var body: some View {
        ZStack {
            LockBackground()
            VStack(spacing: 22) {
                AppMark(size: 84)
                VStack(spacing: 6) {
                    Text("Verrou")
                        .font(.system(size: 30, weight: .bold, design: .rounded))
                        .layoutMark("lock-title")
                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                VStack(spacing: 12) {
                    if model.keyExchange == .unlock {
                        SecurityKeyPanel()
                    } else {
                        unlockMethods
                    }

                    if let until = model.remoteSessionUntil {
                        // Opened by the iPhone for the terminal.
                        HStack(spacing: 8) {
                            Label("Open for the terminal (approved on the iPhone) until \(until.formatted(date: .omitted, time: .shortened))",
                                  systemImage: "iphone.radiowaves.left.and.right")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Button("Lock Now") { model.endRemoteSession(lock: true) }
                                .controlSize(.small)
                        }
                        .frame(maxWidth: 420)
                    }

                    if let error = model.unlockError, !error.isEmpty {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 360)
                            .transition(.opacity)
                    }
                }
            }
            .padding(48)
        }
        .frame(minWidth: 520, minHeight: 460)
        .onAppear {
            Perf.log.notice("lock screen shown at +\(Perf.msSinceLaunch) ms after launch")
            model.activatedAt = .now
            if model.canUseTouchID {
                Task { await model.promptTouchIDIfPossible() }
            } else {
                passwordFocused = true
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.activatedAt = .now
            Biometrics.refresh()
            Task { await model.promptTouchIDIfPossible() }
        }
    }

    /// Touch ID, security key, master password.
    @ViewBuilder
    private var unlockMethods: some View {
        if model.canUseTouchID {
            Button {
                Task { await model.unlockWithBiometrics() }
            } label: {
                Label("Unlock with Touch ID", systemImage: Biometrics.symbolName)
                    .font(.body.weight(.semibold))
                    .frame(width: 280, height: 30)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(model.lockState == .unlocking)
        }

        if model.canUseSecurityKey {
            securityKeyButton
        }

        HStack(spacing: 8) {
            SecureField("Master password", text: $password)
                .disabled(model.lockState == .unlocking)
                .textFieldStyle(.plain)
                .font(.body)
                .focused($passwordFocused)
                .onSubmit(submit)
            Button(action: submit) {
                if model.lockState == .unlocking {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.right.circle.fill")
                        .accessibilityLabel("Unlock")
                        .font(.title2)
                        .foregroundStyle(password.isEmpty ? Color.secondary : Theme.accent)
                }
            }
            .buttonStyle(.plain)
            .disabled(password.isEmpty)
            .accessibilityLabel("Unlock")
        }
        .padding(.horizontal, 12)
        .frame(width: 280, height: 38)
        .background(.background.opacity(0.7), in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(passwordFocused ? Theme.accent : Color.secondary.opacity(0.25)))
    }

    /// Highlighted when Touch ID is not offered.
    @ViewBuilder
    private var securityKeyButton: some View {
        let button = Button {
            Task { await model.unlockWithSecurityKey() }
        } label: {
            Label("Unlock with the Security Key", systemImage: "key.horizontal.fill")
                .font(.body.weight(.semibold))
                .frame(width: 280, height: 30)
        }
        .controlSize(.large)
        .disabled(model.lockState == .unlocking)
        if model.canUseTouchID {
            button.buttonStyle(.bordered)
        } else {
            button.buttonStyle(.borderedProminent)
        }
    }

    private var subtitle: String {
        guard model.mode == .vaultwarden, let account = model.account else {
            return String(localized: "Mock vault · demo data")
        }
        let host = URL(string: account.server)?.host() ?? account.server
        return "\(account.email) · \(host)"
    }

    private func submit() {
        let typed = password
        password = ""
        Task { await model.unlock(masterPassword: typed) }
    }
}
