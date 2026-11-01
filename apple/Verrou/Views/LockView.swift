import SwiftUI

struct LockView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var confirmLogout = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        ZStack {
            LockBackground()
            VStack(spacing: 24) {
                AppMark(size: 84)
                VStack(spacing: 8) {
                    Text("Verrou")
                        .font(.system(.largeTitle, design: .rounded, weight: .bold))
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
        .overlay(alignment: .bottom) {
            if model.mode == .vaultwarden, model.account != nil, model.keyExchange == nil {
                Button("Log Out of This Mac…") {
                    model.refreshPending()
                    confirmLogout = true
                }
                .buttonStyle(.link)
                .font(.callout)
                .disabled(model.lockState == .unlocking)
                .help("Forgot your master password, or moved to another server? Log out, then log in again.")
                .padding(.bottom, 20)
            }
        }
        .modifier(LogoutConfirmation(isPresented: $confirmLogout))
        .frame(minWidth: 520, minHeight: 460)
        .announcing(model.unlockError)
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
                    .frame(minWidth: 280, minHeight: 30)
                    .fixedSize()
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
        .background(.background.opacity(0.7), in: RoundedRectangle(cornerRadius: Theme.radiusMedium))
        .overlay(RoundedRectangle(cornerRadius: Theme.radiusMedium).strokeBorder(passwordFocused ? Theme.focusRing() : Theme.border(0.25)))
    }

    /// Highlighted when Touch ID is not offered.
    @ViewBuilder
    private var securityKeyButton: some View {
        let button = Button {
            Task { await model.unlockWithSecurityKey() }
        } label: {
            Label("Unlock with Security Key", systemImage: "key.horizontal.fill")
                .font(.body.weight(.semibold))
                .frame(minWidth: 280, minHeight: 30)
                .fixedSize()
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
