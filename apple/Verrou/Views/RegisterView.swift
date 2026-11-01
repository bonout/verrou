import SwiftUI

/// "Create an Account", on the login screen: for a person invited to a
/// server with closed sign-ups. Pasting the invitation link prefills the
/// server and the address.
struct RegisterStep: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: RegistrationFlow
    let cancel: () -> Void
    @FocusState private var focus: Field?

    enum Field { case link, server, email, name, password, confirmation, hint }

    var body: some View {
        VStack(spacing: 16) {
            VStack(spacing: 8) {
                Text("Create an Account")
                    .font(.system(.largeTitle, design: .rounded, weight: .bold))
                    .layoutMark("login-title")
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
            }

            VStack(spacing: 8) {
                LabeledField(label: "Invitation link (optional)") {
                    TextField("https://vault.example.com/#/accept-organization/?…", text: $flow.link)
                        .focused($focus, equals: .link)
                        .onSubmit { focus = .password }
                }
                if let error = flow.linkError {
                    hintLine(error, symbol: "exclamationmark.triangle.fill", tint: .orange)
                } else if let info = flow.linkInfo {
                    hintLine(info.organizationName.map { String(localized: "Invitation from \($0) for \(info.email)") }
                             ?? (info.invitation ? String(localized: "Invitation to the server for \(info.email)")
                                                 : String(localized: "Address to verify: \(info.email)")),
                             symbol: "checkmark.seal.fill", tint: .green)
                }
                LabeledField(label: "Server") {
                    TextField("https://vault.example.com", text: $flow.server)
                        .textContentType(.URL)
                        .focused($focus, equals: .server)
                        .onSubmit { focus = .email }
                }
                LabeledField(label: "Email") {
                    TextField("you@example.com", text: $flow.email)
                        .textContentType(.username)
                        .focused($focus, equals: .email)
                        .onSubmit { focus = .name }
                        .disabled(flow.linkInfo != nil)
                }
                LabeledField(label: "Name (seen by the other members)") {
                    TextField("Jane Doe", text: $flow.name)
                        .textContentType(.name)
                        .focused($focus, equals: .name)
                        .onSubmit { focus = .password }
                }
                LabeledField(label: "Master password") {
                    SecureField("", text: $flow.password)
                        .textContentType(.newPassword)
                        .focused($focus, equals: .password)
                        .onSubmit { focus = .confirmation }
                }
                MasterPasswordStrengthMeter(score: flow.strength)
                LabeledField(label: "Confirm the master password") {
                    SecureField("", text: $flow.confirmation)
                        .textContentType(.newPassword)
                        .focused($focus, equals: .confirmation)
                        .onSubmit { focus = .hint }
                }
                LabeledField(label: "Hint (optional, visible without password)") {
                    TextField("", text: $flow.hint)
                        .focused($focus, equals: .hint)
                        .onSubmit(submit)
                }
                ForEach(flow.problems, id: \.self) { problem in
                    hintLine(problem, symbol: "exclamationmark.circle", tint: .orange)
                }
                DisclosureGroup("Advanced") {
                    Picker("Key derivation", selection: $flow.kdf) {
                        Text("PBKDF2 (600,000 iterations)").tag(NewAccountKdfChoice.pbkdf2)
                        Text("Argon2id (64 MiB)").tag(NewAccountKdfChoice.argon2id)
                    }
                    .pickerStyle(.menu)
                    .font(.callout)
                    .help("PBKDF2: the default setting of the Bitwarden apps. Argon2id better withstands graphics card attacks.")
                    .padding(.top, 4)
                }
                .font(.callout)
            }
            .frame(width: 340)
            .disabled(flow.busy)

            Label {
                Text("The master password can't be recovered: without it, the vault is lost.")
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
            .font(.callout.weight(.medium))
            .padding(12)
            .frame(width: 340, alignment: .leading)
            .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: Theme.radiusMedium))

            Button(action: submit) {
                HStack(spacing: 8) {
                    if flow.busy { ProgressView().controlSize(.small) }
                    Text(flow.busy ? "Creating the account…" : "Create the Account")
                }
                .font(.body.weight(.semibold))
                .frame(width: 316, height: 30)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(!flow.canSubmit)

            if let error = flow.error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 340)
            }

            Button("I Already Have an Account") { cancel() }
                .buttonStyle(.link)
        }
        .onAppear { focus = .link }
        .announcing(flow.error)
    }

    private var subtitle: LocalizedStringKey {
        "To join a server by invitation: paste the “Join” link received by email. The keys of your vault are created on this Mac."
    }

    private func hintLine(_ text: String, symbol: String, tint: Color) -> some View {
        Label(text, systemImage: symbol)
            .font(.caption)
            .foregroundStyle(tint)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func submit() {
        guard flow.canSubmit else { return }
        Task {
            if await model.register(flow) { cancel() }
        }
    }
}

/// Strength of the master password (zxcvbn, 0 to 4).
struct MasterPasswordStrengthMeter: View {
    let score: UInt8?

    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                ForEach(0..<4) { index in
                    Capsule()
                        .fill(index < filled ? ContrastStyle(tint) : Theme.border(0.2))
                        .frame(height: 4)
                }
            }
            // The word in the meter's color; in the text color with
            // Increase Contrast (yellow on white can't be read), the bar
            // keeps the color.
            Text(label)
                .font(.caption)
                .foregroundStyle(score == nil ? AnyShapeStyle(.secondary)
                                              : AnyShapeStyle(ContrastStyle(normal: tint, increased: Color.primary)))
                .frame(width: 70, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Strength: \(label)")
    }

    private var filled: Int {
        guard let score else { return 0 }
        return max(1, Int(score))
    }

    private var label: String {
        switch score {
        case nil: String(localized: "Strength")
        case 0, 1: String(localized: "Weak")
        case 2: String(localized: "Fair")
        case 3: String(localized: "Good")
        default: String(localized: "Strong")
        }
    }

    private var tint: Color {
        switch score {
        case nil, 0, 1: .red
        case 2: .orange
        case 3: .yellow
        default: .green
        }
    }
}
