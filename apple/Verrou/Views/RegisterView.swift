import SwiftUI

/// « Créer un compte », sur l'écran de connexion : pour une personne invitée
/// sur un serveur aux inscriptions fermées. Coller le lien de l'invitation
/// préremplit le serveur et l'adresse.
struct RegisterStep: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: RegistrationFlow
    let cancel: () -> Void
    @FocusState private var focus: Field?

    enum Field { case link, server, email, name, password, confirmation, hint }

    var body: some View {
        VStack(spacing: 18) {
            VStack(spacing: 6) {
                Text("Créer un compte")
                    .font(.system(size: 26, weight: .bold, design: .rounded))
                    .layoutMark("login-title")
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
            }

            VStack(spacing: 10) {
                LabeledField(label: "Lien d'invitation (facultatif)") {
                    TextField("https://vault.exemple.fr/#/accept-organization/?…", text: $flow.link)
                        .focused($focus, equals: .link)
                        .onSubmit { focus = .password }
                }
                if let error = flow.linkError {
                    hintLine(error, symbol: "exclamationmark.triangle.fill", tint: .orange)
                } else if let info = flow.linkInfo {
                    hintLine(info.organizationName.map { "Invitation de \($0) pour \(info.email)" }
                             ?? (info.invitation ? "Invitation au serveur pour \(info.email)"
                                                 : "Adresse à vérifier : \(info.email)"),
                             symbol: "checkmark.seal.fill", tint: .green)
                }
                LabeledField(label: "Serveur") {
                    TextField("https://vault.exemple.fr", text: $flow.server)
                        .textContentType(.URL)
                        .focused($focus, equals: .server)
                        .onSubmit { focus = .email }
                }
                LabeledField(label: "E-mail") {
                    TextField("vous@exemple.fr", text: $flow.email)
                        .textContentType(.username)
                        .focused($focus, equals: .email)
                        .onSubmit { focus = .name }
                        .disabled(flow.linkInfo != nil)
                }
                LabeledField(label: "Nom (vu par les autres membres)") {
                    TextField("Léa Martin", text: $flow.name)
                        .textContentType(.name)
                        .focused($focus, equals: .name)
                        .onSubmit { focus = .password }
                }
                LabeledField(label: "Mot de passe principal") {
                    SecureField("", text: $flow.password)
                        .textContentType(.newPassword)
                        .focused($focus, equals: .password)
                        .onSubmit { focus = .confirmation }
                }
                MasterPasswordStrengthMeter(score: flow.strength)
                LabeledField(label: "Confirmer le mot de passe principal") {
                    SecureField("", text: $flow.confirmation)
                        .textContentType(.newPassword)
                        .focused($focus, equals: .confirmation)
                        .onSubmit { focus = .hint }
                }
                LabeledField(label: "Indice (facultatif, visible sans mot de passe)") {
                    TextField("", text: $flow.hint)
                        .focused($focus, equals: .hint)
                        .onSubmit(submit)
                }
                Picker("Dérivation de la clé", selection: $flow.kdf) {
                    Text("PBKDF2 (600 000 itérations)").tag(NewAccountKdfChoice.pbkdf2)
                    Text("Argon2id (64 Mio)").tag(NewAccountKdfChoice.argon2id)
                }
                .pickerStyle(.menu)
                .font(.callout)
                .help("PBKDF2 : le réglage par défaut des apps Bitwarden. Argon2id résiste mieux aux attaques par carte graphique.")
                ForEach(flow.problems, id: \.self) { problem in
                    hintLine(problem, symbol: "exclamationmark.circle", tint: .orange)
                }
            }
            .frame(width: 340)
            .disabled(flow.busy)

            Text("Le mot de passe principal ne peut pas être récupéré : sans lui, le coffre est perdu.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(width: 340)

            Button(action: submit) {
                HStack(spacing: 8) {
                    if flow.busy { ProgressView().controlSize(.small) }
                    Text(flow.busy ? "Création du compte…" : "Créer le compte")
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

            Button("J'ai déjà un compte") { cancel() }
                .buttonStyle(.link)
        }
        .onAppear { focus = .link }
    }

    private var subtitle: String {
        "Pour rejoindre un serveur sur invitation : collez le lien « Rejoindre » reçu par e-mail. Les clés de votre coffre sont créées sur ce Mac."
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

/// Robustesse du mot de passe principal (zxcvbn, 0 à 4).
struct MasterPasswordStrengthMeter: View {
    let score: UInt8?

    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 3) {
                ForEach(0..<4) { index in
                    Capsule()
                        .fill(index < filled ? tint : Color.secondary.opacity(0.2))
                        .frame(height: 4)
                }
            }
            Text(label)
                .font(.caption)
                .foregroundStyle(score == nil ? .secondary : tint)
                .frame(width: 70, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Robustesse : \(label)")
    }

    private var filled: Int {
        guard let score else { return 0 }
        return max(1, Int(score))
    }

    private var label: String {
        switch score {
        case nil: "Robustesse"
        case 0, 1: "Faible"
        case 2: "Moyen"
        case 3: "Bon"
        default: "Fort"
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
