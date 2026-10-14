import SwiftUI

/// « Nouvelle clé SSH » : un titre, l'algorithme, le dossier. La clé est
/// générée par le cœur Rust et rangée comme les apps Bitwarden le font
/// (clé privée OpenSSH, clé publique, empreinte SHA256).
struct NewSshKeyView: View {
    @Environment(AppModel.self) private var model
    let generator: SshKeyGenerator
    @State private var name = "Clé SSH"
    @State private var type: SshKeyType = .ed25519
    @State private var folderID: String?
    @State private var busy = false
    @State private var error: String?
    @FocusState private var titleFocused: Bool

    init(generator: SshKeyGenerator) {
        self.generator = generator
        _folderID = State(initialValue: generator.folderID)
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Titre", text: $name, prompt: Text("GitHub, serveur maison…"))
                        .focused($titleFocused)
                    Picker("Type", selection: $type) {
                        Text("Ed25519 (recommandé)").tag(SshKeyType.ed25519)
                        Text("RSA 4096 bits").tag(SshKeyType.rsa4096)
                    }
                    Picker("Dossier", selection: $folderID) {
                        Text("Aucun").tag(String?.none)
                        ForEach(model.folders, id: \.id) { folder in
                            Text(folder.name).tag(Optional(folder.id))
                        }
                    }
                } footer: {
                    Text(type == .ed25519
                         ? "Courte et rapide, acceptée par GitHub, GitLab et tout serveur OpenSSH récent."
                         : "Pour les serveurs anciens qui n'acceptent que RSA. La génération prend quelques secondes.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section {
                    Label("La clé privée reste dans le coffre : l'agent SSH de Verrou signe pour ssh et git, après votre accord.",
                          systemImage: "lock.shield")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                if let error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack(spacing: 10) {
                Spacer()
                if busy {
                    ProgressView().controlSize(.small)
                    Text("Génération…").font(.callout).foregroundStyle(.secondary)
                }
                Button("Annuler") { model.sshKeyGenerator = nil }
                    .keyboardShortcut(.cancelAction)
                    .disabled(busy)
                Button("Générer") { create() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || busy)
            }
            .padding(16)
        }
        .frame(width: 480)
        .navigationTitle("Nouvelle clé SSH")
        .onAppear { titleFocused = true }
        .interactiveDismissDisabled(busy)
    }

    private func create() {
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                try await model.createSshKey(name: name, type: type, folderID: folderID)
            } catch {
                self.error = AppModel.describe(error)
            }
        }
    }
}
