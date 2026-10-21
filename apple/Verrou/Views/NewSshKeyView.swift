import SwiftUI

/// "New SSH Key": a title, the algorithm, the folder. The key is generated
/// by the Rust core and stored the way the Bitwarden apps do it (OpenSSH
/// private key, public key, SHA256 fingerprint).
struct NewSshKeyView: View {
    @Environment(AppModel.self) private var model
    let generator: SshKeyGenerator
    @State private var name = String(localized: "SSH key")
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
                    TextField("Title", text: $name, prompt: Text("GitHub, home server…"))
                        .focused($titleFocused)
                    Picker("Type", selection: $type) {
                        Text("Ed25519 (recommended)").tag(SshKeyType.ed25519)
                        Text("RSA 4096 bits").tag(SshKeyType.rsa4096)
                    }
                    Picker("Folder", selection: $folderID) {
                        Text("No folder").tag(String?.none)
                        ForEach(model.folders, id: \.id) { folder in
                            Text(folder.name).tag(Optional(folder.id))
                        }
                    }
                } footer: {
                    Text(type == .ed25519
                         ? "Short and fast, accepted by GitHub, GitLab and any recent OpenSSH server."
                         : "For old servers that only accept RSA. Generation takes a few seconds.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section {
                    Label("The private key stays in the vault: Verrou's SSH agent signs for ssh and git, after your approval.",
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
                    Text("Generating…").font(.callout).foregroundStyle(.secondary)
                }
                Button("Cancel") { model.sshKeyGenerator = nil }
                    .keyboardShortcut(.cancelAction)
                    .disabled(busy)
                Button("Generate") { create() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || busy)
            }
            .padding(16)
        }
        .frame(width: 480)
        .navigationTitle("New SSH Key")
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
