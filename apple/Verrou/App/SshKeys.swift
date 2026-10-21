import SwiftUI

/// SSH key generation in progress: the "New SSH Key" window.
struct SshKeyGenerator: Identifiable {
    let id = UUID()
    /// Folder displayed when opened: the key goes there.
    let folderID: String?
}

extension AppModel {
    /// "New SSH Key…": Ed25519 by default, RSA 4096 as an option. The key is
    /// drawn by the Rust core and stored in the vault; the private key never
    /// goes through Swift.
    func newSshKey() {
        guard canEdit else { return }
        var folderID: String?
        if case .folder(let name) = filter {
            folderID = folders.first { $0.name == name }?.id
        }
        sshKeyGenerator = SshKeyGenerator(folderID: folderID)
    }

    /// Generates the key, saves it, then selects it.
    func createSshKey(name: String, type: SshKeyType, folderID: String?) async throws {
        guard canEdit else { return }
        let id = try await session.createSshKey(name: name, folderId: folderID, keyType: type)
        afterWrite(select: id)
        sshKeyGenerator = nil
        toast = writeToast(String(localized: "SSH key created"),
                           detail: String(localized: "“Copy Public Key” to install it on a server"))
    }

    /// The public key (`ssh-ed25519 AAAA…`): not a secret, copied as is.
    func copyPublicKey(of itemID: String) {
        guard let detail = try? session.detail(id: itemID),
              let key = detail.fields.first(where: { $0.id == "public_key" })?.value,
              !key.isEmpty
        else {
            toast = Toast(message: String(localized: "No public key"),
                          detail: String(localized: "This item has no public key"), failure: true)
            return
        }
        copy(key.trimmingCharacters(in: .whitespacesAndNewlines), label: String(localized: "Public key"), secret: false)
    }
}
