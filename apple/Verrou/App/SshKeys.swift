import SwiftUI

/// Génération d'une clé SSH en cours : la fenêtre « Nouvelle clé SSH ».
struct SshKeyGenerator: Identifiable {
    let id = UUID()
    /// Dossier affiché à l'ouverture : la clé y est rangée.
    let folderID: String?
}

extension AppModel {
    /// « Nouvelle clé SSH… » : Ed25519 par défaut, RSA 4096 au choix. La clé
    /// est tirée par le cœur Rust et rangée dans le coffre ; la clé privée ne
    /// passe jamais par Swift.
    func newSshKey() {
        guard canEdit else { return }
        var folderID: String?
        if case .folder(let name) = filter {
            folderID = folders.first { $0.name == name }?.id
        }
        sshKeyGenerator = SshKeyGenerator(folderID: folderID)
    }

    /// Génère la clé, l'enregistre, puis la sélectionne.
    func createSshKey(name: String, type: SshKeyType, folderID: String?) async throws {
        guard canEdit else { return }
        let id = try await session.createSshKey(name: name, folderId: folderID, keyType: type)
        afterWrite(select: id)
        sshKeyGenerator = nil
        toast = writeToast("Clé SSH créée", detail: "« Copier la clé publique » pour l'installer sur un serveur")
    }

    /// La clé publique (`ssh-ed25519 AAAA…`) : pas un secret, copiée telle quelle.
    func copyPublicKey(of itemID: String) {
        guard let detail = try? session.detail(id: itemID),
              let key = detail.fields.first(where: { $0.id == "public_key" })?.value,
              !key.isEmpty
        else {
            toast = Toast(message: "Pas de clé publique", detail: "Cet élément n'a pas de clé publique", failure: true)
            return
        }
        copy(key.trimmingCharacters(in: .whitespacesAndNewlines), label: "Clé publique", secret: false)
    }
}
