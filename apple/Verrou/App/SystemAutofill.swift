import AuthenticationServices
import Foundation

/// Fournisseur d'identifiants du système (Réglages → Général → Remplissage
/// automatique et mots de passe) : l'extension `VerrouAutoFillMac`, livrée
/// seulement dans un build signé par l'équipe (voir `VerrouStorage`).
///
/// L'app publie, après chaque rechargement du coffre, les sites, noms
/// d'utilisateur, codes et passkeys (jamais un secret) dans le magasin
/// d'identités d'AuthenticationServices : Safari et les apps les proposent,
/// puis l'extension remplit après Touch ID.
@MainActor
enum SystemAutofill {
    private static var task: Task<Void, Never>?

    /// L'extension est dans l'app (build signé par l'équipe, groupe d'apps).
    static var isBundled: Bool {
        VerrouStorage.appGroupID != nil
            && FileManager.default.fileExists(atPath: Bundle.main.builtInPlugInsURL?
                .appending(path: "VerrouAutoFillMac.appex").path ?? "")
    }

    /// Un instant après le dernier changement, hors du fil principal.
    static func publish(_ session: VaultSession) {
        guard isBundled, session.isUnlocked() else { return }
        task?.cancel()
        task = Task.detached(priority: .utility) {
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled, let identities = try? session.autofillIdentities() else { return }
            await CredentialIdentities.publish(identities)
        }
    }

    /// Déconnexion : plus aucune suggestion.
    static func clear() {
        task?.cancel()
        guard isBundled else { return }
        Task { await CredentialIdentities.clear() }
    }

    /// Verrou est-il choisi dans les réglages du système ?
    static func isEnabled() async -> Bool {
        guard isBundled else { return false }
        return await CredentialIdentities.isEnabled()
    }

    /// Ouvre les réglages où choisir Verrou.
    static func openSettings() {
        Task { try? await ASSettingsHelper.openCredentialProviderAppSettings() }
    }
}
