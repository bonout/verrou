#if os(iOS) || os(macOS)
import AuthenticationServices
import CryptoKit
import Foundation
import os

/// Les suggestions du système (barre QuickType au-dessus du clavier, liste
/// de Safari) : le magasin d'identités d'AuthenticationServices.
///
/// L'app y publie, après chaque déverrouillage, synchronisation ou écriture,
/// les sites (domaines) et noms d'utilisateur de ses identifiants, les codes
/// à usage unique (iOS 18) et ses passkeys (site, utilisateur, identifiant de
/// l'accréditation). **Jamais un secret** : mot de passe, code et clé privée
/// ne sortent du coffre que dans l'extension, après Face ID ou le mot de
/// passe principal. Le magasin est vidé à la déconnexion ; le verrouillage
/// le garde (rien de secret, et les suggestions restent utiles).
enum CredentialIdentities {
    private static let log = Logger(subsystem: "app.verrou", category: "autofill")
    /// Empreinte de la dernière liste publiée : rien à refaire si elle n'a
    /// pas changé (la plupart des synchronisations).
    private static let publishedKey = "autofillIdentitiesDigest"

    /// Verrou est-il choisi dans Réglages → Général → Remplissage
    /// automatique et mots de passe ?
    static func isEnabled() async -> Bool {
        await ASCredentialIdentityStore.shared.state().isEnabled
    }

    /// Remplace les identités publiées par celles du coffre.
    static func publish(_ identities: [AutofillIdentity]) async {
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else {
            // Désactivé : le système a pu vider le magasin, tout republier
            // quand Verrou sera de nouveau choisi.
            UserDefaults.standard.removeObject(forKey: publishedKey)
            return
        }
        let digest = digest(of: identities)
        if UserDefaults.standard.string(forKey: publishedKey) == digest { return }
        var converted: [any ASCredentialIdentity] = []
        converted.reserveCapacity(identities.count)
        for identity in identities {
            if let value = convert(identity) { converted.append(value) }
        }
        do {
            try await store.replaceCredentialIdentities(converted)
            UserDefaults.standard.set(digest, forKey: publishedKey)
            log.notice("identités publiées : \(converted.count, privacy: .public)")
        } catch {
            log.error("publication des identités impossible : \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Déconnexion : plus aucune suggestion.
    static func clear() async {
        UserDefaults.standard.removeObject(forKey: publishedKey)
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }

    private static func convert(_ identity: AutofillIdentity) -> (any ASCredentialIdentity)? {
        switch identity.kind {
        case .password:
            return ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: identity.service, type: .domain),
                user: identity.user, recordIdentifier: identity.itemId)
        case .passkey:
            return ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: identity.service, userName: identity.user,
                credentialID: Data(identity.credentialId), userHandle: Data(identity.userHandle),
                recordIdentifier: identity.itemId)
        case .oneTimeCode:
            if #available(iOS 18.0, *) {
                return ASOneTimeCodeCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: identity.service, type: .domain),
                    label: identity.user, recordIdentifier: identity.itemId)
            }
            return nil
        }
    }

    /// Empreinte (SHA-256) de la liste : ni secret ni nom n'est gardé en clair.
    private static func digest(of identities: [AutofillIdentity]) -> String {
        var text = ""
        for identity in identities {
            text += "\(identity.kind)|\(identity.itemId)|\(identity.service)|\(identity.user)|"
            text += Data(identity.credentialId).base64EncodedString() + "\n"
        }
        return Data(SHA256.hash(data: Data(text.utf8))).base64EncodedString()
    }
}
#endif
