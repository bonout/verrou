import Foundation

/// Les erreurs du cœur Rust, en phrases pour l'utilisateur. Partagé par les
/// apps et, plus tard, l'extension de remplissage automatique.
enum ErrorText {
    /// L'appareil, dans les messages (« sur ce Mac », « sur cet iPhone »).
    static var onThisDevice: String {
        #if os(macOS)
        "sur ce Mac"
        #else
        "sur cet iPhone"
        #endif
    }

    static func describe(_ error: Error) -> String {
        guard let error = error as? VerrouError else { return error.localizedDescription }
        switch error {
        case .WrongPassword: return "Mot de passe principal incorrect."
        case .TwoFactorRejected(let message): return "Second facteur refusé (\(message))."
        case .NoAccount: return "Aucun compte n'est configuré \(onThisDevice)."
        case .SessionExpired: return "La session a expiré : reconnectez-vous."
        case .InvalidServer(let message): return "Adresse du serveur invalide : \(message)"
        case .Network(let message): return "Serveur injoignable : cette action a besoin du réseau. \(message)"
        case .Server(let message): return "Le serveur a répondu : \(message)"
        case .Crypto(let message): return "Déchiffrement impossible : \(message)"
        case .Storage(let message): return "Stockage local : \(message)"
        case .Locked: return "Le coffre est verrouillé."
        case .NotFound: return "Élément introuvable."
        case .InvalidTotp(let message): return "Code à usage unique invalide : \(message)"
        case .NoPendingLogin: return "Recommencez la connexion."
        case .SecurityKey(let message): return "Clé de sécurité : \(message)."
        case .ReadOnly: return "Cet élément est en lecture seule pour votre compte."
        case .Invalid(let message): return message.prefix(1).uppercased() + message.dropFirst() + "."
        case .Conflict: return "L'élément a changé sur le serveur : synchronisez, puis recommencez."
        case .RepromptRequired: return "Cet élément est protégé : confirmez d'abord votre identité."
        }
    }

    /// Une demande à la clé de sécurité annulée (par l'utilisateur ou par le
    /// changement de méthode) : rien à afficher.
    static func isCancellation(_ error: Error) -> Bool {
        if case VerrouError.SecurityKey(let message) = error, message == "demande annulée" { return true }
        return false
    }
}
