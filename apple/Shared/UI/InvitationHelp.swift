import SwiftUI

/// Ce qu'il faut savoir des invitations de Vaultwarden, pour l'invité et
/// pour celui qui invite (Mac et iPhone).
///
/// Vaultwarden 1.37 ne montre une invitation à l'invité qu'une fois
/// acceptée : tant qu'elle est « envoyée », seul l'e-mail la porte (sujet
/// « Join <organisation> », lien après « Click here to join »). Le serveur
/// ne rend le lien à personne d'autre : pas de « Copier le lien ».
enum InvitationHelp {
    /// L'hôte du serveur (« vault.exemple.fr »), pour dire d'où vient l'e-mail.
    static func host(_ server: String?) -> String? {
        guard let server, let host = URL(string: server)?.host() else { return nil }
        return host
    }

    /// Feuille « Rejoindre » : où trouver le lien.
    static func join(server: String?) -> String {
        let from = host(server).map { "l'e-mail de Vaultwarden (serveur \($0))" } ?? "l'e-mail de Vaultwarden"
        return "Ouvrez \(from), sujet « Join … », copiez le lien qui suit « Click here to join » puis collez-le ici. "
            + "Rien reçu ? Regardez dans les indésirables, ou demandez de renvoyer l'invitation."
    }

    /// Sous la feuille « Rejoindre » : pourquoi Verrou ne la montre pas.
    static let notListed = "Une invitation n'apparaît dans Verrou qu'une fois acceptée : avant, le serveur ne la montre qu'à l'e-mail. "
        + "Sur un serveur sans e-mail, l'invitation d'un compte existant est acceptée d'office : rien à coller."

    /// « Et ensuite ? », pour celui qui vient d'inviter.
    /// `email` absent : plusieurs invitations ; `hasAccount` absent : on ne
    /// sait pas si la personne a déjà un compte.
    static func nextSteps(email: String?, server: String?, hasAccount: Bool?) -> [String] {
        let where_ = host(server).map { " (\($0))" } ?? ""
        let accept = switch hasAccount {
        case true?: "La personne accepte : dans Verrou, « Rejoindre une organisation » en collant le lien, ou dans le coffre web."
        case false?: "La personne crée son compte avec ce lien (dans Verrou : « Créer un compte »), ce qui accepte l'invitation."
        case nil: "La personne accepte avec ce lien : « Rejoindre une organisation » si elle a un compte, sinon « Créer un compte »."
        }
        return [
            "Le serveur\(where_) envoie un e-mail à \(email ?? "chaque adresse"), sujet « Join … ». S'il n'arrive pas : indésirables, puis « Renvoyer l'invitation ».",
            "Le lien ne s'ouvre que là où le serveur est joignable : sur son réseau, ou par son VPN s'il n'est pas public.",
            accept,
            "Vous êtes prévenu quand elle a accepté : comparez sa phrase d'empreinte, puis confirmez-la ici.",
        ]
    }

    /// Pourquoi il n'y a pas de bouton « Copier le lien ».
    static let noLink = "Verrou ne peut pas copier le lien : Vaultwarden ne le donne qu'à l'e-mail de la personne invitée."
}

/// « Et ensuite ? » : les étapes d'une invitation envoyée.
struct InvitationNextSteps: View {
    let email: String?
    let server: String?
    let hasAccount: Bool?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Et ensuite ?", systemImage: "envelope.badge")
                .font(.headline)
            ForEach(Array(InvitationHelp.nextSteps(email: email, server: server, hasAccount: hasAccount).enumerated()),
                    id: \.offset) { index, step in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(index + 1).")
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                    Text(step)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.callout)
            }
            Text(InvitationHelp.noLink)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
