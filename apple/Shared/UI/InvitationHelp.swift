import SwiftUI

/// What to know about Vaultwarden invitations, for the invitee and for the
/// inviter (Mac and iPhone).
///
/// Vaultwarden 1.37 only shows an invitation to the invitee once accepted:
/// while it is "sent", only the email carries it (subject "Join
/// <organization>", link after "Click here to join"). The server gives the
/// link to no one else: no "Copy link".
enum InvitationHelp {
    /// The server's host ("vault.exemple.fr"), to say where the email comes from.
    static func host(_ server: String?) -> String? {
        guard let server, let host = URL(string: server)?.host() else { return nil }
        return host
    }

    /// "Join" sheet: where to find the link.
    static func join(server: String?) -> String {
        let from = host(server).map { String(localized: "the Vaultwarden email (server \($0))") } ?? String(localized: "the Vaultwarden email")
        return String(localized: "Open \(from), subject “Join …”, copy the link that follows “Click here to join” then paste it here. Nothing received? Look in spam, or ask for the invitation to be sent again.")
    }

    /// Under the "Join" sheet: why Verrou doesn't show it.
    static let notListed = String(localized: "An invitation only appears in Verrou once accepted: before that, the server only shows it to the email. On a server without email, the invitation of an existing account is accepted automatically: nothing to paste.")

    /// "What's next?", for the person who just invited.
    /// `email` missing: several invitations; `hasAccount` missing: we don't
    /// know whether the person already has an account.
    static func nextSteps(email: String?, server: String?, hasAccount: Bool?) -> [String] {
        let where_ = host(server).map { " (\($0))" } ?? ""
        let accept = switch hasAccount {
        case true?: String(localized: "The person accepts: in Verrou, “Join an organization” by pasting the link, or in the web vault.")
        case false?: String(localized: "The person creates their account with this link (in Verrou: “Create an account”), which accepts the invitation.")
        case nil: String(localized: "The person accepts with this link: “Join an organization” if they have an account, otherwise “Create an account”.")
        }
        return [
            String(localized: "The server\(where_) sends an email to \(email ?? String(localized: "each address")), subject “Join …”. If it doesn't arrive: spam, then “Resend invitation”."),
            String(localized: "The link only opens where the server is reachable: on its network, or through its VPN if it isn't public."),
            accept,
            String(localized: "You are notified when they have accepted: compare their fingerprint phrase, then confirm them here."),
        ]
    }

    /// Why there is no "Copy link" button.
    static let noLink = String(localized: "Verrou can't copy the link: Vaultwarden only gives it to the invited person's email.")
}

/// "What's next?": the steps of a sent invitation.
struct InvitationNextSteps: View {
    let email: String?
    let server: String?
    let hasAccount: Bool?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("What's next?", systemImage: "envelope.badge")
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
