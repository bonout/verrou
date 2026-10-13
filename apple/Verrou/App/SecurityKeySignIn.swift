import AppKit
import AuthenticationServices

/// Second facteur par clé de sécurité (YubiKey en FIDO2/WebAuthn).
///
/// WebAuthn vérifie que la page qui demande la signature appartient au
/// domaine du serveur. Une app native ne peut l'affirmer qu'avec un domaine
/// associé (équipe de développeur Apple, fichier sur le serveur) ; Verrou
/// passe donc par la page que tout Vaultwarden publie pour les apps mobiles,
/// `webauthn-mobile-connector.html`, ouverte dans une session Safari éphémère.
/// Elle signe le défi avec la clé, puis redirige vers
/// `bitwarden://webauthn-callback?data=…`, que la session intercepte.
@MainActor
final class SecurityKeySignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    enum Failure: LocalizedError {
        case cancelled
        case page(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: "Connexion par clé de sécurité annulée."
            case .page(let message): "La clé de sécurité n'a pas répondu : \(message)"
            }
        }
    }

    private var session: ASWebAuthenticationSession?

    /// Rend le JSON de l'assertion, à envoyer au serveur comme jeton.
    func sign(server: String, challenge: String) async throws -> String {
        let payload: [String: Any] = [
            "data": challenge,
            "callbackUri": "bitwarden://webauthn-callback",
            "mobile": true,
            "headerText": "Verrou",
            "btnText": "Utiliser ma clé de sécurité",
            "btnReturnText": "Revenir à Verrou",
        ]
        let json = try JSONSerialization.data(withJSONObject: payload)
        // La page décode `data` après avoir changé les `+` en espaces : tout
        // ce qui n'est pas alphanumérique doit être encodé.
        let strict = CharacterSet.alphanumerics
        let encoded = json.base64EncodedString().addingPercentEncoding(withAllowedCharacters: strict)!
        let parent = "bitwarden://webauthn-callback".addingPercentEncoding(withAllowedCharacters: strict)!
        guard let url = URL(string: "\(server)/webauthn-mobile-connector.html?data=\(encoded)&parent=\(parent)&v=2") else {
            throw Failure.page("adresse invalide")
        }

        let callback: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "bitwarden") { url, error in
                if let url {
                    continuation.resume(returning: url)
                } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
                    continuation.resume(throwing: Failure.cancelled)
                } else {
                    continuation.resume(throwing: Failure.page(error?.localizedDescription ?? "réponse vide"))
                }
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            self.session = session
            session.start()
        }
        session = nil

        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        if let data = items.first(where: { $0.name == "data" })?.value, !data.isEmpty {
            return data
        }
        throw Failure.page(items.first(where: { $0.name == "error" })?.value ?? "réponse vide")
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            NSApp.windows.first { $0.identifier?.rawValue == "main" } ?? NSApp.keyWindow ?? ASPresentationAnchor()
        }
    }
}
