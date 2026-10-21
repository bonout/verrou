// Not in the AutoFill extension: it opens no session and
// UIApplication.shared is off limits to it.
#if !AUTOFILL_EXTENSION
import AuthenticationServices
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Second factor by security key (YubiKey over FIDO2/WebAuthn).
///
/// WebAuthn checks that the page requesting the signature belongs to the
/// server's domain. A native app can only assert that with an associated
/// domain (Apple developer team, file on the server); Verrou therefore goes
/// through the page every Vaultwarden publishes for mobile apps,
/// `webauthn-mobile-connector.html`, opened in an ephemeral Safari session.
/// It signs the challenge with the key, then redirects to
/// `bitwarden://webauthn-callback?data=…`, which the session intercepts.
///
/// On iPhone, Safari talks to the key over NFC or the USB-C/Lightning port.
@MainActor
final class SecurityKeySignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    enum Failure: LocalizedError {
        case cancelled
        case page(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: String(localized: "Security key sign-in cancelled.")
            case .page(let message): String(localized: "The security key did not respond: \(message)")
            }
        }
    }

    private var session: ASWebAuthenticationSession?

    /// Returns the assertion's JSON, to send to the server as a token.
    func sign(server: String, challenge: String) async throws -> String {
        let payload: [String: Any] = [
            "data": challenge,
            "callbackUri": "bitwarden://webauthn-callback",
            "mobile": true,
            "headerText": "Verrou",
            "btnText": String(localized: "Use my security key"),
            "btnReturnText": String(localized: "Back to Verrou"),
        ]
        let json = try JSONSerialization.data(withJSONObject: payload)
        // The page decodes `data` after turning `+` into spaces: everything
        // that isn't alphanumeric must be encoded.
        let strict = CharacterSet.alphanumerics
        let encoded = json.base64EncodedString().addingPercentEncoding(withAllowedCharacters: strict)!
        let parent = "bitwarden://webauthn-callback".addingPercentEncoding(withAllowedCharacters: strict)!
        guard let url = URL(string: "\(server)/webauthn-mobile-connector.html?data=\(encoded)&parent=\(parent)&v=2") else {
            throw Failure.page(String(localized: "invalid address"))
        }

        let callback: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "bitwarden") { url, error in
                if let url {
                    continuation.resume(returning: url)
                } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
                    continuation.resume(throwing: Failure.cancelled)
                } else {
                    continuation.resume(throwing: Failure.page(error?.localizedDescription ?? String(localized: "empty response")))
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
        throw Failure.page(items.first(where: { $0.name == "error" })?.value ?? String(localized: "empty response"))
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            #if os(macOS)
            NSApp.windows.first { $0.identifier?.rawValue == "main" } ?? NSApp.keyWindow ?? ASPresentationAnchor()
            #else
            UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap(\.windows)
                .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
            #endif
        }
    }
}
#endif
