import Observation
import SwiftUI

/// « Créer un compte » sur l'écran de connexion, pour une personne invitée
/// sur un serveur aux inscriptions fermées. Le cœur Rust génère les clés
/// (SDK de Bitwarden) et crée le compte, puis Verrou s'y connecte et
/// accepte l'invitation de l'organisation si un lien a été collé.
@MainActor
@Observable
final class RegistrationFlow {
    var server: String
    var email: String
    var name = ""
    var password = ""
    var confirmation = ""
    var hint = ""
    var kdf: NewAccountKdfChoice = .pbkdf2
    /// Lien « Rejoindre » du courriel d'invitation (ou de vérification).
    var link = "" { didSet { readLink() } }
    private(set) var linkInfo: SignupLinkInfo?
    private(set) var linkError: String?
    var busy = false
    var error: String?

    init(server: String, email: String) {
        self.server = server
        self.email = email
    }

    /// Préremplit le serveur et l'adresse d'après le lien collé.
    private func readLink() {
        let text = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else {
            linkInfo = nil
            linkError = nil
            return
        }
        do {
            let info = try parseSignupLink(text: text)
            linkInfo = info
            linkError = nil
            server = info.server
            email = info.email
        } catch {
            linkInfo = nil
            linkError = AppModel.describe(error)
        }
    }

    /// Robustesse de 0 à 4 (zxcvbn, comme les apps Bitwarden).
    var strength: UInt8? {
        password.isEmpty ? nil : masterPasswordStrength(password: password, email: email,
                                                         name: name.isEmpty ? nil : name)
    }

    static let minimumLength = 12

    var problems: [String] {
        var list: [String] = []
        if !password.isEmpty && password.count < Self.minimumLength {
            list.append("Au moins \(Self.minimumLength) caractères.")
        }
        if !confirmation.isEmpty && confirmation != password {
            list.append("Les deux mots de passe diffèrent.")
        }
        if !hint.isEmpty && hint == password {
            list.append("L'indice ne doit pas être le mot de passe.")
        }
        return list
    }

    var canSubmit: Bool {
        !busy && email.contains("@") && !server.isEmpty && password.count >= Self.minimumLength
            && confirmation == password && hint != password && linkError == nil
    }

    /// Oublie ce qui a été saisi (mot de passe compris).
    func reset() {
        password = ""
        confirmation = ""
    }
}

extension AppModel {
    /// Crée le compte, s'y connecte, puis accepte l'invitation (voir
    /// `acceptPendingInvitation`, appelée une fois le coffre ouvert).
    func register(_ flow: RegistrationFlow) async -> Bool {
        guard flow.canSubmit, !loginBusy else { return false }
        flow.busy = true
        flow.error = nil
        loginError = nil
        defer { flow.busy = false }
        loginServer = flow.server
        loginEmail = flow.email.trimmingCharacters(in: .whitespaces)
        let trimmedName = flow.name.trimmingCharacters(in: .whitespaces)
        let trimmedHint = flow.hint.trimmingCharacters(in: .whitespaces)
        let request = NewAccountRequest(server: flow.server, email: loginEmail,
                                        name: trimmedName.isEmpty ? nil : trimmedName,
                                        password: flow.password,
                                        passwordHint: trimmedHint.isEmpty ? nil : trimmedHint,
                                        kdf: flow.kdf, link: flow.link.isEmpty ? nil : flow.link)
        do {
            let result = try await session.registerAccount(request: request)
            flow.reset()
            await handle(result)
            return true
        } catch {
            flow.error = Self.describe(error)
            return false
        }
    }
}
