import Observation
import SwiftUI

/// "Create an account" on the login screen, for a person invited to a
/// server with closed sign-ups. The Rust core generates the keys (Bitwarden
/// SDK) and creates the account, then Verrou logs in and accepts the
/// organization's invitation if a link was pasted.
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
    /// "Join" link from the invitation (or verification) email.
    var link = "" { didSet { readLink() } }
    private(set) var linkInfo: SignupLinkInfo?
    private(set) var linkError: String?
    var busy = false
    var error: String?

    init(server: String, email: String) {
        self.server = server
        self.email = email
    }

    /// Prefills the server and the address from the pasted link.
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

    /// Strength from 0 to 4 (zxcvbn, like the Bitwarden apps).
    var strength: UInt8? {
        password.isEmpty ? nil : masterPasswordStrength(password: password, email: email,
                                                         name: name.isEmpty ? nil : name)
    }

    static let minimumLength = 12

    var problems: [String] {
        var list: [String] = []
        if !password.isEmpty && password.count < Self.minimumLength {
            list.append(String(localized: "At least \(Self.minimumLength) characters."))
        }
        if !confirmation.isEmpty && confirmation != password {
            list.append(String(localized: "The two passwords differ."))
        }
        if !hint.isEmpty && hint == password {
            list.append(String(localized: "The hint must not be the password."))
        }
        return list
    }

    var canSubmit: Bool {
        !busy && email.contains("@") && !server.isEmpty && password.count >= Self.minimumLength
            && confirmation == password && hint != password && linkError == nil
    }

    /// Forgets what was entered (password included).
    func reset() {
        password = ""
        confirmation = ""
    }
}

extension AppModel {
    /// Creates the account, logs in, then accepts the invitation (see
    /// `acceptPendingInvitation`, called once the vault is open).
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
