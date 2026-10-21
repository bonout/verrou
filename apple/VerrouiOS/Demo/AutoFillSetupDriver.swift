#if DEBUG
import Foundation

/// Setup of the AutoFill test (Debug builds only):
/// `scripts/ios-autofill-e2e.sh` launches the app from the XCUITest test
/// with `VERROU_AUTOFILL_E2E_SERVER`, `_EMAIL`, `_PASSWORD`, `_TOTP` (seed
/// of the second factor), `_SITE` (the test page) and `_ACK` (folder on the
/// Mac where to report progress).
///
/// Unlike the app's run (`EndToEndDriver`), the account lives in its real
/// place, the app group folder: the extension must see it. The driver
/// signs in (TOTP second factor), creates the test site's login (with a
/// one-time code seed), syncs, waits for the Face ID seal and the
/// publication of the identities, opens the app's Settings, then creates
/// `<_ACK>/app-ready`.
@MainActor
final class AutoFillSetupDriver {
    struct Config {
        let server: String
        let email: String
        let password: String
        let totpSecret: String
        let site: String
        let ack: URL

        init?(_ environment: [String: String]) {
            guard let server = environment["VERROU_AUTOFILL_E2E_SERVER"],
                  let email = environment["VERROU_AUTOFILL_E2E_EMAIL"],
                  let password = environment["VERROU_AUTOFILL_E2E_PASSWORD"],
                  let secret = environment["VERROU_AUTOFILL_E2E_TOTP"],
                  let site = environment["VERROU_AUTOFILL_E2E_SITE"],
                  let ack = environment["VERROU_AUTOFILL_E2E_ACK"] else { return nil }
            self.server = server
            self.email = email
            self.password = password
            totpSecret = secret
            self.site = site
            self.ack = URL(fileURLWithPath: ack)
        }
    }

    /// The test site's login, which the test finds again in Safari.
    static let title = "Banc d'essai"
    static let username = "camille@verrou.test"
    static let sitePassword = "Verrou-AutoFill-42"
    static let codeSeed = "JBSWY3DPEHPK3PXP"

    private let model: PhoneModel
    private let config: Config

    init(model: PhoneModel, config: Config) {
        self.model = model
        self.config = config
    }

    func start() {
        Task {
            do {
                try await run()
                signal("app-ready")
            } catch {
                signal("app-failed", "\(error)")
            }
        }
    }

    private func signal(_ name: String, _ text: String = "") {
        print("AUTOFILL_E2E \(name) \(text)")
        try? FileManager.default.createDirectory(at: config.ack, withIntermediateDirectories: true)
        try? Data(text.utf8).write(to: config.ack.appending(path: name))
    }

    private struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    private func wait(_ seconds: Double, _ what: String, until condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition() {
            if Date() > deadline { throw Failure(description: "timed out: \(what)") }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    private func run() async throws {
        try? await Task.sleep(for: .seconds(1))
        if model.needsLogin {
            model.loginServer = config.server
            model.loginEmail = config.email
            await model.signIn(password: config.password)
            if model.twoFactorOptions != nil {
                let code = EndToEndDriver.totp(config.totpSecret, at: Date().timeIntervalSince1970)
                await model.answerTwoFactor(.authenticator, token: code)
            }
        } else if model.lockState != .unlocked {
            await model.unlock(masterPassword: config.password)
        }
        try await wait(60, "vault open") { model.lockState == .unlocked }
        if !model.summaries.contains(where: { $0.title == Self.title }) {
            let draft = ItemDraft(name: Self.title, folderId: nil, favorite: false, notes: nil,
                                  login: LoginFields(username: Self.username, password: Self.sitePassword,
                                                     totp: Self.codeSeed, urls: [config.site]),
                                  fields: [], template: nil)
            _ = try await model.session.createItem(draft: draft)
        }
        await model.syncNow()
        try await wait(30, "upload to the server") { model.pendingChanges == 0 }
        try await wait(30, "Face ID seal") { model.biometricEnrolled }
        model.tab = .settings
        await model.refreshAutofillStatus()
        try await wait(20, "Verrou enabled as provider") { model.autofillEnabled == true }
        // Publishing the identities follows the reload by a few hundred
        // milliseconds.
        try? await Task.sleep(for: .seconds(2))
    }
}
#endif
