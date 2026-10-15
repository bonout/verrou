#if DEBUG
import Foundation

/// Préparation du test du remplissage automatique (builds Debug
/// seulement) : `scripts/ios-autofill-e2e.sh` lance l'app depuis le test
/// XCUITest avec `VERROU_AUTOFILL_E2E_SERVER`, `_EMAIL`, `_PASSWORD`,
/// `_TOTP` (graine du second facteur), `_SITE` (la page de test) et
/// `_ACK` (dossier du Mac où signaler l'avancement).
///
/// Contrairement au parcours de l'app (`EndToEndDriver`), le compte vit à
/// sa vraie place, le dossier du groupe d'apps : l'extension doit le voir.
/// Le pilote se connecte (second facteur TOTP), crée l'identifiant du site
/// de test (avec une graine de code à usage unique), synchronise, attend le
/// scellement Face ID et la publication des identités, ouvre les Réglages
/// de l'app, puis crée `<_ACK>/app-ready`.
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

    /// L'identifiant du site de test, que le test retrouve dans Safari.
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
            if Date() > deadline { throw Failure(description: "délai dépassé : \(what)") }
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
        try await wait(60, "coffre ouvert") { model.lockState == .unlocked }
        if !model.summaries.contains(where: { $0.title == Self.title }) {
            let draft = ItemDraft(name: Self.title, folderId: nil, favorite: false, notes: nil,
                                  login: LoginFields(username: Self.username, password: Self.sitePassword,
                                                     totp: Self.codeSeed, urls: [config.site]),
                                  fields: [], template: nil)
            _ = try await model.session.createItem(draft: draft)
        }
        await model.syncNow()
        try await wait(30, "envoi au serveur") { model.pendingChanges == 0 }
        try await wait(30, "scellement Face ID") { model.biometricEnrolled }
        model.tab = .settings
        await model.refreshAutofillStatus()
        try await wait(20, "Verrou activé comme fournisseur") { model.autofillEnabled == true }
        // La publication des identités suit le rechargement de quelques
        // centaines de millisecondes.
        try? await Task.sleep(for: .seconds(2))
    }
}
#endif
