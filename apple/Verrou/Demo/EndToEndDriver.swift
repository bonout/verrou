#if DEBUG
import AppKit
import CryptoKit
import SwiftUI

/// Parcours de bout en bout contre un Vaultwarden de test (builds Debug
/// seulement) : connexion, second facteur TOTP, coffre, verrouillage,
/// déverrouillage hors ligne, déconnexion. Lancé par `scripts/e2e.sh` avec
/// `VERROU_E2E_SERVER`, `_EMAIL`, `_PASSWORD` et `_TOTP` (graine).
///
/// Annonce `E2E_OUT <dossier>` (captures), `E2E_OK <étape>` à chaque
/// vérification, puis `E2E_DONE` ou `E2E_FAIL <raison>`.
@MainActor
final class EndToEndDriver {
    struct Config {
        let server: String
        let email: String
        let password: String
        let totpSecret: String

        init?(_ environment: [String: String]) {
            guard let server = environment["VERROU_E2E_SERVER"], let email = environment["VERROU_E2E_EMAIL"],
                  let password = environment["VERROU_E2E_PASSWORD"], let secret = environment["VERROU_E2E_TOTP"]
            else { return nil }
            self.server = server
            self.email = email
            self.password = password
            totpSecret = secret
        }
    }

    private let model: AppModel
    private let config: Config
    private let output = FileManager.default.temporaryDirectory.appending(path: "verrou-e2e")
    private var recorder: WindowRecorder?

    init(model: AppModel, config: Config) {
        self.model = model
        self.config = config
    }

    func start() {
        Task {
            await run()
            NSApp.terminate(nil)
        }
    }

    private func log(_ line: String) {
        print(line)
        fflush(stdout)
    }

    private func check(_ condition: Bool, _ step: String) {
        if condition {
            log("E2E_OK \(step)")
        } else {
            log("E2E_FAIL \(step)")
            exit(1)
        }
    }

    private func snap(_ name: String) async {
        try? await Task.sleep(for: .seconds(0.6))
        if let image = recorder?.snapshot() {
            try? WindowSnapshot.writePNG(image, to: output.appending(path: "\(name).png"))
        }
    }

    private func run() async {
        try? await Task.sleep(for: .seconds(1))
        let window = NSApp.windows.first { !($0 is NSPanel) && $0.canBecomeMain }
        window?.setFrame(NSRect(x: 120, y: 120, width: 1280, height: 800), display: true, animate: false)
        try? FileManager.default.removeItem(at: output)
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        log("E2E_OUT \(output.path)")
        if let window {
            do {
                let recorder = try await WindowRecorder(url: output.appending(path: "e2e.mov"), main: window)
                try await recorder.start()
                self.recorder = recorder
            } catch {
                // Les vérifications ne dépendent pas des captures : on continue.
                log("E2E_WARN captures indisponibles : \(error.localizedDescription)")
            }
        }

        check(model.needsLogin, "écran de connexion sans compte")
        model.loginServer = config.server
        model.loginEmail = config.email
        await snap("20-connexion")

        await model.signIn(password: "pas le bon mot de passe")
        check(model.loginError?.contains("incorrect") == true, "mauvais mot de passe refusé")

        await model.signIn(password: config.password)
        check(model.twoFactorOptions == [.authenticator], "second facteur demandé")
        await snap("21-second-facteur")

        await model.answerTwoFactor(.authenticator, token: "000000")
        check(model.loginError != nil && model.lockState != .unlocked, "mauvais code refusé")
        // Le code de la période courante peut avoir déjà servi : on tente aussi
        // la suivante, que le serveur tolère.
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0] where model.lockState != .unlocked {
            await model.answerTwoFactor(.authenticator, token: Self.totp(config.totpSecret, at: now + offset))
        }
        check(model.lockState == .unlocked, "coffre ouvert après le second facteur")
        check(model.counts?.all == 9 && model.counts?.trashed == 1,
              "9 éléments déchiffrés, 1 à la corbeille (\(model.counts?.all ?? 0), \(model.counts?.trashed ?? 0))")
        check(model.counts?.folders.map(\.name).sorted() == ["Personnel", "Travail"], "dossiers déchiffrés")
        check(model.biometricEnrolled == Biometrics.isAvailable, "Touch ID enrôlé si disponible")

        if let github = model.summaries.first(where: { $0.title == "GitHub" }) {
            model.selection = github.id
            model.toggleReveal("password", of: github.id)
            check(model.revealed["password"] == "hunter2-hunter2", "mot de passe révélé")
        }
        if let github = model.summaries.first(where: { $0.title == "GitHub" }), let host = github.host {
            _ = model.siteIcons.image(for: host)
            for _ in 0..<100 where model.siteIcons.images[SiteIcons.site(of: host)] == nil {
                try? await Task.sleep(for: .milliseconds(100))
            }
            check(model.siteIcons.images[SiteIcons.site(of: host)] != nil, "icône du site servie par Vaultwarden")
        }
        await snap("22-coffre-vaultwarden")

        await model.syncNow()
        check(model.syncState == .idle, "synchronisation par jeton de renouvellement")

        // Audit : calculé sur le coffre, sans réseau.
        model.openAudit()
        check(model.showAudit && (model.audit?.checked ?? 0) >= 5, "audit du coffre (\(model.audit?.checked ?? 0) mots de passe)")
        await snap("23-audit")
        model.filter = .all
        check(!model.showAudit, "retour à la liste")

        // Écriture : créer, modifier, mettre à la corbeille.
        model.newItem(login: true)
        let generated = model.editor?.draft.login?.password ?? ""
        check(generated.count == 20, "nouvel identifiant avec un mot de passe généré")
        if var draft = model.editor?.draft {
            draft.name = "Créé par Verrou"
            draft.login?.username = "e2e@verrou.test"
            draft.login?.urls = ["https://exemple.fr"]
            await model.saveEditor(draft)
        }
        let created = model.summaries.first { $0.title == "Créé par Verrou" }
        check(model.editor == nil && created != nil && model.selection == created?.id, "élément créé sur le serveur")
        if let created {
            await model.edit(created.id)
            check(model.editor?.draft.login?.password == generated, "brouillon prérempli, secrets compris")
            await snap("24-modification")
            if var draft = model.editor?.draft {
                draft.name = "Modifié par Verrou"
                draft.login?.password = "nouveau-mot-de-passe"
                await model.saveEditor(draft)
            }
            check(model.reveal("password", of: created.id) == "nouveau-mot-de-passe"
                  && model.summaries.contains { $0.title == "Modifié par Verrou" }, "modification enregistrée")
            await model.trash(created.id)
            let state = { [model] in model.summaries.first { $0.id == created.id }?.state }
            check(state() == .trashed && model.counts?.all == 9, "mis à la corbeille")
            model.filter = .trash
            check(model.rows.contains { $0.id == created.id }, "visible dans la corbeille")
            await model.restore(created.id)
            check(state() == .active, "restauré")
            // Vaultwarden refuse une modification datée de la même seconde.
            try? await Task.sleep(for: .seconds(1.5))
            await model.setArchived(created.id, true)
            model.filter = .all
            check(state() == .archived && !model.rows.contains { $0.id == created.id }, "archivé, hors de la liste")
            await model.setArchived(created.id, false)
            try? await Task.sleep(for: .seconds(1.5))
            await model.setFavorite(created.id, true)
            check(state() == .active && model.summaries.first { $0.id == created.id }?.favorite == true,
                  "sorti des archives, mis en favori")
            check(model.selectedDetail?.fields.contains { $0.id.hasPrefix("history-") } ?? false
                  || model.selection != created.id, "historique des mots de passe")
            await model.trash(created.id)
        }

        // Pont vers Brave, sur un port de test : écoute TCP et écriture des
        // déclarations Native Messaging, sous le sandbox de l'app.
        if ProcessInfo.processInfo.environment["VERROU_BRIDGE_PORT"] != nil {
            let bridge = BrowserBridge(model: model)
            model.browserBridge = bridge
            bridge.enabled = true
            check(bridge.running && bridge.error == nil, "pont vers Brave à l'écoute dans le sandbox (\(bridge.error ?? "ok"))")
            bridge.enabled = false
            check(!bridge.running, "pont arrêté")
        }

        model.lock()
        check(model.lockState == .locked && !model.needsLogin, "verrouillé, compte conservé")
        await snap("23-verrouille")

        await model.unlock(masterPassword: "faux")
        check(model.unlockError == "Mot de passe principal incorrect.", "mauvais mot de passe au déverrouillage")
        await model.unlock(masterPassword: config.password)
        check(model.lockState == .unlocked && model.counts?.all == 9, "déverrouillage hors ligne par mot de passe")

        model.logout()
        check(model.needsLogin && !model.biometricEnrolled && model.account == nil, "déconnexion")
        await recorder?.finish()
        log("E2E_DONE")
    }

    /// RFC 6238 (SHA-1, 6 chiffres, 30 s), pour répondre au second facteur.
    static func totp(_ secret: String, at time: TimeInterval) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, value = 0
        var key = Data()
        for character in secret.uppercased() where character != "=" {
            guard let index = alphabet.firstIndex(of: character) else { continue }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                key.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        var counter = UInt64(time / 30).bigEndian
        let message = Data(bytes: &counter, count: 8)
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        let offset = Int(mac[19] & 0x0F)
        let code = (UInt32(mac[offset] & 0x7F) << 24 | UInt32(mac[offset + 1]) << 16
            | UInt32(mac[offset + 2]) << 8 | UInt32(mac[offset + 3])) % 1_000_000
        return String(format: "%06u", code)
    }
}
#endif
