#if DEBUG
import CryptoKit
import SwiftUI
import UIKit

/// Parcours de bout en bout de l'app iPhone contre un Vaultwarden de test
/// (builds Debug seulement), dans le simulateur : connexion, second facteur
/// TOTP, coffre, recherche, révélation, copie, élément protégé (Face ID
/// simulé), QR code Wi-Fi, création et modification, carte, actions
/// groupées, modification hors ligne et resynchronisation, verrouillage,
/// Face ID, déconnexion.
///
/// Lancé par `scripts/ios-e2e.sh` avec `VERROU_E2E_SERVER`, `_EMAIL`,
/// `_PASSWORD` et `_TOTP` (graine), passés par `SIMCTL_CHILD_*`. Il annonce
/// sur sa sortie standard (lue par le script) :
///
/// - `E2E_OK <étape>` à chaque vérification, `E2E_DONE` ou `E2E_FAIL <raison>` ;
/// - `E2E_SNAP <nom>` : l'écran est prêt, le script prend la capture
///   (`xcrun simctl io … screenshot`) ;
/// - `E2E_FACEID` : une demande Face ID attend, le script présente un visage
///   reconnu (`notifyutil … pearl.match`) ;
/// - `E2E_NET off|on` : le script coupe ou rétablit le relais vers le serveur.
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

    private let model: PhoneModel
    private let config: Config

    init(model: PhoneModel, config: Config) {
        self.model = model
        self.config = config
    }

    func start() {
        Task {
            await run()
            log("E2E_DONE")
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

    private func pause(_ seconds: Double) async {
        try? await Task.sleep(for: .seconds(seconds))
    }

    /// Laisse l'écran se poser, demande la capture et attend qu'elle soit
    /// prise : le script crée alors `<VERROU_E2E_ACK>/<nom>` (les apps du
    /// simulateur voient le disque du Mac), sinon on attend 3 s.
    private func snap(_ name: String) async {
        await pause(1.0)
        log("E2E_SNAP \(name)")
        guard let ack = ProcessInfo.processInfo.environment["VERROU_E2E_ACK"] else {
            await pause(3)
            return
        }
        let marker = URL(fileURLWithPath: ack).appending(path: name)
        _ = await wait(15) { FileManager.default.fileExists(atPath: marker.path) }
    }

    /// Attend une condition (au plus `seconds`).
    private func wait(_ seconds: Double, until condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition() {
            if Date() > deadline { return false }
            await pause(0.25)
        }
        return true
    }

    private func id(of title: String) -> String? {
        model.summaries.first { $0.title == title }?.id
    }

    private func run() async {
        await pause(1.5)

        // Connexion
        check(model.needsLogin, "écran de connexion sans compte")
        model.loginServer = config.server
        model.loginEmail = config.email
        await snap("01-connexion")
        await model.signIn(password: "pas le bon mot de passe")
        check(model.loginError?.contains("incorrect") == true, "mauvais mot de passe refusé")
        await model.signIn(password: config.password)
        check(model.twoFactorOptions == [.authenticator], "second facteur demandé")
        await snap("02-second-facteur")
        await model.answerTwoFactor(.authenticator, token: "000000")
        check(model.loginError != nil && model.lockState != .unlocked, "mauvais code refusé")
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0] where model.lockState != .unlocked {
            await model.answerTwoFactor(.authenticator, token: Self.totp(config.totpSecret, at: now + offset))
        }
        check(model.lockState == .unlocked, "coffre ouvert après le second facteur")
        check(model.counts?.all == 9 && model.counts?.trashed == 1,
              "9 éléments déchiffrés, 1 à la corbeille (\(model.counts?.all ?? 0), \(model.counts?.trashed ?? 0))")
        check(model.counts?.folders.map(\.name).sorted() == ["Personnel", "Travail"], "dossiers déchiffrés")
        check(model.vault.location.directory.path.contains("verrou-e2e-data"), "compte dans le dossier jetable")
        check(model.biometricEnrolled == Biometrics.isAvailable,
              "Face ID enrôlé s'il est disponible (\(Biometrics.isAvailable ? "oui" : "non"))")
        // La synchronisation du déverrouillage d'abord, puis une à la demande.
        _ = await wait(30) { model.syncState != .syncing }
        await model.syncNow()
        check(model.syncState == .idle, "synchronisation")
        await snap("03-coffre")

        // Recherche (cœur Rust), sans accents ni majuscules, dans l'onglet Rechercher
        model.tab = .search
        model.searchQuery = "gith"
        check(model.rows(query: "gith", filter: .all).first?.summary.title == "GitHub", "recherche floue")
        check(model.rows(query: "telecom", filter: .all).isEmpty, "recherche sans résultat")
        await snap("04-recherche")
        model.searchQuery = ""
        model.tab = .vault

        // Fiche, révélation, copie
        guard let github = id(of: "GitHub") else { return check(false, "GitHub présent") }
        model.open(github)
        model.toggleReveal("password", of: github)
        check(model.revealedValue("password", of: github) == "hunter2-hunter2", "mot de passe révélé")
        check(model.totpCode(of: github)?.code.count == 6, "code à usage unique")
        model.copyPassword(of: github)
        check(UIPasteboard.general.string == "hunter2-hunter2", "mot de passe copié (local, expirant)")
        await snap("05-identifiant")
        model.vaultPath = []
        await pause(0.8)
        check(model.revealedValue("password", of: github) == nil, "secrets oubliés en quittant la fiche")

        // Élément protégé : Face ID (simulé) ou mot de passe principal
        guard let bank = id(of: "Banque") else { return check(false, "Banque présente") }
        model.open(bank)
        await pause(0.8)
        check(model.session.needsConfirmation(id: bank), "élément protégé : confirmation demandée")
        model.toggleReveal("password", of: bank)
        if Biometrics.isAvailable {
            await pause(1.5)
            log("E2E_FACEID")
        } else {
            _ = await wait(5) { model.reprompt != nil }
            await snap("06-mot-de-passe-principal")
            await model.answerReprompt(password: config.password)
        }
        check(await wait(15) { model.revealedValue("password", of: bank) != nil },
              "élément protégé révélé après confirmation")
        await snap("06-element-protege")
        model.vaultPath = []

        // Carte, Wi-Fi
        if let visa = id(of: "Visa") {
            model.open(visa)
            await snap("07-carte")
            model.vaultPath = []
        }
        guard let wifi = id(of: "Wi-Fi maison") else { return check(false, "réseau Wi-Fi présent") }
        check(model.summary(id: wifi)?.template == .wifi, "modèle Wi-Fi reconnu")
        model.open(wifi)
        await pause(0.6)
        model.showWifiQRCode(of: wifi)
        check(model.qrSheet != nil, "QR code du Wi-Fi")
        await snap("08-wifi-qr")
        model.qrSheet = nil
        model.vaultPath = []

        // Création et modification
        model.newItem(.login)
        let generated = model.editor?.draft.login?.password ?? ""
        check(generated.count == 20, "nouvel identifiant avec un mot de passe généré")
        if var draft = model.editor?.draft {
            draft.name = "Créé sur iPhone"
            draft.login?.username = "iphone@verrou.test"
            draft.login?.urls = ["https://exemple.fr"]
            model.editor = PhoneModel.Editor(itemID: nil, draft: draft)
            await snap("09-nouvel-identifiant")
            await model.saveEditor(draft)
        }
        // Écrit localement : la feuille se ferme aussitôt, l'envoi suit en arrière-plan.
        check(model.editor == nil, "feuille fermée sans attendre le serveur")
        guard case .item(let opened)? = model.vaultPath.last, model.summary(id: opened)?.title == "Créé sur iPhone"
        else { return check(false, "élément créé, fiche ouverte") }
        check(await wait(20) { model.pendingChanges == 0 && model.syncState == .idle }, "élément envoyé au serveur")
        guard let created = id(of: "Créé sur iPhone") else { return check(false, "élément créé sur le serveur") }
        check(model.vaultPath.last == .item(created), "la fiche suit l'identifiant du serveur")
        await pause(1.2)
        await model.edit(created)
        check(model.editor?.draft.login?.password == generated, "brouillon prérempli, secrets compris")
        if var draft = model.editor?.draft {
            draft.name = "Modifié sur iPhone"
            draft.login?.password = "nouveau-mot-de-passe"
            draft.fields.append(CustomField(name: "PIN", value: "2468", fieldType: .hidden, linkedId: nil))
            model.editor = PhoneModel.Editor(itemID: created, draft: draft)
            await snap("10-modification")
            await model.saveEditor(draft)
        }
        model.toggleReveal("password", of: created)
        check(model.revealedValue("password", of: created) == "nouveau-mot-de-passe"
              && model.summary(id: created)?.title == "Modifié sur iPhone", "modification enregistrée")
        check(model.detail(id: created)?.fields.contains { $0.label == "PIN" } == true, "champ personnalisé ajouté")
        model.vaultPath = []
        await pause(1.2)

        // Carte bancaire créée sur l'iPhone
        model.newItem(.card)
        if var draft = model.editor?.draft {
            draft.name = "Carte du test"
            draft.card?.cardholderName = "CAMILLE MARTIN"
            draft.card?.number = "5555555555554444"
            draft.card?.brand = "Mastercard"
            draft.card?.expMonth = "4"
            draft.card?.expYear = "2030"
            draft.card?.code = "321"
            model.editor = PhoneModel.Editor(itemID: nil, draft: draft)
            await snap("11-nouvelle-carte")
            await model.saveEditor(draft)
        }
        guard let card = id(of: "Carte du test") else { return check(false, "carte créée") }
        check(model.summary(id: card)?.category == .card, "créée comme carte bancaire")
        model.toggleReveal("number", of: card)
        check(model.revealedValue("number", of: card)?.filter(\.isNumber) == "5555555555554444", "numéro de carte enregistré")
        model.vaultPath = []
        await pause(1.2)

        // Actions groupées : favoris puis archives (identifiants du serveur,
        // une fois la carte envoyée)
        _ = await wait(20) { model.pendingChanges == 0 && model.syncState == .idle }
        let pair = ["Modifié sur iPhone", "Carte du test"].compactMap { id(of: $0) }
        check(pair.count == 2, "éléments créés retrouvés")
        await model.performBulk(.favorite(favorite: true), on: pair)
        check(pair.allSatisfy { model.summary(id: $0)?.favorite == true },
              "deux éléments mis en favoris (\(model.toast?.message ?? "") \(model.toast?.detail ?? ""))")
        model.vaultPath = [.list(.favorites)]
        await snap("12-favoris")
        await pause(1.2)
        await model.performBulk(.archive, on: pair)
        check(pair.allSatisfy { model.summary(id: $0)?.state == .archived }, "deux éléments archivés")
        model.vaultPath = []

        // Hors ligne : la modification attend, puis part au retour du réseau
        log("E2E_NET off")
        await pause(1.5)
        check(await wait(30) {
            if model.syncState != .offline, model.syncState != .syncing { Task { await model.syncNow() } }
            return model.syncState == .offline
        }, "serveur injoignable : hors ligne")
        await model.setFavorite(github, false)
        check(model.pendingChanges > 0 && model.summary(id: github)?.pendingSync == true,
              "modification hors ligne en attente (\(model.pendingChanges))")
        model.open(github)
        await snap("13-hors-ligne")
        model.vaultPath = []
        log("E2E_NET on")
        await pause(1.5)
        check(await wait(40) {
            if model.syncState != .syncing, model.pendingChanges > 0 { Task { await model.syncNow() } }
            return model.pendingChanges == 0 && model.syncState == .idle
        }, "modification hors ligne synchronisée")
        check(model.summary(id: github)?.favorite == false && model.summary(id: github)?.pendingSync == false,
              "état du serveur après synchronisation")

        // Audit, générateur, réglages
        model.openAudit()
        check((model.audit?.checked ?? 0) >= 4, "audit du coffre (\(model.audit?.checked ?? 0) mots de passe)")
        await snap("14-audit")
        model.vaultPath = []
        model.tab = .generator
        await snap("15-generateur")
        model.tab = .settings
        await snap("16-reglages")
        model.tab = .vault

        // Verrouillage, mot de passe, Face ID
        // Un secret copié juste avant : le verrouillage l'efface.
        model.copyPassword(of: github)
        check(UIPasteboard.general.string == "hunter2-hunter2", "secret copié avant le verrouillage")
        model.lock()
        check(model.lockState == .locked && !model.needsLogin && model.summaries.isEmpty, "verrouillé, coffre effacé")
        check(UIPasteboard.general.string != "hunter2-hunter2", "presse-papiers effacé au verrouillage")
        await snap("17-verrouille")
        await model.unlock(masterPassword: "faux")
        check(model.unlockError == "Mot de passe principal incorrect.", "mauvais mot de passe au déverrouillage")
        await model.unlock(masterPassword: config.password)
        check(model.lockState == .unlocked && model.counts?.all == 9, "déverrouillage par mot de passe")
        if model.biometricEnrolled {
            model.lock()
            let unlocking = Task { await model.unlockWithBiometrics() }
            await pause(1.5)
            log("E2E_FACEID")
            await unlocking.value
            check(model.lockState == .unlocked, "déverrouillage par Face ID (clé scellée)")
        }

        // Verrouillage automatique : immédiat à l'arrière-plan
        let previous = model.autoLockSeconds
        model.autoLockSeconds = 0
        model.scenePhaseChanged(to: .background)
        check(model.lockState == .locked, "verrouillé en passant à l'arrière-plan")
        model.autoLockSeconds = previous

        model.logout()
        check(model.needsLogin && !model.biometricEnrolled && model.account == nil, "déconnexion")
        check(!FileManager.default.fileExists(atPath: model.vault.directory.appending(path: "account.json").path),
              "fichiers du compte effacés")
        await snap("18-deconnecte")
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
