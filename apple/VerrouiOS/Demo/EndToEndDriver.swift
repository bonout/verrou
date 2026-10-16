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
/// - `E2E_NET off|on` : le script coupe ou rétablit le relais vers le serveur ;
/// - `E2E_TEXT <taille>` : le script change la taille du texte du simulateur.
@MainActor
final class EndToEndDriver {
    struct Config {
        let server: String
        let email: String
        let password: String
        let totpSecret: String
        /// Second compte (membre invité), pour le partage : adresse, mot de
        /// passe, graine du second facteur.
        let member: (email: String, password: String, totp: String)?

        init?(_ environment: [String: String]) {
            guard let server = environment["VERROU_E2E_SERVER"], let email = environment["VERROU_E2E_EMAIL"],
                  let password = environment["VERROU_E2E_PASSWORD"], let secret = environment["VERROU_E2E_TOTP"]
            else { return nil }
            self.server = server
            self.email = email
            self.password = password
            totpSecret = secret
            if let memberEmail = environment["VERROU_E2E_MEMBER_EMAIL"],
               let memberPassword = environment["VERROU_E2E_MEMBER_PASSWORD"],
               let memberTotp = environment["VERROU_E2E_MEMBER_TOTP"], !memberEmail.isEmpty {
                member = (memberEmail, memberPassword, memberTotp)
            } else {
                member = nil
            }
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

        // Coffres partagés, côté propriétaire
        let shared = await sharingAsOwner()

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

        // Le membre invité, puis la confirmation, puis ses droits
        if let shared, let member = config.member {
            await sharingWithMember(shared, member: member)
        }
    }

    // MARK: Partage

    struct SharedFixture {
        let organizationID: String
        let communs: String
        let banque: String
        let memberID: String?
    }

    /// Se connecte (second facteur TOTP compris) avec ce compte.
    private func signIn(_ email: String, _ password: String, totp: String, step: String) async {
        model.loginServer = config.server
        model.loginEmail = email
        await model.signIn(password: password)
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0, 60.0] where model.lockState != .unlocked {
            await model.answerTwoFactor(.authenticator, token: Self.totp(totp, at: now + offset))
        }
        check(model.lockState == .unlocked, step)
        _ = await wait(30) { model.syncState != .syncing }
    }

    /// Le propriétaire crée l'organisation et ses collections, partage
    /// (plusieurs éléments, puis un seul), change des collections, invite le
    /// membre ; la dernière propriétaire ne peut pas partir.
    private func sharingAsOwner() async -> SharedFixture? {
        check(await model.createOrganization(name: "Famille iPhone", collection: "Comptes communs"),
              "organisation créée sur l'iPhone (\(model.sharing.error ?? "ok"))")
        guard let org = model.organizations.first(where: { $0.name == "Famille iPhone" }),
              let communs = org.collections.first?.id else {
            check(false, "organisation et collection lues après la création")
            return nil
        }
        check(org.isOwner && org.canCreateCollections && org.canRename, "propriétaire, avec tous les droits")
        model.tab = .vault
        model.vaultPath = [.organization(org.id)]
        await snap("19-organisation")

        // Nouvelle collection : la feuille lit les membres de l'organisation
        model.openCollectionEditor(org, collection: nil)
        guard case .collection(let opened) = model.sharing.sheet else {
            check(false, "éditeur de collection ouvert")
            return nil
        }
        var draft = await model.session.loadCollectionDraft(opened, organization: org, accountEmail: model.account?.email)
        check(!draft.loading && draft.accessUnavailable == nil && !draft.members.isEmpty,
              "membres de l'organisation lus pour la collection (\(draft.accessUnavailable ?? "ok"))")
        draft.name = "Banque iPhone"
        // Rouverte avec le brouillon lu et le nom saisi.
        model.sharing.sheet = nil
        await pause(1.5)
        model.sharing.sheet = .collection(draft)
        await snap("20-nouvelle-collection")
        model.sharing.sheet = nil
        await pause(0.6)
        check(await model.saveCollection(draft), "collection créée (\(model.sharing.error ?? "ok"))")
        guard let banque = model.organization(org.id)?.collections.first(where: { $0.name == "Banque iPhone" })?.id else {
            check(false, "nom de la collection chiffré puis relu")
            return nil
        }
        check(model.organization(org.id)?.collections.first { $0.id == banque }?.canManage == true,
              "collection gérée par la propriétaire")

        // Partage groupé : les deux éléments créés plus haut
        let pair = ["Modifié sur iPhone", "Carte du test"].compactMap { id(of: $0) }
        model.vaultPath = [.list(.archived)]
        model.openSharing(items: pair)
        guard let flow = model.sharing.shareFlow, flow.isBulk else {
            check(false, "feuille « Partager » pour deux éléments")
            return nil
        }
        flow.collectionIDs = [communs]
        await snap("21-partager-plusieurs")
        check(await model.applySharing(flow), "deux éléments partagés (\(flow.error ?? "ok"))")
        check(pair.allSatisfy { model.summary(id: $0)?.sharing?.organizationId == org.id },
              "rechiffrés pour l'organisation (\(model.toast?.message ?? ""))")
        await pause(1.0)

        // Un seul élément, dans la collection de la banque seulement
        if let netflix = id(of: "Netflix") {
            model.openSharing(netflix)
            if let single = model.sharing.shareFlow {
                single.collectionIDs = [banque]
                check(await model.applySharing(single), "Netflix partagé dans « Banque iPhone » (\(single.error ?? "ok"))")
            }
        }
        // Changer les collections d'un élément partagé
        if let card = id(of: "Carte du test") {
            model.openSharing(card)
            if let collections = model.sharing.shareFlow, collections.current != nil {
                collections.collectionIDs = [communs, banque]
                await snap("22-collections")
                check(await model.applySharing(collections), "collections de la carte changées")
                check(model.summary(id: card)?.sharing?.collectionIds.count == 2, "carte dans deux collections")
            }
        }
        model.vaultPath = [.organization(org.id)]
        await pause(1.0)

        // Inviter le membre (sans courriel, le serveur accepte d'office)
        var memberID: String?
        if let member = config.member {
            model.vaultPath = [.organization(org.id), .members(org.id)]
            await model.loadMembers(org.id)
            let invite = MemberDraft(member: nil, emails: member.email, role: .user,
                                     access: [communs: .edit, banque: .edit])
            model.sharing.sheet = .member(invite, organizationID: org.id)
            await snap("23-inviter")
            model.sharing.sheet = nil
            await pause(0.6)
            check(await model.saveMember(invite, in: org.id), "membre invité (\(model.sharing.error ?? "ok"))")
            let invited = model.sharing.members[org.id]?.first { $0.email == member.email }
            check(invited?.status == .accepted, "invitation acceptée d'office : à confirmer")
            memberID = invited?.id
            await snap("24-membres")
            await model.refreshSharingStatus()
            check(model.sharing.totalToConfirm == 1, "« 1 membre à confirmer »")
            model.vaultPath = []
            await snap("25-membres-a-confirmer")
            // L'éditeur d'une collection ouvert comme par un toucher : il lit
            // lui-même membres et droits (capture vérifiée à l'œil).
            if let banqueView = model.organization(org.id)?.collections.first(where: { $0.id == banque }) {
                model.vaultPath = [.organization(org.id)]
                model.openCollectionEditor(model.organization(org.id) ?? org, collection: banqueView)
                await pause(3)
                await snap("25b-collection-ouverte")
                model.sharing.sheet = nil
                await pause(0.8)
                model.vaultPath = []
            }
        }

        // Ma phrase d'empreinte, l'écran « Rejoindre », renommer, quitter
        model.sharing.sheet = .fingerprint(nil)
        await snap("26-empreinte")
        // Aux plus grandes tailles de texte : la phrase reste entière.
        log("E2E_TEXT accessibility-extra-extra-extra-large")
        await pause(2)
        await snap("26b-empreinte-grand-texte")
        log("E2E_TEXT large")
        await pause(1.5)
        model.sharing.sheet = nil
        await pause(0.6)
        let link = "\(config.server)/#/accept-organization/?email=\(config.email.replacingOccurrences(of: "@", with: "%40"))"
            + "&organizationName=Club%20d%27escalade&organizationId=8e2d4f1a-0000-4000-8000-000000000001"
            + "&organizationUserId=8e2d4f1a-0000-4000-8000-000000000002&token=eyJ0eXAiOiJKV1QifQ.e30.c2ln"
        check((try? model.session.invitationInfo(link: link))?.forThisAccount == true, "lien d'invitation lu")
        model.sharing.sheet = .join(link)
        await snap("27-rejoindre")
        model.sharing.sheet = nil
        await pause(0.6)
        check(await model.renameOrganization(org, to: "Famille Martin"), "organisation renommée")
        check(model.organization(org.id)?.name == "Famille Martin", "nouveau nom relu")
        await model.leaveOrganization(model.organization(org.id) ?? org)
        check(model.organization(org.id) != nil && model.toast?.failure == true, "la dernière propriétaire ne part pas")

        // Envoi de texte (Bitwarden Send) : créé, lien copié, listé, supprimé
        model.vaultPath = [.sends]
        await model.reloadSends()
        var fields = model.session.newSendFields()
        fields.name = "Code du portail"
        fields.text = "4589B"
        let composer = SendComposer(fields: fields, file: nil)
        model.sharing.sendComposer = composer
        await snap("34-nouvel-envoi")
        check(await model.createSend(composer), "envoi créé (\(model.sharing.error ?? "ok"))")
        check(UIPasteboard.general.string?.contains("/#/send/") == true, "lien de l'envoi copié")
        await snap("35-envoi-cree")
        model.sharing.sendComposer = nil
        await pause(0.8)
        check(model.sharing.sends?.contains { $0.name == "Code du portail" } == true, "envoi listé")
        await snap("36-envois")
        if let send = model.sharing.sends?.first(where: { $0.name == "Code du portail" }) {
            await model.deleteSend(send)
            check(model.sharing.sends?.contains { $0.id == send.id } == false, "envoi supprimé")
        }
        model.vaultPath = []
        return SharedFixture(organizationID: org.id, communs: communs, banque: banque, memberID: memberID)
    }

    /// Le membre attend sa confirmation, la propriétaire la lui donne après
    /// avoir comparé l'empreinte, puis il lit ce qui lui est partagé, avec
    /// ses droits.
    private func sharingWithMember(_ shared: SharedFixture, member: (email: String, password: String, totp: String)) async {
        await signIn(member.email, member.password, totp: member.totp, step: "membre connecté")
        await model.refreshSharingStatus()
        guard let pending = model.sharing.pending.first(where: { $0.organizationId == shared.organizationID }) else {
            return check(false, "invitation en attente de confirmation visible")
        }
        check(model.organization(shared.organizationID) == nil, "pas de clé avant la confirmation")
        await snap("28-invitation-en-attente")
        model.sharing.sheet = .fingerprint(pending)
        await snap("29-empreinte-membre")
        model.sharing.sheet = nil
        let memberFingerprint = (try? await model.session.ownFingerprint()) ?? ""
        await pause(0.6)
        model.logout()

        await signIn(config.email, config.password, totp: config.totpSecret, step: "propriétaire reconnectée")
        await model.loadMembers(shared.organizationID)
        guard let accepted = model.sharing.members[shared.organizationID]?.first(where: { $0.email == member.email })
        else { return check(false, "membre listé") }
        model.vaultPath = [.organization(shared.organizationID), .members(shared.organizationID)]
        await model.prepareConfirmation(accepted, in: shared.organizationID)
        check(model.sharing.confirmation?.fingerprint == memberFingerprint, "empreinte identique des deux côtés")
        await snap("30-verifier-empreinte")
        if let confirmation = model.sharing.confirmation {
            await model.confirmMember(confirmation)
        }
        check(model.sharing.members[shared.organizationID]?.first { $0.email == member.email }?.status == .confirmed,
              "membre confirmé")
        // « Banque iPhone » : lecture seule, mots de passe masqués pour lui
        if let org = model.organization(shared.organizationID),
           let banque = org.collections.first(where: { $0.id == shared.banque }) {
            var draft = await model.session.loadCollectionDraft(
                CollectionDraft(organizationID: org.id, collectionID: banque.id, name: banque.name),
                organization: org, accountEmail: model.account?.email)
            check(draft.accessUnavailable == nil && draft.members.contains { $0.id == accepted.id }
                  && draft.memberAccess[accepted.id] == .edit,
                  "accès de la collection lus : le membre et son droit (\(draft.accessUnavailable ?? "ok"))")
            do {
                draft.memberAccess[accepted.id] = .viewExceptPasswords
                model.sharing.sheet = nil
                await pause(1.5)
                model.sharing.sheet = .collection(draft)
                await snap("31-acces-collection")
                model.sharing.sheet = nil
                await pause(0.6)
                check(await model.saveCollection(draft), "droits de la collection enregistrés")
            }
            let access = try? await model.session.collectionAccess(organizationId: org.id, collectionId: banque.id)
            check(access?.members.contains { $0.id == accepted.id && $0.readOnly && $0.hidePasswords } == true,
                  "lecture seule et mots de passe masqués relus")
        }
        model.vaultPath = []
        model.logout()

        await signIn(member.email, member.password, totp: member.totp, step: "membre reconnecté")
        guard let org = model.organization(shared.organizationID) else {
            return check(false, "organisation déchiffrée par le membre")
        }
        check(!org.canRename && !org.canCreateCollections && !org.collections.contains(where: \.canManage),
              "membre sans droits de gestion")
        guard let netflix = model.summaries.first(where: { $0.title == "Netflix" && $0.sharing != nil }) else {
            return check(false, "élément partagé lisible par le membre")
        }
        check(netflix.sharing?.readOnly == true && netflix.sharing?.hidePasswords == true && !model.canModify(netflix),
              "lecture seule, mots de passe masqués")
        model.open(netflix.id)
        model.toggleReveal("password", of: netflix.id)
        check(model.revealedValue("password", of: netflix.id) == nil, "mot de passe masqué par l'organisation")
        await snap("32-lecture-seule")
        model.vaultPath = [.organization(org.id)]
        await snap("33-organisation-membre")
        model.vaultPath = []
        if let card = model.summaries.first(where: { $0.title == "Carte du test" }) {
            check(model.canModify(card), "élément d'une collection modifiable : modifiable")
        }
        model.logout()
        check(model.needsLogin, "membre déconnecté")
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
