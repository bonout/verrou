import AuthenticationServices
import Foundation
import LocalAuthentication
import Observation
import os

/// L'état de l'extension de remplissage pour une demande du système : ce
/// qu'il veut (liste, identifiant précis, passkey, code, création de
/// passkey), le déverrouillage, puis la réponse.
///
/// Une demande, un processus court : le coffre est ouvert pour elle (Face ID
/// ou mot de passe principal), puis refermé dès la réponse donnée.
@MainActor
@Observable
final class AutoFillModel {
    enum Phase: Equatable {
        /// Aucun compte dans le dossier partagé (app jamais ouverte, ou build
        /// sans groupe d'apps).
        case noAccount
        case locked
        case unlocking
        case ready
        /// Écriture ou signature en cours (passkey).
        case working
    }

    /// Ce que le système demande.
    enum Request {
        /// Liste des identifiants pour ces sites (et des passkeys du site si
        /// `passkeys` est donné).
        case list(services: [ASCredentialServiceIdentifier], passkeys: PasskeyQuery?)
        /// Liste des codes à usage unique pour ces sites (iOS 18).
        case oneTimeCodes(services: [ASCredentialServiceIdentifier])
        /// Une suggestion du système touchée par l'utilisateur.
        case provide(ASCredentialRequest)
        /// Création d'une passkey.
        case register(ASPasskeyCredentialRequest)
        /// Rien (configuration).
        case none
    }

    /// Une demande de passkey du site (`prepareCredentialList(for:requestParameters:)`).
    struct PasskeyQuery {
        let rpID: String
        let clientDataHash: Data
        let allowed: [Data]
    }

    /// La réponse rendue au système.
    enum Completion {
        case password(user: String, password: String)
        case assertion(ASPasskeyAssertionCredential)
        case registration(ASPasskeyRegistrationCredential)
        case oneTimeCode(String)
        case cancel
        case failed(String)
    }

    /// Un élément protégé attend une confirmation (Face ID ou mot de passe).
    struct Confirmation: Identifiable {
        let id = UUID()
        let itemID: String
        let title: String
        fileprivate let action: () async -> Void
    }

    let vault: VaultAccess?
    private(set) var phase: Phase
    private(set) var request: Request = .none
    var unlockError: String?
    var actionError: String?
    var query = ""
    var confirmation: Confirmation?

    /// Identifiants du site (ou codes), du plus précis au moins précis.
    private(set) var matches: [ItemSummary] = []
    /// Toutes les fiches du coffre (recherche), une fois ouvert.
    private(set) var everything: [ItemSummary] = []
    private(set) var passkeys: [AutofillPasskey] = []
    /// Création de passkey : identifiants du site qui peuvent la recevoir.
    private(set) var targets: [ItemSummary] = []
    /// Passkey créée : la feuille confirme (coche) avant de se refermer.
    private(set) var passkeyCreated = false

    private let complete: (Completion) -> Void
    private let log = Logger(subsystem: "app.verrou.autofill", category: "extension")
    /// Face ID ou mot de passe principal passé pour cette demande : la
    /// passkey pose l'indicateur « utilisateur vérifié ».
    private var userVerified = false
    private var finished = false

    init(complete: @escaping (Completion) -> Void) {
        self.complete = complete
        let location = VerrouStorage.accountLocation()
        if location.shared {
            let vault = VaultAccess(autofillAt: location)
            self.vault = vault
            phase = vault.account == nil ? .noAccount : .locked
        } else {
            vault = nil
            phase = .noAccount
        }
        Memory.log("ouverture")
    }

    var account: AccountInfo? { vault?.account }
    var canUseBiometrics: Bool { (vault?.autofillBiometricEnrolled ?? false) && Biometrics.isAvailable }

    /// Le titre de l'écran.
    var title: String {
        switch request {
        case .register: "Enregistrer une passkey"
        case .oneTimeCodes: "Codes à usage unique"
        default: "Verrou"
        }
    }

    /// Le site demandé, pour l'en-tête.
    var site: String? {
        switch request {
        case .list(let services, let passkeys): passkeys?.rpID ?? services.first.map(Self.host)
        case .oneTimeCodes(let services): services.first.map(Self.host)
        case .register(let request): (request.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier
        case .provide, .none: nil
        }
    }

    static func host(of service: ASCredentialServiceIdentifier) -> String {
        if service.type == .URL, let host = URL(string: service.identifier)?.host() { return host }
        return service.identifier
    }

    // MARK: Demande

    func start(_ request: Request) {
        self.request = request
        if phase == .ready { load() }
    }

    // MARK: Déverrouillage

    /// Face ID tout de suite si possible (la demande vient d'un geste de
    /// l'utilisateur).
    func autoUnlock() async {
        guard phase == .locked, canUseBiometrics else { return }
        // L'interface de l'extension n'est au premier plan qu'une fois sa
        // feuille présentée : avant, LocalAuthentication refuse (« caller is
        // not running foreground »). On attend, puis on réessaie un peu.
        for attempt in 0..<6 {
            try? await Task.sleep(for: .milliseconds(attempt == 0 ? 350 : 500))
            guard phase == .locked else { return }
            if await unlockWithBiometrics(quietWhenNotForeground: attempt < 5) { return }
        }
    }

    /// Rend `false` si la demande n'a pas pu s'afficher (extension pas encore
    /// au premier plan) et que `quietWhenNotForeground` permet de réessayer.
    @discardableResult
    func unlockWithBiometrics(quietWhenNotForeground: Bool = false) async -> Bool {
        guard let vault, phase == .locked else { return true }
        phase = .unlocking
        unlockError = nil
        do {
            _ = try await vault.unlockForAutofill(reason: "remplir avec Verrou")
            userVerified = true
            didUnlock()
        } catch BiometricVault.Failure.cancelled, BiometricVault.Failure.interrupted {
            phase = .locked
        } catch BiometricVault.Failure.unavailable {
            unlockError = "\(Biometrics.name) n'est pas disponible : saisissez votre mot de passe principal."
            phase = .locked
        } catch BiometricVault.Failure.invalidated {
            unlockError = "\(Biometrics.name) doit être réactivé : saisissez votre mot de passe principal."
            phase = .locked
        } catch let error as LAError where error.code == .notInteractive && quietWhenNotForeground {
            phase = .locked
            return false
        } catch {
            log.error("Face ID : \(String(describing: error), privacy: .public)")
            unlockError = ErrorText.describe(error)
            phase = .locked
        }
        return true
    }

    func unlock(masterPassword: String) async {
        guard let vault, phase == .locked, !masterPassword.isEmpty else { return }
        phase = .unlocking
        unlockError = nil
        do {
            _ = try await vault.unlock(masterPassword: masterPassword)
            userVerified = true
            await vault.enrollAutofillBiometrics()
            didUnlock()
        } catch {
            unlockError = ErrorText.describe(error)
            phase = .locked
        }
    }

    private func didUnlock() {
        phase = .ready
        Memory.log("coffre ouvert")
        load()
    }

    /// Lit ce que la demande montre, ou y répond directement (suggestion
    /// touchée).
    private func load() {
        guard let vault else { return }
        let session = vault.session
        everything = ((try? session.summaries()) ?? []).filter { $0.category == .login && $0.state == .active }
        switch request {
        case .list(let services, let query):
            matches = (try? session.autofillMatches(services: services.map(\.identifier))) ?? []
            if let query {
                passkeys = (try? session.autofillPasskeys(rpId: query.rpID, allowed: query.allowed)) ?? []
            }
        case .oneTimeCodes(let services):
            matches = ((try? session.autofillMatches(services: services.map(\.identifier))) ?? []).filter(\.hasTotp)
            everything = everything.filter(\.hasTotp)
        case .register(let request):
            if let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity {
                targets = (try? session.autofillPasskeyTargets(rpId: identity.relyingPartyIdentifier)) ?? []
            }
        case .provide(let request):
            Task { await provide(request) }
        case .none:
            break
        }
    }

    /// Résultats de la recherche dans tout le coffre (cœur Rust).
    var searchResults: [ItemSummary] {
        guard let session = vault?.session, !query.isEmpty else { return [] }
        let filter: SidebarFilter = .category(category: .login)
        let hits = (try? session.search(query: query, filter: filter, order: .relevance)) ?? []
        let byID = Dictionary(everything.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return hits.prefix(50).compactMap { byID[$0.id] }
    }

    // MARK: Réponses

    /// L'utilisateur a choisi un identifiant (ou un code) dans la liste.
    func choose(_ item: ItemSummary) {
        guarded(item.id, title: item.title) { [weak self] in
            guard let self else { return }
            if case .oneTimeCodes = request {
                await self.fillCode(item.id)
            } else {
                await self.fillPassword(item.id)
            }
        }
    }

    func choose(_ passkey: AutofillPasskey) {
        guard case .list(_, let query?) = request else { return }
        guarded(passkey.itemId, title: passkey.title) { [weak self] in
            await self?.sign(rpID: query.rpID, credentialID: Data(passkey.credentialId),
                             clientDataHash: query.clientDataHash)
        }
    }

    /// Création : dans un identifiant existant, ou un nouveau (`nil`).
    func register(into item: ItemSummary?) {
        guard case .register(let request) = request else { return }
        if let item {
            guarded(item.id, title: item.title) { [weak self] in await self?.create(request, item: item.id) }
        } else {
            Task { await create(request, item: nil) }
        }
    }

    func cancel() { finish(.cancel) }

    /// Une suggestion touchée (QuickType, liste de Safari) : la demande
    /// désigne déjà l'élément.
    private func provide(_ request: ASCredentialRequest) async {
        switch request.type {
        case .password:
            guard let identity = request.credentialIdentity as? ASPasswordCredentialIdentity,
                  let id = identity.recordIdentifier else { return finish(.failed("identifiant inconnu")) }
            guarded(id, title: identity.user) { [weak self] in await self?.fillPassword(id) }
        case .passkeyAssertion:
            guard let request = request as? ASPasskeyCredentialRequest,
                  let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
            else { return finish(.failed("passkey inconnue")) }
            guard request.supportedAlgorithms.isEmpty || request.supportedAlgorithms.contains(.ES256) else {
                return finish(.failed("le site n'accepte pas les clés ES256"))
            }
            let id = identity.recordIdentifier ?? ""
            guarded(id, title: identity.userName) { [weak self] in
                await self?.sign(rpID: identity.relyingPartyIdentifier, credentialID: identity.credentialID,
                                 clientDataHash: request.clientDataHash)
            }
        default:
            if #available(iOS 18.0, *), request.type == .oneTimeCode,
               let identity = request.credentialIdentity as? ASOneTimeCodeCredentialIdentity,
               let id = identity.recordIdentifier {
                guarded(id, title: identity.label) { [weak self] in await self?.fillCode(id) }
                return
            }
            finish(.failed("demande non prise en charge"))
        }
    }

    /// Un élément protégé (« redemander le mot de passe principal ») attend
    /// sa confirmation, comme dans l'app ; sinon l'action part tout de suite.
    private func guarded(_ itemID: String, title: String, _ action: @escaping () async -> Void) {
        guard let session = vault?.session else { return }
        if session.needsConfirmation(id: itemID) {
            confirmation = Confirmation(itemID: itemID, title: title, action: action)
            Task { await confirmWithBiometrics() }
        } else {
            Task { await action() }
        }
    }

    /// Confirmation d'un élément protégé par Face ID.
    func confirmWithBiometrics() async {
        guard let confirmation, let session = vault?.session else { return }
        switch await Biometrics.authenticate(reason: "confirmer l'accès à « \(confirmation.title) »") {
        case .success:
            session.authorizeItem(id: confirmation.itemID)
            self.confirmation = nil
            await confirmation.action()
        case .fallback, .failure:
            break // le mot de passe principal reste proposé
        }
    }

    /// Confirmation d'un élément protégé par le mot de passe principal.
    func confirm(masterPassword: String) async {
        guard let confirmation, let session = vault?.session else { return }
        if (try? await session.verifyMasterPassword(password: masterPassword)) == true {
            session.authorizeItem(id: confirmation.itemID)
            self.confirmation = nil
            await confirmation.action()
        } else {
            actionError = "Mot de passe principal incorrect."
        }
    }

    private func fillPassword(_ id: String) async {
        guard let session = vault?.session else { return }
        do {
            let credential = try session.autofillPassword(id: id)
            finish(.password(user: credential.username, password: credential.password))
        } catch {
            actionError = ErrorText.describe(error)
        }
    }

    private func fillCode(_ id: String) async {
        guard let vault else { return }
        if let code = vault.currentCode(of: id) {
            // Noté pour le tri « Dernière utilisation » de l'app.
            vault.session.recordItemUse(id: id)
            finish(.oneTimeCode(code.code))
        } else {
            actionError = "Cet élément n'a pas de code à usage unique."
        }
    }

    private func sign(rpID: String, credentialID: Data, clientDataHash: Data) async {
        guard let session = vault?.session else { return }
        phase = .working
        do {
            let result = try await session.passkeyAssertion(
                rpId: rpID, credentialId: credentialID, clientDataHash: clientDataHash,
                userVerified: userVerified)
            let credential = ASPasskeyAssertionCredential(
                userHandle: Data(result.userHandle), relyingParty: rpID, signature: Data(result.signature),
                clientDataHash: clientDataHash, authenticatorData: Data(result.authenticatorData),
                credentialID: Data(result.credentialId))
            finish(.assertion(credential))
        } catch {
            phase = .ready
            actionError = ErrorText.describe(error)
        }
    }

    private func create(_ request: ASPasskeyCredentialRequest, item: String?) async {
        guard let session = vault?.session,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else { return }
        guard request.supportedAlgorithms.isEmpty || request.supportedAlgorithms.contains(.ES256) else {
            actionError = "Ce site n'accepte pas les clés ES256 : utilisez un autre gestionnaire."
            return
        }
        var excluded: [Data] = []
        if #available(iOS 18.0, *) {
            excluded = (request.excludedCredentials ?? []).map(\.credentialID)
        }
        phase = .working
        do {
            let result = try await session.passkeyRegistration(request: PasskeyCreationRequest(
                rpId: identity.relyingPartyIdentifier, userName: identity.userName,
                userHandle: identity.userHandle, clientDataHash: request.clientDataHash,
                userVerified: userVerified, itemId: item, excludedCredentials: excluded))
            let credential = ASPasskeyRegistrationCredential(
                relyingParty: identity.relyingPartyIdentifier, clientDataHash: request.clientDataHash,
                credentialID: Data(result.credentialId), attestationObject: Data(result.attestationObject))
            // Le système ne propose une passkey (`allowCredentials`) que si
            // elle est dans son magasin d'identités : on le met à jour ici,
            // sans attendre que l'app se synchronise.
            if let identities = try? session.autofillIdentities() {
                await CredentialIdentities.publish(identities)
            }
            // Courte confirmation dans la feuille (effets de symboles), puis réponse.
            passkeyCreated = true
            try? await Task.sleep(for: .milliseconds(650))
            finish(.registration(credential))
        } catch {
            phase = .ready
            actionError = ErrorText.describe(error)
        }
    }

    /// Répond une seule fois, referme le coffre (le cœur Rust efface ses
    /// secrets) et note la mémoire.
    private func finish(_ completion: Completion) {
        guard !finished else { return }
        finished = true
        Memory.log("réponse")
        vault?.lock()
        complete(completion)
    }
}
