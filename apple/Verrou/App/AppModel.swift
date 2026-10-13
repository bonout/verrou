import AppKit
import Observation
import SwiftUI

/// État de l'application : compte, verrouillage, sélection, recherche.
///
/// Les résumés des éléments (titres, identifiants affichés, sites) sont
/// chargés une fois au déverrouillage, puis après chaque synchronisation.
/// Chaque frappe interroge le cœur Rust, qui renvoie des positions dans ce
/// tableau : rien d'autre ne traverse la frontière, et aucun secret.
@MainActor
@Observable
final class AppModel {
    enum LockState: Equatable {
        case locked
        case unlocking
        case unlocked
    }

    /// `demo` : coffre fictif (captures, `VERROU_DEMO=1` ou `VERROU_MOCK=1`).
    enum Mode {
        case demo
        case vaultwarden
    }

    enum SyncState: Equatable {
        case idle
        case syncing
        /// Serveur injoignable : le coffre affiché est le cache.
        case offline
        case failed(String)
    }

    let mode: Mode
    /// Dossier du compte, dans le conteneur de l'app.
    let dataDirectory: URL
    let session: VaultSession

    private(set) var lockState: LockState = .locked
    private(set) var account: AccountInfo?
    private(set) var summaries: [ItemSummary] = []
    private(set) var results: [SearchHit] = []
    /// Les résultats prêts à afficher, une ligne par élément : la liste de
    /// SwiftUI ne construit alors que les lignes visibles (avec un `if` par
    /// ligne, elle les construisait toutes à chaque frappe).
    private(set) var rows: [ResultRow] = []
    private(set) var counts: SidebarCounts?
    private(set) var lastSearchDuration: Duration = .zero
    private(set) var syncState: SyncState = .idle
    private(set) var biometricEnrolled = false
    var unlockError: String?

    // Connexion
    /// `nil` : étape identifiants ; sinon les méthodes de second facteur.
    private(set) var twoFactorOptions: [TwoFactorOption]?
    private(set) var loginBusy = false
    /// En attente du contact sur la clé de sécurité (USB).
    private(set) var securityKeyWaiting = false
    var loginError: String?
    /// Adresse et e-mail saisis, gardés pour le second facteur et pour
    /// préremplir une reconnexion.
    var loginServer = "https://vault.example.net"
    var loginEmail = ""
    /// La session a expiré : il faut se reconnecter (mot de passe et second facteur).
    private(set) var reloginRequired = false

    var filter: SidebarFilter = .all { didSet { showAudit = false; refresh() } }

    // Audit
    /// La colonne centrale montre l'audit au lieu de la liste.
    var showAudit = false
    private(set) var audit: AuditReport?
    /// `nil` : pas encore vérifié (seulement sur demande : réseau).
    private(set) var breaches: [BreachedPassword]?
    private(set) var checkingBreaches = false
    var breachError: String?
    var query: String = "" { didSet { refresh() } }
    var sort: ResultOrder = .relevance { didSet { refresh() } }
    var selection: String? { didSet { if oldValue != selection { revealed.removeAll() } } }
    /// Champs révélés pour l'élément sélectionné, effacés dès qu'on en change.
    var revealed: [String: String] = [:]
    var toast: Toast?
    /// Requête de la fenêtre d'accès rapide, indépendante de la fenêtre principale.
    var quickQuery = "" { didSet { refreshQuick() } }
    /// Les 8 meilleurs résultats de l'accès rapide, calculés une fois par
    /// frappe (et non à chaque rendu du panneau).
    private(set) var quickRows: [ResultRow] = []
    /// Incrémenté à chaque ouverture de l'accès rapide : la fenêtre est
    /// réutilisée, son `onAppear` ne revient pas.
    private(set) var quickAccessOpenings = 0

    func quickAccessOpened() {
        quickAccessOpenings += 1
    }

    // Édition
    /// Écran de création ou de modification ouvert.
    var editor: Editor?
    private(set) var editorBusy = false
    var editorError: String?

    struct Editor: Identifiable {
        let id = UUID()
        /// `nil` : création.
        let itemID: String?
        let draft: ItemDraft
    }

    /// Remplissage dans Brave (absent en démonstration et pendant les parcours scriptés).
    var browserBridge: BrowserBridge?

    let clipboard = Clipboard()
    let siteIcons = SiteIcons()

    /// Préférence : icônes des sites, demandées au serveur du compte.
    var showSiteIcons: Bool = UserDefaults.standard.object(forKey: "showSiteIcons") as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(showSiteIcons, forKey: "showSiteIcons")
            updateSiteIcons()
        }
    }

    private func updateSiteIcons() {
        let wanted = mode == .vaultwarden && showSiteIcons && lockState == .unlocked
        siteIcons.server = wanted ? account?.server : nil
    }
    let mockSize: UInt32
    private var autoLock: AutoLock?
    /// Fin de la dernière demande Touch ID : la fenêtre système fait perdre
    /// puis reprendre le premier plan, il ne faut pas la rouvrir aussitôt.
    private var lastBiometricPrompt: Date?
    /// Demande Touch ID d'elle-même sur l'écran verrouillé (pas pendant les
    /// parcours scriptés, qui n'ont personne pour toucher le capteur).
    private let autoTouchID: Bool
    private var syncLoop: Task<Void, Never>?

    /// Préférence : proposer Touch ID après un déverrouillage par mot de passe.
    var touchIDWanted: Bool {
        get { UserDefaults.standard.object(forKey: "touchIDWanted") as? Bool ?? true }
        set {
            UserDefaults.standard.set(newValue, forKey: "touchIDWanted")
            if !newValue { disableBiometrics() }
        }
    }

    init() {
        let environment = ProcessInfo.processInfo.environment
        mockSize = UInt32(environment["VERROU_MOCK_SIZE"] ?? "") ?? 0
        autoTouchID = environment["VERROU_DEMO"] == nil && environment["VERROU_E2E_SERVER"] == nil
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var directory = support.appending(path: "Verrou", directoryHint: .isDirectory)
        #if DEBUG
        // Parcours de bout en bout : un compte jetable, jamais le vrai.
        if environment["VERROU_E2E_SERVER"] != nil {
            directory = FileManager.default.temporaryDirectory.appending(path: "verrou-e2e-data")
            try? FileManager.default.removeItem(at: directory)
        }
        #endif
        dataDirectory = directory
        if environment["VERROU_DEMO"] == "1" || environment["VERROU_MOCK"] == "1" {
            mode = .demo
            session = VaultSession()
        } else {
            mode = .vaultwarden
            try? FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
            session = VaultSession.withStorage(dataDir: dataDirectory.path)
            account = session.account()
            biometricEnrolled = BiometricVault.isEnrolled(in: dataDirectory)
            if let account {
                loginServer = account.server
                loginEmail = account.email
            }
        }
        // Préchauffe la réponse de LocalAuthentication avant le premier rendu.
        Biometrics.refresh()
        Perf.log.notice("modèle prêt à +\(Perf.msSinceLaunch) ms du lancement")
    }

    /// Début du dernier déverrouillage, et dernière activation de l'app : pour
    /// mesurer ce que l'utilisateur attend.
    @ObservationIgnored var unlockStartedAt: ContinuousClock.Instant?
    @ObservationIgnored var activatedAt: ContinuousClock.Instant?

    /// Pas de compte sur ce Mac, ou session expirée : écran de connexion.
    var needsLogin: Bool {
        mode == .vaultwarden && (account == nil || reloginRequired)
    }

    var canUseTouchID: Bool {
        mode == .demo ? Biometrics.isAvailable : biometricEnrolled && Biometrics.isAvailable
    }

    // MARK: Connexion

    func signIn(password: String) async {
        guard !loginBusy else { return }
        loginBusy = true
        loginError = nil
        defer { loginBusy = false }
        do {
            let result = try await session.login(server: loginServer, email: loginEmail, password: password)
            await handle(result)
        } catch {
            loginError = Self.describe(error)
        }
    }

    func answerTwoFactor(_ option: TwoFactorOption, token: String) async {
        guard !loginBusy else { return }
        loginBusy = true
        loginError = nil
        defer { loginBusy = false }
        do {
            await handle(try await session.answerTwoFactor(option: option, token: token))
        } catch {
            loginError = Self.describe(error)
        }
    }

    /// Clé de sécurité branchée en USB, sans navigateur : on attend le contact.
    func useSecurityKeyNatively(challenge: String) async {
        guard !securityKeyWaiting, !loginBusy else { return }
        securityKeyWaiting = true
        loginError = nil
        let token: String
        do {
            token = try await session.signWithSecurityKey(challenge: challenge)
        } catch {
            securityKeyWaiting = false
            // Annulé par l'utilisateur (ou par le changement de méthode) : rien à dire.
            if case VerrouError.SecurityKey(let message) = error, message == "demande annulée" { return }
            loginError = Self.describe(error)
            return
        }
        securityKeyWaiting = false
        await answerTwoFactor(.securityKey(challenge: challenge), token: token)
        if lockState != .unlocked, loginError != nil {
            // Le serveur ne laisse qu'une tentative par défi : on en redemande un.
            if case .twoFactorRequired(let options)? = try? await session.restartTwoFactor() {
                twoFactorOptions = options
            }
        }
    }

    func cancelSecurityKey() {
        session.cancelSecurityKey()
    }

    /// Repli : la page de connexion du serveur, dans Safari.
    func useSecurityKey(challenge: String) async {
        loginError = nil
        do {
            let token = try await SecurityKeySignIn().sign(server: normalizedServer, challenge: challenge)
            await answerTwoFactor(.securityKey(challenge: challenge), token: token)
        } catch SecurityKeySignIn.Failure.cancelled {
            // L'utilisateur a fermé la fenêtre : rien à dire.
        } catch {
            loginError = Self.describe(error)
        }
    }

    func sendEmailCode() async {
        do {
            try await session.sendEmailCode()
            toast = Toast(message: "Code envoyé", detail: "Consultez votre boîte de réception")
        } catch {
            loginError = Self.describe(error)
        }
    }

    func cancelTwoFactor() {
        session.cancelSecurityKey()
        twoFactorOptions = nil
        loginError = nil
    }

    private var normalizedServer: String {
        var server = loginServer.trimmingCharacters(in: .whitespaces)
        while server.hasSuffix("/") { server.removeLast() }
        return server.contains("://") ? server : "https://\(server)"
    }

    private func handle(_ result: LoginResult) async {
        switch result {
        case .twoFactorRequired(let options):
            twoFactorOptions = options
        case .unlocked(let failures):
            twoFactorOptions = nil
            reloginRequired = false
            account = session.account()
            // Une reconnexion change la clé du coffre : l'ancien Touch ID ne vaut plus.
            BiometricVault.remove(in: dataDirectory)
            biometricEnrolled = false
            didUnlock(failures: failures)
            await enrollBiometricsIfWanted()
        }
    }

    /// Session expirée, mais on veut quand même consulter le cache.
    func continueOffline() {
        reloginRequired = false
        loginError = nil
    }

    func logout() {
        lock()
        try? session.logout()
        BiometricVault.remove(in: dataDirectory)
        biometricEnrolled = false
        account = nil
        reloginRequired = false
        twoFactorOptions = nil
        syncState = .idle
    }

    // MARK: Verrouillage

    /// Écran verrouillé affiché ou app revenue au premier plan : Touch ID
    /// directement, sans passer par le bouton.
    func promptTouchIDIfPossible() async {
        guard autoTouchID, mode == .vaultwarden, canUseTouchID, lockState == .locked, !needsLogin,
              NSApp.isActive else { return }
        if let last = lastBiometricPrompt, Date().timeIntervalSince(last) < 3 { return }
        await unlockWithBiometrics()
    }

    func unlockWithBiometrics() async {
        defer { lastBiometricPrompt = Date() }
        if let activatedAt {
            Perf.log.notice("Touch ID demandé à +\(Perf.ms(since: activatedAt)) ms de l'activation")
        }
        lockState = .unlocking
        unlockError = nil
        if mode == .demo {
            switch await Biometrics.authenticate(reason: "déverrouiller votre coffre") {
            case .success: openVault()
            case .fallback:
                lockState = .locked
            case .failure(let message):
                unlockError = message
                lockState = .locked
            }
            return
        }
        do {
            let key = try await BiometricVault.open(in: dataDirectory, reason: "déverrouiller votre coffre")
            unlockStartedAt = .now
            let failures = try await Perf.measure("déchiffrement du coffre (Rust)") {
                try await session.unlockWithUserKey(userKey: key)
            }
            didUnlock(failures: failures)
        } catch BiometricVault.Failure.cancelled {
            lockState = .locked
        } catch BiometricVault.Failure.unavailable {
            unlockError = "Touch ID n'est pas disponible : saisissez votre mot de passe principal."
            lockState = .locked
        } catch {
            // Empreintes changées, ou clé périmée : retour au mot de passe.
            disableBiometrics()
            unlockError = "Touch ID doit être réactivé : saisissez votre mot de passe principal."
            lockState = .locked
        }
    }

    func unlock(masterPassword: String) async {
        guard !masterPassword.isEmpty else {
            unlockError = "Saisissez votre mot de passe principal."
            return
        }
        if mode == .demo {
            // Coffre fictif : tout mot de passe non vide l'ouvre.
            openVault()
            return
        }
        lockState = .unlocking
        unlockError = nil
        unlockStartedAt = .now
        do {
            let failures = try await Perf.measure("déverrouillage par mot de passe (dérivation + déchiffrement)") {
                try await session.unlockWithPassword(password: masterPassword)
            }
            didUnlock(failures: failures)
            await enrollBiometricsIfWanted()
        } catch {
            unlockError = Self.describe(error)
            lockState = .locked
        }
    }

    /// Coffre fictif (démonstration).
    func openVault() {
        session.unlockMock(size: mockSize, seed: 42)
        didUnlock(failures: 0)
    }

    private func didUnlock(failures: UInt32) {
        reloadVault()
        lockState = .unlocked
        updateSiteIcons()
        autoLock = AutoLock { [weak self] in self?.lock() }
        if failures > 0 {
            toast = Toast(message: "\(failures) élément\(failures > 1 ? "s" : "") illisible\(failures > 1 ? "s" : "")",
                          detail: "Le SDK Bitwarden n'a pas pu les déchiffrer")
        }
        guard mode == .vaultwarden else { return }
        syncLoop?.cancel()
        syncLoop = Task { [weak self] in
            while !Task.isCancelled {
                await self?.syncNow()
                try? await Task.sleep(for: .seconds(5 * 60))
            }
        }
    }

    /// Recharge résumés et compteurs (après déverrouillage ou synchronisation),
    /// en gardant la sélection si l'élément existe encore.
    func openAudit() {
        audit = try? session.audit()
        showAudit = true
    }

    /// Have I Been Pwned, par k-anonymat (5 caractères d'empreinte par mot de passe).
    func checkBreaches() async {
        guard !checkingBreaches, lockState == .unlocked else { return }
        checkingBreaches = true
        breachError = nil
        defer { checkingBreaches = false }
        do {
            breaches = try await session.checkBreaches()
        } catch {
            breachError = Self.describe(error)
        }
    }

    private func reloadVault() {
        if showAudit { audit = try? session.audit() }
        let start = ContinuousClock.now
        defer { Perf.log.notice("rechargement de la liste (\(self.summaries.count) éléments) : \(Perf.ms(since: start)) ms") }
        summaries = (try? session.summaries()) ?? []
        counts = try? session.counts()
        refresh()
        if selection.map({ id in !summaries.contains { $0.id == id } }) ?? true {
            selection = results.first?.id
        }
    }

    func lock() {
        syncLoop?.cancel()
        syncLoop = nil
        session.lock()
        summaries = []
        results = []
        rows = []
        quickRows = []
        counts = nil
        revealed.removeAll()
        selection = nil
        query = ""
        quickQuery = ""
        showAudit = false
        audit = nil
        breaches = nil
        breachError = nil
        // La fenêtre du coffre reste montée derrière l'écran verrouillé :
        // rien d'ouvert ne doit y survivre.
        editor = nil
        editorError = nil
        autoLock = nil
        clipboard.clearIfOurs()
        lockState = .locked
        updateSiteIcons()
    }

    // MARK: Synchronisation

    func syncNow() async {
        guard mode == .vaultwarden, lockState == .unlocked, syncState != .syncing else { return }
        syncState = .syncing
        do {
            let outcome = try await Perf.measure("synchronisation (réseau + déchiffrement)") {
                try await session.sync()
            }
            guard lockState == .unlocked else { return }
            account = session.account()
            syncState = .idle
            // Rien de nouveau : la liste affichée est à jour, on n'y touche pas.
            guard outcome.changed else { return }
            reloadVault()
            if outcome.failures > 0 { syncState = .failed("\(outcome.failures) élément(s) illisible(s)") }
        } catch VerrouError.Locked {
            syncState = .idle
        } catch VerrouError.SessionExpired {
            syncState = .failed("Session expirée")
            reloginRequired = true
            lock()
        } catch VerrouError.Network {
            syncState = .offline
        } catch {
            syncState = .failed(Self.describe(error))
        }
    }

    // MARK: Touch ID

    private func enrollBiometricsIfWanted() async {
        guard mode == .vaultwarden, touchIDWanted, !biometricEnrolled, Biometrics.isAvailable,
              lockState == .unlocked else { return }
        do {
            let key = try await session.userKey()
            try BiometricVault.enroll(userKey: key, in: dataDirectory)
            biometricEnrolled = true
        } catch {
            biometricEnrolled = false
        }
    }

    func enableBiometrics() async {
        UserDefaults.standard.set(true, forKey: "touchIDWanted")
        await enrollBiometricsIfWanted()
    }

    private func disableBiometrics() {
        BiometricVault.remove(in: dataDirectory)
        biometricEnrolled = false
    }

    static func describe(_ error: Error) -> String {
        guard let error = error as? VerrouError else { return error.localizedDescription }
        switch error {
        case .WrongPassword: return "Mot de passe principal incorrect."
        case .TwoFactorRejected(let message): return "Second facteur refusé (\(message))."
        case .NoAccount: return "Aucun compte n'est configuré sur ce Mac."
        case .SessionExpired: return "La session a expiré : reconnectez-vous."
        case .InvalidServer(let message): return "Adresse du serveur invalide : \(message)"
        case .Network(let message): return "Serveur injoignable. \(message)"
        case .Server(let message): return "Le serveur a répondu : \(message)"
        case .Crypto(let message): return "Déchiffrement impossible : \(message)"
        case .Storage(let message): return "Stockage local : \(message)"
        case .Locked: return "Le coffre est verrouillé."
        case .NotFound: return "Élément introuvable."
        case .InvalidTotp(let message): return "Code à usage unique invalide : \(message)"
        case .NoPendingLogin: return "Recommencez la connexion."
        case .SecurityKey(let message): return "Clé de sécurité : \(message)."
        case .ReadOnly: return "Cet élément est en lecture seule pour votre compte."
        case .Invalid(let message): return message.prefix(1).uppercased() + message.dropFirst() + "."
        case .Conflict: return "L'élément a changé sur le serveur : synchronisez, puis recommencez."
        case .RepromptRequired: return "Cet élément est protégé : confirmez d'abord votre identité."
        }
    }

    // MARK: Recherche

    private func refreshQuick() {
        guard lockState == .unlocked, !quickQuery.isEmpty else {
            quickRows = []
            return
        }
        let hits = (try? session.search(query: quickQuery, filter: .all, order: .relevance)) ?? []
        quickRows = hits.prefix(8).compactMap { hit in
            summary(for: hit).map { ResultRow(summary: $0, highlights: hit.highlights) }
        }
    }

    private func refresh() {
        refreshQuick()
        guard lockState == .unlocked else { return }
        let clock = ContinuousClock()
        let start = clock.now
        let effectiveSort = query.isEmpty && sort == .relevance ? ResultOrder.title : sort
        results = (try? session.search(query: query, filter: filter, order: effectiveSort)) ?? []
        rows = results.compactMap { hit in summary(for: hit).map { ResultRow(summary: $0, highlights: hit.highlights) } }
        lastSearchDuration = clock.now - start
    }

    /// Le résumé d'un résultat, s'il désigne toujours le même élément : entre
    /// le remplacement du coffre côté Rust (synchronisation, écriture) et le
    /// rechargement ici, un ancien résultat peut encore être affiché.
    func summary(for hit: SearchHit) -> ItemSummary? {
        let position = Int(hit.position)
        if summaries.indices.contains(position), summaries[position].id == hit.id {
            return summaries[position]
        }
        return summaries.first { $0.id == hit.id }
    }

    /// Résumé de l'élément sélectionné (sans appel au cœur Rust).
    var selectedSummary: ItemSummary? {
        guard let selection else { return nil }
        return rows.first { $0.id == selection }?.summary ?? summaries.first { $0.id == selection }
    }

    var selectedDetail: ItemDetail? {
        guard let selection else { return nil }
        return try? session.detail(id: selection)
    }

    func moveSelection(by offset: Int) {
        guard !results.isEmpty else { return }
        let ids = results.map(\.id)
        let current = selection.flatMap { ids.firstIndex(of: $0) } ?? -1
        let next = min(max(current + offset, 0), ids.count - 1)
        selection = ids[next]
    }

    // MARK: Édition

    /// Le coffre fictif reste en lecture seule ; Vaultwarden demande le réseau.
    var canEdit: Bool { mode == .vaultwarden && lockState == .unlocked }

    var folders: [FolderOption] {
        lockState == .unlocked ? session.folders() : []
    }

    /// Nouvel élément, rangé dans le dossier affiché ; un identifiant arrive
    /// avec un mot de passe déjà généré.
    func newItem(login: Bool) {
        guard canEdit else { return }
        var folderID: String?
        if case .folder(let name) = filter {
            folderID = folders.first { $0.name == name }?.id
        }
        editorError = nil
        let fields = login
            ? LoginFields(username: nil, password: generatePassword(length: 20, digits: true, symbols: true),
                          totp: nil, urls: [])
            : nil
        editor = Editor(itemID: nil, draft: ItemDraft(name: "", folderId: folderID, favorite: false,
                                                     notes: nil, login: fields))
    }

    func edit(_ itemID: String) async {
        guard canEdit else { return }
        if session.needsConfirmation(id: itemID) {
            let title = summaries.first { $0.id == itemID }?.title ?? "cet élément"
            guard await confirmAccess(itemID: itemID, title: title) else { return }
        }
        editorError = nil
        do {
            editor = Editor(itemID: itemID, draft: try await session.editDraft(id: itemID))
        } catch {
            toast = Toast(message: "Modification impossible", detail: Self.describe(error), failure: true)
        }
    }

    func saveEditor(_ draft: ItemDraft) async {
        guard let editor, !editorBusy else { return }
        editorBusy = true
        editorError = nil
        defer { editorBusy = false }
        do {
            let id: String
            if let existing = editor.itemID {
                try await session.updateItem(id: existing, draft: draft)
                id = existing
            } else {
                id = try await session.createItem(draft: draft)
            }
            afterWrite(select: id)
            self.editor = nil
            toast = Toast(message: editor.itemID == nil ? "Élément créé" : "Modifications enregistrées", detail: nil)
        } catch VerrouError.Conflict {
            editorError = "L'élément a changé ailleurs entre-temps. Verrou vient de le recharger : rouvrez-le pour refaire la modification."
            await syncNow()
        } catch {
            editorError = Self.describe(error)
        }
    }

    /// Corbeille du serveur : restaurable depuis le coffre web.
    func trash(_ itemID: String) async {
        guard canEdit else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            try await session.trashItem(id: itemID)
            editor = nil
            afterWrite(select: nil)
            toast = Toast(message: "Mis à la corbeille", detail: "Restaurable depuis le coffre web")
        } catch {
            editorError = Self.describe(error)
            toast = Toast(message: "Corbeille impossible", detail: Self.describe(error), failure: true)
        }
    }

    /// L'extension a enregistré un identifiant ou un code : le cœur Rust a
    /// déjà remplacé le coffre, on recharge l'affichage sans changer de sélection.
    func didSaveFromBrowser(title: String) {
        guard lockState == .unlocked else { return }
        afterWrite(select: selection)
        toast = Toast(message: "Enregistré depuis Brave", detail: title.isEmpty ? nil : title)
    }

    // MARK: Rangement

    func setFavorite(_ itemID: String, _ favorite: Bool) async {
        await perform(favorite ? "Ajouté aux favoris" : "Retiré des favoris", select: itemID) {
            try await self.session.setFavorite(id: itemID, favorite: favorite)
        }
    }

    /// Archiver : l'élément quitte la liste, la recherche et le remplissage,
    /// sans être supprimé.
    func setArchived(_ itemID: String, _ archived: Bool) async {
        await perform(archived ? "Archivé" : "Sorti des archives",
                      detail: archived ? "Retrouvez-le dans Archives" : nil,
                      select: archived ? nil : itemID) {
            try await self.session.setArchived(id: itemID, archived: archived)
        }
    }

    func restore(_ itemID: String) async {
        await perform("Restauré", select: itemID) {
            try await self.session.restoreItem(id: itemID)
        }
    }

    private func perform(_ done: String, detail: String? = nil, select: String?,
                         _ action: @escaping () async throws -> Void) async {
        guard canEdit, !editorBusy else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            try await action()
            afterWrite(select: select)
            toast = Toast(message: done, detail: detail)
        } catch {
            toast = Toast(message: "Action impossible", detail: Self.describe(error), failure: true)
        }
    }

    /// Le serveur a répondu et le coffre a été resynchronisé : on recharge.
    private func afterWrite(select id: String?) {
        guard lockState == .unlocked else { return }
        account = session.account()
        revealed.removeAll()
        reloadVault()
        if let id { selection = id }
        syncState = .idle
    }

    // MARK: Éléments protégés

    /// Élément protégé (« redemander le mot de passe principal ») pas encore
    /// confirmé : demande la confirmation, puis rejoue `retry`. Rend `true`
    /// si l'action doit attendre.
    func awaitsConfirmation(_ itemID: String, retry: @escaping @MainActor () -> Void) -> Bool {
        guard session.needsConfirmation(id: itemID) else { return false }
        let title = summaries.first { $0.id == itemID }?.title ?? "cet élément"
        Task {
            if await confirmAccess(itemID: itemID, title: title) { retry() }
        }
        return true
    }

    /// Touch ID, sinon le mot de passe principal ; la confirmation vaut
    /// 5 minutes pour cet élément (côté Rust, effacée au verrouillage).
    func confirmAccess(itemID: String, title: String) async -> Bool {
        if mode == .vaultwarden, canUseTouchID {
            switch await Biometrics.authenticate(reason: "afficher « \(title) »") {
            case .success:
                session.authorizeItem(id: itemID)
                return true
            case .failure:
                return false
            case .fallback:
                break
            }
        }
        guard mode == .vaultwarden else {
            // Coffre fictif : pas de mot de passe principal à vérifier.
            session.authorizeItem(id: itemID)
            return true
        }
        NSApp.activate()
        let alert = NSAlert()
        alert.messageText = "« \(title) » est protégé"
        alert.informativeText = "Saisissez votre mot de passe principal pour afficher ses secrets."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Confirmer")
        alert.addButton(withTitle: "Annuler")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn, !field.stringValue.isEmpty else { return false }
        let password = field.stringValue
        field.stringValue = ""
        do {
            guard try await session.verifyMasterPassword(password: password) else {
                toast = Toast(message: "Mot de passe principal incorrect", detail: nil, failure: true)
                return false
            }
            session.authorizeItem(id: itemID)
            return true
        } catch {
            toast = Toast(message: "Confirmation impossible", detail: Self.describe(error), failure: true)
            return false
        }
    }

    // MARK: Secrets

    func reveal(_ fieldID: String, of itemID: String) -> String? {
        if let value = revealed[fieldID] { return value }
        guard let value = try? session.reveal(id: itemID, fieldId: fieldID) else { return nil }
        revealed[fieldID] = value
        return value
    }

    func toggleReveal(_ fieldID: String, of itemID: String) {
        if revealed[fieldID] != nil {
            revealed[fieldID] = nil
        } else {
            if awaitsConfirmation(itemID, retry: { [weak self] in self?.toggleReveal(fieldID, of: itemID) }) { return }
            _ = reveal(fieldID, of: itemID)
        }
    }

    /// Code à usage unique du moment, s'il est accessible sans confirmation.
    func totpCode(of itemID: String, at date: Date = Date()) -> TotpView? {
        try? session.totp(id: itemID, unixTime: UInt64(date.timeIntervalSince1970))
    }

    func copyCode(of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyCode(of: itemID) }) { return }
        guard let code = totpCode(of: itemID) else { return }
        copy(code.code, label: "Code", secret: true)
    }

    func copy(_ value: String, label: String, secret: Bool) {
        clipboard.copy(value, concealed: secret)
        withAnimation(.snappy) {
            toast = Toast(message: "\(label) copié", detail: secret ? "Effacé du presse-papiers dans 90 s" : nil)
        }
    }

    func copyField(_ field: FieldView, of itemID: String) {
        if field.fieldType == .totp {
            copyCode(of: itemID)
            return
        }
        if field.secret,
           awaitsConfirmation(itemID, retry: { [weak self] in self?.copyField(field, of: itemID) }) { return }
        let value = field.secret ? reveal(field.id, of: itemID) : field.value
        guard let value else { return }
        // Le numéro de carte se copie sans espaces : c'est ce qu'attendent les
        // formulaires.
        let copied = field.fieldType == .cardNumber ? value.replacingOccurrences(of: " ", with: "") : value
        copy(copied, label: field.label, secret: field.secret)
        if field.secret { revealed[field.id] = nil }
    }

    func copyPassword(of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyPassword(of: itemID) }) { return }
        guard let value = try? session.reveal(id: itemID, fieldId: "password") else { return }
        copy(value, label: "Mot de passe", secret: true)
    }

    /// Fenêtre principale au premier plan. Fermée (lancement à l'ouverture
    /// de session), un « rouvrir » la recrée, comme un clic sur le Dock.
    func showMainWindow() {
        NSApp.activate()
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == "main" }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: NSWorkspace.OpenConfiguration())
        }
    }

    func noteActivity() {
        autoLock?.touch()
    }
}

struct ResultRow: Identifiable {
    let summary: ItemSummary
    let highlights: [UInt32]
    var id: String { summary.id }
}

struct Toast: Equatable, Identifiable {
    let id = UUID()
    let message: String
    let detail: String?
    var failure = false
}

/// Verrouillage automatique : inactivité (`autoLockMinutes`, 0 : jamais),
/// mise en veille et écran verrouillé (`lockOnSleep`).
@MainActor
final class AutoLock {
    static let minutesKey = "autoLockMinutes"
    static let sleepKey = "lockOnSleep"
    static var minutes: Int {
        UserDefaults.standard.object(forKey: minutesKey) as? Int ?? 10
    }
    static var lockOnSleep: Bool {
        UserDefaults.standard.object(forKey: sleepKey) as? Bool ?? true
    }

    private var timeout: TimeInterval? {
        Self.minutes > 0 ? TimeInterval(Self.minutes * 60) : nil
    }
    private var lastActivity = Date()
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private let onLock: @MainActor () -> Void

    init(onLock: @escaping @MainActor () -> Void) {
        self.onLock = onLock
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.check() }
        }
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { if AutoLock.lockOnSleep { self?.onLock() } }
            })
        }
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { if AutoLock.lockOnSleep { self?.onLock() } }
        })
    }

    func touch() { lastActivity = Date() }

    private func check() {
        if let timeout, Date().timeIntervalSince(lastActivity) > timeout { onLock() }
    }

    deinit {
        timer?.invalidate()
        observers.forEach {
            NSWorkspace.shared.notificationCenter.removeObserver($0)
            DistributedNotificationCenter.default().removeObserver($0)
        }
    }
}
