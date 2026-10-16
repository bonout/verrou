import AuthenticationServices
import BackgroundTasks
import Observation
import SwiftUI
import UIKit

/// État de l'app iPhone : compte, verrouillage, navigation, écritures.
///
/// Même principe que sur le Mac : les résumés des éléments (titres,
/// identifiants affichés, sites) arrivent une fois au déverrouillage, puis
/// après chaque synchronisation ; chaque frappe de recherche interroge le
/// cœur Rust, qui rend des positions dans ce tableau. Un secret ne traverse
/// la frontière que quand l'utilisateur l'affiche ou le copie. L'ouverture
/// du coffre passe par `VaultAccess` (partagé avec la future extension de
/// remplissage automatique).
@MainActor
@Observable
final class PhoneModel {
    enum LockState: Equatable {
        case locked
        case unlocking
        case unlocked
    }

    /// `demo` : coffre fictif (`VERROU_MOCK=1`).
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

    enum Tab: Hashable {
        case vault
        case generator
        case settings
        /// Recherche dans tout le coffre (onglet à part, rôle « search »).
        case search
    }

    /// Écrans empilés dans l'onglet Coffre.
    enum Route: Hashable {
        case list(SidebarFilter)
        case item(String)
        case audit
        /// Un coffre partagé : ses collections, ses membres, ses groupes.
        case organization(String)
        case members(String)
        case groups(String)
        /// Envois (Bitwarden Send).
        case sends
    }

    struct Editor: Identifiable {
        let id = UUID()
        /// `nil` : création.
        let itemID: String?
        let draft: ItemDraft
        /// Création directe dans une collection partagée.
        var destination: SharedDestination?
    }

    /// Demande du mot de passe principal pour un élément protégé, quand Face
    /// ID n'est pas disponible ou que l'utilisateur l'a écarté.
    struct RepromptRequest: Identifiable {
        let id = UUID()
        let itemID: String
        let title: String
        fileprivate let answer: (Bool) -> Void
    }

    /// QR code d'un réseau Wi-Fi affiché.
    struct QRSheet: Identifiable {
        let id = UUID()
        let title: String
        let image: CGImage
    }

    /// Fichier déchiffré à partager (pièce jointe).
    struct SharedFile: Identifiable {
        let id = UUID()
        let url: URL
    }

    /// « Déplacer vers un dossier » ouvert pour ces éléments.
    struct MoveRequest: Identifiable {
        let id = UUID()
        let itemIDs: [String]
    }

    let mode: Mode
    let vault: VaultAccess
    var session: VaultSession { vault.session }
    var dataDirectory: URL { vault.directory }

    private(set) var lockState: LockState = .locked
    private(set) var account: AccountInfo?
    private(set) var summaries: [ItemSummary] = []
    @ObservationIgnored private var summaryIndex: [String: Int] = [:]
    private(set) var counts: SidebarCounts?
    private(set) var organizations: [OrganizationView] = []
    private(set) var folders: [FolderOption] = []
    private(set) var syncState: SyncState = .idle
    /// Modifications faites hors ligne qui attendent le serveur.
    private(set) var pendingChanges = 0
    private(set) var biometricEnrolled = false
    /// Change à chaque rechargement du coffre : les listes se recalculent.
    private(set) var revision = 0
    var unlockError: String?

    // Connexion
    /// `nil` : étape identifiants ; sinon les méthodes de second facteur.
    private(set) var twoFactorOptions: [TwoFactorOption]?
    private(set) var loginBusy = false
    var loginError: String?
    var loginServer = "https://"
    var loginEmail = ""
    /// La session a expiré : il faut se reconnecter.
    private(set) var reloginRequired = false

    // Navigation et feuilles
    var tab: Tab = .vault {
        didSet {
            if tab == .search, oldValue != .search { searchChosenAt = .now }
        }
    }
    /// Choix de l'onglet Rechercher : mesure du délai jusqu'au clavier.
    @ObservationIgnored var searchChosenAt: ContinuousClock.Instant?
    var vaultPath: [Route] = [] {
        didSet { forgetClosedItems() }
    }
    /// Écrans empilés dans l'onglet Réglages.
    var settingsPath: [SettingsRoute] = []
    enum SettingsRoute: Hashable {
        /// Tri, liste au déverrouillage, règles de correspondance.
        case filling
    }
    /// Écrans empilés dans l'onglet Rechercher.
    var searchPath: [Route] = [] {
        didSet { forgetClosedItems() }
    }
    /// Recherche dans tout le coffre (onglet Rechercher).
    var searchQuery = ""
    /// Copies faites : chacune déclenche un retour haptique (`sensoryFeedback`).
    private(set) var copies = 0
    var editor: Editor?
    var editorBusy = false
    var editorError: String?
    var toast: Toast?
    var reprompt: RepromptRequest?
    var qrSheet: QRSheet?
    /// Lecture d'un QR code de double authentification (feuille ouverte).
    var otpScan: OTPScanFlow?
    /// Compte scanné à reporter dans l'écran de modification ouvert.
    var otpFormFill: OTPFormFill?
    #if DEBUG
    /// Pilote de bout en bout : enregistre l'écran de modification ouvert,
    /// comme le bouton « Créer » (brouillon de la vue compris).
    var e2eSaveEditor = 0
    #endif
    var moveRequest: MoveRequest?
    /// « Retirer du partage… » en attente de confirmation.
    var unshareRequest: UnshareRequest?
    /// Retrait du partage en cours.
    var unshareBusy = false
    /// Ordre des listes, gardé sur cet iPhone.
    var sortOrder: ResultOrder = DevicePreferences.sort {
        didSet { DevicePreferences.sort = sortOrder }
    }
    /// Liste ouverte au déverrouillage, gardée sur cet iPhone.
    var defaultFilter: DefaultFilter = DevicePreferences.defaultFilter {
        didSet { DevicePreferences.defaultFilter = defaultFilter }
    }
    /// Règles de correspondance de cet iPhone et domaines équivalents du compte.
    var matchSettings: MatchSettingsView?
    /// Pièce jointe déchiffrée montrée par Quick Look (fichier temporaire).
    var preview: URL? {
        didSet { if let oldValue, oldValue != preview { Attachments.discard(oldValue) } }
    }
    var sharedFile: SharedFile?
    /// Pièces jointes chargées, par élément.
    private(set) var attachments: [String: [AttachmentEntry]] = [:]
    /// Téléchargement ou envoi en cours.
    private(set) var attachmentActivity: String?

    /// Champs révélés, par élément ; effacés quand on quitte la fiche et au
    /// verrouillage.
    private(set) var revealed: [String: [String: String]] = [:]

    // Audit
    private(set) var audit: AuditReport?
    private(set) var breaches: [BreachedPassword]?
    private(set) var checkingBreaches = false
    var breachError: String?
    /// « Passkey possible » (`PasskeyUpgrade.swift`).
    let passkeyAudit = PhonePasskeyAudit()

    let clipboard = Clipboard()
    let siteIcons = SiteIcons()
    /// Partage avec d'autres comptes (organisations, collections, membres).
    let sharing = PhoneSharingModel()

    @ObservationIgnored private var syncLoop: Task<Void, Never>?
    /// Mises à jour en direct du serveur, au premier plan.
    @ObservationIgnored let live = LiveUpdates()
    /// Notification touchée coffre verrouillé : ouverte après le déverrouillage.
    @ObservationIgnored var pendingActivityRoute: ActivityRoute?
    /// La prochaine synchronisation est la première après le déverrouillage :
    /// on mesure le plus long blocage du fil principal pendant qu'elle tourne.
    @ObservationIgnored private var watchFirstSync = false
    /// Synchronisations terminées depuis le lancement (mesures).
    @ObservationIgnored private(set) var syncsFinished = 0
    @ObservationIgnored private var identitiesTask: Task<Void, Never>?
    /// Verrou est choisi comme fournisseur de remplissage automatique
    /// (`nil` : pas encore demandé au système).
    private(set) var autofillEnabled: Bool?
    /// Synchronisations en cours (le cœur Rust les regroupe) : la dernière
    /// qui se termine donne l'état affiché.
    @ObservationIgnored private var syncsInFlight = 0
    /// Rechargements de la liste : une lecture faite hors du fil principal
    /// n'écrase pas une écriture locale plus récente.
    @ObservationIgnored private var reloads = 0
    @ObservationIgnored private var backgroundedAt: Date?
    @ObservationIgnored private var lastBiometricPrompt: Date?
    /// La dernière demande de Face ID a été interrompue par le système.
    @ObservationIgnored private var interruptedPrompt = false
    /// Face ID demandé de lui-même sur l'écran verrouillé (pas pendant les
    /// parcours scriptés).
    @ObservationIgnored private let autoFaceID: Bool
    @ObservationIgnored let mockSize: UInt32

    init() {
        let environment = ProcessInfo.processInfo.environment
        mockSize = UInt32(environment["VERROU_MOCK_SIZE"] ?? "") ?? 0
        #if DEBUG
        showcase = environment["VERROU_SHOWCASE"] == "1" && environment["VERROU_MOCK"] == "1"
        #else
        showcase = false
        #endif
        autoFaceID = environment["VERROU_E2E_SERVER"] == nil && environment["VERROU_MOCK"] == nil
        var location = VerrouStorage.accountLocation()
        #if DEBUG
        // Parcours de bout en bout : un compte jetable, jamais le vrai.
        if environment["VERROU_E2E_SERVER"] != nil {
            let directory = FileManager.default.temporaryDirectory.appending(path: "verrou-e2e-data")
            try? FileManager.default.removeItem(at: directory)
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            location = VerrouStorage.Location(directory: directory, shared: false)
        }
        #endif
        if environment["VERROU_MOCK"] == "1" {
            mode = .demo
            vault = VaultAccess(mockAt: location)
        } else {
            mode = .vaultwarden
            vault = VaultAccess(location: location)
            account = vault.account
            biometricEnrolled = vault.biometricEnrolled
            pendingChanges = Int(session.pendingChanges())
            if let account {
                loginServer = account.server
                loginEmail = account.email
                NetworkWake.nudge(server: account.server)
            }
        }
        Attachments.purge()
        Biometrics.refresh()
        Perf.mark("modèle prêt à +\(Perf.msSinceLaunch) ms du lancement")
    }

    /// Pas de compte sur cet iPhone, ou session expirée : écran de connexion.
    var needsLogin: Bool {
        mode == .vaultwarden && (account == nil || reloginRequired)
    }

    var canUseBiometrics: Bool {
        mode == .demo ? Biometrics.isAvailable : biometricEnrolled && Biometrics.isAvailable
    }

    var canEdit: Bool { (mode == .vaultwarden || showcase) && lockState == .unlocked }

    /// Vitrine (builds Debug, `VERROU_SHOWCASE=1`) : sur le coffre fictif, les
    /// boutons de modification sont affichés pour les captures d'écran.
    @ObservationIgnored let showcase: Bool

    // MARK: Réglages

    /// Délai de verrouillage une fois l'app en arrière-plan, en secondes ;
    /// 0 : aussitôt ; -1 : jamais (seulement à la fermeture de l'app).
    var autoLockSeconds: Int {
        get { access(keyPath: \.autoLockSeconds); return UserDefaults.standard.object(forKey: "autoLockSeconds") as? Int ?? 60 }
        set { withMutation(keyPath: \.autoLockSeconds) { UserDefaults.standard.set(newValue, forKey: "autoLockSeconds") } }
    }

    /// Durée de vie d'un secret copié dans le presse-papiers, en secondes.
    var clipboardSeconds: Int {
        get { access(keyPath: \.clipboardSeconds); return UserDefaults.standard.object(forKey: "clipboardSeconds") as? Int ?? 90 }
        set { withMutation(keyPath: \.clipboardSeconds) { UserDefaults.standard.set(newValue, forKey: "clipboardSeconds") } }
    }

    /// Proposer Face ID après un déverrouillage par mot de passe.
    var biometricsWanted: Bool {
        get { access(keyPath: \.biometricsWanted); return UserDefaults.standard.object(forKey: "faceIDWanted") as? Bool ?? true }
        set {
            withMutation(keyPath: \.biometricsWanted) { UserDefaults.standard.set(newValue, forKey: "faceIDWanted") }
            if newValue {
                Task { await enrollBiometricsIfWanted() }
            } else {
                vault.removeBiometrics()
                biometricEnrolled = false
            }
        }
    }

    /// Icônes des sites, demandées au serveur du compte.
    var showSiteIcons: Bool {
        get { access(keyPath: \.showSiteIcons); return UserDefaults.standard.object(forKey: "showSiteIcons") as? Bool ?? true }
        set {
            withMutation(keyPath: \.showSiteIcons) { UserDefaults.standard.set(newValue, forKey: "showSiteIcons") }
            updateSiteIcons()
        }
    }

    private func updateSiteIcons() {
        let wanted = mode == .vaultwarden && showSiteIcons && lockState == .unlocked
        siteIcons.server = wanted ? account?.server : nil
    }

    // MARK: Connexion

    func signIn(password: String) async {
        guard !loginBusy else { return }
        loginBusy = true
        loginError = nil
        defer { loginBusy = false }
        do {
            let result = try await session.login(server: normalizedServer, email: loginEmail.trimmingCharacters(in: .whitespaces),
                                                 password: password)
            await handle(result)
        } catch {
            loginError = ErrorText.describe(error)
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
            loginError = ErrorText.describe(error)
        }
    }

    /// Clé de sécurité (FIDO2) : la page de connexion du serveur, dans une
    /// session Safari éphémère ; la YubiKey répond en NFC ou en USB-C.
    func useSecurityKey(challenge: String) async {
        guard !loginBusy else { return }
        loginError = nil
        do {
            let token = try await SecurityKeySignIn().sign(server: normalizedServer, challenge: challenge)
            await answerTwoFactor(.securityKey(challenge: challenge), token: token)
        } catch SecurityKeySignIn.Failure.cancelled {
            // Feuille fermée : rien à dire.
        } catch {
            loginError = ErrorText.describe(error)
        }
        if loginError != nil, twoFactorOptions != nil {
            // Le serveur ne laisse qu'une tentative par défi : on en redemande un.
            if case .twoFactorRequired(let options)? = try? await session.restartTwoFactor() {
                twoFactorOptions = options
            }
        }
    }

    func sendEmailCode() async {
        do {
            try await session.sendEmailCode()
            toast = Toast(message: "Code envoyé", detail: "Consultez votre boîte de réception")
        } catch {
            loginError = ErrorText.describe(error)
        }
    }

    func cancelTwoFactor() {
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
            // Une reconnexion change la clé du coffre : l'ancien Face ID ne vaut plus.
            vault.removeBiometrics()
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

    /// Oublie le compte : cache, file hors ligne, Face ID. Le serveur garde tout.
    func logout() {
        lock()
        identitiesTask?.cancel()
        Task { await CredentialIdentities.clear() }
        try? session.logout()
        vault.removeBiometrics()
        biometricEnrolled = false
        account = nil
        reloginRequired = false
        twoFactorOptions = nil
        syncState = .idle
        pendingChanges = 0
        tab = .vault
    }

    // MARK: Verrouillage

    /// Écran verrouillé affiché ou app revenue au premier plan : Face ID
    /// directement, sans passer par le bouton.
    ///
    /// Au lancement, l'écran verrouillé apparaît avant que l'app ne soit
    /// active (jusqu'à 300 ms plus tôt) : Face ID est demandé dès ce moment ;
    /// si le système l'interrompt, il est redemandé à l'activation.
    func promptBiometricsIfPossible() async {
        guard autoFaceID, mode == .vaultwarden, canUseBiometrics, lockState == .locked, !needsLogin,
              UIApplication.shared.applicationState != .background else { return }
        if let last = lastBiometricPrompt, Date().timeIntervalSince(last) < 3 { return }
        await unlockWithBiometrics()
    }

    /// Face ID reconnu, coffre en cours de déchiffrement : l'écran verrouillé
    /// s'ouvre déjà (le coffre vide est construit dessous), sans attendre.
    private(set) var opening = false
    /// Face ID demandé par l'app : l'inactivité qui suit vient de la feuille
    /// du système, pas du sélecteur d'apps. Levé au retour au premier plan
    /// (ou en arrière-plan).
    private(set) var biometricPrompt = false

    func unlockWithBiometrics() async {
        defer {
            lastBiometricPrompt = interruptedPrompt ? nil : Date()
            opening = false
        }
        interruptedPrompt = false
        guard lockState == .locked else { return }
        lockState = .unlocking
        unlockError = nil
        biometricPrompt = true
        if mode == .demo {
            switch await Biometrics.authenticate(reason: "déverrouiller votre coffre") {
            case .success: openMockVault()
            case .fallback: lockState = .locked
            case .failure(let message):
                unlockError = message.isEmpty ? nil : message
                lockState = .locked
            }
            return
        }
        do {
            let failures = try await Perf.measure("\(Biometrics.name) + déchiffrement du coffre") {
                try await vault.unlockWithBiometrics(reason: "déverrouiller votre coffre") { [weak self] in
                    self?.opening = true
                }
            }
            didUnlock(failures: failures)
        } catch BiometricVault.Failure.cancelled {
            lockState = .locked
        } catch BiometricVault.Failure.interrupted {
            // Pas un refus : redemandé à la prochaine activation, sans délai.
            lockState = .locked
            interruptedPrompt = true
        } catch BiometricVault.Failure.unavailable {
            unlockError = "\(Biometrics.name) n'est pas disponible : saisissez votre mot de passe principal."
            lockState = .locked
        } catch {
            // Visages ou empreintes changés, ou clé périmée : retour au mot de passe.
            vault.removeBiometrics()
            biometricEnrolled = false
            unlockError = "\(Biometrics.name) doit être réactivé : saisissez votre mot de passe principal."
            lockState = .locked
        }
    }

    func unlock(masterPassword: String) async {
        guard !masterPassword.isEmpty else {
            unlockError = "Saisissez votre mot de passe principal."
            return
        }
        if mode == .demo {
            openMockVault()
            return
        }
        lockState = .unlocking
        unlockError = nil
        do {
            let failures = try await Perf.measure("déverrouillage par mot de passe") {
                try await vault.unlock(masterPassword: masterPassword)
            }
            Perf.unlockSucceeded("le mot de passe")
            didUnlock(failures: failures)
            await enrollBiometricsIfWanted()
        } catch {
            unlockError = ErrorText.describe(error)
            lockState = .locked
        }
    }

    /// Coffre fictif (démonstration).
    func openMockVault() {
        session.unlockMock(size: mockSize, seed: 42)
        Perf.unlockSucceeded("l'ouverture du coffre fictif")
        didUnlock(failures: 0)
    }

    private func didUnlock(failures: UInt32) {
        reloadVault()
        // La liste choisie dans les réglages s'ouvre d'elle-même.
        if defaultFilter != .all, vaultPath.isEmpty, !showcase {
            vaultPath = [.list(defaultFilter.filter)]
        }
        lockState = .unlocked
        updateSiteIcons()
        if failures > 0 {
            toast = Toast(message: "\(failures) élément\(failures > 1 ? "s" : "") illisible\(failures > 1 ? "s" : "")",
                          detail: "Le SDK Bitwarden n'a pas pu les déchiffrer", failure: true)
        }
        watchFirstSync = true
        startSyncLoop()
        if let route = pendingActivityRoute {
            pendingActivityRoute = nil
            openActivity(route)
        }
    }

    func lock() {
        syncLoop?.cancel()
        syncLoop = nil
        live.stop(session: session)
        vault.lock()
        summaries = []
        summaryIndex = [:]
        counts = nil
        organizations = []
        folders = []
        revealed = [:]
        attachments = [:]
        audit = nil
        breaches = nil
        breachError = nil
        passkeyAudit.reset()
        editor = nil
        editorError = nil
        qrSheet = nil
        otpScan = nil
        otpFormFill = nil
        moveRequest = nil
        sharing.clear()
        preview = nil
        sharedFile = nil
        reprompt?.answer(false)
        reprompt = nil
        toast = nil
        vaultPath = []
        searchPath = []
        searchQuery = ""
        Attachments.purge()
        clipboard.clearIfOurs()
        lockState = .locked
        revision += 1
        updateSiteIcons()
    }

    // MARK: Premier plan, arrière-plan

    /// Verrouillage automatique et synchronisation au retour au premier plan.
    func scenePhaseChanged(to phase: ScenePhase) {
        Perf.mark("scène \(String(describing: phase)) à +\(Perf.msSinceLaunch) ms du lancement (\(String(describing: lockState)))")
        // Au lancement, la scène devient active juste après la demande, avant
        // la feuille de Face ID : on ne lève qu'une fois la demande close.
        if phase == .background || (phase == .active && lockState != .unlocking) { biometricPrompt = false }
        switch phase {
        case .background:
            backgroundedAt = Date()
            syncLoop?.cancel()
            syncLoop = nil
            live.stop(session: session)
            if lockState == .unlocked, autoLockSeconds == 0 { lock() }
            scheduleBackgroundCheck()
        case .active:
            // Retour de l'arrière-plan (pas d'un simple état inactif) : le
            // réseau est réveillé pendant Face ID ou avant la synchronisation.
            if backgroundedAt != nil, mode == .vaultwarden, let server = account?.server {
                NetworkWake.nudge(server: server)
            }
            if let since = backgroundedAt, lockState == .unlocked, autoLockSeconds > 0,
               Date().timeIntervalSince(since) >= TimeInterval(autoLockSeconds) {
                lock()
            }
            backgroundedAt = nil
            Biometrics.refresh()
            if lockState == .unlocked {
                // Retour de l'arrière-plan : la boucle avait été arrêtée.
                // Simple retour de l'état inactif (Face ID, centre de
                // contrôle) : elle tourne encore, et la relancer doublerait
                // la synchronisation du déverrouillage.
                if syncLoop == nil { startSyncLoop() }
                Task { await refreshAutofillStatus() }
            } else {
                Task { await promptBiometricsIfPossible() }
            }
        default:
            break
        }
    }

    // MARK: Synchronisation

    /// Synchronise tout de suite, puis toutes les 5 minutes tant que l'app
    /// est au premier plan (30 s si des modifications attendent le serveur).
    private func startSyncLoop() {
        guard mode == .vaultwarden else { return }
        syncLoop?.cancel()
        syncLoop = Task { [weak self] in
            while !Task.isCancelled {
                await self?.syncNow()
                let waiting = (self?.pendingChanges ?? 0) > 0
                try? await Task.sleep(for: .seconds(waiting ? 30 : 5 * 60))
            }
        }
        // Au premier plan, le canal des mises à jour en direct : un partage
        // ou une confirmation arrive en quelques secondes.
        live.start(session: session) { [weak self] in
            await self?.syncNow()
        } expired: { [weak self] in
            guard let self, self.lockState == .unlocked else { return }
            self.reloginRequired = true
            self.lock()
        }
    }

    // MARK: Arrière-plan : nouveautés du partage

    /// Identifiant de la tâche d'arrière-plan (Info.plist,
    /// `BGTaskSchedulerPermittedIdentifiers`).
    static let activityTaskID = "app.verrou.activite"

    /// Demande à iOS un réveil dans 30 minutes au plus tôt (iOS choisit le
    /// moment, ou ne réveille pas l'app du tout).
    func scheduleBackgroundCheck() {
        guard mode == .vaultwarden, account != nil, ActivityNotifier.enabled, !ActivityNotifier.shared.silent else {
            return
        }
        let request = BGAppRefreshTaskRequest(identifier: Self.activityTaskID)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 30 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    /// Réveil en arrière-plan (`BGAppRefreshTask`) : un examen léger, qui ne
    /// déchiffre rien et ne garde aucune clé plus longtemps que prévu.
    /// - Délai de verrouillage dépassé : on verrouille d'abord (la clé n'a
    ///   plus rien à faire en mémoire).
    /// - Coffre encore ouvert (dans le délai) : synchronisation et examen
    ///   comme au premier plan, avec la clé déjà en mémoire.
    /// - Verrouillé : seulement le cache déjà téléchargé, sans clé ni réseau
    ///   (le jeton de renouvellement est chiffré par la clé de
    ///   l'utilisateur) ; voir SECURITY.md.
    func backgroundActivityCheck() async {
        scheduleBackgroundCheck()
        guard mode == .vaultwarden, account != nil, ActivityNotifier.enabled else { return }
        if lockState == .unlocked, let since = backgroundedAt, autoLockSeconds > 0,
           Date().timeIntervalSince(since) >= TimeInterval(autoLockSeconds) {
            lock()
        }
        if lockState == .unlocked {
            await syncNow(awaitActivity: true)
        } else {
            ActivityNotifier.shared.post(session.checkActivityLocked())
        }
    }

    /// Envoie en arrière-plan ce qui vient d'être écrit (voir `outbox.rs`),
    /// puis synchronise : l'interface n'attend pas le serveur.
    func pushChanges() {
        guard mode == .vaultwarden else { return }
        Task { await syncNow(afterWrite: true) }
    }

    /// `afterWrite` : juste après une écriture locale ; hors ligne il y a
    /// peu, le cœur ne retente pas tout de suite (la synchronisation
    /// périodique s'en charge). Les demandes simultanées sont regroupées par
    /// le cœur Rust.
    func syncNow(afterWrite: Bool = false, awaitActivity: Bool = false) async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        syncsInFlight += 1
        syncState = .syncing
        var result: SyncState = .idle
        defer {
            syncsInFlight -= 1
            if syncsInFlight == 0, lockState == .unlocked { syncState = result }
            refreshPending()
            Task { await self.showSyncReport() }
        }
        let watch = watchFirstSync ? MainThreadWatch() : nil
        watchFirstSync = false
        defer {
            syncsFinished += 1
            if let watch {
                Perf.mark("plus long blocage du fil principal pendant la première synchro : \(watch.stop()) ms")
            }
        }
        do {
            let outcome = try await Perf.measure("synchronisation") {
                try await afterWrite ? session.pushChanges() : session.sync()
            }
            guard lockState == .unlocked else { return }
            account = session.account()
            // Invitations en attente et membres à confirmer : à chaque
            // synchronisation périodique (pas après chaque écriture).
            // En arrière-plan, l'examen est attendu : iOS peut suspendre
            // l'app dès la fin de la tâche.
            if awaitActivity {
                await refreshSharingStatus()
            } else if !afterWrite {
                Task { await self.refreshSharingStatus() }
                Task { await self.finishPendingPasskeys() }
            }
            guard outcome.changed else { return }
            await reloadVaultAfterSync()
            if outcome.failures > 0 { result = .failed("\(outcome.failures) élément(s) illisible(s)") }
        } catch VerrouError.Locked {
            result = .idle
        } catch VerrouError.SessionExpired {
            result = .failed("Session expirée")
            reloginRequired = true
            lock()
        } catch VerrouError.Network {
            result = .offline
        } catch {
            result = .failed(ErrorText.describe(error))
        }
    }

    func refreshPending() {
        pendingChanges = mode == .vaultwarden ? Int(session.pendingChanges()) : 0
    }

    var pendingLabel: String? {
        guard pendingChanges > 0 else { return nil }
        return pendingChanges == 1 ? "1 modification en attente" : "\(pendingChanges) modifications en attente"
    }

    /// Toast d'une écriture, aussitôt faite (l'envoi suit en arrière-plan) ;
    /// hors ligne, elle attend le serveur.
    private func writeToast(_ message: String, detail: String? = nil) -> Toast {
        guard syncState == .offline else { return Toast(message: message, detail: detail) }
        return Toast(message: message, detail: "Hors ligne : synchronisé dès que le serveur répondra")
    }

    /// Bilan des modifications hors ligne envoyées : conflits et refus
    /// d'abord, puis les réussites.
    func showSyncReport() async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        let report = await session.takeSyncReport()
        if !report.conflicts.isEmpty {
            let count = report.conflicts.count
            toast = Toast(message: count == 1 ? "Conflit : version locale gardée en copie"
                                              : "\(count) conflits : versions locales gardées en copie",
                          detail: report.conflicts.map { "« \($0) »" }.joined(separator: ", "), failure: true, seconds: 4)
        } else if !report.rejected.isEmpty {
            // Retirée de la file : le coffre affiché est revenu à la version du serveur.
            toast = Toast(message: report.rejected.count == 1 ? "Modification refusée par le serveur, annulée"
                                                              : "\(report.rejected.count) modifications refusées par le serveur, annulées",
                          detail: report.rejected.joined(separator: "\n"), failure: true, seconds: 6)
        } else if report.sent > 0 {
            toast = Toast(message: report.sent == 1 ? "Modification hors ligne synchronisée"
                                                    : "\(report.sent) modifications hors ligne synchronisées", detail: nil)
        }
    }

    // MARK: Face ID

    private func enrollBiometricsIfWanted() async {
        guard mode == .vaultwarden, biometricsWanted, !biometricEnrolled, Biometrics.isAvailable,
              lockState == .unlocked else { return }
        do {
            try await vault.enrollBiometrics()
            biometricEnrolled = true
        } catch {
            Perf.log.error("enrôlement \(Biometrics.name, privacy: .public) impossible : \(String(describing: error), privacy: .public)")
            #if DEBUG
            print("E2E_INFO enrôlement Face ID impossible : \(error)")
            #endif
            biometricEnrolled = false
        }
    }

    // MARK: Coffre

    /// Résumés, compteurs et coffres partagés lus d'un coup (hors du fil
    /// principal après une synchronisation).
    private struct LoadedVault: @unchecked Sendable {
        let summaries: [ItemSummary]
        let counts: SidebarCounts?
        let organizations: [OrganizationView]
        let folders: [FolderOption]
    }

    /// Recharge la liste depuis le coffre local (après une écriture : il est
    /// déjà à jour, sans attendre le serveur).
    private func reloadVault(_ loaded: LoadedVault? = nil) {
        reloads += 1
        let start = ContinuousClock.now
        summaries = loaded?.summaries ?? (try? session.summaries()) ?? []
        summaryIndex = Dictionary(summaries.enumerated().map { ($1.id, $0) }, uniquingKeysWith: { first, _ in first })
        counts = loaded.map(\.counts) ?? (try? session.counts())
        organizations = loaded?.organizations ?? session.organizations()
        folders = loaded?.folders ?? session.folders()
        matchSettings = session.matchSettings()
        if let known = breaches { breaches = session.stillBreached(breaches: known) }
        if audit != nil {
            audit = try? session.audit()
            refreshPasskeyAudit()
        }
        refreshPending()
        // Un élément créé a reçu son identifiant du serveur : la fiche ouverte
        // suit ; un élément disparu (écriture refusée, annulée) la ferme.
        vaultPath = resolved(vaultPath)
        searchPath = resolved(searchPath)
        revision += 1
        publishAutofillIdentities()
        Perf.mark("rechargement de la liste (\(self.summaries.count) éléments) : \(Perf.ms(since: start)) ms")
    }

    private func resolved(_ path: [Route]) -> [Route] {
        path.compactMap { route in
            guard case .item(let id) = route else { return route }
            let resolved = session.resolveItemId(id: id)
            return summaryIndex[resolved] == nil ? nil : .item(resolved)
        }
    }

    // MARK: Remplissage automatique

    /// Sites, noms d'utilisateur et passkeys pour les suggestions du
    /// système (jamais un secret), un instant après le dernier changement.
    func publishAutofillIdentities() {
        guard mode == .vaultwarden, session.isUnlocked() else { return }
        identitiesTask?.cancel()
        let session = session
        identitiesTask = Task.detached(priority: .utility) {
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled, let identities = try? session.autofillIdentities() else { return }
            await CredentialIdentities.publish(identities)
        }
    }

    /// Demande au système si Verrou est choisi (Réglages), et republie.
    func refreshAutofillStatus() async {
        autofillEnabled = await CredentialIdentities.isEnabled()
        if autofillEnabled == true { publishAutofillIdentities() }
    }

    /// Ouvre la page des réglages où choisir Verrou (iOS 18), sinon les
    /// réglages de l'app.
    func openAutofillSettings() {
        if #available(iOS 18.0, *) {
            Task { try? await ASSettingsHelper.openCredentialProviderAppSettings() }
        } else if let url = URL(string: UIApplication.openSettingsURLString) {
            UIApplication.shared.open(url)
        }
    }

    /// Après une synchronisation : la lecture se fait hors du fil principal,
    /// puis tout est publié d'un coup ; une écriture locale plus récente
    /// l'emporte.
    private func reloadVaultAfterSync() async {
        let session = session
        let generation = reloads
        let loaded = await Task.detached(priority: .userInitiated) {
            LoadedVault(summaries: (try? session.summaries()) ?? [], counts: try? session.counts(),
                        organizations: session.organizations(), folders: session.folders())
        }.value
        guard lockState == .unlocked, generation == reloads else { return }
        reloadVault(loaded)
    }

    /// Résultats d'une recherche (cœur Rust, quelques millisecondes).
    func rows(query: String, filter: SidebarFilter, order: ResultOrder = .relevance) -> [ResultRow] {
        guard lockState == .unlocked else { return [] }
        let effective = query.isEmpty && order == .relevance ? ResultOrder.title : order
        let hits = (try? session.search(query: query, filter: filter, order: effective)) ?? []
        return hits.compactMap { hit in summary(for: hit).map { ResultRow(summary: $0, highlights: hit.highlights) } }
    }

    private func summary(for hit: SearchHit) -> ItemSummary? {
        let position = Int(hit.position)
        if summaries.indices.contains(position), summaries[position].id == hit.id { return summaries[position] }
        return summary(id: hit.id)
    }

    func summary(id: String) -> ItemSummary? {
        summaryIndex[id].flatMap { summaries.indices.contains($0) && summaries[$0].id == id ? summaries[$0] : nil }
    }

    func detail(id: String) -> ItemDetail? {
        _ = revision
        return try? session.detail(id: id)
    }

    func passkeys(of itemID: String) -> [PasskeyInfo] {
        _ = revision
        return session.passkeys(id: itemID)
    }

    /// Ouvre la fiche d'un élément dans l'onglet Coffre.
    func open(_ itemID: String) {
        tab = .vault
        vaultPath.append(.item(itemID))
    }

    /// Une fiche qui n'est plus dans aucune pile perd ses secrets révélés,
    /// sans attendre la fin de l'animation (ni compter sur `onDisappear`).
    private func forgetClosedItems() {
        guard !revealed.isEmpty else { return }
        var open = Set<String>()
        for case .item(let id) in vaultPath + searchPath { open.insert(id) }
        for id in revealed.keys where !open.contains(id) { revealed[id] = nil }
    }

    /// La fiche est quittée : ses secrets révélés sont oubliés.
    func forgetRevealed(of itemID: String) {
        revealed[itemID] = nil
    }

    func canModify(_ summary: ItemSummary?) -> Bool {
        canEdit && summary?.sharing?.readOnly != true
    }

    var writableOrganizations: [OrganizationView] {
        organizations.filter(\.writable)
    }

    // MARK: Éléments protégés

    /// Élément protégé pas encore confirmé : demande la confirmation, puis
    /// rejoue `retry`. Rend `true` si l'action doit attendre.
    func awaitsConfirmation(_ itemID: String, retry: @escaping @MainActor () -> Void) -> Bool {
        guard session.needsConfirmation(id: itemID) else { return false }
        let title = summary(id: itemID)?.title ?? "cet élément"
        Task {
            if await confirmAccess(itemID: itemID, title: title) { retry() }
        }
        return true
    }

    /// Face ID, sinon le mot de passe principal ; la confirmation vaut
    /// 5 minutes pour cet élément (côté Rust, effacée au verrouillage).
    func confirmAccess(itemID: String, title: String) async -> Bool {
        guard mode == .vaultwarden else {
            session.authorizeItem(id: itemID)
            return true
        }
        if Biometrics.isAvailable {
            switch await Biometrics.authenticate(reason: "afficher « \(title) »") {
            case .success:
                session.authorizeItem(id: itemID)
                return true
            case .failure(let message) where !message.isEmpty:
                break
            case .failure:
                return false
            case .fallback:
                break
            }
        }
        let confirmed = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            reprompt?.answer(false)
            reprompt = RepromptRequest(itemID: itemID, title: title) { continuation.resume(returning: $0) }
        }
        return confirmed
    }

    /// Réponse à la demande du mot de passe principal (`nil` : annulée).
    func answerReprompt(password: String?) async {
        guard let request = reprompt else { return }
        reprompt = nil
        guard let password, !password.isEmpty else {
            request.answer(false)
            return
        }
        do {
            guard try await session.verifyMasterPassword(password: password) else {
                toast = Toast(message: "Mot de passe principal incorrect", detail: nil, failure: true)
                request.answer(false)
                return
            }
            session.authorizeItem(id: request.itemID)
            request.answer(true)
        } catch {
            toast = Toast(message: "Confirmation impossible", detail: ErrorText.describe(error), failure: true)
            request.answer(false)
        }
    }

    // MARK: Secrets

    func revealedValue(_ fieldID: String, of itemID: String) -> String? {
        revealed[itemID]?[fieldID]
    }

    private func reveal(_ fieldID: String, of itemID: String) -> String? {
        if let value = revealed[itemID]?[fieldID] { return value }
        return try? session.reveal(id: itemID, fieldId: fieldID)
    }

    func toggleReveal(_ fieldID: String, of itemID: String) {
        if revealed[itemID]?[fieldID] != nil {
            revealed[itemID]?[fieldID] = nil
            return
        }
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.toggleReveal(fieldID, of: itemID) }) { return }
        guard let value = reveal(fieldID, of: itemID) else { return }
        revealed[itemID, default: [:]][fieldID] = value
    }

    /// Code à usage unique du moment, s'il est accessible sans confirmation.
    func totpCode(of itemID: String, at date: Date = Date()) -> TotpView? {
        vault.currentCode(of: itemID, at: date)
    }

    func copyCode(of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyCode(of: itemID) }) { return }
        guard let code = totpCode(of: itemID) else { return }
        session.recordItemUse(id: itemID)
        copy(code.code, label: "Code", secret: true)
    }

    func copy(_ value: String, label: String, secret: Bool) {
        let seconds = secret ? clipboardSeconds : 0
        clipboard.copy(value, expiresIn: seconds > 0 ? TimeInterval(seconds) : nil)
        copies += 1
        // Pas d'animation ici : la notification anime son arrivée elle-même
        // (ToastHost), sans entraîner les autres vues du modèle.
        toast = Toast(message: "\(label) copié",
                      detail: secret && seconds > 0 ? "Effacé du presse-papiers dans \(Self.durationLabel(seconds))" : nil)
    }

    func copyField(_ field: FieldView, of itemID: String) {
        if field.fieldType == .totp {
            copyCode(of: itemID)
            return
        }
        if field.hidden {
            toast = Toast(message: "Champ masqué", detail: "L'organisation le cache à votre compte", failure: true)
            return
        }
        if field.secret,
           awaitsConfirmation(itemID, retry: { [weak self] in self?.copyField(field, of: itemID) }) { return }
        let value = field.secret ? reveal(field.id, of: itemID) : field.value
        guard let value else { return }
        // Le numéro de carte se copie sans espaces : c'est ce qu'attendent les formulaires.
        let copied = field.fieldType == .cardNumber ? value.replacingOccurrences(of: " ", with: "") : value
        // Un secret révélé est déjà noté par le cœur ; un champ en clair, ici.
        if !field.secret { session.recordItemUse(id: itemID) }
        copy(copied, label: field.label, secret: field.secret)
    }

    func copyUsername(of itemID: String) {
        guard let field = detail(id: itemID)?.fields.first(where: { $0.fieldType == .username || $0.id == "username" }) else { return }
        copyField(field, of: itemID)
    }

    func copyPassword(of itemID: String) {
        if summary(id: itemID)?.sharing?.hidePasswords == true {
            toast = Toast(message: "Mot de passe masqué", detail: "L'organisation le cache à votre compte", failure: true)
            return
        }
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyPassword(of: itemID) }) { return }
        guard let value = try? session.reveal(id: itemID, fieldId: "password") else { return }
        copy(value, label: "Mot de passe", secret: true)
    }

    /// QR code d'un réseau Wi-Fi : le mot de passe passe par la même
    /// confirmation que les autres secrets, et seule l'image reste.
    func showWifiQRCode(of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.showWifiQRCode(of: itemID) }) { return }
        guard let payload = try? session.wifiQrCode(id: itemID), let image = QRCode.cgImage(payload) else {
            toast = Toast(message: "QR code impossible", detail: nil, failure: true)
            return
        }
        qrSheet = QRSheet(title: summary(id: itemID)?.title ?? "Wi-Fi", image: image)
    }

    static func durationLabel(_ seconds: Int) -> String {
        switch seconds {
        case ..<60: "\(seconds) s"
        case 60: "1 min"
        case ..<3600: "\(seconds / 60) min"
        default: "\(seconds / 3600) h"
        }
    }

    // MARK: Édition

    enum NewItemKind: Hashable {
        case login
        case note
        case card
        case identity
        case template(ItemTemplate)
    }

    func newItem(_ kind: NewItemKind, folderID: String? = nil, destination: SharedDestination? = nil) {
        guard canEdit else { return }
        editorError = nil
        var draft: ItemDraft
        switch kind {
        case .login:
            draft = ItemDraft(name: "", folderId: nil, favorite: false, notes: nil,
                              login: LoginFields(username: nil, password: generatePassword(length: 20, digits: true, symbols: true),
                                                 totp: nil, urls: []),
                              fields: [], template: nil)
        case .note:
            draft = ItemDraft(name: "", folderId: nil, favorite: false, notes: nil, login: nil, fields: [], template: nil)
        case .card:
            draft = ItemDraft(name: "", folderId: nil, favorite: false, notes: nil, login: nil, fields: [], template: nil,
                              card: CardFields(cardholderName: nil, brand: nil, number: nil, expMonth: nil, expYear: nil, code: nil))
        case .identity:
            draft = ItemDraft(name: "", folderId: nil, favorite: false, notes: nil, login: nil, fields: [], template: nil,
                              identity: IdentityFields(title: nil, firstName: nil, middleName: nil, lastName: nil, company: nil,
                                                       email: nil, phone: nil, username: nil, address1: nil, address2: nil,
                                                       address3: nil, postalCode: nil, city: nil, state: nil, country: nil,
                                                       ssn: nil, passportNumber: nil, licenseNumber: nil))
        case .template(let template):
            draft = templateDraft(template: template)
        }
        draft.folderId = folderID
        editor = Editor(itemID: nil, draft: draft, destination: destination)
    }

    func edit(_ itemID: String) async {
        guard canEdit else { return }
        if session.needsConfirmation(id: itemID) {
            guard await confirmAccess(itemID: itemID, title: summary(id: itemID)?.title ?? "cet élément") else { return }
        }
        editorError = nil
        do {
            editor = Editor(itemID: itemID, draft: try await session.editDraft(id: itemID))
        } catch {
            toast = Toast(message: "Modification impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Enregistre l'écran de modification ; rend `true` s'il peut se fermer.
    @discardableResult
    func saveEditor(_ draft: ItemDraft, destination: SharedDestination? = nil) async -> Bool {
        guard let editor, !editorBusy else { return false }
        editorBusy = true
        editorError = nil
        defer { editorBusy = false }
        do {
            let id: String
            if let existing = editor.itemID {
                try await session.updateItem(id: existing, draft: draft)
                id = existing
            } else if let destination {
                id = try await session.createSharedItem(draft: draft, organizationId: destination.organizationID,
                                                        collectionIds: destination.collectionIDs)
            } else {
                id = try await session.createItem(draft: draft)
            }
            // Écrit localement : la feuille se ferme tout de suite, l'envoi suit.
            self.editor = nil
            afterWrite()
            if editor.itemID == nil { open(session.resolveItemId(id: id)) }
            toast = writeToast(editor.itemID == nil ? "Élément créé" : "Enregistré")
            pushChanges()
            return true
        } catch VerrouError.Conflict {
            editorError = "L'élément a changé ailleurs entre-temps. Verrou vient de le recharger : rouvrez-le pour refaire la modification."
            await syncNow()
        } catch {
            editorError = ErrorText.describe(error)
        }
        return false
    }

    func trash(_ itemID: String) async {
        await perform("Mis à la corbeille", detail: "Restaurable depuis la corbeille") {
            try await self.session.trashItem(id: itemID)
        }
        editor = nil
        vaultPath.removeAll { $0 == .item(itemID) }
    }

    func restore(_ itemID: String) async {
        await perform("Restauré") { try await self.session.restoreItem(id: itemID) }
    }

    func setFavorite(_ itemID: String, _ favorite: Bool) async {
        await perform(favorite ? "Ajouté aux favoris" : "Retiré des favoris") {
            try await self.session.setFavorite(id: itemID, favorite: favorite)
        }
    }

    func setArchived(_ itemID: String, _ archived: Bool) async {
        await perform(archived ? "Archivé" : "Sorti des archives", detail: archived ? "Retrouvez-le dans Archives" : nil) {
            try await self.session.setArchived(id: itemID, archived: archived)
        }
    }

    func deletePasskey(itemID: String, credentialID: String) async {
        await perform("Passkey supprimée") {
            try await self.session.deletePasskey(id: itemID, credentialId: credentialID)
        }
    }

    private func perform(_ done: String, detail: String? = nil, _ action: @escaping () async throws -> Void) async {
        guard canEdit, !editorBusy else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            try await action()
            afterWrite()
            toast = writeToast(done, detail: detail)
            pushChanges()
        } catch {
            toast = Toast(message: "Action impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Écriture appliquée au coffre local (l'envoi suit, `pushChanges`) :
    /// la liste se met à jour tout de suite, les éléments en attente portent
    /// leur marque.
    func afterWrite() {
        guard lockState == .unlocked else { return }
        revealed = [:]
        reloadVault()
    }

    // MARK: Actions groupées

    /// Applique l'action aux éléments, en une fois (voir `bulk.rs`).
    func performBulk(_ action: BulkItemAction, on ids: [String], folderName: String? = nil) async {
        guard canEdit, !editorBusy, !ids.isEmpty else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            let result = try await session.bulkAction(ids: ids, action: action, progress: NoBulkProgress())
            afterWrite()
            toast = bulkToast(result, action: action, folderName: folderName)
            pushChanges()
        } catch {
            toast = Toast(message: "Action impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    func moveToNewFolder(_ name: String, ids: [String]) async {
        guard canEdit, !editorBusy else { return }
        do {
            let folder = try await session.createFolder(name: name)
            await performBulk(.moveToFolder(folderId: folder), on: ids, folderName: name.trimmingCharacters(in: .whitespaces))
        } catch {
            toast = Toast(message: "Dossier impossible à créer", detail: ErrorText.describe(error), failure: true)
        }
    }

    private func bulkToast(_ result: BulkResult, action: BulkItemAction, folderName: String?) -> Toast {
        let n = Int(result.done)
        let s = n > 1 ? "s" : ""
        var message: String
        switch action {
        case .archive: message = "\(n) archivé\(s)"
        case .unarchive: message = "\(n) sorti\(s) des archives"
        case .trash: message = "\(n) mis à la corbeille"
        case .restore: message = "\(n) restauré\(s)"
        case .favorite(let favorite): message = favorite ? "\(n) ajouté\(s) aux favoris" : "\(n) retiré\(s) des favoris"
        case .moveToFolder(let folder):
            message = folder == nil ? "\(n) retiré\(s) de leur dossier"
                : "\(n) déplacé\(s) vers « \(folderName ?? folders.first { $0.id == folder }?.name ?? "dossier") »"
        }
        var ignored: [String] = []
        if result.readOnly > 0 { ignored.append("\(result.readOnly) ignoré\(result.readOnly > 1 ? "s" : "") (lecture seule)") }
        if result.inTrash > 0 { ignored.append("\(result.inTrash) ignoré\(result.inTrash > 1 ? "s" : "") (dans la corbeille)") }
        if result.notFound > 0 { ignored.append("\(result.notFound) introuvable\(result.notFound > 1 ? "s" : "")") }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !result.failures.isEmpty {
            return Toast(message: message + ", \(result.failures.count) refusé\(result.failures.count > 1 ? "s" : "")",
                         detail: result.failures.joined(separator: "\n"), failure: true, seconds: 5)
        }
        let detail = result.queued > 0 && syncState == .offline ? "Hors ligne : synchronisé dès que le serveur répondra" : nil
        return Toast(message: message, detail: detail, seconds: ignored.isEmpty ? 2.2 : 4)
    }

    // MARK: Pièces jointes

    func loadAttachments(of itemID: String) async {
        let entries = (try? await session.attachments(itemId: itemID)) ?? []
        guard lockState == .unlocked else { return }
        attachments[itemID] = entries
    }

    /// Ouvre la pièce jointe dans Quick Look (téléchargée et déchiffrée).
    func openAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.openAttachment(entry, of: itemID) }) { return }
        Task {
            guard let url = await decryptedFile(entry, of: itemID) else { return }
            preview = url
        }
    }

    /// Partage une copie déchiffrée (Fichiers, AirDrop, autre app).
    func shareAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.shareAttachment(entry, of: itemID) }) { return }
        Task {
            guard let url = await decryptedFile(entry, of: itemID) else { return }
            sharedFile = SharedFile(url: url)
        }
    }

    private func decryptedFile(_ entry: AttachmentEntry, of itemID: String) async -> URL? {
        guard attachmentActivity == nil else { return nil }
        attachmentActivity = "Téléchargement de « \(entry.fileName) »…"
        defer { attachmentActivity = nil }
        do {
            let content = try await session.downloadAttachment(itemId: itemID, attachmentId: entry.id)
            guard lockState == .unlocked else { return nil }
            return try Attachments.temporaryFile(named: content.fileName, data: content.data)
        } catch {
            toast = Toast(message: "Pièce jointe illisible", detail: ErrorText.describe(error), failure: true)
            return nil
        }
    }

    func addAttachment(from url: URL, to itemID: String) async {
        guard canEdit, attachmentActivity == nil else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            toast = Toast(message: "Fichier illisible", detail: url.lastPathComponent, failure: true)
            return
        }
        guard data.count <= Attachments.maxSize else {
            toast = Toast(message: "Fichier trop volumineux", detail: "100 Mo au plus", failure: true)
            return
        }
        attachmentActivity = "Envoi de « \(url.lastPathComponent) »…"
        defer { attachmentActivity = nil }
        do {
            try await session.addAttachment(itemId: itemID, fileName: url.lastPathComponent, data: data)
            afterWrite()
            await loadAttachments(of: itemID)
            toast = Toast(message: "Pièce jointe ajoutée", detail: url.lastPathComponent)
        } catch {
            toast = Toast(message: "Envoi impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    func deleteAttachment(_ entry: AttachmentEntry, of itemID: String) async {
        guard canEdit, attachmentActivity == nil else { return }
        attachmentActivity = "Suppression…"
        defer { attachmentActivity = nil }
        do {
            try await session.deleteAttachment(itemId: itemID, attachmentId: entry.id)
            afterWrite()
            await loadAttachments(of: itemID)
            toast = Toast(message: "Pièce jointe supprimée", detail: entry.fileName)
        } catch {
            toast = Toast(message: "Suppression impossible", detail: ErrorText.describe(error), failure: true)
        }
    }

    // MARK: Audit

    func openAudit() {
        audit = try? session.audit()
        refreshPasskeyAudit()
        tab = .vault
        vaultPath = [.audit]
    }

    func refreshAudit() {
        audit = try? session.audit()
        refreshPasskeyAudit()
    }

    /// Have I Been Pwned, par k-anonymat (5 caractères d'empreinte par mot de passe).
    func checkBreaches() async {
        guard !checkingBreaches, lockState == .unlocked, mode == .vaultwarden else { return }
        checkingBreaches = true
        breachError = nil
        defer { checkingBreaches = false }
        do {
            breaches = try await session.checkBreaches()
        } catch {
            breachError = ErrorText.describe(error)
        }
    }
}

/// Où ranger un élément partagé : une organisation et ses collections.
struct SharedDestination: Equatable, Hashable {
    var organizationID: String
    var collectionIDs: [String]
}

/// Les actions groupées de l'iPhone n'affichent pas d'avancement : une
/// requête par lot de 500, l'attente est courte.
final class NoBulkProgress: BulkProgress, @unchecked Sendable {
    func progress(done: UInt32, total: UInt32) {}
}
