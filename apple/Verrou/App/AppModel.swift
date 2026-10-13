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

    var filter: SidebarFilter = .all { didSet { refresh() } }
    var query: String = "" { didSet { refresh() } }
    var sort: ResultOrder = .relevance { didSet { refresh() } }
    var selection: String? { didSet { if oldValue != selection { revealed.removeAll() } } }
    /// Champs révélés pour l'élément sélectionné, effacés dès qu'on en change.
    var revealed: [String: String] = [:]
    var toast: Toast?
    /// Requête de la fenêtre d'accès rapide, indépendante de la fenêtre principale.
    var quickQuery = ""
    /// Incrémenté à chaque ouverture de l'accès rapide : la fenêtre est
    /// réutilisée, son `onAppear` ne revient pas.
    private(set) var quickAccessOpenings = 0

    func quickAccessOpened() {
        quickAccessOpenings += 1
    }

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
    }

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
        lockState = .unlocking
        unlockError = nil
        if mode == .demo {
            switch await Biometrics.authenticate(reason: "déverrouiller votre coffre") {
            case .success: openVault()
            case .failure(let message):
                unlockError = message
                lockState = .locked
            }
            return
        }
        do {
            let key = try await BiometricVault.open(in: dataDirectory, reason: "déverrouiller votre coffre")
            didUnlock(failures: try await session.unlockWithUserKey(userKey: key))
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
        do {
            didUnlock(failures: try await session.unlockWithPassword(password: masterPassword))
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
    private func reloadVault() {
        summaries = (try? session.summaries()) ?? []
        counts = try? session.counts()
        refresh()
        if selection.map({ id in !summaries.contains { $0.id == id } }) ?? true {
            selection = results.first.map { summaries[Int($0.position)].id }
        }
    }

    func lock() {
        syncLoop?.cancel()
        syncLoop = nil
        session.lock()
        summaries = []
        results = []
        counts = nil
        revealed.removeAll()
        selection = nil
        query = ""
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
            let failures = try await session.sync()
            guard lockState == .unlocked else { return }
            account = session.account()
            reloadVault()
            syncState = .idle
            if failures > 0 { syncState = .failed("\(failures) élément(s) illisible(s)") }
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
        }
    }

    // MARK: Recherche

    private func refresh() {
        guard lockState == .unlocked else { return }
        let clock = ContinuousClock()
        let start = clock.now
        let effectiveSort = query.isEmpty && sort == .relevance ? ResultOrder.title : sort
        results = (try? session.search(query: query, filter: filter, order: effectiveSort)) ?? []
        lastSearchDuration = clock.now - start
    }

    func summary(for hit: SearchHit) -> ItemSummary {
        summaries[Int(hit.position)]
    }

    var selectedDetail: ItemDetail? {
        guard let selection else { return nil }
        return try? session.detail(id: selection)
    }

    func moveSelection(by offset: Int) {
        guard !results.isEmpty else { return }
        let ids = results.map { summaries[Int($0.position)].id }
        let current = selection.flatMap { ids.firstIndex(of: $0) } ?? -1
        let next = min(max(current + offset, 0), ids.count - 1)
        selection = ids[next]
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
            _ = reveal(fieldID, of: itemID)
        }
    }

    func copy(_ value: String, label: String, secret: Bool) {
        clipboard.copy(value, concealed: secret)
        withAnimation(.snappy) {
            toast = Toast(message: "\(label) copié", detail: secret ? "Effacé du presse-papiers dans 90 s" : nil)
        }
    }

    func copyField(_ field: FieldView, of itemID: String) {
        if field.fieldType == .totp {
            guard let code = try? session.totp(id: itemID, unixTime: UInt64(Date().timeIntervalSince1970)) else { return }
            copy(code.code, label: "Code", secret: true)
            return
        }
        let value = field.secret ? reveal(field.id, of: itemID) : field.value
        guard let value else { return }
        // Le numéro de carte se copie sans espaces : c'est ce qu'attendent les
        // formulaires.
        let copied = field.fieldType == .cardNumber ? value.replacingOccurrences(of: " ", with: "") : value
        copy(copied, label: field.label, secret: field.secret)
        if field.secret { revealed[field.id] = nil }
    }

    func copyPassword(of itemID: String) {
        guard let value = try? session.reveal(id: itemID, fieldId: "password") else { return }
        copy(value, label: "Mot de passe", secret: true)
    }

    func noteActivity() {
        autoLock?.touch()
    }
}

struct Toast: Equatable, Identifiable {
    let id = UUID()
    let message: String
    let detail: String?
}

/// Verrouillage automatique : inactivité, mise en veille, écran verrouillé.
@MainActor
final class AutoLock {
    private let timeout: TimeInterval = 10 * 60
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
                MainActor.assumeIsolated { self?.onLock() }
            })
        }
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.onLock() }
        })
    }

    func touch() { lastActivity = Date() }

    private func check() {
        if Date().timeIntervalSince(lastActivity) > timeout { onLock() }
    }

    deinit {
        timer?.invalidate()
        observers.forEach {
            NSWorkspace.shared.notificationCenter.removeObserver($0)
            DistributedNotificationCenter.default().removeObserver($0)
        }
    }
}
