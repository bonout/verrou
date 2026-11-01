import AuthenticationServices
import Foundation
import LocalAuthentication
import Observation
import os

/// The AutoFill extension's state for a system request: what it wants
/// (list, specific login, passkey, code, passkey creation), the unlock, then
/// the response.
///
/// One request, a short process: the vault is opened for it (Face ID or
/// master password), then closed again as soon as the response is given.
@MainActor
@Observable
final class AutoFillModel {
    enum Phase: Equatable {
        /// No account in the shared folder (app never opened, or build
        /// without an app group).
        case noAccount
        case locked
        case unlocking
        case ready
        /// Write or signature in progress (passkey).
        case working
    }

    /// What the system requests.
    enum Request {
        /// List of logins for these sites (and of the site's passkeys if
        /// `passkeys` is given).
        case list(services: [ASCredentialServiceIdentifier], passkeys: PasskeyQuery?)
        /// List of one-time codes for these sites (iOS 18).
        case oneTimeCodes(services: [ASCredentialServiceIdentifier])
        /// A system suggestion tapped by the user.
        case provide(ASCredentialRequest)
        /// Creation of a passkey.
        case register(ASPasskeyCredentialRequest)
        case alias
        case save(LoginToSave)
        /// Nothing (configuration).
        case none
    }

    /// A passkey request from the site (`prepareCredentialList(for:requestParameters:)`).
    struct LoginToSave {
        let site: String
        let user: String
        let password: String
    }

    struct PasskeyQuery {
        let rpID: String
        let clientDataHash: Data
        let allowed: [Data]
        /// PRF extension requested by the site (iOS 18, macOS 15).
        var prf: PasskeyPrfAssertion?
    }

    /// The response given back to the system.
    enum Completion {
        case password(user: String, password: String)
        case assertion(ASPasskeyAssertionCredential)
        case registration(ASPasskeyRegistrationCredential)
        case oneTimeCode(String)
        case text(String)
        case saved
        case cancel
        case failed(String)
    }

    /// A protected item awaits a confirmation (Face ID or password).
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
    var aliasSite = ""
    private(set) var aliasSettings: EmailAliasSettings?
    private(set) var alias = ""
    private(set) var saveCheck: AutofillSaveCheck?
    private(set) var loginSaved = false

    /// The site's logins (or codes), from most to least specific.
    private(set) var matches: [ItemSummary] = []
    /// All the vault's items (search), once open.
    private(set) var everything: [ItemSummary] = []
    private(set) var passkeys: [AutofillPasskey] = []
    /// Passkey creation: the site's logins that can receive it.
    private(set) var targets: [ItemSummary] = []
    /// Passkey created: the sheet confirms (checkmark) before closing.
    private(set) var passkeyCreated = false
    /// iPhone: the login filled less than 90 seconds ago on the list's site
    /// (`RecentFill`), offered at the top of the lock screen ("Continue
    /// as…") instead of starting Face ID.
    private(set) var recentLogin: (itemID: String, user: String)?

    private let complete: (Completion) -> Void
    private let log = Logger(subsystem: "app.verrou.autofill", category: "extension")
    /// Face ID or master password passed for this request: the passkey sets
    /// the "user verified" flag.
    private var userVerified = false
    private var finished = false
    /// Items that asked for their confirmation: never kept for the next step
    /// (`RecentFill`).
    private var protectedItems: Set<String> = []

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
        Memory.log("open")
    }

    var account: AccountInfo? { vault?.account }
    var canUseBiometrics: Bool { (vault?.autofillBiometricEnrolled ?? false) && Biometrics.isAvailable }

    /// The screen's title.
    var title: String {
        switch request {
        case .register: String(localized: "Save a passkey")
        case .oneTimeCodes: String(localized: "One-time codes")
        case .alias: String(localized: "Email alias")
        case .save: saveCheck?.action == .update ? String(localized: "Update Password") : String(localized: "Save Login")
        default: "Verrou"
        }
    }

    /// The requested site, for the header.
    var site: String? {
        switch request {
        case .list(let services, let passkeys): passkeys?.rpID ?? services.first.map(Self.host)
        case .oneTimeCodes(let services): services.first.map(Self.host)
        case .register(let request): (request.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier
        case .save(let login): login.site
        case .provide, .alias, .none: nil
        }
    }

    static func host(of service: ASCredentialServiceIdentifier) -> String {
        if service.type == .URL, let host = URL(string: service.identifier)?.host() { return host }
        return service.identifier
    }

    // MARK: Request

    func start(_ request: Request) {
        Perf.mark("request at +\(Perf.msSinceLaunch) ms from launch")
        self.request = request
        if case .alias = request {
            aliasSettings = vault?.session.emailAliasSettings()
            generateAlias()
        }
        if phase == .ready { load() }
        offerRecentLogin()
    }

    var aliasUsesSite: Bool { aliasSettings?.includeSite ?? true }

    var canSignUpWithAlias: Bool {
        guard case .list = request else { return false }
        return aliasSettings?.domain != nil && site != nil
    }

    func signUpWithAlias() {
        guard let session = vault?.session, let site, canSignUpWithAlias else { return }
        phase = .working
        Task {
            do {
                let alias = try session.generateEmailAlias(uri: site, includeSite: nil)
                let password = GeneratorSettings.forAutoFill.password(rules: "")
                let id = try await session.autofillSave(service: site, username: alias, password: password, itemId: nil)
                if let identities = try? session.autofillIdentities() {
                    await CredentialIdentities.publish(identities)
                }
                RecentFill.remember(itemID: id, user: alias, password: password, sites: [site])
                finish(.password(user: alias, password: password))
            } catch {
                phase = .ready
                actionError = ErrorText.describe(error)
            }
        }
    }

    func generateAlias() {
        guard let session = vault?.session, aliasSettings?.domain != nil else { return }
        let site = aliasUsesSite ? aliasSite.trimmingCharacters(in: .whitespacesAndNewlines) : ""
        alias = (try? session.generateEmailAlias(uri: site, includeSite: site.isEmpty ? false : nil)) ?? ""
    }

    var canSignUpWithInsertedAlias: Bool {
        !alias.isEmpty && !aliasSite.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && (phase == .ready || canUseBiometrics)
    }

    func signUpWithInsertedAlias() {
        let site = aliasSite.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard canSignUpWithInsertedAlias else { return }
        Task {
            if phase == .locked, await !unlockWithSession() { await unlockWithBiometrics() }
            guard phase == .ready, let session = vault?.session else { return }
            phase = .working
            do {
                let password = GeneratorSettings.forAutoFill.password(rules: "")
                let id = try await session.autofillSave(service: site, username: alias, password: password, itemId: nil)
                if let identities = try? session.autofillIdentities() {
                    await CredentialIdentities.publish(identities)
                }
                RecentFill.remember(itemID: id, user: alias, password: password, sites: [site],
                                    lifetime: RecentFill.signUpLifetime)
                finish(.text(alias))
            } catch {
                phase = .ready
                actionError = ErrorText.describe(error)
            }
        }
    }

    func insertAlias() {
        guard !alias.isEmpty else { return }
        finish(.text(alias))
    }

    /// The list of a site where a login was just filled (two-step form, the
    /// key icon tapped for the second page): that login is offered without
    /// Face ID. Not when the 5-minute session opens the list by itself, nor
    /// on the Mac, whose sheet starts Face ID as soon as it appears.
    private func offerRecentLogin() {
        #if os(iOS)
        recentLogin = nil
        guard phase == .locked, case .list(let services, _) = request else { return }
        if !wantsPasskey, AutofillSession.userKey() != nil { return }
        recentLogin = RecentFill.login(forSites: services.map(Self.host))
        #endif
    }

    /// "Continue as…": the remembered login, without Face ID; Face ID if it
    /// expired in the meantime.
    func continueWithRecentLogin() {
        guard let recent = recentLogin else { return }
        if let credential = RecentFill.credential(for: recent.itemID) {
            Perf.mark("recent login filled from the list")
            finish(.password(user: credential.user, password: credential.password))
        } else {
            recentLogin = nil
            if canUseBiometrics { Task { await unlockWithBiometrics() } }
        }
    }

    // MARK: Unlocking

    /// Face ID right away if possible (the request comes from a user
    /// gesture). `appeared`: the sheet is on screen (`viewDidAppear`), no
    /// need to wait for it.
    func autoUnlock(appeared: Bool = false) async {
        if await unlockWithSession() { return }
        // The user chooses: the login just filled, or Face ID for another.
        guard recentLogin == nil else { return }
        guard phase == .locked, canUseBiometrics else { return }
        // The extension's interface is only in the foreground once its sheet
        // is presented: before that, LocalAuthentication refuses ("caller is
        // not running foreground"). We wait, then retry a little.
        for attempt in 0..<6 {
            if attempt > 0 || !appeared {
                try? await Task.sleep(for: .milliseconds(attempt == 0 ? 350 : 500))
            }
            guard phase == .locked else { return }
            if await unlockWithBiometrics(quietWhenNotForeground: attempt < 5) { return }
        }
    }

    /// Within 5 minutes of a Face ID (`AutofillSession`): the vault opens
    /// without asking. Not for passkeys, whose signature tells the site that
    /// the user was verified.
    private func unlockWithSession() async -> Bool {
        #if os(iOS)
        guard let vault, phase == .locked, !wantsPasskey, let key = AutofillSession.userKey() else { return false }
        phase = .unlocking
        do {
            _ = try await vault.session.unlockWithUserKey(userKey: key)
            Perf.mark("vault opened without \(Biometrics.name) (session)")
            didUnlock()
            return true
        } catch {
            AutofillSession.forget()
            phase = .locked
            offerRecentLogin()
            return false
        }
        #else
        return false
        #endif
    }

    /// A tapped suggestion within 5 minutes of a Face ID: the login, without
    /// an interface; `nil` if Face ID is needed (no session, protected item,
    /// not a password).
    func fillWithoutInteraction(_ request: ASCredentialRequest) async -> Completion? {
        #if os(iOS)
        guard request.type == .password,
              let id = request.credentialIdentity.recordIdentifier,
              let key = AutofillSession.userKey(), let vault else { return nil }
        let session = vault.session
        do {
            _ = try await session.unlockWithUserKey(userKey: key)
        } catch {
            AutofillSession.forget()
            return nil
        }
        defer { vault.lock() }
        guard !session.needsConfirmation(id: id), let credential = try? session.autofillPassword(id: id) else { return nil }
        if #available(iOS 18.0, *) {
            _ = try? await session.preparePasskeyUpgrade(id: id)
        }
        Perf.mark("filled without \(Biometrics.name) (session)")
        return .password(user: credential.username, password: credential.password)
        #else
        return nil
        #endif
    }

    /// The request involves a passkey (list with the site's passkeys,
    /// assertion, creation).
    private var wantsPasskey: Bool {
        switch request {
        case .list(_, let passkeys): passkeys != nil
        case .provide(let request): request.type != .password && !Self.isOneTimeCode(request)
        case .register: true
        case .oneTimeCodes, .alias, .save, .none: false
        }
    }

    private static func isOneTimeCode(_ request: ASCredentialRequest) -> Bool {
        if #available(iOS 18.0, macOS 15.0, *) { return request.type == .oneTimeCode }
        return false
    }

    /// Face ID or the master password passed: the next fills skip it for
    /// 5 minutes (iPhone).
    private func startSession() async {
        #if os(iOS)
        guard AutofillSession.isEnabled, let key = try? await vault?.session.userKey() else { return }
        AutofillSession.remember(userKey: key)
        #endif
    }

    /// Returns `false` if the prompt could not be shown (extension not yet in
    /// the foreground) and `quietWhenNotForeground` allows retrying.
    @discardableResult
    func unlockWithBiometrics(quietWhenNotForeground: Bool = false) async -> Bool {
        guard let vault, phase == .locked else { return true }
        phase = .unlocking
        unlockError = nil
        do {
            _ = try await vault.unlockForAutofill(reason: String(localized: "fill with Verrou"))
            userVerified = true
            await startSession()
            didUnlock()
        } catch BiometricVault.Failure.cancelled, BiometricVault.Failure.interrupted {
            phase = .locked
        } catch BiometricVault.Failure.unavailable {
            unlockError = String(localized: "\(Biometrics.name) is not available: enter your master password.")
            phase = .locked
        } catch BiometricVault.Failure.invalidated {
            unlockError = String(localized: "\(Biometrics.name) needs to be turned on again: enter your master password.")
            phase = .locked
        } catch let error as LAError where error.code == .notInteractive && quietWhenNotForeground {
            phase = .locked
            return false
        } catch {
            log.error("Face ID: \(String(describing: error), privacy: .public)")
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
            await startSession()
            didUnlock()
        } catch {
            unlockError = ErrorText.describe(error)
            phase = .locked
        }
    }

    private func didUnlock() {
        phase = .ready
        Memory.log("vault open")
        load()
    }

    /// Reads what the request shows, or answers it directly (tapped
    /// suggestion).
    private func load() {
        guard let vault else { return }
        let session = vault.session
        // A tapped suggestion fills right away: no list to read.
        if case .provide(let request) = request {
            Task { await provide(request) }
            return
        }
        everything = ((try? session.summaries()) ?? []).filter { $0.category == .login && $0.state == .active }
        switch request {
        case .list(let services, let query):
            matches = (try? session.autofillMatches(services: services.map(\.identifier))) ?? []
            if let query {
                passkeys = (try? session.autofillPasskeys(rpId: query.rpID, allowed: query.allowed)) ?? []
            }
            if matches.isEmpty { aliasSettings = session.emailAliasSettings() }
        case .oneTimeCodes(let services):
            matches = ((try? session.autofillMatches(services: services.map(\.identifier))) ?? []).filter(\.hasTotp)
            everything = everything.filter(\.hasTotp)
        case .register(let request):
            if let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity {
                targets = (try? session.autofillPasskeyTargets(rpId: identity.relyingPartyIdentifier)) ?? []
            }
        case .save(let login):
            do {
                let check = try session.autofillSaveCheck(service: login.site, username: login.user, password: login.password)
                saveCheck = check
                if check.action == .known { finish(.saved) }
            } catch {
                finish(.failed(ErrorText.describe(error)))
            }
        case .provide, .alias, .none:
            break
        }
    }

    /// Search results across the whole vault (Rust core).
    var searchResults: [ItemSummary] {
        Array(allSearchResults.prefix(50))
    }

    var allSearchResults: [ItemSummary] {
        guard let session = vault?.session, !query.isEmpty else { return [] }
        let filter: SidebarFilter = .category(category: .login)
        let hits = (try? session.search(query: query, filter: filter, order: .relevance)) ?? []
        let byID = Dictionary(everything.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return hits.compactMap { byID[$0.id] }
    }

    // MARK: Responses

    /// The user chose a login (or a code) in the list.
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
            let credentialID = Data(passkey.credentialId)
            await self?.sign(rpID: query.rpID, credentialID: credentialID,
                             clientDataHash: query.clientDataHash, prf: query.prf?.inputs(for: credentialID))
        }
    }

    /// Creation: in an existing login, or a new one (`nil`).
    func register(into item: ItemSummary?) {
        guard case .register(let request) = request else { return }
        if let item {
            guarded(item.id, title: item.title) { [weak self] in await self?.create(request, item: item.id) }
        } else {
            Task { await create(request, item: nil) }
        }
    }

    func cancel() { finish(.cancel) }

    func saveLogin() {
        guard case .save(let login) = request, let check = saveCheck else { return }
        if check.action == .update, let id = check.itemId {
            guarded(id, title: check.title ?? login.site) { [weak self] in await self?.store(login, into: id) }
        } else {
            Task { await store(login, into: nil) }
        }
    }

    func saveWithoutInteraction(_ login: LoginToSave) async -> Completion? {
        #if os(iOS)
        if RecentFill.isLogin(user: login.user, password: login.password, site: login.site) { return .saved }
        guard let key = AutofillSession.userKey(), let vault else { return nil }
        let session = vault.session
        do {
            _ = try await session.unlockWithUserKey(userKey: key)
        } catch {
            AutofillSession.forget()
            return nil
        }
        defer { vault.lock() }
        let check = try? session.autofillSaveCheck(service: login.site, username: login.user, password: login.password)
        return check?.action == .known ? .saved : nil
        #else
        return nil
        #endif
    }

    private func store(_ login: LoginToSave, into item: String?) async {
        guard let session = vault?.session else { return }
        phase = .working
        do {
            _ = try await session.autofillSave(service: login.site, username: login.user, password: login.password, itemId: item)
            if let identities = try? session.autofillIdentities() {
                await CredentialIdentities.publish(identities)
            }
            loginSaved = true
            try? await Task.sleep(for: .milliseconds(650))
            finish(.saved)
        } catch {
            phase = .ready
            actionError = ErrorText.describe(error)
        }
    }

    /// A tapped suggestion (QuickType, Safari's list): the request already
    /// designates the item.
    private func provide(_ request: ASCredentialRequest) async {
        switch request.type {
        case .password:
            guard let identity = request.credentialIdentity as? ASPasswordCredentialIdentity,
                  let id = identity.recordIdentifier else { return finish(.failed("unknown login")) }
            guarded(id, title: identity.user) { [weak self] in await self?.fillPassword(id) }
        case .passkeyAssertion:
            guard let request = request as? ASPasskeyCredentialRequest,
                  let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
            else { return finish(.failed("unknown passkey")) }
            guard request.supportedAlgorithms.isEmpty || request.supportedAlgorithms.contains(.ES256) else {
                return finish(.failed("the site doesn't accept ES256 keys"))
            }
            let id = identity.recordIdentifier ?? ""
            var prf: PrfInputs?
            if #available(iOS 18.0, *) {
                prf = PasskeyPrfAssertion(request: request)?.inputs(for: identity.credentialID)
            }
            guarded(id, title: identity.userName) { [weak self] in
                await self?.sign(rpID: identity.relyingPartyIdentifier, credentialID: identity.credentialID,
                                 clientDataHash: request.clientDataHash, prf: prf)
            }
        default:
            if #available(iOS 18.0, *), request.type == .oneTimeCode,
               let identity = request.credentialIdentity as? ASOneTimeCodeCredentialIdentity,
               let id = identity.recordIdentifier {
                guarded(id, title: identity.label) { [weak self] in await self?.fillCode(id) }
                return
            }
            finish(.failed("unsupported request"))
        }
    }

    /// A protected item ("re-ask for the master password") awaits its
    /// confirmation, as in the app; otherwise the action starts right away.
    private func guarded(_ itemID: String, title: String, _ action: @escaping () async -> Void) {
        guard let session = vault?.session else { return }
        if session.needsConfirmation(id: itemID) {
            protectedItems.insert(itemID)
            confirmation = Confirmation(itemID: itemID, title: title, action: action)
            Task { await confirmWithBiometrics() }
        } else {
            Task { await action() }
        }
    }

    /// Confirmation of a protected item by Face ID.
    func confirmWithBiometrics() async {
        guard let confirmation, let session = vault?.session else { return }
        switch await Biometrics.authenticate(reason: String(localized: "confirm access to “\(confirmation.title)”")) {
        case .success:
            session.authorizeItem(id: confirmation.itemID)
            self.confirmation = nil
            await confirmation.action()
        case .fallback, .failure:
            break // the master password stays offered
        }
    }

    /// Confirmation of a protected item by the master password.
    func confirm(masterPassword: String) async {
        guard let confirmation, let session = vault?.session else { return }
        if (try? await session.verifyMasterPassword(password: masterPassword)) == true {
            session.authorizeItem(id: confirmation.itemID)
            self.confirmation = nil
            await confirmation.action()
        } else {
            actionError = String(localized: "Incorrect master password.")
        }
    }

    private func fillPassword(_ id: String) async {
        guard let session = vault?.session else { return }
        do {
            let credential = try await Perf.measure("password read") { try session.autofillPassword(id: id) }
            // The next step of the form fills without Face ID; a protected
            // item asks again each time.
            if protectedItems.contains(id) {
                RecentFill.forget()
            } else {
                RecentFill.remember(itemID: id, user: credential.username, password: credential.password,
                                    sites: sites(filling: id))
            }
            // Conditional creation (iOS 18): Safari may request, right after,
            // a passkey for this account, in the background with the vault
            // closed. The key is prepared now (see conditional.rs).
            if #available(iOS 18.0, *) {
                do {
                    _ = try await Perf.measure("passkey prepared") { try await session.preparePasskeyUpgrade(id: id) }
                } catch {
                    log.notice("passkey key not prepared: \(String(describing: error), privacy: .public)")
                }
            }
            finish(.password(user: credential.username, password: credential.password))
        } catch {
            actionError = ErrorText.describe(error)
        }
    }

    /// The hosts a filled login is offered again on (`RecentFill`): the
    /// request's sites and the login's own.
    private func sites(filling id: String) -> [String] {
        var hosts: [String] = []
        switch request {
        case .list(let services, _):
            hosts = services.map(Self.host)
        case .provide(let request):
            if let identity = request.credentialIdentity as? ASPasswordCredentialIdentity {
                hosts = [Self.host(of: identity.serviceIdentifier)]
            }
        default:
            break
        }
        if let host = (matches + everything).first(where: { $0.id == id })?.host { hosts.append(host) }
        return hosts
    }

    private func fillCode(_ id: String) async {
        guard let vault else { return }
        if let code = vault.currentCode(of: id) {
            // Recorded for the app's "Last used" sort.
            vault.session.recordItemUse(id: id)
            finish(.oneTimeCode(code.code))
        } else {
            actionError = String(localized: "This item has no one-time code.")
        }
    }

    private func sign(rpID: String, credentialID: Data, clientDataHash: Data, prf: PrfInputs? = nil) async {
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
            // PRF: outputs alongside the assertion (nothing in authenticatorData).
            if #available(iOS 18.0, *), let prf {
                do {
                    let output = try session.passkeyPrf(rpId: rpID, credentialId: credentialID, first: prf.first,
                                                        second: prf.second, userVerified: userVerified)
                    credential.extensionOutput = PasskeyPrfOutputs.assertion(output)
                } catch {
                    log.error("PRF not evaluated: \(String(describing: error), privacy: .public)")
                }
            }
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
            actionError = String(localized: "This site doesn't accept ES256 keys: use another manager.")
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
            // PRF requested: the passkey supports it, and already gives its
            // outputs if the site provided inputs.
            if #available(iOS 18.0, *), let prf = PasskeyPrfRegistration(request: request) {
                var output: PasskeyPrfOutput?
                if let eval = prf.eval {
                    output = try? session.passkeyPrf(
                        rpId: identity.relyingPartyIdentifier, credentialId: Data(result.credentialId),
                        first: eval.first, second: eval.second, userVerified: userVerified)
                }
                credential.extensionOutput = PasskeyPrfOutputs.registration(output)
            }
            // The system only offers a passkey (`allowCredentials`) if it is
            // in its identity store: we update it here, without waiting for
            // the app to sync.
            if let identities = try? session.autofillIdentities() {
                await CredentialIdentities.publish(identities)
            }
            // Short confirmation in the sheet (symbol effects), then response.
            passkeyCreated = true
            try? await Task.sleep(for: .milliseconds(650))
            finish(.registration(credential))
        } catch {
            phase = .ready
            actionError = ErrorText.describe(error)
        }
    }

    /// Responds only once, closes the vault (the Rust core erases its
    /// secrets) and logs the memory.
    private func finish(_ completion: Completion) {
        guard !finished else { return }
        finished = true
        Memory.log("response")
        Perf.mark("response at +\(Perf.msSinceLaunch) ms from launch")
        // The answer first: the system fills while the vault closes.
        complete(completion)
        vault?.lock()
    }
}
