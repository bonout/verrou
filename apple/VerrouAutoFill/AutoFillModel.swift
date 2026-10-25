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
        /// Nothing (configuration).
        case none
    }

    /// A passkey request from the site (`prepareCredentialList(for:requestParameters:)`).
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

    /// The site's logins (or codes), from most to least specific.
    private(set) var matches: [ItemSummary] = []
    /// All the vault's items (search), once open.
    private(set) var everything: [ItemSummary] = []
    private(set) var passkeys: [AutofillPasskey] = []
    /// Passkey creation: the site's logins that can receive it.
    private(set) var targets: [ItemSummary] = []
    /// Passkey created: the sheet confirms (checkmark) before closing.
    private(set) var passkeyCreated = false

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
        default: "Verrou"
        }
    }

    /// The requested site, for the header.
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

    // MARK: Request

    func start(_ request: Request) {
        self.request = request
        if phase == .ready { load() }
    }

    // MARK: Unlocking

    /// Face ID right away if possible (the request comes from a user
    /// gesture). `appeared`: the sheet is on screen (`viewDidAppear`), no
    /// need to wait for it.
    func autoUnlock(appeared: Bool = false) async {
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
        case .oneTimeCodes(let services):
            matches = ((try? session.autofillMatches(services: services.map(\.identifier))) ?? []).filter(\.hasTotp)
            everything = everything.filter(\.hasTotp)
        case .register(let request):
            if let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity {
                targets = (try? session.autofillPasskeyTargets(rpId: identity.relyingPartyIdentifier)) ?? []
            }
        case .provide, .none:
            break
        }
    }

    /// Search results across the whole vault (Rust core).
    var searchResults: [ItemSummary] {
        guard let session = vault?.session, !query.isEmpty else { return [] }
        let filter: SidebarFilter = .category(category: .login)
        let hits = (try? session.search(query: query, filter: filter, order: .relevance)) ?? []
        let byID = Dictionary(everything.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return hits.prefix(50).compactMap { byID[$0.id] }
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
            let credential = try session.autofillPassword(id: id)
            // The next step of the form fills without Face ID; a protected
            // item asks again each time.
            if protectedItems.contains(id) {
                RecentFill.forget()
            } else {
                RecentFill.remember(itemID: id, user: credential.username, password: credential.password)
            }
            // Conditional creation (iOS 18): Safari may request, right after,
            // a passkey for this account, in the background with the vault
            // closed. The key is prepared now (see conditional.rs).
            if #available(iOS 18.0, *) {
                do {
                    _ = try await session.preparePasskeyUpgrade(id: id)
                } catch {
                    log.notice("passkey key not prepared: \(String(describing: error), privacy: .public)")
                }
            }
            finish(.password(user: credential.username, password: credential.password))
        } catch {
            actionError = ErrorText.describe(error)
        }
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
        vault?.lock()
        complete(completion)
    }
}
