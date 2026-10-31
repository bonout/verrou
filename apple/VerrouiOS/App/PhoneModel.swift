import AuthenticationServices
import BackgroundTasks
import Observation
import SwiftUI
import UIKit

/// The iPhone app's state: account, locking, navigation, writes.
///
/// Same principle as on the Mac: the item summaries (titles, displayed
/// usernames, sites) arrive once on unlock, then after each sync; each
/// search keystroke queries the Rust core, which returns positions in this
/// array. A secret only crosses the boundary when the user shows or copies
/// it. Opening the vault goes through `VaultAccess` (shared with the future
/// AutoFill extension).
@MainActor
@Observable
final class PhoneModel {
    enum LockState: Equatable {
        case locked
        case unlocking
        case unlocked
    }

    /// `demo`: demo vault (`VERROU_MOCK=1`, or *Try the Demo Vault* on the
    /// sign-in screen).
    enum Mode {
        case demo
        case vaultwarden
    }

    enum SyncState: Equatable {
        case idle
        case syncing
        /// Server unreachable: the vault shown is the cache.
        case offline
        case failed(String)
    }

    enum Tab: Hashable {
        case vault
        case generator
        case settings
        /// Search across the whole vault (separate tab, "search" role).
        case search
    }

    /// Screens stacked in the Vault tab.
    enum Route: Hashable {
        case list(SidebarFilter)
        case item(String)
        case audit
        /// A shared vault: its collections, its members, its groups.
        case organization(String)
        case members(String)
        case groups(String)
        /// Sends (Bitwarden Send).
        case sends
    }

    struct Editor: Identifiable {
        let id = UUID()
        /// `nil`: creation.
        let itemID: String?
        let draft: ItemDraft
        /// Direct creation in a shared collection.
        var destination: SharedDestination?
        let original: ItemDraft
        let originalDestination: SharedDestination?

        init(itemID: String?, draft: ItemDraft, destination: SharedDestination? = nil) {
            self.init(itemID: itemID, draft: draft, destination: destination, original: draft,
                      originalDestination: destination)
        }

        private init(itemID: String?, draft: ItemDraft, destination: SharedDestination?, original: ItemDraft,
                     originalDestination: SharedDestination?) {
            self.itemID = itemID
            self.draft = draft
            self.destination = destination
            self.original = original
            self.originalDestination = originalDestination
        }

        func resumed(_ progress: EditorProgress?) -> Editor {
            guard let progress, progress.editorID == id else {
                return Editor(itemID: itemID, draft: draft, destination: destination, original: original,
                              originalDestination: originalDestination)
            }
            return Editor(itemID: itemID, draft: progress.draft, destination: progress.destination, original: original,
                          originalDestination: originalDestination)
        }
    }

    struct EditorProgress {
        let editorID: UUID
        var draft: ItemDraft
        var destination: SharedDestination?
    }

    struct UndoAction {
        let toastID: UUID
        let perform: @MainActor () async -> Void
    }

    /// Master password prompt for a protected item, when Face ID is not
    /// available or the user dismissed it.
    struct RepromptRequest: Identifiable {
        let id = UUID()
        let itemID: String
        let title: String
        fileprivate let answer: (Bool) -> Void
    }

    /// QR code of a Wi-Fi network shown.
    struct QRSheet: Identifiable {
        let id = UUID()
        let title: String
        let image: CGImage
    }

    /// Decrypted file to share (attachment).
    struct SharedFile: Identifiable {
        let id = UUID()
        let url: URL
    }

    /// "Move to folder" open for these items.
    struct MoveRequest: Identifiable {
        let id = UUID()
        let itemIDs: [String]
    }

    private(set) var mode: Mode
    private(set) var vault: VaultAccess
    /// Demo vault opened from the sign-in screen: the account's vault, set
    /// aside until the demo is left (on lock).
    @ObservationIgnored private var signInVault: VaultAccess?
    var isTryingDemo: Bool { signInVault != nil }
    var session: VaultSession { vault.session }
    var dataDirectory: URL { vault.directory }

    private(set) var lockState: LockState = .locked
    private(set) var account: AccountInfo?
    private(set) var summaries: [ItemSummary] = []
    @ObservationIgnored private var summaryIndex: [String: Int] = [:]
    private(set) var counts: SidebarCounts?
    /// Folders nested by name, counted with their subfolders (home screen,
    /// folder screens).
    var folderTree: [FolderNode] {
        FolderNode.tree((counts?.folders ?? []).map { ($0.name, $0.count) })
    }
    private(set) var organizations: [OrganizationView] = []
    private(set) var folders: [FolderOption] = []
    private(set) var syncState: SyncState = .idle
    /// Changes made offline that are waiting for the server.
    private(set) var pendingChanges = 0
    private(set) var biometricEnrolled = false
    /// Changes on each vault reload: the lists are recomputed.
    private(set) var revision = 0
    var unlockError: String?

    // Sign-in
    /// `nil`: credentials step; otherwise the second factor methods.
    private(set) var twoFactorOptions: [TwoFactorOption]?
    private(set) var loginBusy = false
    var loginError: String?
    var loginServer = "https://"
    var loginEmail = ""
    /// The session has expired: signing in again is needed.
    private(set) var reloginRequired = false

    // Navigation and sheets
    var tab: Tab = .vault {
        didSet {
            if tab == .search, oldValue != .search { searchChosenAt = .now }
        }
    }
    /// Choosing the Search tab: measures the delay until the keyboard.
    @ObservationIgnored var searchChosenAt: ContinuousClock.Instant?
    var vaultPath: [Route] = [] {
        didSet { forgetClosedItems() }
    }
    /// Screens stacked in the Settings tab.
    var settingsPath: [SettingsRoute] = []
    enum SettingsRoute: Hashable {
        /// Sorting, list on unlock, match rules.
        case filling
    }
    /// Screens stacked in the Search tab.
    var searchPath: [Route] = [] {
        didSet { forgetClosedItems() }
    }
    /// Search across the whole vault (Search tab).
    var searchQuery = ""
    /// Copies made: each one triggers a haptic (`sensoryFeedback`).
    private(set) var copies = 0
    var editor: Editor?
    var editorBusy = false
    var editorError: String?
    @ObservationIgnored var editorProgress: EditorProgress?
    @ObservationIgnored private var suspendedEditor: Editor?
    var toast: Toast?
    var undo: UndoAction?
    var reprompt: RepromptRequest?
    var qrSheet: QRSheet?
    /// Reading a two-factor authentication QR code (sheet open).
    var otpScan: OTPScanFlow?
    /// Scanned account to carry over into the open edit screen.
    var otpFormFill: OTPFormFill?
    #if DEBUG
    /// End-to-end driver: saves the open edit screen, like the "Create"
    /// button (the view's draft included).
    var e2eSaveEditor = 0
    #endif
    var moveRequest: MoveRequest?
    /// "Remove from sharing…" awaiting confirmation.
    var unshareRequest: UnshareRequest?
    /// Removal from sharing in progress.
    var unshareBusy = false
    /// Order of the lists, kept on this iPhone.
    var sortOrder: ResultOrder = DevicePreferences.sort {
        didSet { DevicePreferences.sort = sortOrder }
    }
    /// List opened on unlock, kept on this iPhone.
    var defaultFilter: DefaultFilter = DevicePreferences.defaultFilter {
        didSet { DevicePreferences.defaultFilter = defaultFilter }
    }
    /// This iPhone's match rules and the account's equivalent domains.
    var matchSettings: MatchSettingsView?
    var aliasSettings: EmailAliasSettings?
    /// Decrypted attachment shown by Quick Look (temporary file).
    var preview: URL? {
        didSet { if let oldValue, oldValue != preview { Attachments.discard(oldValue) } }
    }
    var sharedFile: SharedFile?
    /// Loaded attachments, per item.
    private(set) var attachments: [String: [AttachmentEntry]] = [:]
    /// Download or upload in progress.
    private(set) var attachmentActivity: String?

    /// Revealed fields, per item; erased when leaving the item page and on
    /// lock.
    private(set) var revealed: [String: [String: String]] = [:]

    // Audit
    private(set) var audit: AuditReport?
    private(set) var breaches: [BreachedPassword]?
    private(set) var checkingBreaches = false
    var breachError: String?
    /// "Passkey possible" (`PasskeyUpgrade.swift`).
    let passkeyAudit = PhonePasskeyAudit()

    let clipboard = Clipboard()
    let siteIcons = SiteIcons()
    /// Sharing with other accounts (organizations, collections, members).
    let sharing = PhoneSharingModel()
    /// Approving the Mac's requests (`RemoteApprover`): independent of this
    /// iPhone's vault.
    let remote = RemoteApprover()

    @ObservationIgnored private var syncLoop: Task<Void, Never>?
    /// Live updates from the server, in the foreground.
    @ObservationIgnored let live = LiveUpdates()
    /// Notification tapped with the vault locked: opened after the unlock.
    @ObservationIgnored var pendingActivityRoute: ActivityRoute?
    /// `otpauth://` link opened with the vault locked: read after the unlock,
    /// if it is still recent (`OTPScanFlow.openLink`).
    @ObservationIgnored var pendingOTPLink: (text: String, at: Date)?
    /// Widget, control or Shortcut destination given with the vault
    /// locked: taken after the unlock, if it is still recent
    /// (`AppLinks.swift`).
    @ObservationIgnored var pendingLink: (link: VerrouLink, at: Date)?
    /// Items whose code is pinned for the widgets (`PinnedCodes`), as read
    /// at the last unlock or sync (`PinnedCodesSync.swift`).
    var pinnedCodeIDs: Set<String> = []
    /// Hands the pinned codes to the Apple Watch (`WatchSync.swift`).
    @ObservationIgnored let watchSync = WatchSync()
    /// The next sync is the first after the unlock: we measure the longest
    /// main thread stall while it runs.
    @ObservationIgnored private var watchFirstSync = false
    /// Syncs finished since launch (measurements).
    @ObservationIgnored private(set) var syncsFinished = 0
    @ObservationIgnored private var identitiesTask: Task<Void, Never>?
    /// Verrou is chosen as the AutoFill provider (`nil`: not asked of the
    /// system yet).
    private(set) var autofillEnabled: Bool?
    /// Syncs in progress (the Rust core batches them): the last one to
    /// finish gives the state shown.
    @ObservationIgnored private var syncsInFlight = 0
    /// List reloads: a read done off the main thread doesn't overwrite a
    /// more recent local write.
    @ObservationIgnored private var reloads = 0
    @ObservationIgnored private var backgroundedAt: Date?
    @ObservationIgnored private var lastBiometricPrompt: Date?
    /// The last Face ID prompt was interrupted by the system.
    @ObservationIgnored private var interruptedPrompt = false
    /// Face ID requested on its own on the lock screen (not during scripted
    /// runs).
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
        // End-to-end run: a throwaway account, never the real one.
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
        // Shortcuts and Siri look up the vault's items here, while it is open.
        IntentVault.model = self
        watchSync.activate(sendsCodes: mode == .vaultwarden)
        Perf.mark("model ready at +\(Perf.msSinceLaunch) ms from launch")
    }

    /// No account on this iPhone, or session expired: sign-in screen.
    var needsLogin: Bool {
        mode == .vaultwarden && (account == nil || reloginRequired)
    }

    var canUseBiometrics: Bool {
        mode == .demo ? Biometrics.isAvailable : biometricEnrolled && Biometrics.isAvailable
    }

    var canEdit: Bool { (mode == .vaultwarden || showcase) && lockState == .unlocked }

    /// Showcase (Debug builds, `VERROU_SHOWCASE=1`): on the demo vault, the
    /// edit buttons are shown for screenshots.
    @ObservationIgnored let showcase: Bool

    // MARK: Settings

    /// Lock delay once the app is in the background, in seconds; 0: right
    /// away; -1: never (only when the app is closed).
    var autoLockSeconds: Int {
        get { access(keyPath: \.autoLockSeconds); return UserDefaults.standard.object(forKey: "autoLockSeconds") as? Int ?? 60 }
        set { withMutation(keyPath: \.autoLockSeconds) { UserDefaults.standard.set(newValue, forKey: "autoLockSeconds") } }
    }

    /// Lifetime of a secret copied to the clipboard, in seconds.
    var clipboardSeconds: Int {
        get { access(keyPath: \.clipboardSeconds); return UserDefaults.standard.object(forKey: "clipboardSeconds") as? Int ?? 90 }
        set { withMutation(keyPath: \.clipboardSeconds) { UserDefaults.standard.set(newValue, forKey: "clipboardSeconds") } }
    }

    /// Offer Face ID after an unlock with the password.
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

    /// Site icons, requested from the account's server.
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

    // MARK: Sign-in

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

    /// Security key (FIDO2): the server's sign-in page, in an ephemeral
    /// Safari session; the YubiKey answers over NFC or USB-C.
    func useSecurityKey(challenge: String) async {
        guard !loginBusy else { return }
        loginError = nil
        do {
            let token = try await SecurityKeySignIn().sign(server: normalizedServer, challenge: challenge)
            await answerTwoFactor(.securityKey(challenge: challenge), token: token)
        } catch SecurityKeySignIn.Failure.cancelled {
            // Sheet closed: nothing to say.
        } catch {
            loginError = ErrorText.describe(error)
        }
        if loginError != nil, twoFactorOptions != nil {
            // The server only allows one attempt per challenge: we ask for another.
            if case .twoFactorRequired(let options)? = try? await session.restartTwoFactor() {
                twoFactorOptions = options
            }
        }
    }

    func sendEmailCode() async {
        do {
            try await session.sendEmailCode()
            toast = Toast(message: String(localized: "Code sent"), detail: String(localized: "Check your inbox"))
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
            let previous = account
            account = session.account()
            if previous?.email != account?.email || previous?.server != account?.server { suspendedEditor = nil }
            // Signing in again changes the vault key: the old Face ID is no longer valid.
            vault.removeBiometrics()
            biometricEnrolled = false
            didUnlock(failures: failures)
            await enrollBiometricsIfWanted()
        }
    }

    /// Session expired, but we still want to look at the cache.
    func continueOffline() {
        reloginRequired = false
        loginError = nil
    }

    /// Forgets the account: cache, offline queue, Face ID. The server keeps everything.
    func logout() {
        lock()
        suspendedEditor = nil
        identitiesTask?.cancel()
        Task { await CredentialIdentities.clear() }
        // The codes pinned for the widgets leave with the account.
        unpinAllCodes()
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

    // MARK: Locking

    /// Lock screen shown or app back in the foreground: Face ID directly,
    /// without going through the button.
    ///
    /// At launch, the lock screen appears before the app is active (up to
    /// 300 ms earlier): Face ID is requested right then; if the system
    /// interrupts it, it is requested again on activation.
    func promptBiometricsIfPossible() async {
        guard autoFaceID, mode == .vaultwarden, canUseBiometrics, lockState == .locked, !needsLogin,
              UIApplication.shared.applicationState != .background else { return }
        if let last = lastBiometricPrompt, Date().timeIntervalSince(last) < 3 { return }
        // Opened for a request of the Mac: its Face ID is the only one.
        guard await remote.allowsVaultPrompt(), lockState == .locked else { return }
        await unlockWithBiometrics()
    }

    /// Face ID recognized, vault being decrypted: the lock screen already
    /// opens (the empty vault is built underneath), without waiting.
    private(set) var opening = false
    /// Face ID requested by the app: the inactivity that follows comes from
    /// the system sheet, not the app switcher. Cleared on return to the
    /// foreground (or in the background).
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
            switch await Biometrics.authenticate(reason: String(localized: "unlock your vault")) {
            case .success: openMockVault()
            case .fallback: lockState = .locked
            case .failure(let message):
                unlockError = message.isEmpty ? nil : message
                lockState = .locked
            }
            return
        }
        do {
            let failures = try await Perf.measure("\(Biometrics.name) + vault decryption") {
                try await vault.unlockWithBiometrics(reason: String(localized: "unlock your vault")) { [weak self] in
                    self?.opening = true
                }
            }
            didUnlock(failures: failures)
        } catch BiometricVault.Failure.cancelled {
            lockState = .locked
        } catch BiometricVault.Failure.interrupted {
            // Not a refusal: asked again at the next activation, without delay.
            lockState = .locked
            interruptedPrompt = true
        } catch BiometricVault.Failure.unavailable {
            unlockError = String(localized: "\(Biometrics.name) is not available: enter your master password.")
            lockState = .locked
        } catch {
            // Faces or fingerprints changed, or stale key: back to the password.
            vault.removeBiometrics()
            biometricEnrolled = false
            unlockError = String(localized: "\(Biometrics.name) needs to be turned on again: enter your master password.")
            lockState = .locked
        }
    }

    func unlock(masterPassword: String) async {
        guard !masterPassword.isEmpty else {
            unlockError = String(localized: "Enter your master password.")
            return
        }
        if mode == .demo {
            openMockVault()
            return
        }
        lockState = .unlocking
        unlockError = nil
        do {
            let failures = try await Perf.measure("password unlock") {
                try await vault.unlock(masterPassword: masterPassword)
            }
            Perf.unlockSucceeded("the password")
            didUnlock(failures: failures)
            await enrollBiometricsIfWanted()
        } catch {
            unlockError = ErrorText.describe(error)
            lockState = .locked
        }
    }

    /// Demo vault (demonstration).
    func openMockVault() {
        session.unlockMock(size: mockSize, seed: 42, language: .current)
        Perf.unlockSucceeded("opening the demo vault")
        didUnlock(failures: 0)
    }

    /// Sign-in screen, no account on this iPhone: opens the demo vault in
    /// memory (nothing written, no server). Locking goes back to sign-in.
    func tryDemo() {
        guard mode == .vaultwarden, account == nil, lockState == .locked else { return }
        signInVault = vault
        vault = VaultAccess(mockAt: vault.location)
        mode = .demo
        loginError = nil
        openMockVault()
    }

    private func didUnlock(failures: UInt32) {
        reloadVault()
        // The list chosen in the settings opens by itself.
        if defaultFilter != .all, vaultPath.isEmpty, !showcase {
            vaultPath = [.list(defaultFilter.filter)]
        }
        lockState = .unlocked
        updateSiteIcons()
        if let suspended = suspendedEditor {
            suspendedEditor = nil
            if canEdit { editor = suspended }
        }
        if failures > 0 {
            toast = Toast(message: failures > 1 ? String(localized: "\(failures) unreadable items") : String(localized: "\(failures) unreadable item"),
                          detail: String(localized: "The Bitwarden SDK could not decrypt them"), failure: true)
        }
        watchFirstSync = true
        startSyncLoop()
        if let route = pendingActivityRoute {
            pendingActivityRoute = nil
            openActivity(route)
        }
        if let link = pendingOTPLink {
            pendingOTPLink = nil
            if Date().timeIntervalSince(link.at) < OTPScanFlow.linkLifetime { openOTPLink(link.text) }
        }
        if let pending = pendingLink {
            pendingLink = nil
            if Date().timeIntervalSince(pending.at) < Self.pendingLinkLifetime { open(pending.link) }
        }
    }

    func lock(clearsClipboard: Bool = true) {
        // AutoFill without Face ID ends with the app's lock.
        AutofillSession.forget()
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
        if let editor { suspendedEditor = editor.resumed(editorProgress) }
        editor = nil
        editorProgress = nil
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
        undo = nil
        vaultPath = []
        searchPath = []
        searchQuery = ""
        Attachments.purge()
        if clearsClipboard { clipboard.clearIfOurs() }
        lockState = .locked
        revision += 1
        if let signInVault {
            vault = signInVault
            self.signInVault = nil
            suspendedEditor = nil
            mode = .vaultwarden
            tab = .vault
        }
        updateSiteIcons()
    }

    // MARK: Foreground, background

    /// Auto-lock and sync on return to the foreground.
    func scenePhaseChanged(to phase: ScenePhase) {
        Perf.mark("scene \(String(describing: phase)) at +\(Perf.msSinceLaunch) ms from launch (\(String(describing: lockState)))")
        // At launch, the scene becomes active right after the prompt, before
        // the Face ID sheet: we only clear it once the prompt is closed.
        if phase == .background || (phase == .active && lockState != .unlocking) { biometricPrompt = false }
        switch phase {
        case .background:
            backgroundedAt = Date()
            syncLoop?.cancel()
            syncLoop = nil
            live.stop(session: session)
            if lockState == .unlocked, autoLockSeconds == 0 { lock(clearsClipboard: false) }
            scheduleBackgroundCheck()
        case .active:
            // Back from the background (not from a mere inactive state): the
            // network is woken up during Face ID or before the sync.
            if backgroundedAt != nil, mode == .vaultwarden, let server = account?.server {
                NetworkWake.nudge(server: server)
            }
            if let since = backgroundedAt, lockState == .unlocked, autoLockSeconds > 0,
               Date().timeIntervalSince(since) >= TimeInterval(autoLockSeconds) {
                lock(clearsClipboard: false)
            }
            backgroundedAt = nil
            Biometrics.refresh()
            if lockState == .unlocked {
                // Back from the background: the loop had been stopped. Mere
                // return from the inactive state (Face ID, Control Center):
                // it is still running, and restarting it would double the
                // unlock sync.
                if syncLoop == nil { startSyncLoop() }
                Task { await refreshAutofillStatus() }
            } else {
                Task { await promptBiometricsIfPossible() }
            }
        default:
            break
        }
    }

    // MARK: Sync

    /// Syncs right away, then every 5 minutes while the app is in the
    /// foreground (30 s if changes are waiting for the server).
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
        // In the foreground, the live updates channel: a share or a
        // confirmation arrives within a few seconds.
        live.start(session: session) { [weak self] in
            await self?.syncNow()
        } expired: { [weak self] in
            guard let self, self.lockState == .unlocked else { return }
            self.reloginRequired = true
            self.lock()
        }
    }

    // MARK: Background: sharing news

    /// Identifier of the background task (Info.plist,
    /// `BGTaskSchedulerPermittedIdentifiers`).
    static let activityTaskID = "app.verrou.activite"

    /// Asks iOS for a wake-up in 30 minutes at the earliest (iOS picks the
    /// moment, or doesn't wake the app at all).
    func scheduleBackgroundCheck() {
        guard mode == .vaultwarden, account != nil, ActivityNotifier.enabled, !ActivityNotifier.shared.silent else {
            return
        }
        let request = BGAppRefreshTaskRequest(identifier: Self.activityTaskID)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 30 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    /// Background wake-up (`BGAppRefreshTask`): a light check, which decrypts
    /// nothing and keeps no key longer than planned.
    /// - Lock delay exceeded: we lock first (the key has nothing more to do
    ///   in memory).
    /// - Vault still open (within the delay): sync and check as in the
    ///   foreground, with the key already in memory.
    /// - Locked: only the already downloaded cache, without key or network
    ///   (the refresh token is encrypted with the user's key); see
    ///   SECURITY.md.
    func backgroundActivityCheck() async {
        scheduleBackgroundCheck()
        guard mode == .vaultwarden, account != nil, ActivityNotifier.enabled else { return }
        if lockState == .unlocked, let since = backgroundedAt, autoLockSeconds > 0,
           Date().timeIntervalSince(since) >= TimeInterval(autoLockSeconds) {
            lock(clearsClipboard: false)
        }
        if lockState == .unlocked {
            await syncNow(awaitActivity: true)
        } else {
            ActivityNotifier.shared.post(session.checkActivityLocked())
        }
    }

    /// Sends in the background what was just written (see `outbox.rs`),
    /// then syncs: the interface doesn't wait for the server.
    func pushChanges() {
        guard mode == .vaultwarden else { return }
        Task { await syncNow(afterWrite: true) }
    }

    /// `afterWrite`: right after a local write; offline a moment ago, the
    /// core doesn't retry right away (the periodic sync takes care of it).
    /// Simultaneous requests are batched by the Rust core.
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
                Perf.mark("longest main thread stall during the first sync: \(watch.stop()) ms")
            }
        }
        do {
            let outcome = try await Perf.measure("sync") {
                try await afterWrite ? session.pushChanges() : session.sync()
            }
            guard lockState == .unlocked else { return }
            account = session.account()
            // Pending invitations and members to confirm: at each periodic
            // sync (not after each write). In the background, the check is
            // awaited: iOS may suspend the app as soon as the task ends.
            if awaitActivity {
                await refreshSharingStatus()
            } else if !afterWrite {
                Task { await self.refreshSharingStatus() }
                Task { await self.finishPendingPasskeys() }
            }
            guard outcome.changed else { return }
            await reloadVaultAfterSync()
            if outcome.failures > 0 { result = .failed(String(localized: "\(outcome.failures) unreadable item(s)")) }
        } catch VerrouError.Locked {
            result = .idle
        } catch VerrouError.SessionExpired {
            result = .failed(String(localized: "Session expired"))
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
        return pendingChanges == 1 ? String(localized: "1 pending change") : String(localized: "\(pendingChanges) pending changes")
    }

    /// Toast for a write, as soon as it is done (sending follows in the
    /// background); offline, it waits for the server.
    private func writeToast(_ message: String, detail: String? = nil) -> Toast {
        guard syncState == .offline else { return Toast(message: message, detail: detail) }
        return Toast(message: message, detail: String(localized: "Offline: synced as soon as the server responds"))
    }

    /// Report of the sent offline changes: conflicts and refusals first,
    /// then the successes.
    func showSyncReport() async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        let report = await session.takeSyncReport()
        if !report.conflicts.isEmpty {
            let count = report.conflicts.count
            toast = Toast(message: count == 1 ? String(localized: "Conflict: local version kept as a copy")
                                              : String(localized: "\(count) conflicts: local versions kept as copies"),
                          detail: report.conflicts.map { String(localized: "“\($0)”") }.joined(separator: ", "), failure: true, seconds: 4)
        } else if !report.rejected.isEmpty {
            // Removed from the queue: the vault shown is back to the server's version.
            toast = Toast(message: report.rejected.count == 1 ? String(localized: "Change refused by the server, cancelled")
                                                              : String(localized: "\(report.rejected.count) changes refused by the server, cancelled"),
                          detail: report.rejected.joined(separator: "\n"), failure: true, seconds: 6)
        } else if report.sent > 0 {
            toast = Toast(message: report.sent == 1 ? String(localized: "Offline change synced")
                                                    : String(localized: "\(report.sent) offline changes synced"), detail: nil)
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
            Perf.log.error("\(Biometrics.name, privacy: .public) enrollment failed: \(String(describing: error), privacy: .public)")
            #if DEBUG
            print("E2E_INFO Face ID enrollment failed: \(error)")
            #endif
            biometricEnrolled = false
        }
    }

    // MARK: Vault

    /// Summaries, counters and shared vaults read in one go (off the main
    /// thread after a sync).
    private struct LoadedVault: @unchecked Sendable {
        let summaries: [ItemSummary]
        let counts: SidebarCounts?
        let organizations: [OrganizationView]
        let folders: [FolderOption]
    }

    /// Reloads the list from the local vault (after a write: it is already
    /// up to date, without waiting for the server).
    private func reloadVault(_ loaded: LoadedVault? = nil) {
        reloads += 1
        let start = ContinuousClock.now
        summaries = loaded?.summaries ?? (try? session.summaries()) ?? []
        summaryIndex = Dictionary(summaries.enumerated().map { ($1.id, $0) }, uniquingKeysWith: { first, _ in first })
        counts = loaded.map(\.counts) ?? (try? session.counts())
        organizations = loaded?.organizations ?? session.organizations()
        folders = loaded?.folders ?? session.folders()
        matchSettings = session.matchSettings()
        aliasSettings = session.emailAliasSettings()
        if let known = breaches { breaches = session.stillBreached(breaches: known) }
        if audit != nil {
            audit = try? session.audit()
            refreshPasskeyAudit()
        }
        refreshPending()
        // A created item received its ID from the server: the open item page
        // follows; an item that disappeared (write refused, cancelled) closes it.
        vaultPath = resolved(vaultPath)
        searchPath = resolved(searchPath)
        revision += 1
        publishAutofillIdentities()
        refreshPinnedCodes()
        Perf.mark("list reload (\(self.summaries.count) items): \(Perf.ms(since: start)) ms")
    }

    private func resolved(_ path: [Route]) -> [Route] {
        path.compactMap { route in
            guard case .item(let id) = route else { return route }
            let resolved = session.resolveItemId(id: id)
            return summaryIndex[resolved] == nil ? nil : .item(resolved)
        }
    }

    // MARK: AutoFill

    /// Sites, user names and passkeys for the system's suggestions (never a
    /// secret), a moment after the last change.
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

    /// Asks the system whether Verrou is chosen (Settings), and republishes.
    func refreshAutofillStatus() async {
        autofillEnabled = await CredentialIdentities.isEnabled()
        if autofillEnabled == true { publishAutofillIdentities() }
    }

    /// Opens the settings page where to choose Verrou (iOS 18), otherwise the
    /// app's settings.
    func openAutofillSettings() {
        if #available(iOS 18.0, *) {
            Task { try? await ASSettingsHelper.openCredentialProviderAppSettings() }
        } else if let url = URL(string: UIApplication.openSettingsURLString) {
            UIApplication.shared.open(url)
        }
    }

    /// After a sync: reading is done off the main thread, then everything is
    /// published at once; a more recent local write wins.
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

    /// Search results (Rust core, a few milliseconds).
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

    /// Opens an item's page in the Vault tab.
    func open(_ itemID: String) {
        tab = .vault
        vaultPath.append(.item(itemID))
    }

    /// An item page that is no longer in any stack loses its revealed
    /// secrets, without waiting for the end of the animation (nor relying on `onDisappear`).
    private func forgetClosedItems() {
        guard !revealed.isEmpty else { return }
        var open = Set<String>()
        for case .item(let id) in vaultPath + searchPath { open.insert(id) }
        for id in revealed.keys where !open.contains(id) { revealed[id] = nil }
    }

    /// The item page is left: its revealed secrets are forgotten.
    func forgetRevealed(of itemID: String) {
        revealed[itemID] = nil
    }

    func canModify(_ summary: ItemSummary?) -> Bool {
        canEdit && summary?.sharing?.readOnly != true
    }

    var writableOrganizations: [OrganizationView] {
        organizations.filter(\.writable)
    }

    // MARK: Protected items

    /// Protected item not confirmed yet: asks for confirmation, then replays
    /// `retry`. Returns `true` if the action must wait.
    func awaitsConfirmation(_ itemID: String, retry: @escaping @MainActor () -> Void) -> Bool {
        guard session.needsConfirmation(id: itemID) else { return false }
        let title = summary(id: itemID)?.title ?? String(localized: "this item")
        Task {
            if await confirmAccess(itemID: itemID, title: title) { retry() }
        }
        return true
    }

    /// Face ID, otherwise the master password; the confirmation lasts 5
    /// minutes for this item (on the Rust side, erased on lock).
    func confirmAccess(itemID: String, title: String) async -> Bool {
        guard mode == .vaultwarden else {
            session.authorizeItem(id: itemID)
            return true
        }
        if Biometrics.isAvailable {
            switch await Biometrics.authenticate(reason: String(localized: "show “\(title)”")) {
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

    /// Answer to the master password prompt (`nil`: cancelled).
    func answerReprompt(password: String?) async {
        guard let request = reprompt else { return }
        reprompt = nil
        guard let password, !password.isEmpty else {
            request.answer(false)
            return
        }
        do {
            guard try await session.verifyMasterPassword(password: password) else {
                toast = Toast(message: String(localized: "Incorrect master password"), detail: nil, failure: true)
                request.answer(false)
                return
            }
            session.authorizeItem(id: request.itemID)
            request.answer(true)
        } catch {
                toast = Toast(message: String(localized: "Could not confirm"), detail: ErrorText.describe(error), failure: true)
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

    /// Current one-time code, if it is accessible without confirmation.
    func totpCode(of itemID: String, at date: Date = Date()) -> TotpView? {
        vault.currentCode(of: itemID, at: date)
    }

    func copyCode(of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyCode(of: itemID) }) { return }
        guard let code = totpCode(of: itemID) else { return }
        session.recordItemUse(id: itemID)
        copy(code.code, label: String(localized: "Code"), secret: true)
    }

    func copy(_ value: String, label: String, secret: Bool) {
        let seconds = secret ? clipboardSeconds : 0
        clipboard.copy(value, expiresIn: seconds > 0 ? TimeInterval(seconds) : nil)
        copies += 1
        // No animation here: the notification animates its own arrival
        // (ToastHost), without dragging the model's other views along.
        toast = Toast(message: String(localized: "\(label) copied"),
                      detail: secret && seconds > 0 ? String(localized: "Cleared from the clipboard in \(Self.durationLabel(seconds))") : nil)
    }

    func copyField(_ field: FieldView, of itemID: String) {
        if field.fieldType == .totp {
            copyCode(of: itemID)
            return
        }
        if field.hidden {
            toast = Toast(message: String(localized: "Hidden field"), detail: String(localized: "The organization hides it from your account"), failure: true)
            return
        }
        if field.secret,
           awaitsConfirmation(itemID, retry: { [weak self] in self?.copyField(field, of: itemID) }) { return }
        let value = field.secret ? reveal(field.id, of: itemID) : field.value
        guard let value else { return }
        // The card number is copied without spaces: that's what forms expect.
        let copied = field.fieldType == .cardNumber ? value.replacingOccurrences(of: " ", with: "") : value
        // A revealed secret is already recorded by the core; a plain field, here.
        if !field.secret { session.recordItemUse(id: itemID) }
        copy(copied, label: field.label, secret: field.secret)
    }

    func copyUsername(of itemID: String) {
        guard let field = detail(id: itemID)?.displayFields.first(where: { $0.fieldType == .username || $0.id == "username" }) else { return }
        copyField(field, of: itemID)
    }

    func copyPassword(of itemID: String) {
        if summary(id: itemID)?.sharing?.hidePasswords == true {
            toast = Toast(message: String(localized: "Hidden password"), detail: String(localized: "The organization hides it from your account"), failure: true)
            return
        }
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyPassword(of: itemID) }) { return }
        guard let value = try? session.reveal(id: itemID, fieldId: "password") else { return }
        copy(value, label: String(localized: "Password"), secret: true)
    }

    /// QR code of a Wi-Fi network: the password goes through the same
    /// confirmation as the other secrets, and only the image remains.
    func showWifiQRCode(of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.showWifiQRCode(of: itemID) }) { return }
        guard let payload = try? session.wifiQrCode(id: itemID), let image = QRCode.cgImage(payload) else {
            toast = Toast(message: String(localized: "Could not create QR code"), detail: nil, failure: true)
            return
        }
        qrSheet = QRSheet(title: summary(id: itemID)?.title ?? "Wi-Fi", image: image)
    }

    static func durationLabel(_ seconds: Int) -> String {
        Duration.seconds(seconds).formatted(.units(allowed: [.hours, .minutes, .seconds], width: .abbreviated))
    }

    // MARK: Editing

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
                              login: LoginFields(username: nil, password: Self.generatedWithSavedSettings(),
                                                 totp: nil, urls: [""]),
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

    static func generatedWithSavedSettings() -> String {
        let defaults = UserDefaults.standard
        let mode = defaults.string(forKey: "generatorMode").flatMap(GeneratorMode.init(rawValue:)) ?? .password
        switch mode {
        case .password:
            let length = defaults.object(forKey: "generatorLength") as? Double ?? 20
            return generatePassword(length: UInt32(length), digits: defaults.object(forKey: "generatorDigits") as? Bool ?? true,
                                    symbols: defaults.object(forKey: "generatorSymbols") as? Bool ?? true)
        case .passphrase:
            let words = defaults.object(forKey: "generatorWords") as? Double ?? 5
            let separator = defaults.string(forKey: "generatorSeparator").flatMap(PassphraseSeparatorChoice.init(rawValue:))
                ?? .hyphen
            let language = defaults.string(forKey: "generatorLanguage").flatMap(PassphraseLanguageChoice.init(rawValue:))
                ?? .preferred
            return generatePassphrase(settings: PassphraseSettings(
                words: UInt32(words), separator: separator.ffi,
                capitalize: defaults.object(forKey: "generatorCapitalize") as? Bool ?? false,
                includeNumber: defaults.object(forKey: "generatorNumber") as? Bool ?? false,
                language: language.ffi)).value
        }
    }

    func edit(_ itemID: String) async {
        guard canEdit else { return }
        if session.needsConfirmation(id: itemID) {
            guard await confirmAccess(itemID: itemID, title: summary(id: itemID)?.title ?? String(localized: "this item")) else { return }
        }
        editorError = nil
        do {
            editor = Editor(itemID: itemID, draft: try await session.editDraft(id: itemID))
        } catch {
            toast = Toast(message: String(localized: "Could not edit"), detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Saves the edit screen; returns `true` if it can close.
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
            // Written locally: the sheet closes right away, sending follows.
            self.editor = nil
            afterWrite()
            if editor.itemID == nil { open(session.resolveItemId(id: id)) }
            toast = writeToast(editor.itemID == nil ? String(localized: "Item created") : String(localized: "Saved"))
            pushChanges()
            return true
        } catch VerrouError.Conflict {
            editorError = String(localized: "The item changed elsewhere in the meantime. Verrou just reloaded it: reopen it to redo the change.")
            await syncNow()
        } catch {
            editorError = ErrorText.describe(error)
        }
        return false
    }

    func trash(_ itemID: String) async {
        await perform(String(localized: "Moved to the trash"), detail: String(localized: "Can be restored from the trash")) {
            try await self.session.trashItem(id: itemID)
        }
        editor = nil
        vaultPath.removeAll { $0 == .item(itemID) }
    }

    func restore(_ itemID: String) async {
        await perform(String(localized: "Restored")) { try await self.session.restoreItem(id: itemID) }
    }

    func setFavorite(_ itemID: String, _ favorite: Bool) async {
        await perform(favorite ? String(localized: "Added to favorites") : String(localized: "Removed from favorites")) {
            try await self.session.setFavorite(id: itemID, favorite: favorite)
        }
    }

    func setArchived(_ itemID: String, _ archived: Bool) async {
        await perform(archived ? String(localized: "Archived") : String(localized: "Unarchived"), detail: archived ? String(localized: "Find it in Archived items") : nil) {
            try await self.session.setArchived(id: itemID, archived: archived)
        }
    }

    func deletePasskey(itemID: String, credentialID: String) async {
        await perform(String(localized: "Passkey deleted")) {
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
            toast = Toast(message: String(localized: "Action failed"), detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Write applied to the local vault (sending follows, `pushChanges`):
    /// the list updates right away, the pending items carry their mark.
    func afterWrite() {
        guard lockState == .unlocked else { return }
        revealed = [:]
        reloadVault()
    }

    // MARK: Bulk actions

    /// Applies the action to the items, in one go (see `bulk.rs`).
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
            toast = Toast(message: String(localized: "Action failed"), detail: ErrorText.describe(error), failure: true)
        }
    }

    func moveToNewFolder(_ name: String, ids: [String]) async {
        guard canEdit, !editorBusy else { return }
        do {
            let folder = try await session.createFolder(name: name)
            await performBulk(.moveToFolder(folderId: folder), on: ids, folderName: name.trimmingCharacters(in: .whitespaces))
        } catch {
            toast = Toast(message: String(localized: "Could not create folder"), detail: ErrorText.describe(error), failure: true)
        }
    }

    private func bulkToast(_ result: BulkResult, action: BulkItemAction, folderName: String?) -> Toast {
        let n = Int(result.done)
        let plural = n > 1
        var message: String
        switch action {
        case .archive: message = plural ? String(localized: "\(n) items archived") : String(localized: "\(n) item archived")
        case .unarchive: message = plural ? String(localized: "\(n) items unarchived") : String(localized: "\(n) item unarchived")
        case .trash: message = plural ? String(localized: "\(n) items moved to the trash") : String(localized: "\(n) item moved to the trash")
        case .restore: message = plural ? String(localized: "\(n) items restored") : String(localized: "\(n) item restored")
        case .favorite(let favorite): message = favorite ? (plural ? String(localized: "\(n) items added to favorites") : String(localized: "\(n) item added to favorites")) : (plural ? String(localized: "\(n) items removed from favorites") : String(localized: "\(n) item removed from favorites"))
        case .moveToFolder(let folder):
            let name = folderName ?? folders.first { $0.id == folder }?.name ?? String(localized: "folder")
            message = folder == nil ? (plural ? String(localized: "\(n) items removed from their folder") : String(localized: "\(n) item removed from its folder")) : (plural ? String(localized: "\(n) items moved to “\(name)”") : String(localized: "\(n) item moved to “\(name)”"))
        }
        var ignored: [String] = []
        if result.readOnly > 0 { ignored.append(result.readOnly > 1 ? String(localized: "\(result.readOnly) skipped items (read-only)") : String(localized: "\(result.readOnly) skipped item (read-only)")) }
        if result.inTrash > 0 { ignored.append(result.inTrash > 1 ? String(localized: "\(result.inTrash) skipped items (in the trash)") : String(localized: "\(result.inTrash) skipped item (in the trash)")) }
        if result.notFound > 0 { ignored.append(result.notFound > 1 ? String(localized: "\(result.notFound) items not found") : String(localized: "\(result.notFound) item not found")) }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !result.failures.isEmpty {
            return Toast(message: message + ", " + (result.failures.count > 1 ? String(localized: "\(result.failures.count) refused items") : String(localized: "\(result.failures.count) refused item")),
                         detail: result.failures.joined(separator: "\n"), failure: true, seconds: 5)
        }
        let detail = result.queued > 0 && syncState == .offline ? String(localized: "Offline: synced as soon as the server responds") : nil
        return Toast(message: message, detail: detail, seconds: ignored.isEmpty ? 2.2 : 4)
    }

    // MARK: Attachments

    func loadAttachments(of itemID: String) async {
        let entries = (try? await session.attachments(itemId: itemID)) ?? []
        guard lockState == .unlocked else { return }
        attachments[itemID] = entries
    }

    /// Opens the attachment in Quick Look (downloaded and decrypted).
    func openAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.openAttachment(entry, of: itemID) }) { return }
        Task {
            guard let url = await decryptedFile(entry, of: itemID) else { return }
            preview = url
        }
    }

    /// Shares a decrypted copy (Files, AirDrop, another app).
    func shareAttachment(_ entry: AttachmentEntry, of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.shareAttachment(entry, of: itemID) }) { return }
        Task {
            guard let url = await decryptedFile(entry, of: itemID) else { return }
            sharedFile = SharedFile(url: url)
        }
    }

    private func decryptedFile(_ entry: AttachmentEntry, of itemID: String) async -> URL? {
        guard attachmentActivity == nil else { return nil }
        attachmentActivity = String(localized: "Downloading “\(entry.fileName)”…")
        defer { attachmentActivity = nil }
        do {
            let content = try await session.downloadAttachment(itemId: itemID, attachmentId: entry.id)
            guard lockState == .unlocked else { return nil }
            return try Attachments.temporaryFile(named: content.fileName, data: content.data)
        } catch {
            toast = Toast(message: String(localized: "Could not read attachment"), detail: ErrorText.describe(error), failure: true)
            return nil
        }
    }

    func addAttachment(from url: URL, to itemID: String) async {
        guard canEdit, attachmentActivity == nil else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            toast = Toast(message: String(localized: "Could not read file"), detail: url.lastPathComponent, failure: true)
            return
        }
        guard data.count <= Attachments.maxSize else {
            toast = Toast(message: String(localized: "File too large"), detail: String(localized: "100 MB at most"), failure: true)
            return
        }
        attachmentActivity = String(localized: "Uploading “\(url.lastPathComponent)”…")
        defer { attachmentActivity = nil }
        do {
            try await session.addAttachment(itemId: itemID, fileName: url.lastPathComponent, data: data)
            afterWrite()
            await loadAttachments(of: itemID)
            toast = Toast(message: String(localized: "Attachment added"), detail: url.lastPathComponent)
        } catch {
            toast = Toast(message: String(localized: "Could not upload"), detail: ErrorText.describe(error), failure: true)
        }
    }

    func deleteAttachment(_ entry: AttachmentEntry, of itemID: String) async {
        guard canEdit, attachmentActivity == nil else { return }
        attachmentActivity = String(localized: "Deleting…")
        defer { attachmentActivity = nil }
        do {
            try await session.deleteAttachment(itemId: itemID, attachmentId: entry.id)
            afterWrite()
            await loadAttachments(of: itemID)
            toast = Toast(message: String(localized: "Attachment deleted"), detail: entry.fileName)
        } catch {
            toast = Toast(message: String(localized: "Could not delete"), detail: ErrorText.describe(error), failure: true)
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

    /// Have I Been Pwned, by k-anonymity (5 hash characters per password).
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

/// Where to store a shared item: an organization and its collections.
struct SharedDestination: Equatable, Hashable {
    var organizationID: String
    var collectionIDs: [String]
}

/// The iPhone's bulk actions show no progress: one request per batch of
/// 500, the wait is short.
final class NoBulkProgress: BulkProgress, @unchecked Sendable {
    func progress(done: UInt32, total: UInt32) {}
}
