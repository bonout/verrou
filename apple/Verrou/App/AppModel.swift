import AppKit
import LocalAuthentication
import Observation
import SwiftUI

/// Application state: account, locking, selection, search.
///
/// Item summaries (titles, displayed usernames, sites) are loaded once at
/// unlock, then after each sync. Each keystroke queries the Rust core, which
/// returns positions in this array: nothing else crosses the boundary, and
/// no secret.
@MainActor
@Observable
final class AppModel {
    enum LockState: Equatable {
        case locked
        case unlocking
        case unlocked
    }

    /// Entries at the bottom of the sidebar: each one replaces the item list
    /// in the middle column, and its selection shows on the right.
    enum SidebarPane {
        case audit
        case sends
        case emergency
        /// Members of an organization (`Members.swift`).
        case members
    }

    /// `demo`: mock vault (screenshots, `VERROU_DEMO=1` or `VERROU_MOCK=1`).
    enum Mode {
        case demo
        case vaultwarden
    }

    enum SyncState: Equatable {
        case idle
        case syncing
        /// Server unreachable: the displayed vault is the cache.
        case offline
        case failed(String)
    }

    let mode: Mode
    /// Account folder, in the app's container.
    let dataDirectory: URL
    let session: VaultSession

    private(set) var lockState: LockState = .locked
    private(set) var account: AccountInfo?
    private(set) var summaries: [ItemSummary] = []
    private(set) var results: [SearchHit] = []
    /// The results ready to display, one row per item: SwiftUI's list then
    /// only builds the visible rows (with an `if` per row, it built all of
    /// them on every keystroke).
    private(set) var rows: [ResultRow] = []
    private(set) var counts: SidebarCounts?
    /// Shared vaults (organizations) and their collections.
    private(set) var organizations: [OrganizationView] = []
    private(set) var lastSearchDuration: Duration = .zero
    private(set) var syncState: SyncState = .idle
    /// Changes made offline waiting for the server (kept, encrypted, even
    /// with the vault locked; lost on logout).
    private(set) var pendingChanges = 0
    private(set) var biometricEnrolled = false
    var unlockError: String?

    // Security keys (unlock through hmac-secret)
    /// Keys enrolled to unlock this vault.
    private(set) var unlockKeys: [UnlockKey] = []
    /// Exchange in progress with a security key, and what for.
    private(set) var keyExchange: KeyExchange?
    /// What the key is waiting for (touch, PIN); `nil`: waiting for the key.
    fileprivate(set) var keyPrompt: SecurityKeyPrompt?
    var enrollError: String?

    enum KeyExchange: Equatable {
        case unlock
        case enroll
    }

    // Login
    /// `nil`: credentials step; otherwise the second factor methods.
    private(set) var twoFactorOptions: [TwoFactorOption]?
    private(set) var loginBusy = false
    /// Waiting for a touch on the security key (USB).
    private(set) var securityKeyWaiting = false
    var loginError: String?
    /// Address and email entered, kept for the second factor and to prefill
    /// a new login.
    var loginServer = "https://"
    var loginEmail = ""
    /// The session expired: log in again (password and second factor).
    private(set) var reloginRequired = false

    var filter: SidebarFilter = .all { didSet { pane = nil; refresh() } }
    /// Pane from the bottom of the sidebar shown in the middle column instead
    /// of the list; `nil`: the item list.
    var pane: SidebarPane?

    // Audit
    /// The middle column shows the audit instead of the list.
    var showAudit: Bool { pane == .audit }
    private(set) var audit: AuditReport?
    /// `nil`: not checked yet (only on request: network).
    private(set) var breaches: [BreachedPassword]?
    private(set) var checkingBreaches = false
    var breachError: String?
    /// Item whose change-password page is being looked up
    /// (`changePassword`, in `Watchtower.swift`).
    var changingPassword: String?
    /// Cards, old passwords, two-factor authentication (`Watchtower.swift`).
    let watchtower = Watchtower()
    var query: String = "" { didSet { refresh() } }
    /// List order, kept on this Mac.
    var sort: ResultOrder = DevicePreferences.sort {
        didSet {
            DevicePreferences.sort = sort
            refresh()
        }
    }
    /// Filter opened at unlock, kept on this Mac.
    var defaultFilter: DefaultFilter = DevicePreferences.defaultFilter {
        didSet { DevicePreferences.defaultFilter = defaultFilter }
    }
    /// Match rules of this Mac (default, folders) and the account's
    /// equivalent domains.
    var matchSettings: MatchSettingsView?
    /// "Remove from sharing…" waiting for confirmation.
    var unshareRequest: UnshareRequest?
    /// Removal from sharing in progress (sheet open).
    var unshareBusy = false
    /// The removal failed: shown in the sheet.
    var unshareError: String?
    /// The active item: shown in the detail column, target of single-item
    /// actions. Changing it directly amounts to a simple selection (see
    /// `MultiSelection.swift` for ⌘-click, ⇧-click, ⌘A).
    var selection: String? {
        didSet {
            if oldValue != selection { revealed.removeAll() }
            if !applyingGesture { collapseSelection() }
            scheduleDetail()
        }
    }
    /// Selected items, in display order: the active item alone, or several
    /// (`MultiSelection.swift`).
    var selectedIDs: [String] = []
    /// The same, to know in constant time whether a row is selected.
    var selectedSet: Set<String> = []
    /// Several items selected: the detail column shows their summary, and
    /// actions apply to all of them. Kept separately (not computed): the
    /// window only redraws when it changes, not on every click.
    var isMultiSelection = false
    /// Range anchor (⇧-click, ⇧↑/⇧↓).
    var selectionAnchor: String?
    @ObservationIgnored var applyingGesture = false
    /// The item shown in the detail column. It follows `selection` on the
    /// next run loop turn: the clicked row lights up without waiting for the
    /// detail, and held arrow keys only build the last one.
    private(set) var detailID: String?
    @ObservationIgnored private var detailScheduled = false
    /// IDs of the displayed results, in order (computed once per search, not
    /// on every gesture).
    @ObservationIgnored private(set) var resultIDs: [String] = []
    /// Position of each item in `summaries`.
    @ObservationIgnored private var summaryIndex: [String: Int] = [:]
    /// Bulk action in progress: (items sent, to send).
    var bulkProgress: (done: Int, total: Int)?
    /// "Move to folder…" open, for these items.
    var moveRequest: MoveRequest?
    /// "New folder…" or "Rename…" open (see `FolderManagement.swift`).
    var folderRequest: FolderRequest?
    /// Fields revealed for the selected item, cleared as soon as it changes.
    var revealed: [String: String] = [:]
    var toast: Toast?
    /// Query of the quick access window, independent of the main window.
    var quickQuery = "" { didSet { refreshQuick() } }
    /// The 8 best quick access results, computed once per keystroke (and not
    /// on every render of the panel).
    private(set) var quickRows: [ResultRow] = []
    /// Incremented each time quick access opens: the window is reused, its
    /// `onAppear` doesn't come back.
    private(set) var quickAccessOpenings = 0

    func quickAccessOpened() {
        quickAccessOpenings += 1
    }

    // Editing
    /// Creation or edit screen open.
    var editor: Editor?
    var editorBusy = false
    var editorError: String?

    struct Editor: Identifiable {
        let id = UUID()
        /// `nil`: creation.
        let itemID: String?
        let draft: ItemDraft
        /// Direct creation in a shared vault (suggested from the sidebar).
        var destination: SharedDestination?
    }

    /// Import from another manager in progress (see `ImportFlow.swift`).
    var importFlow: ImportFlow?
    /// Duplicate cleanup open.
    var duplicatesFlow: DuplicatesFlow?
    /// Emergency access, see `EmergencyAccess.swift`.
    let emergency = EmergencyModel()
    /// Sends (Bitwarden Send), see `Sends.swift`.
    let sends = SendsModel()
    /// Organization members, see `Members.swift`.
    let members = MembersModel()
    /// Management of shared vaults (organizations, collections, groups,
    /// received invitations).
    let organizationAdmin = OrganizationAdminModel()
    /// SSH key generation open (see `SshKeys.swift`).
    var sshKeyGenerator: SshKeyGenerator?
    /// Attachments of the displayed item (see `Attachments.swift`).
    let attachments = AttachmentsModel()
    /// "Share…" or "Collections…" in progress (see SharedVaults.swift).
    var sharingFlow: SharingFlow?

    /// Filling in Brave and Firefox (absent in the demo and during scripted runs).
    var browserBridge: BrowserBridge?
    /// Approving the terminal from the iPhone (Vaultwarden account only).
    private(set) var remote: RemoteApprovals?
    /// The vault was opened by the iPhone for the terminal, the window
    /// staying locked: it locks again at this date (pushed back by each
    /// approval).
    private(set) var remoteSessionUntil: Date?
    @ObservationIgnored private var remoteUnlocking = false
    @ObservationIgnored private var remoteSessionTimer: Task<Void, Never>?

    let clipboard = Clipboard()
    let siteIcons = SiteIcons()

    /// Preference: site icons, requested from the account's server.
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
    /// End of the last Touch ID request: the system window makes the app
    /// lose then regain the foreground, it must not reopen right away.
    private var lastBiometricPrompt: Date?
    /// Asks for Touch ID by itself on the lock screen (not during scripted
    /// runs, which have nobody to touch the sensor).
    private let autoTouchID: Bool
    private var syncLoop: Task<Void, Never>?
    /// Live updates from the server (Vaultwarden's `WebSocket` channel).
    @ObservationIgnored let live = LiveUpdates()
    /// Notification tapped with the vault locked: opened after unlocking.
    @ObservationIgnored var pendingActivityRoute: ActivityRoute?
    /// Syncs requested and not finished yet (the Rust core groups them: one
    /// in progress, one after).
    @ObservationIgnored private var syncsInFlight = 0
    /// Incremented on each list reload: a reload read off the main thread
    /// and overtaken in the meantime is not published.
    @ObservationIgnored private var reloads = 0

    /// Preference: offer Touch ID after unlocking with the password.
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
        autoTouchID = environment["VERROU_DEMO"] == nil && environment["VERROU_E2E_SERVER"] == nil && !Self.isReview
        let demo = environment["VERROU_DEMO"] == "1" || environment["VERROU_MOCK"] == "1" || Self.isReview
        var e2e = false
        #if DEBUG
        e2e = environment["VERROU_E2E_SERVER"] != nil
        #endif
        var directory: URL
        if e2e {
            // End-to-end run: a throwaway account, never the real one.
            directory = FileManager.default.temporaryDirectory.appending(path: "verrou-e2e-data")
            try? FileManager.default.removeItem(at: directory)
        } else if demo {
            directory = VerrouStorage.privateDirectory()
        } else {
            // Build signed by the team: the app group shared with the
            // autofill extension (and the migration, once); ad hoc build:
            // the private folder, as before.
            directory = VerrouStorage.accountLocation().directory
        }
        dataDirectory = directory
        if demo {
            mode = .demo
            session = VaultSession()
        } else {
            mode = .vaultwarden
            try? FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
            session = VaultSession.withStorage(dataDir: dataDirectory.path)
            account = session.account()
            biometricEnrolled = BiometricVault.isEnrolled(in: dataDirectory)
            remote = RemoteApprovals(directory: dataDirectory)
            unlockKeys = session.securityKeys()
            pendingChanges = Int(session.pendingChanges())
            if let account {
                loginServer = account.server
                loginEmail = account.email
            }
        }
        // Decrypted attachments left over from an interrupted session (not
        // during the review: the temporary folder is the real Verrou's).
        if !Self.isReview { AttachmentsModel.purge() }
        // Warms up LocalAuthentication's answer before the first render.
        Biometrics.refresh()
        remote?.escrowNeeded = { [weak self] in Task { await self?.prepareRemoteEscrow(local: true) } }
        Perf.log.notice("model ready at +\(Perf.msSinceLaunch) ms after launch")
    }

    /// Start of the last unlock, and last app activation: to measure what
    /// the user waits for.
    @ObservationIgnored var unlockStartedAt: ContinuousClock.Instant?
    @ObservationIgnored var activatedAt: ContinuousClock.Instant?

    /// Offscreen visual review (`VERROU_REVIEW=1`, Debug builds): mock
    /// vault, no window on screen (see `ReviewDriver`).
    nonisolated static var isReview: Bool {
        #if DEBUG
        ProcessInfo.processInfo.environment["VERROU_REVIEW"] == "1"
        #else
        false
        #endif
    }

    /// Sends and emergency access in the sidebar: a Vaultwarden account, or
    /// the review (mock sends and contacts).
    var showsAccountPanes: Bool { mode == .vaultwarden || Self.isReview }

    #if DEBUG
    /// Review: the login screen (`login`), at the second factor step if
    /// `options`, without a server.
    func reviewLogin(_ login: Bool, twoFactor options: [TwoFactorOption]? = nil) {
        reviewNeedsLogin = login
        twoFactorOptions = options
    }

    private var reviewNeedsLogin = false
    #else
    private let reviewNeedsLogin = false
    #endif

    /// No account on this Mac, or session expired: login screen.
    var needsLogin: Bool {
        (mode == .vaultwarden && (account == nil || reloginRequired)) || reviewNeedsLogin
    }

    var canUseTouchID: Bool {
        mode == .demo ? Biometrics.isAvailable : biometricEnrolled && Biometrics.isAvailable
    }

    var canUseSecurityKey: Bool {
        mode == .vaultwarden && !unlockKeys.isEmpty
    }

    // MARK: Login

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

    /// Security key plugged in over USB, without a browser: wait for the touch.
    func useSecurityKeyNatively(challenge: String) async {
        guard !securityKeyWaiting, !loginBusy else { return }
        securityKeyWaiting = true
        loginError = nil
        let token: String
        do {
            token = try await session.signWithSecurityKey(challenge: challenge)
        } catch {
            securityKeyWaiting = false
            // Cancelled by the user (or by switching methods): nothing to say.
            if ErrorText.isCancellation(error) { return }
            loginError = Self.describe(error)
            return
        }
        securityKeyWaiting = false
        await answerTwoFactor(.securityKey(challenge: challenge), token: token)
        if lockState != .unlocked, loginError != nil {
            // The server only allows one attempt per challenge: ask for a new one.
            if case .twoFactorRequired(let options)? = try? await session.restartTwoFactor() {
                twoFactorOptions = options
            }
        }
    }

    func cancelSecurityKey() {
        session.cancelSecurityKey()
    }

    /// Fallback: the server's login page, in Safari.
    func useSecurityKey(challenge: String) async {
        loginError = nil
        do {
            let token = try await SecurityKeySignIn().sign(server: normalizedServer, challenge: challenge)
            await answerTwoFactor(.securityKey(challenge: challenge), token: token)
        } catch SecurityKeySignIn.Failure.cancelled {
            // The user closed the window: nothing to say.
        } catch {
            loginError = Self.describe(error)
        }
    }

    func sendEmailCode() async {
        do {
            try await session.sendEmailCode()
            toast = Toast(message: String(localized: "Code sent"), detail: String(localized: "Check your inbox"))
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

    func handle(_ result: LoginResult) async {
        switch result {
        case .twoFactorRequired(let options):
            twoFactorOptions = options
        case .unlocked(let failures):
            twoFactorOptions = nil
            reloginRequired = false
            account = session.account()
            // A new login changes the vault key: the old Touch ID is no
            // longer valid, nor are the enrolled security keys.
            BiometricVault.remove(in: dataDirectory)
            biometricEnrolled = false
            removeAllUnlockKeys()
            didUnlock(failures: failures)
            // Account created with an invitation link: accept it (`Members.swift`).
            await acceptPendingInvitation()
            await enrollBiometricsIfWanted()
        }
    }

    /// Session expired, but we still want to browse the cache.
    func continueOffline() {
        reloginRequired = false
        loginError = nil
    }

    func logout() {
        lock()
        endRemoteSession(lock: true)
        remote?.clearEscrow()
        try? session.logout()
        SystemAutofill.clear()
        BiometricVault.remove(in: dataDirectory)
        biometricEnrolled = false
        removeAllUnlockKeys()
        account = nil
        reloginRequired = false
        twoFactorOptions = nil
        syncState = .idle
        pendingChanges = 0
    }

    // MARK: Locking

    /// Lock screen shown or app back in the foreground: Touch ID right away,
    /// without going through the button.
    func promptTouchIDIfPossible() async {
        guard autoTouchID, mode == .vaultwarden, canUseTouchID, lockState == .locked, !needsLogin,
              NSApp.isActive else { return }
        if let last = lastBiometricPrompt, Date().timeIntervalSince(last) < 3 { return }
        await unlockWithBiometrics()
    }

    func unlockWithBiometrics() async {
        defer { lastBiometricPrompt = Date() }
        if let activatedAt {
            Perf.log.notice("Touch ID requested at +\(Perf.ms(since: activatedAt)) ms after activation")
        }
        lockState = .unlocking
        unlockError = nil
        if mode == .demo {
            switch await Biometrics.authenticate(reason: String(localized: "unlock your vault")) {
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
            let key = try await BiometricVault.open(in: dataDirectory, reason: String(localized: "unlock your vault"))
            unlockStartedAt = .now
            let failures = try await Perf.measure("vault decryption (Rust)") {
                try await session.unlockWithUserKey(userKey: key)
            }
            didUnlock(failures: failures)
        } catch BiometricVault.Failure.cancelled, BiometricVault.Failure.interrupted {
            lockState = .locked
        } catch BiometricVault.Failure.unavailable {
            unlockError = String(localized: "Touch ID is not available: enter your master password.")
            lockState = .locked
        } catch {
            // Fingerprints changed, or stale key: back to the password.
            disableBiometrics()
            unlockError = String(localized: "Touch ID must be turned on again: enter your master password.")
            lockState = .locked
        }
    }

    func unlock(masterPassword: String) async {
        guard !masterPassword.isEmpty else {
            unlockError = String(localized: "Enter your master password.")
            return
        }
        if mode == .demo {
            // Mock vault: any non-empty password opens it.
            openVault()
            return
        }
        lockState = .unlocking
        unlockError = nil
        unlockStartedAt = .now
        do {
            let failures = try await Perf.measure("password unlock (derivation + decryption)") {
                try await session.unlockWithPassword(password: masterPassword)
            }
            didUnlock(failures: failures)
            await enrollBiometricsIfWanted()
        } catch {
            unlockError = Self.describe(error)
            lockState = .locked
        }
    }

    /// Mock vault (demo).
    func openVault() {
        session.unlockMock(size: mockSize, seed: 42, language: .current)
        didUnlock(failures: 0)
    }

    private func didUnlock(failures: UInt32) {
        // The filter chosen in the settings (except the review and the demo,
        // which start from "All items").
        if !Self.isReview { filter = defaultFilter.filter }
        reloadVault()
        lockState = .unlocked
        endRemoteSession(lock: false)
        updateSiteIcons()
        autoLock = AutoLock { [weak self] in self?.lock() }
        // Unlocked on the Mac: the iPhone may unlock for 12 hours.
        if mode == .vaultwarden { Task { await prepareRemoteEscrow(local: true) } }
        if failures > 0 {
            let count = Int(failures)
            toast = Toast(message: count > 1 ? String(localized: "\(count) unreadable items")
                                             : String(localized: "\(count) unreadable item"),
                          detail: String(localized: "The Bitwarden SDK could not decrypt them"))
        }
        if let route = pendingActivityRoute {
            pendingActivityRoute = nil
            openActivity(route)
        }
        guard mode == .vaultwarden else { return }
        syncLoop?.cancel()
        syncLoop = Task { [weak self] in
            while !Task.isCancelled {
                await self?.syncNow()
                // Changes are waiting for the server: retry more often.
                // Without a live channel, every 2 minutes; with one, every 5
                // (members to confirm and emergency access don't go through
                // it).
                let waiting = (self?.pendingChanges ?? 0) > 0
                let live = self?.live.connected ?? false
                try? await Task.sleep(for: .seconds(waiting ? 30 : live ? 5 * 60 : 2 * 60))
            }
        }
        startLiveUpdates()
    }

    /// The live updates channel, while the vault is open: a change on the
    /// server (sharing, confirmation) is synced and notified within a few
    /// seconds.
    func startLiveUpdates() {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        live.start(session: session) { [weak self] in
            await self?.syncNow()
        } expired: { [weak self] in
            guard let self, self.lockState == .unlocked else { return }
            self.reloginRequired = true
            self.lock()
        }
    }

    /// Reloads summaries and counters (after unlocking or syncing), keeping
    /// the selection if the item still exists.
    func openAudit() {
        audit = try? session.audit()
        watchtower.refresh(session, network: mode == .vaultwarden)
        pane = .audit
    }

    /// Adds to the leaks already displayed those of the passwords just
    /// checked (`checkNewPasswords`).
    func mergeBreaches(_ found: [BreachedPassword]) {
        guard var known = breaches else { return }
        known.removeAll { old in found.contains { $0.item.id == old.item.id } }
        breaches = (known + found).sorted { $0.count > $1.count }
    }

    /// Have I Been Pwned, through k-anonymity (5 hash characters per password).
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

    /// What the reload reads from the Rust core, read off the main thread
    /// after a sync (`reloadVaultAfterSync`).
    private struct LoadedVault: @unchecked Sendable {
        let summaries: [ItemSummary]
        let counts: SidebarCounts?
        let organizations: [OrganizationView]
    }

    private func reloadVault(_ loaded: LoadedVault? = nil) {
        reloads += 1
        if showAudit {
            audit = try? session.audit()
            watchtower.refresh(session, network: mode == .vaultwarden)
        }
        // A changed password (here, in the browser, or elsewhere then
        // synced) leaves the leak list without a new check.
        if let known = breaches { breaches = session.stillBreached(breaches: known) }
        let start = ContinuousClock.now
        defer { Perf.log.notice("list reload (\(self.summaries.count) items): \(Perf.ms(since: start)) ms") }
        summaries = loaded?.summaries ?? (try? session.summaries()) ?? []
        summaryIndex = Dictionary(summaries.enumerated().map { ($1.id, $0) }, uniquingKeysWith: { first, _ in first })
        counts = loaded.map(\.counts) ?? (try? session.counts())
        organizations = loaded?.organizations ?? session.organizations()
        matchSettings = session.matchSettings()
        refreshPending()
        // A created item got its ID from the server: the selection follows.
        resolveTemporaryIDs()
        refresh()
        if selection.map({ id in !summaries.contains { $0.id == id } }) ?? true {
            selection = results.first?.id
        }
        if mode == .vaultwarden { SystemAutofill.publish(session) }
    }

    /// After a sync: the summaries (several hundred) are read off the main
    /// thread, then published at once; the selection, the search, the
    /// scroll position and the open editor stay.
    private func reloadVaultAfterSync() async {
        let session = session
        let generation = reloads
        let start = ContinuousClock.now
        let loaded = await Task.detached(priority: .userInitiated) {
            LoadedVault(summaries: (try? session.summaries()) ?? [], counts: try? session.counts(),
                        organizations: session.organizations())
        }.value
        // Locked, or a write reloaded something newer in the meantime.
        guard lockState == .unlocked, generation == reloads else { return }
        let read = Perf.ms(since: start)
        let main = ContinuousClock.now
        reloadVault(loaded)
        Perf.log.notice("sync applied (\(loaded.summaries.count) items): read \(read) ms off the main thread, \(Perf.ms(since: main)) ms on the main thread")
    }

    func lock() {
        syncLoop?.cancel()
        syncLoop = nil
        live.stop(session: session)
        session.lock()
        summaries = []
        results = []
        rows = []
        quickRows = []
        counts = nil
        organizations = []
        sharingFlow = nil
        revealed.removeAll()
        selection = nil
        query = ""
        quickQuery = ""
        pane = nil
        audit = nil
        breaches = nil
        breachError = nil
        changingPassword = nil
        watchtower.reset()
        // The vault window stays mounted behind the lock screen: nothing
        // open must survive there.
        editor = nil
        editorError = nil
        // An enrollment in progress needs the vault open.
        if keyExchange == .enroll { session.cancelSecurityKey() }
        importFlow = nil
        duplicatesFlow = nil
        emergency.clear()
        members.clear()
        organizationAdmin.clear()
        sends.clear()
        attachments.clear()
        autoLock = nil
        clipboard.clearIfOurs()
        lockState = .locked
        endRemoteSession(lock: false)
        updateSiteIcons()
    }

    // MARK: Sync

    /// Sends in the background what was just written (see `outbox.rs`),
    /// then syncs: the interface doesn't wait for the server.
    func pushChanges() {
        guard mode == .vaultwarden else { return }
        Task { await syncNow(afterWrite: true) }
    }

    /// `afterWrite`: right after a write; offline a short while ago, the
    /// core doesn't retry right away (the periodic sync takes care of it).
    /// Simultaneous requests are grouped by the Rust core.
    func syncNow(afterWrite: Bool = false) async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        syncsInFlight += 1
        syncState = .syncing
        var result: SyncState = .idle
        // The queue goes out before the vault is read: its report
        // (conflicts, rejections) shows afterwards, success or not.
        defer {
            syncsInFlight -= 1
            // Another sync follows: that one will tell the state.
            if syncsInFlight == 0, lockState == .unlocked { syncState = result }
            refreshPending()
            Task { await self.showSyncReport() }
        }
        do {
            let outcome = try await Perf.measure("sync (network + decryption, off the main thread)") {
                try await afterWrite ? session.pushChanges() : session.sync()
            }
            guard lockState == .unlocked else { return }
            account = session.account()
            // Pending invitations and members to confirm: on every periodic
            // sync (not after each write).
            if !afterWrite { Task { await self.refreshSharingStatus() } }
            // Nothing new: the displayed list is up to date, leave it alone.
            guard outcome.changed else { return }
            await reloadVaultAfterSync()
            if outcome.failures > 0 {
                result = .failed(String(localized: "\(Int(outcome.failures)) unreadable item(s)"))
            }
        } catch VerrouError.Locked {
            result = .idle
        } catch VerrouError.SessionExpired {
            result = .failed(String(localized: "Session expired"))
            reloginRequired = true
            lock()
        } catch VerrouError.Network {
            result = .offline
        } catch {
            result = .failed(Self.describe(error))
        }
    }

    // MARK: Offline changes

    func refreshPending() {
        pendingChanges = mode == .vaultwarden ? Int(session.pendingChanges()) : 0
    }

    /// Label of the number of pending changes ("3 pending changes").
    var pendingLabel: String? {
        guard pendingChanges > 0 else { return nil }
        return pendingChanges == 1 ? String(localized: "1 pending change")
                                   : String(localized: "\(pendingChanges) pending changes")
    }

    /// Toast of an item write, written right away (sending follows in the
    /// background); offline, it waits for the server.
    func writeToast(_ message: String, detail: String? = nil) -> Toast {
        guard syncState == .offline else { return Toast(message: message, detail: detail) }
        return Toast(message: message, detail: String(localized: "Offline: synced as soon as the server responds"))
    }

    /// Report of sending the offline changes: conflicts and rejections first
    /// (nothing must disappear without saying so), then the successes.
    func showSyncReport() async {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        let report = await session.takeSyncReport()
        if !report.conflicts.isEmpty {
            let count = report.conflicts.count
            toast = Toast(message: count == 1 ? String(localized: "Conflict: local version kept as a copy")
                                              : String(localized: "\(count) conflicts: local versions kept as copies"),
                          detail: report.conflicts.map { String(localized: "“\($0)”") }.joined(separator: ", "), failure: true)
        } else if !report.rejected.isEmpty {
            // Removed from the queue: the displayed vault went back to the server's version.
            toast = Toast(message: report.rejected.count == 1 ? String(localized: "Change rejected by the server, cancelled")
                                                              : String(localized: "\(report.rejected.count) changes rejected by the server, cancelled"),
                          detail: report.rejected.joined(separator: "\n"), failure: true, seconds: 6)
        } else if report.sent > 0 {
            toast = Toast(message: report.sent == 1 ? String(localized: "Offline change synced")
                                                    : String(localized: "\(Int(report.sent)) offline changes synced"),
                          detail: nil)
        }
    }

    // MARK: Approving from the iPhone

    /// The vault key sealed for the paired iPhones (`RemoteApprovals`).
    /// `local`: unlocked on the Mac, the 12 hours start again.
    func prepareRemoteEscrow(local: Bool) async {
        // `local`: unlocked on the Mac, not just for the terminal.
        guard let remote, remote.unlockEnabled, remote.isReady, session.isUnlocked(),
              !local || lockState == .unlocked,
              let key = try? await session.userKey() else { return }
        remote.prepareEscrow(userKey: key, local: local)
    }

    /// The terminal found the vault locked while you are away: the iPhone
    /// opens it for the terminal only. The window stays locked; the vault
    /// locks again `remoteSessionLifetime` after the last approval.
    /// `then`: what the terminal reads once unlocked (one approval for
    /// both). `true`: unlocked from the iPhone.
    @discardableResult
    func unlockFromPhone(client: String, reason: String, then: (item: String, field: String)? = nil) async -> Bool {
        guard let remote, remote.canUnlock, lockState == .locked, !needsLogin, !remoteUnlocking,
              !session.isUnlocked() else { return false }
        remoteUnlocking = true
        defer { remoteUnlocking = false }
        guard let key = await remote.unlock(client: client, reason: reason, then: then),
              lockState == .locked else { return false }
        do {
            _ = try await Perf.measure("vault decryption (Rust, from the iPhone)") {
                try await session.unlockWithUserKey(userKey: key)
            }
        } catch {
            return false
        }
        // Unlocked on the Mac meanwhile: nothing more to do.
        guard lockState == .locked else { return false }
        extendRemoteSession()
        // A new K: the one the iPhone just returned is spent.
        await prepareRemoteEscrow(local: false)
        return true
    }

    /// An approval from the iPhone pushes back the lock of the vault it
    /// opened.
    func extendRemoteSession() {
        guard lockState == .locked, session.isUnlocked() else { return }
        remoteSessionUntil = Date().addingTimeInterval(RemoteApprovals.remoteSessionLifetime)
        guard remoteSessionTimer == nil else { return }
        remoteSessionTimer = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                guard let self, let until = self.remoteSessionUntil else { return }
                if Date() >= until { self.endRemoteSession(lock: true) }
            }
        }
    }

    /// Back to the locked vault (`lock`), or the session continues on the
    /// Mac (unlocked there).
    func endRemoteSession(lock: Bool) {
        remoteSessionTimer?.cancel()
        remoteSessionTimer = nil
        guard remoteSessionUntil != nil else { return }
        remoteSessionUntil = nil
        if lock, lockState == .locked { session.lock() }
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

    // MARK: Security keys

    /// Unlocks with an enrolled YubiKey: wait for the key, its PIN, then the
    /// touch. Everything else (the key's secret, unsealing) happens in Rust.
    func unlockWithSecurityKey() async {
        guard canUseSecurityKey, keyExchange == nil, lockState == .locked else { return }
        lockState = .unlocking
        unlockError = nil
        beginKeyExchange(.unlock)
        defer { endKeyExchange() }
        do {
            let failures = try await session.unlockWithSecurityKey(observer: KeyPrompts(model: self))
            unlockStartedAt = .now
            didUnlock(failures: failures)
        } catch {
            lockState = .locked
            // A stale key removed all the enrolled keys.
            unlockKeys = session.securityKeys()
            if !Self.isCancellation(error) {
                unlockError = Self.describe(error)
            }
        }
    }

    /// Adds the plugged-in key to the keys that unlock this vault (vault open).
    func enrollSecurityKey(label: String) async -> Bool {
        guard mode == .vaultwarden, lockState == .unlocked, keyExchange == nil else { return false }
        enrollError = nil
        beginKeyExchange(.enroll)
        defer { endKeyExchange() }
        do {
            let key = try await session.enrollSecurityKey(label: label, observer: KeyPrompts(model: self))
            unlockKeys = session.securityKeys()
            toast = Toast(message: String(localized: "Security key added"), detail: key.label)
            return true
        } catch {
            if !Self.isCancellation(error) {
                enrollError = Self.describe(error)
            }
            return false
        }
    }

    /// The PIN requested by the key: it goes straight to Rust.
    func submitSecurityKeyPin(_ pin: String) {
        guard keyExchange != nil else { return }
        keyPrompt = nil
        session.submitSecurityKeyPin(pin: pin)
    }

    func cancelKeyExchange() {
        session.cancelSecurityKey()
    }

    func removeUnlockKey(_ key: UnlockKey) {
        do {
            try session.removeSecurityKey(id: key.id)
        } catch {
            toast = Toast(message: String(localized: "Couldn't remove the key"), detail: Self.describe(error), failure: true)
        }
        unlockKeys = session.securityKeys()
    }

    private func removeAllUnlockKeys() {
        try? session.removeSecurityKeys()
        unlockKeys = []
    }

    private func beginKeyExchange(_ purpose: KeyExchange) {
        keyExchange = purpose
        keyPrompt = nil
    }

    private func endKeyExchange() {
        keyExchange = nil
        keyPrompt = nil
    }

    private static func isCancellation(_ error: Error) -> Bool {
        ErrorText.isCancellation(error)
    }

    static func describe(_ error: Error) -> String {
        ErrorText.describe(error)
    }

    // MARK: Search

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
        resultIDs = rows.map(\.id)
        lastSearchDuration = clock.now - start
        pruneSelection()
    }

    /// The summary of a result, if it still points to the same item: between
    /// the replacement of the vault on the Rust side (sync, write) and the
    /// reload here, an old result can still be displayed.
    func summary(for hit: SearchHit) -> ItemSummary? {
        let position = Int(hit.position)
        if summaries.indices.contains(position), summaries[position].id == hit.id {
            return summaries[position]
        }
        return summaryIndex[hit.id].map { summaries[$0] }
    }

    /// Summary of a vault item (without calling the Rust core).
    func summary(id: String) -> ItemSummary? {
        summaryIndex[id].flatMap { summaries.indices.contains($0) && summaries[$0].id == id ? summaries[$0] : nil }
    }

    /// Summary of the selected item (without calling the Rust core).
    var selectedSummary: ItemSummary? {
        guard let selection else { return nil }
        return summary(id: selection)
    }

    var selectedDetail: ItemDetail? {
        guard let selection else { return nil }
        return try? session.detail(id: selection)
    }

    /// The detail of the detail column (see `detailID`).
    var displayedDetail: ItemDetail? {
        guard let detailID else { return nil }
        return try? session.detail(id: detailID)
    }

    private func scheduleDetail() {
        guard !detailScheduled else { return }
        detailScheduled = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            detailScheduled = false
            if detailID != selection { detailID = selection }
        }
    }

    func moveSelection(by offset: Int) {
        let ids = resultIDs
        guard !ids.isEmpty else { return }
        let current = selection.flatMap { ids.firstIndex(of: $0) } ?? -1
        let next = min(max(current + offset, 0), ids.count - 1)
        withoutAnimation { selection = ids[next] }
    }

    // MARK: Editing

    /// The mock vault stays read-only. Offline, item writes wait for the
    /// server (see `outbox.rs`).
    var canEdit: Bool { mode == .vaultwarden && lockState == .unlocked }

    var folders: [FolderOption] {
        lockState == .unlocked ? session.folders() : []
    }

    /// New item, put in the displayed folder; a login comes with a password
    /// already generated.
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
                                                     notes: nil, login: fields, fields: [], template: nil),
                        destination: destinationFromFilter)
    }

    /// New item from a template (Wi-Fi, passport…): its predefined fields,
    /// to fill in.
    func newItem(template: ItemTemplate) {
        guard canEdit else { return }
        var draft = templateDraft(template: template)
        if case .folder(let name) = filter {
            draft.folderId = folders.first { $0.name == name }?.id
        }
        editorError = nil
        editor = Editor(itemID: nil, draft: draft, destination: destinationFromFilter)
    }

    func edit(_ itemID: String) async {
        guard canEdit else { return }
        if session.needsConfirmation(id: itemID) {
            let title = summaries.first { $0.id == itemID }?.title ?? String(localized: "this item")
            guard await confirmAccess(itemID: itemID, title: title) else { return }
        }
        editorError = nil
        do {
            editor = Editor(itemID: itemID, draft: try await session.editDraft(id: itemID))
        } catch {
            toast = Toast(message: String(localized: "Couldn't edit"), detail: Self.describe(error), failure: true)
        }
    }

    func saveEditor(_ draft: ItemDraft, destination: SharedDestination? = nil) async {
        guard let editor, !editorBusy else { return }
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
            afterWrite(select: id)
            self.editor = nil
            toast = writeToast(editor.itemID == nil ? String(localized: "Item created") : String(localized: "Saved"))
            pushChanges()
        } catch VerrouError.Conflict {
            editorError = String(localized: "The item changed elsewhere in the meantime. Verrou just reloaded it: open it again to redo the change.")
            await syncNow()
        } catch {
            editorError = Self.describe(error)
        }
    }

    /// The server's trash: restorable from the web vault.
    func trash(_ itemID: String) async {
        guard canEdit else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            try await session.trashItem(id: itemID)
            editor = nil
            afterWrite(select: nil)
            toast = writeToast(String(localized: "Moved to trash"), detail: String(localized: "Restorable from the web vault"))
            pushChanges()
        } catch {
            editorError = Self.describe(error)
            toast = Toast(message: String(localized: "Couldn't move to trash"), detail: Self.describe(error), failure: true)
        }
    }

    /// The extension saved a login or a code: the Rust core already replaced
    /// the vault (and answered the extension), we reload the display without
    /// changing the selection, then send.
    func didSaveFromBrowser(title: String) {
        guard lockState == .unlocked else { return }
        afterWrite(select: selection)
        toast = writeToast(String(localized: "Saved from the browser"), detail: title.isEmpty ? nil : title)
        pushChanges()
    }

    // MARK: Organizing

    func setFavorite(_ itemID: String, _ favorite: Bool) async {
        await perform(favorite ? String(localized: "Added to favorites") : String(localized: "Removed from favorites"),
                      select: itemID) {
            try await self.session.setFavorite(id: itemID, favorite: favorite)
        }
    }

    /// Archive: the item leaves the list, the search and autofill, without
    /// being deleted.
    func setArchived(_ itemID: String, _ archived: Bool) async {
        await perform(archived ? String(localized: "Archived") : String(localized: "Unarchived"),
                      detail: archived ? String(localized: "Find it in Archive") : nil,
                      select: archived ? nil : itemID) {
            try await self.session.setArchived(id: itemID, archived: archived)
        }
    }

    func restore(_ itemID: String) async {
        await perform(String(localized: "Restored"), select: itemID) {
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
            toast = writeToast(done, detail: detail)
            pushChanges()
        } catch {
            toast = Toast(message: String(localized: "Action failed"), detail: Self.describe(error), failure: true)
        }
    }

    /// A write just changed the displayed vault (the change is waiting for
    /// the server, or a direct write resynced it): reload.
    func afterWrite(select id: String?) {
        guard lockState == .unlocked else { return }
        account = session.account()
        revealed.removeAll()
        reloadVault()
        if let id { selection = session.resolveItemId(id: id) }
        if pendingChanges == 0 { syncState = .idle }
        checkNewPasswords()
        // A write first sends what was waiting: its report follows.
        Task { await showSyncReport() }
    }

    // MARK: Protected items

    /// Protected item ("master password re-prompt") not confirmed yet: asks
    /// for confirmation, then replays `retry`. Returns `true` if the action
    /// must wait.
    func awaitsConfirmation(_ itemID: String, retry: @escaping @MainActor () -> Void) -> Bool {
        guard session.needsConfirmation(id: itemID) else { return false }
        let title = summaries.first { $0.id == itemID }?.title ?? String(localized: "this item")
        Task {
            if await confirmAccess(itemID: itemID, title: title) { retry() }
        }
        return true
    }

    /// Touch ID, otherwise the master password; the confirmation lasts
    /// 5 minutes for this item (on the Rust side, cleared on lock).
    func confirmAccess(itemID: String, title: String, context: LAContext = LAContext()) async -> Bool {
        if mode == .vaultwarden, canUseTouchID {
            switch await Biometrics.authenticate(reason: String(localized: "show “\(title)”"), context: context) {
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
            // Mock vault: no master password to check.
            session.authorizeItem(id: itemID)
            return true
        }
        NSApp.activate()
        let alert = NSAlert()
        alert.messageText = String(localized: "“\(title)” is protected")
        alert.informativeText = String(localized: "Enter your master password to show its secrets.")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: String(localized: "Confirm"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn, !field.stringValue.isEmpty else { return false }
        let password = field.stringValue
        field.stringValue = ""
        do {
            guard try await session.verifyMasterPassword(password: password) else {
                toast = Toast(message: String(localized: "Incorrect master password"), detail: nil, failure: true)
                return false
            }
            session.authorizeItem(id: itemID)
            return true
        } catch {
            toast = Toast(message: String(localized: "Couldn't confirm"), detail: Self.describe(error), failure: true)
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

    /// Current one-time code, if accessible without confirmation.
    func totpCode(of itemID: String, at date: Date = Date()) -> TotpView? {
        try? session.totp(id: itemID, unixTime: UInt64(date.timeIntervalSince1970))
    }

    func copyCode(of itemID: String) {
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyCode(of: itemID) }) { return }
        guard let code = totpCode(of: itemID) else { return }
        session.recordItemUse(id: itemID)
        copy(code.code, label: String(localized: "Code"), secret: true)
    }

    func copy(_ value: String, label: String, secret: Bool) {
        clipboard.copy(value, concealed: secret)
        withAnimation(.snappy) {
            toast = Toast(message: String(localized: "\(label) copied"),
                          detail: secret ? String(localized: "Cleared from the clipboard in 90 s") : nil)
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
        // The card number is copied without spaces: that's what forms
        // expect.
        let copied = field.fieldType == .cardNumber ? value.replacingOccurrences(of: " ", with: "") : value
        // A revealed secret is already recorded by the core; a plain field, here.
        if !field.secret { session.recordItemUse(id: itemID) }
        copy(copied, label: field.label, secret: field.secret)
        if field.secret { revealed[field.id] = nil }
    }

    func copyUsername(of itemID: String) {
        guard let summary = summary(id: itemID), summary.category == .login, !summary.subtitle.isEmpty else { return }
        session.recordItemUse(id: itemID)
        copy(summary.subtitle, label: String(localized: "Username"), secret: false)
    }

    /// The first website, in full (not only its host).
    func copyWebsite(of itemID: String) {
        guard let url = (try? session.detail(id: itemID))?.urls.first else { return }
        session.recordItemUse(id: itemID)
        copy(url, label: String(localized: "Website"), secret: false)
    }

    func copyPassword(of itemID: String) {
        if summaries.first(where: { $0.id == itemID })?.sharing?.hidePasswords == true {
            toast = Toast(message: String(localized: "Password hidden"),
                          detail: String(localized: "The organization hides it from your account"), failure: true)
            return
        }
        if awaitsConfirmation(itemID, retry: { [weak self] in self?.copyPassword(of: itemID) }) { return }
        guard let value = try? session.reveal(id: itemID, fieldId: "password") else { return }
        copy(value, label: String(localized: "Password"), secret: true)
    }

    /// Main window in the foreground. Closed (launched at login), a "reopen"
    /// recreates it, like a click on the Dock.
    func showMainWindow() {
        // Offscreen review: nothing must appear, nor the app come to the front.
        guard !Self.isReview else { return }
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

/// Steps of the exchange with the security key, reported from the
/// exchange's thread: hand over to the main thread right away.
private final class KeyPrompts: SecurityKeyObserver, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) {
        self.model = model
    }

    func prompt(prompt: SecurityKeyPrompt) {
        DispatchQueue.main.async { [weak model] in
            MainActor.assumeIsolated {
                guard let model, model.keyExchange != nil else { return }
                model.keyPrompt = prompt
            }
        }
    }
}

/// Auto-lock: inactivity (`autoLockMinutes`, 0: never), sleep, screen saver
/// and screen locked (`lockOnSleep`).
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
    // Set on the main actor, released in deinit (nonisolated).
    nonisolated(unsafe) private var timer: Timer?
    nonisolated(unsafe) private var observers: [NSObjectProtocol] = []
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
        for name in ["com.apple.screenIsLocked", "com.apple.screensaver.didstart"] {
            observers.append(DistributedNotificationCenter.default().addObserver(
                forName: .init(name), object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { if AutoLock.lockOnSleep { self?.onLock() } }
            })
        }
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

// MARK: Passkeys

extension AppModel {
    /// Removes a passkey from the login, on the server.
    func deletePasskey(itemID: String, credentialID: String) async {
        await perform(String(localized: "Passkey deleted"), select: itemID) {
            try await self.session.deletePasskey(id: itemID, credentialId: credentialID)
        }
    }
}
