import QuickLook
import SwiftUI

/// The push token's answer (iCloud notifications of the Mac's requests).
final class PhoneAppDelegate: NSObject, UIApplicationDelegate {
    static var pushRegistered: ((Error?) -> Void)?

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Self.pushRegistered?(nil)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Self.pushRegistered?(error)
    }
}

@main
struct VerrouPhoneApp: App {
    @UIApplicationDelegateAdaptor(PhoneAppDelegate.self) private var delegate
    @State private var model = PhoneModel()
    @Environment(\.scenePhase) private var scenePhase
    #if DEBUG
    @State private var endToEnd: EndToEndDriver?
    @State private var autoFillSetup: AutoFillSetupDriver?
    @State private var bench: PhoneBenchDriver?
    @State private var launchBench: LaunchBenchDriver?
    #endif

    init() {
        // Tapping a notification that launches the app goes through here:
        // installed before launch finishes, kept until the app is ready
        // (`setHandler`).
        let environment = ProcessInfo.processInfo.environment
        ActivityNotifier.shared.silent = environment["VERROU_E2E_SERVER"] != nil || environment["VERROU_DEMO"] != nil
        ActivityNotifier.shared.install()
        Diagnostics.shared.start()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .onChange(of: scenePhase) { _, phase in
                    // The requests first: the vault's Face ID waits for them.
                    model.remote.sceneChanged(to: phase)
                    model.scenePhaseChanged(to: phase)
                }
                // `otpauth://` links: Verrou can be the app chosen to set up
                // verification codes. `verrou://`: the widgets and the
                // control.
                .onOpenURL { url in
                    if let link = VerrouLink(url: url) {
                        model.open(link)
                    } else {
                        model.openOTPLink(url)
                    }
                }
                .task {
                    if model.mode != .vaultwarden { ActivityNotifier.shared.silent = true }
                    ActivityNotifier.shared.setHandler { [weak model] route in model?.openActivity(route) }
                    // Shortcuts (App Intents).
                    VerrouLinkCenter.setHandler { [weak model] link in model?.open(link) }
                    // A request from the Mac (iCloud notification): fetched
                    // and shown above everything.
                    PhoneAppDelegate.pushRegistered = { [weak model] error in model?.remote.pushRegistered(error) }
                    ActivityNotifier.shared.setApprovalHandler { [weak model] in
                        Task { await model?.remote.refresh() }
                    }
                    #if DEBUG
                    if endToEnd == nil, let config = EndToEndDriver.Config(ProcessInfo.processInfo.environment) {
                        let driver = EndToEndDriver(model: model, config: config)
                        endToEnd = driver
                        driver.start()
                    }
                    if autoFillSetup == nil, let config = AutoFillSetupDriver.Config(ProcessInfo.processInfo.environment) {
                        let driver = AutoFillSetupDriver(model: model, config: config)
                        autoFillSetup = driver
                        driver.start()
                    }
                    // Screenshots: `VERROU_OPEN_TAB=generator|vault` opens the demo vault on that tab.
                    if let tab = ProcessInfo.processInfo.environment["VERROU_OPEN_TAB"], model.mode == .demo,
                       model.lockState == .locked {
                        model.openMockVault()
                        model.tab = tab == "generator" ? .generator : .vault
                    }
                    if launchBench == nil, let phase = LaunchBenchDriver.phase {
                        let driver = LaunchBenchDriver(model: model, phase: phase)
                        launchBench = driver
                        driver.start()
                    }
                    if bench == nil, PhoneBenchDriver.enabled {
                        let driver = PhoneBenchDriver(model: model)
                        bench = driver
                        driver.start()
                    }
                    #endif
                }
        }
        // Background wake-up: sharing news (see
        // `PhoneModel.backgroundActivityCheck`).
        .backgroundTask(.appRefresh(PhoneModel.activityTaskID)) {
            await model.backgroundActivityCheck()
        }
    }
}

struct RootView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The lock screen is shown: on unlock, it stays above the vault
    /// (already usable) while it fades out.
    @State private var lockOnScreen = false
    /// The vault is built under the lock screen while Face ID (or the
    /// password derivation) works: on success, only the data remains to be
    /// poured in, without waiting for the tabs, lists and bars to be
    /// built.
    @State private var vaultPrepared = false

    /// Out of the foreground (app switcher, Control Center): the content is
    /// blurred and covered, the switcher's preview shows nothing. Not during
    /// the Face ID prompt the app made itself: iOS leaves it inactive for up
    /// to two seconds after the success, and the privacy screen then covered
    /// the already open vault.
    private var shielded: Bool {
        scenePhase == .background || (scenePhase == .inactive && !model.biometricPrompt)
    }

    private var showsLock: Bool {
        !model.needsLogin && (model.lockState != .unlocked || lockOnScreen)
    }

    var body: some View {
        @Bindable var model = model
        ZStack {
            ZStack {
                if model.lockState == .unlocked || (vaultPrepared && !model.needsLogin) {
                    // Placed right away, opaque, under the fading lock
                    // screen: no cross-fade where both would be half
                    // transparent. With the vault closed, it is empty (no
                    // item loaded), hidden by the opaque lock screen, and
                    // receives neither touches nor VoiceOver.
                    MainTabs()
                        .allowsHitTesting(model.lockState == .unlocked)
                        .accessibilityHidden(model.lockState != .unlocked)
                        // The data arrives all at once, without animating
                        // the sections: only the lock screen fades out.
                        .animation(nil, value: model.lockState)
                        .transition(.asymmetric(insertion: .identity, removal: .opacity))
                        .zIndex(0)
                } else if model.needsLogin {
                    LoginView()
                        .transition(.opacity)
                        .zIndex(0)
                }
                if showsLock {
                    LockView(departing: model.lockState == .unlocked || model.opening) { lockOnScreen = false }
                        .onAppear { lockOnScreen = true }
                        .transition(.opacity)
                        // Always above the vault inserted underneath.
                        .zIndex(1)
                }
            }
            .blur(radius: shielded ? 28 : 0)
            if shielded {
                PrivacyCover(opaque: scenePhase == .background)
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.lockState)
        .onChange(of: model.lockState) { _, state in
            switch state {
            case .unlocking: vaultPrepared = true
            case .locked: vaultPrepared = false
            case .unlocked: break
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.needsLogin)
        // Progressive blur toward the app switcher; never when going
        // straight to the background, where the preview is taken at once.
        .animation(scenePhase == .background ? nil : .easeOut(duration: 0.18), value: shielded)
        // Each copy: a success haptic.
        .sensoryFeedback(.success, trigger: model.copies)
        .tint(Theme.accent)
        // Vault open: above the tab bar; otherwise at the top, away from the
        // input fields.
        .overlay(alignment: model.lockState == .unlocked ? .bottom : .top) { ToastHost() }
        .alert(repromptTitle, isPresented: repromptShown, presenting: model.reprompt) { _ in
            RepromptFields()
        } message: { _ in
            Text("Enter your master password to show its secrets.")
        }
    }

    private var repromptTitle: String {
        model.reprompt.map { String(localized: "“\($0.title)” is protected") } ?? ""
    }

    private var repromptShown: Binding<Bool> {
        Binding(get: { model.reprompt != nil },
                set: { if !$0, model.reprompt != nil { Task { await model.answerReprompt(password: nil) } } })
    }
}

/// Field and buttons of the master password prompt.
private struct RepromptFields: View {
    @Environment(PhoneModel.self) private var model
    @State private var password = ""

    var body: some View {
        SecureField("Master password", text: $password)
            .textContentType(.password)
        Button("Confirm") {
            let typed = password
            password = ""
            Task { await model.answerReprompt(password: typed) }
        }
        Button("Cancel", role: .cancel) {
            password = ""
            Task { await model.answerReprompt(password: nil) }
        }
    }
}

/// Screen placed over the app when it leaves the foreground.
struct PrivacyCover: View {
    /// In the background: a solid background, placed without animation, in
    /// case the switcher's preview is taken before the blur finishes.
    var opaque = false

    var body: some View {
        ZStack {
            if opaque {
                Color(.systemBackground)
                    .transition(.identity)
            }
            Rectangle().fill(.regularMaterial)
            VStack(spacing: 14) {
                AppMark(size: 76, glow: false)
                Text("Verrou")
                    .font(.system(.title2, design: .rounded, weight: .bold))
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// The open vault's tabs: Vault, Generator, Settings and Search (iOS 18+:
/// separate search tab, in the glass tab bar on iOS 26, which collapses on
/// scroll).
struct MainTabs: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Group {
            if #available(iOS 18, *) {
                modernTabs
            } else {
                legacyTabs
            }
        }
        .sheet(item: $model.editor) { editor in
            EditItemView(editor: editor)
                .interactiveDismissDisabled(model.editorBusy)
        }
        .sheet(item: $model.qrSheet) { sheet in
            WifiQRSheet(sheet: sheet)
        }
        .sheet(item: itemScan) { flow in
            OTPScanSheet(flow: flow)
        }
        .sheet(item: $model.moveRequest) { request in
            MoveToFolderSheet(request: request)
        }
        .sheet(item: $model.sharedFile, onDismiss: { model.sharedFile.map { Attachments.discard($0.url) } }) { file in
            ShareSheet(url: file.url)
        }
        .quickLookPreview($model.preview)
        .modifier(SharingPresentations())
        .modifier(UnsharePresentation())
        .modifier(FolderPresentations())
    }

    /// QR code sheet opened from an item page (the edit screen presents its
    /// own).
    private var itemScan: Binding<OTPScanFlow?> {
        Binding(get: { model.otpScan?.purpose.isEditor == false ? model.otpScan : nil },
                set: { if $0 == nil { model.otpScan = nil } })
    }

    @available(iOS 18, *)
    private var modernTabs: some View {
        @Bindable var model = model
        return TabView(selection: $model.tab) {
            Tab("Vault", systemImage: "lock.rectangle.stack.fill", value: PhoneModel.Tab.vault) {
                VaultTab()
            }
            Tab("Generator", systemImage: "wand.and.stars", value: PhoneModel.Tab.generator) {
                GeneratorTab()
            }
            Tab("Settings", systemImage: "gearshape.fill", value: PhoneModel.Tab.settings) {
                SettingsTab()
            }
            Tab("Search", systemImage: "magnifyingglass", value: PhoneModel.Tab.search, role: .search) {
                SearchTab()
            }
        }
        .modifier(MinimizingTabBar())
    }

    /// iOS 17: the same tabs, search last.
    private var legacyTabs: some View {
        @Bindable var model = model
        return TabView(selection: $model.tab) {
            VaultTab()
                .tabItem { Label("Vault", systemImage: "lock.rectangle.stack.fill") }
                .tag(PhoneModel.Tab.vault)
            GeneratorTab()
                .tabItem { Label("Generator", systemImage: "wand.and.stars") }
                .tag(PhoneModel.Tab.generator)
            SettingsTab()
                .tabItem { Label("Settings", systemImage: "gearshape.fill") }
                .tag(PhoneModel.Tab.settings)
            SearchTab()
                .tabItem { Label("Search", systemImage: "magnifyingglass") }
                .tag(PhoneModel.Tab.search)
        }
    }
}

/// iOS 26: the tab bar collapses when scrolling down.
private struct MinimizingTabBar: ViewModifier {
    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, *) {
            content.tabBarMinimizeBehavior(.onScrollDown)
        } else {
            content
        }
        #else
        content
        #endif
    }
}

/// Transient notification, above the tab bar.
private struct ToastHost: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        ZStack {
            if let toast = model.toast {
                PhoneToast(toast: toast)
                    .padding(.horizontal, 20)
                    .padding(.bottom, model.lockState == .unlocked ? 92 : 0)
                    .padding(.top, model.lockState == .unlocked ? 0 : 8)
                    .transition(.move(edge: model.lockState == .unlocked ? .bottom : .top).combined(with: .opacity))
                    .onTapGesture { model.toast = nil }
                    .task(id: toast.id) {
                        try? await Task.sleep(for: .seconds(toast.seconds))
                        if model.toast?.id == toast.id { model.toast = nil }
                    }
            }
        }
        .animation(.snappy, value: model.toast)
    }
}

/// The notification, in glass on iOS 26 (blurred material before).
private struct PhoneToast: View {
    let toast: Toast

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: toast.failure ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(toast.failure ? .orange : .green)
                .font(.title2)
                .symbolEffect(.bounce, value: toast.id)
            VStack(alignment: .leading, spacing: 1) {
                Text(toast.message).font(.callout.weight(.semibold))
                if let detail = toast.detail {
                    Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(3)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .glassSurface(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .shadow(color: LiquidGlass.isAvailable ? .clear : .black.opacity(0.15), radius: 12, y: 4)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("toast")
    }
}
