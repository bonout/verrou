import ServiceManagement
import SwiftUI

/// Entry point: the app, or (Debug builds, `VERROU_REVIEW=1`) the offscreen
/// visual review, which opens no SwiftUI scene and no window.
@main
enum VerrouMain {
    static func main() {
        #if DEBUG
        if AppModel.isReview {
            MainActor.assumeIsolated { ReviewDriver.run() }
            return
        }
        #endif
        VerrouApp.main()
    }
}

struct VerrouApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true

    var body: some Scene {
        Window("Verrou", id: "main") {
            RootView()
                .environment(delegate.model)
                .frame(minWidth: 900, minHeight: 560)
        }
        .defaultSize(width: 1180, height: 760)
        .windowToolbarStyle(.unified(showsTitle: false))
        .commands {
            CommandGroup(after: .appInfo) {
                if delegate.updates.isAvailable {
                    Button("Check for Updates…") { delegate.updates.check() }
                        .disabled(!delegate.updates.canCheck)
                }
            }
            CommandGroup(replacing: .appSettings) {
                SettingsLink { Text("Settings…") }
                    .keyboardShortcut(",", modifiers: .command)
            }
            CommandGroup(replacing: .newItem) {
                Button("New Login") { delegate.model.newItem(login: true) }
                    .keyboardShortcut("n", modifiers: .command)
                    .disabled(!delegate.model.canEdit)
                Button("New Secure Note") { delegate.model.newItem(login: false) }
                    .keyboardShortcut("n", modifiers: [.command, .shift])
                    .disabled(!delegate.model.canEdit)
                Button("New Document…") { delegate.model.newDocument() }
                    .disabled(!delegate.model.canEdit)
                // ⇧⌘N is the secure note.
                Button("New Folder…") { delegate.model.folderRequest = FolderRequest(kind: .create(parent: nil)) }
                    .keyboardShortcut("n", modifiers: [.command, .option])
                    .disabled(!delegate.model.canEdit)
                Divider()
                Button("Import…") { delegate.model.startImport() }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                    .disabled(!delegate.model.canEdit)
            }
            // The selected item, as in 1Password and Quick Access: ⌘C alone
            // stays the text copy of the fields.
            CommandMenu("Item") {
                let item = delegate.model.isMultiSelection ? nil : delegate.model.selectedSummary
                Button("Copy Username") { if let item { delegate.model.copyUsername(of: item.id) } }
                    .keyboardShortcut("c", modifiers: [.command, .control])
                    .disabled(item?.category != .login || item?.subtitle.isEmpty != false)
                Button("Copy Password") { if let item { delegate.model.copyPassword(of: item.id) } }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
                    .disabled(item?.category != .login)
                Button("Copy One-Time Code") { if let item { delegate.model.copyCode(of: item.id) } }
                    .keyboardShortcut("c", modifiers: [.command, .option])
                    .disabled(item?.hasTotp != true)
                Button("Copy Website") { if let item { delegate.model.copyWebsite(of: item.id) } }
                    .keyboardShortcut("c", modifiers: [.command, .option, .shift])
                    .disabled(item?.host == nil)
                Divider()
                Text("Hold ⌥ to show the hidden fields")
            }
            CommandMenu("Vault") {
                Button("Quick Access") { delegate.quickAccess?.toggle() }
                    .keyboardShortcut(.space, modifiers: [.command, .shift])
                Divider()
                Button("Sync") { Task { await delegate.model.syncNow() } }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(delegate.model.lockState != .unlocked || delegate.model.mode == .demo)
                Button("Clean Up Duplicates…") { delegate.model.openDuplicates() }
                    .disabled(delegate.model.lockState != .unlocked)
                // Panes of the main window, as in the sidebar.
                Divider()
                Button("Security Audit") {
                    delegate.model.showMainWindow()
                    delegate.model.openAudit()
                }
                .disabled(delegate.model.lockState != .unlocked)
                if delegate.model.mode == .vaultwarden {
                    Button("Sends") { delegate.model.openSends() }
                        .disabled(!delegate.model.sendsAvailable)
                    Button("New Send…") {
                        delegate.model.showMainWindow()
                        delegate.model.newSend()
                    }
                    .disabled(!delegate.model.sendsAvailable)
                    Button("New File Send…") {
                        delegate.model.showMainWindow()
                        delegate.model.newFileSend()
                    }
                    .disabled(!delegate.model.sendsAvailable)
                    Button("Emergency Access") { delegate.model.openEmergency() }
                        .disabled(!delegate.model.emergencyAvailable)
                    Divider()
                    Button("New Organization…") {
                        delegate.model.showMainWindow()
                        delegate.model.openNewOrganization()
                    }
                    .disabled(!delegate.model.canEdit)
                    Button("Join an Organization…") {
                        delegate.model.showMainWindow()
                        delegate.model.openJoin()
                    }
                    .disabled(!delegate.model.canEdit)
                }
                Divider()
                Button("Lock") { delegate.model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .control])
                    .disabled(delegate.model.lockState != .unlocked)
            }
        }

        Settings {
            SettingsView()
                .environment(delegate.model)
                .environment(delegate.updates)
        }

        MenuBarExtra(isInserted: $showMenuBarExtra) {
            MenuBarMenu(quickAccess: { delegate.quickAccess?.show() })
                .environment(delegate.model)
        } label: {
            MenuBarIcon()
                .environment(delegate.model)
        }
    }
}

/// Menu bar icon: padlock closed or open, depending on the vault.
struct MenuBarIcon: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Image(systemName: model.lockState == .unlocked ? "lock.open.fill" : "lock.fill")
            .accessibilityLabel(model.lockState == .unlocked ? "Verrou, unlocked" : "Verrou, locked")
    }
}

struct MenuBarMenu: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    let quickAccess: () -> Void

    var body: some View {
        Text(status)
        Divider()
        Button("Quick Access", action: quickAccess)
            .keyboardShortcut(.space, modifiers: [.command, .shift])
        Button("Open Verrou", action: showMainWindow)
        Divider()
        if model.lockState == .unlocked {
            if model.mode == .vaultwarden {
                Button("Sync") { Task { await model.syncNow() } }
            }
            Button("Lock") { model.lock() }
        } else {
            // The main window asks for Touch ID by itself.
            Button("Unlock…", action: showMainWindow)
        }
        Divider()
        SettingsLink { Text("Settings…") }
        Button("Quit Verrou") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private var status: String {
        switch model.lockState {
        case .unlocked: model.account.map { String(localized: "Unlocked · \($0.email)") } ?? String(localized: "Unlocked")
        case .unlocking: String(localized: "Unlocking…")
        case .locked: model.needsLogin ? String(localized: "Not logged in") : String(localized: "Locked")
        }
    }

    private func showMainWindow() {
        openWindow(id: "main")
        NSApp.activate()
    }
}

/// Opening Verrou at login (login item).
enum LaunchAtLogin {
    static var isEnabled: Bool { SMAppService.mainApp.status == .enabled }
    /// macOS waits for the user's approval in System Settings.
    static var needsApproval: Bool { SMAppService.mainApp.status == .requiresApproval }

    static func set(_ enabled: Bool) throws {
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }

    /// Launched by macOS at login (and not by the user).
    static var launchedAtLogin: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == kAEOpenApplication
            && event.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model
    /// The vault window is built once, behind the lock screen (empty:
    /// locking clears everything it displays), and kept: unlocking reveals
    /// it instead of rebuilding it. It is built right after the lock screen
    /// first shows, while Touch ID waits for the finger.
    @State private var vaultMounted = false

    private var unlocked: Bool { model.lockState == .unlocked }

    var body: some View {
        ZStack {
            if vaultMounted || unlocked {
                MainView()
                    .opacity(unlocked ? 1 : 0)
                    .allowsHitTesting(unlocked)
                    .accessibilityHidden(!unlocked)
            }
            if !unlocked {
                Group {
                    if model.needsLogin {
                        LoginView()
                    } else {
                        LockView()
                    }
                }
                .transition(.opacity)
                .onAppear {
                    DispatchQueue.main.async { vaultMounted = true }
                }
            }
        }
        .toolbar(unlocked ? .automatic : .hidden, for: .windowToolbar)
        .animation(.easeOut(duration: 0.15), value: model.lockState)
        .animation(.easeOut(duration: 0.15), value: model.needsLogin)
        .onContinuousHover { _ in model.noteActivity() }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    let updates = Updates()
    private(set) var quickAccess: QuickAccessController?
    /// Filling in apps (⌘\), through quick access.
    private(set) var autofill: UniversalAutofill?
    private var demo: DemoDriver?
    #if DEBUG
    private var endToEnd: EndToEndDriver?
    #endif
    #if DEBUG || BENCH
    private var bench: BenchDriver?
    #endif

    /// To read before launch finishes: the open event is no longer
    /// "current" afterwards.
    private var launchedAtLogin = false

    func applicationWillFinishLaunching(_ notification: Notification) {
        launchedAtLogin = LaunchAtLogin.launchedAtLogin
        // Sharing notifications: before launch finishes, to receive the tap
        // that launched the app. Nothing real in the demo or during a test
        // run.
        let environment = ProcessInfo.processInfo.environment
        let notifier = ActivityNotifier.shared
        notifier.silent = model.mode != .vaultwarden || environment["VERROU_E2E_SERVER"] != nil
        notifier.install()
        notifier.setHandler { [weak model] route in model?.openActivity(route) }
        // Button tooltips (toolbar, icons) after 0.3 s instead of about a
        // second: hovering responds right away.
        UserDefaults.standard.register(defaults: ["NSInitialToolTipDelay": 300])
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Diagnostics.shared.start()
        let quickAccess = QuickAccessController(model: model)
        self.quickAccess = quickAccess
        autofill = UniversalAutofill(model: model, quickAccess: quickAccess)
        quickAccess.autofill = autofill
        let environment = ProcessInfo.processInfo.environment
        if model.mode == .vaultwarden, environment["VERROU_E2E_SERVER"] == nil {
            let bridge = BrowserBridge(model: model)
            model.browserBridge = bridge
            bridge.apply()
        }
        if launchedAtLogin {
            // Login: Verrou waits quietly, in the menu bar and behind ⌘⇧Space,
            // with no window and no Touch ID.
            DispatchQueue.main.async {
                NSApp.windows.filter { $0.identifier?.rawValue == "main" }.forEach { $0.close() }
            }
        }
        if ProcessInfo.processInfo.environment["VERROU_DEMO"] == "1" {
            demo = DemoDriver(model: model, quickAccess: quickAccess)
            demo?.start()
        }
        #if DEBUG
        if let config = EndToEndDriver.Config(ProcessInfo.processInfo.environment) {
            endToEnd = EndToEndDriver(model: model, config: config)
            endToEnd?.start()
        }
        #endif
        #if DEBUG || BENCH
        if environment["VERROU_BENCH"] == "1" {
            bench = BenchDriver(model: model)
            bench?.start()
        }
        #endif
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// An answer from the iPhone (silent iCloud notification): read it
    /// without waiting for the next poll.
    func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
        if RemoteCloud.isApproval(userInfo) { model.remote?.poke() }
    }

    func applicationWillTerminate(_ notification: Notification) {
        model.lock()
    }
}
