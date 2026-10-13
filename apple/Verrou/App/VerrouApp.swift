import ServiceManagement
import SwiftUI

@main
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
            CommandGroup(replacing: .appSettings) {
                SettingsLink { Text("Réglages…") }
                    .keyboardShortcut(",", modifiers: .command)
            }
            CommandGroup(replacing: .newItem) {
                Button("Nouvel identifiant") { delegate.model.newItem(login: true) }
                    .keyboardShortcut("n", modifiers: .command)
                    .disabled(!delegate.model.canEdit)
                Button("Nouvelle note sécurisée") { delegate.model.newItem(login: false) }
                    .keyboardShortcut("n", modifiers: [.command, .shift])
                    .disabled(!delegate.model.canEdit)
            }
            CommandMenu("Coffre") {
                Button("Accès rapide") { delegate.quickAccess?.toggle() }
                    .keyboardShortcut(.space, modifiers: [.command, .shift])
                Divider()
                Button("Synchroniser") { Task { await delegate.model.syncNow() } }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(delegate.model.lockState != .unlocked || delegate.model.mode == .demo)
                Button("Verrouiller") { delegate.model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .control])
                    .disabled(delegate.model.lockState != .unlocked)
            }
        }

        Settings {
            SettingsView()
                .environment(delegate.model)
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

/// Icône de la barre des menus : cadenas fermé ou ouvert, selon le coffre.
struct MenuBarIcon: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Image(systemName: model.lockState == .unlocked ? "lock.open.fill" : "lock.fill")
            .accessibilityLabel(model.lockState == .unlocked ? "Verrou, déverrouillé" : "Verrou, verrouillé")
    }
}

struct MenuBarMenu: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    let quickAccess: () -> Void

    var body: some View {
        Text(status)
        Divider()
        Button("Accès rapide", action: quickAccess)
            .keyboardShortcut(.space, modifiers: [.command, .shift])
        Button("Ouvrir Verrou", action: showMainWindow)
        Divider()
        if model.lockState == .unlocked {
            if model.mode == .vaultwarden {
                Button("Synchroniser") { Task { await model.syncNow() } }
            }
            Button("Verrouiller") { model.lock() }
        } else {
            // La fenêtre principale demande Touch ID d'elle-même.
            Button("Déverrouiller…", action: showMainWindow)
        }
        Divider()
        SettingsLink { Text("Réglages…") }
        Button("Quitter Verrou") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private var status: String {
        switch model.lockState {
        case .unlocked: model.account.map { "Déverrouillé · \($0.email)" } ?? "Déverrouillé"
        case .unlocking: "Déverrouillage…"
        case .locked: model.needsLogin ? "Non connecté" : "Verrouillé"
        }
    }

    private func showMainWindow() {
        openWindow(id: "main")
        NSApp.activate()
    }
}

/// Ouverture de Verrou à l'ouverture de session (élément de connexion).
enum LaunchAtLogin {
    static var isEnabled: Bool { SMAppService.mainApp.status == .enabled }
    /// macOS attend l'accord de l'utilisateur dans Réglages Système.
    static var needsApproval: Bool { SMAppService.mainApp.status == .requiresApproval }

    static func set(_ enabled: Bool) throws {
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }

    /// Lancé par macOS à l'ouverture de session (et non par l'utilisateur).
    static var launchedAtLogin: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == kAEOpenApplication
            && event.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.lockState == .unlocked {
                MainView()
                    .transition(.opacity.combined(with: .scale(scale: 1.01)))
            } else if model.needsLogin {
                LoginView()
                    .transition(.opacity)
            } else {
                LockView()
                    .transition(.opacity)
            }
        }
        .animation(.smooth(duration: 0.35), value: model.lockState)
        .animation(.smooth(duration: 0.35), value: model.needsLogin)
        .onContinuousHover { _ in model.noteActivity() }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    private(set) var quickAccess: QuickAccessController?
    private var demo: DemoDriver?
    #if DEBUG
    private var endToEnd: EndToEndDriver?
    #endif

    /// À relire avant la fin du lancement : l'événement d'ouverture n'est
    /// plus « courant » ensuite.
    private var launchedAtLogin = false

    func applicationWillFinishLaunching(_ notification: Notification) {
        launchedAtLogin = LaunchAtLogin.launchedAtLogin
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        quickAccess = QuickAccessController(model: model)
        let environment = ProcessInfo.processInfo.environment
        if model.mode == .vaultwarden, environment["VERROU_E2E_SERVER"] == nil {
            let bridge = BrowserBridge(model: model)
            model.browserBridge = bridge
            bridge.apply()
        }
        if launchedAtLogin {
            // Ouverture de session : Verrou attend discrètement, dans la barre
            // des menus et derrière ⌘⇧Espace, sans fenêtre ni Touch ID.
            DispatchQueue.main.async {
                NSApp.windows.filter { $0.identifier?.rawValue == "main" }.forEach { $0.close() }
            }
        }
        if ProcessInfo.processInfo.environment["VERROU_DEMO"] == "1", let quickAccess {
            demo = DemoDriver(model: model, quickAccess: quickAccess)
            demo?.start()
        }
        #if DEBUG
        if let config = EndToEndDriver.Config(ProcessInfo.processInfo.environment) {
            endToEnd = EndToEndDriver(model: model, config: config)
            endToEnd?.start()
        }
        #endif
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) {
        model.lock()
    }
}
