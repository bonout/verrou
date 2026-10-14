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
                Button("Nouveau document…") { delegate.model.newDocument() }
                    .disabled(!delegate.model.canEdit)
                Divider()
                Button("Importer…") { delegate.model.startImport() }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                    .disabled(!delegate.model.canEdit)
            }
            CommandMenu("Coffre") {
                Button("Accès rapide") { delegate.quickAccess?.toggle() }
                    .keyboardShortcut(.space, modifiers: [.command, .shift])
                Divider()
                Button("Synchroniser") { Task { await delegate.model.syncNow() } }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(delegate.model.lockState != .unlocked || delegate.model.mode == .demo)
                Button("Nettoyer les doublons…") { delegate.model.openDuplicates() }
                    .disabled(delegate.model.lockState != .unlocked)
                Button("Verrouiller") { delegate.model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .control])
                    .disabled(delegate.model.lockState != .unlocked)
            }
        }

        // Accès d'urgence : fenêtre à part, ouverte depuis la barre latérale.
        Window("Accès d'urgence", id: "emergency") {
            EmergencyWindow()
                .environment(delegate.model)
        }
        .defaultSize(width: 720, height: 560)

        // Envois (Bitwarden Send) : fenêtre à part, ouverte depuis la barre latérale.
        Window("Envois", id: "sends") {
            SendsWindow()
                .environment(delegate.model)
        }
        .defaultSize(width: 640, height: 520)

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
    /// La fenêtre du coffre est construite une fois, derrière l'écran
    /// verrouillé (vide : le verrouillage efface tout ce qu'elle affiche), et
    /// gardée : déverrouiller la découvre au lieu de la reconstruire. Elle
    /// se construit juste après le premier affichage de l'écran verrouillé,
    /// pendant que Touch ID attend le doigt.
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
    private(set) var quickAccess: QuickAccessController?
    /// Remplissage dans les apps (⌘\), à travers l'accès rapide.
    private(set) var autofill: UniversalAutofill?
    private var demo: DemoDriver?
    #if DEBUG
    private var endToEnd: EndToEndDriver?
    #endif
    #if DEBUG || BENCH
    private var bench: BenchDriver?
    #endif

    /// À relire avant la fin du lancement : l'événement d'ouverture n'est
    /// plus « courant » ensuite.
    private var launchedAtLogin = false

    func applicationWillFinishLaunching(_ notification: Notification) {
        launchedAtLogin = LaunchAtLogin.launchedAtLogin
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
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
            // Ouverture de session : Verrou attend discrètement, dans la barre
            // des menus et derrière ⌘⇧Espace, sans fenêtre ni Touch ID.
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

    func applicationWillTerminate(_ notification: Notification) {
        model.lock()
    }
}
