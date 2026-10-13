import SwiftUI

@main
struct VerrouApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

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
            CommandGroup(replacing: .newItem) {}
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

    func applicationDidFinishLaunching(_ notification: Notification) {
        quickAccess = QuickAccessController(model: model)
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
