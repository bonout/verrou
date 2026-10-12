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
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Coffre") {
                Button("Accès rapide") { delegate.quickAccess?.toggle() }
                    .keyboardShortcut(.space, modifiers: [.command, .shift])
                Divider()
                Button("Verrouiller") { delegate.model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .control])
                    .disabled(delegate.model.lockState != .unlocked)
            }
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
            } else {
                LockView()
                    .transition(.opacity)
            }
        }
        .animation(.smooth(duration: 0.35), value: model.lockState)
        .onContinuousHover { _ in model.noteActivity() }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    private(set) var quickAccess: QuickAccessController?
    private var demo: DemoDriver?

    func applicationDidFinishLaunching(_ notification: Notification) {
        quickAccess = QuickAccessController(model: model)
        if ProcessInfo.processInfo.environment["VERROU_DEMO"] == "1", let quickAccess {
            demo = DemoDriver(model: model, quickAccess: quickAccess)
            demo?.start()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) {
        model.lock()
    }
}
