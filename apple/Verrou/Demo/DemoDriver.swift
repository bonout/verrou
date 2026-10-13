import AppKit
import SwiftUI

/// Démonstration scriptée (`VERROU_DEMO=1`) pour les captures d'écran et la
/// vidéo de la PR : rejoue un parcours réaliste sans toucher au clavier.
///
/// L'app capture ses propres fenêtres par ScreenCaptureKit (`WindowSnapshot`,
/// `WindowRecorder`) dans son dossier temporaire, qu'elle annonce par `DEMO_OUT <chemin>` ;
/// `scripts/demo-capture.sh` les récupère. Le déverrouillage simule Touch ID :
/// le coffre fictif n'a rien à protéger.
@MainActor
final class DemoDriver {
    private let model: AppModel
    private let quickAccess: QuickAccessController
    private let output = FileManager.default.temporaryDirectory.appending(path: "verrou-demo")
    private var recorder: WindowRecorder?
    private var mainWindow: NSWindow? {
        NSApp.windows.first { $0.identifier?.rawValue == "main" } ?? NSApp.windows.first { $0.isVisible && !($0 is NSPanel) }
    }

    init(model: AppModel, quickAccess: QuickAccessController) {
        self.model = model
        self.quickAccess = quickAccess
        quickAccess.staysOpen = true
    }

    func start() {
        Task { await run() }
    }

    private func pause(_ seconds: Double) async {
        try? await Task.sleep(for: .seconds(seconds))
    }

    private func snap(_ name: String) async {
        await pause(0.25)
        guard let image = recorder?.snapshot() else { fail("capture \(name) : aucune image reçue") }
        do {
            try WindowSnapshot.writePNG(image, to: output.appending(path: "\(name).png"))
        } catch {
            fail("capture \(name) : \(error.localizedDescription)")
        }
        print("DEMO_SNAP \(name)")
        fflush(stdout)
        await pause(1.0)
    }

    /// Le script attend `DEMO_DONE` : sans lui, il affiche ce journal et échoue.
    private func fail(_ message: String) -> Never {
        print("DEMO_ERROR \(message)")
        fflush(stdout)
        exit(1)
    }

    private func type(_ text: String, into keyPath: ReferenceWritableKeyPath<AppModel, String>) async {
        for character in text {
            model[keyPath: keyPath].append(character)
            await pause(0.16)
        }
    }

    private func select(title: String) {
        if let hit = model.results.first(where: { model.summary(for: $0).title == title }) {
            withAnimation(.snappy) { model.selection = model.summary(for: hit).id }
        }
    }

    private func run() async {
        await pause(1.0)
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == "main" }) ?? NSApp.windows.first {
            window.setFrame(NSRect(x: 120, y: 120, width: 1280, height: 800), display: true, animate: false)
            window.identifier = NSUserInterfaceItemIdentifier("main")
            window.makeKeyAndOrderFront(nil)
        }
        NSApp.activate()
        try? FileManager.default.removeItem(at: output)
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        print("DEMO_OUT \(output.path)")
        fflush(stdout)
        await pause(0.5)
        if let main = mainWindow {
            do {
                let recorder = try await WindowRecorder(url: output.appending(path: "demo.mov"), main: main)
                try await recorder.start()
                self.recorder = recorder
            } catch {
                // Sans l'autorisation « Enregistrement de l'écran », inutile d'aller plus loin.
                fail("enregistrement : \(error.localizedDescription)")
            }
        }
        await pause(1.5)
        await snap("01-verrouille")

        withAnimation { model.openVault() }
        await pause(1.0)
        select(title: "GitHub")
        await pause(0.6)
        await snap("02-coffre")

        await type("git", into: \.query)
        await pause(0.4)
        await snap("03-recherche")
        select(title: "GitHub")
        await pause(0.8)
        model.toggleReveal("password", of: model.selection ?? "")
        await pause(0.6)
        await snap("04-identifiant-revele")
        model.copyPassword(of: model.selection ?? "")
        await pause(1.4)

        model.query = ""
        await pause(0.3)
        await type("societe gen", into: \.query)
        await pause(0.5)
        select(title: "Société Générale")
        await snap("05-recherche-accents")

        model.query = ""
        model.filter = .category(category: .card)
        await pause(0.5)
        select(title: "Visa Boursorama")
        await pause(0.5)
        if let id = model.selection {
            model.toggleReveal("number", of: id)
            model.toggleReveal("code", of: id)
        }
        await pause(0.4)
        await snap("06-carte")

        model.filter = .category(category: .identity)
        await pause(0.4)
        select(title: "Camille Martin")
        await pause(0.5)
        await snap("07-identite")

        model.filter = .all
        await pause(0.3)
        quickAccess.show(anchor: NSApp.windows.first { $0.identifier?.rawValue == "main" }?.frame)
        await pause(0.6)
        await type("net", into: \.quickQuery)
        await pause(0.6)
        await snap("08-acces-rapide")
        model.quickQuery = ""
        await type("cloud", into: \.quickQuery)
        await pause(0.8)
        await snap("09-acces-rapide-code")
        quickAccess.close()
        await pause(0.8)

        model.lock()
        await pause(1.2)
        await recorder?.finish()
        print("DEMO_DONE")
        fflush(stdout)
        await pause(0.5)
        NSApp.terminate(nil)
    }
}
