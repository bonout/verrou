import AppKit
import SwiftUI

/// Scripted demo (`VERROU_DEMO=1`) for the screenshots and the PR video:
/// replays a realistic walk without touching the keyboard.
///
/// The app captures its own windows through ScreenCaptureKit (`WindowSnapshot`,
/// `WindowRecorder`) in its temporary folder, which it announces with `DEMO_OUT <path>`;
/// `scripts/demo-capture.sh` collects them. Unlocking simulates Touch ID:
/// the mock vault has nothing to protect.
@MainActor
final class DemoDriver {
    private let model: AppModel
    /// Language of the mock vault's words (titles).
    private let language = MockLanguage.current
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
        guard let image = recorder?.snapshot() else { fail("capture \(name): no image received") }
        do {
            try WindowSnapshot.writePNG(image, to: output.appending(path: "\(name).png"))
        } catch {
            fail("capture \(name): \(error.localizedDescription)")
        }
        print("DEMO_SNAP \(name)")
        fflush(stdout)
        await pause(1.0)
    }

    /// The script waits for `DEMO_DONE`: without it, it shows this log and fails.
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
        if let hit = model.results.first(where: { model.summary(for: $0)?.title == title }) {
            withAnimation(.snappy) { model.selection = hit.id }
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
                // Without the "Screen Recording" permission, no point going further.
                fail("recording: \(error.localizedDescription)")
            }
        }
        await pause(1.5)
        await snap("01-locked")

        withAnimation { model.openVault() }
        await pause(1.0)
        select(title: "GitHub")
        await pause(0.6)
        await snap("02-vault")

        await type("git", into: \.query)
        await pause(0.4)
        await snap("03-search")
        select(title: "GitHub")
        await pause(0.8)
        model.toggleReveal("password", of: model.selection ?? "")
        await pause(0.6)
        await snap("04-login-revealed")
        model.copyPassword(of: model.selection ?? "")
        await pause(1.4)

        model.query = ""
        await pause(0.3)
        // Without accents nor capitals (French), or a partial name (English).
        await type(language.pick("bank of am", "societe gen"), into: \.query)
        await pause(0.5)
        select(title: language.pick("Bank of America", "Société Générale"))
        await snap("05-search-accents")

        model.query = ""
        model.filter = .category(category: .card)
        await pause(0.5)
        select(title: language.pick("Chase Visa", "Visa Boursorama"))
        await pause(0.5)
        if let id = model.selection {
            model.toggleReveal("number", of: id)
            model.toggleReveal("code", of: id)
        }
        await pause(0.4)
        await snap("06-card")

        model.filter = .category(category: .identity)
        await pause(0.4)
        select(title: language.pick("Emily Parker", "Camille Martin"))
        await pause(0.5)
        await snap("07-identity")

        // Wi-Fi template: predefined fields.
        model.filter = .template(template: .wifi)
        await pause(0.4)
        select(title: language.pick("Home Wi-Fi", "Wi-Fi maison"))
        await pause(0.6)
        await snap("08-wifi")

        // The family's shared vault (Vaultwarden organization).
        model.filter = .all
        await pause(0.3)
        await type(language.pick("family", "famille"), into: \.query)
        await pause(0.4)
        select(title: language.pick("Google — family", "Google — famille"))
        await pause(0.6)
        await snap("09-shared-vault")
        model.query = ""

        // Security audit, in the main window.
        withAnimation(.snappy) { model.openAudit() }
        await pause(1.2)
        await snap("10-audit")

        model.filter = .all
        await pause(0.3)
        quickAccess.show(anchor: NSApp.windows.first { $0.identifier?.rawValue == "main" }?.frame)
        await pause(0.6)
        await type("net", into: \.quickQuery)
        await pause(0.6)
        await snap("11-quick-access")
        model.quickQuery = ""
        await type("cloud", into: \.quickQuery)
        await pause(0.8)
        await snap("12-quick-access-code")
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
