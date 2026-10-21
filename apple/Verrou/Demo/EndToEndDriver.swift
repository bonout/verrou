#if DEBUG
import AppKit
import CryptoKit
import SwiftUI

/// End-to-end walk against a test Vaultwarden (Debug builds only): login,
/// TOTP second factor, vault, lock, offline unlock, logout. Launched by
/// `scripts/e2e.sh` with `VERROU_E2E_SERVER`, `_EMAIL`, `_PASSWORD` and
/// `_TOTP` (seed).
///
/// Announces `E2E_OUT <folder>` (captures), `E2E_OK <step>` at each check,
/// then `E2E_DONE` or `E2E_FAIL <reason>`.
@MainActor
final class EndToEndDriver {
    struct Config {
        let server: String
        let email: String
        let password: String
        let totpSecret: String

        init?(_ environment: [String: String]) {
            guard let server = environment["VERROU_E2E_SERVER"], let email = environment["VERROU_E2E_EMAIL"],
                  let password = environment["VERROU_E2E_PASSWORD"], let secret = environment["VERROU_E2E_TOTP"]
            else { return nil }
            self.server = server
            self.email = email
            self.password = password
            totpSecret = secret
        }
    }

    private let model: AppModel
    private let config: Config
    private let output = FileManager.default.temporaryDirectory.appending(path: "verrou-e2e")
    private var recorder: WindowRecorder?

    init(model: AppModel, config: Config) {
        self.model = model
        self.config = config
    }

    func start() {
        Task {
            await run()
            NSApp.terminate(nil)
        }
    }

    private func log(_ line: String) {
        print(line)
        fflush(stdout)
    }

    private func check(_ condition: Bool, _ step: String) {
        if condition {
            log("E2E_OK \(step)")
        } else {
            log("E2E_FAIL \(step)")
            exit(1)
        }
    }

    private static let windowSize = NSSize(width: 1280, height: 800)
    /// The main window, remembered at the start of the walk.
    private weak var mainWindow: NSWindow?
    /// Screens whose layout failed: the walk goes on (to report them all),
    /// but doesn't end with `E2E_DONE`.
    private var layoutFailures = 0

    private func layoutResult(_ screen: String, _ problems: [String]) {
        if problems.isEmpty {
            log("E2E_OK layout: \(screen)")
        } else {
            layoutFailures += 1
            log("E2E_FAIL broken layout: \(screen) — " + problems.joined(separator: "; "))
        }
    }

    /// Layout audit (`LayoutAudit`, without screenshot) of the main window:
    /// views inside the window, `columns` non-empty columns, `identifiers`
    /// markers fully visible; and, if `sheet`, of the sheet attached to it
    /// (`sheet` markers, not taller than the window).
    private func checkLayout(_ screen: String, _ identifiers: [String], columns: Int = 3,
                             sheet: [String]? = nil) async {
        try? await Task.sleep(for: .seconds(0.8))
        guard let window = mainWindow, window.isVisible else {
            layoutFailures += 1
            log("E2E_FAIL \(screen): main window not found (closed during the walk?), layout not checked")
            return
        }
        var problems = LayoutAudit.problems(in: window, .init(identifiers: identifiers, columns: columns,
                                                              size: Self.windowSize))
        if let sheet {
            guard let attached = window.attachedSheet else {
                layoutFailures += 1
                log("E2E_FAIL \(screen): sheet not found (not open, or already closed), layout not checked")
                return
            }
            problems += LayoutAudit.problems(in: attached, .init(identifiers: sheet,
                                                                 maxHeight: window.contentLayoutRect.height))
                .map { "sheet: \($0)" }
        }
        layoutResult(screen, problems)
    }

    /// Settings (`Settings` scene): opened through their entry in the app
    /// menu, each tab audited, then closed. The displayed tab is a preference
    /// (`settingsTab`): put back as before.
    private func checkSettings() async {
        guard let menu = NSApp.mainMenu?.items.first?.submenu,
              let index = menu.items.firstIndex(where: { $0.keyEquivalent == "," }) else {
            log("E2E_SKIP settings: \"Settings…\" entry not found in the app menu")
            return
        }
        let before = Set(NSApp.windows.map(ObjectIdentifier.init))
        menu.performActionForItem(at: index)
        var settings: NSWindow?
        for _ in 0..<30 where settings == nil {
            try? await Task.sleep(for: .milliseconds(100))
            settings = NSApp.windows.first {
                $0.isVisible && !before.contains(ObjectIdentifier($0)) && !($0 is NSPanel) && $0 !== mainWindow
            }
        }
        guard let settings else {
            log("E2E_SKIP settings: the window didn't open (Settings scene not drivable)")
            return
        }
        let saved = UserDefaults.standard.string(forKey: "settingsTab")
        let limit = (settings.screen ?? NSScreen.main)?.visibleFrame.height
        for tab in [SettingsTab.general, .security, .account, .integrations] {
            UserDefaults.standard.set(tab.rawValue, forKey: "settingsTab")
            try? await Task.sleep(for: .seconds(0.8))
            layoutResult("settings, tab \(tab.rawValue)",
                         LayoutAudit.problems(in: settings, .init(maxHeight: limit)))
        }
        if let saved {
            UserDefaults.standard.set(saved, forKey: "settingsTab")
        } else {
            UserDefaults.standard.removeObject(forKey: "settingsTab")
        }
        settings.close()
    }

    private func snap(_ name: String) async {
        try? await Task.sleep(for: .seconds(0.6))
        if let image = recorder?.snapshot() {
            try? WindowSnapshot.writePNG(image, to: output.appending(path: "\(name).png"))
        }
    }

    private func run() async {
        try? await Task.sleep(for: .seconds(1))
        let window = NSApp.windows.first { !($0 is NSPanel) && $0.canBecomeMain }
        mainWindow = window
        window?.setFrame(NSRect(origin: NSPoint(x: 120, y: 120), size: Self.windowSize), display: true, animate: false)
        try? FileManager.default.removeItem(at: output)
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        log("E2E_OUT \(output.path)")
        if let window {
            do {
                let recorder = try await WindowRecorder(url: output.appending(path: "e2e.mov"), main: window)
                try await recorder.start()
                self.recorder = recorder
            } catch {
                // The checks don't depend on the captures: carry on.
                log("E2E_WARN captures unavailable: \(error.localizedDescription)")
            }
        }

        check(model.needsLogin, "login screen without an account")
        model.loginServer = config.server
        model.loginEmail = config.email
        await checkLayout("login screen", ["login-title"], columns: 0)
        await snap("20-login")

        await model.signIn(password: "not the right password")
        check(model.loginError == ErrorText.describe(VerrouError.WrongPassword)
              || model.loginError?.range(of: "incorrect", options: .caseInsensitive) != nil,
              "wrong password rejected")

        await model.signIn(password: config.password)
        check(model.twoFactorOptions == [.authenticator], "second factor requested")
        await checkLayout("second factor", ["login-title"], columns: 0)
        await snap("21-second-factor")

        await model.answerTwoFactor(.authenticator, token: "000000")
        check(model.loginError != nil && model.lockState != .unlocked, "wrong code rejected")
        // The code of the current period may already have been used: also
        // try the next one, which the server tolerates.
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0] where model.lockState != .unlocked {
            await model.answerTwoFactor(.authenticator, token: Self.totp(config.totpSecret, at: now + offset))
        }
        check(model.lockState == .unlocked, "vault open after the second factor")
        check(model.counts?.all == 9 && model.counts?.trashed == 1,
              "9 items decrypted, 1 in the trash (\(model.counts?.all ?? 0), \(model.counts?.trashed ?? 0))")
        check(model.counts?.folders.map(\.name).sorted() == ["Personnel", "Travail"], "folders decrypted")
        check(model.biometricEnrolled == Biometrics.isAvailable, "Touch ID enrolled if available")

        if let github = model.summaries.first(where: { $0.title == "GitHub" }) {
            model.selection = github.id
            model.toggleReveal("password", of: github.id)
            check(model.revealed["password"] == "hunter2-hunter2", "password revealed")
        }
        if let github = model.summaries.first(where: { $0.title == "GitHub" }), let host = github.host {
            _ = model.siteIcons.image(for: host)
            for _ in 0..<100 where model.siteIcons.images[SiteIcons.site(of: host)] == nil {
                try? await Task.sleep(for: .milliseconds(100))
            }
            check(model.siteIcons.images[SiteIcons.site(of: host)] != nil, "site icon served by Vaultwarden")
        }
        await checkLayout("list and selected detail", ["search", "detail-title", "sidebar-footer"])
        await snap("22-vaultwarden-vault")

        await model.syncNow()
        check(model.syncState == .idle, "sync with the refresh token")

        // Audit: computed on the vault, without network.
        model.openAudit()
        check(model.showAudit && (model.audit?.checked ?? 0) >= 5, "vault audit (\(model.audit?.checked ?? 0) passwords)")
        await checkLayout("audit pane", ["pane-title", "sidebar-footer", "detail-title"])
        await snap("23-audit")
        model.filter = .all
        check(!model.showAudit, "back to the list")

        // Sends and emergency access: panes of the main window.
        model.openSends()
        await model.reloadSends()
        check(model.pane == .sends && model.sends.loaded, "sends pane")
        await checkLayout("sends pane", ["pane-title", "sidebar-footer"])
        await snap("25-sends")
        model.openEmergency()
        await model.reloadEmergency()
        check(model.pane == .emergency && model.emergency.loaded, "emergency access pane")
        await checkLayout("emergency access pane", ["pane-title", "sidebar-footer"])
        await snap("26-emergency")
        model.filter = .all
        check(model.pane == nil, "back to the list")

        // Writing: create, edit, move to the trash.
        model.newItem(login: true)
        let generated = model.editor?.draft.login?.password ?? ""
        check(generated.count == 20, "new login with a generated password")
        if var draft = model.editor?.draft {
            draft.name = "Créé par Verrou"
            draft.login?.username = "e2e@verrou.test"
            draft.login?.urls = ["https://exemple.fr"]
            await model.saveEditor(draft)
        }
        let created = model.summaries.first { $0.title == "Créé par Verrou" }
        check(model.editor == nil && created != nil && model.selection == created?.id, "item created on the server")
        if let created {
            // Created offline then sent: the temporary ID becomes the server's.
            let id = { [model] in model.session.resolveItemId(id: created.id) }
            await model.edit(id())
            check(model.editor?.draft.login?.password == generated, "draft prefilled, secrets included")
            await checkLayout("edit sheet", [], sheet: ["edit-title", "sheet-primary"])
            await snap("24-edit")
            if var draft = model.editor?.draft {
                draft.name = "Modifié par Verrou"
                draft.login?.password = "nouveau-mot-de-passe"
                await model.saveEditor(draft)
            }
            check(model.reveal("password", of: id()) == "nouveau-mot-de-passe"
                  && model.summaries.contains { $0.title == "Modifié par Verrou" },
                  "edit saved")
            await model.trash(id())
            let state = { [model] in model.summaries.first { $0.id == id() }?.state }
            check(state() == .trashed && model.counts?.all == 9, "moved to the trash")
            model.filter = .trash
            check(model.rows.contains { $0.id == id() }, "visible in the trash")
            await model.restore(id())
            check(state() == .active, "restored")
            // Vaultwarden rejects a change dated the same second.
            try? await Task.sleep(for: .seconds(1.5))
            await model.setArchived(id(), true)
            model.filter = .all
            check(state() == .archived && !model.rows.contains { $0.id == id() }, "archived, out of the list")
            await model.setArchived(id(), false)
            try? await Task.sleep(for: .seconds(1.5))
            await model.setFavorite(id(), true)
            check(state() == .active && model.summaries.first { $0.id == id() }?.favorite == true,
                  "unarchived, made a favorite")
            check(model.selectedDetail?.fields.contains { $0.id.hasPrefix("history-") } ?? false
                  || model.selection != id(), "password history")
            await sharing(id())
            await model.trash(id())
        }

        // Duplicates and import sheets, then the settings.
        model.openDuplicates()
        await checkLayout("duplicates sheet", [], sheet: ["sheet-title", "sheet-primary"])
        model.duplicatesFlow = nil
        let export = FileManager.default.temporaryDirectory.appending(path: "verrou-e2e-export.csv")
        try? "Title,URL,Username,Password,Notes,OTPAuth\nMastodon,https://mastodon.social,camille,correct-cheval-pile,,\n"
            .write(to: export, atomically: true, encoding: .utf8)
        let flow = ImportFlow(url: export)
        model.importFlow = flow
        await model.readImport(flow)
        check(flow.review != nil, "review of an import (nothing is imported)")
        await checkLayout("import sheet", [], sheet: ["sheet-title", "sheet-primary"])
        model.closeImport()
        try? FileManager.default.removeItem(at: export)
        try? await Task.sleep(for: .seconds(0.6))
        await checkSettings()
        mainWindow?.makeKeyAndOrderFront(nil)

        // Bridge to Brave, on a test port: TCP listening and writing of the
        // Native Messaging declarations, under the app's sandbox.
        if ProcessInfo.processInfo.environment["VERROU_BRIDGE_PORT"] != nil {
            let bridge = BrowserBridge(model: model)
            model.browserBridge = bridge
            bridge.enabled = true
            check(bridge.running && bridge.error == nil, "bridge to Brave listening in the sandbox (\(bridge.error ?? "ok"))")
            bridge.enabled = false
            check(!bridge.running, "bridge stopped")
        }

        model.lock()
        check(model.lockState == .locked && !model.needsLogin, "locked, account kept")
        check(model.pane == nil && !model.sends.loaded && model.emergency.selection == nil,
              "panes and sends forgotten on lock")
        await checkLayout("lock screen", ["lock-title"], columns: 0)
        await snap("23-locked")

        await model.unlock(masterPassword: "wrong")
        check(model.unlockError == ErrorText.describe(VerrouError.WrongPassword), "wrong password on unlock")
        await model.unlock(masterPassword: config.password)
        check(model.lockState == .unlocked && model.counts?.all == 9, "offline unlock with the password")

        model.logout()
        check(model.needsLogin && !model.biometricEnrolled && model.account == nil, "logout")
        await recorder?.finish()
        if layoutFailures > 0 {
            log("E2E_FAIL broken layout on \(layoutFailures) screen(s), see above")
            exit(1)
        }
        log("E2E_DONE")
    }

    /// Shared vaults: create an organization, share the item in it, create
    /// then delete a collection, open "Join".
    private func sharing(_ itemID: String) async {
        if model.organizations.isEmpty {
            model.openNewOrganization()
            await checkLayout("\"New Organization\" sheet", [], sheet: ["sheet-title", "sheet-primary"])
            await model.createOrganization(name: "Famille E2E", collection: "Général")
        }
        check(model.organizationAdmin.error == nil && model.organizationAdmin.sheet == nil
              && model.organizations.first?.isOwner == true,
              "organization created, owner (\(model.organizationAdmin.error ?? "ok"))")
        guard let org = model.organizations.first else { return }
        await snap("27-organization")
        model.selection = itemID
        model.openSharing(itemID)
        check(model.sharingFlow != nil, "\"Share\" sheet")
        await checkLayout("\"Share\" sheet", [], sheet: ["sheet-title", "sheet-primary"])
        if let flow = model.sharingFlow { await model.applySharing(flow) }
        check(model.sharingFlow == nil && model.summaries.first { $0.id == itemID }?.sharing?.organizationId == org.id,
              "item shared in the organization")
        model.openCollectionEditor(org, collection: nil)
        await checkLayout("\"New Collection\" sheet", [], sheet: ["sheet-title", "sheet-primary"])
        if case .collection(var draft) = model.organizationAdmin.sheet {
            draft.name = "Banque E2E"
            await model.saveCollection(draft)
        }
        let banque = model.organizations.first?.collections.first { $0.name == "Banque E2E" }
        check(banque != nil && model.organizationAdmin.sheet == nil, "collection created, encrypted name read back")
        if let banque, let org = model.organizations.first {
            await model.deleteCollection(CollectionTarget(organization: org, collection: banque))
            check(model.organizations.first?.collections.contains { $0.name == "Banque E2E" } == false,
                  "collection deleted")
        }
        model.openJoin()
        await checkLayout("\"Join an Organization\" sheet", [], sheet: ["sheet-title", "sheet-primary"])
        model.organizationAdmin.sheet = nil
        model.filter = .all
        model.selection = itemID
        try? await Task.sleep(for: .seconds(1.5))
    }

    /// RFC 6238 (SHA-1, 6 digits, 30 s), to answer the second factor.
    static func totp(_ secret: String, at time: TimeInterval) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, value = 0
        var key = Data()
        for character in secret.uppercased() where character != "=" {
            guard let index = alphabet.firstIndex(of: character) else { continue }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                key.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        var counter = UInt64(time / 30).bigEndian
        let message = Data(bytes: &counter, count: 8)
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        let offset = Int(mac[19] & 0x0F)
        let code = (UInt32(mac[offset] & 0x7F) << 24 | UInt32(mac[offset + 1]) << 16
            | UInt32(mac[offset + 2]) << 8 | UInt32(mac[offset + 3])) % 1_000_000
        return String(format: "%06u", code)
    }
}
#endif
