import AppKit
import LocalAuthentication
import os
import Observation

/// Brave, Firefox and the terminal: the extension talks to Verrou through the
/// Native Messaging host embedded in the app (`Contents/MacOS/verrou-native-host`),
/// which relays to the Rust core's bridge (`127.0.0.1`, encrypted channel);
/// the `verrou` CLI (and its SSH agent) talks directly to the bridge. See SECURITY.md.
@MainActor
@Observable
final class BrowserBridge {
    /// Extension ID, set by the key of extension/manifest.json (a test checks
    /// that they match).
    static let extensionID = "pmdlgnpbjfdnmpeadbecmgfoojmocibg"
    /// Extension ID in Firefox (`browser_specific_settings.gecko.id`, written by
    /// scripts/firefox-extension.sh; a test checks that they match).
    static let firefoxExtensionID = "verrou@verrou.app"
    static let hostName = "app.verrou.bridge"

    private let model: AppModel
    private(set) var running = false
    private(set) var error: String?
    /// Neither Brave nor Firefox: the terminal can link anyway.
    private(set) var browserNote: String?
    private(set) var clients: [BridgeClient] = []
    /// Confirmations in progress: the extension retries every second.
    @ObservationIgnored private var confirming: Set<String> = []
    /// The iPhone approved "unlock and read <item>": that item's next
    /// reading by the terminal needs no second approval (once, for 60 s,
    /// exact identifier or title).
    @ObservationIgnored private var unlockGrant: (item: String, until: Date)?

    var enabled: Bool = UserDefaults.standard.bool(forKey: "braveBridge") {
        didSet {
            UserDefaults.standard.set(enabled, forKey: "braveBridge")
            apply()
        }
    }

    /// Extension folder, shipped with the app: to load in Brave.
    var extensionFolder: URL? {
        Bundle.main.url(forResource: "extension", withExtension: nil)
    }

    /// The same for Firefox (scripts/firefox-extension.sh, at build time).
    var firefoxExtensionFolder: URL? {
        Bundle.main.url(forResource: "extension-firefox", withExtension: nil)
    }

    init(model: AppModel) {
        self.model = model
    }

    func apply() {
        // Never on an inert session: with the accounts unavailable the bridge
        // would answer from nowhere (`AppModel.retryStorage` applies again).
        guard model.mode == .vaultwarden, model.storageFailure == nil else { return }
        guard enabled else {
            model.session.stopBridge()
            running = false
            error = nil
            return
        }
        do {
            browserNote = nil
            do {
                try installHostManifest()
            } catch {
                // Without a browser, the terminal stays usable.
                browserNote = error.localizedDescription
            }
            _ = try model.session.startBridge(delegate: Callbacks(bridge: self))
            running = true
            error = nil
            refreshClients()
        } catch {
            running = false
            self.error = (error as? VerrouError).map(AppModel.describe) ?? error.localizedDescription
        }
    }

    func refreshClients() {
        clients = model.session.bridgeClients()
    }

    func revoke(_ client: BridgeClient) {
        model.session.revokeBridgeClient(id: client.id)
        refreshClients()
    }

    // MARK: Client requests

    fileprivate func pairingRequested(id: String, name: String, code: String, kind: BridgeClientKind) {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .warning
        switch kind {
        case .browser:
            alert.messageText = String(localized: "Link “\(name)” to Verrou?")
            alert.informativeText = String(localized: """
                Code shown by the extension: \(code)

                Only accept if you just requested pairing in the extension \
                and it shows exactly this code. The extension will then be able \
                to fill your logins on the sites they match.
                """)
        case .cli:
            alert.messageText = String(localized: "Link the terminal (verrou) to Verrou?")
            alert.informativeText = String(localized: """
                Code shown by “verrou link”: \(code)

                Only accept if you just ran “verrou link” and it shows \
                exactly this code. The terminal will then be able to search the vault \
                (titles, usernames, sites), and request a password, a code or \
                an SSH signature: each time, Verrou will ask you for Touch ID.
                """)
        }
        // "Decline" first: the Return key doesn't link anything by mistake.
        alert.addButton(withTitle: String(localized: "Decline"))
        alert.addButton(withTitle: String(localized: "Link"))
        let approved = alert.runModal() == .alertSecondButtonReturn
        model.session.answerBridgePairing(id: id, approved: approved)
        // The record follows the answer, on the bridge's thread.
        Task {
            try? await Task.sleep(for: .milliseconds(300))
            refreshClients()
        }
    }

    fileprivate func unlockRequested(kind: BridgeClientKind, reason: String, thenItem: String, thenField: String) {
        guard model.lockState == .locked else { return }
        // Away from the Mac, the terminal waits for the iPhone (the window
        // stays locked).
        if kind == .cli, let remote = model.remote {
            Logger(subsystem: "app.verrou", category: "remote-approval")
                .notice("terminal unlock: from the iPhone \(remote.canUnlock), away \(remote.isAway)")
        }
        if kind == .cli, let remote = model.remote, remote.canUnlock, remote.isAway {
            let then = thenItem.isEmpty ? nil : (item: thenItem, field: thenField)
            Task {
                let unlocked = await model.unlockFromPhone(client: String(localized: "the terminal"), reason: reason,
                                                           then: then)
                if unlocked, let then { unlockGrant = (then.item, Date().addingTimeInterval(60)) }
            }
            return
        }
        NSApp.activate()
        if model.canUseTouchID, !model.needsLogin {
            Task { await model.unlockWithBiometrics() }
        } else {
            model.showMainWindow()
        }
    }

    fileprivate func vaultChanged(item: String, title: String) {
        model.didSaveFromBrowser(title: title)
    }

    /// The browser wants to fill a protected item: the confirmation happens here;
    /// the extension retries by itself.
    fileprivate func repromptRequested(item: String, title: String) {
        guard !confirming.contains(item) else { return }
        confirming.insert(item)
        Task {
            _ = await model.confirmAccess(itemID: item, title: title)
            confirming.remove(item)
        }
    }

    /// The terminal wants a secret or an SSH signature, or the browser a passkey
    /// for a site that requests user verification: Touch ID, or the session
    /// password if Touch ID is not available. The approval is kept a few
    /// minutes by the bridge, for this terminal and this item.
    /// Protected item ("master password re-prompt"): the same confirmation
    /// as in the app (Touch ID or master password).
    fileprivate func confirmRequested(id: String, clientName: String, purpose: AccessPurpose, item: String, title: String,
                                      site: String, reason motive: String, changes: String) {
        // The name announced at pairing ("Brave", "Firefox").
        let browser = clientName.isEmpty ? String(localized: "the browser") : clientName
        let reason = switch purpose {
        case .reveal: String(localized: "allow the terminal to read “\(title)”")
        case .ssh: String(localized: "allow ssh to use the key “\(title)”")
        case .passkey: String(localized: "allow \(browser) to use a passkey for “\(title)”")
        // `ssh-keygen -Y sign -n git`: git signs a commit (or a tag).
        case .gitSign: String(localized: "sign a git commit with the key “\(title)”")
        // `site`: the host to link to the item.
        case .linkSite: String(localized: "allow \(browser) to link the site \(site) to “\(title)”")
        case .card: String(localized: "allow \(browser) to fill the card “\(title)”")
        // Many items requested in a short time: maybe not you.
        case .bulk: String(localized: "\(browser) is requesting many items in a short time: allow “\(title)”")
        // `verrou item create|edit|delete|archive|restore`.
        // `site`: the folder the item goes to, created if missing.
        case .create where !site.isEmpty: String(localized: "allow the terminal to create “\(title)” in the folder “\(site)”")
        case .create: String(localized: "allow the terminal to create “\(title)”")
        case .edit where !site.isEmpty: String(localized: "allow the terminal to modify “\(title)” and file it in the folder “\(site)”")
        case .edit: String(localized: "allow the terminal to modify “\(title)”")
        case .delete: String(localized: "allow the terminal to move “\(title)” to the trash")
        }
        // Already approved on the iPhone with the unlock: "unlock and read
        // this item".
        if purpose == .reveal, let grant = unlockGrant, grant.until > Date(),
           grant.item == item || grant.item.localizedCaseInsensitiveCompare(title) == .orderedSame {
            unlockGrant = nil
            if model.session.needsConfirmation(id: item) { model.session.authorizeItem(id: item) }
            model.extendRemoteSession()
            model.session.answerBridgeConfirmation(id: id, approved: true)
            return
        }
        // A write names the fields it changes (`password, url, −Old token`),
        // never their values; then the terminal's reason, as it declares it.
        let asked = changes.isEmpty ? reason : "\(reason): \(changes)"
        var prompt = motive.isEmpty ? asked : "\(asked) (\(motive))"
        Task {
            let protected = model.session.needsConfirmation(id: item)
            // The user chose "until Verrou locks" for this key: say what this
            // approval grants. A protected key is never given that scope.
            let untilLocked = (purpose == .ssh || purpose == .gitSign) && !protected
                && model.session.sshApprovalScope(id: item) == .untilLocked
            if untilLocked { prompt = String(localized: "\(prompt) (until Verrou locks)") }
            let local: @MainActor (LAContext) async -> Bool = { [model] context in
                protected ? await model.confirmAccess(itemID: item, title: title, context: context)
                          : await Biometrics.confirm(reason: prompt, context: context)
            }
            // At the Mac: Touch ID; away: the paired iPhone (`RemoteApprovals`).
            let outcome = if let remote = model.remote {
                await remote.decide(client: clientName.isEmpty ? String(localized: "the terminal") : clientName,
                                    purpose: purpose.wire, title: title, site: site, reason: motive,
                                    changes: changes, scope: untilLocked ? "untilLocked" : nil, local: local)
            } else {
                RemoteApprovals.Outcome.local(await local(LAContext()))
            }
            if case .remote(true) = outcome {
                // Face ID on the iPhone stands for Touch ID here.
                if protected { model.session.authorizeItem(id: item) }
                model.extendRemoteSession()
            }
            model.session.answerBridgeConfirmation(id: id, approved: outcome.approved)
        }
    }

    // MARK: Registration with the browser

    /// `NativeMessagingHosts/app.verrou.bridge.json`: the browser only agrees
    /// to launch the host for Verrou's extension. Brave reads Google Chrome's
    /// folder (observed on a separate profile) and its own: we write both,
    /// which also serves Chrome. Firefox reads `Mozilla/NativeMessagingHosts`,
    /// with `allowed_extensions` (its extension ID) instead of
    /// `allowed_origins`.
    private func installHostManifest() throws {
        guard let host = Bundle.main.url(forAuxiliaryExecutable: "verrou-native-host") else {
            throw Failure(String(localized: "the Native Messaging host is missing from the app: reinstall Verrou"))
        }
        let support = Self.realHome.appending(path: "Library/Application Support")
        let exists = { (path: String) in
            FileManager.default.fileExists(atPath: support.appending(path: path, directoryHint: .isDirectory).path)
        }
        var targets: [(directory: URL, allowed: [String: Any])] = []
        let chromium = ["allowed_origins": ["chrome-extension://\(Self.extensionID)/"]]
        for browser in ["BraveSoftware/Brave-Browser", "Google/Chrome"] where exists(browser) {
            targets.append((support.appending(path: "\(browser)/NativeMessagingHosts", directoryHint: .isDirectory), chromium))
        }
        // Firefox (and its Developer, Nightly editions) keeps its profiles in
        // `Firefox`; `Mozilla` already exists if another app registered there.
        if exists("Firefox") || exists("Mozilla") {
            targets.append((support.appending(path: "Mozilla/NativeMessagingHosts", directoryHint: .isDirectory),
                            ["allowed_extensions": [Self.firefoxExtensionID]]))
        }
        guard !targets.isEmpty else {
            throw Failure(String(localized: "neither Brave nor Firefox is installed (or ever launched) on this Mac"))
        }
        var failures: [String] = []
        for target in targets {
            var manifest: [String: Any] = [
                "name": Self.hostName,
                "description": "Verrou",
                "path": host.path,
                "type": "stdio",
            ]
            manifest.merge(target.allowed) { _, new in new }
            do {
                let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
                try FileManager.default.createDirectory(at: target.directory, withIntermediateDirectories: true)
                try data.write(to: target.directory.appending(path: "\(Self.hostName).json"), options: .atomic)
            } catch where target.allowed["allowed_extensions"] != nil && !exists("Mozilla") {
                // The sandbox only opens the NativeMessagingHosts folders:
                // `Mozilla` itself can't be created from here.
                failures.append(String(localized: "for Firefox, create the folder (Terminal: mkdir -p ~/Library/Application\\ Support/Mozilla/NativeMessagingHosts) then turn this setting on again"))
            } catch {
                failures.append("\(target.directory.path): \(error.localizedDescription)")
            }
        }
        if failures.count == targets.count {
            throw Failure(String(localized: "couldn't register with the browser (\(failures.joined(separator: "; ")))"))
        }
        if !failures.isEmpty {
            throw Failure(String(localized: "partial registration with the browser (\(failures.joined(separator: "; ")))"))
        }
    }

    /// The user's real folder: in the sandbox, `NSHomeDirectory()` points to
    /// the app's container.
    private static var realHome: URL {
        if let entry = getpwuid(getuid()), let directory = entry.pointee.pw_dir {
            return URL(fileURLWithPath: String(cString: directory), isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    private struct Failure: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }
}

/// Bridge callbacks, on its thread: hand over to the main thread right away.
private final class Callbacks: BridgeDelegate, @unchecked Sendable {
    private weak var bridge: BrowserBridge?

    init(bridge: BrowserBridge) {
        self.bridge = bridge
    }

    func pairingRequested(id: String, name: String, code: String, kind: BridgeClientKind) {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated { bridge?.pairingRequested(id: id, name: name, code: code, kind: kind) }
        }
    }

    func confirmRequested(id: String, clientName: String, purpose: AccessPurpose, item: String, title: String, site: String,
                          reason: String, changes: String) {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated {
                // Bridge stopped in the meantime: the request expires by itself.
                bridge?.confirmRequested(id: id, clientName: clientName, purpose: purpose, item: item, title: title,
                                         site: site, reason: reason, changes: changes)
            }
        }
    }

    func unlockRequested(kind: BridgeClientKind, reason: String, thenItem: String, thenField: String) {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated {
                bridge?.unlockRequested(kind: kind, reason: reason, thenItem: thenItem, thenField: thenField)
            }
        }
    }

    func vaultChanged(item: String, title: String) {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated { bridge?.vaultChanged(item: item, title: title) }
        }
    }

    func repromptRequested(item: String, title: String) {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated { bridge?.repromptRequested(item: item, title: title) }
        }
    }
}

extension AccessPurpose {
    /// The name the iPhone words (`RemoteApproval.Request.purpose`).
    var wire: String {
        switch self {
        case .reveal: "reveal"
        case .ssh: "ssh"
        case .passkey: "passkey"
        case .gitSign: "gitSign"
        case .linkSite: "linkSite"
        case .card: "card"
        case .bulk: "bulk"
        case .create: "create"
        case .edit: "edit"
        case .delete: "delete"
        }
    }
}
