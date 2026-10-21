import AppKit
import Observation

/// Brave, Firefox et le terminal : l'extension parle à Verrou par l'hôte Native
/// Messaging embarqué dans l'app (`Contents/MacOS/verrou-native-host`), qui
/// relaie vers le pont du cœur Rust (`127.0.0.1`, canal chiffré) ; la CLI
/// `verrou` (et son agent SSH) parle directement au pont. Voir SECURITY.md.
@MainActor
@Observable
final class BrowserBridge {
    /// Identifiant de l'extension, fixé par la clé de extension/manifest.json
    /// (un test vérifie qu'ils concordent).
    static let extensionID = "pmdlgnpbjfdnmpeadbecmgfoojmocibg"
    /// Identifiant de l'extension dans Firefox (`browser_specific_settings.gecko.id`,
    /// écrit par scripts/firefox-extension.sh ; un test vérifie qu'ils concordent).
    static let firefoxExtensionID = "verrou@verrou.app"
    static let hostName = "app.verrou.bridge"

    private let model: AppModel
    private(set) var running = false
    private(set) var error: String?
    /// Ni Brave ni Firefox : le terminal peut se relier quand même.
    private(set) var browserNote: String?
    private(set) var clients: [BridgeClient] = []
    /// Confirmations en cours : l'extension réessaie chaque seconde.
    @ObservationIgnored private var confirming: Set<String> = []

    var enabled: Bool = UserDefaults.standard.bool(forKey: "braveBridge") {
        didSet {
            UserDefaults.standard.set(enabled, forKey: "braveBridge")
            apply()
        }
    }

    /// Dossier de l'extension, livré avec l'app : à charger dans Brave.
    var extensionFolder: URL? {
        Bundle.main.url(forResource: "extension", withExtension: nil)
    }

    /// La même pour Firefox (scripts/firefox-extension.sh, à la compilation).
    var firefoxExtensionFolder: URL? {
        Bundle.main.url(forResource: "extension-firefox", withExtension: nil)
    }

    init(model: AppModel) {
        self.model = model
    }

    func apply() {
        guard model.mode == .vaultwarden else { return }
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
                // Sans navigateur, le terminal reste utilisable.
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

    // MARK: Demandes des clients

    fileprivate func pairingRequested(id: String, name: String, code: String, kind: BridgeClientKind) {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .warning
        switch kind {
        case .browser:
            alert.messageText = "Relier « \(name) » à Verrou ?"
            alert.informativeText = """
                Code affiché par l'extension : \(code)

                N'acceptez que si vous venez de demander l'appairage dans l'extension \
                et qu'elle affiche exactement ce code. L'extension pourra ensuite \
                remplir vos identifiants sur les sites qui leur correspondent.
                """
        case .cli:
            alert.messageText = "Relier le terminal (verrou) à Verrou ?"
            alert.informativeText = """
                Code affiché par « verrou link » : \(code)

                N'acceptez que si vous venez de lancer « verrou link » et qu'il affiche \
                exactement ce code. Le terminal pourra ensuite chercher dans le coffre \
                (titres, identifiants, sites), et demander un mot de passe, un code ou \
                une signature SSH : chaque fois, Verrou vous demandera Touch ID.
                """
        }
        // « Refuser » d'abord : la touche Entrée ne relie rien par mégarde.
        alert.addButton(withTitle: "Refuser")
        alert.addButton(withTitle: "Relier")
        let approved = alert.runModal() == .alertSecondButtonReturn
        model.session.answerBridgePairing(id: id, approved: approved)
        // L'enregistrement suit la réponse, sur le fil du pont.
        Task {
            try? await Task.sleep(for: .milliseconds(300))
            refreshClients()
        }
    }

    fileprivate func unlockRequested() {
        guard model.lockState == .locked else { return }
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

    /// Le navigateur veut remplir un élément protégé : la confirmation se fait ici ;
    /// l'extension réessaie d'elle-même.
    fileprivate func repromptRequested(item: String, title: String) {
        guard !confirming.contains(item) else { return }
        confirming.insert(item)
        Task {
            _ = await model.confirmAccess(itemID: item, title: title)
            confirming.remove(item)
        }
    }

    /// Le terminal veut un secret ou une signature SSH, ou le navigateur une passkey
    /// pour un site qui demande la vérification de l'utilisateur : Touch ID,
    /// ou le mot de passe de la session si Touch ID n'est pas disponible. L'accord est
    /// gardé quelques minutes par le pont, pour ce terminal et cet élément.
    /// Élément protégé (« redemander le mot de passe principal ») : la même
    /// confirmation que dans l'app (Touch ID ou mot de passe principal).
    fileprivate func confirmRequested(id: String, clientName: String, purpose: AccessPurpose, item: String, title: String) {
        // Le nom annoncé à l'appairage (« Brave », « Firefox »).
        let browser = clientName.isEmpty ? "le navigateur" : clientName
        let reason = switch purpose {
        case .reveal: "autoriser le terminal à lire « \(title) »"
        case .ssh: "autoriser ssh à utiliser la clé « \(title) »"
        case .passkey: "autoriser \(browser) à utiliser une passkey pour « \(title) »"
        // `ssh-keygen -Y sign -n git` : git signe un commit (ou une étiquette).
        case .gitSign: "signer un commit git avec la clé « \(title) »"
        // `title` : « le site exemple.fr à « GitHub » ».
        case .linkSite: "autoriser \(browser) à associer \(title)"
        case .card: "autoriser \(browser) à remplir la carte « \(title) »"
        // Beaucoup d'éléments demandés en peu de temps : peut-être pas vous.
        case .bulk: "\(browser) demande beaucoup d'éléments en peu de temps : autoriser « \(title) »"
        }
        Task {
            let approved = if model.session.needsConfirmation(id: item) {
                await model.confirmAccess(itemID: item, title: title)
            } else {
                await Biometrics.confirm(reason: reason)
            }
            model.session.answerBridgeConfirmation(id: id, approved: approved)
        }
    }

    // MARK: Déclaration au navigateur

    /// `NativeMessagingHosts/app.verrou.bridge.json` : le navigateur n'accepte
    /// de lancer l'hôte que pour l'extension de Verrou. Brave lit le dossier
    /// de Google Chrome (constaté sur un profil séparé) et le sien : on écrit
    /// les deux, ce qui sert aussi à Chrome. Firefox lit
    /// `Mozilla/NativeMessagingHosts`, avec `allowed_extensions` (son
    /// identifiant d'extension) au lieu de `allowed_origins`.
    private func installHostManifest() throws {
        guard let host = Bundle.main.url(forAuxiliaryExecutable: "verrou-native-host") else {
            throw Failure("l'hôte Native Messaging manque dans l'app : réinstallez Verrou")
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
        // Firefox (et ses éditions Developer, Nightly) range ses profils dans
        // `Firefox` ; `Mozilla` existe déjà si une autre app s'y est déclarée.
        if exists("Firefox") || exists("Mozilla") {
            targets.append((support.appending(path: "Mozilla/NativeMessagingHosts", directoryHint: .isDirectory),
                            ["allowed_extensions": [Self.firefoxExtensionID]]))
        }
        guard !targets.isEmpty else {
            throw Failure("ni Brave ni Firefox ne sont installés (ou jamais lancés) sur ce Mac")
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
                // Le sandbox n'ouvre que les dossiers NativeMessagingHosts :
                // `Mozilla` lui-même ne peut pas être créé d'ici.
                failures.append("pour Firefox, créez le dossier (Terminal : mkdir -p ~/Library/Application\\ Support/Mozilla/NativeMessagingHosts) puis réactivez ce réglage")
            } catch {
                failures.append("\(target.directory.path) : \(error.localizedDescription)")
            }
        }
        if failures.count == targets.count {
            throw Failure("déclaration au navigateur impossible (\(failures.joined(separator: " ; ")))")
        }
        if !failures.isEmpty {
            throw Failure("déclaration partielle au navigateur (\(failures.joined(separator: " ; ")))")
        }
    }

    /// Le vrai dossier de l'utilisateur : dans le sandbox, `NSHomeDirectory()`
    /// désigne le conteneur de l'app.
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

/// Rappels du pont, sur son fil : on passe aussitôt la main au fil principal.
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

    func confirmRequested(id: String, clientName: String, purpose: AccessPurpose, item: String, title: String) {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated {
                // Pont arrêté entre-temps : la demande expire d'elle-même.
                bridge?.confirmRequested(id: id, clientName: clientName, purpose: purpose, item: item, title: title)
            }
        }
    }

    func unlockRequested() {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated { bridge?.unlockRequested() }
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
