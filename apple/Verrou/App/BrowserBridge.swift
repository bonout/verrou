import AppKit
import Observation

/// Remplissage dans Brave : l'extension parle à Verrou par l'hôte Native
/// Messaging embarqué dans l'app (`Contents/MacOS/verrou-native-host`), qui
/// relaie vers le pont du cœur Rust (`127.0.0.1`, canal chiffré). Voir
/// SECURITY.md.
@MainActor
@Observable
final class BrowserBridge {
    /// Identifiant de l'extension, fixé par la clé de extension/manifest.json
    /// (un test vérifie qu'ils concordent).
    static let extensionID = "pmdlgnpbjfdnmpeadbecmgfoojmocibg"
    static let hostName = "app.verrou.bridge"

    private let model: AppModel
    private(set) var running = false
    private(set) var error: String?
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
            try installHostManifest()
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

    // MARK: Demandes de l'extension

    fileprivate func pairingRequested(id: String, name: String, code: String) {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Relier « \(name) » à Verrou ?"
        alert.informativeText = """
            Code affiché par l'extension : \(code)

            N'acceptez que si vous venez de demander l'appairage dans l'extension \
            et qu'elle affiche exactement ce code. L'extension pourra ensuite \
            remplir vos identifiants sur les sites qui leur correspondent.
            """
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

    /// Brave veut remplir un élément protégé : la confirmation se fait ici ;
    /// l'extension réessaie d'elle-même.
    fileprivate func repromptRequested(item: String, title: String) {
        guard !confirming.contains(item) else { return }
        confirming.insert(item)
        Task {
            _ = await model.confirmAccess(itemID: item, title: title)
            confirming.remove(item)
        }
    }

    // MARK: Déclaration au navigateur

    /// `NativeMessagingHosts/app.verrou.bridge.json` : le navigateur n'accepte
    /// de lancer l'hôte que pour l'extension de Verrou. Brave lit le dossier
    /// de Google Chrome (constaté sur un profil séparé) et le sien : on écrit
    /// les deux, ce qui sert aussi à Chrome.
    private func installHostManifest() throws {
        guard let host = Bundle.main.url(forAuxiliaryExecutable: "verrou-native-host") else {
            throw Failure("l'hôte Native Messaging manque dans l'app : réinstallez Verrou")
        }
        let support = Self.realHome.appending(path: "Library/Application Support")
        let browsers = ["BraveSoftware/Brave-Browser", "Google/Chrome"]
            .map { support.appending(path: $0, directoryHint: .isDirectory) }
            .filter { FileManager.default.fileExists(atPath: $0.path) }
        guard !browsers.isEmpty else {
            throw Failure("Brave n'est pas installé (ou jamais lancé) sur ce Mac")
        }
        let manifest: [String: Any] = [
            "name": Self.hostName,
            "description": "Verrou",
            "path": host.path,
            "type": "stdio",
            "allowed_origins": ["chrome-extension://\(Self.extensionID)/"],
        ]
        let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        for browser in browsers {
            let directory = browser.appending(path: "NativeMessagingHosts", directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try data.write(to: directory.appending(path: "\(Self.hostName).json"), options: .atomic)
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

    func pairingRequested(id: String, name: String, code: String) {
        DispatchQueue.main.async { [weak bridge] in
            MainActor.assumeIsolated { bridge?.pairingRequested(id: id, name: name, code: code) }
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
