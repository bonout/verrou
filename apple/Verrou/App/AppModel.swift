import AppKit
import Observation
import SwiftUI

/// État de l'application : verrouillage, sélection, recherche.
///
/// Les résumés des éléments (titres, identifiants affichés, sites) sont
/// chargés une fois au déverrouillage. Chaque frappe interroge le cœur Rust,
/// qui renvoie des positions dans ce tableau : rien d'autre ne traverse la
/// frontière, et aucun secret.
@MainActor
@Observable
final class AppModel {
    enum LockState: Equatable {
        case locked
        case unlocking
        case unlocked
    }

    private(set) var lockState: LockState = .locked
    private(set) var summaries: [ItemSummary] = []
    private(set) var results: [SearchHit] = []
    private(set) var counts: SidebarCounts?
    private(set) var lastSearchDuration: Duration = .zero
    var unlockError: String?

    var filter: SidebarFilter = .all { didSet { refresh() } }
    var query: String = "" { didSet { refresh() } }
    var sort: ResultOrder = .relevance { didSet { refresh() } }
    var selection: String? { didSet { if oldValue != selection { revealed.removeAll() } } }
    /// Champs révélés pour l'élément sélectionné, effacés dès qu'on en change.
    var revealed: [String: String] = [:]
    var toast: Toast?
    /// Requête de la fenêtre d'accès rapide, indépendante de la fenêtre principale.
    var quickQuery = ""

    let session = VaultSession()
    let clipboard = Clipboard()
    let mockSize: UInt32
    private var autoLock: AutoLock?

    init() {
        mockSize = UInt32(ProcessInfo.processInfo.environment["VERROU_MOCK_SIZE"] ?? "") ?? 0
    }

    // MARK: Verrouillage

    func unlockWithBiometrics() async {
        lockState = .unlocking
        unlockError = nil
        switch await Biometrics.authenticate(reason: "déverrouiller votre coffre") {
        case .success:
            openVault()
        case .failure(let message):
            unlockError = message
            lockState = .locked
        }
    }

    func unlock(masterPassword: String) {
        // Coffre fictif : tout mot de passe non vide l'ouvre. La vérification
        // réelle (dérivation de clé Bitwarden) arrive avec Vaultwarden.
        guard !masterPassword.isEmpty else {
            unlockError = "Saisissez votre mot de passe principal."
            return
        }
        openVault()
    }

    func openVault() {
        session.unlockMock(size: mockSize, seed: 42)
        summaries = (try? session.summaries()) ?? []
        counts = try? session.counts()
        lockState = .unlocked
        refresh()
        if selection == nil { selection = results.first.map { summaries[Int($0.position)].id } }
        autoLock = AutoLock { [weak self] in self?.lock() }
    }

    func lock() {
        session.lock()
        summaries = []
        results = []
        counts = nil
        revealed.removeAll()
        selection = nil
        query = ""
        autoLock = nil
        clipboard.clearIfOurs()
        lockState = .locked
    }

    // MARK: Recherche

    private func refresh() {
        guard lockState == .unlocked else { return }
        let clock = ContinuousClock()
        let start = clock.now
        let effectiveSort = query.isEmpty && sort == .relevance ? ResultOrder.title : sort
        results = (try? session.search(query: query, filter: filter, order: effectiveSort)) ?? []
        lastSearchDuration = clock.now - start
    }

    func summary(for hit: SearchHit) -> ItemSummary {
        summaries[Int(hit.position)]
    }

    var selectedDetail: ItemDetail? {
        guard let selection else { return nil }
        return try? session.detail(id: selection)
    }

    func moveSelection(by offset: Int) {
        guard !results.isEmpty else { return }
        let ids = results.map { summaries[Int($0.position)].id }
        let current = selection.flatMap { ids.firstIndex(of: $0) } ?? -1
        let next = min(max(current + offset, 0), ids.count - 1)
        selection = ids[next]
    }

    // MARK: Secrets

    func reveal(_ fieldID: String, of itemID: String) -> String? {
        if let value = revealed[fieldID] { return value }
        guard let value = try? session.reveal(id: itemID, fieldId: fieldID) else { return nil }
        revealed[fieldID] = value
        return value
    }

    func toggleReveal(_ fieldID: String, of itemID: String) {
        if revealed[fieldID] != nil {
            revealed[fieldID] = nil
        } else {
            _ = reveal(fieldID, of: itemID)
        }
    }

    func copy(_ value: String, label: String, secret: Bool) {
        clipboard.copy(value, concealed: secret)
        withAnimation(.snappy) {
            toast = Toast(message: "\(label) copié", detail: secret ? "Effacé du presse-papiers dans 90 s" : nil)
        }
    }

    func copyField(_ field: FieldView, of itemID: String) {
        if field.fieldType == .totp {
            guard let code = try? session.totp(id: itemID, unixTime: UInt64(Date().timeIntervalSince1970)) else { return }
            copy(code.code, label: "Code", secret: true)
            return
        }
        let value = field.secret ? reveal(field.id, of: itemID) : field.value
        guard let value else { return }
        // Le numéro de carte se copie sans espaces : c'est ce qu'attendent les
        // formulaires.
        let copied = field.fieldType == .cardNumber ? value.replacingOccurrences(of: " ", with: "") : value
        copy(copied, label: field.label, secret: field.secret)
        if field.secret { revealed[field.id] = nil }
    }

    func copyPassword(of itemID: String) {
        guard let value = try? session.reveal(id: itemID, fieldId: "password") else { return }
        copy(value, label: "Mot de passe", secret: true)
    }

    func noteActivity() {
        autoLock?.touch()
    }
}

struct Toast: Equatable, Identifiable {
    let id = UUID()
    let message: String
    let detail: String?
}

/// Verrouillage automatique : inactivité, mise en veille, écran verrouillé.
@MainActor
final class AutoLock {
    private let timeout: TimeInterval = 10 * 60
    private var lastActivity = Date()
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private let onLock: @MainActor () -> Void

    init(onLock: @escaping @MainActor () -> Void) {
        self.onLock = onLock
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.check() }
        }
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.onLock() }
            })
        }
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.onLock() }
        })
    }

    func touch() { lastActivity = Date() }

    private func check() {
        if Date().timeIntervalSince(lastActivity) > timeout { onLock() }
    }

    deinit {
        timer?.invalidate()
        observers.forEach {
            NSWorkspace.shared.notificationCenter.removeObserver($0)
            DistributedNotificationCenter.default().removeObserver($0)
        }
    }
}
