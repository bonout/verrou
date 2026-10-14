import AppKit
import ApplicationServices
import Carbon.HIToolbox
import SwiftUI

/// Remplissage dans n'importe quelle app du Mac (⌘\ par défaut).
///
/// Le raccourci retient l'app au premier plan, ouvre l'accès rapide avec les
/// identifiants reliés à cette app (`macapp://<identifiant de paquet>` parmi
/// les sites de l'élément, synchronisé), puis, une fois l'identifiant choisi,
/// rend la main à l'app et tape l'identifiant, Tab et le mot de passe en
/// caractères Unicode (indépendant de la disposition du clavier).
///
/// Taper au clavier pour une autre app demande l'accès « Accessibilité ».
@MainActor
@Observable
final class UniversalAutofill {
    /// Réglages (onglet Général).
    static let enabledKey = "appAutofillEnabled"
    static let shortcutKey = "appAutofillShortcut"
    static let submitKey = "appAutofillSubmit"
    static let copyTotpKey = "appAutofillCopyTotp"

    /// L'instance de l'app, pour les réglages.
    private(set) static weak var current: UniversalAutofill?

    /// App où remplir, retenue au moment du raccourci. `nil` : l'accès rapide
    /// sert normalement.
    var target: AutofillTarget?
    /// Identifiants reliés à l'app visée.
    private(set) var suggestions: [ItemSummary] = []
    /// La combinaison choisie est déjà prise par une autre app.
    private(set) var shortcutUnavailable = false
    private(set) var filling = false

    @ObservationIgnored private let model: AppModel
    @ObservationIgnored private weak var quickAccess: QuickAccessController?
    @ObservationIgnored private var hotKey: HotKey?
    @ObservationIgnored private var registered: (enabled: Bool, shortcut: AutofillShortcut)?
    @ObservationIgnored private var defaultsObserver: NSObjectProtocol?
    @ObservationIgnored var sink: KeystrokeSink = CGEventKeystrokeSink()

    init(model: AppModel, quickAccess: QuickAccessController) {
        self.model = model
        self.quickAccess = quickAccess
        Self.current = self
        apply()
        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.apply() }
        }
    }

    static var isEnabled: Bool {
        UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true
    }

    static var shortcut: AutofillShortcut {
        UserDefaults.standard.string(forKey: shortcutKey).flatMap(AutofillShortcut.init) ?? .command
    }

    private static var submits: Bool { UserDefaults.standard.bool(forKey: submitKey) }

    private static var copiesTotp: Bool {
        UserDefaults.standard.object(forKey: copyTotpKey) as? Bool ?? true
    }

    /// (Ré)enregistre le raccourci selon les réglages.
    func apply() {
        let wanted = (enabled: Self.isEnabled, shortcut: Self.shortcut)
        if let registered, registered == wanted { return }
        registered = wanted
        hotKey = nil
        guard wanted.enabled else {
            shortcutUnavailable = false
            return
        }
        let key = HotKey(keyCode: UInt32(kVK_ANSI_Backslash), modifiers: wanted.shortcut.carbonModifiers) { [weak self] in
            self?.trigger()
        }
        shortcutUnavailable = !key.isRegistered
        hotKey = key
    }

    /// Le raccourci : retenir l'app au premier plan, puis ouvrir l'accès rapide.
    func trigger() {
        guard let quickAccess else { return }
        let front = NSWorkspace.shared.frontmostApplication
        // Verrou lui-même au premier plan (ou rien d'identifiable) : il n'y a
        // pas d'autre app où taper, l'accès rapide sert normalement.
        guard let front, front.processIdentifier != ProcessInfo.processInfo.processIdentifier,
              let bundleID = front.bundleIdentifier else {
            quickAccess.toggle()
            return
        }
        if quickAccess.isVisible { quickAccess.close() }
        target = AutofillTarget(
            pid: front.processIdentifier,
            bundleID: bundleID,
            name: front.localizedName ?? bundleID,
            icon: front.icon,
            secureInputOwner: SecureInput.foreignOwner(besides: front.processIdentifier))
        refreshSuggestions()
        quickAccess.show()
    }

    func refreshSuggestions() {
        guard let target, model.lockState == .unlocked else {
            suggestions = []
            return
        }
        suggestions = (try? model.session.appSuggestions(bundleId: target.bundleID)) ?? []
    }

    func isLinked(_ itemID: String, to target: AutofillTarget) -> Bool {
        model.session.isLinkedToApp(id: itemID, bundleId: target.bundleID)
    }

    /// Relie l'identifiant à l'app visée, sans remplir.
    func link(itemID: String, to target: AutofillTarget) async {
        guard model.canEdit else { return }
        do {
            if try await model.session.linkToApp(id: itemID, bundleId: target.bundleID) {
                model.afterWrite(select: model.selection)
                if self.target?.bundleID == target.bundleID { refreshSuggestions() }
                AutofillHUD.show("Associé à « \(target.name) »", detail: "Proposé en premier au prochain ⌘\\")
            }
        } catch {
            AutofillHUD.show("Association impossible", detail: AppModel.describe(error), failure: true)
        }
    }

    /// Remplit l'identifiant choisi dans l'app visée : confirmation d'un
    /// élément protégé, retour à l'app, frappes, puis code à usage unique
    /// copié et association demandée.
    func fill(itemID: String, link: Bool) {
        guard let target, !filling else { return }
        let summary = model.summaries.first { $0.id == itemID }
        guard summary?.category == .login else { return }
        filling = true
        Task {
            defer { filling = false }
            await perform(itemID: itemID, summary: summary, target: target, link: link)
        }
    }

    private func perform(itemID: String, summary: ItemSummary?, target: AutofillTarget, link: Bool) async {
        let title = summary?.title ?? "cet élément"
        guard model.lockState == .unlocked else { return }
        // Élément protégé : Touch ID ou mot de passe principal, comme pour le copier.
        if model.session.needsConfirmation(id: itemID) {
            guard await model.confirmAccess(itemID: itemID, title: title) else { return }
        }
        guard AccessibilityPermission.isGranted else {
            AutofillHUD.show("Accès « Accessibilité » requis",
                             detail: "Réglages Système → Confidentialité et sécurité → Accessibilité", failure: true)
            AccessibilityPermission.request()
            return
        }
        let keys: [AutofillKeystroke]
        do {
            keys = try model.session.autofillKeystrokes(id: itemID, submit: Self.submits)
        } catch {
            AutofillHUD.show("Remplissage impossible", detail: AppModel.describe(error), failure: true)
            return
        }
        quickAccess?.close()
        guard await activate(target) else {
            AutofillHUD.show("Impossible de revenir à « \(target.name) »", detail: "Rien n'a été tapé", failure: true)
            return
        }
        // Une autre app a activé la saisie sécurisée (Terminal, par exemple) :
        // les frappes risquent de ne pas arriver, ou ailleurs. On s'abstient.
        if let owner = SecureInput.foreignOwner(besides: target.pid) {
            AutofillHUD.show("Saisie sécurisée activée par « \(owner) »",
                             detail: "Rien n'a été tapé : désactivez-la, ou copiez le mot de passe depuis l'accès rapide (⌘⇧Espace).",
                             failure: true)
            return
        }
        await KeystrokePlayer(sink: sink).play(keys)
        if Self.copiesTotp, summary?.hasTotp == true, let code = model.totpCode(of: itemID) {
            model.copy(code.code, label: "Code", secret: true)
            AutofillHUD.show("Code à usage unique copié", detail: "Effacé du presse-papiers dans 90 s")
        }
        if link, model.canEdit {
            await self.link(itemID: itemID, to: target)
        }
    }

    /// Rend le premier plan à l'app visée et attend qu'elle l'ait.
    private func activate(_ target: AutofillTarget) async -> Bool {
        guard let app = NSRunningApplication(processIdentifier: target.pid), !app.isTerminated else { return false }
        NSApp.yieldActivation(to: app)
        app.activate()
        for _ in 0..<75 {
            if NSWorkspace.shared.frontmostApplication?.processIdentifier == target.pid {
                // Le temps que sa fenêtre redevienne clé et rende le focus au champ.
                try? await Task.sleep(for: .milliseconds(150))
                return true
            }
            try? await Task.sleep(for: .milliseconds(20))
        }
        return false
    }
}

/// L'app où remplir, retenue au moment du raccourci.
struct AutofillTarget: Equatable {
    let pid: pid_t
    let bundleID: String
    let name: String
    let icon: NSImage?
    /// App (autre que la cible) qui avait activé la saisie sécurisée.
    let secureInputOwner: String?
}

/// Combinaisons proposées. La touche est celle de `\` sur un clavier
/// américain (à gauche de Retour) : sa position, quelle que soit la
/// disposition ; le libellé montre le caractère de la disposition active.
enum AutofillShortcut: String, CaseIterable, Identifiable {
    case command
    case optionCommand
    case controlCommand

    var id: String { rawValue }

    var carbonModifiers: UInt32 {
        switch self {
        case .command: UInt32(cmdKey)
        case .optionCommand: UInt32(cmdKey | optionKey)
        case .controlCommand: UInt32(cmdKey | controlKey)
        }
    }

    var label: String {
        let key = KeyboardLayout.character(for: UInt16(kVK_ANSI_Backslash)) ?? "\\"
        switch self {
        case .command: return "⌘\(key)"
        case .optionCommand: return "⌥⌘\(key)"
        case .controlCommand: return "⌃⌘\(key)"
        }
    }
}

enum KeyboardLayout {
    /// Caractère que produit une touche dans la disposition active (sans
    /// modificateur ni touche morte).
    static func character(for keyCode: UInt16) -> String? {
        guard let source = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(),
              let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else { return nil }
        let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
        var deadKeys: UInt32 = 0
        var length = 0
        var chars = [UniChar](repeating: 0, count: 4)
        let status = data.withUnsafeBytes { buffer -> OSStatus in
            guard let layout = buffer.bindMemory(to: UCKeyboardLayout.self).baseAddress else { return -1 }
            return UCKeyTranslate(layout, keyCode, UInt16(kUCKeyActionDisplay), 0, UInt32(LMGetKbdType()),
                                  OptionBits(kUCKeyTranslateNoDeadKeysBit), &deadKeys, chars.count, &length, &chars)
        }
        guard status == noErr, length > 0 else { return nil }
        let text = String(utf16CodeUnits: chars, count: length).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text.uppercased()
    }
}

/// Autorisation de taper pour les autres apps (« Accessibilité »).
enum AccessibilityPermission {
    static var isGranted: Bool {
        AXIsProcessTrustedWithOptions(nil) || CGPreflightPostEventAccess()
    }

    /// Demande à macOS d'ajouter Verrou à la liste (et ouvre les réglages).
    static func request() {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        if AXIsProcessTrustedWithOptions(options) { return }
        // App sandboxée : c'est cette demande qui inscrit Verrou dans la liste.
        if CGRequestPostEventAccess() { return }
        openSettings()
    }

    static func openSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(url)
        }
    }
}

/// Saisie sécurisée (« Secure Keyboard Entry ») : tant qu'une app la tient,
/// les frappes simulées peuvent être bloquées.
enum SecureInput {
    /// Nom de l'app qui tient la saisie sécurisée, si ce n'est ni `pid` ni
    /// Verrou. Un champ de mot de passe de l'app visée l'active aussi : c'est
    /// normal, et le remplissage y fonctionne.
    static func foreignOwner(besides pid: pid_t) -> String? {
        guard IsSecureEventInputEnabled() else { return nil }
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard let owner = (session?["kCGSSessionSecureInputPID"] as? NSNumber)?.int32Value else {
            // Propriétaire inconnu : on ne sait pas, on ne bloque pas.
            return nil
        }
        if owner == pid || owner == ProcessInfo.processInfo.processIdentifier { return nil }
        return NSRunningApplication(processIdentifier: owner)?.localizedName ?? "une autre app"
    }
}

// MARK: Frappes

/// Une touche simulée : un caractère (texte Unicode, pas un code de touche),
/// Tab ou Retour.
enum SyntheticKey: Equatable {
    case character(String)
    case tab
    case returnKey
}

/// Où partent les frappes : le clavier du système, ou un enregistreur en test.
protocol KeystrokeSink {
    func post(_ key: SyntheticKey)
}

/// Joue les frappes calculées par le cœur Rust, un caractère à la fois.
struct KeystrokePlayer {
    let sink: KeystrokeSink
    /// Pause entre deux frappes : certaines apps perdent des caractères tapés
    /// trop vite ; un peu plus après Tab, le temps que le champ suivant prenne le focus.
    var characterDelay: Duration = .milliseconds(6)
    var fieldDelay: Duration = .milliseconds(60)

    static func keys(for strokes: [AutofillKeystroke]) -> [SyntheticKey] {
        strokes.flatMap { stroke -> [SyntheticKey] in
            switch stroke {
            case .text(let value): value.map { .character(String($0)) }
            case .tab: [.tab]
            case .`return`: [.returnKey]
            }
        }
    }

    func play(_ strokes: [AutofillKeystroke]) async {
        for key in Self.keys(for: strokes) {
            sink.post(key)
            if case .character = key {
                try? await Task.sleep(for: characterDelay)
            } else {
                try? await Task.sleep(for: fieldDelay)
            }
        }
    }
}

/// Frappes envoyées au système par `CGEvent`. Le texte passe par
/// `keyboardSetUnicodeString` : la disposition du clavier n'intervient pas.
/// Les modificateurs sont effacés (⌘ encore enfoncé ne doit pas transformer
/// un caractère en raccourci).
struct CGEventKeystrokeSink: KeystrokeSink {
    private let source = CGEventSource(stateID: .privateState)

    func post(_ key: SyntheticKey) {
        switch key {
        case .character(let text):
            let units = Array(text.utf16)
            for down in [true, false] {
                guard let event = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: down) else { continue }
                event.flags = []
                units.withUnsafeBufferPointer {
                    event.keyboardSetUnicodeString(stringLength: units.count, unicodeString: $0.baseAddress)
                }
                event.post(tap: .cghidEventTap)
            }
        case .tab:
            press(CGKeyCode(kVK_Tab))
        case .returnKey:
            press(CGKeyCode(kVK_Return))
        }
    }

    private func press(_ code: CGKeyCode) {
        for down in [true, false] {
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: down) else { continue }
            event.flags = []
            event.post(tap: .cghidEventTap)
        }
    }
}

// MARK: Vues

/// Bandeau de l'accès rapide en mode remplissage : l'app visée.
struct AutofillTargetBar: View {
    let target: AutofillTarget

    var body: some View {
        HStack(spacing: 8) {
            if let icon = target.icon {
                Image(nsImage: icon).resizable().frame(width: 18, height: 18)
            }
            Text("Remplir dans « \(target.name) »")
                .font(.callout.weight(.medium))
            Spacer()
            if let owner = target.secureInputOwner {
                Label("Saisie sécurisée activée par « \(owner) »", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(1)
                    .help("Tant qu'elle est active, macOS peut bloquer les frappes de Verrou.")
            }
        }
        .padding(.horizontal, 20)
        .frame(height: 32)
    }
}

/// Association de l'identifiant affiché à l'app visée.
struct AutofillLinkRow: View {
    @Environment(AppModel.self) private var model
    let autofill: UniversalAutofill
    let target: AutofillTarget
    let item: ItemSummary

    var body: some View {
        Group {
            if item.category != .login {
                EmptyView()
            } else if autofill.isLinked(item.id, to: target) {
                Label("Associé à « \(target.name) »", systemImage: "link")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if model.canEdit {
                Button {
                    Task { await autofill.link(itemID: item.id, to: target) }
                } label: {
                    Label("Associer à « \(target.name) »", systemImage: "link.badge.plus")
                        .lineLimit(1)
                }
                .buttonStyle(.link)
                .font(.caption)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.bottom, 12)
    }
}

/// Autorisation manquante : explication et bouton vers les réglages.
struct AccessibilityRequestView: View {
    var body: some View {
        // Revérifié chaque seconde : l'autorisation se donne dans une autre app.
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            VStack(spacing: 12) {
                Image(systemName: "keyboard.badge.ellipsis").font(.largeTitle).foregroundStyle(.secondary)
                Text("Verrou doit pouvoir taper pour vous").font(.headline)
                Text("Pour remplir l'identifiant et le mot de passe dans une autre app, autorisez Verrou dans Réglages Système → Confidentialité et sécurité → Accessibilité, puis refaites le raccourci.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 440)
                Button("Ouvrir Réglages Système") { AccessibilityPermission.request() }
                    .buttonStyle(.borderedProminent)
                Text("Verrou étant signé sur ce Mac, macOS peut oublier cette autorisation après une mise à jour : retirez-le de la liste et ajoutez-le à nouveau.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 440)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// Réglages du remplissage dans les apps (onglet Général).
struct AppAutofillSection: View {
    @AppStorage(UniversalAutofill.enabledKey) private var enabled = true
    @AppStorage(UniversalAutofill.shortcutKey) private var shortcut = AutofillShortcut.command
    @AppStorage(UniversalAutofill.submitKey) private var submit = false
    @AppStorage(UniversalAutofill.copyTotpKey) private var copyTotp = true

    var body: some View {
        Section {
            Toggle("Remplir les identifiants dans les apps", isOn: $enabled)
            if enabled {
                Picker("Raccourci", selection: $shortcut) {
                    ForEach(AutofillShortcut.allCases) { Text($0.label).tag($0) }
                }
                Toggle("Valider avec Retour après le mot de passe", isOn: $submit)
                Toggle("Copier le code à usage unique après le remplissage", isOn: $copyTotp)
                LabeledContent("Accessibilité") {
                    TimelineView(.periodic(from: .now, by: 2)) { _ in
                        if AccessibilityPermission.isGranted {
                            Label("Autorisée", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        } else {
                            Button("Autoriser…") { AccessibilityPermission.request() }
                        }
                    }
                }
            }
        } header: {
            Text("Remplissage dans les apps")
        } footer: {
            Text(footer)
                .foregroundStyle(UniversalAutofill.current?.shortcutUnavailable == true ? Color.red : .secondary)
        }
    }

    private var footer: String {
        if enabled, UniversalAutofill.current?.shortcutUnavailable == true {
            return "\(shortcut.label) est déjà pris par une autre app : choisissez une autre combinaison."
        }
        return "\(shortcut.label) dans n'importe quelle app : Verrou propose les identifiants associés à cette app, puis tape l'identifiant, Tab et le mot de passe. ⌘↩ associe l'identifiant choisi à l'app (synchronisé avec le coffre). La touche est celle à gauche de Retour. Verrou étant signé sur ce Mac, macOS peut oublier l'autorisation Accessibilité après une mise à jour : retirez-le de la liste et autorisez-le à nouveau."
    }
}

/// Petit message passager en haut de l'écran : l'accès rapide est fermé
/// et Verrou n'est plus au premier plan quand le remplissage se termine.
@MainActor
enum AutofillHUD {
    private static var panel: NSPanel?
    private static var hideTask: Task<Void, Never>?

    static func show(_ message: String, detail: String? = nil, failure: Bool = false) {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        let view = HStack(spacing: 10) {
            Image(systemName: failure ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(failure ? Color.orange : Color.green)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(message).font(.callout.weight(.semibold))
                if let detail {
                    Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .frame(width: 380, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        let hosting = NSHostingView(rootView: view)
        panel.contentView = hosting
        let size = hosting.fittingSize
        if let screen = NSScreen.main {
            let frame = screen.visibleFrame
            panel.setFrame(NSRect(x: frame.midX - size.width / 2, y: frame.maxY - size.height - 24,
                                  width: size.width, height: size.height), display: true)
        }
        panel.orderFrontRegardless()
        hideTask?.cancel()
        hideTask = Task {
            try? await Task.sleep(for: .seconds(failure ? 5 : 2.5))
            guard !Task.isCancelled else { return }
            panel.orderOut(nil)
        }
    }

    private static func makePanel() -> NSPanel {
        let panel = NSPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel],
                            backing: .buffered, defer: true)
        panel.level = .statusBar
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.ignoresMouseEvents = true
        panel.isReleasedWhenClosed = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        return panel
    }
}
