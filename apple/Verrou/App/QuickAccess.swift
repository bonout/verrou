import AppKit
import Carbon.HIToolbox
import SwiftUI

/// Fenêtre d'accès rapide, ouverte depuis n'importe quelle application par
/// ⌘⇧Espace, à la manière de Spotlight.
@MainActor
final class QuickAccessController {
    private let model: AppModel
    private var panel: QuickAccessPanel?
    private var hotKey: HotKey?
    /// Démonstration : la fenêtre reste ouverte même si Verrou n'est pas au
    /// premier plan (macOS refuse de lui donner la main pendant qu'on se sert
    /// d'une autre app).
    var staysOpen = false

    init(model: AppModel) {
        self.model = model
        hotKey = HotKey(keyCode: UInt32(kVK_Space), modifiers: UInt32(cmdKey | shiftKey)) { [weak self] in
            self?.toggle()
        }
    }

    var isVisible: Bool { panel?.isVisible ?? false }

    func toggle() {
        if isVisible { close() } else { show() }
    }

    /// `anchor` : centrer sur ce rectangle plutôt que sur l'écran (la
    /// démonstration s'en sert pour que la fenêtre tienne dans la capture).
    func show(query: String = "", anchor: NSRect? = nil) {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        model.quickQuery = query
        if let anchor {
            let size = panel.frame.size
            panel.setFrameOrigin(NSPoint(x: anchor.midX - size.width / 2, y: anchor.midY - size.height / 2 + 60))
        } else if let screen = NSScreen.main {
            let frame = screen.visibleFrame
            let size = panel.frame.size
            panel.setFrameOrigin(NSPoint(x: frame.midX - size.width / 2, y: frame.minY + frame.height * 0.62))
        }
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        if staysOpen { panel.orderFrontRegardless() }
        model.quickAccessOpened()
    }

    func close() {
        panel?.orderOut(nil)
        model.quickQuery = ""
    }

    private func makePanel() -> QuickAccessPanel {
        let panel = QuickAccessPanel(
            contentRect: NSRect(x: 0, y: 0, width: 680, height: 440),
            styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel],
            backing: .buffered, defer: false)
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = !staysOpen
        panel.isReleasedWhenClosed = false
        panel.backgroundColor = .clear
        panel.standardWindowButton(.closeButton)?.isHidden = true
        panel.standardWindowButton(.miniaturizeButton)?.isHidden = true
        panel.standardWindowButton(.zoomButton)?.isHidden = true
        panel.onResignKey = { [weak self] in
            guard let self, !self.staysOpen else { return }
            self.close()
        }
        let root = QuickAccessView(close: { [weak self] in self?.close() })
            .environment(model)
        panel.contentView = NSHostingView(rootView: root)
        return panel
    }
}

final class QuickAccessPanel: NSPanel {
    var onResignKey: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override func resignKey() {
        super.resignKey()
        onResignKey?()
    }
}

/// Raccourci global via Carbon : la seule API qui ne demande pas l'accès
/// « Accessibilité » pour un raccourci clavier.
final class HotKey {
    private var reference: EventHotKeyRef?
    private var handler: EventHandlerRef?
    nonisolated(unsafe) private static var action: (() -> Void)?

    init(keyCode: UInt32, modifiers: UInt32, action: @escaping @MainActor () -> Void) {
        Self.action = { MainActor.assumeIsolated { action() } }
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, _, _ in
            HotKey.action?()
            return noErr
        }, 1, &spec, nil, &handler)
        let id = EventHotKeyID(signature: OSType(0x5652_5255), id: 1) // « VRRU »
        RegisterEventHotKey(keyCode, modifiers, id, GetApplicationEventTarget(), 0, &reference)
    }

    deinit {
        if let reference { UnregisterEventHotKey(reference) }
        if let handler { RemoveEventHandler(handler) }
    }
}

// MARK: Vue

struct QuickAccessView: View {
    @Environment(AppModel.self) private var model
    let close: () -> Void
    @FocusState private var focused: Bool
    @State private var selected = 0

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                AppMark(size: 26)
                // Le texte indicatif ne prend pas la police du champ : sans la
                // lui donner, ni une hauteur explicite, il est coupé en bas.
                TextField("", text: $model.quickQuery,
                          prompt: Text("Rechercher un identifiant, une carte, un code…")
                              .font(.system(size: 22, weight: .regular)))
                    .textFieldStyle(.plain)
                    .font(.system(size: 22, weight: .regular))
                    .frame(height: 30)
                    .focused($focused)
                    .onSubmit(primaryAction)
            }
            .padding(.horizontal, 20)
            .frame(height: 64)

            Divider()

            if model.lockState != .unlocked {
                lockedState
            } else if hits.isEmpty {
                Text(model.quickQuery.isEmpty ? "Tapez pour chercher dans le coffre" : "Aucun résultat")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HStack(spacing: 0) {
                    resultsList
                    Divider()
                    if let current {
                        QuickDetail(summary: current)
                            .frame(width: 250)
                    }
                }
            }

            Divider()
            HStack(spacing: 16) {
                KeyHint(keys: "↩", label: "Copier le mot de passe")
                KeyHint(keys: "⌘C", label: "Identifiant")
                KeyHint(keys: "⌥⌘C", label: "Code")
                Spacer()
                KeyHint(keys: "esc", label: "Fermer")
            }
            .padding(.horizontal, 16)
            .frame(height: 34)
        }
        .frame(width: 680, height: 440)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
        // Le curseur dans le champ à chaque ouverture : on tape directement.
        .onAppear { focused = true; selected = 0 }
        .onChange(of: model.quickAccessOpenings) {
            selected = 0
            focused = false
            Task { focused = true }
        }
        .onChange(of: model.quickQuery) { selected = 0 }
        .onKeyPress(.downArrow) { selected = min(selected + 1, max(hits.count - 1, 0)); return .handled }
        .onKeyPress(.upArrow) { selected = max(selected - 1, 0); return .handled }
        .onKeyPress(.escape) { close(); return .handled }
        .background {
            Group {
                Button("") { copyUsername() }.keyboardShortcut("c", modifiers: .command)
                Button("") { copyCode() }.keyboardShortcut("c", modifiers: [.command, .option])
            }
            .opacity(0)
        }
    }

    private var hits: [ResultRow] {
        model.lockState == .unlocked ? model.quickRows : []
    }

    private var resultsList: some View {
        ScrollView {
            VStack(spacing: 2) {
                ForEach(Array(hits.enumerated()), id: \.element.id) { index, hit in
                    let summary = hit.summary
                    HStack(spacing: 11) {
                        ItemIcon(summary: summary, size: 30)
                        VStack(alignment: .leading, spacing: 1) {
                            HighlightedText(text: summary.title, highlights: hit.highlights,
                                            tint: index == selected ? nil : Theme.accent).lineLimit(1)
                            Text(summary.subtitle).font(.caption).foregroundStyle(index == selected ? Color.white.opacity(0.8) : .secondary).lineLimit(1)
                        }
                        Spacer()
                        if summary.hasTotp {
                            Image(systemName: "clock.badge.checkmark").font(.caption)
                        }
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .foregroundStyle(index == selected ? Color.white : Color.primary)
                    .background(index == selected ? Theme.accent : .clear, in: RoundedRectangle(cornerRadius: 8))
                    .contentShape(Rectangle())
                    .onTapGesture { selected = index }
                }
            }
            .padding(8)
        }
    }

    private var lockedState: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
            Text("Verrou est verrouillé").font(.headline)
            if model.canUseTouchID {
                Button {
                    Task { await model.unlockWithBiometrics() }
                } label: {
                    Label("Déverrouiller avec Touch ID", systemImage: "touchid")
                }
                .buttonStyle(.borderedProminent)
            } else {
                // Sans Touch ID, le mot de passe se saisit dans la fenêtre principale.
                Button("Ouvrir Verrou") {
                    close()
                    NSApp.activate()
                    NSApp.windows.first { !($0 is NSPanel) && $0.canBecomeMain }?.makeKeyAndOrderFront(nil)
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var current: ItemSummary? {
        hits.indices.contains(selected) ? hits[selected].summary : nil
    }

    private func primaryAction() {
        guard let item = current else { return }
        if item.category == .login {
            model.copyPassword(of: item.id)
        } else {
            model.selection = item.id
            NSApp.windows.first { $0.identifier?.rawValue == "main" }?.makeKeyAndOrderFront(nil)
        }
        close()
    }

    private func copyUsername() {
        guard let item = current, item.category == .login else { return }
        model.copy(item.subtitle, label: "Identifiant", secret: false)
    }

    private func copyCode() {
        guard let item = current, item.hasTotp,
              let code = try? model.session.totp(id: item.id, unixTime: UInt64(Date().timeIntervalSince1970)) else { return }
        model.copy(code.code, label: "Code", secret: true)
        close()
    }
}

struct QuickDetail: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                ItemIcon(summary: summary, size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(summary.title).font(.headline).lineLimit(2)
                    Text(summary.host ?? summary.category.singular).font(.caption).foregroundStyle(.secondary)
                }
            }
            if summary.category == .login {
                labeled("Identifiant") { Text(summary.subtitle).lineLimit(1) }
                labeled("Mot de passe") { MaskedText() }
            }
            if summary.hasTotp {
                labeled("Code à usage unique") {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        if let code = try? model.session.totp(id: summary.id, unixTime: UInt64(context.date.timeIntervalSince1970)) {
                            TotpCodeView(code: code, size: 18)
                        }
                    }
                }
            }
            Spacer()
        }
        .padding(16)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private func labeled(_ label: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            content()
        }
    }
}
