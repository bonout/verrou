import AppKit
import Carbon.HIToolbox
import SwiftUI

/// Quick access window, opened from any application with ⌘⇧Space, the way
/// Spotlight is.
@MainActor
final class QuickAccessController {
    private let model: AppModel
    private var panel: QuickAccessPanel?
    private var hotKey: HotKey?
    /// Demo: the window stays open even if Verrou is not in the foreground
    /// (macOS refuses to hand it control while another app is in use).
    var staysOpen = false
    /// Filling in apps (⌘\): the window also serves to choose the login to
    /// type in the frontmost app.
    var autofill: UniversalAutofill?
    var generator: GeneratorWindow?

    init(model: AppModel) {
        self.model = model
        hotKey = HotKey(keyCode: UInt32(kVK_Space), modifiers: UInt32(cmdKey | shiftKey)) { [weak self] in
            self?.toggle()
        }
    }

    var isVisible: Bool { panel?.isVisible ?? false }

    func toggle() {
        if isVisible {
            close()
        } else {
            autofill?.target = nil
            show()
        }
    }

    /// `anchor`: center on this rectangle rather than on the screen (the demo
    /// uses it so the window fits in the capture).
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
        autofill?.target = nil
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
        let root = QuickAccessView(autofill: autofill, close: { [weak self] in self?.close() },
                                   generate: { [weak self] in
                                       self?.close()
                                       self?.generator?.show()
                                   })
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

/// Global shortcut through Carbon: the only API that doesn't require
/// "Accessibility" access for a keyboard shortcut. Several shortcuts (quick
/// access ⌘⇧Space, filling ⌘\) share a single handler, which finds the
/// action by the shortcut's ID.
final class HotKey {
    private var reference: EventHotKeyRef?
    private let id: UInt32
    /// `false`: the combination is already taken (by another app, often).
    let isRegistered: Bool
    nonisolated(unsafe) private static var actions: [UInt32: () -> Void] = [:]
    nonisolated(unsafe) private static var handler: EventHandlerRef?
    nonisolated(unsafe) private static var nextID: UInt32 = 1

    init(keyCode: UInt32, modifiers: UInt32, action: @escaping @MainActor @Sendable () -> Void) {
        Self.installHandlerIfNeeded()
        id = Self.nextID
        Self.nextID += 1
        Self.actions[id] = { MainActor.assumeIsolated { action() } }
        let hotKeyID = EventHotKeyID(signature: OSType(0x5652_5255), id: id) // "VRRU"
        isRegistered = RegisterEventHotKey(keyCode, modifiers, hotKeyID, GetApplicationEventTarget(), 0, &reference) == noErr
    }

    private static func installHandlerIfNeeded() {
        guard handler == nil else { return }
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, event, _ in
            var pressed = EventHotKeyID()
            let status = GetEventParameter(event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID),
                                           nil, MemoryLayout<EventHotKeyID>.size, nil, &pressed)
            guard status == noErr, pressed.signature == OSType(0x5652_5255) else { return OSStatus(eventNotHandledErr) }
            HotKey.actions[pressed.id]?()
            return noErr
        }, 1, &spec, nil, &handler)
    }

    deinit {
        if let reference { UnregisterEventHotKey(reference) }
        Self.actions[id] = nil
    }
}

// MARK: View

struct QuickAccessView: View {
    @Environment(AppModel.self) private var model
    var autofill: UniversalAutofill?
    let close: () -> Void
    var generate: () -> Void = {}
    @FocusState private var focused: Bool
    @State private var selected = 0

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                AppMark(size: 26)
                // The placeholder doesn't take the field's font: without giving
                // it that, nor an explicit height, it is cut off at the bottom.
                TextField("", text: $model.quickQuery,
                          prompt: Text("Search for a login, a card, a code…")
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

            if let autofill, let target = autofill.target {
                AutofillTargetBar(target: target)
                Divider()
            }

            if model.lockState != .unlocked {
                lockedState
            } else if autofill?.target != nil, !AccessibilityPermission.isGranted {
                AccessibilityRequestView()
            } else if hits.isEmpty {
                VStack(spacing: 14) {
                    Text(emptyMessage)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    if autofill?.target == nil {
                        Button("Generate Password…", systemImage: "wand.and.stars", action: generate)
                    }
                }
                .padding(.horizontal, 40)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HStack(spacing: 0) {
                    resultsList
                    Divider()
                    if let current {
                        VStack(spacing: 0) {
                            QuickDetail(summary: current)
                            if let autofill, let target = autofill.target {
                                AutofillLinkRow(autofill: autofill, target: target, item: current)
                            }
                        }
                        .frame(width: 250)
                    }
                }
            }

            Divider()
            HStack(spacing: 16) {
                if autofill?.target != nil {
                    KeyHint(keys: "↩", label: "Fill")
                    if model.canEdit {
                        KeyHint(keys: "⌘↩", label: "Link and Fill")
                    }
                } else {
                    KeyHint(keys: "↩", label: "Copy Password")
                }
                KeyHint(keys: "⌘C", label: "Username")
                KeyHint(keys: "⌥⌘C", label: "Code")
                if autofill?.target == nil {
                    KeyHint(keys: "⌥⌘G", label: "Generate")
                }
                Spacer()
                KeyHint(keys: "esc", label: "Close")
            }
            .padding(.horizontal, 16)
            .frame(height: 34)
        }
        .frame(width: 680, height: 440)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
        // The cursor in the field on each opening: typing goes straight in.
        .onAppear { focused = true; selected = 0 }
        .onChange(of: model.quickAccessOpenings) {
            selected = 0
            focused = false
            Task { focused = true }
        }
        .onChange(of: model.quickQuery) { selected = 0 }
        // Unlocked from the window: the app's logins arrive.
        .onChange(of: model.lockState) { autofill?.refreshSuggestions() }
        .onKeyPress(.downArrow) { selected = min(selected + 1, max(hits.count - 1, 0)); return .handled }
        .onKeyPress(.upArrow) { selected = max(selected - 1, 0); return .handled }
        .onKeyPress(.escape) { close(); return .handled }
        .background {
            Group {
                Button("") { copyUsername() }.keyboardShortcut("c", modifiers: .command)
                Button("") { copyCode() }.keyboardShortcut("c", modifiers: [.command, .option])
                Button("") { fillAndLink() }.keyboardShortcut(.return, modifiers: .command)
                Button("") { generate() }.keyboardShortcut("g", modifiers: [.command, .option])
            }
            .opacity(0)
            .accessibilityHidden(true)
        }
    }

    private var hits: [ResultRow] {
        guard model.lockState == .unlocked else { return [] }
        guard let autofill, autofill.target != nil else { return model.quickRows }
        // Filling: without a search, the logins linked to the app; when
        // searching, only logins (the rest can't be typed).
        if model.quickQuery.isEmpty {
            return autofill.suggestions.map { ResultRow(summary: $0, highlights: []) }
        }
        return model.quickRows.filter { $0.summary.category == .login }
    }

    private var emptyMessage: String {
        if let target = autofill?.target, model.quickQuery.isEmpty {
            return model.canEdit
                ? String(localized: "No login linked to “\(target.name)”. Search for it, then ⌘↩ to fill it and link it to this app.")
                : String(localized: "No login linked to “\(target.name)”. Type to search the vault.")
        }
        return model.quickQuery.isEmpty ? String(localized: "Type to search the vault") : String(localized: "No results")
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
                            Text(summary.displaySubtitle).font(.caption).foregroundStyle(index == selected ? AnyShapeStyle(Theme.onAccentSecondary()) : AnyShapeStyle(.secondary)).lineLimit(1)
                        }
                        Spacer()
                        if summary.hasTotp {
                            Image(systemName: "clock.badge.checkmark").font(.caption)
                                .accessibilityLabel("One-time code")
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
                .accessibilityHidden(true)
            Text("Verrou is locked").font(.headline)
            if model.canUseTouchID {
                Button {
                    Task { await model.unlockWithBiometrics() }
                } label: {
                    Label("Unlock with Touch ID", systemImage: "touchid")
                }
                .buttonStyle(.borderedProminent)
            } else {
                // Without Touch ID, the password is entered in the main window.
                Button("Open Verrou") {
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
        if let autofill, autofill.target != nil {
            autofill.fill(itemID: item.id, link: false)
            return
        }
        if item.category == .login {
            model.copyPassword(of: item.id)
        } else {
            model.selection = item.id
            NSApp.windows.first { $0.identifier?.rawValue == "main" }?.makeKeyAndOrderFront(nil)
        }
        close()
    }

    private func fillAndLink() {
        guard let item = current, let autofill, autofill.target != nil else { return }
        autofill.fill(itemID: item.id, link: model.canEdit)
    }

    private func copyUsername() {
        guard let item = current, item.category == .login else { return }
        model.copy(item.subtitle, label: String(localized: "Username"), secret: false)
    }

    private func copyCode() {
        guard let item = current, item.hasTotp else { return }
        model.copyCode(of: item.id)
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
                labeled("Username") { Text(summary.subtitle).lineLimit(1) }
                labeled("Password") { MaskedText() }
            }
            if summary.hasTotp {
                labeled("One-time code") {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        if let code = model.totpCode(of: summary.id, at: context.date) {
                            TotpCodeView(code: code, size: 18)
                        } else {
                            MaskedText(count: 6)
                        }
                    }
                }
            }
            Spacer()
        }
        .padding(16)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private func labeled(_ label: LocalizedStringKey, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            content()
        }
    }
}
