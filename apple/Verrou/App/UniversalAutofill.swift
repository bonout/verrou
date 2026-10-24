import AppKit
import ApplicationServices
import Carbon.HIToolbox
import SwiftUI

/// Filling in any Mac app (⌘\ by default).
///
/// The shortcut remembers the frontmost app, opens quick access with the
/// logins linked to that app (`macapp://<bundle identifier>` among the
/// item's sites, synced), then, once the login is chosen, hands back to the
/// app and types the username, Tab and the password as Unicode characters
/// (independent of the keyboard layout).
///
/// Typing on the keyboard for another app requires "Accessibility" access.
@MainActor
@Observable
final class UniversalAutofill {
    /// Settings (General tab).
    static let enabledKey = "appAutofillEnabled"
    static let shortcutKey = "appAutofillShortcut"
    static let submitKey = "appAutofillSubmit"
    static let copyTotpKey = "appAutofillCopyTotp"

    /// The app's instance, for the settings.
    private(set) static weak var current: UniversalAutofill?

    /// App to fill in, remembered when the shortcut is pressed. `nil`: quick
    /// access works normally.
    var target: AutofillTarget?
    /// Logins linked to the target app.
    private(set) var suggestions: [ItemSummary] = []
    /// The chosen combination is already taken by another app.
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

    /// (Re)registers the shortcut according to the settings.
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

    /// The shortcut: remember the frontmost app, then open quick access.
    func trigger() {
        guard let quickAccess else { return }
        let front = NSWorkspace.shared.frontmostApplication
        // Verrou itself in the foreground (or nothing identifiable): there is
        // no other app to type in, quick access works normally.
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

    /// Links the login to the target app, without filling.
    func link(itemID: String, to target: AutofillTarget) async {
        guard model.canEdit else { return }
        do {
            if try await model.session.linkToApp(id: itemID, bundleId: target.bundleID) {
                model.afterWrite(select: model.selection)
                if self.target?.bundleID == target.bundleID { refreshSuggestions() }
                AutofillHUD.show(String(localized: "Linked to “\(target.name)”"),
                                 detail: String(localized: "Suggested first on the next ⌘\\"))
            }
        } catch {
            AutofillHUD.show(String(localized: "Couldn't link"), detail: AppModel.describe(error), failure: true)
        }
    }

    /// Fills the chosen login in the target app: confirmation of a protected
    /// item, back to the app, keystrokes, then one-time code copied and link
    /// requested.
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
        let title = summary?.title ?? String(localized: "this item")
        guard model.lockState == .unlocked else { return }
        // Protected item: Touch ID or master password, as for copying it.
        if model.session.needsConfirmation(id: itemID) {
            guard await model.confirmAccess(itemID: itemID, title: title) else { return }
        }
        guard AccessibilityPermission.isGranted else {
            AutofillHUD.show(String(localized: "“Accessibility” access required"),
                             detail: String(localized: "System Settings → Privacy & Security → Accessibility"), failure: true)
            AccessibilityPermission.request()
            return
        }
        let keys: [AutofillKeystroke]
        do {
            keys = try model.session.autofillKeystrokes(id: itemID, submit: Self.submits)
        } catch {
            AutofillHUD.show(String(localized: "Couldn't fill"), detail: AppModel.describe(error), failure: true)
            return
        }
        quickAccess?.close()
        guard await activate(target) else {
            AutofillHUD.show(String(localized: "Couldn't go back to “\(target.name)”"),
                             detail: String(localized: "Nothing was typed"), failure: true)
            return
        }
        // Another app turned on secure input (Terminal, for example): the
        // keystrokes may not arrive, or arrive elsewhere. Hold off.
        if let owner = SecureInput.foreignOwner(besides: target.pid) {
            AutofillHUD.show(String(localized: "Secure input turned on by “\(owner)”"),
                             detail: String(localized: "Nothing was typed: turn it off, or copy the password from quick access (⌘⇧Space)."),
                             failure: true)
            return
        }
        await KeystrokePlayer(sink: sink).play(keys)
        if Self.copiesTotp, summary?.hasTotp == true, let code = model.totpCode(of: itemID) {
            model.copy(code.code, label: String(localized: "Code"), secret: true)
            AutofillHUD.show(String(localized: "One-time code copied"),
                             detail: String(localized: "Cleared from the clipboard in 90 s"))
        }
        if link, model.canEdit {
            await self.link(itemID: itemID, to: target)
        }
    }

    /// Hands the foreground back to the target app and waits until it has it.
    private func activate(_ target: AutofillTarget) async -> Bool {
        guard let app = NSRunningApplication(processIdentifier: target.pid), !app.isTerminated else { return false }
        NSApp.yieldActivation(to: app)
        app.activate()
        for _ in 0..<75 {
            if NSWorkspace.shared.frontmostApplication?.processIdentifier == target.pid {
                // Time for its window to become key again and give focus back to the field.
                try? await Task.sleep(for: .milliseconds(150))
                return true
            }
            try? await Task.sleep(for: .milliseconds(20))
        }
        return false
    }
}

/// The app to fill in, remembered when the shortcut is pressed.
struct AutofillTarget: Equatable {
    let pid: pid_t
    let bundleID: String
    let name: String
    let icon: NSImage?
    /// App (other than the target) that had turned on secure input.
    let secureInputOwner: String?
}

/// Offered combinations. The key is the one of `\` on a US keyboard (left
/// of Return): its position, whatever the layout; the label shows the
/// character of the active layout.
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
    /// Character a key produces in the active layout (without modifier or
    /// dead key).
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

/// Permission to type for other apps ("Accessibility").
enum AccessibilityPermission {
    static var isGranted: Bool {
        AXIsProcessTrustedWithOptions(nil) || CGPreflightPostEventAccess()
    }

    /// Asks macOS to add Verrou to the list (and opens the settings).
    static func request() {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        if AXIsProcessTrustedWithOptions(options) { return }
        // Sandboxed app: this request is what adds Verrou to the list.
        if CGRequestPostEventAccess() { return }
        openSettings()
    }

    static func openSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(url)
        }
    }
}

/// Secure input ("Secure Keyboard Entry"): while an app holds it, simulated
/// keystrokes can be blocked.
enum SecureInput {
    /// Name of the app holding secure input, if it is neither `pid` nor
    /// Verrou. A password field of the target app turns it on too: that's
    /// normal, and filling works there.
    static func foreignOwner(besides pid: pid_t) -> String? {
        guard IsSecureEventInputEnabled() else { return nil }
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard let owner = (session?["kCGSSessionSecureInputPID"] as? NSNumber)?.int32Value else {
            // Unknown owner: we don't know, we don't block.
            return nil
        }
        if owner == pid || owner == ProcessInfo.processInfo.processIdentifier { return nil }
        return NSRunningApplication(processIdentifier: owner)?.localizedName ?? String(localized: "another app")
    }
}

// MARK: Keystrokes

/// A simulated key: a character (Unicode text, not a key code), Tab or
/// Return.
enum SyntheticKey: Equatable {
    case character(String)
    case tab
    case returnKey
}

/// Where the keystrokes go: the system keyboard, or a recorder in tests.
protocol KeystrokeSink {
    func post(_ key: SyntheticKey)
}

/// Plays the keystrokes computed by the Rust core, one character at a time.
struct KeystrokePlayer {
    let sink: KeystrokeSink
    /// Pause between two keystrokes: some apps lose characters typed too
    /// fast; a bit more after Tab, for the next field to take focus.
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

/// Keystrokes sent to the system through `CGEvent`. The text goes through
/// `keyboardSetUnicodeString`: the keyboard layout plays no part. Modifiers
/// are cleared (⌘ still held down must not turn a character into a
/// shortcut).
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

// MARK: Views

/// Quick access banner in fill mode: the target app.
struct AutofillTargetBar: View {
    let target: AutofillTarget

    var body: some View {
        HStack(spacing: 8) {
            if let icon = target.icon {
                Image(nsImage: icon).resizable().frame(width: 18, height: 18)
            }
            Text("Fill in “\(target.name)”")
                .font(.callout.weight(.medium))
            Spacer()
            if let owner = target.secureInputOwner {
                Label("Secure input turned on by “\(owner)”", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(1)
                    .help("While it is on, macOS can block Verrou's keystrokes.")
            }
        }
        .padding(.horizontal, 20)
        .frame(height: 32)
    }
}

/// Linking the displayed login to the target app.
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
                Label("Linked to “\(target.name)”", systemImage: "link")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if model.canEdit {
                Button {
                    Task { await autofill.link(itemID: item.id, to: target) }
                } label: {
                    Label("Link to “\(target.name)”", systemImage: "link.badge.plus")
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

/// Missing permission: explanation and button to the settings.
struct AccessibilityRequestView: View {
    var body: some View {
        // Checked again every second: the permission is given in another app.
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            VStack(spacing: 12) {
                Image(systemName: "keyboard.badge.ellipsis").font(.largeTitle).foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text("Verrou needs to be able to type for you").font(.headline)
                Text("To fill the username and password in another app, allow Verrou in System Settings → Privacy & Security → Accessibility, then press the shortcut again.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 440)
                Button("Open System Settings") { AccessibilityPermission.request() }
                    .buttonStyle(.borderedProminent)
                Text("Since Verrou is signed on this Mac, macOS may forget this permission after an update: remove it from the list and add it again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 440)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// Settings of filling in apps (General tab).
struct AppAutofillSection: View {
    @AppStorage(UniversalAutofill.enabledKey) private var enabled = true
    @AppStorage(UniversalAutofill.shortcutKey) private var shortcut = AutofillShortcut.command
    @AppStorage(UniversalAutofill.submitKey) private var submit = false
    @AppStorage(UniversalAutofill.copyTotpKey) private var copyTotp = true

    var body: some View {
        Section {
            Toggle("Fill logins in apps", isOn: $enabled)
            if enabled {
                Picker("Shortcut", selection: $shortcut) {
                    ForEach(AutofillShortcut.allCases) { Text($0.label).tag($0) }
                }
                Toggle("Press Return after the password", isOn: $submit)
                Toggle("Copy the one-time code after filling", isOn: $copyTotp)
                LabeledContent("Accessibility") {
                    TimelineView(.periodic(from: .now, by: 2)) { _ in
                        if AccessibilityPermission.isGranted {
                            Label("Allowed", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        } else {
                            Button("Allow…") { AccessibilityPermission.request() }
                        }
                    }
                }
            }
        } header: {
            Text("Filling in apps")
        } footer: {
            Text(footer)
                .foregroundStyle(UniversalAutofill.current?.shortcutUnavailable == true ? Color.red : .secondary)
        }
    }

    private var footer: LocalizedStringKey {
        if enabled, UniversalAutofill.current?.shortcutUnavailable == true {
            return "\(shortcut.label) is already taken by another app: choose another combination."
        }
        return "\(shortcut.label) in any app: Verrou offers the logins linked to that app, then types the username, Tab and the password. ⌘↩ links the chosen login to the app (synced with the vault). The key is the one left of Return. Since Verrou is signed on this Mac, macOS may forget the Accessibility permission after an update: remove it from the list and allow it again."
    }
}

/// Small passing message at the top of the screen: quick access is closed
/// and Verrou is no longer in the foreground when filling finishes.
@MainActor
enum AutofillHUD {
    private static var panel: NSPanel?
    private static var hideTask: Task<Void, Never>?

    static func show(_ message: String, detail: String? = nil, failure: Bool = false) {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        let view = HStack(spacing: 10) {
            Image(systemName: failure ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .accessibilityHidden(true)
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
