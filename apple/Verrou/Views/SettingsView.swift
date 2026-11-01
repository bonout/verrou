import SwiftUI

/// Settings (⌘,), in tabs: General, AutoFill, Security, Vault, Account,
/// Advanced.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("settingsTab") private var tab = SettingsTab.general

    var body: some View {
        TabView(selection: $tab) {
            GeneralSettings()
                .tabItem { Label("General", systemImage: "gearshape") }
                .tag(SettingsTab.general)
            AutoFillSettings()
                .tabItem { Label("AutoFill", systemImage: "key.viewfinder") }
                .tag(SettingsTab.autofill)
            SecuritySettings()
                .tabItem { Label("Security", systemImage: "lock.shield") }
                .tag(SettingsTab.security)
            VaultSettings()
                .tabItem { Label("Vault", systemImage: "list.bullet.rectangle") }
                .tag(SettingsTab.vault)
            AccountSettings()
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
                .tag(SettingsTab.account)
            SettingsPane {
                CommandLineSection()
                DiagnosticsSection()
            }
            .tabItem { Label("Advanced", systemImage: "wrench.and.screwdriver") }
            .tag(SettingsTab.advanced)
        }
        .frame(width: 500)
    }
}

enum SettingsTab: String, CaseIterable {
    case general, autofill, security, vault, account, advanced
}

/// Form of a tab: fixed width, height fitted to the content.
private struct SettingsPane<Content: View>: View {
    @ViewBuilder var content: Content
    @State private var contentHeight: CGFloat = 320

    var body: some View {
        Form { content }
            .formStyle(.grouped)
            .scrollBounceBehavior(.basedOnSize)
            .onScrollGeometryChange(for: CGFloat.self) { geometry in
                geometry.contentSize.height + geometry.contentInsets.top + geometry.contentInsets.bottom
            } action: { _, height in
                contentHeight = height
            }
            .frame(height: min(contentHeight, Self.maxHeight))
    }

    private static var maxHeight: CGFloat {
        max(320, (NSScreen.main?.visibleFrame.height ?? 800) - 140)
    }
}

/// Text shown instead of a tab that needs a linked account.
private struct NoAccountSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Section {
            Text(model.mode == .demo
                 ? "Mock vault: no account is linked in demo mode."
                 : "No account is linked: log in from the main window.")
                .foregroundStyle(.secondary)
        }
    }
}

/// Startup and appearance.
private struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true
    @State private var launchAtLogin = LaunchAtLogin.isEnabled
    @State private var launchAtLoginError: String?

    var body: some View {
        @Bindable var model = model
        SettingsPane {
            Section {
                Toggle("Open Verrou at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, wanted in setLaunchAtLogin(wanted) }
                Toggle("Show in the menu bar", isOn: $showMenuBarExtra)
                if model.mode == .vaultwarden {
                    Toggle("Show site icons", isOn: $model.showSiteIcons)
                }
            } footer: {
                Text(footer)
                    .foregroundStyle(launchAtLoginError == nil ? .secondary : Color.red)
            }

            if model.mode == .vaultwarden || AppModel.isReview {
                Section {
                    ActivityNotificationsToggle()
                } footer: {
                    Text(ActivityNotificationsText.explanation)
                        .foregroundStyle(.secondary)
                }
            }

            UpdatesSection()
        }
    }

    private var footer: String {
        if let launchAtLoginError { return launchAtLoginError }
        if LaunchAtLogin.needsApproval {
            return String(localized: "To allow in System Settings → General → Login Items.")
        }
        return String(localized: "Site icons come from your Vaultwarden server, which only sees the site names.")
    }

    private func setLaunchAtLogin(_ wanted: Bool) {
        guard wanted != LaunchAtLogin.isEnabled else { return }
        do {
            try LaunchAtLogin.set(wanted)
            launchAtLoginError = nil
        } catch {
            launchAtLoginError = String(localized: "Couldn't change opening at login: \(error.localizedDescription)")
        }
        launchAtLogin = LaunchAtLogin.isEnabled || LaunchAtLogin.needsApproval
    }
}

/// Auto-lock, Touch ID, security keys.
private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage(AutoLock.minutesKey) private var autoLockMinutes = 10
    @AppStorage(AutoLock.sleepKey) private var lockOnSleep = true
    @AppStorage(Clipboard.delayKey) private var clipboardSeconds = 90

    var body: some View {
        SettingsPane {
            Section {
                Picker("Clear clipboard", selection: $clipboardSeconds) {
                    Text("After 30 seconds").tag(30)
                    Text("After 90 seconds").tag(90)
                    Text("After 3 minutes").tag(180)
                    Text("After 10 minutes").tag(600)
                }
            } footer: {
                Text("Hidden from clipboard managers, then cleared after this delay.")
                    .foregroundStyle(.secondary)
            }
            if model.account == nil || model.mode == .demo {
                NoAccountSection()
            } else {
                Section("Locking") {
                    Picker("Lock after", selection: $autoLockMinutes) {
                        Text("1 minute of inactivity").tag(1)
                        Text("5 minutes of inactivity").tag(5)
                        Text("10 minutes of inactivity").tag(10)
                        Text("30 minutes of inactivity").tag(30)
                        Text("1 hour of inactivity").tag(60)
                        Text("Never").tag(0)
                    }
                    Toggle("Lock on sleep, screen saver and screen lock", isOn: $lockOnSleep)
                }

                Section {
                    Toggle("Unlock with Touch ID", isOn: touchID)
                        .disabled(!Biometrics.isAvailable)
                } footer: {
                    Text(touchIDFooter)
                        .foregroundStyle(.secondary)
                }

                SecurityKeysSection()
                if let remote = model.remote {
                    RemoteApprovalSection(remote: remote)
                }
                NewPasswordBreachSection()
            }
        }
    }

    private var touchID: Binding<Bool> {
        Binding(
            get: { model.touchIDWanted && model.biometricEnrolled },
            set: { wanted in
                if wanted {
                    Task { await model.enableBiometrics() }
                } else {
                    model.touchIDWanted = false
                }
            })
    }

    private var touchIDFooter: LocalizedStringKey {
        if !Biometrics.isAvailable { return "Touch ID is not available on this Mac." }
        if model.touchIDWanted && !model.biometricEnrolled {
            return "Turns on at the next password unlock."
        }
        return "Adding or removing a fingerprint turns Touch ID off."
    }
}

/// Server, sync, import, logout.
private struct AccountSettings: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        SettingsPane {
            if let account = model.account, model.mode != .demo {
                Section("Account") {
                    LabeledContent("Server", value: account.server)
                    LabeledContent("Email", value: account.email)
                    OwnFingerprintRow()
                    LabeledContent("Last sync") {
                        Text(account.syncedAt.map {
                            Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .shortened)
                        } ?? String(localized: "never"))
                    }
                    Button("Sync Now") { Task { await model.syncNow() } }
                        .disabled(model.lockState != .unlocked || model.syncState == .syncing)
                }

                Section {
                    LabeledContent("Import") {
                        Button("Choose a File…") { model.startImport() }
                            .disabled(!model.canEdit)
                    }
                } footer: {
                    Text("From Apple Passwords, 1Password or Proton Pass. Duplicates are spotted before importing.")
                        .foregroundStyle(.secondary)
                }

                Section {
                    Button("Log Out of This Mac…", role: .destructive) {
                        model.refreshPending()
                        confirmLogout = true
                    }
                } footer: {
                    Text("Erases this Mac's copy and unsynced changes. The vault stays on the server.")
                        .foregroundStyle(.secondary)
                }
            } else {
                NoAccountSection()
            }
        }
        .modifier(LogoutConfirmation(isPresented: $confirmLogout))
    }
}

struct LogoutConfirmation: ViewModifier {
    @Environment(AppModel.self) private var model
    @Binding var isPresented: Bool

    func body(content: Content) -> some View {
        content
            .confirmationDialog("Log out of this Mac?", isPresented: $isPresented) {
                Button("Log Out", role: .destructive) { model.logout() }
            } message: {
                if model.pendingChanges > 0 {
                    if model.pendingChanges == 1 {
                        Text("1 unsynced change will be lost. You will need your master password and your second factor to log in again.")
                    } else {
                        Text("\(model.pendingChanges) unsynced changes will be lost. You will need your master password and your second factor to log in again.")
                    }
                } else {
                    Text("You will need your master password and your second factor to log in again.")
                }
            }
    }
}

/// Security keys that unlock the vault (YubiKey, hmac-secret): list, add,
/// remove.
struct SecurityKeysSection: View {
    @Environment(AppModel.self) private var model
    @State private var adding = false
    @State private var removing: UnlockKey?

    var body: some View {
        Section {
            ForEach(model.unlockKeys, id: \.id) { key in
                LabeledContent {
                    Button("Remove…", role: .destructive) { removing = key }
                } label: {
                    Text(key.label)
                    Text("Added on \(Date(timeIntervalSince1970: TimeInterval(key.created)).formatted(date: .abbreviated, time: .shortened))")
                }
            }
            Button("Add a Security Key to Unlock…") {
                model.enrollError = nil
                adding = true
            }
            .disabled(model.lockState != .unlocked)
        } header: {
            Text("Security keys")
        } footer: {
            Text(model.unlockKeys.isEmpty
                 ? "A YubiKey (FIDO2, with a PIN) can unlock the vault: PIN, then a touch. Add a backup one."
                 : "Both the PIN and the key are needed. Logging in again or logging out removes these keys.")
                .foregroundStyle(.secondary)
        }
        .sheet(isPresented: $adding) {
            AddSecurityKeySheet()
        }
        .confirmationDialog("Remove the security key “\(removing?.label ?? "")”?",
                            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("Remove Key", role: .destructive) {
                if let key = removing { model.removeUnlockKey(key) }
                removing = nil
            }
        } message: {
            Text("It will no longer unlock the vault on this Mac. To use it again, you will have to add it again.")
        }
    }
}

/// Adding a key: a name, then the exchange with the key (PIN, two touches).
private struct AddSecurityKeySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var label = ""

    var body: some View {
        VStack(spacing: 16) {
            Text("Add a security key")
                .font(.headline)
            if model.keyExchange == .enroll {
                SecurityKeyPanel()
                Text("You will be asked for the key twice: to create its credential, then to read its secret.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else {
                TextField("Name (for example “Backup YubiKey”)", text: $label)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 320)
                    .onSubmit(start)
                if let error = model.enrollError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                }
                HStack {
                    Button("Close") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("Start", action: start)
                        .keyboardShortcut(.defaultAction)
                        .disabled(model.lockState != .unlocked)
                }
            }
        }
        .padding(24)
        .frame(width: 400)
        .onDisappear { model.cancelKeyExchange() }
    }

    private func start() {
        Task {
            if await model.enrollSecurityKey(label: label) { dismiss() }
        }
    }
}

/// Brave, Firefox and the terminal: activation, extensions to load, linked clients.
struct BrowserSection: View {
    @Bindable var bridge: BrowserBridge
    @State private var unlinking: BridgeClient?

    var body: some View {
        Section {
            Toggle("Brave, Firefox and the terminal", isOn: $bridge.enabled)
            if bridge.enabled {
                if let folder = bridge.extensionFolder {
                    extensionRow("Brave extension", folder: folder)
                }
                // Firefox loads a file, not a folder: the copied path is the
                // manifest's (about:debugging).
                if let folder = bridge.firefoxExtensionFolder {
                    extensionRow("Firefox extension", folder: folder, copying: folder.appending(path: "manifest.json"))
                }
            }
            ForEach(bridge.clients, id: \.id) { client in
                LabeledContent {
                    Button("Unlink…", role: .destructive) { unlinking = client }
                } label: {
                    Label(client.name, systemImage: client.kind == .cli ? "terminal" : "globe")
                    let linked = Date(timeIntervalSince1970: TimeInterval(client.created)).formatted(date: .abbreviated, time: .shortened)
                    if client.kind == .cli {
                        Text("Terminal, linked on \(linked)")
                    } else {
                        Text("Browser, linked on \(linked)")
                    }
                }
            }
        } header: {
            Text("Browsers and terminal")
        } footer: {
            Text(footer)
                .foregroundStyle(bridge.error == nil ? Color.secondary : Color.red)
        }
        .onAppear { bridge.refreshClients() }
        .confirmationDialog("Unlink “\(unlinking?.name ?? "")”?",
                            isPresented: Binding(get: { unlinking != nil }, set: { if !$0 { unlinking = nil } })) {
            Button("Unlink", role: .destructive) {
                if let client = unlinking { bridge.revoke(client) }
                unlinking = nil
            }
        } message: {
            Text(unlinking?.kind == .cli
                 ? "The terminal will need “verrou link” and a new approval to read the vault again."
                 : "The browser will need to be linked again, with a new code, to fill your logins.")
        }
    }

    /// A shipped extension: copy its path (`copying`, by default the folder)
    /// or show it in the Finder.
    private func extensionRow(_ title: LocalizedStringKey, folder: URL, copying: URL? = nil) -> some View {
        LabeledContent(title) {
            HStack {
                Button("Copy Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString((copying ?? folder).path, forType: .string)
                }
                Button("Show") { NSWorkspace.shared.activateFileViewerSelecting([folder]) }
            }
        }
    }

    private var footer: String {
        if let error = bridge.error { return error }
        if !bridge.enabled {
            return String(localized: "Verrou's extension fills Brave and Firefox; the “verrou” command reads the vault from the terminal, with your approval.")
        }
        if let note = bridge.browserNote, bridge.clients.isEmpty {
            return "\(note)."
        }
        if bridge.clients.isEmpty {
            return String(localized: "Load the extension in your browser (see the guide), then click its Verrou icon to link it. Terminal: “verrou link”.")
        }
        return String(localized: "The extension only gets the open site's logins; each terminal secret asks for Touch ID.")
    }
}

/// Updates of the app (`Updates`): only in release builds.
private struct UpdatesSection: View {
    /// Optional: the offscreen review shows Settings without an updater.
    @Environment(Updates.self) private var updates: Updates?

    var body: some View {
        if let updates, updates.isAvailable {
            UpdatesControls(updates: updates)
        }
    }
}

private struct UpdatesControls: View {
    @Bindable var updates: Updates

    var body: some View {
        Section {
            Toggle("Check for updates automatically", isOn: $updates.automaticallyChecks)
            Toggle("Download and install updates automatically", isOn: $updates.automaticallyInstalls)
                .disabled(!updates.automaticallyChecks)
            LabeledContent("Verrou \(Updates.version)") {
                Button("Check Now") { updates.check() }
                    .disabled(!updates.canCheck)
            }
        } header: {
            Text("Updates")
        } footer: {
            Text("Installed when you quit Verrou, once its signature is checked.")
                .foregroundStyle(.secondary)
        }
    }
}

/// The `verrou` command shipped in the app (Contents/Helpers/verrou): linked
/// into the PATH, it updates with the app. The sandbox can't write outside
/// the app's container: the user pastes the command in Terminal.
struct CommandLineSection: View {
    @State private var copied = false

    private static let tool = Bundle.main.bundleURL.appending(path: "Contents/Helpers/verrou")
    private static let link = "/usr/local/bin/verrou"

    private static var command: String {
        let quoted = "'" + tool.path.replacingOccurrences(of: "'", with: "'\\''") + "'"
        return "sudo mkdir -p /usr/local/bin && sudo ln -sf \(quoted) \(link)"
    }

    /// The link already points to this app's tool.
    private var installed: Bool {
        (try? FileManager.default.destinationOfSymbolicLink(atPath: Self.link)) == Self.tool.path
    }

    var body: some View {
        if FileManager.default.isExecutableFile(atPath: Self.tool.path) {
            Section {
                LabeledContent {
                    Button(copied ? "Copied" : "Copy Command") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(Self.command, forType: .string)
                        copied = true
                    }
                } label: {
                    Text("“verrou” command")
                    Text(installed ? "Installed in \(Self.link)" : "Not installed")
                }
            } header: {
                Text("Command line")
            } footer: {
                Text("Paste it in Terminal: “verrou” then updates with the app.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// Check of new passwords in known leaks (`AppModel.checkNewPasswords`).
private struct NewPasswordBreachSection: View {
    @AppStorage(Watchtower.checkNewPasswordsKey) private var checkNewPasswords = true

    var body: some View {
        Section {
            Toggle("Check new passwords in known leaks", isOn: $checkNewPasswords)
        } footer: {
            Text("Asks Have I Been Pwned with only the first 5 characters of the password's SHA-1 hash.")
                .foregroundStyle(.secondary)
        }
    }
}

private struct AutoFillSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        SettingsPane {
            SystemAutofillSection()
            AppAutofillSection()
            if let bridge = model.browserBridge {
                BrowserSection(bridge: bridge)
            }
            EmailAliasSection(settings: model.aliasSettings) { domain, includeSite in
                try model.setAliasSettings(domain: domain, includeSite: includeSite)
            }
            .onAppear { model.refreshAliasSettings() }
        }
    }
}

/// Filter opened on unlock, sort, site match rules.
private struct VaultSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        SettingsPane {
            Section {
                Picker("On unlock, show", selection: $model.defaultFilter) {
                    ForEach(DefaultFilter.allCases) { filter in
                        Text(filter.label).tag(filter)
                    }
                }
                Picker("Sort the list by", selection: $model.sort) {
                    ForEach(ResultOrder.menu, id: \.self) { order in
                        Text(order.label).tag(order)
                    }
                }
            } footer: {
                Text("Kept on this Mac, never sent to the server.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Picker("Default match", selection: defaultRule) {
                    ForEach(UriMatchRule.all) { rule in
                        Text(rule.label).tag(rule)
                    }
                }
                .layoutMark("default-match")
                DisclosureGroup("By folder") {
                    folderRules
                }
                DisclosureGroup("Equivalent domains") {
                    equivalentDomains
                }
            } header: {
                Text("Site matching")
            } footer: {
                Text("For sites without their own rule. \(defaultRule.wrappedValue.explanation)")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var folderRules: some View {
        ForEach(model.matchSettings?.folderRules ?? [], id: \.folderId) { rule in
            HStack {
                Label(rule.folderName.isEmpty ? String(localized: "Deleted folder") : rule.folderName, systemImage: "folder")
                Spacer()
                Picker(rule.folderName, selection: folderRule(rule.folderId)) {
                    ForEach(UriMatchRule.all) { option in
                        Text(option.label).tag(option)
                    }
                }
                .labelsHidden()
                .fixedSize()
                Button {
                    model.setFolderMatchRule(rule.folderId, nil)
                } label: {
                    Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                        .accessibilityLabel("Go back to the default rule for this folder")
                }
                .buttonStyle(.plain)
                .help("Go back to the default rule for this folder")
            }
        }
        let free = model.folders.filter { folder in
            !(model.matchSettings?.folderRules.contains { $0.folderId == folder.id } ?? false)
        }
        Menu {
            ForEach(free, id: \.id) { folder in
                Button(folder.name) { model.setFolderMatchRule(folder.id, .host) }
            }
        } label: {
            Label("Rule for a Folder…", systemImage: "plus.circle.fill")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(free.isEmpty)
        Text("Kept on this Mac: Bitwarden has no per-folder rule.")
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    @ViewBuilder private var equivalentDomains: some View {
        let groups = model.matchSettings?.equivalentDomains ?? []
        if groups.isEmpty {
            Text(model.mode == .vaultwarden ? "Read at the next sync." : "None in the mock vault.")
                .foregroundStyle(.secondary)
        } else {
            ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                Text(group.joined(separator: " · "))
                    .font(.callout)
                    .lineLimit(2)
                    .foregroundStyle(.secondary)
            }
        }
        Text("From your account (web vault → Settings → Domains), for the “Base domain” rule.")
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    private var defaultRule: Binding<UriMatchRule> {
        Binding(get: { model.matchSettings?.defaultRule ?? .domain },
                set: { model.setDefaultMatchRule($0) })
    }

    private func folderRule(_ folderID: String) -> Binding<UriMatchRule> {
        Binding(get: { model.matchSettings?.folderRules.first { $0.folderId == folderID }?.rule ?? .domain },
                set: { model.setFolderMatchRule(folderID, $0) })
    }
}
