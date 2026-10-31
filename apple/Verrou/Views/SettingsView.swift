import SwiftUI

/// Settings (⌘,), in tabs: General, Security (locking, Touch ID, security
/// keys), Account (sync, import, logout), Browsers and terminal.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("settingsTab") private var tab = SettingsTab.general

    var body: some View {
        TabView(selection: $tab) {
            GeneralSettings()
                .tabItem { Label("General", systemImage: "gearshape") }
                .tag(SettingsTab.general)
            SecuritySettings()
                .tabItem { Label("Security", systemImage: "lock.shield") }
                .tag(SettingsTab.security)
            AccountSettings()
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
                .tag(SettingsTab.account)
            FillingSettings()
                .tabItem { Label("Vault and Filling", systemImage: "rectangle.and.hand.point.up.left") }
                .tag(SettingsTab.filling)
            Group {
                if let bridge = model.browserBridge {
                    SettingsPane {
                        BrowserSection(bridge: bridge)
                        CommandLineSection()
                    }
                } else {
                    SettingsPane {
                        Section {
                            Text("Unavailable in this mode.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .tabItem { Label("Browsers and Terminal", systemImage: "terminal") }
            .tag(SettingsTab.integrations)
        }
        .frame(width: 500)
    }
}

enum SettingsTab: String {
    case general, security, account, filling, integrations
}

/// Form of a tab: fixed width, height fitted to the content.
private struct SettingsPane<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        Form { content }
            .formStyle(.grouped)
            .fixedSize(horizontal: false, vertical: true)
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
            AppAutofillSection()
            SystemAutofillSection()
            DiagnosticsSection()
        }
    }

    private var footer: String {
        if let launchAtLoginError { return launchAtLoginError }
        if LaunchAtLogin.needsApproval {
            return String(localized: "To allow in System Settings → General → Login Items.")
        }
        return String(localized: "Icons come from your Vaultwarden server, which only receives the names of the sites; they are not kept on disk.")
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

    var body: some View {
        SettingsPane {
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
        return "The vault key is sealed by the Secure Enclave: adding or removing a fingerprint turns off Touch ID."
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
                    Text("Exports from Apple Passwords (CSV), 1Password (1PUX or CSV) or Proton Pass (unencrypted ZIP or CSV). Duplicates are spotted before the import; Vault → Clean Up Duplicates… handles those of the vault.")
                        .foregroundStyle(.secondary)
                }

                Section {
                    Button("Log Out of This Mac…", role: .destructive) {
                        model.refreshPending()
                        confirmLogout = true
                    }
                } footer: {
                    Text("Erases the cache, the tokens and the changes not yet synced from this Mac. The vault stays intact on the server.")
                        .foregroundStyle(.secondary)
                }
            } else {
                NoAccountSection()
            }
        }
        .confirmationDialog("Log out of this Mac?", isPresented: $confirmLogout) {
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

    var body: some View {
        Section {
            ForEach(model.unlockKeys, id: \.id) { key in
                LabeledContent {
                    Button("Remove", role: .destructive) { model.removeUnlockKey(key) }
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
                    Button("Unlink", role: .destructive) { bridge.revoke(client) }
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
            return String(localized: "The Verrou extension fills your logins in Brave or Firefox, site by site; the “verrou” command and its SSH agent read the vault from the terminal, with your approval. Nothing leaves the Mac.")
        }
        let terminal = String(localized: "Terminal: “verrou link”, then each secret or SSH signature asks for Touch ID.")
        if let note = bridge.browserNote, bridge.clients.isEmpty {
            return "\(note). \(terminal)"
        }
        if bridge.clients.isEmpty {
            return String(localized: "In Brave: brave://extensions, “Developer mode”, “Load unpacked”, then ⌘⇧G and paste the path. In Firefox: about:debugging, “This Firefox”, “Load Temporary Add-on…”, then ⌘⇧G and paste the manifest path (to redo at each Firefox start, see the guide). Then click the browser's Verrou icon to link the extension. \(terminal)")
        }
        return String(localized: "The extension only receives the logins of the open site, over HTTPS, with the vault unlocked. The terminal searches without seeing the secrets; each one asks for Touch ID.")
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
            Text("An update is installed when you quit Verrou, never while it's running. Verrou checks its signature first: only an update published by Verrou's developers installs.")
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
                Text("Paste the command in Terminal (it asks for your Mac password): it links “verrou” to the app, so the command updates with Verrou.")
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
            Text("For each password created or changed in Verrou (editor, Brave, import), Have I Been Pwned is queried in the background. Only the first 5 characters of its SHA-1 hash leave this Mac.")
                .foregroundStyle(.secondary)
        }
    }
}

/// Filter opened on unlock, site match rules (this Mac's default, folders)
/// and the account's equivalent domains.
private struct FillingSettings: View {
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
                Text("Kept on this Mac. “Last used” follows what you fill, copy or show here: only item IDs and dates, never sent to the server.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Picker("Default match", selection: defaultRule) {
                    ForEach(UriMatchRule.all) { rule in
                        Text(rule.label).tag(rule)
                    }
                }
                .layoutMark("default-match")
            } header: {
                Text("Site matching")
            } footer: {
                Text("For sites that don't have their own rule (chosen when editing a login). \(defaultRule.wrappedValue.explanation)")
                    .foregroundStyle(.secondary)
            }

            Section {
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
            } header: {
                Text("By folder")
            } footer: {
                Text("Bitwarden has no per-folder rule: this one stays on this Mac, and only applies to sites without their own rule (for example “Host” for the Work folder).")
                    .foregroundStyle(.secondary)
            }

            Section {
                let groups = model.matchSettings?.equivalentDomains ?? []
                if groups.isEmpty {
                    Text(model.mode == .vaultwarden ? "Read at the next sync." : "None in the mock vault.")
                        .foregroundStyle(.secondary)
                } else {
                    DisclosureGroup(groups.count > 1 ? String(localized: "\(groups.count) domain groups")
                                                      : String(localized: "\(groups.count) domain group")) {
                        ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                            Text(group.joined(separator: " · "))
                                .font(.callout)
                                .lineLimit(2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Equivalent domains")
            } footer: {
                Text("Settings of your account, read from the server (web vault → Settings → Domains): the “Base domain” rule also offers the login on the domains of the same group.")
                    .foregroundStyle(.secondary)
            }

            EmailAliasSection(settings: model.aliasSettings) { domain, includeSite in
                try model.setAliasSettings(domain: domain, includeSite: includeSite)
            }
            .onAppear { model.refreshAliasSettings() }
        }
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
