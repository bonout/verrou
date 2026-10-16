import SwiftUI

/// Réglages (⌘,), en onglets : Général, Sécurité (verrouillage, Touch ID,
/// clés de sécurité), Compte (synchronisation, import, déconnexion),
/// Navigateurs et terminal.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("settingsTab") private var tab = SettingsTab.general

    var body: some View {
        TabView(selection: $tab) {
            GeneralSettings()
                .tabItem { Label("Général", systemImage: "gearshape") }
                .tag(SettingsTab.general)
            SecuritySettings()
                .tabItem { Label("Sécurité", systemImage: "lock.shield") }
                .tag(SettingsTab.security)
            AccountSettings()
                .tabItem { Label("Compte", systemImage: "person.crop.circle") }
                .tag(SettingsTab.account)
            FillingSettings()
                .tabItem { Label("Coffre et remplissage", systemImage: "rectangle.and.hand.point.up.left") }
                .tag(SettingsTab.filling)
            Group {
                if let bridge = model.browserBridge {
                    SettingsPane { BrowserSection(bridge: bridge) }
                } else {
                    SettingsPane {
                        Section {
                            Text("Indisponible dans ce mode.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .tabItem { Label("Navigateurs et terminal", systemImage: "terminal") }
            .tag(SettingsTab.integrations)
        }
        .frame(width: 500)
    }
}

enum SettingsTab: String {
    case general, security, account, filling, integrations
}

/// Formulaire d'un onglet : largeur fixe, hauteur ajustée au contenu.
private struct SettingsPane<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        Form { content }
            .formStyle(.grouped)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Texte affiché à la place d'un onglet qui demande un compte relié.
private struct NoAccountSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Section {
            Text(model.mode == .demo
                 ? "Coffre fictif : aucun compte n'est relié en mode démonstration."
                 : "Aucun compte n'est relié : connectez-vous depuis la fenêtre principale.")
                .foregroundStyle(.secondary)
        }
    }
}

/// Démarrage et apparence.
private struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true
    @State private var launchAtLogin = LaunchAtLogin.isEnabled
    @State private var launchAtLoginError: String?

    var body: some View {
        @Bindable var model = model
        SettingsPane {
            Section {
                Toggle("Ouvrir Verrou à l'ouverture de session", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, wanted in setLaunchAtLogin(wanted) }
                Toggle("Afficher dans la barre des menus", isOn: $showMenuBarExtra)
                if model.mode == .vaultwarden {
                    Toggle("Afficher les icônes des sites", isOn: $model.showSiteIcons)
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

            AppAutofillSection()
            SystemAutofillSection()
        }
    }

    private var footer: String {
        if let launchAtLoginError { return launchAtLoginError }
        if LaunchAtLogin.needsApproval {
            return "À autoriser dans Réglages Système → Général → Ouverture."
        }
        return "Les icônes viennent de votre serveur Vaultwarden, qui ne reçoit que le nom des sites ; elles ne sont pas gardées sur le disque."
    }

    private func setLaunchAtLogin(_ wanted: Bool) {
        guard wanted != LaunchAtLogin.isEnabled else { return }
        do {
            try LaunchAtLogin.set(wanted)
            launchAtLoginError = nil
        } catch {
            launchAtLoginError = "Impossible de modifier l'ouverture de session : \(error.localizedDescription)"
        }
        launchAtLogin = LaunchAtLogin.isEnabled || LaunchAtLogin.needsApproval
    }
}

/// Verrouillage automatique, Touch ID, clés de sécurité.
private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage(AutoLock.minutesKey) private var autoLockMinutes = 10
    @AppStorage(AutoLock.sleepKey) private var lockOnSleep = true

    var body: some View {
        SettingsPane {
            if model.account == nil || model.mode == .demo {
                NoAccountSection()
            } else {
                Section("Verrouillage") {
                    Picker("Verrouiller après", selection: $autoLockMinutes) {
                        Text("1 minute d'inactivité").tag(1)
                        Text("5 minutes d'inactivité").tag(5)
                        Text("10 minutes d'inactivité").tag(10)
                        Text("30 minutes d'inactivité").tag(30)
                        Text("1 heure d'inactivité").tag(60)
                        Text("Jamais").tag(0)
                    }
                    Toggle("Verrouiller à la mise en veille et au verrouillage de l'écran", isOn: $lockOnSleep)
                }

                Section {
                    Toggle("Déverrouiller avec Touch ID", isOn: touchID)
                        .disabled(!Biometrics.isAvailable)
                } footer: {
                    Text(touchIDFooter)
                        .foregroundStyle(.secondary)
                }

                SecurityKeysSection()
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

    private var touchIDFooter: String {
        if !Biometrics.isAvailable { return "Touch ID n'est pas disponible sur ce Mac." }
        if model.touchIDWanted && !model.biometricEnrolled {
            return "S'active au prochain déverrouillage par mot de passe."
        }
        return "La clé du coffre est scellée par le Secure Enclave : ajouter ou retirer une empreinte désactive Touch ID."
    }
}

/// Serveur, synchronisation, import, déconnexion.
private struct AccountSettings: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        SettingsPane {
            if let account = model.account, model.mode != .demo {
                Section("Compte") {
                    LabeledContent("Serveur", value: account.server)
                    LabeledContent("E-mail", value: account.email)
                    OwnFingerprintRow()
                    LabeledContent("Dernière synchronisation") {
                        Text(account.syncedAt.map {
                            Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .shortened)
                        } ?? "jamais")
                    }
                    Button("Synchroniser maintenant") { Task { await model.syncNow() } }
                        .disabled(model.lockState != .unlocked || model.syncState == .syncing)
                }

                Section {
                    LabeledContent("Importer") {
                        Button("Choisir un fichier…") { model.startImport() }
                            .disabled(!model.canEdit)
                    }
                } footer: {
                    Text("Exports des Mots de passe d'Apple (CSV), de 1Password (1PUX ou CSV) ou de Proton Pass (ZIP non chiffré ou CSV). Les doublons sont repérés avant l'import ; Coffre → Nettoyer les doublons… traite ceux du coffre.")
                        .foregroundStyle(.secondary)
                }

                Section {
                    Button("Se déconnecter de ce Mac…", role: .destructive) {
                        model.refreshPending()
                        confirmLogout = true
                    }
                } footer: {
                    Text("Efface le cache, les jetons et les modifications pas encore synchronisées de ce Mac. Le coffre reste intact sur le serveur.")
                        .foregroundStyle(.secondary)
                }
            } else {
                NoAccountSection()
            }
        }
        .confirmationDialog("Se déconnecter de ce Mac ?", isPresented: $confirmLogout) {
            Button("Se déconnecter", role: .destructive) { model.logout() }
        } message: {
            if model.pendingChanges > 0 {
                Text("\(model.pendingChanges == 1 ? "1 modification non synchronisée sera perdue" : "\(model.pendingChanges) modifications non synchronisées seront perdues"). Il faudra votre mot de passe principal et votre second facteur pour vous reconnecter.")
            } else {
                Text("Il faudra votre mot de passe principal et votre second facteur pour vous reconnecter.")
            }
        }
    }
}

/// Clés de sécurité qui déverrouillent le coffre (YubiKey, hmac-secret) :
/// liste, ajout, retrait.
struct SecurityKeysSection: View {
    @Environment(AppModel.self) private var model
    @State private var adding = false

    var body: some View {
        Section {
            ForEach(model.unlockKeys, id: \.id) { key in
                LabeledContent {
                    Button("Retirer", role: .destructive) { model.removeUnlockKey(key) }
                } label: {
                    Text(key.label)
                    Text("Ajoutée le \(Date(timeIntervalSince1970: TimeInterval(key.created)).formatted(date: .abbreviated, time: .shortened))")
                }
            }
            Button("Ajouter une clé de sécurité pour déverrouiller…") {
                model.enrollError = nil
                adding = true
            }
            .disabled(model.lockState != .unlocked)
        } header: {
            Text("Clés de sécurité")
        } footer: {
            Text(model.unlockKeys.isEmpty
                 ? "Une YubiKey (FIDO2, avec un code PIN) peut déverrouiller le coffre : code PIN, puis un contact. Ajoutez-en une de secours."
                 : "Le code PIN et la clé sont tous deux nécessaires. Une reconnexion ou une déconnexion retire ces clés.")
                .foregroundStyle(.secondary)
        }
        .sheet(isPresented: $adding) {
            AddSecurityKeySheet()
        }
    }
}

/// Ajout d'une clé : un nom, puis l'échange avec la clé (code PIN, deux contacts).
private struct AddSecurityKeySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var label = ""

    var body: some View {
        VStack(spacing: 16) {
            Text("Ajouter une clé de sécurité")
                .font(.headline)
            if model.keyExchange == .enroll {
                SecurityKeyPanel()
                Text("La clé vous sera demandée deux fois : pour créer son accréditation, puis pour lire son secret.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else {
                TextField("Nom (par exemple « YubiKey de secours »)", text: $label)
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
                    Button("Fermer") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("Commencer", action: start)
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

/// Brave, Firefox et le terminal : activation, extensions à charger, clients reliés.
struct BrowserSection: View {
    @Bindable var bridge: BrowserBridge

    var body: some View {
        Section {
            Toggle("Brave, Firefox et le terminal", isOn: $bridge.enabled)
            if bridge.enabled {
                if let folder = bridge.extensionFolder {
                    extensionRow("Extension Brave", folder: folder)
                }
                // Firefox charge un fichier, pas un dossier : le chemin copié
                // est celui du manifeste (about:debugging).
                if let folder = bridge.firefoxExtensionFolder {
                    extensionRow("Extension Firefox", folder: folder, copying: folder.appending(path: "manifest.json"))
                }
            }
            ForEach(bridge.clients, id: \.id) { client in
                LabeledContent {
                    Button("Délier", role: .destructive) { bridge.revoke(client) }
                } label: {
                    Label(client.name, systemImage: client.kind == .cli ? "terminal" : "globe")
                    Text("\(client.kind == .cli ? "Terminal" : "Navigateur"), relié le \(Date(timeIntervalSince1970: TimeInterval(client.created)).formatted(date: .abbreviated, time: .shortened))")
                }
            }
        } header: {
            Text("Navigateurs et terminal")
        } footer: {
            Text(footer)
                .foregroundStyle(bridge.error == nil ? Color.secondary : Color.red)
        }
        .onAppear { bridge.refreshClients() }
    }

    /// Une extension livrée : copier son chemin (`copying`, par défaut le
    /// dossier) ou l'afficher dans le Finder.
    private func extensionRow(_ title: String, folder: URL, copying: URL? = nil) -> some View {
        LabeledContent(title) {
            HStack {
                Button("Copier le chemin") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString((copying ?? folder).path, forType: .string)
                }
                Button("Afficher") { NSWorkspace.shared.activateFileViewerSelecting([folder]) }
            }
        }
    }

    private var footer: String {
        if let error = bridge.error { return error }
        if !bridge.enabled {
            return "L'extension Verrou remplit vos identifiants dans Brave ou Firefox, site par site ; la commande « verrou » et son agent SSH lisent le coffre depuis le terminal, avec votre accord. Rien ne sort du Mac."
        }
        let terminal = "Terminal : « verrou link », puis chaque secret ou signature SSH demande Touch ID."
        if let note = bridge.browserNote, bridge.clients.isEmpty {
            return "\(note). \(terminal)"
        }
        if bridge.clients.isEmpty {
            return "Dans Brave : brave://extensions, « Mode développeur », « Charger l'extension non empaquetée », puis ⌘⇧G et collez le chemin. Dans Firefox : about:debugging, « Ce Firefox », « Charger un module complémentaire temporaire… », puis ⌘⇧G et collez le chemin du manifeste (à refaire à chaque démarrage de Firefox, voir le guide). Cliquez ensuite sur l'icône Verrou du navigateur pour relier l'extension. \(terminal)"
        }
        return "L'extension ne reçoit que les identifiants du site ouvert, en HTTPS, coffre déverrouillé. Le terminal cherche sans voir les secrets ; chacun demande Touch ID."
    }
}

/// Vérification des nouveaux mots de passe dans les fuites connues
/// (`AppModel.checkNewPasswords`).
private struct NewPasswordBreachSection: View {
    @AppStorage(Watchtower.checkNewPasswordsKey) private var checkNewPasswords = true

    var body: some View {
        Section {
            Toggle("Vérifier les nouveaux mots de passe dans les fuites connues", isOn: $checkNewPasswords)
        } footer: {
            Text("À chaque mot de passe créé ou modifié dans Verrou (éditeur, Brave, import), Have I Been Pwned est interrogé en arrière-plan. Seuls les 5 premiers caractères de son empreinte SHA-1 quittent ce Mac.")
                .foregroundStyle(.secondary)
        }
    }
}

/// Filtre ouvert au déverrouillage, règles de correspondance des sites
/// (défaut de ce Mac, dossiers) et domaines équivalents du compte.
private struct FillingSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        SettingsPane {
            Section {
                Picker("Au déverrouillage, afficher", selection: $model.defaultFilter) {
                    ForEach(DefaultFilter.allCases) { filter in
                        Text(filter.label).tag(filter)
                    }
                }
                Picker("Trier la liste par", selection: $model.sort) {
                    ForEach(ResultOrder.menu, id: \.self) { order in
                        Text(order.label).tag(order)
                    }
                }
            } footer: {
                Text("Gardés sur ce Mac. « Dernière utilisation » suit ce que vous remplissez, copiez ou affichez ici : seulement des identifiants d'éléments et des dates, jamais envoyés au serveur.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Picker("Correspondance par défaut", selection: defaultRule) {
                    ForEach(UriMatchRule.all) { rule in
                        Text(rule.label).tag(rule)
                    }
                }
                .layoutMark("default-match")
            } header: {
                Text("Correspondance des sites")
            } footer: {
                Text("Pour les sites qui n'ont pas leur propre règle (à choisir dans la modification d'un identifiant). \(defaultRule.wrappedValue.explanation)")
                    .foregroundStyle(.secondary)
            }

            Section {
                ForEach(model.matchSettings?.folderRules ?? [], id: \.folderId) { rule in
                    HStack {
                        Label(rule.folderName.isEmpty ? "Dossier supprimé" : rule.folderName, systemImage: "folder")
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
                        }
                        .buttonStyle(.plain)
                        .help("Revenir à la règle par défaut pour ce dossier")
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
                    Label("Règle pour un dossier…", systemImage: "plus.circle.fill")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .disabled(free.isEmpty)
            } header: {
                Text("Par dossier")
            } footer: {
                Text("Bitwarden n'a pas de règle par dossier : celle-ci reste sur ce Mac, et ne vaut que pour les sites sans règle propre (par exemple « Hôte » pour le dossier Travail).")
                    .foregroundStyle(.secondary)
            }

            Section {
                let groups = model.matchSettings?.equivalentDomains ?? []
                if groups.isEmpty {
                    Text(model.mode == .vaultwarden ? "Lus à la prochaine synchronisation." : "Aucun dans le coffre fictif.")
                        .foregroundStyle(.secondary)
                } else {
                    DisclosureGroup("\(groups.count) groupe\(groups.count > 1 ? "s" : "") de domaines") {
                        ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                            Text(group.joined(separator: " · "))
                                .font(.callout)
                                .lineLimit(2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Domaines équivalents")
            } footer: {
                Text("Réglages de votre compte, lus sur le serveur (coffre web → Paramètres → Domaines) : la règle « Domaine de base » propose aussi l'identifiant sur les domaines du même groupe.")
                    .foregroundStyle(.secondary)
            }
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
