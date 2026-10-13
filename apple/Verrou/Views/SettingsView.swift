import SwiftUI

/// Réglages (⌘,) : démarrage, apparence, compte, synchronisation, Touch ID,
/// déconnexion.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true
    @State private var launchAtLogin = LaunchAtLogin.isEnabled
    @State private var launchAtLoginError: String?
    @AppStorage(AutoLock.minutesKey) private var autoLockMinutes = 10
    @AppStorage(AutoLock.sleepKey) private var lockOnSleep = true

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Toggle("Ouvrir Verrou à l'ouverture de session", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, wanted in setLaunchAtLogin(wanted) }
                Toggle("Afficher dans la barre des menus", isOn: $showMenuBarExtra)
                if model.mode == .vaultwarden {
                    Toggle("Afficher les icônes des sites", isOn: $model.showSiteIcons)
                }
            } footer: {
                Text(generalFooter)
                    .foregroundStyle(launchAtLoginError == nil ? .secondary : Color.red)
            }

            if let bridge = model.browserBridge {
                BrowserSection(bridge: bridge)
            }

            if model.mode == .demo {
                Section {
                    Text("Coffre fictif : aucun compte n'est relié en mode démonstration.")
                        .foregroundStyle(.secondary)
                }
            } else if let account = model.account {
                Section("Compte") {
                    LabeledContent("Serveur", value: account.server)
                    LabeledContent("E-mail", value: account.email)
                    LabeledContent("Dernière synchronisation") {
                        Text(account.syncedAt.map {
                            Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .shortened)
                        } ?? "jamais")
                    }
                    Button("Synchroniser maintenant") { Task { await model.syncNow() } }
                        .disabled(model.lockState != .unlocked || model.syncState == .syncing)
                }

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

                Section {
                    Button("Se déconnecter de ce Mac…", role: .destructive) { confirmLogout = true }
                } footer: {
                    Text("Efface le cache et les jetons de ce Mac. Le coffre reste intact sur le serveur.")
                        .foregroundStyle(.secondary)
                }
            } else {
                Section {
                    Text("Aucun compte n'est relié : connectez-vous depuis la fenêtre principale.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .fixedSize(horizontal: false, vertical: true)
        .confirmationDialog("Se déconnecter de ce Mac ?", isPresented: $confirmLogout) {
            Button("Se déconnecter", role: .destructive) { model.logout() }
        } message: {
            Text("Il faudra votre mot de passe principal et votre second facteur pour vous reconnecter.")
        }
    }

    private var generalFooter: String {
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

/// Brave et le terminal : activation, extension à charger, clients reliés.
struct BrowserSection: View {
    @Bindable var bridge: BrowserBridge

    var body: some View {
        Section {
            Toggle("Brave et le terminal", isOn: $bridge.enabled)
            if bridge.enabled, let folder = bridge.extensionFolder {
                LabeledContent("Extension") {
                    HStack {
                        Button("Copier le chemin") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(folder.path, forType: .string)
                        }
                        Button("Afficher") { NSWorkspace.shared.activateFileViewerSelecting([folder]) }
                    }
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
            Text("Navigateur et terminal")
        } footer: {
            Text(footer)
                .foregroundStyle(bridge.error == nil ? Color.secondary : Color.red)
        }
        .onAppear { bridge.refreshClients() }
    }

    private var footer: String {
        if let error = bridge.error { return error }
        if !bridge.enabled {
            return "L'extension Verrou remplit vos identifiants dans Brave, site par site ; la commande « verrou » et son agent SSH lisent le coffre depuis le terminal, avec votre accord. Rien ne sort du Mac."
        }
        let terminal = "Terminal : « verrou link », puis chaque secret ou signature SSH demande Touch ID."
        if let note = bridge.browserNote, bridge.clients.isEmpty {
            return "\(note). \(terminal)"
        }
        if bridge.clients.isEmpty {
            return "Dans Brave : brave://extensions, « Mode développeur », « Charger l'extension non empaquetée », puis ⌘⇧G et collez le chemin. Cliquez ensuite sur l'icône Verrou de Brave pour relier l'extension. \(terminal)"
        }
        return "L'extension ne reçoit que les identifiants du site ouvert, en HTTPS, coffre déverrouillé. Le terminal cherche sans voir les secrets ; chacun demande Touch ID."
    }
}
