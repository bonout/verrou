import SwiftUI

/// Réglages (⌘,) : démarrage, apparence, compte, synchronisation, Touch ID,
/// déconnexion.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true
    @State private var launchAtLogin = LaunchAtLogin.isEnabled
    @State private var launchAtLoginError: String?

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
