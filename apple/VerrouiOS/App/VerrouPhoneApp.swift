import QuickLook
import SwiftUI

@main
struct VerrouPhoneApp: App {
    @State private var model = PhoneModel()
    @Environment(\.scenePhase) private var scenePhase
    #if DEBUG
    @State private var endToEnd: EndToEndDriver?
    #endif

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .onChange(of: scenePhase) { _, phase in model.scenePhaseChanged(to: phase) }
                .task {
                    #if DEBUG
                    if endToEnd == nil, let config = EndToEndDriver.Config(ProcessInfo.processInfo.environment) {
                        let driver = EndToEndDriver(model: model, config: config)
                        endToEnd = driver
                        driver.start()
                    }
                    #endif
                }
        }
    }
}

struct RootView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    /// Hors du premier plan (sélecteur d'apps, centre de contrôle) : le
    /// contenu est flouté et recouvert, l'aperçu du sélecteur ne montre rien.
    private var shielded: Bool { scenePhase != .active }

    var body: some View {
        @Bindable var model = model
        ZStack {
            Group {
                if model.lockState == .unlocked {
                    MainTabs()
                } else if model.needsLogin {
                    LoginView()
                } else {
                    LockView()
                }
            }
            .blur(radius: shielded ? 28 : 0)
            .transition(.opacity)
            if shielded {
                PrivacyCover()
                    .transition(.opacity)
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.lockState)
        .animation(.easeOut(duration: 0.2), value: model.needsLogin)
        // Coffre ouvert : au-dessus de la barre d'onglets ; sinon en haut, loin
        // des champs de saisie.
        .overlay(alignment: model.lockState == .unlocked ? .bottom : .top) { ToastHost() }
        .alert(repromptTitle, isPresented: repromptShown, presenting: model.reprompt) { _ in
            RepromptFields()
        } message: { _ in
            Text("Saisissez votre mot de passe principal pour afficher ses secrets.")
        }
    }

    private var repromptTitle: String {
        model.reprompt.map { "« \($0.title) » est protégé" } ?? ""
    }

    private var repromptShown: Binding<Bool> {
        Binding(get: { model.reprompt != nil },
                set: { if !$0, model.reprompt != nil { Task { await model.answerReprompt(password: nil) } } })
    }
}

/// Champ et boutons de la demande du mot de passe principal.
private struct RepromptFields: View {
    @Environment(PhoneModel.self) private var model
    @State private var password = ""

    var body: some View {
        SecureField("Mot de passe principal", text: $password)
            .textContentType(.password)
        Button("Confirmer") {
            let typed = password
            password = ""
            Task { await model.answerReprompt(password: typed) }
        }
        Button("Annuler", role: .cancel) {
            password = ""
            Task { await model.answerReprompt(password: nil) }
        }
    }
}

/// Écran posé sur l'app quand elle quitte le premier plan.
struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.regularMaterial)
            VStack(spacing: 14) {
                AppMark(size: 76)
                Text("Verrou")
                    .font(.system(.title2, design: .rounded, weight: .bold))
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// Les onglets du coffre ouvert.
struct MainTabs: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        @Bindable var model = model
        TabView(selection: $model.tab) {
            VaultTab()
                .tabItem { Label("Coffre", systemImage: "lock.rectangle.stack.fill") }
                .tag(PhoneModel.Tab.vault)
            GeneratorTab()
                .tabItem { Label("Générateur", systemImage: "wand.and.stars") }
                .tag(PhoneModel.Tab.generator)
            SettingsTab()
                .tabItem { Label("Réglages", systemImage: "gearshape.fill") }
                .tag(PhoneModel.Tab.settings)
        }
        .sheet(item: $model.editor) { editor in
            EditItemView(editor: editor)
                .interactiveDismissDisabled(model.editorBusy)
        }
        .sheet(item: $model.qrSheet) { sheet in
            WifiQRSheet(sheet: sheet)
        }
        .sheet(item: $model.moveRequest) { request in
            MoveToFolderSheet(request: request)
        }
        .sheet(item: $model.sharedFile, onDismiss: { model.sharedFile.map { Attachments.discard($0.url) } }) { file in
            ShareSheet(url: file.url)
        }
        .quickLookPreview($model.preview)
    }
}

/// Notification éphémère, au-dessus de la barre d'onglets.
private struct ToastHost: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        ZStack {
            if let toast = model.toast {
                PhoneToast(toast: toast)
                    .padding(.horizontal, 20)
                    .padding(.bottom, model.lockState == .unlocked ? 92 : 0)
                    .padding(.top, model.lockState == .unlocked ? 0 : 8)
                    .transition(.move(edge: model.lockState == .unlocked ? .bottom : .top).combined(with: .opacity))
                    .onTapGesture { model.toast = nil }
                    .task(id: toast.id) {
                        try? await Task.sleep(for: .seconds(toast.seconds))
                        if model.toast?.id == toast.id { model.toast = nil }
                    }
            }
        }
        .animation(.snappy, value: model.toast)
    }
}

/// La notification, en verre sur iOS 26.
private struct PhoneToast: View {
    let toast: Toast

    var body: some View {
        let content = HStack(spacing: 10) {
            Image(systemName: toast.failure ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(toast.failure ? .orange : .green)
                .font(.title3)
            VStack(alignment: .leading, spacing: 1) {
                Text(toast.message).font(.callout.weight(.semibold))
                if let detail = toast.detail {
                    Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(3)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        // Verre (Liquid Glass) avec le SDK d'iOS 26 (Xcode 26, Swift 6.2) ;
        // matériau flou sinon.
        #if compiler(>=6.2)
        if #available(iOS 26, *) {
            content.glassEffect(.regular, in: .rect(cornerRadius: 22))
        } else {
            materialToast(content)
        }
        #else
        materialToast(content)
        #endif
    }

    private func materialToast(_ content: some View) -> some View {
        content
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
            .shadow(color: .black.opacity(0.15), radius: 12, y: 4)
    }
}
