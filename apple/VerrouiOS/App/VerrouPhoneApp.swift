import QuickLook
import SwiftUI

@main
struct VerrouPhoneApp: App {
    @State private var model = PhoneModel()
    @Environment(\.scenePhase) private var scenePhase
    #if DEBUG
    @State private var endToEnd: EndToEndDriver?
    @State private var autoFillSetup: AutoFillSetupDriver?
    @State private var bench: PhoneBenchDriver?
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
                    if autoFillSetup == nil, let config = AutoFillSetupDriver.Config(ProcessInfo.processInfo.environment) {
                        let driver = AutoFillSetupDriver(model: model, config: config)
                        autoFillSetup = driver
                        driver.start()
                    }
                    // Captures : `VERROU_OPEN_TAB=generator|vault` ouvre le coffre fictif sur cet onglet.
                    if let tab = ProcessInfo.processInfo.environment["VERROU_OPEN_TAB"], model.mode == .demo,
                       model.lockState == .locked {
                        model.openMockVault()
                        model.tab = tab == "generator" ? .generator : .vault
                    }
                    if bench == nil, PhoneBenchDriver.enabled {
                        let driver = PhoneBenchDriver(model: model)
                        bench = driver
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
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// L'écran verrouillé est affiché : au déverrouillage, il reste au-dessus
    /// du coffre (déjà utilisable) le temps de s'effacer.
    @State private var lockOnScreen = false

    /// Hors du premier plan (sélecteur d'apps, centre de contrôle) : le
    /// contenu est flouté et recouvert, l'aperçu du sélecteur ne montre rien.
    private var shielded: Bool { scenePhase != .active }

    private var showsLock: Bool {
        !model.needsLogin && (model.lockState != .unlocked || lockOnScreen)
    }

    var body: some View {
        @Bindable var model = model
        ZStack {
            ZStack {
                if model.lockState == .unlocked {
                    MainTabs()
                        .transition(.opacity)
                        .zIndex(0)
                } else if model.needsLogin {
                    LoginView()
                        .transition(.opacity)
                        .zIndex(0)
                }
                if showsLock {
                    LockView(departing: model.lockState == .unlocked) { lockOnScreen = false }
                        .onAppear { lockOnScreen = true }
                        .transition(.opacity)
                        // Toujours au-dessus du coffre qui s'insère dessous.
                        .zIndex(1)
                }
            }
            .blur(radius: shielded ? 28 : 0)
            if shielded {
                PrivacyCover(opaque: scenePhase == .background)
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.lockState)
        .animation(.easeOut(duration: 0.2), value: model.needsLogin)
        // Flou progressif vers le sélecteur d'apps ; jamais en passant
        // directement en arrière-plan, où l'aperçu est pris aussitôt.
        .animation(scenePhase == .background ? nil : .easeOut(duration: 0.18), value: shielded)
        // Chaque copie : un retour haptique de réussite.
        .sensoryFeedback(.success, trigger: model.copies)
        .tint(Theme.accent)
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
    /// En arrière-plan : un fond plein, posé sans animation, au cas où
    /// l'aperçu du sélecteur serait pris avant la fin du flou.
    var opaque = false

    var body: some View {
        ZStack {
            if opaque {
                Color(.systemBackground)
                    .transition(.identity)
            }
            Rectangle().fill(.regularMaterial)
            VStack(spacing: 14) {
                AppMark(size: 76, glow: false)
                Text("Verrou")
                    .font(.system(.title2, design: .rounded, weight: .bold))
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// Les onglets du coffre ouvert : Coffre, Générateur, Réglages et
/// Rechercher (iOS 18+ : onglet de recherche à part, dans la barre d'onglets
/// de verre sur iOS 26, qui se replie au défilement).
struct MainTabs: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Group {
            if #available(iOS 18, *) {
                modernTabs
            } else {
                legacyTabs
            }
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

    @available(iOS 18, *)
    private var modernTabs: some View {
        @Bindable var model = model
        return TabView(selection: $model.tab) {
            Tab("Coffre", systemImage: "lock.rectangle.stack.fill", value: PhoneModel.Tab.vault) {
                VaultTab()
            }
            Tab("Générateur", systemImage: "wand.and.stars", value: PhoneModel.Tab.generator) {
                GeneratorTab()
            }
            Tab("Réglages", systemImage: "gearshape.fill", value: PhoneModel.Tab.settings) {
                SettingsTab()
            }
            Tab("Rechercher", systemImage: "magnifyingglass", value: PhoneModel.Tab.search, role: .search) {
                SearchTab()
            }
        }
        .modifier(MinimizingTabBar())
    }

    /// iOS 17 : les mêmes onglets, la recherche en dernier.
    private var legacyTabs: some View {
        @Bindable var model = model
        return TabView(selection: $model.tab) {
            VaultTab()
                .tabItem { Label("Coffre", systemImage: "lock.rectangle.stack.fill") }
                .tag(PhoneModel.Tab.vault)
            GeneratorTab()
                .tabItem { Label("Générateur", systemImage: "wand.and.stars") }
                .tag(PhoneModel.Tab.generator)
            SettingsTab()
                .tabItem { Label("Réglages", systemImage: "gearshape.fill") }
                .tag(PhoneModel.Tab.settings)
            SearchTab()
                .tabItem { Label("Rechercher", systemImage: "magnifyingglass") }
                .tag(PhoneModel.Tab.search)
        }
    }
}

/// iOS 26 : la barre d'onglets se replie quand on fait défiler vers le bas.
private struct MinimizingTabBar: ViewModifier {
    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, *) {
            content.tabBarMinimizeBehavior(.onScrollDown)
        } else {
            content
        }
        #else
        content
        #endif
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

/// La notification, en verre sur iOS 26 (matériau flou avant).
private struct PhoneToast: View {
    let toast: Toast

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: toast.failure ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(toast.failure ? .orange : .green)
                .font(.title2)
                .symbolEffect(.bounce, value: toast.id)
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
        .glassSurface(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .shadow(color: LiquidGlass.isAvailable ? .clear : .black.opacity(0.15), radius: 12, y: 4)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("toast")
    }
}
