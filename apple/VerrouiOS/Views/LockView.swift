import SwiftUI

/// Coffre verrouillé : Face ID (ou Touch ID), sinon le mot de passe principal.
/// Même composition que l'écran verrouillé du Mac : halo d'accent, logo,
/// titre arrondi ; les commandes en verre au bas de l'écran (iOS 26).
///
/// Au déverrouillage (`departing`), le coffre est déjà affiché et utilisable
/// dessous : cet écran ne reçoit plus les touchers et s'efface en moins d'une
/// demi-seconde. L'anse du cadenas s'ouvre (images clés), une onde part du
/// bouton utilisé (shader Metal) et le logo file vers le coffre
/// (`matchedGeometryEffect`) ; un simple fondu avec « Réduire les animations ».
struct LockView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Coffre ouvert : l'écran s'efface au-dessus du coffre.
    var departing = false
    /// Fin de l'effacement : l'écran peut quitter la hiérarchie.
    var departed: () -> Void = {}
    @State private var password = ""
    /// Mot de passe choisi plutôt que Face ID.
    @State private var usePassword = false
    /// Centre de la commande principale (bouton Face ID ou champ), dans
    /// l'espace de l'écran : départ de l'onde.
    @State private var controlCenter = CGPoint.zero
    @FocusState private var passwordFocused: Bool
    @Namespace private var logoSpace
    /// Apparition de l'écran : un coffre ouvert presque aussitôt (moins de
    /// 0,3 s) s'affiche par un simple fondu, sans l'animation complète.
    @State private var shownAt = Date()

    /// Durée de l'effacement.
    static func departure(reduceMotion: Bool) -> Duration {
        reduceMotion ? .milliseconds(240) : .milliseconds(480)
    }

    private var flourish: Bool {
        departing && !reduceMotion && Date().timeIntervalSince(shownAt) > 0.3
    }

    var body: some View {
        KeyframeAnimator(initialValue: UnlockFrame(), trigger: departing) { frame in
            screen(flourish ? frame : UnlockFrame())
        } keyframes: { _ in
            KeyframeTrack(\.shackle) {
                SpringKeyframe(1.15, duration: 0.18, spring: .snappy)
                SpringKeyframe(1, duration: 0.2, spring: .bouncy)
                LinearKeyframe(1, duration: 0.4)
            }
            KeyframeTrack(\.ripple) {
                LinearKeyframe(RippleEffect.duration, duration: RippleEffect.duration)
            }
        }
        // Tout l'écran s'efface ensemble, lentement d'abord (l'onde et l'anse
        // restent visibles), sans délai : un délai ne s'applique pas au calque
        // du shader, qui disparaîtrait avant le texte.
        .opacity(departing ? 0 : 1)
        .animation(departing
                   ? (reduceMotion ? .easeOut(duration: 0.22) : .timingCurve(0.55, 0, 0.75, 0.6, duration: 0.45))
                   : .easeOut(duration: 0.15),
                   value: departing)
        .allowsHitTesting(!departing)
        .accessibilityHidden(departing)
        .task(id: departing) {
            guard departing else { return }
            Perf.log.notice("écran verrouillé : effacement au-dessus du coffre")
            // Tâche annulée (vue reconstruite) : la suivante prend le relais.
            do { try await Task.sleep(for: Self.departure(reduceMotion: reduceMotion)) } catch { return }
            if departing { departed() }
        }
        .animation(.snappy, value: model.unlockError)
        .sensoryFeedback(.error, trigger: model.unlockError) { _, new in new != nil }
        #if DEBUG
        .onAppear { PhoneBenchDriver.lockShown = true }
        .onDisappear { PhoneBenchDriver.lockShown = false }
        #endif
        .onAppear {
            guard !departing else { return }
            Perf.log.notice("écran verrouillé affiché à +\(Perf.msSinceLaunch) ms du lancement")
            if model.canUseBiometrics {
                Task { await model.promptBiometricsIfPossible() }
            }
        }
    }

    /// Builds Debug : `VERROU_RIPPLE_AT=<secondes>` fige l'onde à cet instant
    /// sur l'écran verrouillé (captures du shader).
    private static let frozenRipple: Double? = {
        #if DEBUG
        ProcessInfo.processInfo.environment["VERROU_RIPPLE_AT"].flatMap(Double.init)
        #else
        nil
        #endif
    }()

    private func screen(_ frame: UnlockFrame) -> some View {
        ZStack {
            LockMeshBackground(rippleOrigin: controlCenter, rippleElapsed: Self.frozenRipple ?? frame.ripple)
            VStack(spacing: 28) {
                Spacer()
                VStack(spacing: 14) {
                    // Le logo suit l'ancre « accueil », puis celle du haut de
                    // l'écran au départ, en rapetissant.
                    ZStack {
                        Color.clear
                            .matchedGeometryEffect(id: "home", in: logoSpace)
                        AppMark(size: 96, glow: !flourish, shackle: frame.shackle)
                            .scaleEffect(flourish ? 0.36 : 1)
                            .matchedGeometryEffect(id: flourish ? "dock" : "home", in: logoSpace,
                                                   properties: .position, isSource: false)
                    }
                    .frame(width: 96, height: 96)
                    .padding(.bottom, 6)
                    // Le titre part vite : le logo reste seul à filer vers le coffre.
                    VStack(spacing: 14) {
                        Text("Verrou")
                            .font(.system(size: 36, weight: .bold, design: .rounded))
                            .accessibilityAddTraits(.isHeader)
                        Text(subtitle)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .opacity(departing ? 0 : 1)
                    .animation(.easeOut(duration: 0.15), value: departing)
                }
                Spacer()
                LockControls(password: $password, usePassword: $usePassword, focused: $passwordFocused,
                             submit: submit)
                    .onGeometryChange(for: CGPoint.self) { proxy in
                        let frame = proxy.frame(in: .global)
                        return CGPoint(x: frame.midX, y: frame.minY + min(frame.height, 52) / 2)
                    } action: { controlCenter = $0 }
                    .opacity(departing ? 0 : 1)
                    .animation(.easeOut(duration: 0.12), value: departing)
                if let error = model.unlockError, !error.isEmpty {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                }
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 20)
            .frame(maxWidth: 520)
        }
        // Le logo file vers le haut, là où s'affiche le coffre.
        .overlay(alignment: .top) {
            Color.clear
                .frame(width: 34, height: 34)
                .matchedGeometryEffect(id: "dock", in: logoSpace)
                .padding(.top, 4)
                .allowsHitTesting(false)
        }
        .animation(.spring(response: 0.34, dampingFraction: 0.86).delay(0.1), value: flourish)
    }

    private var subtitle: String {
        guard model.mode == .vaultwarden, let account = model.account else {
            return "Coffre fictif · données de démonstration"
        }
        let host = URL(string: account.server)?.host() ?? account.server
        return "\(account.email)\n\(host)"
    }

    private func submit() {
        let typed = password
        password = ""
        passwordFocused = false
        Task { await model.unlock(masterPassword: typed) }
    }
}

/// Valeurs animées du déverrouillage (images clés).
struct UnlockFrame {
    /// Ouverture de l'anse (`Padlock.shackle`).
    var shackle: CGFloat = 0
    /// Secondes écoulées de l'onde.
    var ripple: Double = 0
}

/// Les commandes : Face ID, ou le mot de passe principal quand on le choisit
/// (ou sans Face ID). Sur iOS 26, le bouton de verre se transforme en champ
/// (`glassEffectID`) ; avant, ou avec « Réduire les animations », un fondu.
private struct LockControls: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Binding var password: String
    @Binding var usePassword: Bool
    var focused: FocusState<Bool>.Binding
    let submit: () -> Void
    @Namespace private var glass

    var body: some View {
        let biometrics = model.canUseBiometrics
        let morph = LiquidGlass.isAvailable && !reduceMotion
        GlassGroup(spacing: 14) {
            VStack(spacing: 14) {
                if biometrics && !usePassword {
                    BiometricUnlockButton(title: "Déverrouiller avec \(Biometrics.name)",
                                          symbol: Biometrics.symbolName,
                                          busy: model.lockState == .unlocking) {
                        Task { await model.unlockWithBiometrics() }
                    }
                    .glassMorphID("primary", in: glass, morph: morph)
                    Button("Utiliser le mot de passe principal") { usePassword = true }
                        .font(.callout.weight(.medium))
                        .disabled(model.lockState == .unlocking)
                        .accessibilityIdentifier("lock-use-password")
                        .transition(.opacity)
                } else {
                    HStack(spacing: 10) {
                        MasterPasswordField(password: $password, busy: model.lockState == .unlocking,
                                            focused: focused, submit: submit)
                            .glassMorphID("primary", in: glass, morph: morph)
                        if biometrics {
                            Button {
                                usePassword = false
                                focused.wrappedValue = false
                                Task { await model.unlockWithBiometrics() }
                            } label: {
                                Image(systemName: Biometrics.symbolName)
                                    .font(.title2)
                                    .frame(width: 52, height: 52)
                                    .contentShape(Circle())
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Theme.accent)
                            .glassSurface(Circle(), interactive: true)
                            .glassMorphID("biometrics", in: glass, morph: morph)
                            .accessibilityLabel("Déverrouiller avec \(Biometrics.name)")
                            .transition(.opacity)
                        }
                    }
                }
            }
        }
        .animation(morph ? .bouncy(duration: 0.45) : .easeInOut(duration: 0.25), value: usePassword)
        .onChange(of: usePassword) { _, chosen in
            guard chosen else { return }
            // Le clavier arrive une fois le champ en place.
            Task {
                try? await Task.sleep(for: .milliseconds(morph ? 380 : 200))
                if usePassword { focused.wrappedValue = true }
            }
        }
    }
}
