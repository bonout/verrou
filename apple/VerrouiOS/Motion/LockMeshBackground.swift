import SwiftUI

/// Fond de l'écran verrouillé : un dégradé maillé aux couleurs de Verrou
/// dont les points dérivent lentement (iOS 18). L'horloge s'arrête quand la
/// scène n'est pas active ou que l'écran n'est pas affiché ; maillage immobile
/// avec « Réduire les animations » ; le fond fixe de toujours sur iOS 17.
struct LockMeshBackground: View {
    /// Onde du déverrouillage sur le fond (RippleEffect) : centre global et
    /// secondes écoulées (0 : pas d'onde).
    var rippleOrigin: CGPoint = .zero
    var rippleElapsed: Double = 0
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorScheme) private var colorScheme
    @State private var onScreen = false
    /// Le maillage n'arrive qu'après 0,5 s à l'écran, en fondu sur le fond
    /// fixe : la première image (lancement) n'attend pas sa mise en place, et
    /// un coffre ouvert aussitôt ne le construit jamais.
    @State private var meshReady = false

    var body: some View {
        // L'onde s'applique au fond déjà étendu sous les barres du système.
        ZStack {
            LockBackground()
            if #available(iOS 18, *), Motion.modern, meshReady {
                mesh
                    .transition(.opacity)
            }
        }
        .ignoresSafeArea()
        .animation(.easeIn(duration: 0.8), value: meshReady)
        .task {
            guard Motion.modern else { return }
            do { try await Task.sleep(for: .milliseconds(500)) } catch { return }
            meshReady = true
        }
        .modifier(RippleEffect(origin: rippleOrigin, elapsed: rippleElapsed))
    }

    @available(iOS 18, *)
    private var mesh: some View {
        // 30 images par seconde suffisent à une dérive aussi lente.
        let paused = !onScreen || scenePhase != .active || reduceMotion
        return TimelineView(.animation(minimumInterval: 1.0 / 30, paused: paused)) { context in
            let time = reduceMotion ? 0 : context.date.timeIntervalSinceReferenceDate
            ZStack {
                Color(.systemGroupedBackground)
                MeshGradient(width: 3, height: 3, points: Self.points(at: time), colors: colors)
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
        .onAppear { onScreen = true }
        .onDisappear { onScreen = false }
    }

    /// Coins fixes ; milieux des bords et centre qui dérivent, chacun à son
    /// rythme (périodes de 11 à 23 s), sans jamais se croiser.
    static func points(at time: TimeInterval) -> [SIMD2<Float>] {
        func drift(_ period: Double, _ phase: Double, _ range: Float) -> Float {
            Float(sin(time * 2 * .pi / period + phase)) * range
        }
        return [
            [0, 0], [0.5 + drift(17, 0, 0.12), 0], [1, 0],
            [0, 0.45 + drift(13, 1.1, 0.1)],
            [0.5 + drift(19, 2.3, 0.14), 0.42 + drift(23, 0.7, 0.1)],
            [1, 0.5 + drift(11, 3.4, 0.1)],
            [0, 1], [0.5 + drift(15, 4.2, 0.12), 1], [1, 1],
        ]
    }

    /// Teintes de la marque, plus soutenues en sombre ; le bas reste proche
    /// du fond pour la lisibilité des commandes.
    private var colors: [Color] {
        let dark = colorScheme == .dark
        let strong = dark ? 0.42 : 0.30
        let soft = dark ? 0.22 : 0.14
        return [
            Theme.accent.opacity(strong), Theme.brandTop.opacity(strong * 0.8), Theme.accent.opacity(soft),
            Theme.brandTop.opacity(soft), Theme.brandBottom.opacity(soft * 0.8), Theme.accent.opacity(soft * 0.7),
            Theme.brandBottom.opacity(soft * 0.6), Theme.accent.opacity(soft * 0.4), Theme.brandBottom.opacity(soft * 0.9),
        ]
    }
}
