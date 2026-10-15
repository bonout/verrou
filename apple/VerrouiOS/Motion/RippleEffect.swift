import os
import SwiftUI

/// L'onde du déverrouillage (Ripple.metal) appliquée à une vue. Le shader
/// ne tourne que pendant l'onde (`isEnabled`), jamais au repos ni hors écran.
struct RippleEffect: ViewModifier {
    /// Centre de l'onde, dans l'espace global (celui de l'écran).
    let origin: CGPoint
    /// Secondes depuis le départ de l'onde.
    let elapsed: Double

    /// Assez court pour tenir dans l'effacement de l'écran verrouillé.
    static let duration = 0.26
    private static let amplitude: Double = 16

    func body(content: Content) -> some View {
        // Au repos, la vue telle quelle : la bibliothèque Metal n'est chargée
        // qu'au premier déverrouillage, pas au lancement.
        if elapsed > 0 && elapsed < Self.duration {
            rippled(content)
        } else {
            content
        }
    }

    private static func shader(size: CGSize, origin: CGPoint, elapsed: Double) -> Shader {
        ShaderLibrary.Ripple(.float2(size), .float2(origin), .float(elapsed), .float(amplitude),
                             .float(36), .float(6), .float(1100))
    }

    /// Compile le shader hors du fil principal, une fois : le premier
    /// déverrouillage ne l'attend pas (iOS 18 ; avant, il est compilé à la
    /// première onde).
    static func prewarm() {
        guard !prewarmed.withLock({ done in defer { done = true }; return done }) else { return }
        if #available(iOS 18, *) {
            Task.detached(priority: .utility) {
                try? await shader(size: CGSize(width: 1, height: 1), origin: .zero, elapsed: 0.1)
                    .compile(as: .layerEffect)
            }
        }
    }

    private static let prewarmed = OSAllocatedUnfairLock(initialState: false)

    private func rippled(_ content: Content) -> some View {
        let origin = origin
        let elapsed = elapsed
        return content.visualEffect { view, proxy in
            // Le centre, ramené dans l'espace de la vue.
            let frame = proxy.frame(in: .global)
            let local = CGPoint(x: origin.x - frame.minX, y: origin.y - frame.minY)
            return view.layerEffect(
                Self.shader(size: proxy.size, origin: local, elapsed: elapsed),
                maxSampleOffset: CGSize(width: Self.amplitude, height: Self.amplitude))
        }
    }
}
