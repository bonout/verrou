import SwiftUI

/// L'onde du déverrouillage (Ripple.metal) appliquée à une vue. Le shader
/// ne tourne que pendant l'onde (`isEnabled`), jamais au repos ni hors écran.
struct RippleEffect: ViewModifier {
    /// Centre de l'onde, dans l'espace global (celui de l'écran).
    let origin: CGPoint
    /// Secondes depuis le départ de l'onde.
    let elapsed: Double

    static let duration = 0.7
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

    private func rippled(_ content: Content) -> some View {
        let origin = origin
        let elapsed = elapsed
        return content.visualEffect { view, proxy in
            // Le centre, ramené dans l'espace de la vue.
            let frame = proxy.frame(in: .global)
            let local = CGPoint(x: origin.x - frame.minX, y: origin.y - frame.minY)
            return view.layerEffect(
                ShaderLibrary.Ripple(.float2(proxy.size), .float2(local), .float(elapsed), .float(Self.amplitude),
                                     .float(36), .float(6), .float(1100)),
                maxSampleOffset: CGSize(width: Self.amplitude, height: Self.amplitude))
        }
    }
}
