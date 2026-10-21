import os
import SwiftUI

/// The unlock ripple (Ripple.metal) applied to a view. The shader only runs
/// during the ripple (`isEnabled`), never at rest or off screen.
struct RippleEffect: ViewModifier {
    /// Center of the ripple, in global space (the screen's).
    let origin: CGPoint
    /// Seconds since the ripple started.
    let elapsed: Double

    /// Short enough to fit in the lock screen's fade.
    static let duration = 0.26
    private static let amplitude: Double = 16

    func body(content: Content) -> some View {
        // At rest, the view as is: the Metal library is only loaded at the
        // first unlock, not at launch.
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

    /// Compiles the shader off the main thread, once: the first unlock
    /// doesn't wait for it (iOS 18; before, it is compiled at the first
    /// ripple).
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
            // The center, brought into the view's space.
            let frame = proxy.frame(in: .global)
            let local = CGPoint(x: origin.x - frame.minX, y: origin.y - frame.minY)
            return view.layerEffect(
                Self.shader(size: proxy.size, origin: local, elapsed: elapsed),
                maxSampleOffset: CGSize(width: Self.amplitude, height: Self.amplitude))
        }
    }
}
