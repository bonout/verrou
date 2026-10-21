import SwiftUI

/// Lock screen background: a mesh gradient in Verrou's colors whose points
/// drift slowly (iOS 18). The clock stops when the scene isn't active or the
/// screen isn't shown; still mesh with "Reduce Motion"; the usual fixed
/// background on iOS 17.
struct LockMeshBackground: View {
    /// Unlock ripple on the background (RippleEffect): global center and
    /// seconds elapsed (0: no ripple).
    var rippleOrigin: CGPoint = .zero
    var rippleElapsed: Double = 0
    /// On unlock: the mesh freezes during the fade, the rendering goes to
    /// the vault appearing underneath.
    var frozen = false
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorScheme) private var colorScheme
    @State private var onScreen = false
    /// The mesh only arrives after 0.5 s on screen, fading in over the fixed
    /// background: the first frame (launch) doesn't wait for it to be set
    /// up, and a vault opened right away never builds it.
    @State private var meshReady = false

    var body: some View {
        // The ripple applies to the background already extended under the system bars.
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
        // 30 frames per second are enough for such a slow drift.
        let paused = !onScreen || scenePhase != .active || reduceMotion || frozen
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

    /// Fixed corners; edge midpoints and center that drift, each at its own
    /// pace (periods of 11 to 23 s), without ever crossing.
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

    /// Brand hues, deeper in dark mode; the bottom stays close to the
    /// background for the controls' readability.
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
