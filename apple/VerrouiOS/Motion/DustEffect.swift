import os
import SwiftUI
import UIKit

/// A page that turns to dust (Dust.metal): archiving an item. The shader
/// works on a snapshot of the page (a `List` is drawn by UIKit, out of
/// SwiftUI's effects); the snapshot only lives in memory for the animation.
struct DustView: View {
    let image: UIImage
    /// The clock starts at the first frame drawn, not at the tap.
    @State private var start: Date?

    static let duration: TimeInterval = 1.1
    nonisolated private static let grain: Double = 3
    nonisolated private static let distance: Double = 110

    var body: some View {
        TimelineView(.animation) { context in
            let progress = start.map { min(1, context.date.timeIntervalSince($0) / Self.duration) } ?? 0
            Image(uiImage: image)
                .resizable()
                .visualEffect { view, proxy in
                    view.layerEffect(Self.shader(size: proxy.size, progress: progress),
                                     maxSampleOffset: CGSize(width: Self.distance * 1.1, height: Self.distance * 1.5))
                }
        }
        .onAppear { start = Date() }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    nonisolated private static func shader(size: CGSize, progress: Double) -> Shader {
        ShaderLibrary.Dust(.float2(size), .float(progress), .float(grain), .float(distance))
    }

    /// Compiles the shader off the main thread, once (iOS 18): the first
    /// archive doesn't freeze while Metal compiles it.
    static func prewarm() {
        guard !prewarmed.withLock({ done in defer { done = true }; return done }) else { return }
        if #available(iOS 18, *) {
            Task.detached(priority: .utility) {
                try? await shader(size: CGSize(width: 1, height: 1), progress: 0.5).compile(as: .layerEffect)
            }
        }
    }

    private static let prewarmed = OSAllocatedUnfairLock(initialState: false)

    /// What is on screen in `rect` (global points), from the key window.
    static func snapshot(_ rect: CGRect) -> UIImage? {
        guard rect.width > 0, rect.height > 0,
              let window = UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene })
                .flatMap(\.windows)
                .first(where: \.isKeyWindow) else { return nil }
        let renderer = UIGraphicsImageRenderer(bounds: rect, format: UIGraphicsImageRendererFormat(for: window.traitCollection))
        return renderer.image { _ in
            window.drawHierarchy(in: window.bounds, afterScreenUpdates: false)
        }
    }
}
