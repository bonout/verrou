import SwiftUI

// "Decrypted" password: when it appears, each character goes through
// random glyphs then settles, from left to right. Drawn by a TextRenderer
// (iOS 18): no view created per character, only glyphs placed in the
// text's graphics context. Fallback: a fade (iOS 17, "Reduce Motion").

/// Schedule of the effect for `length` characters: under a second, whatever
/// the length.
struct DecryptTiming {
    let length: Int
    /// Before the first character settles.
    var lead: Double { 0.08 }
    /// Gap between two characters settling.
    var step: Double { length > 0 ? min(0.045, 0.6 / Double(length)) : 0 }
    /// Fade of a settling character.
    var settle: Double { 0.1 }
    var total: Double { lead + step * Double(max(length - 1, 0)) + settle }
}

@available(iOS 18, *)
struct DecryptRenderer: TextRenderer {
    var elapsed: Double
    let timing: DecryptTiming
    let fontSize: CGFloat

    var animatableData: Double {
        get { elapsed }
        set { elapsed = newValue }
    }

    /// Scrambling glyphs: readable letters, digits and symbols.
    private static let pool = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789#$%&*+=?@")

    func draw(layout: Text.Layout, in context: inout GraphicsContext) {
        // Done: the text as is.
        guard elapsed < timing.total else {
            for line in layout { context.draw(line) }
            return
        }
        // The scrambling changes glyph every 50 ms.
        let tick = Int(elapsed / 0.05)
        var resolved: [Character: GraphicsContext.ResolvedText] = [:]
        var index = 0
        for line in layout {
            for run in line {
                for slice in run {
                    let settleAt = timing.lead + timing.step * Double(index)
                    let progress = (elapsed - settleAt) / timing.settle
                    if progress >= 1 {
                        context.draw(slice)
                    } else {
                        if progress > 0 {
                            var settled = context
                            settled.opacity = progress
                            settled.draw(slice)
                        }
                        let character = Self.pool[Self.scramble(index, tick) % Self.pool.count]
                        let glyph = resolved[character] ?? context.resolve(
                            Text(String(character))
                                .font(.system(size: fontSize, design: .monospaced))
                                .foregroundStyle(Theme.accent.opacity(0.75)))
                        resolved[character] = glyph
                        let bounds = slice.typographicBounds.rect
                        var scrambled = context
                        scrambled.opacity = 1 - max(0, progress)
                        scrambled.draw(glyph, at: CGPoint(x: bounds.midX, y: bounds.midY), anchor: .center)
                    }
                    index += 1
                }
            }
        }
    }

    /// Reproducible randomness (same frame, same glyph), without a generator.
    private static func scramble(_ index: Int, _ tick: Int) -> Int {
        var value = UInt64(truncatingIfNeeded: index &* 7919 &+ tick &* 104_729 &+ 12_345)
        value ^= value >> 33
        value = value &* 0xff51_afd7_ed55_8ccd
        value ^= value >> 33
        return Int(value % 1_000_003)
    }
}

/// The text decrypts when it appears and, if `replays`, at each new value.
/// The TextRenderer is driven by a clock (`TimelineView`) that only runs
/// during the effect, under a second.
///
/// An insertion transition (`Transition` protocol) would have been more
/// natural, but transitions don't animate in the rows of a list or a form,
/// where the item page and the generator are shown.
@available(iOS 18, *)
private struct DecryptingContent<Content: View>: View {
    let value: String
    let fontSize: CGFloat
    let replays: Bool
    @ViewBuilder let content: Content
    /// Start of the effect: the view's creation (appearance), then each new
    /// value.
    @State private var start = Date()
    @State private var running = true

    var body: some View {
        let timing = DecryptTiming(length: value.count)
        TimelineView(.animation(paused: !running)) { context in
            let elapsed = running ? max(0, context.date.timeIntervalSince(start)) : timing.total
            content.textRenderer(DecryptRenderer(elapsed: elapsed, timing: timing, fontSize: fontSize))
        }
        .onChange(of: value) {
            guard replays else { return }
            start = .now
            running = true
        }
        .task(id: start) {
            // Clock stopped once all characters have settled.
            do { try await Task.sleep(for: .seconds(timing.total)) } catch { return }
            running = false
        }
    }
}

/// Secret value revealed or generated: decrypted when it appears (iOS 18),
/// with a fade otherwise. `replaysOnChange` replays the effect at each new
/// value (generator); otherwise only when the value appears (reveal).
struct DecryptReveal<Revealed: View, Masked: View>: View {
    let value: String?
    var fontSize: CGFloat = 17
    var replaysOnChange = false
    @ViewBuilder let revealed: (String) -> Revealed
    @ViewBuilder let masked: () -> Masked
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Debug builds: `VERROU_DECRYPT_AT=<seconds>` freezes the effect (screenshots).
    private static var frozen: Double? {
        #if DEBUG
        ProcessInfo.processInfo.environment["VERROU_DECRYPT_AT"].flatMap(Double.init)
        #else
        nil
        #endif
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            if let value {
                if #available(iOS 18, *), let frozen = Self.frozen {
                    revealed(value).textRenderer(DecryptRenderer(elapsed: frozen, timing: DecryptTiming(length: value.count),
                                                                 fontSize: fontSize))
                } else if #available(iOS 18, *), Motion.modern, !reduceMotion {
                    DecryptingContent(value: value, fontSize: fontSize, replays: replaysOnChange) {
                        revealed(value)
                    }
                } else {
                    // iOS 17 or "Reduce Motion": a fade.
                    revealed(value)
                        .contentTransition(.opacity)
                        .animation(.easeInOut(duration: 0.2), value: value)
                        .transition(.opacity)
                }
            } else {
                masked()
                    .transition(.opacity)
            }
        }
        // Only the hidden ↔ revealed change animates here: a new value
        // decrypts in place, without a cross-fade with the old one.
        .animation(.easeInOut(duration: 0.2), value: value == nil)
    }
}
