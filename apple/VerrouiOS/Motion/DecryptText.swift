import SwiftUI

// Mot de passe « déchiffré » : à son apparition, chaque caractère passe par
// des glyphes au hasard puis se fixe, de gauche à droite. Dessiné par un
// TextRenderer (iOS 18) : aucune vue créée par caractère, seulement des
// glyphes posés dans le contexte graphique du texte. Repli : un fondu
// (iOS 17, « Réduire les animations »).

/// Calendrier de l'effet pour `length` caractères : moins d'une seconde,
/// quelle que soit la longueur.
struct DecryptTiming {
    let length: Int
    /// Avant que le premier caractère se fixe.
    var lead: Double { 0.08 }
    /// Écart entre deux caractères qui se fixent.
    var step: Double { length > 0 ? min(0.045, 0.6 / Double(length)) : 0 }
    /// Fondu d'un caractère qui se fixe.
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

    /// Glyphes du brouillage : lettres, chiffres et symboles lisibles.
    private static let pool = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789#$%&*+=?@")

    func draw(layout: Text.Layout, in context: inout GraphicsContext) {
        // Fini : le texte tel quel.
        guard elapsed < timing.total else {
            for line in layout { context.draw(line) }
            return
        }
        // Le brouillage change de glyphe toutes les 50 ms.
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

    /// Hasard reproductible (même image, même glyphe), sans générateur.
    private static func scramble(_ index: Int, _ tick: Int) -> Int {
        var value = UInt64(truncatingIfNeeded: index &* 7919 &+ tick &* 104_729 &+ 12_345)
        value ^= value >> 33
        value = value &* 0xff51_afd7_ed55_8ccd
        value ^= value >> 33
        return Int(value % 1_000_003)
    }
}

/// Le texte se déchiffre à son apparition et, si `replays`, à chaque
/// nouvelle valeur. Le TextRenderer est piloté par une horloge
/// (`TimelineView`) qui ne tourne que pendant l'effet, moins d'une seconde.
///
/// Une transition d'insertion (protocole `Transition`) aurait été plus
/// naturelle, mais les transitions ne s'animent pas dans les lignes d'une
/// liste ou d'un formulaire, là où s'affichent la fiche et le générateur.
@available(iOS 18, *)
private struct DecryptingContent<Content: View>: View {
    let value: String
    let fontSize: CGFloat
    let replays: Bool
    @ViewBuilder let content: Content
    /// Départ de l'effet : la création de la vue (apparition), puis chaque
    /// nouvelle valeur.
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
            // Horloge arrêtée une fois tous les caractères fixés.
            do { try await Task.sleep(for: .seconds(timing.total)) } catch { return }
            running = false
        }
    }
}

/// Valeur secrète révélée ou générée : déchiffrée à son apparition (iOS 18),
/// en fondu sinon. `replaysOnChange` rejoue l'effet à chaque nouvelle valeur
/// (générateur) ; sinon seulement quand la valeur apparaît (révélation).
struct DecryptReveal<Revealed: View, Masked: View>: View {
    let value: String?
    var fontSize: CGFloat = 17
    var replaysOnChange = false
    @ViewBuilder let revealed: (String) -> Revealed
    @ViewBuilder let masked: () -> Masked
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Builds Debug : `VERROU_DECRYPT_AT=<secondes>` fige l'effet (captures).
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
                    // iOS 17 ou « Réduire les animations » : un fondu.
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
        // Seul le passage masqué ↔ révélé s'anime ici : une nouvelle valeur
        // se déchiffre en place, sans fondu croisé avec l'ancienne.
        .animation(.easeInOut(duration: 0.2), value: value == nil)
    }
}
