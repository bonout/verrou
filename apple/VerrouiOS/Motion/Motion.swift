import SwiftUI

// Petites briques d'animation de l'iPhone. Chaque animation est liée à sa
// valeur (`.animation(_, value:)`), jamais au modèle ; « Réduire les
// animations » remplace les mouvements par des fondus. `VERROU_LEGACY_UI=1`
// (builds Debug) force les replis d'iOS 17 sur un iOS récent.

enum Motion {
    /// API d'iOS 18 permises (TextRenderer, MeshGradient, effets de symboles
    /// récents) : iOS 18 ou plus, sans repli forcé.
    static var modern: Bool {
        if #available(iOS 18, *) { return !LiquidGlass.forcedFallback }
        return false
    }
}

// MARK: Symbole remplacé

/// Remplacement d'un symbole (copie → coche) : « magique » sur iOS 18
/// (les éléments communs restent en place), remplacement simple sur iOS 17,
/// fondu avec « Réduire les animations ».
private struct SymbolReplaceTransition: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        if reduceMotion {
            content.contentTransition(.opacity)
        } else if #available(iOS 18, *), Motion.modern {
            content.contentTransition(.symbolEffect(.replace.magic(fallback: .replace)))
        } else {
            content.contentTransition(.symbolEffect(.replace))
        }
    }
}

extension View {
    func symbolReplaceTransition() -> some View {
        modifier(SymbolReplaceTransition())
    }
}

/// Symbole de copie qui devient une coche, puis revient.
struct CopySymbol: View {
    var symbol = "doc.on.doc"
    let copied: Bool

    var body: some View {
        Image(systemName: copied ? "checkmark" : symbol)
            .symbolReplaceTransition()
            .animation(.snappy(duration: 0.3), value: copied)
    }
}

/// État « copié » d'un bouton : vrai pendant 1,5 s après chaque copie.
/// Remis à faux par une échéance, pas par une tâche de la vue : une ligne de
/// liste rechargée annulerait la tâche et ferait disparaître la coche aussitôt.
struct CopiedFlag: ViewModifier {
    @Binding var copied: Bool
    @State private var token = 0

    func body(content: Content) -> some View {
        content.onChange(of: copied) { _, now in
            guard now else { return }
            token += 1
            let mine = token
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                if token == mine { copied = false }
            }
        }
    }
}

// MARK: Apparition en cascade

/// Apparition décalée (cartes de l'audit) : chaque élément glisse et apparaît
/// après le précédent ; un simple fondu avec « Réduire les animations ».
struct StaggeredAppearance: ViewModifier {
    let index: Int
    let shown: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0)
            .offset(y: shown || reduceMotion ? 0 : 16)
            .animation(reduceMotion
                       ? .easeOut(duration: 0.2)
                       : .spring(response: 0.45, dampingFraction: 0.82).delay(Double(min(index, 8)) * 0.07),
                       value: shown)
    }
}

extension View {
    func staggered(_ index: Int, shown: Bool) -> some View {
        modifier(StaggeredAppearance(index: index, shown: shown))
    }
}

// MARK: Rotation d'un cran

/// Le symbole tourne d'un tour à chaque `value` (iOS 18 : effet de symbole ;
/// iOS 17 : rotation de la vue) ; immobile avec « Réduire les animations ».
private struct RotateOnChange: ViewModifier {
    let value: Int
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        if reduceMotion {
            content
        } else if #available(iOS 18, *), Motion.modern {
            content.symbolEffect(.rotate.byLayer, options: .speed(1.6), value: value)
        } else {
            content
                .rotationEffect(.degrees(Double(value) * 360))
                .animation(.spring(response: 0.5, dampingFraction: 0.8), value: value)
        }
    }
}

extension View {
    func rotatesOnChange(of value: Int) -> some View {
        modifier(RotateOnChange(value: value))
    }

    /// Rebond du symbole à chaque changement de `value`, sauf avec « Réduire
    /// les animations ».
    func bounceOnChange(of value: some Equatable) -> some View {
        modifier(BounceOnChange(value: value))
    }
}

private struct BounceOnChange<Value: Equatable>: ViewModifier {
    let value: Value
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content.symbolEffect(.bounce, value: value)
            .symbolEffectsRemoved(reduceMotion)
    }
}
