import SwiftUI

// Small animation building blocks of the iPhone. Each animation is tied to
// its value (`.animation(_, value:)`), never to the model; "Reduce Motion"
// replaces movements with fades. `VERROU_LEGACY_UI=1` (Debug builds) forces
// the iOS 17 fallbacks on a recent iOS.

enum Motion {
    /// iOS 18 APIs allowed (TextRenderer, MeshGradient, recent symbol
    /// effects): iOS 18 or later, without a forced fallback.
    static var modern: Bool {
        if #available(iOS 18, *) { return !LiquidGlass.forcedFallback }
        return false
    }
}

// MARK: Replaced symbol

/// Replacing a symbol (copy → checkmark): "magic" on iOS 18 (the common
/// parts stay in place), simple replace on iOS 17, fade with "Reduce
/// Motion".
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

/// Copy symbol that becomes a checkmark, then comes back.
struct CopySymbol: View {
    var symbol = "doc.on.doc"
    let copied: Bool

    var body: some View {
        Image(systemName: copied ? "checkmark" : symbol)
            .symbolReplaceTransition()
            .animation(.snappy(duration: 0.3), value: copied)
    }
}

/// "Copied" state of a button: true for 1.5 s after each copy. Reset to
/// false by a deadline, not by a view task: a reloaded list row would cancel
/// the task and make the checkmark disappear right away.
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

// MARK: Staggered appearance

/// Staggered appearance (audit cards): each element slides and appears
/// after the previous one; a simple fade with "Reduce Motion".
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

// MARK: One-notch rotation

/// The symbol turns one full turn at each `value` (iOS 18: symbol effect;
/// iOS 17: view rotation); still with "Reduce Motion".
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

    /// Symbol bounce at each change of `value`, except with "Reduce
    /// Motion".
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
