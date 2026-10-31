#if os(iOS)
import SwiftUI

// iOS 26 glass (Liquid Glass), with a fallback for iOS 17 to 25: every
// call goes through these few functions, which check the version.
//
// Glass is reserved for the controls that float above the content
// (buttons, unlock field, notification); never in the rows of a list,
// where it would make scrolling expensive.

enum LiquidGlass {
    /// Debug builds: `VERROU_LEGACY_UI=1` forces the iOS 17 fallback on
    /// iOS 26, to take screenshots of it (the system bars stay the iOS 26
    /// ones).
    static let forcedFallback: Bool = {
        #if DEBUG
        ProcessInfo.processInfo.environment["VERROU_LEGACY_UI"] == "1"
        #else
        false
        #endif
    }()

    /// iOS 26 glass is available (and not ruled out).
    static var isAvailable: Bool {
        #if compiler(>=6.2)
        if #available(iOS 26, *) { return !forcedFallback }
        #endif
        return false
    }
}

extension View {
    /// Glass background in `shape` on iOS 26; blurred material otherwise.
    @ViewBuilder
    func glassSurface<S: InsettableShape>(_ shape: S, tint: Color? = nil, interactive: Bool = false) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, *), !LiquidGlass.forcedFallback {
            self.glassEffect(Self.glass(tint: tint, interactive: interactive), in: shape)
        } else {
            materialSurface(shape, tint: tint)
        }
        #else
        materialSurface(shape, tint: tint)
        #endif
    }

    #if compiler(>=6.2)
    @available(iOS 26, *)
    private static func glass(tint: Color?, interactive: Bool) -> Glass {
        var glass = Glass.regular
        if let tint { glass = glass.tint(tint) }
        if interactive { glass = glass.interactive() }
        return glass
    }
    #endif

    private func materialSurface<S: InsettableShape>(_ shape: S, tint: Color?) -> some View {
        background {
            ZStack {
                shape.fill(.regularMaterial)
                if let tint { shape.fill(tint.opacity(0.18)) }
            }
        }
        .overlay(shape.strokeBorder(ContrastStyle(normal: Color.white.opacity(0.12), increased: Color.secondary.opacity(0.7)),
                                    lineWidth: 0.5))
    }

    /// Glass button (`prominent`: tinted with the accent) on iOS 26; capsule
    /// button, filled or tinted, otherwise.
    @ViewBuilder
    func glassButton(prominent: Bool = false) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, *), !LiquidGlass.forcedFallback {
            if prominent {
                self.buttonStyle(.glassProminent)
            } else {
                self.buttonStyle(.glass)
            }
        } else {
            fallbackButton(prominent: prominent)
        }
        #else
        fallbackButton(prominent: prominent)
        #endif
    }

    @ViewBuilder
    private func fallbackButton(prominent: Bool) -> some View {
        if prominent {
            self.buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
        } else {
            self.buttonStyle(.bordered).buttonBorderShape(.capsule)
        }
    }
}

/// Groups neighboring glass elements (iOS 26): they blend into each other
/// and share a single render; a plain stack otherwise.
struct GlassGroup<Content: View>: View {
    var spacing: CGFloat = 12
    @ViewBuilder var content: Content

    var body: some View {
        #if compiler(>=6.2)
        if #available(iOS 26, *), !LiquidGlass.forcedFallback {
            GlassEffectContainer(spacing: spacing) { content }
        } else {
            content
        }
        #else
        content
        #endif
    }
}

// MARK: Morphing

extension View {
    /// Glass identity (iOS 26): two views with the same `id` in a
    /// `GlassGroup` morph into each other; `morph` false (Reduce Motion):
    /// the glass simply appears. Nothing before iOS 26.
    @ViewBuilder
    func glassMorphID(_ id: String, in namespace: Namespace.ID, morph: Bool = true) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, *), !LiquidGlass.forcedFallback {
            self.glassEffectID(id, in: namespace)
                .glassEffectTransition(morph ? .matchedGeometry : .materialize)
        } else {
            self
        }
        #else
        self
        #endif
    }
}

// MARK: Navigation

private struct ZoomNamespaceKey: EnvironmentKey {
    static let defaultValue: Namespace.ID? = nil
}

extension EnvironmentValues {
    /// Namespace of a navigation stack's "zoom" transitions (iOS 18+).
    var zoomNamespace: Namespace.ID? {
        get { self[ZoomNamespaceKey.self] }
        set { self[ZoomNamespaceKey.self] = newValue }
    }
}

extension View {
    /// Source of a "zoom" transition to the item page (iOS 18+; nothing before).
    @ViewBuilder
    func zoomSource(id: String, in namespace: Namespace.ID?) -> some View {
        if #available(iOS 18, *), let namespace {
            self.matchedTransitionSource(id: id, in: namespace)
        } else {
            self
        }
    }

    /// The item page opens by zooming from its row (iOS 18+; classic side
    /// slide before).
    @ViewBuilder
    func zoomDestination(id: String, in namespace: Namespace.ID?) -> some View {
        if #available(iOS 18, *), let namespace {
            self.navigationTransition(.zoom(sourceID: id, in: namespace))
        } else {
            self
        }
    }

    /// Navigation bar subtitle (iOS 26; nothing before).
    @ViewBuilder
    func navigationSubtitleIfAvailable(_ text: String) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, *) {
            self.navigationSubtitle(text)
        } else {
            self
        }
        #else
        self
        #endif
    }
}

// MARK: Symbols

extension View {
    /// Symbol that rotates continuously (iOS 18+); still before.
    @ViewBuilder
    func spinning(_ active: Bool) -> some View {
        if #available(iOS 18, *) {
            self.symbolEffect(.rotate, options: .repeating, isActive: active)
        } else {
            self
        }
    }
}

// MARK: Unlocking

/// Master password field, with its arrow: interactive glass on iOS 26,
/// rounded field with an accent border otherwise (as on the Mac).
struct MasterPasswordField: View {
    @Binding var password: String
    let busy: Bool
    var focused: FocusState<Bool>.Binding
    let submit: () -> Void

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 26, style: .continuous)
        HStack(spacing: 8) {
            Image(systemName: "key.fill")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .submitLabel(.go)
                .focused(focused)
                .onSubmit(submit)
                .disabled(busy)
            Button(action: submit) {
                if busy {
                    ProgressView()
                } else {
                    Image(systemName: "arrow.right.circle.fill")
                        .font(.title2)
                        .foregroundStyle(password.isEmpty ? Color.secondary : Theme.accent)
                        .contentTransition(.symbolEffect(.replace))
                }
            }
            .frame(minWidth: 44, minHeight: 44)
            .contentShape(Rectangle())
            .disabled(password.isEmpty)
            .accessibilityLabel("Unlock")
        }
        .padding(.leading, 18)
        .padding(.trailing, 10)
        .frame(minHeight: 52)
        .modifier(PasswordFieldSurface(shape: shape, focused: focused.wrappedValue))
    }
}

private struct PasswordFieldSurface: ViewModifier {
    let shape: RoundedRectangle
    let focused: Bool

    func body(content: Content) -> some View {
        if LiquidGlass.isAvailable {
            content
                .glassSurface(shape, interactive: true)
                .overlay(shape.strokeBorder(focused ? Theme.focusRing(0.7) : ContrastStyle(Color.clear), lineWidth: 1.5))
        } else {
            content
                .background(Color(.secondarySystemGroupedBackground), in: shape)
                .overlay(shape.strokeBorder(focused ? Theme.focusRing() : Theme.border(0.25),
                                            lineWidth: focused ? 1.5 : 0.5))
        }
    }
}

/// Face ID (or Touch ID) unlock button.
struct BiometricUnlockButton: View {
    let title: LocalizedStringKey
    let symbol: String
    let busy: Bool
    /// False under a more likely choice (AutoFill's "Continue as…").
    var prominent = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.body.weight(.semibold))
                .symbolEffect(.pulse, options: .repeating, isActive: busy)
                .frame(maxWidth: .infinity, minHeight: 36)
        }
        .controlSize(.large)
        .glassButton(prominent: prominent)
        .disabled(busy)
    }
}

// MARK: Pictograms

/// White symbol on a tinted rounded square (home, settings).
struct TintedSymbol: View {
    let symbol: String
    let tint: Color
    var size: CGFloat = 30

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.47, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(tint.gradient, in: RoundedRectangle(cornerRadius: size * 0.27, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// Mac-style section header: small spaced capitals.
struct SectionHeader: View {
    let title: Text
    init(_ title: LocalizedStringKey) { self.title = Text(title) }
    // Disfavored, as in Text: a literal goes to the LocalizedStringKey init.
    @_disfavoredOverload init<S: StringProtocol>(_ title: S) { self.title = Text(title) }
    var body: some View {
        title
            .font(.footnote.weight(.semibold))
            .textCase(.uppercase)
            .tracking(0.6)
            .foregroundStyle(.secondary)
    }
}
#endif
