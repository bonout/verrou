#if os(iOS)
import SwiftUI

// Verre (Liquid Glass) d'iOS 26, avec un repli pour iOS 17 à 25 : chaque
// appel passe par ces quelques fonctions, qui vérifient la version.
//
// Le verre est réservé aux commandes qui flottent au-dessus du contenu
// (boutons, champ de déverrouillage, notification) ; jamais dans les lignes
// d'une liste, où il coûterait cher au défilement.

enum LiquidGlass {
    /// Builds Debug : `VERROU_LEGACY_UI=1` force le repli d'iOS 17 sur
    /// iOS 26, pour en faire des captures (les barres du système restent
    /// celles d'iOS 26).
    static let forcedFallback: Bool = {
        #if DEBUG
        ProcessInfo.processInfo.environment["VERROU_LEGACY_UI"] == "1"
        #else
        false
        #endif
    }()

    /// Le verre d'iOS 26 est disponible (et pas écarté).
    static var isAvailable: Bool {
        #if compiler(>=6.2)
        if #available(iOS 26, *) { return !forcedFallback }
        #endif
        return false
    }
}

extension View {
    /// Fond de verre dans `shape` sur iOS 26 ; matériau flou sinon.
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
        .overlay(shape.strokeBorder(.white.opacity(0.12), lineWidth: 0.5))
    }

    /// Bouton de verre (`prominent` : teinté de l'accent) sur iOS 26 ; bouton
    /// en capsule, plein ou teinté, sinon.
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

/// Regroupe des éléments de verre voisins (iOS 26) : ils se fondent l'un
/// dans l'autre et partagent un seul rendu ; une simple pile sinon.
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

// MARK: Navigation

private struct ZoomNamespaceKey: EnvironmentKey {
    static let defaultValue: Namespace.ID? = nil
}

extension EnvironmentValues {
    /// Espace des transitions « zoom » d'une pile de navigation (iOS 18+).
    var zoomNamespace: Namespace.ID? {
        get { self[ZoomNamespaceKey.self] }
        set { self[ZoomNamespaceKey.self] = newValue }
    }
}

extension View {
    /// Source d'une transition « zoom » vers la fiche (iOS 18+ ; rien avant).
    @ViewBuilder
    func zoomSource(id: String, in namespace: Namespace.ID?) -> some View {
        if #available(iOS 18, *), let namespace {
            self.matchedTransitionSource(id: id, in: namespace)
        } else {
            self
        }
    }

    /// La fiche s'ouvre en zoomant depuis sa ligne (iOS 18+ ; glissement
    /// latéral classique avant).
    @ViewBuilder
    func zoomDestination(id: String, in namespace: Namespace.ID?) -> some View {
        if #available(iOS 18, *), let namespace {
            self.navigationTransition(.zoom(sourceID: id, in: namespace))
        } else {
            self
        }
    }

    /// Sous-titre de la barre de navigation (iOS 26 ; rien avant).
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

// MARK: Symboles

extension View {
    /// Symbole qui tourne en continu (iOS 18+) ; immobile avant.
    @ViewBuilder
    func spinning(_ active: Bool) -> some View {
        if #available(iOS 18, *) {
            self.symbolEffect(.rotate, options: .repeating, isActive: active)
        } else {
            self
        }
    }
}

// MARK: Déverrouillage

/// Champ du mot de passe principal, avec sa flèche : verre interactif sur
/// iOS 26, champ arrondi bordé d'accent sinon (comme sur le Mac).
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
            SecureField("Mot de passe principal", text: $password)
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
            .disabled(password.isEmpty)
            .accessibilityLabel("Déverrouiller")
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
                .overlay(shape.strokeBorder(focused ? Theme.accent.opacity(0.7) : .clear, lineWidth: 1.5))
        } else {
            content
                .background(Color(.secondarySystemGroupedBackground), in: shape)
                .overlay(shape.strokeBorder(focused ? Theme.accent : Color.secondary.opacity(0.25),
                                            lineWidth: focused ? 1.5 : 0.5))
        }
    }
}

/// Bouton de déverrouillage par Face ID (ou Touch ID).
struct BiometricUnlockButton: View {
    let title: String
    let symbol: String
    let busy: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.body.weight(.semibold))
                .symbolEffect(.pulse, options: .repeating, isActive: busy)
                .frame(maxWidth: .infinity, minHeight: 36)
        }
        .controlSize(.large)
        .glassButton(prominent: true)
        .disabled(busy)
    }
}

// MARK: Pictogrammes

/// Symbole blanc sur un carré arrondi teinté (accueil, réglages).
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

/// En-tête de section à la manière du Mac : petites capitales espacées.
struct SectionHeader: View {
    let title: String
    init(_ title: String) { self.title = title }

    var body: some View {
        Text(title)
            .font(.footnote.weight(.semibold))
            .textCase(.uppercase)
            .tracking(0.6)
            .foregroundStyle(.secondary)
    }
}
#endif
