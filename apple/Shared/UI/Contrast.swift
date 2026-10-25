import SwiftUI

// "Increase Contrast" (Accessibility › Display on the Mac, Display & Text
// Size on the iPhone): system colors and materials adapt by themselves,
// not the faint colors the apps draw (field and card borders, hover and
// selection washes, secondary text on the accent, the strength meter's
// track, focus rings). They go through the styles below, which pick a
// stronger color with the setting on. With it off, each one resolves to
// the color used before, to the pixel: nothing is redesigned.

/// `normal`, or `increased` with Increase Contrast, read from the
/// environment where the style is drawn: no view has to watch the setting.
struct ContrastStyle<Normal: ShapeStyle, Increased: ShapeStyle>: ShapeStyle {
    let normal: Normal
    let increased: Increased

    func resolve(in environment: EnvironmentValues) -> AnyShapeStyle {
        environment.colorSchemeContrast == .increased ? AnyShapeStyle(increased) : AnyShapeStyle(normal)
    }
}

extension ContrastStyle where Normal == Color, Increased == Color {
    /// The same color either way (the other branch of a condition).
    init(_ color: Color) {
        self.init(normal: color, increased: color)
    }
}

extension Theme {
    /// Border of a field or a search box: gray at `opacity`, a clear gray
    /// with Increase Contrast.
    static func border(_ opacity: Double) -> ContrastStyle<Color, Color> {
        ContrastStyle(normal: Color.secondary.opacity(opacity), increased: Color.secondary)
    }

    /// Outline of a card drawn without one (iPhone home tiles, generator,
    /// AutoFill's password field): none, a gray line with Increase Contrast.
    static let cardBorder = ContrastStyle(normal: Color.clear, increased: Color.secondary.opacity(0.7))

    /// Hairline around a card (Mac item fields), stronger than the
    /// separator with Increase Contrast.
    static let hairline = ContrastStyle(normal: AnyShapeStyle(.separator.opacity(0.6)), increased: Color.secondary)

    /// Thin outline of an item's icon.
    static let iconBorder = ContrastStyle(normal: AnyShapeStyle(.primary.opacity(0.12)), increased: Color.primary.opacity(0.35))

    /// Focus ring: the accent at `opacity`, opaque with Increase Contrast.
    static func focusRing(_ opacity: Double = 1) -> ContrastStyle<Color, Color> {
        ContrastStyle(normal: Theme.accent.opacity(opacity), increased: Theme.accent)
    }

    /// Hover or active-row wash: the text color at `opacity`, more than
    /// twice as visible with Increase Contrast.
    static func wash(_ opacity: Double) -> ContrastStyle<Color, Color> {
        ContrastStyle(normal: Color.primary.opacity(opacity), increased: Color.primary.opacity(min(opacity * 2.5, 0.2)))
    }

    /// Faint fill behind a tag, a counter or a code (`.quaternary` at
    /// `opacity`), a visible gray with Increase Contrast.
    static func faintFill(_ opacity: Double = 1) -> ContrastStyle<AnyShapeStyle, HierarchicalShapeStyle> {
        ContrastStyle(normal: AnyShapeStyle(.quaternary.opacity(opacity)), increased: .tertiary)
    }

    /// Secondary text or symbol on the accent (selected row): white at
    /// `opacity`, plain white with Increase Contrast.
    static func onAccentSecondary(_ opacity: Double = 0.8) -> ContrastStyle<Color, Color> {
        ContrastStyle(normal: Color.white.opacity(opacity), increased: Color.white)
    }
}
