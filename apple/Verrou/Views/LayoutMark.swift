import SwiftUI

extension View {
    /// Repère stable d'un élément clé (titre d'un volet, pied de la barre
    /// latérale…) : identifiant d'accessibilité, et dans les builds Debug une
    /// vue AppKit invisible de la même taille, que l'audit de mise en page
    /// (`LayoutAudit`) retrouve dans la hiérarchie des vues sans dépendre de
    /// l'arbre d'accessibilité de SwiftUI (construit seulement pour un client
    /// d'accessibilité).
    func layoutMark(_ identifier: String) -> some View {
        #if DEBUG
        accessibilityIdentifier(identifier)
            .background(LayoutMarkView(identifier: identifier))
        #else
        accessibilityIdentifier(identifier)
        #endif
    }
}

#if DEBUG
/// Vue AppKit transparente posée derrière l'élément repéré.
private struct LayoutMarkView: NSViewRepresentable {
    let identifier: String

    func makeNSView(context: Context) -> NSView {
        let view = LayoutMarkNSView()
        view.identifier = NSUserInterfaceItemIdentifier(identifier)
        return view
    }

    func updateNSView(_ view: NSView, context: Context) {
        view.identifier = NSUserInterfaceItemIdentifier(identifier)
    }
}

/// Le repère lui-même : ni clics, ni accessibilité.
final class LayoutMarkNSView: NSView {
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    override func isAccessibilityElement() -> Bool { false }
}
#endif
