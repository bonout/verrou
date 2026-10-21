import SwiftUI

extension View {
    /// Stable marker of a key element (title of a pane, footer of the
    /// sidebar…): accessibility identifier, and in Debug builds an invisible
    /// AppKit view of the same size, which the layout audit (`LayoutAudit`)
    /// finds in the view hierarchy without depending on SwiftUI's
    /// accessibility tree (built only for an accessibility client).
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
/// Transparent AppKit view placed behind the marked element.
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

/// The marker itself: no clicks, no accessibility.
final class LayoutMarkNSView: NSView {
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    override func isAccessibilityElement() -> Bool { false }
}
#endif
