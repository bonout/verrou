#if DEBUG
import AppKit

/// Layout audit of a window, without capturing anything on screen:
/// measurements on the view hierarchy and the accessibility tree. Used by
/// the end-to-end walk (real window) as well as the offscreen review
/// (`ReviewDriver`), and also holds when the window is on another Space.
///
/// Rules:
/// - split views (`NSSplitView`) and hosted SwiftUI views fit in their
///   window's content view (a text with a forced height outside a scroll
///   view enlarges them, centered then cut at the top and bottom);
/// - no column of the split view is empty or squashed;
/// - the marker elements (`layoutMark`) are present, whole and in the
///   visible area of the window (`contentLayoutRect`, under the toolbar);
/// - the window keeps the size it was given (too demanding a content
///   enlarges it offscreen); a sheet is not taller than its window.
@MainActor
enum LayoutAudit {
    struct Expectation {
        /// Accessibility identifiers that must be fully visible.
        var identifiers: [String] = []
        /// Columns expected in the main split view (0: no rule).
        var columns = 0
        /// Sheet: maximum height (the content area of the parent window).
        var maxHeight: CGFloat?
        /// Size the window must keep (the one it was given): a content that
        /// demands more makes it grow, or go past the screen.
        var size: NSSize?
    }

    /// The problems found; empty: the layout holds.
    static func problems(in window: NSWindow, _ expectation: Expectation) -> [String] {
        guard let content = window.contentView else { return ["window without a content view"] }
        content.layoutSubtreeIfNeeded()
        var problems: [String] = []
        let bounds = content.bounds

        // 1. Overflows: only views outside a scroll view count (the rows of a
        // list legitimately scroll out of the window).
        for view in containers(in: content) {
            let frame = view.convert(view.bounds, to: content)
            if frame.height > bounds.height + 0.5 || frame.width > bounds.width + 0.5
                || frame.minY < bounds.minY - 0.5 || frame.maxY > bounds.maxY + 0.5
                || frame.minX < bounds.minX - 0.5 || frame.maxX > bounds.maxX + 0.5 {
                problems.append("\(kind(of: view)) of \(Int(frame.width))×\(Int(frame.height)) pt "
                    + "overflows the window (\(Int(bounds.width))×\(Int(bounds.height)) pt)")
            }
        }

        // 2. Columns: those of the highest split view in the hierarchy.
        if expectation.columns > 0 {
            if let split = splitViews(in: content).first {
                let visible = split.arrangedSubviews.filter { !$0.isHidden && !split.isSubviewCollapsed($0) }
                if visible.count < expectation.columns {
                    problems.append("\(visible.count) visible column(s) out of \(expectation.columns) expected")
                }
                for (index, column) in visible.enumerated() where column.frame.width < 40 || column.frame.height < 40 {
                    problems.append("column \(index + 1) empty or squashed (\(Int(column.frame.width))×\(Int(column.frame.height)) pt)")
                }
            } else {
                problems.append("no split view: the \(expectation.columns) columns are missing")
            }
        }

        // 3. Marker elements (`layoutMark`), in window coordinates: present,
        // whole (nothing clips them) and under the toolbar.
        if !expectation.identifiers.isEmpty {
            let visible = window.contentLayoutRect.insetBy(dx: -1, dy: -1)
            let marks = markedViews(in: content)
            for identifier in expectation.identifiers {
                guard let view = marks[identifier] else {
                    problems.append("\"\(identifier)\" missing from the window")
                    continue
                }
                let frame = view.convert(view.bounds, to: nil)
                // The part nothing clips: neither a scroll view nor the window.
                let shown = view.convert(view.visibleRect, to: nil).intersection(visible)
                if frame.width < 1 || frame.height < 1 {
                    problems.append("\"\(identifier)\" of zero size")
                } else if !visible.contains(frame) || shown.height < frame.height - 1 || shown.width < frame.width - 1 {
                    let top = Int(visible.maxY - frame.maxY), bottom = Int(frame.minY - visible.minY)
                    problems.append("\"\(identifier)\" cut or out of the visible area "
                        + "(\(top) pt below the top, \(bottom) pt above the bottom, "
                        + "\(Int(max(shown.height, 0))) pt visible out of \(Int(frame.height)))")
                }
            }
        }

        // 4. Window enlarged by its content, or content that demands more than
        // the window (minimum size imposed by SwiftUI).
        if let size = expectation.size {
            let frame = window.frame.size
            if abs(frame.width - size.width) > 0.5 || abs(frame.height - size.height) > 0.5 {
                problems.append("the window took \(Int(frame.width))×\(Int(frame.height)) pt instead of "
                    + "\(Int(size.width))×\(Int(size.height)): its content demands more room")
            }
            let minimum = window.frameRect(forContentRect: NSRect(origin: .zero, size: window.contentMinSize)).size
            if minimum.height > size.height + 0.5 || minimum.width > size.width + 0.5 {
                problems.append("the content demands at least \(Int(minimum.width))×\(Int(minimum.height)) pt, "
                    + "more than the window (\(Int(size.width))×\(Int(size.height)))")
            }
        }

        // 5. Sheet taller than the window that carries it.
        if let limit = expectation.maxHeight, window.frame.height > limit + 0.5 {
            problems.append("sheet of \(Int(window.frame.height)) pt, taller than the window (\(Int(limit)) pt)")
        }
        return problems
    }

    /// Split views and top-level SwiftUI views, outside scroll views.
    private static func containers(in root: NSView) -> [NSView] {
        var found: [NSView] = []
        func visit(_ view: NSView) {
            if view.isHidden || view is NSClipView { return }
            // The top-level SwiftUI views (window, columns), not the internal
            // hostings of controls (tabs, cells).
            if view is NSSplitView || kind(of: view) == "NSHostingView" { found.append(view) }
            view.subviews.forEach(visit)
        }
        root.subviews.forEach(visit)
        return found
    }

    private static func splitViews(in root: NSView) -> [NSSplitView] {
        var found: [NSSplitView] = []
        func visit(_ view: NSView) {
            if let split = view as? NSSplitView, !split.isHidden {
                found.append(split)
                return
            }
            view.subviews.forEach(visit)
        }
        visit(root)
        return found
    }

    private static func kind(of view: NSView) -> String {
        let name = String(describing: type(of: view))
        return name.split(separator: "<").first.map(String.init) ?? name
    }

    /// The markers placed by `layoutMark`, visible (neither hidden nor
    /// transparent): the first one met wins.
    static func markedViews(in root: NSView) -> [String: NSView] {
        var found: [String: NSView] = [:]
        func visit(_ view: NSView) {
            if view.isHidden || view.alphaValue < 0.01 { return }
            if let identifier = view.identifier?.rawValue, view is LayoutMarkNSView,
               found[identifier] == nil {
                found[identifier] = view
            }
            view.subviews.forEach(visit)
        }
        visit(root)
        return found
    }
}
#endif
