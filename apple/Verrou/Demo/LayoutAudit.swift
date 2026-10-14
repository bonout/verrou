#if DEBUG
import AppKit

/// Audit de mise en page d'une fenêtre, sans rien capturer à l'écran : des
/// mesures sur la hiérarchie des vues et l'arbre d'accessibilité. Sert au
/// parcours de bout en bout (fenêtre réelle) comme à la revue hors écran
/// (`ReviewDriver`), et vaut aussi quand la fenêtre est sur un autre Space.
///
/// Règles :
/// - les vues partagées (`NSSplitView`) et les vues SwiftUI hébergées tiennent
///   dans la vue de contenu de leur fenêtre (un texte à hauteur imposée hors
///   d'une vue défilante les agrandit, centrées puis coupées en haut et en bas) ;
/// - aucune colonne de la vue partagée n'est vide ou écrasée ;
/// - les éléments repères (`layoutMark`) sont présents, entiers et dans la
///   zone visible de la fenêtre (`contentLayoutRect`, sous la barre d'outils) ;
/// - la fenêtre garde la taille qu'on lui a donnée (un contenu trop exigeant
///   l'agrandit hors écran) ; une feuille n'est pas plus haute que sa fenêtre.
@MainActor
enum LayoutAudit {
    struct Expectation {
        /// Identifiants d'accessibilité qui doivent être visibles en entier.
        var identifiers: [String] = []
        /// Colonnes attendues dans la vue partagée principale (0 : pas de règle).
        var columns = 0
        /// Feuille : hauteur au plus (la zone de contenu de la fenêtre parente).
        var maxHeight: CGFloat?
        /// Taille que la fenêtre doit garder (celle qu'on lui a donnée) : un
        /// contenu qui exige plus la fait grandir, ou dépasse de l'écran.
        var size: NSSize?
    }

    /// Les problèmes trouvés, en français ; vide : la mise en page tient.
    static func problems(in window: NSWindow, _ expectation: Expectation) -> [String] {
        guard let content = window.contentView else { return ["fenêtre sans vue de contenu"] }
        content.layoutSubtreeIfNeeded()
        var problems: [String] = []
        let bounds = content.bounds

        // 1. Débordements : seules comptent les vues hors d'une vue défilante
        // (les lignes d'une liste défilent légitimement hors de la fenêtre).
        for view in containers(in: content) {
            let frame = view.convert(view.bounds, to: content)
            if frame.height > bounds.height + 0.5 || frame.width > bounds.width + 0.5
                || frame.minY < bounds.minY - 0.5 || frame.maxY > bounds.maxY + 0.5
                || frame.minX < bounds.minX - 0.5 || frame.maxX > bounds.maxX + 0.5 {
                problems.append("\(kind(of: view)) de \(Int(frame.width))×\(Int(frame.height)) pt "
                    + "déborde de la fenêtre (\(Int(bounds.width))×\(Int(bounds.height)) pt)")
            }
        }

        // 2. Colonnes : celles de la vue partagée la plus haute dans la hiérarchie.
        if expectation.columns > 0 {
            if let split = splitViews(in: content).first {
                let visible = split.arrangedSubviews.filter { !$0.isHidden && !split.isSubviewCollapsed($0) }
                if visible.count < expectation.columns {
                    problems.append("\(visible.count) colonne(s) visible(s) sur \(expectation.columns) attendues")
                }
                for (index, column) in visible.enumerated() where column.frame.width < 40 || column.frame.height < 40 {
                    problems.append("colonne \(index + 1) vide ou écrasée (\(Int(column.frame.width))×\(Int(column.frame.height)) pt)")
                }
            } else {
                problems.append("aucune vue partagée : les \(expectation.columns) colonnes manquent")
            }
        }

        // 3. Éléments repères (`layoutMark`), en coordonnées de la fenêtre :
        // présents, entiers (rien ne les rogne) et sous la barre d'outils.
        if !expectation.identifiers.isEmpty {
            let visible = window.contentLayoutRect.insetBy(dx: -1, dy: -1)
            let marks = markedViews(in: content)
            for identifier in expectation.identifiers {
                guard let view = marks[identifier] else {
                    problems.append("« \(identifier) » absent de la fenêtre")
                    continue
                }
                let frame = view.convert(view.bounds, to: nil)
                // La partie que rien ne rogne : ni une vue défilante, ni la fenêtre.
                let shown = view.convert(view.visibleRect, to: nil).intersection(visible)
                if frame.width < 1 || frame.height < 1 {
                    problems.append("« \(identifier) » de taille nulle")
                } else if !visible.contains(frame) || shown.height < frame.height - 1 || shown.width < frame.width - 1 {
                    let top = Int(visible.maxY - frame.maxY), bottom = Int(frame.minY - visible.minY)
                    problems.append("« \(identifier) » coupé ou hors de la zone visible "
                        + "(\(top) pt sous le haut, \(bottom) pt au-dessus du bas, "
                        + "\(Int(max(shown.height, 0))) pt visibles sur \(Int(frame.height)))")
                }
            }
        }

        // 4. Fenêtre agrandie par son contenu, ou contenu qui exige plus que
        // la fenêtre (taille minimale imposée par SwiftUI).
        if let size = expectation.size {
            let frame = window.frame.size
            if abs(frame.width - size.width) > 0.5 || abs(frame.height - size.height) > 0.5 {
                problems.append("la fenêtre a pris \(Int(frame.width))×\(Int(frame.height)) pt au lieu de "
                    + "\(Int(size.width))×\(Int(size.height)) : son contenu exige plus de place")
            }
            let minimum = window.frameRect(forContentRect: NSRect(origin: .zero, size: window.contentMinSize)).size
            if minimum.height > size.height + 0.5 || minimum.width > size.width + 0.5 {
                problems.append("le contenu exige au moins \(Int(minimum.width))×\(Int(minimum.height)) pt, "
                    + "plus que la fenêtre (\(Int(size.width))×\(Int(size.height)))")
            }
        }

        // 5. Feuille plus haute que la fenêtre qui la porte.
        if let limit = expectation.maxHeight, window.frame.height > limit + 0.5 {
            problems.append("feuille de \(Int(window.frame.height)) pt, plus haute que la fenêtre (\(Int(limit)) pt)")
        }
        return problems
    }

    /// Vues partagées et vues SwiftUI de premier niveau, hors des vues défilantes.
    private static func containers(in root: NSView) -> [NSView] {
        var found: [NSView] = []
        func visit(_ view: NSView) {
            if view.isHidden || view is NSClipView { return }
            // Les vues SwiftUI de premier niveau (fenêtre, colonnes), pas les
            // hébergements internes des contrôles (onglets, cellules).
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

    /// Les repères posés par `layoutMark`, visibles (ni masqués, ni
    /// transparents) : le premier rencontré l'emporte.
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
