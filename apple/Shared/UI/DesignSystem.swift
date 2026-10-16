import SwiftUI

// Identité visuelle commune au Mac, à l'iPhone et à l'extension de
// remplissage : logo (le cadenas de l'icône et de l'extension de navigateur),
// fond des écrans verrouillés, pastilles, compteurs, ligne d'élément.
// Tout est dessiné (aucune image) : rien de lourd dans l'extension.

// MARK: Jetons

extension Theme {
    /// Dégradé du logo (haut, bas), celui de l'icône de l'app.
    static let brandTop = Color(red: 0.36, green: 0.42, blue: 1.0)
    static let brandBottom = Color(red: 0.20, green: 0.17, blue: 0.62)
    /// Rayon des cartes de l'iPhone (champs de la fiche, générateur).
    static let cardRadius: CGFloat = 16
    /// Vert de l'état « en ligne » (pied de la barre latérale du Mac).
    static let online = Color.green
}

// MARK: Logo

/// Le cadenas de Verrou : anse, corps et trou de serrure, d'après le dessin
/// SVG de l'extension (boîte de 24 × 24).
struct Padlock: View {
    var size: CGFloat = 24
    /// Ouverture de l'anse : 0 fermée, 1 levée et pivotée sur sa branche
    /// droite (animation du déverrouillage de l'iPhone). Au-delà de 1 : léger
    /// dépassement d'un ressort.
    var shackle: CGFloat = 0
    var body: some View {
        Canvas { context, canvas in
            let unit = canvas.width / 24
            // Anse levée puis pivotée autour du pied de sa branche droite.
            var shackleContext = context
            if shackle != 0 {
                let pivot = CGPoint(x: 16.5 * unit, y: 10.5 * unit)
                shackleContext.translateBy(x: 0, y: -2.6 * unit * shackle)
                shackleContext.translateBy(x: pivot.x, y: pivot.y)
                shackleContext.rotate(by: .degrees(22 * Double(max(0, shackle - 0.35)) / 0.65))
                shackleContext.translateBy(x: -pivot.x, y: -pivot.y)
            }
            var arc = Path()
            arc.move(to: CGPoint(x: 7.5 * unit, y: 10.5 * unit))
            arc.addLine(to: CGPoint(x: 7.5 * unit, y: 8 * unit))
            arc.addArc(center: CGPoint(x: 12 * unit, y: 8 * unit), radius: 4.5 * unit,
                       startAngle: .degrees(180), endAngle: .degrees(0), clockwise: false)
            arc.addLine(to: CGPoint(x: 16.5 * unit, y: 10.5 * unit))
            shackleContext.stroke(arc, with: .color(.white),
                                  style: StrokeStyle(lineWidth: 2.2 * unit, lineCap: .round))
            let body = Path(roundedRect: CGRect(x: 4.5 * unit, y: 10 * unit, width: 15 * unit, height: 11 * unit),
                            cornerRadius: 3 * unit, style: .continuous)
            context.fill(body, with: .linearGradient(
                Gradient(colors: [.white, Color(white: 0.9)]),
                startPoint: CGPoint(x: 0, y: 10 * unit), endPoint: CGPoint(x: 0, y: 21 * unit)))
            let hole = Path(ellipseIn: CGRect(x: 10.4 * unit, y: 13 * unit, width: 3.2 * unit, height: 3.2 * unit))
            context.fill(hole, with: .color(Theme.brandBottom.opacity(0.85)))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// Le logo : le cadenas sur un écusson arrondi, comme l'icône de l'app.
struct AppMark: View {
    var size: CGFloat = 64
    /// Halo coloré sous le logo (écrans verrouillés) ; sans, pour les petites tailles.
    var glow = true
    /// Ouverture de l'anse du cadenas (`Padlock.shackle`).
    var shackle: CGFloat = 0

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                .fill(LinearGradient(colors: [Theme.brandTop, Theme.brandBottom],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay(
                    RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                        .strokeBorder(.white.opacity(0.18), lineWidth: max(0.5, size / 120)))
                .shadow(color: glow ? Theme.brandTop.opacity(0.35) : .clear,
                        radius: size * 0.18, y: size * 0.08)
            Padlock(size: size * 0.62, shackle: shackle)
                .offset(y: -size * 0.01)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

// MARK: Fond des écrans verrouillés

/// Fond des écrans verrouillé et de connexion : la couleur de la fenêtre et
/// un halo de la couleur d'accent venu du haut.
struct LockBackground: View {
    var body: some View {
        ZStack {
            #if canImport(AppKit)
            Color(nsColor: .windowBackgroundColor)
            RadialGradient(colors: [Theme.accent.opacity(0.18), .clear], center: .top, startRadius: 10, endRadius: 520)
            #else
            Color(.systemGroupedBackground)
            RadialGradient(colors: [Theme.accent.opacity(0.26), .clear], center: .top, startRadius: 0, endRadius: 560)
            RadialGradient(colors: [Theme.brandBottom.opacity(0.10), .clear], center: .bottomTrailing,
                           startRadius: 0, endRadius: 420)
            #endif
        }
        .ignoresSafeArea()
    }
}

// MARK: Pastilles et compteurs

/// Pastille d'information (type, dossier, partage…) : symbole et texte sur
/// un fond teinté, jamais coupée lettre par lettre.
struct Chip: View {
    let text: String
    let symbol: String
    let tint: Color

    var body: some View {
        Label(text, systemImage: symbol)
            .labelStyle(.titleAndIcon)
            .lineLimit(1)
            .truncationMode(.tail)
            .font(.caption.weight(.medium))
            .foregroundStyle(tint == .secondary ? Color.secondary : tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background((tint == .secondary ? Color.secondary : tint).opacity(0.12), in: Capsule())
    }
}

/// Compteur à pastille de couleur : « ● 3 réutilisés ».
struct CountCapsule: View {
    let text: String
    let tint: Color

    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(tint).frame(width: 7, height: 7)
            Text(text)
                .font(.caption.weight(.medium))
                .monospacedDigit()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(.quaternary.opacity(0.6), in: Capsule())
    }
}

/// Étiquette pleine : niveau de confiance, gravité.
struct Badge: View {
    let text: String
    /// `nil` : fond neutre.
    let tint: Color?

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            // Texte sombre sur le jaune : le blanc n'y serait pas lisible.
            .foregroundStyle(tint == nil ? Color.primary : tint == .yellow ? Color.black : Color.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(tint.map { AnyShapeStyle($0) } ?? AnyShapeStyle(.quaternary), in: Capsule())
    }
}

/// Étiquettes d'un élément (« #dev »), à la ligne quand la place manque.
struct TagsRow: View {
    let tags: [String]

    var body: some View {
        FlowLayout(spacing: 6, lineSpacing: 6) {
            ForEach(tags, id: \.self) { tag in
                Text("#\(tag)")
                    .font(.caption.weight(.medium))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(.quaternary.opacity(0.7), in: Capsule())
            }
        }
    }
}

// MARK: Mise en page

/// Des vues côte à côte qui passent à la ligne suivante quand la place
/// manque (pastilles du détail). Chaque vue garde sa largeur idéale, au plus
/// celle du conteneur : un texte trop long est tronqué, jamais coupé lettre
/// par lettre.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8
    var lineSpacing: CGFloat = 6
    /// Lignes centrées (en-tête de l'iPhone) plutôt qu'alignées à gauche.
    var centered = false

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        let width = rows.map(\.width).max() ?? 0
        let height = rows.map(\.height).reduce(0, +) + lineSpacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: proposal.width.map { min($0, width) } ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = centered ? bounds.minX + (bounds.width - row.width) / 2 : bounds.minX
            for (index, size) in zip(row.indices, row.sizes) {
                subviews[index].place(at: CGPoint(x: x, y: y + (row.height - size.height) / 2),
                                      proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + lineSpacing
        }
    }

    private struct Row {
        var indices: [Int] = []
        var sizes: [CGSize] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width maxWidth: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = []
        var row = Row()
        for index in subviews.indices {
            let ideal = subviews[index].sizeThatFits(.unspecified)
            let width = min(ideal.width, maxWidth)
            let size = width < ideal.width
                ? subviews[index].sizeThatFits(ProposedViewSize(width: width, height: nil))
                : ideal
            let needed = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            if !row.indices.isEmpty && needed > maxWidth {
                rows.append(row)
                row = Row()
            }
            row.width = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            row.height = max(row.height, size.height)
            row.indices.append(index)
            row.sizes.append(size)
        }
        if !row.indices.isEmpty { rows.append(row) }
        return rows
    }
}

// MARK: Ligne d'élément

/// Titre (caractères trouvés surlignés) avec favori et partage, sous-titre,
/// puis les indicateurs : la ligne des listes du Mac, de l'iPhone et de
/// l'extension. Pas de géométrie ni d'ombre : la ligne reste bon marché à
/// construire pendant le défilement.
struct ItemRowContent<Icon: View>: View {
    let summary: ItemSummary
    let highlights: [UInt32]
    /// Sur fond d'accent (ligne sélectionnée du Mac) : texte blanc.
    var selected = false
    var spacing: CGFloat = 11
    var subtitleFont: Font = .callout
    /// Indicateur « protégé » (iPhone, extension).
    var showsProtection = false
    /// Vue des passkeys : la ligne secondaire montre le site et
    /// l'utilisateur de la passkey au lieu du sous-titre.
    var showsPasskey = false
    @ViewBuilder let icon: Icon

    var body: some View {
        HStack(spacing: spacing) {
            icon
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    HighlightedText(text: summary.title, highlights: highlights,
                                    tint: selected ? nil : Theme.accent)
                        .lineLimit(1)
                    if summary.favorite {
                        Image(systemName: "star.fill").font(.system(size: 9)).foregroundStyle(.yellow)
                            .accessibilityLabel("Favori")
                    }
                    if let sharing = summary.sharing {
                        Image(systemName: "person.2.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(selected ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.indigo))
                            .help(sharing.label)
                            .accessibilityLabel("Partagé")
                    }
                }
                if showsPasskey, let line = summary.passkeyLine {
                    Label {
                        Text(line)
                    } icon: {
                        Image(systemName: "person.badge.key.fill")
                    }
                    .labelStyle(CompactLabelStyle())
                    .font(subtitleFont)
                    .foregroundStyle(selected ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.secondary))
                    .lineLimit(1)
                    .accessibilityLabel("Passkey \(line)")
                } else {
                    Text(summary.subtitle)
                        .font(subtitleFont)
                        .foregroundStyle(selected ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.secondary))
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
            if summary.pendingSync {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .orange)
                    .help("En attente de synchronisation")
                    .accessibilityLabel("En attente de synchronisation")
            }
            if showsProtection, summary.reprompt {
                Image(systemName: "lock.shield")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .orange)
                    .accessibilityLabel("Protégé")
            }
            if summary.passkeyRpId != nil, !showsPasskey {
                Image(systemName: "person.badge.key")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .purple)
                    .help("Passkey")
                    .accessibilityLabel("Passkey")
            }
            if summary.hasTotp {
                Image(systemName: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .teal)
                    .help("Code à usage unique")
                    .accessibilityLabel("Code à usage unique")
            }
        }
        .foregroundStyle(selected ? Color.white : Color.primary)
    }
}

/// Icône et texte serrés, alignés sur la ligne de base.
struct CompactLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon.imageScale(.small)
            configuration.title
        }
    }
}
