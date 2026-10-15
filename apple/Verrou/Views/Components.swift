import SwiftUI

// MARK: Icône d'élément

struct ItemIcon: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary
    var size: CGFloat = 32

    var body: some View {
        ItemIconContent(summary: summary, image: siteImage, size: size)
    }

    /// L'icône du site, servie par le Vaultwarden du compte (identifiants seulement).
    private var siteImage: PlatformImage? {
        guard summary.category == .login, summary.template == nil, let host = summary.host else { return nil }
        return model.siteIcons.image(for: host)
    }
}

/// Raccourci clavier affiché en pied de liste ou dans l'accès rapide.
struct KeyHint: View {
    let keys: String
    let label: String

    var body: some View {
        HStack(spacing: 5) {
            Text(keys)
                .font(.system(size: 10, weight: .semibold, design: .rounded))
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }
}

/// Des vues côte à côte qui passent à la ligne suivante quand la place
/// manque (pastilles du détail). Chaque vue garde sa largeur idéale, au plus
/// celle du conteneur : un texte trop long est tronqué, jamais coupé lettre
/// par lettre.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8
    var lineSpacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        let width = rows.map(\.width).max() ?? 0
        let height = rows.map(\.height).reduce(0, +) + lineSpacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: proposal.width.map { min($0, width) } ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = bounds.minX
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
