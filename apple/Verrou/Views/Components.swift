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
