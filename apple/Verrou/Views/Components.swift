import SwiftUI

extension Theme {
    static let selection = Color(light: Theme.accent, dark: Color(red: 0.31, green: 0.35, blue: 0.92))
}

// MARK: Item icon

struct ItemIcon: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary
    var size: CGFloat = 32

    var body: some View {
        ItemIconContent(summary: summary, image: siteImage, size: size)
    }

    /// The site's icon, served by the account's Vaultwarden (logins only).
    private var siteImage: PlatformImage? {
        guard summary.category == .login, summary.template == nil, let host = summary.host else { return nil }
        return model.siteIcons.image(for: host)
    }
}

/// Keyboard shortcut shown at the bottom of the list or in quick access.
struct KeyHint: View {
    let keys: String
    let label: LocalizedStringKey

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
