import AppIntents
import SwiftUI
import WidgetKit

/// "Quick actions": Search, Generator and Scan a QR code, each a
/// `verrou://` link into the app. Nothing of the vault is shown: the
/// widget never changes, a single entry is enough.
struct QuickActionsWidget: Widget {
    static let kind = "app.verrou.ios.quick-actions"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: Self.kind, provider: QuickActionsProvider()) { _ in
            QuickActionsView()
                .containerBackground(for: .widget) { Color(.systemBackground) }
        }
        .configurationDisplayName("Quick actions")
        .description("Search your vault, generate a password or scan a two-factor QR code.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct QuickActionsProvider: TimelineProvider {
    struct Entry: TimelineEntry {
        let date: Date
    }

    func placeholder(in context: Context) -> Entry { Entry(date: Date()) }

    func getSnapshot(in context: Context, completion: @escaping (Entry) -> Void) {
        completion(Entry(date: Date()))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<Entry>) -> Void) {
        completion(Timeline(entries: [Entry(date: Date())], policy: .never))
    }
}

private struct QuickAction: Identifiable {
    let id: String
    let title: LocalizedStringKey
    let symbol: String
    let link: VerrouLink

    static var all: [QuickAction] {
        [
            QuickAction(id: "search", title: "Search", symbol: "magnifyingglass", link: .search(nil)),
            QuickAction(id: "generator", title: "Generator", symbol: "wand.and.stars", link: .generator),
            QuickAction(id: "scan", title: "Scan a QR code", symbol: "qrcode.viewfinder", link: .scanCode),
        ]
    }
}

struct QuickActionsView: View {
    @Environment(\.widgetFamily) private var family

    var body: some View {
        if family == .systemMedium {
            HStack(spacing: 8) {
                ForEach(QuickAction.all) { action in
                    tile(action, vertical: true)
                }
            }
        } else {
            VStack(spacing: 8) {
                ForEach(QuickAction.all) { action in
                    tile(action, vertical: false)
                }
            }
        }
    }

    @ViewBuilder
    private func tile(_ action: QuickAction, vertical: Bool) -> some View {
        if let url = action.link.url {
            Link(destination: url) {
                Group {
                    if vertical {
                        VStack(spacing: 8) {
                            Image(systemName: action.symbol)
                                .font(.title2.weight(.semibold))
                            Text(action.title)
                                .font(.caption.weight(.medium))
                                .multilineTextAlignment(.center)
                                .lineLimit(2)
                                .minimumScaleFactor(0.8)
                        }
                    } else {
                        HStack(spacing: 8) {
                            Image(systemName: action.symbol)
                                .font(.body.weight(.semibold))
                                .frame(width: 22)
                            Text(action.title)
                                .font(.caption.weight(.medium))
                                .lineLimit(1)
                                .minimumScaleFactor(0.7)
                            Spacer(minLength: 0)
                        }
                        .padding(.horizontal, 8)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .foregroundStyle(Color.accentColor)
                .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            }
        }
    }
}

/// Control Center (iOS 18): "Search in Verrou".
@available(iOS 18.0, *)
struct SearchControl: ControlWidget {
    static let kind = "app.verrou.ios.search-control"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind) {
            ControlWidgetButton(action: SearchVaultIntent()) {
                Label("Search in Verrou", systemImage: "magnifyingglass")
            }
        }
        .displayName("Search in Verrou")
        .description("Opens Verrou on the search.")
    }
}

#Preview("Small", as: .systemSmall) {
    QuickActionsWidget()
} timeline: {
    QuickActionsProvider.Entry(date: .now)
}

#Preview("Medium", as: .systemMedium) {
    QuickActionsWidget()
} timeline: {
    QuickActionsProvider.Entry(date: .now)
}
