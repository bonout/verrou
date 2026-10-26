import AppIntents
import SwiftUI
import WidgetKit

/// Which pinned code the widget shows (edited by long-pressing it).
struct SelectPinnedCodeIntent: WidgetConfigurationIntent {
    static let title: LocalizedStringResource = "One-time code"
    static let description = IntentDescription("Shows a one-time code pinned in Verrou.")

    @Parameter(title: "Code")
    var code: PinnedCodeEntity?

    init() {}
}

/// A moment of the widget: a code and its window, or why there is none.
struct CodeEntry: TimelineEntry {
    enum Content {
        case code(id: String, title: String, host: String?, code: PinnedCode.Code)
        /// Nothing pinned, or the chosen item was unpinned.
        case nothingPinned
        /// The keychain can't be read yet (restart, before the first
        /// unlock).
        case unavailable
        /// End of the timeline: shown only if WidgetKit is late reloading,
        /// rather than a code past its window.
        case refreshing
    }

    let date: Date
    let content: Content
}

struct CodeProvider: AppIntentTimelineProvider {
    /// Codes computed in advance: two hours at most, about twelve reloads
    /// a day, well within WidgetKit's budget.
    static let horizon: TimeInterval = 2 * 60 * 60
    static let maxEntries = 240

    func placeholder(in context: Context) -> CodeEntry {
        CodeEntry(date: Date(), content: .code(id: "", title: "Verrou", host: nil, code: Self.sampleCode(at: Date())))
    }

    func snapshot(for configuration: SelectPinnedCodeIntent, in context: Context) async -> CodeEntry {
        // The widget gallery: a sample, not the user's codes.
        if context.isPreview { return placeholder(in: context) }
        return Self.entries(for: configuration, from: Date(), limit: 1).first ?? placeholder(in: context)
    }

    func timeline(for configuration: SelectPinnedCodeIntent, in context: Context) async -> Timeline<CodeEntry> {
        let now = Date()
        let entries = Self.entries(for: configuration, from: now, limit: Self.maxEntries)
        switch entries.first?.content {
        case .unavailable:
            // Readable again after the first unlock.
            return Timeline(entries: entries, policy: .after(now.addingTimeInterval(15 * 60)))
        case .nothingPinned, .none:
            // The app reloads the widgets when a code is pinned.
            return Timeline(entries: entries, policy: .never)
        default:
            return Timeline(entries: entries, policy: .atEnd)
        }
    }

    /// One entry per code window, from now until the horizon, then
    /// `refreshing`.
    static func entries(for configuration: SelectPinnedCodeIntent, from now: Date, limit: Int) -> [CodeEntry] {
        guard case .codes(let codes) = PinnedCodes.read() else {
            return [CodeEntry(date: now, content: .unavailable)]
        }
        let chosen = configuration.code.map { entity in codes.first { ItemID.same($0.id, entity.id) } } ?? codes.first
        guard let pinned = chosen else { return [CodeEntry(date: now, content: .nothingPinned)] }
        var entries: [CodeEntry] = []
        var moment = now
        while entries.count < limit, moment < now.addingTimeInterval(horizon) {
            let code = pinned.code(at: moment)
            entries.append(CodeEntry(date: entries.isEmpty ? now : code.start,
                                     content: .code(id: pinned.id, title: pinned.title, host: pinned.host, code: code)))
            moment = code.end
        }
        if limit > 1 { entries.append(CodeEntry(date: moment, content: .refreshing)) }
        return entries
    }

    /// The gallery's sample (a fixed seed, not a real account).
    static func sampleCode(at date: Date) -> PinnedCode.Code {
        PinnedCode(id: "", title: "Verrou", host: nil, secret: Data("verrou-widget-sample".utf8), algorithm: .sha1,
                   digits: 6, period: 30).code(at: date)
    }
}

/// "One-time code": a pinned code and its countdown, on the home screen,
/// the lock screen and in StandBy. Tapping it opens the item in Verrou.
struct CodeWidget: Widget {
    static let kind = "app.verrou.ios.code"

    var body: some WidgetConfiguration {
        AppIntentConfiguration(kind: Self.kind, intent: SelectPinnedCodeIntent.self, provider: CodeProvider()) { entry in
            CodeWidgetView(entry: entry)
        }
        .configurationDisplayName("One-time code")
        .description("A code you pinned in Verrou, without opening the vault.")
        .supportedFamilies([.systemSmall, .accessoryRectangular, .accessoryCircular, .accessoryInline])
    }
}

struct CodeWidgetView: View {
    let entry: CodeEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        content
            .widgetURL(link?.url)
            .containerBackground(for: .widget) { background }
    }

    private var link: VerrouLink? {
        if case .code(let id, _, _, _) = entry.content, !id.isEmpty { return .item(id) }
        return nil
    }

    @ViewBuilder
    private var background: some View {
        if family == .systemSmall {
            Color(.systemBackground)
        } else {
            Color.clear
        }
    }

    @ViewBuilder
    private var content: some View {
        switch (entry.content, family) {
        case (.code(_, let title, _, let code), .accessoryCircular):
            CircularCode(title: title, code: code)
        case (.code(_, let title, _, let code), .accessoryRectangular):
            RectangularCode(title: title, code: code)
        case (.code(_, let title, _, let code), .accessoryInline):
            Text(verbatim: "\(title) \(code.grouped)")
                .privacySensitive()
        case (.code(_, let title, let host, let code), _):
            SmallCode(title: title, host: host, code: code)
        case (_, .accessoryInline):
            Text(message.title)
        case (_, .accessoryCircular):
            Image(systemName: symbol)
                .font(.title2)
                .widgetAccentable()
                .accessibilityLabel(Text(message.title))
        default:
            WidgetMessage(symbol: symbol, title: message.title, detail: message.detail, compact: family != .systemSmall)
        }
    }

    private var symbol: String {
        switch entry.content {
        case .unavailable: "lock"
        case .refreshing: "arrow.clockwise"
        default: "pin"
        }
    }

    private var message: (title: LocalizedStringKey, detail: LocalizedStringKey) {
        switch entry.content {
        case .unavailable:
            ("Unlock your iPhone", "Your pinned codes show after the first unlock.")
        case .refreshing:
            ("Updating…", "Open Verrou if the code doesn't show.")
        default:
            ("Pin a code in Verrou", "On an item's page: Show in widgets and on Apple Watch.")
        }
    }
}

/// Home screen and StandBy: title, site, code and countdown.
private struct SmallCode: View {
    let title: String
    let host: String?
    let code: PinnedCode.Code

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: "clock.badge.checkmark")
                    .foregroundStyle(Color.accentColor)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.headline)
                    .lineLimit(1)
            }
            if let host {
                Text(host)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            Text(code.grouped)
                .font(.system(size: 30, weight: .semibold, design: .monospaced))
                .minimumScaleFactor(0.5)
                .lineLimit(1)
                .privacySensitive()
                .accessibilityLabel(Text("Code \(code.value)"))
            HStack(spacing: 6) {
                ProgressView(timerInterval: code.start...code.end, countsDown: true) {
                    EmptyView()
                } currentValueLabel: {
                    EmptyView()
                }
                .progressViewStyle(.circular)
                .tint(Color.accentColor)
                .frame(width: 16, height: 16)
                Text(timerInterval: code.start...code.end, countsDown: true)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Lock screen, rectangle: title, code, countdown.
private struct RectangularCode: View {
    let title: String
    let code: PinnedCode.Code

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title)
                .font(.headline)
                .widgetAccentable()
                .lineLimit(1)
            Text(code.grouped)
                .font(.system(size: 24, weight: .semibold, design: .monospaced))
                .minimumScaleFactor(0.6)
                .lineLimit(1)
                .privacySensitive()
                .accessibilityLabel(Text("Code \(code.value)"))
            Text(timerInterval: code.start...code.end, countsDown: true)
                .font(.caption.monospacedDigit())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Lock screen, circle: the code in two lines inside the countdown ring.
private struct CircularCode: View {
    let title: String
    let code: PinnedCode.Code

    var body: some View {
        let halves = code.grouped.split(separator: " ").map(String.init)
        ProgressView(timerInterval: code.start...code.end, countsDown: true) {
            EmptyView()
        } currentValueLabel: {
            VStack(spacing: -2) {
                ForEach(halves, id: \.self) { half in
                    Text(half)
                }
            }
            .font(.system(size: 12, weight: .semibold, design: .monospaced))
            .privacySensitive()
        }
        .progressViewStyle(.circular)
        .widgetAccentable()
        .accessibilityLabel(Text("\(title): code \(code.value)"))
    }
}

/// An explanation instead of a code.
struct WidgetMessage: View {
    let symbol: String
    let title: LocalizedStringKey
    let detail: LocalizedStringKey
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 1 : 6) {
            Image(systemName: symbol)
                .font(compact ? .body : .title2)
                .foregroundStyle(Color.accentColor)
                .widgetAccentable()
                .accessibilityHidden(true)
            Text(title)
                .font(.headline)
                .lineLimit(2)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(compact ? 2 : 4)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
    }
}

#Preview("Code", as: .systemSmall) {
    CodeWidget()
} timeline: {
    CodeEntry(date: .now, content: .code(id: "1", title: "GitHub", host: "github.com", code: CodeProvider.sampleCode(at: .now)))
    CodeEntry(date: .now, content: .nothingPinned)
    CodeEntry(date: .now, content: .unavailable)
}

#Preview("Lock screen", as: .accessoryRectangular) {
    CodeWidget()
} timeline: {
    CodeEntry(date: .now, content: .code(id: "1", title: "GitHub", host: "github.com", code: CodeProvider.sampleCode(at: .now)))
    CodeEntry(date: .now, content: .nothingPinned)
}

#Preview("Circle", as: .accessoryCircular) {
    CodeWidget()
} timeline: {
    CodeEntry(date: .now, content: .code(id: "1", title: "GitHub", host: "github.com", code: CodeProvider.sampleCode(at: .now)))
}
