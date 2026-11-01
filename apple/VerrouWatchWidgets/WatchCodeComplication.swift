import AppIntents
import SwiftUI
import WidgetKit

/// A pinned one-time code (`PinnedCodes`), for the complication's
/// configuration. Only what the user pinned is listed.
struct PinnedCodeEntity: AppEntity {
    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "One-time code")
    static let defaultQuery = PinnedCodeQuery()

    let id: String
    let title: String
    let host: String?

    init(_ code: PinnedCode) {
        id = code.id
        title = code.title
        host = code.host
    }

    var displayRepresentation: DisplayRepresentation {
        DisplayRepresentation(title: "\(title)", subtitle: host.map { "\($0)" })
    }
}

struct PinnedCodeQuery: EntityQuery {
    func entities(for identifiers: [String]) async throws -> [PinnedCodeEntity] {
        PinnedCodes.all.filter { identifiers.contains($0.id) }.map(PinnedCodeEntity.init)
    }

    func suggestedEntities() async throws -> [PinnedCodeEntity] {
        PinnedCodes.all.map(PinnedCodeEntity.init)
    }

    /// One code pinned: the complication shows it without asking.
    func defaultResult() async -> PinnedCodeEntity? {
        PinnedCodes.all.first.map(PinnedCodeEntity.init)
    }
}

/// Which pinned code the complication shows (edited when choosing it on the
/// watch face, or in the Watch app on the iPhone).
struct SelectPinnedCodeIntent: WidgetConfigurationIntent {
    static let title: LocalizedStringResource = "One-time code"
    static let description = IntentDescription("Shows a one-time code pinned in Verrou.")

    @Parameter(title: "Code")
    var code: PinnedCodeEntity?

    init() {}
}

/// A moment of the complication: a code and its window, or why there is
/// none.
struct CodeEntry: TimelineEntry {
    enum Content {
        case code(title: String, code: PinnedCode.Code)
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

/// The same approach as the iPhone widget (`CodeWidget`): one entry per code
/// window, computed in advance.
struct CodeProvider: AppIntentTimelineProvider {
    /// One hour, half the iPhone's: a 30-second window already makes 120
    /// entries, and the system reloads at the end of the timeline.
    static let horizon: TimeInterval = 60 * 60
    static let maxEntries = 240

    func placeholder(in context: Context) -> CodeEntry {
        CodeEntry(date: Date(), content: .code(title: "Verrou", code: Self.sampleCode(at: Date())))
    }

    func snapshot(for configuration: SelectPinnedCodeIntent, in context: Context) async -> CodeEntry {
        // The complication gallery: a sample, not the user's codes.
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
            // The Watch app reloads the complications when the iPhone
            // sends a new list.
            return Timeline(entries: entries, policy: .never)
        default:
            return Timeline(entries: entries, policy: .atEnd)
        }
    }

    /// One suggestion per pinned code, in the watch face's complication
    /// picker (watchOS asks for them).
    func recommendations() -> [AppIntentRecommendation<SelectPinnedCodeIntent>] {
        PinnedCodes.all.map { pinned in
            let intent = SelectPinnedCodeIntent()
            intent.code = PinnedCodeEntity(pinned)
            return AppIntentRecommendation(intent: intent, description: "\(pinned.title)")
        }
    }

    /// One entry per code window, from now until the horizon, then
    /// `refreshing`.
    static func entries(for configuration: SelectPinnedCodeIntent, from now: Date, limit: Int) -> [CodeEntry] {
        guard case .codes(let codes) = PinnedCodes.read() else {
            return [CodeEntry(date: now, content: .unavailable)]
        }
        let chosen = configuration.code.map { entity in codes.first { $0.id == entity.id } } ?? codes.first
        guard let pinned = chosen else { return [CodeEntry(date: now, content: .nothingPinned)] }
        var entries: [CodeEntry] = []
        var moment = now
        while entries.count < limit, moment < now.addingTimeInterval(horizon) {
            let code = pinned.code(at: moment)
            entries.append(CodeEntry(date: entries.isEmpty ? now : code.start, content: .code(title: pinned.title, code: code)))
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

/// "One-time code": a pinned code and its countdown on the watch face.
struct WatchCodeComplication: Widget {
    static let kind = "app.verrou.ios.watchkitapp.code"

    var body: some WidgetConfiguration {
        AppIntentConfiguration(kind: Self.kind, intent: SelectPinnedCodeIntent.self, provider: CodeProvider()) { entry in
            WatchCodeView(entry: entry)
        }
        .configurationDisplayName("One-time code")
        .description("A code you pinned in Verrou.")
        .supportedFamilies([.accessoryCircular, .accessoryRectangular, .accessoryInline])
    }
}

struct WatchCodeView: View {
    let entry: CodeEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        content
            .containerBackground(for: .widget) { Color.clear }
    }

    @ViewBuilder
    private var content: some View {
        switch (entry.content, family) {
        case (.code(let title, let code), .accessoryCircular):
            CircularCode(title: title, code: code)
        case (.code(let title, let code), .accessoryRectangular):
            RectangularCode(title: title, code: code)
        case (.code(let title, let code), _):
            Text(verbatim: "\(title) \(code.grouped)")
                .privacySensitive()
        case (_, .accessoryInline):
            Text(message.title)
        case (_, .accessoryCircular):
            Image(systemName: symbol)
                .font(.title3)
                .widgetAccentable()
                .accessibilityLabel(Text(message.title))
        default:
            VStack(alignment: .leading, spacing: 1) {
                Label(message.title, systemImage: symbol)
                    .font(.headline)
                    .widgetAccentable()
                    .lineLimit(2)
                Text(message.detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
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
            ("Unlock your watch", "Your pinned codes show after the first unlock.")
        case .refreshing:
            ("Updating…", "Open Verrou if the code doesn't show.")
        default:
            ("Pin a code in Verrou", "On your iPhone, open an item and turn on Show in widgets and on Apple Watch.")
        }
    }
}

/// Rectangle: title, code, countdown.
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
                .font(.system(.title2, design: .monospaced, weight: .semibold))
                .minimumScaleFactor(0.6)
                .lineLimit(1)
                .privacySensitive()
                .accessibilityLabel(Text("\(title): code \(code.value)"))
            Text(timerInterval: code.start...code.end, countsDown: true)
                .font(.caption.monospacedDigit())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Circle: the code in two lines inside the countdown ring.
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
            .font(.system(.caption, design: .monospaced, weight: .semibold))
            .privacySensitive()
        }
        .progressViewStyle(.circular)
        .widgetAccentable()
        .accessibilityLabel(Text("\(title): code \(code.value)"))
    }
}

#Preview("Rectangular", as: .accessoryRectangular) {
    WatchCodeComplication()
} timeline: {
    CodeEntry(date: .now, content: .code(title: "GitHub", code: CodeProvider.sampleCode(at: .now)))
    CodeEntry(date: .now, content: .nothingPinned)
}

#Preview("Circular", as: .accessoryCircular) {
    WatchCodeComplication()
} timeline: {
    CodeEntry(date: .now, content: .code(title: "GitHub", code: CodeProvider.sampleCode(at: .now)))
}
