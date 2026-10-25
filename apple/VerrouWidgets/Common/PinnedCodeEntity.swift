import AppIntents
import Foundation

/// A pinned one-time code (`PinnedCodes`), for Shortcuts, Siri and the
/// widget's configuration. Only what the user pinned is listed: the vault
/// stays closed. Compiled into the app and the widget extension.
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

    /// One code pinned: the widget shows it without asking.
    func defaultResult() async -> PinnedCodeEntity? {
        PinnedCodes.all.first.map(PinnedCodeEntity.init)
    }
}

/// Opens Verrou on the Search tab (the Control Center control, Siri,
/// Shortcuts, Spotlight), with the query if one is given. The vault opens
/// with Face ID as usual.
struct SearchVaultIntent: AppIntent {
    static let title: LocalizedStringResource = "Search in Verrou"
    static let description = IntentDescription("Opens Verrou on the search, with the text if you give one.")
    static let openAppWhenRun = true

    @Parameter(title: "Text to search for")
    var query: String?

    init() {}

    init(query: String?) {
        self.query = query
    }

    @MainActor
    func perform() async throws -> some IntentResult {
        VerrouLinkCenter.open(.search(query))
        return .result()
    }
}
