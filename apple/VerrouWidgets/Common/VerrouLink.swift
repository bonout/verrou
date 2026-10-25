import Foundation

/// Where a widget, a control, a Live Activity or a Shortcut leads in the
/// iPhone app: `verrou://` links (the app's URL scheme), and the same
/// destinations handed over by App Intents running in the app.
///
/// Any app or web page can open a `verrou://` link: each one only
/// navigates (a search, a tab, a sheet), and anything that touches the
/// vault waits for its unlock. Nothing is copied, revealed or approved by a
/// link. Compiled into the app and the widget extension.
enum VerrouLink: Equatable, Sendable {
    /// The Search tab, with the query if there is one.
    case search(String?)
    case generator
    /// The camera, to add a one-time code from its QR code.
    case scanCode
    /// An item's page.
    case item(String)
    /// The Mac's request in progress (approval screen, Face ID).
    case approval
    /// App Intent only (never from a URL): copies the item's password once
    /// the vault is open, with the app's usual confirmations.
    case copyPassword(String)

    static let scheme = "verrou"

    init?(url: URL) {
        guard url.scheme?.lowercased() == Self.scheme,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let value = { (name: String) in components.queryItems?.first { $0.name == name }?.value }
        switch components.host?.lowercased() {
        case "search":
            let query = value("q")?.trimmingCharacters(in: .whitespacesAndNewlines)
            // A search query, not a document: long texts are cut.
            self = .search(query.map { String($0.prefix(200)) }.flatMap { $0.isEmpty ? nil : $0 })
        case "generator":
            self = .generator
        case "scan":
            self = .scanCode
        case "item":
            guard let id = value("id"), !id.isEmpty, id.count <= 100 else { return nil }
            self = .item(id)
        case "approval":
            self = .approval
        default:
            return nil
        }
    }

    /// The link for the URL scheme (`nil` for what only an intent may do).
    var url: URL? {
        var components = URLComponents()
        components.scheme = Self.scheme
        switch self {
        case .search(let query):
            components.host = "search"
            if let query, !query.isEmpty { components.queryItems = [URLQueryItem(name: "q", value: query)] }
        case .generator:
            components.host = "generator"
        case .scanCode:
            components.host = "scan"
        case .item(let id):
            components.host = "item"
            components.queryItems = [URLQueryItem(name: "id", value: id)]
        case .approval:
            components.host = "approval"
        case .copyPassword:
            return nil
        }
        return components.url
    }
}

/// App Intents that run in the app hand their destination over here; the
/// app's model takes it (`setHandler`), or finds it waiting at launch. In
/// the widget extension, nothing is installed: the intents it shows run in
/// the app (`openAppWhenRun`, `LiveActivityIntent`).
@MainActor
enum VerrouLinkCenter {
    private static var handler: ((VerrouLink) -> Void)?
    private static var pending: VerrouLink?

    static func open(_ link: VerrouLink) {
        if let handler { handler(link) } else { pending = link }
    }

    static func setHandler(_ handler: @escaping (VerrouLink) -> Void) {
        self.handler = handler
        if let link = pending {
            pending = nil
            handler(link)
        }
    }
}
