import Foundation

/// What the iPhone's approval of "unlock and read <item>" covers: that item,
/// for the terminal that asked, once, for a minute. Nothing else rides on it:
/// not another client's request, not another item that happens to share the
/// title, not an AI agent's request (which is approved on its own, showing
/// the command it will run).
struct UnlockGrant: Equatable {
    /// The item's identifier, never its title.
    let itemID: String
    /// The bridge's identifier of the client that asked for the unlock.
    let client: String
    let until: Date

    static let lifetime: TimeInterval = 60

    /// The identifier a terminal's reference names: the identifier itself, or
    /// the one item with exactly that title (case included). A title two
    /// items share, or none, names nothing: the grant is not given.
    static func resolve(reference: String, among items: [(id: String, title: String)]) -> String? {
        if let exact = items.first(where: { $0.id == reference }) { return exact.id }
        let titled = items.filter { $0.title == reference }
        return titled.count == 1 ? titled[0].id : nil
    }

    /// Does this request need no second approval? Only a plain one (not an
    /// agent's, which carries a command or is marked ephemeral), from the
    /// same client, for the same item, within the minute.
    func covers(item: String, client: String, ephemeral: Bool, command: String, now: Date = Date()) -> Bool {
        !ephemeral && command.isEmpty && until > now && itemID == item && self.client == client
    }
}
