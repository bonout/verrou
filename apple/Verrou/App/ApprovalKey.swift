import Foundation

/// What makes two approval requests one for `RemoteApprovals`: the bridge
/// sometimes asks the same thing twice in a row, and one answer then serves
/// both.
enum ApprovalKey {
    /// Everything that is shown to the user, and the item's identifier (two
    /// items can share a title). `nil`: never merged. An agent's request
    /// (`ephemeral`) is its own question, however much it looks like the
    /// previous one: an answer given to one must not be given to another.
    static func make(client: String, purpose: String, item: String, title: String, site: String, reason: String,
                     changes: String, command: String, fields: String, ephemeral: Bool, scope: String?) -> String? {
        guard !ephemeral else { return nil }
        return [client, purpose, item, title, site, reason, changes, command, fields, scope ?? ""]
            .joined(separator: "\u{1F}")
    }
}
