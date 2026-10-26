import Foundation

/// Item identifiers as the Rust core hands them out: `"<tag>:<id>"`, where
/// `<tag>` is the six characters (`a-z`, `2-7`) of the account's folder
/// (`Accounts`). Swift treats them as opaque strings, and only goes through
/// here for what is stored on this device (the pinned one-time codes, the
/// recent login, the system's identity store), where an id written before
/// accounts had tags, without `<tag>:`, can still be there.
///
/// The Rust core accepts both forms for its own account (an unqualified id is
/// the session's own) and refuses another account's: this is the Swift side
/// of that rule. What is written is always qualified (the id a summary has);
/// what is read accepts both.
///
/// Platform-neutral and dependency-free: compiled into the widgets and the
/// Apple Watch with `PinnedCodes`.
enum ItemID {
    /// `tag` is `nil` for an unqualified id.
    static func split(_ id: String) -> (tag: String?, id: String) {
        guard let colon = id.firstIndex(of: ":"), isTag(id[..<colon]) else { return (nil, id) }
        return (String(id[..<colon]), String(id[id.index(after: colon)...]))
    }

    /// The vault's own id, whichever form it came in.
    static func local(_ id: String) -> String {
        split(id).id
    }

    /// The qualified form for account `tag` (unchanged if it already carries
    /// a tag, or when there is no tag, the demo vault).
    static func qualified(_ id: String, tag: String?) -> String {
        guard let tag, split(id).tag == nil else { return id }
        return "\(tag):\(id)"
    }

    /// The same item: equal ids, or equal local ids when one of them is
    /// unqualified. Two ids with different tags are never the same item.
    static func same(_ first: String, _ second: String) -> Bool {
        let a = split(first), b = split(second)
        if let x = a.tag, let y = b.tag, x != y { return false }
        return a.id == b.id
    }

    /// Six characters of `a-z2-7`, as `verrou_vaultwarden::accounts::valid_tag`.
    static func isTag(_ text: Substring) -> Bool {
        text.utf8.count == 6 && text.utf8.allSatisfy { ($0 >= 97 && $0 <= 122) || ($0 >= 50 && $0 <= 55) }
    }
}
