import Foundation

/// A folder in a tree: Bitwarden nests folders by their name ("Work/Clients"
/// is inside "Work"). A parent that only exists through its subfolders still
/// shows; its count includes its subfolders' items, as does its filter
/// (`Filter::Folder` in the core). The Mac's sidebar shows it as an outline,
/// the iPhone one level per screen, like Files.
struct FolderNode: Identifiable, Hashable {
    /// The full name, the one the server knows ("Work/Clients").
    let path: String
    /// The last part of the name, shown in the tree ("Clients").
    let name: String
    let count: UInt32
    /// Nil for a folder without subfolders: no disclosure triangle.
    let children: [FolderNode]?

    var id: String { path }

    /// A folder's name as a path of the tree: "/Work//Clients/" is
    /// "Work/Clients", as Bitwarden's clients show it.
    static func path(of name: String) -> String {
        name.split(separator: "/", omittingEmptySubsequences: true).joined(separator: "/")
    }

    /// The folder at `path` in `tree`, at any depth.
    static func find(_ path: String, in tree: [FolderNode]) -> FolderNode? {
        for node in tree {
            if node.path == path { return node }
            // Only down the branch that leads to it.
            if path.hasPrefix(node.path + "/") { return find(path, in: node.children ?? []) }
        }
        return nil
    }

    /// The tree of the vault's counts plus every folder the server has, so
    /// that a folder created empty shows right away (counts only list folders
    /// that hold items).
    static func tree(counts: [(name: String, count: UInt32)], folders: [String]) -> [FolderNode] {
        let counted = Set(counts.map { path(of: $0.name) })
        let empty = folders.filter { !counted.contains(path(of: $0)) }.map { (name: $0, count: UInt32(0)) }
        return tree(counts + empty)
    }

    /// The server's folders that stand for `path` or sit below it, the
    /// outermost only (a folder follows its parent when this one is renamed
    /// or deleted). A parent that only exists through its subfolders has no
    /// folder of its own: its subfolders are what the server can act on.
    static func roots(of path: String, in folders: [(id: String, name: String)]) -> [(id: String, name: String)] {
        let inside = folders.filter {
            let own = Self.path(of: $0.name)
            return own == path || own.hasPrefix(path + "/")
        }
        return inside.filter { folder in
            let own = Self.path(of: folder.name)
            return !inside.contains { other in
                let parent = Self.path(of: other.name)
                return parent != own && own.hasPrefix(parent + "/")
            }
        }
    }

    /// `name` after the folder `old` became `new`: "Work/Clients" under
    /// Work renamed to Job is "Job/Clients".
    static func moved(_ name: String, from old: String, to new: String) -> String {
        let own = path(of: name)
        return own == old ? new : new + own.dropFirst(old.count)
    }

    /// The parent of a path ("Work/Clients" is in "Work"), nil at the top.
    static func parent(of path: String) -> String? {
        guard let slash = path.lastIndex(of: "/") else { return nil }
        return String(path[..<slash])
    }

    /// Every path in the tree, parents first, for a parent picker.
    static func paths(in tree: [FolderNode]) -> [String] {
        tree.flatMap { [$0.path] + paths(in: $0.children ?? []) }
    }

    static func tree(_ folders: [(name: String, count: UInt32)]) -> [FolderNode] {
        var own: [String: UInt32] = [:]
        for folder in folders {
            let path = path(of: folder.name)
            guard !path.isEmpty else { continue }
            own[path, default: 0] += folder.count
        }
        // Every path and its parents.
        var paths = Set<String>()
        for path in own.keys {
            var parts = path.split(separator: "/").map(String.init)
            while !parts.isEmpty {
                paths.insert(parts.joined(separator: "/"))
                parts.removeLast()
            }
        }
        func children(of parent: String?) -> [FolderNode] {
            let depth = parent.map { $0.split(separator: "/").count + 1 } ?? 1
            return paths
                .filter { path in
                    path.split(separator: "/").count == depth
                        && (parent.map { path.hasPrefix($0 + "/") } ?? true)
                }
                .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
                .map { path in
                    let nested = children(of: path)
                    let total = (own[path] ?? 0) + nested.reduce(0) { $0 + $1.count }
                    return FolderNode(path: path, name: String(path.split(separator: "/").last ?? ""),
                                      count: total, children: nested.isEmpty ? nil : nested)
                }
        }
        return children(of: nil)
    }
}
