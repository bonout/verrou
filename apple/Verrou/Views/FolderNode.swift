import Foundation

/// A folder of the sidebar, in a tree: Bitwarden nests folders by their
/// name ("Work/Clients" is inside "Work"). A parent that only exists through
/// its subfolders still shows; its count includes its subfolders' items, as
/// does its filter (`Filter::Folder` in the core).
struct FolderNode: Identifiable, Hashable {
    /// The full name, the one the server knows ("Work/Clients").
    let path: String
    /// The last part of the name, shown in the tree ("Clients").
    let name: String
    let count: UInt32
    /// Nil for a folder without subfolders: no disclosure triangle.
    let children: [FolderNode]?

    var id: String { path }

    static func tree(_ folders: [(name: String, count: UInt32)]) -> [FolderNode] {
        var own: [String: UInt32] = [:]
        for folder in folders {
            let path = folder.name.split(separator: "/", omittingEmptySubsequences: true).joined(separator: "/")
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
