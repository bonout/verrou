import SwiftUI
import UniformTypeIdentifiers

/// Items dragged from the list, only within Verrou: their IDs, never their
/// content, and no other app accepts them.
enum ItemDrag {
    static let type = UTType(exportedAs: "app.verrou.items")

    static func provider(_ ids: [String]) -> NSItemProvider {
        let provider = NSItemProvider()
        provider.registerDataRepresentation(forTypeIdentifier: type.identifier, visibility: .ownProcess) { done in
            done(Data(ids.joined(separator: "\n").utf8), nil)
            return nil
        }
        return provider
    }

    static func load(_ providers: [NSItemProvider], then: @escaping @MainActor ([String]) -> Void) {
        guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(type.identifier) }) else { return }
        _ = provider.loadDataRepresentation(forTypeIdentifier: type.identifier) { data, _ in
            guard let data, let text = String(data: data, encoding: .utf8) else { return }
            let ids = text.split(separator: "\n").map(String.init)
            Task { @MainActor in then(ids) }
        }
    }
}

/// A sidebar folder that items dropped on move into (created on the server
/// if it only existed as the parent of subfolders).
struct FolderDropTarget: ViewModifier {
    @Environment(AppModel.self) private var model
    let path: String
    @State private var targeted = false

    func body(content: Content) -> some View {
        content
            .onDrop(of: [ItemDrag.type], isTargeted: $targeted) { providers in
                guard model.canEdit else { return false }
                ItemDrag.load(providers) { ids in
                    Task { await model.moveItems(ids, toFolder: path) }
                }
                return true
            }
            .listRowBackground(targeted ? RoundedRectangle(cornerRadius: 6).fill(Theme.accent.opacity(0.3)) : nil)
    }
}

extension AppModel {
    /// Moves items into the folder of that name, creating it if needed.
    func moveItems(_ ids: [String], toFolder path: String) async {
        if let folder = folders.first(where: { $0.name == path }) {
            await performBulk(.moveToFolder(folderId: folder.id), on: ids, folderName: path)
        } else {
            await moveToNewFolder(path, ids: ids)
        }
    }

    /// What a drag from this row carries: the whole selection if the row is
    /// part of it, otherwise the row alone.
    func dragIDs(from id: String) -> [String] {
        isMultiSelection && selectedSet.contains(id) ? selectedIDs : [id]
    }
}
