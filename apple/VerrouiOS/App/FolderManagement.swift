import SwiftUI

/// What the folder sheet or the delete confirmation is about: a new folder
/// (inside `parent`, nil at the top), a folder being renamed (by its full
/// name) or a folder awaiting its deletion.
struct FolderRequest: Identifiable {
    enum Kind {
        case create(parent: String?)
        case rename(path: String)
        case delete(FolderNode)
    }

    let id = UUID()
    let kind: Kind
}

/// Folders created empty, renamed and deleted. Nested folders are names with
/// "/" (see `FolderNode`): the Rust core renames or deletes a folder together
/// with its subfolders, one request each.
extension PhoneModel {
    /// The server's folders, with their IDs.
    private var serverFolders: [(id: String, name: String)] {
        folders.map { ($0.id, $0.name) }
    }

    /// Creates a folder; the home screen shows it right away, empty.
    func createFolder(_ path: String) async {
        guard canEdit, !editorBusy else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            _ = try await session.createFolder(name: path)
            afterWrite()
        } catch {
            toast = Toast(message: String(localized: "Could not create folder"), detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Renames the folder at `path` (its subfolders follow); the folder
    /// screens open on it follow too.
    func renameFolder(_ path: String, to newPath: String) async {
        guard canEdit, !editorBusy, path != newPath else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            // A parent that only exists through its subfolders has no folder
            // of its own: its outermost subfolders are renamed instead.
            for folder in FolderNode.roots(of: path, in: serverFolders) {
                try await session.renameFolder(id: folder.id, name: FolderNode.moved(folder.name, from: path, to: newPath))
            }
            vaultPath = routes(vaultPath, movingFolder: path, to: newPath)
            searchPath = routes(searchPath, movingFolder: path, to: newPath)
            afterWrite()
            toast = Toast(message: String(localized: "Folder renamed"), detail: nil)
        } catch {
            afterWrite()
            toast = Toast(message: String(localized: "Could not rename folder"), detail: ErrorText.describe(error), failure: true)
        }
    }

    /// Deletes the folder and its subfolders; the items are kept, outside any
    /// folder. The screens open on them close.
    func deleteFolder(_ node: FolderNode) async {
        guard canEdit, !editorBusy else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            for folder in FolderNode.roots(of: node.path, in: serverFolders) {
                _ = try await session.deleteFolder(id: folder.id, includeSubfolders: true)
            }
            vaultPath = routes(vaultPath, movingFolder: node.path, to: nil)
            searchPath = routes(searchPath, movingFolder: node.path, to: nil)
            afterWrite()
            toast = Toast(message: String(localized: "Folder deleted"), detail: nil)
        } catch {
            afterWrite()
            toast = Toast(message: String(localized: "Could not delete folder"), detail: ErrorText.describe(error), failure: true)
        }
    }

    /// The screens of a navigation stack after a folder was renamed (`newPath`)
    /// or deleted (nil): the folder's screens, and its subfolders', follow it
    /// or leave the stack.
    private func routes(_ path: [Route], movingFolder old: String, to new: String?) -> [Route] {
        path.compactMap { route in
            guard case .list(.folder(let name)) = route, name == old || name.hasPrefix(old + "/") else { return route }
            return new.map { .list(.folder(name: FolderNode.moved(name, from: old, to: $0))) }
        }
    }

    /// The confirmation text: what happens to the items and the subfolders.
    func deletionMessage(_ node: FolderNode) -> String {
        var lines: [String] = []
        if node.count == 1 {
            lines.append(String(localized: "1 item will be moved out of the folder, to no folder. The item is not deleted."))
        } else if node.count > 1 {
            lines.append(String(localized: "\(Int(node.count)) items will be moved out of the folder, to no folder. The items are not deleted."))
        } else {
            lines.append(String(localized: "The folder is empty."))
        }
        if node.children != nil {
            lines.append(String(localized: "Its subfolders will be deleted too."))
        }
        return lines.joined(separator: " ")
    }
}

/// Swipe and long-press actions of a folder row.
private struct FolderActions: ViewModifier {
    @Environment(PhoneModel.self) private var model
    let node: FolderNode

    func body(content: Content) -> some View {
        if model.canEdit {
            content
                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                    Button("Delete", systemImage: "trash", role: .destructive) {
                        model.folderRequest = FolderRequest(kind: .delete(node))
                    }
                    Button("Rename", systemImage: "pencil") {
                        model.folderRequest = FolderRequest(kind: .rename(path: node.path))
                    }
                    .tint(.blue)
                }
                .contextMenu {
                    FolderMenuItems(node: node)
                }
        } else {
            content
        }
    }
}

extension View {
    /// Rename, delete and new subfolder on a folder row of a list.
    func folderActions(_ node: FolderNode) -> some View {
        modifier(FolderActions(node: node))
    }
}

/// New subfolder, rename and delete: long press on a row, or the menu of the
/// folder's own screen.
struct FolderMenuItems: View {
    @Environment(PhoneModel.self) private var model
    let node: FolderNode

    var body: some View {
        Button("New Subfolder", systemImage: "folder.badge.plus") {
            model.folderRequest = FolderRequest(kind: .create(parent: node.path))
        }
        Button("Rename", systemImage: "pencil") {
            model.folderRequest = FolderRequest(kind: .rename(path: node.path))
        }
        Button("Delete", systemImage: "trash", role: .destructive) {
            model.folderRequest = FolderRequest(kind: .delete(node))
        }
    }
}

/// The sheet for a new or renamed folder, and the delete confirmation.
struct FolderPresentations: ViewModifier {
    @Environment(PhoneModel.self) private var model

    private var deletion: FolderNode? {
        if case .delete(let node)? = model.folderRequest?.kind { return node }
        return nil
    }

    func body(content: Content) -> some View {
        @Bindable var model = model
        content
            .sheet(item: Binding(get: { deletion == nil ? model.folderRequest : nil },
                                 set: { model.folderRequest = $0 })) { request in
                FolderNameSheet(request: request)
            }
            .confirmationDialog(deletion.map { String(localized: "Delete the folder “\($0.name)”?") } ?? "",
                                isPresented: Binding(get: { deletion != nil },
                                                     set: { if !$0 { model.folderRequest = nil } }),
                                titleVisibility: .visible,
                                presenting: deletion) { node in
                Button("Delete Folder", role: .destructive) {
                    model.folderRequest = nil
                    Task { await model.deleteFolder(node) }
                }
                Button("Cancel", role: .cancel) { model.folderRequest = nil }
            } message: { node in
                Text(model.deletionMessage(node))
            }
    }
}

/// "New Folder" and "Rename": a name, and for a new folder the folder it goes
/// in.
private struct FolderNameSheet: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: FolderRequest
    @State private var name = ""
    @State private var parent: String?
    @State private var error: String?
    @FocusState private var focused: Bool

    private var renamed: String? {
        if case .rename(let path) = request.kind { return path }
        return nil
    }

    init(request: FolderRequest) {
        self.request = request
        switch request.kind {
        case .create(let parent):
            _parent = State(initialValue: parent)
        case .rename(let path):
            _name = State(initialValue: String(path.split(separator: "/").last ?? ""))
            _parent = State(initialValue: FolderNode.parent(of: path))
        case .delete:
            break
        }
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Folder name", text: $name)
                        .focused($focused)
                        .submitLabel(.done)
                        .onSubmit(submit)
                        .accessibilityIdentifier("folder-name")
                }
                if renamed == nil {
                    Section {
                        Picker("Inside", selection: $parent) {
                            Text("No parent (top level)").tag(String?.none)
                            ForEach(FolderNode.paths(in: model.folderTree), id: \.self) { path in
                                Text(path).tag(Optional(path))
                            }
                        }
                    }
                }
                if let error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(renamed == nil ? "New Folder" : "Rename Folder")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(renamed == nil ? "Create" : "Rename", action: submit)
                        .disabled(trimmed.isEmpty)
                }
            }
            .onAppear { focused = true }
        }
        .presentationDetents([.medium])
    }

    private func submit() {
        guard !trimmed.isEmpty else { return }
        guard !trimmed.contains("/") else {
            error = String(localized: "A folder name can't contain a slash. Choose the parent folder instead.")
            return
        }
        let path = parent.map { $0 + "/" + trimmed } ?? trimmed
        // Same refusal as the core's, before the network.
        if path != renamed, FolderNode.find(path, in: model.folderTree) != nil {
            error = String(localized: "A folder named “\(path)” already exists.")
            return
        }
        dismiss()
        Task {
            if let renamed {
                await model.renameFolder(renamed, to: path)
            } else {
                await model.createFolder(path)
            }
        }
    }
}
