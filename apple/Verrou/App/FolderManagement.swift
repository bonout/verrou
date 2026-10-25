import AppKit
import SwiftUI

/// The folder sheet that is open: a new folder (inside `parent`, nil at the
/// top) or a folder being renamed (by its full name).
struct FolderRequest: Identifiable {
    enum Kind {
        case create(parent: String?)
        case rename(path: String)
    }

    let id = UUID()
    let kind: Kind
}

/// Folders created empty, renamed and deleted from the sidebar. Nested
/// folders are names with "/" (see `FolderNode`): the Rust core renames or
/// deletes a folder together with its subfolders, one request each.
extension AppModel {
    /// The sidebar's folders, empty ones included.
    var folderTree: [FolderNode] {
        FolderNode.tree(counts: (counts?.folders ?? []).map { ($0.name, $0.count) },
                        folders: folders.map(\.name))
    }

    /// The server's folders, with their IDs.
    private var serverFolders: [(id: String, name: String)] {
        folders.map { ($0.id, $0.name) }
    }

    /// Creates a folder and returns its ID; the sidebar shows it right away.
    func createFolder(_ path: String) async -> String? {
        guard canEdit, !editorBusy else { return nil }
        editorBusy = true
        defer { editorBusy = false }
        do {
            let id = try await session.createFolder(name: path)
            afterWrite(select: nil)
            return id
        } catch {
            toast = Toast(message: String(localized: "Couldn't create the folder"), detail: Self.describe(error), failure: true)
            return nil
        }
    }

    /// Renames the folder at `path` (its subfolders follow). The selected
    /// sidebar filter follows too.
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
            if case .folder(let selected) = filter, selected == path || selected.hasPrefix(path + "/") {
                filter = .folder(name: FolderNode.moved(selected, from: path, to: newPath))
            }
            afterWrite(select: nil)
            toast = Toast(message: String(localized: "Folder renamed"), detail: nil)
        } catch {
            afterWrite(select: nil)
            toast = Toast(message: String(localized: "Couldn't rename the folder"), detail: Self.describe(error), failure: true)
        }
    }

    /// Asks for confirmation, then deletes the folder and its subfolders. The
    /// items are kept, outside any folder.
    func confirmDeleteFolder(_ node: FolderNode) async {
        guard canEdit, !editorBusy else { return }
        let alert = NSAlert()
        alert.messageText = String(localized: "Delete the folder “\(node.name)”?")
        var lines: [String] = []
        if node.count == 1 {
            lines.append(String(localized: "1 item will be moved out of the folder, to “No folder”. The item is not deleted."))
        } else if node.count > 1 {
            lines.append(String(localized: "\(Int(node.count)) items will be moved out of the folder, to “No folder”. The items are not deleted."))
        } else {
            lines.append(String(localized: "The folder is empty."))
        }
        if node.children != nil {
            lines.append(String(localized: "Its subfolders will be deleted too."))
        }
        alert.informativeText = lines.joined(separator: " ")
        alert.alertStyle = .warning
        alert.addButton(withTitle: String(localized: "Delete Folder"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        editorBusy = true
        defer { editorBusy = false }
        do {
            for folder in FolderNode.roots(of: node.path, in: serverFolders) {
                _ = try await session.deleteFolder(id: folder.id, includeSubfolders: true)
            }
            if case .folder(let selected) = filter, selected == node.path || selected.hasPrefix(node.path + "/") {
                filter = .all
            }
            afterWrite(select: nil)
            toast = Toast(message: String(localized: "Folder deleted"), detail: nil)
        } catch {
            afterWrite(select: nil)
            toast = Toast(message: String(localized: "Couldn't delete the folder"), detail: Self.describe(error), failure: true)
        }
    }
}

/// "New Folder…" and "Rename…": a name, and for a new folder the folder it
/// goes in.
struct FolderNameView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: FolderRequest
    /// The edit sheet files its item in the folder it just created.
    var onCreated: (@MainActor (String) -> Void)?
    @State private var name = ""
    @State private var parent: String?
    @State private var error: String?
    @FocusState private var focused: Bool

    private var renamed: String? {
        if case .rename(let path) = request.kind { return path }
        return nil
    }

    init(request: FolderRequest, onCreated: (@MainActor (String) -> Void)? = nil) {
        self.request = request
        self.onCreated = onCreated
        switch request.kind {
        case .create(let parent):
            _parent = State(initialValue: parent)
        case .rename(let path):
            _name = State(initialValue: String(path.split(separator: "/").last ?? ""))
            _parent = State(initialValue: FolderNode.parent(of: path))
        }
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(renamed == nil ? "New Folder" : "Rename Folder")
                .font(.title3.weight(.semibold))
            TextField("Name", text: $name)
                .focused($focused)
                .onSubmit(submit)
            if renamed == nil {
                Picker("Inside", selection: $parent) {
                    Text("No parent (top level)").tag(String?.none)
                    ForEach(FolderNode.paths(in: model.folderTree), id: \.self) { path in
                        Text(path).tag(Optional(path))
                    }
                }
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(renamed == nil ? "Create" : "Rename", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(trimmed.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 360)
        .onAppear { focused = true }
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
                if let id = await model.createFolder(path) { onCreated?(id) }
            }
        }
    }
}

/// Right-click on a folder of the sidebar.
struct FolderMenu: View {
    @Environment(AppModel.self) private var model
    let node: FolderNode

    var body: some View {
        if model.canEdit {
            Button("New Subfolder…") { model.folderRequest = FolderRequest(kind: .create(parent: node.path)) }
            Button("Rename…") { model.folderRequest = FolderRequest(kind: .rename(path: node.path)) }
            Divider()
            Button("Delete…", role: .destructive) { Task { await model.confirmDeleteFolder(node) } }
        }
    }
}
