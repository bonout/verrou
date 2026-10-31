import SwiftUI

struct FolderPrompt: Identifiable {
    let id = UUID()
    let folder: FolderOption?
    var name: String
}

extension AppModel {
    var canManageFolders: Bool { canEdit }

    func folder(at path: String) -> FolderOption? {
        folders.first { $0.name == path }
    }

    func promptNewFolder() {
        guard canManageFolders else { return }
        showMainWindow()
        folderPrompt = FolderPrompt(folder: nil, name: "")
    }

    func promptRenameFolder(_ folder: FolderOption) {
        guard canManageFolders else { return }
        folderPrompt = FolderPrompt(folder: folder, name: folder.name)
    }

    func submitFolderPrompt() async {
        guard let prompt = folderPrompt else { return }
        folderPrompt = nil
        if let folder = prompt.folder {
            await renameFolder(folder, to: prompt.name)
        } else {
            _ = await createFolder(prompt.name)
        }
    }

    @discardableResult
    func createFolder(_ name: String) async -> String? {
        let name = name.trimmingCharacters(in: .whitespaces)
        guard canManageFolders, !name.isEmpty else { return nil }
        do {
            let id = try await session.createFolder(name: name)
            afterWrite(select: selection)
            toast = Toast(message: String(localized: "Folder “\(name)” created"), detail: nil)
            return id
        } catch {
            toast = Toast(message: String(localized: "Couldn't create the folder"), detail: Self.describe(error), failure: true)
            return nil
        }
    }

    func renameFolder(_ folder: FolderOption, to name: String) async {
        let name = name.trimmingCharacters(in: .whitespaces)
        guard canManageFolders, !name.isEmpty, name != folder.name else { return }
        do {
            try await session.renameFolder(id: folder.id, name: name)
            if filter == .folder(name: folder.name) { filter = .folder(name: name) }
            afterWrite(select: selection)
            toast = Toast(message: String(localized: "Folder renamed"), detail: name)
        } catch {
            toast = Toast(message: String(localized: "Couldn't rename the folder"), detail: Self.describe(error), failure: true)
        }
    }

    func deleteFolder(_ folder: FolderOption) async {
        guard canManageFolders else { return }
        do {
            try await session.deleteFolder(id: folder.id)
            if filter == .folder(name: folder.name) { filter = .all }
            afterWrite(select: selection)
            toast = Toast(message: String(localized: "Folder “\(folder.name)” deleted"),
                          detail: String(localized: "Its items stay in the vault, without a folder"))
        } catch {
            toast = Toast(message: String(localized: "Couldn't delete the folder"), detail: Self.describe(error), failure: true)
        }
    }
}
