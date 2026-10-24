import SwiftUI

/// Detail column when several items are selected: their number and the
/// actions that apply to all of them.
struct MultiSelectionView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let ids = model.selectedIDs
        let available = model.availability(of: ids)
        VStack(spacing: 18) {
            Image(systemName: "square.stack.3d.up.fill")
                .accessibilityHidden(true)
                .font(.system(size: 46))
                .foregroundStyle(Theme.accent)
            VStack(spacing: 4) {
                Text("\(ids.count) items selected")
                    .font(.title2.weight(.semibold))
                    .monospacedDigit()
                if available.readOnly > 0 {
                    Text("including \(available.readOnly) read-only, which will be skipped")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            if let progress = model.bulkProgress {
                ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1))) {
                    Text("\(progress.done) of \(progress.total)").font(.caption).monospacedDigit()
                }
                .frame(maxWidth: 260)
            }
            VStack(spacing: 8) {
                BulkActions(ids: ids, style: .buttons)
                Divider().frame(maxWidth: 260).padding(.vertical, 4)
                Button("Deselect All") { model.applySelection(.collapse) }
                    .buttonStyle(.borderless)
                    .help("Go back to a single item (Esc in the list)")
            }
            .frame(maxWidth: 260)
            .disabled(model.bulkProgress != nil)
            if !model.canEdit {
                Text("Mock vault: read-only").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// The bulk actions: as big buttons (summary of the selection) or as menu
/// items (right-click on a row of the selection).
struct BulkActions: View {
    enum Style {
        case buttons
        case menu
    }

    @Environment(AppModel.self) private var model
    let ids: [String]
    let style: Style

    var body: some View {
        let a = model.availability(of: ids)
        let modifiable = a.active + a.archived + a.trashed
        if model.canEdit, modifiable > 0 {
            if a.trashed > 0 {
                action(String(localized: "Restore"), "arrow.uturn.backward", .restore)
            }
            if a.active > 0 {
                action(String(localized: "Archive"), "archivebox", .archive)
            }
            if a.archived > 0 {
                action(String(localized: "Unarchive"), "archivebox.fill", .unarchive)
            }
            if a.notFavorite > 0 {
                action(String(localized: "Add to Favorites"), "star", .favorite(favorite: true))
            } else if a.favorite > 0 {
                action(String(localized: "Remove from Favorites"), "star.slash", .favorite(favorite: false))
            }
            if a.active + a.archived > 0 {
                item(String(localized: "Move to Folder…"), "folder") {
                    model.moveRequest = MoveRequest(itemIDs: ids)
                }
                if !model.writableOrganizations.isEmpty, !model.shareableIDs(ids).isEmpty {
                    item(String(localized: "Share…"), "person.2") { model.openSharing(items: ids) }
                }
                if !model.unshareableIDs(ids).isEmpty {
                    item(String(localized: "Remove from Sharing…"), "person.2.slash") { model.requestUnshare(ids) }
                }
                action(String(localized: "Move to Trash"), "trash", .trash, destructive: true)
            }
        } else if style == .menu {
            Text(model.canEdit ? "These items are shared read-only" : "Mock vault: read-only")
        }
    }

    private func action(_ title: String, _ symbol: String, _ bulk: BulkItemAction,
                        destructive: Bool = false) -> some View {
        item(title, symbol, destructive: destructive) {
            Task { await model.performBulk(bulk, on: ids) }
        }
    }

    @ViewBuilder
    private func item(_ title: String, _ symbol: String, destructive: Bool = false,
                      perform: @escaping () -> Void) -> some View {
        switch style {
        case .menu:
            Button(role: destructive ? .destructive : nil, action: perform) {
                Text(ids.count > 1 ? "\(title) (\(ids.count))" : title)
            }
        case .buttons:
            Button(role: destructive ? .destructive : nil, action: perform) {
                Label(title, systemImage: symbol)
                    .frame(maxWidth: .infinity)
            }
            .controlSize(.large)
            .buttonStyle(.bordered)
            .disabled(model.editorBusy)
        }
    }
}

/// "Move to Folder…": an existing folder, none, or a new one.
struct MoveToFolderView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: MoveRequest
    @State private var newFolder = ""

    var body: some View {
        let count = request.itemIDs.count
        VStack(alignment: .leading, spacing: 12) {
            Text(count > 1 ? "Move \(count) Items" : "Move the Item")
                .font(.title3.weight(.semibold))
            List {
                row(String(localized: "No folder"), symbol: "tray") { move(to: nil, name: nil) }
                ForEach(model.folders, id: \.id) { folder in
                    row(folder.name, symbol: "folder") { move(to: folder.id, name: folder.name) }
                }
            }
            .listStyle(.bordered)
            .frame(minHeight: 180)
            HStack {
                TextField("New folder", text: $newFolder)
                    .onSubmit(createAndMove)
                Button("Create and Move", action: createAndMove)
                    .disabled(newFolder.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private func row(_ title: String, symbol: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.vertical, 3)
    }

    private func move(to folder: String?, name: String?) {
        let ids = request.itemIDs
        dismiss()
        Task { await model.performBulk(.moveToFolder(folderId: folder), on: ids, folderName: name) }
    }

    private func createAndMove() {
        let name = newFolder.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        let ids = request.itemIDs
        dismiss()
        Task { await model.moveToNewFolder(name, ids: ids) }
    }
}
