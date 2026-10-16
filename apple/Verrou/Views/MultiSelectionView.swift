import SwiftUI

/// Colonne de détail quand plusieurs éléments sont sélectionnés : leur
/// nombre et les actions qui valent pour tous.
struct MultiSelectionView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let ids = model.selectedIDs
        let available = model.availability(of: ids)
        VStack(spacing: 18) {
            Image(systemName: "square.stack.3d.up.fill")
                .font(.system(size: 46))
                .foregroundStyle(Theme.accent)
            VStack(spacing: 4) {
                Text("\(ids.count) éléments sélectionnés")
                    .font(.title2.weight(.semibold))
                    .monospacedDigit()
                if available.readOnly > 0 {
                    Text("dont \(available.readOnly) en lecture seule, qui seront ignorés")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            if let progress = model.bulkProgress {
                ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1))) {
                    Text("\(progress.done) sur \(progress.total)").font(.caption).monospacedDigit()
                }
                .frame(maxWidth: 260)
            }
            VStack(spacing: 8) {
                BulkActions(ids: ids, style: .buttons)
                Divider().frame(maxWidth: 260).padding(.vertical, 4)
                Button("Tout désélectionner") { model.applySelection(.collapse) }
                    .buttonStyle(.borderless)
                    .help("Revenir à un seul élément (Échap dans la liste)")
            }
            .frame(maxWidth: 260)
            .disabled(model.bulkProgress != nil)
            if !model.canEdit {
                Text("Coffre fictif : lecture seule").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Les actions groupées : en gros boutons (résumé de la sélection) ou en
/// entrées de menu (clic droit sur une ligne de la sélection).
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
                action("Restaurer", "arrow.uturn.backward", .restore)
            }
            if a.active > 0 {
                action("Archiver", "archivebox", .archive)
            }
            if a.archived > 0 {
                action("Désarchiver", "archivebox.fill", .unarchive)
            }
            if a.notFavorite > 0 {
                action("Ajouter aux favoris", "star", .favorite(favorite: true))
            } else if a.favorite > 0 {
                action("Retirer des favoris", "star.slash", .favorite(favorite: false))
            }
            if a.active + a.archived > 0 {
                item("Déplacer vers un dossier…", "folder") {
                    model.moveRequest = MoveRequest(itemIDs: ids)
                }
                if !model.writableOrganizations.isEmpty, !model.shareableIDs(ids).isEmpty {
                    item("Partager…", "person.2") { model.openSharing(items: ids) }
                }
                action("Mettre à la corbeille", "trash", .trash, destructive: true)
            }
        } else if style == .menu {
            Text(model.canEdit ? "Partagés en lecture seule" : "Coffre fictif : lecture seule")
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

/// « Déplacer vers un dossier… » : un dossier existant, aucun, ou un nouveau.
struct MoveToFolderView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: MoveRequest
    @State private var newFolder = ""

    var body: some View {
        let count = request.itemIDs.count
        VStack(alignment: .leading, spacing: 12) {
            Text(count > 1 ? "Déplacer \(count) éléments" : "Déplacer l'élément")
                .font(.title3.weight(.semibold))
            List {
                row("Aucun dossier", symbol: "tray") { move(to: nil, name: nil) }
                ForEach(model.folders, id: \.id) { folder in
                    row(folder.name, symbol: "folder") { move(to: folder.id, name: folder.name) }
                }
            }
            .listStyle(.bordered)
            .frame(minHeight: 180)
            HStack {
                TextField("Nouveau dossier", text: $newFolder)
                    .onSubmit(createAndMove)
                Button("Créer et déplacer", action: createAndMove)
                    .disabled(newFolder.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            HStack {
                Spacer()
                Button("Annuler", role: .cancel) { dismiss() }
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
