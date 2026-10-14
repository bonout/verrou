import AppKit
import SwiftUI

/// Sélection de plusieurs éléments (comme le Finder ou Mail) et actions
/// groupées.
///
/// La logique des gestes (clic, ⌘-clic, ⇧-clic, ⇧↑/⇧↓, ⌘A, Échap) est une
/// fonction pure du cœur Rust (`select_items`, testée là-bas), linéaire en
/// nombre de lignes. Ici, seulement l'état : `selection` reste l'élément
/// actif (colonne de détail, actions d'un seul élément) ; `selectedIDs`,
/// tous les éléments sélectionnés, dans l'ordre affiché.
extension AppModel {
    /// Les résumés des éléments sélectionnés, dans l'ordre affiché.
    var selectedSummaries: [ItemSummary] {
        selectedIDs.compactMap { summary(id: $0) }
    }

    /// Applique un geste de sélection, sans animation : la surbrillance
    /// suit la souris ou le clavier tout de suite.
    func applySelection(_ gesture: SelectionGesture) {
        let current = ItemSelection(selected: selectedIDs, anchor: selectionAnchor, focus: selection)
        let next = selectItems(current: current, order: resultIDs, gesture: gesture)
        withoutAnimation {
            applyingGesture = true
            selection = next.focus
            applyingGesture = false
            setSelected(next.selected)
            if selectionAnchor != next.anchor { selectionAnchor = next.anchor }
        }
    }

    /// Clic sur une ligne : ⌘ ajoute ou retire, ⇧ étend depuis l'ancre.
    func click(_ id: String, modifiers: NSEvent.ModifierFlags) {
        if modifiers.contains(.command) {
            applySelection(.toggle(id: id))
        } else if modifiers.contains(.shift) {
            applySelection(.extend(id: id))
        } else if selection != id || isMultiSelection {
            withoutAnimation { selection = id }
        }
    }

    /// Retour à une sélection simple (ou vide), sur l'élément actif.
    func collapseSelection() {
        setSelected(selection.map { [$0] } ?? [])
        if selectionAnchor != selection { selectionAnchor = selection }
    }

    private func setSelected(_ ids: [String]) {
        guard selectedIDs != ids else { return }
        selectedIDs = ids
        selectedSet = Set(ids)
        let multi = ids.count > 1
        if isMultiSelection != multi { isMultiSelection = multi }
    }

    /// Un élément créé a reçu son identifiant du serveur : la sélection (et
    /// l'ancre) passent de l'identifiant provisoire à celui-ci, sans
    /// changer d'élément.
    func resolveTemporaryIDs() {
        let resolve = { (id: String) in self.session.resolveItemId(id: id) }
        let focus = selection.map(resolve)
        let ids = selectedIDs.map(resolve)
        guard focus != selection || ids != selectedIDs else { return }
        withoutAnimation {
            applyingGesture = true
            selection = focus
            applyingGesture = false
            setSelected(ids)
            selectionAnchor = selectionAnchor.map(resolve)
        }
    }

    /// Les résultats ont changé (recherche, filtre, écriture) : on oublie
    /// les éléments qui ne sont plus affichés.
    func pruneSelection() {
        guard isMultiSelection else { return }
        let shown = Set(resultIDs)
        let kept = selectedIDs.filter(shown.contains)
        if kept.count == selectedIDs.count { return }
        withoutAnimation {
            if let focus = selection, kept.contains(focus) {
                setSelected(kept)
            } else if let first = kept.first {
                applyingGesture = true
                selection = first
                applyingGesture = false
                setSelected(kept)
                selectionAnchor = first
            } else {
                collapseSelection()
            }
            if selectedIDs.count <= 1 { collapseSelection() }
        }
    }

    // MARK: Actions groupées

    /// Ce que la sélection permet (boutons de la barre, du menu et du résumé).
    struct BulkAvailability {
        var count = 0
        var readOnly = 0
        var active = 0
        var archived = 0
        var trashed = 0
        var notFavorite = 0
        var favorite = 0
    }

    func availability(of ids: [String]) -> BulkAvailability {
        var a = BulkAvailability()
        for summary in ids.compactMap({ summary(id: $0) }) {
            a.count += 1
            if !canModify(summary) { a.readOnly += 1; continue }
            switch summary.state {
            case .active: a.active += 1
            case .archived: a.archived += 1
            case .trashed: a.trashed += 1; continue
            }
            if summary.favorite { a.favorite += 1 } else { a.notFavorite += 1 }
        }
        return a
    }

    /// Les éléments visés par une action lancée depuis la ligne `id` : la
    /// sélection si la ligne en fait partie, sinon cette ligne seule
    /// (comme le Finder).
    func targets(forRow id: String) -> [String] {
        isMultiSelection && selectedSet.contains(id) ? selectedIDs : [id]
    }

    /// Applique l'action à ces éléments, en une fois (voir `bulk.rs`) ; la
    /// corbeille de plusieurs éléments demande confirmation.
    func performBulk(_ action: BulkItemAction, on ids: [String], folderName: String? = nil) async {
        guard canEdit, !editorBusy, !ids.isEmpty else { return }
        if case .trash = action, ids.count > 1, !confirmBulkTrash(count: ids.count) { return }
        editorBusy = true
        bulkProgress = (0, ids.count)
        defer {
            editorBusy = false
            bulkProgress = nil
        }
        let start = ContinuousClock.now
        do {
            let result = try await session.bulkAction(ids: ids, action: action,
                                                      progress: BulkProgressRelay(model: self))
            Perf.log.notice("action groupée (\(ids.count) éléments) : \(Perf.ms(since: start)) ms")
            afterWrite(select: nil)
            pushChanges()
            // Les éléments archivés, mis à la corbeille ou restaurés
            // quittent la liste : la sélection suit les résultats.
            pruneSelection()
            if let focus = selection, !resultIDs.contains(focus) {
                withoutAnimation { selection = resultIDs.first }
            }
            toast = bulkToast(result, action: action, folderName: folderName)
        } catch {
            toast = Toast(message: "Action impossible", detail: Self.describe(error), failure: true)
        }
    }

    /// Range ces éléments dans un nouveau dossier (créé sur le serveur).
    func moveToNewFolder(_ name: String, ids: [String]) async {
        guard canEdit, !editorBusy else { return }
        do {
            let folder = try await session.createFolder(name: name)
            await performBulk(.moveToFolder(folderId: folder), on: ids,
                              folderName: name.trimmingCharacters(in: .whitespaces))
        } catch {
            toast = Toast(message: "Dossier impossible à créer", detail: Self.describe(error), failure: true)
        }
    }

    private func confirmBulkTrash(count: Int) -> Bool {
        let alert = NSAlert()
        alert.messageText = "Mettre \(count) éléments à la corbeille ?"
        alert.informativeText = "Restaurables 30 jours depuis la corbeille."
        alert.addButton(withTitle: "Mettre à la corbeille")
        alert.addButton(withTitle: "Annuler")
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// « 10 archivés, 2 ignorés (lecture seule) ».
    private func bulkToast(_ result: BulkResult, action: BulkItemAction, folderName: String?) -> Toast {
        let n = Int(result.done)
        let s = n > 1 ? "s" : ""
        var message: String
        switch action {
        case .archive: message = "\(n) archivé\(s)"
        case .unarchive: message = "\(n) sorti\(s) des archives"
        case .trash: message = "\(n) mis à la corbeille"
        case .restore: message = "\(n) restauré\(s)"
        case .favorite(let favorite): message = favorite ? "\(n) ajouté\(s) aux favoris" : "\(n) retiré\(s) des favoris"
        case .moveToFolder(let folder):
            message = folder == nil ? "\(n) retiré\(s) de leur dossier"
                                    : "\(n) déplacé\(s) vers « \(folderName ?? folders.first { $0.id == folder }?.name ?? "dossier") »"
        }
        var ignored: [String] = []
        if result.readOnly > 0 { ignored.append("\(result.readOnly) ignoré\(result.readOnly > 1 ? "s" : "") (lecture seule)") }
        if result.inTrash > 0 { ignored.append("\(result.inTrash) ignoré\(result.inTrash > 1 ? "s" : "") (dans la corbeille)") }
        if result.notFound > 0 { ignored.append("\(result.notFound) introuvable\(result.notFound > 1 ? "s" : "")") }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !result.failures.isEmpty {
            return Toast(message: message + ", \(result.failures.count) refusé\(result.failures.count > 1 ? "s" : "")",
                         detail: result.failures.joined(separator: "\n"), failure: true, seconds: 5)
        }
        let detail = result.queued > 0 && syncState == .offline ? "Hors ligne : synchronisé dès que le serveur répondra" : nil
        return Toast(message: message, detail: detail, seconds: ignored.isEmpty ? 2.2 : 4)
    }
}

/// « Déplacer vers un dossier… » : les éléments concernés.
struct MoveRequest: Identifiable {
    let id = UUID()
    let itemIDs: [String]
}

/// Sans animation implicite : sélection et surbrillance changent tout de suite.
func withoutAnimation(_ body: () -> Void) {
    var transaction = Transaction()
    transaction.disablesAnimations = true
    withTransaction(transaction, body)
}

/// Avancement envoyé par Rust depuis son fil : on passe au fil principal.
private final class BulkProgressRelay: BulkProgress, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) {
        self.model = model
    }

    func progress(done: UInt32, total: UInt32) {
        DispatchQueue.main.async { [weak model] in
            MainActor.assumeIsolated {
                guard let model, model.bulkProgress != nil else { return }
                model.bulkProgress = (Int(done), Int(total))
            }
        }
    }
}
