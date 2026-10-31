import AppKit
import SwiftUI

/// Selection of several items (like the Finder or Mail) and bulk actions.
///
/// The gesture logic (click, ⌘-click, ⇧-click, ⇧↑/⇧↓, ⌘A, Esc) is a pure
/// function of the Rust core (`select_items`, tested there), linear in the
/// number of rows. Here, only the state: `selection` stays the active item
/// (detail column, single-item actions); `selectedIDs`, all the selected
/// items, in display order.
extension AppModel {
    /// The summaries of the selected items, in display order.
    var selectedSummaries: [ItemSummary] {
        selectedIDs.compactMap { summary(id: $0) }
    }

    /// Applies a selection gesture, without animation: the highlight follows
    /// the mouse or the keyboard right away.
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

    /// Click on a row: ⌘ adds or removes, ⇧ extends from the anchor.
    func click(_ id: String, modifiers: NSEvent.ModifierFlags) {
        if modifiers.contains(.command) {
            applySelection(.toggle(id: id))
        } else if modifiers.contains(.shift) {
            applySelection(.extend(id: id))
        } else if selection != id || isMultiSelection {
            withoutAnimation { selection = id }
        }
    }

    /// Back to a simple (or empty) selection, on the active item.
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

    /// A created item got its ID from the server: the selection (and the
    /// anchor) move from the temporary ID to this one, without changing
    /// item.
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

    /// The results changed (search, filter, write): forget the items that
    /// are no longer displayed.
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

    // MARK: Bulk actions

    /// What the selection allows (buttons of the toolbar, the menu and the summary).
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

    /// The items targeted by an action started from the row `id`: the
    /// selection if the row is part of it, otherwise this row alone (like
    /// the Finder).
    func targets(forRow id: String) -> [String] {
        isMultiSelection && selectedSet.contains(id) ? selectedIDs : [id]
    }

    /// Applies the action to these items, at once (see `bulk.rs`); moving
    /// several items to the trash asks for confirmation.
    func performBulk(_ action: BulkItemAction, on ids: [String], folderName: String? = nil) async {
        guard canEdit, !editorBusy, !ids.isEmpty else { return }
        if case .trash = action, ids.count > 1, !confirmBulkTrash(count: ids.count) { return }
        let notTrashed = ids.filter { summary(id: $0)?.state != .trashed }
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
            Perf.log.notice("bulk action (\(ids.count) items): \(Perf.ms(since: start)) ms")
            afterWrite(select: nil)
            pushChanges()
            // Archived, trashed or restored items leave the list: the
            // selection follows the results.
            pruneSelection()
            if let focus = selection, !resultIDs.contains(focus) {
                withoutAnimation { selection = resultIDs.first }
            }
            var done = bulkToast(result, action: action, folderName: folderName)
            if case .trash = action, result.done > 0, result.failures.isEmpty {
                done.action = undoAction { [weak self] in await self?.performBulk(.restore, on: notTrashed) }
                done.seconds = 8
            }
            toast = done
        } catch {
            toast = Toast(message: String(localized: "Action failed"), detail: Self.describe(error), failure: true)
        }
    }

    /// Puts these items in a new folder (created on the server).
    func moveToNewFolder(_ name: String, ids: [String]) async {
        guard canEdit, !editorBusy else { return }
        do {
            let folder = try await session.createFolder(name: name)
            await performBulk(.moveToFolder(folderId: folder), on: ids,
                              folderName: name.trimmingCharacters(in: .whitespaces))
        } catch {
            toast = Toast(message: String(localized: "Couldn't create the folder"), detail: Self.describe(error), failure: true)
        }
    }

    private func confirmBulkTrash(count: Int) -> Bool {
        let alert = NSAlert()
        alert.messageText = String(localized: "Move \(count) items to the trash?")
        alert.informativeText = String(localized: "You can restore them from the Trash.")
        alert.addButton(withTitle: String(localized: "Move to Trash"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// "10 archived, 2 skipped (read-only)".
    private func bulkToast(_ result: BulkResult, action: BulkItemAction, folderName: String?) -> Toast {
        let n = Int(result.done)
        let many = n > 1
        var message: String
        switch action {
        case .archive: message = many ? String(localized: "\(n) items archived") : String(localized: "\(n) item archived")
        case .unarchive: message = many ? String(localized: "\(n) items unarchived") : String(localized: "\(n) item unarchived")
        case .trash: message = String(localized: "\(n) moved to the trash")
        case .restore: message = many ? String(localized: "\(n) items restored") : String(localized: "\(n) item restored")
        case .favorite(let favorite):
            message = favorite
                ? (many ? String(localized: "\(n) items added to favorites") : String(localized: "\(n) item added to favorites"))
                : (many ? String(localized: "\(n) items removed from favorites") : String(localized: "\(n) item removed from favorites"))
        case .moveToFolder(let folder):
            if folder == nil {
                message = many ? String(localized: "\(n) items removed from their folder")
                               : String(localized: "\(n) item removed from its folder")
            } else {
                let name = folderName ?? folders.first { $0.id == folder }?.name ?? String(localized: "folder")
                message = many ? String(localized: "\(n) items moved to “\(name)”")
                               : String(localized: "\(n) item moved to “\(name)”")
            }
        }
        var ignored: [String] = []
        let readOnly = Int(result.readOnly), inTrash = Int(result.inTrash), notFound = Int(result.notFound)
        if readOnly > 0 {
            ignored.append(readOnly > 1 ? String(localized: "\(readOnly) items skipped (read-only)")
                                        : String(localized: "\(readOnly) item skipped (read-only)"))
        }
        if inTrash > 0 {
            ignored.append(inTrash > 1 ? String(localized: "\(inTrash) items skipped (in the trash)")
                                       : String(localized: "\(inTrash) item skipped (in the trash)"))
        }
        if notFound > 0 {
            ignored.append(notFound > 1 ? String(localized: "\(notFound) items not found")
                                        : String(localized: "\(notFound) item not found"))
        }
        if !ignored.isEmpty { message += ", " + ignored.joined(separator: ", ") }
        if !result.failures.isEmpty {
            let refused = result.failures.count
            return Toast(message: message + ", " + (refused > 1 ? String(localized: "\(refused) items rejected")
                                                                : String(localized: "\(refused) item rejected")),
                         detail: result.failures.joined(separator: "\n"), failure: true, seconds: 5)
        }
        let detail = result.queued > 0 && syncState == .offline
            ? String(localized: "Offline: synced as soon as the server responds") : nil
        return Toast(message: message, detail: detail, seconds: ignored.isEmpty ? 2.2 : 4)
    }
}

/// "Move to Folder…": the items concerned.
struct MoveRequest: Identifiable {
    let id = UUID()
    let itemIDs: [String]
}

/// Without implicit animation: selection and highlight change right away.
func withoutAnimation(_ body: () -> Void) {
    var transaction = Transaction()
    transaction.disablesAnimations = true
    withTransaction(transaction, body)
}

/// Progress sent by Rust from its thread: move to the main thread.
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
