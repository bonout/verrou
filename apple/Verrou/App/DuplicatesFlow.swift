import Foundation
import Observation

/// Vault duplicates: groups ranked by the Rust core (certain, probable, to
/// check), kept item, selection for the trash, merge, ignored groups.
///
/// Swift sees neither password nor seed: only titles, usernames, sites and
/// the verdict of the comparison.
@MainActor
@Observable
final class DuplicatesFlow: Identifiable {
    let id = UUID()
    private(set) var groups: [DuplicateGroupView] = []
    private(set) var loaded = false
    /// Items to move to the trash: by default, the certain copies.
    var selected: Set<String> = []
    /// Kept item chosen by hand, per group (group key).
    private(set) var kept: [String: String] = [:]
    /// Ignored groups (fingerprints of the item sets), kept on this machine:
    /// an ignored group comes back if it changes.
    private(set) var ignored: Set<String>
    var busy = false
    var error: String?

    private let defaults: UserDefaults
    static let ignoredKey = "duplicates.ignored"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        ignored = Set(defaults.stringArray(forKey: Self.ignoredKey) ?? [])
    }

    /// The vault's groups; what was checked and kept by hand stays so as
    /// long as the item is still there.
    func load(_ groups: [DuplicateGroupView]) {
        let first = !loaded
        self.groups = groups
        loaded = true
        let present = Set(groups.flatMap { $0.members.map(\.item.id) })
        kept = kept.filter { key, id in present.contains(id) && groups.contains { $0.key == key } }
        if first {
            selected = Set(visible.flatMap { group in
                group.members.dropFirst().filter(\.preselected).map(\.item.id)
            })
        } else {
            selected.formIntersection(present)
        }
        selected.subtract(visible.map(keptID))
    }

    /// The displayed groups (not ignored), the most certain first.
    var visible: [DuplicateGroupView] {
        groups.filter { !ignored.contains($0.key) }
    }

    var ignoredCount: Int {
        groups.count - visible.count
    }

    func count(_ confidence: DuplicateConfidence) -> Int {
        visible.filter { $0.confidence == confidence }.count
    }

    func keptID(_ group: DuplicateGroupView) -> String {
        kept[group.key] ?? group.members.first?.item.id ?? ""
    }

    /// Keeps this item rather than the one Verrou suggested.
    func keep(_ id: String, in group: DuplicateGroupView) {
        kept[group.key] = id
        selected.remove(id)
    }

    /// Checks or unchecks an item. Checking the kept item moves it to the
    /// trash and keeps in its place the first unchecked item of the group.
    func toggle(_ id: String, _ on: Bool, in group: DuplicateGroupView) {
        guard on else {
            selected.remove(id)
            return
        }
        if id == keptID(group) {
            guard let next = replacement(for: id, in: group) else { return }
            kept[group.key] = next
        }
        selected.insert(id)
    }

    /// The item that would be kept if `id` went to the trash: the first
    /// unchecked one of the group, in the order suggested by Verrou.
    func replacement(for id: String, in group: DuplicateGroupView) -> String? {
        group.members.map(\.item.id).first { $0 != id && !selected.contains($0) }
    }

    /// The checked items of a group (never the kept item).
    func checked(in group: DuplicateGroupView) -> [String] {
        let keep = keptID(group)
        return group.members.map(\.item.id).filter { $0 != keep && selected.contains($0) }
    }

    /// What "Merge" folds into the kept item: the checked items, otherwise
    /// the certain and probable duplicates (never the "to check" ones without
    /// checking them).
    func mergeTargets(in group: DuplicateGroupView) -> [String] {
        let checked = checked(in: group)
        if !checked.isEmpty { return checked }
        let keep = keptID(group)
        return group.members
            .filter { $0.item.id != keep && ($0.confidence == .certain || $0.confidence == .probable) }
            .map(\.item.id)
    }

    func title(of id: String) -> String {
        groups.lazy.flatMap(\.members).first { $0.item.id == id }?.item.title ?? ""
    }

    func ignore(_ group: DuplicateGroupView) {
        ignored.insert(group.key)
        selected.subtract(group.members.map(\.item.id))
        saveIgnored()
    }

    /// Shows the ignored groups again (without checking anything).
    func clearIgnored() {
        ignored.removeAll()
        saveIgnored()
    }

    private func saveIgnored() {
        if ignored.isEmpty {
            defaults.removeObject(forKey: Self.ignoredKey)
        } else {
            defaults.set(ignored.sorted(), forKey: Self.ignoredKey)
        }
    }
}

extension AppModel {
    // MARK: Duplicates

    /// Vault → Clean Up Duplicates…
    func openDuplicates() {
        guard lockState == .unlocked else { return }
        showMainWindow()
        let flow = DuplicatesFlow()
        duplicatesFlow = flow
        Task { await loadDuplicates(flow) }
    }

    func loadDuplicates(_ flow: DuplicatesFlow) async {
        do {
            flow.load(try await session.duplicates())
        } catch {
            flow.error = Self.describe(error)
            flow.load([])
        }
    }

    /// Moves the checked items to the trash: all, or those of `group`.
    func trashDuplicates(_ flow: DuplicatesFlow, in group: DuplicateGroupView? = nil) async {
        let ids = group.map { flow.checked(in: $0) } ?? Array(flow.selected)
        guard canEdit, !flow.busy, !ids.isEmpty else { return }
        flow.busy = true
        flow.error = nil
        defer { flow.busy = false }
        do {
            try await session.trashItems(ids: ids)
            afterWrite(select: nil)
            flow.selected.subtract(ids)
            toast = writeToast(ids.count > 1 ? String(localized: "\(ids.count) items moved to the trash")
                                             : String(localized: "\(ids.count) item moved to the trash"),
                               detail: String(localized: "You can restore them from the Trash."),
                               action: undoAction { [weak self] in await self?.performBulk(.restore, on: ids) })
            await loadDuplicates(flow)
        } catch {
            flow.error = Self.describe(error)
        }
    }

    /// Merges into the kept item, then moves the others to the trash.
    func mergeDuplicates(_ flow: DuplicatesFlow, group: DuplicateGroupView) async {
        let keep = flow.keptID(group)
        let others = flow.mergeTargets(in: group)
        guard canEdit, !flow.busy, !others.isEmpty else { return }
        flow.busy = true
        flow.error = nil
        defer { flow.busy = false }
        do {
            let report = try await session.mergeDuplicates(keep: keep, others: others)
            afterWrite(select: keep)
            flow.selected.subtract(others)
            toast = writeToast(String(localized: "Merged into “\(flow.title(of: keep))”"), detail: Self.mergeDetail(report))
            await loadDuplicates(flow)
        } catch {
            flow.error = Self.describe(error)
        }
    }

    /// "2 sites, the code, 1 old password; 2 in the trash"
    static func mergeDetail(_ report: MergeReport) -> String {
        var parts: [String] = []
        let sites = Int(report.sites), fields = Int(report.fields), history = Int(report.history)
        if sites > 0 { parts.append(sites > 1 ? String(localized: "\(sites) sites") : String(localized: "\(sites) site")) }
        if report.username { parts.append(String(localized: "the username")) }
        if report.totp { parts.append(String(localized: "the code")) }
        if report.notes > 0 { parts.append(String(localized: "notes")) }
        if fields > 0 { parts.append(fields > 1 ? String(localized: "\(fields) fields") : String(localized: "\(fields) field")) }
        if history > 0 {
            parts.append(history > 1 ? String(localized: "\(history) old passwords") : String(localized: "\(history) old password"))
        }
        let added = parts.isEmpty ? String(localized: "nothing to take over") : parts.joined(separator: ", ")
        return String(localized: "\(added); \(Int(report.trashed)) in the trash")
    }
}
