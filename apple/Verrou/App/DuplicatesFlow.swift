import Foundation
import Observation

/// Doublons du coffre : groupes classés par le cœur Rust (certain, probable,
/// à vérifier), élément gardé, sélection pour la corbeille, fusion, groupes
/// ignorés.
///
/// Swift ne voit ni mot de passe ni graine : seulement titres, identifiants,
/// sites et le verdict de la comparaison.
@MainActor
@Observable
final class DuplicatesFlow: Identifiable {
    let id = UUID()
    private(set) var groups: [DuplicateGroupView] = []
    private(set) var loaded = false
    /// Éléments à mettre à la corbeille : par défaut, les copies certaines.
    var selected: Set<String> = []
    /// Élément gardé choisi à la main, par groupe (clé du groupe).
    private(set) var kept: [String: String] = [:]
    /// Groupes ignorés (empreintes des ensembles d'éléments), gardés sur
    /// cette machine : un groupe ignoré revient s'il change.
    private(set) var ignored: Set<String>
    var busy = false
    var error: String?

    private let defaults: UserDefaults
    static let ignoredKey = "duplicates.ignored"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        ignored = Set(defaults.stringArray(forKey: Self.ignoredKey) ?? [])
    }

    /// Les groupes du coffre ; ce qui était coché et gardé à la main le reste
    /// tant que l'élément est toujours là.
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

    /// Les groupes affichés (ni ignorés), les plus certains d'abord.
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

    /// Garde cet élément plutôt que celui que Verrou suggérait.
    func keep(_ id: String, in group: DuplicateGroupView) {
        kept[group.key] = id
        selected.remove(id)
    }

    func toggle(_ id: String, _ on: Bool) {
        if on { selected.insert(id) } else { selected.remove(id) }
    }

    /// Les éléments cochés d'un groupe (jamais l'élément gardé).
    func checked(in group: DuplicateGroupView) -> [String] {
        let keep = keptID(group)
        return group.members.map(\.item.id).filter { $0 != keep && selected.contains($0) }
    }

    /// Ce que « Fusionner » fond dans l'élément gardé : les éléments cochés,
    /// sinon les doublons certains et probables (jamais ceux « à vérifier »
    /// sans les cocher).
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

    /// Réaffiche les groupes ignorés (sans rien cocher).
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
    // MARK: Doublons

    /// Coffre → Nettoyer les doublons…
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

    /// Met les éléments cochés à la corbeille : tous, ou ceux de `group`.
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
            toast = writeToast("\(ids.count) élément\(ids.count > 1 ? "s" : "") mis à la corbeille",
                               detail: "Restaurables depuis le coffre web")
            await loadDuplicates(flow)
        } catch {
            flow.error = Self.describe(error)
        }
    }

    /// Fusionne dans l'élément gardé, puis met les autres à la corbeille.
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
            toast = writeToast("Fusionné dans « \(flow.title(of: keep)) »", detail: Self.mergeDetail(report))
            await loadDuplicates(flow)
        } catch {
            flow.error = Self.describe(error)
        }
    }

    /// « 2 sites, le code, 1 ancien mot de passe ; 2 à la corbeille »
    static func mergeDetail(_ report: MergeReport) -> String {
        var parts: [String] = []
        if report.sites > 0 { parts.append("\(report.sites) site\(report.sites > 1 ? "s" : "")") }
        if report.username { parts.append("l'identifiant") }
        if report.totp { parts.append("le code") }
        if report.notes > 0 { parts.append("des notes") }
        if report.fields > 0 { parts.append("\(report.fields) champ\(report.fields > 1 ? "s" : "")") }
        if report.history > 0 {
            parts.append("\(report.history) ancien\(report.history > 1 ? "s" : "") mot\(report.history > 1 ? "s" : "") de passe")
        }
        let added = parts.isEmpty ? "rien à reprendre" : parts.joined(separator: ", ")
        return "\(added) ; \(report.trashed) à la corbeille"
    }
}
