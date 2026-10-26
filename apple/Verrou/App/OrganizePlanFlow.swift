import Foundation
import Observation

/// A reorganization an agent proposed (`verrou mcp`), in review: what the
/// user checks, what is being applied, how it ended, and how long it can
/// still be undone.
///
/// Verrou already checked the plan against the vault (Rust, when it was
/// proposed, and again when it is applied): the operations here passed. The
/// user decides which of them to apply, with one Touch ID. Swift sees titles
/// and folder names only, and the agent's own words, cleaned.
@MainActor
@Observable
final class OrganizePlanFlow: Identifiable {
    enum Phase: Equatable {
        case reviewing
        case applying
        case done
        /// It can no longer be reviewed: it expired, or the agent withdrew it.
        case withdrawn(String)
        case failed(String)
    }

    /// The kinds of operation, in the order the review lists them.
    enum Section: Int, CaseIterable {
        case folders, merges, moves, renames, archive, trash
    }

    /// Operations listed together: a kind, and for moves a destination.
    struct Group: Identifiable {
        let id: String
        let section: Section
        /// Moves: the folder they go into (empty: out of any folder).
        let destination: String
        let ops: [OrganizeOpView]
    }

    /// How long an applied plan can be undone.
    static let undoWindow: TimeInterval = 10 * 60

    let plan: OrganizeReview
    let id: String
    /// When it can no longer be reviewed.
    let expires: Date
    private(set) var phase: Phase = .reviewing
    /// The checked operations, by position in the plan.
    private(set) var checked: Set<UInt32>
    private(set) var progress: (done: Int, total: Int)?
    private(set) var outcome: OrganizeOutcome?
    /// Until when "Undo" is offered.
    private(set) var undoDeadline: Date?
    private(set) var undoReport: UndoReport?
    var undoing = false
    var undoError: String?
    /// Touch ID is being asked for Apply: a second tap does nothing.
    private(set) var confirming = false

    init(plan: OrganizeReview, now: Date = Date()) {
        self.plan = plan
        id = plan.id
        expires = now.addingTimeInterval(TimeInterval(plan.expiresIn))
        checked = Set(plan.ops.filter(\.defaultOn).map(\.index))
        // A move that is checked brings its new folder along.
        for op in plan.ops where checked.contains(op.index) {
            if let folder = op.dependsOn { checked.insert(folder) }
        }
    }

    /// "9:41": a time left, for the countdowns.
    static func clock(_ seconds: Int) -> String {
        "\(seconds / 60):" + String(format: "%02d", seconds % 60)
    }

    // MARK: Review

    /// The operations by section; moves by destination, in the order of a
    /// folder list.
    var groups: [Group] {
        func ops(_ kind: OrganizeKind) -> [OrganizeOpView] { plan.ops.filter { $0.kind == kind } }
        var groups: [Group] = []
        let folders = ops(.createFolder)
        if !folders.isEmpty { groups.append(Group(id: "folders", section: .folders, destination: "", ops: folders)) }
        let merges = ops(.merge)
        if !merges.isEmpty { groups.append(Group(id: "merges", section: .merges, destination: "", ops: merges)) }
        let moves = ops(.move)
        let destinations = Set(moves.map(\.detail))
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        for destination in destinations {
            groups.append(Group(id: "moves:\(destination)", section: .moves, destination: destination,
                                ops: moves.filter { $0.detail == destination }))
        }
        let renames = ops(.rename)
        if !renames.isEmpty { groups.append(Group(id: "renames", section: .renames, destination: "", ops: renames)) }
        let archive = ops(.archive)
        if !archive.isEmpty { groups.append(Group(id: "archive", section: .archive, destination: "", ops: archive)) }
        let trash = ops(.trash)
        if !trash.isEmpty { groups.append(Group(id: "trash", section: .trash, destination: "", ops: trash)) }
        return groups
    }

    func count(of section: Section) -> Int {
        groups.filter { $0.section == section }.reduce(0) { $0 + $1.ops.count }
    }

    func isOn(_ op: OrganizeOpView) -> Bool {
        checked.contains(op.index)
    }

    /// Checks or unchecks an operation. A move into a folder the plan creates
    /// checks the creation too; unchecking the creation unchecks the moves
    /// that wait for it.
    func set(_ op: OrganizeOpView, on: Bool) {
        guard phase == .reviewing else { return }
        if on {
            checked.insert(op.index)
            if let folder = op.dependsOn { checked.insert(folder) }
        } else {
            checked.remove(op.index)
            if op.kind == .createFolder {
                for dependent in plan.ops where dependent.dependsOn == op.index {
                    checked.remove(dependent.index)
                }
            }
        }
    }

    /// Checks or unchecks everything (protected items included: the user asked).
    func setAll(_ on: Bool) {
        guard phase == .reviewing else { return }
        checked = on ? Set(plan.ops.map(\.index)) : []
    }

    /// The creation a move waits for, if it is not checked: what checking the
    /// move would also do.
    func folderToCreate(for op: OrganizeOpView) -> OrganizeOpView? {
        guard let folder = op.dependsOn, !checked.contains(folder) else { return nil }
        return plan.ops.first { $0.index == folder }
    }

    var checkedCount: Int { checked.count }

    /// What the checked operations do that is hard to take back, for the
    /// Touch ID text: items going to the trash, and merges (which trash the
    /// merged copies).
    var destructiveCounts: (trash: Int, merges: Int) {
        let ops = plan.ops.filter { checked.contains($0.index) }
        return (ops.filter { $0.kind == .trash }.count, ops.filter { $0.kind == .merge }.count)
    }

    /// What Touch ID says: how many changes, from whom, and the number of
    /// those that go to the trash or merge items.
    var confirmationPrompt: String {
        let count = checkedCount, client = plan.clientName
        let (trash, merges) = destructiveCounts
        var parts: [String] = []
        if trash > 0 { parts.append(String(localized: "\(trash) to the trash")) }
        if merges > 0 {
            parts.append(merges > 1 ? String(localized: "\(merges) merges") : String(localized: "\(merges) merge"))
        }
        let including: String? = switch parts.count {
        case 0: nil
        case 1: parts[0]
        default: String(localized: "\(parts[0]) and \(parts[1])")
        }
        if let including {
            return count > 1 ? String(localized: "Apply \(count) changes proposed by \(client), including \(including)")
                             : String(localized: "Apply \(count) change proposed by \(client), including \(including)")
        }
        return count > 1 ? String(localized: "Apply \(count) changes proposed by \(client)")
                         : String(localized: "Apply \(count) change proposed by \(client)")
    }

    /// A new plan cannot take this sheet's place while it is being reviewed
    /// or applied, or while its result can still be undone: the user would
    /// lose the Undo.
    func holdsTheSheet(now: Date = Date()) -> Bool {
        switch phase {
        case .reviewing, .applying: true
        case .done: canUndo(now: now) || undoing
        case .withdrawn, .failed: false
        }
    }

    /// What `apply_organize_plan` takes, in plan order.
    var acceptedIndices: [UInt32] { checked.sorted() }

    /// Seconds left to review it.
    func secondsLeft(now: Date = Date()) -> Int {
        max(0, Int(expires.timeIntervalSince(now).rounded(.up)))
    }

    // MARK: Applying

    /// Starts asking for Touch ID: `false` if it is already being asked, or
    /// the plan is not in review (a second tap on Apply does nothing).
    func beginConfirmation() -> Bool {
        guard phase == .reviewing, !confirming else { return false }
        confirming = true
        return true
    }

    func endConfirmation() {
        confirming = false
    }

    func begin() {
        phase = .applying
        confirming = false
        progress = (0, checked.count)
    }

    func advance(done: Int, total: Int) {
        guard phase == .applying else { return }
        progress = (done, total)
    }

    func finish(_ outcome: OrganizeOutcome, now: Date = Date()) {
        self.outcome = outcome
        phase = .done
        progress = nil
        let undo = outcome.undo
        let nothing = undo.trashed.isEmpty && undo.archived.isEmpty && undo.moves.isEmpty && undo.renames.isEmpty
            && undo.merged.isEmpty
        undoDeadline = nothing ? nil : now.addingTimeInterval(Self.undoWindow)
    }

    func fail(_ message: String) {
        phase = .failed(message)
        progress = nil
    }

    /// The plan can no longer be reviewed (only while it is being reviewed:
    /// an application in progress goes on).
    func withdraw(_ message: String) {
        guard phase == .reviewing else { return }
        phase = .withdrawn(message)
    }

    // MARK: Undoing

    func canUndo(now: Date = Date()) -> Bool {
        guard phase == .done, undoReport == nil, !undoing, let deadline = undoDeadline else { return false }
        return now < deadline
    }

    func undone(_ report: UndoReport) {
        undoReport = report
        undoDeadline = nil
    }

    func secondsToUndo(now: Date = Date()) -> Int {
        guard let deadline = undoDeadline else { return 0 }
        return max(0, Int(deadline.timeIntervalSince(now).rounded(.up)))
    }
}
