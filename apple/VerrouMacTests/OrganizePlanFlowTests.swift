import XCTest

/// An agent's reorganization plan in review: what is checked by default,
/// how the new folders and the moves into them follow one another, how the
/// review is grouped, and the life of the sheet (applying, result, undo).
@MainActor
final class OrganizePlanFlowTests: XCTestCase {
    private func op(_ index: UInt32, _ kind: OrganizeKind, title: String = "", detail: String = "", from: String = "",
                    flags: [OrganizeFlag] = [], dependsOn: UInt32? = nil, on: Bool = true) -> OrganizeOpView {
        OrganizeOpView(index: index, kind: kind, title: title, detail: detail, from: from, members: [],
                       passwordFrom: "", rationale: "because", flags: flags, dependsOn: dependsOn, defaultOn: on)
    }

    private func plan(_ ops: [OrganizeOpView], expiresIn: UInt32 = 600) -> OrganizeReview {
        OrganizeReview(id: "abc", clientName: "Coding Agent", reason: "tidy up", expiresIn: expiresIn, ops: ops, refused: [])
    }

    private func outcome(undo: Bool) -> OrganizeOutcome {
        OrganizeOutcome(
            report: OrganizeReport(applied: 2, queued: 0, unchanged: 1, failed: []),
            undo: OrganizeUndo(plan: "abc", expires: 0, trashed: undo ? ["a"] : [], archived: [], moves: [], renames: [],
                               merged: []))
    }

    func testChecksWhatIsCheckedByDefaultAndLeavesProtectedItemsToTheUser() {
        let flow = OrganizePlanFlow(plan: plan([
            op(0, .rename, title: "A"),
            op(1, .rename, title: "B", flags: [.protected], on: false),
            op(2, .merge, title: "C", flags: [.differentUsernames], on: false),
            op(3, .archive, title: "D"),
        ]))
        XCTAssertEqual(flow.acceptedIndices, [0, 3])
        XCTAssertEqual(flow.checkedCount, 2)
        XCTAssertFalse(flow.isOn(flow.plan.ops[1]))
    }

    func testAMoveBringsItsNewFolderAndUncheckingTheFolderUnchecksTheMoves() {
        let ops = [
            op(0, .createFolder, title: "Bank"),
            op(1, .move, title: "Visa", detail: "Bank", dependsOn: 0),
            op(2, .move, title: "Mortgage", detail: "Bank", dependsOn: 0),
            op(3, .move, title: "Gym", detail: "Sport"),
        ]
        let flow = OrganizePlanFlow(plan: plan(ops))
        XCTAssertEqual(flow.acceptedIndices, [0, 1, 2, 3])
        // The folder goes: the moves that wait for it go with it, not the others.
        flow.set(ops[0], on: false)
        XCTAssertEqual(flow.acceptedIndices, [3])
        // Checking a move checks the folder it needs, not the other move.
        XCTAssertEqual(flow.folderToCreate(for: ops[1])?.title, "Bank")
        flow.set(ops[1], on: true)
        XCTAssertEqual(flow.acceptedIndices, [0, 1, 3])
        XCTAssertNil(flow.folderToCreate(for: ops[1]), "nothing left to bring along")
        // A folder alone is fine.
        flow.set(ops[1], on: false)
        XCTAssertEqual(flow.acceptedIndices, [0, 3])
    }

    func testAFolderNeededByACheckedMoveIsCheckedFromTheStart() {
        // Defensive: Rust leaves folder creations on, but a plan that did not
        // would still not leave a move without its folder.
        let ops = [op(0, .createFolder, title: "Bank", on: false), op(1, .move, title: "Visa", detail: "Bank", dependsOn: 0)]
        XCTAssertEqual(OrganizePlanFlow(plan: plan(ops)).acceptedIndices, [0, 1])
    }

    func testGroupsFollowTheOrderOfTheReviewAndMovesGoByDestination() {
        let flow = OrganizePlanFlow(plan: plan([
            op(0, .trash, title: "T"),
            op(1, .move, title: "M1", detail: "Work"),
            op(2, .rename, title: "R"),
            op(3, .move, title: "M2", detail: ""),
            op(4, .createFolder, title: "F"),
            op(5, .move, title: "M3", detail: "Work"),
            op(6, .merge, title: "G"),
            op(7, .archive, title: "A"),
            op(8, .move, title: "M4", detail: "Admin"),
        ]))
        let groups = flow.groups
        XCTAssertEqual(groups.map(\.section), [.folders, .merges, .moves, .moves, .moves, .renames, .archive, .trash])
        XCTAssertEqual(groups.filter { $0.section == .moves }.map(\.destination), ["", "Admin", "Work"])
        XCTAssertEqual(groups.first { $0.destination == "Work" }?.ops.map(\.index), [1, 5])
        XCTAssertEqual(flow.count(of: .moves), 4)
        XCTAssertEqual(flow.count(of: .renames), 1)
    }

    func testSelectAllAndNone() {
        let ops = [op(0, .rename, title: "A"), op(1, .rename, title: "B", flags: [.protected], on: false)]
        let flow = OrganizePlanFlow(plan: plan(ops))
        flow.setAll(true)
        XCTAssertEqual(flow.acceptedIndices, [0, 1], "protected items too, when the user asks")
        flow.setAll(false)
        XCTAssertEqual(flow.checkedCount, 0)
    }

    func testTheReviewCountsDown() {
        let now = Date(timeIntervalSince1970: 1_000)
        let flow = OrganizePlanFlow(plan: plan([op(0, .rename)], expiresIn: 600), now: now)
        XCTAssertEqual(flow.secondsLeft(now: now), 600)
        XCTAssertEqual(flow.secondsLeft(now: now.addingTimeInterval(125.4)), 475)
        XCTAssertEqual(flow.secondsLeft(now: now.addingTimeInterval(900)), 0)
        XCTAssertEqual(OrganizePlanFlow.clock(475), "7:55")
        XCTAssertEqual(OrganizePlanFlow.clock(5), "0:05")
    }

    func testApplyingThenTheResultAndTheUndoWindow() {
        let flow = OrganizePlanFlow(plan: plan([op(0, .rename), op(1, .trash)]))
        let applied = Date(timeIntervalSince1970: 5_000)
        flow.begin()
        XCTAssertEqual(flow.phase, .applying)
        XCTAssertEqual(flow.progress?.total, 2)
        flow.advance(done: 1, total: 2)
        XCTAssertEqual(flow.progress?.done, 1)
        // Nothing is checked or unchecked while it is applied.
        flow.set(flow.plan.ops[0], on: false)
        XCTAssertEqual(flow.checkedCount, 2)
        flow.finish(outcome(undo: true), now: applied)
        XCTAssertEqual(flow.phase, .done)
        XCTAssertNil(flow.progress)
        XCTAssertTrue(flow.canUndo(now: applied.addingTimeInterval(599)))
        XCTAssertFalse(flow.canUndo(now: applied.addingTimeInterval(600)), "ten minutes")
        XCTAssertEqual(flow.secondsToUndo(now: applied.addingTimeInterval(100)), 500)
        flow.undone(UndoReport(restored: 1, skipped: 0, failures: []))
        XCTAssertFalse(flow.canUndo(now: applied), "once")
        XCTAssertEqual(flow.secondsToUndo(now: applied), 0)
    }

    func testThereIsNoUndoWhenNothingWasChanged() {
        let flow = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        flow.begin()
        flow.finish(outcome(undo: false))
        XCTAssertNil(flow.undoDeadline)
        XCTAssertFalse(flow.canUndo())
    }

    func testAPlanThatIsWithdrawnWhileReviewedSaysSoButOneBeingAppliedGoesOn() {
        let reviewed = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        reviewed.withdraw("the agent withdrew the plan")
        XCTAssertEqual(reviewed.phase, .withdrawn("the agent withdrew the plan"))
        // Nothing can be checked or applied from a withdrawn plan.
        reviewed.setAll(false)
        XCTAssertEqual(reviewed.checkedCount, 1)
        let applying = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        applying.begin()
        applying.withdraw("expired")
        XCTAssertEqual(applying.phase, .applying)
        applying.fail("the vault is locked")
        XCTAssertEqual(applying.phase, .failed("the vault is locked"))
        XCTAssertNil(applying.progress)
    }

    // MARK: Defaults, a second plan, a second tap

    func testTheTrashAndAnOrganizationsItemsAreNotCheckedByDefaultButTheUserMayCheckThem() {
        // What Rust decides (`default_on`): the trash is never checked; a merge
        // or an archive of a shared vault's items neither.
        let ops = [
            op(0, .rename, title: "A"),
            op(1, .trash, title: "T", on: false),
            op(2, .merge, title: "M", flags: [.shared], on: false),
            op(3, .archive, title: "Z", flags: [.shared], on: false),
            op(4, .rename, title: "S", flags: [.shared]),
            op(5, .merge, title: "G", flags: [.passwordsAsFields]),
        ]
        let flow = OrganizePlanFlow(plan: plan(ops))
        XCTAssertEqual(flow.acceptedIndices, [0, 4, 5])
        XCTAssertEqual(flow.destructiveCounts.trash, 0)
        XCTAssertEqual(flow.destructiveCounts.merges, 1)
        flow.set(ops[1], on: true)
        XCTAssertEqual(flow.acceptedIndices, [0, 1, 4, 5], "the user can check the trash")
        XCTAssertEqual(flow.destructiveCounts.trash, 1)
    }

    func testTouchIDNamesWhatGoesToTheTrashAndWhatIsMerged() {
        let ops = [
            op(0, .rename, title: "A"),
            op(1, .trash, title: "T1", on: false),
            op(2, .trash, title: "T2", on: false),
            op(3, .merge, title: "M"),
        ]
        let flow = OrganizePlanFlow(plan: plan(ops))
        XCTAssertEqual(flow.confirmationPrompt, "Apply 2 changes proposed by Coding Agent, including 1 merge")
        flow.set(ops[1], on: true)
        flow.set(ops[2], on: true)
        XCTAssertEqual(flow.confirmationPrompt,
                       "Apply 4 changes proposed by Coding Agent, including 2 to the trash and 1 merge")
        flow.set(ops[3], on: false)
        XCTAssertEqual(flow.confirmationPrompt, "Apply 3 changes proposed by Coding Agent, including 2 to the trash")
        flow.setAll(false)
        flow.set(ops[0], on: true)
        XCTAssertEqual(flow.confirmationPrompt, "Apply 1 change proposed by Coding Agent",
                       "nothing destructive, nothing said")
    }

    func testASecondTapOnApplyWhileTouchIDIsUpDoesNothing() {
        let flow = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        XCTAssertTrue(flow.beginConfirmation())
        XCTAssertTrue(flow.confirming)
        XCTAssertFalse(flow.beginConfirmation(), "the second tap")
        flow.endConfirmation()
        XCTAssertTrue(flow.beginConfirmation(), "asked again once the first is over")
        flow.begin()
        XCTAssertFalse(flow.confirming)
        XCTAssertFalse(flow.beginConfirmation(), "nor once it is being applied")
        flow.finish(outcome(undo: true))
        XCTAssertFalse(flow.beginConfirmation(), "nor from the result")
    }

    func testANewPlanDoesNotTakeTheSheetOfOneInReviewApplyingOrStillUndoable() {
        let applied = Date(timeIntervalSince1970: 5_000)
        let reviewing = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        XCTAssertTrue(reviewing.holdsTheSheet(now: applied))
        let applying = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        applying.begin()
        XCTAssertTrue(applying.holdsTheSheet(now: applied))
        // Done, undo still available: it holds the sheet, until the window ends.
        let done = OrganizePlanFlow(plan: plan([op(0, .trash)]))
        done.begin()
        done.finish(outcome(undo: true), now: applied)
        XCTAssertTrue(done.holdsTheSheet(now: applied.addingTimeInterval(599)))
        XCTAssertFalse(done.holdsTheSheet(now: applied.addingTimeInterval(601)))
        // Done and undone, or with nothing to undo: nothing to protect.
        done.undone(UndoReport(restored: 1, skipped: 0, failures: []))
        XCTAssertFalse(done.holdsTheSheet(now: applied))
        let nothing = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        nothing.begin()
        nothing.finish(outcome(undo: false), now: applied)
        XCTAssertFalse(nothing.holdsTheSheet(now: applied))
        // Withdrawn or failed.
        let withdrawn = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        withdrawn.withdraw("expired")
        XCTAssertFalse(withdrawn.holdsTheSheet())
        let failed = OrganizePlanFlow(plan: plan([op(0, .rename)]))
        failed.begin()
        failed.fail("locked")
        XCTAssertFalse(failed.holdsTheSheet())
    }

    func testAResultWithOnlyMergesCanStillBeUndone() {
        let flow = OrganizePlanFlow(plan: plan([op(0, .merge)]))
        flow.begin()
        let merged = OrganizeOutcome(
            report: OrganizeReport(applied: 1, queued: 0, unchanged: 0, failed: []),
            undo: OrganizeUndo(plan: "abc", expires: 0, trashed: [], archived: [], moves: [], renames: [],
                               merged: ["kept"]))
        flow.finish(merged)
        XCTAssertNotNil(flow.undoDeadline)
    }
}
