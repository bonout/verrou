import AppKit
import Foundation

/// An agent's reorganization plan (`verrou mcp`, see `OrganizePlanFlow`):
/// shown here for review, applied with one Touch ID, undone for ten minutes.
extension AppModel {
    // MARK: Organizing with an agent

    /// Verrou checked a plan an agent proposed: show it for review. A plan is
    /// reviewed at the Mac, by someone in front of it: away (screen locked, no
    /// input), it is declined (the agent is told only that plans are reviewed
    /// at the Mac, not whether anyone is there). A plan that arrives while
    /// another is being reviewed, applied or can still be undone is declined
    /// as well: it never takes its sheet, and the Undo, away.
    func organizePlanProposed(_ plan: OrganizeReview) {
        guard canEdit else {
            session.declineOrganizePlan(id: plan.id, away: false)
            return
        }
        if let current = organizePlan, current.holdsTheSheet() {
            session.declineOrganizePlanBusy(id: plan.id)
            return
        }
        if remote?.isAway == true {
            session.declineOrganizePlan(id: plan.id, away: true)
            return
        }
        // The app comes to the front only for a plan that is to be reviewed.
        if let previous = organizePlan { session.organizePlanClosed(id: previous.id) }
        let flow = OrganizePlanFlow(plan: plan)
        organizePlan = flow
        NSApp.activate()
        showMainWindow()
    }

    /// The plan can no longer be reviewed (it expired, or the agent withdrew
    /// it): the sheet says so.
    func organizePlanWithdrawn(id: String, message: String) {
        guard let flow = organizePlan, flow.id == id else { return }
        flow.withdraw(message)
    }

    /// Touch ID, then the checked operations.
    func applyOrganizePlan(_ flow: OrganizePlanFlow) async {
        guard canEdit, flow.phase == .reviewing, flow.checkedCount > 0, flow.beginConfirmation() else { return }
        let confirmed = await Biometrics.confirm(reason: flow.confirmationPrompt)
        flow.endConfirmation()
        guard confirmed else { return }
        // The plan may have expired while Touch ID was up.
        guard flow.phase == .reviewing else { return }
        flow.begin()
        do {
            let outcome = try await session.applyOrganizePlan(id: flow.id, accepted: flow.acceptedIndices,
                                                              progress: OrganizeProgressRelay(flow: flow))
            flow.finish(outcome)
            afterWrite(select: nil)
            pushChanges()
        } catch {
            flow.fail(Self.describe(error))
            afterWrite(select: nil)
        }
    }

    /// Closes the sheet. A plan still in review is declined: the agent is
    /// told, and does not insist.
    func closeOrganizePlan(_ flow: OrganizePlanFlow) {
        if flow.phase == .reviewing {
            session.declineOrganizePlan(id: flow.id, away: false)
        }
        // The agent may propose another plan now; what undoes this one goes.
        session.organizePlanClosed(id: flow.id)
        if organizePlan?.id == flow.id { organizePlan = nil }
    }

    /// Puts back what the plan changed: no Touch ID, it only undoes what was
    /// just approved.
    func undoOrganizePlan(_ flow: OrganizePlanFlow) async {
        guard canEdit, flow.canUndo(), let undo = flow.outcome?.undo else { return }
        flow.undoing = true
        flow.undoError = nil
        defer { flow.undoing = false }
        do {
            let report = try await session.undoOrganizePlan(id: flow.id, undo: undo,
                                                            progress: OrganizeProgressRelay(flow: nil))
            flow.undone(report)
            afterWrite(select: nil)
            pushChanges()
        } catch {
            flow.undoError = Self.describe(error)
        }
    }
}

/// Progress sent by Rust from its thread: move to the main thread.
private final class OrganizeProgressRelay: BulkProgress, @unchecked Sendable {
    private weak var flow: OrganizePlanFlow?

    init(flow: OrganizePlanFlow?) {
        self.flow = flow
    }

    func progress(done: UInt32, total: UInt32) {
        DispatchQueue.main.async { [weak flow] in
            MainActor.assumeIsolated { flow?.advance(done: Int(done), total: Int(total)) }
        }
    }
}
