import ActivityKit
import Foundation
import os

/// The Live Activity of the Mac's request shown (`RemoteApprover.current`):
/// Dynamic Island and lock screen, with the Mac's name and the time left.
/// Approve and Deny bring the app back to the request; Face ID shows what
/// is asked and the answer is given there (`ApproveRequestIntent`).
///
/// Started locally, when the app finds the request (in the foreground: the
/// notification of a request is an iCloud alert, which doesn't wake the
/// app). Starting or updating it from a push needs an APNs server holding
/// the activity's push token, which Verrou doesn't have (CloudKit only).
/// Ended when the request is answered (its outcome stays a few seconds),
/// put aside, withdrawn by the Mac or expired; past the expiry, while the app
/// is suspended, it shows "Expired" (`staleDate`) until the app ends it.
@MainActor
final class ApprovalActivities {
    private let log = Logger(subsystem: "app.verrou", category: "remote-approval")

    /// Follows the request shown: one activity at most, the current
    /// request's.
    func update(_ pending: RemoteApprover.Pending?) {
        // Ended ones may still show their outcome for a few seconds.
        let activities = Activity<ApprovalActivityAttributes>.activities
            .filter { $0.activityState == .active || $0.activityState == .stale }
        // Any other request's activity (answered, withdrawn, a previous
        // launch's) ends now.
        for activity in activities where activity.attributes.requestID != pending?.id {
            end(activity, stage: nil)
        }
        guard let pending else { return }
        let existing = activities.first { $0.attributes.requestID == pending.id }
        switch pending.state {
        case .answered(let approved):
            if let existing { end(existing, stage: approved ? .approved : .denied, expires: pending.sealed.expires) }
        case .failed:
            if let existing { end(existing, stage: nil) }
        case .sealed, .ready, .sending:
            guard existing == nil, ActivityAuthorizationInfo().areActivitiesEnabled,
                  pending.sealed.expires > Date() else { return }
            let state = ApprovalActivityAttributes.ContentState(stage: .waiting, expires: pending.sealed.expires)
            do {
                _ = try Activity.request(
                    attributes: ApprovalActivityAttributes(requestID: pending.id, macName: pending.mac.name),
                    content: ActivityContent(state: state, staleDate: pending.sealed.expires),
                    pushType: nil)
            } catch {
                // Not allowed in the background, or turned off in Settings:
                // the approval screen and the notification remain.
                log.notice("Live Activity not started: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// `stage`: the outcome to show for a few seconds; `nil`, removed at
    /// once.
    private func end(_ activity: Activity<ApprovalActivityAttributes>, stage: ApprovalActivityAttributes.ContentState.Stage?,
                     expires: Date = Date()) {
        let content = stage.map {
            ActivityContent(state: ApprovalActivityAttributes.ContentState(stage: $0, expires: expires), staleDate: nil)
        }
        let policy: ActivityUIDismissalPolicy = stage == nil ? .immediate : .after(Date().addingTimeInterval(4))
        Task { await activity.end(content, dismissalPolicy: policy) }
    }
}
