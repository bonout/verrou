import ActivityKit
import AppIntents
import SwiftUI
import WidgetKit

/// A request from the Mac, on the lock screen and in the Dynamic Island:
/// the Mac's name, the time left, and Approve / Deny, which open Verrou on
/// the request (Face ID shows what is asked; the answer is given there).
struct ApprovalLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: ApprovalActivityAttributes.self) { context in
            ApprovalBanner(context: context)
                .padding(16)
                .activityBackgroundTint(Color(.systemBackground).opacity(0.6))
                .widgetURL(VerrouLink.approval.url)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Image(systemName: "laptopcomputer.and.iphone")
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(Color.accentColor)
                        .accessibilityHidden(true)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    ApprovalCountdown(context: context)
                        .font(.title3.monospacedDigit().weight(.semibold))
                }
                DynamicIslandExpandedRegion(.center) {
                    Text("Request from “\(context.attributes.macName)”")
                        .font(.headline)
                        .lineLimit(1)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    ApprovalActions(context: context)
                }
            } compactLeading: {
                Image(systemName: "laptopcomputer.and.iphone")
                    .foregroundStyle(Color.accentColor)
                    .accessibilityLabel(Text("Request from “\(context.attributes.macName)”"))
            } compactTrailing: {
                ApprovalCountdown(context: context)
                    .font(.caption.monospacedDigit().weight(.semibold))
                    .frame(maxWidth: 44)
            } minimal: {
                Image(systemName: "laptopcomputer.and.iphone")
                    .foregroundStyle(Color.accentColor)
                    .accessibilityLabel(Text("Request from “\(context.attributes.macName)”"))
            }
            .widgetURL(VerrouLink.approval.url)
            .keylineTint(Color.accentColor)
        }
    }
}

/// The lock screen's banner.
private struct ApprovalBanner: View {
    let context: ActivityViewContext<ApprovalActivityAttributes>

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "laptopcomputer.and.iphone")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Color.accentColor)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Request from “\(context.attributes.macName)”")
                        .font(.headline)
                        .lineLimit(1)
                    Text("Face ID shows what is asked.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                ApprovalCountdown(context: context)
                    .font(.title3.monospacedDigit().weight(.semibold))
            }
            ApprovalActions(context: context)
        }
    }
}

/// Time left before the Mac stops waiting; past it, "Expired".
private struct ApprovalCountdown: View {
    let context: ActivityViewContext<ApprovalActivityAttributes>

    var body: some View {
        let expires = context.state.expires
        if context.state.stage != .waiting || context.isStale || expires <= Date() {
            EmptyView()
        } else {
            Text(timerInterval: Date()...expires, countsDown: true)
                .multilineTextAlignment(.trailing)
                .foregroundStyle(Color.accentColor)
        }
    }
}

/// Approve and Deny while the request waits; its outcome afterwards.
private struct ApprovalActions: View {
    let context: ActivityViewContext<ApprovalActivityAttributes>

    var body: some View {
        switch context.state.stage {
        case .approved:
            Label("Approved", systemImage: "checkmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.green)
        case .denied:
            Label("Denied", systemImage: "xmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.secondary)
        case .waiting where context.isStale || context.state.expires <= Date():
            Label("Expired", systemImage: "clock.badge.xmark")
                .font(.headline)
                .foregroundStyle(.secondary)
        case .waiting:
            HStack(spacing: 10) {
                Button(intent: DenyRequestIntent(requestID: context.attributes.requestID)) {
                    Text("Deny")
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                }
                .tint(.secondary)
                Button(intent: ApproveRequestIntent(requestID: context.attributes.requestID)) {
                    Text("Approve")
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                }
                .tint(Color.accentColor)
            }
            .buttonStyle(.borderedProminent)
        }
    }
}

#Preview("Lock screen", as: .content, using: ApprovalActivityAttributes(requestID: "1", macName: "MacBook Pro")) {
    ApprovalLiveActivity()
} contentStates: {
    ApprovalActivityAttributes.ContentState(stage: .waiting, expires: .now.addingTimeInterval(80))
    ApprovalActivityAttributes.ContentState(stage: .approved, expires: .now.addingTimeInterval(80))
}

#Preview("Island", as: .dynamicIsland(.expanded), using: ApprovalActivityAttributes(requestID: "1", macName: "MacBook Pro")) {
    ApprovalLiveActivity()
} contentStates: {
    ApprovalActivityAttributes.ContentState(stage: .waiting, expires: .now.addingTimeInterval(80))
}
