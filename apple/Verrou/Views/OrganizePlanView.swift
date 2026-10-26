import SwiftUI

extension OrganizeFlag {
    var label: String {
        switch self {
        case .protected: String(localized: "Protected")
        case .shared: String(localized: "Shared vault")
        case .differentPasswords: String(localized: "Different passwords")
        case .keepDiffers: String(localized: "Not the suggested item")
        case .differentUsernames: String(localized: "Different usernames")
        case .otherTotp: String(localized: "Other one-time codes")
        case .passwordsAsFields: String(localized: "Passwords kept as fields")
        }
    }

    var tint: Color {
        switch self {
        case .protected, .differentUsernames: .orange
        case .shared: .blue
        case .differentPasswords, .keepDiffers, .otherTotp, .passwordsAsFields: .secondary
        }
    }

    var help: LocalizedStringKey {
        switch self {
        case .protected: "This item asks for confirmation before it releases a secret: not checked by default."
        case .shared: "This item belongs to a shared vault."
        case .differentPasswords: "The passwords differ: the most recent becomes the current one, the others join the history."
        case .keepDiffers: "Verrou would have kept another item."
        case .differentUsernames: "The usernames differ: these may be two accounts. Not checked by default."
        case .otherTotp: "The one-time codes differ: the kept item keeps its own, the others become fields."
        case .passwordsAsFields: "More passwords than an item's history holds: the ones that do not fit are kept as hidden fields of the kept item. None is lost."
        }
    }
}

extension OrganizePlanFlow.Section {
    var symbol: String {
        switch self {
        case .folders: "folder.badge.plus"
        case .merges: "arrow.triangle.merge"
        case .moves: "folder"
        case .renames: "pencil"
        case .archive: "archivebox"
        case .trash: "trash"
        }
    }
}

/// An agent's reorganization, for the user to review: what Verrou checked,
/// each operation with the agent's reason, and one button (one Touch ID)
/// that applies the checked ones. Nothing is applied by the agent.
struct OrganizePlanView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: OrganizePlanFlow

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            footer
        }
        .frame(width: 680, height: 640)
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "wand.and.stars")
                .accessibilityHidden(true)
                .font(.system(size: 26))
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 4) {
                Text("Reorganize the Vault").font(.title3.weight(.semibold))
                    .layoutMark("sheet-title")
                Text("\(flow.plan.clientName) proposes these changes. Nothing happens until you apply them.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !flow.plan.reason.isEmpty {
                    Text("The agent says: “\(flow.plan.reason)”")
                        .font(.callout.italic())
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 2)
                }
                if flow.phase == .reviewing {
                    HStack(spacing: 6) {
                        ForEach(OrganizePlanFlow.Section.allCases, id: \.self) { section in
                            if flow.count(of: section) > 0 {
                                CountCapsule(text: Self.countText(section, flow.count(of: section)), tint: .secondary)
                            }
                        }
                        Spacer(minLength: 0)
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            Text("Expires in \(OrganizePlanFlow.clock(flow.secondsLeft(now: context.date)))")
                                .font(.caption)
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.top, 2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(16)
    }

    private static func countText(_ section: OrganizePlanFlow.Section, _ n: Int) -> String {
        switch section {
        case .folders: n > 1 ? String(localized: "\(n) new folders") : String(localized: "\(n) new folder")
        case .merges: n > 1 ? String(localized: "\(n) merges") : String(localized: "\(n) merge")
        case .moves: n > 1 ? String(localized: "\(n) moves") : String(localized: "\(n) move")
        case .renames: n > 1 ? String(localized: "\(n) renames") : String(localized: "\(n) rename")
        case .archive: String(localized: "\(n) to archive")
        case .trash: String(localized: "\(n) to trash")
        }
    }

    // MARK: Content

    @ViewBuilder
    private var content: some View {
        switch flow.phase {
        case .reviewing:
            review
        case .applying:
            applying
        case .done:
            result
        case .withdrawn(let reason):
            notice(symbol: "clock.badge.xmark", title: String(localized: "The plan is no longer there"), text: reason)
        case .failed(let reason):
            notice(symbol: "exclamationmark.triangle.fill", title: String(localized: "The plan could not be applied"),
                   text: reason)
        }
    }

    private var review: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 14) {
                ForEach(flow.groups) { group in
                    GroupSection(flow: flow, group: group)
                }
                if !flow.plan.refused.isEmpty {
                    DisclosureGroup("Refused by Verrou (\(flow.plan.refused.count))") {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(flow.plan.refused, id: \.index) { refused in
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(refused.what).font(.callout)
                                    Text(refused.reason).font(.caption).foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                        .padding(.top, 6)
                    }
                    .font(.callout.weight(.medium))
                    .help("Verrou checked these operations against your vault and refused them: they cannot be applied.")
                }
            }
            .padding(16)
        }
    }

    private var applying: some View {
        VStack(spacing: 14) {
            ProgressView().controlSize(.large)
            Text("Applying the changes…").font(.headline)
            if let progress = flow.progress {
                ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1))) {
                    Text("\(progress.done) of \(progress.total)").font(.caption).monospacedDigit()
                }
                .frame(maxWidth: 280)
            }
            Text("Nothing is lost on the way: a merge writes the kept item before it trashes the others.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
        }
        .padding(30)
    }

    private func notice(symbol: String, title: String, text: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: symbol)
                .accessibilityHidden(true)
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text(title).font(.title3.weight(.semibold))
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
                .textSelection(.enabled)
        }
        .padding(30)
    }

    // MARK: Result

    private var result: some View {
        let report = flow.outcome?.report
        return ScrollView {
            VStack(spacing: 14) {
                Image(systemName: report?.failed.isEmpty == false ? "exclamationmark.circle.fill" : "checkmark.seal.fill")
                    .accessibilityHidden(true)
                    .font(.system(size: 40))
                    .foregroundStyle(report?.failed.isEmpty == false ? Color.orange : Color.green)
                Text(flow.undoReport == nil ? "Changes applied" : "Changes undone")
                    .font(.title3.weight(.semibold))
                if let report {
                    let applied = Int(report.applied), unchanged = Int(report.unchanged), queued = Int(report.queued)
                    HStack(spacing: 6) {
                        CountCapsule(text: String(localized: "\(applied) applied"), tint: .green)
                        if unchanged > 0 {
                            CountCapsule(text: String(localized: "\(unchanged) left as they were"), tint: .secondary)
                        }
                        if !report.failed.isEmpty {
                            CountCapsule(text: String(localized: "\(report.failed.count) failed"), tint: .orange)
                        }
                    }
                    if queued > 0 {
                        Text("\(queued) waiting for the server: they go out as soon as it responds")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if !report.failed.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(report.failed, id: \.index) { failure in
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(title(of: failure)).font(.callout)
                                    Text(failure.reason).font(.caption).foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                        .frame(maxWidth: 480, alignment: .leading)
                    }
                }
                undoSection
            }
            .padding(30)
            .frame(maxWidth: .infinity)
        }
    }

    private func title(of failure: OrganizeFailure) -> String {
        let title = flow.plan.ops.first { $0.index == failure.index }?.title ?? ""
        return title.isEmpty ? failure.op : "“\(title)”"
    }

    @ViewBuilder
    private var undoSection: some View {
        if let undone = flow.undoReport {
            VStack(spacing: 4) {
                Text("\(Int(undone.restored)) put back, \(Int(undone.skipped)) left alone because they changed since")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                ForEach(undone.failures, id: \.self) { failure in
                    Text(failure).font(.caption).foregroundStyle(.orange)
                }
                Text("The new folders stay.").font(.caption).foregroundStyle(.secondary)
            }
        } else if flow.undoDeadline != nil {
            VStack(spacing: 6) {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    if flow.canUndo(now: context.date) {
                        Button("Undo") { Task { await model.undoOrganizePlan(flow) } }
                            .disabled(flow.undoing || !model.canEdit)
                            .help("Put back what this plan changed, as long as nothing changed it since")
                        Text("You can undo for \(OrganizePlanFlow.clock(flow.secondsToUndo(now: context.date)))")
                            .font(.caption)
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    } else {
                        Text("It is too late to undo this plan here; trashed items stay restorable from the web vault for 30 days.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                }
                if let error = flow.undoError {
                    Text(error).font(.caption).foregroundStyle(.orange)
                }
            }
        }
    }

    // MARK: Footer

    private var footer: some View {
        HStack(spacing: 10) {
            switch flow.phase {
            case .reviewing:
                Menu("Select") {
                    Button("Check All") { flow.setAll(true) }
                    Button("Uncheck All") { flow.setAll(false) }
                }
                .fixedSize()
                Text("One Touch ID applies the checked changes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Decline") { model.closeOrganizePlan(flow) }
                    .keyboardShortcut(.cancelAction)
                    .help("Apply nothing: the agent is told you declined")
                Button(applyLabel) { Task { await model.applyOrganizePlan(flow) } }
                    // No default action: Return must not apply changes to the
                    // vault, whatever has the focus.
                    .buttonStyle(.borderedProminent)
                    .layoutMark("sheet-primary")
                    .disabled(flow.checkedCount == 0 || !model.canEdit || flow.confirming)
            case .applying:
                Spacer()
            case .done, .withdrawn, .failed:
                Spacer()
                Button("Close") { model.closeOrganizePlan(flow) }
                    .keyboardShortcut(.cancelAction)
                    .keyboardShortcut(.defaultAction)
                    .disabled(flow.undoing)
            }
        }
        .padding(16)
    }

    private var applyLabel: String {
        let n = flow.checkedCount
        return n > 1 ? String(localized: "Apply \(n) Changes") : String(localized: "Apply \(n) Change")
    }
}

/// A group of operations: a heading, then one row each.
private struct GroupSection: View {
    @Bindable var flow: OrganizePlanFlow
    let group: OrganizePlanFlow.Group

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: group.section.symbol)
                    .accessibilityHidden(true)
                    .foregroundStyle(.secondary)
                Text(heading).font(.headline)
            }
            ForEach(group.ops, id: \.index) { op in
                OperationRow(flow: flow, op: op)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.faintFill(0.35), in: RoundedRectangle(cornerRadius: 10))
    }

    private var heading: String {
        switch group.section {
        case .folders: String(localized: "New folders")
        case .merges: String(localized: "Merges")
        case .moves: group.destination.isEmpty ? String(localized: "Take out of their folders")
                                               : String(localized: "Move into “\(group.destination)”")
        case .renames: String(localized: "Renames")
        case .archive: String(localized: "Archive")
        case .trash: String(localized: "Move to the trash")
        }
    }
}

/// One operation: checkbox, what changes (from the vault), what the agent
/// says about it, and what to watch.
private struct OperationRow: View {
    @Bindable var flow: OrganizePlanFlow
    let op: OrganizeOpView

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Toggle("", isOn: Binding(get: { flow.isOn(op) }, set: { flow.set(op, on: $0) }))
                .toggleStyle(.checkbox)
                .labelsHidden()
                .disabled(flow.phase != .reviewing)
                .accessibilityLabel(op.title)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    primary
                    ForEach(op.flags, id: \.self) { flag in
                        Badge(text: flag.label, tint: flag.tint == .secondary ? nil : flag.tint)
                            .help(flag.help)
                    }
                }
                if let secondary {
                    Text(secondary).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let folder = flow.folderToCreate(for: op) {
                    Text("Also creates the folder “\(folder.title)”").font(.caption).foregroundStyle(.secondary)
                }
                if !op.rationale.isEmpty {
                    Text("Agent: \(op.rationale)")
                        .font(.caption.italic())
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private var primary: some View {
        switch op.kind {
        case .rename:
            Text(verbatim: "\(op.from) → \(op.detail)").lineLimit(2)
        default:
            Text(op.title).lineLimit(1)
        }
    }

    private var secondary: String? {
        switch op.kind {
        case .merge:
            let members = String(localized: "Merged in, then trashed: \(op.members.map { "“\($0)”" }.joined(separator: ", "))")
            guard !op.passwordFrom.isEmpty else { return members }
            return members + "\n" + String(localized: "The password of “\(op.passwordFrom)” becomes the current one")
        case .move:
            return op.from.isEmpty ? String(localized: "Now in no folder") : String(localized: "Now in “\(op.from)”")
        case .archive, .trash:
            return op.from.isEmpty ? nil : String(localized: "In “\(op.from)”")
        case .createFolder, .rename:
            return nil
        }
    }
}
