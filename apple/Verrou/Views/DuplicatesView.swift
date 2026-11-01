import SwiftUI

/// Sidebar entry, under the audit: opens the duplicate cleanup.
struct DuplicatesSidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        // A sheet rather than a pane: never highlighted.
        SidebarPaneButton(title: String(localized: "Duplicates"), symbol: "square.on.square.dashed",
                          help: String(localized: "Clean up the vault's duplicates")) {
            model.openDuplicates()
        }
    }
}

extension DuplicateConfidence {
    var label: String {
        switch self {
        case .certain: String(localized: "Certain")
        case .probable: String(localized: "Probable")
        case .review: String(localized: "To check")
        }
    }

    var tint: Color {
        switch self {
        case .certain: .green
        case .probable: .orange
        case .review: .secondary
        }
    }

    var help: LocalizedStringKey {
        switch self {
        case .certain: "Same site, same username, same password: the copies are checked."
        case .probable: "Very similar, but one difference (password, missing username): to confirm."
        case .review: "Only a resemblance: check before deleting."
        }
    }
}

/// Vault duplicates, ranked by the Rust core: certain, probable, to check.
/// In each group, the kept item (passkeys, attachments, one-time code, the
/// most recent, the most complete) receives the others through "Merge"; the
/// certain copies are checked for the trash, restorable from the web vault.
struct DuplicatesView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: DuplicatesFlow
    @State private var confirmTrash = false
    @State private var merging: DuplicateGroupView?

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if !flow.loaded {
                ProgressView("Looking for duplicates…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if flow.visible.isEmpty {
                ContentUnavailableView(
                    "No duplicates", systemImage: "checkmark.seal",
                    description: Text(flow.ignoredCount > 0
                        ? "The remaining groups are ignored."
                        : "No item looks like another: no site, title or username in common."))
                    .frame(maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(flow.visible, id: \.key) { group in
                            GroupView(flow: flow, group: group,
                                      merge: { merging = group },
                                      trash: { Task { await model.trashDuplicates(flow, in: group) } })
                        }
                    }
                    .padding(16)
                }
            }

            Divider()
            footer
        }
        .frame(width: 680, height: 640)
        .confirmationDialog(trashQuestion, isPresented: $confirmTrash) {
            Button("Move to Trash", role: .destructive) {
                Task { await model.trashDuplicates(flow) }
            }
        } message: {
            Text("You can restore them from the Trash.")
        }
        .confirmationDialog(mergeTitle, isPresented: Binding(
            get: { merging != nil }, set: { if !$0 { merging = nil } })
        ) {
            Button("Merge") {
                if let group = merging {
                    Task { await model.mergeDuplicates(flow, group: group) }
                }
            }
        } message: {
            Text("Sites, one-time code, notes, fields and old passwords join the kept item; the most recent password stays the current password. The others then go to the Trash, where you can restore them.")
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "square.on.square.dashed")
                .accessibilityHidden(true)
                .font(.system(size: 26))
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 4) {
                Text("Duplicates").font(.title3.weight(.semibold))
                    .layoutMark("sheet-title")
                Text("The same account, imported several times: addresses, titles and usernames compared. The certain copies are checked.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if flow.loaded, !flow.visible.isEmpty {
                    HStack(spacing: 8) {
                        ForEach([DuplicateConfidence.certain, .probable, .review], id: \.self) { level in
                            ConfidenceCount(level: level, count: flow.count(level))
                        }
                    }
                    .padding(.top, 2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(16)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Text(status)
                .font(.caption)
                .foregroundStyle(flow.error == nil ? Color.secondary : Color.orange)
                .fixedSize(horizontal: false, vertical: true)
            if flow.ignoredCount > 0 {
                Button(flow.ignoredCount > 1 ? "Show \(flow.ignoredCount) Ignored Groups Again" : "Show \(flow.ignoredCount) Ignored Group Again") {
                    flow.clearIgnored()
                }
                .buttonStyle(.link)
                .font(.caption)
                .help("Ignored groups are remembered on this Mac")
            }
            Spacer()
            if flow.busy { ProgressView().controlSize(.small) }
            Button("Close") { model.duplicatesFlow = nil }
                .keyboardShortcut(.cancelAction)
            Button(trashLabel) { confirmTrash = true }
                .buttonStyle(.borderedProminent)
                .layoutMark("sheet-primary")
                .disabled(flow.selected.isEmpty || flow.busy || !model.canEdit)
                .help(model.canEdit ? "All the checked items, in all groups" : "Mock vault: read-only")
        }
        .padding(16)
    }

    private var trashLabel: String {
        let n = flow.selected.count
        return n > 1 ? String(localized: "Move \(n) Items to Trash") : String(localized: "Move \(n) Item to Trash")
    }

    private var trashQuestion: String {
        let n = flow.selected.count
        return n > 1 ? String(localized: "Move \(n) items to the trash?") : String(localized: "Move \(n) item to the trash?")
    }

    private var mergeTitle: String {
        guard let group = merging else { return String(localized: "Merge?") }
        let n = flow.mergeTargets(in: group).count
        let kept = flow.title(of: flow.keptID(group))
        return n > 1 ? String(localized: "Merge \(n) items into “\(kept)”?") : String(localized: "Merge \(n) item into “\(kept)”?")
    }

    private var status: String {
        if let error = flow.error { return error }
        let n = flow.visible.count
        return n == 0 ? "" : n > 1 ? String(localized: "\(n) duplicate groups") : String(localized: "\(n) duplicate group")
    }
}

private struct ConfidenceCount: View {
    let level: DuplicateConfidence
    let count: Int

    var body: some View {
        CountCapsule(text: text, tint: level.tint)
            .help(level.help)
    }

    private var text: String {
        let many = count > 1
        switch level {
        case .certain: return many ? String(localized: "\(count) certain groups") : String(localized: "\(count) certain group")
        case .probable: return many ? String(localized: "\(count) probable groups") : String(localized: "\(count) probable group")
        case .review: return String(localized: "\(count) to check")
        }
    }
}

private struct ConfidenceBadge: View {
    let level: DuplicateConfidence

    var body: some View {
        Badge(text: level.label, tint: level == .review ? nil : level.tint)
            .help(level.help)
    }
}

private struct GroupView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: DuplicatesFlow
    let group: DuplicateGroupView
    let merge: () -> Void
    let trash: () -> Void

    var body: some View {
        let keep = flow.keptID(group)
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                ConfidenceBadge(level: group.confidence)
                Text(group.label).font(.headline).lineLimit(1)
                if !group.username.isEmpty {
                    Text(group.username).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
            }
            Text(CoreText.duplicateReason(group.reason))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(group.members, id: \.item.id) { member in
                MemberRow(flow: flow, group: group, member: member, kept: member.item.id == keep)
            }
            HStack(spacing: 8) {
                if group.mergeable {
                    Button("Merge and Move the Others to Trash", action: merge)
                        .disabled(flow.mergeTargets(in: group).isEmpty || flow.busy || !model.canEdit)
                        .help(mergeHelp)
                }
                Button("Move the Selection to Trash", action: trash)
                    .disabled(flow.checked(in: group).isEmpty || flow.busy || !model.canEdit)
                Spacer()
                Button("Ignore This Group") { flow.ignore(group) }
                    .help("Stop suggesting these items together (remembered on this Mac)")
            }
            .controlSize(.small)
            .padding(.top, 2)
        }
        .padding(12)
        .background(Theme.faintFill(0.35), in: RoundedRectangle(cornerRadius: Theme.radiusLarge))
    }

    private var mergeHelp: String {
        guard model.canEdit else { return String(localized: "Mock vault: read-only") }
        let targets = flow.mergeTargets(in: group)
        if targets.isEmpty { return String(localized: "Check the items to merge") }
        let names = targets.map { String(localized: "“\(flow.title(of: $0))”") }.joined(separator: ", ")
        return String(localized: "Merges \(names) into the kept item")
    }
}

/// An item: checkbox (checking the kept item keeps another one), title,
/// username, site, date, and why it looks like the kept item.
private struct MemberRow: View {
    @Bindable var flow: DuplicatesFlow
    let group: DuplicateGroupView
    let member: DuplicateMemberView
    let kept: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Toggle("", isOn: Binding(
                get: { flow.selected.contains(member.item.id) },
                set: { flow.toggle(member.item.id, $0, in: group) })
            )
            .toggleStyle(.checkbox)
            .labelsHidden()
            .disabled(kept && replacement == nil)
            .help(checkboxHelp)
            .padding(.top, 4)
            ItemIcon(summary: member.item, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 8) {
                    Text(member.item.title).lineLimit(1)
                    if kept {
                        Text("To keep")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(Theme.accent.opacity(0.18), in: Capsule())
                    } else if let level = member.confidence, level != group.confidence || level == .probable {
                        Text(level == .probable ? String(localized: "Suggested") : level.label)
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(level.tint)
                    }
                }
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if !kept, !member.reason.isEmpty {
                    Text(CoreText.duplicateReason(member.reason))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }
            }
            Spacer(minLength: 4)
            if member.item.hasTotp {
                Image(systemName: "clock.badge.checkmark").font(.caption).foregroundStyle(.teal)
                    .accessibilityLabel("One-time code")
                    .help("One-time code")
                    .padding(.top, 4)
            }
            if !kept {
                Button("Keep") { flow.keep(member.item.id, in: group) }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .help("Keep this item rather than the suggested one")
                    .padding(.top, 4)
            }
        }
    }

    private var replacement: String? {
        flow.replacement(for: member.item.id, in: group)
    }

    private var checkboxHelp: String {
        guard kept else { return String(localized: "Check to move to the trash") }
        guard let next = replacement else { return String(localized: "At least one item of the group must be kept") }
        return String(localized: "Check to move to the trash and keep “\(flow.title(of: next))” instead")
    }

    private var detail: String {
        let modified = Date(timeIntervalSince1970: TimeInterval(member.item.modified))
            .formatted(date: .abbreviated, time: .omitted)
        return [member.item.subtitle, member.item.host ?? "", member.item.folder.map { String(localized: "folder \($0)") } ?? "",
                String(localized: "modified on \(modified)")]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }
}
