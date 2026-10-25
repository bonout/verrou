import SwiftUI

/// Review of an import: what is new, already present, in conflict, skipped;
/// one choice per conflict; the folder where the created items go. No
/// secret is shown: titles, usernames and sites only.
struct ImportView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: ImportFlow

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            footer
        }
        .frame(width: 640, height: 620)
    }

    // MARK: Header and footer

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "square.and.arrow.down.on.square.fill")
                .accessibilityHidden(true)
                .font(.system(size: 26))
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(flow.review.map { String(localized: "Import from \($0.source)") } ?? String(localized: "Import Passwords"))
                    .font(.title3.weight(.semibold))
                    .layoutMark("sheet-title")
                Text(flow.url.lastPathComponent + (flow.review.map { " · \(CoreText.localized($0.formatLabel))" } ?? ""))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            if flow.review != nil {
                formatMenu
            }
        }
        .padding(16)
    }

    /// Read the file again in another format (detection fooled).
    private var formatMenu: some View {
        Menu("Format") {
            ForEach(ImportFlow.formats, id: \.self) { format in
                Button(CoreText.localized(importFormatLabel(format: format))) {
                    flow.format = format
                    Task { await model.readImport(flow) }
                }
            }
        }
        .fixedSize()
        .help("Read the file again in another format")
    }

    private var footer: some View {
        HStack(spacing: 10) {
            switch flow.stage {
            case .review:
                Text("The export file contains your passwords in the clear: delete it after the import.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Cancel") { model.closeImport() }
                    .keyboardShortcut(.cancelAction)
                Button(importLabel) { Task { await model.commitImport(flow) } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .layoutMark("sheet-primary")
                    .disabled(flow.writeCount == 0)
            case .done:
                Button("Show the File in the Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([flow.url])
                }
                Spacer()
                Button("Done") { model.closeImport() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            case .importing:
                Spacer()
            case .reading, .failed:
                Spacer()
                Button("Cancel") { model.closeImport() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
    }

    private var importLabel: String {
        let n = flow.writeCount
        return n > 1 ? String(localized: "Import \(n) Items") : String(localized: "Import \(n) Item")
    }

    // MARK: Content

    @ViewBuilder
    private var content: some View {
        switch flow.stage {
        case .reading:
            ProgressView("Reading the file…")
        case .importing(let count):
            ProgressView(count > 1 ? "Encrypting and uploading \(count) items…" : "Encrypting and uploading \(count) item…")
        case .failed(let message):
            FailedImportView(flow: flow, message: message)
        case .review(let review):
            ReviewList(flow: flow, review: review)
        case .done(let outcome):
            ImportDoneView(outcome: outcome)
        }
    }
}

/// Couldn't read: the message, and the format to choose by hand.
private struct FailedImportView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: ImportFlow
    let message: String
    @State private var format: ImportFormat = .applePasswords

    var body: some View {
        VStack(spacing: 14) {
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .multilineTextAlignment(.center)
            HStack {
                Picker("Format", selection: $format) {
                    ForEach(ImportFlow.formats, id: \.self) { format in
                        Text(CoreText.localized(importFormatLabel(format: format))).tag(format)
                    }
                }
                .fixedSize()
                Button("Read Again") {
                    flow.format = format
                    Task { await model.readImport(flow) }
                }
            }
        }
        .padding(30)
        .onAppear { if let chosen = flow.format { format = chosen } }
    }
}

/// Report: items written, and those that weren't.
private struct ImportDoneView: View {
    let outcome: ImportOutcome

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Label(createdText + ", " + updatedText, systemImage: "checkmark.circle.fill")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.green)
                Text("The export file contains your passwords in the clear. Delete it, then empty the Finder's trash.")
                    .foregroundStyle(.secondary)
                if !outcome.failures.isEmpty {
                    Text("Not imported").font(.headline).padding(.top, 6)
                    ForEach(Array(outcome.failures.enumerated()), id: \.offset) { _, failure in
                        SkippedRow(skipped: failure)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
    }

    private var createdText: String {
        let n = Int(outcome.created)
        return n > 1 ? String(localized: "\(n) items created") : String(localized: "\(n) item created")
    }

    private var updatedText: String {
        let n = Int(outcome.updated)
        return n > 1 ? String(localized: "\(n) items completed") : String(localized: "\(n) item completed")
    }
}

private struct SkippedRow: View {
    let skipped: ImportSkipped

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(CoreText.title(skipped.title)).lineLimit(1)
            Spacer()
            Text(CoreText.message(skipped.reason)).font(.callout).foregroundStyle(.secondary).lineLimit(2)
        }
        .padding(.vertical, 2)
    }
}

/// The review: report, conflicts to settle, collapsed lists, destination.
private struct ReviewList: View {
    @Bindable var flow: ImportFlow
    let review: ImportReview

    private func indices(_ statuses: Set<ImportStatus>) -> [Int] {
        review.entries.indices.filter { statuses.contains(review.entries[$0].status) }
    }

    var body: some View {
        let fresh = indices([.new])
        let present = indices([.alreadyPresent, .repeatedInFile])
        let conflicts = indices([.newPassword, .conflictInFile, .addsCode, .similar])
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    CountTile(count: fresh.count, label: "new", tint: .green)
                    CountTile(count: present.count, label: "already present", tint: .secondary)
                    CountTile(count: indices([.newPassword, .conflictInFile]).count,
                              label: "different password", tint: .orange)
                    CountTile(count: indices([.addsCode, .similar]).count, label: "to complete", tint: .teal)
                    CountTile(count: review.skipped.count, label: "skipped", tint: .secondary)
                }

                if let error = flow.error {
                    Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }

                if !conflicts.isEmpty {
                    Text("To decide").font(.headline)
                    Text("Looks like an existing item (same site or same title, same username). Replace keeps the old password in the item's history.")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(conflicts, id: \.self) { index in
                        ConflictRow(entry: review.entries[index], choice: $flow.choices[index])
                    }
                }

                destination

                if !fresh.isEmpty {
                    DisclosureGroup("New (\(fresh.count))") {
                        ForEach(fresh, id: \.self) { index in
                            Toggle(isOn: Binding(
                                get: { flow.choices[index] == .create },
                                set: { flow.choices[index] = $0 ? .create : .skip })
                            ) {
                                EntryLabel(entry: review.entries[index])
                            }
                            .toggleStyle(.checkbox)
                        }
                    }
                }
                if !present.isEmpty {
                    DisclosureGroup("Already present, skipped (\(present.count))") {
                        ForEach(present, id: \.self) { index in
                            EntryLabel(entry: review.entries[index])
                        }
                    }
                }
                if !review.skipped.isEmpty {
                    DisclosureGroup("Can't be imported (\(review.skipped.count))") {
                        ForEach(Array(review.skipped.enumerated()), id: \.offset) { _, skipped in
                            SkippedRow(skipped: skipped)
                        }
                    }
                }
            }
            .padding(16)
        }
    }

    private var destination: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Put the created items").font(.headline)
            Picker("Put the created items", selection: $flow.placement) {
                Text("In the folder").tag(ImportFlow.Placement.folder)
                if review.hasFolders {
                    Text("In the folders (vaults) of \(review.source)").tag(ImportFlow.Placement.originalFolders)
                }
                Text("Without a folder").tag(ImportFlow.Placement.none)
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            if flow.placement == .folder {
                TextField("Folder name", text: $flow.folderName)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)
            }
        }
    }
}

private struct CountTile: View {
    let count: Int
    let label: LocalizedStringKey
    let tint: Color

    var body: some View {
        VStack(spacing: 2) {
            Text("\(count)").font(.title2.weight(.semibold)).monospacedDigit().foregroundStyle(tint)
            Text(label).font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 58)
        .background(Theme.faintFill(0.5), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Title, username and site of a row (never the password).
private struct EntryLabel: View {
    let entry: ImportEntry

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: entry.category.symbol)
                .accessibilityLabel(Text(entry.category.label))
                .foregroundStyle(entry.category.tint)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(CoreText.title(entry.title)).lineLimit(1)
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if entry.hasTotp {
                Image(systemName: "clock.badge.checkmark").font(.caption).foregroundStyle(.teal)
                    .accessibilityLabel("One-time code")
                    .help("One-time code")
            }
        }
        .padding(.vertical, 2)
    }

    private var detail: String {
        [entry.username, entry.host ?? "", entry.folder.map { String(localized: "folder \($0)") } ?? ""]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }
}

/// A conflict: the item, the one it recalls, and the choice.
private struct ConflictRow: View {
    let entry: ImportEntry
    @Binding var choice: ImportChoice

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                EntryLabel(entry: entry)
                Text(explanation).font(.caption).foregroundStyle(.secondary)
            }
            Picker("Choice", selection: $choice) {
                ForEach(options, id: \.self) { option in
                    Text(label(option)).tag(option)
                }
            }
            .labelsHidden()
            .fixedSize()
        }
        .padding(10)
        .background(Theme.faintFill(0.35), in: RoundedRectangle(cornerRadius: 8))
    }

    private var existing: String { entry.existingTitle.map { String(localized: "“\($0)”") } ?? String(localized: "an item") }

    private var explanation: String {
        let base = switch entry.status {
        case .addsCode: String(localized: "Like \(existing) in the vault, which has no one-time code.")
        case .conflictInFile: String(localized: "Like \(existing), higher up in the file.")
        case .similar: String(localized: "Looks like \(existing) in the vault.")
        default: String(localized: "Different password from \(existing) in the vault.")
        }
        let reason = CoreText.duplicateReason(entry.reason)
        return reason.isEmpty ? base : "\(base) \(reason.prefix(1).uppercased())\(reason.dropFirst())."
    }

    private var options: [ImportChoice] {
        entry.status == .conflictInFile ? [.skip, .create] : [.update, .skip, .create]
    }

    private func label(_ option: ImportChoice) -> String {
        switch (option, entry.status) {
        case (.update, .addsCode): String(localized: "Add the Code")
        case (.update, .similar): String(localized: "Complete the Existing One")
        case (.update, _): String(localized: "Replace the Password")
        case (.skip, .conflictInFile): String(localized: "Skip")
        case (.skip, _): String(localized: "Keep the Existing One")
        case (.create, _): String(localized: "Import Separately")
        }
    }
}
