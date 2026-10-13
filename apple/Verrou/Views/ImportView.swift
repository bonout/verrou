import SwiftUI

/// Revue d'un import : ce qui est nouveau, déjà présent, en conflit, ignoré ;
/// un choix par conflit ; le dossier où ranger les éléments créés. Aucun
/// secret n'est affiché : titres, identifiants et sites seulement.
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

    // MARK: En-tête et pied

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "square.and.arrow.down.on.square.fill")
                .font(.system(size: 26))
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(flow.review.map { "Importer depuis \($0.source)" } ?? "Importer des mots de passe")
                    .font(.title3.weight(.semibold))
                Text(flow.url.lastPathComponent + (flow.review.map { " · \($0.formatLabel)" } ?? ""))
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

    /// Relire le fichier dans un autre format (détection trompée).
    private var formatMenu: some View {
        Menu("Format") {
            ForEach(ImportFlow.formats, id: \.self) { format in
                Button(importFormatLabel(format: format)) {
                    flow.format = format
                    Task { await model.readImport(flow) }
                }
            }
        }
        .fixedSize()
        .help("Relire le fichier dans un autre format")
    }

    private var footer: some View {
        HStack(spacing: 10) {
            switch flow.stage {
            case .review:
                Text("Le fichier d'export contient vos mots de passe en clair : supprimez-le après l'import.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Annuler") { model.closeImport() }
                    .keyboardShortcut(.cancelAction)
                Button(importLabel) { Task { await model.commitImport(flow) } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(flow.writeCount == 0)
            case .done:
                Button("Afficher le fichier dans le Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([flow.url])
                }
                Spacer()
                Button("Terminé") { model.closeImport() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            case .importing:
                Spacer()
            case .reading, .failed:
                Spacer()
                Button("Annuler") { model.closeImport() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
    }

    private var importLabel: String {
        let n = flow.writeCount
        return "Importer \(n) élément\(n > 1 ? "s" : "")"
    }

    // MARK: Contenu

    @ViewBuilder
    private var content: some View {
        switch flow.stage {
        case .reading:
            ProgressView("Lecture du fichier…")
        case .importing(let count):
            ProgressView("Chiffrement et envoi de \(count) élément\(count > 1 ? "s" : "")…")
        case .failed(let message):
            FailedImportView(flow: flow, message: message)
        case .review(let review):
            ReviewList(flow: flow, review: review)
        case .done(let outcome):
            ImportDoneView(outcome: outcome)
        }
    }
}

/// Lecture impossible : le message, et le format à choisir à la main.
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
                        Text(importFormatLabel(format: format)).tag(format)
                    }
                }
                .fixedSize()
                Button("Relire") {
                    flow.format = format
                    Task { await model.readImport(flow) }
                }
            }
        }
        .padding(30)
        .onAppear { if let chosen = flow.format { format = chosen } }
    }
}

/// Bilan : éléments écrits, et ceux qui ne l'ont pas été.
private struct ImportDoneView: View {
    let outcome: ImportOutcome

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Label("\(outcome.created) créé\(outcome.created > 1 ? "s" : ""), \(outcome.updated) complété\(outcome.updated > 1 ? "s" : "")",
                      systemImage: "checkmark.circle.fill")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.green)
                Text("Le fichier d'export contient vos mots de passe en clair. Supprimez-le, puis videz la corbeille du Finder.")
                    .foregroundStyle(.secondary)
                if !outcome.failures.isEmpty {
                    Text("Non importés").font(.headline).padding(.top, 6)
                    ForEach(Array(outcome.failures.enumerated()), id: \.offset) { _, failure in
                        SkippedRow(skipped: failure)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
    }
}

private struct SkippedRow: View {
    let skipped: ImportSkipped

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(skipped.title).lineLimit(1)
            Spacer()
            Text(skipped.reason).font(.callout).foregroundStyle(.secondary).lineLimit(2)
        }
        .padding(.vertical, 2)
    }
}

/// La revue : bilan, conflits à trancher, listes repliées, destination.
private struct ReviewList: View {
    @Bindable var flow: ImportFlow
    let review: ImportReview

    private func indices(_ statuses: Set<ImportStatus>) -> [Int] {
        review.entries.indices.filter { statuses.contains(review.entries[$0].status) }
    }

    var body: some View {
        let fresh = indices([.new])
        let present = indices([.alreadyPresent, .repeatedInFile])
        let conflicts = indices([.newPassword, .conflictInFile, .addsCode])
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    CountTile(count: fresh.count, label: "nouveaux", tint: .green)
                    CountTile(count: present.count, label: "déjà présents", tint: .secondary)
                    CountTile(count: indices([.newPassword, .conflictInFile]).count,
                              label: "mot de passe différent", tint: .orange)
                    CountTile(count: indices([.addsCode]).count, label: "code à ajouter", tint: .teal)
                    CountTile(count: review.skipped.count, label: "ignorés", tint: .secondary)
                }

                if let error = flow.error {
                    Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }

                if !conflicts.isEmpty {
                    Text("À décider").font(.headline)
                    Text("Même site et même identifiant qu'un élément existant. Remplacer garde l'ancien mot de passe dans l'historique de l'élément.")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(conflicts, id: \.self) { index in
                        ConflictRow(entry: review.entries[index], choice: $flow.choices[index])
                    }
                }

                destination

                if !fresh.isEmpty {
                    DisclosureGroup("Nouveaux (\(fresh.count))") {
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
                    DisclosureGroup("Déjà présents, ignorés (\(present.count))") {
                        ForEach(present, id: \.self) { index in
                            EntryLabel(entry: review.entries[index])
                        }
                    }
                }
                if !review.skipped.isEmpty {
                    DisclosureGroup("Non importables (\(review.skipped.count))") {
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
            Text("Ranger les éléments créés").font(.headline)
            Picker("Ranger les éléments créés", selection: $flow.placement) {
                Text("Dans le dossier").tag(ImportFlow.Placement.folder)
                if review.hasFolders {
                    Text("Dans les dossiers (coffres) de \(review.source)").tag(ImportFlow.Placement.originalFolders)
                }
                Text("Sans dossier").tag(ImportFlow.Placement.none)
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            if flow.placement == .folder {
                TextField("Nom du dossier", text: $flow.folderName)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)
            }
        }
    }
}

private struct CountTile: View {
    let count: Int
    let label: String
    let tint: Color

    var body: some View {
        VStack(spacing: 2) {
            Text("\(count)").font(.title2.weight(.semibold)).monospacedDigit().foregroundStyle(tint)
            Text(label).font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 58)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Titre, identifiant et site d'une ligne (jamais le mot de passe).
private struct EntryLabel: View {
    let entry: ImportEntry

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: entry.category.symbol)
                .foregroundStyle(entry.category.tint)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.title).lineLimit(1)
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if entry.hasTotp {
                Image(systemName: "clock.badge.checkmark").font(.caption).foregroundStyle(.teal)
                    .help("Code à usage unique")
            }
        }
        .padding(.vertical, 2)
    }

    private var detail: String {
        [entry.username, entry.host ?? "", entry.folder.map { "dossier \($0)" } ?? ""]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }
}

/// Un conflit : l'élément, celui qu'il rappelle, et le choix.
private struct ConflictRow: View {
    let entry: ImportEntry
    @Binding var choice: ImportChoice

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                EntryLabel(entry: entry)
                Text(explanation).font(.caption).foregroundStyle(.secondary)
            }
            Picker("Choix", selection: $choice) {
                ForEach(options, id: \.self) { option in
                    Text(label(option)).tag(option)
                }
            }
            .labelsHidden()
            .fixedSize()
        }
        .padding(10)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
    }

    private var existing: String { entry.existingTitle.map { "« \($0) »" } ?? "un élément" }

    private var explanation: String {
        switch entry.status {
        case .addsCode: "Comme \(existing) du coffre, qui n'a pas de code à usage unique."
        case .conflictInFile: "Autre mot de passe que \(existing), plus haut dans le fichier."
        default: "Autre mot de passe que \(existing) du coffre."
        }
    }

    private var options: [ImportChoice] {
        entry.status == .conflictInFile ? [.skip, .create] : [.update, .skip, .create]
    }

    private func label(_ option: ImportChoice) -> String {
        switch (option, entry.status) {
        case (.update, .addsCode): "Ajouter le code"
        case (.update, _): "Remplacer le mot de passe"
        case (.skip, .conflictInFile): "Ignorer"
        case (.skip, _): "Garder l'existant"
        case (.create, _): "Importer à part"
        }
    }
}
