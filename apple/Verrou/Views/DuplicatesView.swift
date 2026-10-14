import SwiftUI

/// Entrée de la barre latérale, sous l'audit : ouvre le nettoyage des doublons.
struct DuplicatesSidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        // Une feuille plutôt qu'un volet : jamais en surbrillance.
        SidebarPaneButton(title: "Doublons", symbol: "square.on.square.dashed",
                          help: "Nettoyer les doublons du coffre") {
            model.openDuplicates()
        }
    }
}

/// Doublons du coffre : même site et même identifiant. Dans chaque groupe,
/// l'élément suggéré (code à usage unique, plus récent, plus complet) est
/// gardé ; les autres sont cochés pour la corbeille, restaurable depuis le
/// coffre web.
struct DuplicatesView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: DuplicatesFlow
    @State private var confirm = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "square.on.square.dashed")
                    .font(.system(size: 26))
                    .foregroundStyle(Theme.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Doublons").font(.title3.weight(.semibold))
                    Text("Même site et même identifiant. L'élément suggéré a un code à usage unique, ou est le plus récent.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(16)
            Divider()

            if flow.groups.isEmpty {
                ContentUnavailableView("Aucun doublon", systemImage: "checkmark.seal",
                                       description: Text("Aucun élément ne partage son site et son identifiant avec un autre."))
                    .frame(maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(Array(flow.groups.enumerated()), id: \.offset) { _, group in
                            GroupView(group: group, selected: $flow.selected)
                        }
                    }
                    .padding(16)
                }
            }

            Divider()
            HStack(spacing: 10) {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(flow.error == nil && flow.emptiedGroups.isEmpty ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                if flow.busy { ProgressView().controlSize(.small) }
                Button("Fermer") { model.duplicatesFlow = nil }
                    .keyboardShortcut(.cancelAction)
                Button(trashLabel) { confirm = true }
                    .buttonStyle(.borderedProminent)
                    .disabled(flow.selected.isEmpty || flow.busy || !model.canEdit)
                    .help(model.canEdit ? "" : "Coffre fictif : lecture seule")
            }
            .padding(16)
        }
        .frame(width: 600, height: 600)
        .confirmationDialog(trashLabel + " ?", isPresented: $confirm) {
            Button("Mettre à la corbeille", role: .destructive) {
                Task { await model.trashDuplicates(flow) }
            }
        } message: {
            Text("Les éléments restent restaurables depuis le coffre web pendant 30 jours.")
        }
    }

    private var trashLabel: String {
        let n = flow.selected.count
        return "Mettre \(n) élément\(n > 1 ? "s" : "") à la corbeille"
    }

    private var status: String {
        if let error = flow.error { return error }
        if let emptied = flow.emptiedGroups.first {
            return "Tous les éléments de « \(emptied.label) » sont cochés : aucun ne restera."
        }
        let n = flow.groups.count
        return "\(n) groupe\(n > 1 ? "s" : "") de doublons"
    }
}

private struct GroupView: View {
    let group: DuplicateGroupView
    @Binding var selected: Set<String>

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(group.label).font(.headline)
                if !group.username.isEmpty {
                    Text(group.username).foregroundStyle(.secondary)
                }
                Spacer()
                Label(group.samePassword ? "Mot de passe identique" : "Mots de passe différents",
                      systemImage: group.samePassword ? "equal.circle.fill" : "exclamationmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(group.samePassword ? .green : .orange)
                    .help(group.samePassword
                          ? "Supprimer les autres ne perd aucun mot de passe."
                          : "Vérifiez lequel est à jour avant de supprimer : les mots de passe diffèrent.")
            }
            ForEach(Array(group.items.enumerated()), id: \.element.id) { index, item in
                Toggle(isOn: Binding(
                    get: { selected.contains(item.id) },
                    set: { trash in
                        if trash { selected.insert(item.id) } else { selected.remove(item.id) }
                    })
                ) {
                    DuplicateRow(item: item, suggested: index == 0)
                }
                .toggleStyle(.checkbox)
                .help("Cocher pour mettre à la corbeille")
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }
}

/// Titre, identifiant, site, date de modification : jamais le mot de passe.
private struct DuplicateRow: View {
    let item: ItemSummary
    let suggested: Bool

    var body: some View {
        HStack(spacing: 10) {
            ItemIcon(summary: item, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(item.title).lineLimit(1)
                    if suggested {
                        Text("À garder")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Theme.accent.opacity(0.18), in: Capsule())
                    }
                }
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if item.hasTotp {
                Image(systemName: "clock.badge.checkmark").font(.caption).foregroundStyle(.teal)
                    .help("Code à usage unique")
            }
        }
    }

    private var detail: String {
        let modified = Date(timeIntervalSince1970: TimeInterval(item.modified))
            .formatted(date: .abbreviated, time: .omitted)
        return [item.subtitle, item.host ?? "", item.folder.map { "dossier \($0)" } ?? "", "modifié le \(modified)"]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }
}
