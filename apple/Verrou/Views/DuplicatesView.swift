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

extension DuplicateConfidence {
    var label: String {
        switch self {
        case .certain: "Certain"
        case .probable: "Probable"
        case .review: "À vérifier"
        }
    }

    var tint: Color {
        switch self {
        case .certain: .green
        case .probable: .orange
        case .review: .secondary
        }
    }

    var help: String {
        switch self {
        case .certain: "Même site, même identifiant, même mot de passe : les copies sont cochées."
        case .probable: "Très ressemblants, mais une différence (mot de passe, identifiant manquant) : à confirmer."
        case .review: "Une ressemblance seulement : vérifiez avant de supprimer."
        }
    }
}

/// Doublons du coffre, classés par le cœur Rust : certains, probables, à
/// vérifier. Dans chaque groupe, l'élément gardé (passkeys, pièces jointes,
/// code à usage unique, le plus récent, le plus complet) reçoit les autres
/// par « Fusionner » ; les copies certaines sont cochées pour la corbeille,
/// restaurable depuis le coffre web.
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
                ProgressView("Recherche des doublons…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if flow.visible.isEmpty {
                ContentUnavailableView(
                    "Aucun doublon", systemImage: "checkmark.seal",
                    description: Text(flow.ignoredCount > 0
                        ? "Les groupes restants sont ignorés."
                        : "Aucun élément ne ressemble à un autre : ni site, ni titre, ni identifiant en commun."))
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
        .confirmationDialog(trashLabel + " ?", isPresented: $confirmTrash) {
            Button("Mettre à la corbeille", role: .destructive) {
                Task { await model.trashDuplicates(flow) }
            }
        } message: {
            Text("Les éléments restent restaurables depuis le coffre web pendant 30 jours.")
        }
        .confirmationDialog(mergeTitle, isPresented: Binding(
            get: { merging != nil }, set: { if !$0 { merging = nil } })
        ) {
            Button("Fusionner") {
                if let group = merging {
                    Task { await model.mergeDuplicates(flow, group: group) }
                }
            }
        } message: {
            Text("Sites, code à usage unique, notes, champs et anciens mots de passe rejoignent l'élément gardé ; le mot de passe le plus récent reste le mot de passe actuel. Les autres partent ensuite à la corbeille, restaurables 30 jours.")
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "square.on.square.dashed")
                .font(.system(size: 26))
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 4) {
                Text("Doublons").font(.title3.weight(.semibold))
                    .layoutMark("sheet-title")
                Text("Le même compte, importé plusieurs fois : adresses, titres et identifiants comparés. Les copies certaines sont cochées.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if flow.loaded, !flow.visible.isEmpty {
                    HStack(spacing: 6) {
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
        HStack(spacing: 10) {
            Text(status)
                .font(.caption)
                .foregroundStyle(flow.error == nil ? Color.secondary : Color.orange)
                .fixedSize(horizontal: false, vertical: true)
            if flow.ignoredCount > 0 {
                Button("Réafficher \(flow.ignoredCount) ignoré\(flow.ignoredCount > 1 ? "s" : "")") {
                    flow.clearIgnored()
                }
                .buttonStyle(.link)
                .font(.caption)
                .help("Les groupes ignorés sont retenus sur ce Mac")
            }
            Spacer()
            if flow.busy { ProgressView().controlSize(.small) }
            Button("Fermer") { model.duplicatesFlow = nil }
                .keyboardShortcut(.cancelAction)
            Button(trashLabel) { confirmTrash = true }
                .buttonStyle(.borderedProminent)
                .layoutMark("sheet-primary")
                .disabled(flow.selected.isEmpty || flow.busy || !model.canEdit)
                .help(model.canEdit ? "Tous les éléments cochés, dans tous les groupes" : "Coffre fictif : lecture seule")
        }
        .padding(16)
    }

    private var trashLabel: String {
        let n = flow.selected.count
        return "Mettre \(n) élément\(n > 1 ? "s" : "") à la corbeille"
    }

    private var mergeTitle: String {
        guard let group = merging else { return "Fusionner ?" }
        let n = flow.mergeTargets(in: group).count
        return "Fusionner \(n) élément\(n > 1 ? "s" : "") dans « \(flow.title(of: flow.keptID(group))) » ?"
    }

    private var status: String {
        if let error = flow.error { return error }
        let n = flow.visible.count
        return n == 0 ? "" : "\(n) groupe\(n > 1 ? "s" : "") de doublons"
    }
}

private struct ConfidenceCount: View {
    let level: DuplicateConfidence
    let count: Int

    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(level.tint).frame(width: 7, height: 7)
            Text("\(count) \(level.label.lowercased())\(count > 1 && level != .review ? "s" : "")")
                .font(.caption.weight(.medium))
                .monospacedDigit()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(.quaternary.opacity(0.6), in: Capsule())
        .help(level.help)
    }
}

private struct ConfidenceBadge: View {
    let level: DuplicateConfidence

    var body: some View {
        Text(level.label)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(level == .review ? Color.primary : Color.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(level == .review ? AnyShapeStyle(.quaternary) : AnyShapeStyle(level.tint), in: Capsule())
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
            Text(group.reason)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(group.members, id: \.item.id) { member in
                MemberRow(flow: flow, group: group, member: member, kept: member.item.id == keep)
            }
            HStack(spacing: 8) {
                if group.mergeable {
                    Button("Fusionner et mettre les autres à la corbeille", action: merge)
                        .disabled(flow.mergeTargets(in: group).isEmpty || flow.busy || !model.canEdit)
                        .help(mergeHelp)
                }
                Button("Mettre la sélection à la corbeille", action: trash)
                    .disabled(flow.checked(in: group).isEmpty || flow.busy || !model.canEdit)
                Spacer()
                Button("Ignorer ce groupe") { flow.ignore(group) }
                    .help("Ne plus proposer ces éléments ensemble (retenu sur ce Mac)")
            }
            .controlSize(.small)
            .padding(.top, 2)
        }
        .padding(12)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }

    private var mergeHelp: String {
        guard model.canEdit else { return "Coffre fictif : lecture seule" }
        let targets = flow.mergeTargets(in: group)
        if targets.isEmpty { return "Cochez les éléments à fusionner" }
        return "Fusionne " + targets.map { "« \(flow.title(of: $0)) »" }.joined(separator: ", ")
            + " dans l'élément gardé"
    }
}

/// Un élément : case à cocher (jamais pour l'élément gardé), titre,
/// identifiant, site, date, et pourquoi il ressemble à l'élément gardé.
private struct MemberRow: View {
    @Bindable var flow: DuplicatesFlow
    let group: DuplicateGroupView
    let member: DuplicateMemberView
    let kept: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Toggle("", isOn: Binding(
                get: { flow.selected.contains(member.item.id) },
                set: { flow.toggle(member.item.id, $0) })
            )
            .toggleStyle(.checkbox)
            .labelsHidden()
            .disabled(kept)
            .help(kept ? "L'élément gardé ne part pas à la corbeille" : "Cocher pour mettre à la corbeille")
            .padding(.top, 4)
            ItemIcon(summary: member.item, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(member.item.title).lineLimit(1)
                    if kept {
                        Text("À garder")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Theme.accent.opacity(0.18), in: Capsule())
                    } else if let level = member.confidence, level != group.confidence || level == .probable {
                        Text(level == .probable ? "Suggéré" : level.label)
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(level.tint)
                    }
                }
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if !kept, !member.reason.isEmpty {
                    Text(member.reason)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }
            }
            Spacer(minLength: 4)
            if member.item.hasTotp {
                Image(systemName: "clock.badge.checkmark").font(.caption).foregroundStyle(.teal)
                    .help("Code à usage unique")
                    .padding(.top, 4)
            }
            if !kept {
                Button("Garder") { flow.keep(member.item.id, in: group) }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .help("Garder cet élément plutôt que celui suggéré")
                    .padding(.top, 3)
            }
        }
    }

    private var detail: String {
        let modified = Date(timeIntervalSince1970: TimeInterval(member.item.modified))
            .formatted(date: .abbreviated, time: .omitted)
        return [member.item.subtitle, member.item.host ?? "", member.item.folder.map { "dossier \($0)" } ?? "",
                "modifié le \(modified)"]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }
}
