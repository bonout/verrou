import SwiftUI

/// Entrée de la barre latérale : l'audit occupe alors la colonne centrale.
struct AuditSidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Button {
            model.openAudit()
        } label: {
            Label {
                HStack {
                    Text("Audit de sécurité")
                    Spacer()
                    if let audit = model.audit, model.showAudit {
                        Text("\(issues(audit))").monospacedDigit().foregroundStyle(.secondary).font(.callout)
                    }
                }
            } icon: {
                Image(systemName: "checkmark.shield").foregroundStyle(.orange)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(model.showAudit ? Color.primary.opacity(0.08) : .clear,
                        in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 10)
        .padding(.bottom, 6)
    }

    private func issues(_ audit: AuditReport) -> Int {
        audit.reused.reduce(0) { $0 + $1.count } + audit.weak.count + audit.insecure.count
    }
}

/// Audit du coffre : fuites connues (sur demande), mots de passe réutilisés,
/// faibles, sites en HTTP. Un clic montre l'élément à droite.
struct AuditView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 4) {
                header
                breachSection
                if let audit = model.audit {
                    if !audit.reused.isEmpty {
                        title("Réutilisés", count: audit.reused.reduce(0) { $0 + $1.count },
                              detail: "Un même mot de passe sur plusieurs sites : une fuite chez l'un ouvre les autres.")
                        ForEach(Array(audit.reused.enumerated()), id: \.offset) { _, group in
                            Text("Même mot de passe sur \(group.count) éléments")
                                .font(.caption).foregroundStyle(.secondary)
                                .padding(.horizontal, 8).padding(.top, 6)
                            ForEach(group, id: \.id) { row($0) }
                        }
                    }
                    if !audit.weak.isEmpty {
                        title("Faibles", count: audit.weak.count,
                              detail: "Trop courts ou trop simples pour résister à une attaque hors ligne.")
                        ForEach(audit.weak, id: \.item.id) { weak in
                            row(weak.item, note: "\(Int(weak.bits)) bits")
                        }
                    }
                    if !audit.insecure.isEmpty {
                        title("Sites en HTTP", count: audit.insecure.count,
                              detail: "Le mot de passe y circule en clair : Verrou ne le remplit pas dans Brave.")
                        ForEach(audit.insecure, id: \.id) { row($0) }
                    }
                    if audit.reused.isEmpty && audit.weak.isEmpty && audit.insecure.isEmpty {
                        Label("Aucun mot de passe réutilisé ou faible", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                            .padding(8)
                    }
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 10)
        }
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("Audit de sécurité").font(.title3.weight(.semibold))
            if let audit = model.audit {
                Text("\(audit.checked) mots de passe examinés, sur ce Mac")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 8)
        .padding(.bottom, 6)
    }

    @ViewBuilder private var breachSection: some View {
        if let breaches = model.breaches {
            title("Fuites connues", count: breaches.count,
                  detail: breaches.isEmpty
                      ? "Aucun de vos mots de passe n'apparaît dans les fuites recensées."
                      : "Ces mots de passe circulent dans des fuites publiques : changez-les en premier.")
            ForEach(breaches, id: \.item.id) { breach in
                row(breach.item, note: "vu \(breach.count.formatted()) fois")
            }
        } else {
            VStack(alignment: .leading, spacing: 8) {
                Text("Fuites connues").font(.headline)
                Text("Verrou peut vérifier vos mots de passe auprès de Have I Been Pwned. Seuls les 5 premiers caractères de leur empreinte SHA-1 partent : ni les mots de passe, ni leur empreinte complète ne quittent ce Mac.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Vérifier les fuites") { Task { await model.checkBreaches() } }
                        .disabled(model.checkingBreaches || model.mode == .demo)
                    if model.checkingBreaches { ProgressView().controlSize(.small) }
                }
                if let error = model.breachError {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }
            .padding(10)
            .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .padding(.bottom, 6)
        }
    }

    private func title(_ text: String, count: Int, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(text).font(.headline)
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
            }
            Text(detail).font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 8)
        .padding(.top, 14)
        .padding(.bottom, 2)
    }

    private func row(_ summary: ItemSummary, note: String? = nil) -> some View {
        let selected = summary.id == model.selection
        return HStack {
            ItemRow(summary: summary, highlights: [], selected: selected)
            if let note {
                Text(note).font(.caption).monospacedDigit()
                    .foregroundStyle(selected ? Color.white.opacity(0.85) : .secondary)
            }
        }
        .padding(.horizontal, 8)
        .background(selected ? Theme.accent : .clear, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        .contentShape(Rectangle())
        .onTapGesture { model.selection = summary.id }
        .contextMenu { RowMenu(summary: summary) }
    }
}
