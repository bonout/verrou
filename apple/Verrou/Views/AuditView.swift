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
            + model.watchtower.issues
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
                WatchtowerSections(row: { row($0, note: $1) })
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

/// Compléments de l'audit : double authentification disponible, cartes
/// expirées ou bientôt expirées, mots de passe anciens (`Watchtower`).
private struct WatchtowerSections<Row: View>: View {
    @Environment(AppModel.self) private var model
    let row: (ItemSummary, String?) -> Row

    var body: some View {
        let watchtower = model.watchtower
        twoFactorSection(watchtower)
        if let report = watchtower.report {
            if !report.cards.isEmpty {
                title("Cartes expirées ou bientôt expirées", count: report.cards.count,
                      detail: "Mettez à jour la date et le cryptogramme de la nouvelle carte, ici et chez les marchands.")
                ForEach(report.cards, id: \.item.id) { card in
                    row(card.item, cardNote(card))
                }
            }
            if !report.old.isEmpty {
                title("Mots de passe anciens", count: report.old.count,
                      detail: "Éléments inchangés depuis plus de 3 ans : leur mot de passe date au moins de cette époque.")
                ForEach(report.old, id: \.item.id) { old in
                    row(old.item, age(days: old.days))
                }
            }
        }
    }

    @ViewBuilder private func twoFactorSection(_ watchtower: Watchtower) -> some View {
        if let report = watchtower.twoFactor {
            if !report.missing.isEmpty {
                title("Double authentification disponible", count: report.missing.count,
                      detail: twoFactorDetail(report))
                ForEach(report.missing, id: \.item.id) { missing in
                    HStack(spacing: 4) {
                        row(missing.item, missing.totp ? nil : methods(missing.methods))
                        if let doc = missing.documentation, let url = URL(string: doc) {
                            Link(destination: url) {
                                Image(systemName: "questionmark.circle")
                            }
                            .buttonStyle(.borderless)
                            .help("Activer la double authentification sur \(missing.site)")
                        }
                    }
                }
            }
        } else if watchtower.loadingTwoFactor {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Recherche des sites qui proposent la double authentification…")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8).padding(.top, 14)
        } else if let error = watchtower.twoFactorError, model.mode == .vaultwarden {
            title("Double authentification disponible", count: 0,
                  detail: "Catégorie ignorée : la liste de 2fa.directory n'a pas pu être téléchargée (\(error)).")
        }
    }

    private func twoFactorDetail(_ report: TwoFactorReport) -> String {
        var text = "Ces sites proposent la double authentification, mais aucun code à usage unique n'est enregistré dans Verrou. D'après 2fa.directory"
        if report.stale {
            let date = Date(timeIntervalSince1970: TimeInterval(report.fetchedAt))
            text += " (liste du \(date.formatted(date: .abbreviated, time: .omitted)), hors ligne)"
        }
        return text + "."
    }

    private func methods(_ methods: [String]) -> String {
        let names = methods.map { method -> String in
            switch method {
            case "sms": "SMS"
            case "call": "appel"
            case "email": "e-mail"
            case "u2f": "clé de sécurité"
            case "custom-software": "application"
            case "custom-hardware": "matériel"
            default: method
            }
        }
        return names.joined(separator: ", ")
    }

    private func cardNote(_ card: ExpiringCard) -> String {
        if card.daysLeft < 0 { return "expirée (\(card.expiry))" }
        if card.daysLeft == 0 { return "expire aujourd'hui" }
        return "expire dans \(card.daysLeft) jour\(card.daysLeft > 1 ? "s" : "")"
    }

    private func age(days: Int64) -> String {
        let years = days / 365
        return "\(years) an\(years > 1 ? "s" : "")"
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
}
