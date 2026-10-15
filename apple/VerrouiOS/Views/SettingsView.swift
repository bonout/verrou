import SwiftUI

/// Réglages : compte et synchronisation, sécurité (Face ID, verrouillage
/// automatique, presse-papiers), affichage, à propos, déconnexion.
struct SettingsTab: View {
    @Environment(PhoneModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            Form {
                if model.mode == .vaultwarden, let account = model.account {
                    Section {
                        LabeledContent("E-mail", value: account.email)
                        LabeledContent("Serveur", value: URL(string: account.server)?.host() ?? account.server)
                        LabeledContent("Synchronisé", value: syncedLabel(account))
                        if let pending = model.pendingLabel {
                            Label(pending, systemImage: "arrow.triangle.2.circlepath")
                                .foregroundStyle(.orange)
                        }
                        Button {
                            Task { await model.syncNow() }
                        } label: {
                            HStack {
                                Text("Synchroniser maintenant")
                                Spacer()
                                if model.syncState == .syncing { ProgressView() }
                            }
                        }
                        .disabled(model.syncState == .syncing)
                    } header: {
                        Text("Compte")
                    } footer: {
                        if case .failed(let message) = model.syncState {
                            Text("Dernière synchronisation impossible : \(message)").foregroundStyle(.red)
                        } else if model.syncState == .offline {
                            Text("Serveur injoignable : le coffre affiché vient du cache, les modifications attendent le réseau.")
                        }
                    }
                }

                Section {
                    Toggle(isOn: $model.biometricsWanted) {
                        Label("Déverrouiller avec \(Biometrics.name)", systemImage: Biometrics.symbolName)
                    }
                    .disabled(!Biometrics.isAvailable || model.mode == .demo)
                    Picker(selection: $model.autoLockSeconds) {
                        Text("Immédiatement").tag(0)
                        Text("Après 1 minute").tag(60)
                        Text("Après 5 minutes").tag(300)
                        Text("Après 15 minutes").tag(900)
                        Text("Après 1 heure").tag(3600)
                        Text("Jamais").tag(-1)
                    } label: {
                        Label("Verrouillage automatique", systemImage: "lock.badge.clock")
                    }
                    .pickerStyle(.navigationLink)
                    Picker(selection: $model.clipboardSeconds) {
                        Text("Après 30 secondes").tag(30)
                        Text("Après 90 secondes").tag(90)
                        Text("Après 3 minutes").tag(180)
                        Text("Après 10 minutes").tag(600)
                    } label: {
                        Label("Effacer le presse-papiers", systemImage: "doc.on.clipboard")
                    }
                    .pickerStyle(.navigationLink)
                    Button {
                        model.lock()
                    } label: {
                        Label("Verrouiller maintenant", systemImage: "lock.fill")
                    }
                } header: {
                    Text("Sécurité")
                } footer: {
                    Text(securityFooter)
                }

                if model.mode == .vaultwarden {
                    AutoFillSection()
                }

                Section("Affichage") {
                    Toggle(isOn: $model.showSiteIcons) {
                        Label("Icônes des sites", systemImage: "photo.on.rectangle")
                    }
                }

                Section {
                    Button {
                        model.openAudit()
                    } label: {
                        Label("Audit de sécurité", systemImage: "checkmark.shield")
                    }
                    NavigationLink {
                        AboutView()
                    } label: {
                        Label("À propos et licences", systemImage: "info.circle")
                    }
                }

                if model.mode == .vaultwarden, model.account != nil {
                    Section {
                        Button("Se déconnecter de cet iPhone", role: .destructive) { confirmLogout = true }
                    } footer: {
                        Text("Efface le compte, le cache chiffré et \(Biometrics.name) de cet iPhone. Votre coffre reste sur le serveur.")
                    }
                }
            }
            .navigationTitle("Réglages")
            .confirmationDialog("Se déconnecter de cet iPhone ?", isPresented: $confirmLogout, titleVisibility: .visible) {
                Button("Se déconnecter", role: .destructive) { model.logout() }
            } message: {
                if let pending = model.pendingLabel {
                    Text("\(pending) : elles seront perdues.")
                } else {
                    Text("Il faudra le mot de passe principal et le second facteur pour revenir.")
                }
            }
        }
    }

    private var securityFooter: String {
        var parts = [
            "Le délai compte à partir du moment où Verrou passe en arrière-plan. Hors du premier plan, l'écran de Verrou est masqué dans le sélecteur d'apps.",
            "Les secrets copiés ne vont pas sur vos autres appareils et sont effacés par iOS au bout du délai.",
        ]
        if !Biometrics.isAvailable {
            parts.insert("\(Biometrics.name) n'est pas configuré sur cet iPhone.", at: 0)
        }
        return parts.joined(separator: " ")
    }

    private func syncedLabel(_ account: AccountInfo) -> String {
        guard let synced = account.syncedAt else { return "jamais" }
        let date = Date(timeIntervalSince1970: TimeInterval(synced))
        return date.formatted(.relative(presentation: .named).locale(Locale(identifier: "fr_FR")))
    }
}

/// Version, licence et composants tiers.
struct AboutView: View {
    var body: some View {
        Form {
            Section {
                VStack(spacing: 10) {
                    AppMark(size: 64)
                    Text("Verrou").font(.title2.weight(.bold))
                    Text("Version \(version)").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
            }
            .listRowBackground(Color.clear)

            Section("Licence") {
                Text("Verrou est un logiciel libre, sous licence GPL-3.0-or-later.")
                Link("Code source", destination: URL(string: "https://github.com/bonout/verrou")!)
            }
            Section("Composants") {
                credit("SDK Rust de Bitwarden", "GPL-3.0 : chiffrement, déchiffrement et synchronisation du coffre (crates GPL de bitwarden/sdk-internal uniquement).")
                credit("EFF Long Wordlist", "Electronic Frontier Foundation, CC BY 3.0 US : phrases de passe en anglais.")
                credit("Liste diceware française", "Tango pour Tails et le projet Tor (ulif/diceware), CC0 1.0 : phrases de passe en français.")
                credit("UniFFI", "Mozilla, MPL-2.0 : liaison entre le cœur Rust et Swift.")
            }
            Section {
                Text("« Bitwarden » est une marque de Bitwarden, Inc. Verrou n'est ni affilié ni approuvé par Bitwarden.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("À propos")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }

    private func credit(_ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }
    }
}

// MARK: Audit

/// Audit du coffre, calculé localement : mots de passe réutilisés, faibles,
/// sites en HTTP ; fuites connues sur demande (Have I Been Pwned, par
/// k-anonymat : 5 caractères de l'empreinte SHA-1 de chaque mot de passe).
struct AuditView: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        List {
            if let audit = model.audit {
                Section {
                    LabeledContent("Mots de passe examinés", value: "\(audit.checked)")
                    breachesRow
                } footer: {
                    Text("Seuls les 5 premiers caractères de l'empreinte SHA-1 de chaque mot de passe quittent l'iPhone.")
                }
                if let breaches = model.breaches, !breaches.isEmpty {
                    Section("Compromis (\(breaches.count))") {
                        ForEach(breaches, id: \.item.id) { breach in
                            AuditRow(summary: breach.item,
                                     detail: "Vu \(breach.count.formatted(.number.locale(Locale(identifier: "fr_FR")))) fois dans des fuites",
                                     tint: .red)
                        }
                    }
                }
                if !audit.reused.isEmpty {
                    Section("Réutilisés (\(audit.reused.count) groupe\(audit.reused.count > 1 ? "s" : ""))") {
                        ForEach(Array(audit.reused.enumerated()), id: \.offset) { _, group in
                            ForEach(group, id: \.id) { summary in
                                AuditRow(summary: summary, detail: "Même mot de passe que \(group.count - 1) autre\(group.count > 2 ? "s" : "")",
                                         tint: .orange)
                            }
                        }
                    }
                }
                if !audit.weak.isEmpty {
                    Section("Faibles (\(audit.weak.count))") {
                        ForEach(audit.weak, id: \.item.id) { weak in
                            AuditRow(summary: weak.item, detail: "\(Int(weak.bits)) bits d'entropie estimée", tint: .orange)
                        }
                    }
                }
                if !audit.insecure.isEmpty {
                    Section("Sites en HTTP (\(audit.insecure.count))") {
                        ForEach(audit.insecure, id: \.id) { summary in
                            AuditRow(summary: summary, detail: "Le mot de passe circule en clair", tint: .yellow)
                        }
                    }
                }
                if audit.reused.isEmpty, audit.weak.isEmpty, audit.insecure.isEmpty, model.breaches?.isEmpty ?? true {
                    Section {
                        Label("Rien à signaler", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    }
                }
            } else {
                ProgressView()
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Audit de sécurité")
        .onAppear { model.refreshAudit() }
        .refreshable { model.refreshAudit() }
    }

    @ViewBuilder private var breachesRow: some View {
        if model.mode == .vaultwarden {
            Button {
                Task { await model.checkBreaches() }
            } label: {
                HStack {
                    Label(model.breaches == nil ? "Rechercher les fuites connues" : "Vérifier à nouveau",
                          systemImage: "exclamationmark.shield")
                    Spacer()
                    if model.checkingBreaches { ProgressView() }
                }
            }
            .disabled(model.checkingBreaches)
            if let error = model.breachError {
                ErrorLabel(text: error)
            } else if model.breaches?.isEmpty == true {
                Label("Aucun mot de passe trouvé dans les fuites connues", systemImage: "checkmark.seal")
                    .foregroundStyle(.green)
            }
        }
    }
}

private struct AuditRow: View {
    let summary: ItemSummary
    let detail: String
    let tint: Color

    var body: some View {
        NavigationLink(value: PhoneModel.Route.item(summary.id)) {
            HStack(spacing: 12) {
                ItemIcon(summary: summary, size: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Text(summary.title).lineLimit(1)
                    Text(detail).font(.caption).foregroundStyle(tint)
                }
            }
        }
    }
}

/// Remplissage automatique : comment choisir Verrou dans les Réglages
/// d'iOS, et où il en est.
private struct AutoFillSection: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        Section {
            HStack {
                Label("Remplissage automatique", systemImage: "key.viewfinder")
                Spacer()
                switch model.autofillEnabled {
                case .some(true):
                    Text("Activé").foregroundStyle(.green)
                case .some(false):
                    Text("Désactivé").foregroundStyle(.secondary)
                case .none:
                    ProgressView()
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("autofill-status")
            if model.autofillEnabled != true {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Pour remplir vos identifiants, codes et passkeys dans Safari et les apps :")
                    Text("1. Ouvrez **Réglages → Général → Remplissage automatique et mots de passe**.")
                    Text("2. Activez **Verrou** dans la liste des apps.")
                    Text("3. Touchez un champ d'identifiant : Verrou propose les comptes du site au-dessus du clavier.")
                }
                .font(.callout)
                .padding(.vertical, 2)
            }
            Button {
                model.openAutofillSettings()
            } label: {
                Label(model.autofillEnabled == true ? "Réglages du remplissage" : "Ouvrir les Réglages",
                      systemImage: "gear")
            }
        } header: {
            Text("Remplissage automatique")
        } footer: {
            Text("Le système ne reçoit que les sites et noms d'utilisateur, pour ses suggestions. Les mots de passe, codes et passkeys ne sortent du coffre qu'après \(Biometrics.name) ou votre mot de passe principal.")
        }
        .task { await model.refreshAutofillStatus() }
    }
}
