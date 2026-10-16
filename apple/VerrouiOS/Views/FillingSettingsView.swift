import SwiftUI

/// Liste ouverte au déverrouillage, tri, règles de correspondance des sites
/// (défaut de l'iPhone, dossiers) et domaines équivalents du compte.
struct FillingSettingsView: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Picker("Au déverrouillage", selection: $model.defaultFilter) {
                    ForEach(DefaultFilter.allCases) { filter in
                        Text(filter.label).tag(filter)
                    }
                }
                Picker("Trier les listes par", selection: $model.sortOrder) {
                    ForEach(ResultOrder.menu, id: \.self) { order in
                        Text(order.label).tag(order)
                    }
                }
            } header: {
                SectionHeader("Coffre")
            } footer: {
                Text("Gardés sur cet iPhone. « Dernière utilisation » suit ce que vous remplissez, copiez ou affichez ici : seulement des identifiants d'éléments et des dates, jamais envoyés au serveur.")
            }

            Section {
                Picker("Par défaut", selection: defaultRule) {
                    ForEach(UriMatchRule.all) { rule in
                        Text(rule.label).tag(rule)
                    }
                }
                .accessibilityIdentifier("default-match")
            } header: {
                SectionHeader("Correspondance des sites")
            } footer: {
                Text("Pour les sites sans règle propre (à choisir en modifiant un identifiant). \(defaultRule.wrappedValue.explanation)")
            }

            Section {
                ForEach(model.matchSettings?.folderRules ?? [], id: \.folderId) { rule in
                    Picker(selection: folderRule(rule.folderId)) {
                        ForEach(UriMatchRule.all) { option in
                            Text(option.label).tag(option)
                        }
                    } label: {
                        Label(rule.folderName.isEmpty ? "Dossier supprimé" : rule.folderName, systemImage: "folder.fill")
                    }
                    .swipeActions {
                        Button("Retirer", systemImage: "minus.circle", role: .destructive) {
                            model.setFolderMatchRule(rule.folderId, nil)
                        }
                    }
                }
                let free = model.folders.filter { folder in
                    !(model.matchSettings?.folderRules.contains { $0.folderId == folder.id } ?? false)
                }
                Menu {
                    ForEach(free, id: \.id) { folder in
                        Button(folder.name) { model.setFolderMatchRule(folder.id, .host) }
                    }
                } label: {
                    Label("Règle pour un dossier…", systemImage: "plus.circle.fill")
                }
                .disabled(free.isEmpty)
                .accessibilityIdentifier("add-folder-rule")
            } header: {
                SectionHeader("Par dossier")
            } footer: {
                Text("Bitwarden n'a pas de règle par dossier : celle-ci reste sur cet iPhone et ne vaut que pour les sites sans règle propre (par exemple « Hôte » pour le dossier Travail).")
            }

            Section {
                let groups = model.matchSettings?.equivalentDomains ?? []
                if groups.isEmpty {
                    Text(model.mode == .vaultwarden ? "Lus à la prochaine synchronisation." : "Aucun dans le coffre fictif.")
                        .foregroundStyle(.secondary)
                } else {
                    DisclosureGroup("\(groups.count) groupe\(groups.count > 1 ? "s" : "") de domaines") {
                        ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                            Text(group.joined(separator: " · "))
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                SectionHeader("Domaines équivalents")
            } footer: {
                Text("Réglages de votre compte, lus sur le serveur (coffre web → Paramètres → Domaines) : la règle « Domaine de base » propose aussi l'identifiant sur les domaines du même groupe.")
            }
        }
        .navigationTitle("Coffre et remplissage")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var defaultRule: Binding<UriMatchRule> {
        Binding(get: { model.matchSettings?.defaultRule ?? .domain },
                set: { model.setDefaultMatchRule($0) })
    }

    private func folderRule(_ folderID: String) -> Binding<UriMatchRule> {
        Binding(get: { model.matchSettings?.folderRules.first { $0.folderId == folderID }?.rule ?? .domain },
                set: { model.setFolderMatchRule(folderID, $0) })
    }
}
