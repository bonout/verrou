import SwiftUI

/// Réglages : Verrou comme fournisseur d'identifiants du système (onglet
/// Général). Seulement dans un build signé par l'équipe, le seul qui livre
/// l'extension ; un build ad hoc dit simplement comment l'obtenir.
struct SystemAutofillSection: View {
    @Environment(AppModel.self) private var model
    @State private var enabled: Bool?

    var body: some View {
        if model.mode == .vaultwarden || AppModel.isReview {
            Section {
                if SystemAutofill.isBundled || AppModel.isReview {
                    LabeledContent("Safari et les apps du Mac") {
                        switch enabled {
                        case true?:
                            Label("Verrou est choisi", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        case false?:
                            Button("Choisir Verrou…") { SystemAutofill.openSettings() }
                        case nil:
                            ProgressView().controlSize(.small)
                        }
                    }
                } else {
                    LabeledContent("Safari et les apps du Mac") {
                        Text("Build signé requis").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Mots de passe et passkeys du système")
            } footer: {
                Text(footer).foregroundStyle(.secondary)
            }
            .task(id: SystemAutofill.isBundled) {
                // Revue (captures) : l'état « choisi » sans interroger le système.
                enabled = AppModel.isReview ? true : await SystemAutofill.isEnabled()
            }
        }
    }

    private var footer: String {
        if SystemAutofill.isBundled || AppModel.isReview {
            return "Choisi dans Réglages Système → Général → Remplissage automatique et mots de passe, Verrou propose ses identifiants, codes et passkeys dans Safari, dans les apps, et dans Chrome ou Brave quand ils demandent une passkey au système. Touch ID ouvre le coffre à chaque fois. L'extension de Verrou pour Brave et Firefox reste utile : elle remplit aussi les cartes et les adresses."
        }
        return "Pour proposer vos mots de passe et passkeys dans Safari et les apps du Mac, Verrou doit être signé par une équipe de développeur Apple (macOS l'exige du fournisseur d'identifiants et du groupe d'apps partagé) : voir le guide, « Fournisseur d'identifiants du Mac »."
    }
}
