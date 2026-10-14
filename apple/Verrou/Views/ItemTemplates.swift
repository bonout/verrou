import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

// MARK: Modèles

/// Modèles d'éléments à la 1Password : des notes sécurisées (ou des
/// identifiants) avec des champs prédéfinis, reconnus grâce au champ réservé
/// `verrou:type` (voir `verrou_core::template`).
extension ItemTemplate {
    /// Ordre du menu « Nouvel élément » et de la barre latérale.
    static let menuOrder: [ItemTemplate] = [
        .softwareLicense, .wifi, .bankAccount, .passport, .driversLicense,
        .idCard, .server, .database, .apiKey, .membership,
    ]

    var label: String {
        switch self {
        case .softwareLicense: "Licences logicielles"
        case .wifi: "Réseaux Wi-Fi"
        case .bankAccount: "Comptes bancaires"
        case .passport: "Passeports"
        case .driversLicense: "Permis de conduire"
        case .idCard: "Cartes d'identité"
        case .server: "Serveurs"
        case .database: "Bases de données"
        case .apiKey: "Clés API"
        case .membership: "Adhésions et abonnements"
        }
    }

    var singular: String {
        switch self {
        case .softwareLicense: "Licence logicielle"
        case .wifi: "Réseau Wi-Fi"
        case .bankAccount: "Compte bancaire"
        case .passport: "Passeport"
        case .driversLicense: "Permis de conduire"
        case .idCard: "Carte d'identité"
        case .server: "Serveur"
        case .database: "Base de données"
        case .apiKey: "Clé API"
        case .membership: "Adhésion ou abonnement"
        }
    }

    /// Libellé du menu « Nouvel élément ».
    var menuTitle: String {
        self == .membership ? "Adhésion/abonnement" : singular
    }

    var symbol: String {
        switch self {
        case .softwareLicense: "app.badge.checkmark"
        case .wifi: "wifi"
        case .bankAccount: "building.columns.fill"
        case .passport: "book.closed.fill"
        case .driversLicense: "car.fill"
        case .idCard: "person.crop.rectangle.fill"
        case .server: "server.rack"
        case .database: "cylinder.split.1x2.fill"
        case .apiKey: "curlybraces"
        case .membership: "rosette"
        }
    }

    var tint: Color {
        switch self {
        case .softwareLicense: .indigo
        case .wifi: .cyan
        case .bankAccount: .mint
        case .passport: .red
        case .driversLicense: .orange
        case .idCard: .green
        case .server: .gray
        case .database: .purple
        case .apiKey: .pink
        case .membership: .teal
        }
    }

    /// Exemple de titre à la création.
    var titlePrompt: String {
        switch self {
        case .softwareLicense: "Logiciel"
        case .wifi: "Wi-Fi maison"
        case .bankAccount: "Compte courant"
        case .passport: "Passeport"
        case .driversLicense: "Permis de conduire"
        case .idCard: "Carte d'identité"
        case .server: "Serveur web"
        case .database: "Base de production"
        case .apiKey: "Clé API"
        case .membership: "Abonnement"
        }
    }
}

extension ItemSummary {
    /// Symbole et teinte de l'icône : ceux du modèle, sinon ceux du type.
    var symbol: String { template?.symbol ?? category.symbol }
    var tint: Color { template?.tint ?? category.tint }
    var kindLabel: String { template?.singular ?? category.singular }
}

// MARK: Champs personnalisés (écran de modification)

/// Champs personnalisés d'un élément : ajouter, supprimer, réordonner,
/// renommer. Texte, masqué, case à cocher ; un champ lié s'affiche et se
/// déplace, sans se modifier. Les champs réservés à Verrou n'arrivent jamais
/// ici (le cœur Rust les garde de côté).
struct CustomFieldsSection: View {
    @Binding var fields: [CustomField]
    @State private var shown: Set<Int> = []

    var body: some View {
        Section("Champs personnalisés") {
            ForEach(Array(fields.indices), id: \.self) { index in
                row(index)
            }
            Menu {
                Button("Texte") { add(.text) }
                Button("Masqué") { add(.hidden) }
                Button("Case à cocher") { add(.boolean) }
            } label: {
                Label("Ajouter un champ", systemImage: "plus.circle.fill")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }

    @ViewBuilder private func row(_ index: Int) -> some View {
        HStack(alignment: .center, spacing: 8) {
            TextField("Nom", text: nameBinding(index), prompt: Text("Nom du champ"))
                .labelsHidden()
                .frame(width: 150)
            value(index)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                move(index, by: -1)
            } label: {
                Image(systemName: "chevron.up")
            }
            .buttonStyle(.borderless)
            .disabled(index == 0)
            .help("Monter")
            Button {
                move(index, by: 1)
            } label: {
                Image(systemName: "chevron.down")
            }
            .buttonStyle(.borderless)
            .disabled(index == fields.count - 1)
            .help("Descendre")
            Button {
                fields.remove(at: index)
                shown.removeAll()
            } label: {
                Image(systemName: "minus.circle.fill").foregroundStyle(.red)
            }
            .buttonStyle(.plain)
            .help("Supprimer ce champ")
        }
    }

    @ViewBuilder private func value(_ index: Int) -> some View {
        switch fields[index].fieldType {
        case .text:
            TextField("Valeur", text: valueBinding(index)).labelsHidden()
        case .hidden:
            HStack(spacing: 6) {
                if shown.contains(index) {
                    TextField("Valeur", text: valueBinding(index))
                        .labelsHidden()
                        .font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Valeur", text: valueBinding(index)).labelsHidden()
                }
                Button {
                    if shown.contains(index) { shown.remove(index) } else { shown.insert(index) }
                } label: {
                    Image(systemName: shown.contains(index) ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(shown.contains(index) ? "Masquer" : "Afficher")
            }
        case .boolean:
            Toggle("Coché", isOn: Binding(
                get: { fields.indices.contains(index) && fields[index].value == "true" },
                set: { if fields.indices.contains(index) { fields[index].value = $0 ? "true" : "false" } }))
                .labelsHidden()
        case .linked:
            Text("Champ lié (modifiable dans le coffre web)")
                .foregroundStyle(.secondary)
                .help("Il renvoie à un autre champ de l'élément")
        }
    }

    private func add(_ type: CustomFieldType) {
        fields.append(CustomField(name: "", value: type == .boolean ? "false" : nil,
                                  fieldType: type, linkedId: nil))
    }

    private func move(_ index: Int, by offset: Int) {
        let target = index + offset
        guard fields.indices.contains(index), fields.indices.contains(target) else { return }
        fields.swapAt(index, target)
        // Le champ affiché suit sa ligne.
        let wasShown = shown.contains(index), otherShown = shown.contains(target)
        shown.remove(index); shown.remove(target)
        if wasShown { shown.insert(target) }
        if otherShown { shown.insert(index) }
    }

    private func nameBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: { fields.indices.contains(index) ? fields[index].name : "" },
            set: { if fields.indices.contains(index) { fields[index].name = $0 } })
    }

    private func valueBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: { fields.indices.contains(index) ? fields[index].value ?? "" : "" },
            set: { if fields.indices.contains(index) { fields[index].value = $0.isEmpty ? nil : $0 } })
    }
}

// MARK: QR code du Wi-Fi

/// « Afficher le QR code » d'un réseau Wi-Fi : un téléphone le scanne pour
/// rejoindre le réseau. Le mot de passe passe par la même confirmation que
/// les autres secrets (élément protégé) et n'est jamais gardé : seule
/// l'image reste à l'écran, le temps du popover.
struct WifiQRButton: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let title: String
    @State private var image: NSImage?

    var body: some View {
        Button {
            show()
        } label: {
            Label("Afficher le QR code", systemImage: "qrcode")
        }
        .popover(isPresented: Binding(get: { image != nil }, set: { if !$0 { image = nil } }),
                 arrowEdge: .bottom) {
            if let image {
                VStack(spacing: 12) {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 220, height: 220)
                        .padding(10)
                        .background(.white, in: RoundedRectangle(cornerRadius: 8))
                        .accessibilityLabel("QR code du réseau « \(title) »")
                    Text("Scannez avec l'appareil photo pour rejoindre « \(title) ».")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(width: 240)
                }
                .padding(18)
            }
        }
    }

    private func show() {
        if model.awaitsConfirmation(itemID, retry: { show() }) { return }
        guard let payload = try? model.session.wifiQrCode(id: itemID) else {
            model.toast = Toast(message: "QR code impossible", detail: nil, failure: true)
            return
        }
        image = Self.qrImage(payload)
    }

    /// QR code net (sans lissage), correction d'erreur moyenne.
    static func qrImage(_ payload: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let cgImage = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: output.extent.width, height: output.extent.height))
    }
}
