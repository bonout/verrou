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

// MARK: QR code

enum QRCode {
    /// QR code net (sans lissage, 10 pixels par module), correction d'erreur
    /// moyenne. Le contenu n'est gardé nulle part : seule l'image reste.
    static func cgImage(_ payload: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        return CIContext().createCGImage(output, from: output.extent)
    }
}
