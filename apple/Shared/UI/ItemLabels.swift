import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

// MARK: Templates

/// 1Password-style item templates: secure notes (or logins) with predefined
/// fields, recognized thanks to the reserved `verrou:type` field (see
/// `verrou_core::template`).
extension ItemTemplate {
    /// Order of the "New item" menu and of the sidebar.
    static let menuOrder: [ItemTemplate] = [
        .softwareLicense, .wifi, .bankAccount, .passport, .driversLicense,
        .idCard, .server, .database, .apiKey, .membership,
    ]

    var label: String {
        switch self {
        case .softwareLicense: String(localized: "Software licenses")
        case .wifi: String(localized: "Wi-Fi networks")
        case .bankAccount: String(localized: "Bank accounts")
        case .passport: String(localized: "Passports")
        case .driversLicense: String(localized: "Driver's licenses")
        case .idCard: String(localized: "ID cards")
        case .server: String(localized: "Servers")
        case .database: String(localized: "Databases")
        case .apiKey: String(localized: "API keys")
        case .membership: String(localized: "Memberships and subscriptions")
        }
    }

    var singular: String {
        switch self {
        case .softwareLicense: String(localized: "Software license")
        case .wifi: String(localized: "Wi-Fi network")
        case .bankAccount: String(localized: "Bank account")
        case .passport: String(localized: "Passport")
        case .driversLicense: String(localized: "Driver's license")
        case .idCard: String(localized: "ID card")
        case .server: String(localized: "Server")
        case .database: String(localized: "Database")
        case .apiKey: String(localized: "API key")
        case .membership: String(localized: "Membership or subscription")
        }
    }

    /// Label in the "New item" menu.
    var menuTitle: String {
        self == .membership ? String(localized: "Membership/subscription") : singular
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

    /// Sample title on creation.
    var titlePrompt: String {
        switch self {
        case .softwareLicense: String(localized: "Software")
        case .wifi: String(localized: "Home Wi-Fi")
        case .bankAccount: String(localized: "Checking account")
        case .passport: String(localized: "Passport")
        case .driversLicense: String(localized: "Driver's license")
        case .idCard: String(localized: "ID card")
        case .server: String(localized: "Web server")
        case .database: String(localized: "Production database")
        case .apiKey: String(localized: "API key")
        case .membership: String(localized: "Subscription")
        }
    }
}

extension ItemSummary {
    /// Icon symbol and tint: the template's, otherwise the type's.
    var symbol: String { template?.symbol ?? category.symbol }
    var tint: Color { template?.tint ?? category.tint }
    var kindLabel: String { template?.singular ?? category.singular }
}

extension ItemSharing {
    /// "Organization › Collection, Collection".
    var label: String {
        collections.isEmpty ? organization : "\(organization) › \(collections.joined(separator: ", "))"
    }
}

// MARK: QR code

enum QRCode {
    /// Sharp QR code (no smoothing, 10 pixels per module), medium error
    /// correction. The content is kept nowhere: only the image remains.
    static func cgImage(_ payload: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        return CIContext().createCGImage(output, from: output.extent)
    }
}
