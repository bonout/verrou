import SwiftUI

// Réglages et robustesse du générateur de mots de passe, communs au Mac et à
// l'iPhone (les clés `@AppStorage` sont les mêmes partout).

/// Ce que le générateur produit ; le dernier choix est retenu.
enum GeneratorMode: String, CaseIterable {
    case password
    case passphrase

    var label: String {
        switch self {
        case .password: "Mot de passe"
        case .passphrase: "Phrase de passe"
        }
    }
}

/// Séparateur des mots d'une phrase de passe (gardé dans les réglages).
enum PassphraseSeparatorChoice: String, CaseIterable {
    case hyphen, space, period, underscore, comma, digit

    var label: String {
        switch self {
        case .hyphen: "Tiret ( - )"
        case .space: "Espace"
        case .period: "Point ( . )"
        case .underscore: "Tiret bas ( _ )"
        case .comma: "Virgule ( , )"
        case .digit: "Chiffre au hasard"
        }
    }

    var ffi: PassphraseSeparator {
        switch self {
        case .hyphen: .hyphen
        case .space: .space
        case .period: .period
        case .underscore: .underscore
        case .comma: .comma
        case .digit: .digit
        }
    }
}

/// Langue des mots d'une phrase de passe.
enum PassphraseLanguageChoice: String, CaseIterable {
    case french, english

    var label: String {
        switch self {
        case .french: "Français"
        case .english: "English"
        }
    }

    var ffi: PassphraseLanguage {
        switch self {
        case .french: .french
        case .english: .english
        }
    }
}

/// Robustesse estimée (entropie) : barre et mot.
struct StrengthMeter: View {
    let password: String
    /// Entropie connue (phrase de passe générée) ; sinon estimée d'après les
    /// caractères.
    var bits: Double?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let bits = bits ?? passwordStrength(password: password)
        let (label, color, fraction) = Self.grade(bits)
        HStack(spacing: 10) {
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(.quaternary)
                    Capsule().fill(color).frame(width: proxy.size.width * fraction)
                }
            }
            .frame(height: 5)
            Text("\(label) · \(Int(bits)) bits")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
                .fixedSize()
        }
        // La barre se remplit avec un ressort (sans rebond si « Réduire les animations »).
        .animation(reduceMotion ? .easeInOut(duration: 0.2) : .spring(response: 0.5, dampingFraction: 0.62),
                   value: fraction)
    }

    static func grade(_ bits: Double) -> (String, Color, Double) {
        switch bits {
        case ..<40: ("Faible", .red, 0.2)
        case ..<60: ("Moyen", .orange, 0.45)
        case ..<80: ("Bon", .yellow, 0.7)
        case ..<100: ("Fort", .green, 0.88)
        default: ("Excellent", .green, 1)
        }
    }
}
