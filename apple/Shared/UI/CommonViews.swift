import SwiftUI

// Briques d'interface communes au Mac et à l'iPhone : thème, libellés des
// types d'éléments, textes surlignés ou colorés, codes à usage unique,
// notifications éphémères.

// MARK: Thème

enum Theme {
    static let accent = Color("AccentColor")
    static let cornerRadius: CGFloat = 10
    static let digit = Color(red: 0.20, green: 0.48, blue: 0.98)
    static let symbol = Color(red: 0.93, green: 0.36, blue: 0.27)

    /// Teinte stable par site ou par titre : la même icône d'un lancement à
    /// l'autre, quand le serveur n'a pas d'icône pour le site.
    static func hue(for key: String) -> Double {
        var hash: UInt64 = 1469598103934665603
        for byte in key.utf8 {
            hash = (hash ^ UInt64(byte)) &* 1099511628211
        }
        return Double(hash % 360) / 360
    }
}

extension ItemCategory {
    var label: String {
        switch self {
        case .login: "Identifiants"
        case .card: "Cartes bancaires"
        case .identity: "Identités"
        case .secureNote: "Notes sécurisées"
        case .sshKey: "Clés SSH"
        }
    }

    var singular: String {
        switch self {
        case .login: "Identifiant"
        case .card: "Carte bancaire"
        case .identity: "Identité"
        case .secureNote: "Note sécurisée"
        case .sshKey: "Clé SSH"
        }
    }

    var symbol: String {
        switch self {
        case .login: "key.horizontal.fill"
        case .card: "creditcard.fill"
        case .identity: "person.text.rectangle.fill"
        case .secureNote: "note.text"
        case .sshKey: "terminal.fill"
        }
    }

    var tint: Color {
        switch self {
        case .login: .blue
        case .card: .orange
        case .identity: .green
        case .secureNote: .yellow
        case .sshKey: .purple
        }
    }
}

// MARK: Icône d'élément

/// Icône d'un élément : celle du site (fournie par l'app), sinon
/// l'initiale sur une teinte stable, sinon le symbole du type.
struct ItemIconContent: View {
    let summary: ItemSummary
    /// Icône du site, déjà chargée (`SiteIcons`).
    let image: PlatformImage?
    var size: CGFloat = 32

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
        ZStack {
            if summary.category == .login, summary.template == nil, let image {
                // Fond blanc : beaucoup d'icônes sont transparentes et
                // disparaîtraient en mode sombre.
                shape.fill(.white)
                Image(platformImage: image)
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(contentMode: .fit)
                    .padding(size * 0.14)
            } else if summary.category == .login, summary.template == nil, let initial = initial {
                let hue = Theme.hue(for: summary.host ?? summary.title)
                shape.fill(
                    LinearGradient(
                        colors: [Color(hue: hue, saturation: 0.62, brightness: 0.90),
                                 Color(hue: hue, saturation: 0.78, brightness: 0.68)],
                        startPoint: .topLeading, endPoint: .bottomTrailing))
                Text(initial)
                    .font(.system(size: size * 0.48, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .shadow(color: .black.opacity(0.18), radius: 1, y: 0.5)
            } else {
                shape.fill(summary.tint.gradient)
                Image(systemName: summary.symbol)
                    .font(.system(size: size * 0.44, weight: .semibold))
                    .foregroundStyle(.white)
            }
        }
        .frame(width: size, height: size)
        .clipShape(shape)
        .overlay(shape.strokeBorder(.primary.opacity(0.12), lineWidth: 0.5))
        .accessibilityHidden(true)
    }

    private var initial: String? {
        summary.title.first.map { String($0).uppercased() }
    }
}

// MARK: Texte surligné

/// Titre dont les caractères trouvés par la recherche sont mis en évidence.
struct HighlightedText: View {
    let text: String
    let highlights: [UInt32]
    /// `nil` sur fond d'accent (ligne sélectionnée) : la couleur d'accent y
    /// disparaîtrait, les caractères trouvés sont alors soulignés.
    var tint: Color? = Theme.accent

    var body: some View {
        Text(attributed)
    }

    private var attributed: AttributedString {
        var result = AttributedString()
        let marked = Set(highlights)
        for (offset, character) in text.enumerated() {
            var piece = AttributedString(String(character))
            if marked.contains(UInt32(offset)) {
                if let tint {
                    piece.foregroundColor = tint
                } else {
                    piece.underlineStyle = .single
                }
                piece.font = .body.weight(.semibold)
            }
            result += piece
        }
        return result
    }
}

// MARK: Mot de passe coloré

/// Mot de passe révélé : chiffres et symboles colorés, police à chasse fixe,
/// pour distinguer `O` de `0` et `l` de `1` en un coup d'œil.
struct PasswordText: View {
    let value: String
    var size: CGFloat = 15

    var body: some View {
        Text(attributed)
            .font(.system(size: size, design: .monospaced))
            .textSelection(.enabled)
    }

    private var attributed: AttributedString {
        var result = AttributedString()
        for character in value {
            var piece = AttributedString(String(character))
            if character.isNumber {
                piece.foregroundColor = Theme.digit
            } else if !character.isLetter {
                piece.foregroundColor = Theme.symbol
            }
            result += piece
        }
        return result
    }
}

struct MaskedText: View {
    var count = 12
    var body: some View {
        Text(String(repeating: "•", count: count))
            .font(.system(size: 15, design: .monospaced))
            .foregroundStyle(.secondary)
            .accessibilityLabel("masqué")
    }
}

// MARK: Code à usage unique

struct TotpCodeView: View {
    let code: TotpView
    var size: CGFloat = 22

    var body: some View {
        HStack(spacing: 10) {
            Text(grouped)
                .font(.system(size: size, weight: .semibold, design: .monospaced))
                .contentTransition(.numericText())
            CountdownRing(remaining: code.remaining, period: code.period)
                .frame(width: size * 0.9, height: size * 0.9)
        }
    }

    private var grouped: String {
        let digits = Array(code.code)
        let half = digits.count / 2
        return String(digits[..<half]) + " " + String(digits[half...])
    }
}

struct CountdownRing: View {
    let remaining: UInt64
    let period: UInt64

    var body: some View {
        let fraction = Double(remaining) / Double(max(period, 1))
        let urgent = remaining <= 7
        ZStack {
            Circle().stroke(.quaternary, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(urgent ? Color.orange : Theme.accent, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: remaining)
            Text("\(remaining)")
                .font(.system(size: 9, weight: .bold, design: .rounded))
                .foregroundStyle(urgent ? Color.orange : Color.secondary)
                .monospacedDigit()
        }
        .accessibilityLabel("\(remaining) secondes restantes")
    }
}

// MARK: Notification éphémère

struct ToastView: View {
    let toast: Toast

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: toast.failure ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(toast.failure ? .orange : .green)
                .font(.title3)
            VStack(alignment: .leading, spacing: 1) {
                Text(toast.message).font(.callout.weight(.semibold))
                if let detail = toast.detail {
                    Text(detail).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(.separator, lineWidth: 0.5))
        .shadow(color: .black.opacity(0.15), radius: 12, y: 4)
    }
}


/// Une ligne de résultat : le résumé de l'élément et les caractères du titre
/// trouvés par la recherche.
struct ResultRow: Identifiable {
    let summary: ItemSummary
    let highlights: [UInt32]
    var id: String { summary.id }
}

/// Notification éphémère (copie, enregistrement, erreur).
struct Toast: Equatable, Identifiable {
    let id = UUID()
    let message: String
    let detail: String?
    var failure = false
    /// Durée d'affichage.
    var seconds = 2.2
}

// MARK: Logo

/// Le logo : un verrou sur un écusson arrondi.
struct AppMark: View {
    var size: CGFloat = 64

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                .fill(LinearGradient(colors: [Color(red: 0.36, green: 0.42, blue: 1.0), Color(red: 0.20, green: 0.17, blue: 0.62)],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
                .shadow(color: Color(red: 0.25, green: 0.25, blue: 0.8).opacity(0.35), radius: size * 0.18, y: size * 0.08)
            Image(systemName: "lock.fill")
                .font(.system(size: size * 0.46, weight: .semibold))
                .foregroundStyle(.white.gradient)
        }
        .frame(width: size, height: size)
    }
}
