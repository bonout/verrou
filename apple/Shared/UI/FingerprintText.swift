import SwiftUI

/// Une phrase d'empreinte (5 mots reliés par des tirets), toujours affichée
/// en entier : elle passe à la ligne entre ses mots, jamais tronquée par
/// « … », en chasse fixe et sélectionnable. La comparer en entier est tout
/// l'intérêt de la vérification.
struct FingerprintText: View {
    @Environment(\.dynamicTypeSize) private var typeSize
    let phrase: String?
    var font: Font = .system(.title3, design: .monospaced).weight(.semibold)
    var alignment: TextAlignment = .center

    var body: some View {
        Text(shown)
            .font(font)
            .multilineTextAlignment(alignment)
            // Grandes tailles : un mot par ligne, réduit au besoin plutôt
            // que coupé en plein mot.
            .lineLimit(large ? wordCount : nil)
            .minimumScaleFactor(large ? 0.5 : 1)
            // Toute la hauteur nécessaire, même dans une feuille courte ou
            // aux grandes tailles de texte : jamais de troncature.
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .accessibilityLabel(phrase.map { "Phrase d'empreinte : \($0.replacingOccurrences(of: "-", with: " "))" } ?? "Phrase d'empreinte en cours de lecture")
    }

    private var large: Bool { typeSize.isAccessibilitySize && phrase != nil }

    private var wordCount: Int { (phrase ?? "").split(separator: "-").count }

    /// Aux grandes tailles de texte, un mot par ligne (sans les tirets, qui
    /// passeraient seuls à la ligne) ; sinon la phrase telle quelle.
    private var shown: String {
        guard let phrase else { return "…" }
        return large ? phrase.split(separator: "-").joined(separator: "\n") : phrase
    }
}
