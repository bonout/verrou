import SwiftUI

/// A fingerprint phrase (5 words joined by hyphens), always shown in full:
/// it wraps between its words, never truncated by "…", monospaced and
/// selectable. Comparing it in full is the whole point of the
/// verification.
struct FingerprintText: View {
    @Environment(\.dynamicTypeSize) private var typeSize
    let phrase: String?
    var font: Font = .system(.title3, design: .monospaced).weight(.semibold)
    var alignment: TextAlignment = .center

    var body: some View {
        Text(shown)
            .font(font)
            .multilineTextAlignment(alignment)
            // Large sizes: one word per line, scaled down if needed rather
            // than cut in the middle of a word.
            .lineLimit(large ? wordCount : nil)
            .minimumScaleFactor(large ? 0.5 : 1)
            // All the height needed, even in a short sheet or at large text
            // sizes: never truncated.
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .accessibilityLabel(phrase.map { String(localized: "Fingerprint phrase: \($0.replacingOccurrences(of: "-", with: " "))") } ?? String(localized: "Fingerprint phrase loading"))
    }

    private var large: Bool { typeSize.isAccessibilitySize && phrase != nil }

    private var wordCount: Int { (phrase ?? "").split(separator: "-").count }

    /// At large text sizes, one word per line (without the hyphens, which
    /// would wrap on their own); otherwise the phrase as is.
    private var shown: String {
        guard let phrase else { return "…" }
        return large ? phrase.split(separator: "-").joined(separator: "\n") : phrase
    }
}
