import SwiftUI

// Interface building blocks shared by the Mac and the iPhone: theme, item
// type labels, highlighted or colored text, one-time codes, transient
// notifications.

// MARK: Theme

enum Theme {
    static let accent = Color("AccentColor")
    static let cornerRadius: CGFloat = 10
    static let digit = Color(red: 0.20, green: 0.48, blue: 0.98)
    static let symbol = Color(red: 0.93, green: 0.36, blue: 0.27)

    /// Stable hue per site or title: the same icon from one launch to the
    /// next, when the server has no icon for the site.
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
        case .login: String(localized: "Logins")
        case .card: String(localized: "Cards")
        case .identity: String(localized: "Identities")
        case .secureNote: String(localized: "Secure notes")
        case .sshKey: String(localized: "SSH keys")
        }
    }

    var singular: String {
        switch self {
        case .login: String(localized: "Login")
        case .card: String(localized: "Card")
        case .identity: String(localized: "Identity")
        case .secureNote: String(localized: "Secure note")
        case .sshKey: String(localized: "SSH key")
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

// MARK: Item icon

/// An item's icon: the site's (provided by the app), otherwise the initial
/// on a stable hue, otherwise the type's symbol.
struct ItemIconContent: View {
    let summary: ItemSummary
    /// Site icon, already loaded (`SiteIcons`).
    let image: PlatformImage?
    var size: CGFloat = 32
    /// Light shadow under the initial; without it, on the iPhone: one text
    /// shadow per row costs an offscreen render while scrolling.
    var initialShadow = true

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
        ZStack {
            if summary.category == .login, summary.template == nil, let image {
                // White background: many icons are transparent and would
                // disappear in dark mode.
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
                let letter = Text(initial)
                    .font(.system(size: size * 0.48, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                if initialShadow {
                    letter.shadow(color: .black.opacity(0.18), radius: 1, y: 0.5)
                } else {
                    letter
                }
            } else {
                shape.fill(summary.tint.gradient)
                Image(systemName: summary.symbol)
                    .font(.system(size: size * 0.44, weight: .semibold))
                    .foregroundStyle(.white)
            }
        }
        .frame(width: size, height: size)
        .clipShape(shape)
        .overlay(shape.strokeBorder(Theme.iconBorder, lineWidth: 0.5))
        .accessibilityHidden(true)
    }

    private var initial: String? {
        summary.title.first.map { String($0).uppercased() }
    }
}

// MARK: Highlighted text

/// Title whose characters found by the search are highlighted.
struct HighlightedText: View {
    let text: String
    let highlights: [UInt32]
    /// `nil` on an accent background (selected row): the accent color would
    /// disappear there, so the found characters are underlined.
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
                    piece[AttributeScopes.SwiftUIAttributes.ForegroundColorAttribute.self] = tint
                } else {
                    piece[AttributeScopes.SwiftUIAttributes.UnderlineStyleAttribute.self] = .single
                }
                piece[AttributeScopes.SwiftUIAttributes.FontAttribute.self] = .body.weight(.semibold)
            }
            result += piece
        }
        return result
    }
}

// MARK: Colored password

/// Revealed password: digits and symbols colored, monospaced font, to tell
/// `O` from `0` and `l` from `1` at a glance.
struct PasswordText: View {
    let value: String
    var size: CGFloat = 15
    /// Selectable text. False under a TextRenderer (the iPhone's "decrypted"
    /// effect): selection goes through another render, which would ignore it.
    var selectable = true

    var body: some View {
        if selectable {
            text.textSelection(.enabled)
        } else {
            text
        }
    }

    private var text: some View {
        Text(attributed)
            .font(.system(size: size, design: .monospaced))
    }

    private var attributed: AttributedString {
        var result = AttributedString()
        for character in value {
            var piece = AttributedString(String(character))
            if character.isNumber {
                piece[AttributeScopes.SwiftUIAttributes.ForegroundColorAttribute.self] = Theme.digit
            } else if !character.isLetter {
                piece[AttributeScopes.SwiftUIAttributes.ForegroundColorAttribute.self] = Theme.symbol
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
            .accessibilityLabel("hidden")
    }
}

// MARK: One-time code

struct TotpCodeView: View {
    let code: TotpView
    var size: CGFloat = 22

    var body: some View {
        HStack(spacing: 10) {
            Text(grouped)
                .font(.system(size: size, weight: .semibold, design: .monospaced))
                .contentTransition(.numericText())
                // The digits roll when the code changes.
                .animation(.snappy, value: code.code)
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

/// The code's countdown: the ring empties, then turns orange and pulses
/// every second during the last 5 (a fade with "Reduce Motion").
struct CountdownRing: View {
    let remaining: UInt64
    let period: UInt64
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let fraction = Double(remaining) / Double(max(period, 1))
        let urgent = remaining <= 5
        let reduceMotion = reduceMotion
        ZStack {
            Circle().stroke(.quaternary, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(urgent ? Color.orange : Theme.accent, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: remaining)
            Text("\(remaining)")
                .font(.system(size: 9, weight: .bold, design: .rounded))
                .contentTransition(.numericText(countsDown: true))
                .animation(.snappy, value: remaining)
                .foregroundStyle(urgent ? Color.orange : Color.secondary)
                .monospacedDigit()
        }
        .animation(.easeInOut(duration: 0.3), value: urgent)
        // One pulse per second, only at the end of the countdown.
        .keyframeAnimator(initialValue: 1.0, trigger: urgent ? remaining : 0) { content, pulse in
            content
                .scaleEffect(urgent && !reduceMotion ? pulse : 1)
                .opacity(urgent && reduceMotion ? 1 - (pulse - 1) * 2.5 : 1)
        } keyframes: { _ in
            CubicKeyframe(1.18, duration: 0.14)
            CubicKeyframe(1.0, duration: 0.36)
        }
        .accessibilityLabel("\(remaining) seconds remaining")
    }
}

// MARK: Transient notification

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


/// A result row: the item's summary and the title characters found by the
/// search.
struct ResultRow: Identifiable {
    let summary: ItemSummary
    let highlights: [UInt32]
    var id: String { summary.id }
}

/// Transient notification (copy, save, error).
struct Toast: Equatable, Identifiable {
    let id = UUID()
    let message: String
    let detail: String?
    var failure = false
    /// Display duration.
    var seconds = 2.2
}
