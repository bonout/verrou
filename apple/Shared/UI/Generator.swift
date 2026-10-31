import SwiftUI

// Settings and strength of the password generator, shared by the Mac and
// the iPhone (the `@AppStorage` keys are the same everywhere).

/// What the generator produces; the last choice is remembered.
enum GeneratorMode: String, CaseIterable {
    case password
    case passphrase
    case alias

    var label: String {
        switch self {
        case .password: String(localized: "Password")
        case .passphrase: String(localized: "Passphrase")
        case .alias: String(localized: "Email alias")
        }
    }

    static func available(alias: Bool) -> [GeneratorMode] {
        alias ? allCases : allCases.filter { $0 != .alias }
    }
}

struct EmailAliasSection: View {
    let settings: EmailAliasSettings?
    let save: (String?, Bool) throws -> Void
    @State private var domain = ""
    @State private var error: String?
    @FocusState private var focused: Bool

    var body: some View {
        Section {
            TextField("Alias domain", text: $domain, prompt: Text(verbatim: "alias.example.com"))
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                #endif
                .focused($focused)
                .onSubmit(commit)
            if settings?.domain != nil {
                Toggle("Start with the site's name", isOn: includeSite)
            }
            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }
        } header: {
            #if os(iOS)
            SectionHeader("Email aliases")
            #else
            Text("Email aliases")
            #endif
        } footer: {
            Text("A domain whose mail provider forwards every address to you (catch-all). The generator then makes one address per site, such as netflix.k3x9a@alias.example.com, saved as the login's username. Kept on this device.")
                .foregroundStyle(.secondary)
        }
        .onAppear { domain = settings?.domain ?? "" }
        .onChange(of: settings?.domain) { domain = settings?.domain ?? "" }
        .onChange(of: focused) { if !focused { commit() } }
    }

    private var includeSite: Binding<Bool> {
        Binding(get: { settings?.includeSite ?? true },
                set: { try? save(settings?.domain, $0) })
    }

    private func commit() {
        let trimmed = domain.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed != (settings?.domain ?? "") else {
            error = nil
            return
        }
        do {
            try save(trimmed.isEmpty ? nil : trimmed, settings?.includeSite ?? true)
            error = nil
        } catch {
            self.error = String(localized: "“\(trimmed)” is not a domain name.")
        }
    }
}

/// Separator of a passphrase's words (kept in the settings).
enum PassphraseSeparatorChoice: String, CaseIterable {
    case hyphen, space, period, underscore, comma, digit

    var label: String {
        switch self {
        case .hyphen: String(localized: "Hyphen ( - )")
        case .space: String(localized: "Space")
        case .period: String(localized: "Period ( . )")
        case .underscore: String(localized: "Underscore ( _ )")
        case .comma: String(localized: "Comma ( , )")
        case .digit: String(localized: "Random digit")
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

/// Language of a passphrase's words.
enum PassphraseLanguageChoice: String, CaseIterable {
    case french, english

    static var preferred: PassphraseLanguageChoice {
        Locale.current.language.languageCode == .french ? .french : .english
    }

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

/// Estimated strength (entropy): bar and word.
struct StrengthMeter: View {
    let password: String
    /// Known entropy (generated passphrase); otherwise estimated from the
    /// characters.
    var bits: Double?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let bits = bits ?? passwordStrength(password: password)
        let (label, color, fraction) = Self.grade(bits)
        HStack(spacing: 10) {
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(Theme.faintFill())
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
        // The bar fills with a spring (no bounce with "Reduce Motion").
        .animation(reduceMotion ? .easeInOut(duration: 0.2) : .spring(response: 0.5, dampingFraction: 0.62),
                   value: fraction)
    }

    static func grade(_ bits: Double) -> (String, Color, Double) {
        switch bits {
        case ..<40: (String(localized: "Weak"), .red, 0.2)
        case ..<60: (String(localized: "Fair"), .orange, 0.45)
        case ..<80: (String(localized: "Good"), .yellow, 0.7)
        case ..<100: (String(localized: "Strong"), .green, 0.88)
        default: (String(localized: "Excellent"), .green, 1)
        }
    }
}
