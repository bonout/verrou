import SwiftUI

/// Générateur : mot de passe (longueur, chiffres, symboles) ou phrase de
/// passe (mots tirés dans une liste de 7 776, séparateur, majuscules,
/// chiffre), avec un aperçu coloré et sa robustesse. Les réglages sont ceux
/// du Mac (mêmes clés).
struct GeneratorView: View {
    enum Purpose {
        /// Onglet Générateur : copier la valeur.
        case copy
        /// Écran de modification : la valeur et, pour une phrase de passe, son entropie exacte.
        case use((String, Double?) -> Void)
    }

    @Environment(PhoneModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let purpose: Purpose
    @AppStorage("generatorMode") private var mode = GeneratorMode.password
    @AppStorage("generatorLength") private var length = 20.0
    @AppStorage("generatorDigits") private var digits = true
    @AppStorage("generatorSymbols") private var symbols = true
    @AppStorage("generatorWords") private var words = 5.0
    @AppStorage("generatorSeparator") private var separator = PassphraseSeparatorChoice.hyphen
    @AppStorage("generatorCapitalize") private var capitalize = false
    @AppStorage("generatorNumber") private var number = false
    @AppStorage("generatorLanguage") private var language = PassphraseLanguageChoice.french
    @State private var value = ""
    @State private var bits: Double?
    /// Tirages faits : le symbole « Autre » rebondit à chacun.
    @State private var draws = 0

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 16) {
                        PasswordText(value: value, size: 22)
                            .lineLimit(6)
                            .frame(maxWidth: .infinity, minHeight: 60, alignment: .leading)
                            .contentTransition(.interpolate)
                            .accessibilityLabel("Valeur générée")
                            .accessibilityValue(value)
                        StrengthMeter(password: value, bits: bits)
                        GlassGroup(spacing: 12) {
                            HStack(spacing: 12) {
                                Button {
                                    withAnimation(.snappy) { regenerate() }
                                    draws += 1
                                } label: {
                                    Label("Autre", systemImage: "arrow.clockwise")
                                        .labelStyle(.titleAndIcon)
                                        .symbolEffect(.bounce, value: draws)
                                        .frame(maxWidth: .infinity)
                                }
                                .glassButton()
                                primaryButton
                            }
                            .controlSize(.large)
                            .font(.body.weight(.semibold))
                        }
                    }
                    .padding(18)
                    .background(Color(.secondarySystemGroupedBackground),
                                in: RoundedRectangle(cornerRadius: Theme.cardRadius + 6, style: .continuous))
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
                Section {
                    Picker("Type", selection: $mode) {
                        ForEach(GeneratorMode.allCases, id: \.self) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }
                switch mode {
                case .password: passwordOptions
                case .passphrase: passphraseOptions
                }
            }
            .navigationTitle("Générateur")
            .navigationBarTitleDisplayMode(isSheet ? .inline : .large)
            .toolbar {
                if isSheet {
                    ToolbarItem(placement: .cancellationAction) { Button("Annuler") { dismiss() } }
                }
            }
        }
        .onAppear(perform: regenerate)
        .onChange(of: mode) { regenerate() }
        .onChange(of: length) { regenerate() }
        .onChange(of: digits) { regenerate() }
        .onChange(of: symbols) { regenerate() }
        .onChange(of: words) { regenerate() }
        .onChange(of: separator) { regenerate() }
        .onChange(of: capitalize) { regenerate() }
        .onChange(of: number) { regenerate() }
        .onChange(of: language) { regenerate() }
    }

    private var isSheet: Bool {
        if case .use = purpose { return true }
        return false
    }

    @ViewBuilder private var primaryButton: some View {
        switch purpose {
        case .copy:
            Button {
                model.copy(value, label: mode == .password ? "Mot de passe" : "Phrase de passe", secret: true)
            } label: {
                Label("Copier", systemImage: "doc.on.doc").labelStyle(.titleAndIcon).frame(maxWidth: .infinity)
            }
            .glassButton(prominent: true)
        case .use(let use):
            Button {
                use(value, bits)
            } label: {
                Label("Utiliser", systemImage: "checkmark").labelStyle(.titleAndIcon).frame(maxWidth: .infinity)
            }
            .glassButton(prominent: true)
        }
    }

    @ViewBuilder private var passwordOptions: some View {
        Section {
            VStack(alignment: .leading) {
                HStack {
                    Text("Longueur")
                    Spacer()
                    Text("\(Int(length))")
                        .font(.body.weight(.semibold))
                        .monospacedDigit()
                        .foregroundStyle(Theme.accent)
                        .contentTransition(.numericText())
                        .animation(.snappy, value: length)
                }
                Slider(value: $length, in: 8...64, step: 1)
            }
            Toggle("Chiffres", isOn: $digits)
            Toggle("Symboles", isOn: $symbols)
        } header: {
            SectionHeader("Mot de passe")
        }
    }

    @ViewBuilder private var passphraseOptions: some View {
        Section {
            Stepper("Mots : \(Int(words))", value: $words, in: 3...20, step: 1)
            Picker("Séparateur", selection: $separator) {
                ForEach(PassphraseSeparatorChoice.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            Picker("Langue", selection: $language) {
                ForEach(PassphraseLanguageChoice.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            Toggle("Majuscules", isOn: $capitalize)
            Toggle("Ajouter un chiffre", isOn: $number)
        } header: {
            SectionHeader("Phrase de passe")
        }
    }

    private func regenerate() {
        switch mode {
        case .password:
            value = generatePassword(length: UInt32(length), digits: digits, symbols: symbols)
            bits = nil
        case .passphrase:
            let phrase = generatePassphrase(settings: PassphraseSettings(
                words: UInt32(words), separator: separator.ffi, capitalize: capitalize,
                includeNumber: number, language: language.ffi))
            value = phrase.value
            bits = phrase.entropyBits
        }
    }
}

/// L'onglet Générateur.
struct GeneratorTab: View {
    var body: some View {
        GeneratorView(purpose: .copy)
    }
}
