import SwiftUI

/// Generator: password (length, digits, symbols) or passphrase (words drawn
/// from a list of 7,776, separator, capitals, digit), with a colored preview
/// and its strength. The settings are the Mac's (same keys).
struct GeneratorView: View {
    enum Purpose {
        /// Generator tab: copy the value.
        case copy
        /// Edit screen: the value and, for a passphrase, its exact entropy.
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
    /// Draws made: the "Another" arrow turns one full turn at each.
    @State private var draws = 0
    /// "Copy" just copied: checkmark for 1.5 s.
    @State private var copied = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 16) {
                        // Each new value arrives "decrypted" (iOS 18).
                        DecryptReveal(value: value.isEmpty ? nil : value, fontSize: 22, replaysOnChange: true) { value in
                            PasswordText(value: value, size: 22, selectable: false)
                                .lineLimit(6)
                        } masked: {
                            Color.clear
                        }
                        .frame(maxWidth: .infinity, minHeight: 60, alignment: .leading)
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("Generated value")
                        .accessibilityValue(value)
                        StrengthMeter(password: value, bits: bits)
                        GlassGroup(spacing: 12) {
                            HStack(spacing: 12) {
                                Button {
                                    regenerate()
                                    draws += 1
                                } label: {
                                    Label {
                                        Text("Another")
                                    } icon: {
                                        Image(systemName: "arrow.clockwise")
                                            .rotatesOnChange(of: draws)
                                    }
                                    .labelStyle(.titleAndIcon)
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
            .navigationTitle("Generator")
            .navigationBarTitleDisplayMode(isSheet ? .inline : .large)
            .toolbar {
                if isSheet {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                }
            }
        }
        .onAppear(perform: regenerate)
        #if DEBUG
        // Screenshots: `VERROU_GENERATOR_DEMO=1` draws a value every 2 s.
        .task {
            guard ProcessInfo.processInfo.environment["VERROU_GENERATOR_DEMO"] == "1" else { return }
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                regenerate()
                draws += 1
            }
        }
        #endif
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
                let before = model.copies
                model.copy(value, label: mode == .password ? String(localized: "Password") : String(localized: "Passphrase"), secret: true)
                if model.copies != before { copied = true }
            } label: {
                Label {
                    Text("Copy")
                } icon: {
                    CopySymbol(copied: copied)
                }
                .labelStyle(.titleAndIcon)
                .frame(maxWidth: .infinity)
            }
            .glassButton(prominent: true)
            .modifier(CopiedFlag(copied: $copied))
        case .use(let use):
            Button {
                use(value, bits)
            } label: {
                Label("Use", systemImage: "checkmark").labelStyle(.titleAndIcon).frame(maxWidth: .infinity)
            }
            .glassButton(prominent: true)
        }
    }

    @ViewBuilder private var passwordOptions: some View {
        Section {
            VStack(alignment: .leading) {
                HStack {
                    Text("Length")
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
            Toggle("Digits", isOn: $digits)
            Toggle("Symbols", isOn: $symbols)
        } header: {
            SectionHeader("Password")
        }
    }

    @ViewBuilder private var passphraseOptions: some View {
        Section {
            Stepper("Words: \(Int(words))", value: $words, in: 3...20, step: 1)
            Picker("Separator", selection: $separator) {
                ForEach(PassphraseSeparatorChoice.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            Picker("Language", selection: $language) {
                ForEach(PassphraseLanguageChoice.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            Toggle("Capitals", isOn: $capitalize)
            Toggle("Add a digit", isOn: $number)
        } header: {
            SectionHeader("Passphrase")
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

/// The Generator tab.
struct GeneratorTab: View {
    var body: some View {
        GeneratorView(purpose: .copy)
    }
}
