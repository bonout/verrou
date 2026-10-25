import Foundation

extension MockLanguage {
    /// Language of the demo vault's words: `VERROU_MOCK_LANG` (`en`, `fr`,
    /// `de`, `es`, `it`) when set, for scripts; otherwise the app's: that of
    /// the first preferred language when the demo vault has it, English
    /// otherwise.
    static var current: MockLanguage {
        if let code = ProcessInfo.processInfo.environment["VERROU_MOCK_LANG"], !code.isEmpty {
            return mockLanguage(code: code)
        }
        return mockLanguage(code: Locale.preferredLanguages.first ?? "en")
    }

    // MARK: The demo vault's words (demo drivers)

    /// The owner's first name, as typed in a search.
    var firstName: String {
        pick("emily", "camille",
             "anna", "lucia", "giulia")
    }

    /// The owner's email address.
    var ownerEmail: String {
        pick("emily.parker@example.com", "camille.martin@exemple.fr",
             "anna.schneider@beispiel.de", "lucia.garcia@ejemplo.es", "giulia.rossi@esempio.it")
    }

    /// The owner's identity.
    var ownerName: String {
        pick("Emily Parker", "Camille Martin",
             "Anna Schneider", "Lucía García", "Giulia Rossi")
    }

    /// The owner's username on developer sites.
    var devUsername: String {
        pick("emily-dev", "camille-dev",
             "anna-dev", "lucia-dev", "giulia-dev")
    }

    /// The favorite card.
    var cardTitle: String {
        pick("Chase Visa", "Visa Boursorama",
             "DKB Visa", "Visa BBVA", "Visa Fineco")
    }

    /// The Wi-Fi network note.
    var wifiTitle: String {
        pick("Home Wi-Fi", "Wi-Fi maison",
             "WLAN Zuhause", "Wi-Fi de casa", "Wi-Fi di casa")
    }

    /// A search that finds the shared family account.
    var familyQuery: String {
        pick("family", "famille",
             "familie", "familia", "famiglia")
    }

    /// The shared family account.
    var familyTitle: String {
        pick("Google — family", "Google — famille",
             "Google — Familie", "Google — familia", "Google — famiglia")
    }

    /// The family's organization.
    var organization: String {
        pick("Parker Family", "Famille Martin",
             "Familie Schneider", "Familia García", "Famiglia Rossi")
    }

    /// The work folder.
    var workFolder: String {
        pick("Work", "Travail",
             "Arbeit", "Trabajo", "Lavoro")
    }

    /// The tax administration's login.
    var taxTitle: String {
        pick("IRS", "Impôts",
             "ELSTER", "Agencia Tributaria", "Agenzia delle Entrate")
    }

    /// A partial search, without accents nor capitals, for `bankTitle`.
    var bankQuery: String {
        pick("bank of am", "societe gen",
             "sparkasse mun", "banco sant", "intesa san")
    }

    /// A bank's login, found by `bankQuery`.
    var bankTitle: String {
        pick("Bank of America", "Société Générale",
             "Sparkasse München", "Banco Santander", "Intesa Sanpaolo")
    }

    /// The demo vault's word for this language.
    private func pick(_ english: String, _ french: String, _ german: String, _ spanish: String,
                      _ italian: String) -> String {
        switch self {
        case .english: english
        case .french: french
        case .german: german
        case .spanish: spanish
        case .italian: italian
        }
    }
}
