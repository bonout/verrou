import Foundation

extension MockLanguage {
    /// Language of the demo vault's words: `VERROU_MOCK_LANG` (`en`, `fr`)
    /// when set, for scripts; otherwise the app's, French when the first
    /// preferred language is French, English otherwise.
    static var current: MockLanguage {
        if let code = ProcessInfo.processInfo.environment["VERROU_MOCK_LANG"], !code.isEmpty {
            return mockLanguage(code: code)
        }
        return mockLanguage(code: Locale.preferredLanguages.first ?? "en")
    }

    /// The demo vault's word for this language (demo drivers, UI tests).
    func pick(_ english: String, _ french: String) -> String {
        self == .french ? french : english
    }
}
