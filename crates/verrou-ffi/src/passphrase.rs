//! Passphrases for the app's generator: drawn in the core, with their
//! exact entropy (the gauge can't guess it from the characters, which
//! overestimate it by a lot).

use verrou_core::passphrase::{self, Language, PassphraseOptions, Separator};

/// Language of the word list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PassphraseLanguage {
    /// Default.
    French,
    English,
}

/// What separates the words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PassphraseSeparator {
    Hyphen,
    Space,
    Period,
    Underscore,
    Comma,
    /// A random digit between each pair of words.
    Digit,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PassphraseSettings {
    /// Clamped between 3 and 20.
    pub words: u32,
    pub separator: PassphraseSeparator,
    pub capitalize: bool,
    pub include_number: bool,
    pub language: PassphraseLanguage,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GeneratedPassphrase {
    pub value: String,
    /// Exact entropy, in bits, for the strength gauge.
    pub entropy_bits: f64,
}

impl From<&PassphraseSettings> for PassphraseOptions {
    fn from(settings: &PassphraseSettings) -> Self {
        Self {
            words: settings.words as usize,
            separator: match settings.separator {
                PassphraseSeparator::Hyphen => Separator::Hyphen,
                PassphraseSeparator::Space => Separator::Space,
                PassphraseSeparator::Period => Separator::Period,
                PassphraseSeparator::Underscore => Separator::Underscore,
                PassphraseSeparator::Comma => Separator::Comma,
                PassphraseSeparator::Digit => Separator::Digit,
            },
            capitalize: settings.capitalize,
            include_number: settings.include_number,
            language: match settings.language {
                PassphraseLanguage::French => Language::French,
                PassphraseLanguage::English => Language::English,
            },
        }
    }
}

#[uniffi::export]
pub fn generate_passphrase(settings: PassphraseSettings) -> GeneratedPassphrase {
    let options = PassphraseOptions::from(&settings);
    GeneratedPassphrase {
        value: passphrase::passphrase(&options),
        entropy_bits: passphrase::entropy_bits(&options),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_reach_the_core() {
        let generated = generate_passphrase(PassphraseSettings {
            words: 4,
            separator: PassphraseSeparator::Period,
            capitalize: true,
            include_number: true,
            language: PassphraseLanguage::English,
        });
        let words: Vec<_> = generated.value.split('.').collect();
        assert_eq!(words.len(), 4, "{}", generated.value);
        assert!(
            words
                .iter()
                .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
        );
        let expected = 4.0 * 7776f64.log2() + 10f64.log2() + 4f64.log2();
        assert!((generated.entropy_bits - expected).abs() < 1e-9);
    }
}
