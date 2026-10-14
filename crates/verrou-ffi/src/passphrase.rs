//! Phrases de passe pour le générateur de l'app : tirées dans le cœur, avec
//! leur entropie exacte (la jauge ne peut pas la deviner d'après les
//! caractères, qui la surestiment de beaucoup).

use verrou_core::passphrase::{self, Language, PassphraseOptions, Separator};

/// Langue de la liste de mots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PassphraseLanguage {
    /// Par défaut.
    French,
    English,
}

/// Ce qui sépare les mots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PassphraseSeparator {
    Hyphen,
    Space,
    Period,
    Underscore,
    Comma,
    /// Un chiffre au hasard entre chaque paire de mots.
    Digit,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PassphraseSettings {
    /// Ramené entre 3 et 20.
    pub words: u32,
    pub separator: PassphraseSeparator,
    pub capitalize: bool,
    pub include_number: bool,
    pub language: PassphraseLanguage,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GeneratedPassphrase {
    pub value: String,
    /// Entropie exacte, en bits, pour la jauge de robustesse.
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
