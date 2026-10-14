//! Phrases de passe (« diceware ») : des mots tirés au hasard dans une grande
//! liste, comme le « mot de passe mémorisable » de 1Password ou la phrase de
//! passe de Bitwarden.
//!
//! Le hasard vient du générateur du système (`OsRng`) ; chaque mot est tiré
//! uniformément par rejet (pas de biais de modulo). Les listes sont
//! embarquées à la compilation, telles que publiées par leurs auteurs (voir
//! `wordlists/NOTICE`) : Verrou n'en garde que le mot de chaque ligne, en
//! minuscules, sans doublon.

use std::sync::LazyLock;

use rand::{CryptoRng, RngCore};

/// Liste de l'EFF (« large wordlist », 7 776 mots, CC BY 3.0 US).
const EFF_LARGE: &str = include_str!("../wordlists/eff_large_wordlist.txt");
/// Liste française de Tango pour Tails et Tor (7 776 lignes, CC0 1.0).
const FRENCH: &str = include_str!("../wordlists/wordlist_fr.txt");

pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;
pub const DEFAULT_WORDS: usize = 5;

static ENGLISH_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| parse(EFF_LARGE));
static FRENCH_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| parse(FRENCH));

/// Langue de la liste de mots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Language {
    #[default]
    French,
    English,
}

impl Language {
    /// Mots de la liste, en minuscules, sans doublon, dans l'ordre du fichier.
    pub fn words(self) -> &'static [&'static str] {
        match self {
            Self::French => &FRENCH_WORDS,
            Self::English => &ENGLISH_WORDS,
        }
    }
}

/// Ce qui sépare les mots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Separator {
    #[default]
    Hyphen,
    Space,
    Period,
    Underscore,
    Comma,
    /// Un chiffre tiré au hasard entre chaque paire de mots.
    Digit,
}

impl Separator {
    /// `-`, ` `, `.`, `_`, `,` ou `digit` (aussi `space`, `chiffre`).
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "-" | "hyphen" => Self::Hyphen,
            " " | "space" | "espace" => Self::Space,
            "." | "period" | "point" => Self::Period,
            "_" | "underscore" => Self::Underscore,
            "," | "comma" | "virgule" => Self::Comma,
            "digit" | "chiffre" | "0-9" => Self::Digit,
            _ => return None,
        })
    }

    fn fixed(self) -> Option<char> {
        match self {
            Self::Hyphen => Some('-'),
            Self::Space => Some(' '),
            Self::Period => Some('.'),
            Self::Underscore => Some('_'),
            Self::Comma => Some(','),
            Self::Digit => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// Nombre de mots, ramené entre 3 et 20.
    pub words: usize,
    pub separator: Separator,
    /// Initiale de chaque mot en majuscule.
    pub capitalize: bool,
    /// Un chiffre ajouté à la fin d'un mot tiré au hasard.
    pub include_number: bool,
    pub language: Language,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: DEFAULT_WORDS,
            separator: Separator::default(),
            capitalize: false,
            include_number: false,
            language: Language::default(),
        }
    }
}

impl PassphraseOptions {
    fn word_count(&self) -> usize {
        self.words.clamp(MIN_WORDS, MAX_WORDS)
    }
}

/// Phrase de passe tirée avec le générateur du système.
pub fn passphrase(options: &PassphraseOptions) -> String {
    passphrase_with(&mut rand::rngs::OsRng, options)
}

pub fn passphrase_with<R: RngCore + CryptoRng>(rng: &mut R, options: &PassphraseOptions) -> String {
    generate(rng, options.language.words(), options)
}

/// Entropie exacte, en bits, d'une phrase tirée avec ces réglages :
/// log2(taille de la liste) par mot, plus le chiffre et sa position, plus
/// les chiffres séparateurs. La majuscule n'ajoute rien (elle est fixe).
pub fn entropy_bits(options: &PassphraseOptions) -> f64 {
    entropy_for(options.language.words().len(), options)
}

fn entropy_for(list_len: usize, options: &PassphraseOptions) -> f64 {
    let words = options.word_count();
    let mut bits = words as f64 * (list_len as f64).log2();
    if options.include_number {
        bits += 10f64.log2() + (words as f64).log2();
    }
    if options.separator == Separator::Digit {
        bits += (words - 1) as f64 * 10f64.log2();
    }
    bits
}

fn generate<R: RngCore + CryptoRng>(
    rng: &mut R,
    list: &[&str],
    options: &PassphraseOptions,
) -> String {
    let count = options.word_count();
    let numbered = options
        .include_number
        .then(|| (uniform_index(rng, count), digit(rng)));
    let mut out = String::new();
    for i in 0..count {
        if i > 0 {
            match options.separator.fixed() {
                Some(c) => out.push(c),
                None => out.push(digit(rng)),
            }
        }
        let word = list[uniform_index(rng, list.len())];
        if options.capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
        if let Some((_, d)) = numbered.filter(|(at, _)| *at == i) {
            out.push(d);
        }
    }
    out
}

fn digit<R: RngCore>(rng: &mut R) -> char {
    char::from(b'0' + uniform_index(rng, 10) as u8)
}

/// Entier uniforme dans `0..n`, par rejet : on écarte les tirages au-delà du
/// plus grand multiple de `n` qui tient sur 32 bits, puis on prend le reste.
fn uniform_index<R: RngCore>(rng: &mut R, n: usize) -> usize {
    assert!(
        n > 0 && u32::try_from(n).is_ok(),
        "taille de tirage invalide"
    );
    let n = n as u64;
    let limit = (1u64 << 32) / n * n;
    loop {
        let x = u64::from(rng.next_u32());
        if x < limit {
            return (x % n) as usize;
        }
    }
}

/// Une ligne = « numéro de dés, mot » (ou le mot seul) : on garde le dernier
/// champ, en minuscules, sans doublon.
fn parse(source: &'static str) -> Vec<&'static str> {
    let mut seen = std::collections::HashSet::new();
    let mut words = Vec::with_capacity(7776);
    for line in source.lines() {
        let Some(word) = line.split_whitespace().last() else {
            continue;
        };
        // Les mots sont en ASCII ; une majuscule éventuelle (« Internet »)
        // donne un doublon qu'on écarte.
        let word: &'static str = if word.bytes().any(|b| b.is_ascii_uppercase()) {
            Box::leak(word.to_ascii_lowercase().into_boxed_str())
        } else {
            word
        };
        if seen.insert(word) {
            words.push(word);
        }
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng(seed: u64) -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(seed)
    }

    #[test]
    fn wordlists_are_intact() {
        let english = Language::English.words();
        assert_eq!(english.len(), 7776);
        // La liste française contient « Internet » et « internet » : un
        // doublon une fois en minuscules.
        let french = Language::French.words();
        assert_eq!(french.len(), 7775);
        for list in [english, french] {
            let unique: std::collections::HashSet<_> = list.iter().collect();
            assert_eq!(unique.len(), list.len(), "doublon");
            for word in list {
                assert_ne!(*word, "");
                assert!(
                    word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                    "mot inattendu : {word:?}"
                );
            }
        }
        // L'EFF garde quatre mots composés (« t-shirt »…), le français aucun.
        assert_eq!(english.iter().filter(|w| w.contains('-')).count(), 4);
        assert!(french.iter().all(|w| !w.contains('-')));
        assert!(english.contains(&"abacus") && english.contains(&"zoom"));
        assert!(french.contains(&"abaisse") && french.contains(&"internet"));
    }

    #[test]
    fn eff_list_is_prefix_free() {
        let english = Language::English.words();
        let set: std::collections::HashSet<_> = english.iter().copied().collect();
        for word in english {
            for end in 1..word.len() {
                assert!(
                    !set.contains(&word[..end]),
                    "{} préfixe de {word}",
                    &word[..end]
                );
            }
        }
    }

    #[test]
    fn default_is_five_french_words_with_hyphens() {
        let p = passphrase_with(&mut rng(1), &PassphraseOptions::default());
        let words: Vec<_> = p.split('-').collect();
        assert_eq!(words.len(), 5);
        for w in words {
            assert!(Language::French.words().contains(&w), "{w}");
        }
    }

    #[test]
    fn word_count_is_clamped() {
        for (asked, got) in [(0, 3), (3, 3), (7, 7), (20, 20), (99, 20)] {
            let options = PassphraseOptions {
                words: asked,
                separator: Separator::Space,
                language: Language::English,
                ..Default::default()
            };
            let p = passphrase_with(&mut rng(2), &options);
            assert_eq!(p.split(' ').count(), got);
        }
    }

    #[test]
    fn separators() {
        for (separator, c) in [
            (Separator::Hyphen, '-'),
            (Separator::Space, ' '),
            (Separator::Period, '.'),
            (Separator::Underscore, '_'),
            (Separator::Comma, ','),
        ] {
            let options = PassphraseOptions {
                separator,
                words: 6,
                ..Default::default()
            };
            let p = passphrase_with(&mut rng(3), &options);
            assert_eq!(p.split(c).count(), 6, "{p}");
        }
        let options = PassphraseOptions {
            separator: Separator::Digit,
            words: 6,
            ..Default::default()
        };
        let p = passphrase_with(&mut rng(4), &options);
        let parts: Vec<_> = p.split(|c: char| c.is_ascii_digit()).collect();
        assert_eq!(parts.len(), 6, "{p}");
        assert_eq!(p.chars().filter(char::is_ascii_digit).count(), 5);
        assert_eq!(Separator::parse("digit"), Some(Separator::Digit));
        assert_eq!(Separator::parse(" "), Some(Separator::Space));
        assert_eq!(Separator::parse("x"), None);
    }

    #[test]
    fn capitalize_and_number() {
        let options = PassphraseOptions {
            capitalize: true,
            include_number: true,
            ..Default::default()
        };
        let mut positions = std::collections::HashSet::new();
        let mut r = rng(5);
        for _ in 0..500 {
            let p = passphrase_with(&mut r, &options);
            let words: Vec<_> = p.split('-').collect();
            assert_eq!(words.len(), 5);
            let numbered: Vec<_> = words
                .iter()
                .enumerate()
                .filter(|(_, w)| w.ends_with(|c: char| c.is_ascii_digit()))
                .collect();
            assert_eq!(numbered.len(), 1, "{p}");
            positions.insert(numbered[0].0);
            for w in &words {
                assert!(w.starts_with(|c: char| c.is_ascii_uppercase()), "{p}");
                let bare = w.trim_end_matches(|c: char| c.is_ascii_digit());
                assert!(bare.len() >= w.len() - 1);
                assert!(
                    Language::French
                        .words()
                        .contains(&bare.to_lowercase().as_str())
                );
            }
        }
        // Le chiffre peut tomber sur chaque mot.
        assert_eq!(positions.len(), 5);
    }

    #[test]
    fn entropy_matches_formula() {
        let base = PassphraseOptions {
            language: Language::English,
            ..Default::default()
        };
        let per_word = 7776f64.log2();
        assert!((entropy_bits(&base) - 5.0 * per_word).abs() < 1e-9);
        assert!((entropy_bits(&base) - 64.6).abs() < 0.1);
        let numbered = PassphraseOptions {
            include_number: true,
            ..base.clone()
        };
        let extra = 10f64.log2() + 5f64.log2();
        assert!((entropy_bits(&numbered) - 5.0 * per_word - extra).abs() < 1e-9);
        let digits = PassphraseOptions {
            separator: Separator::Digit,
            ..base.clone()
        };
        assert!((entropy_bits(&digits) - 5.0 * per_word - 4.0 * 10f64.log2()).abs() < 1e-9);
        let capital = PassphraseOptions {
            capitalize: true,
            ..base.clone()
        };
        assert!((entropy_bits(&capital) - entropy_bits(&base)).abs() < 1e-9);
        let french = PassphraseOptions::default();
        assert!((entropy_bits(&french) - 5.0 * 7775f64.log2()).abs() < 1e-9);
        // Le nombre de mots est ramené dans les bornes, l'entropie aussi.
        let many = PassphraseOptions { words: 50, ..base };
        assert!((entropy_bits(&many) - 20.0 * per_word).abs() < 1e-9);
    }

    #[test]
    fn every_word_of_a_small_list_is_reachable_and_roughly_uniform() {
        // Liste de 7 mots : 7 ne divise pas 2^32, le rejet doit corriger le biais.
        let list = ["a", "b", "c", "d", "e", "f", "g"];
        let options = PassphraseOptions {
            words: 3,
            ..Default::default()
        };
        let mut counts = [0u32; 7];
        let mut r = rng(6);
        let draws = 30_000;
        for _ in 0..draws / 3 {
            for w in generate(&mut r, &list, &options).split('-') {
                counts[list.iter().position(|x| *x == w).unwrap()] += 1;
            }
        }
        let expected = f64::from(draws) / 7.0;
        let chi2: f64 = counts
            .iter()
            .map(|&c| (f64::from(c) - expected).powi(2) / expected)
            .sum();
        // 6 degrés de liberté : 22,46 au seuil de 0,1 %.
        assert!(chi2 < 22.46, "chi2 = {chi2}, {counts:?}");
        assert!(counts.iter().all(|&c| c > 0));
    }

    #[test]
    fn uniform_index_rejects_the_biased_tail() {
        // Générateur truqué : d'abord u32::MAX (dans la zone rejetée pour
        // n = 3, car 2^32 n'est pas multiple de 3), puis 4.
        struct Scripted(Vec<u32>);
        impl RngCore for Scripted {
            fn next_u32(&mut self) -> u32 {
                self.0.remove(0)
            }
            fn next_u64(&mut self) -> u64 {
                u64::from(self.next_u32())
            }
            fn fill_bytes(&mut self, _: &mut [u8]) {
                unreachable!()
            }
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
                unreachable!()
            }
        }
        let mut r = Scripted(vec![u32::MAX, 4]);
        assert_eq!(uniform_index(&mut r, 3), 1);
        assert_eq!(r.0.len(), 0);
        // Puissance de deux : rien n'est rejeté.
        let mut r = Scripted(vec![u32::MAX]);
        assert_eq!(uniform_index(&mut r, 8), 7);
    }

    #[test]
    fn real_entropy_is_fresh() {
        let a = passphrase(&PassphraseOptions::default());
        let b = passphrase(&PassphraseOptions::default());
        assert_ne!(a, b);
    }
}
