//! Password and PIN generator.
//!
//! Randomness comes from the system generator (`OsRng`); a deterministic source
//! is accepted only for mock data and tests.

use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";
// Ambiguous characters excluded by default: l, I, O, 0, 1.
const LOWER_ALL: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER_ALL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS_ALL: &str = "0123456789";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
        }
    }
}

/// Random password, with at least one character from each requested
/// class.
pub fn password(options: &PasswordOptions) -> String {
    password_with(&mut rand::rngs::OsRng, options)
}

pub fn password_with<R: RngCore + CryptoRng>(rng: &mut R, options: &PasswordOptions) -> String {
    let (lower, upper, digits) = if options.avoid_ambiguous {
        (LOWER, UPPER, DIGITS)
    } else {
        (LOWER_ALL, UPPER_ALL, DIGITS_ALL)
    };
    let mut classes: Vec<Vec<char>> = vec![lower.chars().collect(), upper.chars().collect()];
    if options.digits {
        classes.push(digits.chars().collect());
    }
    if options.symbols {
        classes.push(SYMBOLS.chars().collect());
    }
    let length = options.length.clamp(classes.len().max(8), 128);
    let pool: Vec<char> = classes.iter().flatten().copied().collect();

    let mut chars: Vec<char> = classes
        .iter()
        .map(|class| class[rng.gen_range(0..class.len())])
        .collect();
    while chars.len() < length {
        chars.push(pool[rng.gen_range(0..pool.len())]);
    }
    chars.shuffle(rng);
    chars.into_iter().collect()
}

/// Numeric PIN code.
pub fn pin<R: RngCore + CryptoRng>(rng: &mut R, length: usize) -> String {
    (0..length.clamp(4, 12))
        .map(|_| char::from(b'0' + rng.gen_range(0..10u8)))
        .collect()
}

/// Approximate entropy, in bits, for the strength gauge.
pub fn entropy_bits(password: &str) -> f64 {
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32;
    }
    if pool == 0 {
        return 0.0;
    }
    password.chars().count() as f64 * f64::from(pool).log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn every_requested_class_is_present() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        for _ in 0..200 {
            let p = password_with(&mut rng, &PasswordOptions::default());
            assert_eq!(p.chars().count(), 20);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!p.contains(['l', 'I', 'O', '0', '1']));
        }
    }

    #[test]
    fn length_is_clamped() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let short = password_with(
            &mut rng,
            &PasswordOptions {
                length: 2,
                ..Default::default()
            },
        );
        assert_eq!(short.len(), 8);
        let long = password_with(
            &mut rng,
            &PasswordOptions {
                length: 500,
                ..Default::default()
            },
        );
        assert_eq!(long.len(), 128);
    }

    #[test]
    fn entropy_grows_with_length_and_classes() {
        assert!(entropy_bits("abcdefgh") < entropy_bits("abcdefghij"));
        assert!(entropy_bits("abcdefgh") < entropy_bits("abcdEF1!"));
        assert!(entropy_bits(&password(&PasswordOptions::default())) > 120.0);
    }
}
