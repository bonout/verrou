//! Codes à usage unique (RFC 6238), à partir d'une graine Base32 ou d'une URI
//! `otpauth://`.

use hmac::{Hmac, Mac};
use thiserror::Error;
use url::Url;

macro_rules! hmac_digest {
    ($hash:ty, $key:expr, $msg:expr) => {{
        let mut mac =
            Hmac::<$hash>::new_from_slice($key).expect("HMAC accepte toute longueur de clé");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("graine TOTP vide")]
    Empty,
    #[error("graine TOTP illisible (Base32 attendu)")]
    InvalidSecret,
    #[error("URI otpauth invalide")]
    InvalidUri,
    #[error("paramètre TOTP non pris en charge : {0}")]
    Unsupported(String),
}

/// Paramètres d'un générateur TOTP. La graine décodée est effacée à la
/// libération.
#[derive(Clone, Debug)]
pub struct Totp {
    secret: zeroize::Zeroizing<Vec<u8>>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

/// Un code et sa fenêtre de validité.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub period: u64,
    /// Secondes restantes avant le code suivant.
    pub remaining: u64,
}

impl Totp {
    pub fn parse(input: &str) -> Result<Self, TotpError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(TotpError::Empty);
        }
        if input.to_ascii_lowercase().starts_with("otpauth://") {
            return Self::parse_uri(input);
        }
        Ok(Self {
            secret: decode_base32(input)?,
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
        })
    }

    fn parse_uri(input: &str) -> Result<Self, TotpError> {
        let uri = Url::parse(input).map_err(|_| TotpError::InvalidUri)?;
        if uri.host_str() != Some("totp") {
            return Err(TotpError::Unsupported(
                uri.host_str().unwrap_or("").to_owned(),
            ));
        }
        let mut totp = Self {
            secret: zeroize::Zeroizing::new(Vec::new()),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
        };
        let mut has_secret = false;
        for (key, value) in uri.query_pairs() {
            match key.as_ref() {
                "secret" => {
                    totp.secret = decode_base32(&value)?;
                    has_secret = true;
                }
                "digits" => {
                    totp.digits = value
                        .parse()
                        .ok()
                        .filter(|d| (6..=10).contains(d))
                        .ok_or_else(|| TotpError::Unsupported(format!("digits={value}")))?;
                }
                "period" => {
                    totp.period = value
                        .parse()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or_else(|| TotpError::Unsupported(format!("period={value}")))?;
                }
                "algorithm" => {
                    totp.algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        other => return Err(TotpError::Unsupported(other.to_owned())),
                    };
                }
                _ => {}
            }
        }
        if has_secret {
            Ok(totp)
        } else {
            Err(TotpError::InvalidUri)
        }
    }

    /// Code valable à l'instant `unix_time` (secondes).
    pub fn generate(&self, unix_time: u64) -> TotpCode {
        let counter = unix_time / self.period;
        let msg = counter.to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac_digest!(sha1::Sha1, &self.secret, &msg),
            Algorithm::Sha256 => hmac_digest!(sha2::Sha256, &self.secret, &msg),
            Algorithm::Sha512 => hmac_digest!(sha2::Sha512, &self.secret, &msg),
        };
        // Troncature dynamique, RFC 4226 §5.3.
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary = (u32::from(digest[offset]) & 0x7f) << 24
            | u32::from(digest[offset + 1]) << 16
            | u32::from(digest[offset + 2]) << 8
            | u32::from(digest[offset + 3]);
        let modulo = 10u64.pow(self.digits);
        let value = u64::from(binary) % modulo;
        TotpCode {
            code: format!("{value:0width$}", width = self.digits as usize),
            period: self.period,
            remaining: self.period - unix_time % self.period,
        }
    }
}

fn decode_base32(input: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, TotpError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let cleaned = cleaned.trim_end_matches('=');
    if cleaned.is_empty() {
        return Err(TotpError::Empty);
    }
    let bytes = data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| TotpError::InvalidSecret)?;
    Ok(zeroize::Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vecteurs de la RFC 6238, annexe B (graine ASCII « 12345678901234567890 »).
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_sha1_vectors() {
        let mut totp = Totp::parse(RFC_SECRET).unwrap();
        totp.digits = 8;
        assert_eq!(totp.generate(59).code, "94287082");
        assert_eq!(totp.generate(1_111_111_109).code, "07081804");
        assert_eq!(totp.generate(2_000_000_000).code, "69279037");
    }

    #[test]
    fn rfc6238_sha256_and_sha512_vectors() {
        let sha256 = Totp::parse(
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8",
        )
        .unwrap();
        assert_eq!(sha256.generate(59).code, "46119246");
        let sha512 = Totp::parse(
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&algorithm=SHA512&digits=8",
        )
        .unwrap();
        assert_eq!(sha512.generate(59).code, "90693936");
    }

    #[test]
    fn remaining_seconds_count_down() {
        let totp = Totp::parse(RFC_SECRET).unwrap();
        assert_eq!(totp.generate(60).remaining, 30);
        assert_eq!(totp.generate(89).remaining, 1);
    }

    #[test]
    fn secrets_tolerate_spaces_and_lowercase() {
        let a = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        let b = Totp::parse(RFC_SECRET).unwrap();
        assert_eq!(a.generate(1000), b.generate(1000));
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        assert_eq!(Totp::parse("").unwrap_err(), TotpError::Empty);
        assert_eq!(
            Totp::parse("not base32 !").unwrap_err(),
            TotpError::InvalidSecret
        );
        assert!(matches!(
            Totp::parse("otpauth://hotp/x?secret=GEZDGNBV"),
            Err(TotpError::Unsupported(_))
        ));
    }
}
