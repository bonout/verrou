//! `WebAuthn` PRF extension (`prf`), for the vault's passkeys.
//!
//! A site asks for a pseudo-random value tied to the passkey and to a salt
//! of its choice (`eval.first`, `eval.second`); it uses it as an encryption
//! key (end-to-end encrypted vaults, passkey unlock). The value must stay
//! **the same** for the same passkey and the same salt, on every device, and
//! differ from one salt to another.
//!
//! Computation, like the CTAP2 `hmac-secret` extension that carries the PRF
//! on a hardware key, and like `passkey-rs` (the library of the Bitwarden
//! SDK):
//!
//! ```text
//! salt      = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ site input)       (client side)
//! output    = HMAC-SHA256(passkey secret, salt)                  (authenticator side)
//! ```
//!
//! **The passkey secret.** The Bitwarden passkey format
//! (`login.fido2Credentials`) has no field for an `hmac-secret` secret:
//! the Bitwarden SDK does not evaluate the PRF for vault passkeys
//! (`CredentialExtensions { hmac_secret: None }`, PM-30510). Rather than
//! inventing a field the official apps would erase when rewriting the item,
//! Verrou **derives** the secret from what the passkey already contains:
//!
//! ```text
//! secret = HKDF-SHA256(ikm  = P-256 private scalar (32 bytes),
//!                      salt = "verrou.passkey.prf.v1",
//!                      info = raw credential identifier)
//! ```
//!
//! Consequences: every vault passkey (created by Verrou or by a Bitwarden
//! app) has a PRF, stable on every device where Verrou runs; whoever holds
//! the private key can recompute it (as with a secret stored alongside). If
//! Bitwarden one day adds a field, its outputs will differ from these: data
//! a site encrypted with Verrou's PRF would not open with the official apps
//! (today, they have no PRF at all).
//!
//! The PRF is only returned after user verification (Face ID, Touch ID or
//! master password): like `hmac-secret` with `CredRandomWithUV` only.

use hmac::{Hmac, Mac as _};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey as _;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::passkey::{Passkey, PasskeyError, b64url_decode};

type HmacSha256 = Hmac<Sha256>;

/// Prefix of the input hash (`WebAuthn` level 3, §10.1.4).
const SALT_PREFIX: &[u8] = b"WebAuthn PRF\0";
/// Verrou's own HKDF salt: changing the derivation requires a new version.
const SECRET_SALT: &[u8] = b"verrou.passkey.prf.v1";
/// Size of an accepted input (a page can send anything).
const MAX_INPUT: usize = 1024;

/// The salts of an evaluation, already hashed (32 bytes each).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfSalts {
    pub first: [u8; 32],
    pub second: Option<[u8; 32]>,
}

/// The PRF outputs: keys, wiped from memory at the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfOutputs {
    pub first: Zeroizing<[u8; 32]>,
    pub second: Option<Zeroizing<[u8; 32]>>,
}

/// Hashes a site input into a salt (`SHA-256("WebAuthn PRF" ‖ 0 ‖ input)`),
/// which the client (browser, system) does before the authenticator.
pub fn salt(input: &[u8]) -> Result<[u8; 32], PasskeyError> {
    if input.len() > MAX_INPUT {
        return Err(PasskeyError::BadRequest("PRF input too long"));
    }
    let mut hasher = Sha256::new();
    hasher.update(SALT_PREFIX);
    hasher.update(input);
    Ok(hasher.finalize().into())
}

/// The salts of the site's raw inputs (`eval.first`, `eval.second`).
pub fn salts(first: &[u8], second: Option<&[u8]>) -> Result<PrfSalts, PasskeyError> {
    Ok(PrfSalts {
        first: salt(first)?,
        second: second.map(salt).transpose()?,
    })
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 (RFC 5869), a single output block (32 bytes).
fn hkdf_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut prk = hmac(salt, &[ikm]);
    let okm = Zeroizing::new(hmac(&prk, &[info, &[1]]));
    prk.zeroize();
    okm
}

/// The passkey's `hmac-secret` secret, derived from its private key and its
/// identifier (see the module header).
fn credential_secret(passkey: &Passkey) -> Result<Zeroizing<[u8; 32]>, PasskeyError> {
    let mut der = b64url_decode(passkey.key.expose()).ok_or(PasskeyError::BadKey)?;
    let key = SigningKey::from_pkcs8_der(&der).map_err(|_| PasskeyError::BadKey);
    der.zeroize();
    let key = key?;
    let credential_id = passkey.raw_id().ok_or(PasskeyError::BadKey)?;
    let scalar = Zeroizing::new(<[u8; 32]>::from(key.to_bytes()));
    Ok(hkdf_32(SECRET_SALT, scalar.as_slice(), &credential_id))
}

/// Evaluates the passkey's PRF for already hashed salts (what a CTAP2
/// authenticator receives). Refused without user verification.
pub fn evaluate(
    passkey: &Passkey,
    salts: &PrfSalts,
    user_verified: bool,
) -> Result<PrfOutputs, PasskeyError> {
    if !user_verified {
        return Err(PasskeyError::BadRequest(
            "the PRF requires user verification",
        ));
    }
    let secret = credential_secret(passkey)?;
    Ok(PrfOutputs {
        first: Zeroizing::new(hmac(secret.as_slice(), &[&salts.first])),
        second: salts
            .second
            .map(|s| Zeroizing::new(hmac(secret.as_slice(), &[&s]))),
    })
}

/// Evaluates the PRF for the site's raw inputs (what the iOS and macOS
/// provider and the browser extension receive): `WebAuthn` hashing, then
/// [`evaluate`].
pub fn evaluate_inputs(
    passkey: &Passkey,
    first: &[u8],
    second: Option<&[u8]>,
    user_verified: bool,
) -> Result<PrfOutputs, PasskeyError> {
    evaluate(passkey, &salts(first, second)?, user_verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretString;
    use crate::passkey::{SystemRegistrationRequest, b64url, register_for_system};
    use p256::pkcs8::EncodePrivateKey as _;
    use rand::SeedableRng as _;

    fn hex(bytes: &[u8]) -> String {
        data_encoding::HEXLOWER.encode(bytes)
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Passkey with a fixed scalar (1, 2, …, 32) and a fixed identifier, in the
    /// Bitwarden format: the vectors below depend on it.
    fn fixed_passkey() -> Passkey {
        let scalar: Vec<u8> = (1..=32).collect();
        let key = SigningKey::from_slice(&scalar).unwrap();
        let pkcs8 = key.to_pkcs8_der().unwrap();
        Passkey {
            item: "item".into(),
            credential_id: "0f4e3c2a-1b5d-4e6f-8a9b-0c1d2e3f4a5b".into(),
            rp_id: "example.com".into(),
            rp_name: None,
            user_handle: Some(b64url(b"user")),
            user_name: Some("alice".into()),
            user_display_name: None,
            counter: 0,
            discoverable: true,
            created: 0,
            key: SecretString::new(b64url(pkcs8.as_bytes())),
        }
    }

    /// RFC 5869, test case 1 (L = 32: the first 32 bytes of the OKM).
    #[test]
    fn hkdf_matches_rfc5869() {
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        assert_eq!(
            hex(hkdf_32(&salt, &ikm, &info).as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    /// Input hashing: `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`,
    /// recomputed here without going through `salt`.
    #[test]
    fn salts_use_the_webauthn_prefix() {
        let mut message = b"WebAuthn PRF".to_vec();
        message.push(0);
        message.extend_from_slice(b"verrou");
        assert_eq!(
            salt(b"verrou").unwrap(),
            <[u8; 32]>::from(Sha256::digest(&message))
        );
        assert_eq!(
            hex(&salt(b"").unwrap()),
            hex(&Sha256::digest(b"WebAuthn PRF\0"))
        );
        assert!(salt(&[0; MAX_INPUT + 1]).is_err());
    }

    /// Vectors (computed independently, with Python's `hmac` and `hashlib`):
    /// secret and outputs of the fixed passkey. They freeze the derivation; if
    /// they change, data a site encrypted with the PRF no longer opens.
    #[test]
    fn outputs_match_the_test_vectors() {
        let passkey = fixed_passkey();
        let secret = credential_secret(&passkey).unwrap();
        // secret = HKDF(salt, scalar 01..20, raw identifier)
        let expected_secret = hkdf_32(
            SECRET_SALT,
            &(1..=32).collect::<Vec<u8>>(),
            &unhex("0f4e3c2a1b5d4e6f8a9b0c1d2e3f4a5b"),
        );
        assert_eq!(secret, expected_secret);
        assert_eq!(
            hex(secret.as_slice()),
            "572edae5817c24b325a6359d8e66e13ef0cf8eb80a936aaf229fc900fa519e3f"
        );

        let out = evaluate_inputs(&passkey, b"salt-1", Some(b"salt-2"), true).unwrap();
        assert_eq!(
            hex(out.first.as_slice()),
            "4db4bb49d07a3468bfb8c027f4efcfd256ac22e2d950967ea104dcbe6e61dbe5"
        );
        assert_eq!(
            hex(out.second.as_ref().unwrap().as_slice()),
            "13d10b5e1bb2dc5de5fbd92273f9389b9fae9f274d6909c944742f8e38ca199b"
        );
        // Output = HMAC-SHA256(secret, salt), like hmac-secret.
        let salt1 = salt(b"salt-1").unwrap();
        assert_eq!(*out.first, hmac(secret.as_slice(), &[&salt1]));
    }

    #[test]
    fn outputs_are_stable_and_differ_per_salt_and_passkey() {
        let passkey = fixed_passkey();
        let a = evaluate_inputs(&passkey, b"a", None, true).unwrap();
        let again = evaluate_inputs(&passkey, b"a", None, true).unwrap();
        let b = evaluate_inputs(&passkey, b"b", None, true).unwrap();
        assert_eq!(a, again);
        assert_ne!(a.first, b.first);
        assert!(a.second.is_none());

        // Same key, other identifier: other secret.
        let mut other = fixed_passkey();
        other.credential_id = "b64.AQID".into();
        assert_ne!(
            evaluate_inputs(&other, b"a", None, true).unwrap().first,
            a.first
        );

        // Passkey created for the system: its PRF depends only on what is
        // kept in the vault (reading it back gives the same output).
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let (created, _) = register_for_system(
            &SystemRegistrationRequest {
                rp_id: "example.com",
                rp_name: None,
                user_id: b"u",
                user_name: None,
                user_display_name: None,
                client_data_hash: &[0; 32],
                user_verified: true,
            },
            "x",
            0,
            &mut rng,
        )
        .unwrap();
        let reread = created.clone();
        assert_eq!(
            evaluate_inputs(&created, b"a", None, true).unwrap(),
            evaluate_inputs(&reread, b"a", None, true).unwrap()
        );
    }

    #[test]
    fn requires_user_verification_and_a_readable_key() {
        let passkey = fixed_passkey();
        assert!(evaluate_inputs(&passkey, b"a", None, false).is_err());
        let mut broken = fixed_passkey();
        broken.key = SecretString::new("pas-une-clé");
        assert_eq!(
            evaluate_inputs(&broken, b"a", None, true),
            Err(PasskeyError::BadKey)
        );
    }
}
