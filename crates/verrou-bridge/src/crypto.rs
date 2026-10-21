//! Cryptography of the channel between the extension and Verrou.
//!
//! - **Pairing**: ECDH P-256 between a key of the extension (kept in the
//!   browser) and an ephemeral key of Verrou; HKDF-SHA256 derives the channel
//!   key from it. Both sides show a 6-digit code derived from this
//!   key: the user checks it is the same before accepting, which
//!   rules out a program slipping in between.
//! - **Messages**: AES-256-GCM, random 96-bit nonce, associated
//!   data = client identifier and message direction (a response
//!   cannot be sent back as a request).
//!
//! The same primitives exist in `WebCrypto`, which leaves the extension
//! without a cryptography library.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use data_encoding::BASE64;
use hkdf::Hkdf;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const INFO: &[u8] = b"verrou-bridge v1";
const CODE_LABEL: &[u8] = b"verrou-bridge code";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid public key")]
    InvalidKey,
    #[error("unreadable message")]
    Unreadable,
}

/// Direction of an encrypted message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// From the extension to Verrou.
    Request,
    /// From Verrou to the extension.
    Response,
}

/// Symmetric channel key, specific to one paired client.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChannelKey([u8; 32]);

impl ChannelKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_base64(text: &str) -> Result<Self, CryptoError> {
        let bytes = BASE64
            .decode(text.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(array))
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.0)
    }

    /// Verification code shown on both sides: `482 913`.
    pub fn pairing_code(&self) -> String {
        let digest = Sha256::new()
            .chain_update(CODE_LABEL)
            .chain_update(self.0)
            .finalize();
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
        format!("{:03} {:03}", n / 1000, n % 1000)
    }

    /// Encrypts `plaintext`; returns the nonce and the ciphertext (base64).
    pub fn seal(&self, client: &str, direction: Direction, plaintext: &[u8]) -> (String, String) {
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);
        let cipher = Aes256Gcm::new_from_slice(&self.0).expect("32-byte key");
        let aad = aad(client, direction);
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AES-GCM encryption");
        (BASE64.encode(&iv), BASE64.encode(&sealed))
    }

    pub fn open(
        &self,
        client: &str,
        direction: Direction,
        iv: &str,
        data: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let iv = BASE64
            .decode(iv.as_bytes())
            .map_err(|_| CryptoError::Unreadable)?;
        if iv.len() != 12 {
            return Err(CryptoError::Unreadable);
        }
        let data = BASE64
            .decode(data.as_bytes())
            .map_err(|_| CryptoError::Unreadable)?;
        let cipher = Aes256Gcm::new_from_slice(&self.0).expect("32-byte key");
        let aad = aad(client, direction);
        cipher
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &data,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Unreadable)
    }
}

fn aad(client: &str, direction: Direction) -> Vec<u8> {
    let tag = match direction {
        Direction::Request => "q",
        Direction::Response => "r",
    };
    format!("{client}:{tag}").into_bytes()
}

/// One half of a key agreement: the ephemeral secret key and its public key
/// (uncompressed SEC1, 65 bytes, like `exportKey("raw")` in `WebCrypto`).
pub struct KeyPair {
    secret: EphemeralSecret,
    public: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { secret, public }
    }

    pub fn public_base64(&self) -> String {
        BASE64.encode(&self.public)
    }

    /// Channel key. `client_public` and `server_public` salt the derivation
    /// in that order, whichever side computes it.
    pub fn agree(&self, peer_base64: &str, we_are_server: bool) -> Result<ChannelKey, CryptoError> {
        let peer = BASE64
            .decode(peer_base64.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
        let peer_key = PublicKey::from_sec1_bytes(&peer).map_err(|_| CryptoError::InvalidKey)?;
        // Always the uncompressed form, to salt like WebCrypto.
        let peer = peer_key.to_encoded_point(false).as_bytes().to_vec();
        let shared = self.secret.diffie_hellman(&peer_key);
        let (client, server) = if we_are_server {
            (&peer, &self.public)
        } else {
            (&self.public, &peer)
        };
        let salt = [client.as_slice(), server.as_slice()].concat();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(INFO, &mut key).expect("32 bytes");
        Ok(ChannelKey(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree_on_key_and_code() {
        let client = KeyPair::generate();
        let server = KeyPair::generate();
        let on_server = server.agree(&client.public_base64(), true).unwrap();
        let on_client = client.agree(&server.public_base64(), false).unwrap();
        assert_eq!(on_server.to_base64(), on_client.to_base64());
        let code = on_server.pairing_code();
        assert_eq!(code.len(), 7);
        assert_eq!(code, on_client.pairing_code());
    }

    #[test]
    fn messages_are_bound_to_client_and_direction() {
        let key = ChannelKey::from_bytes([7; 32]);
        let (iv, data) = key.seal("abc", Direction::Request, b"bonjour");
        assert_eq!(
            key.open("abc", Direction::Request, &iv, &data).unwrap(),
            b"bonjour"
        );
        assert_eq!(
            key.open("abc", Direction::Response, &iv, &data),
            Err(CryptoError::Unreadable)
        );
        assert_eq!(
            key.open("xyz", Direction::Request, &iv, &data),
            Err(CryptoError::Unreadable)
        );
        let other = ChannelKey::from_bytes([8; 32]);
        assert!(other.open("abc", Direction::Request, &iv, &data).is_err());
    }

    #[test]
    fn invalid_public_keys_are_refused() {
        let pair = KeyPair::generate();
        assert!(pair.agree("AAAA", true).is_err());
        assert!(pair.agree("pas du base64", true).is_err());
    }
}
