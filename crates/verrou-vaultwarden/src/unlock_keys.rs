//! Unlocking with a security key (`YubiKey` over `FIDO2`, `hmac-secret`
//! extension).
//!
//! Principle: the security key keeps, for each credential created by
//! Verrou, a secret that never leaves it. Queried with a 32-byte salt
//! (after a touch, and its PIN), it returns `HMAC-SHA-256(secret, salt)`:
//! always the same value for the same salt, impossible to compute without
//! the key.
//!
//! - **Enrolment**: a random salt; the value returned by the key goes
//!   through HKDF-SHA256 and gives an AES-256-GCM key, which seals the
//!   user's key. The file keeps the credential id, the salt and the sealed
//!   key: nothing useful without the physical key.
//! - **Unlocking**: same question to the key, same value, the user's key is
//!   unsealed.
//!
//! Several keys can be enrolled (a main one, a backup one): each has its
//! credential, its salt and its sealed copy. The USB dialogue is in
//! `security_key`; this module only does the cryptography and the file,
//! and is tested without hardware.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use verrou_core::SecretString;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;
use crate::store::Store;

/// "Site" id (`rpId`) of the unlock credentials. Not a domain name, like
/// `OpenSSH`'s `ssh:`: no web page can ask a browser to use it.
pub const RP_ID: &str = "verrou:";

/// Domain separation: these bytes go into the derivation and into the
/// encryption's associated data. Changing them makes the enrolled keys
/// unreadable: it is the format version.
const LABEL: &[u8] = b"verrou.security-key.v1";
const NONCE_LEN: usize = 12;

/// The value returned by the key (`hmac-secret`), wiped when freed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HmacSecret([u8; 32]);

impl HmacSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key never returns anything but 32 bytes; this checks it.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::SecurityKey("the key returned an unreadable secret".to_owned()))?;
        Ok(Self(array))
    }
}

impl std::fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacSecret(***)")
    }
}

/// An enrolled security key, as written on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledKey {
    /// Id of the credential created on the key (base64url).
    pub id: String,
    /// Salt asked of the key (base64), drawn at random at enrolment.
    pub salt: String,
    /// Nonce, then the encrypted user key and its tag (base64).
    pub sealed_user_key: String,
    /// Name given by the user ("main `YubiKey`").
    pub label: String,
    /// Unix timestamp of the enrolment.
    pub created: i64,
}

impl EnrolledKey {
    pub fn credential_id(&self) -> Result<Vec<u8>, Error> {
        BASE64URL_NOPAD
            .decode(self.id.as_bytes())
            .map_err(|_| Error::Storage("unreadable security key id".to_owned()))
    }

    pub fn salt(&self) -> Result<[u8; 32], Error> {
        BASE64
            .decode(self.salt.as_bytes())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::Storage("unreadable security key salt".to_owned()))
    }

    /// Unseals the user's key with the value returned by the security key.
    /// Fails (without revealing anything) if the value doesn't come from the
    /// right key, or if the file was modified.
    pub fn open(&self, secret: &HmacSecret) -> Result<SecretString, Error> {
        let credential_id = self.credential_id()?;
        let salt = self.salt()?;
        let sealed = BASE64
            .decode(self.sealed_user_key.as_bytes())
            .map_err(|_| Error::Storage("unreadable sealed key".to_owned()))?;
        if sealed.len() <= NONCE_LEN {
            return Err(Error::Storage("unreadable sealed key".to_owned()));
        }
        let (nonce, data) = sealed.split_at(NONCE_LEN);
        let plain = Zeroizing::new(
            cipher(secret, &credential_id)
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: data,
                        aad: &aad(&credential_id, &salt),
                    },
                )
                .map_err(|_| {
                    Error::SecurityKey("this key does not unlock this vault".to_owned())
                })?,
        );
        let text = std::str::from_utf8(&plain)
            .map_err(|_| Error::Storage("unreadable sealed key".to_owned()))?;
        Ok(SecretString::new(text))
    }
}

/// What to ask the key for one of the enrolled keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockCredential {
    pub credential_id: Vec<u8>,
    pub salt: [u8; 32],
}

/// A fresh salt, for an enrolment.
pub fn new_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Seals the user's key for a credential.
pub fn seal(
    user_key: &SecretString,
    secret: &HmacSecret,
    credential_id: &[u8],
    salt: &[u8; 32],
    label: &str,
    created: i64,
) -> Result<EnrolledKey, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let data = cipher(secret, credential_id)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: user_key.expose().as_bytes(),
                aad: &aad(credential_id, salt),
            },
        )
        .map_err(|_| Error::Crypto("sealing failed".to_owned()))?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&data);
    Ok(EnrolledKey {
        id: BASE64URL_NOPAD.encode(credential_id),
        salt: BASE64.encode(salt),
        sealed_user_key: BASE64.encode(&sealed),
        label: label.trim().to_owned(),
        created,
    })
}

/// The credentials to present to the key: all the enrolled ones. The
/// plugged-in key only answers for its own.
pub fn credentials(keys: &[EnrolledKey]) -> Result<Vec<UnlockCredential>, Error> {
    keys.iter()
        .map(|key| {
            Ok(UnlockCredential {
                credential_id: key.credential_id()?,
                salt: key.salt()?,
            })
        })
        .collect()
}

/// Unseals the user's key with the security key's answer. `credential_id`:
/// the credential that answered, if the key said so; otherwise each
/// enrolled key is tried (AES-GCM refuses all the others).
pub fn unseal(
    keys: &[EnrolledKey],
    credential_id: Option<&[u8]>,
    secret: &HmacSecret,
) -> Result<SecretString, Error> {
    let not_enrolled =
        || Error::SecurityKey("this key is not registered for this vault".to_owned());
    if let Some(id) = credential_id {
        let id = BASE64URL_NOPAD.encode(id);
        let key = keys.iter().find(|k| k.id == id).ok_or_else(not_enrolled)?;
        return key.open(secret);
    }
    keys.iter()
        .find_map(|key| key.open(secret).ok())
        .ok_or_else(not_enrolled)
}

/// Adds (or replaces, for the same credential) an enrolled key.
pub fn add(store: &Store, key: EnrolledKey) -> Result<(), Error> {
    let mut keys = store.load_security_keys()?;
    keys.retain(|k| k.id != key.id);
    keys.push(key);
    store.save_security_keys(&keys)
}

/// Removes an enrolled key (by its credential id).
pub fn remove(store: &Store, id: &str) -> Result<(), Error> {
    let mut keys = store.load_security_keys()?;
    keys.retain(|k| k.id != id);
    store.save_security_keys(&keys)
}

fn cipher(secret: &HmacSecret, credential_id: &[u8]) -> Aes256Gcm {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(LABEL), &secret.0)
        .expand(credential_id, key.as_mut())
        .expect("32 bytes: a valid length for HKDF-SHA256");
    Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key")
}

/// Associated data: the format version, the credential and the salt. A
/// sealed copy moved to another entry of the file doesn't open.
fn aad(credential_id: &[u8], salt: &[u8; 32]) -> Vec<u8> {
    let mut aad = LABEL.to_vec();
    aad.extend_from_slice(&(credential_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(credential_id);
    aad.extend_from_slice(salt);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_KEY: &str = "dGVzdC11c2VyLWtleS1ub3QtYS1yZWFsLW9uZS0wMTIzNDU2Nzg5YWJjZGVm";

    fn fake_secret(byte: u8) -> HmacSecret {
        HmacSecret::from_bytes([byte; 32])
    }

    fn enrolled(credential: &[u8], secret: &HmacSecret) -> EnrolledKey {
        seal(
            &SecretString::new(USER_KEY),
            secret,
            credential,
            &new_salt(),
            " YubiKey principale ",
            1_760_000_000,
        )
        .unwrap()
    }

    #[test]
    fn seal_then_open_gives_the_user_key_back() {
        let secret = fake_secret(7);
        let key = enrolled(&[1, 2, 3], &secret);
        assert_eq!(key.label, "YubiKey principale");
        assert_eq!(key.id, "AQID");
        assert_eq!(key.open(&secret).unwrap().expose(), USER_KEY);
        assert!(!key.sealed_user_key.contains(USER_KEY));
    }

    #[test]
    fn another_secret_does_not_open() {
        let key = enrolled(&[1, 2, 3], &fake_secret(7));
        assert!(matches!(
            key.open(&fake_secret(8)),
            Err(Error::SecurityKey(_))
        ));
    }

    #[test]
    fn a_sealed_copy_moved_to_another_entry_does_not_open() {
        let secret = fake_secret(7);
        let first = enrolled(&[1, 2, 3], &secret);
        let second = enrolled(&[4, 5, 6], &secret);
        // Same secret (impossible in reality, but the worst case): the
        // credential and the salt are part of the derivation and of the
        // associated data.
        let swapped = EnrolledKey {
            sealed_user_key: first.sealed_user_key.clone(),
            ..second.clone()
        };
        assert!(swapped.open(&secret).is_err());
        let other_salt = EnrolledKey {
            salt: second.salt.clone(),
            ..first.clone()
        };
        assert!(other_salt.open(&secret).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let secret = fake_secret(7);
        let mut key = enrolled(&[1, 2, 3], &secret);
        let mut bytes = BASE64.decode(key.sealed_user_key.as_bytes()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        key.sealed_user_key = BASE64.encode(&bytes);
        assert!(key.open(&secret).is_err());
        key.sealed_user_key = BASE64.encode(&[0; 4]);
        assert!(matches!(key.open(&secret), Err(Error::Storage(_))));
    }

    #[test]
    fn salts_and_nonces_are_fresh() {
        assert_ne!(new_salt(), new_salt());
        let secret = fake_secret(7);
        let a = enrolled(&[1], &secret);
        let b = enrolled(&[1], &secret);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.sealed_user_key, b.sealed_user_key);
    }

    #[test]
    fn unseal_picks_the_key_that_answered() {
        let main = fake_secret(1);
        let backup = fake_secret(2);
        let keys = vec![enrolled(&[1], &main), enrolled(&[2], &backup)];
        let creds = credentials(&keys).unwrap();
        assert_eq!(creds[1].credential_id, [2]);
        assert_eq!(creds[1].salt, keys[1].salt().unwrap());

        assert_eq!(
            unseal(&keys, Some(&[2]), &backup).unwrap().expose(),
            USER_KEY
        );
        // The key didn't say which credential answered: everything is tried.
        assert_eq!(unseal(&keys, None, &backup).unwrap().expose(), USER_KEY);
        assert_eq!(unseal(&keys, None, &main).unwrap().expose(), USER_KEY);
        assert!(unseal(&keys, Some(&[3]), &main).is_err());
        assert!(unseal(&keys, Some(&[1]), &backup).is_err());
        assert!(unseal(&keys, None, &fake_secret(3)).is_err());
        assert!(unseal(&[], None, &main).is_err());
    }

    #[test]
    fn hmac_output_must_be_32_bytes() {
        assert!(HmacSecret::from_slice(&[0; 31]).is_err());
        assert!(HmacSecret::from_slice(&[0; 32]).is_ok());
        assert_eq!(format!("{:?}", fake_secret(9)), "HmacSecret(***)");
    }

    #[test]
    fn file_keeps_several_keys_privately() {
        let store =
            Store::new(std::env::temp_dir().join(format!("verrou-keys-{}", uuid::Uuid::new_v4())));
        assert_eq!(store.load_security_keys().unwrap(), []);
        let main = enrolled(&[1], &fake_secret(1));
        let backup = enrolled(&[2], &fake_secret(2));
        add(&store, main.clone()).unwrap();
        add(&store, backup.clone()).unwrap();
        // Re-enrolling the same credential replaces it.
        let again = enrolled(&[1], &fake_secret(1));
        add(&store, again.clone()).unwrap();
        assert_eq!(store.load_security_keys().unwrap(), [backup.clone(), again]);

        let path = store.dir().join(crate::store::SECURITY_KEYS_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(USER_KEY));
        assert!(text.contains("\"version\":1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        remove(&store, &backup.id).unwrap();
        remove(&store, &main.id).unwrap();
        // No key left: no file left.
        assert!(!path.exists());
        assert_eq!(store.load_security_keys().unwrap(), []);

        add(&store, backup).unwrap();
        store.delete_security_keys().unwrap();
        assert!(!path.exists());
        std::fs::remove_dir_all(store.dir()).unwrap();
    }

    #[test]
    fn unknown_file_version_is_refused() {
        let store =
            Store::new(std::env::temp_dir().join(format!("verrou-keys-{}", uuid::Uuid::new_v4())));
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(
            store.dir().join(crate::store::SECURITY_KEYS_FILE),
            r#"{"version":2,"keys":[]}"#,
        )
        .unwrap();
        assert!(matches!(store.load_security_keys(), Err(Error::Storage(_))));
        std::fs::remove_dir_all(store.dir()).unwrap();
    }
}
