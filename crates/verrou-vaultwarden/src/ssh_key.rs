//! SSH key generation, stored the way the Bitwarden apps create them: an
//! item of type "SSH key" (type 5) with the private key in OpenSSH format
//! (without passphrase), the public key and its SHA256 fingerprint.

use bitwarden_vault::{CipherType, SshKeyView};
use chrono::Utc;
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use verrou_core::SecretString;

use crate::edit::new_view;
use crate::{Connection, Decrypted, Draft, Error};

/// Size of the generated RSA keys (like Bitwarden's "RSA 4096" option).
const RSA_BITS: usize = 4096;

/// Algorithm of a new key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SshKeyAlgorithm {
    /// Default: short, fast, accepted everywhere since OpenSSH 6.5.
    #[default]
    Ed25519,
    /// For old servers that only accept RSA.
    Rsa4096,
}

/// A freshly generated key, in the formats Bitwarden stores.
#[derive(Clone, Debug)]
pub struct GeneratedKey {
    /// OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`), LF line
    /// endings.
    pub private_key: SecretString,
    /// Public key on one line (`ssh-ed25519 AAAA…`), without comment.
    pub public_key: String,
    /// Fingerprint as `ssh-keygen -l` shows it: `SHA256:…`.
    pub fingerprint: String,
}

/// Draws a new key from the system's generator.
pub fn generate(algorithm: SshKeyAlgorithm) -> Result<GeneratedKey, Error> {
    let mut rng = UnwrapErr(SysRng);
    let failed = |e: ssh_key::Error| Error::Invalid(format!("could not generate the key ({e})"));
    let key = match algorithm {
        SshKeyAlgorithm::Ed25519 => {
            PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(failed)?
        }
        SshKeyAlgorithm::Rsa4096 => {
            let pair = RsaKeypair::random(&mut rng, RSA_BITS).map_err(failed)?;
            PrivateKey::new(KeypairData::from(pair), "").map_err(failed)?
        }
    };
    let private_key = key.to_openssh(LineEnding::LF).map_err(failed)?;
    Ok(GeneratedKey {
        private_key: SecretString::new(private_key.as_str()),
        public_key: key.public_key().to_openssh().map_err(failed)?,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

impl Connection {
    /// Stores a key drawn by [`generate`] in the personal vault; returns the
    /// item's id and the resynced vault.
    pub async fn create_ssh_key(
        &mut self,
        name: String,
        folder_id: Option<String>,
        key: GeneratedKey,
    ) -> Result<(String, Decrypted), Error> {
        let mut view = new_view(
            Draft {
                name,
                folder_id,
                ..Draft::default()
            },
            Utc::now(),
        )?;
        view.r#type = CipherType::SshKey;
        view.secure_note = None;
        view.ssh_key = Some(SshKeyView {
            private_key: key.private_key.expose().to_owned(),
            public_key: key.public_key,
            fingerprint: key.fingerprint,
        });
        self.queue_save(None, view).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_key_parses_back_and_matches_its_fingerprint() {
        let key = generate(SshKeyAlgorithm::Ed25519).unwrap();
        let pem = key.private_key.expose();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(!pem.contains('\r'));
        let parsed = PrivateKey::from_openssh(pem).unwrap();
        assert!(!parsed.is_encrypted());
        assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
        assert_eq!(parsed.public_key().to_openssh().unwrap(), key.public_key);
        assert!(key.public_key.starts_with("ssh-ed25519 AAAA"));
        assert_eq!(
            parsed.fingerprint(HashAlg::Sha256).to_string(),
            key.fingerprint
        );
        // `SHA256:` then 43 base64 characters without padding, like `ssh-keygen -l`.
        let digest = key.fingerprint.strip_prefix("SHA256:").unwrap();
        assert_eq!(digest.len(), 43);
        assert!(!digest.ends_with('='));
        // Two draws, two keys.
        assert_ne!(
            generate(SshKeyAlgorithm::Ed25519).unwrap().public_key,
            key.public_key
        );
    }

    /// The fingerprint is the one `ssh-keygen -l` computes, and the private
    /// key is readable by OpenSSH (`ssh-keygen -y` derives its public key).
    /// Without `ssh-keygen` on the machine, the test does nothing.
    #[test]
    fn openssh_reads_the_generated_key() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        if Command::new("ssh-keygen").arg("-?").output().is_err() {
            eprintln!("ssh-keygen missing: test skipped");
            return;
        }
        let key = generate(SshKeyAlgorithm::Ed25519).unwrap();
        let dir = std::env::temp_dir().join(format!("verrou-keygen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let private = dir.join("id_ed25519");
        std::fs::write(&private, key.private_key.expose()).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
        let public = dir.join("id_ed25519.pub");
        std::fs::write(&public, format!("{}\n", key.public_key)).unwrap();

        let listed = Command::new("ssh-keygen")
            .args(["-l", "-E", "sha256", "-f"])
            .arg(&public)
            .output()
            .unwrap();
        assert!(listed.status.success());
        let listed = String::from_utf8(listed.stdout).unwrap();
        assert_eq!(
            listed.split_whitespace().nth(1),
            Some(key.fingerprint.as_str())
        );

        let derived = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&private)
            .output()
            .unwrap();
        assert!(derived.status.success(), "{derived:?}");
        assert_eq!(
            String::from_utf8(derived.stdout).unwrap().trim(),
            key.public_key
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// RSA 4096: slow in debug mode, hence `--include-ignored`.
    #[test]
    #[ignore = "RSA 4096 generation is slow without optimisations"]
    fn rsa_key_is_4096_bits() {
        let key = generate(SshKeyAlgorithm::Rsa4096).unwrap();
        let parsed = PrivateKey::from_openssh(key.private_key.expose()).unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Rsa { hash: None });
        let KeypairData::Rsa(rsa) = parsed.key_data() else {
            panic!("expected an RSA key");
        };
        assert_eq!(
            rsa.public().n().as_positive_bytes().unwrap().len() * 8,
            4096
        );
        assert!(key.public_key.starts_with("ssh-rsa AAAA"));
    }
}
