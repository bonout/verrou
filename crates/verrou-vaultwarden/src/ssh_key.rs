//! Génération de clés SSH, rangées comme les apps Bitwarden les créent :
//! élément de type « clé SSH » (type 5) avec la clé privée au format
//! OpenSSH (sans phrase de passe), la clé publique et son empreinte SHA256.

use bitwarden_vault::{CipherType, SshKeyView};
use chrono::Utc;
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use verrou_core::SecretString;

use crate::edit::new_view;
use crate::{Connection, Decrypted, Draft, Error};

/// Taille des clés RSA générées (comme l'option « RSA 4096 » de Bitwarden).
const RSA_BITS: usize = 4096;

/// Algorithme d'une nouvelle clé.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SshKeyAlgorithm {
    /// Par défaut : courte, rapide, acceptée partout depuis OpenSSH 6.5.
    #[default]
    Ed25519,
    /// Pour les serveurs anciens qui n'acceptent que RSA.
    Rsa4096,
}

/// Une clé fraîchement générée, aux formats que Bitwarden range.
#[derive(Clone, Debug)]
pub struct GeneratedKey {
    /// Clé privée OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), fins de
    /// ligne LF.
    pub private_key: SecretString,
    /// Clé publique sur une ligne (`ssh-ed25519 AAAA…`), sans commentaire.
    pub public_key: String,
    /// Empreinte comme l'affiche `ssh-keygen -l` : `SHA256:…`.
    pub fingerprint: String,
}

/// Tire une nouvelle clé du générateur du système.
pub fn generate(algorithm: SshKeyAlgorithm) -> Result<GeneratedKey, Error> {
    let mut rng = UnwrapErr(SysRng);
    let failed =
        |e: ssh_key::Error| Error::Invalid(format!("génération de la clé impossible ({e})"));
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
    /// Range une clé tirée par [`generate`] dans le coffre personnel ; rend
    /// l'identifiant de l'élément et le coffre resynchronisé.
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
        // `SHA256:` puis 43 caractères base64 sans remplissage, comme `ssh-keygen -l`.
        let digest = key.fingerprint.strip_prefix("SHA256:").unwrap();
        assert_eq!(digest.len(), 43);
        assert!(!digest.ends_with('='));
        // Deux tirages, deux clés.
        assert_ne!(
            generate(SshKeyAlgorithm::Ed25519).unwrap().public_key,
            key.public_key
        );
    }

    /// L'empreinte est celle que calcule `ssh-keygen -l`, et la clé privée
    /// est lisible par OpenSSH (`ssh-keygen -y` en retrouve la clé publique).
    /// Sans `ssh-keygen` sur la machine, le test ne fait rien.
    #[test]
    fn openssh_reads_the_generated_key() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        if Command::new("ssh-keygen").arg("-?").output().is_err() {
            eprintln!("ssh-keygen absent : test ignoré");
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

    /// RSA 4096 : lent en mode debug, d'où `--include-ignored`.
    #[test]
    #[ignore = "génération RSA 4096 lente sans optimisations"]
    fn rsa_key_is_4096_bits() {
        let key = generate(SshKeyAlgorithm::Rsa4096).unwrap();
        let parsed = PrivateKey::from_openssh(key.private_key.expose()).unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Rsa { hash: None });
        let KeypairData::Rsa(rsa) = parsed.key_data() else {
            panic!("clé RSA attendue");
        };
        assert_eq!(
            rsa.public().n().as_positive_bytes().unwrap().len() * 8,
            4096
        );
        assert!(key.public_key.starts_with("ssh-rsa AAAA"));
    }
}
