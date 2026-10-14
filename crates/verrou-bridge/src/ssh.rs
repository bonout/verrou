//! Clés SSH du coffre, pour l'agent SSH du terminal (`verrou ssh-agent`).
//!
//! L'agent ne reçoit que les clés publiques et les signatures : la clé
//! privée (OpenSSH, telle que Vaultwarden la garde) est lue et utilisée ici,
//! dans l'app, le temps d'une signature.

use data_encoding::BASE64;
use signature::Signer as _;
use ssh_key::encoding::Encode as _;
use ssh_key::private::KeypairData;
use ssh_key::{HashAlg, PrivateKey};
use verrou_core::{Item, ItemKind, Vault};

use crate::protocol::SshIdentity;

/// Drapeaux de `SSH_AGENTC_SIGN_REQUEST` (draft-miller-ssh-agent, 4.5.1).
pub const RSA_SHA2_256: u32 = 0x02;
pub const RSA_SHA2_512: u32 = 0x04;

/// Identifiant du champ de la clé privée (voir `verrou-vaultwarden`).
const PRIVATE_KEY_FIELD: &str = "private_key";

/// La clé privée d'un élément « clé SSH », si elle est lisible et sans
/// phrase de passe (celles que Bitwarden génère ou importe n'en ont pas).
fn private_key(item: &Item) -> Option<PrivateKey> {
    if item.kind != ItemKind::SshKey {
        return None;
    }
    let pem = item.field(PRIVATE_KEY_FIELD)?.value.expose();
    PrivateKey::from_openssh(pem.trim())
        .ok()
        .filter(|key| !key.is_encrypted())
}

/// Forme binaire SSH de la clé publique (`string` algorithme, puis la clé).
fn public_blob(key: &PrivateKey) -> Option<Vec<u8>> {
    key.public_key().to_bytes().ok()
}

/// Les clés SSH utilisables du coffre (ni archivées, ni à la corbeille) :
/// leur clé publique et leur titre.
pub fn identities(vault: &Vault) -> Vec<SshIdentity> {
    vault
        .items()
        .iter()
        .filter(|item| item.is_active())
        .filter_map(|item| {
            let blob = public_blob(&private_key(item)?)?;
            Some(SshIdentity {
                item: item.id.clone(),
                title: item.title.clone(),
                public_key: BASE64.encode(&blob),
            })
        })
        .collect()
}

/// L'élément dont la clé publique est `blob`.
pub fn key_item<'v>(vault: &'v Vault, blob: &[u8]) -> Option<&'v Item> {
    vault.items().iter().find(|item| {
        item.kind == ItemKind::SshKey
            && item.is_active()
            && private_key(item)
                .and_then(|key| public_blob(&key))
                .is_some_and(|b| b == blob)
    })
}

/// En-tête des données que `ssh-keygen -Y sign` fait signer (PROTOCOL.sshsig
/// d'OpenSSH) : pas de longueur devant, contrairement aux `string`.
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// Espace de noms (`-n`) des signatures de git (`gpg.format=ssh`) : commits,
/// étiquettes et `push --signed`.
pub const GIT_NAMESPACE: &str = "git";

/// L'espace de noms d'une demande `ssh-keygen -Y sign` : `data` est alors
/// « SSHSIG », `string` espace de noms, `string` réservé, `string`
/// algorithme de hachage, `string` empreinte du message. `None` pour tout
/// autre contenu (l'authentification SSH, notamment, commence par la
/// longueur de l'identifiant de session : jamais « SSHS »).
pub fn sshsig_namespace(data: &[u8]) -> Option<&str> {
    let mut rest = data.strip_prefix(SSHSIG_MAGIC)?;
    let mut string = || -> Option<&[u8]> {
        let (length, tail) = rest.split_at_checked(4)?;
        let length = u32::from_be_bytes(length.try_into().ok()?) as usize;
        let (value, tail) = tail.split_at_checked(length)?;
        rest = tail;
        Some(value)
    };
    let namespace = string()?;
    let _reserved = string()?;
    let hash = string()?;
    let _digest = string()?;
    let known_hash = hash == b"sha256" || hash == b"sha512";
    if !(rest.is_empty() && known_hash) || namespace.is_empty() {
        return None;
    }
    std::str::from_utf8(namespace).ok()
}

/// La demande signe-t-elle pour git (commit, étiquette) ?
pub fn is_git_signature(data: &[u8]) -> bool {
    sshsig_namespace(data) == Some(GIT_NAMESPACE)
}

/// Signe `data` avec la clé de l'élément dont la clé publique est `blob`.
/// Rend la signature au format de l'agent : `string` algorithme, `string`
/// signature. Pour RSA, `flags` choisit SHA-512, SHA-256, ou SHA-1
/// (`ssh-rsa`) faute de drapeau.
pub fn sign(vault: &Vault, blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
    let item = key_item(vault, blob).ok_or_else(|| "clé SSH inconnue".to_owned())?;
    let key = private_key(item).ok_or_else(|| "clé SSH illisible".to_owned())?;
    let signature = match key.key_data() {
        KeypairData::Rsa(rsa) => {
            let hash = if flags & RSA_SHA2_512 != 0 {
                Some(HashAlg::Sha512)
            } else if flags & RSA_SHA2_256 != 0 {
                Some(HashAlg::Sha256)
            } else {
                None
            };
            (rsa, hash).try_sign(data)
        }
        other => other.try_sign(data),
    }
    .map_err(|_| "signature impossible avec cette clé".to_owned())?;
    signature
        .encode_vec()
        .map_err(|_| "signature impossible avec cette clé".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use getrandom::rand_core::UnwrapErr;
    use signature::Verifier as _;
    use ssh_key::encoding::Decode as _;
    use ssh_key::{Algorithm, EcdsaCurve, LineEnding, Signature};
    use verrou_core::{Field, FieldKind};

    fn key_item(id: &str, key: &PrivateKey) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::SshKey,
            title: format!("Clé {id}"),
            subtitle: String::new(),
            urls: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![
                Field::new(
                    "public_key",
                    "Clé publique",
                    FieldKind::Multiline,
                    key.public_key().to_openssh().unwrap(),
                ),
                Field::new(
                    PRIVATE_KEY_FIELD,
                    "Clé privée",
                    FieldKind::Concealed,
                    key.to_openssh(LineEnding::LF).unwrap().as_str(),
                ),
            ],
            notes: None,
            reprompt: false,
            state: verrou_core::ItemState::Active,
        }
    }

    fn verify(key: &PrivateKey, data: &[u8], encoded: &[u8]) -> Signature {
        let signature = Signature::decode(&mut &encoded[..]).unwrap();
        key.public_key()
            .key_data()
            .verify(data, &signature)
            .unwrap();
        signature
    }

    #[test]
    fn signs_with_ed25519_and_ecdsa_keys() {
        let mut rng = UnwrapErr(SysRng);
        let ed25519 = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let p256 = PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        let p384 = PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
        )
        .unwrap();
        let vault = Vault::new(vec![
            key_item("ed", &ed25519),
            key_item("p256", &p256),
            key_item("p384", &p384),
        ]);
        let found = identities(&vault);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].title, "Clé ed");
        for (key, name) in [
            (&ed25519, "ssh-ed25519"),
            (&p256, "ecdsa-sha2-nistp256"),
            (&p384, "ecdsa-sha2-nistp384"),
        ] {
            let blob = key.public_key().to_bytes().unwrap();
            let signed = sign(&vault, &blob, b"session", 0).unwrap();
            assert_eq!(verify(key, b"session", &signed).algorithm().as_str(), name);
        }
    }

    /// Clé RSA 2048 jetable, créée pour ce test (`ssh-keygen -t rsa`) : en
    /// générer une en mode debug prend trop de temps. Forme binaire OpenSSH,
    /// sans l'enveloppe PEM.
    const RSA_TEST_KEY: &str = concat!(
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcnNhAAAA",
        "AwEAAQAAAQEAowAOcjB490Vmkbel88tGDKoM88NH44+Yxz2fKx4n2li/qFoqCInPVq5kMTeOyNQ+",
        "97GVLlucktESseMnrRraVS26qEuVU+8IuxKt6IAF8XjddBwGLbap8y9J7iHSwImcgJe1YO8Fqzpk",
        "m3KdrJ7EDjCJW2xhW+iTfrpq9H7XSi5Jc/pqkhPyQPjFbHNWs8h8wF0OttF0S5bKFWJaQPkaD+ZM",
        "6TC8dQjycDgR3iC2cbDam8UF2i8bN/ggXR5qGkuYnQI/RyKc7Pur2emnSW48A5KEK+02FSbHQP8J",
        "9bM4jzRxwZeSr+IhUeAaC+OwvwAGhwUWmFy3CG6yOUFjfKYQVQAAA8BEewyHRHsMhwAAAAdzc2gt",
        "cnNhAAABAQCjAA5yMHj3RWaRt6Xzy0YMqgzzw0fjj5jHPZ8rHifaWL+oWioIic9WrmQxN47I1D73",
        "sZUuW5yS0RKx4yetGtpVLbqoS5VT7wi7Eq3ogAXxeN10HAYttqnzL0nuIdLAiZyAl7Vg7wWrOmSb",
        "cp2snsQOMIlbbGFb6JN+umr0ftdKLklz+mqSE/JA+MVsc1azyHzAXQ620XRLlsoVYlpA+RoP5kzp",
        "MLx1CPJwOBHeILZxsNqbxQXaLxs3+CBdHmoaS5idAj9HIpzs+6vZ6adJbjwDkoQr7TYVJsdA/wn1",
        "sziPNHHBl5Kv4iFR4BoL47C/AAaHBRaYXLcIbrI5QWN8phBVAAAAAwEAAQAAAQEAl+wmisGpDXcu",
        "6WQNFhSBHq6kUdLSP0QItrM1lj+OD5GmWOhowvqHOJhkJAdPWtmQMtbeX43dem3JielZgptDoh50",
        "GgYQkWF6drorQ0eHwo/PgDfafmMBNfr+Yig+QVxBdQ1xbX56fyR2vvfuBAUaYMtWStLST5KPXo+r",
        "vmQ2jxjmaIngc4Q1zL+E+zOecqu+VJ1elO20eTOYI7wGT50isZm14HEN2a7UyIkY+ZEE2uxwg/i8",
        "zPr0mj2Sj3wEWyC7+d2gkMI+PV6rodPvfZUSYmMxnuI8xH3o80Kgr03mHL3m/lMK8YST1ass9TM0",
        "RR7M6hEnWWFzapt8ibLO2D+YRQAAAIA1i7SxxECMPT7O+mgroGqtvplpUZhKqDPi5ABiWjdfIzOA",
        "8uouiLdn+mzmnBNiZRQePbkZBpUnB3BrRK6bSYeDpGIkVQcB7oHpGgIwZQLV3vyMYRMuD5o07lg2",
        "oocnp+oduD0/7S6Yr8lWcNQ4reJqBMMdmrBN0LC/7FndXULQfQAAAIEAzlKHB6PU5pxUpMLWMmTm",
        "A8s8KqEVjcBDpHfAihtXZj/MxrH6Ya8C8x+I0/TwyJhEGAnrHW0nOkRb9YAJLtebZefKBn6iHKdd",
        "2xRZthYJEkXpPW+5gNo34aS6VZa1JduPyxEn3dHtMywAeK3UBwMh0czpguOvAL6xQPh8b+KMvicA",
        "AACBAMo/M5p21T7+8IF/SUXLDRluHbadg27rngsPYTzXs7SqLo6XxyLkPwbZXeI2el9Vfplv9ikY",
        "MWjF+BcCsNLfytxkLwmYTDOLXSCLscqtzutbCjokDUT1SLRT2FvMYTsWgDg/HG4KZ46uAIKszjj0",
        "1P+G2Nqtri6rripfrCaqQwcjAAAABHRlc3QBAgMEBQY=",
    );

    #[test]
    fn rsa_follows_the_requested_hash() {
        let rsa = PrivateKey::from_bytes(&BASE64.decode(RSA_TEST_KEY.as_bytes()).unwrap()).unwrap();
        let vault = Vault::new(vec![key_item("rsa", &rsa)]);
        let blob = rsa.public_key().to_bytes().unwrap();
        for (flags, name) in [
            (RSA_SHA2_512, "rsa-sha2-512"),
            (RSA_SHA2_256, "rsa-sha2-256"),
            (0, "ssh-rsa"),
        ] {
            let signed = sign(&vault, &blob, b"session", flags).unwrap();
            assert_eq!(verify(&rsa, b"session", &signed).algorithm().as_str(), name);
        }
    }

    /// Ce que `ssh-keygen -Y sign -n <namespace>` fait signer à l'agent.
    fn sshsig(namespace: &str, hash: &str) -> Vec<u8> {
        let mut out = SSHSIG_MAGIC.to_vec();
        for part in [namespace.as_bytes(), b"", hash.as_bytes(), &[7u8; 64][..]] {
            out.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn recognizes_git_signature_requests() {
        assert_eq!(sshsig_namespace(&sshsig("git", "sha512")), Some("git"));
        assert!(is_git_signature(&sshsig("git", "sha256")));
        assert_eq!(sshsig_namespace(&sshsig("file", "sha512")), Some("file"));
        assert!(!is_git_signature(&sshsig("file", "sha512")));
        // Ni SSHSIG, ni bien formé : rien.
        assert_eq!(sshsig_namespace(b"donnees de session"), None);
        assert_eq!(sshsig_namespace(b"SSHSIG"), None);
        assert_eq!(sshsig_namespace(&sshsig("", "sha512")), None);
        assert_eq!(sshsig_namespace(&sshsig("git", "md5")), None);
        let mut trailing = sshsig("git", "sha512");
        trailing.push(0);
        assert_eq!(sshsig_namespace(&trailing), None);
        let mut truncated = sshsig("git", "sha512");
        truncated.truncate(truncated.len() - 1);
        assert_eq!(sshsig_namespace(&truncated), None);
        // Une authentification SSH : `string` identifiant de session, puis
        // SSH_MSG_USERAUTH_REQUEST (50)…
        let mut userauth = vec![0, 0, 0, 32];
        userauth.extend_from_slice(&[1u8; 32]);
        userauth.push(50);
        assert!(!is_git_signature(&userauth));
    }

    #[test]
    fn unknown_or_unreadable_keys_are_refused() {
        let key = PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519).unwrap();
        let mut broken = key_item("cassée", &other);
        broken.fields[1] = Field::new(PRIVATE_KEY_FIELD, "Clé privée", FieldKind::Concealed, "x");
        let vault = Vault::new(vec![key_item("bonne", &key), broken]);
        assert_eq!(identities(&vault).len(), 1);
        let blob = other.public_key().to_bytes().unwrap();
        assert!(sign(&vault, &blob, b"x", 0).is_err());
    }
}
