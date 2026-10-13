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

/// Les clés SSH utilisables du coffre : leur clé publique et leur titre.
pub fn identities(vault: &Vault) -> Vec<SshIdentity> {
    vault
        .items()
        .iter()
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
            && private_key(item)
                .and_then(|key| public_blob(&key))
                .is_some_and(|b| b == blob)
    })
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
