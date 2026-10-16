//! Extension PRF de `WebAuthn` (`prf`), pour les passkeys du coffre.
//!
//! Un site demande une valeur pseudo-aléatoire liée à la passkey et à un sel
//! de son choix (`eval.first`, `eval.second`) ; il s'en sert comme clé de
//! chiffrement (coffres chiffrés de bout en bout, déverrouillage par
//! passkey). La valeur doit rester **la même** pour la même passkey et le
//! même sel, sur tous les appareils, et différer d'un sel à l'autre.
//!
//! Calcul, comme l'extension CTAP2 `hmac-secret` qui porte la PRF sur une
//! clé matérielle, et comme `passkey-rs` (la bibliothèque du SDK de
//! Bitwarden) :
//!
//! ```text
//! sel       = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ entrée du site)   (côté client)
//! sortie    = HMAC-SHA256(secret de la passkey, sel)             (côté authentificateur)
//! ```
//!
//! **Le secret de la passkey.** Le format des passkeys de Bitwarden
//! (`login.fido2Credentials`) n'a aucun champ pour un secret `hmac-secret` :
//! le SDK de Bitwarden n'évalue pas la PRF pour les passkeys du coffre
//! (`CredentialExtensions { hmac_secret: None }`, PM-30510). Plutôt que
//! d'inventer un champ que les apps officielles effaceraient en réécrivant
//! l'élément, Verrou **dérive** le secret de ce que la passkey contient déjà :
//!
//! ```text
//! secret = HKDF-SHA256(ikm  = scalaire privé P-256 (32 octets),
//!                      salt = "verrou.passkey.prf.v1",
//!                      info = identifiant brut de l'accréditation)
//! ```
//!
//! Conséquences : toute passkey du coffre (créée par Verrou ou par une app
//! Bitwarden) a une PRF, stable sur tous les appareils où Verrou tourne ; qui
//! détient la clé privée peut la recalculer (comme pour un secret rangé à
//! côté). Si Bitwarden ajoute un jour un champ, ses sorties différeront de
//! celles-ci : les données chiffrées par un site avec la PRF de Verrou ne
//! s'ouvriraient pas avec les apps officielles (aujourd'hui, elles n'ont pas
//! de PRF du tout).
//!
//! La PRF n'est rendue qu'après vérification de l'utilisateur (Face ID,
//! Touch ID ou mot de passe principal) : comme `hmac-secret` avec
//! `CredRandomWithUV` seul.

use hmac::{Hmac, Mac as _};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey as _;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::passkey::{Passkey, PasskeyError, b64url_decode};

type HmacSha256 = Hmac<Sha256>;

/// Préfixe du hachage des entrées (`WebAuthn` niveau 3, §10.1.4).
const SALT_PREFIX: &[u8] = b"WebAuthn PRF\0";
/// Sel HKDF propre à Verrou : changer la dérivation exige une nouvelle version.
const SECRET_SALT: &[u8] = b"verrou.passkey.prf.v1";
/// Taille d'une entrée acceptée (une page peut envoyer n'importe quoi).
const MAX_INPUT: usize = 1024;

/// Les sels d'une évaluation, déjà hachés (32 octets chacun).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfSalts {
    pub first: [u8; 32],
    pub second: Option<[u8; 32]>,
}

/// Les sorties de la PRF : des clés, effacées de la mémoire à la fin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfOutputs {
    pub first: Zeroizing<[u8; 32]>,
    pub second: Option<Zeroizing<[u8; 32]>>,
}

/// Hache une entrée du site en sel (`SHA-256("WebAuthn PRF" ‖ 0 ‖ entrée)`),
/// ce que fait le client (navigateur, système) avant l'authentificateur.
pub fn salt(input: &[u8]) -> Result<[u8; 32], PasskeyError> {
    if input.len() > MAX_INPUT {
        return Err(PasskeyError::BadRequest("entrée PRF trop longue"));
    }
    let mut hasher = Sha256::new();
    hasher.update(SALT_PREFIX);
    hasher.update(input);
    Ok(hasher.finalize().into())
}

/// Les sels des entrées brutes du site (`eval.first`, `eval.second`).
pub fn salts(first: &[u8], second: Option<&[u8]>) -> Result<PrfSalts, PasskeyError> {
    Ok(PrfSalts {
        first: salt(first)?,
        second: second.map(salt).transpose()?,
    })
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepte toute longueur de clé");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 (RFC 5869), un seul bloc de sortie (32 octets).
fn hkdf_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut prk = hmac(salt, &[ikm]);
    let okm = Zeroizing::new(hmac(&prk, &[info, &[1]]));
    prk.zeroize();
    okm
}

/// Le secret `hmac-secret` de la passkey, dérivé de sa clé privée et de son
/// identifiant (voir l'en-tête du module).
fn credential_secret(passkey: &Passkey) -> Result<Zeroizing<[u8; 32]>, PasskeyError> {
    let mut der = b64url_decode(passkey.key.expose()).ok_or(PasskeyError::BadKey)?;
    let key = SigningKey::from_pkcs8_der(&der).map_err(|_| PasskeyError::BadKey);
    der.zeroize();
    let key = key?;
    let credential_id = passkey.raw_id().ok_or(PasskeyError::BadKey)?;
    let scalar = Zeroizing::new(<[u8; 32]>::from(key.to_bytes()));
    Ok(hkdf_32(SECRET_SALT, scalar.as_slice(), &credential_id))
}

/// Évalue la PRF de la passkey pour des sels déjà hachés (ce que reçoit un
/// authentificateur CTAP2). Refusée sans vérification de l'utilisateur.
pub fn evaluate(
    passkey: &Passkey,
    salts: &PrfSalts,
    user_verified: bool,
) -> Result<PrfOutputs, PasskeyError> {
    if !user_verified {
        return Err(PasskeyError::BadRequest(
            "la PRF exige la vérification de l'utilisateur",
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

/// Évalue la PRF pour les entrées brutes du site (ce que reçoivent le
/// fournisseur d'iOS et de macOS, et l'extension de navigateur) : hachage
/// `WebAuthn`, puis [`evaluate`].
pub fn evaluate_inputs(
    passkey: &Passkey,
    first: &[u8],
    second: Option<&[u8]>,
    user_verified: bool,
) -> Result<PrfOutputs, PasskeyError> {
    evaluate(passkey, &salts(first, second)?, user_verified)
}

/// `evalByCredential` : l'entrée propre à cette passkey si le site en donne
/// une (identifiant brut), sinon `eval`.
pub fn select_inputs<'a, T>(
    credential_id: &[u8],
    eval: Option<&'a T>,
    by_credential: impl IntoIterator<Item = (&'a [u8], &'a T)>,
) -> Option<&'a T> {
    by_credential
        .into_iter()
        .find(|(id, _)| *id == credential_id)
        .map(|(_, value)| value)
        .or(eval)
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

    /// Passkey au scalaire fixe (1, 2, …, 32) et à l'identifiant fixe, au
    /// format de Bitwarden : les vecteurs ci-dessous en dépendent.
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

    /// RFC 5869, cas de test 1 (L = 32 : les 32 premiers octets de l'OKM).
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

    /// Hachage des entrées : `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ entrée)`,
    /// recalculé ici sans passer par `salt`.
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

    /// Vecteurs (calculés indépendamment, avec `hmac` et `hashlib` de
    /// Python) : secret et sorties de la passkey fixe. Ils figent la
    /// dérivation ; s'ils changent, les données qu'un site a chiffrées avec
    /// la PRF ne s'ouvrent plus.
    #[test]
    fn outputs_match_the_test_vectors() {
        let passkey = fixed_passkey();
        let secret = credential_secret(&passkey).unwrap();
        // secret = HKDF(salt, scalaire 01..20, identifiant brut)
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
        // Sortie = HMAC-SHA256(secret, sel), comme hmac-secret.
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

        // Même clé, autre identifiant : autre secret.
        let mut other = fixed_passkey();
        other.credential_id = "b64.AQID".into();
        assert_ne!(
            evaluate_inputs(&other, b"a", None, true).unwrap().first,
            a.first
        );

        // Passkey créée pour le système : sa PRF ne dépend que de ce qui est
        // gardé dans le coffre (la relire donne la même sortie).
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

    #[test]
    fn eval_by_credential_wins_over_eval() {
        let eval = "défaut";
        let mine = "pour moi";
        let other = "pour une autre";
        let list: Vec<(&[u8], &&str)> = vec![(b"\x02", &other), (b"\x01", &mine)];
        assert_eq!(
            select_inputs(b"\x01", Some(&eval), list.clone()),
            Some(&mine)
        );
        assert_eq!(
            select_inputs(b"\x03", Some(&eval), list.clone()),
            Some(&eval)
        );
        assert_eq!(select_inputs::<&str>(b"\x03", None, list), None);
    }
}
