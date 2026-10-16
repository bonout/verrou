//! Passkeys pour l'extension : ce que la page peut obtenir, et rien de plus.
//!
//! - **Lister** : les passkeys du site (`rpId`, vérifié sur l'adresse de la
//!   page donnée par le navigateur), avec titre et nom d'utilisateur. Ni clé,
//!   ni compteur.
//! - **Utiliser** : une passkey du site signe le défi de la page ; la clé
//!   privée reste dans Verrou ([`verrou_core::passkey::assert`]). Le nouveau
//!   compteur est enregistré dans le coffre avant que la réponse parte.
//! - **Créer** : Verrou crée la clé, l'enregistre dans un identifiant du site
//!   (ou un nouveau) et ne rend à la page que la clé publique et
//!   l'attestation.
//!
//! Comme pour les mots de passe : HTTPS seulement (HTTP vers `localhost`),
//! coffre déverrouillé, élément protégé confirmé dans Verrou (voir
//! [`crate::Backend::gate`]), et la vérification de l'utilisateur demandée par
//! le site passe par Touch ID dans Verrou.

use verrou_core::passkey::{
    self, AssertionRequest, ES256, RegistrationRequest, b64url, b64url_decode,
};
use verrou_core::passkey_prf;
use verrou_core::{FieldKind, Item, Passkey, Vault};

use crate::access::{Write, logins_for, page_allowed};
use crate::protocol::{
    PasskeyAssertion, PasskeyCreation, PasskeyQuery, PasskeyRegistration, PasskeySuggestion,
    PasskeyTarget, PasskeyTargetsQuery, PasskeyUse, PrfCreated, PrfRequest, PrfValues,
};

/// Longueur maximale des textes venus de la page (noms, identifiants).
const MAX_TEXT: usize = 256;
/// Nombre maximal d'identifiants d'accréditation dans une liste.
const MAX_IDS: usize = 64;

/// Refus d'une création : la passkey est déjà dans le coffre (la page reçoit
/// `InvalidStateError`, comme le prévoit `WebAuthn`).
pub const ALREADY_SAVED: &str = "cette passkey est déjà dans Verrou";

fn site(page_url: &str, requested: Option<&str>) -> Result<String, String> {
    if !page_allowed(page_url) {
        return Err("page non sécurisée (HTTPS exigé)".to_owned());
    }
    passkey::origin_and_rp_id(page_url, requested)
        .map(|(_, rp_id)| rp_id)
        .map_err(|e| e.to_string())
}

fn ids(list: &[String]) -> Result<Vec<Vec<u8>>, String> {
    if list.len() > MAX_IDS {
        return Err("trop d'identifiants de passkey".to_owned());
    }
    Ok(list.iter().filter_map(|id| b64url_decode(id)).collect())
}

fn clip(text: Option<&str>) -> Option<String> {
    text.map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| t.chars().take(MAX_TEXT).collect())
}

fn username_of(item: &Item) -> String {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose().to_owned())
        .unwrap_or_default()
}

/// Passkeys proposées à la page pour `navigator.credentials.get`.
pub fn list(vault: &Vault, query: &PasskeyQuery) -> Result<Vec<PasskeySuggestion>, String> {
    let rp_id = site(&query.url, query.rp_id.as_deref())?;
    let allow = ids(&query.allow)?;
    Ok(vault
        .passkeys_for(&rp_id)
        .into_iter()
        .filter(|p| {
            if allow.is_empty() {
                p.discoverable
            } else {
                p.raw_id().is_some_and(|id| allow.contains(&id))
            }
        })
        .filter_map(|p| {
            let item = vault.get(&p.item)?;
            Some(PasskeySuggestion {
                item: item.id.clone(),
                title: item.title.clone(),
                credential: b64url(&p.raw_id()?),
                user_name: p
                    .user_name
                    .clone()
                    .or_else(|| p.user_display_name.clone())
                    .unwrap_or_else(|| username_of(item)),
            })
        })
        .collect())
}

/// La passkey demandée, si elle appartient au site de la page.
pub fn find<'v>(vault: &'v Vault, request: &PasskeyUse) -> Result<(&'v Item, &'v Passkey), String> {
    let rp_id = site(&request.url, request.rp_id.as_deref())?;
    let credential = b64url_decode(&request.credential)
        .ok_or_else(|| "identifiant de passkey illisible".to_owned())?;
    let passkey = vault
        .passkeys_for(&rp_id)
        .into_iter()
        .find(|p| p.item == request.item && p.raw_id().as_deref() == Some(credential.as_slice()))
        .ok_or_else(|| "cette passkey n'appartient pas à ce site".to_owned())?;
    let item = vault
        .get(&passkey.item)
        .ok_or_else(|| "élément introuvable".to_owned())?;
    Ok((item, passkey))
}

/// Évalue la PRF de la passkey pour les entrées de la page (base64url).
/// Sans vérification de l'utilisateur (Touch ID refusé ou non demandé), pas
/// de sortie : la page ne reçoit rien plutôt qu'une erreur.
fn prf_results(
    passkey: &Passkey,
    values: &PrfValues,
    user_verified: bool,
) -> Result<Option<PrfValues>, String> {
    if !user_verified {
        return Ok(None);
    }
    let first = b64url_decode(&values.first).ok_or_else(|| "entrée PRF illisible".to_owned())?;
    let second = values
        .second
        .as_deref()
        .map(|s| b64url_decode(s).ok_or_else(|| "entrée PRF illisible".to_owned()))
        .transpose()?;
    let out = passkey_prf::evaluate_inputs(passkey, &first, second.as_deref(), true)
        .map_err(|e| e.to_string())?;
    Ok(Some(PrfValues {
        first: b64url(out.first.as_slice()),
        second: out.second.map(|s| b64url(s.as_slice())),
    }))
}

/// Les entrées PRF de la page pour cette passkey : `evalByCredential` si
/// elle y figure (identifiant brut, quel que soit l'encodage base64url),
/// sinon `eval`.
fn prf_inputs<'r>(request: &'r PrfRequest, credential_id: &[u8]) -> Option<&'r PrfValues> {
    request
        .eval_by_credential
        .iter()
        .take(MAX_IDS)
        .find(|(id, _)| b64url_decode(id).as_deref() == Some(credential_id))
        .map(|(_, values)| values)
        .or(request.eval.as_ref())
}

/// Signe le défi de la page ; l'écriture à faire : le nouveau compteur.
pub fn plan_assertion(
    vault: &Vault,
    request: &PasskeyUse,
    user_verified: bool,
) -> Result<(Write, PasskeyAssertion), String> {
    let (item, passkey) = find(vault, request)?;
    let challenge = b64url_decode(&request.challenge).ok_or_else(|| "défi illisible".to_owned())?;
    let assertion = passkey::assert(
        passkey,
        &AssertionRequest {
            page_url: &request.url,
            rp_id: request.rp_id.as_deref(),
            challenge: &challenge,
            user_verified,
        },
    )
    .map_err(|e| e.to_string())?;
    let write = Write::PasskeyCounter {
        item: item.id.clone(),
        credential_id: passkey.credential_id.clone(),
        counter: assertion.counter,
    };
    Ok((
        write,
        PasskeyAssertion {
            credential: b64url(&assertion.credential_id),
            client_data: b64url(&assertion.client_data_json),
            authenticator_data: b64url(&assertion.authenticator_data),
            signature: b64url(&assertion.signature),
            user_handle: assertion.user_handle.as_deref().map(b64url),
            prf: match request
                .prf
                .as_ref()
                .and_then(|p| prf_inputs(p, &assertion.credential_id))
            {
                Some(values) => prf_results(passkey, values, user_verified)?,
                None => None,
            },
        },
    ))
}

/// Identifiants du site qui peuvent recevoir une nouvelle passkey, et si
/// l'une des passkeys exclues par le site est déjà dans le coffre.
pub fn targets(
    vault: &Vault,
    query: &PasskeyTargetsQuery,
) -> Result<(bool, Vec<PasskeyTarget>), String> {
    let rp_id = site(&query.url, query.rp_id.as_deref())?;
    let exclude = ids(&query.exclude)?;
    let excluded = vault
        .passkeys_for(&rp_id)
        .iter()
        .any(|p| p.raw_id().is_some_and(|id| exclude.contains(&id)));
    let logins = logins_for(vault, &query.url)
        .into_iter()
        .map(|item| PasskeyTarget {
            id: item.id.clone(),
            title: item.title.clone(),
            username: username_of(item),
            has_passkey: !vault.passkeys_of(&item.id).is_empty(),
        })
        .collect();
    Ok((excluded, logins))
}

/// Vérifie une demande de création avant de demander quoi que ce soit à
/// l'utilisateur. Rend la clé de l'accord (l'élément visé, ou le site pour
/// un nouvel élément) et le titre à montrer.
pub fn check_creation(
    vault: &Vault,
    request: &PasskeyCreation,
) -> Result<(String, String), String> {
    let rp_id = site(&request.url, request.rp_id.as_deref())?;
    if !request.algorithms.is_empty() && !request.algorithms.contains(&ES256) {
        return Err("le site n'accepte pas les clés ES256".to_owned());
    }
    let exclude = ids(&request.exclude)?;
    if vault
        .passkeys_for(&rp_id)
        .iter()
        .any(|p| p.raw_id().is_some_and(|id| exclude.contains(&id)))
    {
        return Err(ALREADY_SAVED.to_owned());
    }
    match &request.item {
        Some(id) => {
            let item = logins_for(vault, &request.url)
                .into_iter()
                .find(|i| &i.id == id)
                .ok_or_else(|| "cet identifiant ne correspond pas à ce site".to_owned())?;
            Ok((item.id.clone(), item.title.clone()))
        }
        None => Ok((format!("passkey:{rp_id}"), rp_id)),
    }
}

/// Crée la passkey : l'écriture à faire (dans l'élément visé, ou un nouvel
/// identifiant) et la réponse pour la page (son `item` reste à remplir avec
/// l'élément écrit).
pub fn plan_creation(
    vault: &Vault,
    request: &PasskeyCreation,
    user_verified: bool,
    now: i64,
) -> Result<(Write, PasskeyRegistration), String> {
    check_creation(vault, request)?;
    let user_id =
        b64url_decode(&request.user_id).ok_or_else(|| "utilisateur illisible".to_owned())?;
    let challenge = b64url_decode(&request.challenge).ok_or_else(|| "défi illisible".to_owned())?;
    let rp_name = clip(request.rp_name.as_deref());
    let user_name = clip(request.user_name.as_deref());
    let user_display_name = clip(request.user_display_name.as_deref());
    let self_attestation = matches!(
        request.attestation.as_deref(),
        Some("direct" | "enterprise")
    );
    let (passkey, registration) = passkey::register(
        &RegistrationRequest {
            page_url: &request.url,
            rp_id: request.rp_id.as_deref(),
            rp_name: rp_name.as_deref(),
            user_id: &user_id,
            user_name: user_name.as_deref(),
            user_display_name: user_display_name.as_deref(),
            challenge: &challenge,
            user_verified,
            self_attestation,
        },
        request.item.as_deref().unwrap_or_default(),
        now,
        &mut rand::rngs::OsRng,
    )
    .map_err(|e| e.to_string())?;
    let prf = match &request.prf {
        Some(prf) => Some(PrfCreated {
            enabled: true,
            results: match &prf.eval {
                Some(values) => prf_results(&passkey, values, user_verified)?,
                None => None,
            },
        }),
        None => None,
    };
    let (title, uri) = crate::access::new_site(&request.url)?;
    let write = Write::Passkey {
        item: request.item.clone(),
        title,
        uri,
        username: user_name,
        passkey: Box::new(passkey),
    };
    Ok((
        write,
        PasskeyRegistration {
            item: String::new(),
            credential: b64url(&registration.credential_id),
            client_data: b64url(&registration.client_data_json),
            authenticator_data: b64url(&registration.authenticator_data),
            attestation_object: b64url(&registration.attestation_object),
            public_key: b64url(&registration.public_key),
            algorithm: ES256,
            prf,
        },
    ))
}

/// [`crate::access::apply_in_memory`] pour les passkeys : faux coffres
/// (tests, serveur de test de l'extension).
pub(crate) fn apply_in_memory(vault: &Vault, write: Write, new_id: &str) -> (Vault, String) {
    let mut passkeys = vault.passkeys().to_vec();
    match write {
        Write::Passkey {
            item,
            title,
            uri,
            username,
            mut passkey,
        } => {
            let (vault, id) = if let Some(id) = item {
                (Vault::new(vault.items().to_vec()), id)
            } else {
                let created = Write::Create {
                    title,
                    uri,
                    username,
                    password: None,
                    totp: None,
                };
                crate::access::apply_in_memory(vault, created, new_id)
            };
            // Comme Bitwarden : une passkey par identifiant.
            passkeys.retain(|p| p.item != id);
            id.clone_into(&mut passkey.item);
            passkeys.push(*passkey);
            (
                Vault::new(vault.items().to_vec())
                    .with_passkeys(passkeys)
                    .with_match_rules(vault.match_rules().clone()),
                id,
            )
        }
        Write::PasskeyCounter {
            item,
            credential_id,
            counter,
        } => {
            for passkey in &mut passkeys {
                if passkey.item == item && passkey.credential_id == credential_id {
                    passkey.counter = counter;
                }
            }
            (
                Vault::new(vault.items().to_vec())
                    .with_passkeys(passkeys)
                    .with_match_rules(vault.match_rules().clone()),
                item,
            )
        }
        other => crate::access::apply_in_memory(vault, other, new_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::apply_in_memory;
    use verrou_core::{Field, ItemKind};

    fn login(id: &str, url: &str, username: &str) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: username.to_owned(),
            urls: vec![url.to_owned()],
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![Field::new(
                "username",
                "Identifiant",
                FieldKind::Username,
                username,
            )],
            notes: None,
            reprompt: false,
            state: verrou_core::ItemState::Active,
            shared: None,
        }
    }

    fn creation(url: &str, item: Option<&str>) -> PasskeyCreation {
        PasskeyCreation {
            url: url.to_owned(),
            rp_id: None,
            rp_name: Some("GitHub".to_owned()),
            user_id: b64url(b"id-camille"),
            user_name: Some("camille".to_owned()),
            user_display_name: None,
            challenge: b64url(&[5; 32]),
            algorithms: vec![-8, ES256],
            exclude: Vec::new(),
            uv: false,
            attestation: None,
            item: item.map(str::to_owned),
            prf: None,
        }
    }

    #[test]
    fn create_list_use_and_count() {
        let vault = Vault::new(vec![
            login("github", "https://github.com", "camille"),
            login("banque", "https://banque.fr", "camille"),
        ]);
        // Dans l'identifiant du site.
        let request = creation("https://github.com/settings", Some("github"));
        let (write, registration) = plan_creation(&vault, &request, false, 0).unwrap();
        let (vault, id) = apply_in_memory(&vault, write, "nouveau");
        assert_eq!(id, "github");
        assert_eq!(vault.passkeys_of("github").len(), 1);
        assert!(registration.attestation_object.len() > 100);

        // La page la retrouve, sans secret.
        let query = PasskeyQuery {
            url: "https://github.com/login".to_owned(),
            rp_id: None,
            allow: Vec::new(),
        };
        let found = list(&vault, &query).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential, registration.credential);
        assert_eq!(found[0].user_name, "camille");
        let json = serde_json::to_string(&found).unwrap();
        assert!(!json.contains(vault.passkeys()[0].key.expose()));
        // Pas pour un autre site, ni en HTTP.
        let elsewhere = PasskeyQuery {
            url: "https://banque.fr/".to_owned(),
            ..query.clone()
        };
        assert_eq!(list(&vault, &elsewhere).unwrap(), []);
        let insecure = PasskeyQuery {
            url: "http://github.com/".to_owned(),
            ..query.clone()
        };
        assert!(list(&vault, &insecure).is_err());

        // Deux utilisations : le compteur avance, enregistré à chaque fois.
        let mut vault = vault;
        for expected in 1..=2 {
            let use_ = PasskeyUse {
                url: "https://github.com/login".to_owned(),
                rp_id: Some("github.com".to_owned()),
                item: "github".to_owned(),
                credential: registration.credential.clone(),
                challenge: b64url(&[7; 32]),
                uv: false,
                prf: None,
            };
            let (write, assertion) = plan_assertion(&vault, &use_, false).unwrap();
            assert!(matches!(write, Write::PasskeyCounter { counter, .. } if counter == expected));
            assert_eq!(
                assertion.user_handle.as_deref(),
                Some(b64url(b"id-camille").as_str())
            );
            vault = apply_in_memory(&vault, write, "x").0;
            assert_eq!(vault.passkeys()[0].counter, expected);
        }
        // Une autre page ne l'obtient pas.
        let stolen = PasskeyUse {
            url: "https://banque.fr/".to_owned(),
            rp_id: Some("github.com".to_owned()),
            item: "github".to_owned(),
            credential: registration.credential.clone(),
            challenge: b64url(&[7; 32]),
            uv: false,
            prf: None,
        };
        assert!(plan_assertion(&vault, &stolen, false).is_err());

        // Le site l'exclut : déjà enregistrée.
        let mut again = creation("https://github.com/", None);
        again.exclude = vec![registration.credential.clone()];
        assert_eq!(
            check_creation(&vault, &again).unwrap_err(),
            ALREADY_SAVED.to_owned()
        );
        let (excluded, logins) = targets(
            &vault,
            &PasskeyTargetsQuery {
                url: "https://github.com/".to_owned(),
                rp_id: None,
                exclude: again.exclude.clone(),
            },
        )
        .unwrap();
        assert!(excluded);
        assert_eq!(logins.len(), 1);
        assert!(logins[0].has_passkey);
    }

    /// PRF : sorties à la création (`eval`), les mêmes à la connexion pour
    /// la même entrée, `evalByCredential` prioritaire, rien sans Touch ID.
    #[test]
    fn prf_at_creation_and_assertion() {
        let vault = Vault::new(vec![login("github", "https://github.com", "camille")]);
        let values = |first: &[u8], second: Option<&[u8]>| PrfValues {
            first: b64url(first),
            second: second.map(b64url),
        };
        let mut request = creation("https://github.com/", Some("github"));
        request.uv = true;
        request.prf = Some(PrfRequest {
            eval: Some(values(b"sel-a", Some(b"sel-b"))),
            ..PrfRequest::default()
        });
        let (write, registration) = plan_creation(&vault, &request, true, 0).unwrap();
        let created = registration.prf.clone().unwrap();
        assert!(created.enabled);
        let at_creation = created.results.unwrap();
        assert_ne!(Some(&at_creation.first), at_creation.second.as_ref());
        let (vault, _) = apply_in_memory(&vault, write, "x");

        // Sans Touch ID : la passkey sait faire, mais pas de sortie.
        let (_, quiet) = plan_creation(
            &Vault::new(vec![login("github", "https://github.com", "camille")]),
            &request,
            false,
            0,
        )
        .unwrap();
        assert_eq!(
            quiet.prf,
            Some(PrfCreated {
                enabled: true,
                results: None
            })
        );

        let use_with = |prf: PrfRequest, uv: bool| PasskeyUse {
            url: "https://github.com/login".to_owned(),
            rp_id: None,
            item: "github".to_owned(),
            credential: registration.credential.clone(),
            challenge: b64url(&[9; 32]),
            uv,
            prf: Some(prf),
        };
        let eval = PrfRequest {
            eval: Some(values(b"sel-a", Some(b"sel-b"))),
            ..PrfRequest::default()
        };
        let (_, assertion) = plan_assertion(&vault, &use_with(eval.clone(), true), true).unwrap();
        assert_eq!(assertion.prf.as_ref(), Some(&at_creation));
        let (_, without_uv) = plan_assertion(&vault, &use_with(eval, false), false).unwrap();
        assert_eq!(without_uv.prf, None);

        // `evalByCredential` (identifiant avec remplissage `=` : même octets).
        let mut by_credential = PrfRequest {
            eval: Some(values(b"sel-a", None)),
            ..PrfRequest::default()
        };
        by_credential.eval_by_credential.insert(
            format!("{}==", registration.credential),
            values(b"sel-c", None),
        );
        let (_, chosen) = plan_assertion(&vault, &use_with(by_credential, true), true).unwrap();
        let chosen = chosen.prf.unwrap();
        assert_ne!(chosen.first, at_creation.first);
        assert_eq!(chosen.second, None);
        let mut garbled = use_with(PrfRequest::default(), true);
        garbled.prf = Some(PrfRequest {
            eval: Some(PrfValues {
                first: "@@".to_owned(),
                second: None,
            }),
            ..PrfRequest::default()
        });
        assert!(plan_assertion(&vault, &garbled, true).is_err());
    }

    #[test]
    fn creation_is_checked_against_the_page() {
        let vault = Vault::new(vec![
            login("github", "https://github.com", "camille"),
            login("banque", "https://banque.fr", "camille"),
        ]);
        // L'identifiant d'un autre site ne reçoit pas la passkey.
        assert!(check_creation(&vault, &creation("https://github.com/", Some("banque"))).is_err());
        // Un rpId d'un autre site est refusé.
        let mut foreign = creation("https://github.com/", None);
        foreign.rp_id = Some("banque.fr".to_owned());
        assert!(check_creation(&vault, &foreign).is_err());
        // Sans ES256, le navigateur s'en charge.
        let mut rsa = creation("https://github.com/", None);
        rsa.algorithms = vec![-257];
        assert!(check_creation(&vault, &rsa).is_err());
        // Nouvel élément : titre et site tirés de la page.
        let (write, _) = plan_creation(
            &vault,
            &creation("https://www.exemple.fr/inscription", None),
            true,
            0,
        )
        .unwrap();
        let Write::Passkey {
            item,
            title,
            uri,
            username,
            passkey,
        } = &write
        else {
            panic!("passkey attendue");
        };
        assert_eq!(item, &None);
        assert_eq!(
            (title.as_str(), uri.as_str()),
            ("exemple.fr", "https://www.exemple.fr")
        );
        assert_eq!(username.as_deref(), Some("camille"));
        assert_eq!(passkey.rp_id, "www.exemple.fr");
        let (vault, id) = apply_in_memory(&vault, write, "nouveau");
        assert_eq!(id, "nouveau");
        assert_eq!(vault.passkeys_of("nouveau").len(), 1);
    }
}
