//! Remplissage automatique d'iOS (extension `VerrouAutoFill`).
//!
//! L'extension ouvre le coffre du dossier partagé en **invitée**
//! (`VaultSession::for_autofill`) : elle lit le cache et la file de l'app,
//! écrit directement sur le serveur ce qui ne peut pas attendre (passkey
//! créée, compteur d'une passkey), puis enregistre le cache resynchronisé ;
//! elle n'envoie ni n'écrit jamais la file de l'app (voir
//! `verrou_vaultwarden::Store::guest`).
//!
//! Ce module donne aussi à l'app ce qu'elle publie dans le magasin des
//! identités du système (`ASCredentialIdentityStore`) : sites, noms
//! d'utilisateur et identifiants de passkeys, **jamais un secret**.

use std::collections::HashSet;
use std::sync::Arc;

use verrou_bridge::access::Write;
use verrou_core::matching::host_of;
use verrou_core::passkey::{self, Passkey, SystemRegistrationRequest};
use verrou_core::{FieldKind, Item, ItemKind, Vault};
use verrou_vaultwarden::Store;

use crate::{ItemSummary, VaultSession, VerrouError, summary};

/// Longueur maximale des textes venus du site (nom, utilisateur).
const MAX_TEXT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AutofillIdentityKind {
    Password,
    /// Code à usage unique (iOS 18) : l'élément a une graine TOTP.
    OneTimeCode,
    Passkey,
}

/// Une suggestion pour la barre `QuickType` : où et pour qui, sans secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AutofillIdentity {
    pub kind: AutofillIdentityKind,
    /// L'élément du coffre (`recordIdentifier`).
    pub item_id: String,
    /// Domaine du site (mot de passe, code), ou `rpId` (passkey).
    pub service: String,
    /// Nom d'utilisateur montré (ou titre de l'élément s'il n'en a pas).
    pub user: String,
    /// Passkey : identifiant brut de l'accréditation.
    pub credential_id: Vec<u8>,
    /// Passkey : identifiant de l'utilisateur chez le site (vide sinon).
    pub user_handle: Vec<u8>,
}

/// Identifiant et mot de passe d'un élément, pour `ASPasswordCredential`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AutofillPassword {
    pub username: String,
    pub password: String,
}

/// Une passkey proposée pour un site, sans clé privée.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AutofillPasskey {
    pub item_id: String,
    pub title: String,
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub reprompt: bool,
}

/// Assertion signée pour `ASPasskeyAssertionCredential`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyAssertionResult {
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// Nouvelle passkey, pour `ASPasskeyRegistrationCredential`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyRegistrationResult {
    /// L'identifiant qui la porte (nouveau ou existant).
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// Ce que le système demande de créer (`ASPasskeyCredentialRequest`).
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyCreationRequest {
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    /// Face ID ou mot de passe principal demandé pour cette création.
    pub user_verified: bool,
    /// Identifiant existant qui recevra la passkey ; `None` : un nouveau.
    pub item_id: Option<String>,
    /// Passkeys que le site exclut (déjà enregistrées chez lui).
    pub excluded_credentials: Vec<Vec<u8>>,
}

fn username_of(item: &Item) -> String {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose().to_owned())
        .unwrap_or_default()
}

fn clip(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.chars().take(MAX_TEXT).collect())
}

/// Les sites d'un élément (hôtes sans `www.`, sans doublon), dans l'ordre.
fn hosts(item: &Item) -> Vec<String> {
    let mut seen = HashSet::new();
    item.urls
        .iter()
        .filter_map(|u| host_of(u))
        .filter(|h| seen.insert(h.clone()))
        .collect()
}

/// Identités de tout le coffre : identifiants actifs avec un site, codes
/// des éléments qui ont une graine TOTP, passkeys. Les éléments protégés
/// en font partie (seul le nom d'utilisateur est montré ; le secret
/// attendra la confirmation).
fn identities(vault: &Vault) -> Vec<AutofillIdentity> {
    let mut out = Vec::new();
    for item in vault.items() {
        if item.kind != ItemKind::Login || !item.is_active() {
            continue;
        }
        let username = username_of(item);
        let user = if username.is_empty() {
            item.title.clone()
        } else {
            username
        };
        let has_password = item
            .field_of_kind(FieldKind::Password)
            .is_some_and(|f| !f.value.expose().is_empty());
        for host in hosts(item) {
            if has_password {
                out.push(AutofillIdentity {
                    kind: AutofillIdentityKind::Password,
                    item_id: item.id.clone(),
                    service: host.clone(),
                    user: user.clone(),
                    credential_id: Vec::new(),
                    user_handle: Vec::new(),
                });
            }
            if item.has_totp() {
                out.push(AutofillIdentity {
                    kind: AutofillIdentityKind::OneTimeCode,
                    item_id: item.id.clone(),
                    service: host,
                    user: user.clone(),
                    credential_id: Vec::new(),
                    user_handle: Vec::new(),
                });
            }
        }
    }
    for key in vault.passkeys() {
        let Some(item) = vault.get(&key.item) else {
            continue;
        };
        if item.kind != ItemKind::Login || !item.is_active() {
            continue;
        }
        let Some(credential_id) = key.raw_id() else {
            continue;
        };
        out.push(AutofillIdentity {
            kind: AutofillIdentityKind::Passkey,
            item_id: item.id.clone(),
            service: key.rp_id.clone(),
            user: passkey_user(key, item),
            credential_id,
            user_handle: key
                .user_handle
                .as_deref()
                .and_then(passkey::b64url_decode)
                .unwrap_or_default(),
        });
    }
    out
}

fn passkey_user(key: &Passkey, item: &Item) -> String {
    key.user_name
        .clone()
        .or_else(|| key.user_display_name.clone())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| {
            let username = username_of(item);
            if username.is_empty() {
                item.title.clone()
            } else {
                username
            }
        })
}

/// Page à partir d'un identifiant de service du système : un domaine nu
/// (`exemple.fr`) ou une URL.
fn page_of(service: &str) -> String {
    let service = service.trim();
    if service.contains("://") {
        service.to_owned()
    } else {
        format!("https://{service}")
    }
}

/// Adresse enregistrée dans un nouvel identifiant créé pour une passkey.
fn site_uri(rp_id: &str) -> String {
    if rp_id == "localhost" {
        "http://localhost".to_owned()
    } else {
        format!("https://{rp_id}")
    }
}

impl VaultSession {
    fn find_passkey<'v>(
        vault: &'v Vault,
        rp_id: &str,
        credential_id: &[u8],
    ) -> Result<(&'v Item, &'v Passkey), VerrouError> {
        let passkey = vault
            .passkeys_for(rp_id)
            .into_iter()
            .find(|p| p.raw_id().as_deref() == Some(credential_id))
            .ok_or(VerrouError::NotFound)?;
        let item = vault.get(&passkey.item).ok_or(VerrouError::NotFound)?;
        Ok((item, passkey))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Session de l'extension de remplissage automatique : même dossier que
    /// l'app, ouvert en invitée (jamais d'envoi ni d'écriture de la file).
    #[uniffi::constructor]
    pub fn for_autofill(data_dir: String) -> Arc<Self> {
        Self::with_store(Store::new(data_dir).guest())
    }

    /// Ce que l'app publie pour les suggestions du système (`QuickType`) :
    /// sites, noms d'utilisateur, passkeys. Aucun secret.
    pub fn autofill_identities(&self) -> Result<Vec<AutofillIdentity>, VerrouError> {
        self.with_vault(|v| Ok(identities(v)))
    }

    /// Identifiants correspondant aux services demandés par le système
    /// (domaines ou URL), du plus précis au moins précis, sans doublon.
    pub fn autofill_matches(&self, services: Vec<String>) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            let mut seen = HashSet::new();
            Ok(services
                .iter()
                .flat_map(|s| v.suggestions_for(&page_of(s)))
                .filter(|item| seen.insert(item.id.clone()))
                .map(|item| self.summary_of(item))
                .collect())
        })
    }

    /// ⚠️ Identifiant et mot de passe d'un identifiant, pour le remplir :
    /// seulement après le choix de l'utilisateur (ou une suggestion du
    /// système qu'il a touchée). Un élément protégé doit avoir été confirmé
    /// (`authorize_item`). Comme sur le Mac, « masquer les mots de passe »
    /// d'une organisation n'empêche pas le remplissage.
    pub fn autofill_password(&self, id: String) -> Result<AutofillPassword, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if item.kind != ItemKind::Login {
                return Err(VerrouError::Invalid {
                    message: "seul un identifiant se remplit".to_owned(),
                });
            }
            self.require_authorized(item)?;
            Ok(AutofillPassword {
                username: username_of(item),
                password: item
                    .field_of_kind(FieldKind::Password)
                    .map(|f| f.value.expose().to_owned())
                    .unwrap_or_default(),
            })
        })
    }

    /// Passkeys du site `rp_id` ; `allowed` (non vide) : seulement celles-là.
    pub fn autofill_passkeys(
        &self,
        rp_id: String,
        allowed: Vec<Vec<u8>>,
    ) -> Result<Vec<AutofillPasskey>, VerrouError> {
        let rp_id = passkey::system_rp_id(&rp_id).map_err(|e| VerrouError::Invalid {
            message: e.to_string(),
        })?;
        self.with_vault(|v| {
            Ok(v.passkeys_for(&rp_id)
                .into_iter()
                .filter_map(|p| {
                    let id = p.raw_id()?;
                    if !allowed.is_empty() && !allowed.contains(&id) {
                        return None;
                    }
                    let item = v.get(&p.item)?;
                    Some(AutofillPasskey {
                        item_id: item.id.clone(),
                        title: item.title.clone(),
                        credential_id: id,
                        rp_id: p.rp_id.clone(),
                        user_name: passkey_user(p, item),
                        user_handle: p
                            .user_handle
                            .as_deref()
                            .and_then(passkey::b64url_decode)
                            .unwrap_or_default(),
                        reprompt: item.reprompt,
                    })
                })
                .collect())
        })
    }

    /// Identifiants du site qui peuvent recevoir une nouvelle passkey.
    pub fn autofill_passkey_targets(&self, rp_id: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.suggestions_for(&site_uri(&rp_id))
                .into_iter()
                .filter(|i| i.kind == ItemKind::Login && i.is_writable())
                .map(summary)
                .collect())
        })
    }

    /// Signe pour le système : `authenticatorData ‖ clientDataHash` avec la
    /// passkey `credential_id` du site `rp_id`. Le nouveau compteur est
    /// enregistré sur le serveur **avant** de rendre la signature (comme
    /// dans le navigateur) ; hors ligne, la passkey ne signe pas.
    pub async fn passkey_assertion(
        &self,
        rp_id: String,
        credential_id: Vec<u8>,
        client_data_hash: Vec<u8>,
        user_verified: bool,
    ) -> Result<PasskeyAssertionResult, VerrouError> {
        let rp_id = passkey::system_rp_id(&rp_id).map_err(|e| VerrouError::Invalid {
            message: e.to_string(),
        })?;
        let (write, result) = self.with_vault(|v| {
            let (item, key) = Self::find_passkey(v, &rp_id, &credential_id)?;
            self.require_authorized(item)?;
            let assertion =
                passkey::assert_for_system(key, &rp_id, &client_data_hash, user_verified).map_err(
                    |e| VerrouError::Invalid {
                        message: e.to_string(),
                    },
                )?;
            Ok((
                Write::PasskeyCounter {
                    item: item.id.clone(),
                    credential_id: key.credential_id.clone(),
                    counter: assertion.counter,
                },
                PasskeyAssertionResult {
                    item_id: item.id.clone(),
                    credential_id: assertion.credential_id,
                    authenticator_data: assertion.authenticator_data,
                    signature: assertion.signature,
                    user_handle: assertion.user_handle.unwrap_or_default(),
                },
            ))
        })?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        self.perform_write(&connection, write).await?;
        Ok(result)
    }

    /// Crée une passkey pour le système (attestation `none`) et l'enregistre
    /// dans le coffre, sur le serveur, avant de répondre.
    pub async fn passkey_registration(
        &self,
        request: PasskeyCreationRequest,
    ) -> Result<PasskeyRegistrationResult, VerrouError> {
        let rp_id = passkey::system_rp_id(&request.rp_id).map_err(|e| VerrouError::Invalid {
            message: e.to_string(),
        })?;
        let user_name = clip(&request.user_name);
        let (write, registration) = self.with_vault(|v| {
            if v.passkeys_for(&rp_id).iter().any(|p| {
                p.raw_id()
                    .is_some_and(|id| request.excluded_credentials.contains(&id))
            }) {
                return Err(VerrouError::Invalid {
                    message: "une passkey de ce compte est déjà enregistrée pour ce site"
                        .to_owned(),
                });
            }
            if let Some(id) = &request.item_id {
                let item = Self::item(v, id)?;
                if item.kind != ItemKind::Login || !item.is_writable() {
                    return Err(VerrouError::ReadOnly);
                }
                self.require_authorized(item)?;
            }
            let (passkey, registration) = passkey::register_for_system(
                &SystemRegistrationRequest {
                    rp_id: &rp_id,
                    rp_name: None,
                    user_id: &request.user_handle,
                    user_name: user_name.as_deref(),
                    user_display_name: None,
                    client_data_hash: &request.client_data_hash,
                    user_verified: request.user_verified,
                },
                request.item_id.as_deref().unwrap_or_default(),
                chrono::Utc::now().timestamp(),
                &mut rand::rngs::OsRng,
            )
            .map_err(|e| VerrouError::Invalid {
                message: e.to_string(),
            })?;
            Ok((
                Write::Passkey {
                    item: request.item_id.clone(),
                    title: rp_id.clone(),
                    uri: site_uri(&rp_id),
                    username: user_name.clone(),
                    passkey: Box::new(passkey),
                },
                registration,
            ))
        })?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let item_id = self.perform_write(&connection, write).await?;
        Ok(PasskeyRegistrationResult {
            item_id,
            credential_id: registration.credential_id,
            attestation_object: registration.attestation_object,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verrou_core::{Field, SecretString};

    fn login(id: &str, urls: &[&str], user: &str, password: &str, totp: bool) -> Item {
        let mut fields = vec![
            Field::new("username", "Identifiant", FieldKind::Username, user),
            Field::new("password", "Mot de passe", FieldKind::Password, password),
        ];
        if totp {
            fields.push(Field::new(
                "totp",
                "Code",
                FieldKind::Totp,
                "JBSWY3DPEHPK3PXP",
            ));
        }
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: format!("Titre {id}"),
            subtitle: user.to_owned(),
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields,
            notes: None,
            reprompt: false,
            state: verrou_core::ItemState::Active,
            shared: None,
        }
    }

    #[test]
    fn identities_carry_sites_and_users_never_secrets() {
        let (key, _) = passkey::register_for_system(
            &SystemRegistrationRequest {
                rp_id: "github.com",
                rp_name: None,
                user_id: b"u-1",
                user_name: Some("camille"),
                user_display_name: None,
                client_data_hash: &[0; 32],
                user_verified: true,
            },
            "b",
            0,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let mut trashed = login("c", &["https://trash.example"], "x", "y", false);
        trashed.state = verrou_core::ItemState::Trashed;
        let vault = Vault::new(vec![
            login(
                "a",
                &[
                    "https://www.exemple.fr/login",
                    "exemple.fr",
                    "iosapp://app.x",
                ],
                "camille@exemple.fr",
                "s3cret-mot-de-passe",
                true,
            ),
            login("b", &["https://github.com"], "", "pw", false),
            trashed,
        ])
        .with_passkeys(vec![key]);
        let all = identities(&vault);
        let summary: Vec<_> = all
            .iter()
            .map(|i| {
                (
                    i.kind,
                    i.item_id.as_str(),
                    i.service.as_str(),
                    i.user.as_str(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    AutofillIdentityKind::Password,
                    "a",
                    "exemple.fr",
                    "camille@exemple.fr"
                ),
                (
                    AutofillIdentityKind::OneTimeCode,
                    "a",
                    "exemple.fr",
                    "camille@exemple.fr"
                ),
                (AutofillIdentityKind::Password, "b", "github.com", "Titre b"),
                (AutofillIdentityKind::Passkey, "b", "github.com", "camille"),
            ]
        );
        let passkey = &all[3];
        assert_eq!(passkey.credential_id.len(), 16);
        assert_eq!(passkey.user_handle, b"u-1");
        let dump = format!("{all:?}");
        assert!(!dump.contains("s3cret") && !dump.contains("JBSWY3DP"));
    }

    #[test]
    fn services_become_pages() {
        assert_eq!(page_of("exemple.fr"), "https://exemple.fr");
        assert_eq!(
            page_of("http://localhost:8123/x"),
            "http://localhost:8123/x"
        );
        assert_eq!(site_uri("localhost"), "http://localhost");
        assert_eq!(site_uri("github.com"), "https://github.com");
        assert_eq!(clip("  "), None);
        assert_eq!(clip(&"é".repeat(300)).unwrap().chars().count(), MAX_TEXT);
        let _ = SecretString::new("");
    }
}
