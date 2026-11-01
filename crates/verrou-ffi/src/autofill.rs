//! iOS `AutoFill` (`VerrouAutoFill` extension).
//!
//! The extension opens the shared folder's vault as a **guest**
//! (`VaultSession::for_autofill`): it reads the app's cache and queue,
//! writes directly to the server what can't wait (created passkey, a
//! passkey's counter), then saves the resynced cache; it never sends
//! nor writes the app's queue (see `verrou_vaultwarden::Store::guest`).
//!
//! This module also gives the app what it publishes to the system's
//! identity store (`ASCredentialIdentityStore`): sites, usernames and
//! passkey identifiers, **never a secret**.

use std::collections::HashSet;
use std::sync::Arc;

use verrou_bridge::access::{Write, check_save, plan_save};
use verrou_bridge::protocol::SaveAction;
use verrou_core::matching::host_of;
use verrou_core::passkey::{self, Passkey, SystemRegistrationRequest};
use verrou_core::{FieldKind, Item, ItemKind, Vault};
use verrou_vaultwarden::Store;

use crate::{ItemSummary, VaultSession, VerrouError};

/// Maximum length of texts coming from the site (name, user).
const MAX_TEXT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AutofillIdentityKind {
    Password,
    /// One-time code (iOS 18): the item has a TOTP seed.
    OneTimeCode,
    Passkey,
}

/// A suggestion for the `QuickType` bar: where and for whom, without secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AutofillIdentity {
    pub kind: AutofillIdentityKind,
    /// The vault item (`recordIdentifier`).
    pub item_id: String,
    /// Site domain (password, code), or `rpId` (passkey).
    pub service: String,
    /// Username shown (or the item's title if it has none).
    pub user: String,
    /// Passkey: raw credential identifier.
    pub credential_id: Vec<u8>,
    /// Passkey: the user's identifier at the site (empty otherwise).
    pub user_handle: Vec<u8>,
}

/// Username and password of an item, for `ASPasswordCredential`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AutofillPassword {
    pub username: String,
    pub password: String,
}

/// A passkey offered for a site, without private key.
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

/// Signed assertion for `ASPasskeyAssertionCredential`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyAssertionResult {
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// New passkey, for `ASPasskeyRegistrationCredential`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyRegistrationResult {
    /// The login that holds it (new or existing).
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AutofillSaveAction {
    Known,
    New,
    Update,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AutofillSaveCheck {
    pub action: AutofillSaveAction,
    pub item_id: Option<String>,
    pub title: Option<String>,
}

/// What the system asks to create (`ASPasskeyCredentialRequest`).
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyCreationRequest {
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    /// Face ID or master password asked for this creation.
    pub user_verified: bool,
    /// Existing login that will receive the passkey; `None`: a new one.
    pub item_id: Option<String>,
    /// Passkeys the site excludes (already registered with it).
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

/// An item's sites (hosts without `www.`, no duplicates), in order.
fn hosts(item: &Item) -> Vec<String> {
    let mut seen = HashSet::new();
    item.urls
        .iter()
        .filter_map(|u| host_of(u))
        .filter(|h| seen.insert(h.clone()))
        .collect()
}

/// Identities of the whole vault: active logins with a site, codes of
/// the items that have a TOTP seed, passkeys. Protected items are
/// included (only the username is shown; the secret will wait for the
/// confirmation).
pub(crate) fn identities(vault: &Vault) -> Vec<AutofillIdentity> {
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

/// Page from a system service identifier: a bare domain
/// (`exemple.fr`) or a URL.
fn page_of(service: &str) -> String {
    let service = service.trim();
    if service.contains("://") {
        service.to_owned()
    } else {
        format!("https://{service}")
    }
}

/// Address saved in a new login created for a passkey.
pub(crate) fn site_uri(rp_id: &str) -> String {
    if rp_id == "localhost" {
        "http://localhost".to_owned()
    } else {
        format!("https://{rp_id}")
    }
}

impl VaultSession {
    pub(crate) fn find_passkey<'v>(
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
    /// Session of the `AutoFill` extension: same folder as the app, opened
    /// as a guest (never sends nor writes the queue).
    #[uniffi::constructor]
    pub fn for_autofill(data_dir: String) -> Arc<Self> {
        Self::with_store(Store::new(data_dir).guest())
    }

    /// What the app publishes for the system's suggestions (`QuickType`):
    /// sites, usernames, passkeys. No secret.
    /// The sites' signals (rejected passkeys, unneeded passwords,
    /// changed names) correct the list: see `signals`.
    pub fn autofill_identities(&self) -> Result<Vec<AutofillIdentity>, VerrouError> {
        self.with_vault(|v| {
            let mut list = identities(v);
            if let Ok(store) = self.store() {
                crate::signals::apply_to_identities(v, store.dir(), &mut list);
            }
            Ok(list)
        })
    }

    /// Logins matching the services asked by the system (domains or
    /// URLs), from most to least precise, no duplicates.
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

    /// ⚠️ Username and password of a login, to fill it: only after the
    /// user's choice (or a system suggestion they tapped). A protected
    /// item must have been confirmed (`authorize_item`). As on the Mac,
    /// an organization's "hide passwords" doesn't prevent filling.
    pub fn autofill_password(&self, id: String) -> Result<AutofillPassword, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if item.kind != ItemKind::Login {
                return Err(VerrouError::Invalid {
                    message: "only a login can be filled".to_owned(),
                });
            }
            self.require_authorized(item)?;
            self.record_use(&item.id);
            Ok(AutofillPassword {
                username: username_of(item),
                password: item
                    .field_of_kind(FieldKind::Password)
                    .map(|f| f.value.expose().to_owned())
                    .unwrap_or_default(),
            })
        })
    }

    /// Passkeys of site `rp_id`; `allowed` (non-empty): only those.
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

    /// The site's logins that can receive a new passkey.
    pub fn autofill_passkey_targets(&self, rp_id: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.suggestions_for(&site_uri(&rp_id))
                .into_iter()
                .filter(|i| i.kind == ItemKind::Login && i.is_writable())
                .map(|i| self.summary_in(v, i))
                .collect())
        })
    }

    pub fn autofill_save_check(
        &self,
        service: String,
        username: String,
        password: String,
    ) -> Result<AutofillSaveCheck, VerrouError> {
        self.with_vault(|v| {
            let (action, found) = check_save(v, &page_of(&service), &username, &password, None)
                .map_err(|message| VerrouError::Invalid { message })?;
            Ok(AutofillSaveCheck {
                action: match action {
                    SaveAction::Known => AutofillSaveAction::Known,
                    SaveAction::New => AutofillSaveAction::New,
                    SaveAction::Update => AutofillSaveAction::Update,
                },
                item_id: found.as_ref().map(|s| s.id.clone()),
                title: found.map(|s| s.title),
            })
        })
    }

    pub async fn autofill_save(
        &self,
        service: String,
        username: String,
        password: String,
        item_id: Option<String>,
    ) -> Result<String, VerrouError> {
        let write = self.with_vault(|v| {
            if let Some(id) = &item_id {
                self.require_authorized(Self::item(v, id)?)?;
            }
            plan_save(
                v,
                &page_of(&service),
                &username,
                &password,
                item_id.as_deref(),
            )
            .map_err(|message| VerrouError::Invalid { message })
        })?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let id = self.perform_write(&connection, write).await?;
        self.record_use(&id);
        Ok(id)
    }

    /// Signs for the system: `authenticatorData ‖ clientDataHash` with
    /// passkey `credential_id` of site `rp_id`. The new counter is saved
    /// on the server **before** returning the signature (as in the
    /// browser); offline, the passkey doesn't sign.
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
        self.record_use(&result.item_id);
        Ok(result)
    }

    /// Creates a passkey for the system (`none` attestation) and saves it
    /// in the vault, on the server, before answering.
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
                    message: "a passkey of this account is already registered for this site"
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
            url_matches: Vec::new(),
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
    fn passkey_targets_say_which_login_already_holds_one() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
        let targets = session
            .autofill_passkey_targets("github.com".to_owned())
            .unwrap();
        let github = targets.iter().find(|t| t.title == "GitHub").unwrap();
        assert_eq!(github.passkey_rp_id.as_deref(), Some("github.com"));
        assert_eq!(github.passkey_user_name.as_deref(), Some("emily-dev"));
        let amazon = session
            .autofill_passkey_targets("amazon.com".to_owned())
            .unwrap();
        assert!(!amazon.is_empty());
        assert!(amazon.iter().all(|t| t.passkey_rp_id.is_none()));
    }

    #[test]
    fn a_login_to_save_is_new_an_update_or_known() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
        let github = session
            .autofill_passkey_targets("github.com".to_owned())
            .unwrap()
            .into_iter()
            .find(|t| t.title == "GitHub")
            .unwrap();
        let current = session.autofill_password(github.id.clone()).unwrap();
        let check = |user: &str, password: &str| {
            session
                .autofill_save_check(
                    "github.com".to_owned(),
                    user.to_owned(),
                    password.to_owned(),
                )
                .unwrap()
        };
        let known = check(&current.username, &current.password);
        assert_eq!(known.action, AutofillSaveAction::Known);
        assert_eq!(known.item_id.as_deref(), Some(github.id.as_str()));
        let update = check(&current.username.to_uppercase(), "another-password");
        assert_eq!(update.action, AutofillSaveAction::Update);
        assert_eq!(update.title.as_deref(), Some("GitHub"));
        let new = check("someone-else@example.com", "another-password");
        assert_eq!(new.action, AutofillSaveAction::New);
        assert_eq!(new.item_id, None);
        assert!(
            session
                .autofill_save_check(
                    "http://github.com".to_owned(),
                    "x".to_owned(),
                    "y".to_owned()
                )
                .is_err()
        );
        assert!(
            session
                .autofill_save_check("github.com".to_owned(), "x".to_owned(), String::new())
                .is_err()
        );
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
