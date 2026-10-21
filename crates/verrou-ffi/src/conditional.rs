//! Conditional passkey creation (iOS 18, `mediation: "conditional"`).
//!
//! After a password filled by Verrou, Safari can request in the
//! background a passkey for the same account, without UI
//! (`performWithoutUserInteractionIfPossible(passkeyRegistration:)`). The
//! extension's vault is then closed: a new process, with no Face
//! ID possible. Hence three steps:
//!
//! 1. **Fill** (vault open, Face ID passed): `prepare_passkey_upgrade`
//!    prepares a key for the filled login if it has no passkey. The
//!    "ticket" (`passkey-upgrade.json`, account folder) keeps the public
//!    key, the credential id, the registrable domains
//!    and the item's user name, and the private key **sealed** by
//!    the account's local key (readable only with the vault open). Valid for
//!    5 minutes, once.
//! 2. **Background request** (vault closed): `conditional_passkey_registration`
//!    consumes the ticket if the site and the user name match, and
//!    returns the attestation (`none`, without presence or verification). The passkey
//!    waits in `passkeys-pending.json`, key still sealed.
//! 3. **Next vault unlock** in the app: `finish_pending_passkeys`
//!    unseals each key and saves the passkey in the login, on the
//!    server. The password stays: nothing is ever deleted.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use verrou_bridge::access::Write;
use verrou_core::matching::registrable_domain;
use verrou_core::passkey::{self, ConditionalPasskey};
use verrou_core::{FieldKind, ItemKind};

use crate::autofill::{PasskeyCreationRequest, PasskeyRegistrationResult};
use crate::{VaultSession, VerrouError};
use verrou_vaultwarden::Store;

const TICKET_FILE: &str = "passkey-upgrade.json";
const PENDING_FILE: &str = "passkeys-pending.json";
/// Validity of a ticket: Safari requests the passkey right after
/// the form is submitted.
const TICKET_SECONDS: i64 = 5 * 60;
/// Safeguard: maximum number of pending passkeys kept.
const MAX_PENDING: usize = 20;

/// Key prepared while filling a password.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Ticket {
    item_id: String,
    /// Registrable domains of the item's sites.
    domains: Vec<String>,
    /// User name of the item, lowercased.
    user: String,
    created: i64,
    /// base64url.
    credential_id: String,
    /// SEC1 public key, base64url.
    public_key: String,
    /// PKCS#8 private key (base64url), sealed by the account's local key.
    sealed_key: String,
}

/// Passkey registered with the site, not yet in the vault.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pending {
    item_id: String,
    rp_id: String,
    /// base64url.
    user_handle: String,
    user_name: Option<String>,
    /// base64url.
    credential_id: String,
    sealed_key: String,
    created: i64,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn invalid(message: &str) -> VerrouError {
    VerrouError::Invalid {
        message: message.to_owned(),
    }
}

fn storage(error: impl std::fmt::Display) -> VerrouError {
    VerrouError::Storage {
        message: error.to_string(),
    }
}

fn read<T: for<'de> Deserialize<'de>>(dir: &Path, file: &str) -> Option<T> {
    serde_json::from_slice(&fs::read(dir.join(file)).ok()?).ok()
}

/// Reads, transforms and rewrites a file of the folder under its lock
/// (`Store::update_file`): the app and its extension share it.
fn update<T: Serialize + for<'de> Deserialize<'de>, R>(
    dir: &Path,
    file: &str,
    change: impl FnOnce(Option<T>) -> (Option<T>, R),
) -> Result<R, VerrouError> {
    let mut failure = None;
    let result = Store::new(dir).update_file(file, |data| {
        let current = data.and_then(|d| serde_json::from_slice(&d).ok());
        let (next, result) = change(current);
        let bytes = next.and_then(|v| match serde_json::to_vec(&v) {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                failure = Some(storage(error));
                None
            }
        });
        (bytes, result)
    })?;
    failure.map_or(Ok(result), Err)
}

fn write<T: Serialize + for<'de> Deserialize<'de>>(
    dir: &Path,
    file: &str,
    value: T,
) -> Result<(), VerrouError> {
    update(dir, file, |_: Option<T>| (Some(value), ()))
}

fn remove(dir: &Path, file: &str) {
    let _ = Store::new(dir).update_file(file, |_| (None, ()));
}

/// The ticket, removed from disk (single use, valid or not).
fn take_ticket(dir: &Path) -> Option<Ticket> {
    update(dir, TICKET_FILE, |ticket: Option<Ticket>| (None, ticket))
        .ok()
        .flatten()
}

fn pending(dir: &Path) -> Vec<Pending> {
    read(dir, PENDING_FILE).unwrap_or_default()
}

/// Adds a pending passkey (the oldest go beyond
/// `MAX_PENDING`).
fn push_pending(dir: &Path, entry: Pending) -> Result<(), VerrouError> {
    update(dir, PENDING_FILE, |list: Option<Vec<Pending>>| {
        let mut list = list.unwrap_or_default();
        list.push(entry);
        let overflow = list.len().saturating_sub(MAX_PENDING);
        list.drain(..overflow);
        (Some(list), ())
    })
}

/// Removes the processed passkeys; those added in the meantime stay.
fn forget_pending(dir: &Path, done: &[String]) -> Result<(), VerrouError> {
    update(dir, PENDING_FILE, |list: Option<Vec<Pending>>| {
        let list: Vec<Pending> = list
            .unwrap_or_default()
            .into_iter()
            .filter(|p| !done.contains(&p.credential_id))
            .collect();
        ((!list.is_empty()).then_some(list), ())
    })
}

/// Does the site's request fit the ticket: recent, same site (registrable
/// domain), same user name?
fn check_ticket(ticket: &Ticket, rp_id: &str, user_name: &str, at: i64) -> Result<(), VerrouError> {
    if at < ticket.created || at - ticket.created > TICKET_SECONDS {
        return Err(invalid("no password filled recently"));
    }
    let site = registrable_domain(rp_id).ok_or_else(|| invalid("invalid site"))?;
    if !ticket.domains.contains(&site) {
        return Err(invalid("this site is not the one of the filled password"));
    }
    if ticket.user.is_empty() || user_name.trim().to_lowercase() != ticket.user {
        return Err(invalid(
            "this account is not the one of the filled password",
        ));
    }
    Ok(())
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Extension, right after filling the password of `id` (vault
    /// open): prepares the key of a possible conditional creation.
    /// Nothing if the item already has a passkey, has no site or no user
    /// name (the previous ticket is then erased). Returns `true` if
    /// a ticket is ready.
    pub async fn prepare_passkey_upgrade(&self, id: String) -> Result<bool, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        remove(&dir, TICKET_FILE);
        let target = self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if item.kind != ItemKind::Login
                || !item.is_active()
                || !item.is_writable()
                || !v.passkeys_of(&item.id).is_empty()
            {
                return Ok(None);
            }
            let mut domains: Vec<String> = item
                .urls
                .iter()
                .filter_map(|u| registrable_domain(u))
                .collect();
            domains.sort();
            domains.dedup();
            let user = item
                .field_of_kind(FieldKind::Username)
                .or_else(|| item.field_of_kind(FieldKind::Email))
                .map(|f| f.value.expose().trim().to_lowercase())
                .unwrap_or_default();
            Ok((!domains.is_empty() && !user.is_empty()).then_some((domains, user)))
        })?;
        let Some((domains, user)) = target else {
            return Ok(false);
        };
        let prepared = passkey::prepare_credential(&mut rand::rngs::OsRng).map_err(|e| {
            VerrouError::Invalid {
                message: e.to_string(),
            }
        })?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let sealed_key = connection
            .lock()
            .await
            .seal_local(prepared.private_key.expose().to_owned())?;
        write(
            &dir,
            TICKET_FILE,
            Ticket {
                item_id: id,
                domains,
                user,
                created: now(),
                credential_id: passkey::b64url(&prepared.credential_id),
                public_key: passkey::b64url(&prepared.public_key),
                sealed_key,
            },
        )?;
        Ok(true)
    }

    /// Extension, Safari background request (vault closed): creates the
    /// passkey with the key prepared at fill time, if the request comes from the
    /// same site and the same account within 5 minutes. The passkey waits for the
    /// next vault unlock (`finish_pending_passkeys`). Any
    /// other situation is refused, without UI.
    pub fn conditional_passkey_registration(
        &self,
        request: PasskeyCreationRequest,
    ) -> Result<PasskeyRegistrationResult, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        let ticket = take_ticket(&dir).ok_or_else(|| invalid("no password filled recently"))?;
        let rp_id = passkey::system_rp_id(&request.rp_id).map_err(|e| VerrouError::Invalid {
            message: e.to_string(),
        })?;
        check_ticket(&ticket, &rp_id, &request.user_name, now())?;
        if request.user_handle.is_empty() || request.user_handle.len() > 64 {
            return Err(invalid("invalid user id"));
        }
        let credential_id = passkey::b64url_decode(&ticket.credential_id)
            .ok_or_else(|| invalid("unreadable ticket"))?;
        let public_key = passkey::b64url_decode(&ticket.public_key)
            .ok_or_else(|| invalid("unreadable ticket"))?;
        let registration = passkey::conditional_registration(
            &rp_id,
            &credential_id,
            &public_key,
            &request.client_data_hash,
        )
        .map_err(|e| VerrouError::Invalid {
            message: e.to_string(),
        })?;
        push_pending(
            &dir,
            Pending {
                item_id: ticket.item_id.clone(),
                rp_id,
                user_handle: passkey::b64url(&request.user_handle),
                user_name: Some(request.user_name.trim().chars().take(256).collect())
                    .filter(|n: &String| !n.is_empty()),
                credential_id: ticket.credential_id,
                sealed_key: ticket.sealed_key,
                created: now(),
            },
        )?;
        Ok(PasskeyRegistrationResult {
            item_id: ticket.item_id,
            credential_id: registration.credential_id,
            attestation_object: registration.attestation_object,
        })
    }

    /// Passkeys created in the background waiting to enter the vault.
    pub fn pending_passkeys(&self) -> u32 {
        self.store().map_or(0, |s| pending(s.dir()).len() as u32)
    }

    /// App, vault open and online: saves in their login the
    /// passkeys created in the background (a new login if the item
    /// is gone). Returns the titles of the items that received one; the
    /// others stay pending (offline) or are dropped (unreadable
    /// key: another account's vault).
    pub async fn finish_pending_passkeys(&self) -> Result<Vec<String>, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        let list = pending(&dir);
        if list.is_empty() {
            return Ok(Vec::new());
        }
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let handled: Vec<String> = list.iter().map(|p| p.credential_id.clone()).collect();
        let mut done = Vec::new();
        let mut left = Vec::new();
        let mut failure = None;
        for entry in list {
            if failure.is_some() {
                left.push(entry);
                continue;
            }
            let Ok(key) = connection.lock().await.open_local(entry.sealed_key.clone()) else {
                continue; // sealed by another account: dropped
            };
            let (Some(credential_id), Some(user_id)) = (
                passkey::b64url_decode(&entry.credential_id),
                passkey::b64url_decode(&entry.user_handle),
            ) else {
                continue;
            };
            let built = self.with_vault(|v| {
                let target = v
                    .get(&entry.item_id)
                    .filter(|i| i.kind == ItemKind::Login && i.is_active() && i.is_writable());
                // Already there (a first attempt succeeded): nothing to redo.
                if v.passkeys()
                    .iter()
                    .any(|p| p.raw_id().as_deref() == Some(&credential_id))
                {
                    return Ok(None);
                }
                let item_id = target.map(|i| i.id.clone());
                let key = passkey::conditional_passkey(&ConditionalPasskey {
                    item: item_id.as_deref().unwrap_or_default(),
                    rp_id: &entry.rp_id,
                    user_id: &user_id,
                    user_name: entry.user_name.as_deref(),
                    credential_id: &credential_id,
                    private_key: key.expose(),
                    created: entry.created,
                })
                .map_err(|e| VerrouError::Invalid {
                    message: e.to_string(),
                })?;
                let title = target.map_or_else(|| entry.rp_id.clone(), |i| i.title.clone());
                Ok(Some((
                    title,
                    Write::Passkey {
                        item: item_id,
                        title: entry.rp_id.clone(),
                        uri: crate::autofill::site_uri(&entry.rp_id),
                        username: entry.user_name.clone(),
                        passkey: Box::new(key),
                    },
                )))
            });
            match built {
                // Already in the vault, or invalid key: dropped.
                Ok(None) | Err(VerrouError::Invalid { .. }) => {}
                Ok(Some((title, write))) => match self.perform_write(&connection, write).await {
                    Ok(_) => done.push(title),
                    Err(error) => {
                        left.push(entry);
                        failure = Some(error);
                    }
                },
                Err(error) => {
                    left.push(entry);
                    failure = Some(error);
                }
            }
        }
        let kept: Vec<&String> = left.iter().map(|p| &p.credential_id).collect();
        let processed: Vec<String> = handled
            .into_iter()
            .filter(|id| !kept.contains(&id))
            .collect();
        forget_pending(&dir, &processed)?;
        match failure {
            Some(error) if done.is_empty() => Err(error),
            _ => Ok(done),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(created: i64) -> Ticket {
        Ticket {
            item_id: "github".to_owned(),
            domains: vec!["github.com".to_owned()],
            user: "camille".to_owned(),
            created,
            credential_id: String::new(),
            public_key: String::new(),
            sealed_key: String::new(),
        }
    }

    #[test]
    fn a_ticket_matches_the_same_site_and_account_for_five_minutes() {
        let t = ticket(1_000);
        assert!(check_ticket(&t, "github.com", "camille", 1_000).is_ok());
        assert!(check_ticket(&t, "login.github.com", " Camille ", 1_299).is_ok());
        assert!(
            check_ticket(&t, "github.com", "camille", 1_301).is_err(),
            "expired"
        );
        assert!(
            check_ticket(&t, "github.com", "camille", 999).is_err(),
            "clock"
        );
        assert!(
            check_ticket(&t, "github.io", "camille", 1_000).is_err(),
            "other site"
        );
        assert!(check_ticket(&t, "evil.com", "camille", 1_000).is_err());
        assert!(
            check_ticket(&t, "github.com", "dominique", 1_000).is_err(),
            "other account"
        );
        let mut anonymous = ticket(1_000);
        anonymous.user = String::new();
        assert!(check_ticket(&anonymous, "github.com", "", 1_000).is_err());
    }

    #[test]
    fn the_background_request_consumes_the_ticket_once() {
        let dir = std::env::temp_dir().join(format!("verrou-conditional-{}", uuid::Uuid::new_v4()));
        let session = VaultSession::with_store(verrou_vaultwarden::Store::new(
            dir.to_string_lossy().into_owned(),
        ));
        let prepared = passkey::prepare_credential(&mut rand::rngs::OsRng).unwrap();
        let mut t = ticket(now());
        t.credential_id = passkey::b64url(&prepared.credential_id);
        t.public_key = passkey::b64url(&prepared.public_key);
        t.sealed_key = "sealed".to_owned();
        write(&dir, TICKET_FILE, t.clone()).unwrap();
        let request = |user: &str| PasskeyCreationRequest {
            rp_id: "github.com".to_owned(),
            user_name: user.to_owned(),
            user_handle: b"u-42".to_vec(),
            client_data_hash: vec![3; 32],
            user_verified: false,
            item_id: None,
            excluded_credentials: Vec::new(),
        };
        let result = session
            .conditional_passkey_registration(request("camille"))
            .unwrap();
        assert_eq!(result.item_id, "github");
        assert_eq!(result.credential_id, prepared.credential_id);
        assert_eq!(session.pending_passkeys(), 1);
        let waiting = pending(&dir);
        assert_eq!(waiting[0].rp_id, "github.com");
        assert_eq!(waiting[0].user_name.as_deref(), Some("camille"));
        assert_eq!(waiting[0].sealed_key, "sealed");
        // Only once.
        assert!(
            session
                .conditional_passkey_registration(request("camille"))
                .is_err()
        );
        // A ticket for another account is consumed without creating anything.
        write(&dir, TICKET_FILE, t.clone()).unwrap();
        assert!(
            session
                .conditional_passkey_registration(request("dominique"))
                .is_err()
        );
        assert!(!dir.join(TICKET_FILE).exists());
        assert_eq!(session.pending_passkeys(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
