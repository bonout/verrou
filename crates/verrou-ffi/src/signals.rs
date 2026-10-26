//! Site signals (Signal API, iOS 26): a site tells the autofill
//! provider that a passkey no longer exists on its side, which passkeys of an
//! account it still accepts, that a user name changed, or that a
//! password is no longer used (the account moved to the passkey).
//!
//! The system passes them to the extension in the background, vault closed:
//! it records them (`credential-signals.json`, account folder; sites,
//! credential ids and user names, **never a
//! secret**). Then:
//! - the system suggestions (`QuickType`) hide the rejected passkeys
//!   and the unused passwords, and take the new name;
//! - the iPhone audit shows them, so the user decides. Nothing
//!   is deleted from the vault automatically.
//!
//! A signal that no longer matches anything (passkey deleted, password
//! removed) goes away by itself.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use verrou_core::matching::{SiteMatch, site_match};
use verrou_core::passkey::{self, Passkey};
use verrou_core::{FieldKind, Item, ItemKind, Vault};

use crate::autofill::{AutofillIdentity, AutofillIdentityKind};
use crate::{ItemSummary, VaultSession, VerrouError};
use verrou_vaultwarden::Store;

const FILE: &str = "credential-signals.json";
/// Safeguards: maximum number of signals kept, and length of received texts.
const MAX_SIGNALS: usize = 200;
const MAX_TEXT: usize = 256;
/// An older signal is forgotten.
const MAX_AGE: i64 = 180 * 24 * 60 * 60;

/// What a site reports (`ASCredentialUpdater`, received by the extension).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum CredentialSignal {
    /// `reportUnknownPublicKeyCredential`: the site doesn't know (anymore)
    /// this passkey.
    UnknownPasskey {
        rp_id: String,
        credential_id: Vec<u8>,
    },
    /// `reportAllAcceptedPublicKeyCredentials`: the only passkeys the
    /// site accepts for this account.
    AcceptedPasskeys {
        rp_id: String,
        user_handle: Vec<u8>,
        accepted: Vec<Vec<u8>>,
    },
    /// `reportPublicKeyCredentialUpdate`: new user name.
    PasskeyRenamed {
        rp_id: String,
        user_handle: Vec<u8>,
        name: String,
    },
    /// `reportUnusedPasswordCredential`: the password of this account is no
    /// longer used.
    UnusedPassword { domain: String, user_name: String },
}

impl CredentialSignal {
    /// Two signals on the same subject: the most recent replaces the other.
    fn subject(&self) -> String {
        match self {
            Self::UnknownPasskey {
                rp_id,
                credential_id,
            } => {
                format!("unknown|{rp_id}|{}", passkey::b64url(credential_id))
            }
            Self::AcceptedPasskeys {
                rp_id, user_handle, ..
            } => format!("accepted|{rp_id}|{}", passkey::b64url(user_handle)),
            Self::PasskeyRenamed {
                rp_id, user_handle, ..
            } => format!("renamed|{rp_id}|{}", passkey::b64url(user_handle)),
            Self::UnusedPassword { domain, user_name } => {
                format!("unused|{domain}|{}", user_name.to_lowercase())
            }
        }
    }

    /// Normalized and bounded: nothing abnormally long coming from the system.
    fn sanitized(self) -> Option<Self> {
        let host = |s: &str| {
            let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
            (!s.is_empty() && s.len() <= MAX_TEXT).then_some(s)
        };
        let bytes = |b: &Vec<u8>| (!b.is_empty() && b.len() <= 1024).then_some(());
        Some(match self {
            Self::UnknownPasskey {
                rp_id,
                credential_id,
            } => {
                bytes(&credential_id)?;
                Self::UnknownPasskey {
                    rp_id: host(&rp_id)?,
                    credential_id,
                }
            }
            Self::AcceptedPasskeys {
                rp_id,
                user_handle,
                accepted,
            } => {
                bytes(&user_handle)?;
                if accepted.len() > 100 || accepted.iter().any(|a| a.len() > 1024) {
                    return None;
                }
                Self::AcceptedPasskeys {
                    rp_id: host(&rp_id)?,
                    user_handle,
                    accepted,
                }
            }
            Self::PasskeyRenamed {
                rp_id,
                user_handle,
                name,
            } => {
                bytes(&user_handle)?;
                let name = name.trim();
                if name.is_empty() || name.len() > MAX_TEXT {
                    return None;
                }
                Self::PasskeyRenamed {
                    rp_id: host(&rp_id)?,
                    user_handle,
                    name: name.to_owned(),
                }
            }
            Self::UnusedPassword { domain, user_name } => {
                let user_name = user_name.trim();
                if user_name.is_empty() || user_name.len() > MAX_TEXT {
                    return None;
                }
                Self::UnusedPassword {
                    domain: host(&domain)?,
                    user_name: user_name.to_owned(),
                }
            }
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stored {
    signal: CredentialSignal,
    /// Unix timestamp of reception.
    at: i64,
}

/// What the audit shows of a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SignalFindingKind {
    /// The site no longer recognizes this passkey: it can be deleted.
    PasskeyRejected,
    /// The site changed the passkey's user name.
    PasskeyRenamed,
    /// The site no longer uses this password: it can be removed.
    PasswordUnused,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignalFinding {
    pub kind: SignalFindingKind,
    pub item: ItemSummary,
    /// Site concerned (`rpId` or domain).
    pub site: String,
    /// New name (`PasskeyRenamed`).
    pub detail: Option<String>,
    /// Unix timestamp of the signal.
    pub at: i64,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn read(dir: &Path) -> Vec<Stored> {
    fs::read(dir.join(FILE))
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

/// Rewrites the list under the folder's lock (`Store::update_file`):
/// the app and the extension share it.
fn update(dir: &Path, change: impl FnOnce(Vec<Stored>) -> Vec<Stored>) -> Result<(), VerrouError> {
    Store::new(dir).update_file(FILE, |data| {
        let list = data
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        let list = change(list);
        let bytes = (!list.is_empty())
            .then(|| serde_json::to_vec(&list).ok())
            .flatten();
        (bytes, ())
    })?;
    Ok(())
}

#[cfg(test)]
fn save(dir: &Path, list: &[Stored]) -> Result<(), VerrouError> {
    let list = list.to_vec();
    update(dir, |_| list)
}

fn user_of(item: &Item) -> Option<String> {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose().trim().to_lowercase())
        .filter(|u| !u.is_empty())
}

fn active_login<'v>(vault: &'v Vault, id: &str) -> Option<&'v Item> {
    vault
        .get(id)
        .filter(|i| i.kind == ItemKind::Login && i.is_active())
}

fn handle_of(key: &Passkey) -> Vec<u8> {
    key.user_handle
        .as_deref()
        .and_then(passkey::b64url_decode)
        .unwrap_or_default()
}

/// What the signals say about the vault, signal by signal (with the item
/// concerned). A signal without a match yields nothing.
fn findings_of<'v>(
    vault: &'v Vault,
    stored: &Stored,
) -> Vec<(SignalFindingKind, &'v Item, String, Option<String>)> {
    match &stored.signal {
        CredentialSignal::UnknownPasskey {
            rp_id,
            credential_id,
        } => vault
            .passkeys_for(rp_id)
            .into_iter()
            .filter(|p| p.raw_id().as_deref() == Some(credential_id.as_slice()))
            .filter_map(|p| active_login(vault, &p.item))
            .map(|i| (SignalFindingKind::PasskeyRejected, i, rp_id.clone(), None))
            .collect(),
        CredentialSignal::AcceptedPasskeys {
            rp_id,
            user_handle,
            accepted,
        } => vault
            .passkeys_for(rp_id)
            .into_iter()
            .filter(|p| handle_of(p) == *user_handle)
            .filter(|p| p.raw_id().is_some_and(|id| !accepted.contains(&id)))
            .filter_map(|p| active_login(vault, &p.item))
            .map(|i| (SignalFindingKind::PasskeyRejected, i, rp_id.clone(), None))
            .collect(),
        CredentialSignal::PasskeyRenamed {
            rp_id,
            user_handle,
            name,
        } => vault
            .passkeys_for(rp_id)
            .into_iter()
            .filter(|p| handle_of(p) == *user_handle && p.user_name.as_deref() != Some(name))
            .filter_map(|p| active_login(vault, &p.item))
            .map(|i| {
                (
                    SignalFindingKind::PasskeyRenamed,
                    i,
                    rp_id.clone(),
                    Some(name.clone()),
                )
            })
            .collect(),
        CredentialSignal::UnusedPassword { domain, user_name } => {
            let wanted = user_name.trim().to_lowercase();
            vault
                .items()
                .iter()
                .filter(|i| i.kind == ItemKind::Login && i.is_active())
                .filter(|i| verrou_core::audit::password_of(i).is_some())
                .filter(|i| user_of(i).as_deref() == Some(wanted.as_str()))
                .filter(|i| site_match(&i.urls, &format!("https://{domain}")) != SiteMatch::None)
                .map(|i| (SignalFindingKind::PasswordUnused, i, domain.clone(), None))
                .collect()
        }
    }
}

/// The system suggestions, corrected by the signals: without the
/// rejected passkeys or the unused passwords, with the changed names.
pub(crate) fn apply_to_identities(
    vault: &Vault,
    dir: &Path,
    identities: &mut Vec<AutofillIdentity>,
) {
    let stored = read(dir);
    if stored.is_empty() {
        return;
    }
    let mut hidden_passkeys: HashSet<Vec<u8>> = HashSet::new();
    let mut hidden_passwords: HashSet<String> = HashSet::new();
    let mut renamed: Vec<(Vec<u8>, String)> = Vec::new();
    for entry in &stored {
        match &entry.signal {
            CredentialSignal::UnknownPasskey { credential_id, .. } => {
                hidden_passkeys.insert(credential_id.clone());
            }
            CredentialSignal::AcceptedPasskeys {
                rp_id,
                user_handle,
                accepted,
            } => {
                for key in vault.passkeys_for(rp_id) {
                    if handle_of(key) == *user_handle
                        && let Some(id) = key.raw_id()
                        && !accepted.contains(&id)
                    {
                        hidden_passkeys.insert(id);
                    }
                }
            }
            CredentialSignal::PasskeyRenamed {
                rp_id,
                user_handle,
                name,
            } => {
                for key in vault.passkeys_for(rp_id) {
                    if handle_of(key) == *user_handle
                        && let Some(id) = key.raw_id()
                    {
                        renamed.push((id, name.clone()));
                    }
                }
            }
            CredentialSignal::UnusedPassword { .. } => {
                for (_, item, _, _) in findings_of(vault, entry) {
                    hidden_passwords.insert(item.id.clone());
                }
            }
        }
    }
    identities.retain(|identity| match identity.kind {
        AutofillIdentityKind::Passkey => !hidden_passkeys.contains(&identity.credential_id),
        AutofillIdentityKind::Password => !hidden_passwords.contains(&identity.item_id),
        AutofillIdentityKind::OneTimeCode => true,
    });
    for identity in identities.iter_mut() {
        if identity.kind == AutofillIdentityKind::Passkey
            && let Some((_, name)) = renamed.iter().find(|(id, _)| *id == identity.credential_id)
        {
            identity.user.clone_from(name);
        }
    }
}

#[uniffi::export]
impl VaultSession {
    /// Extension, in the background (vault closed): records a site signal.
    /// The most recent one on a subject replaces the old one; the oldest
    /// are forgotten beyond 200.
    pub fn record_credential_signal(&self, signal: CredentialSignal) -> Result<(), VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        let signal = signal.sanitized().ok_or_else(|| VerrouError::Invalid {
            message: "invalid signal".to_owned(),
        })?;
        let subject = signal.subject();
        let at = now();
        update(&dir, |mut list| {
            list.retain(|s| s.signal.subject() != subject && at - s.at < MAX_AGE);
            list.push(Stored { signal, at });
            let overflow = list.len().saturating_sub(MAX_SIGNALS);
            list.drain(..overflow);
            list
        })
    }

    /// iPhone audit: what the sites reported that still concerns
    /// the vault, most recent first. Signals that no longer
    /// match anything are forgotten.
    pub fn credential_signal_findings(&self) -> Result<Vec<SignalFinding>, VerrouError> {
        let Ok(store) = self.store() else {
            return Ok(Vec::new());
        };
        let dir = store.dir().to_path_buf();
        let stored = read(&dir);
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        let (findings, stale) = self.with_vault(|v| {
            let mut findings = Vec::new();
            let mut stale = Vec::new();
            let mut seen = HashSet::new();
            for entry in &stored {
                let found = findings_of(v, entry);
                if found.is_empty() {
                    stale.push((entry.signal.subject(), entry.at));
                    continue;
                }
                for (kind, item, site, detail) in found {
                    if seen.insert((kind as u8, item.id.clone())) {
                        findings.push(SignalFinding {
                            kind,
                            item: self.summary(item),
                            site,
                            detail,
                            at: entry.at,
                        });
                    }
                }
            }
            Ok((findings, stale))
        })?;
        if !stale.is_empty() {
            // Only the signals read here and now pointless: a signal that arrived
            // in the meantime stays.
            let _ = update(&dir, |list| {
                list.into_iter()
                    .filter(|s| !stale.contains(&(s.signal.subject(), s.at)))
                    .collect()
            });
        }
        let mut findings = findings;
        findings.sort_by_key(|f| std::cmp::Reverse(f.at));
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verrou_core::{Field, ItemState, SecretString};

    fn login(id: &str, url: &str, user: &str) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: String::new(),
            urls: vec![url.to_owned()],
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![
                Field::new("username", "Identifiant", FieldKind::Username, user),
                Field::new("password", "Mot de passe", FieldKind::Password, "x"),
            ],
            notes: None,
            reprompt: false,
            state: ItemState::Active,
            shared: None,
        }
    }

    fn key(item: &str, rp_id: &str, id: u8, handle: &[u8], user: &str) -> Passkey {
        Passkey {
            item: item.to_owned(),
            credential_id: passkey::credential_id_string(&[id; 16]),
            rp_id: rp_id.to_owned(),
            rp_name: None,
            user_handle: Some(passkey::b64url(handle)),
            user_name: Some(user.to_owned()),
            user_display_name: None,
            counter: 0,
            discoverable: true,
            created: 0,
            key: SecretString::new("clé"),
        }
    }

    fn vault() -> Vault {
        Vault::new(vec![
            login("GitHub", "https://github.com", "camille"),
            login("GitHub pro", "https://github.com", "camille-pro"),
            login("Exemple", "https://exemple.fr", "camille"),
        ])
        .with_passkeys(vec![
            key("GitHub", "github.com", 1, b"u1", "camille"),
            key("GitHub", "github.com", 2, b"u1", "camille"),
            key("GitHub pro", "github.com", 3, b"u2", "camille-pro"),
        ])
    }

    fn temp_session() -> (std::path::PathBuf, std::sync::Arc<VaultSession>) {
        let dir = std::env::temp_dir().join(format!("verrou-signals-{}", uuid::Uuid::new_v4()));
        let session = VaultSession::with_store(
            verrou_vaultwarden::Store::new(dir.to_string_lossy().into_owned()),
            None,
        );
        (dir, session)
    }

    #[test]
    fn signals_are_recorded_deduplicated_and_bounded() {
        let (dir, session) = temp_session();
        let renamed = |name: &str| CredentialSignal::PasskeyRenamed {
            rp_id: "GitHub.com.".to_owned(),
            user_handle: b"u1".to_vec(),
            name: name.to_owned(),
        };
        session.record_credential_signal(renamed("ancien")).unwrap();
        session
            .record_credential_signal(renamed(" nouveau "))
            .unwrap();
        let list = read(&dir);
        assert_eq!(list.len(), 1);
        assert_eq!(
            list[0].signal,
            CredentialSignal::PasskeyRenamed {
                rp_id: "github.com".to_owned(),
                user_handle: b"u1".to_vec(),
                name: "nouveau".to_owned(),
            }
        );
        assert!(
            session
                .record_credential_signal(CredentialSignal::UnusedPassword {
                    domain: "exemple.fr".to_owned(),
                    user_name: "x".repeat(1000),
                })
                .is_err()
        );
        for n in 0..250u32 {
            session
                .record_credential_signal(CredentialSignal::UnknownPasskey {
                    rp_id: "exemple.fr".to_owned(),
                    credential_id: n.to_be_bytes().to_vec(),
                })
                .unwrap();
        }
        assert_eq!(read(&dir).len(), MAX_SIGNALS);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn findings_and_identities_follow_the_signals() {
        let vault = vault();
        let dir = std::env::temp_dir().join(format!("verrou-signals-{}", uuid::Uuid::new_v4()));
        let stored = |signal| Stored { signal, at: 10 };
        let list = vec![
            // Passkey 2 is no longer accepted for account u1.
            stored(CredentialSignal::AcceptedPasskeys {
                rp_id: "github.com".to_owned(),
                user_handle: b"u1".to_vec(),
                accepted: vec![vec![1; 16]],
            }),
            stored(CredentialSignal::PasskeyRenamed {
                rp_id: "github.com".to_owned(),
                user_handle: b"u2".to_vec(),
                name: "camille-travail".to_owned(),
            }),
            stored(CredentialSignal::UnusedPassword {
                domain: "exemple.fr".to_owned(),
                user_name: "CAMILLE".to_owned(),
            }),
            // Matches nothing.
            stored(CredentialSignal::UnknownPasskey {
                rp_id: "github.com".to_owned(),
                credential_id: vec![9; 16],
            }),
        ];
        let found: Vec<(SignalFindingKind, String, Option<String>)> = list
            .iter()
            .flat_map(|s| findings_of(&vault, s))
            .map(|(kind, item, _, detail)| (kind, item.id.clone(), detail))
            .collect();
        assert_eq!(
            found,
            vec![
                (
                    SignalFindingKind::PasskeyRejected,
                    "GitHub".to_owned(),
                    None
                ),
                (
                    SignalFindingKind::PasskeyRenamed,
                    "GitHub pro".to_owned(),
                    Some("camille-travail".to_owned())
                ),
                (
                    SignalFindingKind::PasswordUnused,
                    "Exemple".to_owned(),
                    None
                ),
            ]
        );
        save(&dir, &list).unwrap();
        let mut identities = crate::autofill::identities(&vault);
        let before = identities.len();
        apply_to_identities(&vault, &dir, &mut identities);
        // Passkey 2 and Exemple's password hidden.
        assert_eq!(identities.len(), before - 2);
        assert!(!identities.iter().any(|i| i.credential_id == vec![2; 16]));
        assert!(identities.iter().any(|i| i.credential_id == vec![1; 16]));
        assert!(
            !identities
                .iter()
                .any(|i| { i.item_id == "Exemple" && i.kind == AutofillIdentityKind::Password })
        );
        let pro = identities
            .iter()
            .find(|i| i.credential_id == vec![3; 16])
            .unwrap();
        assert_eq!(pro.user, "camille-travail");
        fs::remove_dir_all(dir).unwrap();
    }
}
