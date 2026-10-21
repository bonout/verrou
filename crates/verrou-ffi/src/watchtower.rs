//! Audit extras for the app: two-factor authentication available but
//! missing (2fa.directory), expired cards, old passwords, and checking
//! freshly saved passwords against known breaches. See
//! `verrou_core::watchtower`.

use std::sync::{Arc, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};
use verrou_core::passkey_upgrade::{self, PasskeyDirectory, Support};
use verrou_core::{SecretString, Vault, mock, watchtower};
use verrou_vaultwarden::change_password::{self, Source};
use verrou_vaultwarden::passkey_setup;
use verrou_vaultwarden::{Connection, Decrypted};

use crate::{BreachedPassword, ItemSummary, VaultSession, VerrouError, summary};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Cards and old passwords: computed locally, no network.
#[derive(Clone, Debug, uniffi::Record)]
pub struct WatchtowerReport {
    /// Cards expired or expiring within 60 days, most urgent first.
    pub cards: Vec<ExpiringCard>,
    /// Logins unchanged for more than 3 years, oldest first.
    pub old: Vec<OldPassword>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ExpiringCard {
    pub item: ItemSummary,
    /// Expiry month and year (`09/2029`).
    pub expiry: String,
    /// Days left until the end of the expiry month; negative: expired.
    pub days_left: i64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct OldPassword {
    pub item: ItemSummary,
    /// Days since the item was last modified.
    pub days: i64,
}

/// Logins whose site offers two-factor authentication, with no one-time
/// code in Verrou.
#[derive(Clone, Debug, uniffi::Record)]
pub struct TwoFactorReport {
    pub missing: Vec<MissingTwoFactor>,
    /// Unix timestamp of the copy of the list used.
    pub fetched_at: i64,
    /// Copy older than 7 days, for lack of network.
    pub stale: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MissingTwoFactor {
    pub item: ItemSummary,
    /// Site name in 2fa.directory.
    pub site: String,
    /// The site accepts one-time codes (TOTP), which Verrou can store and
    /// fill.
    pub totp: bool,
    /// Methods offered (`totp`, `sms`, `u2f`, `email`…).
    pub methods: Vec<String>,
    /// The site's help page for turning it on (HTTPS).
    pub documentation: Option<String>,
}

/// Logins whose site accepts passkeys, with no passkey in Verrou
/// ("Passkey possible").
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyReport {
    pub candidates: Vec<PasskeyCandidate>,
    /// Unix timestamp of the copy of the directory used.
    pub fetched_at: i64,
    /// Copy older than 7 days, for lack of network.
    pub stale: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyCandidate {
    pub item: ItemSummary,
    /// Site domain in the directory (passkeys.2fa.directory).
    pub domain: String,
    /// The passkey can replace the password at sign-in; otherwise it is a
    /// second factor, after the password.
    pub passwordless: bool,
    /// The site requires the passkey (rare).
    pub required: bool,
    /// The site's help page about passkeys (HTTPS).
    pub documentation: Option<String>,
    /// Note from the directory, in English.
    pub notes: Option<String>,
}

/// Where the page offered by "Create a passkey" comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasskeySetupSource {
    /// The site publishes its creation page (`/.well-known/passkey-endpoints`).
    WellKnown,
    /// Major site known in advance, no request.
    Known,
    /// The site doesn't give its page: its home page (or the directory's
    /// address).
    Home,
}

impl From<passkey_setup::Source> for PasskeySetupSource {
    fn from(source: passkey_setup::Source) -> Self {
        match source {
            passkey_setup::Source::WellKnown => Self::WellKnown,
            passkey_setup::Source::Known => Self::Known,
            passkey_setup::Source::Home => Self::Home,
        }
    }
}

/// Page to open to create a passkey (HTTPS).
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeySetupPage {
    pub url: String,
    pub source: PasskeySetupSource,
}

fn passkey_candidates(v: &Vault, directory: &PasskeyDirectory) -> Vec<PasskeyCandidate> {
    passkey_upgrade::passkey_candidates(v, directory)
        .into_iter()
        .filter_map(|(id, site)| {
            v.get(&id).map(|i| PasskeyCandidate {
                item: summary(i),
                domain: site.domain.clone(),
                passwordless: site.passwordless(),
                required: site.passwordless == Some(Support::Required)
                    || site.mfa == Some(Support::Required),
                documentation: site.documentation.clone(),
                notes: site.notes.clone(),
            })
        })
        .collect()
}

/// Where the page offered by "Change password" comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChangePasswordSource {
    /// Major site known in advance (Google, GitHub…), no request.
    Known,
    /// The site follows the `/.well-known/change-password` standard.
    WellKnown,
    /// The site doesn't give its page (or doesn't answer): its home page.
    Home,
}

impl From<Source> for ChangePasswordSource {
    fn from(source: Source) -> Self {
        match source {
            Source::Known => Self::Known,
            Source::WellKnown => Self::WellKnown,
            Source::Home => Self::Home,
        }
    }
}

/// Page to open to change a login's password (HTTPS).
#[derive(Clone, Debug, uniffi::Record)]
pub struct ChangePasswordPage {
    pub url: String,
    pub source: ChangePasswordSource,
}

fn fingerprint(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

impl VaultSession {
    /// Remembers the fingerprint of passwords found in breaches, as they
    /// were checked (see `still_breached`).
    pub(crate) fn remember_breached(
        &self,
        checked: &[(String, SecretString)],
        found: &[BreachedPassword],
    ) {
        let mut breached = self.breached.lock().unwrap_or_else(PoisonError::into_inner);
        for (id, password) in checked {
            if found.iter().any(|b| &b.item.id == id) {
                breached.insert(id.clone(), fingerprint(password.expose()));
            } else {
                breached.remove(id);
            }
        }
    }

    /// Installs the vault returned by a write made from Verrou (editor,
    /// extension, import) and remembers the logins whose password is new,
    /// for `check_new_passwords`.
    pub(crate) fn install_written(
        &self,
        connection: &Arc<tokio::sync::Mutex<Connection>>,
        decrypted: Decrypted,
    ) -> Result<(), VerrouError> {
        let before = self.vault.read().unwrap_or_else(PoisonError::into_inner);
        let changed = watchtower::changed_passwords(before.as_ref(), &decrypted.items);
        drop(before);
        self.install_if_current(connection, decrypted)?;
        if !changed.is_empty() {
            let mut queue = self
                .new_passwords
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for id in changed {
                if !queue.contains(&id) {
                    queue.push(id);
                }
            }
        }
        Ok(())
    }
}

#[uniffi::export]
impl VaultSession {
    /// Expired or soon-to-expire cards, old passwords.
    pub fn watchtower(&self) -> Result<WatchtowerReport, VerrouError> {
        let now = now();
        self.with_vault(|v| {
            Ok(WatchtowerReport {
                cards: watchtower::expiring_cards(v, now)
                    .into_iter()
                    .filter_map(|c| {
                        v.get(&c.id).map(|i| ExpiringCard {
                            item: summary(i),
                            expiry: format!("{:02}/{}", c.expiry.month, c.expiry.year),
                            days_left: c.days_left,
                        })
                    })
                    .collect(),
                old: watchtower::old_passwords(v, now)
                    .into_iter()
                    .filter_map(|(id, days)| {
                        v.get(&id).map(|i| OldPassword {
                            item: summary(i),
                            days,
                        })
                    })
                    .collect(),
            })
        })
    }

    /// Breaches still current: the logins whose password hasn't changed
    /// since they were checked, with their up-to-date summary. An item
    /// deleted, moved to the trash or whose password changed (in Verrou, the
    /// browser or elsewhere, then synced) leaves the list. Local, no
    /// network.
    pub fn still_breached(&self, breaches: Vec<BreachedPassword>) -> Vec<BreachedPassword> {
        let known = self.breached.lock().unwrap_or_else(PoisonError::into_inner);
        self.with_vault(|v| {
            Ok(breaches
                .into_iter()
                .filter_map(|b| {
                    let item = v.get(&b.item.id).filter(|i| i.is_active())?;
                    let password = verrou_core::audit::password_of(item)?;
                    (known.get(&item.id) == Some(&fingerprint(password))).then(|| {
                        BreachedPassword {
                            item: summary(item),
                            count: b.count,
                        }
                    })
                })
                .collect())
        })
        .unwrap_or_default()
    }

    /// Forgets the pending new passwords (check turned off).
    pub fn forget_new_passwords(&self) {
        self.new_passwords
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Sites of logins that offer two-factor authentication while the item
    /// has no one-time code. Downloads the full 2fa.directory list (nothing
    /// from the vault is sent), kept 7 days in the account folder; offline,
    /// the last copy.
    pub async fn two_factor_audit(&self) -> Result<TwoFactorReport, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        let loaded = verrou_vaultwarden::two_factor_directory::load(&dir).await?;
        self.with_vault(|v| {
            Ok(TwoFactorReport {
                missing: watchtower::missing_two_factor(v, &loaded.directory)
                    .into_iter()
                    .filter_map(|(id, site)| {
                        v.get(&id).map(|i| MissingTwoFactor {
                            item: summary(i),
                            site: site.name.clone(),
                            totp: site.supports_totp(),
                            methods: site.methods.clone(),
                            documentation: site.documentation.clone(),
                        })
                    })
                    .collect(),
                fetched_at: loaded.fetched_at,
                stale: loaded.stale,
            })
        })
    }

    /// Logins whose site accepts passkeys but that don't have one yet
    /// ("Passkey possible"). Downloads the full passkeys.2fa.directory
    /// directory (nothing from the vault is sent, no per-site request), kept
    /// 7 days in the account folder; offline, the last copy. Mock vault: an
    /// embedded excerpt, no network.
    pub async fn passkey_audit(&self) -> Result<PasskeyReport, VerrouError> {
        let Ok(store) = self.store() else {
            let directory =
                PasskeyDirectory::parse(mock::PASSKEY_DIRECTORY.as_bytes()).map_err(|e| {
                    VerrouError::Invalid {
                        message: e.to_string(),
                    }
                })?;
            return self.with_vault(|v| {
                Ok(PasskeyReport {
                    candidates: passkey_candidates(v, &directory),
                    fetched_at: now(),
                    stale: false,
                })
            });
        };
        let dir = store.dir().to_path_buf();
        let loaded = verrou_vaultwarden::passkey_directory::load(&dir).await?;
        self.with_vault(|v| {
            Ok(PasskeyReport {
                candidates: passkey_candidates(v, &loaded.directory),
                fetched_at: loaded.fetched_at,
                stale: loaded.stale,
            })
        })
    }

    /// Page where to create a passkey for a login: the one the site
    /// publishes (`/.well-known/passkey-endpoints`, checked on its host then
    /// its domain), otherwise a page known in advance, otherwise the
    /// directory's address or the site's home page. Only on the user's
    /// request, for this item alone: requests only go to the site they are
    /// about to open.
    pub async fn passkey_setup_page(&self, id: String) -> Result<PasskeySetupPage, VerrouError> {
        let host = self
            .with_vault(|v| Ok(v.get(&id).ok_or(VerrouError::NotFound)?.primary_host()))?
            .ok_or_else(|| VerrouError::Invalid {
                message: "this item has no site".to_owned(),
            })?;
        // Site address according to the cached directory (never downloaded here).
        let site_url = match self.store() {
            Ok(store) => verrou_vaultwarden::passkey_directory::cached(store.dir())
                .and_then(|d| d.lookup(&host).and_then(|s| s.url.clone())),
            Err(_) => None,
        };
        let page = passkey_setup::find(&host, site_url.as_deref()).await?;
        Ok(PasskeySetupPage {
            url: page.url,
            source: page.source.into(),
        })
    }

    /// Checks against Have I Been Pwned (k-anonymity: 5 characters of the
    /// SHA-1) the passwords saved from Verrou since the last call, and
    /// returns those that appear in known breaches. Passwords coming from
    /// elsewhere (sync) are not concerned.
    pub async fn check_new_passwords(&self) -> Result<Vec<BreachedPassword>, VerrouError> {
        let ids: Vec<String> = std::mem::take(
            &mut *self
                .new_passwords
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let candidates: Vec<(String, verrou_core::SecretString)> = self.with_vault(|v| {
            Ok(ids
                .iter()
                .filter_map(|id| v.get(id))
                .filter(|i| i.is_active())
                .filter_map(|i| {
                    verrou_core::audit::password_of(i)
                        .map(|p| (i.id.clone(), verrou_core::SecretString::new(p)))
                })
                .collect())
        })?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let passwords: Vec<&str> = candidates.iter().map(|(_, p)| p.expose()).collect();
        let counts = match verrou_vaultwarden::breach::pwned_counts(&passwords).await {
            Ok(counts) => counts,
            Err(error) => {
                // Offline: we'll retry on the next write.
                let mut queue = self
                    .new_passwords
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                for (id, _) in candidates {
                    if !queue.contains(&id) {
                        queue.push(id);
                    }
                }
                return Err(error.into());
            }
        };
        let found: Vec<BreachedPassword> = self.with_vault(|v| {
            Ok(candidates
                .iter()
                .zip(counts)
                .filter(|(_, count)| *count > 0)
                .filter_map(|((id, _), count)| {
                    v.get(id).map(|i| BreachedPassword {
                        item: summary(i),
                        count,
                    })
                })
                .collect())
        })?;
        self.remember_breached(&candidates, &found);
        Ok(found)
    }

    /// Page where to change a login's password: major known site, otherwise
    /// `/.well-known/change-password` checked on its host then its domain,
    /// otherwise the site's home page. Only on the user's request, for this
    /// item alone: requests only go to the site they are about to open.
    pub async fn change_password_page(
        &self,
        id: String,
    ) -> Result<ChangePasswordPage, VerrouError> {
        let host = self
            .with_vault(|v| Ok(v.get(&id).ok_or(VerrouError::NotFound)?.primary_host()))?
            .ok_or_else(|| VerrouError::Invalid {
                message: "this item has no site".to_owned(),
            })?;
        let page = change_password::find(&host).await?;
        Ok(ChangePasswordPage {
            url: page.url,
            source: page.source.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchtower_reports_mock_cards() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        // The mock vault has cards (09/29, 03/28, 11/27): none expires
        // before autumn 2027.
        let report = session.watchtower().unwrap();
        assert!(report.cards.iter().all(|c| c.days_left <= 60));
    }

    #[test]
    fn breaches_leave_the_list_once_the_password_changed() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        let (id, password, item) = session
            .with_vault(|v| {
                let item = v
                    .items()
                    .iter()
                    .find(|i| i.is_active() && verrou_core::audit::password_of(i).is_some())
                    .unwrap();
                Ok((
                    item.id.clone(),
                    verrou_core::audit::password_of(item).unwrap().to_owned(),
                    summary(item),
                ))
            })
            .unwrap();
        let found = vec![BreachedPassword { item, count: 3 }];
        // Checked with the current password: still current.
        session.remember_breached(&[(id.clone(), SecretString::new(password))], &found);
        assert_eq!(session.still_breached(found.clone()).len(), 1);
        // Checked with another password: it changed since.
        session.remember_breached(&[(id.clone(), SecretString::new("ancien"))], &found);
        assert!(session.still_breached(found.clone()).is_empty());
        // Rechecked and clean: forgotten.
        session.remember_breached(&[(id, SecretString::new("x"))], &[]);
        assert!(session.still_breached(found.clone()).is_empty());
        // Locked: nothing left.
        session.lock();
        assert!(session.still_breached(found).is_empty());
    }

    #[tokio::test]
    async fn passkey_audit_of_the_mock_vault_needs_no_network() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        let report = session.passkey_audit().await.unwrap();
        assert!(!report.stale);
        let domains: Vec<&str> = report
            .candidates
            .iter()
            .map(|c| c.domain.as_str())
            .collect();
        assert!(domains.contains(&"github.com"), "{domains:?}");
        // Google already has a passkey in the mock vault: nothing to offer
        // (subdomain matching is tested in the core).
        assert!(!report.candidates.iter().any(|c| c.item.title == "Google"));
        // npm: second factor only.
        assert!(
            report
                .candidates
                .iter()
                .filter(|c| c.domain == "npmjs.com")
                .all(|c| !c.passwordless)
        );
        // Sorted by title.
        let titles: Vec<String> = report
            .candidates
            .iter()
            .map(|c| c.item.title.to_lowercase())
            .collect();
        let mut sorted = titles.clone();
        sorted.sort();
        assert_eq!(titles, sorted);
        session.lock();
        assert!(matches!(
            session.passkey_audit().await,
            Err(VerrouError::Locked)
        ));
    }

    #[tokio::test]
    async fn change_password_page_needs_a_site() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        assert!(matches!(
            session.change_password_page("absent".to_owned()).await,
            Err(VerrouError::NotFound)
        ));
    }

    #[tokio::test]
    async fn no_new_password_means_no_request() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        assert!(session.check_new_passwords().await.unwrap().is_empty());
        // Without an account, no folder to keep the list in.
        assert!(matches!(
            session.two_factor_audit().await,
            Err(VerrouError::NoAccount)
        ));
    }
}
