//! Merging duplicates: a kept login receives what the others have in
//! addition, then the others go to the trash (restorable for 30 days).
//!
//! Carried over to the kept item: the sites of missing hosts (and app
//! addresses; a site with a match rule of its own always), the username and
//! the one-time code if it has none, the notes (appended, with the original
//! title), the missing custom fields, the other passwords into the history.
//! The most recently changed password becomes the current password: merging
//! never brings a stale password back into use. The history holds five
//! passwords: any further distinct password becomes a hidden field, "Password
//! (from “X”)" or "Old password (from “X”)", never dropped.
//!
//! A username or a one-time code the kept item already has and another item
//! has differently is not dropped: it becomes a field of the kept item,
//! "Username (from “X”)" or, hidden, "One-time code (from “X”)". A merge
//! never silently loses a password, a site, a code or a username.
//!
//! Same write path as an edit: revision date sent (a stale copy is refused
//! by the server), offline queue. Attachments and passkeys don't move: an
//! item that has some is kept, it isn't merged into another.

use bitwarden_vault::{
    CipherType, CipherView, FieldType, FieldView, LoginUriView, LoginView, PasswordHistoryView,
};
use chrono::{DateTime, Utc};
use verrou_core::matching::host_of;
use verrou_core::template;

use crate::edit::{CustomFieldDraft, CustomFieldKind, MAX_PASSWORD_HISTORY, field_view};
use crate::{Connection, Decrypted, Error};

/// What the merge carried over to the kept item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeSummary {
    pub uris: usize,
    pub username: bool,
    pub totp: bool,
    /// Notes appended.
    pub notes: usize,
    pub fields: usize,
    /// Passwords added to the history.
    pub history: usize,
    /// The current password comes from another, more recent item.
    pub newer_password: bool,
    /// Passwords the history had no room for, kept as hidden fields.
    pub password_fields: usize,
}

pub struct MergeOutcome {
    pub summary: MergeSummary,
    /// Items moved to the trash (or pending, offline).
    pub trashed: usize,
    pub vault: Decrypted,
    /// The kept item as it was before, to undo the merge. Holds secrets: for
    /// memory only, never stored nor sent anywhere.
    pub snapshot: MergeSnapshot,
}

/// The kept item before a merge, and as the merge left it (its revision date
/// included): the merge is undone only if the item still is the latter.
pub struct MergeSnapshot {
    id: String,
    before: Box<CipherView>,
    merged: Option<Box<CipherView>>,
}

impl std::fmt::Debug for MergeSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the item's content.
        f.debug_struct("MergeSnapshot")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl MergeSnapshot {
    /// The kept item's identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl Connection {
    /// Merges `others` into `keep`, then moves `others` to the trash. The
    /// kept item is written first: if the rest fails, nothing is lost (the
    /// others stay in the vault).
    pub async fn merge_duplicates(
        &mut self,
        keep: &str,
        others: &[String],
    ) -> Result<MergeOutcome, Error> {
        let keep = self.resolve(keep);
        let mut others: Vec<String> = others
            .iter()
            .map(|id| self.resolve(id))
            .filter(|id| *id != keep)
            .collect();
        others.sort();
        others.dedup();
        if others.is_empty() {
            return Err(Error::Invalid("nothing to merge".to_owned()));
        }
        let access = self.online().await?;
        let mut ids = vec![keep.clone()];
        ids.extend(others.iter().cloned());
        let mut views = self.editable_views(&ids).await?;
        let mut kept = views.remove(0);
        check(&kept, &views)?;
        let before = Box::new(kept.clone());
        let summary = merge_views(&mut kept, &views, Utc::now());
        self.save_cipher(Some(&keep), kept, access).await?;
        // The kept item right after the merge: an edit since (even one still
        // waiting in the queue, whose revision date has not moved yet)
        // makes it differ.
        let merged = self.editable_view(&keep).await.ok().map(Box::new);
        let vault = self.trash_many(&others).await?;
        Ok(MergeOutcome {
            summary,
            trashed: others.len(),
            vault,
            snapshot: MergeSnapshot {
                id: keep,
                before,
                merged,
            },
        })
    }

    /// When each login's password last changed (Unix seconds), from the cache
    /// and without decrypting anything; an item that never had its password
    /// dated gets its creation date, never its last modification. For the
    /// review of a merge: the newest password becomes the current one.
    pub fn password_dates(&self) -> Result<std::collections::HashMap<String, i64>, Error> {
        Ok(self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| {
                let id = c.id?.to_string();
                let date = c
                    .login
                    .as_ref()
                    .and_then(|l| l.password_revision_date)
                    .unwrap_or(c.creation_date);
                Some((id, date.timestamp()))
            })
            .collect())
    }

    /// Puts the kept item back as it was before the merge, if nobody changed
    /// it since (same content and revision date): the vault as it is then.
    /// `None`: the item is left as it is, with what the merge gave it
    /// (nothing is lost: the merge only added).
    pub async fn undo_merge(
        &mut self,
        snapshot: &MergeSnapshot,
    ) -> Result<Option<Decrypted>, Error> {
        let Some(merged) = &snapshot.merged else {
            return Ok(None);
        };
        let access = self.online().await?;
        let Ok(current) = self.editable_view(&snapshot.id).await else {
            return Ok(None);
        };
        if current != **merged {
            return Ok(None);
        }
        let mut view = (*snapshot.before).clone();
        // The write carries the revision it replaces.
        view.revision_date = current.revision_date;
        let (_, vault) = self.save_cipher(Some(&snapshot.id), view, access).await?;
        Ok(Some(vault))
    }
}

/// Only logins of the same vault; nothing that doesn't move.
pub(crate) fn check(kept: &CipherView, others: &[CipherView]) -> Result<(), Error> {
    for view in std::iter::once(kept).chain(others) {
        if view.r#type != CipherType::Login || view.login.is_none() {
            return Err(Error::Invalid(format!(
                "\"{}\" is not a login: only logins can be merged",
                view.name
            )));
        }
        if view.organization_id != kept.organization_id {
            return Err(Error::Invalid(format!(
                "\"{}\" is not in the same vault",
                view.name
            )));
        }
    }
    for view in others {
        let attachments = view.attachments.as_ref().is_some_and(|a| !a.is_empty())
            || view
                .attachment_decryption_failures
                .as_ref()
                .is_some_and(|a| !a.is_empty());
        if attachments {
            return Err(Error::Invalid(format!(
                "\"{}\" has attachments: keep it instead, or move them first",
                view.name
            )));
        }
        let passkeys = view
            .login
            .as_ref()
            .and_then(|l| l.fido2_credentials.as_ref())
            .is_some_and(|c| !c.is_empty());
        if passkeys {
            return Err(Error::Invalid(format!(
                "\"{}\" has a passkey: keep it instead",
                view.name
            )));
        }
    }
    Ok(())
}

/// Date of the current password: its last change, otherwise the item's
/// creation. Never the item's last modification: renaming or moving an item
/// says nothing about its password, and must not make an old password the
/// newest.
pub(crate) fn password_date(view: &CipherView) -> DateTime<Utc> {
    view.login
        .as_ref()
        .and_then(|l| l.password_revision_date)
        .unwrap_or(view.creation_date)
}

fn present(value: Option<&String>) -> Option<&String> {
    value.filter(|v| !v.trim().is_empty())
}

/// What makes a site "the same": its host, or its application. A site with a
/// match rule of its own (starts with, exact, regular expression) means more
/// than its host, and is the same only as a whole.
fn site_key(uri: &LoginUriView) -> Option<String> {
    let address = uri.uri.as_deref()?;
    // An application address always carries the rule "never" (it matches no
    // web page): that says nothing about it.
    Some(match uri.r#match {
        Some(rule) if !verrou_core::apps::is_app_uri(address) => {
            format!("rule:{rule:?}:{}", address.trim().to_lowercase())
        }
        _ => uri_key(address),
    })
}

fn uri_key(uri: &str) -> String {
    if verrou_core::apps::is_app_uri(uri) {
        format!("app:{}", uri.trim().trim_end_matches('/').to_lowercase())
    } else {
        host_of(uri).map_or_else(|| uri.trim().to_lowercase(), |h| format!("host:{h}"))
    }
}

/// The same text (trimmed; `fold`: whatever its case).
fn same_text(a: Option<&str>, b: &str, fold: bool) -> bool {
    let (a, b) = (a.unwrap_or_default().trim(), b.trim());
    if fold {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

fn is_reserved(field: &FieldView) -> bool {
    field.name.as_deref().is_some_and(template::is_reserved)
}

/// Adds the usernames and codes that differ from the kept item's as fields
/// of it (once each).
fn add_fields(
    kept: &mut CipherView,
    differing: Vec<(String, String, CustomFieldKind)>,
    summary: &mut MergeSummary,
) {
    for (name, value, kind) in differing {
        let fields = kept.fields.get_or_insert_with(Vec::new);
        let present = fields.iter().any(|f| {
            f.name.as_deref() == Some(name.as_str()) && f.value.as_deref() == Some(value.as_str())
        });
        if present {
            continue;
        }
        if let Ok(view) = field_view(CustomFieldDraft {
            name,
            value: Some(verrou_core::SecretString::new(value)),
            kind,
            linked_id: None,
        }) {
            fields.push(view);
            summary.fields += 1;
        }
    }
}

/// The passwords the history has no room for: hidden fields of the kept item,
/// counted apart from the fields carried over.
fn add_password_fields(
    kept: &mut CipherView,
    overflow: Vec<(String, String)>,
    summary: &mut MergeSummary,
) {
    let carried = summary.fields;
    add_fields(
        kept,
        overflow
            .into_iter()
            .map(|(name, value)| (name, value, CustomFieldKind::Hidden))
            .collect(),
        summary,
    );
    summary.password_fields = summary.fields - carried;
    summary.fields = carried;
}

/// The sites of `from` that `login` lacks (see [`site_key`]).
fn carry_uris(login: &mut LoginView, from: &LoginView, summary: &mut MergeSummary) {
    let mut keys: Vec<String> = login.uris.iter().flatten().filter_map(site_key).collect();
    for uri in from.uris.iter().flatten() {
        let Some(address) = uri.uri.as_deref().filter(|u| !u.trim().is_empty()) else {
            continue;
        };
        let Some(key) = site_key(uri) else { continue };
        if keys.contains(&key) {
            continue;
        }
        keys.push(key);
        login.uris.get_or_insert_with(Vec::new).push(LoginUriView {
            uri: Some(address.to_owned()),
            r#match: uri.r#match,
            uri_checksum: None,
        });
        summary.uris += 1;
    }
}

/// Carries `others` over to `kept` (see the module header).
pub(crate) fn merge_views(
    kept: &mut CipherView,
    others: &[CipherView],
    now: DateTime<Utc>,
) -> MergeSummary {
    let mut summary = MergeSummary::default();
    // The others, the most recent password first.
    let mut sorted: Vec<&CipherView> = others.iter().collect();
    sorted.sort_by_key(|v| std::cmp::Reverse(password_date(v)));

    let overflow = merge_passwords(kept, &sorted, now, &mut summary);

    let Some(login) = kept.login.as_mut() else {
        return summary;
    };
    // A username or a code that differs from the kept item's: a field.
    let mut differing: Vec<(String, String, CustomFieldKind)> = Vec::new();
    let mut seen_usernames: Vec<String> = Vec::new();
    let mut seen_codes: Vec<String> = Vec::new();
    for other in &sorted {
        let Some(from) = &other.login else { continue };
        if let Some(username) = present(from.username.as_ref()) {
            if present(login.username.as_ref()).is_none() {
                login.username = Some(username.clone());
                summary.username = true;
            } else if !same_text(login.username.as_deref(), username, true)
                && !seen_usernames
                    .iter()
                    .any(|s| same_text(Some(s), username, true))
            {
                seen_usernames.push(username.clone());
                differing.push((
                    format!("Username (from “{}”)", other.name),
                    username.clone(),
                    CustomFieldKind::Text,
                ));
            }
        }
        if let Some(totp) = present(from.totp.as_ref()) {
            if present(login.totp.as_ref()).is_none() {
                login.totp = Some(totp.clone());
                summary.totp = true;
            } else if !same_text(login.totp.as_deref(), totp, false)
                && !seen_codes.iter().any(|s| same_text(Some(s), totp, false))
            {
                seen_codes.push(totp.clone());
                differing.push((
                    format!("One-time code (from “{}”)", other.name),
                    totp.clone(),
                    CustomFieldKind::Hidden,
                ));
            }
        }
        carry_uris(login, from, &mut summary);
    }
    login.generate_checksums();
    add_fields(kept, differing, &mut summary);
    add_password_fields(kept, overflow, &mut summary);

    for other in &sorted {
        if let Some(notes) = present(other.notes.as_ref()) {
            let notes = notes.trim();
            match present(kept.notes.as_ref()) {
                Some(existing) if existing.contains(notes) => {}
                Some(existing) => {
                    kept.notes = Some(format!(
                        "{}\n\n— Merged from \"{}\" —\n{notes}",
                        existing.trim_end(),
                        other.name
                    ));
                    summary.notes += 1;
                }
                None => {
                    kept.notes = Some(notes.to_owned());
                    summary.notes += 1;
                }
            }
        }
        for field in other.fields.iter().flatten() {
            if is_reserved(field) {
                continue;
            }
            let fields = kept.fields.get_or_insert_with(Vec::new);
            let same_name = fields.iter().find(|f| f.name == field.name);
            match same_name {
                Some(f) if f.value == field.value && f.r#type == field.r#type => continue,
                // A linked field with the same name designates the same field of the item.
                Some(f) if field.r#type == FieldType::Linked && f.r#type == FieldType::Linked => {
                    continue;
                }
                Some(_) => {
                    let mut renamed = field.clone();
                    renamed.name = Some(format!(
                        "{} ({})",
                        field.name.as_deref().unwrap_or("Field"),
                        other.name
                    ));
                    fields.push(renamed);
                }
                None => fields.push(field.clone()),
            }
            summary.fields += 1;
        }
    }
    kept.favorite |= others.iter().any(|o| o.favorite);
    summary
}

/// The most recent password becomes the current one; the others (and the
/// others' histories) join the history, without duplicates. The history
/// holds [`MAX_PASSWORD_HISTORY`] at most: a password that does not fit is
/// never dropped, it becomes a hidden field of the kept item, "Password (from
/// “X”)" (the current password of X) or "Old password (from “X”)" (a former
/// one). A value is never in a name. Returns those fields (name, value).
fn merge_passwords(
    kept: &mut CipherView,
    sorted: &[&CipherView],
    now: DateTime<Utc>,
    summary: &mut MergeSummary,
) -> Vec<(String, String)> {
    let kept_date = password_date(kept);
    let kept_name = kept.name.clone();
    let Some(login) = kept.login.as_mut() else {
        return Vec::new();
    };
    let current = present(login.password.as_ref()).cloned();
    // (password, date, from, it is the kept item's), most recent first; the
    // kept item's wins a tie.
    let mut candidates: Vec<(String, DateTime<Utc>, &str, bool)> = Vec::new();
    if let Some(password) = &current {
        candidates.push((password.clone(), kept_date, kept_name.as_str(), true));
    }
    for other in sorted {
        if let Some(password) = other
            .login
            .as_ref()
            .and_then(|l| present(l.password.as_ref()))
        {
            candidates.push((
                password.clone(),
                password_date(other),
                other.name.as_str(),
                false,
            ));
        }
    }
    candidates.sort_by_key(|(_, date, _, _)| std::cmp::Reverse(*date));
    let Some((newest, newest_date, _, _)) = candidates.first().cloned() else {
        return Vec::new();
    };
    if current.as_ref() != Some(&newest) {
        login.password = Some(newest.clone());
        login.password_revision_date = Some(newest_date);
        summary.newer_password = current.is_some();
    }
    let before: Vec<String> = kept
        .password_history
        .iter()
        .flatten()
        .map(|h| h.password.clone())
        .collect();
    // Every other distinct password, in the order they would enter the
    // history: (password, date, the item it comes from, still its current one).
    let mut all: Vec<(String, DateTime<Utc>, String, bool)> = Vec::new();
    let mut push = |password: &String, date: DateTime<Utc>, from: &str, is_current: bool| {
        if *password != newest && !all.iter().any(|(p, ..)| p == password) {
            all.push((password.clone(), date, from.to_owned(), is_current));
        }
    };
    for (password, _, from, is_kept) in candidates.iter().skip(1) {
        // The kept item's former current password is an old one now.
        push(password, now, from, !is_kept);
    }
    for entry in kept.password_history.iter().flatten() {
        push(&entry.password, entry.last_used_date, &kept_name, false);
    }
    for other in sorted {
        for entry in other.password_history.iter().flatten() {
            push(&entry.password, entry.last_used_date, &other.name, false);
        }
    }
    let mut history: Vec<PasswordHistoryView> = Vec::new();
    let mut overflow: Vec<(String, String)> = Vec::new();
    for (password, date, from, is_current) in all {
        if history.len() < MAX_PASSWORD_HISTORY {
            history.push(PasswordHistoryView {
                password,
                last_used_date: date,
            });
        } else {
            let label = if is_current {
                "Password"
            } else {
                "Old password"
            };
            overflow.push((format!("{label} (from “{from}”)"), password));
        }
    }
    summary.history = history
        .iter()
        .filter(|h| !before.contains(&h.password))
        .count();
    kept.password_history = (!history.is_empty()).then_some(history);
    overflow
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::CipherView;
    use chrono::TimeZone;
    use verrou_core::SecretString;

    use super::*;
    use crate::edit::{CustomFieldDraft, CustomFieldKind, Draft, LoginDraft, new_view};

    fn date(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 12, 0, 0).unwrap()
    }

    fn view(name: &str, username: &str, password: &str, uris: &[&str], day: u32) -> CipherView {
        let mut view = new_view(
            Draft {
                name: name.to_owned(),
                login: Some(LoginDraft {
                    uri_matches: None,
                    username: Some(username.to_owned()),
                    password: Some(SecretString::new(password)),
                    totp: None,
                    uris: uris.iter().map(|u| (*u).to_owned()).collect(),
                }),
                ..Draft::default()
            },
            date(day),
        )
        .unwrap();
        view.revision_date = date(day);
        view
    }

    fn field(name: &str, value: &str) -> FieldView {
        crate::edit::field_view(CustomFieldDraft {
            name: name.to_owned(),
            value: Some(SecretString::new(value)),
            kind: CustomFieldKind::Text,
            linked_id: None,
        })
        .unwrap()
    }

    fn uris(view: &CipherView) -> Vec<String> {
        view.login
            .as_ref()
            .unwrap()
            .uris
            .iter()
            .flatten()
            .filter_map(|u| u.uri.clone())
            .collect()
    }

    #[test]
    fn missing_data_is_carried_over_without_duplicates() {
        let mut kept = view(
            "Maif",
            "camille@exemple.fr",
            "lilas",
            &["https://www.maif.fr"],
            10,
        );
        kept.notes = Some("Contrat habitation".to_owned());
        kept.fields = Some(vec![field("Numéro sociétaire", "123")]);
        let mut a = view(
            "MAIF - Espace sociétaire",
            "",
            "lilas",
            &[
                "https://maif.fr/espace-perso",
                "https://connect.maif.fr",
                "iosapp://fr.maif.app",
            ],
            5,
        );
        a.login.as_mut().unwrap().totp = Some("JBSWY3DPEHPK3PXP".to_owned());
        a.notes = Some("Contrat auto".to_owned());
        a.fields = Some(vec![
            field("Numéro sociétaire", "123"),
            field("Numéro sociétaire", "456"),
            field("Agence", "Niort"),
        ]);
        let mut b = view("maif.fr", "", "", &["IOSAPP://fr.maif.app/"], 1);
        b.notes = Some("Contrat habitation".to_owned());
        b.favorite = true;

        let summary = merge_views(&mut kept, &[a, b], date(20));
        assert_eq!(
            uris(&kept),
            [
                "https://www.maif.fr",
                "https://connect.maif.fr",
                "iosapp://fr.maif.app"
            ],
            "one site per host, an app once"
        );
        let login = kept.login.as_ref().unwrap();
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(login.username.as_deref(), Some("camille@exemple.fr"));
        assert_eq!(login.password.as_deref(), Some("lilas"));
        assert!(kept.password_history.is_none(), "same password");
        assert_eq!(
            kept.notes.as_deref(),
            Some(
                "Contrat habitation\n\n— Merged from \"MAIF - Espace sociétaire\" —\nContrat auto"
            )
        );
        let names: Vec<_> = kept
            .fields
            .iter()
            .flatten()
            .map(|f| f.name.clone().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Numéro sociétaire",
                "Numéro sociétaire (MAIF - Espace sociétaire)",
                "Agence"
            ]
        );
        assert!(kept.favorite);
        assert_eq!(
            summary,
            MergeSummary {
                uris: 2,
                username: false,
                totp: true,
                notes: 1,
                fields: 2,
                history: 0,
                newer_password: false,
                password_fields: 0,
            }
        );
    }

    fn field_named<'a>(view: &'a CipherView, name: &str) -> Option<&'a FieldView> {
        view.fields
            .iter()
            .flatten()
            .find(|f| f.name.as_deref() == Some(name))
    }

    #[test]
    fn a_different_username_or_code_becomes_a_field_never_a_loss() {
        let mut kept = view("GitHub", "camille", "pw", &["https://github.com"], 10);
        kept.login.as_mut().unwrap().totp = Some("KEPTSEED".to_owned());
        let mut a = view("GitHub (perso)", "camille.perso", "pw", &[], 5);
        a.login.as_mut().unwrap().totp = Some("OTHERSEED".to_owned());
        // Same username in other letters, same code: nothing to keep apart.
        let mut b = view("github.com", " CAMILLE ", "pw", &[], 4);
        b.login.as_mut().unwrap().totp = Some("KEPTSEED".to_owned());
        // Another one saying the same as `a`: said once.
        let mut c = view("gh", "camille.perso", "pw", &[], 3);
        c.login.as_mut().unwrap().totp = Some("OTHERSEED".to_owned());

        let summary = merge_views(&mut kept, &[a, b, c], date(20));
        let login = kept.login.as_ref().unwrap();
        assert_eq!(
            login.username.as_deref(),
            Some("camille"),
            "the kept item keeps its own"
        );
        assert_eq!(login.totp.as_deref(), Some("KEPTSEED"));
        let username = field_named(&kept, "Username (from “GitHub (perso)”)").unwrap();
        assert_eq!(username.value.as_deref(), Some("camille.perso"));
        assert_eq!(username.r#type, FieldType::Text);
        let code = field_named(&kept, "One-time code (from “GitHub (perso)”)").unwrap();
        assert_eq!(code.value.as_deref(), Some("OTHERSEED"));
        assert_eq!(
            code.r#type,
            FieldType::Hidden,
            "a seed is never shown in the clear"
        );
        assert_eq!(
            kept.fields.as_ref().unwrap().len(),
            2,
            "no field for a repeat"
        );
        assert_eq!(summary.fields, 2);
        assert!(
            !summary.username && !summary.totp,
            "nothing carried into the empty slots"
        );
    }

    #[test]
    fn two_different_codes_and_no_kept_one_keep_both() {
        let mut kept = view("Site", "camille", "pw", &[], 10);
        let mut a = view("Site A", "camille", "pw", &[], 8);
        a.login.as_mut().unwrap().totp = Some("SEEDA".to_owned());
        let mut b = view("Site B", "camille", "pw", &[], 5);
        b.login.as_mut().unwrap().totp = Some("SEEDB".to_owned());
        let summary = merge_views(&mut kept, &[a, b], date(20));
        // The first (most recent password) fills the empty slot, the other is
        // kept as a field.
        assert_eq!(kept.login.as_ref().unwrap().totp.as_deref(), Some("SEEDA"));
        assert_eq!(
            field_named(&kept, "One-time code (from “Site B”)")
                .unwrap()
                .value
                .as_deref(),
            Some("SEEDB")
        );
        assert!(summary.totp);
    }

    #[test]
    fn a_site_with_a_match_rule_of_its_own_is_not_taken_for_its_host() {
        let mut kept = view("Bank", "camille", "pw", &["https://bank.example.com"], 10);
        let mut other = view(
            "Bank SSO",
            "camille",
            "pw",
            &["https://bank.example.com/sso"],
            5,
        );
        other.login.as_mut().unwrap().uris.as_mut().unwrap()[0].r#match =
            Some(bitwarden_vault::UriMatchType::StartsWith);
        // Same host, default rule: the path means nothing, one site is enough.
        let plain = view(
            "Bank 2",
            "camille",
            "pw",
            &["https://bank.example.com/elsewhere"],
            4,
        );
        merge_views(&mut kept, &[other, plain], date(20));
        assert_eq!(
            uris(&kept),
            ["https://bank.example.com", "https://bank.example.com/sso"],
            "the path-specific site is kept, with its rule"
        );
        let rules: Vec<_> = kept
            .login
            .unwrap()
            .uris
            .unwrap()
            .iter()
            .map(|u| u.r#match)
            .collect();
        assert_eq!(rules[1], Some(bitwarden_vault::UriMatchType::StartsWith));
    }

    #[test]
    fn the_newest_password_wins_and_the_others_go_to_history() {
        let mut kept = view("Google", "camille", "ancien", &["https://google.com"], 10);
        kept.password_history = Some(vec![PasswordHistoryView {
            password: "très-ancien".to_owned(),
            last_used_date: date(2),
        }]);
        let newer = view(
            "Gmail",
            "camille",
            "récent",
            &["https://mail.google.com"],
            15,
        );
        let older = view("google.com", "", "ancien", &[], 3);
        let mut other = view("Google 2", "camille", "autre", &[], 4);
        other.password_history = Some(vec![PasswordHistoryView {
            password: "récent".to_owned(),
            last_used_date: date(1),
        }]);
        let summary = merge_views(&mut kept, &[older, newer, other], date(20));
        assert_eq!(
            kept.login.as_ref().unwrap().password.as_deref(),
            Some("récent")
        );
        assert_eq!(
            kept.login.as_ref().unwrap().password_revision_date,
            Some(date(15))
        );
        let history: Vec<_> = kept
            .password_history
            .iter()
            .flatten()
            .map(|h| h.password.as_str())
            .collect();
        assert_eq!(history, ["ancien", "autre", "très-ancien"]);
        assert!(summary.newer_password);
        assert_eq!(summary.history, 2, "the former current one and \"autre\"");
    }

    /// Every password of the merged items, wherever the merge put it.
    fn kept_passwords(view: &CipherView) -> Vec<String> {
        let mut all: Vec<String> = view
            .login
            .iter()
            .filter_map(|l| l.password.clone())
            .collect();
        all.extend(
            view.password_history
                .iter()
                .flatten()
                .map(|h| h.password.clone()),
        );
        all.extend(
            view.fields
                .iter()
                .flatten()
                .filter(|f| {
                    f.name
                        .as_deref()
                        .is_some_and(|n| n.contains("assword (from"))
                })
                .filter_map(|f| f.value.clone()),
        );
        all
    }

    #[test]
    fn history_is_capped_and_what_does_not_fit_becomes_hidden_fields() {
        let mut kept = view("Site", "camille", "actuel", &[], 28);
        kept.password_history = Some(vec![PasswordHistoryView {
            password: "tout-vieux".to_owned(),
            last_used_date: date(1),
        }]);
        let others: Vec<CipherView> = (1..=8)
            .map(|n| {
                view(
                    &format!("Copie {n}"),
                    "camille",
                    &format!("vieux-{n}"),
                    &[],
                    n,
                )
            })
            .collect();
        let summary = merge_views(&mut kept, &others, date(28));
        let history = kept.password_history.clone().unwrap();
        assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
        assert_eq!(history[0].password, "vieux-8", "the most recent first");
        // 8 others + the kept item's own history = 9 passwords besides the
        // current one: 5 in the history, 4 in hidden fields. None is lost,
        // the kept item's own old one included.
        assert_eq!(summary.password_fields, 4);
        assert_eq!(summary.fields, 0, "not counted with the carried fields");
        let mut all = kept_passwords(&kept);
        all.sort();
        let mut expected: Vec<String> = (1..=8).map(|n| format!("vieux-{n}")).collect();
        expected.push("actuel".to_owned());
        expected.push("tout-vieux".to_owned());
        expected.sort();
        assert_eq!(all, expected);
        let field = field_named(&kept, "Password (from “Copie 3”)").unwrap();
        assert_eq!(field.value.as_deref(), Some("vieux-3"));
        assert_eq!(field.r#type, FieldType::Hidden, "never shown in the clear");
        let old = field_named(&kept, "Old password (from “Site”)").unwrap();
        assert_eq!(old.value.as_deref(), Some("tout-vieux"));
        for f in kept.fields.iter().flatten() {
            let name = f.name.as_deref().unwrap_or_default();
            assert!(
                !name.contains("vieux-") && !name.contains("actuel"),
                "{name}"
            );
        }
        // Merging the same items again adds nothing.
        let again = merge_views(&mut kept, &others, date(29));
        assert_eq!(again.password_fields, 0);
        assert_eq!(kept.fields.as_ref().unwrap().len(), 4);
    }

    #[test]
    fn identical_overflowing_passwords_are_kept_once() {
        let mut kept = view("Site", "camille", "actuel", &[], 28);
        let mut others: Vec<CipherView> = (1..=6)
            .map(|n| {
                view(
                    &format!("Copie {n}"),
                    "camille",
                    &format!("vieux-{n}"),
                    &[],
                    n,
                )
            })
            .collect();
        // A seventh copy repeating the oldest one.
        others.push(view("Doublon", "camille", "vieux-1", &[], 1));
        let summary = merge_views(&mut kept, &others, date(28));
        assert_eq!(summary.password_fields, 1, "6 distinct others, 5 fit");
        assert_eq!(kept.password_history.as_ref().unwrap().len(), 5);
    }

    #[test]
    fn a_password_without_a_revision_date_is_dated_by_its_creation_not_its_last_edit() {
        // The copy was renamed yesterday: that says nothing about its password.
        let mut kept = view("Site", "camille", "recent", &[], 20);
        let mut copy = view("Site copy", "camille", "ancien", &[], 5);
        copy.revision_date = date(27);
        let summary = merge_views(&mut kept, &[copy], date(28));
        assert_eq!(
            kept.login.as_ref().unwrap().password.as_deref(),
            Some("recent")
        );
        assert!(!summary.newer_password);
        assert_eq!(password_date(&kept), date(20));
    }

    #[test]
    fn only_logins_of_one_vault_without_attachments_or_passkeys_merge() {
        let kept = view("A", "camille", "a", &[], 1);
        let mut note = view("Note", "", "", &[], 1);
        note.r#type = CipherType::SecureNote;
        note.login = None;
        assert!(matches!(check(&kept, &[note]), Err(Error::Invalid(_))));
        let mut shared = view("B", "camille", "a", &[], 1);
        shared.organization_id = Some(bitwarden_core::OrganizationId::new(uuid::Uuid::new_v4()));
        assert!(matches!(check(&kept, &[shared]), Err(Error::Invalid(_))));
        assert!(check(&kept, &[view("C", "camille", "a", &[], 1)]).is_ok());
    }
}
