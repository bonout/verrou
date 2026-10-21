//! Merging duplicates: a kept login receives what the others have in
//! addition, then the others go to the trash (restorable for 30 days).
//!
//! Carried over to the kept item: the sites of missing hosts (and app
//! addresses), the username and the one-time code if it has none, the
//! notes (appended, with the original title), the missing custom fields,
//! the other passwords into the history. The most recently changed password
//! becomes the current password: merging never brings a stale password
//! back into use.
//!
//! Same write path as an edit: revision date sent (a stale copy is refused
//! by the server), offline queue. Attachments and passkeys don't move: an
//! item that has some is kept, it isn't merged into another.

use bitwarden_vault::{
    CipherType, CipherView, FieldType, FieldView, LoginUriView, PasswordHistoryView,
};
use chrono::{DateTime, Utc};
use verrou_core::matching::host_of;
use verrou_core::template;

use crate::edit::MAX_PASSWORD_HISTORY;
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
}

pub struct MergeOutcome {
    pub summary: MergeSummary,
    /// Items moved to the trash (or pending, offline).
    pub trashed: usize,
    pub vault: Decrypted,
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
        let summary = merge_views(&mut kept, &views, Utc::now());
        self.save_cipher(Some(&keep), kept, access).await?;
        let vault = self.trash_many(&others).await?;
        Ok(MergeOutcome {
            summary,
            trashed: others.len(),
            vault,
        })
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

/// Date of the current password: its last change, otherwise the item's last
/// modification.
fn password_date(view: &CipherView) -> DateTime<Utc> {
    view.login
        .as_ref()
        .and_then(|l| l.password_revision_date)
        .unwrap_or(view.revision_date)
}

fn present(value: Option<&String>) -> Option<&String> {
    value.filter(|v| !v.trim().is_empty())
}

fn uri_key(uri: &str) -> String {
    if verrou_core::apps::is_app_uri(uri) {
        format!("app:{}", uri.trim().trim_end_matches('/').to_lowercase())
    } else {
        host_of(uri).map_or_else(|| uri.trim().to_lowercase(), |h| format!("host:{h}"))
    }
}

fn is_reserved(field: &FieldView) -> bool {
    field.name.as_deref().is_some_and(template::is_reserved)
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

    merge_passwords(kept, &sorted, now, &mut summary);

    let Some(login) = kept.login.as_mut() else {
        return summary;
    };
    for other in &sorted {
        let Some(from) = &other.login else { continue };
        if present(login.username.as_ref()).is_none()
            && let Some(username) = present(from.username.as_ref())
        {
            login.username = Some(username.clone());
            summary.username = true;
        }
        if present(login.totp.as_ref()).is_none()
            && let Some(totp) = present(from.totp.as_ref())
        {
            login.totp = Some(totp.clone());
            summary.totp = true;
        }
        let mut keys: Vec<String> = login
            .uris
            .iter()
            .flatten()
            .filter_map(|u| u.uri.as_deref().map(uri_key))
            .collect();
        for uri in from.uris.iter().flatten() {
            let Some(address) = uri.uri.as_deref().filter(|u| !u.trim().is_empty()) else {
                continue;
            };
            let key = uri_key(address);
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
    login.generate_checksums();

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
/// others' histories) join the history, without duplicates.
fn merge_passwords(
    kept: &mut CipherView,
    sorted: &[&CipherView],
    now: DateTime<Utc>,
    summary: &mut MergeSummary,
) {
    let kept_date = password_date(kept);
    let Some(login) = kept.login.as_mut() else {
        return;
    };
    let current = present(login.password.as_ref()).cloned();
    // (password, date), most recent first; the current one wins a tie.
    let mut candidates: Vec<(String, DateTime<Utc>)> = Vec::new();
    if let Some(password) = &current {
        candidates.push((password.clone(), kept_date));
    }
    for other in sorted {
        if let Some(password) = other
            .login
            .as_ref()
            .and_then(|l| present(l.password.as_ref()))
        {
            candidates.push((password.clone(), password_date(other)));
        }
    }
    candidates.sort_by_key(|(_, date)| std::cmp::Reverse(*date));
    let Some((newest, newest_date)) = candidates.first().cloned() else {
        return;
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
    let mut history: Vec<PasswordHistoryView> = Vec::new();
    let mut push = |password: &String, date: DateTime<Utc>| {
        if *password != newest && !history.iter().any(|h| h.password == *password) {
            history.push(PasswordHistoryView {
                password: password.clone(),
                last_used_date: date,
            });
        }
    };
    for (password, _) in &candidates[1..] {
        push(password, now);
    }
    for entry in kept.password_history.iter().flatten() {
        push(&entry.password, entry.last_used_date);
    }
    for other in sorted {
        for entry in other.password_history.iter().flatten() {
            push(&entry.password, entry.last_used_date);
        }
    }
    history.truncate(MAX_PASSWORD_HISTORY);
    summary.history = history
        .iter()
        .filter(|h| !before.contains(&h.password))
        .count();
    kept.password_history = (!history.is_empty()).then_some(history);
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
            }
        );
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

    #[test]
    fn history_is_capped() {
        let mut kept = view("Site", "camille", "actuel", &[], 28);
        let others: Vec<CipherView> = (1..=8)
            .map(|n| view("Site", "camille", &format!("vieux-{n}"), &[], n))
            .collect();
        merge_views(&mut kept, &others, date(28));
        let history = kept.password_history.unwrap();
        assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
        assert_eq!(history[0].password, "vieux-8", "the most recent first");
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
