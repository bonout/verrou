//! Writing to the vault: create, modify, move to the trash.
//!
//! Same split as for reading: the SDK encrypts (`CipherView` →
//! `Cipher` → API request), Verrou sends the request. A modification starts
//! from the item as the cache knows it, decrypted, and only touches the
//! fields Verrou can edit: the rest (passkeys, attachments,
//! history, reserved `verrou:…` fields) goes back intact. The revision
//! date sent lets the server refuse a modification made on
//! a stale copy.
//!
//! Nothing waits for the network: the write, encrypted, joins the queue
//! (`outbox`), applied right away to the displayed vault; sending follows in
//! the background (`sync_shared`), or when the network comes back.

use std::collections::HashMap;

use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_vault::{
    CardView, CipherRepromptType, CipherType, CipherView, FieldType, FieldView, FolderId,
    IdentityView, LoginUriView, LoginView, PasswordHistoryView, SecureNoteType, SecureNoteView,
    UriMatchType, VaultClientExt,
};
use chrono::{DateTime, Utc};
use verrou_core::template::{self, Template};
use verrou_core::{SecretString, UriMatch};

use crate::outbox::{Action, request_of};
use crate::{Connection, Decrypted, Error};

/// Old passwords kept per item, like the Bitwarden apps.
pub(crate) const MAX_PASSWORD_HISTORY: usize = 5;

/// What the edit screen modifies. A draft with `login` creates a
/// login, with `card` a card, with `identity` an identity; with
/// none of the three, a secure note.
#[derive(Clone, Debug, Default)]
pub struct Draft {
    pub name: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub notes: Option<SecretString>,
    pub login: Option<LoginDraft>,
    /// Custom fields, in order, excluding reserved `verrou:…` fields
    /// (never shown, always kept). `None`: leave them alone.
    pub fields: Option<Vec<CustomFieldDraft>>,
    /// Template (Wi-Fi, passport…): set at creation, kept afterwards.
    pub template: Option<Template>,
    /// Payment card: its fields (ignored for another type).
    pub card: Option<CardDraft>,
    /// Identity: its fields (ignored for another type).
    pub identity: Option<IdentityDraft>,
}

/// The fields of a payment card, Bitwarden's. The number and the
/// security code are secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CardDraft {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<SecretString>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<SecretString>,
}

/// The fields of an identity, Bitwarden's. Social security,
/// passport and license numbers: secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityDraft {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub postal_code: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub ssn: Option<SecretString>,
    pub passport_number: Option<SecretString>,
    pub license_number: Option<SecretString>,
}

impl CardDraft {
    fn view(self) -> CardView {
        CardView {
            cardholder_name: text(self.cardholder_name),
            exp_month: text(self.exp_month),
            exp_year: text(self.exp_year),
            code: secret(self.code),
            brand: text(self.brand),
            number: secret(self.number),
        }
    }

    fn of(view: CardView) -> Self {
        Self {
            cardholder_name: view.cardholder_name,
            brand: view.brand,
            number: view.number.map(SecretString::new),
            exp_month: view.exp_month,
            exp_year: view.exp_year,
            code: view.code.map(SecretString::new),
        }
    }
}

impl IdentityDraft {
    fn view(self) -> IdentityView {
        IdentityView {
            title: text(self.title),
            first_name: text(self.first_name),
            middle_name: text(self.middle_name),
            last_name: text(self.last_name),
            address1: text(self.address1),
            address2: text(self.address2),
            address3: text(self.address3),
            city: text(self.city),
            state: text(self.state),
            postal_code: text(self.postal_code),
            country: text(self.country),
            company: text(self.company),
            email: text(self.email),
            phone: text(self.phone),
            ssn: secret(self.ssn),
            username: text(self.username),
            passport_number: secret(self.passport_number),
            license_number: secret(self.license_number),
        }
    }

    fn of(view: IdentityView) -> Self {
        Self {
            title: view.title,
            first_name: view.first_name,
            middle_name: view.middle_name,
            last_name: view.last_name,
            company: view.company,
            email: view.email,
            phone: view.phone,
            username: view.username,
            address1: view.address1,
            address2: view.address2,
            address3: view.address3,
            postal_code: view.postal_code,
            city: view.city,
            state: view.state,
            country: view.country,
            ssn: view.ssn.map(SecretString::new),
            passport_number: view.passport_number.map(SecretString::new),
            license_number: view.license_number.map(SecretString::new),
        }
    }
}

/// Kind of a custom field, Bitwarden's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CustomFieldKind {
    #[default]
    Text,
    /// Hidden on screen.
    Hidden,
    /// Checkbox (`"true"` or `"false"`).
    Boolean,
    /// Refers to a field of the item (username, password…): has no
    /// value of its own, can be moved or deleted but not modified.
    Linked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustomFieldDraft {
    pub name: String,
    pub value: Option<SecretString>,
    pub kind: CustomFieldKind,
    /// Field a linked field points to (Bitwarden numbering: 100
    /// username, 101 password…).
    pub linked_id: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct LoginDraft {
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub totp: Option<SecretString>,
    pub uris: Vec<String>,
    /// Match rule of each site, in the order of `uris`
    /// (`None` in the list: default rule). `None`: each kept site
    /// keeps its rule (drafts that don't show it).
    pub uri_matches: Option<Vec<Option<UriMatch>>>,
}

impl Connection {
    /// Prefilled draft to modify an item.
    pub async fn draft(&self, id: &str) -> Result<Draft, Error> {
        self.editable_view(&self.resolve(id)).await.map(draft_of)
    }

    /// Creates the item in the personal vault, under a provisional
    /// id (the server's replaces it when sent, see `resolve`);
    /// returns that id and the displayed vault.
    pub async fn create(&mut self, draft: Draft) -> Result<(String, Decrypted), Error> {
        let view = new_view(draft, Utc::now())?;
        self.queue_save(None, view).await
    }

    pub async fn update(&mut self, id: &str, draft: Draft) -> Result<Decrypted, Error> {
        let id = self.resolve(id);
        let mut view = self.editable_view(&id).await?;
        apply(&mut view, draft, Utc::now())?;
        Ok(self.queue_save(Some(&id), view).await?.1)
    }

    /// Replaces, in an existing login, what is provided: the
    /// password (the old one joins the history), the TOTP seed, and the username
    /// only if there is none. The rest of the item goes back intact.
    /// This is the browser extension's write.
    pub async fn amend_login(
        &mut self,
        id: &str,
        username: Option<String>,
        password: Option<SecretString>,
        totp: Option<SecretString>,
        uri: Option<String>,
    ) -> Result<Decrypted, Error> {
        let mut draft = self.draft(id).await?;
        let Some(login) = draft.login.as_mut() else {
            return Err(Error::Invalid("this item is not a login".to_owned()));
        };
        if login.username.as_deref().is_none_or(str::is_empty) && username.is_some() {
            login.username = username;
        }
        if password.is_some() {
            login.password = password;
        }
        if totp.is_some() {
            login.totp = totp;
        }
        if let Some(uri) = uri.filter(|u| !login.uris.contains(u)) {
            login.uris.push(uri);
        }
        self.update(id, draft).await
    }

    /// Server trash: the item can be restored from the web vault
    /// for 30 days (Vaultwarden setting).
    pub async fn trash(&mut self, id: &str) -> Result<Decrypted, Error> {
        let id = self.resolve(id);
        let view = self.editable_view(&id).await?;
        self.queue_action(&id, view.name, Action::Trash).await
    }

    /// Archives the item (or takes it out of the archive): it leaves the main
    /// list and autofill, without being deleted.
    pub async fn set_archived(&mut self, id: &str, archived: bool) -> Result<Decrypted, Error> {
        let id = self.resolve(id);
        let view = self.editable_view(&id).await?;
        let action = if archived {
            Action::Archive
        } else {
            Action::Unarchive
        };
        self.queue_action(&id, view.name, action).await
    }

    /// Takes the item out of the trash.
    pub async fn restore(&mut self, id: &str) -> Result<Decrypted, Error> {
        let id = self.resolve(id);
        let title = self.cached_title(&id).await?;
        self.queue_action(&id, title, Action::Restore).await
    }

    pub async fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<Decrypted, Error> {
        let id = self.resolve(id);
        let mut view = self.editable_view(&id).await?;
        view.favorite = favorite;
        Ok(self.queue_save(Some(&id), view).await?.1)
    }

    /// The item as the displayed vault knows it (cache and offline
    /// modifications), decrypted, if it can be modified.
    pub(crate) async fn editable_view(&self, id: &str) -> Result<CipherView, Error> {
        let mut views = self.editable_views(&[id.to_owned()]).await?;
        views.pop().ok_or(Error::NotFound)
    }

    /// Several items, in the requested order, reading the cache
    /// only once. A single one missing or read-only, and nothing is
    /// returned.
    pub(crate) async fn editable_views(&self, ids: &[String]) -> Result<Vec<CipherView>, Error> {
        let mut ciphers: HashMap<String, _> = self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| Some((c.id?.to_string(), c)))
            .collect();
        let mut views = Vec::with_capacity(ids.len());
        for id in ids {
            let cipher = ciphers.remove(id).ok_or(Error::NotFound)?;
            let view = self
                .sdk
                .vault()
                .ciphers()
                .decrypt(cipher)
                .await
                .map_err(Error::crypto)?;
            if !view.edit || view.partial || view.deleted_date.is_some() {
                return Err(Error::ReadOnly);
            }
            views.push(view);
        }
        Ok(views)
    }

    pub(crate) async fn encrypt(&self, view: CipherView) -> Result<CipherRequestModel, Error> {
        request_of(self.encrypt_context(view).await?)
    }
}

pub(crate) fn folder_id(id: Option<String>) -> Result<Option<FolderId>, Error> {
    id.filter(|f| !f.is_empty())
        .map(|f| {
            f.parse()
                .map_err(|_| Error::Storage(format!("unknown folder ({f})")))
        })
        .transpose()
}

fn text(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

fn secret(value: Option<SecretString>) -> Option<String> {
    text(value.map(|v| v.expose().to_owned()))
}

fn uris(
    list: Vec<String>,
    matches: Option<&[Option<UriMatch>]>,
    previous: &[LoginUriView],
) -> Option<Vec<LoginUriView>> {
    let uris: Vec<LoginUriView> = list
        .into_iter()
        .enumerate()
        .map(|(i, u)| (i, u.trim().to_owned()))
        .filter(|(_, u)| !u.is_empty())
        .map(|(index, uri)| {
            // The rule chosen in the editor; otherwise, a kept site keeps
            // its own. A new app address (`macapp://`) never
            // matches a web page in the Bitwarden
            // extensions: rule "never".
            let chosen = matches.map(|m| {
                m.get(index)
                    .copied()
                    .flatten()
                    .map(crate::convert::uri_match_type)
            });
            let rule = match chosen {
                Some(Some(rule)) => Some(rule),
                Some(None) => verrou_core::apps::is_app_uri(&uri).then_some(UriMatchType::Never),
                None => previous
                    .iter()
                    .find(|p| p.uri.as_deref() == Some(uri.as_str()))
                    .map_or_else(
                        || verrou_core::apps::is_app_uri(&uri).then_some(UriMatchType::Never),
                        |p| p.r#match,
                    ),
            };
            LoginUriView {
                uri: Some(uri),
                r#match: rule,
                uri_checksum: None,
            }
        })
        .collect();
    (!uris.is_empty()).then_some(uris)
}

/// The reserved field that names the template.
fn marker(template: Template) -> FieldView {
    FieldView {
        name: Some(template::MARKER.to_owned()),
        value: Some(template.key().to_owned()),
        r#type: FieldType::Text,
        linked_id: None,
    }
}

fn is_reserved(field: &FieldView) -> bool {
    field.name.as_deref().is_some_and(template::is_reserved)
}

pub(crate) fn field_view(field: CustomFieldDraft) -> Result<FieldView, Error> {
    if template::is_reserved(field.name.trim()) {
        return Err(Error::Invalid(format!(
            "\"{}\" is a name reserved for Verrou",
            field.name.trim()
        )));
    }
    let value = secret(field.value);
    let (r#type, value, linked_id) = match field.kind {
        CustomFieldKind::Text => (FieldType::Text, value, None),
        CustomFieldKind::Hidden => (FieldType::Hidden, value, None),
        CustomFieldKind::Boolean => {
            let checked = value.as_deref() == Some("true");
            (FieldType::Boolean, Some(checked.to_string()), None)
        }
        CustomFieldKind::Linked => {
            let id = field
                .linked_id
                .ok_or_else(|| Error::Invalid("linked field without a target".to_owned()))?;
            let linked = id
                .try_into()
                .map_err(|_| Error::Invalid(format!("unknown linked field ({id})")))?;
            (FieldType::Linked, None, Some(linked))
        }
    };
    Ok(FieldView {
        name: Some(field.name),
        value,
        r#type,
        linked_id,
    })
}

/// The draft's fields, followed by the item's reserved fields (taken
/// as is) and the template field if missing.
fn merge_fields(
    drafted: Vec<CustomFieldDraft>,
    previous: Option<Vec<FieldView>>,
    template: Option<Template>,
) -> Result<Option<Vec<FieldView>>, Error> {
    let mut fields = drafted
        .into_iter()
        .map(field_view)
        .collect::<Result<Vec<_>, _>>()?;
    fields.extend(previous.into_iter().flatten().filter(is_reserved));
    if let Some(template) = template
        && !fields
            .iter()
            .any(|f| f.name.as_deref() == Some(template::MARKER))
    {
        fields.push(marker(template));
    }
    Ok((!fields.is_empty()).then_some(fields))
}

fn custom_field(field: FieldView) -> CustomFieldDraft {
    let kind = match field.r#type {
        FieldType::Text => CustomFieldKind::Text,
        FieldType::Hidden => CustomFieldKind::Hidden,
        FieldType::Boolean => CustomFieldKind::Boolean,
        FieldType::Linked => CustomFieldKind::Linked,
    };
    CustomFieldDraft {
        name: field.name.unwrap_or_default(),
        value: field.value.map(SecretString::new),
        kind,
        linked_id: field.linked_id.map(u32::from),
    }
}

pub(crate) fn new_view(draft: Draft, now: DateTime<Utc>) -> Result<CipherView, Error> {
    let name = draft.name.trim().to_owned();
    if name.is_empty() {
        return Err(Error::Invalid("the title is required".to_owned()));
    }
    let mut card = None;
    let mut identity = None;
    let (r#type, login, secure_note) = match draft.login {
        None if draft.card.is_some() => {
            card = draft.card.map(CardDraft::view);
            (CipherType::Card, None, None)
        }
        None if draft.identity.is_some() => {
            identity = draft.identity.map(IdentityDraft::view);
            (CipherType::Identity, None, None)
        }
        Some(d) => {
            let mut login = LoginView {
                username: text(d.username),
                password: secret(d.password),
                password_revision_date: None,
                uris: uris(d.uris, d.uri_matches.as_deref(), &[]),
                totp: secret(d.totp),
                autofill_on_page_load: None,
                fido2_credentials: None,
            };
            login.generate_checksums();
            (CipherType::Login, Some(login), None)
        }
        None => (
            CipherType::SecureNote,
            None,
            Some(SecureNoteView {
                r#type: SecureNoteType::Generic,
            }),
        ),
    };
    let fields = merge_fields(draft.fields.unwrap_or_default(), None, draft.template)?;
    Ok(CipherView {
        id: None,
        organization_id: None,
        folder_id: folder_id(draft.folder_id)?,
        collection_ids: Vec::new(),
        key: None,
        name,
        notes: secret(draft.notes),
        r#type,
        login,
        identity,
        card,
        secure_note,
        ssh_key: None,
        bank_account: None,
        drivers_license: None,
        passport: None,
        favorite: draft.favorite,
        reprompt: CipherRepromptType::None,
        organization_use_totp: false,
        edit: true,
        permissions: None,
        view_password: true,
        local_data: None,
        attachments: None,
        attachment_decryption_failures: None,
        fields,
        password_history: None,
        creation_date: now,
        deleted_date: None,
        revision_date: now,
        archived_date: None,
        partial: false,
    })
}

/// What the edit screen shows of an item.
pub(crate) fn draft_of(view: CipherView) -> Draft {
    let template = view
        .fields
        .iter()
        .flatten()
        .find(|f| f.name.as_deref() == Some(template::MARKER))
        .and_then(|f| Template::from_key(f.value.as_deref()?));
    let fields = view
        .fields
        .into_iter()
        .flatten()
        .filter(|f| !is_reserved(f))
        .map(custom_field)
        .collect();
    Draft {
        fields: Some(fields),
        template,
        card: view.card.map(CardDraft::of),
        identity: view.identity.map(IdentityDraft::of),
        name: view.name,
        folder_id: view.folder_id.map(|f| f.to_string()),
        favorite: view.favorite,
        notes: view.notes.filter(|n| !n.is_empty()).map(SecretString::new),
        login: view.login.map(|login| LoginDraft {
            username: login.username,
            password: login.password.map(SecretString::new),
            totp: login.totp.map(SecretString::new),
            uri_matches: Some(
                login
                    .uris
                    .iter()
                    .flatten()
                    .filter(|u| u.uri.is_some())
                    .map(|u| u.r#match.map(crate::convert::uri_match))
                    .collect(),
            ),
            uris: login
                .uris
                .into_iter()
                .flatten()
                .filter_map(|u| u.uri)
                .collect(),
        }),
    }
}

/// Applies the draft to the item. A replaced password joins
/// the item's history.
pub(crate) fn apply(view: &mut CipherView, draft: Draft, now: DateTime<Utc>) -> Result<(), Error> {
    let name = draft.name.trim().to_owned();
    if name.is_empty() {
        return Err(Error::Invalid("the title is required".to_owned()));
    }
    view.name = name;
    view.folder_id = folder_id(draft.folder_id)?;
    view.favorite = draft.favorite;
    view.notes = secret(draft.notes);
    if let Some(fields) = draft.fields {
        view.fields = merge_fields(fields, view.fields.take(), draft.template)?;
    }
    if let (Some(card), Some(_)) = (draft.card, view.card.as_ref()) {
        view.card = Some(card.view());
    }
    if let (Some(identity), Some(_)) = (draft.identity, view.identity.as_ref()) {
        view.identity = Some(identity.view());
    }
    let (Some(d), Some(login)) = (draft.login, view.login.as_mut()) else {
        return Ok(());
    };
    let password = secret(d.password);
    if let Some(old) = login
        .password
        .take()
        .filter(|old| Some(old) != password.as_ref())
    {
        let mut history = vec![PasswordHistoryView {
            password: old,
            last_used_date: now,
        }];
        history.extend(view.password_history.take().into_iter().flatten());
        history.truncate(MAX_PASSWORD_HISTORY);
        view.password_history = Some(history);
        login.password_revision_date = Some(now);
    }
    login.password = password;
    login.username = text(d.username);
    login.totp = secret(d.totp);
    login.uris = uris(
        d.uris,
        d.uri_matches.as_deref(),
        login.uris.as_deref().unwrap_or_default(),
    );
    login.generate_checksums();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_draft(password: &str) -> Draft {
        Draft {
            name: " Exemple ".to_owned(),
            login: Some(LoginDraft {
                uri_matches: None,
                username: Some("camille".to_owned()),
                password: Some(SecretString::new(password)),
                totp: None,
                uris: vec!["https://exemple.fr".to_owned(), "  ".to_owned()],
            }),
            ..Draft::default()
        }
    }

    #[test]
    fn new_login_is_trimmed_and_personal() {
        let view = new_view(login_draft("un"), Utc::now()).unwrap();
        assert_eq!(view.name, "Exemple");
        assert_eq!(view.r#type, CipherType::Login);
        assert!(view.organization_id.is_none());
        let login = view.login.unwrap();
        assert_eq!(login.uris.unwrap().len(), 1);
        assert!(login.totp.is_none());
    }

    #[test]
    fn app_uris_never_match_web_pages_in_bitwarden() {
        let mut draft = login_draft("un");
        draft.login.as_mut().unwrap().uris = vec![
            "https://slack.com".to_owned(),
            "macapp://com.tinyspeck.slackmacgap".to_owned(),
        ];
        let view = new_view(draft.clone(), Utc::now()).unwrap();
        let uris = view.login.as_ref().unwrap().uris.clone().unwrap();
        assert_eq!(uris[0].r#match, None);
        assert_eq!(uris[1].r#match, Some(UriMatchType::Never));
        // A rule chosen elsewhere for this address is kept.
        let previous = vec![LoginUriView {
            uri: Some("macapp://com.tinyspeck.slackmacgap".to_owned()),
            r#match: Some(UriMatchType::Exact),
            uri_checksum: None,
        }];
        let kept = uris_from(&draft, &previous);
        assert_eq!(kept[1].r#match, Some(UriMatchType::Exact));
    }

    fn uris_from(draft: &Draft, previous: &[LoginUriView]) -> Vec<LoginUriView> {
        let login = draft.login.as_ref().unwrap();
        uris(login.uris.clone(), login.uri_matches.as_deref(), previous).unwrap()
    }

    #[test]
    fn card_and_identity_drafts_round_trip() {
        let now = Utc::now();
        let card = CardDraft {
            cardholder_name: Some("CAMILLE MARTIN".to_owned()),
            brand: Some("Visa".to_owned()),
            number: Some(SecretString::new("4242424242424242")),
            exp_month: Some("9".to_owned()),
            exp_year: Some("2029".to_owned()),
            code: Some(SecretString::new("123")),
        };
        let mut view = new_view(
            Draft {
                name: "Visa".to_owned(),
                card: Some(card.clone()),
                ..Draft::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(view.r#type, CipherType::Card);
        assert!(view.secure_note.is_none() && view.login.is_none());
        let mut draft = draft_of(view.clone());
        assert_eq!(draft.card.as_ref(), Some(&card));
        // Modify: the erased security code disappears, the rest is kept.
        draft.card.as_mut().unwrap().code = Some(SecretString::new("  "));
        draft.card.as_mut().unwrap().exp_year = Some("2031".to_owned());
        apply(&mut view, draft, now).unwrap();
        let saved = view.card.clone().unwrap();
        assert_eq!(saved.code, None);
        assert_eq!(saved.exp_year.as_deref(), Some("2031"));
        assert_eq!(saved.number.as_deref(), Some("4242424242424242"));

        let identity = IdentityDraft {
            first_name: Some("Camille".to_owned()),
            last_name: Some("Martin".to_owned()),
            city: Some("Annecy".to_owned()),
            passport_number: Some(SecretString::new("12AB34567")),
            ..IdentityDraft::default()
        };
        let mut view = new_view(
            Draft {
                name: "Moi".to_owned(),
                identity: Some(identity.clone()),
                ..Draft::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(view.r#type, CipherType::Identity);
        let mut draft = draft_of(view.clone());
        assert_eq!(draft.identity.as_ref(), Some(&identity));
        draft.identity.as_mut().unwrap().email = Some("camille@exemple.fr".to_owned());
        apply(&mut view, draft, now).unwrap();
        let saved = view.identity.unwrap();
        assert_eq!(saved.email.as_deref(), Some("camille@exemple.fr"));
        assert_eq!(saved.passport_number.as_deref(), Some("12AB34567"));
    }

    #[test]
    fn card_fields_never_turn_a_login_into_a_card() {
        let now = Utc::now();
        let mut view = new_view(login_draft("un"), now).unwrap();
        let mut draft = login_draft("un");
        draft.card = Some(CardDraft::default());
        apply(&mut view, draft, now).unwrap();
        assert_eq!(view.r#type, CipherType::Login);
        assert!(view.card.is_none());
    }

    #[test]
    fn draft_without_login_is_a_note_and_title_is_required() {
        let note = new_view(
            Draft {
                name: "Wi-Fi".to_owned(),
                ..Draft::default()
            },
            Utc::now(),
        )
        .unwrap();
        assert_eq!(note.r#type, CipherType::SecureNote);
        assert!(matches!(
            new_view(Draft::default(), Utc::now()),
            Err(Error::Invalid(_))
        ));
    }

    fn field(name: &str, value: &str, kind: CustomFieldKind) -> CustomFieldDraft {
        CustomFieldDraft {
            name: name.to_owned(),
            value: Some(SecretString::new(value)),
            kind,
            linked_id: None,
        }
    }

    fn view_field(name: &str, value: Option<&str>, r#type: FieldType) -> FieldView {
        FieldView {
            name: Some(name.to_owned()),
            value: value.map(str::to_owned),
            r#type,
            linked_id: None,
        }
    }

    #[test]
    fn template_marker_is_written_and_kept_out_of_the_draft() {
        let view = new_view(
            Draft {
                name: "Maison".to_owned(),
                template: Some(Template::Wifi),
                fields: Some(vec![
                    field("Nom du réseau (SSID)", "Martin-5G", CustomFieldKind::Text),
                    field("Mot de passe", "lilas", CustomFieldKind::Hidden),
                    field("Invités", "true", CustomFieldKind::Boolean),
                ]),
                ..Draft::default()
            },
            Utc::now(),
        )
        .unwrap();
        assert_eq!(view.r#type, CipherType::SecureNote);
        let fields = view.fields.clone().unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[1].r#type, FieldType::Hidden);
        assert_eq!(fields[2].value.as_deref(), Some("true"));
        assert_eq!(fields[3].name.as_deref(), Some("verrou:type"));
        assert_eq!(fields[3].value.as_deref(), Some("wifi"));
        assert_eq!(fields[3].r#type, FieldType::Text);

        let draft = draft_of(view);
        assert_eq!(draft.template, Some(Template::Wifi));
        let drafted = draft.fields.unwrap();
        assert_eq!(drafted.len(), 3, "the reserved field is not editable");
        assert_eq!(drafted[1].kind, CustomFieldKind::Hidden);
        assert_eq!(drafted[1].value.as_ref().unwrap().expose(), "lilas");
    }

    #[test]
    fn edited_fields_keep_reserved_ones_untouched() {
        let now = Utc::now();
        let mut linked = view_field("Mot de passe (lié)", None, FieldType::Linked);
        linked.linked_id = Some(101u32.try_into().unwrap());
        let original = vec![
            view_field("verrou:type", Some("server"), FieldType::Text),
            view_field("Port", Some("22"), FieldType::Text),
            linked,
        ];
        let mut view = new_view(login_draft("un"), now).unwrap();
        view.fields = Some(original.clone());
        let mut draft = draft_of(view.clone());
        assert_eq!(draft.template, Some(Template::Server));
        let mut fields = draft.fields.take().unwrap();
        assert_eq!(fields[1].kind, CustomFieldKind::Linked);
        assert_eq!(fields[1].linked_id, Some(101));
        // Rename, reorder, add.
        "Port SSH".clone_into(&mut fields[0].name);
        fields.swap(0, 1);
        fields.push(field("Clé", "abc", CustomFieldKind::Hidden));
        draft.fields = Some(fields);
        apply(&mut view, draft, now).unwrap();
        let fields = view.fields.clone().unwrap();
        let names: Vec<_> = fields.iter().map(|f| f.name.clone().unwrap()).collect();
        assert_eq!(
            names,
            ["Mot de passe (lié)", "Port SSH", "Clé", "verrou:type"]
        );
        assert_eq!(fields[0].linked_id.map(u32::from), Some(101));
        assert_eq!(fields[3].value.as_deref(), Some("server"));

        // Deleting everything keeps the reserved field; `None` touches nothing.
        let mut draft = login_draft("un");
        draft.fields = Some(Vec::new());
        apply(&mut view, draft, now).unwrap();
        assert_eq!(view.fields.as_ref().unwrap().len(), 1);
        apply(&mut view, login_draft("un"), now).unwrap();
        assert_eq!(view.fields.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn reserved_names_are_refused() {
        let draft = Draft {
            name: "Note".to_owned(),
            fields: Some(vec![field("verrou:type", "wifi", CustomFieldKind::Text)]),
            ..Draft::default()
        };
        assert!(matches!(
            new_view(draft, Utc::now()),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn replaced_password_goes_to_history() {
        let now = Utc::now();
        let mut view = new_view(login_draft("ancien"), now).unwrap();
        apply(&mut view, login_draft("ancien"), now).unwrap();
        assert!(view.password_history.is_none(), "unchanged: no history");
        for n in 0..7 {
            apply(&mut view, login_draft(&format!("nouveau-{n}")), now).unwrap();
        }
        let history = view.password_history.unwrap();
        assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
        assert_eq!(history[0].password, "nouveau-5");
        assert_eq!(view.login.unwrap().password.as_deref(), Some("nouveau-6"));
    }
}
