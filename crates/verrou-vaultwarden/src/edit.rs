//! Écriture dans le coffre : créer, modifier, mettre à la corbeille.
//!
//! Même répartition que pour la lecture : le SDK chiffre (`CipherView` →
//! `Cipher` → requête d'API), Verrou envoie la requête. Une modification part
//! de l'élément tel que le cache le connaît, déchiffré, et ne touche qu'aux
//! champs que Verrou sait éditer : le reste (passkeys, pièces jointes,
//! historique, champs réservés `verrou:…`) repart intact. La date de
//! révision envoyée permet au serveur de refuser une modification faite sur
//! une copie périmée.

use std::collections::HashMap;

use bitwarden_api_api::models::{CipherRequestModel, SyncResponseModel};
use bitwarden_vault::{
    Cipher, CipherRepromptType, CipherType, CipherView, FieldType, FieldView, FolderId,
    LoginUriView, LoginView, PasswordHistoryView, SecureNoteType, SecureNoteView, UriMatchType,
    VaultClientExt,
};
use chrono::{DateTime, Utc};
use verrou_core::SecretString;
use verrou_core::template::{self, Template};

use crate::{Connection, Decrypted, Error};

/// Anciens mots de passe gardés par élément, comme les apps Bitwarden.
const MAX_PASSWORD_HISTORY: usize = 5;

/// Ce que l'écran d'édition modifie. Un brouillon sans `login` crée une note
/// sécurisée.
#[derive(Clone, Debug, Default)]
pub struct Draft {
    pub name: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub notes: Option<SecretString>,
    pub login: Option<LoginDraft>,
    /// Champs personnalisés, dans l'ordre, hors champs réservés `verrou:…`
    /// (jamais montrés, toujours conservés). `None` : ne pas y toucher.
    pub fields: Option<Vec<CustomFieldDraft>>,
    /// Modèle (Wi-Fi, passeport…) : posé à la création, ensuite conservé.
    pub template: Option<Template>,
}

/// Nature d'un champ personnalisé, celle de Bitwarden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CustomFieldKind {
    #[default]
    Text,
    /// Masqué à l'écran.
    Hidden,
    /// Case à cocher (`"true"` ou `"false"`).
    Boolean,
    /// Renvoie à un champ de l'élément (identifiant, mot de passe…) : n'a pas
    /// de valeur propre, se déplace ou se supprime mais ne se modifie pas.
    Linked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustomFieldDraft {
    pub name: String,
    pub value: Option<SecretString>,
    pub kind: CustomFieldKind,
    /// Champ désigné par un champ lié (numérotation de Bitwarden : 100
    /// identifiant, 101 mot de passe…).
    pub linked_id: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct LoginDraft {
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub totp: Option<SecretString>,
    pub uris: Vec<String>,
}

impl Connection {
    /// Brouillon prérempli pour modifier un élément.
    pub async fn draft(&self, id: &str) -> Result<Draft, Error> {
        self.editable_view(id).await.map(draft_of)
    }

    /// Crée l'élément dans le coffre personnel ; rend son identifiant et le
    /// coffre resynchronisé.
    pub async fn create(&mut self, draft: Draft) -> Result<(String, Decrypted), Error> {
        let view = new_view(draft, Utc::now())?;
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        let id = self.api.create_cipher(&access, &request).await?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    pub async fn update(&mut self, id: &str, draft: Draft) -> Result<Decrypted, Error> {
        let mut view = self.editable_view(id).await?;
        apply(&mut view, draft, Utc::now())?;
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        self.api.update_cipher(&access, id, &request).await?;
        self.sync_with(&access).await
    }

    /// Remplace, dans un identifiant existant, ce qui est fourni : le mot de
    /// passe (l'ancien rejoint l'historique), la graine TOTP, et l'identifiant
    /// seulement s'il n'y en a pas. Le reste de l'élément repart intact.
    /// C'est l'écriture de l'extension de navigateur.
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
            return Err(Error::Invalid(
                "cet élément n'est pas un identifiant".to_owned(),
            ));
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

    /// Corbeille du serveur : l'élément se restaure depuis le coffre web
    /// pendant 30 jours (réglage de Vaultwarden).
    pub async fn trash(&mut self, id: &str) -> Result<Decrypted, Error> {
        self.editable_view(id).await?;
        let access = self.access_token().await?;
        self.api.trash_cipher(&access, id).await?;
        self.sync_with(&access).await
    }

    /// Archive l'élément (ou le sort des archives) : il quitte la liste
    /// principale et le remplissage, sans être supprimé.
    pub async fn set_archived(&mut self, id: &str, archived: bool) -> Result<Decrypted, Error> {
        self.editable_view(id).await?;
        let access = self.access_token().await?;
        let action = if archived { "archive" } else { "unarchive" };
        self.api.cipher_action(&access, id, action).await?;
        self.sync_with(&access).await
    }

    /// Sort l'élément de la corbeille.
    pub async fn restore(&mut self, id: &str) -> Result<Decrypted, Error> {
        let access = self.access_token().await?;
        self.api.cipher_action(&access, id, "restore").await?;
        self.sync_with(&access).await
    }

    pub async fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<Decrypted, Error> {
        let mut view = self.editable_view(id).await?;
        view.favorite = favorite;
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        self.api.update_cipher(&access, id, &request).await?;
        self.sync_with(&access).await
    }

    /// L'élément tel que le cache le connaît, déchiffré, s'il peut être modifié.
    pub(crate) async fn editable_view(&self, id: &str) -> Result<CipherView, Error> {
        let mut views = self.editable_views(&[id.to_owned()]).await?;
        views.pop().ok_or(Error::NotFound)
    }

    /// Plusieurs éléments, dans l'ordre demandé, en ne lisant le cache
    /// qu'une fois. Un seul introuvable ou en lecture seule, et rien n'est
    /// rendu.
    pub(crate) async fn editable_views(&self, ids: &[String]) -> Result<Vec<CipherView>, Error> {
        let json = self.account.sync.as_deref().ok_or(Error::NotFound)?;
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("cache illisible ({e})")))?;
        let mut models: HashMap<String, _> = sync
            .ciphers
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| Some((c.id?.to_string(), c)))
            .collect();
        let mut views = Vec::with_capacity(ids.len());
        for id in ids {
            let model = models.remove(id).ok_or(Error::NotFound)?;
            let cipher = Cipher::try_from(model).map_err(Error::crypto)?;
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
        let encrypted = self
            .sdk
            .vault()
            .ciphers()
            .encrypt(view)
            .await
            .map_err(Error::crypto)?;
        let mut request = CipherRequestModel::try_from(encrypted.cipher).map_err(Error::crypto)?;
        request.encrypted_for = Some(encrypted.encrypted_for.into());
        request.encrypted_by_key_id = encrypted.encrypted_by_key_id;
        Ok(request)
    }
}

fn folder_id(id: Option<String>) -> Result<Option<FolderId>, Error> {
    id.filter(|f| !f.is_empty())
        .map(|f| {
            f.parse()
                .map_err(|_| Error::Storage(format!("dossier inconnu ({f})")))
        })
        .transpose()
}

fn text(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

fn secret(value: Option<SecretString>) -> Option<String> {
    text(value.map(|v| v.expose().to_owned()))
}

fn uris(list: Vec<String>, previous: &[LoginUriView]) -> Option<Vec<LoginUriView>> {
    let uris: Vec<LoginUriView> = list
        .into_iter()
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty())
        .map(|uri| {
            // Un site gardé garde sa règle de correspondance. Une nouvelle
            // adresse d'app (`macapp://`) ne correspond jamais à une page web
            // dans les extensions Bitwarden : règle « jamais ».
            let rule = previous
                .iter()
                .find(|p| p.uri.as_deref() == Some(uri.as_str()))
                .map_or_else(
                    || verrou_core::apps::is_app_uri(&uri).then_some(UriMatchType::Never),
                    |p| p.r#match,
                );
            LoginUriView {
                uri: Some(uri),
                r#match: rule,
                uri_checksum: None,
            }
        })
        .collect();
    (!uris.is_empty()).then_some(uris)
}

/// Le champ réservé qui désigne le modèle.
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

fn field_view(field: CustomFieldDraft) -> Result<FieldView, Error> {
    if template::is_reserved(field.name.trim()) {
        return Err(Error::Invalid(format!(
            "« {} » est un nom réservé à Verrou",
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
                .ok_or_else(|| Error::Invalid("champ lié sans cible".to_owned()))?;
            let linked = id
                .try_into()
                .map_err(|_| Error::Invalid(format!("champ lié inconnu ({id})")))?;
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

/// Les champs du brouillon, suivis des champs réservés de l'élément (repris
/// tels quels) et du champ du modèle s'il manque.
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
        return Err(Error::Invalid("le titre est obligatoire".to_owned()));
    }
    let (r#type, login, secure_note) = match draft.login {
        Some(d) => {
            let mut login = LoginView {
                username: text(d.username),
                password: secret(d.password),
                password_revision_date: None,
                uris: uris(d.uris, &[]),
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
        identity: None,
        card: None,
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

/// Ce que l'écran d'édition montre d'un élément.
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
        name: view.name,
        folder_id: view.folder_id.map(|f| f.to_string()),
        favorite: view.favorite,
        notes: view.notes.filter(|n| !n.is_empty()).map(SecretString::new),
        login: view.login.map(|login| LoginDraft {
            username: login.username,
            password: login.password.map(SecretString::new),
            totp: login.totp.map(SecretString::new),
            uris: login
                .uris
                .into_iter()
                .flatten()
                .filter_map(|u| u.uri)
                .collect(),
        }),
    }
}

/// Reporte le brouillon sur l'élément. Un mot de passe remplacé rejoint
/// l'historique de l'élément.
pub(crate) fn apply(view: &mut CipherView, draft: Draft, now: DateTime<Utc>) -> Result<(), Error> {
    let name = draft.name.trim().to_owned();
    if name.is_empty() {
        return Err(Error::Invalid("le titre est obligatoire".to_owned()));
    }
    view.name = name;
    view.folder_id = folder_id(draft.folder_id)?;
    view.favorite = draft.favorite;
    view.notes = secret(draft.notes);
    if let Some(fields) = draft.fields {
        view.fields = merge_fields(fields, view.fields.take(), draft.template)?;
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
    login.uris = uris(d.uris, login.uris.as_deref().unwrap_or_default());
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
        // Une règle choisie ailleurs pour cette adresse est gardée.
        let previous = vec![LoginUriView {
            uri: Some("macapp://com.tinyspeck.slackmacgap".to_owned()),
            r#match: Some(UriMatchType::Exact),
            uri_checksum: None,
        }];
        let kept = uris_from(&draft, &previous);
        assert_eq!(kept[1].r#match, Some(UriMatchType::Exact));
    }

    fn uris_from(draft: &Draft, previous: &[LoginUriView]) -> Vec<LoginUriView> {
        uris(draft.login.as_ref().unwrap().uris.clone(), previous).unwrap()
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
        assert_eq!(drafted.len(), 3, "le champ réservé n'est pas modifiable");
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
        // Renommer, réordonner, ajouter.
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

        // Tout supprimer garde le champ réservé ; `None` ne touche à rien.
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
        assert!(
            view.password_history.is_none(),
            "inchangé : pas d'historique"
        );
        for n in 0..7 {
            apply(&mut view, login_draft(&format!("nouveau-{n}")), now).unwrap();
        }
        let history = view.password_history.unwrap();
        assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
        assert_eq!(history[0].password, "nouveau-5");
        assert_eq!(view.login.unwrap().password.as_deref(), Some("nouveau-6"));
    }
}
