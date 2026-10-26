//! Item templates (Wi-Fi, passport…) and custom fields, Swift side. See
//! `verrou_core::template`.

use verrou_core::SecretString;
use verrou_core::template::{self, Template};
use verrou_vaultwarden::{CustomFieldDraft, CustomFieldKind, LoginDraft};

use crate::{ItemDraft, LoginFields, VaultSession, VerrouError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum ItemTemplate {
    SoftwareLicense,
    Wifi,
    BankAccount,
    Passport,
    DriversLicense,
    IdCard,
    Server,
    Database,
    ApiKey,
    Membership,
}

impl From<Template> for ItemTemplate {
    fn from(template: Template) -> Self {
        match template {
            Template::SoftwareLicense => Self::SoftwareLicense,
            Template::Wifi => Self::Wifi,
            Template::BankAccount => Self::BankAccount,
            Template::Passport => Self::Passport,
            Template::DriversLicense => Self::DriversLicense,
            Template::IdCard => Self::IdCard,
            Template::Server => Self::Server,
            Template::Database => Self::Database,
            Template::ApiKey => Self::ApiKey,
            Template::Membership => Self::Membership,
        }
    }
}

impl From<ItemTemplate> for Template {
    fn from(template: ItemTemplate) -> Self {
        match template {
            ItemTemplate::SoftwareLicense => Self::SoftwareLicense,
            ItemTemplate::Wifi => Self::Wifi,
            ItemTemplate::BankAccount => Self::BankAccount,
            ItemTemplate::Passport => Self::Passport,
            ItemTemplate::DriversLicense => Self::DriversLicense,
            ItemTemplate::IdCard => Self::IdCard,
            ItemTemplate::Server => Self::Server,
            ItemTemplate::Database => Self::Database,
            ItemTemplate::ApiKey => Self::ApiKey,
            ItemTemplate::Membership => Self::Membership,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemTemplateCount {
    pub template: ItemTemplate,
    pub count: u32,
}

/// Kind of a custom field (Bitwarden's).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum CustomFieldType {
    #[default]
    Text,
    Hidden,
    /// Checkbox: value `"true"` or `"false"`.
    Boolean,
    /// Refers to another field of the item: shown, never edited.
    Linked,
}

/// A custom field in the edit screen. Fields reserved for Verrou
/// (`verrou:…`) never appear there: they are kept on save.
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct CustomField {
    pub name: String,
    pub value: Option<String>,
    pub field_type: CustomFieldType,
    /// Field a linked field points to (Bitwarden's numbering).
    pub linked_id: Option<u32>,
}

impl From<CustomField> for CustomFieldDraft {
    fn from(field: CustomField) -> Self {
        Self {
            name: field.name,
            value: field.value.map(SecretString::new),
            kind: match field.field_type {
                CustomFieldType::Text => CustomFieldKind::Text,
                CustomFieldType::Hidden => CustomFieldKind::Hidden,
                CustomFieldType::Boolean => CustomFieldKind::Boolean,
                CustomFieldType::Linked => CustomFieldKind::Linked,
            },
            linked_id: field.linked_id,
        }
    }
}

impl From<CustomFieldDraft> for CustomField {
    fn from(field: CustomFieldDraft) -> Self {
        Self {
            name: field.name,
            value: field.value.map(|v| v.expose().to_owned()),
            field_type: match field.kind {
                CustomFieldKind::Text => CustomFieldType::Text,
                CustomFieldKind::Hidden => CustomFieldType::Hidden,
                CustomFieldKind::Boolean => CustomFieldType::Boolean,
                CustomFieldKind::Linked => CustomFieldType::Linked,
            },
            linked_id: field.linked_id,
        }
    }
}

/// Is the field reserved for Verrou (never shown)?
pub(crate) fn is_reserved_field(id: &str) -> bool {
    id.starts_with("part:") || template::is_reserved(id)
}

/// Draft of a new item from a template: its predefined fields, empty; a
/// login (with a generated password) for a server, a database or an API
/// key.
#[uniffi::export]
pub fn template_draft(template: ItemTemplate) -> ItemDraft {
    let template = Template::from(template);
    let login = (template.kind() == verrou_core::ItemKind::Login).then(|| LoginDraft {
        password: (template != Template::ApiKey)
            .then(|| SecretString::new(crate::generate_password(24, true, true))),
        ..LoginDraft::default()
    });
    let fields = template
        .fields()
        .iter()
        .map(|f| CustomField {
            name: f.label.to_owned(),
            value: None,
            field_type: if f.hidden {
                CustomFieldType::Hidden
            } else {
                CustomFieldType::Text
            },
            linked_id: None,
        })
        .collect();
    ItemDraft {
        name: String::new(),
        folder_id: None,
        favorite: false,
        notes: None,
        login: login.map(|l| LoginFields {
            username: l.username,
            password: l.password.map(|p| p.expose().to_owned()),
            totp: None,
            urls: Vec::new(),
            url_matches: None,
        }),
        fields,
        template: Some(template.into()),
        ..ItemDraft::default()
    }
}

#[uniffi::export]
impl VaultSession {
    /// ⚠️ Content of a Wi-Fi network's QR code (`WIFI:T:WPA;S:…;P:…;;`):
    /// contains the password, only when the user shows the QR code. A
    /// protected item asks for confirmation first; an organization that
    /// hides passwords refuses it.
    pub fn wifi_qr_code(&self, id: String) -> Result<String, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, self.local_id(&id)?)?;
            if item.template() != Some(Template::Wifi) {
                return Err(VerrouError::NotFound);
            }
            if item
                .field_labelled(template::WIFI_PASSWORD)
                .is_some_and(|f| item.hides(f))
            {
                return Err(crate::hidden_by_organization());
            }
            self.require_authorized(item)?;
            let value = |label: &str| {
                item.field_labelled(label)
                    .map(|f| f.value.expose().to_owned())
                    .unwrap_or_default()
            };
            let ssid = Some(value(template::WIFI_SSID))
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| item.title.clone());
            Ok(template::wifi_qr_payload(
                &ssid,
                &value(template::WIFI_PASSWORD),
                &value(template::WIFI_SECURITY),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResultOrder, SidebarFilter};

    #[test]
    fn template_drafts_carry_their_fields() {
        let wifi = template_draft(ItemTemplate::Wifi);
        assert!(wifi.login.is_none());
        assert_eq!(wifi.template, Some(ItemTemplate::Wifi));
        assert_eq!(wifi.fields[1].name, template::WIFI_PASSWORD);
        assert_eq!(wifi.fields[1].field_type, CustomFieldType::Hidden);
        let server = template_draft(ItemTemplate::Server);
        assert!(server.login.unwrap().password.is_some());
        let api = template_draft(ItemTemplate::ApiKey);
        assert!(api.login.unwrap().password.is_none());
    }

    #[test]
    fn wifi_is_listed_and_gives_its_qr_code() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
        let counts = session.counts().unwrap();
        assert_eq!(counts.templates.len(), 1);
        assert_eq!(counts.templates[0].template, ItemTemplate::Wifi);
        let summaries = session.summaries().unwrap();
        let wifi = summaries
            .iter()
            .find(|s| s.template == Some(ItemTemplate::Wifi))
            .unwrap();
        let filter = SidebarFilter::Template {
            template: ItemTemplate::Wifi,
        };
        let hits = session
            .search(String::new(), filter, ResultOrder::Title)
            .unwrap();
        assert_eq!(hits.len(), 1);
        let detail = session.detail(wifi.id.clone()).unwrap();
        assert!(detail.fields.iter().all(|f| !f.id.starts_with("verrou:")));
        let password = detail
            .fields
            .iter()
            .find(|f| f.label == template::WIFI_PASSWORD)
            .unwrap();
        assert!(password.secret && password.value.is_none());
        assert_eq!(
            session.wifi_qr_code(wifi.id.clone()).unwrap(),
            "WIFI:T:WPA;S:Parker-5G;P:maple-porch-27;;"
        );
        let other = summaries.iter().find(|s| s.template.is_none()).unwrap();
        assert!(session.wifi_qr_code(other.id.clone()).is_err());
    }
}
