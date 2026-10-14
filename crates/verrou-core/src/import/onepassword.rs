//! Export 1PUX de 1Password : une archive ZIP dont `export.data` décrit
//! comptes → coffres → éléments.
//!
//! Identifiants (et « mots de passe » seuls), notes sécurisées, cartes
//! bancaires et identités sont repris tels quels ; licences, routeurs Wi-Fi,
//! comptes bancaires, passeports, permis, serveurs, bases de données, clés
//! API et adhésions deviennent les modèles de Verrou correspondants (voir
//! [`crate::template`]). Les autres catégories deviennent des notes
//! sécurisées dont les notes reprennent les champs. Un document devient une
//! note sécurisée avec son fichier en pièce jointe ; les fichiers joints aux
//! autres éléments suivent aussi (`files/<documentId>__<nom>` dans l'archive).

use serde_json::Value;

use super::{
    CardData, ExtraField, IdentityData, ImportError, ImportKind, ImportedFile, ImportedItem,
    Parsed, append_lines, date_of, expiry, secret, template_fields, text,
};
use crate::template::{Template, WIFI_PASSWORD, WIFI_SECURITY, WIFI_SSID};

const LOGIN: &str = "001";
const CARD: &str = "002";
const NOTE: &str = "003";
const PASSWORD: &str = "005";

/// Fichiers d'un élément : celui d'un document (`documentAttributes`) et
/// ceux des champs de type fichier. Leur contenu est lu ensuite dans
/// l'archive.
fn files(details: &Value) -> Vec<ImportedFile> {
    let document = details.get("documentAttributes").into_iter();
    let fields = array(details, "sections")
        .flat_map(|section| array(section, "fields"))
        .filter_map(|field| field.pointer("/value/file"));
    let mut files: Vec<ImportedFile> = Vec::new();
    for attributes in document.chain(fields) {
        let Some(id) = text(attributes.get("documentId").and_then(Value::as_str)) else {
            continue;
        };
        let name = text(attributes.get("fileName").and_then(Value::as_str))
            .unwrap_or_else(|| "fichier".to_owned());
        if files
            .iter()
            .all(|f| f.reference.as_deref() != Some(id.as_str()))
        {
            files.push(ImportedFile::pending(&name, id));
        }
    }
    files
}

/// `files/<documentId>__<nom>` (deux ou trois tirets bas, selon les versions).
pub(super) fn archive_entry(name: &str, document_id: &str) -> bool {
    name.strip_prefix("files/")
        .and_then(|rest| rest.strip_prefix(document_id))
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('_'))
}

const IDENTITY: &str = "004";

/// Catégories de 1Password qui ont un modèle dans Verrou.
fn template_of(category: &str) -> Option<Template> {
    Some(match category {
        "100" => Template::SoftwareLicense,
        "101" => Template::BankAccount,
        "102" => Template::Database,
        "103" => Template::DriversLicense,
        "105" => Template::Membership,
        "106" => Template::Passport,
        "109" => Template::Wifi,
        "110" => Template::Server,
        "112" => Template::ApiKey,
        _ => return None,
    })
}

/// Champs de 1Password (identifiant de champ) → libellés du modèle.
fn field_map(template: Template) -> &'static [(&'static str, &'static str)] {
    match template {
        Template::SoftwareLicense => &[
            ("product_version", "Version"),
            ("reg_code", "Clé de licence"),
            ("reg_name", "Licencié à"),
            ("reg_email", "E-mail"),
            ("publisher_name", "Éditeur"),
            ("order_date", "Date d'achat"),
            ("order_number", "Numéro de commande"),
        ],
        Template::BankAccount => &[
            ("bankName", "Banque"),
            ("owner", "Titulaire"),
            ("accountType", "Type de compte"),
            ("iban", "IBAN"),
            ("swift", "BIC"),
            ("accountNo", "Numéro de compte"),
            ("telephonePin", "Code PIN"),
        ],
        Template::Database => &[
            ("database_type", "Type"),
            ("port", "Port"),
            ("database", "Base"),
            ("options", "Options de connexion"),
        ],
        Template::DriversLicense => &[
            ("number", "Numéro"),
            ("fullname", "Nom"),
            ("birthdate", "Date de naissance"),
            ("class", "Catégories"),
            ("expiry_date", "Date d'expiration"),
            ("country", "Pays ou région"),
        ],
        Template::Membership => &[
            ("org_name", "Organisation"),
            ("member_name", "Membre"),
            ("membership_no", "Numéro de membre"),
            ("member_since", "Membre depuis"),
            ("expiry_date", "Date d'expiration"),
            ("pin", "Code PIN"),
            ("phone", "Téléphone"),
        ],
        Template::Passport => &[
            ("number", "Numéro"),
            ("fullname", "Nom"),
            ("nationality", "Nationalité"),
            ("birthdate", "Date de naissance"),
            ("birthplace", "Lieu de naissance"),
            ("sex", "Sexe"),
            ("issue_date", "Date de délivrance"),
            ("expiry_date", "Date d'expiration"),
            ("issuing_authority", "Autorité de délivrance"),
        ],
        Template::Wifi => &[
            ("network_name", WIFI_SSID),
            ("wireless_password", WIFI_PASSWORD),
            ("wireless_security", WIFI_SECURITY),
        ],
        Template::Server => &[
            ("name", "Hébergeur"),
            ("admin_console_url", "Console d'administration"),
            ("admin_console_username", "Identifiant de la console"),
            ("admin_console_password", "Mot de passe de la console"),
        ],
        Template::ApiKey => &[("type", "Type"), ("expires", "Date d'expiration")],
        Template::IdCard => &[],
    }
}

/// Champs d'un modèle « identifiant » : (identifiant, mot de passe, site).
fn login_ids(template: Template) -> Option<(&'static str, &'static str, &'static str)> {
    match template {
        Template::Server => Some(("username", "password", "url")),
        Template::Database => Some(("username", "password", "hostname")),
        Template::ApiKey => Some(("username", "credential", "hostname")),
        _ => None,
    }
}

/// `wpa2p` → `WPA2 Personnel` : la sécurité d'un routeur, lisible.
fn wireless_security(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "none" => "Aucune".to_owned(),
        "wep" => "WEP".to_owned(),
        "wpap" => "WPA Personnel".to_owned(),
        "wpae" => "WPA Entreprise".to_owned(),
        "wpa2p" => "WPA2 Personnel".to_owned(),
        "wpa2e" => "WPA2 Entreprise".to_owned(),
        "wpa3p" => "WPA3 Personnel".to_owned(),
        "wpa3e" => "WPA3 Entreprise".to_owned(),
        _ => value.trim().to_owned(),
    }
}

pub(super) fn parse(json: &Value, parsed: &mut Parsed) -> Result<(), ImportError> {
    let accounts = json
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or(ImportError::WrongFormat(parsed.format.label()))?;
    for account in accounts {
        for vault in array(account, "vaults") {
            let vault_name = text(vault.pointer("/attrs/name").and_then(Value::as_str));
            for entry in array(vault, "items") {
                item(entry, vault_name.as_ref(), parsed);
            }
        }
    }
    Ok(())
}

fn array<'v>(value: &'v Value, key: &str) -> impl Iterator<Item = &'v Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn str_at<'v>(value: &'v Value, pointer: &str) -> Option<&'v str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Un champ d'une section : identifiant, libellé, nature de la valeur et
/// valeur en texte.
struct SectionField {
    id: String,
    title: String,
    kind: String,
    value: String,
}

fn section_fields(details: &Value) -> Vec<SectionField> {
    array(details, "sections")
        .flat_map(|section| array(section, "fields"))
        .filter_map(|field| {
            let (kind, raw) = field.get("value")?.as_object()?.iter().next()?;
            let value = value_text(kind, raw)?;
            Some(SectionField {
                id: field
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                title: field
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
                kind: kind.clone(),
                value,
            })
        })
        .collect()
}

/// La valeur d'un champ en texte, selon sa nature ; `None` pour une valeur
/// vide ou qui n'a pas de sens hors de 1Password (référence, fichier).
fn value_text(kind: &str, raw: &Value) -> Option<String> {
    let value = match (kind, raw) {
        ("date", Value::Number(n)) => n.as_i64().map(date_of)?,
        ("monthYear", Value::Number(n)) => {
            let n = n.as_i64()?;
            format!("{:04}-{:02}", n / 100, n % 100)
        }
        ("email", Value::Object(o)) => o.get("email_address")?.as_str()?.to_owned(),
        ("address", Value::Object(o)) => ["street", "zip", "city", "state", "country"]
            .iter()
            .filter_map(|k| o.get(*k)?.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        ("sshKey", Value::Object(o)) => o.get("privateKey")?.as_str()?.to_owned(),
        ("reference" | "file", _) => return None,
        (_, Value::String(s)) => s.clone(),
        (_, Value::Number(n)) => n.to_string(),
        (_, Value::Bool(b)) => if *b { "Oui" } else { "Non" }.to_owned(),
        _ => return None,
    };
    (!value.trim().is_empty()).then_some(value)
}

fn is_secret(field: &SectionField) -> bool {
    matches!(
        field.kind.as_str(),
        "concealed" | "creditCardNumber" | "sshKey" | "totp"
    ) || field.id.contains("password")
}

fn label(field: &SectionField) -> String {
    if field.title.is_empty() {
        "Champ".to_owned()
    } else {
        field.title.clone()
    }
}

fn item(entry: &Value, vault: Option<&String>, parsed: &mut Parsed) {
    let overview = entry.get("overview").unwrap_or(&Value::Null);
    let details = entry.get("details").unwrap_or(&Value::Null);
    let title = overview
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match entry.get("state").and_then(Value::as_str) {
        Some("archived") => return parsed.skip(title, "archivé dans 1Password"),
        Some("deleted") => return parsed.skip(title, "dans la corbeille de 1Password"),
        _ => {}
    }
    let category = entry
        .get("categoryUuid")
        .and_then(Value::as_str)
        .unwrap_or(NOTE);
    let mut item = ImportedItem::new(ImportKind::SecureNote, title);
    item.folder = vault.cloned();
    item.favorite = entry
        .get("favIndex")
        .and_then(Value::as_i64)
        .is_some_and(|i| i > 0);
    item.modified = entry.get("updatedAt").and_then(Value::as_i64);
    item.notes = secret(details.get("notesPlain").and_then(Value::as_str));
    let mut fields = section_fields(details);
    match category {
        LOGIN | PASSWORD => {
            item.kind = ImportKind::Login;
            login(&mut item, overview, details);
            if let Some(i) = fields.iter().position(|f| f.kind == "totp") {
                item.totp = Some(fields.remove(i).value.into());
            }
            item.fields.extend(fields.into_iter().map(|f| ExtraField {
                name: label(&f),
                hidden: is_secret(&f),
                value: f.value.into(),
            }));
        }
        CARD => {
            item.kind = ImportKind::Card;
            item.card = Some(card(&mut fields));
            item.fields.extend(fields.into_iter().map(|f| ExtraField {
                name: label(&f),
                hidden: is_secret(&f),
                value: f.value.into(),
            }));
        }
        IDENTITY => identity(&mut item, details, fields),
        other if let Some(template) = template_of(other) => {
            templated(&mut item, template, overview, details, fields);
        }
        _ => {
            // Note, document, autres catégories : tout dans les notes.
            let mut lines = Vec::new();
            for (designation, label) in [("username", "Identifiant"), ("password", "Mot de passe")]
            {
                if let Some(value) = login_field(details, designation) {
                    lines.push((label.to_owned(), value));
                }
            }
            if let Some(password) = text(details.get("password").and_then(Value::as_str)) {
                lines.push(("Mot de passe".to_owned(), password));
            }
            lines.extend(fields.iter().map(|f| (label(f), f.value.clone())));
            item.urls = urls(overview);
            append_lines(&mut item.notes, &lines);
        }
    }
    item.attachments = files(details);
    parsed.push(item);
}

/// Retire de la liste le champ qui porte cet identifiant, et rend sa valeur.
fn take(fields: &mut Vec<SectionField>, id: &str) -> Option<String> {
    fields
        .iter()
        .position(|f| f.id == id)
        .map(|i| fields.remove(i).value)
}

fn extras(fields: Vec<SectionField>) -> Vec<ExtraField> {
    fields
        .into_iter()
        .map(|f| ExtraField {
            name: label(&f),
            hidden: is_secret(&f),
            value: f.value.into(),
        })
        .collect()
}

/// Catégorie qui a un modèle : ses champs reconnus sous les libellés du
/// modèle, les autres à la suite.
fn templated(
    item: &mut ImportedItem,
    template: Template,
    overview: &Value,
    details: &Value,
    mut fields: Vec<SectionField>,
) {
    item.template = Some(template);
    if let Some((user, password, site)) = login_ids(template) {
        item.kind = ImportKind::Login;
        item.username = take(&mut fields, user)
            .or_else(|| login_field(details, "username"))
            .map(|u| u.trim().to_owned());
        item.password = take(&mut fields, password)
            .or_else(|| login_field(details, "password"))
            .map(Into::into);
        item.urls = urls(overview);
        item.urls.extend(take(&mut fields, site));
    }
    let found: Vec<_> = field_map(template)
        .iter()
        .filter_map(|(id, label)| {
            let value = take(&mut fields, id)?;
            let value = if template == Template::Wifi && *id == "wireless_security" {
                wireless_security(&value)
            } else {
                value
            };
            Some((*label, value))
        })
        .collect();
    item.fields = template_fields(template, &found, extras(fields));
}

/// Identité : les champs que Bitwarden connaît, le reste en champs
/// personnalisés.
fn identity(item: &mut ImportedItem, details: &Value, mut fields: Vec<SectionField>) {
    item.kind = ImportKind::Identity;
    let address = array(details, "sections")
        .flat_map(|section| array(section, "fields"))
        .find_map(|f| f.pointer("/value/address"))
        .cloned();
    let part = |key: &str| text(address.as_ref().and_then(|a| a.get(key)?.as_str()));
    let street = part("street");
    let mut identity = IdentityData {
        first_name: take(&mut fields, "firstname"),
        middle_name: take(&mut fields, "initial"),
        last_name: take(&mut fields, "lastname"),
        company: take(&mut fields, "company"),
        email: take(&mut fields, "email"),
        username: take(&mut fields, "username"),
        address1: street,
        postal_code: part("zip"),
        city: part("city"),
        state: part("state"),
        country: part("country"),
        ..IdentityData::default()
    };
    if address.is_some() {
        take(&mut fields, "address");
    }
    identity.phone = ["defphone", "cellphone", "homephone", "busphone"]
        .iter()
        .find_map(|id| take(&mut fields, id));
    item.identity = Some(identity);
    item.fields = extras(fields);
}

fn login_field(details: &Value, designation: &str) -> Option<String> {
    array(details, "loginFields")
        .find(|f| f.get("designation").and_then(Value::as_str) == Some(designation))
        .and_then(|f| f.get("value").and_then(Value::as_str))
        .filter(|v| !v.trim().is_empty())
        .map(str::to_owned)
}

fn urls(overview: &Value) -> Vec<String> {
    let mut urls: Vec<String> = array(overview, "urls")
        .filter_map(|u| u.get("url").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    if urls.is_empty() {
        urls.extend(text(str_at(overview, "/url")));
    }
    urls
}

fn login(item: &mut ImportedItem, overview: &Value, details: &Value) {
    item.username = login_field(details, "username").map(|u| u.trim().to_owned());
    item.password = login_field(details, "password")
        .or_else(|| {
            details
                .get("password")
                .and_then(Value::as_str)
                .filter(|p| !p.trim().is_empty())
                .map(str::to_owned)
        })
        .map(Into::into);
    item.urls = urls(overview);
}

/// Champs d'une carte : retirés de la liste, le reste devient des champs
/// personnalisés.
fn card(fields: &mut Vec<SectionField>) -> CardData {
    let mut take = |ids: &[&str]| {
        fields
            .iter()
            .position(|f| ids.contains(&f.id.as_str()))
            .map(|i| fields.remove(i).value)
    };
    let mut card = CardData {
        cardholder: take(&["cardholder"]),
        brand: take(&["type"]).map(|b| brand(&b)),
        number: take(&["ccnum"]).map(Into::into),
        code: take(&["cvv"]).map(Into::into),
        ..CardData::default()
    };
    if let Some((month, year)) = take(&["expiry"]).as_deref().and_then(expiry) {
        card.exp_month = Some(month);
        card.exp_year = Some(year);
    }
    card
}

/// `visa` → `Visa`, `mc` → `Mastercard` : les noms que Bitwarden reconnaît.
fn brand(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "visa" => "Visa".to_owned(),
        "mc" | "mastercard" => "Mastercard".to_owned(),
        "amex" | "american express" => "Amex".to_owned(),
        "discover" => "Discover".to_owned(),
        "jcb" => "JCB".to_owned(),
        "diners" | "dinersclub" => "Diners Club".to_owned(),
        "unionpay" => "UnionPay".to_owned(),
        "maestro" => "Maestro".to_owned(),
        _ => value.trim().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::super::{Format, ImportKind, parse};
    use crate::template::{Template, WIFI_PASSWORD, WIFI_SECURITY, WIFI_SSID};

    const EXPORT_DATA: &str = r#"{
      "accounts": [{
        "attrs": { "accountName": "Camille", "email": "camille@exemple.fr" },
        "vaults": [{
          "attrs": { "name": "Personnel", "type": "P" },
          "items": [
            {
              "uuid": "a1", "favIndex": 1, "createdAt": 1600000000, "updatedAt": 1700000000,
              "state": "active", "categoryUuid": "001",
              "details": {
                "loginFields": [
                  { "value": "camille", "name": "username", "fieldType": "T", "designation": "username" },
                  { "value": "Gh!2024", "name": "password", "fieldType": "P", "designation": "password" }
                ],
                "notesPlain": "compte principal",
                "sections": [{
                  "title": "", "name": "",
                  "fields": [
                    { "title": "one-time password", "id": "TOTP_1", "value": { "totp": "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP" } },
                    { "title": "code de secours", "id": "abc", "value": { "concealed": "1111-2222" } },
                    { "title": "lien", "id": "ref", "value": { "reference": "xyz" } }
                  ]
                }]
              },
              "overview": {
                "title": "GitHub", "url": "https://github.com",
                "urls": [{ "label": "", "url": "https://github.com" }, { "label": "", "url": "https://gist.github.com" }],
                "tags": ["dev"]
              }
            },
            {
              "uuid": "a2", "favIndex": 0, "updatedAt": 1700000001, "state": "active", "categoryUuid": "002",
              "details": {
                "notesPlain": "",
                "sections": [{
                  "title": "", "fields": [
                    { "title": "titulaire", "id": "cardholder", "value": { "string": "CAMILLE MARTIN" } },
                    { "title": "type", "id": "type", "value": { "creditCardType": "visa" } },
                    { "title": "numéro", "id": "ccnum", "value": { "creditCardNumber": "4242424242424242" } },
                    { "title": "code", "id": "cvv", "value": { "concealed": "123" } },
                    { "title": "expiration", "id": "expiry", "value": { "monthYear": 202709 } },
                    { "title": "PIN", "id": "pin", "value": { "concealed": "0000" } }
                  ]
                }]
              },
              "overview": { "title": "Visa" }
            },
            {
              "uuid": "a3", "state": "active", "categoryUuid": "004",
              "details": {
                "sections": [{
                  "title": "Identification", "fields": [
                    { "title": "prénom", "id": "firstname", "value": { "string": "Camille" } },
                    { "title": "e-mail", "id": "email", "value": { "email": { "email_address": "camille@exemple.fr", "provider": null } } },
                    { "title": "naissance", "id": "birthdate", "value": { "date": 631152000 } }
                  ]
                }, {
                  "title": "Adresse", "fields": [
                    { "title": "adresse", "id": "address", "value": { "address": { "street": "12 rue des Lilas", "city": "Annecy", "country": "fr", "zip": "74000", "state": "" } } },
                    { "title": "mobile", "id": "cellphone", "value": { "phone": "+33 6 00 00 00 00" } }
                  ]
                }]
              },
              "overview": { "title": "Moi" }
            },
            {
              "uuid": "a6", "state": "active", "categoryUuid": "109",
              "details": {
                "sections": [{
                  "title": "", "fields": [
                    { "title": "nom de la station", "id": "name", "value": { "string": "Freebox" } },
                    { "title": "mot de passe de la station", "id": "password", "value": { "concealed": "admin-box" } },
                    { "title": "nom du réseau", "id": "network_name", "value": { "string": "Martin-5G" } },
                    { "title": "sécurité", "id": "wireless_security", "value": { "menu": "wpa2p" } },
                    { "title": "mot de passe du réseau", "id": "wireless_password", "value": { "concealed": "lilas-27" } }
                  ]
                }]
              },
              "overview": { "title": "Wi-Fi maison" }
            },
            {
              "uuid": "a7", "state": "active", "categoryUuid": "110",
              "details": {
                "sections": [{
                  "title": "", "fields": [
                    { "title": "URL", "id": "url", "value": { "string": "ssh://web.exemple.fr" } },
                    { "title": "identifiant", "id": "username", "value": { "string": "root" } },
                    { "title": "mot de passe", "id": "password", "value": { "concealed": "s3rv3ur" } }
                  ]
                }, {
                  "title": "Hébergeur", "name": "hosting_provider_details", "fields": [
                    { "title": "nom", "id": "name", "value": { "string": "OVH" } },
                    { "title": "support", "id": "support_contact_phone", "value": { "phone": "3900" } }
                  ]
                }]
              },
              "overview": { "title": "Serveur web" }
            },
            {
              "uuid": "a8", "state": "active", "categoryUuid": "112",
              "details": {
                "sections": [{
                  "title": "", "fields": [
                    { "title": "identifiant", "id": "username", "value": { "string": "ci-bot" } },
                    { "title": "clé", "id": "credential", "value": { "concealed": "sk_test_123" } },
                    { "title": "type", "id": "type", "value": { "menu": "bearer" } },
                    { "title": "hôte", "id": "hostname", "value": { "string": "https://api.exemple.fr" } },
                    { "title": "expire", "id": "expires", "value": { "date": 1893456000 } }
                  ]
                }]
              },
              "overview": { "title": "API exemple" }
            },
            {
              "uuid": "a9", "state": "active", "categoryUuid": "101",
              "details": {
                "sections": [{
                  "title": "", "fields": [
                    { "title": "banque", "id": "bankName", "value": { "string": "Banque fictive" } },
                    { "title": "IBAN", "id": "iban", "value": { "string": "FR76 0000 0000 0000" } },
                    { "title": "code guichet", "id": "routingNo", "value": { "string": "00001" } }
                  ]
                }]
              },
              "overview": { "title": "Compte courant" }
            },
            {
              "uuid": "a4", "state": "archived", "categoryUuid": "001",
              "details": { "loginFields": [] }, "overview": { "title": "Ancien" }
            },
            {
              "uuid": "a5", "state": "active", "categoryUuid": "005",
              "details": { "password": "seul-mot-de-passe" }, "overview": { "title": "Routeur" }
            }
          ]
        }]
      }]
    }"#;

    fn onepux(data: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("export.attributes", options).unwrap();
        zip.write_all(b"{\"version\":3}").unwrap();
        zip.start_file("export.data", options).unwrap();
        zip.write_all(data.as_bytes()).unwrap();
        zip.finish().unwrap();
        bytes
    }

    #[test]
    fn onepux_logins_cards_and_others() {
        let parsed = parse(&onepux(EXPORT_DATA), None).unwrap();
        assert_eq!(parsed.format, Format::OnePassword1pux);
        assert_eq!(parsed.items.len(), 8);
        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].reason, "archivé dans 1Password");

        let github = &parsed.items[0];
        assert_eq!(github.kind, ImportKind::Login);
        assert!(github.favorite);
        assert_eq!(github.folder.as_deref(), Some("Personnel"));
        assert_eq!(github.username.as_deref(), Some("camille"));
        assert_eq!(github.password.as_ref().unwrap().expose(), "Gh!2024");
        assert!(github.totp.is_some());
        assert_eq!(github.urls.len(), 2);
        assert_eq!(github.modified, Some(1_700_000_000));
        assert_eq!(github.fields.len(), 1, "la référence est ignorée");
        assert!(github.fields[0].hidden);

        let visa = &parsed.items[1];
        assert_eq!(visa.kind, ImportKind::Card);
        let card = visa.card.as_ref().unwrap();
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.number.as_ref().unwrap().expose(), "4242424242424242");
        assert_eq!(card.exp_month.as_deref(), Some("09"));
        assert_eq!(card.exp_year.as_deref(), Some("2027"));
        assert_eq!(visa.fields[0].name, "PIN");

        let identity = &parsed.items[2];
        assert_eq!(identity.kind, ImportKind::Identity);
        let data = identity.identity.as_ref().unwrap();
        assert_eq!(data.first_name.as_deref(), Some("Camille"));
        assert_eq!(data.email.as_deref(), Some("camille@exemple.fr"));
        assert_eq!(data.address1.as_deref(), Some("12 rue des Lilas"));
        assert_eq!(data.postal_code.as_deref(), Some("74000"));
        assert_eq!(data.city.as_deref(), Some("Annecy"));
        assert_eq!(data.state, None);
        assert_eq!(data.phone.as_deref(), Some("+33 6 00 00 00 00"));
        assert_eq!(identity.fields.len(), 1);
        assert_eq!(identity.fields[0].name, "naissance");
        assert_eq!(identity.fields[0].value.expose(), "1990-01-01");
        assert!(identity.notes.is_none());

        let wifi = &parsed.items[3];
        assert_eq!(wifi.kind, ImportKind::SecureNote);
        assert_eq!(wifi.template, Some(Template::Wifi));
        let fields: Vec<(&str, &str, bool)> = wifi
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.expose(), f.hidden))
            .collect();
        assert_eq!(
            fields,
            [
                (WIFI_SSID, "Martin-5G", false),
                (WIFI_PASSWORD, "lilas-27", true),
                (WIFI_SECURITY, "WPA2 Personnel", false),
                ("nom de la station", "Freebox", false),
                ("mot de passe de la station", "admin-box", true),
            ]
        );

        let server = &parsed.items[4];
        assert_eq!(server.kind, ImportKind::Login);
        assert_eq!(server.template, Some(Template::Server));
        assert_eq!(server.username.as_deref(), Some("root"));
        assert_eq!(server.password.as_ref().unwrap().expose(), "s3rv3ur");
        assert_eq!(server.urls, ["ssh://web.exemple.fr"]);
        assert_eq!(server.fields[0].name, "Hébergeur");
        assert_eq!(server.fields[0].value.expose(), "OVH");
        assert_eq!(server.fields[1].name, "support");

        let api = &parsed.items[5];
        assert_eq!(api.kind, ImportKind::Login);
        assert_eq!(api.template, Some(Template::ApiKey));
        assert_eq!(api.username.as_deref(), Some("ci-bot"));
        assert_eq!(api.password.as_ref().unwrap().expose(), "sk_test_123");
        assert_eq!(api.urls, ["https://api.exemple.fr"]);
        let names: Vec<&str> = api.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["Type", "Date d'expiration"]);
        assert_eq!(api.fields[1].value.expose(), "2030-01-01");

        let bank = &parsed.items[6];
        assert_eq!(bank.template, Some(Template::BankAccount));
        let names: Vec<&str> = bank.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["Banque", "IBAN", "code guichet"]);
        assert!(bank.fields[1].hidden, "l'IBAN est masqué par le modèle");

        let router = &parsed.items[7];
        assert_eq!(router.kind, ImportKind::Login);
        assert_eq!(
            router.password.as_ref().unwrap().expose(),
            "seul-mot-de-passe"
        );
    }

    const DOCUMENTS: &str = r#"{
      "accounts": [{ "vaults": [{
        "attrs": { "name": "Papiers" },
        "items": [
          {
            "uuid": "d1", "state": "active", "categoryUuid": "006",
            "details": {
              "notesPlain": "",
              "documentAttributes": { "fileName": "Passeport.pdf", "documentId": "docpasseport", "decryptedSize": 9 }
            },
            "overview": { "title": "Passeport" }
          },
          {
            "uuid": "d2", "state": "active", "categoryUuid": "001",
            "details": {
              "loginFields": [{ "value": "camille", "designation": "username" }],
              "sections": [{ "fields": [
                { "title": "facture", "id": "f1", "value": { "file": { "fileName": "facture.txt", "documentId": "docfacture", "decryptedSize": 5 } } },
                { "title": "perdu", "id": "f2", "value": { "file": { "fileName": "perdu.txt", "documentId": "docperdu", "decryptedSize": 5 } } }
              ] }]
            },
            "overview": { "title": "Boutique", "url": "https://boutique.fr" }
          }
        ]
      }] }]
    }"#;

    #[test]
    fn onepux_documents_and_files_become_attachments() {
        let mut bytes = Vec::new();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("export.data", options).unwrap();
        zip.write_all(DOCUMENTS.as_bytes()).unwrap();
        zip.start_file("files/docpasseport___Passeport.pdf", options)
            .unwrap();
        zip.write_all(b"%PDF-1.7\n").unwrap();
        zip.start_file("files/docfacture__facture.txt", options)
            .unwrap();
        zip.write_all(b"12 EUR").unwrap();
        zip.finish().unwrap();

        let parsed = parse(&bytes, None).unwrap();
        assert_eq!(parsed.items.len(), 2);
        let passport = &parsed.items[0];
        assert_eq!(
            passport.kind,
            ImportKind::SecureNote,
            "un document est une note"
        );
        assert_eq!(passport.attachments.len(), 1);
        assert_eq!(passport.attachments[0].name, "Passeport.pdf");
        assert_eq!(passport.attachments[0].data.as_slice(), b"%PDF-1.7\n");
        assert!(passport.notes.is_none());
        assert!(
            !format!("{passport:?}").contains("PDF"),
            "Debug ne montre pas le contenu"
        );

        let shop = &parsed.items[1];
        assert_eq!(shop.kind, ImportKind::Login);
        assert_eq!(shop.attachments.len(), 1);
        assert_eq!(shop.attachments[0].data.as_slice(), b"12 EUR");
        let notes = shop.notes.as_ref().unwrap().expose();
        assert!(notes.contains("Pièce jointe « perdu.txt » : non importée (absente de l'export)"));

        // `export.data` seul : les fichiers manquent, les notes le disent.
        let bare = parse(DOCUMENTS.as_bytes(), Some(Format::OnePassword1pux)).unwrap();
        assert_eq!(bare.items[0].attachments.len(), 0);
        assert!(bare.items[0].notes.is_some());
    }

    #[test]
    fn bare_export_data_is_accepted() {
        let parsed = parse(EXPORT_DATA.as_bytes(), None).unwrap();
        assert_eq!(parsed.format, Format::OnePassword1pux);
        assert_eq!(parsed.items.len(), 8);
    }

    #[test]
    fn mapped_labels_belong_to_their_template() {
        for template in Template::ALL {
            for (_, label) in super::field_map(template) {
                assert!(
                    template.fields().iter().any(|f| f.label == *label),
                    "{label} absent du modèle {template:?}"
                );
            }
        }
    }
}
