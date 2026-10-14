//! Export de Proton Pass, non chiffré : une archive ZIP contenant
//! `Proton Pass/data.json` (coffres → éléments).
//!
//! Identifiants, notes, cartes et identités sont repris ; un réseau Wi-Fi
//! devient le modèle Wi-Fi de Verrou ; un alias (une adresse e-mail relais,
//! sans mot de passe) est laissé de côté.
//!
//! Pièces jointes : l'élément cite ses fichiers (`files`) sous leur nom
//! d'export, `<nom>.<identifiant><extension>`, rangés dans
//! `Proton Pass/files/`.

use serde_json::Value;

use super::{
    CardData, ExtraField, IdentityData, ImportError, ImportKind, ImportedFile, ImportedItem,
    Parsed, append_lines, expiry, secret, template_fields, text,
};
use crate::secret::SecretString;
use crate::template::{Template, WIFI_PASSWORD, WIFI_SECURITY, WIFI_SSID};

/// État d'un élément dans Proton Pass : 1 actif, 2 à la corbeille.
const TRASHED: i64 = 2;

/// Fichiers cités par l'élément, à lire ensuite dans l'archive.
fn files(entry: &Value) -> Vec<ImportedFile> {
    entry
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .map(|name| ImportedFile::pending(&original_name(name), name.to_owned()))
        .collect()
}

/// `facture.1a2b3c.pdf` → `facture.pdf` : Proton Pass glisse un identifiant
/// hexadécimal avant l'extension (ou à la fin, sans extension).
fn original_name(export_name: &str) -> String {
    let hex = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    let mut parts: Vec<&str> = export_name.split('.').collect();
    if parts.len() >= 3 && hex(parts[parts.len() - 2]) {
        parts.remove(parts.len() - 2);
    } else if parts.len() == 2 && hex(parts[1]) {
        parts.pop();
    }
    parts.join(".")
}

/// `Proton Pass/files/<nom d'export>`, où `/` et `\` deviennent `_`.
pub(super) fn archive_entry(name: &str, export_name: &str) -> bool {
    let sanitized = export_name.replace(['/', '\\'], "_");
    name.strip_suffix(sanitized.trim())
        .is_some_and(|dir| dir.ends_with("files/"))
}

pub(super) fn parse(json: &Value, parsed: &mut Parsed) -> Result<(), ImportError> {
    if json.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(ImportError::Encrypted);
    }
    let vaults = json
        .get("vaults")
        .and_then(Value::as_object)
        .ok_or(ImportError::WrongFormat(parsed.format.label()))?;
    for vault in vaults.values() {
        let name = text(vault.get("name").and_then(Value::as_str));
        for entry in vault
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            item(entry, name.as_ref(), parsed);
        }
    }
    Ok(())
}

fn string<'v>(value: &'v Value, key: &str) -> Option<&'v str> {
    value.get(key).and_then(Value::as_str)
}

fn item(entry: &Value, vault: Option<&String>, parsed: &mut Parsed) {
    let data = entry.get("data").unwrap_or(&Value::Null);
    let metadata = data.get("metadata").unwrap_or(&Value::Null);
    let content = data.get("content").unwrap_or(&Value::Null);
    let title = string(metadata, "name").unwrap_or_default();
    if entry.get("state").and_then(Value::as_i64) == Some(TRASHED) {
        return parsed.skip(title, "dans la corbeille de Proton Pass");
    }
    let mut item = ImportedItem::new(ImportKind::SecureNote, title);
    item.folder = vault.cloned();
    item.favorite = entry
        .get("pinned")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    item.modified = entry.get("modifyTime").and_then(Value::as_i64);
    item.notes = secret(string(metadata, "note"));
    for field in data
        .get("extraFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        extra_field(field, &mut item);
    }
    let mut lines = Vec::new();
    match string(data, "type").unwrap_or("note") {
        "login" => login(content, &mut item),
        "creditCard" => card(content, &mut item),
        "alias" => {
            return parsed.skip(title, "alias e-mail de Proton Pass (sans mot de passe)");
        }
        "note" => {}
        "wifi" => wifi(content, &mut item),
        "identity" => identity(content, &mut item),
        _ => {
            // Identité, clé SSH, Wi-Fi… : chaque champ renseigné, dans les notes.
            if let Some(map) = content.as_object() {
                lines.extend(map.iter().filter_map(|(key, value)| {
                    let value = text(value.as_str())?;
                    Some((humanize(key), value))
                }));
            }
        }
    }
    // Seul un identifiant a un code à usage unique.
    if item.kind != ImportKind::Login
        && let Some(totp) = item.totp.take()
    {
        item.fields.push(ExtraField {
            name: "Code à usage unique".to_owned(),
            value: totp,
            hidden: true,
        });
    }
    // Champs supplémentaires d'une note (ou d'un autre type) : dans les notes.
    if item.kind == ImportKind::SecureNote && item.template.is_none() {
        lines.extend(
            item.fields
                .drain(..)
                .map(|f| (f.name, f.value.expose().to_owned())),
        );
    }
    append_lines(&mut item.notes, &lines);
    item.attachments = files(entry);
    parsed.push(item);
}

/// Identifiant : l'identifiant est `itemUsername`, sinon `itemEmail` (l'autre
/// devient un champ « E-mail »).
fn login(content: &Value, item: &mut ImportedItem) {
    item.kind = ImportKind::Login;
    let username =
        text(string(content, "itemUsername")).or_else(|| text(string(content, "username")));
    let email = text(string(content, "itemEmail"));
    item.username = username.clone().or_else(|| email.clone());
    if let (Some(_), Some(email)) = (username, email)
        && Some(&email) != item.username.as_ref()
    {
        item.fields.insert(
            0,
            ExtraField {
                name: "E-mail".to_owned(),
                value: email.into(),
                hidden: false,
            },
        );
    }
    item.password = secret(string(content, "password"));
    if let Some(totp) = secret(string(content, "totpUri")) {
        // Le code de l'identifiant passe avant celui d'un champ.
        if let Some(other) = item.totp.replace(totp) {
            item.fields.push(ExtraField {
                name: "Code à usage unique".to_owned(),
                value: other,
                hidden: true,
            });
        }
    }
    item.urls = content
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
}

fn card(content: &Value, item: &mut ImportedItem) {
    item.kind = ImportKind::Card;
    let mut card = CardData {
        cardholder: text(string(content, "cardholderName")),
        number: secret(string(content, "number")),
        code: secret(string(content, "verificationNumber")),
        ..CardData::default()
    };
    if let Some((month, year)) = string(content, "expirationDate").and_then(expiry) {
        card.exp_month = Some(month);
        card.exp_year = Some(year);
    }
    if let Some(pin) = secret(string(content, "pin")) {
        item.fields.push(ExtraField {
            name: "PIN".to_owned(),
            value: pin,
            hidden: true,
        });
    }
    item.card = Some(card);
}

/// Réseau Wi-Fi : le modèle Wi-Fi de Verrou.
fn wifi(content: &Value, item: &mut ImportedItem) {
    item.template = Some(Template::Wifi);
    // Énumération de Proton Pass : 1 WPA, 2 WPA2, 3 WPA3, 4 WEP.
    let security = match content.get("security") {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(1) => Some("WPA".to_owned()),
            Some(2) => Some("WPA2".to_owned()),
            Some(3) => Some("WPA3".to_owned()),
            Some(4) => Some("WEP".to_owned()),
            _ => None,
        },
        Some(Value::String(s)) => text(Some(s)),
        _ => None,
    };
    let found: Vec<_> = [
        (WIFI_SSID, text(string(content, "ssid"))),
        (
            WIFI_PASSWORD,
            string(content, "password").map(str::to_owned),
        ),
        (WIFI_SECURITY, security),
    ]
    .into_iter()
    .filter_map(|(label, value)| Some((label, value?)))
    .collect();
    let others = std::mem::take(&mut item.fields);
    item.fields = template_fields(Template::Wifi, &found, others);
}

/// Identité : les champs que Bitwarden connaît ; les autres (date de
/// naissance, réseaux sociaux, sections ajoutées…) en champs personnalisés.
fn identity(content: &Value, item: &mut ImportedItem) {
    item.kind = ImportKind::Identity;
    let mut used: Vec<&str> = Vec::new();
    let mut take = |key: &'static str| {
        used.push(key);
        text(string(content, key))
    };
    let mut identity = IdentityData {
        first_name: take("firstName"),
        middle_name: take("middleName"),
        last_name: take("lastName"),
        company: take("company").or_else(|| take("organization")),
        email: take("email"),
        phone: take("phoneNumber"),
        address1: take("streetAddress"),
        address2: take("floor"),
        postal_code: take("zipOrPostalCode"),
        city: take("city"),
        state: take("stateOrProvince"),
        country: take("countryOrRegion"),
        ssn: take("socialSecurityNumber").map(Into::into),
        passport_number: take("passportNumber").map(Into::into),
        license_number: take("licenseNumber").map(Into::into),
        ..IdentityData::default()
    };
    // Le nom complet seul : prénom(s), puis nom (le dernier mot).
    if let Some(full) = take("fullName")
        && identity.first_name.is_none()
        && identity.last_name.is_none()
    {
        match full.rsplit_once(' ') {
            Some((first, last)) => {
                identity.first_name = Some(first.trim().to_owned());
                identity.last_name = Some(last.trim().to_owned());
            }
            None => identity.last_name = Some(full),
        }
    }
    item.identity = Some(identity);
    let Some(map) = content.as_object() else {
        return;
    };
    let mut fields = Vec::new();
    for (key, value) in map {
        match value {
            Value::String(_) if !used.contains(&key.as_str()) => {
                if let Some(value) = text(value.as_str()) {
                    fields.push(ExtraField {
                        name: humanize(key),
                        value: value.into(),
                        hidden: false,
                    });
                }
            }
            // `extraPersonalDetails`, `extraSections`… : des champs comme
            // ceux de `extraFields`, parfois rangés dans des sections.
            Value::Array(list) => {
                for entry in list {
                    let nested = entry.get("sectionFields").and_then(Value::as_array);
                    for field in nested
                        .into_iter()
                        .flatten()
                        .chain(entry.get("fieldName").is_some().then_some(entry))
                    {
                        let mut holder = ImportedItem::new(ImportKind::Identity, "");
                        // Graine déjà « prise » : un champ TOTP reste un champ masqué.
                        holder.totp = Some(SecretString::default());
                        extra_field(field, &mut holder);
                        fields.extend(holder.fields);
                    }
                }
            }
            _ => {}
        }
    }
    item.fields.splice(0..0, fields);
}

/// Champ personnalisé : texte, masqué, TOTP (le premier sert de code à usage
/// unique si l'identifiant n'en a pas).
fn extra_field(field: &Value, item: &mut ImportedItem) {
    let name = text(string(field, "fieldName")).unwrap_or_else(|| "Champ".to_owned());
    let data = field.get("data").unwrap_or(&Value::Null);
    let value = string(data, "content")
        .or_else(|| string(data, "totpUri"))
        .map(str::to_owned)
        .or_else(|| {
            data.get("timestamp")
                .and_then(Value::as_i64)
                .map(super::date_of)
        });
    let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
        return;
    };
    let kind = string(field, "type").unwrap_or("text");
    if kind == "totp" && item.totp.is_none() {
        // Graine de l'identifiant, sauf s'il en a déjà une (voir `item`).
        item.totp = Some(value.into());
        return;
    }
    item.fields.push(ExtraField {
        name,
        value: value.into(),
        hidden: matches!(kind, "hidden" | "totp"),
    });
}

/// `phoneNumber` → `Phone number`.
fn humanize(key: &str) -> String {
    let mut out = String::new();
    for (i, c) in key.chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else if c.is_uppercase() {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::super::{Format, ImportError, ImportKind, parse};
    use crate::template::{Template, WIFI_PASSWORD, WIFI_SECURITY, WIFI_SSID};

    const DATA: &str = r#"{
      "version": "1.21.2", "userId": "u1", "encrypted": false,
      "vaults": {
        "share1": {
          "name": "Personnel", "description": "",
          "items": [
            {
              "itemId": "i1", "shareId": "share1", "state": 1, "pinned": true,
              "createTime": 1690000000, "modifyTime": 1710000000,
              "data": {
                "metadata": { "name": "Doctolib", "note": "", "itemUuid": "x" },
                "extraFields": [
                  { "fieldName": "Question secrète", "type": "hidden", "data": { "content": "Annecy" } }
                ],
                "type": "login",
                "content": {
                  "itemEmail": "camille@exemple.fr", "itemUsername": "",
                  "password": "d0ct0!", "urls": ["https://www.doctolib.fr/"],
                  "totpUri": "", "passkeys": []
                }
              }
            },
            {
              "itemId": "i2", "state": 1,
              "data": {
                "metadata": { "name": "Carte pro", "note": "" }, "extraFields": [],
                "type": "creditCard",
                "content": {
                  "cardholderName": "Camille Martin", "cardType": 0,
                  "number": "5555555555554444", "verificationNumber": "321",
                  "expirationDate": "2028-02", "pin": "9876"
                }
              }
            },
            {
              "itemId": "i3", "state": 1,
              "data": { "metadata": { "name": "Boutique", "note": "" }, "type": "alias", "content": {} },
              "aliasEmail": "boutique.x@passinbox.com"
            },
            {
              "itemId": "i4", "state": 2,
              "data": { "metadata": { "name": "Supprimé", "note": "" }, "type": "login", "content": {} }
            },
            {
              "itemId": "i5", "state": 1,
              "data": {
                "metadata": { "name": "Identité", "note": "" }, "type": "identity",
                "content": {
                  "fullName": "Camille Martin", "phoneNumber": "+33 6 00 00 00 00", "company": "",
                  "birthdate": "1990-01-01",
                  "extraPersonalDetails": [
                    { "fieldName": "Instagram", "type": "text", "data": { "content": "@camille" } }
                  ]
                }
              }
            },
            {
              "itemId": "i6", "state": 1,
              "data": {
                "metadata": { "name": "Box", "note": "" },
                "extraFields": [
                  { "fieldName": "Emplacement", "type": "text", "data": { "content": "salon" } }
                ],
                "type": "wifi",
                "content": { "ssid": "Martin-5G", "password": "lilas-27", "security": 2 }
              }
            }
          ]
        },
        "share2": {
          "name": "Famille",
          "items": [{
            "itemId": "j1", "state": 1,
            "data": {
              "metadata": { "name": "Netflix", "note": "partagé" },
              "extraFields": [
                { "fieldName": "2FA", "type": "totp", "data": { "totpUri": "otpauth://totp/Netflix?secret=JBSWY3DPEHPK3PXP" } }
              ],
              "type": "login",
              "content": { "itemEmail": "", "itemUsername": "famille", "password": "n", "urls": [], "totpUri": "" }
            }
          }]
        }
      }
    }"#;

    fn archive(data: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Proton Pass/data.json", options).unwrap();
        zip.write_all(data.as_bytes()).unwrap();
        zip.finish().unwrap();
        bytes
    }

    #[test]
    fn proton_pass_zip() {
        let parsed = parse(&archive(DATA), None).unwrap();
        assert_eq!(parsed.format, Format::ProtonPassZip);
        assert_eq!(parsed.items.len(), 5);
        assert_eq!(parsed.skipped.len(), 2);

        let doctolib = parsed.items.iter().find(|i| i.title == "Doctolib").unwrap();
        assert_eq!(doctolib.username.as_deref(), Some("camille@exemple.fr"));
        assert!(doctolib.favorite);
        assert_eq!(doctolib.folder.as_deref(), Some("Personnel"));
        assert_eq!(doctolib.fields[0].name, "Question secrète");
        assert!(doctolib.fields[0].hidden);

        let card = parsed
            .items
            .iter()
            .find(|i| i.kind == ImportKind::Card)
            .unwrap();
        let data = card.card.as_ref().unwrap();
        assert_eq!(data.exp_month.as_deref(), Some("02"));
        assert_eq!(data.exp_year.as_deref(), Some("2028"));
        assert_eq!(card.fields[0].name, "PIN");

        let identity = parsed.items.iter().find(|i| i.title == "Identité").unwrap();
        assert_eq!(identity.kind, ImportKind::Identity);
        let data = identity.identity.as_ref().unwrap();
        assert_eq!(data.first_name.as_deref(), Some("Camille"));
        assert_eq!(data.last_name.as_deref(), Some("Martin"));
        assert_eq!(data.phone.as_deref(), Some("+33 6 00 00 00 00"));
        assert_eq!(data.company, None);
        assert_eq!(identity.fields.len(), 2);
        assert_eq!(identity.fields[0].name, "Birthdate");
        assert_eq!(identity.fields[1].name, "Instagram");
        assert!(identity.notes.is_none());

        let wifi = parsed.items.iter().find(|i| i.title == "Box").unwrap();
        assert_eq!(wifi.kind, ImportKind::SecureNote);
        assert_eq!(wifi.template, Some(Template::Wifi));
        let names: Vec<&str> = wifi.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [WIFI_SSID, WIFI_PASSWORD, WIFI_SECURITY, "Emplacement"]
        );
        assert_eq!(wifi.fields[0].value.expose(), "Martin-5G");
        assert!(wifi.fields[1].hidden && !wifi.fields[0].hidden);
        assert_eq!(wifi.fields[2].value.expose(), "WPA2");
        assert!(wifi.notes.is_none(), "les champs restent des champs");

        let netflix = parsed.items.iter().find(|i| i.title == "Netflix").unwrap();
        assert_eq!(netflix.folder.as_deref(), Some("Famille"));
        assert!(netflix.totp.as_ref().unwrap().expose().contains("Netflix"));
        assert_eq!(netflix.fields, Vec::new());
    }

    #[test]
    fn proton_pass_files_become_attachments() {
        let data = r#"{
          "version": "1.30.0", "encrypted": false,
          "vaults": { "s": { "name": "Perso", "items": [{
            "itemId": "f1", "state": 1,
            "data": { "metadata": { "name": "Bail", "note": "" }, "type": "note", "content": {} },
            "files": ["bail signé.7f3a9c12.pdf", "README.4bc1", "absent.aa11.txt"]
          }] } }
        }"#;
        let mut bytes = Vec::new();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Proton Pass/data.json", options).unwrap();
        zip.write_all(data.as_bytes()).unwrap();
        zip.start_file("Proton Pass/files/bail signé.7f3a9c12.pdf", options)
            .unwrap();
        zip.write_all(b"bail").unwrap();
        zip.start_file("Proton Pass/files/README.4bc1", options)
            .unwrap();
        zip.write_all(b"lisez-moi").unwrap();
        zip.finish().unwrap();

        let parsed = parse(&bytes, None).unwrap();
        let lease = &parsed.items[0];
        assert_eq!(lease.kind, ImportKind::SecureNote);
        let names: Vec<&str> = lease.attachments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["bail signé.pdf", "README"]);
        assert_eq!(lease.attachments[0].data.as_slice(), b"bail");
        assert!(
            lease
                .notes
                .as_ref()
                .unwrap()
                .expose()
                .contains("« absent.txt » : non importée")
        );
    }

    #[test]
    fn encrypted_export_is_refused() {
        let encrypted = r#"{ "version": "1", "encrypted": true, "vaults": {} }"#;
        assert_eq!(
            parse(&archive(encrypted), None).unwrap_err(),
            ImportError::Encrypted
        );
    }
}
