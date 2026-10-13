//! Exports CSV : Mots de passe d'Apple, 1Password, Proton Pass.
//!
//! Les colonnes sont retrouvées par leur nom (l'ordre change d'une version à
//! l'autre) ; guillemets, retours à la ligne et virgules dans les champs sont
//! l'affaire du crate `csv`.

use std::collections::HashMap;

use csv::StringRecord;

use super::{
    Format, ImportError, ImportKind, ImportedItem, Parsed, append_lines, secret, text, timestamp_of,
};

/// En-tête d'un CSV, en minuscules, et ses lignes.
struct Table {
    columns: HashMap<String, usize>,
    rows: Vec<StringRecord>,
}

impl Table {
    fn read(bytes: &[u8]) -> Result<Self, ImportError> {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .trim(csv::Trim::None)
            .from_reader(bytes);
        let header = reader
            .headers()
            .map_err(|e| ImportError::Unreadable(format!("CSV ({e})")))?;
        let columns = header
            .iter()
            .enumerate()
            .map(|(i, name)| (name.trim().to_lowercase(), i))
            .collect();
        let mut rows = Vec::new();
        for record in reader.records() {
            let record = record.map_err(|e| ImportError::Unreadable(format!("CSV ({e})")))?;
            // Ligne vide en fin de fichier.
            if record.iter().all(|v| v.trim().is_empty()) {
                continue;
            }
            rows.push(record);
        }
        Ok(Self { columns, rows })
    }

    fn has(&self, name: &str) -> bool {
        self.columns.contains_key(name)
    }

    /// Valeur brute de la première colonne présente parmi `names`.
    fn get<'r>(&self, row: &'r StringRecord, names: &[&str]) -> Option<&'r str> {
        names
            .iter()
            .find_map(|n| self.columns.get(*n))
            .and_then(|&i| row.get(i))
    }
}

/// Reconnaît un CSV d'après son en-tête.
pub(super) fn detect(bytes: &[u8]) -> Option<Format> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let header: Vec<String> = reader
        .headers()
        .ok()?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let has = |name: &str| header.iter().any(|h| h == name);
    if has("type") && has("name") && has("vault") && has("password") {
        return Some(Format::ProtonPassCsv);
    }
    if has("title") && has("password") && (has("archived") || has("favorite") || has("tags")) {
        return Some(Format::OnePasswordCsv);
    }
    if has("title") && has("url") && has("username") && has("password") {
        return Some(Format::ApplePasswordsCsv);
    }
    None
}

fn require(table: &Table, columns: &[&str], format: Format) -> Result<(), ImportError> {
    if columns.iter().all(|c| table.has(c)) {
        Ok(())
    } else {
        Err(ImportError::WrongFormat(format.label()))
    }
}

/// `Title,URL,Username,Password,Notes,OTPAuth`
pub(super) fn apple(bytes: &[u8], parsed: &mut Parsed) -> Result<(), ImportError> {
    let table = Table::read(bytes)?;
    require(&table, &["title", "username", "password"], parsed.format)?;
    for row in &table.rows {
        let mut item = ImportedItem::new(
            ImportKind::Login,
            table.get(row, &["title"]).unwrap_or_default(),
        );
        item.username = text(table.get(row, &["username"]));
        item.password = secret(table.get(row, &["password"]));
        item.urls.extend(text(table.get(row, &["url"])));
        item.totp = secret(table.get(row, &["otpauth"]));
        item.notes = secret(table.get(row, &["notes"]));
        parsed.push(item);
    }
    Ok(())
}

/// `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`, dans
/// un ordre qui varie selon la version de 1Password.
pub(super) fn onepassword(bytes: &[u8], parsed: &mut Parsed) -> Result<(), ImportError> {
    let table = Table::read(bytes)?;
    require(&table, &["title", "password"], parsed.format)?;
    for row in &table.rows {
        let title = table.get(row, &["title"]).unwrap_or_default();
        let flag = |name: &str| {
            table
                .get(row, &[name])
                .is_some_and(|v| matches!(v.trim().to_lowercase().as_str(), "true" | "1" | "yes"))
        };
        if flag("archived") {
            parsed.skip(title, "archivé dans 1Password");
            continue;
        }
        let mut item = ImportedItem::new(ImportKind::Login, title);
        item.username = text(table.get(row, &["username"]));
        item.password = secret(table.get(row, &["password"]));
        item.urls.extend(
            table
                .get(row, &["url", "urls", "website"])
                .into_iter()
                .flat_map(split_urls),
        );
        item.totp = secret(table.get(row, &["otpauth", "one-time password", "totp"]));
        item.notes = secret(table.get(row, &["notes", "notesplain"]));
        item.favorite = flag("favorite");
        parsed.push(item);
    }
    Ok(())
}

/// `type,name,url,email,username,password,note,totp,createTime,modifyTime,vault`
pub(super) fn proton(bytes: &[u8], parsed: &mut Parsed) -> Result<(), ImportError> {
    let table = Table::read(bytes)?;
    require(&table, &["type", "name"], parsed.format)?;
    for row in &table.rows {
        let title = table.get(row, &["name"]).unwrap_or_default();
        let kind = table.get(row, &["type"]).unwrap_or_default().trim();
        let mut item = ImportedItem::new(ImportKind::SecureNote, title);
        item.notes = secret(table.get(row, &["note"]));
        item.folder = text(table.get(row, &["vault"]));
        item.modified = table.get(row, &["modifytime"]).and_then(timestamp_of);
        match kind {
            "login" => {
                item.kind = ImportKind::Login;
                let username = text(table.get(row, &["username"]));
                let email = text(table.get(row, &["email"]));
                item.username = username.clone().or_else(|| email.clone());
                if let (Some(_), Some(email)) = (&username, email)
                    && Some(&email) != item.username.as_ref()
                {
                    item.fields.push(super::ExtraField {
                        name: "E-mail".to_owned(),
                        value: email.into(),
                        hidden: false,
                    });
                }
                item.password = secret(table.get(row, &["password"]));
                item.urls
                    .extend(table.get(row, &["url"]).into_iter().flat_map(split_urls));
                item.totp = secret(table.get(row, &["totp"]));
            }
            "alias" => {
                parsed.skip(title, "alias e-mail de Proton Pass (sans mot de passe)");
                continue;
            }
            "note" => {}
            other => {
                // Identité, carte… : le CSV n'en donne guère que la note.
                let lines: Vec<(String, String)> = [
                    ("E-mail", table.get(row, &["email"])),
                    ("Identifiant", table.get(row, &["username"])),
                    ("Mot de passe", table.get(row, &["password"])),
                    ("Site", table.get(row, &["url"])),
                ]
                .into_iter()
                .filter_map(|(label, value)| Some((label.to_owned(), text(value)?)))
                .collect();
                append_lines(&mut item.notes, &lines);
                if item.notes.is_none() {
                    parsed.skip(title, &format!("type « {other} » vide dans le CSV"));
                    continue;
                }
            }
        }
        parsed.push(item);
    }
    Ok(())
}

/// Plusieurs sites dans une même cellule, séparés par des virgules (Proton)
/// ou des retours à la ligne.
fn split_urls(value: &str) -> Vec<String> {
    value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::{Format, ImportKind, parse};

    const APPLE: &str = "\u{feff}Title,URL,Username,Password,Notes,OTPAuth\r\n\
        github.com (camille),https://github.com/,camille,\"mot,de\"\"passe\",\"ligne 1\nligne 2\",otpauth://totp/GitHub:camille?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\r\n\
        exemple.fr,https://exemple.fr/,,sans-identifiant,,\r\n\
        ,,,,,\r\n";

    #[test]
    fn apple_passwords_csv() {
        let parsed = parse(APPLE.as_bytes(), None).unwrap();
        assert_eq!(parsed.format, Format::ApplePasswordsCsv);
        assert_eq!(parsed.items.len(), 2);
        let github = &parsed.items[0];
        assert_eq!(github.kind, ImportKind::Login);
        assert_eq!(github.title, "github.com (camille)");
        assert_eq!(github.username.as_deref(), Some("camille"));
        assert_eq!(github.password.as_ref().unwrap().expose(), "mot,de\"passe");
        assert_eq!(github.notes.as_ref().unwrap().expose(), "ligne 1\nligne 2");
        assert!(
            github
                .totp
                .as_ref()
                .unwrap()
                .expose()
                .starts_with("otpauth://")
        );
        assert_eq!(github.urls, vec!["https://github.com/"]);
        assert!(parsed.items[1].username.is_none());
        assert!(parsed.skipped.is_empty(), "la ligne vide est ignorée");
    }

    const ONEPASSWORD: &str = "Notes,Title,Username,Password,Url,OTPAuth,Favorite,Archived,Tags\n\
        ,Banque,camille,b4nque!,https://banque.fr,,true,false,finances\n\
        ,Vieux forum,camille,x,https://forum.fr,,false,true,\n\
        code porte 1234,Digicode,,,,,false,false,\n";

    #[test]
    fn onepassword_csv_by_header_names() {
        let parsed = parse(ONEPASSWORD.as_bytes(), None).unwrap();
        assert_eq!(parsed.format, Format::OnePasswordCsv);
        assert_eq!(parsed.items.len(), 2);
        let bank = &parsed.items[0];
        assert!(bank.favorite);
        assert_eq!(bank.password.as_ref().unwrap().expose(), "b4nque!");
        assert_eq!(bank.urls, vec!["https://banque.fr"]);
        let note = &parsed.items[1];
        assert_eq!(
            note.kind,
            ImportKind::SecureNote,
            "sans identifiant : une note"
        );
        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].title, "Vieux forum");
    }

    const PROTON: &str = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
        login,Doctolib,\"https://doctolib.fr, https://www.doctolib.de\",camille@exemple.fr,,s3cret,,,1700000000,1710000000,Personnel\n\
        login,Forum,https://forum.fr,camille@exemple.fr,cam,pw,,,,,Personnel\n\
        alias,Alias boutique,,x.y@passinbox.com,,,,,,,Personnel\n\
        note,Wi-Fi,,,,,motdepassewifi,,,,Maison\n";

    #[test]
    fn proton_pass_csv() {
        let parsed = parse(PROTON.as_bytes(), None).unwrap();
        assert_eq!(parsed.format, Format::ProtonPassCsv);
        assert_eq!(parsed.items.len(), 3);
        let doctolib = &parsed.items[0];
        assert_eq!(doctolib.username.as_deref(), Some("camille@exemple.fr"));
        assert_eq!(doctolib.urls.len(), 2);
        assert_eq!(doctolib.folder.as_deref(), Some("Personnel"));
        assert_eq!(doctolib.modified, Some(1_710_000_000));
        let forum = &parsed.items[1];
        assert_eq!(forum.username.as_deref(), Some("cam"));
        assert_eq!(forum.fields[0].name, "E-mail");
        assert_eq!(parsed.items[2].kind, ImportKind::SecureNote);
        assert_eq!(parsed.skipped.len(), 1);
    }

    #[test]
    fn forced_format_must_match_the_header() {
        assert!(parse(PROTON.as_bytes(), Some(Format::ApplePasswordsCsv)).is_err());
    }
}
