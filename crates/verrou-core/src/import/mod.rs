//! Reading exports from other password managers: Apple Passwords (CSV),
//! 1Password (`.1pux` or CSV) and Proton Pass (unencrypted ZIP or CSV).
//!
//! Like the rest of the crate, no I/O: we receive the file's content and
//! return items in the common format ([`ImportedItem`]) plus the list of
//! what was left out, with the reason. Secrets go straight into
//! `SecretString`s. Known limit: the CSV and JSON readers keep intermediate
//! copies that are not zeroed; they are freed at the end of the read.
//!
//! Comparison with the vault (duplicates, different passwords) is in
//! [`crate::duplicates`].
//!
//! Attachments: the 1Password (`files/`) and Proton Pass
//! (`Proton Pass/files/`) archives carry the items' files. They are read
//! here, into buffers wiped on drop ([`ImportedFile`]), to become Bitwarden
//! attachments.

mod csv_formats;
mod onepassword;
mod proton;

use std::io::{Cursor, Read};

use crate::matching::host_of;
use crate::secret::SecretString;
use crate::template::Template;

/// Maximum size of an export file, and of a file extracted from an
/// archive: enough for tens of thousands of items, not a decompression
/// bomb.
pub const MAX_SIZE: u64 = 64 * 1024 * 1024;

/// Maximum size of an export archive (1Password or Proton Pass ZIP),
/// attachments included.
pub const MAX_ARCHIVE_SIZE: u64 = 512 * 1024 * 1024;

/// Maximum size of an attachment, before encryption: the same one Verrou
/// applies when a file is added.
pub const MAX_ATTACHMENT_SIZE: u64 = 100 * 1024 * 1024;

/// Format of an export file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// macOS Passwords app: File → Export All Passwords.
    ApplePasswordsCsv,
    /// 1Password: File → Export → 1PUX.
    OnePassword1pux,
    /// 1Password: File → Export → CSV.
    OnePasswordCsv,
    /// Proton Pass: Settings → Export, unencrypted ZIP.
    ProtonPassZip,
    /// Proton Pass: Settings → Export, CSV.
    ProtonPassCsv,
}

impl Format {
    pub const ALL: [Self; 5] = [
        Self::ApplePasswordsCsv,
        Self::OnePassword1pux,
        Self::OnePasswordCsv,
        Self::ProtonPassZip,
        Self::ProtonPassCsv,
    ];

    /// Name of the source app (and of the "Import …" folder).
    pub fn source(self) -> &'static str {
        match self {
            Self::ApplePasswordsCsv => "Apple",
            Self::OnePassword1pux | Self::OnePasswordCsv => "1Password",
            Self::ProtonPassZip | Self::ProtonPassCsv => "Proton Pass",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ApplePasswordsCsv => "Apple Passwords (CSV)",
            Self::OnePassword1pux => "1Password (1PUX)",
            Self::OnePasswordCsv => "1Password (CSV)",
            Self::ProtonPassZip => "Proton Pass (ZIP)",
            Self::ProtonPassCsv => "Proton Pass (CSV)",
        }
    }
}

/// What an imported item becomes in Vaultwarden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportKind {
    Login,
    SecureNote,
    Card,
    Identity,
}

/// Imported payment card.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CardData {
    pub cardholder: Option<String>,
    pub brand: Option<String>,
    pub number: Option<SecretString>,
    /// Month as one or two digits (`9`, `09`).
    pub exp_month: Option<String>,
    /// Four-digit year.
    pub exp_year: Option<String>,
    pub code: Option<SecretString>,
}

/// Imported identity (Bitwarden's Identity type).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityData {
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
    pub postal_code: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub ssn: Option<SecretString>,
    pub passport_number: Option<SecretString>,
    pub license_number: Option<SecretString>,
}

impl IdentityData {
    /// First and last name, to compare with the vault.
    pub fn full_name(&self) -> String {
        [&self.first_name, &self.middle_name, &self.last_name]
            .into_iter()
            .flatten()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Extra field of a login or a card (becomes a Bitwarden custom field,
/// hidden if it is secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraField {
    pub name: String,
    pub value: SecretString,
    pub hidden: bool,
}

/// File attached to an imported item. Its content is wiped from memory on
/// drop; `Debug` does not show it.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedFile {
    pub name: String,
    pub data: zeroize::Zeroizing<Vec<u8>>,
    /// Where to find it in the archive, while reading.
    reference: Option<String>,
}

impl ImportedFile {
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data: zeroize::Zeroizing::new(data),
            reference: None,
        }
    }

    /// File announced by the export, to look up in the archive.
    fn pending(name: &str, reference: String) -> Self {
        Self {
            name: name.trim().to_owned(),
            data: zeroize::Zeroizing::new(Vec::new()),
            reference: Some(reference),
        }
    }
}

impl std::fmt::Debug for ImportedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedFile")
            .field("name", &self.name)
            .field("size", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// An item read from an export, in the common format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedItem {
    pub kind: ImportKind,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub urls: Vec<String>,
    /// TOTP seed (`otpauth://…` or base32).
    pub totp: Option<SecretString>,
    pub notes: Option<SecretString>,
    /// Folder (or vault) in the source app.
    pub folder: Option<String>,
    pub favorite: bool,
    pub card: Option<CardData>,
    pub identity: Option<IdentityData>,
    /// Verrou template (Wi-Fi, passport…): the predefined fields are in
    /// `fields`, the `verrou:type` field is added on write.
    pub template: Option<Template>,
    pub fields: Vec<ExtraField>,
    /// Last modification in the source app (Unix, seconds), when the export
    /// gives it.
    pub modified: Option<i64>,
    /// Attachments (1Password and Proton Pass archives).
    pub attachments: Vec<ImportedFile>,
}

impl ImportedItem {
    fn new(kind: ImportKind, title: &str) -> Self {
        Self {
            kind,
            title: title.trim().to_owned(),
            username: None,
            password: None,
            urls: Vec::new(),
            totp: None,
            notes: None,
            folder: None,
            favorite: false,
            card: None,
            identity: None,
            template: None,
            fields: Vec::new(),
            modified: None,
            attachments: Vec::new(),
        }
    }

    /// Host of the first site, without `www.`.
    pub fn primary_host(&self) -> Option<String> {
        self.urls.iter().find_map(|u| host_of(u))
    }
}

/// An item left out, and why. Never a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub title: String,
    pub reason: String,
}

/// The content of an export.
#[derive(Debug)]
pub struct Parsed {
    pub format: Format,
    pub items: Vec<ImportedItem>,
    pub skipped: Vec<Skipped>,
}

impl Parsed {
    fn new(format: Format) -> Self {
        Self {
            format,
            items: Vec::new(),
            skipped: Vec::new(),
        }
    }

    fn skip(&mut self, title: &str, reason: &str) {
        let title = title.trim();
        self.skipped.push(Skipped {
            title: if title.is_empty() {
                "(untitled)".to_owned()
            } else {
                title.to_owned()
            },
            reason: reason.to_owned(),
        });
    }

    /// Stores an item read: fallback title, empty login turned into a note,
    /// empty item ignored.
    fn push(&mut self, mut item: ImportedItem) {
        item.urls.retain(|u| !u.trim().is_empty());
        for url in &mut item.urls {
            *url = url.trim().to_owned();
        }
        item.urls.dedup();
        if item.title.is_empty() {
            item.title = item
                .primary_host()
                .or_else(|| item.username.clone())
                .unwrap_or_default();
        }
        if item.kind == ImportKind::Login
            && item.username.is_none()
            && item.password.is_none()
            && item.totp.is_none()
            && item.urls.is_empty()
            && item.fields.is_empty()
        {
            item.kind = ImportKind::SecureNote;
        }
        let empty = match item.kind {
            // A document (a file alone) stays a secure note.
            ImportKind::SecureNote => {
                item.notes.is_none() && item.fields.is_empty() && item.attachments.is_empty()
            }
            ImportKind::Card => item.card.as_ref().is_none_or(|c| *c == CardData::default()),
            ImportKind::Identity => {
                item.notes.is_none()
                    && item.fields.is_empty()
                    && item
                        .identity
                        .as_ref()
                        .is_none_or(|i| *i == IdentityData::default())
            }
            ImportKind::Login => false,
        };
        if empty {
            let title = item.title.clone();
            self.skip(&title, "empty item");
            return;
        }
        if item.title.is_empty() {
            "(untitled)".clone_into(&mut item.title);
        }
        self.items.push(item);
    }
}

/// What prevents a file from being read.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("unrecognized format: choose the app the file comes from")]
    UnknownFormat,
    #[error("encrypted export: export again, without encryption")]
    Encrypted,
    #[error("file too large (64 MB at most, 512 MB for an archive)")]
    TooLarge,
    #[error("unreadable file: {0}")]
    Unreadable(String),
    #[error("this file is not a {0} export")]
    WrongFormat(&'static str),
}

/// Recognizes an export's format from its content.
pub fn detect(bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(b"PK") {
        let names = zip_names(bytes).ok()?;
        if names.iter().any(|n| n == "export.data") {
            return Some(Format::OnePassword1pux);
        }
        if names.iter().any(|n| n.ends_with("data.json")) {
            return Some(Format::ProtonPassZip);
        }
        return None;
    }
    let text = strip_bom(bytes);
    if text.trim_ascii_start().starts_with(b"{") {
        let json: serde_json::Value = serde_json::from_slice(text).ok()?;
        if json.get("accounts").is_some() {
            return Some(Format::OnePassword1pux);
        }
        if json.get("vaults").is_some() {
            return Some(Format::ProtonPassZip);
        }
        return None;
    }
    csv_formats::detect(text)
}

/// Reads an export; without `format`, recognizes it first.
pub fn parse(bytes: &[u8], format: Option<Format>) -> Result<Parsed, ImportError> {
    let limit = if bytes.starts_with(b"PK") {
        MAX_ARCHIVE_SIZE
    } else {
        MAX_SIZE
    };
    if bytes.len() as u64 > limit {
        return Err(ImportError::TooLarge);
    }
    if looks_encrypted(bytes) {
        return Err(ImportError::Encrypted);
    }
    let format = match format {
        Some(format) => format,
        None => detect(bytes).ok_or(ImportError::UnknownFormat)?,
    };
    let mut parsed = Parsed::new(format);
    match format {
        Format::ApplePasswordsCsv => csv_formats::apple(strip_bom(bytes), &mut parsed)?,
        Format::OnePasswordCsv => csv_formats::onepassword(strip_bom(bytes), &mut parsed)?,
        Format::ProtonPassCsv => csv_formats::proton(strip_bom(bytes), &mut parsed)?,
        Format::OnePassword1pux => {
            let json = json_document(bytes, |name| name == "export.data", format)?;
            onepassword::parse(&json, &mut parsed)?;
            attach_files(bytes, &mut parsed, onepassword::archive_entry)?;
        }
        Format::ProtonPassZip => {
            let json = json_document(bytes, |name| name.ends_with("data.json"), format)?;
            proton::parse(&json, &mut parsed)?;
            attach_files(bytes, &mut parsed, proton::archive_entry)?;
        }
    }
    Ok(parsed)
}

/// Reads from the archive the files announced by the export; `entry` tells
/// whether an archive name is the one of a reference. A missing or too
/// large file is not imported, and the item's notes say so.
fn attach_files(
    bytes: &[u8],
    parsed: &mut Parsed,
    entry: fn(&str, &str) -> bool,
) -> Result<(), ImportError> {
    let wanted = parsed
        .items
        .iter()
        .any(|i| i.attachments.iter().any(|a| a.reference.is_some()));
    if !wanted {
        return Ok(());
    }
    // `export.data` alone, without its archive: the files are missing.
    let mut archive = if bytes.starts_with(b"PK") {
        Some(
            zip::ZipArchive::new(Cursor::new(bytes))
                .map_err(|e| ImportError::Unreadable(format!("archive ZIP ({e})")))?,
        )
    } else {
        None
    };
    let names = if archive.is_some() {
        zip_names(bytes)?
    } else {
        Vec::new()
    };
    for item in &mut parsed.items {
        let mut missing = Vec::new();
        let mut kept = Vec::new();
        for mut file in std::mem::take(&mut item.attachments) {
            let Some(reference) = file.reference.take() else {
                kept.push(file);
                continue;
            };
            let name = names.iter().find(|n| entry(n, &reference));
            let read = match (name, archive.as_mut()) {
                (Some(name), Some(archive)) => read_entry(archive, name),
                _ => Err("missing from the export"),
            };
            match read {
                Ok(data) => {
                    file.data = data;
                    kept.push(file);
                }
                Err(reason) => missing.push((
                    format!("Attachment \"{}\"", file.name),
                    format!("not imported ({reason})"),
                )),
            }
        }
        item.attachments = kept;
        append_lines(&mut item.notes, &missing);
    }
    Ok(())
}

fn read_entry(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
    let file = archive.by_name(name).map_err(|_| "unreadable")?;
    if file.encrypted() {
        return Err("encrypted");
    }
    if file.size() > MAX_ATTACHMENT_SIZE {
        return Err("over 100 MB");
    }
    let mut data = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_ATTACHMENT_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|_| "unreadable")?;
    if data.len() as u64 > MAX_ATTACHMENT_SIZE {
        return Err("over 100 MB");
    }
    Ok(data)
}

/// Encrypted export (Proton Pass PGP, protected archive): nothing to read.
fn looks_encrypted(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"-----BEGIN PGP") {
        return true;
    }
    if bytes.starts_with(b"PK") {
        return zip_names(bytes).is_ok_and(|names| {
            names.iter().any(|n| {
                std::path::Path::new(n)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("pgp"))
            }) && !names
                .iter()
                .any(|n| n.ends_with("data.json") || n == "export.data")
        });
    }
    false
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

fn zip_names(bytes: &[u8]) -> Result<Vec<String>, ImportError> {
    let archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ImportError::Unreadable(format!("archive ZIP ({e})")))?;
    Ok(archive
        .file_names()
        .filter_map(Result::ok)
        .map(std::borrow::Cow::into_owned)
        .collect())
}

/// The JSON document of an export: inside a ZIP archive (the file whose
/// name matches), or the file itself.
fn json_document(
    bytes: &[u8],
    wanted: impl Fn(&str) -> bool,
    format: Format,
) -> Result<serde_json::Value, ImportError> {
    let wrong = || ImportError::WrongFormat(format.label());
    if !bytes.starts_with(b"PK") {
        return serde_json::from_slice(strip_bom(bytes)).map_err(|_| wrong());
    }
    let name = zip_names(bytes)?
        .into_iter()
        .find(|n| wanted(n))
        .ok_or_else(wrong)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ImportError::Unreadable(format!("archive ZIP ({e})")))?;
    let file = archive
        .by_name(&name)
        .map_err(|e| ImportError::Unreadable(format!("{name} ({e})")))?;
    if file.encrypted() {
        return Err(ImportError::Encrypted);
    }
    let mut content = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_SIZE + 1)
        .read_to_end(&mut content)
        .map_err(|e| ImportError::Unreadable(format!("{name} ({e})")))?;
    if content.len() as u64 > MAX_SIZE {
        return Err(ImportError::TooLarge);
    }
    serde_json::from_slice(strip_bom(&content)).map_err(|_| wrong())
}

/// Non-empty text, without surrounding whitespace.
fn text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

fn secret(value: Option<&str>) -> Option<SecretString> {
    // A password keeps its spaces: only empty fields disappear.
    value
        .filter(|v| !v.trim().is_empty())
        .map(SecretString::new)
}

/// Fields of an item imported with a template: the values found, under the
/// template's labels and in its order (hidden as it says), then the
/// export's other fields.
fn template_fields(
    template: Template,
    found: &[(&'static str, String)],
    others: Vec<ExtraField>,
) -> Vec<ExtraField> {
    let mut fields: Vec<ExtraField> = template
        .fields()
        .iter()
        .filter_map(|def| {
            let value = found
                .iter()
                .find(|(label, value)| *label == def.label && !value.trim().is_empty())?;
            Some(ExtraField {
                name: def.label.to_owned(),
                value: SecretString::new(value.1.clone()),
                hidden: def.hidden,
            })
        })
        .collect();
    debug_assert!(
        found
            .iter()
            .all(|(label, _)| template.fields().iter().any(|d| d.label == *label)),
        "label outside template {template:?}"
    );
    fields.extend(others);
    fields
}

/// "Label: value" lines, appended to an item's notes.
fn append_lines(notes: &mut Option<SecretString>, lines: &[(String, String)]) {
    if lines.is_empty() {
        return;
    }
    let mut text = notes
        .as_ref()
        .map(|n| n.expose().to_owned())
        .unwrap_or_default();
    for (label, value) in lines {
        if !text.is_empty() {
            text.push('\n');
        }
        let separator = if value.contains('\n') { ":\n" } else { ": " };
        text.push_str(label);
        text.push_str(separator);
        text.push_str(value);
    }
    *notes = Some(SecretString::new(text));
}

/// Calendar date of a Unix timestamp (`YYYY-MM-DD`), without a dependency.
fn date_of(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    // Howard Hinnant's algorithm ("civil_from_days").
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Unix timestamp of a `YYYY-MM-DD[THH:MM:SS…]` date, or of a number
/// (seconds or milliseconds).
fn timestamp_of(value: &str) -> Option<i64> {
    let value = value.trim();
    if let Ok(n) = value.parse::<i64>() {
        return Some(if n > 100_000_000_000 { n / 1000 } else { n });
    }
    let year: i64 = value.get(0..4)?.parse().ok()?;
    let month: i64 = value.get(5..7)?.parse().ok()?;
    let day: i64 = value.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Inverse of `date_of` ("days_from_civil").
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = value
        .get(11..19)
        .and_then(|t| {
            let h: i64 = t.get(0..2)?.parse().ok()?;
            let m: i64 = t.get(3..5)?.parse().ok()?;
            let s: i64 = t.get(6..8)?.parse().ok()?;
            Some(h * 3600 + m * 60 + s)
        })
        .unwrap_or(0);
    Some(days * 86_400 + seconds)
}

/// Card expiry: `2027-05`, `05/27`, `052027`, `202705` →
/// (`05`, `2027`).
fn expiry(value: &str) -> Option<(String, String)> {
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    let (month, year) = if value.contains('-') && digits.len() == 6 {
        (digits[4..].to_owned(), digits[..4].to_owned())
    } else {
        match digits.len() {
            4 => (digits[..2].to_owned(), format!("20{}", &digits[2..])),
            6 if digits.starts_with("20") || digits.starts_with("19") => {
                (digits[4..].to_owned(), digits[..4].to_owned())
            }
            6 => (digits[..2].to_owned(), digits[2..].to_owned()),
            _ => return None,
        }
    };
    let n: u32 = month.parse().ok()?;
    (1..=12).contains(&n).then(|| (format!("{n:02}"), year))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(1_709_251_200), "2024-03-01");
        assert_eq!(timestamp_of("2024-03-01"), Some(1_709_251_200));
        assert_eq!(timestamp_of("2024-03-01T01:00:00Z"), Some(1_709_254_800));
        assert_eq!(timestamp_of("1709251200000"), Some(1_709_251_200));
        assert_eq!(timestamp_of("hier"), None);
    }

    #[test]
    fn card_expiry_formats() {
        let both = |m: &str, y: &str| Some((m.to_owned(), y.to_owned()));
        assert_eq!(expiry("2027-05"), both("05", "2027"));
        assert_eq!(expiry("05/27"), both("05", "2027"));
        assert_eq!(expiry("052027"), both("05", "2027"));
        assert_eq!(expiry("202705"), both("05", "2027"));
        assert_eq!(expiry("13/27"), None);
        assert_eq!(expiry(""), None);
    }

    #[test]
    fn unknown_and_encrypted_files_are_refused() {
        assert_eq!(
            parse(b"bonjour", None).unwrap_err(),
            ImportError::UnknownFormat
        );
        assert_eq!(
            parse(b"-----BEGIN PGP MESSAGE-----\n...", None).unwrap_err(),
            ImportError::Encrypted
        );
        assert!(matches!(
            parse(b"{\"vaults\": 3}", Some(Format::OnePassword1pux)),
            Err(ImportError::WrongFormat(_))
        ));
    }
}
