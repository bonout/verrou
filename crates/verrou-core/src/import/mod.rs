//! Lecture des exports d'autres gestionnaires de mots de passe : Mots de
//! passe d'Apple (CSV), 1Password (`.1pux` ou CSV) et Proton Pass (ZIP non
//! chiffré ou CSV).
//!
//! Comme le reste du crate, aucune entrée-sortie : on reçoit le contenu du
//! fichier, on rend des éléments au format commun ([`ImportedItem`]) et la
//! liste de ce qui a été laissé de côté, avec la raison. Les secrets passent
//! aussitôt dans des `SecretString`. Limite connue : les lecteurs CSV et JSON
//! gardent des copies intermédiaires qui ne sont pas mises à zéro ; elles
//! sont libérées à la fin de la lecture.
//!
//! La comparaison avec le coffre (doublons, mots de passe différents) est
//! dans [`crate::duplicates`].
//!
//! Pièces jointes : les archives de 1Password (`files/`) et de Proton Pass
//! (`Proton Pass/files/`) portent les fichiers des éléments. Ils sont lus
//! ici, dans des tampons effacés à la libération ([`ImportedFile`]), pour
//! devenir des pièces jointes Bitwarden.

mod csv_formats;
mod onepassword;
mod proton;

use std::io::{Cursor, Read};

use crate::matching::host_of;
use crate::secret::SecretString;

/// Taille maximale d'un fichier d'export, et d'un fichier extrait d'une
/// archive : de quoi contenir des dizaines de milliers d'éléments, pas une
/// bombe de décompression.
pub const MAX_SIZE: u64 = 64 * 1024 * 1024;

/// Taille maximale d'une archive d'export (ZIP de 1Password ou de Proton
/// Pass), pièces jointes comprises.
pub const MAX_ARCHIVE_SIZE: u64 = 512 * 1024 * 1024;

/// Taille maximale d'une pièce jointe, avant chiffrement : celle que Verrou
/// applique aussi à l'ajout d'un fichier.
pub const MAX_ATTACHMENT_SIZE: u64 = 100 * 1024 * 1024;

/// Format d'un fichier d'export.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// App Mots de passe de macOS : Fichier → Exporter tous les mots de passe.
    ApplePasswordsCsv,
    /// 1Password : Fichier → Exporter → 1PUX.
    OnePassword1pux,
    /// 1Password : Fichier → Exporter → CSV.
    OnePasswordCsv,
    /// Proton Pass : Réglages → Exporter, ZIP non chiffré.
    ProtonPassZip,
    /// Proton Pass : Réglages → Exporter, CSV.
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

    /// Nom de l'application d'origine (et du dossier « Import … »).
    pub fn source(self) -> &'static str {
        match self {
            Self::ApplePasswordsCsv => "Apple",
            Self::OnePassword1pux | Self::OnePasswordCsv => "1Password",
            Self::ProtonPassZip | Self::ProtonPassCsv => "Proton Pass",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ApplePasswordsCsv => "Mots de passe d'Apple (CSV)",
            Self::OnePassword1pux => "1Password (1PUX)",
            Self::OnePasswordCsv => "1Password (CSV)",
            Self::ProtonPassZip => "Proton Pass (ZIP)",
            Self::ProtonPassCsv => "Proton Pass (CSV)",
        }
    }
}

/// Ce que devient un élément importé dans Vaultwarden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportKind {
    Login,
    SecureNote,
    Card,
}

/// Carte bancaire importée.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CardData {
    pub cardholder: Option<String>,
    pub brand: Option<String>,
    pub number: Option<SecretString>,
    /// Mois sur un ou deux chiffres (`9`, `09`).
    pub exp_month: Option<String>,
    /// Année sur quatre chiffres.
    pub exp_year: Option<String>,
    pub code: Option<SecretString>,
}

/// Champ supplémentaire d'un identifiant ou d'une carte (devient un champ
/// personnalisé Bitwarden, masqué s'il est secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraField {
    pub name: String,
    pub value: SecretString,
    pub hidden: bool,
}

/// Fichier joint à un élément importé. Son contenu est effacé de la
/// mémoire à la libération ; `Debug` ne le montre pas.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedFile {
    pub name: String,
    pub data: zeroize::Zeroizing<Vec<u8>>,
    /// Où le trouver dans l'archive, le temps de la lecture.
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

    /// Fichier annoncé par l'export, à chercher dans l'archive.
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

/// Un élément lu dans un export, au format commun.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedItem {
    pub kind: ImportKind,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub urls: Vec<String>,
    /// Graine TOTP (`otpauth://…` ou base32).
    pub totp: Option<SecretString>,
    pub notes: Option<SecretString>,
    /// Dossier (ou coffre) dans l'application d'origine.
    pub folder: Option<String>,
    pub favorite: bool,
    pub card: Option<CardData>,
    pub fields: Vec<ExtraField>,
    /// Dernière modification dans l'application d'origine (Unix, secondes),
    /// quand l'export la donne.
    pub modified: Option<i64>,
    /// Pièces jointes (archives de 1Password et de Proton Pass).
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
            fields: Vec::new(),
            modified: None,
            attachments: Vec::new(),
        }
    }

    /// Hôte du premier site, sans `www.`.
    pub fn primary_host(&self) -> Option<String> {
        self.urls.iter().find_map(|u| host_of(u))
    }
}

/// Un élément laissé de côté, et pourquoi. Jamais de secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub title: String,
    pub reason: String,
}

/// Le contenu d'un export.
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
                "(sans nom)".to_owned()
            } else {
                title.to_owned()
            },
            reason: reason.to_owned(),
        });
    }

    /// Range un élément lu : titre de repli, identifiant vide changé en note,
    /// élément vide ignoré.
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
            // Un document (un fichier seul) reste une note sécurisée.
            ImportKind::SecureNote => {
                item.notes.is_none() && item.fields.is_empty() && item.attachments.is_empty()
            }
            ImportKind::Card => item.card.as_ref().is_none_or(|c| *c == CardData::default()),
            ImportKind::Login => false,
        };
        if empty {
            let title = item.title.clone();
            self.skip(&title, "élément vide");
            return;
        }
        if item.title.is_empty() {
            "(sans nom)".clone_into(&mut item.title);
        }
        self.items.push(item);
    }
}

/// Ce qui empêche de lire un fichier.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("format non reconnu : choisissez l'application d'origine")]
    UnknownFormat,
    #[error("export chiffré : exportez de nouveau, sans chiffrement")]
    Encrypted,
    #[error("fichier trop volumineux (64 Mo au plus, 512 Mo pour une archive)")]
    TooLarge,
    #[error("fichier illisible : {0}")]
    Unreadable(String),
    #[error("ce fichier n'est pas un export {0}")]
    WrongFormat(&'static str),
}

/// Reconnaît le format d'un export d'après son contenu.
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

/// Lit un export ; sans `format`, le reconnaît d'abord.
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

/// Lit dans l'archive les fichiers annoncés par l'export ; `entry` dit si un
/// nom de l'archive est celui d'une référence. Un fichier absent ou trop
/// volumineux n'est pas importé, et les notes de l'élément le disent.
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
    // `export.data` seul, sans son archive : les fichiers manquent.
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
                _ => Err("absente de l'export"),
            };
            match read {
                Ok(data) => {
                    file.data = data;
                    kept.push(file);
                }
                Err(reason) => missing.push((
                    format!("Pièce jointe « {} »", file.name),
                    format!("non importée ({reason})"),
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
    let file = archive.by_name(name).map_err(|_| "illisible")?;
    if file.encrypted() {
        return Err("chiffrée");
    }
    if file.size() > MAX_ATTACHMENT_SIZE {
        return Err("plus de 100 Mo");
    }
    let mut data = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_ATTACHMENT_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|_| "illisible")?;
    if data.len() as u64 > MAX_ATTACHMENT_SIZE {
        return Err("plus de 100 Mo");
    }
    Ok(data)
}

/// Export chiffré (PGP de Proton Pass, archive protégée) : rien à lire.
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

/// Le document JSON d'un export : dans une archive ZIP (le fichier dont le
/// nom convient), ou le fichier lui-même.
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

/// Texte non vide, sans espaces autour.
fn text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

fn secret(value: Option<&str>) -> Option<SecretString> {
    // Un mot de passe garde ses espaces : seuls les champs vides disparaissent.
    value
        .filter(|v| !v.trim().is_empty())
        .map(SecretString::new)
}

/// Lignes « Libellé : valeur », ajoutées aux notes d'un élément.
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
        let separator = if value.contains('\n') { " :\n" } else { " : " };
        text.push_str(label);
        text.push_str(separator);
        text.push_str(value);
    }
    *notes = Some(SecretString::new(text));
}

/// Date civile d'un horodatage Unix (`AAAA-MM-JJ`), sans dépendance.
fn date_of(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    // Algorithme de Howard Hinnant (« civil_from_days »).
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

/// Horodatage Unix d'une date `AAAA-MM-JJ[THH:MM:SS…]`, ou d'un nombre
/// (secondes ou millisecondes).
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
    // Inverse de `date_of` (« days_from_civil »).
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

/// Expiration d'une carte : `2027-05`, `05/27`, `052027`, `202705` →
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
