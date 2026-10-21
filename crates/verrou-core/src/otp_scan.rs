//! Content of a two-factor authentication QR code: an `otpauth://totp` link,
//! a Google Authenticator export (`otpauth-migration://offline?data=…`,
//! protobuf) or a bare Base32 seed.
//!
//! Each account read is validated (Base32 seed, parameters supported by
//! [`Totp`]) then rewritten as a canonical `otpauth://totp` link: that link
//! is what goes into the item's encrypted draft. Decoded seeds are wiped on
//! drop.
//!
//! HOTP (counter) codes are not supported: Bitwarden only stores TOTP. An
//! `otpauth://hotp` link is refused with a clear message; in a Google
//! Authenticator export, those accounts are skipped and counted.

use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL};
use url::Url;
use zeroize::Zeroizing;

use crate::matching::registrable_domain;
use crate::model::{FieldKind, Item, ItemKind};
use crate::search::fold;
use crate::totp::{Algorithm, Totp, TotpError};
use crate::vault::Vault;

/// An account ready to save.
#[derive(Clone, Debug)]
pub struct OtpAccount {
    /// Service (`GitHub`), if known.
    pub issuer: Option<String>,
    /// Account at that service (`camille@exemple.fr`), if known.
    pub account: Option<String>,
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

/// Result of reading a QR code.
#[derive(Clone, Debug)]
pub struct OtpScan {
    pub accounts: Vec<OtpAccount>,
    /// HOTP accounts of a Google Authenticator export, skipped.
    pub skipped: usize,
    /// Export across several QR codes: (index from 0, total count).
    pub batch: Option<(u32, u32)>,
}

impl OtpAccount {
    /// Code generator for this account.
    pub fn totp(&self) -> Totp {
        // The canonical link always parses back: the parameters were validated.
        Totp::parse(&self.uri()).expect("canonical otpauth link")
    }

    /// Canonical `otpauth://totp` link, seed included: the value of the item's
    /// "one-time code" field.
    pub fn uri(&self) -> String {
        let mut uri = Url::parse("otpauth://totp/").expect("fixed URL");
        let label = match (&self.issuer, &self.account) {
            (Some(issuer), Some(account)) => format!("{issuer}:{account}"),
            (Some(only), None) | (None, Some(only)) => only.clone(),
            (None, None) => String::new(),
        };
        if !label.is_empty()
            && let Ok(mut segments) = uri.path_segments_mut()
        {
            segments.clear().push(&label);
        }
        {
            let secret = Zeroizing::new(BASE32_NOPAD.encode(&self.secret));
            let mut query = uri.query_pairs_mut();
            query.append_pair("secret", &secret);
            if let Some(issuer) = &self.issuer {
                query.append_pair("issuer", issuer);
            }
            match self.algorithm {
                Algorithm::Sha1 => {}
                Algorithm::Sha256 => {
                    query.append_pair("algorithm", "SHA256");
                }
                Algorithm::Sha512 => {
                    query.append_pair("algorithm", "SHA512");
                }
            }
            if self.digits != 6 {
                query.append_pair("digits", &self.digits.to_string());
            }
            if self.period != 30 {
                query.append_pair("period", &self.period.to_string());
            }
        }
        uri.to_string()
    }

    /// Title suggested for a new login.
    pub fn suggested_title(&self) -> String {
        self.issuer
            .clone()
            .or_else(|| self.account.clone())
            .unwrap_or_else(|| "One-time code".to_owned())
    }
}

/// Reads the text of a QR code (or pasted text).
pub fn parse_scan(input: &str) -> Result<OtpScan, TotpError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(TotpError::Empty);
    }
    let lower = input.to_ascii_lowercase();
    if lower.starts_with("otpauth-migration://") {
        return parse_migration(input);
    }
    let single = |account| OtpScan {
        accounts: vec![account],
        skipped: 0,
        batch: None,
    };
    if lower.starts_with("otpauth://") {
        return parse_otpauth(input).map(single);
    }
    // Other link, Wi-Fi, text: not a Base32 seed.
    if lower.contains("://")
        || !input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c.is_whitespace() || c == '-' || c == '=')
    {
        return Err(TotpError::NotOtp);
    }
    // Bare seed: validated as the editor's field would.
    let totp = Totp::parse(input)?;
    Ok(single(OtpAccount {
        issuer: None,
        account: None,
        secret: Zeroizing::new(totp.secret().to_vec()),
        algorithm: totp.algorithm,
        digits: totp.digits,
        period: totp.period,
    }))
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Splits the `Service:account` label; the `issuer` parameter, when
/// present, wins over the prefix.
fn split_label(label: &str, issuer_param: Option<String>) -> (Option<String>, Option<String>) {
    let (prefix, account) = match label.split_once(':') {
        Some((prefix, account)) => (non_empty(prefix), non_empty(account)),
        None => (None, non_empty(label)),
    };
    (issuer_param.or(prefix), account)
}

/// `%XX` decoding of a path (a `+` stays a `+` there).
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_otpauth(input: &str) -> Result<OtpAccount, TotpError> {
    let uri = Url::parse(input).map_err(|_| TotpError::InvalidUri)?;
    match uri.host_str().map(str::to_ascii_lowercase).as_deref() {
        Some("totp") => {}
        Some("hotp") => return Err(TotpError::Hotp),
        other => return Err(TotpError::Unsupported(other.unwrap_or("").to_owned())),
    }
    // Parameters and seed validated by the existing parser.
    let totp = Totp::parse(input)?;
    let label = percent_decode(uri.path().trim_start_matches('/'));
    let issuer = uri
        .query_pairs()
        .find(|(k, _)| k == "issuer")
        .and_then(|(_, v)| non_empty(&v));
    let (issuer, account) = split_label(&label, issuer);
    Ok(OtpAccount {
        issuer,
        account,
        secret: Zeroizing::new(totp.secret().to_vec()),
        algorithm: totp.algorithm,
        digits: totp.digits,
        period: totp.period,
    })
}

// MARK: Google Authenticator export

fn parse_migration(input: &str) -> Result<OtpScan, TotpError> {
    let uri = Url::parse(input).map_err(|_| TotpError::InvalidMigration)?;
    if uri.host_str() != Some("offline") {
        return Err(TotpError::InvalidMigration);
    }
    let data = uri
        .query_pairs()
        .find(|(k, _)| k == "data")
        .map(|(_, v)| v.into_owned())
        .ok_or(TotpError::InvalidMigration)?;
    let bytes = Zeroizing::new(decode_base64(&data)?);
    let mut accounts = Vec::new();
    let mut skipped = 0;
    let (mut batch_size, mut batch_index) = (0u64, 0u64);
    let mut reader = Proto::new(&bytes);
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (1, Value::Bytes(parameters)) => match migration_account(parameters)? {
                Some(account) => accounts.push(account),
                None => skipped += 1,
            },
            (3, Value::Varint(n)) => batch_size = n,
            (4, Value::Varint(n)) => batch_index = n,
            _ => {}
        }
    }
    if accounts.is_empty() && skipped == 0 {
        return Err(TotpError::InvalidMigration);
    }
    let batch = (batch_size > 1).then_some((batch_index as u32, batch_size as u32));
    Ok(OtpScan {
        accounts,
        skipped,
        batch,
    })
}

/// Standard or "URL" Base64, with or without padding. A `+` turned into a
/// space by link decoding becomes `+` again.
fn decode_base64(data: &str) -> Result<Vec<u8>, TotpError> {
    let cleaned: String = data
        .chars()
        .map(|c| if c == ' ' { '+' } else { c })
        .filter(|c| !c.is_whitespace())
        .collect();
    let unpadded = cleaned.trim_end_matches('=');
    let padded = format!("{unpadded}{}", "=".repeat((4 - unpadded.len() % 4) % 4));
    BASE64
        .decode(padded.as_bytes())
        .or_else(|_| BASE64URL.decode(padded.as_bytes()))
        .map_err(|_| TotpError::InvalidMigration)
}

/// An `OtpParameters` of the Google Authenticator protobuf; `None` for a
/// skipped account (HOTP, MD5).
fn migration_account(bytes: &[u8]) -> Result<Option<OtpAccount>, TotpError> {
    let mut secret = Zeroizing::new(Vec::new());
    let (mut name, mut issuer) = (String::new(), String::new());
    let (mut algorithm, mut digits, mut kind) = (0u64, 0u64, 0u64);
    let mut reader = Proto::new(bytes);
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (1, Value::Bytes(b)) => secret = Zeroizing::new(b.to_vec()),
            (2, Value::Bytes(b)) => name = String::from_utf8_lossy(b).into_owned(),
            (3, Value::Bytes(b)) => issuer = String::from_utf8_lossy(b).into_owned(),
            (4, Value::Varint(n)) => algorithm = n,
            (5, Value::Varint(n)) => digits = n,
            (6, Value::Varint(n)) => kind = n,
            _ => {}
        }
    }
    // Type: 0 unspecified (TOTP), 1 HOTP, 2 TOTP.
    if kind == 1 {
        return Ok(None);
    }
    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        // MD5 (4): no serious service, and Bitwarden does not know it.
        _ => return Ok(None),
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        _ => return Err(TotpError::InvalidMigration),
    };
    if secret.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    // The name often carries the service as a prefix (`GitHub:camille`).
    let issuer_field = non_empty(&issuer);
    let (issuer, account) = match name.split_once(':') {
        Some((prefix, rest)) if issuer_field.as_deref().is_none_or(|i| prefix.trim() == i) => {
            (issuer_field.or_else(|| non_empty(prefix)), non_empty(rest))
        }
        _ => (issuer_field, non_empty(&name)),
    };
    Ok(Some(OtpAccount {
        issuer,
        account,
        secret,
        algorithm,
        digits,
        period: 30,
    }))
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

/// Minimal protobuf reader: varints, length-delimited fields, fixed
/// integers (ignored). Enough for the export format, without one more
/// dependency.
struct Proto<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Proto<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn varint(&mut self) -> Result<u64, TotpError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.bytes.get(self.at).ok_or(TotpError::InvalidMigration)?;
            self.at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(TotpError::InvalidMigration)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TotpError> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(TotpError::InvalidMigration)?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>, TotpError> {
        if self.at >= self.bytes.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let value = match key & 7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed
            }
            2 => {
                let len =
                    usize::try_from(self.varint()?).map_err(|_| TotpError::InvalidMigration)?;
                Value::Bytes(self.take(len)?)
            }
            5 => {
                self.take(4)?;
                Value::Fixed
            }
            _ => return Err(TotpError::InvalidMigration),
        };
        Ok(Some((key >> 3, value)))
    }
}

// MARK: Matching logins

/// Comparable form of a service name: without accents, case, spaces or
/// punctuation (`Free Mobile` → `freemobile`).
fn compact(text: &str) -> String {
    fold(text).chars().filter(|c| c.is_alphanumeric()).collect()
}

/// Name of the registrable domain without its suffix (`github.com` → `github`).
fn domain_name(url: &str) -> Option<String> {
    let domain = registrable_domain(url)?;
    let name = domain.split('.').next()?;
    Some(compact(name))
}

/// Active, writable logins without a one-time code that this account can be
/// added to: same service (title or registrable domain of a site), or, with
/// no known service, same username. Most likely first (both service and
/// username).
pub fn matching_logins<'v>(vault: &'v Vault, account: &OtpAccount) -> Vec<&'v Item> {
    let issuer = account
        .issuer
        .as_deref()
        .map(compact)
        .filter(|s| !s.is_empty());
    // A service written as a domain (`github.com`) is also compared by domain.
    let issuer_domain = account
        .issuer
        .as_deref()
        .filter(|i| i.contains('.'))
        .and_then(domain_name);
    let user = account.account.as_deref().map(fold);
    let mut found: Vec<(u8, &Item)> = vault
        .items()
        .iter()
        .filter(|item| item.kind == ItemKind::Login && item.is_active() && item.is_writable())
        .filter(|item| !item.has_totp())
        .filter_map(|item| {
            let same_user = user.as_ref().is_some_and(|u| {
                item.field_of_kind(FieldKind::Username)
                    .or_else(|| item.field_of_kind(FieldKind::Email))
                    .is_some_and(|f| fold(f.value.expose().trim()) == *u)
            });
            let same_service = issuer.as_ref().is_some_and(|issuer| {
                let title = compact(&item.title);
                title == *issuer
                    || (issuer.len() >= 3 && title.contains(issuer.as_str()))
                    || item.urls.iter().any(|u| {
                        domain_name(u)
                            .is_some_and(|d| d == *issuer || Some(&d) == issuer_domain.as_ref())
                    })
            });
            let rank = match (same_service, same_user, issuer.is_some()) {
                (true, true, _) => 2,
                (true, false, _) | (false, true, false) => 1,
                _ => return None,
            };
            Some((rank, item))
        })
        .collect();
    found.sort_by(|(ra, a), (rb, b)| {
        rb.cmp(ra)
            .then(b.favorite.cmp(&a.favorite))
            .then_with(|| fold(&a.title).cmp(&fold(&b.title)))
    });
    found.into_iter().map(|(_, item)| item).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, ItemState, Sharing};

    /// Published Google Authenticator example: seed "Hello!\xde\xad\xbe\xef".
    const GOOGLE_EXAMPLE: &str =
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    /// The same account, exported by Google Authenticator (vector known to
    /// extraction tools).
    const GOOGLE_MIGRATION: &str = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC";
    /// Export of three accounts, batch 1 of 2: RFC 6238 seed (SHA-1,
    /// 8 digits), the RFC's SHA-256 seed (6 digits, accented name),
    /// and an HOTP account to skip. Built byte by byte from
    /// `google_auth.proto`.
    const MULTI_MIGRATION: &str = "otpauth-migration://offline?data=CjcKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg9yZmNAZXhhbXBsZS5jb20aCFJGQyA2MjM4IAEoAjACCkIKIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyEg%2FDiXF1aXBlOmNhbWlsbGUaB8OJcXVpcGUgAigBMAIKMAoKSGVsbG8h3q2%2B7xIQaG90cEBleGFtcGxlLmNvbRoIQ29tcHRldXIgASgBMAE4BxABGAIgACjAxAc%3D";

    #[test]
    fn otpauth_link_gives_issuer_account_and_code() {
        let scan = parse_scan(GOOGLE_EXAMPLE).unwrap();
        assert_eq!(scan.accounts.len(), 1);
        let account = &scan.accounts[0];
        assert_eq!(account.issuer.as_deref(), Some("Example"));
        assert_eq!(account.account.as_deref(), Some("alice@google.com"));
        let direct = Totp::parse(GOOGLE_EXAMPLE).unwrap();
        assert_eq!(
            account.totp().generate(1_700_000_000),
            direct.generate(1_700_000_000)
        );
        assert_eq!(
            account.uri(),
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        );
    }

    #[test]
    fn label_prefix_and_encoding() {
        let scan = parse_scan(
            "otpauth://totp/Free%20Mobile%3Acamille%2Bpro%40exemple.fr?secret=JBSWY3DPEHPK3PXP",
        )
        .unwrap();
        let account = &scan.accounts[0];
        assert_eq!(account.issuer.as_deref(), Some("Free Mobile"));
        assert_eq!(account.account.as_deref(), Some("camille+pro@exemple.fr"));
        // The canonical link parses back identically.
        let again = parse_scan(&account.uri()).unwrap();
        assert_eq!(again.accounts[0].issuer, account.issuer);
        assert_eq!(again.accounts[0].account, account.account);

        let bare = parse_scan("otpauth://totp/?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(bare.accounts[0].issuer, None);
        assert_eq!(bare.accounts[0].account, None);
        assert_eq!(bare.accounts[0].suggested_title(), "One-time code");
    }

    #[test]
    fn non_default_parameters_survive_the_canonical_link() {
        let scan = parse_scan(
            "otpauth://TOTP/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=sha256&digits=8&period=60",
        )
        .unwrap();
        let account = &scan.accounts[0];
        assert_eq!(
            (account.algorithm, account.digits, account.period),
            (Algorithm::Sha256, 8, 60)
        );
        assert!(
            account
                .uri()
                .contains("algorithm=SHA256&digits=8&period=60")
        );
        // RFC 6238, SHA-256, t = 59 s (60 s period: same counter as t = 0..59).
        assert_eq!(
            Totp::parse(&account.uri()).unwrap().generate(59).code.len(),
            8
        );
    }

    #[test]
    fn bare_secret_is_accepted_and_validated() {
        let scan = parse_scan("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(
            scan.accounts[0].uri(),
            "otpauth://totp/?secret=JBSWY3DPEHPK3PXP"
        );
        assert_eq!(
            parse_scan("pas une graine !").unwrap_err(),
            TotpError::NotOtp
        );
        assert_eq!(
            parse_scan("0189 0189").unwrap_err(),
            TotpError::InvalidSecret
        );
    }

    #[test]
    fn invalid_or_foreign_codes_are_rejected() {
        assert_eq!(parse_scan("  ").unwrap_err(), TotpError::Empty);
        assert_eq!(
            parse_scan("https://exemple.fr/login").unwrap_err(),
            TotpError::NotOtp
        );
        assert_eq!(
            parse_scan("WIFI:S:maison;T:WPA;P:x;;").unwrap_err(),
            TotpError::NotOtp
        );
        assert_eq!(
            parse_scan("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").unwrap_err(),
            TotpError::Hotp
        );
        assert_eq!(
            parse_scan("otpauth://totp/x?secret=0189").unwrap_err(),
            TotpError::InvalidSecret
        );
        assert_eq!(
            parse_scan("otpauth://totp/x?issuer=Sans").unwrap_err(),
            TotpError::InvalidUri
        );
        assert!(matches!(
            parse_scan("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4"),
            Err(TotpError::Unsupported(_))
        ));
        assert_eq!(
            parse_scan("otpauth-migration://offline?data=%%%").unwrap_err(),
            TotpError::InvalidMigration
        );
        assert_eq!(
            parse_scan("otpauth-migration://offline?data=CgUKA").unwrap_err(),
            TotpError::InvalidMigration
        );
        assert_eq!(
            parse_scan("otpauth-migration://offline").unwrap_err(),
            TotpError::InvalidMigration
        );
    }

    #[test]
    fn google_migration_known_vector() {
        let scan = parse_scan(GOOGLE_MIGRATION).unwrap();
        assert_eq!(
            (scan.accounts.len(), scan.skipped, scan.batch),
            (1, 0, None)
        );
        let account = &scan.accounts[0];
        assert_eq!(account.issuer.as_deref(), Some("Example"));
        assert_eq!(account.account.as_deref(), Some("alice@google.com"));
        assert_eq!(
            account.uri(),
            parse_scan(GOOGLE_EXAMPLE).unwrap().accounts[0].uri()
        );
    }

    #[test]
    fn google_migration_several_accounts() {
        let scan = parse_scan(MULTI_MIGRATION).unwrap();
        assert_eq!(scan.accounts.len(), 2);
        assert_eq!(scan.skipped, 1, "the HOTP account is skipped");
        assert_eq!(scan.batch, Some((0, 2)));

        let rfc = &scan.accounts[0];
        assert_eq!(rfc.issuer.as_deref(), Some("RFC 6238"));
        assert_eq!(rfc.account.as_deref(), Some("rfc@example.com"));
        assert_eq!((rfc.algorithm, rfc.digits), (Algorithm::Sha1, 8));
        // RFC 6238 vectors, appendix B.
        assert_eq!(rfc.totp().generate(59).code, "94287082");
        assert_eq!(rfc.totp().generate(1_111_111_109).code, "07081804");

        let team = &scan.accounts[1];
        assert_eq!(team.issuer.as_deref(), Some("Équipe"));
        assert_eq!(
            team.account.as_deref(),
            Some("camille"),
            "service prefix removed from the name"
        );
        assert_eq!((team.algorithm, team.digits), (Algorithm::Sha256, 6));
        assert_eq!(team.totp().generate(59).code, "119246");
        assert!(
            team.uri()
                .starts_with("otpauth://totp/%C3%89quipe:camille?secret=")
        );
    }

    #[test]
    fn migration_tolerates_unencoded_plus_and_url_safe_base64() {
        let raw = MULTI_MIGRATION
            .replace("%2F", "/")
            .replace("%2B", "+")
            .replace("%3D", "");
        assert_eq!(parse_scan(&raw).unwrap().accounts.len(), 2);
        let (prefix, data) = raw.split_once("data=").unwrap();
        let url_safe = format!("{prefix}data={}", data.replace('+', "-").replace('/', "_"));
        assert_eq!(parse_scan(&url_safe).unwrap().accounts.len(), 2);
    }

    fn login(id: &str, title: &str, user: &str, urls: &[&str], totp: bool) -> Item {
        let mut fields = vec![Field::new(
            "username",
            "Identifiant",
            FieldKind::Username,
            user,
        )];
        if totp {
            fields.push(Field::new(
                "totp",
                "Code",
                FieldKind::Totp,
                "JBSWY3DPEHPK3PXP",
            ));
        }
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: title.to_owned(),
            subtitle: user.to_owned(),
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            url_matches: Vec::new(),
            folder: None,
            tags: vec![],
            favorite: false,
            created: 0,
            modified: 0,
            fields,
            notes: None,
            reprompt: false,
            state: ItemState::Active,
            shared: None,
        }
    }

    fn account(issuer: Option<&str>, user: Option<&str>) -> OtpAccount {
        let mut account = parse_scan("JBSWY3DPEHPK3PXP").unwrap().accounts.remove(0);
        account.issuer = issuer.map(str::to_owned);
        account.account = user.map(str::to_owned);
        account
    }

    #[test]
    fn matching_logins_by_service_domain_and_user() {
        let mut trashed = login("trash", "GitHub", "camille", &["https://github.com"], false);
        trashed.state = ItemState::Trashed;
        let mut read_only = login("ro", "GitHub", "camille", &["https://github.com"], false);
        read_only.shared = Some(Sharing {
            read_only: true,
            ..Sharing::default()
        });
        let vault = Vault::new(vec![
            login(
                "gh-other",
                "Code",
                "autre",
                &["https://login.github.com"],
                false,
            ),
            login("gh", "Mon GitHub", "camille@exemple.fr", &[], false),
            login(
                "gh-totp",
                "GitHub pro",
                "camille@exemple.fr",
                &["https://github.com"],
                true,
            ),
            login(
                "free",
                "Opérateur",
                "camille",
                &["https://mobile.free.fr"],
                false,
            ),
            login(
                "bank",
                "Banque",
                "camille@exemple.fr",
                &["https://banque.fr"],
                false,
            ),
            trashed,
            read_only,
        ]);
        let ids = |a: &OtpAccount| {
            matching_logins(&vault, a)
                .iter()
                .map(|i| i.id.clone())
                .collect::<Vec<_>>()
        };
        // Service and username first, then the domain alone; never an item
        // that already has a code, is in the trash or is read-only.
        assert_eq!(
            ids(&account(Some("GitHub"), Some("camille@exemple.fr"))),
            ["gh", "gh-other"]
        );
        assert_eq!(ids(&account(Some("github.com"), None)), ["gh-other"]);
        assert_eq!(ids(&account(Some("Free"), Some("camille"))), ["free"]);
        // An unknown service does not attach to a shared username.
        assert_eq!(
            ids(&account(Some("Inconnu"), Some("camille@exemple.fr"))),
            Vec::<String>::new()
        );
        // Without a service: the username alone.
        assert_eq!(
            ids(&account(None, Some("CAMILLE@exemple.fr"))),
            ["bank", "gh"]
        );
    }
}
