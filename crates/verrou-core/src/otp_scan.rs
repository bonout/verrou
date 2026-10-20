//! Contenu d'un QR code de double authentification : lien `otpauth://totp`,
//! export de Google Authenticator (`otpauth-migration://offline?data=…`,
//! protobuf) ou graine Base32 nue.
//!
//! Chaque compte lu est validé (graine Base32, paramètres pris en charge par
//! [`Totp`]) puis réécrit en un lien `otpauth://totp` canonique : c'est ce lien
//! qui part dans le brouillon chiffré de l'élément. Les graines décodées sont
//! effacées à la libération.
//!
//! Les codes HOTP (à compteur) ne sont pas pris en charge : Bitwarden ne
//! stocke que des TOTP. Un lien `otpauth://hotp` est refusé avec un message
//! clair ; dans un export Google Authenticator, ces comptes sont écartés et
//! comptés.

use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL};
use url::Url;
use zeroize::Zeroizing;

use crate::matching::registrable_domain;
use crate::model::{FieldKind, Item, ItemKind};
use crate::search::fold;
use crate::totp::{Algorithm, Totp, TotpError};
use crate::vault::Vault;

/// Un compte prêt à enregistrer.
#[derive(Clone, Debug)]
pub struct OtpAccount {
    /// Service (`GitHub`), s'il est connu.
    pub issuer: Option<String>,
    /// Compte chez ce service (`camille@exemple.fr`), s'il est connu.
    pub account: Option<String>,
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

/// Résultat de la lecture d'un QR code.
#[derive(Clone, Debug)]
pub struct OtpScan {
    pub accounts: Vec<OtpAccount>,
    /// Comptes HOTP d'un export Google Authenticator, écartés.
    pub skipped: usize,
    /// Export en plusieurs QR codes : (rang à partir de 0, nombre total).
    pub batch: Option<(u32, u32)>,
}

impl OtpAccount {
    /// Générateur de codes de ce compte.
    pub fn totp(&self) -> Totp {
        // Le lien canonique se relit toujours : les paramètres ont été validés.
        Totp::parse(&self.uri()).expect("lien otpauth canonique")
    }

    /// Lien `otpauth://totp` canonique, graine comprise : la valeur du champ
    /// « code à usage unique » de l'élément.
    pub fn uri(&self) -> String {
        let mut uri = Url::parse("otpauth://totp/").expect("URL fixe");
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

    /// Titre proposé pour un nouvel identifiant.
    pub fn suggested_title(&self) -> String {
        self.issuer
            .clone()
            .or_else(|| self.account.clone())
            .unwrap_or_else(|| "Code à usage unique".to_owned())
    }
}

/// Lit le texte d'un QR code (ou un texte collé).
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
    // Autre lien, Wi-Fi, texte : pas une graine Base32.
    if lower.contains("://")
        || !input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c.is_whitespace() || c == '-' || c == '=')
    {
        return Err(TotpError::NotOtp);
    }
    // Graine nue : validée comme le ferait le champ de l'éditeur.
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

/// Sépare l'étiquette `Service:compte` ; le paramètre `issuer`, s'il est
/// présent, l'emporte sur le préfixe.
fn split_label(label: &str, issuer_param: Option<String>) -> (Option<String>, Option<String>) {
    let (prefix, account) = match label.split_once(':') {
        Some((prefix, account)) => (non_empty(prefix), non_empty(account)),
        None => (None, non_empty(label)),
    };
    (issuer_param.or(prefix), account)
}

/// Décodage `%XX` d'un chemin (un `+` y reste un `+`).
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
    // Paramètres et graine validés par l'analyse existante.
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

// MARK: Export de Google Authenticator

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

/// Base64 standard ou « URL », avec ou sans remplissage. Un `+` devenu
/// espace au décodage du lien redevient `+`.
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

/// Un `OtpParameters` du protobuf de Google Authenticator ; `None` pour un
/// compte écarté (HOTP, MD5).
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
    // Type : 0 non précisé (TOTP), 1 HOTP, 2 TOTP.
    if kind == 1 {
        return Ok(None);
    }
    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        // MD5 (4) : aucun service sérieux, et Bitwarden ne le connaît pas.
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
    // Le nom porte souvent le service en préfixe (`GitHub:camille`).
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

/// Lecteur protobuf minimal : varints, champs de longueur, entiers fixes
/// (ignorés). Assez pour le format d'export, sans dépendance de plus.
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

// MARK: Identifiants correspondants

/// Forme comparable d'un nom de service : sans accents, casse, espaces ni
/// ponctuation (`Free Mobile` → `freemobile`).
fn compact(text: &str) -> String {
    fold(text).chars().filter(|c| c.is_alphanumeric()).collect()
}

/// Nom du domaine enregistrable sans son suffixe (`github.com` → `github`).
fn domain_name(url: &str) -> Option<String> {
    let domain = registrable_domain(url)?;
    let name = domain.split('.').next()?;
    Some(compact(name))
}

/// Identifiants actifs et modifiables, sans code à usage unique, auxquels ce
/// compte peut s'ajouter : même service (titre ou domaine enregistrable d'un
/// site), ou, sans service connu, même identifiant. Les plus probables
/// d'abord (service et identifiant à la fois).
pub fn matching_logins<'v>(vault: &'v Vault, account: &OtpAccount) -> Vec<&'v Item> {
    let issuer = account
        .issuer
        .as_deref()
        .map(compact)
        .filter(|s| !s.is_empty());
    // Un service écrit comme un domaine (`github.com`) se compare aussi par domaine.
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

    /// Exemple publié de Google Authenticator : graine « Hello!\xde\xad\xbe\xef ».
    const GOOGLE_EXAMPLE: &str =
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    /// Le même compte, exporté par Google Authenticator (vecteur connu des
    /// outils d'extraction).
    const GOOGLE_MIGRATION: &str = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC";
    /// Export de trois comptes, lot 1 sur 2 : graine de la RFC 6238 (SHA-1,
    /// 8 chiffres), graine SHA-256 de la RFC (6 chiffres, nom accentué),
    /// et un compte HOTP à écarter. Construit octet par octet d'après
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
        // Le lien canonique se relit à l'identique.
        let again = parse_scan(&account.uri()).unwrap();
        assert_eq!(again.accounts[0].issuer, account.issuer);
        assert_eq!(again.accounts[0].account, account.account);

        let bare = parse_scan("otpauth://totp/?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(bare.accounts[0].issuer, None);
        assert_eq!(bare.accounts[0].account, None);
        assert_eq!(bare.accounts[0].suggested_title(), "Code à usage unique");
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
        // RFC 6238, SHA-256, t = 59 s (période de 60 s : même compteur que t = 0..59).
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
        assert_eq!(scan.skipped, 1, "le compte HOTP est écarté");
        assert_eq!(scan.batch, Some((0, 2)));

        let rfc = &scan.accounts[0];
        assert_eq!(rfc.issuer.as_deref(), Some("RFC 6238"));
        assert_eq!(rfc.account.as_deref(), Some("rfc@example.com"));
        assert_eq!((rfc.algorithm, rfc.digits), (Algorithm::Sha1, 8));
        // Vecteurs de la RFC 6238, annexe B.
        assert_eq!(rfc.totp().generate(59).code, "94287082");
        assert_eq!(rfc.totp().generate(1_111_111_109).code, "07081804");

        let team = &scan.accounts[1];
        assert_eq!(team.issuer.as_deref(), Some("Équipe"));
        assert_eq!(
            team.account.as_deref(),
            Some("camille"),
            "préfixe du service retiré du nom"
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
        // Service et identifiant d'abord, puis le domaine seul ; jamais un
        // élément qui a déjà un code, à la corbeille ou en lecture seule.
        assert_eq!(
            ids(&account(Some("GitHub"), Some("camille@exemple.fr"))),
            ["gh", "gh-other"]
        );
        assert_eq!(ids(&account(Some("github.com"), None)), ["gh-other"]);
        assert_eq!(ids(&account(Some("Free"), Some("camille"))), ["free"]);
        // Un service inconnu ne se rattache pas à un identifiant partagé.
        assert_eq!(
            ids(&account(Some("Inconnu"), Some("camille@exemple.fr"))),
            Vec::<String>::new()
        );
        // Sans service : l'identifiant seul.
        assert_eq!(
            ids(&account(None, Some("CAMILLE@exemple.fr"))),
            ["bank", "gh"]
        );
    }
}
