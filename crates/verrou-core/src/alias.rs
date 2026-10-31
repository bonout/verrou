use std::fmt;
use std::net::IpAddr;

use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

use crate::matching::host_of;

pub const SITE_MAX_LEN: usize = 20;
pub const SUFFIX_LEN: usize = 5;
pub const RANDOM_LEN: usize = 10;
pub const FALLBACK_SITE: &str = "alias";
pub const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
const DOMAIN_MAX_LEN: usize = 253;
const LABEL_MAX_LEN: usize = 63;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    #[error("no email alias domain is set")]
    NoDomain,
    #[error("\"{0}\" is not a valid domain name")]
    InvalidDomain(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AliasDomain(String);

impl AliasDomain {
    pub fn parse(input: &str) -> Result<Self, AliasError> {
        let trimmed = input.trim();
        let invalid = || AliasError::InvalidDomain(trimmed.to_owned());
        let bare = trimmed.strip_prefix('@').unwrap_or(trimmed);
        let bare = bare.strip_suffix('.').unwrap_or(bare);
        if bare.is_empty()
            || bare.contains(|c: char| {
                c.is_whitespace()
                    || matches!(c, '/' | '\\' | ':' | '@' | '[' | ']' | '?' | '#' | '%')
            })
        {
            return Err(invalid());
        }
        let Ok(url::Host::Domain(ascii)) = url::Host::parse(bare) else {
            return Err(invalid());
        };
        let ascii = ascii.to_ascii_lowercase();
        let labels: Vec<&str> = ascii.split('.').collect();
        let numeric_tld = labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()));
        let registrable =
            psl::domain(ascii.as_bytes()).is_some_and(|domain| domain.suffix().is_known());
        if ascii.len() > DOMAIN_MAX_LEN
            || labels.len() < 2
            || !labels.iter().all(|label| valid_label(label))
            || numeric_tld
            || !registrable
        {
            return Err(invalid());
        }
        Ok(Self(ascii))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_label(label: &str) -> bool {
    (1..=LABEL_MAX_LEN).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

impl fmt::Display for AliasDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AliasDomain {
    type Error = AliasError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<AliasDomain> for String {
    fn from(domain: AliasDomain) -> Self {
        domain.0
    }
}

pub fn site_slug(uri: &str) -> Option<String> {
    let host = host_of(uri)?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<IpAddr>().is_ok() {
        return None;
    }
    let name = match (psl::domain_str(&host), psl::suffix_str(&host)) {
        (Some(domain), Some(suffix)) => domain
            .strip_suffix(suffix)
            .and_then(|d| d.strip_suffix('.'))
            .unwrap_or(domain),
        _ => host.split('.').next().unwrap_or(&host),
    };
    slug(name)
}

fn slug(label: &str) -> Option<String> {
    let unicode = if label.starts_with("xn--") {
        idna::domain_to_unicode(label).0
    } else {
        label.to_owned()
    };
    let readable = sanitize(&unicode);
    if readable.is_empty() {
        Some(sanitize(label)).filter(|s| !s.is_empty())
    } else {
        Some(readable)
    }
}

fn sanitize(text: &str) -> String {
    let mut out = String::new();
    for c in text.nfkd().filter(|c| !is_combining_mark(*c)) {
        let ascii = match c.to_lowercase().next().unwrap_or(c) {
            'ß' => "ss".to_owned(),
            'æ' => "ae".to_owned(),
            'œ' => "oe".to_owned(),
            'ø' => "o".to_owned(),
            'ł' => "l".to_owned(),
            c => c.to_string(),
        };
        for c in ascii.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_lowercase());
            } else if c.is_ascii() && !out.is_empty() && !out.ends_with('-') {
                out.push('-');
            }
        }
    }
    let cut: String = out.chars().take(SITE_MAX_LEN).collect();
    cut.trim_matches('-').to_owned()
}

fn random_chars<R: RngCore + CryptoRng>(rng: &mut R, count: usize) -> String {
    let alphabet = ALPHABET.as_bytes();
    (0..count)
        .map(|_| char::from(alphabet[rng.gen_range(0..alphabet.len())]))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasRequest {
    pub site: Option<String>,
}

impl AliasRequest {
    pub fn new(uri: Option<&str>, include_site: bool) -> Self {
        Self {
            site: include_site.then(|| {
                uri.and_then(site_slug)
                    .unwrap_or_else(|| FALLBACK_SITE.to_owned())
            }),
        }
    }

    pub fn local_part_with<R: RngCore + CryptoRng>(&self, rng: &mut R) -> String {
        match &self.site {
            Some(site) => format!("{site}.{}", random_chars(rng, SUFFIX_LEN)),
            None => random_chars(rng, RANDOM_LEN),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AliasProvider {
    CatchAll { domain: AliasDomain },
}

impl AliasProvider {
    pub fn domain(&self) -> &AliasDomain {
        match self {
            Self::CatchAll { domain } => domain,
        }
    }

    pub fn generate(&self, request: &AliasRequest) -> String {
        self.generate_with(&mut rand::rngs::OsRng, request)
    }

    pub fn generate_with<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        request: &AliasRequest,
    ) -> String {
        match self {
            Self::CatchAll { domain } => format!("{}@{domain}", request.local_part_with(rng)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AliasProvider>,
    #[serde(default = "include_site_default")]
    pub include_site: bool,
}

fn include_site_default() -> bool {
    true
}

impl Default for AliasSettings {
    fn default() -> Self {
        Self {
            provider: None,
            include_site: true,
        }
    }
}

impl AliasSettings {
    pub fn catch_all(domain: &str, include_site: bool) -> Result<Self, AliasError> {
        let domain = domain.trim();
        Ok(Self {
            provider: if domain.is_empty() {
                None
            } else {
                Some(AliasProvider::CatchAll {
                    domain: AliasDomain::parse(domain)?,
                })
            },
            include_site,
        })
    }

    pub fn generate(
        &self,
        uri: Option<&str>,
        include_site: Option<bool>,
    ) -> Result<String, AliasError> {
        let provider = self.provider.as_ref().ok_or(AliasError::NoDomain)?;
        let request = AliasRequest::new(uri, include_site.unwrap_or(self.include_site));
        Ok(provider.generate(&request))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::SeedableRng;

    use super::*;

    fn rng() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(11)
    }

    fn catch_all(domain: &str) -> AliasProvider {
        AliasProvider::CatchAll {
            domain: AliasDomain::parse(domain).unwrap(),
        }
    }

    fn in_alphabet(text: &str) -> bool {
        text.chars().all(|c| ALPHABET.contains(c))
    }

    #[test]
    fn slug_is_the_registrable_name() {
        for (uri, slug) in [
            ("netflix.com", "netflix"),
            ("https://www.netflix.com/signup", "netflix"),
            ("https://accounts.google.co.uk/login", "google"),
            ("https://a.b.c.example.org", "example"),
            ("https://shop.example.co.uk", "example"),
            ("https://user.github.io/blog", "user"),
            ("github.io", "github"),
            ("HTTPS://My_Shop.COM/", "my-shop"),
            ("https://le-bon-coin.fr", "le-bon-coin"),
            ("https://1password.com", "1password"),
        ] {
            assert_eq!(site_slug(uri).as_deref(), Some(slug), "{uri}");
        }
    }

    #[test]
    fn slug_ignores_ports_and_paths() {
        assert_eq!(
            site_slug("https://example.com:8443/a/b?c=d").as_deref(),
            Some("example")
        );
        assert_eq!(site_slug("example.com:8080").as_deref(), Some("example"));
        assert_eq!(
            site_slug("http://localhost:3000/register").as_deref(),
            Some("localhost")
        );
        assert_eq!(site_slug("localhost:3000").as_deref(), Some("localhost"));
    }

    #[test]
    fn slug_of_an_international_domain_is_ascii() {
        assert_eq!(site_slug("https://bücher.de").as_deref(), Some("bucher"));
        assert_eq!(
            site_slug("https://xn--bcher-kva.de").as_deref(),
            Some("bucher")
        );
        assert_eq!(site_slug("https://www.café.fr/").as_deref(), Some("cafe"));
        let host = url::Url::parse("https://例え.jp")
            .unwrap()
            .host_str()
            .unwrap()
            .to_owned();
        let label = host.split('.').next().unwrap();
        assert!(label.starts_with("xn--"), "{host}");
        let expected = label.replacen("xn--", "xn-", 1);
        assert_eq!(site_slug("https://例え.jp"), Some(expected.clone()));
        assert_eq!(site_slug(&host), Some(expected));
    }

    #[test]
    fn slug_has_no_ip_address_nor_empty_uri() {
        for uri in [
            "",
            "   ",
            "192.168.1.10",
            "https://192.168.1.10:8443/login",
            "http://[::1]:8080/",
            "https://[2001:db8::1]/",
            "iosapp://com.example.app",
            "not a url",
        ] {
            assert_eq!(site_slug(uri), None, "{uri}");
        }
    }

    #[test]
    fn slug_is_short_and_clean() {
        let slug = site_slug("https://my-very-long-company-name-here.com").unwrap();
        assert_eq!(slug, "my-very-long-company");
        let slug = site_slug("https://abcdefghijklmnopqrs-tuvwxyz.com").unwrap();
        assert_eq!(slug, "abcdefghijklmnopqrs");
        let slug = site_slug("https://a--b__c.com").unwrap();
        assert_eq!(slug, "a-b-c");
        for uri in [
            "https://www.netflix.com",
            "https://bücher.de",
            "https://例え.jp",
            "https://abcdefghijklmnopqrs-tuvwxyz.com",
        ] {
            let slug = site_slug(uri).unwrap();
            assert!(slug.len() <= SITE_MAX_LEN, "{slug}");
            assert!(
                slug.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{slug}"
            );
            assert!(!slug.starts_with('-') && !slug.ends_with('-'), "{slug}");
        }
    }

    #[test]
    fn alias_with_the_site() {
        let provider = catch_all("alias.example.com");
        let request = AliasRequest::new(Some("https://www.netflix.com/signup"), true);
        let alias = provider.generate_with(&mut rng(), &request);
        let (local, domain) = alias.split_once('@').unwrap();
        assert_eq!(domain, "alias.example.com");
        let (site, suffix) = local.split_once('.').unwrap();
        assert_eq!(site, "netflix");
        assert_eq!(suffix.len(), SUFFIX_LEN);
        assert!(in_alphabet(suffix), "{alias}");
    }

    #[test]
    fn alias_without_a_uri_falls_back() {
        let alias = catch_all("alias.example.com")
            .generate_with(&mut rng(), &AliasRequest::new(None, true));
        assert!(alias.starts_with("alias."), "{alias}");
        let alias = catch_all("alias.example.com")
            .generate_with(&mut rng(), &AliasRequest::new(Some("192.168.0.1"), true));
        assert!(alias.starts_with("alias."), "{alias}");
    }

    #[test]
    fn alias_without_the_site_is_random_only() {
        let provider = catch_all("example.com");
        let request = AliasRequest::new(Some("https://netflix.com"), false);
        assert_eq!(request.site, None);
        let alias = provider.generate_with(&mut rng(), &request);
        let (local, domain) = alias.split_once('@').unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(local.len(), RANDOM_LEN);
        assert!(in_alphabet(local), "{alias}");
        assert!(!alias.contains("netflix"));
    }

    #[test]
    fn suffixes_are_random_and_use_the_whole_alphabet() {
        let mut rng = rng();
        let request = AliasRequest::new(Some("netflix.com"), true);
        let provider = catch_all("alias.example.com");
        let aliases: HashSet<String> = (0..2000)
            .map(|_| provider.generate_with(&mut rng, &request))
            .collect();
        assert_eq!(aliases.len(), 2000);
        let seen: HashSet<char> = aliases
            .iter()
            .flat_map(|a| a["netflix.".len()..a.find('@').unwrap()].chars())
            .collect();
        assert_eq!(seen.len(), ALPHABET.len());
        let random: HashSet<String> = (0..2000)
            .map(|_| AliasRequest::new(None, false).local_part_with(&mut rng))
            .collect();
        assert_eq!(random.len(), 2000);
    }

    #[test]
    fn system_randomness_is_used_by_default() {
        let provider = catch_all("alias.example.com");
        let request = AliasRequest::new(Some("netflix.com"), true);
        assert_ne!(provider.generate(&request), provider.generate(&request));
    }

    #[test]
    fn valid_domains_are_normalized() {
        for (input, expected) in [
            ("alias.example.com", "alias.example.com"),
            ("  @Alias.Example.COM.  ", "alias.example.com"),
            ("example.co.uk", "example.co.uk"),
            ("mail.bücher.de", "mail.xn--bcher-kva.de"),
            ("a-b.example.fr", "a-b.example.fr"),
        ] {
            assert_eq!(
                AliasDomain::parse(input).unwrap().as_str(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn invalid_domains_are_refused() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}com", "abcdefghi.".repeat(26));
        for input in [
            "",
            "   ",
            "com",
            "co.uk",
            "localhost",
            "example",
            "1.2.3.4",
            "[::1]",
            "https://example.com",
            "example.com/path",
            "example.com:25",
            "user@example.com",
            "a b.com",
            "-bad.com",
            "bad-.com",
            "exa_mple.com",
            "example..com",
            "example.123",
            "example.notarealtld",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(
                matches!(AliasDomain::parse(input), Err(AliasError::InvalidDomain(_))),
                "{input}"
            );
        }
    }

    #[test]
    fn settings_round_trip_and_generate() {
        let settings = AliasSettings::catch_all(" Alias.Example.com ", false).unwrap();
        let json = serde_json::to_string(&settings).unwrap();
        assert_eq!(
            json,
            r#"{"provider":{"kind":"catch_all","domain":"alias.example.com"},"include_site":false}"#
        );
        assert_eq!(
            serde_json::from_str::<AliasSettings>(&json).unwrap(),
            settings
        );
        let alias = settings
            .generate(Some("https://netflix.com"), None)
            .unwrap();
        assert!(!alias.contains("netflix") && alias.ends_with("@alias.example.com"));
        let alias = settings
            .generate(Some("https://netflix.com"), Some(true))
            .unwrap();
        assert!(alias.starts_with("netflix."));
    }

    #[test]
    fn settings_without_a_domain() {
        let settings = AliasSettings::catch_all("  ", true).unwrap();
        assert_eq!(settings, AliasSettings::default());
        assert_eq!(settings.generate(None, None), Err(AliasError::NoDomain));
        assert_eq!(
            serde_json::from_str::<AliasSettings>("{}").unwrap(),
            AliasSettings::default()
        );
        assert!(
            serde_json::from_str::<AliasSettings>(
                r#"{"provider":{"kind":"catch_all","domain":"not a domain"}}"#
            )
            .is_err()
        );
        assert!(matches!(
            AliasSettings::catch_all("nope", true),
            Err(AliasError::InvalidDomain(_))
        ));
    }
}
