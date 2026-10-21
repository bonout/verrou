//! Matching between an item and the current page.
//!
//! Same default rule as Bitwarden ("base domain"): `login.github.com`
//! and `github.com` share a login, but `github.io` and `github.com`
//! do not. The registrable domain comes from the Public Suffix List, which
//! avoids mixing up `example.co.uk` with all of `co.uk`.
//!
//! Each site of a login can carry its own rule (Bitwarden's "match
//! detection" setting, stored in the item): domain, host, "starts with",
//! exact, regular expression or never.
//! Without a rule, the device's default rule applies, or the rule of the
//! item's folder if the device defines one: both settings stay local
//! (Bitwarden has neither per-folder rules nor a default rule shared
//! between devices). The account's equivalent domains
//! (`/api/settings/domains`) widen the "domain" rule, as in the
//! Bitwarden apps.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::Item;

/// Match rule of a site (Bitwarden's `UriMatchType`, same numbering in
/// the encrypted format).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UriMatch {
    /// Same registrable domain (or equivalent domain).
    #[default]
    Domain,
    /// Same host, port included.
    Host,
    /// The page address starts with the site's.
    StartsWith,
    /// Same address, character for character.
    Exact,
    /// The page address matches the regular expression (case-insensitive).
    RegularExpression,
    /// Never offered.
    Never,
}

impl UriMatch {
    pub const ALL: [Self; 6] = [
        Self::Domain,
        Self::Host,
        Self::StartsWith,
        Self::Exact,
        Self::RegularExpression,
        Self::Never,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Domain => "Base domain",
            Self::Host => "Host",
            Self::StartsWith => "Starts with",
            Self::Exact => "Exact",
            Self::RegularExpression => "Regular expression",
            Self::Never => "Never",
        }
    }

    /// Bitwarden value (`0` domain … `5` never).
    pub fn code(self) -> u8 {
        match self {
            Self::Domain => 0,
            Self::Host => 1,
            Self::StartsWith => 2,
            Self::Exact => 3,
            Self::RegularExpression => 4,
            Self::Never => 5,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.code() == code)
    }
}

/// Device rules: the default rule, the folder rules, and the account's
/// equivalent domains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatchRules {
    /// Rule for sites that have none ("base domain" by default, like
    /// Bitwarden).
    pub default: UriMatch,
    /// Rule per folder, keyed by folded folder name (`search::fold`): it
    /// replaces the default rule for the folder's items.
    pub folders: HashMap<String, UriMatch>,
    /// Groups of equivalent domains (`google.com`, `youtube.com`…).
    pub equivalent_domains: Vec<Vec<String>>,
}

impl MatchRules {
    /// Rule that applies to site `index` of an item: its own, otherwise
    /// the folder's, otherwise the device's.
    pub fn rule_for(&self, item: &Item, index: usize) -> UriMatch {
        item.url_matches
            .get(index)
            .copied()
            .flatten()
            .unwrap_or_else(|| self.fallback_for(item))
    }

    /// Rule of a site with no rule of its own in this item.
    pub fn fallback_for(&self, item: &Item) -> UriMatch {
        item.folder
            .as_deref()
            .and_then(|f| self.folders.get(&crate::search::fold(f)))
            .copied()
            .unwrap_or(self.default)
    }

    /// The page's domain and its equivalents.
    fn page_domains(&self, domain: &str) -> HashSet<String> {
        let mut domains: HashSet<String> = HashSet::from([domain.to_owned()]);
        for group in &self.equivalent_domains {
            if group.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
                domains.extend(group.iter().map(|d| d.to_ascii_lowercase()));
            }
        }
        domains
    }
}

/// Match settings stored on the device
/// (`match-rules.json`): never sent to the server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMatchSettings {
    #[serde(default)]
    pub default: UriMatch,
    /// Rule per folder, keyed by folder id.
    #[serde(default)]
    pub folders: BTreeMap<String, UriMatch>,
}

/// Quality of a match, from none to best.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SiteMatch {
    None,
    SameDomain,
    SameHost,
}

/// Lowercase host without `www.`, from a URL or a bare host.
/// An app address (`macapp://`, `iosapp://`, `androidapp://`)
/// has no host: it is not a site.
pub fn host_of(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() || crate::apps::is_app_uri(trimmed) {
        return None;
    }
    let parsed = Url::parse(trimmed)
        .ok()
        .filter(|u| u.host_str().is_some())
        .or_else(|| Url::parse(&format!("https://{trimmed}")).ok())?;
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Some(
        host.strip_prefix("www.")
            .map_or(host.clone(), str::to_owned),
    )
}

/// Registrable domain (`login.github.com` → `github.com`). For an IP
/// address or a name without a public suffix, the host itself.
pub fn registrable_domain(input: &str) -> Option<String> {
    let host = host_of(input)?;
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(host);
    }
    match psl::domain_str(&host) {
        Some(domain) => Some(domain.to_owned()),
        None => Some(host),
    }
}

/// Host and port, lowercase (Bitwarden's `Utils.getHost`): the "host"
/// rule tells `www.exemple.fr` from `exemple.fr`, and ports apart.
fn host_and_port(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() || crate::apps::is_app_uri(trimmed) {
        return None;
    }
    let parsed = Url::parse(trimmed)
        .ok()
        .filter(|u| u.host_str().is_some())
        .or_else(|| Url::parse(&format!("http://{trimmed}")).ok())?;
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// Subdomains excluded from Bitwarden's "domain" rule
/// (`DomainMatchBlacklist`): a Google login is not offered on
/// Apps Script scripts.
const DOMAIN_MATCH_BLACKLIST: [(&str, &str); 1] = [("google.com", "script.google.com")];

/// A page, prepared once for all items.
struct Page<'a> {
    url: &'a str,
    host: String,
    host_and_port: Option<String>,
    /// Registrable domain of the page and its equivalents.
    domains: HashSet<String>,
}

impl<'a> Page<'a> {
    fn new(url: &'a str, rules: &MatchRules) -> Option<Self> {
        let host = host_of(url)?;
        let domain = registrable_domain(&host).unwrap_or_else(|| host.clone());
        Some(Self {
            url: url.trim(),
            host_and_port: host_and_port(url),
            domains: rules.page_domains(&domain),
            host,
        })
    }
}

/// Match of a site (`uri`, rule `rule`) against an already prepared
/// page. An app address never matches a page.
fn uri_match_at(uri: &str, rule: UriMatch, page: &Page<'_>) -> SiteMatch {
    let uri = uri.trim();
    if uri.is_empty() || crate::apps::is_app_uri(uri) {
        return SiteMatch::None;
    }
    let precise = |hit: bool| {
        if hit {
            SiteMatch::SameHost
        } else {
            SiteMatch::None
        }
    };
    match rule {
        UriMatch::Never => SiteMatch::None,
        UriMatch::Exact => precise(page.url == uri),
        UriMatch::StartsWith => precise(page.url.starts_with(uri)),
        UriMatch::RegularExpression => precise(
            regex::RegexBuilder::new(uri)
                .case_insensitive(true)
                // An oversized expression does not block filling.
                .size_limit(1 << 20)
                .build()
                .is_ok_and(|re| re.is_match(page.url)),
        ),
        UriMatch::Host => {
            precise(page.host_and_port.is_some() && host_and_port(uri) == page.host_and_port)
        }
        UriMatch::Domain => {
            let Some(host) = host_of(uri) else {
                return SiteMatch::None;
            };
            let domain = registrable_domain(&host).unwrap_or_else(|| host.clone());
            if !page.domains.contains(&domain) {
                return SiteMatch::None;
            }
            if DOMAIN_MATCH_BLACKLIST
                .iter()
                .any(|(d, excluded)| *d == domain && page.host == *excluded)
            {
                return SiteMatch::None;
            }
            if host == page.host {
                SiteMatch::SameHost
            } else {
                SiteMatch::SameDomain
            }
        }
    }
}

/// Match of a site against a page, with an explicit rule.
pub fn uri_match(uri: &str, rule: UriMatch, page: &str, rules: &MatchRules) -> SiteMatch {
    Page::new(page, rules).map_or(SiteMatch::None, |p| uri_match_at(uri, rule, &p))
}

/// Best match between a page and an item's URL list, with the default
/// rule (base domain) for each.
pub fn site_match(item_urls: &[String], page: &str) -> SiteMatch {
    let rules = MatchRules::default();
    let Some(page) = Page::new(page, &rules) else {
        return SiteMatch::None;
    };
    item_urls
        .iter()
        .map(|u| uri_match_at(u, UriMatch::Domain, &page))
        .max()
        .unwrap_or(SiteMatch::None)
}

/// Best match between a page and an item's sites, each with its rule
/// (or the folder's, or the device's).
pub fn item_match(item: &Item, page: &str, rules: &MatchRules) -> SiteMatch {
    let Some(page) = Page::new(page, rules) else {
        return SiteMatch::None;
    };
    item_match_at(item, &page, rules)
}

fn item_match_at(item: &Item, page: &Page<'_>, rules: &MatchRules) -> SiteMatch {
    item.urls
        .iter()
        .enumerate()
        .map(|(i, u)| uri_match_at(u, rules.rule_for(item, i), page))
        .max()
        .unwrap_or(SiteMatch::None)
}

/// The items that match a page, with their match (the page is parsed
/// only once).
pub fn matching_items<'i>(
    items: impl Iterator<Item = &'i Item>,
    page: &str,
    rules: &MatchRules,
) -> Vec<(SiteMatch, &'i Item)> {
    let Some(page) = Page::new(page, rules) else {
        return Vec::new();
    };
    items
        .map(|item| (item_match_at(item, &page, rules), item))
        .filter(|(m, _)| *m != SiteMatch::None)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_normalised() {
        assert_eq!(
            host_of("https://WWW.GitHub.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(host_of("github.com").as_deref(), Some("github.com"));
        assert_eq!(host_of("  ").as_deref(), None);
    }

    #[test]
    fn app_uris_are_not_sites() {
        assert_eq!(host_of("macapp://com.apple.Terminal"), None);
        assert_eq!(host_of("androidapp://com.github.android"), None);
        let urls = vec!["macapp://com.github.GitHubClient".to_owned()];
        assert_eq!(site_match(&urls, "https://github.com"), SiteMatch::None);
        assert_eq!(
            site_match(&urls, "https://com.github.githubclient"),
            SiteMatch::None
        );
    }

    #[test]
    fn registrable_domain_uses_the_public_suffix_list() {
        assert_eq!(
            registrable_domain("https://login.github.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            registrable_domain("shop.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("192.168.1.132").as_deref(),
            Some("192.168.1.132")
        );
    }

    #[test]
    fn matching_prefers_the_exact_host() {
        let urls = vec!["https://github.com".to_owned()];
        assert_eq!(
            site_match(&urls, "https://github.com/settings"),
            SiteMatch::SameHost
        );
        assert_eq!(
            site_match(&urls, "https://gist.github.com"),
            SiteMatch::SameDomain
        );
        assert_eq!(site_match(&urls, "https://github.io"), SiteMatch::None);
        assert_eq!(site_match(&urls, "https://evilgithub.com"), SiteMatch::None);
    }
    fn login(urls: &[(&str, Option<UriMatch>)], folder: Option<&str>) -> Item {
        let mut item = crate::mock::vault_items(0, 1, crate::mock::MockLanguage::En).remove(0);
        item.urls = urls.iter().map(|(u, _)| (*u).to_owned()).collect();
        item.url_matches = urls.iter().map(|(_, m)| *m).collect();
        item.folder = folder.map(str::to_owned);
        item
    }

    fn check(uri: &str, rule: UriMatch, page: &str) -> SiteMatch {
        uri_match(uri, rule, page, &MatchRules::default())
    }

    #[test]
    fn domain_rule_matches_the_registrable_domain() {
        use UriMatch::Domain;
        assert_eq!(
            check("https://github.com", Domain, "https://github.com/x"),
            SiteMatch::SameHost
        );
        assert_eq!(
            check("github.com", Domain, "https://gist.github.com"),
            SiteMatch::SameDomain
        );
        assert_eq!(
            check("https://github.com", Domain, "https://github.io"),
            SiteMatch::None
        );
        assert_eq!(
            check("http://192.168.1.10:8080", Domain, "https://192.168.1.10"),
            SiteMatch::SameHost
        );
        // Bitwarden's exclusion list.
        assert_eq!(
            check("https://google.com", Domain, "https://script.google.com"),
            SiteMatch::None
        );
        assert_eq!(
            check("https://google.com", Domain, "https://mail.google.com"),
            SiteMatch::SameDomain
        );
    }

    #[test]
    fn host_rule_compares_host_and_port() {
        use UriMatch::Host;
        assert_eq!(
            check("https://github.com/login", Host, "http://github.com/a"),
            SiteMatch::SameHost
        );
        assert_eq!(
            check("https://github.com", Host, "https://gist.github.com"),
            SiteMatch::None
        );
        assert_eq!(
            check("https://www.github.com", Host, "https://github.com"),
            SiteMatch::None
        );
        assert_eq!(
            check("nas.local:5001", Host, "https://nas.local:5001/login"),
            SiteMatch::SameHost
        );
        assert_eq!(
            check("nas.local:5001", Host, "https://nas.local:5000/login"),
            SiteMatch::None
        );
    }

    #[test]
    fn starts_with_exact_regex_and_never() {
        use UriMatch::{Exact, Never, RegularExpression, StartsWith};
        let base = "https://exemple.fr/compte";
        assert_eq!(
            check(base, StartsWith, "https://exemple.fr/compte/login"),
            SiteMatch::SameHost
        );
        assert_eq!(
            check(base, StartsWith, "https://exemple.fr/autre"),
            SiteMatch::None
        );
        assert_eq!(check(base, Exact, base), SiteMatch::SameHost);
        assert_eq!(
            check(base, Exact, "https://exemple.fr/compte/"),
            SiteMatch::None
        );
        assert_eq!(
            check(
                r"^https://([a-z]+\.)?exemple\.fr/",
                RegularExpression,
                "https://MOI.exemple.fr/x"
            ),
            SiteMatch::SameHost
        );
        assert_eq!(
            check(
                r"^https://exemple\.fr/$",
                RegularExpression,
                "https://exemple.fr/x"
            ),
            SiteMatch::None
        );
        // Invalid expression: never, without panicking.
        assert_eq!(
            check("([", RegularExpression, "https://exemple.fr"),
            SiteMatch::None
        );
        assert_eq!(check(base, Never, base), SiteMatch::None);
        // An app address matches no page, whatever the rule.
        for rule in UriMatch::ALL {
            assert_eq!(
                check("macapp://com.apple.Terminal", rule, "https://apple.com"),
                SiteMatch::None
            );
        }
    }

    #[test]
    fn rules_come_from_the_site_then_the_folder_then_the_device() {
        let page = "https://gist.github.com";
        let mut rules = MatchRules::default();
        let item = login(&[("https://github.com", None)], Some("Travail"));
        assert_eq!(item_match(&item, page, &rules), SiteMatch::SameDomain);
        // Device rule: host.
        rules.default = UriMatch::Host;
        assert_eq!(item_match(&item, page, &rules), SiteMatch::None);
        // The "Travail" folder goes back to domain.
        rules
            .folders
            .insert(crate::search::fold("TRAVAIL"), UriMatch::Domain);
        assert_eq!(item_match(&item, page, &rules), SiteMatch::SameDomain);
        // The site's rule wins over both.
        let never = login(
            &[("https://github.com", Some(UriMatch::Never))],
            Some("Travail"),
        );
        assert_eq!(item_match(&never, page, &rules), SiteMatch::None);
        // Each site has its own: the best wins.
        let two = login(
            &[
                ("https://github.com", Some(UriMatch::Never)),
                ("https://gist.github.com/", Some(UriMatch::StartsWith)),
            ],
            None,
        );
        assert_eq!(
            item_match(&two, "https://gist.github.com/moi", &rules),
            SiteMatch::SameHost
        );
    }

    #[test]
    fn equivalent_domains_widen_the_domain_rule_only() {
        let rules = MatchRules {
            equivalent_domains: vec![vec!["google.com".into(), "youtube.com".into()]],
            ..MatchRules::default()
        };
        let item = login(&[("https://accounts.google.com", None)], None);
        assert_eq!(
            item_match(&item, "https://www.youtube.com", &rules),
            SiteMatch::SameDomain
        );
        assert_eq!(
            item_match(&item, "https://www.youtube.com", &MatchRules::default()),
            SiteMatch::None
        );
        let host = login(
            &[("https://accounts.google.com", Some(UriMatch::Host))],
            None,
        );
        assert_eq!(
            item_match(&host, "https://youtube.com", &rules),
            SiteMatch::None
        );
        assert_eq!(
            item_match(&item, "https://vimeo.com", &rules),
            SiteMatch::None
        );
    }

    #[test]
    fn codes_follow_bitwarden() {
        for rule in UriMatch::ALL {
            assert_eq!(UriMatch::from_code(rule.code()), Some(rule));
        }
        assert_eq!(UriMatch::RegularExpression.code(), 4);
        assert_eq!(UriMatch::from_code(9), None);
        let settings: DeviceMatchSettings =
            serde_json::from_str(r#"{"default":"Host","folders":{"f1":"Exact"}}"#).unwrap();
        assert_eq!(settings.default, UriMatch::Host);
        assert_eq!(settings.folders["f1"], UriMatch::Exact);
        assert_eq!(
            serde_json::from_str::<DeviceMatchSettings>("{}").unwrap(),
            DeviceMatchSettings::default()
        );
    }
}
