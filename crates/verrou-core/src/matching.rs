//! Correspondance entre un élément et la page où l'on se trouve.
//!
//! Même règle par défaut que Bitwarden (« domaine de base ») : `login.github.com`
//! et `github.com` partagent un identifiant, mais `github.io` et `github.com`
//! non. Le domaine enregistrable vient de la Public Suffix List, ce qui évite
//! de confondre `example.co.uk` avec tout `co.uk`.
//!
//! Chaque site d'un identifiant peut porter sa propre règle (le réglage
//! « détection de correspondance » de Bitwarden, enregistré dans l'élément) :
//! domaine, hôte, « commence par », exacte, expression régulière ou jamais.
//! Sans règle, c'est la règle par défaut de l'appareil qui s'applique, ou
//! celle du dossier de l'élément si l'appareil en définit une : ces deux
//! réglages restent locaux (Bitwarden n'a ni règle par dossier, ni règle par
//! défaut partagée entre appareils). Les domaines équivalents du compte
//! (`/api/settings/domains`) élargissent la règle « domaine », comme dans les
//! apps Bitwarden.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::Item;

/// Règle de correspondance d'un site (`UriMatchType` de Bitwarden, même
/// numérotation dans le format chiffré).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UriMatch {
    /// Même domaine enregistrable (ou domaine équivalent).
    #[default]
    Domain,
    /// Même hôte, port compris.
    Host,
    /// L'adresse de la page commence par celle du site.
    StartsWith,
    /// Même adresse, caractère pour caractère.
    Exact,
    /// L'adresse de la page vérifie l'expression régulière (sans casse).
    RegularExpression,
    /// Jamais proposé.
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
            Self::Domain => "Domaine de base",
            Self::Host => "Hôte",
            Self::StartsWith => "Commence par",
            Self::Exact => "Exacte",
            Self::RegularExpression => "Expression régulière",
            Self::Never => "Jamais",
        }
    }

    /// Valeur de Bitwarden (`0` domaine … `5` jamais).
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

/// Règles de l'appareil : la règle par défaut, celles des dossiers, et les
/// domaines équivalents du compte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatchRules {
    /// Règle des sites qui n'en ont pas (« Domaine de base » par défaut,
    /// comme Bitwarden).
    pub default: UriMatch,
    /// Règle par dossier, par nom de dossier replié (`search::fold`) : elle
    /// remplace la règle par défaut pour les éléments du dossier.
    pub folders: HashMap<String, UriMatch>,
    /// Groupes de domaines équivalents (`google.com`, `youtube.com`…).
    pub equivalent_domains: Vec<Vec<String>>,
}

impl MatchRules {
    /// Règle qui s'applique au site `index` d'un élément : la sienne, sinon
    /// celle du dossier, sinon celle de l'appareil.
    pub fn rule_for(&self, item: &Item, index: usize) -> UriMatch {
        item.url_matches
            .get(index)
            .copied()
            .flatten()
            .unwrap_or_else(|| self.fallback_for(item))
    }

    /// Règle d'un site sans règle propre dans cet élément.
    pub fn fallback_for(&self, item: &Item) -> UriMatch {
        item.folder
            .as_deref()
            .and_then(|f| self.folders.get(&crate::search::fold(f)))
            .copied()
            .unwrap_or(self.default)
    }

    /// Le domaine de la page et ses équivalents.
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

/// Réglages de correspondance enregistrés sur l'appareil
/// (`match-rules.json`) : jamais envoyés au serveur.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMatchSettings {
    #[serde(default)]
    pub default: UriMatch,
    /// Règle par dossier, par identifiant de dossier.
    #[serde(default)]
    pub folders: BTreeMap<String, UriMatch>,
}

/// Qualité d'une correspondance, de la meilleure à l'absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SiteMatch {
    None,
    SameDomain,
    SameHost,
}

/// Hôte en minuscules et sans `www.`, à partir d'une URL ou d'un hôte nu.
/// Une adresse d'application (`macapp://`, `iosapp://`, `androidapp://`)
/// n'a pas d'hôte : ce n'est pas un site.
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

/// Domaine enregistrable (`login.github.com` → `github.com`). Pour une adresse
/// IP ou un nom sans suffixe public, l'hôte lui-même.
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

/// Hôte et port, en minuscules (`Utils.getHost` de Bitwarden) : la règle
/// « hôte » distingue `www.exemple.fr` d'`exemple.fr`, et les ports.
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

/// Sous-domaines exclus de la règle « domaine » de Bitwarden
/// (`DomainMatchBlacklist`) : un identifiant Google ne se propose pas sur
/// les scripts Apps Script.
const DOMAIN_MATCH_BLACKLIST: [(&str, &str); 1] = [("google.com", "script.google.com")];

/// Une page, préparée une fois pour tous les éléments.
struct Page<'a> {
    url: &'a str,
    host: String,
    host_and_port: Option<String>,
    /// Domaine enregistrable de la page et ses équivalents.
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

/// Correspondance d'un site (`uri`, règle `rule`) avec une page déjà
/// préparée. Une adresse d'application ne correspond jamais à une page.
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
                // Une expression démesurée ne bloque pas le remplissage.
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

/// Correspondance d'un site avec une page, selon une règle explicite.
pub fn uri_match(uri: &str, rule: UriMatch, page: &str, rules: &MatchRules) -> SiteMatch {
    Page::new(page, rules).map_or(SiteMatch::None, |p| uri_match_at(uri, rule, &p))
}

/// Meilleure correspondance entre une page et la liste d'URL d'un élément,
/// avec la règle par défaut (domaine de base) pour chacune.
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

/// Meilleure correspondance entre une page et les sites d'un élément, chacun
/// avec sa règle (ou celle du dossier, ou celle de l'appareil).
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

/// Les éléments qui correspondent à une page, avec leur correspondance (la
/// page n'est analysée qu'une fois).
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
        let mut item = crate::mock::vault_items(0, 1).remove(0);
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
        // Liste d'exclusion de Bitwarden.
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
        // Expression invalide : jamais, sans paniquer.
        assert_eq!(
            check("([", RegularExpression, "https://exemple.fr"),
            SiteMatch::None
        );
        assert_eq!(check(base, Never, base), SiteMatch::None);
        // Une adresse d'app ne correspond à aucune page, quelle que soit la règle.
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
        // Règle de l'appareil : hôte.
        rules.default = UriMatch::Host;
        assert_eq!(item_match(&item, page, &rules), SiteMatch::None);
        // Le dossier « Travail » revient au domaine.
        rules
            .folders
            .insert(crate::search::fold("TRAVAIL"), UriMatch::Domain);
        assert_eq!(item_match(&item, page, &rules), SiteMatch::SameDomain);
        // La règle du site l'emporte sur les deux.
        let never = login(
            &[("https://github.com", Some(UriMatch::Never))],
            Some("Travail"),
        );
        assert_eq!(item_match(&never, page, &rules), SiteMatch::None);
        // Chaque site a la sienne : le meilleur l'emporte.
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
