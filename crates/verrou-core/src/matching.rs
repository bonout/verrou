//! Correspondance entre un élément et la page où l'on se trouve.
//!
//! Même règle par défaut que Bitwarden (« domaine de base ») : `login.github.com`
//! et `github.com` partagent un identifiant, mais `github.io` et `github.com`
//! non. Le domaine enregistrable vient de la Public Suffix List, ce qui évite
//! de confondre `example.co.uk` avec tout `co.uk`.

use url::Url;

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

/// Meilleure correspondance entre une page et la liste d'URL d'un élément.
pub fn site_match(item_urls: &[String], page: &str) -> SiteMatch {
    let Some(page_host) = host_of(page) else {
        return SiteMatch::None;
    };
    let page_domain = registrable_domain(&page_host);
    item_urls
        .iter()
        .map(|u| {
            let Some(host) = host_of(u) else {
                return SiteMatch::None;
            };
            if host == page_host {
                SiteMatch::SameHost
            } else if page_domain.is_some() && registrable_domain(&host) == page_domain {
                SiteMatch::SameDomain
            } else {
                SiteMatch::None
            }
        })
        .max()
        .unwrap_or(SiteMatch::None)
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
}
