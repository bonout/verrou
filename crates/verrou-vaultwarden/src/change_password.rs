//! « Changer le mot de passe » : trouver la page où le faire sur un site.
//!
//! Ordre : une page connue d'avance pour quelques grands sites
//! (`verrou_core::change_password::known_url`, sans requête), puis la norme
//! du W3C « A Well-Known URL for Changing Passwords », vérifiée sur l'hôte
//! de l'élément puis sur son domaine enregistrable, et à défaut l'accueil du
//! site.
//!
//! Confidentialité : seulement sur demande de l'utilisateur, pour un seul
//! élément à la fois, jamais en masse. Les requêtes partent vers le site
//! qu'il s'apprête à ouvrir, et vers lui seul (redirections comprises) : le
//! site apprend qu'on le visite, ce qu'il apprendrait de toute façon. HTTPS
//! seulement, sans cookie (reqwest n'en garde pas sans la fonctionnalité
//! `cookies`), sans en-tête `Referer`, avec un délai court ; le corps des
//! réponses n'est pas lu.

use std::time::Duration;

use futures_util::future::join;
use reqwest::{StatusCode, Url, redirect};
use verrou_core::change_password::{
    NOT_FOUND_PATH, WELL_KNOWN_PATH, candidate_hosts, known_url, origin,
};

use crate::Error;

/// Au-delà, le site est jugé injoignable : on ouvre son accueil.
const TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REDIRECTS: usize = 10;

/// D'où vient l'adresse proposée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Table des grands sites, sans requête.
    Known,
    /// Le site suit la norme : adresse finale après redirections.
    WellKnown,
    /// Le site n'indique pas sa page (ou ne répond pas) : son accueil.
    Home,
}

/// Page à ouvrir pour changer le mot de passe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub url: String,
    pub source: Source,
}

/// La page de changement du mot de passe pour l'hôte (ou l'adresse) d'un
/// identifiant. Erreur seulement s'il n'y a pas de site.
pub async fn find(site: &str) -> Result<Page, Error> {
    let hosts = candidate_hosts(site);
    let Some(host) = hosts.first() else {
        return Err(Error::Invalid("cet élément n'a pas de site".to_owned()));
    };
    if let Some(url) = known_url(host) {
        return Ok(Page {
            url,
            source: Source::Known,
        });
    }
    let origins: Vec<Url> = hosts
        .iter()
        .filter_map(|h| Url::parse(&origin(h)).ok())
        .collect();
    let prober = Prober::new(false)?;
    Ok(resolve(&prober, &origins, origin(host)).await)
}

/// Premier site qui suit la norme, sinon `home`.
async fn resolve(prober: &Prober, origins: &[Url], home: String) -> Page {
    for site in origins {
        if let Some(url) = prober.probe(site).await {
            return Page {
                url: url.into(),
                source: Source::WellKnown,
            };
        }
    }
    Page {
        url: home,
        source: Source::Home,
    }
}

/// Adresse autorisée : HTTPS. HTTP seulement vers la boucle locale, et
/// seulement si `loopback_http` (le serveur factice des tests).
fn allowed(url: &Url, loopback_http: bool) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => loopback_http && is_loopback(url),
        _ => false,
    }
}

fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

struct Prober {
    client: reqwest::Client,
    loopback_http: bool,
}

impl Prober {
    fn new(loopback_http: bool) -> Result<Self, Error> {
        // Une redirection vers HTTP (ou ailleurs qu'en HTTPS) arrête la
        // course : la réponse 3xx n'est pas « OK », le site est jugé sans
        // page de changement.
        let policy = redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("trop de redirections")
            } else if allowed(attempt.url(), loopback_http) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        });
        let client = reqwest::Client::builder()
            .user_agent(concat!("Verrou/", env!("CARGO_PKG_VERSION")))
            .redirect(policy)
            .referer(false)
            .https_only(!loopback_http)
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self {
            client,
            loopback_http,
        })
    }

    /// Statut et adresse finale (après redirections) d'une requête GET ;
    /// `None` si le site ne répond pas.
    async fn get(&self, url: Url) -> Option<(StatusCode, Url)> {
        let response = self.client.get(url).send().await.ok()?;
        Some((response.status(), response.url().clone()))
    }

    /// Adresse finale de `/.well-known/change-password` si `site` suit la
    /// norme : cette adresse répond « OK » (2xx) après redirections, et une
    /// ressource qui ne doit pas exister ne répond pas « OK » (sinon le site
    /// répond 2xx à tout, et sa réponse ne prouve rien).
    async fn probe(&self, site: &Url) -> Option<Url> {
        if !allowed(site, self.loopback_http) {
            return None;
        }
        let bogus = site.join(NOT_FOUND_PATH).ok()?;
        let target = site.join(WELL_KNOWN_PATH).ok()?;
        let (bogus, target) = join(self.get(bogus), self.get(target)).await;
        let (bogus_status, _) = bogus?;
        if bogus_status.is_success() {
            return None;
        }
        let (status, url) = target?;
        (status.is_success() && allowed(&url, self.loopback_http)).then_some(url)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Réponse du serveur factice : statut, et `Location` éventuel.
    type Routes = HashMap<&'static str, (u16, Option<String>)>;

    /// Serveur HTTP minimal sur la boucle locale ; les chemins absents
    /// répondent `fallback`. Rend son origine et le journal des chemins
    /// demandés.
    fn server(routes: Routes, fallback: u16) -> (Url, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&log);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                // Le reste de la requête (en-têtes), jusqu'à la ligne vide.
                let mut header = String::new();
                while reader.read_line(&mut header).is_ok_and(|n| n > 2) {
                    header.clear();
                }
                seen.lock().unwrap().push(path.clone());
                let (status, location) = routes
                    .get(path.as_str())
                    .cloned()
                    .unwrap_or((fallback, None));
                let location = location.map_or(String::new(), |l| format!("Location: {l}\r\n"));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\n{location}Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        });
        (base, log)
    }

    fn prober() -> Prober {
        Prober::new(true).unwrap()
    }

    #[tokio::test]
    async fn supported_site_redirects_to_its_page() {
        let (base, _) = server(
            Routes::from([
                (WELL_KNOWN_PATH, (302, Some("/compte/securite".to_owned()))),
                ("/compte/securite", (200, None)),
            ]),
            404,
        );
        let url = prober().probe(&base).await.unwrap();
        assert_eq!(url.path(), "/compte/securite");
    }

    #[tokio::test]
    async fn direct_ok_is_supported_too() {
        let (base, _) = server(Routes::from([(WELL_KNOWN_PATH, (200, None))]), 404);
        assert_eq!(prober().probe(&base).await.unwrap().path(), WELL_KNOWN_PATH);
    }

    #[tokio::test]
    async fn site_answering_ok_to_everything_is_not_trusted() {
        let (base, log) = server(Routes::new(), 200);
        assert_eq!(prober().probe(&base).await, None);
        assert!(log.lock().unwrap().iter().any(|p| p == NOT_FOUND_PATH));
    }

    #[tokio::test]
    async fn missing_page_or_server_error_is_unsupported() {
        let (base, _) = server(Routes::new(), 404);
        assert_eq!(prober().probe(&base).await, None);
        let (base, _) = server(Routes::from([(WELL_KNOWN_PATH, (500, None))]), 404);
        assert_eq!(prober().probe(&base).await, None);
        // Redirection vers une page absente.
        let (base, _) = server(
            Routes::from([(WELL_KNOWN_PATH, (301, Some("/nulle-part".to_owned())))]),
            404,
        );
        assert_eq!(prober().probe(&base).await, None);
    }

    #[tokio::test]
    async fn redirect_loops_give_up() {
        let (base, _) = server(
            Routes::from([(WELL_KNOWN_PATH, (302, Some(WELL_KNOWN_PATH.to_owned())))]),
            404,
        );
        assert_eq!(prober().probe(&base).await, None);
    }

    #[tokio::test]
    async fn redirect_to_plain_http_elsewhere_is_not_followed() {
        // Une redirection vers un hôte en HTTP (hors boucle locale) n'est
        // pas suivie : aucune requête ne part en clair.
        let (base, _) = server(
            Routes::from([(
                WELL_KNOWN_PATH,
                (302, Some("http://exemple.invalid/compte".to_owned())),
            )]),
            404,
        );
        assert_eq!(prober().probe(&base).await, None);
    }

    #[tokio::test]
    async fn unreachable_site_is_unsupported() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        drop(listener);
        assert_eq!(prober().probe(&base).await, None);
    }

    #[tokio::test]
    async fn plain_http_is_refused_outside_tests() {
        let (base, log) = server(Routes::from([(WELL_KNOWN_PATH, (200, None))]), 404);
        // Le client de production n'autorise que HTTPS : rien ne part.
        let strict = Prober::new(false).unwrap();
        assert_eq!(strict.probe(&base).await, None);
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn only_https_or_loopback_http_in_tests() {
        let url = |s: &str| Url::parse(s).unwrap();
        assert!(allowed(&url("https://exemple.fr"), false));
        assert!(!allowed(&url("http://exemple.fr"), false));
        assert!(!allowed(&url("http://exemple.fr"), true));
        assert!(!allowed(&url("http://127.0.0.1:8080"), false));
        assert!(allowed(&url("http://127.0.0.1:8080"), true));
        assert!(allowed(&url("http://localhost:8080"), true));
        assert!(allowed(&url("http://[::1]:8080"), true));
        assert!(!allowed(&url("ftp://127.0.0.1"), true));
        assert!(!allowed(&url("http://127.0.0.1.exemple.fr"), true));
    }

    #[tokio::test]
    async fn resolve_tries_the_host_then_the_domain_then_falls_back_home() {
        let (unsupported, first) = server(Routes::new(), 404);
        let (supported, _) = server(Routes::from([(WELL_KNOWN_PATH, (200, None))]), 404);
        let page = resolve(
            &prober(),
            &[unsupported.clone(), supported.clone()],
            "https://accueil".to_owned(),
        )
        .await;
        assert_eq!(page.source, Source::WellKnown);
        assert_eq!(page.url, supported.join(WELL_KNOWN_PATH).unwrap().as_str());
        assert!(first.lock().unwrap().iter().any(|p| p == WELL_KNOWN_PATH));

        let page = resolve(&prober(), &[unsupported], "https://accueil".to_owned()).await;
        assert_eq!(
            page,
            Page {
                url: "https://accueil".to_owned(),
                source: Source::Home,
            }
        );
    }

    #[tokio::test]
    async fn known_sites_need_no_request() {
        // Aucune requête : la table suffit (le test passe hors ligne).
        let page = find("https://accounts.google.com/signin").await.unwrap();
        assert_eq!(page.source, Source::Known);
        assert!(page.url.starts_with("https://myaccount.google.com/"));
        assert!(matches!(
            find("macapp://com.exemple").await,
            Err(Error::Invalid(_))
        ));
    }
}
