//! « Créer une passkey » : trouver la page où le faire sur un site.
//!
//! Ordre : la norme du W3C « Passkey Endpoints »
//! (`/.well-known/passkey-endpoints`, adresses `enroll` puis `manage`),
//! vérifiée sur l'hôte de l'élément puis sur son domaine enregistrable ;
//! puis une page connue d'avance pour quelques grands sites
//! (`verrou_core::passkey_upgrade::known_setup_url`) ; puis l'adresse du
//! site donnée par l'annuaire ; à défaut, l'accueil du site.
//!
//! Confidentialité : comme « Changer le mot de passe », seulement sur
//! demande de l'utilisateur, pour un seul élément, jamais en masse. Les
//! requêtes partent vers le site qu'il s'apprête à ouvrir, et vers lui seul :
//! HTTPS, sans cookie, sans `Referer`, sans redirection, délai court, corps
//! borné. Les adresses lues ne sont gardées que si elles restent sur le
//! même domaine enregistrable.

use std::time::Duration;

use reqwest::{Url, redirect};
use verrou_core::change_password::{candidate_hosts, origin};
use verrou_core::passkey_upgrade::{ENDPOINTS_PATH, known_setup_url, parse_endpoints};

use crate::Error;

const TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Le fichier fait quelques centaines d'octets.
const MAX_BODY: usize = 16 * 1024;

/// D'où vient l'adresse proposée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Le site publie sa page de création (`passkey-endpoints`).
    WellKnown,
    /// Table des grands sites, sans requête.
    Known,
    /// Le site n'indique pas sa page : l'adresse de l'annuaire, ou son accueil.
    Home,
}

/// Page à ouvrir pour créer une passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub url: String,
    pub source: Source,
}

/// La page de création d'une passkey pour l'hôte (ou l'adresse) d'un
/// identifiant. `site_url` : l'adresse du site selon l'annuaire, s'il en
/// donne une. Erreur seulement s'il n'y a pas de site.
pub async fn find(site: &str, site_url: Option<&str>) -> Result<Page, Error> {
    let hosts = candidate_hosts(site);
    let Some(host) = hosts.first() else {
        return Err(Error::Invalid("cet élément n'a pas de site".to_owned()));
    };
    let origins: Vec<(String, Url)> = hosts
        .iter()
        .filter_map(|h| Url::parse(&origin(h)).ok().map(|u| (h.clone(), u)))
        .collect();
    let client = client(false)?;
    for (host, site) in &origins {
        if let Some(url) = probe(&client, site, host, false).await {
            return Ok(Page {
                url,
                source: Source::WellKnown,
            });
        }
    }
    if let Some(url) = known_setup_url(host) {
        return Ok(Page {
            url,
            source: Source::Known,
        });
    }
    let home = site_url
        .filter(|u| u.starts_with("https://"))
        .map_or_else(|| origin(host), str::to_owned);
    Ok(Page {
        url: home,
        source: Source::Home,
    })
}

fn client(loopback_http: bool) -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .user_agent(concat!("Verrou/", env!("CARGO_PKG_VERSION")))
        // Le fichier est servi à son adresse : une redirection n'est pas
        // suivie (elle pourrait mener ailleurs, ou en HTTP).
        .redirect(redirect::Policy::none())
        .referer(false)
        .https_only(!loopback_http)
        .timeout(TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|e| Error::Network(e.to_string()))
}

/// La page `enroll` (ou `manage`) publiée par `site`, si le fichier existe,
/// se lit, et désigne une adresse HTTPS du même domaine que `host`.
async fn probe(
    client: &reqwest::Client,
    site: &Url,
    host: &str,
    loopback_http: bool,
) -> Option<String> {
    if site.scheme() != "https" && !loopback_http {
        return None;
    }
    let url = site.join(ENDPOINTS_PATH).ok()?;
    let mut response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BODY {
            return None;
        }
    }
    parse_endpoints(&body, host)?.setup().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpListener;

    use super::*;

    /// Serveur HTTP minimal sur la boucle locale : `ENDPOINTS_PATH` répond
    /// `status` et `body`, le reste 404.
    fn server(status: u16, body: &'static str) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let mut header = String::new();
                while reader.read_line(&mut header).is_ok_and(|n| n > 2) {
                    header.clear();
                }
                let (status, body) = if path == ENDPOINTS_PATH {
                    (status, body)
                } else {
                    (404, "")
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        base
    }

    async fn probe_local(status: u16, body: &'static str) -> Option<String> {
        let base = server(status, body);
        probe(&client(true).unwrap(), &base, "exemple.fr", true).await
    }

    #[tokio::test]
    async fn reads_the_enroll_page() {
        assert_eq!(
            probe_local(
                200,
                r#"{"enroll": "https://exemple.fr/passkeys/nouvelle", "manage": "https://exemple.fr/passkeys"}"#
            )
            .await
            .as_deref(),
            Some("https://exemple.fr/passkeys/nouvelle")
        );
        assert_eq!(
            probe_local(200, r#"{"manage": "https://compte.exemple.fr/passkeys"}"#)
                .await
                .as_deref(),
            Some("https://compte.exemple.fr/passkeys")
        );
    }

    #[tokio::test]
    async fn ignores_missing_foreign_or_bogus_files() {
        assert_eq!(probe_local(404, "").await, None);
        assert_eq!(probe_local(200, "<html>accueil</html>").await, None);
        assert_eq!(
            probe_local(200, r#"{"enroll": "https://ailleurs.fr/passkeys"}"#).await,
            None
        );
        assert_eq!(
            probe_local(302, r#"{"enroll": "https://exemple.fr/passkeys"}"#).await,
            None
        );
    }

    #[tokio::test]
    async fn plain_http_is_refused_outside_tests() {
        let base = server(200, r#"{"enroll": "https://exemple.fr/passkeys"}"#);
        assert_eq!(
            probe(&client(false).unwrap(), &base, "exemple.fr", false).await,
            None
        );
    }

    #[tokio::test]
    async fn needs_a_site() {
        assert!(matches!(
            find("macapp://com.exemple", None).await,
            Err(Error::Invalid(_))
        ));
    }
}
