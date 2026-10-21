//! "Create a passkey": find the page where to do it on a site.
//!
//! Order: the W3C "Passkey Endpoints" standard
//! (`/.well-known/passkey-endpoints`, `enroll` then `manage` addresses),
//! checked on the item's host then on its registrable domain; then a page
//! known in advance for a few big sites
//! (`verrou_core::passkey_upgrade::known_setup_url`); then the site address
//! given by the directory; failing that, the site's home page.
//!
//! Privacy: like "Change password", only at the user's request, for a
//! single item, never in bulk. The requests go to the site they are about
//! to open, and to it alone: HTTPS, no cookie, no `Referer`, no redirect,
//! short timeout, bounded body. The addresses read are kept only if they
//! stay on the same registrable domain.

use std::time::Duration;

use reqwest::{Url, redirect};
use verrou_core::change_password::{candidate_hosts, origin};
use verrou_core::passkey_upgrade::{ENDPOINTS_PATH, known_setup_url, parse_endpoints};

use crate::Error;

const TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// The file is a few hundred bytes.
const MAX_BODY: usize = 16 * 1024;

/// Where the proposed address comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The site publishes its creation page (`passkey-endpoints`).
    WellKnown,
    /// Table of big sites, without request.
    Known,
    /// The site doesn't give its page: the directory's address, or its home page.
    Home,
}

/// Page to open to create a passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub url: String,
    pub source: Source,
}

/// The passkey creation page for a login's host (or address). `site_url`:
/// the site's address according to the directory, if it gives one. An
/// error only if there is no site.
pub async fn find(site: &str, site_url: Option<&str>) -> Result<Page, Error> {
    let hosts = candidate_hosts(site);
    let Some(host) = hosts.first() else {
        return Err(Error::Invalid("this item has no site".to_owned()));
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
        // The file is served at its address: a redirect is not followed (it
        // could lead elsewhere, or to HTTP).
        .redirect(redirect::Policy::none())
        .referer(false)
        .https_only(!loopback_http)
        .timeout(TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|e| Error::Network(e.to_string()))
}

/// The `enroll` (or `manage`) page published by `site`, if the file exists,
/// reads, and points to an HTTPS address on the same domain as `host`.
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

    /// Minimal HTTP server on the loopback: `ENDPOINTS_PATH` answers
    /// `status` and `body`, the rest 404.
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
