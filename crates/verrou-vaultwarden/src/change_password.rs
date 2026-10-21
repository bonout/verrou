//! "Change password": find the page where to do it on a site.
//!
//! Order: a page known in advance for a few big sites
//! (`verrou_core::change_password::known_url`, without request), then the
//! W3C "A Well-Known URL for Changing Passwords" standard, checked on the
//! item's host then on its registrable domain, and failing that the site's
//! home page.
//!
//! Privacy: only at the user's request, for a single item at a time, never
//! in bulk. The requests go to the site they are about to open, and to it
//! alone (redirects included): the site learns it is being visited, which
//! it would learn anyway. HTTPS only, no cookie (reqwest keeps none without
//! the `cookies` feature), no `Referer` header, with a short timeout; the
//! response bodies are not read.

use std::time::Duration;

use futures_util::future::join;
use reqwest::{StatusCode, Url, redirect};
use verrou_core::change_password::{
    NOT_FOUND_PATH, WELL_KNOWN_PATH, candidate_hosts, known_url, origin,
};

use crate::Error;

/// Beyond this, the site is deemed unreachable: its home page is opened.
const TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REDIRECTS: usize = 10;

/// Where the proposed address comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Table of big sites, without request.
    Known,
    /// The site follows the standard: final address after redirects.
    WellKnown,
    /// The site doesn't give its page (or doesn't answer): its home page.
    Home,
}

/// Page to open to change the password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub url: String,
    pub source: Source,
}

/// The password change page for a login's host (or address). An error only
/// if there is no site.
pub async fn find(site: &str) -> Result<Page, Error> {
    let hosts = candidate_hosts(site);
    let Some(host) = hosts.first() else {
        return Err(Error::Invalid("this item has no site".to_owned()));
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

/// First site that follows the standard, otherwise `home`.
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

/// Allowed address: HTTPS. HTTP only to the loopback, and only if
/// `loopback_http` (the tests' fake server).
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
        // A redirect to HTTP (or anything other than HTTPS) stops the chase:
        // the 3xx response is not "OK", the site is deemed to have no change
        // page.
        let policy = redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
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

    /// Status and final address (after redirects) of a GET request; `None`
    /// if the site doesn't answer.
    async fn get(&self, url: Url) -> Option<(StatusCode, Url)> {
        let response = self.client.get(url).send().await.ok()?;
        Some((response.status(), response.url().clone()))
    }

    /// Final address of `/.well-known/change-password` if `site` follows the
    /// standard: this address answers "OK" (2xx) after redirects, and a
    /// resource that must not exist doesn't answer "OK" (otherwise the site
    /// answers 2xx to everything, and its answer proves nothing).
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

    /// The fake server's answer: status, and optional `Location`.
    type Routes = HashMap<&'static str, (u16, Option<String>)>;

    /// Minimal HTTP server on the loopback; missing paths answer `fallback`.
    /// Returns its origin and the log of requested paths.
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
                // The rest of the request (headers), up to the empty line.
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
        // Redirect to a missing page.
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
        // A redirect to a host over HTTP (outside the loopback) is not
        // followed: no request goes out in clear.
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
        // The production client only allows HTTPS: nothing goes out.
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
        // No request: the table is enough (the test passes offline).
        let page = find("https://accounts.google.com/signin").await.unwrap();
        assert_eq!(page.source, Source::Known);
        assert!(page.url.starts_with("https://myaccount.google.com/"));
        assert!(matches!(
            find("macapp://com.exemple").await,
            Err(Error::Invalid(_))
        ));
    }
}
