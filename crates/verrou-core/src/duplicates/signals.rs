//! Signaux d'un identifiant et comparaison de deux identifiants.
//!
//! Chaque identifiant est résumé une fois (sites, domaines, applications,
//! titre normalisé, marque, identifiant normalisé), puis comparé deux à deux
//! dans des « paquets » (même domaine, même marque, même titre) : jamais tout
//! le coffre contre tout le coffre. Les mots de passe et les graines TOTP ne
//! sont comparés qu'ici, en temps constant ; rien ne sort qu'un verdict.

use zeroize::Zeroizing;

use crate::apps::is_app_uri;
use crate::matching::{host_of, registrable_domain};
use crate::search::fold;

/// Premiers niveaux d'un hôte qui désignent la page de connexion (ou
/// l'espace client) d'un site, pas un service à part : `connect.maif.fr`,
/// `accounts.google.com` et `m.facebook.com` sont `maif.fr`, `google.com`
/// et `facebook.com`.
const LOGIN_PREFIXES: [&str; 31] = [
    "login",
    "signin",
    "auth",
    "account",
    "accounts",
    "myaccount",
    "id",
    "sso",
    "secure",
    "m",
    "mobile",
    "touch",
    "my",
    "app",
    "connect",
    "connexion",
    "espace",
    "espaceclient",
    "espace-client",
    "client",
    "clients",
    "compte",
    "moncompte",
    "mon-compte",
    "particulier",
    "particuliers",
    "online",
    "portail",
    "portal",
    "identity",
    "www2",
];

/// Mots d'un titre qui ne disent rien du service : « Mon compte Maif »,
/// « MAIF - Espace sociétaire » et « maif.fr » sont tous « maif ».
const TITLE_NOISE: [&str; 52] = [
    "www",
    "http",
    "https",
    "login",
    "logon",
    "signin",
    "sign",
    "connexion",
    "connecter",
    "se",
    "mon",
    "ma",
    "mes",
    "my",
    "compte",
    "comptes",
    "account",
    "accounts",
    "le",
    "la",
    "les",
    "l",
    "de",
    "du",
    "des",
    "d",
    "the",
    "app",
    "application",
    "site",
    "web",
    "en",
    "ligne",
    "online",
    "acces",
    "espace",
    "perso",
    "personnel",
    "client",
    "clients",
    "societaire",
    "societaires",
    "adherent",
    "membre",
    "abonne",
    "particulier",
    "particuliers",
    "fr",
    "com",
    "net",
    "org",
    "io",
];

/// Site d'une adresse : son hôte sans `www.` ni préfixe de connexion, jamais
/// plus court que le domaine enregistrable.
pub fn site_of(url: &str) -> Option<String> {
    let host = host_of(url)?;
    let domain = registrable_domain(&host)?;
    let mut site = host.as_str();
    while site.len() > domain.len() {
        match site.split_once('.') {
            Some((label, rest)) if LOGIN_PREFIXES.contains(&label) => site = rest,
            _ => break,
        }
    }
    Some(site.to_owned())
}

/// Premier niveau d'un domaine enregistrable, sans tiret : `maif` pour
/// `maif.fr`, `sncfconnect` pour `sncf-connect.com`.
fn label_of(domain: &str) -> Option<String> {
    let first = domain.split('.').next()?;
    let label: String = first.chars().filter(char::is_ascii_alphanumeric).collect();
    (label.len() >= 2 && domain.contains('.')).then_some(label)
}

/// Un mot du titre qui est un nom de domaine (`maif.fr`,
/// `connect.maif.fr`) : son domaine enregistrable.
fn domain_in_word(word: &str) -> Option<String> {
    let word = word
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_ascii_lowercase();
    if !word.contains('.') || word.contains('@') || !word.is_ascii() {
        return None;
    }
    let domain = psl::domain(word.as_bytes())?;
    domain.suffix().is_known().then_some(())?;
    Some(std::str::from_utf8(domain.as_bytes()).ok()?.to_owned())
}

/// Ce que dit un titre.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Title {
    /// Mots significatifs, accents et casse ignorés, séparés par une espace.
    pub normalized: String,
    /// Premier mot significatif (au moins trois lettres).
    pub first: Option<String>,
    /// Les mots significatifs accolés (« creditagricole »).
    pub whole: Option<String>,
    /// Hôtes cités par le titre (`connect.maif.fr`), pour un identifiant
    /// sans adresse.
    pub hosts: Vec<String>,
}

/// Normalise un titre : sans accents ni casse, sans ce qui est entre
/// parenthèses ou crochets, sans ponctuation ni mots de remplissage ; un
/// nom de domaine y devient son premier niveau (`maif.fr` → `maif`).
pub(crate) fn normalize_title(title: &str) -> Title {
    let mut kept = String::with_capacity(title.len());
    let mut depth = 0usize;
    for c in title.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => kept.push(c),
            _ => {}
        }
    }
    let mut hosts = Vec::new();
    let mut words: Vec<String> = Vec::new();
    for word in kept.split_whitespace() {
        if let Some(domain) = domain_in_word(word) {
            let host = word
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_ascii_lowercase();
            hosts.push(host);
            words.extend(label_of(&domain));
            continue;
        }
        let folded = fold(word);
        words.extend(
            folded
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(str::to_owned),
        );
    }
    let significant: Vec<&String> = words
        .iter()
        .filter(|w| !TITLE_NOISE.contains(&w.as_str()))
        .collect();
    // Un titre fait seulement de mots de remplissage (« Mon compte ») reste
    // ce qu'il est.
    let tokens: Vec<&String> = if significant.is_empty() {
        words.iter().collect()
    } else {
        significant
    };
    let normalized = tokens
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let brand = |s: &str| {
        (s.chars().count() >= 3 && !s.chars().all(|c| c.is_ascii_digit())).then(|| s.to_owned())
    };
    let first = tokens.first().and_then(|s| brand(s));
    let whole = brand(&tokens.iter().map(|s| s.as_str()).collect::<String>());
    Title {
        normalized,
        first,
        whole,
        hosts,
    }
}

/// Identifiant normalisé : sans espaces autour, en minuscules. Une adresse
/// électronique perd aussi son étiquette `+…` (`camille+maif@…`), dans
/// `base`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Username {
    pub full: String,
    pub base: String,
}

pub(crate) fn normalize_username(username: Option<&str>) -> Username {
    let full = username.unwrap_or_default().trim().to_lowercase();
    let base = match full.split_once('@') {
        Some((local, domain)) if !domain.is_empty() => match local.split_once('+') {
            Some((head, _)) if !head.is_empty() => format!("{head}@{domain}"),
            _ => full.clone(),
        },
        _ => full.clone(),
    };
    Username { full, base }
}

/// Graine TOTP comparable : celle d'une adresse `otpauth://`, en
/// majuscules, sans espaces, tirets ni remplissage.
pub(crate) fn normalize_totp(totp: &str) -> Zeroizing<String> {
    let trimmed = totp.trim();
    let secret = if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        trimmed
            .split_once('?')
            .map(|(_, query)| query)
            .unwrap_or_default()
            .split('&')
            .find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                key.eq_ignore_ascii_case("secret").then_some(value)
            })
            .unwrap_or_default()
    } else {
        trimmed
    };
    Zeroizing::new(
        secret
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | '='))
            .flat_map(char::to_uppercase)
            .collect(),
    )
}

/// Égalité de deux secrets sans court-circuit : le temps ne dépend que de
/// leurs longueurs.
pub(crate) fn same_secret(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Résumé d'un identifiant, calculé une fois.
pub(crate) struct Signals<'a> {
    /// Coffre de l'élément : personnel (`""`) ou organisation.
    pub owner: &'a str,
    pub display_title: &'a str,
    /// Sites (hôte sans préfixe de connexion), triés, sans doublon.
    pub sites: Vec<String>,
    /// Domaines enregistrables, triés, sans doublon.
    pub domains: Vec<String>,
    /// Premier niveau de chaque domaine (`maif`).
    pub labels: Vec<String>,
    /// Applications (`macapp:com.exemple`), en minuscules.
    pub apps: Vec<String>,
    /// Au moins une adresse web (ou une passkey) : le titre ne sert alors
    /// pas de site.
    pub has_web: bool,
    pub title: Title,
    pub user: Username,
    pub password: &'a str,
    pub totp: Option<Zeroizing<String>>,
}

/// Ce que l'élément apporte pour être comparé.
pub(crate) struct Source<'a> {
    pub owner: &'a str,
    pub title: &'a str,
    pub urls: &'a [String],
    /// Sites des passkeys (`rpId`).
    pub passkeys: &'a [String],
    pub username: Option<&'a str>,
    pub password: &'a str,
    pub totp: Option<&'a str>,
}

fn sorted(mut list: Vec<String>) -> Vec<String> {
    list.sort();
    list.dedup();
    list
}

impl<'a> Signals<'a> {
    pub(crate) fn new(source: &Source<'a>) -> Self {
        let mut hosts: Vec<String> = Vec::new();
        let mut apps = Vec::new();
        for url in source.urls {
            if is_app_uri(url) {
                if let Some((scheme, id)) = url.trim().split_once("://") {
                    let id = id.trim_end_matches('/');
                    if !id.is_empty() {
                        apps.push(format!(
                            "{}:{}",
                            scheme.to_ascii_lowercase(),
                            id.to_ascii_lowercase()
                        ));
                    }
                }
            } else if let Some(host) = host_of(url) {
                hosts.push(host);
            }
        }
        hosts.extend(source.passkeys.iter().filter_map(|rp| host_of(rp)));
        let has_web = !hosts.is_empty();
        let title = normalize_title(source.title);
        // Sans adresse web, un titre qui cite un domaine en tient lieu.
        if !has_web {
            hosts.extend(title.hosts.iter().cloned());
        }
        let sites = sorted(hosts.iter().filter_map(|h| site_of(h)).collect());
        let domains = sorted(hosts.iter().filter_map(|h| registrable_domain(h)).collect());
        let labels = sorted(domains.iter().filter_map(|d| label_of(d)).collect());
        Self {
            owner: source.owner,
            display_title: source.title,
            sites,
            domains,
            labels,
            apps: sorted(apps),
            has_web,
            title,
            user: normalize_username(source.username),
            password: source.password,
            totp: source
                .totp
                .map(normalize_totp)
                .filter(|secret| !secret.is_empty()),
        }
    }

    /// Clés des paquets « web » : domaines et applications.
    pub(crate) fn web_keys(&self) -> impl Iterator<Item = String> + '_ {
        let domains = self
            .domains
            .iter()
            .map(|d| format!("d\u{0}{}\u{0}{d}", self.owner));
        let apps = self
            .apps
            .iter()
            .map(|a| format!("a\u{0}{}\u{0}{a}", self.owner));
        domains.chain(apps)
    }

    /// Clés des paquets « nom » : marques du titre, premiers niveaux des
    /// domaines, titre normalisé. Ne servent qu'à rapprocher un élément
    /// sans adresse web d'un autre.
    pub(crate) fn name_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        let brands = self
            .title
            .first
            .iter()
            .chain(&self.title.whole)
            .chain(&self.labels);
        for brand in brands {
            keys.push(format!("b\u{0}{}\u{0}{brand}", self.owner));
        }
        if !self.title.normalized.is_empty() {
            keys.push(format!(
                "t\u{0}{}\u{0}{}",
                self.owner, self.title.normalized
            ));
        }
        keys.sort();
        keys.dedup();
        keys
    }
}

/// Degré de certitude d'un doublon, du plus faible au plus fort.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// « À vérifier » : jamais coché d'office.
    Review,
    /// « Probable » : suggéré, pas coché.
    Probable,
    /// « Certain » : les copies sont cochées pour la corbeille.
    Certain,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::Certain => "Certain",
            Self::Probable => "Probable",
            Self::Review => "À vérifier",
        }
    }
}

/// Ce que deux identifiants ont en commun côté site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SiteLink {
    App(String),
    Site(String),
    /// Même domaine, sous-domaines différents (`cloud.exemple.fr` et
    /// `vault.exemple.fr`) : souvent deux services.
    Domain(String),
    /// Le titre de l'un (sans adresse web) est la marque du domaine de
    /// l'autre. `whole` : le titre entier, pas seulement son premier mot.
    Brand {
        title: String,
        domain: String,
        whole: bool,
    },
    /// Même titre normalisé, l'un au moins sans adresse web.
    Title(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserLink {
    Same,
    OneMissing,
    BothMissing,
    Different,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PasswordLink {
    /// Égaux (ou tous deux vides).
    Same,
    Different,
    OneMissing,
}

/// Verdict sur deux identifiants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Relation {
    pub confidence: Confidence,
    pub site: SiteLink,
    pub user: UserLink,
    pub password: PasswordLink,
    pub same_totp: bool,
}

impl Relation {
    /// La raison, en clair : « même site (maif.fr), même identifiant, même
    /// mot de passe ».
    pub(crate) fn reason(&self) -> String {
        let site = match &self.site {
            SiteLink::App(app) => format!(
                "même app ({})",
                app.split_once(':').map_or(app.as_str(), |(_, id)| id)
            ),
            SiteLink::Site(site) => format!("même site ({site})"),
            SiteLink::Domain(domain) => format!("même domaine ({domain}), autre sous-domaine"),
            SiteLink::Brand { title, domain, .. } => format!("titre « {title} » ↔ {domain}"),
            SiteLink::Title(title) => format!("même titre « {title} », sans site"),
        };
        let user = match self.user {
            UserLink::Same => "même identifiant",
            UserLink::OneMissing => "un identifiant manquant",
            UserLink::BothMissing => "sans identifiant",
            UserLink::Different => "autre identifiant",
        };
        let password = match self.password {
            PasswordLink::Same => "même mot de passe",
            PasswordLink::Different => "autre mot de passe",
            PasswordLink::OneMissing => "un mot de passe manquant",
        };
        let mut parts = vec![site, user.to_owned(), password.to_owned()];
        if self.same_totp {
            parts.push("même code à usage unique".to_owned());
        }
        parts.join(", ")
    }
}

fn common<'v>(a: &'v [String], b: &[String]) -> Option<&'v String> {
    // Listes triées : parcours conjoint.
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => return Some(&a[i]),
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }
    None
}

/// Le titre de `named` (sans adresse web) désigne-t-il un domaine de `other` ?
fn brand_link(named: &Signals, other: &Signals) -> Option<SiteLink> {
    if named.has_web {
        return None;
    }
    let whole = named.title.whole.as_ref();
    let first = named.title.first.as_ref();
    let (label, whole) = other
        .labels
        .iter()
        .find(|l| Some(*l) == whole)
        .map(|l| (l, true))
        .or_else(|| {
            other
                .labels
                .iter()
                .find(|l| Some(*l) == first)
                .map(|l| (l, false))
        })?;
    let domain = other
        .domains
        .iter()
        .find(|d| label_of(d).as_ref() == Some(label))
        .cloned()
        .unwrap_or_default();
    Some(SiteLink::Brand {
        title: named.display_title.trim().to_owned(),
        domain,
        whole,
    })
}

fn site_link(a: &Signals, b: &Signals) -> Option<SiteLink> {
    if let Some(app) = common(&a.apps, &b.apps) {
        return Some(SiteLink::App(app.clone()));
    }
    if let Some(site) = common(&a.sites, &b.sites) {
        return Some(SiteLink::Site(site.clone()));
    }
    if let Some(domain) = common(&a.domains, &b.domains) {
        return Some(SiteLink::Domain(domain.clone()));
    }
    if a.has_web && b.has_web {
        return None;
    }
    if let Some(link) = brand_link(a, b).or_else(|| brand_link(b, a)) {
        return Some(link);
    }
    (!a.title.normalized.is_empty() && a.title.normalized == b.title.normalized)
        .then(|| SiteLink::Title(a.display_title.trim().to_owned()))
}

fn user_link(a: &Username, b: &Username) -> UserLink {
    match (a.full.is_empty(), b.full.is_empty()) {
        (true, true) => UserLink::BothMissing,
        (true, false) | (false, true) => UserLink::OneMissing,
        (false, false) if a.full == b.full || a.base == b.base => UserLink::Same,
        (false, false) => UserLink::Different,
    }
}

fn password_link(a: &str, b: &str) -> PasswordLink {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => PasswordLink::Same,
        (true, false) | (false, true) => PasswordLink::OneMissing,
        (false, false) if same_secret(a, b) => PasswordLink::Same,
        (false, false) => PasswordLink::Different,
    }
}

/// Le titre de l'un désigne-t-il le domaine commun (ou les titres sont-ils
/// les mêmes) ? Sert à départager deux sous-domaines.
fn titles_agree(a: &Signals, b: &Signals, domain: &str) -> bool {
    if !a.title.normalized.is_empty() && a.title.normalized == b.title.normalized {
        return true;
    }
    let label = label_of(domain);
    [a, b]
        .iter()
        .any(|s| label.is_some() && (s.title.first == label || s.title.whole == label))
}

/// Compare deux identifiants. `None` : rien qui ressemble à un doublon.
pub(crate) fn relate(a: &Signals, b: &Signals) -> Option<Relation> {
    use Confidence::{Certain, Probable, Review};
    use PasswordLink as P;
    use UserLink as U;
    if a.owner != b.owner {
        return None;
    }
    let site = site_link(a, b)?;
    let user = user_link(&a.user, &b.user);
    let password = password_link(a.password, b.password);
    let same_totp = match (&a.totp, &b.totp) {
        (Some(x), Some(y)) => same_secret(x, y),
        _ => false,
    };
    let missing = matches!(user, U::OneMissing | U::BothMissing);
    let confidence = match &site {
        // Même graine TOTP : le même compte, même sur un autre sous-domaine.
        SiteLink::App(_) | SiteLink::Site(_) => strong(user, password),
        SiteLink::Domain(_) if same_totp => strong(user, password),
        SiteLink::Domain(domain) => {
            let agree = titles_agree(a, b, domain);
            match (user, password) {
                (U::Same, P::Same) if agree => Some(Probable),
                (U::Same | U::Different, P::Same) => Some(Review),
                (U::Same, _) if agree => Some(Review),
                (_, P::Same) if missing => Some(Review),
                _ => None,
            }
        }
        SiteLink::Brand { whole: true, .. } | SiteLink::Title(_) => match (user, password) {
            (U::Same, P::Same) => Some(Certain),
            (U::Same, _) => Some(Probable),
            (_, P::Same) if missing => Some(Probable),
            _ if missing => Some(Review),
            _ => None,
        },
        SiteLink::Brand { whole: false, .. } => match (user, password) {
            (U::Same, P::Same) => Some(Probable),
            (U::Same, _) => Some(Review),
            (_, P::Same) if missing => Some(Review),
            _ => None,
        },
    }?;
    Some(Relation {
        confidence,
        site,
        user,
        password,
        same_totp,
    })
}

/// Même site (ou même app) : la règle de base.
fn strong(user: UserLink, password: PasswordLink) -> Option<Confidence> {
    use Confidence::{Certain, Probable, Review};
    use PasswordLink as P;
    use UserLink as U;
    match (user, password) {
        (U::Same, P::Same) => Some(Certain),
        (U::Same, _) | (U::OneMissing | U::BothMissing, P::Same) => Some(Probable),
        (U::OneMissing | U::BothMissing, _) | (U::Different, P::Same) => Some(Review),
        (U::Different, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_lose_their_noise() {
        let maif = |t: &str| normalize_title(t).normalized;
        assert_eq!(maif("Maif"), "maif");
        assert_eq!(maif("maif.fr"), "maif");
        assert_eq!(maif("connect.maif.fr"), "maif");
        assert_eq!(maif("MAIF - Espace sociétaire"), "maif");
        assert_eq!(maif("Mon compte MAIF (Camille)"), "maif");
        assert_eq!(maif("www.maif.fr [ancien]"), "maif");
        assert_eq!(maif("Crédit Agricole"), "credit agricole");
        assert_eq!(
            normalize_title("Crédit Agricole").whole.as_deref(),
            Some("creditagricole")
        );
        assert_eq!(maif("Mon compte"), "mon compte", "rien que du remplissage");
        assert_eq!(
            normalize_title("connect.maif.fr").hosts,
            vec!["connect.maif.fr"]
        );
        assert_eq!(normalize_title("v1.2 notes").hosts, Vec::<String>::new());
        assert_eq!(
            normalize_title("Wi-Fi").first,
            None,
            "trop court pour une marque"
        );
    }

    #[test]
    fn sites_strip_login_prefixes_only() {
        assert_eq!(
            site_of("https://connect.maif.fr/espace").as_deref(),
            Some("maif.fr")
        );
        assert_eq!(
            site_of("https://accounts.google.com").as_deref(),
            Some("google.com")
        );
        assert_eq!(
            site_of("https://m.facebook.com").as_deref(),
            Some("facebook.com")
        );
        assert_eq!(
            site_of("https://cloud.exemple.fr").as_deref(),
            Some("cloud.exemple.fr")
        );
        assert_eq!(site_of("https://app.co.uk").as_deref(), Some("app.co.uk"));
    }

    #[test]
    fn usernames_and_totp_are_normalised() {
        let user = normalize_username(Some("  Camille+Maif@Exemple.fr "));
        assert_eq!(user.full, "camille+maif@exemple.fr");
        assert_eq!(user.base, "camille@exemple.fr");
        assert_eq!(normalize_username(Some("+33 6 12")).base, "+33 6 12");
        assert_eq!(
            normalize_totp("otpauth://totp/X:c?secret=jbsw y3dp&issuer=X").as_str(),
            "JBSWY3DP"
        );
        assert_eq!(normalize_totp("jbsw-y3dp==").as_str(), "JBSWY3DP");
        assert!(same_secret("abc", "abc"));
        assert!(!same_secret("abc", "abd"));
        assert!(!same_secret("abc", "abcd"));
    }
}
