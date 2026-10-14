//! Page de changement du mot de passe d'un site.
//!
//! Norme du W3C « A Well-Known URL for Changing Passwords » : un site qui la
//! suit redirige `https://<hôte>/.well-known/change-password` vers sa page de
//! changement de mot de passe. Ce module ne fait aucune requête : il calcule
//! les adresses à essayer ; la vérification (sur demande, un site à la fois)
//! est dans `verrou_vaultwarden::change_password`.
//!
//! Quelques grands sites ne suivent pas la norme mais ont une page de
//! réglages stable : une courte table (`KNOWN`) les sert directement, sans
//! requête.

use crate::matching::{host_of, registrable_domain};

/// Chemin normalisé de la page de changement de mot de passe.
pub const WELL_KNOWN_PATH: &str = "/.well-known/change-password";

/// Ressource qui ne doit pas exister : un site qui y répond 200 répond 200 à
/// tout, et sa réponse à `WELL_KNOWN_PATH` ne prouve rien.
pub const NOT_FOUND_PATH: &str =
    "/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200";

/// Domaines visés par une entrée de `KNOWN`.
enum Domains {
    /// Domaines enregistrables exacts (`live.com`, `x.com`…).
    Exact(&'static [&'static str]),
    /// Un nom sous n'importe quel suffixe public (`amazon` : `amazon.fr`,
    /// `amazon.co.uk`…).
    AnySuffix(&'static str),
}

/// Grands sites sans `/.well-known/change-password`, et leur page de
/// changement (ou de sécurité du compte). `{domain}` : le domaine
/// enregistrable de l'élément (`amazon.fr` reste sur `amazon.fr`). Liste
/// courte, à garder à jour à la main : une adresse qui change cesse
/// simplement d'être la bonne page, le site redirige alors vers son accueil.
const KNOWN: &[(Domains, &str)] = &[
    (
        Domains::AnySuffix("google"),
        "https://myaccount.google.com/signinoptions/password",
    ),
    (
        Domains::Exact(&["youtube.com", "gmail.com"]),
        "https://myaccount.google.com/signinoptions/password",
    ),
    (
        Domains::Exact(&["github.com"]),
        "https://github.com/settings/security",
    ),
    // « Votre compte », d'où part « Connexion et sécurité ».
    (
        Domains::AnySuffix("amazon"),
        "https://www.{domain}/gp/css/homepage.html",
    ),
    (
        Domains::Exact(&[
            "microsoft.com",
            "live.com",
            "outlook.com",
            "hotmail.com",
            "xbox.com",
            "office.com",
        ]),
        "https://account.live.com/password/change",
    ),
    (
        Domains::Exact(&["apple.com", "icloud.com"]),
        "https://account.apple.com/account/manage",
    ),
    (
        Domains::Exact(&["facebook.com"]),
        "https://accountscenter.facebook.com/password_and_security",
    ),
    (
        Domains::Exact(&["twitter.com", "x.com"]),
        "https://x.com/settings/password",
    ),
    (
        Domains::Exact(&["linkedin.com"]),
        "https://www.linkedin.com/mypreferences/d/change-password",
    ),
    (
        Domains::Exact(&["dropbox.com"]),
        "https://www.dropbox.com/account/security",
    ),
];

/// Page connue d'avance pour l'hôte d'un élément (table `KNOWN`), d'après
/// son domaine enregistrable : `accounts.google.com` comme `google.fr`.
pub fn known_url(host: &str) -> Option<String> {
    let domain = registrable_domain(host)?;
    let (name, _) = domain.split_once('.')?;
    KNOWN.iter().find_map(|(domains, url)| {
        let hit = match domains {
            Domains::Exact(list) => list.contains(&domain.as_str()),
            Domains::AnySuffix(wanted) => name == *wanted,
        };
        hit.then(|| url.replace("{domain}", &domain))
    })
}

/// Hôtes à essayer, dans l'ordre : celui de l'élément tel qu'enregistré
/// (`login.exemple.fr`), puis son domaine enregistrable (`exemple.fr`)
/// s'il diffère. Rien pour une adresse d'application ou une entrée vide.
pub fn candidate_hosts(input: &str) -> Vec<String> {
    let Some(host) = host_of(input) else {
        return Vec::new();
    };
    let mut hosts = vec![host.clone()];
    if let Some(domain) = registrable_domain(&host)
        && domain != host
    {
        hosts.push(domain);
    }
    hosts
}

/// Origine HTTPS d'un hôte (`https://exemple.fr`) : la page d'accueil, à
/// défaut de mieux.
pub fn origin(host: &str) -> String {
    format!("https://{host}")
}

/// Adresse normalisée de la page de changement pour un hôte.
pub fn well_known_url(host: &str) -> String {
    format!("{}{WELL_KNOWN_PATH}", origin(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_url_follows_the_spec() {
        assert_eq!(
            well_known_url("exemple.fr"),
            "https://exemple.fr/.well-known/change-password"
        );
        assert_eq!(origin("exemple.fr"), "https://exemple.fr");
    }

    #[test]
    fn candidates_are_the_host_then_its_registrable_domain() {
        assert_eq!(
            candidate_hosts("https://login.exemple.co.uk/session?x=1"),
            ["login.exemple.co.uk", "exemple.co.uk"]
        );
        // `www.` est déjà retiré par `host_of` : un seul candidat.
        assert_eq!(candidate_hosts("https://www.exemple.fr"), ["exemple.fr"]);
        assert_eq!(candidate_hosts("exemple.fr"), ["exemple.fr"]);
        // Adresse IP, nom local : l'hôte seul.
        assert_eq!(candidate_hosts("http://192.168.1.1:8080"), ["192.168.1.1"]);
        assert_eq!(candidate_hosts("routeur"), ["routeur"]);
        // Une application n'est pas un site.
        assert_eq!(
            candidate_hosts("macapp://com.exemple.app"),
            Vec::<String>::new()
        );
        assert_eq!(candidate_hosts("  "), Vec::<String>::new());
    }

    #[test]
    fn known_sites_skip_the_probe() {
        assert_eq!(
            known_url("accounts.google.com").as_deref(),
            Some("https://myaccount.google.com/signinoptions/password")
        );
        assert_eq!(
            known_url("google.fr").as_deref(),
            Some("https://myaccount.google.com/signinoptions/password")
        );
        assert_eq!(
            known_url("github.com").as_deref(),
            Some("https://github.com/settings/security")
        );
        assert_eq!(
            known_url("login.live.com").as_deref(),
            Some("https://account.live.com/password/change")
        );
        assert_eq!(
            known_url("twitter.com"),
            known_url("x.com"),
            "Twitter et X : même page"
        );
        // Amazon reste sur le domaine de l'élément.
        assert_eq!(
            known_url("amazon.fr").as_deref(),
            Some("https://www.amazon.fr/gp/css/homepage.html")
        );
        assert_eq!(
            known_url("www.amazon.co.uk").as_deref(),
            Some("https://www.amazon.co.uk/gp/css/homepage.html")
        );
    }

    #[test]
    fn unknown_sites_and_lookalikes_are_not_matched() {
        assert_eq!(known_url("exemple.fr"), None);
        // Le nom doit être exactement le domaine enregistrable.
        assert_eq!(known_url("github.io"), None);
        assert_eq!(known_url("mygithub.com"), None);
        assert_eq!(known_url("github.com.evil.fr"), None);
        assert_eq!(known_url("google.evil.fr"), None);
        assert_eq!(known_url("notamazon.fr"), None);
        assert_eq!(known_url("macapp://com.google.app"), None);
    }

    #[test]
    fn every_known_url_is_https() {
        for (_, url) in KNOWN {
            assert!(url.starts_with("https://"), "{url}");
        }
    }
}
