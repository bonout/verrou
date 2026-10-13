//! Mots de passe fuités, par l'API « Pwned Passwords » de Have I Been Pwned.
//!
//! Anonymat par k-anonymat : seuls les 5 premiers caractères hexadécimaux du
//! SHA-1 d'un mot de passe partent ; le service renvoie tous les suffixes
//! connus qui commencent ainsi (avec du remplissage, `Add-Padding`), et la
//! comparaison se fait ici. Ni le mot de passe ni son empreinte complète ne
//! quittent le Mac. Seulement sur demande de l'utilisateur.

use std::collections::HashMap;

use futures_util::{StreamExt as _, stream};
use sha1::{Digest as _, Sha1};

use crate::Error;

const API: &str = "https://api.pwnedpasswords.com/range/";
/// Requêtes simultanées : le service est rapide, inutile de l'assaillir.
const CONCURRENCY: usize = 8;

/// SHA-1 en hexadécimal majuscule, coupé en préfixe (5) et suffixe (35).
fn split_hash(password: &str) -> (String, String) {
    let hex = data_encoding::HEXUPPER.encode(&Sha1::digest(password.as_bytes()));
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_owned(), suffix.to_owned())
}

/// Nombre d'apparitions de `suffix` dans une réponse de l'API (`SUFFIXE:N`
/// par ligne ; les lignes de remplissage valent 0).
fn count_in(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

/// Pour chaque mot de passe, le nombre de fois où il apparaît dans des
/// fuites connues (0 : jamais vu). Une seule requête par préfixe.
pub async fn pwned_counts(passwords: &[&str]) -> Result<Vec<u64>, Error> {
    let hashes: Vec<(String, String)> = passwords.iter().map(|p| split_hash(p)).collect();
    // Préfixes possédés : le futur doit pouvoir changer de fil (`Send`).
    let mut prefixes: Vec<String> = hashes.iter().map(|(p, _)| p.clone()).collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    let client = reqwest::Client::builder()
        .user_agent(concat!("Verrou/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;
    let responses: Vec<Result<(String, String), Error>> = stream::iter(prefixes)
        .map(|prefix| {
            let client = client.clone();
            async move {
                let body = client
                    .get(format!("{API}{prefix}"))
                    .header("Add-Padding", "true")
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|e| Error::Network(e.to_string()))?
                    .text()
                    .await
                    .map_err(|e| Error::Network(e.to_string()))?;
                Ok((prefix, body))
            }
        })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    let bodies: HashMap<String, String> = responses.into_iter().collect::<Result<_, _>>()?;
    Ok(hashes
        .iter()
        .map(|(prefix, suffix)| bodies.get(prefix).map_or(0, |b| count_in(b, suffix)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_prefix_leaves() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = split_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    /// Contre le vrai service (réseau) : `cargo test -p verrou-vaultwarden -- --ignored breach`.
    #[tokio::test]
    #[ignore = "réseau : api.pwnedpasswords.com"]
    async fn real_service_knows_password() {
        let counts = pwned_counts(&["password", "Xk7#pQ2!vL9@mZ4$wR8&-verrou-jamais-vu"])
            .await
            .unwrap();
        assert!(counts[0] > 1_000_000);
        assert_eq!(counts[1], 0);
    }

    #[test]
    fn reads_the_range_response() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\nAAAA0000000000000000000000000000000:0\r\n";
        assert_eq!(
            count_in(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            10_434_004
        );
        assert_eq!(count_in(body, "AAAA0000000000000000000000000000000"), 0);
        assert_eq!(count_in(body, "FFFF0000000000000000000000000000000"), 0);
    }
}
