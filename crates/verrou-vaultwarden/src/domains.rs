//! Domaines équivalents du compte (`/api/settings/domains`).
//!
//! Bitwarden range ces réglages côté serveur : les groupes choisis par
//! l'utilisateur (`equivalentDomains`) et la liste globale du serveur
//! (`globalEquivalentDomains`), dont l'utilisateur peut exclure des groupes.
//! La règle de correspondance « domaine » les honore (voir
//! `verrou_core::matching`). Ils ne sont pas secrets : le serveur les garde
//! en clair, Verrou les garde dans le dossier du compte.

use serde_json::Value;

use crate::api::Api;
use crate::{Connection, Error};

/// Groupes actifs : ceux de l'utilisateur, puis les groupes globaux non
/// exclus. Les domaines sont en minuscules, sans doublon dans un groupe ;
/// un groupe de moins de deux domaines est ignoré.
pub(crate) fn parse(settings: &Value) -> Vec<Vec<String>> {
    let group = |list: &Value| -> Option<Vec<String>> {
        let mut domains: Vec<String> = list
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        domains.dedup();
        (domains.len() > 1).then_some(domains)
    };
    let field = |name: &str| {
        settings
            .get(name)
            .or_else(|| settings.get(capitalised(name)))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let custom = field("equivalentDomains")
        .into_iter()
        .filter_map(|g| group(&g));
    let global = field("globalEquivalentDomains")
        .into_iter()
        .filter_map(|g| {
            let excluded = g
                .get("excluded")
                .or_else(|| g.get("Excluded"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if excluded {
                return None;
            }
            group(g.get("domains").or_else(|| g.get("Domains"))?)
        });
    custom.chain(global).collect()
}

/// `equivalentDomains` → `EquivalentDomains` (anciens serveurs).
fn capitalised(name: &str) -> String {
    let mut chars = name.chars();
    chars
        .next()
        .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
        .unwrap_or_default()
}

/// Les groupes du compte ; `None` si le serveur ne les donne pas (ancien
/// serveur, refus). Une erreur de réseau remonte.
pub(crate) async fn fetch(api: &Api, access: &str) -> Result<Option<Vec<Vec<String>>>, Error> {
    match api
        .call(reqwest::Method::GET, access, "settings/domains", None)
        .await
    {
        Ok(settings) => Ok(Some(parse(&settings))),
        Err(Error::Network(message)) => Err(Error::Network(message)),
        Err(_) => Ok(None),
    }
}

impl Connection {
    /// Relit les domaines équivalents du compte. Rend `true` s'ils ont
    /// changé. Une erreur (serveur ancien, réseau) garde les précédents.
    pub(crate) async fn refresh_domains(&mut self, access: &str) -> Result<bool, Error> {
        let Some(domains) = fetch(&self.api, access).await? else {
            return Ok(false);
        };
        let domains = Some(domains);
        if domains == self.account.equivalent_domains {
            return Ok(false);
        }
        self.account.equivalent_domains = domains;
        self.store.save_account(&self.account)?;
        Ok(true)
    }

    /// Les groupes de domaines équivalents connus (vide avant la première
    /// synchronisation qui les lit).
    pub fn equivalent_domains(&self) -> Vec<Vec<String>> {
        self.account.equivalent_domains.clone().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_then_global_groups_without_excluded_ones() {
        let settings = serde_json::json!({
            "equivalentDomains": [["exemple.fr", "Exemple.COM"], ["seul.fr"]],
            "globalEquivalentDomains": [
                {"type": 0, "domains": ["youtube.com", "google.com"], "excluded": false},
                {"type": 1, "domains": ["apple.com", "icloud.com"], "excluded": true},
            ],
            "object": "domains",
        });
        assert_eq!(
            parse(&settings),
            vec![
                vec!["exemple.fr".to_owned(), "exemple.com".to_owned()],
                vec!["youtube.com".to_owned(), "google.com".to_owned()],
            ]
        );
        assert_eq!(parse(&serde_json::json!({})).len(), 0);
        let old = serde_json::json!({"EquivalentDomains": [["a.fr", "b.fr"]]});
        assert_eq!(parse(&old).len(), 1);
    }
}
