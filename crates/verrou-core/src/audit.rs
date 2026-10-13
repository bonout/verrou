//! Audit du coffre : mots de passe réutilisés, faibles, sites en HTTP.
//!
//! Tout se calcule localement, sur le coffre déverrouillé. La recherche des
//! mots de passe fuités, qui demande le réseau, vit dans
//! `verrou-vaultwarden` (`breach`).

use std::collections::HashMap;

use crate::generator::entropy_bits;
use crate::{FieldKind, Item, ItemKind, Vault};

/// En dessous, un mot de passe est jugé faible (12 caractères mêlant
/// minuscules, majuscules et chiffres en donnent environ 71).
pub const WEAK_BITS: f64 = 60.0;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    /// Groupes d'éléments qui partagent un même mot de passe (2 au moins),
    /// le plus grand d'abord.
    pub reused: Vec<Vec<String>>,
    /// Éléments au mot de passe faible et leur entropie estimée, le plus
    /// faible d'abord.
    pub weak: Vec<(String, f64)>,
    /// Identifiants dont un site est en HTTP (hors machine locale).
    pub insecure: Vec<String>,
    /// Identifiants examinés (ceux qui ont un mot de passe).
    pub checked: usize,
}

impl Report {
    pub fn issues(&self) -> usize {
        self.reused.iter().map(Vec::len).sum::<usize>() + self.weak.len() + self.insecure.len()
    }
}

/// Mot de passe d'un identifiant, s'il en a un.
pub fn password_of(item: &Item) -> Option<&str> {
    if item.kind != ItemKind::Login {
        return None;
    }
    item.field_of_kind(FieldKind::Password)
        .map(|f| f.value.expose())
        .filter(|p| !p.is_empty())
}

fn insecure_url(url: &str) -> bool {
    let Some(rest) = url.trim().strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or_default();
    !matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "")
}

pub fn audit(vault: &Vault) -> Report {
    let mut report = Report::default();
    let mut by_password: HashMap<&str, Vec<&Item>> = HashMap::new();
    for item in vault.items() {
        if item.kind != ItemKind::Login || !item.is_active() {
            continue;
        }
        if item.urls.iter().any(|u| insecure_url(u)) {
            report.insecure.push(item.id.clone());
        }
        let Some(password) = password_of(item) else {
            continue;
        };
        report.checked += 1;
        by_password.entry(password).or_default().push(item);
        let bits = entropy_bits(password);
        if bits < WEAK_BITS {
            report.weak.push((item.id.clone(), bits));
        }
    }
    let mut reused: Vec<Vec<&Item>> = by_password.into_values().filter(|g| g.len() > 1).collect();
    for group in &mut reused {
        group.sort_by_key(|i| i.title.to_lowercase());
    }
    reused.sort_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| a[0].title.cmp(&b[0].title))
    });
    report.reused = reused
        .into_iter()
        .map(|g| g.into_iter().map(|i| i.id.clone()).collect())
        .collect();
    report.weak.sort_by(|a, b| a.1.total_cmp(&b.1));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Field;

    fn login(id: &str, password: &str, url: &str) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: String::new(),
            urls: vec![url.to_owned()],
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![Field::new(
                "password",
                "Mot de passe",
                FieldKind::Password,
                password,
            )],
            notes: None,
            reprompt: false,
            state: crate::ItemState::Active,
        }
    }

    #[test]
    fn finds_reused_weak_and_insecure() {
        let strong = "Xk7#pQ2!vL9@mZ4$wR8&";
        let vault = Vault::new(vec![
            login("a", strong, "https://a.fr"),
            login("b", strong, "https://b.fr"),
            login("c", "soleil", "http://c.fr/login"),
            login("d", "Tr0ub4dor&3-cheval-agrafe", "http://localhost:8080"),
        ]);
        let report = audit(&vault);
        assert_eq!(report.reused, vec![vec!["a".to_owned(), "b".to_owned()]]);
        assert_eq!(report.weak.len(), 1);
        assert_eq!(report.weak[0].0, "c");
        assert_eq!(report.insecure, vec!["c".to_owned()]);
        assert_eq!(report.checked, 4);
        assert_eq!(report.issues(), 4);
    }
}
