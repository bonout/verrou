//! Compléments de l'audit pour l'app : double authentification disponible
//! mais absente (2fa.directory), cartes expirées, mots de passe anciens, et
//! vérification dans les fuites connues des mots de passe qu'on vient
//! d'enregistrer. Voir `verrou_core::watchtower`.

use std::sync::{Arc, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};
use verrou_core::{SecretString, watchtower};
use verrou_vaultwarden::change_password::{self, Source};
use verrou_vaultwarden::{Connection, Decrypted};

use crate::{BreachedPassword, ItemSummary, VaultSession, VerrouError, summary};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Cartes et mots de passe anciens : calculés localement, sans réseau.
#[derive(Clone, Debug, uniffi::Record)]
pub struct WatchtowerReport {
    /// Cartes expirées ou qui expirent dans les 60 jours, la plus urgente
    /// d'abord.
    pub cards: Vec<ExpiringCard>,
    /// Identifiants inchangés depuis plus de 3 ans, le plus ancien d'abord.
    pub old: Vec<OldPassword>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ExpiringCard {
    pub item: ItemSummary,
    /// Mois et année d'expiration (`09/2029`).
    pub expiry: String,
    /// Jours restants jusqu'à la fin du mois d'expiration ; négatif : expirée.
    pub days_left: i64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct OldPassword {
    pub item: ItemSummary,
    /// Jours depuis la dernière modification de l'élément.
    pub days: i64,
}

/// Identifiants dont le site propose la double authentification, sans code
/// à usage unique dans Verrou.
#[derive(Clone, Debug, uniffi::Record)]
pub struct TwoFactorReport {
    pub missing: Vec<MissingTwoFactor>,
    /// Horodatage Unix de la copie de la liste utilisée.
    pub fetched_at: i64,
    /// Copie de plus de 7 jours, faute de réseau.
    pub stale: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MissingTwoFactor {
    pub item: ItemSummary,
    /// Nom du site dans 2fa.directory.
    pub site: String,
    /// Le site accepte les codes à usage unique (TOTP), que Verrou sait
    /// garder et remplir.
    pub totp: bool,
    /// Méthodes proposées (`totp`, `sms`, `u2f`, `email`…).
    pub methods: Vec<String>,
    /// Page d'aide du site pour l'activer (HTTPS).
    pub documentation: Option<String>,
}

/// D'où vient la page proposée par « Changer le mot de passe ».
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChangePasswordSource {
    /// Grand site connu d'avance (Google, GitHub…), sans requête.
    Known,
    /// Le site suit la norme `/.well-known/change-password`.
    WellKnown,
    /// Le site n'indique pas sa page (ou ne répond pas) : son accueil.
    Home,
}

impl From<Source> for ChangePasswordSource {
    fn from(source: Source) -> Self {
        match source {
            Source::Known => Self::Known,
            Source::WellKnown => Self::WellKnown,
            Source::Home => Self::Home,
        }
    }
}

/// Page à ouvrir pour changer le mot de passe d'un identifiant (HTTPS).
#[derive(Clone, Debug, uniffi::Record)]
pub struct ChangePasswordPage {
    pub url: String,
    pub source: ChangePasswordSource,
}

fn fingerprint(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

impl VaultSession {
    /// Retient l'empreinte des mots de passe trouvés dans des fuites, tels
    /// qu'ils ont été vérifiés (voir `still_breached`).
    pub(crate) fn remember_breached(
        &self,
        checked: &[(String, SecretString)],
        found: &[BreachedPassword],
    ) {
        let mut breached = self.breached.lock().unwrap_or_else(PoisonError::into_inner);
        for (id, password) in checked {
            if found.iter().any(|b| &b.item.id == id) {
                breached.insert(id.clone(), fingerprint(password.expose()));
            } else {
                breached.remove(id);
            }
        }
    }

    /// Installe le coffre renvoyé par une écriture faite depuis Verrou
    /// (éditeur, extension, import) et retient les identifiants dont le mot
    /// de passe est nouveau, pour `check_new_passwords`.
    pub(crate) fn install_written(
        &self,
        connection: &Arc<tokio::sync::Mutex<Connection>>,
        decrypted: Decrypted,
    ) -> Result<(), VerrouError> {
        let before = self.vault.read().unwrap_or_else(PoisonError::into_inner);
        let changed = watchtower::changed_passwords(before.as_ref(), &decrypted.items);
        drop(before);
        self.install_if_current(connection, decrypted)?;
        if !changed.is_empty() {
            let mut queue = self
                .new_passwords
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for id in changed {
                if !queue.contains(&id) {
                    queue.push(id);
                }
            }
        }
        Ok(())
    }
}

#[uniffi::export]
impl VaultSession {
    /// Cartes expirées ou bientôt expirées, mots de passe anciens.
    pub fn watchtower(&self) -> Result<WatchtowerReport, VerrouError> {
        let now = now();
        self.with_vault(|v| {
            Ok(WatchtowerReport {
                cards: watchtower::expiring_cards(v, now)
                    .into_iter()
                    .filter_map(|c| {
                        v.get(&c.id).map(|i| ExpiringCard {
                            item: summary(i),
                            expiry: format!("{:02}/{}", c.expiry.month, c.expiry.year),
                            days_left: c.days_left,
                        })
                    })
                    .collect(),
                old: watchtower::old_passwords(v, now)
                    .into_iter()
                    .filter_map(|(id, days)| {
                        v.get(&id).map(|i| OldPassword {
                            item: summary(i),
                            days,
                        })
                    })
                    .collect(),
            })
        })
    }

    /// Fuites encore d'actualité : les identifiants dont le mot de passe n'a
    /// pas changé depuis leur vérification, avec leur résumé à jour. Un
    /// élément supprimé, mis à la corbeille ou au mot de passe changé (dans
    /// Verrou, le navigateur ou ailleurs, puis synchronisé) disparaît de la
    /// liste. Local, sans réseau.
    pub fn still_breached(&self, breaches: Vec<BreachedPassword>) -> Vec<BreachedPassword> {
        let known = self.breached.lock().unwrap_or_else(PoisonError::into_inner);
        self.with_vault(|v| {
            Ok(breaches
                .into_iter()
                .filter_map(|b| {
                    let item = v.get(&b.item.id).filter(|i| i.is_active())?;
                    let password = verrou_core::audit::password_of(item)?;
                    (known.get(&item.id) == Some(&fingerprint(password))).then(|| {
                        BreachedPassword {
                            item: summary(item),
                            count: b.count,
                        }
                    })
                })
                .collect())
        })
        .unwrap_or_default()
    }

    /// Oublie les nouveaux mots de passe en attente (vérification désactivée).
    pub fn forget_new_passwords(&self) {
        self.new_passwords
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Sites des identifiants qui proposent la double authentification alors
    /// que l'élément n'a pas de code à usage unique. Télécharge la liste
    /// complète de 2fa.directory (rien du coffre ne part), gardée 7 jours dans
    /// le dossier du compte ; hors ligne, la dernière copie.
    pub async fn two_factor_audit(&self) -> Result<TwoFactorReport, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        let loaded = verrou_vaultwarden::two_factor_directory::load(&dir).await?;
        self.with_vault(|v| {
            Ok(TwoFactorReport {
                missing: watchtower::missing_two_factor(v, &loaded.directory)
                    .into_iter()
                    .filter_map(|(id, site)| {
                        v.get(&id).map(|i| MissingTwoFactor {
                            item: summary(i),
                            site: site.name.clone(),
                            totp: site.supports_totp(),
                            methods: site.methods.clone(),
                            documentation: site.documentation.clone(),
                        })
                    })
                    .collect(),
                fetched_at: loaded.fetched_at,
                stale: loaded.stale,
            })
        })
    }

    /// Vérifie dans Have I Been Pwned (k-anonymat : 5 caractères du SHA-1)
    /// les mots de passe enregistrés depuis Verrou depuis le dernier appel,
    /// et rend ceux qui figurent dans des fuites connues. Les mots de passe
    /// venus d'ailleurs (synchronisation) ne sont pas concernés.
    pub async fn check_new_passwords(&self) -> Result<Vec<BreachedPassword>, VerrouError> {
        let ids: Vec<String> = std::mem::take(
            &mut *self
                .new_passwords
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let candidates: Vec<(String, verrou_core::SecretString)> = self.with_vault(|v| {
            Ok(ids
                .iter()
                .filter_map(|id| v.get(id))
                .filter(|i| i.is_active())
                .filter_map(|i| {
                    verrou_core::audit::password_of(i)
                        .map(|p| (i.id.clone(), verrou_core::SecretString::new(p)))
                })
                .collect())
        })?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let passwords: Vec<&str> = candidates.iter().map(|(_, p)| p.expose()).collect();
        let counts = match verrou_vaultwarden::breach::pwned_counts(&passwords).await {
            Ok(counts) => counts,
            Err(error) => {
                // Hors ligne : on réessaiera à la prochaine écriture.
                let mut queue = self
                    .new_passwords
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                for (id, _) in candidates {
                    if !queue.contains(&id) {
                        queue.push(id);
                    }
                }
                return Err(error.into());
            }
        };
        let found: Vec<BreachedPassword> = self.with_vault(|v| {
            Ok(candidates
                .iter()
                .zip(counts)
                .filter(|(_, count)| *count > 0)
                .filter_map(|((id, _), count)| {
                    v.get(id).map(|i| BreachedPassword {
                        item: summary(i),
                        count,
                    })
                })
                .collect())
        })?;
        self.remember_breached(&candidates, &found);
        Ok(found)
    }

    /// Page où changer le mot de passe d'un identifiant : grand site connu,
    /// sinon `/.well-known/change-password` vérifié sur son hôte puis son
    /// domaine, sinon l'accueil du site. Seulement sur demande de
    /// l'utilisateur, pour cet élément seul : les requêtes ne partent que
    /// vers le site qu'il s'apprête à ouvrir.
    pub async fn change_password_page(
        &self,
        id: String,
    ) -> Result<ChangePasswordPage, VerrouError> {
        let host = self
            .with_vault(|v| Ok(v.get(&id).ok_or(VerrouError::NotFound)?.primary_host()))?
            .ok_or_else(|| VerrouError::Invalid {
                message: "cet élément n'a pas de site".to_owned(),
            })?;
        let page = change_password::find(&host).await?;
        Ok(ChangePasswordPage {
            url: page.url,
            source: page.source.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchtower_reports_mock_cards() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        // Le coffre fictif a des cartes (09/29, 03/28, 11/27) : aucune
        // n'expire avant l'automne 2027.
        let report = session.watchtower().unwrap();
        assert!(report.cards.iter().all(|c| c.days_left <= 60));
    }

    #[test]
    fn breaches_leave_the_list_once_the_password_changed() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        let (id, password, item) = session
            .with_vault(|v| {
                let item = v
                    .items()
                    .iter()
                    .find(|i| i.is_active() && verrou_core::audit::password_of(i).is_some())
                    .unwrap();
                Ok((
                    item.id.clone(),
                    verrou_core::audit::password_of(item).unwrap().to_owned(),
                    summary(item),
                ))
            })
            .unwrap();
        let found = vec![BreachedPassword { item, count: 3 }];
        // Vérifié avec le mot de passe actuel : toujours d'actualité.
        session.remember_breached(&[(id.clone(), SecretString::new(password))], &found);
        assert_eq!(session.still_breached(found.clone()).len(), 1);
        // Vérifié avec un autre mot de passe : il a changé depuis.
        session.remember_breached(&[(id.clone(), SecretString::new("ancien"))], &found);
        assert!(session.still_breached(found.clone()).is_empty());
        // Revérifié et propre : oublié.
        session.remember_breached(&[(id, SecretString::new("x"))], &[]);
        assert!(session.still_breached(found.clone()).is_empty());
        // Verrouillé : plus rien.
        session.lock();
        assert!(session.still_breached(found).is_empty());
    }

    #[tokio::test]
    async fn change_password_page_needs_a_site() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        assert!(matches!(
            session.change_password_page("absent".to_owned()).await,
            Err(VerrouError::NotFound)
        ));
    }

    #[tokio::test]
    async fn no_new_password_means_no_request() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        assert!(session.check_new_passwords().await.unwrap().is_empty());
        // Sans compte, pas de dossier où garder la liste.
        assert!(matches!(
            session.two_factor_audit().await,
            Err(VerrouError::NoAccount)
        ));
    }
}
