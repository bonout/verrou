//! Sélection de plusieurs éléments et actions groupées.
//!
//! La logique de la sélection (clic, ⌘-clic, ⇧-clic, ⇧↑/⇧↓, ⌘A, Échap) est
//! une fonction pure du cœur (`verrou_core::selection`), testée là-bas ;
//! l'app l'appelle à chaque geste. Les actions groupées passent par le même
//! chemin d'écriture que les actions seules (`verrou_vaultwarden::bulk`) :
//! file hors ligne et conflits compris, une synchronisation à la fin.

use verrou_core::selection::{self, Gesture, ListSelection};
use verrou_vaultwarden::{BulkAction, Skipped};

use crate::{VaultSession, VerrouError};

/// La sélection de la liste : les éléments, dans l'ordre affiché ; l'ancre
/// des plages (⇧) ; l'élément actif, montré dans la colonne de détail.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct ItemSelection {
    pub selected: Vec<String>,
    pub anchor: Option<String>,
    pub focus: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SelectionGesture {
    Click {
        id: String,
    },
    /// ⌘-clic.
    Toggle {
        id: String,
    },
    /// ⇧-clic.
    Extend {
        id: String,
    },
    /// Flèches (⇧ : `extend`).
    Step {
        offset: i32,
        extend: bool,
    },
    /// ⌘A.
    SelectAll,
    /// Échap.
    Collapse,
}

impl From<ItemSelection> for ListSelection {
    fn from(s: ItemSelection) -> Self {
        Self {
            selected: s.selected,
            anchor: s.anchor,
            focus: s.focus,
        }
    }
}

impl From<ListSelection> for ItemSelection {
    fn from(s: ListSelection) -> Self {
        Self {
            selected: s.selected,
            anchor: s.anchor,
            focus: s.focus,
        }
    }
}

impl From<SelectionGesture> for Gesture {
    fn from(g: SelectionGesture) -> Self {
        match g {
            SelectionGesture::Click { id } => Self::Click(id),
            SelectionGesture::Toggle { id } => Self::Toggle(id),
            SelectionGesture::Extend { id } => Self::Extend(id),
            SelectionGesture::Step { offset, extend } => Self::Step { offset, extend },
            SelectionGesture::SelectAll => Self::SelectAll,
            SelectionGesture::Collapse => Self::Collapse,
        }
    }
}

/// La sélection après un geste, sur les éléments affichés (`order`, dans
/// l'ordre de la liste). Linéaire en nombre de lignes.
#[uniffi::export]
pub fn select_items(
    current: ItemSelection,
    order: Vec<String>,
    gesture: SelectionGesture,
) -> ItemSelection {
    selection::apply(&current.into(), &order, &gesture.into()).into()
}

/// Action sur plusieurs éléments.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BulkItemAction {
    Trash,
    Restore,
    Archive,
    Unarchive,
    Favorite {
        favorite: bool,
    },
    /// `None` : hors de tout dossier.
    MoveToFolder {
        folder_id: Option<String>,
    },
}

impl From<BulkItemAction> for BulkAction {
    fn from(action: BulkItemAction) -> Self {
        match action {
            BulkItemAction::Trash => Self::Trash,
            BulkItemAction::Restore => Self::Restore,
            BulkItemAction::Archive => Self::Archive,
            BulkItemAction::Unarchive => Self::Unarchive,
            BulkItemAction::Favorite { favorite } => Self::Favorite(favorite),
            BulkItemAction::MoveToFolder { folder_id } => Self::MoveToFolder(folder_id),
        }
    }
}

/// Avancement d'une action groupée, appelé depuis l'envoi : répondre vite.
#[uniffi::export(callback_interface)]
pub trait BulkProgress: Send + Sync {
    fn progress(&self, done: u32, total: u32);
}

/// Bilan d'une action groupée, pour le message affiché.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BulkResult {
    /// Éléments traités (envoyés, en attente hors ligne, ou déjà dans
    /// l'état voulu).
    pub done: u32,
    /// Dont en attente du serveur (hors ligne).
    pub queued: u32,
    /// Écartés : partagés en lecture seule.
    pub read_only: u32,
    /// Écartés : dans la corbeille.
    pub in_trash: u32,
    /// Écartés : plus dans le coffre.
    pub not_found: u32,
    /// Refusés par le serveur : titres et raisons.
    pub failures: Vec<String>,
}

#[uniffi::export]
impl VaultSession {
    /// Applique l'action aux éléments, puis resynchronise une fois. Les
    /// éléments auxquels elle ne s'applique pas sont écartés et comptés.
    /// Les positions de `summaries()` changent.
    pub async fn bulk_action(
        &self,
        ids: Vec<String>,
        action: BulkItemAction,
        progress: Box<dyn BulkProgress>,
    ) -> Result<BulkResult, VerrouError> {
        let Some(connection) = self.current_connection() else {
            return Err(if self.is_unlocked() {
                VerrouError::Invalid {
                    message: "coffre fictif : lecture seule".to_owned(),
                }
            } else {
                VerrouError::Locked
            });
        };
        let report = |done: usize, total: usize| {
            progress.progress(done as u32, total as u32);
        };
        let outcome = connection
            .lock()
            .await
            .bulk(&ids, &action.into(), &report)
            .await?;
        let count =
            |reason: Skipped| outcome.skipped.iter().filter(|(_, r)| *r == reason).count() as u32;
        let result = BulkResult {
            done: outcome.done as u32,
            queued: outcome.queued as u32,
            read_only: count(Skipped::ReadOnly),
            in_trash: count(Skipped::InTrash),
            not_found: count(Skipped::NotFound),
            failures: outcome
                .failed
                .iter()
                .map(|(title, reason)| format!("{title} : {reason}"))
                .collect(),
        };
        self.install_if_current(&connection, outcome.vault)?;
        Ok(result)
    }

    /// Crée un dossier (réseau nécessaire) ; rend son identifiant.
    pub async fn create_folder(&self, name: String) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, vault) = connection.lock().await.create_folder(&name).await?;
        self.install_if_current(&connection, vault)?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn selection_crosses_the_ffi_unchanged() {
        let order = ids(&["a", "b", "c", "d"]);
        let s = select_items(
            ItemSelection::default(),
            order.clone(),
            SelectionGesture::Click { id: "b".into() },
        );
        let s = select_items(
            s,
            order.clone(),
            SelectionGesture::Extend { id: "d".into() },
        );
        assert_eq!(s.selected, ids(&["b", "c", "d"]));
        assert_eq!(s.anchor.as_deref(), Some("b"));
        assert_eq!(s.focus.as_deref(), Some("d"));
        let s = select_items(
            s,
            order.clone(),
            SelectionGesture::Toggle { id: "a".into() },
        );
        assert_eq!(s.selected, ids(&["a", "b", "c", "d"]));
        let s = select_items(
            s,
            order.clone(),
            SelectionGesture::Step {
                offset: 1,
                extend: true,
            },
        );
        assert_eq!(
            s.selected,
            ids(&["a", "b"]),
            "plage depuis la nouvelle ancre"
        );
        let s = select_items(s, order.clone(), SelectionGesture::SelectAll);
        assert_eq!(s.selected, order);
        let s = select_items(s, order, SelectionGesture::Collapse);
        assert_eq!(s.selected, ids(&["b"]));
    }

    struct Ignore;
    impl BulkProgress for Ignore {
        fn progress(&self, _: u32, _: u32) {}
    }

    #[test]
    fn the_demo_vault_refuses_bulk_actions_and_a_locked_one_too() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session = VaultSession::new();
        let locked = runtime.block_on(session.bulk_action(
            ids(&["x"]),
            BulkItemAction::Archive,
            Box::new(Ignore),
        ));
        assert!(matches!(locked, Err(VerrouError::Locked)));
        session.unlock_mock(0, 42);
        let id = session.summaries().unwrap()[0].id.clone();
        let demo = runtime.block_on(session.bulk_action(
            vec![id],
            BulkItemAction::Trash,
            Box::new(Ignore),
        ));
        assert!(matches!(demo, Err(VerrouError::Invalid { .. })));
    }
}
