//! Interface exposée aux applications Apple par `UniFFI`.
//!
//! Principe : Swift ne reçoit jamais un secret sans l'avoir demandé
//! explicitement. Les résumés (titre, identifiant affiché, site) arrivent une
//! fois au déverrouillage ; chaque frappe de recherche ne renvoie que des
//! positions et des surlignages ; un mot de passe ne traverse la frontière que
//! par `reveal`, au moment où l'utilisateur l'affiche ou le copie.

// UniFFI exige des arguments possédés (`String`, énumérations) : la règle
// pédantique qui voudrait des références ne s'applique pas à une frontière FFI.
#![allow(clippy::needless_pass_by_value)]

use std::sync::{Arc, PoisonError, RwLock};

use verrou_core::generator::{self, PasswordOptions};
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, Filter, Item, ItemKind, Sort, Vault, mock};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VerrouError {
    #[error("le coffre est verrouillé")]
    Locked,
    #[error("élément introuvable")]
    NotFound,
    #[error("code à usage unique invalide : {message}")]
    InvalidTotp { message: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ItemCategory {
    Login,
    Card,
    Identity,
    SecureNote,
    SshKey,
}

impl From<ItemKind> for ItemCategory {
    fn from(kind: ItemKind) -> Self {
        match kind {
            ItemKind::Login => Self::Login,
            ItemKind::Card => Self::Card,
            ItemKind::Identity => Self::Identity,
            ItemKind::SecureNote => Self::SecureNote,
            ItemKind::SshKey => Self::SshKey,
        }
    }
}

impl From<ItemCategory> for ItemKind {
    fn from(category: ItemCategory) -> Self {
        match category {
            ItemCategory::Login => Self::Login,
            ItemCategory::Card => Self::Card,
            ItemCategory::Identity => Self::Identity,
            ItemCategory::SecureNote => Self::SecureNote,
            ItemCategory::SshKey => Self::SshKey,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SidebarFilter {
    All,
    Favorites,
    WithTotp,
    Category { category: ItemCategory },
    Folder { name: String },
    Tag { name: String },
}

impl From<SidebarFilter> for Filter {
    fn from(filter: SidebarFilter) -> Self {
        match filter {
            SidebarFilter::All => Self::All,
            SidebarFilter::Favorites => Self::Favorites,
            SidebarFilter::WithTotp => Self::WithTotp,
            SidebarFilter::Category { category } => Self::Kind(category.into()),
            SidebarFilter::Folder { name } => Self::Folder(name),
            SidebarFilter::Tag { name } => Self::Tag(name),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ResultOrder {
    Relevance,
    Title,
    RecentlyModified,
}

impl From<ResultOrder> for Sort {
    fn from(order: ResultOrder) -> Self {
        match order {
            ResultOrder::Relevance => Self::Relevance,
            ResultOrder::Title => Self::Title,
            ResultOrder::RecentlyModified => Self::RecentlyModified,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FieldType {
    Text,
    Username,
    Email,
    Password,
    Concealed,
    Url,
    Phone,
    Totp,
    CardNumber,
    Expiry,
    Pin,
    Date,
    Address,
    Multiline,
}

impl From<FieldKind> for FieldType {
    fn from(kind: FieldKind) -> Self {
        match kind {
            FieldKind::Text => Self::Text,
            FieldKind::Username => Self::Username,
            FieldKind::Email => Self::Email,
            FieldKind::Password => Self::Password,
            FieldKind::Concealed => Self::Concealed,
            FieldKind::Url => Self::Url,
            FieldKind::Phone => Self::Phone,
            FieldKind::Totp => Self::Totp,
            FieldKind::CardNumber => Self::CardNumber,
            FieldKind::Expiry => Self::Expiry,
            FieldKind::Pin => Self::Pin,
            FieldKind::Date => Self::Date,
            FieldKind::Address => Self::Address,
            FieldKind::Multiline => Self::Multiline,
        }
    }
}

/// Ce que la liste affiche d'un élément. Aucun secret.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub category: ItemCategory,
    pub title: String,
    pub subtitle: String,
    pub host: Option<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_totp: bool,
    pub modified: i64,
}

/// Un résultat de recherche : position dans `summaries()` et caractères du
/// titre à surligner.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SearchHit {
    pub position: u32,
    pub highlights: Vec<u32>,
}

/// Un champ tel que l'écran de détail le présente. `value` est absent pour
/// un champ secret : il faut passer par `reveal`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FieldView {
    pub id: String,
    pub label: String,
    pub field_type: FieldType,
    pub secret: bool,
    pub value: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemDetail {
    pub summary: ItemSummary,
    pub urls: Vec<String>,
    pub fields: Vec<FieldView>,
    pub has_notes: bool,
    pub created: i64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TotpView {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NamedCount {
    pub name: String,
    pub count: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemCategoryCount {
    pub category: ItemCategory,
    pub count: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SidebarCounts {
    pub all: u32,
    pub favorites: u32,
    pub with_totp: u32,
    pub categories: Vec<ItemCategoryCount>,
    pub folders: Vec<NamedCount>,
    pub tags: Vec<NamedCount>,
}

fn summary(item: &Item) -> ItemSummary {
    ItemSummary {
        id: item.id.clone(),
        category: item.kind.into(),
        title: item.title.clone(),
        subtitle: item.subtitle.clone(),
        host: item.primary_host(),
        folder: item.folder.clone(),
        tags: item.tags.clone(),
        favorite: item.favorite,
        has_totp: item.has_totp(),
        modified: item.modified,
    }
}

/// Session du coffre. Verrouiller libère le coffre, ce qui efface ses
/// secrets de la mémoire (`SecretString` est mis à zéro à la libération).
#[derive(uniffi::Object)]
pub struct VaultSession {
    vault: RwLock<Option<Vault>>,
}

impl VaultSession {
    fn with_vault<T>(
        &self,
        f: impl FnOnce(&Vault) -> Result<T, VerrouError>,
    ) -> Result<T, VerrouError> {
        let guard = self.vault.read().unwrap_or_else(PoisonError::into_inner);
        guard.as_ref().map_or(Err(VerrouError::Locked), f)
    }

    fn item<'v>(vault: &'v Vault, id: &str) -> Result<&'v Item, VerrouError> {
        vault.get(id).ok_or(VerrouError::NotFound)
    }
}

#[uniffi::export]
impl VaultSession {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            vault: RwLock::new(None),
        })
    }

    /// Ouvre le coffre fictif (`size` = 0 : seulement les éléments soignés).
    pub fn unlock_mock(&self, size: u32, seed: u64) {
        let vault = Vault::new(mock::vault_items(size as usize, seed));
        *self.vault.write().unwrap_or_else(PoisonError::into_inner) = Some(vault);
    }

    pub fn lock(&self) {
        self.vault
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Tous les résumés, dans l'ordre du coffre. Appelé une fois après le
    /// déverrouillage ; la recherche renvoie ensuite des positions.
    pub fn summaries(&self) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| Ok(v.items().iter().map(summary).collect()))
    }

    pub fn search(
        &self,
        query: String,
        filter: SidebarFilter,
        order: ResultOrder,
    ) -> Result<Vec<SearchHit>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.search(&query, &filter.into(), order.into())
                .into_iter()
                .map(|hit| SearchHit {
                    position: hit.index as u32,
                    highlights: hit.title_indices,
                })
                .collect())
        })
    }

    pub fn detail(&self, id: String) -> Result<ItemDetail, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            let fields = item
                .fields
                .iter()
                .map(|f| {
                    let secret = f.kind.is_secret();
                    FieldView {
                        id: f.id.clone(),
                        label: f.label.clone(),
                        field_type: f.kind.into(),
                        secret,
                        value: (!secret).then(|| f.value.expose().to_owned()),
                    }
                })
                .collect();
            Ok(ItemDetail {
                summary: summary(item),
                urls: item.urls.clone(),
                fields,
                has_notes: item.notes.is_some(),
                created: item.created,
            })
        })
    }

    /// Valeur d'un champ secret (ou `notes`), à la demande de l'utilisateur.
    pub fn reveal(&self, id: String, field_id: String) -> Result<String, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if field_id == "notes" {
                return item
                    .notes
                    .as_ref()
                    .map(|n| n.expose().to_owned())
                    .ok_or(VerrouError::NotFound);
            }
            item.field(&field_id)
                .map(|f| f.value.expose().to_owned())
                .ok_or(VerrouError::NotFound)
        })
    }

    pub fn totp(&self, id: String, unix_time: u64) -> Result<TotpView, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            let field = item
                .field_of_kind(FieldKind::Totp)
                .ok_or(VerrouError::NotFound)?;
            let totp = Totp::parse(field.value.expose()).map_err(|e| VerrouError::InvalidTotp {
                message: e.to_string(),
            })?;
            let code = totp.generate(unix_time);
            Ok(TotpView {
                code: code.code,
                period: code.period,
                remaining: code.remaining,
            })
        })
    }

    pub fn counts(&self) -> Result<SidebarCounts, VerrouError> {
        self.with_vault(|v| {
            let c = v.counts();
            let named = |list: Vec<(String, usize)>| {
                list.into_iter()
                    .map(|(name, count)| NamedCount {
                        name,
                        count: count as u32,
                    })
                    .collect()
            };
            Ok(SidebarCounts {
                all: c.all as u32,
                favorites: c.favorites as u32,
                with_totp: c.with_totp as u32,
                categories: c
                    .kinds
                    .into_iter()
                    .map(|(k, n)| ItemCategoryCount {
                        category: k.into(),
                        count: n as u32,
                    })
                    .collect(),
                folders: named(c.folders),
                tags: named(c.tags),
            })
        })
    }

    /// Identifiants correspondant à une page, du plus précis au moins précis.
    pub fn suggestions(&self, page_url: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.suggestions_for(&page_url)
                .into_iter()
                .map(summary)
                .collect())
        })
    }
}

#[uniffi::export]
pub fn generate_password(length: u32, digits: bool, symbols: bool) -> String {
    generator::password(&PasswordOptions {
        length: length as usize,
        digits,
        symbols,
        avoid_ambiguous: true,
    })
}

/// Entropie estimée, en bits.
#[uniffi::export]
pub fn password_strength(password: String) -> f64 {
    generator::entropy_bits(&password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Arc<VaultSession> {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        session
    }

    #[test]
    fn secrets_never_appear_in_detail() {
        let session = session();
        let github = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.title == "GitHub")
            .unwrap();
        let detail = session.detail(github.id.clone()).unwrap();
        let password = detail.fields.iter().find(|f| f.id == "password").unwrap();
        assert!(password.secret);
        assert!(password.value.is_none());
        assert!(
            session
                .reveal(github.id.clone(), "password".into())
                .unwrap()
                .chars()
                .count()
                >= 16
        );
        assert_eq!(session.totp(github.id, 59).unwrap().code.len(), 6);
    }

    #[test]
    fn locking_forgets_the_vault() {
        let session = session();
        assert!(session.is_unlocked());
        session.lock();
        assert!(matches!(session.summaries(), Err(VerrouError::Locked)));
        assert!(matches!(
            session.search(String::new(), SidebarFilter::All, ResultOrder::Title),
            Err(VerrouError::Locked)
        ));
    }

    #[test]
    fn search_positions_index_into_summaries() {
        let session = session();
        let summaries = session.summaries().unwrap();
        let hits = session
            .search(
                "boursorama".into(),
                SidebarFilter::All,
                ResultOrder::Relevance,
            )
            .unwrap();
        assert_eq!(summaries[hits[0].position as usize].title, "Boursorama");
    }
}
