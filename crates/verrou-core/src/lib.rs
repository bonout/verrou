//! Cœur de Verrou, partagé par l'application Apple (via `verrou-ffi`) et la CLI.
//!
//! Ce crate ne fait aucune entrée-sortie : il reçoit des éléments déjà
//! déchiffrés, les indexe et y cherche. Le déchiffrement et la synchronisation
//! avec Vaultwarden sont dans `verrou-vaultwarden`, construit sur le SDK Rust
//! de Bitwarden.

pub mod audit;
pub mod generator;
pub mod matching;
pub mod mock;
pub mod model;
pub mod search;
pub mod secret;
pub mod totp;
pub mod vault;

pub use model::{Field, FieldKind, Item, ItemKind};
pub use search::{Filter, Hit, Sort};
pub use secret::SecretString;
pub use vault::{Counts, Vault};
