//! Cœur de Verrou, partagé par l'application Apple (via `verrou-ffi`) et la CLI.
//!
//! Ce crate ne fait aucune entrée-sortie : il reçoit des éléments déjà
//! déchiffrés, les indexe et y cherche. Le déchiffrement et la synchronisation
//! avec Vaultwarden sont dans `verrou-vaultwarden`, construit sur le SDK Rust
//! de Bitwarden.

pub mod apps;
pub mod audit;
pub mod change_password;
pub mod duplicates;
pub mod generator;
pub mod import;
pub mod matching;
pub mod mock;
pub mod model;
pub mod otp_scan;
pub mod passkey;
pub mod passphrase;
pub mod search;
pub mod secret;
pub mod selection;
pub mod template;
pub mod totp;
pub mod usage;
pub mod vault;
pub mod watchtower;

pub use matching::{MatchRules, UriMatch};
pub use model::{Field, FieldKind, Item, ItemKind, ItemState, Sharing};
pub use passkey::Passkey;
pub use search::{Filter, Hit, Sort};
pub use secret::SecretString;
pub use template::Template;
pub use vault::{Counts, Vault};
