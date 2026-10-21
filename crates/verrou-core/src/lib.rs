//! Verrou's core, shared by the Apple app (through `verrou-ffi`) and the CLI.
//!
//! This crate does no I/O: it receives items that are already
//! decrypted, indexes them and searches them. Decryption and syncing
//! with Vaultwarden live in `verrou-vaultwarden`, built on Bitwarden's
//! Rust SDK.

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
pub mod passkey_prf;
pub mod passkey_upgrade;
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
