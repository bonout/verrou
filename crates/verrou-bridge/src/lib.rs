//! Pont entre Verrou et l'extension de navigateur.
//!
//! ```text
//! extension ──Native Messaging──▶ verrou-native-host ──TCP 127.0.0.1──▶ Verrou (Bridge)
//! ```
//!
//! - L'hôte (`verrou-native-host`) est lancé par le navigateur ; il relaie les
//!   octets sans les lire, et ouvre Verrou s'il ne tourne pas.
//! - Le canal est chiffré de bout en bout entre l'extension et Verrou
//!   ([`crypto`]) ; l'hôte et quiconque écoute le port ne voient que des
//!   messages chiffrés.
//! - Ce que l'extension peut obtenir est borné par [`access`] : les
//!   identifiants de la page en cours, en HTTPS.

pub mod access;
mod clients;
pub mod crypto;
pub mod protocol;
mod server;

pub use clients::ClientInfo;
pub use server::{Backend, Bridge, PairingRequest};

/// Port d'écoute de Verrou. `VERROU_BRIDGE_PORT` le remplace (tests).
pub const DEFAULT_PORT: u16 = 41_738;

/// Nom de l'hôte Native Messaging, déclaré au navigateur.
pub const HOST_NAME: &str = "app.verrou.bridge";

/// Le port à utiliser, compte tenu de `VERROU_BRIDGE_PORT`.
pub fn port_from_env() -> u16 {
    std::env::var("VERROU_BRIDGE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}
