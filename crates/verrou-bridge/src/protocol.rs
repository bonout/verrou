//! Messages échangés avec l'extension.
//!
//! En clair, l'enveloppe : demande d'appairage, ou requête chiffrée d'un
//! client appairé. Chiffrés, la commande et sa réponse.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Taille maximale d'un message (Native Messaging limite à 1 Mio ce que
/// l'hôte renvoie au navigateur).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Écart toléré entre l'horodatage d'une requête et l'horloge de Verrou.
pub const MAX_CLOCK_SKEW_MS: i64 = 120_000;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Incoming {
    /// `key` : clé publique P-256 de l'extension (SEC1, base64).
    Pair { name: String, key: String },
    Request {
        client: String,
        iv: String,
        data: String,
    },
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outgoing {
    /// Clé publique de Verrou et identifiant attribué : l'extension peut
    /// calculer la clé du canal et afficher le code, en attendant l'accord.
    Pairing {
        client: String,
        key: String,
    },
    Paired,
    Refused,
    Response {
        iv: String,
        data: String,
    },
    Error {
        code: ErrorCode,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Client inconnu ou révoqué : il faut appairer de nouveau.
    UnknownClient,
    /// Message mal formé, illisible ou périmé.
    BadRequest,
    /// Un appairage est déjà en cours, ou trop rapproché du précédent.
    Busy,
}

/// Requête déchiffrée.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    /// Horodatage Unix en millisecondes.
    pub ts: i64,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    Status,
    /// Identifiants proposés pour la page `url`.
    Suggest {
        url: String,
    },
    /// Identifiant, mot de passe et code de l'élément `item`, s'il correspond
    /// à la page `url`.
    Fill {
        url: String,
        item: String,
    },
    /// Amène Verrou au premier plan pour le déverrouiller.
    Unlock,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Reply {
    pub id: u64,
    #[serde(flatten)]
    pub result: ReplyResult,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ReplyResult {
    Status { unlocked: bool },
    Suggestions { items: Vec<Suggestion> },
    Credentials(Credentials),
    Locked,
    Denied { reason: String },
    Done,
}

/// Ce que le menu de l'extension affiche. Aucun secret.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Suggestion {
    pub id: String,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Code à usage unique du moment, s'il y a une graine.
    pub totp: Option<String>,
}
