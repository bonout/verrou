//! Messages échangés avec les clients du pont (extension, terminal).
//!
//! En clair, l'enveloppe : demande d'appairage, ou requête chiffrée d'un
//! client appairé. Chiffrés, la commande et sa réponse.

use serde::{Deserialize, Serialize};
use verrou_core::{FieldKind, ItemKind};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Taille maximale d'un message (Native Messaging limite à 1 Mio ce que
/// l'hôte renvoie au navigateur).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Écart toléré entre l'horodatage d'une requête et l'horloge de Verrou.
pub const MAX_CLOCK_SKEW_MS: i64 = 120_000;

/// Nature d'un client : elle fixe les commandes qu'il peut envoyer
/// ([`crate::access::allowed`]).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// L'extension de navigateur : les identifiants de la page en cours.
    #[default]
    Browser,
    /// Le terminal (`verrou`) : recherche, secrets après confirmation, agent SSH.
    Cli,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Incoming {
    /// `key` : clé publique P-256 du client (SEC1, base64). `kind` absent :
    /// l'extension, qui ne l'envoie pas.
    Pair {
        name: String,
        key: String,
        #[serde(default)]
        kind: ClientKind,
    },
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    /// Identifiant saisi sur la page `url` : déjà dans le coffre, nouveau,
    /// ou nouveau mot de passe d'un élément ? `current` : l'ancien mot de
    /// passe d'un formulaire de changement.
    Check {
        url: String,
        username: String,
        password: String,
        #[serde(default)]
        current: Option<String>,
    },
    /// Enregistre l'identifiant de la page : `item` absent, un nouvel
    /// élément ; sinon le nouveau mot de passe de cet élément.
    Save {
        url: String,
        username: String,
        password: String,
        #[serde(default)]
        item: Option<String>,
    },
    /// Ajoute la graine TOTP (ou l'URI `otpauth://` d'un QR code) à
    /// l'élément `item` de la page, ou à un nouvel élément.
    SetTotp {
        url: String,
        totp: String,
        #[serde(default)]
        item: Option<String>,
    },
    /// Terminal : éléments qui répondent à `query`, sans secret.
    VaultSearch {
        query: String,
        #[serde(default)]
        kind: Option<ItemKind>,
        #[serde(default)]
        favorites: bool,
        #[serde(default)]
        limit: Option<u32>,
    },
    /// Terminal : un élément (identifiant, sinon meilleur résultat de
    /// recherche), sans la valeur de ses champs secrets.
    VaultItem {
        query: String,
    },
    /// Terminal : la valeur d'un champ (`notes` compris) de l'élément `item`.
    /// Un champ secret demande l'accord de l'utilisateur dans Verrou.
    Reveal {
        item: String,
        field: String,
    },
    /// Terminal : le code à usage unique de l'élément `item`, avec accord.
    Totp {
        item: String,
    },
    /// Terminal : oublier ce client (`verrou unlink`).
    Unlink,
    /// Agent SSH : les clés publiques des clés SSH du coffre.
    SshKeys,
    /// Agent SSH : signer `data` (base64) avec la clé dont `public_key` est
    /// la forme binaire SSH (base64). `flags` : ceux de l'agent OpenSSH
    /// (`rsa-sha2-256` = 2, `rsa-sha2-512` = 4). La clé privée ne sort pas
    /// de Verrou : seule la signature revient.
    SshSign {
        public_key: String,
        data: String,
        #[serde(default)]
        flags: u32,
    },
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
    Status {
        unlocked: bool,
    },
    Suggestions {
        items: Vec<Suggestion>,
    },
    Credentials(Credentials),
    Locked,
    Denied {
        reason: String,
    },
    Done,
    Check {
        action: SaveAction,
        /// L'élément concerné, pour `known` et `update`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item: Option<Suggestion>,
    },
    /// Écrit dans le coffre : l'identifiant de l'élément créé ou modifié.
    Saved {
        item: String,
    },
    /// Élément protégé (« redemander le mot de passe principal ») : Verrou
    /// demande confirmation ; l'extension réessaie ensuite.
    Confirm,
    /// Résultats d'une recherche du terminal : les premiers, et leur total.
    Items {
        items: Vec<ItemSummary>,
        total: u32,
    },
    Item {
        item: ItemView,
    },
    /// Valeur d'un champ, révélée avec l'accord de l'utilisateur.
    Secret(SecretValue),
    Code {
        code: String,
        period: u64,
        remaining: u64,
    },
    SshKeys {
        keys: Vec<SshIdentity>,
    },
    /// Signature au format de l'agent SSH (algorithme et signature), base64.
    Signature {
        signature: String,
    },
}

/// Un élément dans une liste du terminal. Aucun secret.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub subtitle: String,
    pub urls: Vec<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_totp: bool,
}

/// Un élément pour `verrou get` : la valeur des champs secrets est absente.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ItemView {
    #[serde(flatten)]
    pub summary: ItemSummary,
    pub fields: Vec<FieldView>,
    pub has_notes: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FieldView {
    pub id: String,
    pub label: String,
    pub kind: FieldKind,
    pub secret: bool,
    /// Absente pour un champ secret : il faut `reveal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    pub value: String,
}

/// Une clé SSH du coffre, vue par l'agent : sa clé publique seulement.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SshIdentity {
    pub item: String,
    pub title: String,
    /// Forme binaire SSH de la clé publique, base64.
    pub public_key: String,
}

/// Refus particulier de [`crate::Backend::credentials`] : l'élément attend une
/// confirmation dans Verrou (renvoyé à l'extension comme [`ReplyResult::Confirm`]).
pub const CONFIRM_IN_APP: &str = "confirmation requise dans Verrou";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SaveAction {
    /// Déjà dans le coffre, à l'identique : rien à proposer.
    Known,
    New,
    Update,
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
