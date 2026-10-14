//! Création d'un compte depuis Verrou, pour une personne invitée sur un
//! serveur aux inscriptions fermées (`SIGNUPS_ALLOWED=false`).
//!
//! Le SDK fait toute la cryptographie, comme dans le coffre web : clé
//! principale dérivée du mot de passe (PBKDF2-SHA256 ou Argon2id), clé de
//! l'utilisateur tirée au hasard et chiffrée par la clé principale, paire de
//! clés RSA dont la clé privée est chiffrée par la clé de l'utilisateur.
//! Le serveur ne reçoit que l'empreinte d'authentification, jamais le mot de
//! passe.
//!
//! Ce que Vaultwarden 1.37.4 accepte (`/identity/accounts/register/finish`,
//! la seule route d'inscription) :
//! - **lien d'invitation** d'une organisation (serveur avec courriel) :
//!   `orgInviteToken` + `organizationUserId`, le jeton signé par le serveur
//!   tiré du lien `…/#/accept-organization/?…&token=…` ; l'adresse est alors
//!   vérifiée. L'invitation reste à accepter une fois connecté
//!   (`Connection::accept_invitation`) ;
//! - **jeton de vérification** : `register/send-verification-email` le rend
//!   directement quand le serveur n'envoie pas de courriel de vérification
//!   (inscriptions ouvertes, ou serveur sans courriel et adresse invitée ;
//!   l'invitation est alors acceptée d'office), sinon il l'envoie par
//!   courriel (lien `…/#/finish-signup/?…&token=…`, à coller dans Verrou).

use std::num::NonZeroU32;

use bitwarden_crypto::{HashPurpose, Kdf, MasterKey};
use reqwest::header::ACCEPT;
use serde_json::{Value, json};
use verrou_core::SecretString;

use crate::api::{Api, error_message};
use crate::{Connection, Error};

/// Longueur minimale du mot de passe principal (celle des apps Bitwarden).
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Itérations PBKDF2-SHA256 d'un nouveau compte (défaut des apps Bitwarden).
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Réglages Argon2id d'un nouveau compte (défauts des apps Bitwarden).
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_MEMORY_MIB: u32 = 64;
pub const ARGON2_PARALLELISM: u32 = 4;

/// Identifiant de membre des invitations du panneau d'administration.
const ADMIN_INVITE: &str = "00000000-0000-0000-0000-000000000000";

/// Dérivation du mot de passe principal d'un nouveau compte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewAccountKdf {
    Pbkdf2,
    Argon2id,
}

impl NewAccountKdf {
    pub fn kdf(self) -> Kdf {
        let n = |value: u32| NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN);
        match self {
            Self::Pbkdf2 => Kdf::PBKDF2 {
                iterations: n(PBKDF2_ITERATIONS),
            },
            Self::Argon2id => Kdf::Argon2id {
                iterations: n(ARGON2_ITERATIONS),
                memory: n(ARGON2_MEMORY_MIB),
                parallelism: n(ARGON2_PARALLELISM),
            },
        }
    }
}

/// Invitation à une organisation, lue dans le lien reçu par courriel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteLink {
    /// Adresse du serveur (`DOMAIN` de Vaultwarden).
    pub server: String,
    pub email: String,
    pub organization_id: String,
    pub organization_user_id: String,
    pub organization_name: Option<String>,
    /// Jeton signé par le serveur.
    pub token: String,
}

impl InviteLink {
    /// Invitation du panneau d'administration du serveur (pas d'une
    /// organisation) : rien à accepter ensuite.
    pub fn is_server_invite(&self) -> bool {
        self.organization_user_id == ADMIN_INVITE
    }
}

/// Un lien reçu par courriel qui permet de créer son compte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignupLink {
    /// « Rejoindre l'organisation » (`#/accept-organization/`).
    Invite(InviteLink),
    /// « Vérifier l'adresse » (`#/finish-signup/`).
    Verification {
        server: String,
        email: String,
        token: String,
    },
}

impl SignupLink {
    pub fn server(&self) -> &str {
        match self {
            Self::Invite(invite) => &invite.server,
            Self::Verification { server, .. } => server,
        }
    }

    pub fn email(&self) -> &str {
        match self {
            Self::Invite(invite) => &invite.email,
            Self::Verification { email, .. } => email,
        }
    }
}

/// Lit un lien d'invitation ou de vérification, tel que copié depuis le
/// courriel (espaces, `&amp;` d'une copie du HTML et retours à la ligne
/// tolérés).
pub fn parse_link(text: &str) -> Result<SignupLink, Error> {
    let cleaned: String = text
        .trim()
        .trim_matches(|c| c == '<' || c == '>' || c == '"')
        .replace("&amp;", "&")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let invalid = || {
        Error::Invalid(
            "lien non reconnu : collez le lien « Rejoindre » du courriel d'invitation".to_owned(),
        )
    };
    let (server, route) = cleaned.split_once("/#/").ok_or_else(invalid)?;
    let (page, query) = route.split_once('?').ok_or_else(invalid)?;
    let base = reqwest::Url::parse(server).map_err(|_| invalid())?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err(invalid());
    }
    let server = base.as_str().trim_end_matches('/').to_owned();
    let parsed = reqwest::Url::parse(&format!("http://lien/?{query}")).map_err(|_| invalid())?;
    let param = |key: &str| {
        parsed
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let required = |key: &str| param(key).ok_or_else(invalid);
    match page.trim_end_matches('/') {
        "accept-organization" => Ok(SignupLink::Invite(InviteLink {
            server,
            email: required("email")?.to_lowercase(),
            organization_id: required("organizationId")?,
            organization_user_id: required("organizationUserId")?,
            organization_name: param("organizationName"),
            token: required("token")?,
        })),
        "finish-signup" => Ok(SignupLink::Verification {
            server,
            email: required("email")?.to_lowercase(),
            token: required("token")?,
        }),
        _ => Err(invalid()),
    }
}

/// Ce que l'utilisateur a saisi pour créer son compte.
pub struct NewAccount {
    pub server: String,
    pub email: String,
    /// Nom affiché aux autres membres.
    pub name: Option<String>,
    pub password: SecretString,
    /// Indice du mot de passe (en clair sur le serveur).
    pub hint: Option<String>,
    pub kdf: NewAccountKdf,
    pub link: Option<SignupLink>,
}

impl NewAccount {
    /// L'adresse comme les clients Bitwarden la salent : sans espaces, en
    /// minuscules.
    fn salt(&self) -> String {
        self.email.trim().to_lowercase()
    }

    fn check(&self) -> Result<(), Error> {
        let email = self.salt();
        if !email.contains('@') {
            return Err(Error::Invalid("adresse e-mail invalide".to_owned()));
        }
        if self.password.expose().chars().count() < MIN_PASSWORD_LENGTH {
            return Err(Error::Invalid(format!(
                "le mot de passe principal doit faire au moins {MIN_PASSWORD_LENGTH} caractères"
            )));
        }
        if self
            .hint
            .as_deref()
            .is_some_and(|hint| hint.trim() == self.password.expose())
        {
            return Err(Error::Invalid(
                "l'indice ne doit pas être le mot de passe".to_owned(),
            ));
        }
        if let Some(link) = &self.link
            && link.email() != email
        {
            return Err(Error::Invalid(format!(
                "ce lien est destiné à {} : utilisez cette adresse",
                link.email()
            )));
        }
        Ok(())
    }
}

/// Le corps de `register/finish`, sans le jeton (clés déjà chiffrées par le
/// SDK). Le mot de passe ne sort pas de cette fonction.
fn finish_body(account: &NewAccount) -> Result<Value, Error> {
    let email = account.salt();
    let kdf = account.kdf.kdf();
    let master_key =
        MasterKey::derive(account.password.expose(), &email, &kdf).map_err(Error::crypto)?;
    let hash = master_key.derive_master_key_hash(
        account.password.expose().as_bytes(),
        HashPurpose::ServerAuthorization,
    );
    let (user_key, wrapped_user_key) = master_key.make_user_key().map_err(Error::crypto)?;
    let keys = user_key.make_key_pair().map_err(Error::crypto)?;
    let (kind, iterations, memory, parallelism) = match kdf {
        Kdf::PBKDF2 { iterations } => (0, iterations.get(), None, None),
        Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => (
            1,
            iterations.get(),
            Some(memory.get()),
            Some(parallelism.get()),
        ),
    };
    let hint = account
        .hint
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty());
    Ok(json!({
        "email": email,
        "name": account.name.as_deref().map(str::trim).filter(|n| !n.is_empty()),
        "masterPasswordHash": hash.to_string(),
        "masterPasswordHint": hint,
        "userSymmetricKey": wrapped_user_key.to_string(),
        "userAsymmetricKeys": {
            "publicKey": keys.public.to_string(),
            "encryptedPrivateKey": keys.private.to_string(),
        },
        "kdf": kind,
        "kdfIterations": iterations,
        "kdfMemory": memory,
        "kdfParallelism": parallelism,
    }))
}

/// Crée le compte sur le serveur. Il reste ensuite à se connecter (et à
/// accepter l'invitation d'une organisation, s'il y en a une).
pub async fn register(account: &NewAccount) -> Result<(), Error> {
    account.check()?;
    let api = Api::new(&account.server)?;
    let mut body = finish_body(account)?;
    match &account.link {
        Some(SignupLink::Invite(invite)) => {
            body["orgInviteToken"] = json!(invite.token);
            body["organizationUserId"] = json!(invite.organization_user_id);
        }
        Some(SignupLink::Verification { token, .. }) => {
            body["emailVerificationToken"] = json!(token);
        }
        None => {
            body["emailVerificationToken"] =
                json!(verification_token(&api, &account.salt(), account.name.as_deref()).await?);
        }
    }
    let response = api
        .http
        .post(format!("{}/identity/accounts/register/finish", api.base))
        .json(&body)
        .send()
        .await?;
    if response.status().is_success() {
        return Ok(());
    }
    let body: Value = response.json().await.unwrap_or(Value::Null);
    Err(registration_error(&body))
}

/// Jeton de vérification de l'adresse, quand le serveur le donne sans
/// courriel. S'il l'envoie par courriel, il faut coller le lien reçu.
async fn verification_token(api: &Api, email: &str, name: Option<&str>) -> Result<String, Error> {
    let response = api
        .http
        .post(format!(
            "{}/identity/accounts/register/send-verification-email",
            api.base
        ))
        .header(ACCEPT, "application/json")
        .json(&json!({ "email": email, "name": name }))
        .send()
        .await?;
    let status = response.status();
    if status == reqwest::StatusCode::NO_CONTENT {
        return Err(Error::Invalid(
            "le serveur vous a envoyé un courriel de vérification : collez ici le lien qu'il \
             contient"
                .to_owned(),
        ));
    }
    let text = response.text().await?;
    if !status.is_success() {
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        return Err(registration_error(&body));
    }
    // JSON (une chaîne) si on le demande, texte brut sinon.
    let token = serde_json::from_str::<String>(&text).unwrap_or(text);
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(Error::Server("jeton de vérification absent".to_owned()));
    }
    Ok(token)
}

fn registration_error(body: &Value) -> Error {
    let message = error_message(body);
    if message.contains("Registration not allowed") {
        Error::Invalid(
            "ce serveur n'accepte pas d'inscription pour cette adresse : collez le lien \
             d'invitation reçu par e-mail (ou le compte existe déjà : connectez-vous)"
                .to_owned(),
        )
    } else if message.contains("does not match") {
        Error::Invalid("ce lien ne correspond pas à cette adresse e-mail".to_owned())
    } else if message.contains("ExpiredSignature") || message.contains("Invalid claim") {
        Error::Invalid(
            "lien expiré ou invalide : demandez qu'on vous renvoie l'invitation".to_owned(),
        )
    } else {
        Error::Server(message)
    }
}

/// Robustesse d'un mot de passe principal (0 à 4, zxcvbn par le SDK, comme
/// les apps Bitwarden), en tenant compte de l'adresse et du nom.
pub fn password_strength(password: &str, email: &str, name: Option<&str>) -> u8 {
    let mut inputs: Vec<String> = Vec::new();
    if let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) {
        inputs.push(name.to_owned());
    }
    bitwarden_core::Client::new(None).auth().password_strength(
        password.to_owned(),
        email.trim().to_lowercase(),
        inputs,
    )
}

impl Connection {
    /// Accepte l'invitation d'une organisation (lien reçu par courriel),
    /// une fois connecté avec le compte invité. Il faudra ensuite qu'un
    /// administrateur confirme le membre.
    pub async fn accept_invitation(&mut self, invite: &InviteLink) -> Result<(), Error> {
        if !invite.email.eq_ignore_ascii_case(&self.account.email) {
            return Err(Error::Invalid(format!(
                "cette invitation est destinée à {}",
                invite.email
            )));
        }
        if invite.is_server_invite() {
            return Ok(());
        }
        let access = self.access_token().await?;
        self.api
            .call(
                reqwest::Method::POST,
                &access,
                &format!(
                    "organizations/{}/users/{}/accept",
                    invite.organization_id, invite.organization_user_id
                ),
                Some(&json!({ "token": invite.token })),
            )
            .await
            .map(drop)
            .map_err(|error| match error {
                Error::Server(message) if message.contains("Reset password key") => Error::Invalid(
                    "cette organisation exige l'inscription à la récupération du compte : \
                         acceptez l'invitation depuis le coffre web"
                        .to_owned(),
                ),
                other => other,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = "http://localhost:8120/#/accept-organization/?email=lea%40exemple.fr\
        &organizationName=Famille%20Martin&organizationId=7c1e2f3a-0000-4000-8000-000000000001\
        &organizationUserId=7c1e2f3a-0000-4000-8000-000000000002&token=eyJ0eXAi.eyJuYmYi.sig\
        &initOrganization=false&orgUserHasExistingUser=false";

    #[test]
    fn invite_links_are_parsed() {
        let SignupLink::Invite(invite) = parse_link(INVITE).unwrap() else {
            panic!("invitation attendue");
        };
        assert_eq!(invite.server, "http://localhost:8120");
        assert_eq!(invite.email, "lea@exemple.fr");
        assert_eq!(invite.organization_name.as_deref(), Some("Famille Martin"));
        assert_eq!(
            invite.organization_user_id,
            "7c1e2f3a-0000-4000-8000-000000000002"
        );
        assert_eq!(invite.token, "eyJ0eXAi.eyJuYmYi.sig");
        assert!(!invite.is_server_invite());

        // Copié depuis le HTML du courriel, coupé en deux lignes.
        let pasted = format!(
            "  <{}>\n",
            INVITE.replace('&', "&amp;").replacen("token", "to\nken", 1)
        );
        assert_eq!(parse_link(&pasted).unwrap(), SignupLink::Invite(invite));
    }

    #[test]
    fn verification_links_are_parsed() {
        let link = parse_link(
            "https://vault.exemple.fr/sub/#/finish-signup/?email=Tom%40Exemple.fr&token=abc",
        )
        .unwrap();
        assert_eq!(
            link,
            SignupLink::Verification {
                server: "https://vault.exemple.fr/sub".into(),
                email: "tom@exemple.fr".into(),
                token: "abc".into(),
            }
        );
    }

    #[test]
    fn other_links_are_refused() {
        for text in [
            "",
            "https://vault.exemple.fr",
            "https://vault.exemple.fr/#/login",
            "https://vault.exemple.fr/#/accept-organization/?email=a%40b.fr",
            "javascript:alert(1)/#/finish-signup/?email=a%40b.fr&token=x",
        ] {
            assert!(parse_link(text).is_err(), "{text}");
        }
    }

    fn account(password: &str, link: Option<SignupLink>) -> NewAccount {
        NewAccount {
            server: "http://localhost:8120".into(),
            email: " Lea@Exemple.fr ".into(),
            name: Some("Léa".into()),
            password: SecretString::new(password),
            hint: Some("  ".into()),
            kdf: NewAccountKdf::Pbkdf2,
            link,
        }
    }

    #[test]
    fn new_accounts_are_checked() {
        assert!(account("court", None).check().is_err());
        assert!(account("cheval correct pile agrafe", None).check().is_ok());
        let mut same_hint = account("cheval correct pile agrafe", None);
        same_hint.hint = Some("cheval correct pile agrafe".into());
        assert!(same_hint.check().is_err());
        let other = parse_link(&INVITE.replace("lea%40", "tom%40")).unwrap();
        assert!(
            account("cheval correct pile agrafe", Some(other))
                .check()
                .is_err()
        );
        let mine = parse_link(INVITE).unwrap();
        assert!(
            account("cheval correct pile agrafe", Some(mine))
                .check()
                .is_ok()
        );
    }

    #[test]
    fn finish_body_carries_keys_not_the_password() {
        let mut new = account("cheval correct pile agrafe", None);
        new.kdf = NewAccountKdf::Argon2id;
        let body = finish_body(&new).unwrap();
        assert_eq!(body["email"], "lea@exemple.fr");
        assert_eq!(body["kdf"], 1);
        assert_eq!(body["kdfIterations"], ARGON2_ITERATIONS);
        assert_eq!(body["kdfMemory"], ARGON2_MEMORY_MIB);
        assert_eq!(body["kdfParallelism"], ARGON2_PARALLELISM);
        assert_eq!(body["masterPasswordHint"], Value::Null, "indice vide omis");
        assert!(body["userSymmetricKey"].as_str().unwrap().starts_with("2."));
        assert!(
            body["userAsymmetricKeys"]["encryptedPrivateKey"]
                .as_str()
                .unwrap()
                .starts_with("2.")
        );
        assert!(!body.to_string().contains("cheval"));

        // Même empreinte que celle de la connexion (sel = adresse normalisée).
        let auth = bitwarden_core::key_management::MasterPasswordAuthenticationData::derive(
            "cheval correct pile agrafe",
            &NewAccountKdf::Argon2id.kdf(),
            "lea@exemple.fr",
        )
        .unwrap();
        assert_eq!(
            body["masterPasswordHash"].as_str().unwrap(),
            auth.master_password_authentication_hash.to_string()
        );
    }

    #[test]
    fn strength_grows_with_the_password() {
        let weak = password_strength("motdepasse12", "lea@exemple.fr", None);
        let strong = password_strength("fixe-pivoine-monceaux-couteau", "lea@exemple.fr", None);
        assert!(weak < strong, "{weak} < {strong}");
        assert_eq!(strong, 4);
    }
}
