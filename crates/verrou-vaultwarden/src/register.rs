//! Account creation from Verrou, for a person invited to a server with
//! closed signups (`SIGNUPS_ALLOWED=false`).
//!
//! The SDK does all the cryptography, as in the web vault: master key
//! derived from the password (PBKDF2-SHA256 or Argon2id), user key drawn at
//! random and encrypted by the master key, RSA key pair whose private key
//! is encrypted by the user key. The server only receives the
//! authentication hash, never the password.
//!
//! What Vaultwarden 1.37.4 accepts (`/identity/accounts/register/finish`,
//! the only signup route):
//! - an organization's **invitation link** (server with email):
//!   `orgInviteToken` + `organizationUserId`, the server-signed token taken
//!   from the `…/#/accept-organization/?…&token=…` link; the address is then
//!   verified. The invitation still has to be accepted once logged in
//!   (`Connection::accept_invitation`);
//! - **verification token**: `register/send-verification-email` returns it
//!   directly when the server doesn't send a verification email (open
//!   signups, or server without email and invited address; the invitation
//!   is then accepted automatically), otherwise it sends it by email
//!   (`…/#/finish-signup/?…&token=…` link, to paste into Verrou).

use std::num::NonZeroU32;

use bitwarden_crypto::{HashPurpose, Kdf, MasterKey};
use reqwest::header::ACCEPT;
use serde_json::{Value, json};
use verrou_core::SecretString;

use crate::api::{Api, error_message};
use crate::{Connection, Decrypted, Error};

/// Minimum master password length (that of the Bitwarden apps).
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// PBKDF2-SHA256 iterations of a new account (the Bitwarden apps' default).
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Argon2id settings of a new account (the Bitwarden apps' defaults).
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_MEMORY_MIB: u32 = 64;
pub const ARGON2_PARALLELISM: u32 = 4;

/// Member id of the admin panel's invitations.
const ADMIN_INVITE: &str = "00000000-0000-0000-0000-000000000000";

/// Master password derivation of a new account.
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

/// Invitation to an organization, read from the link received by email.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteLink {
    /// Server address (Vaultwarden's `DOMAIN`).
    pub server: String,
    pub email: String,
    pub organization_id: String,
    pub organization_user_id: String,
    pub organization_name: Option<String>,
    /// Token signed by the server.
    pub token: String,
}

impl InviteLink {
    /// Invitation from the server's admin panel (not from an organization):
    /// nothing to accept afterwards.
    pub fn is_server_invite(&self) -> bool {
        self.organization_user_id == ADMIN_INVITE
    }
}

/// A link received by email that lets one create their account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignupLink {
    /// "Join organization" (`#/accept-organization/`).
    Invite(InviteLink),
    /// "Verify address" (`#/finish-signup/`).
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

/// Reads an invitation or verification link, as copied from the email
/// (spaces, `&amp;` from an HTML copy and line breaks tolerated).
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
            "unrecognised link: paste the \"Join\" link from the invitation email".to_owned(),
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

/// What the user typed to create their account.
pub struct NewAccount {
    pub server: String,
    pub email: String,
    /// Name shown to the other members.
    pub name: Option<String>,
    pub password: SecretString,
    /// Password hint (in clear on the server).
    pub hint: Option<String>,
    pub kdf: NewAccountKdf,
    pub link: Option<SignupLink>,
}

impl NewAccount {
    /// The address as Bitwarden clients salt it: without spaces, lower-case.
    fn salt(&self) -> String {
        self.email.trim().to_lowercase()
    }

    fn check(&self) -> Result<(), Error> {
        let email = self.salt();
        if !email.contains('@') {
            return Err(Error::Invalid("invalid email address".to_owned()));
        }
        if self.password.expose().chars().count() < MIN_PASSWORD_LENGTH {
            return Err(Error::Invalid(format!(
                "the master password must be at least {MIN_PASSWORD_LENGTH} characters long"
            )));
        }
        if self
            .hint
            .as_deref()
            .is_some_and(|hint| hint.trim() == self.password.expose())
        {
            return Err(Error::Invalid(
                "the hint must not be the password".to_owned(),
            ));
        }
        if let Some(link) = &self.link
            && link.email() != email
        {
            return Err(Error::Invalid(format!(
                "this link is meant for {}: use this address",
                link.email()
            )));
        }
        Ok(())
    }
}

/// The body of `register/finish`, without the token (keys already encrypted
/// by the SDK). The password doesn't leave this function.
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

/// Creates the account on the server. What remains is to log in (and to
/// accept an organization's invitation, if there is one).
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

/// Address verification token, when the server gives it without email. If
/// it sends it by email, the received link must be pasted.
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
            "the server sent you a verification email: paste the link it contains \
             here"
                .to_owned(),
        ));
    }
    let text = response.text().await?;
    if !status.is_success() {
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        return Err(registration_error(&body));
    }
    // JSON (a string) if asked for, plain text otherwise.
    let token = serde_json::from_str::<String>(&text).unwrap_or(text);
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(Error::Server("verification token missing".to_owned()));
    }
    Ok(token)
}

fn registration_error(body: &Value) -> Error {
    let message = error_message(body);
    if message.contains("Registration not allowed") {
        Error::Invalid(
            "this server does not accept signups for this address: paste the invitation \
             link received by email (or the account already exists: log in)"
                .to_owned(),
        )
    } else if message.contains("does not match") {
        Error::Invalid("this link does not match this email address".to_owned())
    } else if message.contains("ExpiredSignature") || message.contains("Invalid claim") {
        Error::Invalid(
            "expired or invalid link: ask for the invitation to be sent again".to_owned(),
        )
    } else {
        Error::Server(message)
    }
}

/// Strength of a master password (0 to 4, zxcvbn through the SDK, like the
/// Bitwarden apps), taking the address and the name into account.
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
    /// "Join an organization" with an existing account: the pasted
    /// invitation link (it carries the server-signed token) is accepted,
    /// then the vault resynced. Returns the organization's name. An
    /// administrator still has to confirm the member (fingerprint) before
    /// they receive the organization key.
    pub async fn join_organization(&mut self, link: &str) -> Result<(String, Decrypted), Error> {
        let SignupLink::Invite(invite) = parse_link(link)? else {
            return Err(Error::Invalid(
                "this link is not an invitation to an organization".to_owned(),
            ));
        };
        if invite.is_server_invite() {
            return Err(Error::Invalid(
                "this link invites you to create an account on the server, not to join an organization"
                    .to_owned(),
            ));
        }
        let access = self.require_online("Joining an organization").await?;
        self.accept_invitation(&invite).await?;
        let vault = self.sync_with(&access).await?;
        let name = invite
            .organization_name
            .unwrap_or_else(|| "the organization".to_owned());
        Ok((name, vault))
    }

    /// Accepts an organization's invitation (link received by email), once
    /// logged in with the invited account. An administrator will then have
    /// to confirm the member.
    pub async fn accept_invitation(&mut self, invite: &InviteLink) -> Result<(), Error> {
        if !invite.email.eq_ignore_ascii_case(&self.account.email) {
            return Err(Error::Invalid(format!(
                "this invitation is meant for {}",
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
                    "this organization requires enrolment in account recovery: \
                         accept the invitation from the web vault"
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
            panic!("expected an invitation");
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

        // Copied from the email's HTML, split over two lines.
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
        assert_eq!(
            body["masterPasswordHint"],
            Value::Null,
            "empty hint omitted"
        );
        assert!(body["userSymmetricKey"].as_str().unwrap().starts_with("2."));
        assert!(
            body["userAsymmetricKeys"]["encryptedPrivateKey"]
                .as_str()
                .unwrap()
                .starts_with("2.")
        );
        assert!(!body.to_string().contains("cheval"));

        // Same hash as the login's (salt = normalised address).
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
