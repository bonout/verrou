//! Emergency access: entrusting one's vault to a trusted person.
//!
//! The **grantor** invites a contact (read-only, or takeover), with a wait
//! time. Once the invitation is accepted, they **confirm** it: their vault
//! key (the user key) is encrypted for the contact's public key
//! (RSA-OAEP-SHA1, by the SDK) and handed to the server, which can't read
//! it. The contact can then **request** access; the grantor approves or
//! rejects it, otherwise access is granted by itself at the end of the
//! wait time. Read-only, the contact then receives the grantor's items and
//! the key encrypted for them, which they open with their private key.
//!
//! Before confirming, the grantor checks the **fingerprint** of the
//! contact's public key (the 5-word phrase of the Bitwarden apps): without
//! this check, a malicious server could substitute its own key.
//!
//! Takeover (changing the grantor's master password) is not done here: it
//! stays in the web vault.

use std::collections::HashMap;

use bitwarden_api_api::models::{CipherResponseModel, EmergencyAccessViewResponseModel};
use bitwarden_core::key_management::{PrivateKeySlotId, SymmetricKeySlotId};
use bitwarden_crypto::{
    Decryptable, PublicKey, SpkiPublicKeyBytes, UnsignedSharedKey, fingerprint,
};
use bitwarden_vault::{Cipher, CipherView};
use data_encoding::BASE64;
use reqwest::Method;
use serde_json::{Value, json};
use verrou_core::Item;

use crate::{Connection, Error, convert};

/// Longest wait time offered by the Bitwarden apps.
pub const MAX_WAIT_DAYS: u32 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmergencyKind {
    /// Read-only access to the vault.
    View,
    /// Takeover (new master password): web vault.
    Takeover,
}

impl EmergencyKind {
    fn code(self) -> u8 {
        match self {
            Self::View => 0,
            Self::Takeover => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmergencyStatus {
    /// Invitation sent, not accepted yet.
    Invited,
    /// Accepted by the contact: up to the grantor to confirm.
    Accepted,
    /// Confirmed: the contact can request access.
    Confirmed,
    /// Access requested: the wait time is running.
    RecoveryInitiated,
    /// Access granted (approved, or wait time elapsed).
    RecoveryApproved,
}

/// An emergency access, seen from either side.
#[derive(Clone, Debug)]
pub struct EmergencyAccess {
    pub id: String,
    /// The other person: the contact (seen from the grantor) or the grantor
    /// (seen from the contact). Missing until an invitation is accepted.
    pub user_id: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub kind: EmergencyKind,
    pub status: EmergencyStatus,
    pub wait_time_days: u32,
}

impl EmergencyAccess {
    fn parse(value: &Value, user_key: &str) -> Option<Self> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let number = |key: &str| value.get(key).and_then(Value::as_u64);
        Some(Self {
            id: text("id")?,
            user_id: text(user_key),
            name: text("name"),
            email: text("email"),
            kind: match number("type")? {
                0 => EmergencyKind::View,
                1 => EmergencyKind::Takeover,
                _ => return None,
            },
            status: match number("status")? {
                0 => EmergencyStatus::Invited,
                1 => EmergencyStatus::Accepted,
                2 => EmergencyStatus::Confirmed,
                3 => EmergencyStatus::RecoveryInitiated,
                4 => EmergencyStatus::RecoveryApproved,
                _ => return None,
            },
            wait_time_days: number("waitTimeDays").unwrap_or(0) as u32,
        })
    }
}

/// The two lists: my trusted contacts, and those who chose me.
#[derive(Clone, Debug, Default)]
pub struct EmergencyOverview {
    /// Contacts I entrusted my vault to (I am the grantor).
    pub trusted: Vec<EmergencyAccess>,
    /// People who entrusted theirs to me (I am their contact).
    pub granted: Vec<EmergencyAccess>,
}

/// A grantor's vault, opened read-only.
pub struct GrantorVault {
    pub items: Vec<Item>,
    /// Items that don't decrypt with the grantor's key.
    pub failures: usize,
}

fn list(body: &Value, user_key: &str) -> Vec<EmergencyAccess> {
    body.get("data")
        .and_then(Value::as_array)
        .map(|data| {
            data.iter()
                .filter_map(|v| EmergencyAccess::parse(v, user_key))
                .collect()
        })
        .unwrap_or_default()
}

/// Fingerprint of a public key (DER, SPKI) for a user: the phrase the
/// Bitwarden apps show to verify a key.
pub fn key_fingerprint(user_id: &str, public_key_der: &[u8]) -> Result<String, Error> {
    fingerprint(user_id, &SpkiPublicKeyBytes::from(public_key_der)).map_err(Error::crypto)
}

impl Connection {
    /// Emergency contacts and grantors, from the server.
    pub async fn emergency_access(&mut self) -> Result<EmergencyOverview, Error> {
        let access = self.access_token().await?;
        let trusted = self
            .api
            .call(Method::GET, &access, "emergency-access/trusted", None)
            .await?;
        let granted = self
            .api
            .call(Method::GET, &access, "emergency-access/granted", None)
            .await?;
        Ok(EmergencyOverview {
            trusted: list(&trusted, "granteeId"),
            granted: list(&granted, "grantorId"),
        })
    }

    /// Invites an emergency contact. Without a mail server, Vaultwarden
    /// accepts an existing account's invitation at once: all that is left is
    /// to confirm it.
    pub async fn invite_emergency_contact(
        &mut self,
        email: &str,
        kind: EmergencyKind,
        wait_time_days: u32,
    ) -> Result<(), Error> {
        let email = email.trim();
        if !email.contains('@') {
            return Err(Error::Invalid("invalid email address".to_owned()));
        }
        if email.eq_ignore_ascii_case(&self.account.email) {
            return Err(Error::Invalid(
                "you cannot be your own emergency contact".to_owned(),
            ));
        }
        check_wait(wait_time_days)?;
        let body = json!({
            "email": email,
            "type": kind.code(),
            "waitTimeDays": wait_time_days,
        });
        let access = self.access_token().await?;
        self.api
            .call(
                Method::POST,
                &access,
                "emergency-access/invite",
                Some(&body),
            )
            .await
            .map(drop)
    }

    /// Changes a contact's access type or wait time.
    pub async fn update_emergency_contact(
        &mut self,
        id: &str,
        kind: EmergencyKind,
        wait_time_days: u32,
    ) -> Result<(), Error> {
        check_wait(wait_time_days)?;
        let body = json!({ "type": kind.code(), "waitTimeDays": wait_time_days });
        self.emergency_call(Method::PUT, &format!("emergency-access/{id}"), Some(&body))
            .await
    }

    /// Fingerprint of a contact's public key, to compare with theirs
    /// (Settings → My account, in the Bitwarden apps) before confirming.
    pub async fn emergency_contact_fingerprint(
        &mut self,
        grantee_id: &str,
    ) -> Result<String, Error> {
        let der = self.public_key(grantee_id).await?;
        key_fingerprint(grantee_id, &der)
    }

    /// Confirms a contact who accepted the invitation: the vault key is
    /// encrypted for their public key. `fingerprint` is the fingerprint the
    /// user checked: if the server's key no longer matches it, nothing is
    /// sent.
    pub async fn confirm_emergency_contact(
        &mut self,
        id: &str,
        grantee_id: &str,
        fingerprint: &str,
    ) -> Result<(), Error> {
        let der = self.public_key(grantee_id).await?;
        if key_fingerprint(grantee_id, &der)? != fingerprint {
            return Err(Error::Crypto(
                "the contact's key has changed since it was verified".to_owned(),
            ));
        }
        let public_key =
            PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).map_err(Error::crypto)?;
        let key_store = self.sdk.internal.get_key_store();
        let wrapped = UnsignedSharedKey::encapsulate(
            SymmetricKeySlotId::User,
            &public_key,
            &key_store.context(),
        )
        .map_err(Error::crypto)?;
        let body = json!({ "key": wrapped.to_string() });
        self.emergency_call(
            Method::POST,
            &format!("emergency-access/{id}/confirm"),
            Some(&body),
        )
        .await
    }

    /// Removes a contact (grantor) or gives up an access (contact).
    pub async fn delete_emergency_access(&mut self, id: &str) -> Result<(), Error> {
        self.emergency_call(Method::DELETE, &format!("emergency-access/{id}"), None)
            .await
    }

    /// Contact: requests access to the grantor's vault. The wait time starts.
    pub async fn request_emergency_access(&mut self, id: &str) -> Result<(), Error> {
        self.emergency_call(
            Method::POST,
            &format!("emergency-access/{id}/initiate"),
            None,
        )
        .await
    }

    /// Grantor: grants the requested access without waiting for the end of the wait time.
    pub async fn approve_emergency_access(&mut self, id: &str) -> Result<(), Error> {
        self.emergency_call(
            Method::POST,
            &format!("emergency-access/{id}/approve"),
            None,
        )
        .await
    }

    /// Grantor: rejects (or withdraws) the requested access.
    pub async fn reject_emergency_access(&mut self, id: &str) -> Result<(), Error> {
        self.emergency_call(Method::POST, &format!("emergency-access/{id}/reject"), None)
            .await
    }

    /// Contact, read-only access granted: the grantor's items, decrypted with
    /// their key, itself opened by my private key.
    pub async fn open_grantor_vault(&mut self, id: &str) -> Result<GrantorVault, Error> {
        let access = self.access_token().await?;
        let body = self
            .api
            .call(
                Method::POST,
                &access,
                &format!("emergency-access/{id}/view"),
                None,
            )
            .await?;
        let response: EmergencyAccessViewResponseModel = serde_json::from_value(body)
            .map_err(|e| Error::Server(format!("unreadable vault ({e})")))?;
        let wrapped: UnsignedSharedKey = response
            .key_encrypted
            .ok_or_else(|| Error::Server("grantor key missing".to_owned()))?
            .parse()
            .map_err(Error::crypto)?;
        self.decrypt_grantor_ciphers(&wrapped, response.ciphers.unwrap_or_default())
    }

    fn decrypt_grantor_ciphers(
        &self,
        wrapped: &UnsignedSharedKey,
        ciphers: Vec<CipherResponseModel>,
    ) -> Result<GrantorVault, Error> {
        let key_store = self.sdk.internal.get_key_store();
        let mut ctx = key_store.context();
        let grantor_key = wrapped
            .decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)
            .map_err(|_| Error::Crypto("the grantor's key does not open with yours".to_owned()))?;
        let no_folders = HashMap::new();
        let mut items = Vec::new();
        let mut failures = 0;
        for model in ciphers {
            let view: Option<CipherView> = Cipher::try_from(model)
                .ok()
                .and_then(|cipher| cipher.decrypt(&mut ctx, grantor_key).ok());
            match view.and_then(|v| convert::item(&v, &no_folders)) {
                // The grantor lends their active items: the trash stays with them.
                Some(item)
                    if item.is_active() || item.state == verrou_core::ItemState::Archived =>
                {
                    items.push(item);
                }
                Some(_) => {}
                None => failures += 1,
            }
        }
        items.sort_by_key(|i| i.title.to_lowercase());
        Ok(GrantorVault { items, failures })
    }

    pub(crate) async fn public_key(&mut self, user_id: &str) -> Result<Vec<u8>, Error> {
        let access = self.access_token().await?;
        let body = self
            .api
            .call(
                Method::GET,
                &access,
                &format!("users/{user_id}/public-key"),
                None,
            )
            .await?;
        let key = body
            .get("publicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("public key missing".to_owned()))?;
        BASE64
            .decode(key.as_bytes())
            .map_err(|_| Error::Server("unreadable public key".to_owned()))
    }

    async fn emergency_call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(), Error> {
        let access = self.access_token().await?;
        self.api.call(method, &access, path, body).await.map(drop)
    }
}

fn check_wait(days: u32) -> Result<(), Error> {
    if (1..=MAX_WAIT_DAYS).contains(&days) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "the wait time ranges from 1 to {MAX_WAIT_DAYS} days"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_parsed_from_both_sides() {
        let trusted = json!({ "data": [
            { "id": "a", "granteeId": "u1", "email": "antonin@exemple.fr", "name": "Antonin",
              "type": 0, "status": 1, "waitTimeDays": 7 },
            { "id": "b", "granteeId": null, "email": "lea@exemple.fr", "name": null,
              "type": 1, "status": 0, "waitTimeDays": 2 },
            { "id": "c", "type": 9, "status": 0 },
        ]});
        let parsed = list(&trusted, "granteeId");
        assert_eq!(parsed.len(), 2, "unknown type ignored");
        assert_eq!(parsed[0].user_id.as_deref(), Some("u1"));
        assert_eq!(parsed[0].status, EmergencyStatus::Accepted);
        assert_eq!(parsed[0].kind, EmergencyKind::View);
        assert_eq!(parsed[1].user_id, None);
        assert_eq!(parsed[1].kind, EmergencyKind::Takeover);
        assert_eq!(parsed[1].wait_time_days, 2);

        let granted = json!({ "data": [
            { "id": "d", "grantorId": "u2", "email": "camille@exemple.fr",
              "type": 0, "status": 4, "waitTimeDays": 1 },
        ]});
        let parsed = list(&granted, "grantorId");
        assert_eq!(parsed[0].user_id.as_deref(), Some("u2"));
        assert_eq!(parsed[0].status, EmergencyStatus::RecoveryApproved);
    }

    #[test]
    fn wait_time_is_bounded() {
        assert!(check_wait(0).is_err());
        assert!(check_wait(1).is_ok());
        assert!(check_wait(MAX_WAIT_DAYS).is_ok());
        assert!(check_wait(MAX_WAIT_DAYS + 1).is_err());
    }

    /// Vector from Bitwarden's SDK (`bitwarden-crypto`, `fingerprint.rs`): a
    /// public key, an id, the expected phrase.
    #[test]
    fn fingerprint_matches_the_bitwarden_vector() {
        let user_id = "a09726a0-9590-49d1-a5f5-afe300b6a515";
        let der: &[u8] = &[
            48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15,
            0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 187, 38, 44, 241, 110, 205, 89, 253, 25, 191, 126,
            84, 121, 202, 61, 223, 189, 244, 118, 212, 74, 139, 130, 97, 115, 164, 167, 106, 191,
            188, 233, 218, 196, 250, 187, 146, 125, 160, 150, 49, 198, 224, 176, 10, 0, 143, 99,
            230, 232, 160, 51, 104, 154, 211, 33, 80, 170, 4, 68, 80, 219, 115, 167, 114, 156, 227,
            125, 193, 128, 123, 39, 254, 191, 124, 63, 129, 44, 63, 18, 56, 161, 48, 158, 0, 27,
            146, 2, 99, 136, 75, 21, 135, 6, 118, 12, 26, 251, 184, 172, 249, 53, 78, 210, 46, 143,
            17, 104, 202, 65, 173, 229, 219, 233, 144, 163, 101, 216, 238, 152, 54, 158, 1, 195,
            50, 203, 21, 226, 12, 82, 170, 175, 170, 160, 21, 247, 248, 80, 97, 123, 0, 152, 116,
            229, 126, 221, 199, 155, 194, 192, 51, 207, 177, 240, 160, 84, 241, 41, 88, 176, 53,
            111, 28, 173, 177, 232, 158, 22, 79, 133, 152, 31, 32, 12, 196, 147, 58, 57, 50, 252,
            208, 131, 150, 179, 132, 178, 150, 234, 251, 143, 125, 163, 144, 20, 46, 71, 168, 252,
            164, 86, 120, 124, 56, 252, 206, 210, 236, 212, 139, 127, 189, 236, 40, 46, 2, 238, 13,
            216, 40, 48, 85, 133, 229, 181, 155, 176, 217, 241, 154, 153, 213, 112, 222, 72, 219,
            197, 3, 219, 56, 77, 109, 47, 72, 251, 131, 36, 240, 96, 169, 31, 82, 93, 166, 242, 3,
            33, 213, 2, 3, 1, 0, 1,
        ];
        assert_eq!(
            key_fingerprint(user_id, der).unwrap(),
            "turban-deftly-anime-chatroom-unselfish"
        );
    }
}
