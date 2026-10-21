//! `WebAuthn` PRF extension for the system provider (iOS 18,
//! macOS 15): `ASPasskeyAssertionCredentialExtensionInput.prf` and its
//! registration counterpart. The computation is `verrou_core::passkey_prf`.
//!
//! The system passes the site's **raw** inputs (`saltInput1`,
//! `saltInput2`): Verrou hashes them (`"WebAuthn PRF" ‖ 0 ‖ input`) as a
//! browser would in front of a CTAP2 key, which is also what Chrome's
//! provider does on iPhone (`PRFInput::FromUnhashedInputs`).
//!
//! The outputs are keys: they leave Rust only towards the extension,
//! which hands them straight back to the system.

use verrou_core::passkey_prf;

use crate::{VaultSession, VerrouError};

/// PRF outputs for a passkey (32 bytes each).
#[derive(Clone, uniffi::Record)]
pub struct PasskeyPrfOutput {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

impl std::fmt::Debug for PasskeyPrfOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasskeyPrfOutput { … }")
    }
}

#[uniffi::export]
impl VaultSession {
    /// Evaluates the PRF of passkey `credential_id` of site `rp_id` for the
    /// site's raw inputs. Vault unlocked, protected item confirmed, and
    /// user verified (Face ID, Touch ID or master password).
    /// Nothing is written: the PRF doesn't touch the counter.
    pub fn passkey_prf(
        &self,
        rp_id: String,
        credential_id: Vec<u8>,
        first: Vec<u8>,
        second: Option<Vec<u8>>,
        user_verified: bool,
    ) -> Result<PasskeyPrfOutput, VerrouError> {
        let rp_id =
            verrou_core::passkey::system_rp_id(&rp_id).map_err(|e| VerrouError::Invalid {
                message: e.to_string(),
            })?;
        self.with_vault(|v| {
            let (item, key) = Self::find_passkey(v, &rp_id, &credential_id)?;
            self.require_authorized(item)?;
            let out = passkey_prf::evaluate_inputs(key, &first, second.as_deref(), user_verified)
                .map_err(|e| VerrouError::Invalid {
                message: e.to_string(),
            })?;
            Ok(PasskeyPrfOutput {
                first: out.first.to_vec(),
                second: out.second.map(|s| s.to_vec()),
            })
        })
    }
}
