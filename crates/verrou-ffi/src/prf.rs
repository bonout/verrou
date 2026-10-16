//! Extension PRF de `WebAuthn` pour le fournisseur du système (iOS 18,
//! macOS 15) : `ASPasskeyAssertionCredentialExtensionInput.prf` et son
//! pendant de création. Le calcul est celui de `verrou_core::passkey_prf`.
//!
//! Le système transmet les entrées **brutes** du site (`saltInput1`,
//! `saltInput2`) : Verrou les hache (`"WebAuthn PRF" ‖ 0 ‖ entrée`) comme le
//! ferait un navigateur devant une clé CTAP2, ce que fait aussi le
//! fournisseur de Chrome sur iPhone (`PRFInput::FromUnhashedInputs`).
//!
//! Les sorties sont des clés : elles ne sortent de Rust que vers
//! l'extension, qui les rend aussitôt au système.

use verrou_core::passkey_prf;

use crate::{VaultSession, VerrouError};

/// Sorties de la PRF pour une passkey (32 octets chacune).
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
    /// Évalue la PRF de la passkey `credential_id` du site `rp_id` pour les
    /// entrées brutes du site. Coffre ouvert, élément protégé confirmé, et
    /// utilisateur vérifié (Face ID, Touch ID ou mot de passe principal).
    /// Rien n'est écrit : la PRF ne touche pas au compteur.
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
