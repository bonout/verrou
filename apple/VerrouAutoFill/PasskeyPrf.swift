import Foundation

/// WebAuthn PRF extension requested by the site, as the system passes it to
/// the provider (iOS 18, macOS 15): **raw** inputs, which the Rust core
/// hashes then evaluates (`VaultSession.passkeyPrf`, see
/// `crates/verrou-core/src/passkey_prf.rs`).
///
/// No dependency on the system: input selection is tested on its own
/// (`VerrouMacTests`).
struct PrfInputs: Equatable {
    let first: Data
    let second: Data?
}

/// Sign-in: `eval`, and `evalByCredential` (raw ID → inputs), which takes
/// precedence for the chosen passkey.
struct PasskeyPrfAssertion: Equatable {
    let eval: PrfInputs?
    let perCredential: [Data: PrfInputs]

    /// The inputs for this passkey, or `nil`: no PRF for it.
    func inputs(for credentialID: Data) -> PrfInputs? {
        perCredential[credentialID] ?? eval
    }

    var isEmpty: Bool { eval == nil && perCredential.isEmpty }
}

/// Creation: the site asks whether PRF is possible (`checkForSupport`), and
/// may already give inputs (`eval`).
struct PasskeyPrfRegistration: Equatable {
    let eval: PrfInputs?
}
