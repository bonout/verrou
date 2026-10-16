import Foundation

/// Extension PRF de WebAuthn demandée par le site, telle que le système la
/// transmet au fournisseur (iOS 18, macOS 15) : des entrées **brutes**, que
/// le cœur Rust hache puis évalue (`VaultSession.passkeyPrf`, voir
/// `crates/verrou-core/src/passkey_prf.rs`).
///
/// Sans dépendance au système : la sélection des entrées est testée seule
/// (`VerrouMacTests`).
struct PrfInputs: Equatable {
    let first: Data
    let second: Data?
}

/// Connexion : `eval`, et `evalByCredential` (identifiant brut → entrées),
/// prioritaire pour la passkey choisie.
struct PasskeyPrfAssertion: Equatable {
    let eval: PrfInputs?
    let perCredential: [Data: PrfInputs]

    /// Les entrées pour cette passkey, ou `nil` : pas de PRF pour elle.
    func inputs(for credentialID: Data) -> PrfInputs? {
        perCredential[credentialID] ?? eval
    }

    var isEmpty: Bool { eval == nil && perCredential.isEmpty }
}

/// Création : le site demande si la PRF est possible (`checkForSupport`),
/// et peut déjà donner des entrées (`eval`).
struct PasskeyPrfRegistration: Equatable {
    let eval: PrfInputs?
}
