import Foundation

/// Accès au coffre sans interface : où il vit, comment l'ouvrir (mot de
/// passe principal, Face ID / Touch ID), le refermer, et y chercher les
/// identifiants d'un site.
///
/// Utilisé par l'app iPhone, et pensé pour l'extension de remplissage
/// automatique (`VerrouAutoFill`) : elle tient dans la limite de mémoire des
/// extensions (environ 120 Mo) parce que tout le travail (déchiffrement,
/// recherche, correspondance des sites, codes à usage unique) reste dans le
/// cœur Rust ; Swift ne reçoit que des résumés, et un secret seulement quand
/// on le demande (`reveal`, `totp`).
///
/// Les écritures de la file (synchronisation, modifications hors ligne)
/// restent à l'app. L'extension ouvre le coffre du dossier partagé en
/// invitée (`init(autofillAt:)`) : elle lit le cache et la file de l'app,
/// n'envoie ni n'écrit jamais la file, et n'écrit sur le serveur que ce qui
/// ne peut pas attendre (passkey créée, compteur d'une passkey), avant
/// d'enregistrer le cache resynchronisé (voir SECURITY.md).
final class VaultAccess: @unchecked Sendable {
    let location: VerrouStorage.Location
    let session: VaultSession

    /// Coffre du compte de cet appareil.
    init(location: VerrouStorage.Location = VerrouStorage.accountLocation()) {
        self.location = location
        session = VaultSession.withStorage(dataDir: location.directory.path)
    }

    /// Extension de remplissage automatique : le même dossier, ouvert en
    /// invitée (jamais d'envoi ni d'écriture de la file de l'app).
    init(autofillAt location: VerrouStorage.Location) {
        self.location = location
        session = VaultSession.forAutofill(dataDir: location.directory.path)
    }

    /// Coffre fictif (démonstration, captures).
    init(mockAt location: VerrouStorage.Location) {
        self.location = location
        session = VaultSession()
    }

    var directory: URL { location.directory }

    /// Le compte enregistré, s'il y en a un.
    var account: AccountInfo? { session.account() }

    var isUnlocked: Bool { session.isUnlocked() }

    // MARK: Déverrouillage

    /// Rend le nombre d'éléments que le SDK n'a pas su déchiffrer.
    func unlock(masterPassword: String) async throws -> UInt32 {
        try await session.unlockWithPassword(password: masterPassword)
    }

    /// Le scellement Face ID / Touch ID existe sur cet appareil.
    var biometricEnrolled: Bool { BiometricVault.isEnrolled(in: directory) }

    /// Extension : un scellement (celui de l'app ou le sien) existe.
    var autofillBiometricEnrolled: Bool {
        BiometricVault.isEnrolled(in: directory)
            || BiometricVault.isEnrolled(in: directory, file: BiometricVault.autofillFile)
    }

    /// Extension : ouvre le coffre avec Face ID. D'abord le scellement de
    /// l'app ; s'il ne s'ouvre pas ici (clé du Secure Enclave propre à
    /// l'app), celui de l'extension. `Failure.invalidated` : aucun des deux,
    /// il faut le mot de passe principal (puis `enrollAutofillBiometrics`).
    func unlockForAutofill(reason: String) async throws -> UInt32 {
        if BiometricVault.isEnrolled(in: directory) {
            do {
                let key = try await BiometricVault.open(in: directory, reason: reason)
                return try await session.unlockWithUserKey(userKey: key)
            } catch BiometricVault.Failure.invalidated {
                // Le scellement de l'app ne s'ouvre pas dans l'extension :
                // le sien, s'il existe.
            }
        }
        guard BiometricVault.isEnrolled(in: directory, file: BiometricVault.autofillFile) else {
            throw BiometricVault.Failure.invalidated
        }
        do {
            let key = try await BiometricVault.open(in: directory, reason: reason, file: BiometricVault.autofillFile)
            return try await session.unlockWithUserKey(userKey: key)
        } catch BiometricVault.Failure.invalidated {
            BiometricVault.remove(in: directory, file: BiometricVault.autofillFile)
            throw BiometricVault.Failure.invalidated
        }
    }

    /// Extension, après le mot de passe principal : si l'app a activé Face ID
    /// mais que son scellement ne s'ouvre pas ici, l'extension scelle la clé
    /// pour elle-même.
    func enrollAutofillBiometrics() async {
        guard BiometricVault.isEnrolled(in: directory),
              !BiometricVault.isEnrolled(in: directory, file: BiometricVault.autofillFile),
              let key = try? await session.userKey() else { return }
        try? BiometricVault.enroll(userKey: key, in: directory, file: BiometricVault.autofillFile)
    }

    /// Demande Face ID / Touch ID, descelle la clé de l'utilisateur et ouvre
    /// le coffre avec. Les erreurs sont celles de `BiometricVault`
    /// (annulé, indisponible, invalidé) ou du cœur Rust.
    func unlockWithBiometrics(reason: String, accepted: (@MainActor () -> Void)? = nil) async throws -> UInt32 {
        let key = try await BiometricVault.open(in: directory, reason: reason, accepted: accepted)
        return try await session.unlockWithUserKey(userKey: key)
    }

    /// Scelle la clé de l'utilisateur (coffre ouvert) pour les prochains
    /// déverrouillages biométriques.
    func enrollBiometrics() async throws {
        let key = try await session.userKey()
        try BiometricVault.enroll(userKey: key, in: directory)
    }

    /// Retire les scellements de l'app et de l'extension.
    func removeBiometrics() {
        BiometricVault.remove(in: directory)
        BiometricVault.remove(in: directory, file: BiometricVault.autofillFile)
    }

    /// Referme le coffre : le cœur Rust efface ses secrets.
    func lock() {
        session.lock()
    }

    // MARK: Remplissage

    /// Identifiants proposés pour une page (correspondance des sites comme
    /// l'extension de navigateur : domaine enregistrable, règles de
    /// Bitwarden). Aucun secret.
    func credentials(forPage url: String) -> [ItemSummary] {
        (try? session.suggestions(pageUrl: url)) ?? []
    }

    /// Code à usage unique du moment, si l'élément en a un et qu'il ne
    /// demande pas de confirmation.
    func currentCode(of itemID: String, at date: Date = Date()) -> TotpView? {
        try? session.totp(id: itemID, unixTime: UInt64(date.timeIntervalSince1970))
    }
}
