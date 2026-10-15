import Foundation

/// Accès au coffre sans interface : où il vit, comment l'ouvrir (mot de
/// passe principal, Face ID / Touch ID), le refermer, et y chercher les
/// identifiants d'un site.
///
/// Utilisé par l'app iPhone, et pensé pour l'extension de remplissage
/// automatique (phase 2) : elle tient dans la limite de mémoire des
/// extensions (environ 120 Mo) parce que tout le travail (déchiffrement,
/// recherche, correspondance des sites, codes à usage unique) reste dans le
/// cœur Rust ; Swift ne reçoit que des résumés, et un secret seulement quand
/// on le demande (`reveal`, `totp`).
///
/// Les écritures (synchronisation, file hors ligne) restent à l'app : deux
/// processus qui écriraient le même cache en même temps se marcheraient
/// dessus. L'extension ouvrira le coffre depuis le cache, en lecture.
final class VaultAccess: @unchecked Sendable {
    let location: VerrouStorage.Location
    let session: VaultSession

    /// Coffre du compte de cet appareil.
    init(location: VerrouStorage.Location = VerrouStorage.accountLocation()) {
        self.location = location
        session = VaultSession.withStorage(dataDir: location.directory.path)
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

    /// Demande Face ID / Touch ID, descelle la clé de l'utilisateur et ouvre
    /// le coffre avec. Les erreurs sont celles de `BiometricVault`
    /// (annulé, indisponible, invalidé) ou du cœur Rust.
    func unlockWithBiometrics(reason: String) async throws -> UInt32 {
        let key = try await BiometricVault.open(in: directory, reason: reason)
        return try await session.unlockWithUserKey(userKey: key)
    }

    /// Scelle la clé de l'utilisateur (coffre ouvert) pour les prochains
    /// déverrouillages biométriques.
    func enrollBiometrics() async throws {
        let key = try await session.userKey()
        try BiometricVault.enroll(userKey: key, in: directory)
    }

    func removeBiometrics() {
        BiometricVault.remove(in: directory)
    }

    /// Referme le coffre : le cœur Rust efface ses secrets.
    func lock() {
        session.lock()
    }

    // MARK: Remplissage (phase 2)

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
