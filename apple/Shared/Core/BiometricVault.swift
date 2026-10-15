import CryptoKit
import Foundation
import LocalAuthentication

/// Déverrouillage par Touch ID (Mac) ou Face ID (iPhone) : la clé de
/// l'utilisateur, scellée par une clé du Secure Enclave.
///
/// - Une clé d'accord P-256 est créée **dans** le Secure Enclave, utilisable
///   seulement après Touch ID (`.biometryCurrentSet` : ajouter ou retirer une
///   empreinte l'invalide). Elle ne quitte jamais la puce ; le fichier n'en
///   garde qu'une référence chiffrée, inutilisable sur un autre Mac.
/// - À l'enrôlement, une clé éphémère fait un échange ECDH avec sa clé
///   publique ; le secret partagé (HKDF-SHA256) scelle la clé de
///   l'utilisateur en AES-GCM. Il n'y a besoin d'aucune authentification pour
///   sceller : seule l'ouverture passe par Touch ID.
/// - Pour ouvrir, le Secure Enclave refait l'échange avec la clé publique
///   éphémère, ce qui exige Touch ID.
///
/// Aucun trousseau, donc aucun droit (« entitlement ») ni équipe de
/// développeur : l'app peut être signée localement.
///
/// Le fichier vit dans le dossier du compte (`VerrouStorage`) : sur
/// l'iPhone, dans le conteneur du groupe d'apps quand il existe, pour que
/// l'extension de remplissage automatique puisse l'ouvrir aussi.
///
/// Extension de remplissage : elle ouvre d'abord le scellement de l'app
/// (`touchid.json`). Si la clé du Secure Enclave de l'app ne s'ouvre pas
/// depuis l'extension (non vérifiable sans appareil signé), l'extension
/// scelle la clé avec sa propre clé du Secure Enclave, dans un fichier à
/// elle (`touchid-autofill.json`), après un déverrouillage par le mot de
/// passe principal ; l'app efface les deux.
///
/// Simulateur iOS : son Secure Enclave refuse les clés gardées par la
/// biométrie. Une clé logicielle, gardée
/// dans le fichier lui-même, la remplace, et seul LocalAuthentication
/// (Face ID simulé) garde l'ouverture. Aucune protection réelle : ce chemin
/// ne sert qu'aux tests et n'existe pas dans un build pour appareil.
enum BiometricVault {
    struct Sealed: Codable {
        var enclaveKey: Data
        var ephemeralPublicKey: Data
        var box: Data
        /// Simulateur seulement : `enclaveKey` est une clé logicielle.
        var simulated: Bool?
    }

    enum Failure: Error {
        case unavailable
        case cancelled
        /// Empreintes modifiées, ou clé du Secure Enclave perdue : il faut
        /// repasser par le mot de passe principal.
        case invalidated
    }

    private static let info = Data("verrou.touchid.v1".utf8)

    /// Scellement de l'app.
    static let appFile = "touchid.json"
    /// Scellement propre à l'extension de remplissage (voir plus haut).
    static let autofillFile = "touchid-autofill.json"

    private static func file(in directory: URL, name: String) -> URL {
        directory.appending(path: name)
    }

    static func isEnrolled(in directory: URL, file name: String = appFile) -> Bool {
        FileManager.default.fileExists(atPath: file(in: directory, name: name).path)
    }

    static func remove(in directory: URL, file name: String = appFile) {
        try? FileManager.default.removeItem(at: file(in: directory, name: name))
    }

    static func enroll(userKey: String, in directory: URL, file name: String = appFile) throws {
        #if targetEnvironment(simulator)
        // Le simulateur annonce un Secure Enclave, mais refuse d'y créer une
        // clé gardée par la biométrie (LAError -1020).
        try enrollSimulated(userKey: userKey, to: file(in: directory, name: name))
        return
        #else
        guard SecureEnclave.isAvailable, Biometrics.isAvailable else { throw Failure.unavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error
        ) else { throw error!.takeRetainedValue() as Error }
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let symmetric = derive(shared, ephemeralPublicKey: ephemeral.publicKey.rawRepresentation)
        let box = try AES.GCM.seal(Data(userKey.utf8), using: symmetric)
        let sealed = Sealed(
            enclaveKey: enclaveKey.dataRepresentation,
            ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            box: box.combined!)
        let data = try JSONEncoder().encode(sealed)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try data.write(to: file(in: directory, name: name), options: .atomic)
        #endif
    }

    /// Demande Touch ID et rend la clé de l'utilisateur.
    static func open(in directory: URL, reason: String, file name: String = appFile) async throws -> String {
        guard let data = try? Data(contentsOf: file(in: directory, name: name)),
              let sealed = try? JSONDecoder().decode(Sealed.self, from: data) else { throw Failure.invalidated }
        let context = LAContext()
        context.localizedFallbackTitle = ""
        let prompted = ContinuousClock.now
        defer { Perf.log.notice("Touch ID (attente du doigt comprise) : \(Perf.ms(since: prompted)) ms") }
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let error as LAError where [.userCancel, .appCancel, .systemCancel, .userFallback].contains(error.code) {
            throw Failure.cancelled
        } catch let error as LAError where [.biometryNotAvailable, .biometryNotEnrolled, .biometryLockout].contains(error.code) {
            throw Failure.unavailable
        }
        #if targetEnvironment(simulator)
        if sealed.simulated == true { return try openSimulated(sealed) }
        #endif
        let enclave = ContinuousClock.now
        defer { Perf.log.notice("Secure Enclave (clé du coffre) : \(Perf.ms(since: enclave)) ms") }
        do {
            // Le contexte déjà authentifié évite une seconde demande.
            let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: sealed.enclaveKey, authenticationContext: context)
            let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: sealed.ephemeralPublicKey)
            let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeral)
            let symmetric = derive(shared, ephemeralPublicKey: sealed.ephemeralPublicKey)
            let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed.box), using: symmetric)
            guard let key = String(data: plain, encoding: .utf8) else { throw Failure.invalidated }
            return key
        } catch {
            throw Failure.invalidated
        }
    }

    private static func derive(_ shared: SharedSecret, ephemeralPublicKey: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: info, sharedInfo: ephemeralPublicKey, outputByteCount: 32)
    }

    #if targetEnvironment(simulator)
    /// Simulateur : même scellement, avec une clé logicielle à la place de
    /// celle du Secure Enclave (voir plus haut).
    private static func enrollSimulated(userKey: String, to url: URL) throws {
        guard Biometrics.isAvailable else { throw Failure.unavailable }
        let deviceKey = P256.KeyAgreement.PrivateKey()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: deviceKey.publicKey)
        let symmetric = derive(shared, ephemeralPublicKey: ephemeral.publicKey.rawRepresentation)
        let box = try AES.GCM.seal(Data(userKey.utf8), using: symmetric)
        let sealed = Sealed(
            enclaveKey: deviceKey.rawRepresentation,
            ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            box: box.combined!, simulated: true)
        let data = try JSONEncoder().encode(sealed)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    private static func openSimulated(_ sealed: Sealed) throws -> String {
        do {
            let deviceKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: sealed.enclaveKey)
            let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: sealed.ephemeralPublicKey)
            let shared = try deviceKey.sharedSecretFromKeyAgreement(with: ephemeral)
            let symmetric = derive(shared, ephemeralPublicKey: sealed.ephemeralPublicKey)
            let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed.box), using: symmetric)
            guard let key = String(data: plain, encoding: .utf8) else { throw Failure.invalidated }
            return key
        } catch {
            throw Failure.invalidated
        }
    }
    #endif
}
