import CryptoKit
import Foundation
import LocalAuthentication

/// Déverrouillage par Touch ID : la clé de l'utilisateur, scellée par une clé
/// du Secure Enclave.
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
enum BiometricVault {
    struct Sealed: Codable {
        var enclaveKey: Data
        var ephemeralPublicKey: Data
        var box: Data
    }

    enum Failure: Error {
        case unavailable
        case cancelled
        /// Empreintes modifiées, ou clé du Secure Enclave perdue : il faut
        /// repasser par le mot de passe principal.
        case invalidated
    }

    private static let info = Data("verrou.touchid.v1".utf8)

    private static func file(in directory: URL) -> URL {
        directory.appending(path: "touchid.json")
    }

    static func isEnrolled(in directory: URL) -> Bool {
        FileManager.default.fileExists(atPath: file(in: directory).path)
    }

    static func remove(in directory: URL) {
        try? FileManager.default.removeItem(at: file(in: directory))
    }

    static func enroll(userKey: String, in directory: URL) throws {
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
        try data.write(to: file(in: directory), options: .atomic)
    }

    /// Demande Touch ID et rend la clé de l'utilisateur.
    static func open(in directory: URL, reason: String) async throws -> String {
        guard let data = try? Data(contentsOf: file(in: directory)),
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
}
