import CryptoKit
import Foundation
import LocalAuthentication

/// Unlocking with Touch ID (Mac) or Face ID (iPhone): the user's key,
/// sealed by a Secure Enclave key.
///
/// - A P-256 key agreement key is created **in** the Secure Enclave, usable
///   only after Touch ID (`.biometryCurrentSet`: adding or removing a
///   fingerprint invalidates it). It never leaves the chip; the file only
///   keeps an encrypted reference to it, unusable on another Mac.
/// - On enrollment, an ephemeral key does an ECDH exchange with its public
///   key; the shared secret (HKDF-SHA256) seals the user's key with
///   AES-GCM. No authentication is needed to seal: only opening goes
///   through Touch ID.
/// - To open, the Secure Enclave redoes the exchange with the ephemeral
///   public key, which requires Touch ID.
///
/// No keychain, hence no entitlement and no developer team: the app can be
/// signed locally.
///
/// The file lives in the account folder (`VerrouStorage`): on the iPhone,
/// in the app group container when it exists, so that the AutoFill
/// extension can open it too.
///
/// AutoFill extension: it first opens the app's seal (`touchid.json`). If
/// the app's Secure Enclave key doesn't open from the extension (not
/// verifiable without a signed device), the extension seals the key with
/// its own Secure Enclave key, in a file of its own
/// (`touchid-autofill.json`), after an unlock with the master password;
/// the app erases both.
///
/// iOS Simulator: its Secure Enclave refuses keys guarded by biometrics. A
/// software key, kept in the file itself, replaces it, and only
/// LocalAuthentication (simulated Face ID) guards opening. No real
/// protection: this path is only for tests and doesn't exist in a device
/// build.
enum BiometricVault {
    struct Sealed: Codable {
        var enclaveKey: Data
        var ephemeralPublicKey: Data
        var box: Data
        /// Simulator only: `enclaveKey` is a software key.
        var simulated: Bool?
    }

    enum Failure: Error {
        case unavailable
        case cancelled
        /// Request interrupted by the system (app not active yet, incoming
        /// call): ask again as soon as the app is in the foreground.
        case interrupted
        /// Fingerprints changed, or Secure Enclave key lost: the master
        /// password is needed again.
        case invalidated
    }

    private static let info = Data("verrou.touchid.v1".utf8)

    /// The app's seal.
    static let appFile = "touchid.json"
    /// Seal specific to the AutoFill extension (see above).
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
        // The simulator advertises a Secure Enclave, but refuses to create a
        // key guarded by biometrics in it (LAError -1020).
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

    /// Asks for Touch ID and returns the user's key. `accepted` is called as
    /// soon as the face or finger is recognized, before the Secure Enclave
    /// and decryption: the lock screen can start opening.
    static func open(in directory: URL, reason: String, file name: String = appFile,
                     accepted: (@MainActor () -> Void)? = nil) async throws -> String {
        guard let data = try? Data(contentsOf: file(in: directory, name: name)),
              let sealed = try? JSONDecoder().decode(Sealed.self, from: data) else { throw Failure.invalidated }
        let context = LAContext()
        context.localizedFallbackTitle = ""
        let prompted = ContinuousClock.now
        Perf.mark("\(Biometrics.name) requested at +\(Perf.msSinceLaunch) ms from launch")
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            Perf.unlockSucceeded()
            Perf.mark("\(Biometrics.name) succeeded at +\(Perf.msSinceLaunch) ms from launch "
                      + "(waiting for the face or finger: \(Perf.ms(since: prompted)) ms)")
            if let accepted { await MainActor.run { accepted() } }
        } catch let error as LAError where [.userCancel, .userFallback].contains(error.code) {
            throw Failure.cancelled
        } catch let error as LAError where [.appCancel, .systemCancel, .notInteractive].contains(error.code) {
            throw Failure.interrupted
        } catch let error as LAError where [.biometryNotAvailable, .biometryNotEnrolled, .biometryLockout].contains(error.code) {
            throw Failure.unavailable
        }
        #if targetEnvironment(simulator)
        if sealed.simulated == true { return try openSimulated(sealed) }
        #endif
        let enclave = ContinuousClock.now
        defer {
            // Context closed as soon as the key is obtained: iOS can hand
            // control back to the app instead of leaving it inactive after the Face ID sheet.
            context.invalidate()
            Perf.mark("Secure Enclave (vault key): \(Perf.ms(since: enclave)) ms")
        }
        do {
            // The already authenticated context avoids a second prompt.
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
    /// Simulator: same seal, with a software key instead of the Secure
    /// Enclave's (see above).
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
