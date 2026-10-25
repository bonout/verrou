import Foundation

/// Vault access without UI: where it lives, how to open it (master
/// password, Face ID / Touch ID), close it again, and look up a site's
/// logins in it.
///
/// Used by the iPhone app, and designed for the AutoFill extension
/// (`VerrouAutoFill`): it fits within the extensions' memory limit (about
/// 120 MB) because all the work (decryption, search, site matching,
/// one-time codes) stays in the Rust core; Swift only receives summaries,
/// and a secret only when asked for (`reveal`, `totp`).
///
/// Queue writes (sync, offline changes) stay with the app. The extension
/// opens the shared folder's vault as a guest (`init(autofillAt:)`): it
/// reads the app's cache and queue, never sends nor writes the queue, and
/// only writes to the server what can't wait (created passkey, a passkey's
/// counter), before saving the resynced cache (see SECURITY.md).
final class VaultAccess: @unchecked Sendable {
    let location: VerrouStorage.Location
    let session: VaultSession

    /// Vault of this device's account.
    init(location: VerrouStorage.Location = VerrouStorage.accountLocation()) {
        self.location = location
        session = VaultSession.withStorage(dataDir: location.directory.path)
    }

    /// AutoFill extension: the same folder, opened as a guest (never sends
    /// nor writes the app's queue).
    init(autofillAt location: VerrouStorage.Location) {
        self.location = location
        session = VaultSession.forAutofill(dataDir: location.directory.path)
    }

    /// Demo vault (demonstration, screenshots).
    init(mockAt location: VerrouStorage.Location) {
        self.location = location
        session = VaultSession()
    }

    var directory: URL { location.directory }

    /// The saved account, if there is one.
    var account: AccountInfo? { session.account() }

    var isUnlocked: Bool { session.isUnlocked() }

    // MARK: Unlocking

    /// Returns the number of items the SDK could not decrypt.
    func unlock(masterPassword: String) async throws -> UInt32 {
        try await session.unlockWithPassword(password: masterPassword)
    }

    /// The Face ID / Touch ID seal exists on this device.
    var biometricEnrolled: Bool { BiometricVault.isEnrolled(in: directory) }

    /// Extension: a seal (the app's or its own) exists.
    var autofillBiometricEnrolled: Bool {
        BiometricVault.isEnrolled(in: directory)
            || BiometricVault.isEnrolled(in: directory, file: BiometricVault.autofillFile)
    }

    /// Extension: opens the vault with Face ID. First the app's seal; if it
    /// doesn't open here (Secure Enclave key specific to the app), the
    /// extension's. `Failure.invalidated`: neither, the master password is
    /// needed (then `enrollAutofillBiometrics`).
    func unlockForAutofill(reason: String) async throws -> UInt32 {
        // The extension's own seal only exists because the app's didn't open
        // here: straight to it, rather than a first Face ID for nothing.
        let ownSeal = BiometricVault.isEnrolled(in: directory, file: BiometricVault.autofillFile)
        if !ownSeal, BiometricVault.isEnrolled(in: directory) {
            do {
                let key = try await BiometricVault.open(in: directory, reason: reason)
                return try await Perf.measure("vault opened") { try await session.unlockWithUserKey(userKey: key) }
            } catch BiometricVault.Failure.invalidated {
                // The app's seal doesn't open in the extension: its own,
                // if it exists.
            }
        }
        guard BiometricVault.isEnrolled(in: directory, file: BiometricVault.autofillFile) else {
            throw BiometricVault.Failure.invalidated
        }
        do {
            let key = try await BiometricVault.open(in: directory, reason: reason, file: BiometricVault.autofillFile)
            return try await Perf.measure("vault opened") { try await session.unlockWithUserKey(userKey: key) }
        } catch BiometricVault.Failure.invalidated {
            BiometricVault.remove(in: directory, file: BiometricVault.autofillFile)
            throw BiometricVault.Failure.invalidated
        }
    }

    /// Extension, after the master password: if the app turned Face ID on
    /// but its seal doesn't open here, the extension seals the key for
    /// itself.
    func enrollAutofillBiometrics() async {
        guard BiometricVault.isEnrolled(in: directory),
              !BiometricVault.isEnrolled(in: directory, file: BiometricVault.autofillFile),
              let key = try? await session.userKey() else { return }
        try? BiometricVault.enroll(userKey: key, in: directory, file: BiometricVault.autofillFile)
    }

    /// Asks for Face ID / Touch ID, unseals the user's key and opens the
    /// vault with it. The errors are `BiometricVault`'s (cancelled,
    /// unavailable, invalidated) or the Rust core's.
    func unlockWithBiometrics(reason: String, accepted: (@MainActor @Sendable () -> Void)? = nil) async throws -> UInt32 {
        let key = try await BiometricVault.open(in: directory, reason: reason, accepted: accepted)
        return try await session.unlockWithUserKey(userKey: key)
    }

    /// Seals the user's key (vault open) for the next biometric unlocks.
    func enrollBiometrics() async throws {
        let key = try await session.userKey()
        try BiometricVault.enroll(userKey: key, in: directory)
    }

    /// Removes the app's and the extension's seals.
    func removeBiometrics() {
        BiometricVault.remove(in: directory)
        BiometricVault.remove(in: directory, file: BiometricVault.autofillFile)
    }

    /// Closes the vault: the Rust core erases its secrets.
    func lock() {
        session.lock()
    }

    // MARK: Filling

    /// Logins offered for a page (site matching like the browser
    /// extension: registrable domain, Bitwarden's rules). No secret.
    func credentials(forPage url: String) -> [ItemSummary] {
        (try? session.suggestions(pageUrl: url)) ?? []
    }

    /// Current one-time code, if the item has one and it doesn't ask for
    /// confirmation.
    func currentCode(of itemID: String, at date: Date = Date()) -> TotpView? {
        try? session.totp(id: itemID, unixTime: UInt64(date.timeIntervalSince1970))
    }
}
