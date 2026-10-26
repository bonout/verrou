import Foundation
import OSLog

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
/// opens the shared folder's vault as a guest (`autofill(at:)`): it
/// reads the app's cache and queue, never sends nor writes the queue, and
/// only writes to the server what can't wait (created passkey, a passkey's
/// counter), before saving the resynced cache (see SECURITY.md).
///
/// The account lives in `accounts/<tag>` under the root (`Accounts`, which
/// migrates an older single account into it, once, the first time any
/// process opens the root). The apps still show one account: the registry's
/// default one, or the folder a first sign-in will fill.
final class VaultAccess: @unchecked Sendable {
    let location: VerrouStorage.Location
    let session: VaultSession
    /// The registry of the root; `nil` for the demo vault.
    let accounts: Accounts?
    /// The account's tag in the registry; `nil` for the demo vault.
    let tag: String?
    /// The account's folder: where the Touch ID and Face ID seals live.
    let directory: URL
    /// Why the accounts could not be opened (disk full, protected data not
    /// available yet, a registry written by a newer Verrou). Then nothing is
    /// touched and nothing is written anywhere: the session is an inert one
    /// (no storage, no network), the apps show this error with a Retry
    /// button instead of the sign-in or lock screen, and start nothing (no
    /// sync, no bridge).
    let storageError: Error?
    /// Unsent offline changes an older Verrou left in the root's
    /// `outbox.json`, next to an account that was kept: the apps tell the
    /// user once.
    let unsentLegacyChanges: UInt32
    private static let log = Logger(subsystem: "app.verrou", category: "storage")

    private struct Opened {
        let accounts: Accounts
        let tag: String
        let session: VaultSession
        let directory: URL
    }

    /// The registry of the root (migrating an older account if this is the
    /// first process to open it) and the session of its primary account.
    /// `nil` for the extension when there is no account.
    private static func open(_ location: VerrouStorage.Location, guest: Bool) throws -> Opened? {
        let accounts = guest ? try Accounts.forAutofill(root: location.root.path)
                             : try Accounts.open(root: location.root.path)
        for notice in accounts.notices() { log.notice("\(notice, privacy: .public)") }
        guard let tag = try accounts.primaryTag() else { return nil }
        return Opened(accounts: accounts, tag: tag, session: try accounts.session(tag: tag),
                      directory: URL(fileURLWithPath: try accounts.directory(tag: tag), isDirectory: true))
    }

    private init(location: VerrouStorage.Location, opened: Opened) {
        self.location = location
        accounts = opened.accounts
        tag = opened.tag
        session = opened.session
        directory = opened.directory
        unsentLegacyChanges = opened.accounts.unsentLegacyChanges()
        storageError = nil
    }

    /// Vault of this device's account. When the accounts can't be opened,
    /// `storageError` says why and the session is inert.
    convenience init(location: VerrouStorage.Location = VerrouStorage.rootLocation()) {
        do {
            guard let opened = try Self.open(location, guest: false) else { throw VerrouError.NoAccount }
            self.init(location: location, opened: opened)
        } catch {
            Self.log.error("accounts not opened: \(String(describing: error), privacy: .public)")
            self.init(location: location, failure: error)
        }
    }

    private init(location: VerrouStorage.Location, failure: Error) {
        self.location = location
        accounts = nil
        tag = nil
        // Never written to: nothing is enrolled or saved while this is set.
        directory = location.root
        session = VaultSession()
        unsentLegacyChanges = 0
        storageError = failure
    }

    /// AutoFill extension: the same accounts, opened as a guest (never sends
    /// nor writes the app's queue). `nil` when no account is signed in;
    /// throws when the accounts can't be opened (the extension says so,
    /// rather than "no account").
    static func autofill(at location: VerrouStorage.Location) throws -> VaultAccess? {
        guard let opened = try open(location, guest: true) else { return nil }
        return VaultAccess(location: location, opened: opened)
    }

    /// Demo vault (demonstration, screenshots).
    init(mockAt location: VerrouStorage.Location) {
        self.location = location
        accounts = nil
        tag = nil
        directory = location.root
        storageError = nil
        unsentLegacyChanges = 0
        session = VaultSession()
    }


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
