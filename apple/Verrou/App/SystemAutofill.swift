import AuthenticationServices
import Foundation

/// System credential provider (Settings → General → AutoFill & Passwords):
/// the `VerrouAutoFillMac` extension, shipped only in a build signed by the
/// team (see `VerrouStorage`).
///
/// After each vault reload, the app publishes the sites, usernames, codes
/// and passkeys (never a secret) to AuthenticationServices' identity store:
/// Safari and the apps offer them, then the extension fills after Touch ID.
@MainActor
enum SystemAutofill {
    private static var task: Task<Void, Never>?

    /// The extension is in the app (build signed by the team, app group).
    static var isBundled: Bool {
        VerrouStorage.appGroupID != nil
            && FileManager.default.fileExists(atPath: Bundle.main.builtInPlugInsURL?
                .appending(path: "VerrouAutoFillMac.appex").path ?? "")
    }

    /// A moment after the last change, off the main thread.
    static func publish(_ session: VaultSession) {
        guard isBundled, session.isUnlocked() else { return }
        task?.cancel()
        task = Task.detached(priority: .utility) {
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled, let identities = try? session.autofillIdentities() else { return }
            await CredentialIdentities.publish(identities)
        }
    }

    /// Logout: no more suggestions.
    static func clear() {
        task?.cancel()
        guard isBundled else { return }
        Task { await CredentialIdentities.clear() }
    }

    /// Is Verrou chosen in the system settings?
    static func isEnabled() async -> Bool {
        guard isBundled else { return false }
        return await CredentialIdentities.isEnabled()
    }

    /// Opens the settings where Verrou is chosen.
    static func openSettings() {
        Task { try? await ASSettingsHelper.openCredentialProviderAppSettings() }
    }
}
