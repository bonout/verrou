import Observation
import UIKit

/// "Passkey possible" on the iPhone: logins whose site accepts passkeys,
/// according to the passkeys.2fa.directory directory (downloaded whole,
/// kept 7 days by the Rust core; no request per site).
///
/// "Create a passkey" opens the site's page in Safari: Verrou is the
/// AutoFill provider there, so the created passkey is saved in the vault
/// (VerrouAutoFill extension), in the item of the same account.
@MainActor
@Observable
final class PhonePasskeyAudit {
    /// `nil`: not loaded yet (or unavailable, see `error`).
    private(set) var report: PasskeyReport?
    private(set) var loading = false
    private(set) var error: String?
    /// Item whose creation page is being looked up.
    private(set) var opening: String?
    /// End-to-end run: show the section at the top of the audit.
    var focus = false

    /// What the sites reported to the extension (iOS 26) and that still
    /// concerns the vault.
    private(set) var signals: [SignalFinding] = []

    var count: Int { report?.candidates.count ?? 0 }

    func load(_ session: VaultSession) async {
        guard !loading else { return }
        signals = (try? session.credentialSignalFindings()) ?? []
        loading = true
        defer { loading = false }
        do {
            report = try await session.passkeyAudit()
            error = nil
        } catch {
            report = nil
            self.error = ErrorText.describe(error)
        }
    }

    func reset() {
        report = nil
        error = nil
        signals = []
        opening = nil
        focus = false
    }

    /// Opens the page where to create the passkey: the one the site
    /// publishes (`/.well-known/passkey-endpoints`, verified for this site
    /// only), otherwise a known page, otherwise the site's home. Returns the message to show.
    func open(_ candidate: PasskeyCandidate, session: VaultSession) async -> Toast? {
        guard opening == nil else { return nil }
        opening = candidate.item.id
        defer { opening = nil }
        let hint = String(localized: "When Safari offers to save the passkey, choose Verrou.")
        do {
            let page = try await session.passkeySetupPage(id: candidate.item.id)
            guard let url = URL(string: page.url) else { return nil }
            await UIApplication.shared.open(url)
            switch page.source {
            case .wellKnown, .known:
                return Toast(message: String(localized: "Passkeys page opened"), detail: hint, seconds: 6)
            case .home:
                return Toast(message: String(localized: "This site doesn't indicate its passkeys page"),
                             detail: String(localized: "Look for “passkey” in the account's security settings.") + " " + hint,
                             seconds: 8)
            }
        } catch {
            return Toast(message: String(localized: "Page not found"), detail: ErrorText.describe(error), failure: true)
        }
    }
}

extension PhoneModel {
    /// Loads "Passkey possible" (demo vault: embedded excerpt of the
    /// directory, no network).
    func refreshPasskeyAudit() {
        guard lockState == .unlocked else { return }
        Task { await passkeyAudit.load(session) }
    }

    /// Passkeys created by Safari in the background after a fill
    /// (conditional creation, VerrouAutoFill extension): saved in their
    /// login now that the vault is open.
    func finishPendingPasskeys() async {
        guard mode == .vaultwarden, lockState == .unlocked, session.pendingPasskeys() > 0 else { return }
        guard let titles = try? await session.finishPendingPasskeys(), !titles.isEmpty,
              lockState == .unlocked else { return }
        afterWrite()
        publishAutofillIdentities()
        if audit != nil { refreshPasskeyAudit() }
        toast = Toast(message: titles.count == 1 ? String(localized: "Passkey saved") : String(localized: "\(titles.count) passkeys saved"),
                      detail: String(localized: "Created by Safari for “\(titles.joined(separator: String(localized: "”, “")))”; the password stays as a fallback."),
                      seconds: 5)
    }

    func createPasskey(for candidate: PasskeyCandidate) {
        Task {
            if let message = await passkeyAudit.open(candidate, session: session) {
                toast = message
            }
        }
    }
}
