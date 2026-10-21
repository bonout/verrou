import AppKit
import Observation
import UserNotifications

/// Audit additions: expired cards, old passwords, two-factor authentication
/// available (2fa.directory list), possible passkeys (passkeys.2fa.directory
/// directory), and check in known leaks of the passwords just saved.
@MainActor
@Observable
final class Watchtower {
    /// Preference: check new passwords in Have I Been Pwned.
    static let checkNewPasswordsKey = "checkNewPasswords"
    static var checksNewPasswords: Bool {
        UserDefaults.standard.object(forKey: checkNewPasswordsKey) as? Bool ?? true
    }

    /// Cards and old passwords (local, without network).
    private(set) var report: WatchtowerReport?
    /// `nil`: not loaded yet (or unavailable, see `twoFactorError`).
    private(set) var twoFactor: TwoFactorReport?
    private(set) var loadingTwoFactor = false
    private(set) var twoFactorError: String?
    /// "Passkey available": `nil` as long as the directory is not loaded (or
    /// if it is unavailable, see `passkeysError`).
    private(set) var passkeys: PasskeyReport?
    private(set) var loadingPasskeys = false
    private(set) var passkeysError: String?
    /// Item whose passkey creation page is being looked up
    /// (`AppModel.createPasskey`).
    var creatingPasskey: String?
    /// Visual review: audit section to show at the top (`passkeys`).
    var focus: String?

    /// Issues counted in the sidebar.
    var issues: Int {
        (report.map { $0.cards.count + $0.old.count } ?? 0) + (twoFactor?.missing.count ?? 0)
    }

    func refresh(_ session: VaultSession, network: Bool) {
        report = try? session.watchtower()
        // Mock vault: the passkeys directory comes from an embedded excerpt,
        // without network.
        Task { await loadPasskeys(session) }
        guard network else { return }
        Task { await loadTwoFactor(session) }
    }

    /// Downloads the passkeys directory if needed (in full, kept 7 days);
    /// offline, the last copy, otherwise the category is skipped.
    func loadPasskeys(_ session: VaultSession) async {
        guard !loadingPasskeys else { return }
        loadingPasskeys = true
        defer { loadingPasskeys = false }
        do {
            passkeys = try await session.passkeyAudit()
            passkeysError = nil
        } catch {
            passkeys = nil
            passkeysError = AppModel.describe(error)
        }
    }

    /// Downloads the list if needed (kept 7 days); offline, the last copy,
    /// otherwise the category is skipped.
    private func loadTwoFactor(_ session: VaultSession) async {
        guard !loadingTwoFactor else { return }
        loadingTwoFactor = true
        defer { loadingTwoFactor = false }
        do {
            twoFactor = try await session.twoFactorAudit()
            twoFactorError = nil
        } catch {
            twoFactor = nil
            twoFactorError = AppModel.describe(error)
        }
    }

    func reset() {
        report = nil
        twoFactor = nil
        twoFactorError = nil
        passkeys = nil
        passkeysError = nil
        creatingPasskey = nil
    }
}

extension AppModel {
    /// After a write made in Verrou (editor, extension, import): the new
    /// passwords are checked against known leaks (k-anonymity: 5 characters
    /// of their SHA-1), in the background.
    func checkNewPasswords() {
        guard mode == .vaultwarden, lockState == .unlocked else { return }
        guard Watchtower.checksNewPasswords else {
            session.forgetNewPasswords()
            return
        }
        Task {
            guard let found = try? await session.checkNewPasswords(), !found.isEmpty,
                  lockState == .unlocked else { return }
            mergeBreaches(found)
            let first = found[0]
            let message = found.count == 1
                ? String(localized: "Password found in known leaks")
                : String(localized: "\(found.count) passwords found in known leaks")
            let detail = String(localized: "“\(first.item.title)”: seen \(first.count.formatted()) times. Change it.")
            if NSApp.isActive {
                toast = Toast(message: message, detail: detail, failure: true)
            } else {
                Self.notify(message, detail)
            }
        }
    }

    /// System notification (the user is in Brave, for example).
    private static func notify(_ title: String, _ body: String) {
        let center = UNUserNotificationCenter.current()
        Task {
            guard (try? await center.requestAuthorization(options: [.alert, .sound])) == true else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            try? await center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }
}

// MARK: Change the password

extension ItemSummary {
    /// Login with a site, not in the trash: "Change Password" has a page to
    /// open.
    var canChangePassword: Bool {
        category == .login && host != nil && state != .trashed
    }
}

extension AppModel {
    /// Opens the page where the item's password is changed: page known in
    /// advance (big sites), otherwise `/.well-known/change-password` if the
    /// site offers it (checked by the Rust core, for this site only and only
    /// now), otherwise the site's home page. The extension then suggests a
    /// strong password, then its update in the vault; at the next sync, the
    /// item leaves the audit.
    func changePassword(of summary: ItemSummary) async {
        guard summary.canChangePassword, changingPassword == nil, lockState == .unlocked else { return }
        changingPassword = summary.id
        defer { changingPassword = nil }
        let hint = String(localized: "Verrou will suggest a strong password and saving it")
        do {
            let page = try await session.changePasswordPage(id: summary.id)
            guard lockState == .unlocked, let url = URL(string: page.url) else { return }
            NSWorkspace.shared.open(url)
            switch page.source {
            case .known, .wellKnown:
                toast = Toast(message: String(localized: "Change-password page opened"), detail: hint, seconds: 5)
            case .home:
                toast = Toast(message: String(localized: "This site doesn't state its change-password page: opening the home page"),
                              detail: hint, seconds: 6)
            }
        } catch {
            toast = Toast(message: String(localized: "Page not found"), detail: Self.describe(error), failure: true)
        }
    }
}

// MARK: Create a passkey

extension AppModel {
    /// Opens the page where a passkey is created for the item: the one the
    /// site publishes (`/.well-known/passkey-endpoints`, checked by the Rust
    /// core, for this site only and only now), otherwise a page known in
    /// advance, otherwise the site's home page. In Brave or Firefox, the
    /// extension then offers to save the passkey in the item; at the next
    /// sync, it leaves "Passkey available".
    func createPasskey(for candidate: PasskeyCandidate) async {
        let summary = candidate.item
        guard watchtower.creatingPasskey == nil, lockState == .unlocked else { return }
        watchtower.creatingPasskey = summary.id
        defer { watchtower.creatingPasskey = nil }
        let hint = String(localized: "Create it on the site: the Verrou extension for Brave or Firefox will offer to save it in “\(summary.title)”.")
        do {
            let page = try await session.passkeySetupPage(id: summary.id)
            guard lockState == .unlocked, let url = URL(string: page.url) else { return }
            NSWorkspace.shared.open(url)
            switch page.source {
            case .wellKnown, .known:
                toast = Toast(message: String(localized: "Passkeys page opened"), detail: hint, seconds: 6)
            case .home:
                toast = Toast(message: String(localized: "This site doesn't state its passkeys page: opening the home page"),
                              detail: String(localized: "Look for “passkey” in the account's security settings. ")
                                  + hint, seconds: 8)
            }
        } catch {
            toast = Toast(message: String(localized: "Page not found"), detail: Self.describe(error), failure: true)
        }
    }
}
