import AppKit
import Observation
import UserNotifications

/// Compléments de l'audit : cartes expirées, mots de passe anciens, double
/// authentification disponible (liste de 2fa.directory), passkeys possibles
/// (annuaire passkeys.2fa.directory), et vérification dans les fuites connues
/// des mots de passe qu'on vient d'enregistrer.
@MainActor
@Observable
final class Watchtower {
    /// Préférence : vérifier les nouveaux mots de passe dans Have I Been Pwned.
    static let checkNewPasswordsKey = "checkNewPasswords"
    static var checksNewPasswords: Bool {
        UserDefaults.standard.object(forKey: checkNewPasswordsKey) as? Bool ?? true
    }

    /// Cartes et mots de passe anciens (local, sans réseau).
    private(set) var report: WatchtowerReport?
    /// `nil` : pas encore chargé (ou indisponible, voir `twoFactorError`).
    private(set) var twoFactor: TwoFactorReport?
    private(set) var loadingTwoFactor = false
    private(set) var twoFactorError: String?
    /// « Passkey possible » : `nil` tant que l'annuaire n'est pas chargé (ou
    /// s'il est indisponible, voir `passkeysError`).
    private(set) var passkeys: PasskeyReport?
    private(set) var loadingPasskeys = false
    private(set) var passkeysError: String?
    /// Élément dont on cherche la page de création de passkey
    /// (`AppModel.createPasskey`).
    var creatingPasskey: String?
    /// Revue visuelle : section de l'audit à montrer en haut (`passkeys`).
    var focus: String?

    /// Problèmes comptés dans la barre latérale.
    var issues: Int {
        (report.map { $0.cards.count + $0.old.count } ?? 0) + (twoFactor?.missing.count ?? 0)
    }

    func refresh(_ session: VaultSession, network: Bool) {
        report = try? session.watchtower()
        // Coffre fictif : l'annuaire des passkeys vient d'un extrait
        // embarqué, sans réseau.
        Task { await loadPasskeys(session) }
        guard network else { return }
        Task { await loadTwoFactor(session) }
    }

    /// Télécharge l'annuaire des passkeys au besoin (en entier, gardé 7
    /// jours) ; hors ligne, la dernière copie, sinon la catégorie est
    /// ignorée.
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

    /// Télécharge la liste au besoin (gardée 7 jours) ; hors ligne, la
    /// dernière copie, sinon la catégorie est ignorée.
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
    /// Après une écriture faite dans Verrou (éditeur, extension, import) :
    /// les mots de passe nouveaux partent vérifier dans les fuites connues
    /// (k-anonymat : 5 caractères de leur SHA-1), en arrière-plan.
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
                ? "Mot de passe présent dans des fuites connues"
                : "\(found.count) mots de passe présents dans des fuites connues"
            let detail = "« \(first.item.title) » : vu \(first.count.formatted()) fois. Changez-le."
            if NSApp.isActive {
                toast = Toast(message: message, detail: detail, failure: true)
            } else {
                Self.notify(message, detail)
            }
        }
    }

    /// Notification système (l'utilisateur est dans Brave, par exemple).
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

// MARK: Changer le mot de passe

extension ItemSummary {
    /// Identifiant avec un site, hors corbeille : « Changer le mot de passe »
    /// a une page à ouvrir.
    var canChangePassword: Bool {
        category == .login && host != nil && state != .trashed
    }
}

extension AppModel {
    /// Ouvre la page où changer le mot de passe de l'élément : page connue
    /// d'avance (grands sites), sinon `/.well-known/change-password` si le
    /// site la propose (vérifié par le cœur Rust, pour ce site seul et
    /// seulement maintenant), sinon l'accueil du site. L'extension propose
    /// ensuite un mot de passe fort, puis sa mise à jour dans le coffre ; à
    /// la synchronisation suivante, l'élément quitte l'audit.
    func changePassword(of summary: ItemSummary) async {
        guard summary.canChangePassword, changingPassword == nil, lockState == .unlocked else { return }
        changingPassword = summary.id
        defer { changingPassword = nil }
        let hint = "Verrou proposera un mot de passe fort et l'enregistrement"
        do {
            let page = try await session.changePasswordPage(id: summary.id)
            guard lockState == .unlocked, let url = URL(string: page.url) else { return }
            NSWorkspace.shared.open(url)
            switch page.source {
            case .known, .wellKnown:
                toast = Toast(message: "Page de changement du mot de passe ouverte", detail: hint, seconds: 5)
            case .home:
                toast = Toast(message: "Ce site n'indique pas sa page de changement de mot de passe : ouverture de l'accueil",
                              detail: hint, seconds: 6)
            }
        } catch {
            toast = Toast(message: "Page introuvable", detail: Self.describe(error), failure: true)
        }
    }
}

// MARK: Créer une passkey

extension AppModel {
    /// Ouvre la page où créer une passkey pour l'élément : celle que le site
    /// publie (`/.well-known/passkey-endpoints`, vérifiée par le cœur Rust,
    /// pour ce site seul et seulement maintenant), sinon une page connue
    /// d'avance, sinon l'accueil du site. Dans Brave ou Firefox, l'extension
    /// propose ensuite d'enregistrer la passkey dans l'élément ; à la
    /// synchronisation suivante, il quitte « Passkey possible ».
    func createPasskey(for candidate: PasskeyCandidate) async {
        let summary = candidate.item
        guard watchtower.creatingPasskey == nil, lockState == .unlocked else { return }
        watchtower.creatingPasskey = summary.id
        defer { watchtower.creatingPasskey = nil }
        let hint = "Créez-la sur le site : l'extension Verrou de Brave ou Firefox proposera de l'enregistrer dans « \(summary.title) »."
        do {
            let page = try await session.passkeySetupPage(id: summary.id)
            guard lockState == .unlocked, let url = URL(string: page.url) else { return }
            NSWorkspace.shared.open(url)
            switch page.source {
            case .wellKnown, .known:
                toast = Toast(message: "Page des passkeys ouverte", detail: hint, seconds: 6)
            case .home:
                toast = Toast(message: "Ce site n'indique pas sa page de passkeys : ouverture de l'accueil",
                              detail: "Cherchez « passkey » ou « clé d'accès » dans les réglages de sécurité du compte. "
                                  + hint, seconds: 8)
            }
        } catch {
            toast = Toast(message: "Page introuvable", detail: Self.describe(error), failure: true)
        }
    }
}
