import AppKit
import Observation
import UserNotifications

/// Compléments de l'audit : cartes expirées, mots de passe anciens, double
/// authentification disponible (liste de 2fa.directory), et vérification dans
/// les fuites connues des mots de passe qu'on vient d'enregistrer.
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

    /// Problèmes comptés dans la barre latérale.
    var issues: Int {
        (report.map { $0.cards.count + $0.old.count } ?? 0) + (twoFactor?.missing.count ?? 0)
    }

    func refresh(_ session: VaultSession, network: Bool) {
        report = try? session.watchtower()
        guard network else { return }
        Task { await loadTwoFactor(session) }
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
