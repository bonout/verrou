import Observation
import UIKit

/// « Passkey possible » sur l'iPhone : identifiants dont le site accepte les
/// passkeys, d'après l'annuaire passkeys.2fa.directory (téléchargé en
/// entier, gardé 7 jours par le cœur Rust ; aucune requête par site).
///
/// « Créer une passkey » ouvre la page du site dans Safari : Verrou y est le
/// fournisseur de remplissage, la passkey créée s'enregistre donc dans le
/// coffre (extension VerrouAutoFill), dans l'élément du même compte.
@MainActor
@Observable
final class PhonePasskeyAudit {
    /// `nil` : pas encore chargé (ou indisponible, voir `error`).
    private(set) var report: PasskeyReport?
    private(set) var loading = false
    private(set) var error: String?
    /// Élément dont on cherche la page de création.
    private(set) var opening: String?
    /// Parcours de bout en bout : montrer la section en haut de l'audit.
    var focus = false

    /// Ce que les sites ont signalé à l'extension (iOS 26) et qui concerne
    /// encore le coffre.
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

    /// Ouvre la page où créer la passkey : celle que le site publie
    /// (`/.well-known/passkey-endpoints`, vérifiée pour ce site seul), sinon
    /// une page connue, sinon l'accueil du site. Rend le message à afficher.
    func open(_ candidate: PasskeyCandidate, session: VaultSession) async -> Toast? {
        guard opening == nil else { return nil }
        opening = candidate.item.id
        defer { opening = nil }
        let hint = "Quand Safari propose d'enregistrer la passkey, choisissez Verrou."
        do {
            let page = try await session.passkeySetupPage(id: candidate.item.id)
            guard let url = URL(string: page.url) else { return nil }
            await UIApplication.shared.open(url)
            switch page.source {
            case .wellKnown, .known:
                return Toast(message: "Page des passkeys ouverte", detail: hint, seconds: 6)
            case .home:
                return Toast(message: "Ce site n'indique pas sa page de passkeys",
                             detail: "Cherchez « passkey » dans les réglages de sécurité du compte. " + hint,
                             seconds: 8)
            }
        } catch {
            return Toast(message: "Page introuvable", detail: ErrorText.describe(error), failure: true)
        }
    }
}

extension PhoneModel {
    /// Charge « Passkey possible » (coffre fictif : extrait embarqué de
    /// l'annuaire, sans réseau).
    func refreshPasskeyAudit() {
        guard lockState == .unlocked else { return }
        Task { await passkeyAudit.load(session) }
    }

    /// Passkeys créées par Safari en arrière-plan après un remplissage
    /// (création conditionnelle, extension VerrouAutoFill) : enregistrées
    /// dans leur identifiant maintenant que le coffre est ouvert.
    func finishPendingPasskeys() async {
        guard mode == .vaultwarden, lockState == .unlocked, session.pendingPasskeys() > 0 else { return }
        guard let titles = try? await session.finishPendingPasskeys(), !titles.isEmpty,
              lockState == .unlocked else { return }
        afterWrite()
        publishAutofillIdentities()
        if audit != nil { refreshPasskeyAudit() }
        toast = Toast(message: titles.count == 1 ? "Passkey enregistrée" : "\(titles.count) passkeys enregistrées",
                      detail: "Créée par Safari pour « \(titles.joined(separator: " », « ")) » ; le mot de passe reste en secours.",
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
