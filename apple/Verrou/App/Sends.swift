import AppKit
import Observation
import SwiftUI

/// Envois (Bitwarden Send) : la liste de la fenêtre « Envois » et l'écran de
/// création ou de modification. Le texte et le lien (qui porte la clé) ne
/// viennent de Rust qu'à la demande : copie du lien, ouverture de l'écran.
@MainActor
@Observable
final class SendsModel {
    private(set) var items: [SendSummary] = []
    private(set) var loaded = false
    var busy = false
    var error: String?
    /// Écran de création ou de modification ouvert.
    var composer: Composer?
    /// Dernier envoi créé ou lien copié, pour le signaler dans la fenêtre.
    var notice: String?

    struct Composer: Identifiable {
        let id = UUID()
        /// `nil` : création.
        let sendID: String?
        let fields: SendFields
        let hasPassword: Bool
        /// Prérempli depuis un élément du coffre (titre de l'élément).
        let source: String?
    }

    func set(_ items: [SendSummary]) {
        self.items = items
        loaded = true
    }

    /// Au verrouillage : rien ne doit survivre, brouillon compris.
    func clear() {
        items = []
        loaded = false
        busy = false
        error = nil
        composer = nil
        notice = nil
    }
}

extension AppModel {
    var sendsAvailable: Bool { mode == .vaultwarden && lockState == .unlocked }

    func reloadSends() async {
        guard sendsAvailable else { return }
        do {
            sends.set(try await session.sends())
            sends.error = nil
        } catch {
            sends.error = Self.describe(error)
        }
    }

    func newSend() {
        sends.notice = nil
        sends.composer = .init(sendID: nil, fields: session.newSendFields(), hasPassword: false, source: nil)
    }

    func editSend(_ send: SendSummary) async {
        do {
            let fields = try await session.sendFields(id: send.id)
            sends.composer = .init(sendID: send.id, fields: fields, hasPassword: send.hasPassword, source: nil)
        } catch {
            sends.error = Self.describe(error)
        }
    }

    /// « Envoyer de façon sécurisée… » depuis un élément : un envoi prérempli
    /// avec son mot de passe (ou ses notes), à confirmer dans la fenêtre des envois.
    func composeSend(from summary: ItemSummary, openWindow: @escaping (String) -> Void) {
        if awaitsConfirmation(summary.id, retry: { [weak self] in
            self?.composeSend(from: summary, openWindow: openWindow)
        }) { return }
        let field = summary.category == .login ? "password" : "notes"
        do {
            let fields = try session.sendFieldsForField(itemId: summary.id, fieldId: field)
            sends.notice = nil
            sends.composer = .init(sendID: nil, fields: fields, hasPassword: false, source: summary.title)
            openWindow("sends")
        } catch {
            toast = Toast(message: "Envoi impossible", detail: Self.describe(error), failure: true)
        }
    }

    /// Crée ou modifie l'envoi ; à la création, le lien est copié.
    func saveSend(_ fields: SendFields, id: String?) async {
        guard !sends.busy else { return }
        sends.busy = true
        defer { sends.busy = false }
        do {
            if let id {
                try await session.updateSend(id: id, fields: fields)
                sends.notice = "Envoi « \(fields.name) » enregistré."
            } else {
                let created = try await session.createSend(fields: fields)
                copy(created.link, label: "Lien de l'envoi", secret: true)
                sends.notice = "Envoi « \(fields.name) » créé : lien copié (effacé du presse-papiers dans 90 s)."
            }
            sends.composer = nil
            sends.error = nil
            afterWrite(select: selection)
            await reloadSends()
        } catch {
            sends.error = Self.describe(error)
        }
    }

    func copySendLink(_ send: SendSummary) async {
        do {
            let link = try await session.sendLink(id: send.id)
            copy(link, label: "Lien de l'envoi", secret: true)
            sends.notice = "Lien de « \(send.name) » copié (effacé du presse-papiers dans 90 s)."
        } catch {
            sends.error = Self.describe(error)
        }
    }

    func deleteSend(_ send: SendSummary) async {
        await sendAction("Envoi « \(send.name) » supprimé.") { try await self.session.deleteSend(id: send.id) }
    }

    func removeSendPassword(_ send: SendSummary) async {
        await sendAction("Mot de passe retiré de « \(send.name) ».") {
            try await self.session.removeSendPassword(id: send.id)
        }
    }

    private func sendAction(_ done: String, _ action: @escaping () async throws -> Void) async {
        guard !sends.busy else { return }
        sends.busy = true
        defer { sends.busy = false }
        do {
            try await action()
            sends.notice = done
            sends.error = nil
            afterWrite(select: selection)
            await reloadSends()
        } catch {
            sends.error = Self.describe(error)
        }
    }
}
