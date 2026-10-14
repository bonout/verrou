import AppKit
import Observation
import SwiftUI

/// Accès d'urgence : mes contacts de confiance, ceux qui m'ont choisi, et le
/// coffre d'un concédant ouvert en lecture seule (objet Rust à part, vidé au
/// verrouillage).
@MainActor
@Observable
final class EmergencyModel {
    private(set) var trusted: [EmergencyContact] = []
    private(set) var granted: [EmergencyContact] = []
    private(set) var loaded = false
    var busy = false
    var error: String?
    var notice: String?
    /// Invitation (ou modification d'un contact) en cours.
    var invite: InviteDraft?
    /// Confirmation d'un contact : l'empreinte de sa clé, à vérifier avec lui.
    var confirmation: Confirmation?
    /// Coffre d'un concédant ouvert.
    var grantorVault: GrantorVault?
    /// Accès affiché dans la colonne de droite (un de mes contacts, ou un
    /// concédant qui m'a choisi).
    var selection: String?
    /// Demande d'accès à confirmer.
    var confirmRequest: EmergencyContact?
    /// Suppression (ou renoncement) à confirmer.
    var confirmDelete: EmergencyContact?

    struct InviteDraft: Identifiable {
        let id = UUID()
        /// `nil` : nouvelle invitation.
        let contactID: String?
        var email: String
        var type: EmergencyType
        var waitDays: Int
    }

    struct Confirmation: Identifiable {
        let id = UUID()
        let contact: EmergencyContact
        let granteeID: String
        let fingerprint: String
    }

    /// L'accès sélectionné, et s'il s'agit d'un de mes contacts (`trusted`).
    var selected: (contact: EmergencyContact, trusted: Bool)? {
        guard let selection else { return nil }
        if let contact = trusted.first(where: { $0.id == selection }) { return (contact, true) }
        if let contact = granted.first(where: { $0.id == selection }) { return (contact, false) }
        return nil
    }

    func set(_ overview: EmergencyOverview) {
        trusted = overview.trusted
        granted = overview.granted
        loaded = true
        if selected == nil {
            selection = (trusted + granted).first?.id
        }
    }

    func inviteNew() {
        invite = .init(contactID: nil, email: "", type: .view, waitDays: 7)
    }

    func edit(_ contact: EmergencyContact) {
        invite = .init(contactID: contact.id, email: contact.email ?? "",
                       type: contact.accessType, waitDays: Int(contact.waitTimeDays))
    }

    /// Au verrouillage : listes, brouillons et coffre du concédant oubliés.
    func clear() {
        trusted = []
        granted = []
        loaded = false
        busy = false
        error = nil
        notice = nil
        invite = nil
        confirmation = nil
        selection = nil
        confirmRequest = nil
        confirmDelete = nil
        closeGrantorVault()
    }

    func closeGrantorVault() {
        grantorVault?.vault.close()
        grantorVault = nil
    }
}

/// Le coffre d'un concédant, en lecture seule : résumés, champs révélés à la
/// demande (et oubliés à la fermeture).
@MainActor
@Observable
final class GrantorVault: Identifiable {
    let id = UUID()
    let vault: EmergencyVault
    let grantor: String
    let summaries: [ItemSummary]
    var selection: String?
    var query = ""
    var revealed: [String: String] = [:]

    init(vault: EmergencyVault, grantor: String) {
        self.vault = vault
        self.grantor = grantor
        summaries = (try? vault.summaries()) ?? []
        selection = summaries.first?.id
    }

    var rows: [ItemSummary] {
        let needle = query.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else { return summaries }
        return summaries.filter {
            $0.title.localizedCaseInsensitiveContains(needle) || $0.subtitle.localizedCaseInsensitiveContains(needle)
        }
    }

    var detail: ItemDetail? {
        selection.flatMap { try? vault.detail(id: $0) }
    }
}

extension AppModel {
    var emergencyAvailable: Bool { mode == .vaultwarden && lockState == .unlocked }

    /// Barre latérale ou menu Coffre : le volet des accès d'urgence dans la
    /// fenêtre principale.
    func openEmergency() {
        guard emergencyAvailable else { return }
        showMainWindow()
        pane = .emergency
    }

    func reloadEmergency() async {
        guard emergencyAvailable else { return }
        do {
            emergency.set(try await session.emergencyAccess())
            emergency.error = nil
        } catch {
            emergency.error = Self.describe(error)
        }
    }

    func saveInvite(_ draft: EmergencyModel.InviteDraft) async {
        await emergencyAction(draft.contactID == nil ? "Invitation envoyée à \(draft.email)." : "Contact modifié.") {
            if let id = draft.contactID {
                try await self.session.updateEmergencyContact(id: id, accessType: draft.type, waitTimeDays: UInt32(draft.waitDays))
            } else {
                try await self.session.inviteEmergencyContact(email: draft.email, accessType: draft.type,
                                                              waitTimeDays: UInt32(draft.waitDays))
            }
            self.emergency.invite = nil
        }
    }

    /// Avant de confirmer : l'empreinte de la clé publique du contact.
    func prepareConfirmation(_ contact: EmergencyContact) async {
        guard let granteeID = contact.userId else { return }
        do {
            let fingerprint = try await session.emergencyContactFingerprint(granteeId: granteeID)
            emergency.confirmation = .init(contact: contact, granteeID: granteeID, fingerprint: fingerprint)
        } catch {
            emergency.error = Self.describe(error)
        }
    }

    func confirmContact(_ confirmation: EmergencyModel.Confirmation) async {
        emergency.confirmation = nil
        await emergencyAction("\(confirmation.contact.displayName) est confirmé comme contact d'urgence.") {
            try await self.session.confirmEmergencyContact(id: confirmation.contact.id, granteeId: confirmation.granteeID,
                                                           fingerprint: confirmation.fingerprint)
        }
    }

    func deleteEmergency(_ contact: EmergencyContact) async {
        await emergencyAction("Accès d'urgence supprimé.") {
            try await self.session.deleteEmergencyAccess(id: contact.id)
        }
    }

    func requestEmergency(_ contact: EmergencyContact) async {
        await emergencyAction("Demande envoyée à \(contact.displayName).") {
            try await self.session.requestEmergencyAccess(id: contact.id)
        }
    }

    func approveEmergency(_ contact: EmergencyContact) async {
        await emergencyAction("Accès accordé à \(contact.displayName).") {
            try await self.session.approveEmergencyAccess(id: contact.id)
        }
    }

    func rejectEmergency(_ contact: EmergencyContact) async {
        await emergencyAction("Accès refusé à \(contact.displayName).") {
            try await self.session.rejectEmergencyAccess(id: contact.id)
        }
    }

    func openGrantorVault(_ contact: EmergencyContact) async {
        guard !emergency.busy else { return }
        emergency.busy = true
        defer { emergency.busy = false }
        do {
            let vault = try await session.openEmergencyVault(id: contact.id)
            guard lockState == .unlocked else { vault.close(); return }
            emergency.grantorVault = GrantorVault(vault: vault, grantor: contact.displayName)
            if vault.failures() > 0 {
                emergency.notice = "\(vault.failures()) élément(s) du coffre de \(contact.displayName) n'ont pas pu être déchiffrés."
            }
        } catch {
            emergency.error = Self.describe(error)
        }
    }

    /// Copie un champ du coffre du concédant (presse-papiers masqué, 90 s).
    func copyGrantorField(_ field: FieldView, itemID: String, in vault: GrantorVault) {
        let value: String?
        if field.fieldType == .totp {
            value = (try? vault.vault.totp(id: itemID, unixTime: UInt64(Date().timeIntervalSince1970)))?.code
        } else if field.secret {
            value = try? vault.vault.reveal(id: itemID, fieldId: field.id)
        } else {
            value = field.value
        }
        guard let value else { return }
        copy(value, label: field.label, secret: field.secret)
        emergency.notice = "\(field.label) copié" + (field.secret ? " (effacé du presse-papiers dans 90 s)." : ".")
    }

    private func emergencyAction(_ done: String, _ action: @escaping () async throws -> Void) async {
        guard !emergency.busy else { return }
        emergency.busy = true
        defer { emergency.busy = false }
        do {
            try await action()
            emergency.notice = done
            emergency.error = nil
            await reloadEmergency()
        } catch {
            emergency.error = Self.describe(error)
        }
    }
}

extension EmergencyContact {
    var displayName: String {
        name ?? email ?? "Contact"
    }
}

extension EmergencyType {
    var label: String {
        switch self {
        case .view: "Lecture seule"
        case .takeover: "Prise de contrôle"
        }
    }
}
