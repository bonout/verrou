import AppKit
import Observation
import SwiftUI

/// Emergency access: my trusted contacts, those who chose me, and a
/// grantor's vault opened read-only (separate Rust object, emptied on
/// lock).
@MainActor
@Observable
final class EmergencyModel {
    private(set) var trusted: [EmergencyContact] = []
    private(set) var granted: [EmergencyContact] = []
    private(set) var loaded = false
    var busy = false
    var error: String?
    var notice: String?
    /// Invitation (or edit of a contact) in progress.
    var invite: InviteDraft?
    /// Confirmation of a contact: their key's fingerprint, to check with them.
    var confirmation: Confirmation?
    /// A grantor's vault open.
    var grantorVault: GrantorVault?
    /// Access displayed in the right column (one of my contacts, or a grantor
    /// who chose me).
    var selection: String?
    /// Access request to confirm.
    var confirmRequest: EmergencyContact?
    /// Deletion (or giving up) to confirm.
    var confirmDelete: EmergencyContact?

    struct InviteDraft: Identifiable {
        let id = UUID()
        /// `nil`: new invitation.
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

    /// The selected access, and whether it is one of my contacts (`trusted`).
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

    /// On lock: lists, drafts and the grantor's vault forgotten.
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

/// A grantor's vault, read-only: summaries, fields revealed on request (and
/// forgotten when closed).
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

    /// Sidebar or Vault menu: the emergency access pane in the main window.
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
        await emergencyAction(draft.contactID == nil ? String(localized: "Invitation sent to \(draft.email).")
                                                      : String(localized: "Contact updated.")) {
            if let id = draft.contactID {
                try await self.session.updateEmergencyContact(id: id, accessType: draft.type, waitTimeDays: UInt32(draft.waitDays))
            } else {
                try await self.session.inviteEmergencyContact(email: draft.email, accessType: draft.type,
                                                              waitTimeDays: UInt32(draft.waitDays))
            }
            self.emergency.invite = nil
        }
    }

    /// Before confirming: the fingerprint of the contact's public key.
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
        await emergencyAction(String(localized: "\(confirmation.contact.displayName) is confirmed as an emergency contact.")) {
            try await self.session.confirmEmergencyContact(id: confirmation.contact.id, granteeId: confirmation.granteeID,
                                                           fingerprint: confirmation.fingerprint)
        }
    }

    func deleteEmergency(_ contact: EmergencyContact) async {
        await emergencyAction(String(localized: "Emergency access deleted.")) {
            try await self.session.deleteEmergencyAccess(id: contact.id)
        }
    }

    func requestEmergency(_ contact: EmergencyContact) async {
        await emergencyAction(String(localized: "Request sent to \(contact.displayName).")) {
            try await self.session.requestEmergencyAccess(id: contact.id)
        }
    }

    func approveEmergency(_ contact: EmergencyContact) async {
        await emergencyAction(String(localized: "Access granted to \(contact.displayName).")) {
            try await self.session.approveEmergencyAccess(id: contact.id)
        }
    }

    func rejectEmergency(_ contact: EmergencyContact) async {
        await emergencyAction(String(localized: "Access denied to \(contact.displayName).")) {
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
                emergency.notice = String(localized: "\(Int(vault.failures())) item(s) of \(contact.displayName)'s vault could not be decrypted.")
            }
        } catch {
            emergency.error = Self.describe(error)
        }
    }

    /// Copies a field of the grantor's vault (concealed clipboard, cleared
    /// after the chosen delay).
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
        let delay = DurationLabel.short(Clipboard.clearDelay)
        emergency.notice = field.secret ? String(localized: "\(field.label) copied (cleared from the clipboard in \(delay)).")
                                         : String(localized: "\(field.label) copied.")
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
        name ?? email ?? String(localized: "Contact")
    }
}

extension EmergencyType {
    var label: String {
        switch self {
        case .view: String(localized: "View only")
        case .takeover: String(localized: "Takeover")
        }
    }
}
