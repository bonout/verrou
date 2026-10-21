import SwiftUI

/// Passkeys of a login: site, user, creation date. The private key never
/// leaves the Rust core; it can only be deleted.
struct PasskeysSection: View {
    let itemID: String
    let passkeys: [PasskeyInfo]

    var body: some View {
        if !passkeys.isEmpty {
            SectionTitle(String(localized: "Passkeys"))
            FieldCard {
                ForEach(Array(passkeys.enumerated()), id: \.element.credentialId) { index, passkey in
                    if index > 0 { Divider().padding(.leading, 14) }
                    PasskeyRow(itemID: itemID, passkey: passkey)
                }
            }
        }
    }
}

private struct PasskeyRow: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let passkey: PasskeyInfo
    @State private var hovering = false
    @State private var confirming = false

    private var site: String {
        if let name = passkey.rpName, !name.isEmpty, name != passkey.rpId {
            return "\(name) · \(passkey.rpId)"
        }
        return passkey.rpId
    }

    private var created: String {
        let format = Date.FormatStyle(date: .long, time: .omitted)
        return Date(timeIntervalSince1970: TimeInterval(passkey.created)).formatted(format)
    }

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "person.badge.key.fill")
                .font(.system(size: 16))
                .foregroundStyle(Theme.accent)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 4) {
                Text(site).font(.caption).foregroundStyle(.secondary)
                Text(passkey.userName ?? String(localized: "Unnamed user")).textSelection(.enabled)
                Text("Passkey created on \(created)").font(.caption).foregroundStyle(.tertiary)
            }
            Spacer(minLength: 8)
            if model.canEdit {
                IconButton(symbol: "trash", help: "Delete the passkey") { confirming = true }
                    .opacity(hovering ? 1 : 0)
                    .disabled(model.editorBusy)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .background(hovering ? Color.primary.opacity(0.035) : .clear)
        .onHover { hovering = $0 }
        .accessibilityElement(children: .combine)
        .confirmationDialog("Delete the passkey of “\(passkey.rpId)”?", isPresented: $confirming) {
            Button("Delete", role: .destructive) {
                Task { await model.deletePasskey(itemID: itemID, credentialID: passkey.credentialId) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You will no longer be able to log in to this site with it. Also remove it from the site's security settings.")
        }
    }
}
