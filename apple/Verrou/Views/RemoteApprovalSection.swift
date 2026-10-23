import SwiftUI

/// Settings › Security: the iPhones that approve the terminal's requests
/// when you are away from the Mac (`RemoteApprovals`).
struct RemoteApprovalSection: View {
    @Bindable var remote: RemoteApprovals

    var body: some View {
        Section {
            if let reason = remote.unavailableReason {
                Text(reason)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(remote.phones) { phone in
                    LabeledContent {
                        Button("Remove", role: .destructive) { remote.remove(phone) }
                    } label: {
                        Label(phone.name, systemImage: "iphone")
                        Text("Paired \(phone.paired.formatted(date: .abbreviated, time: .omitted))")
                    }
                }
                Button(remote.phones.isEmpty ? "Pair an iPhone…" : "Pair Another iPhone…") {
                    Task { await remote.startPairing() }
                }
                .disabled(!remote.available || remote.pairing != nil)
                if !remote.phones.isEmpty {
                    Toggle("Also unlock from the iPhone", isOn: $remote.unlockEnabled)
                }
            }
        } header: {
            Text("Approve from the iPhone")
        } footer: {
            Text(footer)
                .foregroundStyle(.secondary)
        }
        .sheet(isPresented: pairingShown) {
            PairingSheet(remote: remote)
        }
    }

    private var footer: LocalizedStringKey {
        if remote.phones.isEmpty {
            return "Away from the Mac, the terminal's requests (a secret, an SSH signature) go to Verrou on the iPhone: Face ID approves them. Through your iCloud account, sealed end to end."
        }
        return remote.unlockEnabled
            ? "At the Mac, Touch ID as before; the iPhone is asked after 15 s, or right away when the screen is locked or idle. For 12 hours after an unlock on this Mac, the iPhone can also unlock the vault for the terminal: the window stays locked, the vault locks again 5 minutes after the last approval."
            : "At the Mac, Touch ID as before; the iPhone is asked after 15 s, or right away when the screen is locked or idle. The vault must be unlocked on the Mac."
    }

    private var pairingShown: Binding<Bool> {
        Binding(get: { remote.pairing != nil }, set: { if !$0 { remote.cancelPairing() } })
    }
}

/// The QR code to scan with the iPhone, until it answers.
private struct PairingSheet: View {
    let remote: RemoteApprovals

    var body: some View {
        VStack(spacing: 18) {
            Text("Pair an iPhone")
                .font(.title2.weight(.semibold))
            switch remote.pairing?.state {
            case .failed(let message):
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .frame(maxWidth: 340)
            default:
                if let invite = remote.pairing?.invite, let cgImage = QRCode.cgImage(invite.qrText) {
                    Image(decorative: cgImage, scale: 1)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 220, height: 220)
                        .padding(12)
                        .background(.white, in: RoundedRectangle(cornerRadius: 14))
                        .accessibilityLabel("Pairing QR code")
                }
                Text("In Verrou on the iPhone: Settings › Approve from the Mac › Pair with a Mac, then scan this code. Both devices must use the same iCloud account.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 340)
                ProgressView()
                    .controlSize(.small)
            }
            Button("Cancel") { remote.cancelPairing() }
                .keyboardShortcut(.cancelAction)
        }
        .padding(28)
        .frame(width: 420)
    }
}
