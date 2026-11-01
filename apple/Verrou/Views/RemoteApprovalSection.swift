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
            return "Away from the Mac, approve the terminal's requests with Face ID on the iPhone, sealed end to end through iCloud."
        }
        return remote.unlockEnabled
            ? "The iPhone is asked after 15 s, or right away when the Mac is locked or idle; for 12 hours it can also unlock the vault for the terminal."
            : "The iPhone is asked after 15 s, or right away when the Mac is locked or idle. The vault must be unlocked on the Mac."
    }

    private var pairingShown: Binding<Bool> {
        Binding(get: { remote.pairing != nil }, set: { if !$0 { remote.cancelPairing() } })
    }
}

/// The QR code to scan with the iPhone, until it answers.
private struct PairingSheet: View {
    let remote: RemoteApprovals

    var body: some View {
        VStack(spacing: 16) {
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
                        .background(.white, in: RoundedRectangle(cornerRadius: Theme.cardRadius))
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
