import AVFoundation
import SwiftUI
import VisionKit

/// A request from the Mac: Face ID, then what is asked, then Approve or
/// Deny. Shown above everything (`ApprovalWindow`).
struct ApprovalScreen: View {
    let approver: RemoteApprover

    var body: some View {
        ZStack {
            Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
            if let pending = approver.current {
                card(pending)
                    .padding(20)
                    .transition(.scale(scale: 0.96).combined(with: .opacity))
            }
        }
        .animation(.snappy, value: approver.current?.id)
    }

    private func card(_ pending: RemoteApprover.Pending) -> some View {
        VStack(spacing: 18) {
            Image(systemName: "laptopcomputer.and.iphone")
                .font(.system(size: 40, weight: .semibold))
                .foregroundStyle(Theme.accent)
            Text("Request from “\(pending.mac.name)”")
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
            content(pending)
        }
        .padding(24)
        .frame(maxWidth: 420)
        .glassSurface(RoundedRectangle(cornerRadius: 32, style: .continuous))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("remote-approval")
    }

    @ViewBuilder
    private func content(_ pending: RemoteApprover.Pending) -> some View {
        switch pending.state {
        case .sealed:
            Text("Face ID shows what is asked.")
                .foregroundStyle(.secondary)
            Button {
                Task { await approver.open() }
            } label: {
                Label("Show with Face ID", systemImage: "faceid")
                    .frame(maxWidth: .infinity, minHeight: 34)
            }
            .glassButton(prominent: true)
            .controlSize(.large)
            Button("Not now", role: .cancel) { approver.dismiss() }
            // Opened right away: it is what the user came for.
            .task(id: pending.id) { await approver.open() }
        case .ready(let opened):
            let request = opened.request
            Text("\(request.client.capitalizedFirst) wants to \(request.action).")
                .font(.body.weight(.medium))
                .multilineTextAlignment(.center)
            if request.kind == .unlock {
                Text("The Mac's window stays locked; the vault locks again 5 minutes after the last approval.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            ExpiryText(expires: request.expires)
            HStack(spacing: 12) {
                Button(role: .destructive) {
                    Task { await approver.answer(approved: false) }
                } label: {
                    Text("Deny").frame(maxWidth: .infinity, minHeight: 34)
                }
                .glassButton(prominent: false)
                Button {
                    Task { await approver.answer(approved: true) }
                } label: {
                    Text("Approve").frame(maxWidth: .infinity, minHeight: 34)
                }
                .glassButton(prominent: true)
                .accessibilityIdentifier("remote-approve")
            }
            .controlSize(.large)
        case .sending:
            ProgressView()
                .controlSize(.large)
                .frame(height: 60)
        case .answered(let approved):
            Label(approved ? "Approved" : "Denied", systemImage: approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.headline)
                .foregroundStyle(approved ? .green : .secondary)
                .frame(height: 60)
        case .failed(let message):
            Text(message)
                .foregroundStyle(.orange)
                .multilineTextAlignment(.center)
            Button("Close") { approver.dismiss() }
                .glassButton(prominent: false)
        }
    }
}

/// Seconds left: past it, the Mac stops waiting.
private struct ExpiryText: View {
    let expires: Date

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(expires.timeIntervalSince(context.date)))
            Text(left > 0 ? "Expires in \(left) s" : "Expired")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }
}

private extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}

// MARK: Settings

/// Settings › Approve from the Mac: the paired Macs, and pairing.
struct RemoteApprovalSettingsView: View {
    @Environment(PhoneModel.self) private var model
    @State private var scanning = false
    @State private var message: String?

    var body: some View {
        let approver = model.remote
        List {
            Section {
                ForEach(approver.macs) { mac in
                    VStack(alignment: .leading, spacing: 2) {
                        Label(mac.name, systemImage: "laptopcomputer")
                        Text("Paired \(mac.paired.formatted(date: .abbreviated, time: .omitted))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .swipeActions {
                        Button("Remove", role: .destructive) { approver.remove(mac) }
                    }
                }
                Button {
                    scanning = true
                } label: {
                    Label("Pair with a Mac", systemImage: "qrcode.viewfinder")
                }
                .disabled(approver.pairingBusy)
            } footer: {
                Text("On the Mac: Verrou › Settings › Security › Pair an iPhone, then scan the code. When you are away from the Mac, the terminal's requests (a secret, an SSH signature, the unlock) come here: Face ID opens them, you approve or deny. Through your iCloud account, sealed end to end; the vault of this iPhone is not involved.")
            }
            if let message {
                Section { Text(message) }
            }
        }
        .navigationTitle("Approve from the Mac")
        .sheet(isPresented: $scanning) {
            PairingScanner { text in
                scanning = false
                Task {
                    do {
                        let name = try await approver.pair(qrText: text)
                        message = String(localized: "Paired with “\(name)”.")
                    } catch {
                        message = RemoteApprover.describe(error)
                    }
                }
            }
        }
    }
}

/// The camera, for the Mac's QR code.
private struct PairingScanner: View {
    let found: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var done = false
    @State private var allowed: Bool?

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                if allowed == true {
                    if DataScannerViewController.isSupported, DataScannerViewController.isAvailable {
                        DataScannerView(found: take)
                    } else {
                        MetadataScannerView(found: take)
                    }
                    ViewfinderFrame()
                        .frame(width: 230, height: 230)
                        .allowsHitTesting(false)
                } else if allowed == false {
                    Text("Allow the camera in Settings to scan the Mac's code.")
                        .foregroundStyle(.white)
                        .multilineTextAlignment(.center)
                        .padding()
                }
            }
            .navigationTitle("Scan the Mac's code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .task {
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized: allowed = true
            case .notDetermined: allowed = await AVCaptureDevice.requestAccess(for: .video)
            default: allowed = false
            }
        }
    }

    /// Only the Mac's codes, once.
    private func take(_ text: String) {
        guard !done, (try? RemoteApproval.Invite(qrText: text)) != nil else { return }
        done = true
        found(text)
    }
}
