import AVFoundation
import PhotosUI
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import VisionKit

/// "Scan a QR code" sheet: the camera (frame and instruction), then a
/// photo or screenshot, or the clipboard; next the preview (service,
/// account, first code) and saving.
struct OTPScanSheet: View {
    @Environment(PhoneModel.self) private var model
    @Bindable var flow: OTPScanFlow

    var body: some View {
        NavigationStack {
            Group {
                if let result = flow.result {
                    OTPPreviewView(flow: flow, result: result)
                        .transition(.opacity)
                } else {
                    OTPScannerPane(flow: flow)
                        .transition(.opacity)
                }
            }
            .navigationTitle(flow.result == nil ? "Scan a QR code" : "One-time code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { model.otpScan = nil }
                }
                // From a link: no camera to go back to.
                if flow.result != nil, flow.purpose != .link {
                    ToolbarItem(placement: .primaryAction) {
                        Button("Scan again", systemImage: "qrcode.viewfinder") { flow.rescan() }
                            .disabled(flow.busy)
                    }
                }
            }
        }
        .interactiveDismissDisabled(flow.busy)
    }
}

// MARK: Sources

/// Camera at the top, other sources below.
private struct OTPScannerPane: View {
    @Environment(PhoneModel.self) private var model
    @Bindable var flow: OTPScanFlow
    @State private var photo: PhotosPickerItem?
    @State private var clipboardHasContent = UIPasteboard.general.hasStrings
        || UIPasteboard.general.hasImages || UIPasteboard.general.hasURLs

    var body: some View {
        VStack(spacing: 0) {
            CameraArea(flow: flow)
                .frame(maxHeight: .infinity)
            sources
        }
        .background(Color(.systemGroupedBackground))
        .task { await flow.prepareCamera() }
        .onChange(of: photo) { _, item in
            guard let item else { return }
            Task {
                // The image's bytes only live while it is being read.
                if let data = try? await item.loadTransferable(type: Data.self) {
                    await flow.handle(imageData: data, session: model.session)
                } else {
                    flow.error = String(localized: "Unreadable image.")
                }
                photo = nil
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIPasteboard.changedNotification)) { _ in
            refreshClipboard()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in
            refreshClipboard()
        }
    }

    /// Knowing whether the clipboard holds something doesn't read it (no
    /// paste alert); only `PasteButton` reads it, on tap.
    private func refreshClipboard() {
        clipboardHasContent = UIPasteboard.general.hasStrings || UIPasteboard.general.hasImages
            || UIPasteboard.general.hasURLs
    }

    private var sources: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let error = flow.error {
                ErrorLabel(text: error)
                    .accessibilityIdentifier("otp-scan-error")
            }
            PhotosPicker(selection: $photo, matching: .images, preferredItemEncoding: .current) {
                Label("Photo or screenshot", systemImage: "photo.on.rectangle.angled")
                    .font(.body.weight(.semibold))
                    .frame(maxWidth: .infinity, minHeight: 34)
            }
            .controlSize(.large)
            .glassButton(prominent: flow.camera == .denied || flow.camera == .unavailable)
            .disabled(flow.busy)
            .accessibilityIdentifier("otp-scan-photo")
            if clipboardHasContent {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Paste from the clipboard")
                            .font(.callout.weight(.semibold))
                        Text("otpauth:// link or image of a QR code")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 8)
                    PasteButton(supportedContentTypes: [.image, .url, .utf8PlainText, .plainText]) { providers in
                        Task { await flow.handle(pasted: providers, session: model.session) }
                    }
                    .labelStyle(.titleAndIcon)
                    .buttonBorderShape(.capsule)
                    .tint(Theme.accent)
                    .disabled(flow.busy)
                }
            }
            Text("On this iPhone, take a screenshot of the QR code shown by the site, then choose it here. The image is not kept.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 20)
        .padding(.top, 16)
        .padding(.bottom, 12)
        .overlay(alignment: .center) {
            if flow.busy { ProgressView().controlSize(.large) }
        }
    }
}

/// Camera image with the frame, or the reason it is missing.
private struct CameraArea: View {
    @Environment(PhoneModel.self) private var model
    @Bindable var flow: OTPScanFlow

    var body: some View {
        ZStack {
            Color.black
            switch flow.camera {
            case .checking:
                ProgressView().tint(.white)
            case .dataScanner:
                DataScannerView { flow.handle(text: $0, session: model.session, fromCamera: true) }
                viewfinder
            case .metadata:
                MetadataScannerView { flow.handle(text: $0, session: model.session, fromCamera: true) }
                viewfinder
            case .denied:
                unavailable(symbol: "video.slash.fill", title: "Camera access denied",
                            text: "Allow the camera in Settings to scan, or choose a screenshot of the QR code.",
                            settings: true)
            case .unavailable:
                unavailable(symbol: "camera.fill", title: "Camera unavailable",
                            text: "Choose a photo or a screenshot of the QR code.", settings: false)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
        .padding(.horizontal, 12)
        .padding(.top, 8)
        .accessibilityIdentifier("otp-scan-camera")
    }

    /// Rounded-corner frame and instruction.
    private var viewfinder: some View {
        VStack(spacing: 22) {
            ViewfinderFrame()
                .frame(width: 230, height: 230)
            Text("Place the site's QR code in the frame")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 9)
                .glassSurface(Capsule())
        }
        .allowsHitTesting(false)
        .accessibilityElement(children: .combine)
    }

    private func unavailable(symbol: String, title: LocalizedStringKey, text: LocalizedStringKey, settings: Bool) -> some View {
        VStack(spacing: 12) {
            ZStack {
                ViewfinderFrame()
                    .frame(width: 150, height: 150)
                    .opacity(0.45)
                Image(systemName: symbol)
                    .font(.system(size: 38, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.85))
            }
            .padding(.bottom, 6)
            Text(title)
                .font(.headline)
                .foregroundStyle(.white)
            Text(text)
                .font(.callout)
                .foregroundStyle(.white.opacity(0.75))
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if settings, let url = URL(string: UIApplication.openSettingsURLString) {
                Link(destination: url) {
                    Label("Open Settings", systemImage: "gear")
                        .font(.callout.weight(.semibold))
                }
                .controlSize(.regular)
                .glassButton(prominent: true)
                .padding(.top, 4)
            }
        }
        .padding(28)
    }
}

/// Four rounded corners, like the Camera app.
struct ViewfinderFrame: View {
    var body: some View {
        GeometryReader { geometry in
            let size = geometry.size
            let corner: CGFloat = 34
            let radius: CGFloat = 18
            Path { path in
                let corners: [(CGFloat, CGFloat, CGFloat, CGFloat)] = [
                    (0, 0, 1, 1), (size.width, 0, -1, 1), (0, size.height, 1, -1), (size.width, size.height, -1, -1),
                ]
                for (x, y, dx, dy) in corners {
                    path.move(to: CGPoint(x: x, y: y + dy * corner))
                    path.addLine(to: CGPoint(x: x, y: y + dy * radius))
                    path.addQuadCurve(to: CGPoint(x: x + dx * radius, y: y), control: CGPoint(x: x, y: y))
                    path.addLine(to: CGPoint(x: x + dx * corner, y: y))
                }
            }
            .stroke(.white, style: StrokeStyle(lineWidth: 5, lineCap: .round, lineJoin: .round))
            .shadow(color: .black.opacity(0.35), radius: 6)
        }
    }
}

// MARK: Camera

/// VisionKit: QR codes only, the system's highlighting and guidance.
/// No image is kept, only the code's text comes up.
struct DataScannerView: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: true,
            isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        context.coordinator.found = found
        if !scanner.isScanning { try? scanner.startScanning() }
    }

    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
        scanner.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        var found: (String) -> Void
        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem],
                         allItems: [RecognizedItem]) {
            for case .barcode(let barcode) in items {
                if let payload = barcode.payloadStringValue { found(payload) }
            }
        }

        func dataScanner(_ scanner: DataScannerViewController, didTapOn item: RecognizedItem) {
            if case .barcode(let barcode) = item, let payload = barcode.payloadStringValue { found(payload) }
        }
    }
}

/// AVFoundation fallback (devices without VisionKit): `AVCaptureMetadataOutput`
/// only returns the QR codes' text, no image.
struct MetadataScannerView: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeUIViewController(context: Context) -> MetadataScannerController {
        MetadataScannerController(found: found)
    }

    func updateUIViewController(_ controller: MetadataScannerController, context: Context) {
        controller.found = found
    }
}

final class MetadataScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var found: (String) -> Void
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?

    init(found: @escaping (String) -> Void) {
        self.found = found
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) unavailable") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        preview = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // AVCaptureSession is thread-safe; Apple asks to start it off the main thread.
        nonisolated(unsafe) let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        nonisolated(unsafe) let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.stopRunning() }
    }

    nonisolated func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
                                    from connection: AVCaptureConnection) {
        let payloads = objects.compactMap { ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }
        MainActor.assumeIsolated {
            for payload in payloads { found(payload) }
        }
    }
}

// MARK: Preview

/// Service, account and first code of each scanned account, then where to
/// save it.
private struct OTPPreviewView: View {
    @Environment(PhoneModel.self) private var model
    @Bindable var flow: OTPScanFlow
    let result: OtpScanResult

    var body: some View {
        Form {
            if result.accounts.count == 1, let account = result.accounts.first {
                Section {
                    OTPAccountCard(account: account)
                }
                notices
                singleActions(account)
            } else {
                notices
                Section {
                    ForEach(Array(result.accounts.enumerated()), id: \.offset) { index, account in
                        OTPAccountRow(account: account, destination: destinationBinding(index),
                                      choices: choices(for: account))
                    }
                } header: {
                    SectionHeader("\(result.accounts.count) accounts")
                } footer: {
                    Text("Each account joins the chosen login, or a new login.")
                }
                Section {
                    Button {
                        apply(flow.plan)
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "square.and.arrow.down.on.square")
                            Text(importTitle)
                        }
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity, minHeight: 34)
                    }
                    .controlSize(.large)
                    .glassButton(prominent: true)
                    .disabled(flow.busy || selectedCount == 0)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                    .accessibilityIdentifier("otp-import-all")
                }
            }
            if let error = flow.error {
                Section { ErrorLabel(text: error) }
            }
            Section {
            } footer: {
                Label("The seed goes encrypted into the item. Nothing is copied or kept: neither the image nor the QR code's text.",
                      systemImage: "lock.fill")
                    .font(.footnote)
            }
        }
    }

    @ViewBuilder private var notices: some View {
        if let number = result.batchNumber, let count = result.batchCount {
            Section {
                Label("Google Authenticator export in \(count) QR codes: this is no. \(number). Save it, then scan the next ones.",
                      systemImage: "square.stack.3d.up")
                    .font(.callout)
            }
        }
        if result.skipped > 0 {
            Section {
                Label(result.skipped == 1
                      ? "1 HOTP (counter-based) account skipped: only TOTP codes are supported."
                      : "\(result.skipped) HOTP (counter-based) accounts skipped: only TOTP codes are supported.",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(Color.warningText)
            }
        }
    }

    // A single account: buttons.
    @ViewBuilder private func singleActions(_ account: ScannedOtp) -> some View {
        Section {
            switch flow.purpose {
            case .item(let id, let title):
                primary(String(localized: "Add to “\(title)”"), symbol: "plus.circle.fill") {
                    apply([(account, .attach(id))])
                }
            case .link, .scan:
                ForEach(account.matches.prefix(3), id: \.id) { target in
                    primary(String(localized: "Add to “\(target.title)”"), symbol: "plus.circle.fill",
                            subtitle: target.subtitle.isEmpty ? nil : target.subtitle) {
                        apply([(account, .attach(target.id))])
                    }
                }
                primary(String(localized: "Create a new login"), symbol: "person.crop.circle.badge.plus",
                        prominent: account.matches.isEmpty) {
                    apply([(account, .newLogin)])
                }
            case .editor(let isNew):
                if isNew {
                    ForEach(account.matches.prefix(3), id: \.id) { target in
                        primary(String(localized: "Add to “\(target.title)”"), symbol: "plus.circle.fill",
                                subtitle: target.subtitle.isEmpty ? nil : target.subtitle) {
                            apply([(account, .attach(target.id))])
                        }
                    }
                }
                let fill = isNew ? (account.matches.isEmpty ? String(localized: "Use for this new login") : String(localized: "Create a new login"))
                                 : String(localized: "Use this code")
                primary(fill, symbol: isNew ? "person.crop.circle.badge.plus" : "checkmark.circle.fill",
                        prominent: !isNew || account.matches.isEmpty) {
                    apply([(account, .form)])
                }
            }
        } header: {
            if flow.purpose == .editor(isNew: true) || flow.purpose.picksLogin, !account.matches.isEmpty {
                SectionHeader("Login already in the vault")
            }
        }
    }

    private func primary(_ title: String, symbol: String, subtitle: String? = nil, prominent: Bool = true,
                         action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 1) {
                HStack(spacing: 8) {
                    Image(systemName: symbol)
                    Text(title).lineLimit(1)
                }
                .font(.body.weight(.semibold))
                if let subtitle {
                    Text(subtitle).font(.caption).opacity(0.8).lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 34)
        }
        .controlSize(.large)
        .glassButton(prominent: prominent)
        .disabled(flow.busy)
        .listRowBackground(Color.clear)
        .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
        .accessibilityIdentifier("otp-action")
    }

    // Several accounts: one destination per account.
    private func choices(for account: ScannedOtp) -> [DestinationChoice] {
        var list: [DestinationChoice] = []
        if flow.purpose.isEditor {
            list.append(DestinationChoice(title: String(localized: "This form"), destination: .form))
        }
        list += account.matches.map { DestinationChoice(title: String(localized: "Add to “\($0.title)”"), destination: .attach($0.id)) }
        list.append(DestinationChoice(title: String(localized: "New login"), destination: .newLogin))
        list.append(DestinationChoice(title: String(localized: "Skip"), destination: .skip))
        return list
    }

    private func destinationBinding(_ index: Int) -> Binding<OTPScanFlow.Destination> {
        Binding(get: { flow.destinations[index] ?? .skip },
                set: { value in
                    // Only one account can fill the form.
                    if value == .form {
                        for (other, destination) in flow.destinations where destination == .form {
                            flow.destinations[other] = .newLogin
                        }
                    }
                    flow.destinations[index] = value
                })
    }

    private var selectedCount: Int { flow.destinations.values.filter { $0 != .skip }.count }

    private var importTitle: String {
        selectedCount == 1 ? String(localized: "Save 1 account") : String(localized: "Save \(selectedCount) accounts")
    }

    private func apply(_ plan: [(ScannedOtp, OTPScanFlow.Destination)]) {
        Task { _ = await flow.apply(plan, model: model) }
    }
}

/// Large card of an account: service, account, scrolling code.
private struct OTPAccountCard: View {
    let account: ScannedOtp

    var body: some View {
        VStack(spacing: 10) {
            TintedSymbol(symbol: "qrcode", tint: Theme.accent, size: 52)
            VStack(spacing: 3) {
                Text(account.displayTitle)
                    .font(.title2.weight(.bold))
                    .multilineTextAlignment(.center)
                if let user = account.account, account.issuer != nil {
                    Text(user)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
            LiveCode(account: account, size: 34)
                .padding(.top, 4)
                .accessibilityIdentifier("otp-preview-code")
            HStack(spacing: 5) {
                Image(systemName: "checkmark.seal.fill")
                Text("Valid seed · \(account.code.code.count) digits · \(account.code.period) s")
            }
            .font(.caption.weight(.medium))
            .foregroundStyle(.green)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
    }
}

/// Destination offered for an account of an export.
private struct DestinationChoice {
    let title: String
    let destination: OTPScanFlow.Destination
}

/// Row of an account of an export, with its destination.
private struct OTPAccountRow: View {
    let account: ScannedOtp
    @Binding var destination: OTPScanFlow.Destination
    let choices: [DestinationChoice]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(account.displayTitle).font(.headline)
                    if let user = account.account, account.issuer != nil {
                        Text(user).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 8)
                LiveCode(account: account, size: 17)
            }
            Picker("Save in", selection: $destination) {
                ForEach(choices, id: \.destination) { choice in
                    Text(choice.title).tag(choice.destination)
                }
            }
            .pickerStyle(.menu)
            .font(.callout)
        }
        .padding(.vertical, 4)
        .opacity(destination == .skip ? 0.55 : 1)
    }
}

/// Current code, recomputed every second by the Rust core.
struct LiveCode: View {
    let value: String
    var fallback: TotpView?
    let size: CGFloat

    init(account: ScannedOtp, size: CGFloat) {
        value = account.uri
        fallback = account.code
        self.size = size
    }

    /// Seed or link entered in the edit screen.
    init(value: String, size: CGFloat) {
        self.value = value
        self.size = size
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if let code = (try? totpPreview(value: value, unixTime: UInt64(context.date.timeIntervalSince1970)))
                ?? fallback {
                TotpCodeView(code: code, size: size)
            }
        }
    }
}
