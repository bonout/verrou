import AVFoundation
import PhotosUI
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import VisionKit

/// Feuille « Scanner un QR code » : la caméra (cadre et consigne), puis
/// une photo ou capture d'écran, ou le presse-papiers ; ensuite l'aperçu
/// (service, compte, premier code) et l'enregistrement.
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
            .navigationTitle(flow.result == nil ? "Scanner un QR code" : "Code à usage unique")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { model.otpScan = nil }
                }
                if flow.result != nil {
                    ToolbarItem(placement: .primaryAction) {
                        Button("Rescanner", systemImage: "qrcode.viewfinder") { flow.rescan() }
                            .disabled(flow.busy)
                    }
                }
            }
        }
        .interactiveDismissDisabled(flow.busy)
    }
}

// MARK: Sources

/// Caméra en haut, autres sources en dessous.
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
                // Les octets de l'image ne vivent que le temps de la lecture.
                if let data = try? await item.loadTransferable(type: Data.self) {
                    await flow.handle(imageData: data, session: model.session)
                } else {
                    flow.error = "Image illisible."
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

    /// Savoir si le presse-papiers contient quelque chose ne le lit pas (pas
    /// d'alerte de collage) ; seul `PasteButton` le lit, au toucher.
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
                Label("Photo ou capture d'écran", systemImage: "photo.on.rectangle.angled")
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
                        Text("Coller depuis le presse-papiers")
                            .font(.callout.weight(.semibold))
                        Text("Lien otpauth:// ou image d'un QR code")
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
            Text("Sur cet iPhone, faites une capture d'écran du QR code affiché par le site, puis choisissez-la ici. L'image n'est pas conservée.")
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

/// Image de la caméra avec le cadre, ou la raison de son absence.
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
                unavailable(symbol: "video.slash.fill", title: "Accès à la caméra refusé",
                            text: "Autorisez la caméra dans Réglages pour scanner, ou choisissez une capture d'écran du QR code.",
                            settings: true)
            case .unavailable:
                unavailable(symbol: "camera.fill", title: "Caméra indisponible",
                            text: "Choisissez une photo ou une capture d'écran du QR code.", settings: false)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
        .padding(.horizontal, 12)
        .padding(.top, 8)
        .accessibilityIdentifier("otp-scan-camera")
    }

    /// Cadre aux coins arrondis et consigne.
    private var viewfinder: some View {
        VStack(spacing: 22) {
            ViewfinderFrame()
                .frame(width: 230, height: 230)
            Text("Placez le QR code du site dans le cadre")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 9)
                .glassSurface(Capsule())
        }
        .allowsHitTesting(false)
        .accessibilityElement(children: .combine)
    }

    private func unavailable(symbol: String, title: String, text: String, settings: Bool) -> some View {
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
                    Label("Ouvrir Réglages", systemImage: "gear")
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

/// Quatre coins arrondis, à la manière de l'appareil photo.
private struct ViewfinderFrame: View {
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

// MARK: Caméra

/// VisionKit : QR codes seulement, mise en évidence et guidage du système.
/// Aucune image n'est gardée, seul le texte du code remonte.
private struct DataScannerView: UIViewControllerRepresentable {
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

/// Repli AVFoundation (appareils sans VisionKit) : `AVCaptureMetadataOutput`
/// ne rend que le texte des QR codes, aucune image.
private struct MetadataScannerView: UIViewControllerRepresentable {
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
    required init?(coder: NSCoder) { fatalError("init(coder:) indisponible") }

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
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        let session = session
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

// MARK: Aperçu

/// Service, compte et premier code de chaque compte lu, puis où
/// l'enregistrer.
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
                    SectionHeader("\(result.accounts.count) comptes")
                } footer: {
                    Text("Chaque compte rejoint l'identifiant choisi, ou un nouvel identifiant.")
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
                Label("La graine part chiffrée dans l'élément. Rien n'est copié ni conservé : ni image, ni texte du QR code.",
                      systemImage: "lock.fill")
                    .font(.footnote)
            }
        }
    }

    @ViewBuilder private var notices: some View {
        if let number = result.batchNumber, let count = result.batchCount {
            Section {
                Label("Export Google Authenticator en \(count) QR codes : voici le n° \(number). Enregistrez-le, puis scannez les suivants.",
                      systemImage: "square.stack.3d.up")
                    .font(.callout)
            }
        }
        if result.skipped > 0 {
            Section {
                Label(result.skipped == 1
                      ? "1 compte HOTP (à compteur) ignoré : seuls les codes TOTP sont pris en charge."
                      : "\(result.skipped) comptes HOTP (à compteur) ignorés : seuls les codes TOTP sont pris en charge.",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
        }
    }

    // Un seul compte : des boutons.
    @ViewBuilder private func singleActions(_ account: ScannedOtp) -> some View {
        Section {
            switch flow.purpose {
            case .item(let id, let title):
                primary("Ajouter à « \(title) »", symbol: "plus.circle.fill") {
                    apply([(account, .attach(id))])
                }
            case .editor(let isNew):
                if isNew {
                    ForEach(account.matches.prefix(3), id: \.id) { target in
                        primary("Ajouter à « \(target.title) »", symbol: "plus.circle.fill",
                                subtitle: target.subtitle.isEmpty ? nil : target.subtitle) {
                            apply([(account, .attach(target.id))])
                        }
                    }
                }
                let fill = isNew ? (account.matches.isEmpty ? "Utiliser pour ce nouvel identifiant" : "Créer un nouvel identifiant")
                                 : "Utiliser ce code"
                primary(fill, symbol: isNew ? "person.crop.circle.badge.plus" : "checkmark.circle.fill",
                        prominent: !isNew || account.matches.isEmpty) {
                    apply([(account, .form)])
                }
            }
        } header: {
            if flow.purpose == .editor(isNew: true), !account.matches.isEmpty {
                SectionHeader("Identifiant déjà dans le coffre")
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

    // Plusieurs comptes : une destination par compte.
    private func choices(for account: ScannedOtp) -> [DestinationChoice] {
        var list: [DestinationChoice] = []
        if flow.purpose.isEditor {
            list.append(DestinationChoice(title: "Ce formulaire", destination: .form))
        }
        list += account.matches.map { DestinationChoice(title: "Ajouter à « \($0.title) »", destination: .attach($0.id)) }
        list.append(DestinationChoice(title: "Nouvel identifiant", destination: .newLogin))
        list.append(DestinationChoice(title: "Ignorer", destination: .skip))
        return list
    }

    private func destinationBinding(_ index: Int) -> Binding<OTPScanFlow.Destination> {
        Binding(get: { flow.destinations[index] ?? .skip },
                set: { value in
                    // Un seul compte peut remplir le formulaire.
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
        selectedCount == 1 ? "Enregistrer 1 compte" : "Enregistrer \(selectedCount) comptes"
    }

    private func apply(_ plan: [(ScannedOtp, OTPScanFlow.Destination)]) {
        Task { _ = await flow.apply(plan, model: model) }
    }
}

/// Grande carte d'un compte : service, compte, code qui défile.
private struct OTPAccountCard: View {
    let account: ScannedOtp

    var body: some View {
        VStack(spacing: 10) {
            TintedSymbol(symbol: "qrcode", tint: Theme.accent, size: 52)
            VStack(spacing: 3) {
                Text(account.issuer ?? account.title)
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
                Text("Graine valide · \(account.code.code.count) chiffres · \(account.code.period) s")
            }
            .font(.caption.weight(.medium))
            .foregroundStyle(.green)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
    }
}

/// Destination proposée pour un compte d'un export.
private struct DestinationChoice {
    let title: String
    let destination: OTPScanFlow.Destination
}

/// Ligne d'un compte d'un export, avec sa destination.
private struct OTPAccountRow: View {
    let account: ScannedOtp
    @Binding var destination: OTPScanFlow.Destination
    let choices: [DestinationChoice]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(account.issuer ?? account.title).font(.headline)
                    if let user = account.account, account.issuer != nil {
                        Text(user).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 8)
                LiveCode(account: account, size: 17)
            }
            Picker("Enregistrer dans", selection: $destination) {
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

/// Code du moment, recalculé chaque seconde par le cœur Rust.
struct LiveCode: View {
    let value: String
    var fallback: TotpView?
    let size: CGFloat

    init(account: ScannedOtp, size: CGFloat) {
        value = account.uri
        fallback = account.code
        self.size = size
    }

    /// Graine ou lien saisi dans l'écran de modification.
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
