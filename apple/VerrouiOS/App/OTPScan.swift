import AVFoundation
import CoreImage
import ImageIO
import Observation
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import Vision
import VisionKit

/// Reading a two-factor authentication QR code: camera, photo or
/// screenshot, clipboard.
///
/// Security (see SECURITY.md, "Scanning a QR code"):
/// - no camera image is saved: VisionKit (or AVFoundation) only returns
///   the QR code's text;
/// - the image chosen in Photos (or pasted) only exists in memory, long
///   enough to read it, then is released;
/// - the seed goes straight into the item's encrypted draft; it is never
///   logged nor copied to the clipboard.
@MainActor
@Observable
final class OTPScanFlow: Identifiable {
    /// Where the request comes from.
    enum Purpose: Equatable {
        /// Edit screen (`isNew`: creating a login).
        case editor(isNew: Bool)
        /// Page of a login without a code ("Add a code (QR)").
        case item(id: String, title: String)
        /// `otpauth://` link opened by iOS: Verrou chosen in Settings ›
        /// General › AutoFill & Passwords › Set Up Codes In, or a link tapped on a page.
        case link

        var isEditor: Bool {
            if case .editor = self { return true }
            return false
        }
    }

    enum Phase {
        case scanning
        case preview(OtpScanResult)
    }

    /// What becomes of a scanned account.
    enum Destination: Hashable {
        case skip
        case newLogin
        case attach(String)
        /// The open edit screen's form.
        case form
    }

    /// Camera state.
    enum Camera: Equatable {
        case checking
        /// VisionKit (`DataScannerViewController`).
        case dataScanner
        /// AVFoundation fallback (`AVCaptureMetadataOutput`).
        case metadata
        case denied
        case unavailable
    }

    let id = UUID()
    let purpose: Purpose
    private(set) var phase: Phase = .scanning
    var error: String?
    private(set) var busy = false
    var camera: Camera = .checking
    /// Destination chosen for each account (by position).
    var destinations: [Int: Destination] = [:]
    /// Last rejected text: the camera sees it again in every frame, we don't
    /// read it again.
    @ObservationIgnored private var lastRejected: String?

    init(purpose: Purpose) {
        self.purpose = purpose
    }

    var result: OtpScanResult? {
        if case .preview(let result) = phase { return result }
        return nil
    }

    // MARK: Camera

    /// Checks there is a camera, then the authorization (asked on first
    /// use), then picks VisionKit or, failing that, AVFoundation.
    func prepareCamera() async {
        // Without a camera (simulator), no point asking for authorization.
        guard AVCaptureDevice.default(for: .video) != nil else {
            camera = .unavailable
            return
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            break
        case .notDetermined:
            guard await AVCaptureDevice.requestAccess(for: .video) else {
                camera = .denied
                return
            }
        default:
            camera = .denied
            return
        }
        camera = DataScannerViewController.isSupported && DataScannerViewController.isAvailable
            ? .dataScanner : .metadata
    }

    // MARK: Reading

    /// Text of a QR code (camera) or pasted. `fromCamera`: a rejected text
    /// is reported only once.
    func handle(text: String, session: VaultSession, fromCamera: Bool = false) {
        guard case .scanning = phase, !busy else { return }
        if fromCamera, text == lastRejected { return }
        do {
            let result = try session.scanOtp(text: text, unixTime: UInt64(Date().timeIntervalSince1970))
            guard !result.accounts.isEmpty else {
                lastRejected = text
                error = result.skipped > 0
                    ? String(localized: "HOTP (counter-based) codes are not supported, only TOTP codes.")
                    : String(localized: "This QR code contains no account.")
                return
            }
            lastRejected = nil
            error = nil
            destinations = defaultDestinations(result)
            withAnimation(.snappy) { phase = .preview(result) }
        } catch {
            lastRejected = text
            self.error = Self.describe(error)
        }
    }

    /// Image (photo, screenshot, pasted image): its QR codes are read off the
    /// main thread, then the image is released.
    func handle(imageData: Data, session: VaultSession) async {
        guard case .scanning = phase, !busy else { return }
        busy = true
        let payloads = await Task.detached(priority: .userInitiated) {
            QRImageReader.payloads(in: imageData)
        }.value
        busy = false
        guard !payloads.isEmpty else {
            error = String(localized: "No QR code found in the image. Crop the screenshot to the QR code, then try again.")
            return
        }
        // The first QR code that carries a one-time code.
        for payload in payloads {
            handle(text: payload, session: session)
            if case .preview = phase { return }
        }
    }

    /// Clipboard content, pasted by `PasteButton` (no paste alert): image or
    /// text.
    func handle(pasted providers: [NSItemProvider], session: VaultSession) async {
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.image.identifier),
               let data = await Self.load(provider, type: .image) {
                await handle(imageData: data, session: session)
                return
            }
            for type in [UTType.url, UTType.utf8PlainText, UTType.plainText]
            where provider.hasItemConformingToTypeIdentifier(type.identifier) {
                if let data = await Self.load(provider, type: type),
                   let text = type == .url ? URL(dataRepresentation: data, relativeTo: nil)?.absoluteString
                                           : String(data: data, encoding: .utf8) {
                    handle(text: text, session: session)
                    return
                }
            }
        }
        error = String(localized: "The clipboard contains neither an otpauth:// link nor a QR code image.")
    }

    private static func load(_ provider: NSItemProvider, type: UTType) async -> Data? {
        await withCheckedContinuation { continuation in
            _ = provider.loadDataRepresentation(for: type) { data, _ in continuation.resume(returning: data) }
        }
    }

    /// Back to the camera (another QR code).
    func rescan() {
        lastRejected = nil
        error = nil
        destinations = [:]
        withAnimation(.snappy) { phase = .scanning }
    }

    private func defaultDestinations(_ result: OtpScanResult) -> [Int: Destination] {
        var chosen: [Int: Destination] = [:]
        for (index, account) in result.accounts.enumerated() {
            switch purpose {
            case .item(let id, _):
                chosen[index] = index == 0 ? .attach(id) : .skip
            case .editor where result.accounts.count == 1:
                chosen[index] = .form
            case .editor, .link:
                chosen[index] = account.matches.first.map { .attach($0.id) } ?? .newLogin
            }
        }
        return chosen
    }

    // MARK: Links

    /// The longest link read: a Google Authenticator export holds at most
    /// a QR code's worth (under 3 KB).
    static let maxLinkLength = 8192
    /// A link opened with the vault locked is only read if the unlock
    /// follows within this time.
    static let linkLifetime: TimeInterval = 300

    static func isOTPLink(_ url: URL) -> Bool {
        ["otpauth", "otpauth-migration"].contains(url.scheme?.lowercased() ?? "")
    }

    static func describe(_ error: Error) -> String {
        if case .InvalidTotp(let message)? = error as? VerrouError {
            let message = CoreText.message(message)
            return message.prefix(1).uppercased() + message.dropFirst() + "."
        }
        return ErrorText.describe(error)
    }

    // MARK: Applying

    /// Applies the chosen destinations; returns `true` if the sheet can
    /// close.
    func apply(_ plan: [(ScannedOtp, Destination)], model: PhoneModel) async -> Bool {
        guard !busy else { return false }
        busy = true
        defer { busy = false }
        error = nil
        let outcome = await model.applyScannedCodes(plan, purpose: purpose)
        if let failure = outcome.failure {
            error = failure
            return false
        }
        return true
    }

    /// Plan from the chosen destinations (all the accounts).
    var plan: [(ScannedOtp, Destination)] {
        guard let result else { return [] }
        return result.accounts.enumerated().map { ($0.element, destinations[$0.offset] ?? .skip) }
    }
}

/// Account chosen to fill the open edit screen.
struct OTPFormFill: Equatable {
    let id = UUID()
    let account: ScannedOtp

    static func == (lhs: Self, rhs: Self) -> Bool { lhs.id == rhs.id }
}

// MARK: Reading images

enum QRImageReader {
    /// Contents of an image's QR codes (PNG, JPEG, HEIC…). Vision first,
    /// Core Image as a fallback.
    nonisolated static func payloads(in data: Data) -> [String] {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return [] }
        let found = vision(image)
        return found.isEmpty ? coreImage(image) : found
    }

    nonisolated private static func vision(_ image: CGImage) -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        do {
            try handler.perform([request])
        } catch {
            return []
        }
        return (request.results ?? []).compactMap(\.payloadStringValue)
    }

    nonisolated private static func coreImage(_ image: CGImage) -> [String] {
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        let features = detector?.features(in: CIImage(cgImage: image)) ?? []
        return features.compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }
}

// MARK: Writes

extension PhoneModel {
    func startOTPScan(_ purpose: OTPScanFlow.Purpose) {
        guard canEdit else { return }
        otpScan = OTPScanFlow(purpose: purpose)
    }

    /// `otpauth://` (or `otpauth-migration://`) link given by iOS. Any app or
    /// page can open one: the link is only read, never saved, until the
    /// user picks where each code goes in the sheet. Not logged.
    func openOTPLink(_ url: URL) {
        guard OTPScanFlow.isOTPLink(url) else { return }
        openOTPLink(url.absoluteString)
    }

    func openOTPLink(_ text: String) {
        guard text.utf8.count <= OTPScanFlow.maxLinkLength else {
            toast = Toast(message: String(localized: "This link is too long to be a one-time code."), detail: nil, failure: true)
            return
        }
        guard lockState == .unlocked else {
            // Kept in memory only, until the unlock.
            pendingOTPLink = (text, Date())
            return
        }
        guard canEdit else {
            toast = Toast(message: String(localized: "Sign in to your Vaultwarden server to save one-time codes."),
                          detail: nil, failure: true)
            return
        }
        // The edit screen presents its own sheets: its draft is not
        // thrown away.
        guard editor == nil else {
            toast = Toast(message: String(localized: "Close the edit screen, then open the link again."), detail: nil, failure: true)
            return
        }
        qrSheet = nil
        moveRequest = nil
        let flow = OTPScanFlow(purpose: .link)
        flow.handle(text: text, session: session)
        guard flow.result != nil else {
            toast = Toast(message: String(localized: "Unreadable one-time code link"), detail: flow.error, failure: true)
            return
        }
        otpScan = flow
    }

    /// Saves the scanned accounts: added to an existing login, new login,
    /// or filling the open form. Returns the error to show in the sheet, if
    /// there is one.
    func applyScannedCodes(_ plan: [(ScannedOtp, OTPScanFlow.Destination)],
                           purpose: OTPScanFlow.Purpose) async -> (written: Int, failure: String?) {
        var written = 0
        var attachedTo: [String] = []
        var created: [String] = []
        for (account, destination) in plan {
            do {
                switch destination {
                case .skip:
                    continue
                case .form:
                    otpFormFill = OTPFormFill(account: account)
                case .attach(let itemID):
                    let title = summary(id: itemID)?.title ?? account.displayTitle
                    if session.needsConfirmation(id: itemID) {
                        guard await confirmAccess(itemID: itemID, title: title) else { return (written, nil) }
                    }
                    var draft = try await session.editDraft(id: itemID)
                    guard draft.login != nil else { return (written, String(localized: "“\(title)” is not a login.")) }
                    guard (draft.login?.totp ?? "").isEmpty else {
                        return (written, String(localized: "“\(title)” already has a one-time code."))
                    }
                    draft.login?.totp = account.uri
                    try await session.updateItem(id: itemID, draft: draft)
                    written += 1
                    attachedTo.append(itemID)
                case .newLogin:
                    var urls: [String] = []
                    // A service written like a domain (`github.com`) becomes the site.
                    if let issuer = account.issuer, issuer.contains("."), !issuer.contains(" ") {
                        urls = ["https://\(issuer.lowercased())"]
                    }
                    let draft = ItemDraft(name: account.displayTitle, folderId: nil, favorite: false, notes: nil,
                                          login: LoginFields(username: account.account, password: nil,
                                                             totp: account.uri, urls: urls),
                                          fields: [], template: nil)
                    created.append(try await session.createItem(draft: draft))
                    written += 1
                }
            } catch {
                if written > 0 { afterWrite(); pushChanges() }
                return (written, OTPScanFlow.describe(error))
            }
        }
        otpScan = nil
        guard written > 0 else { return (0, nil) }
        afterWrite()
        pushChanges()
        // From a new login left empty: the creation screen closes, the added
        // item page opens.
        if purpose == .editor(isNew: true), otpFormFill == nil {
            editor = nil
        }
        let opened = attachedTo.first ?? created.first
        // From an item page, it is already shown.
        if written == 1, purpose.isEditor || purpose == .link, let opened, editor == nil {
            open(session.resolveItemId(id: opened))
        }
        let message = written == 1
            ? (attachedTo.isEmpty ? String(localized: "Login created with its code") : String(localized: "Code added to “\(summary(id: attachedTo[0])?.title ?? String(localized: "the item"))”"))
            : String(localized: "\(written) codes saved")
        toast = Toast(message: message,
                      detail: syncState == .offline ? String(localized: "Offline: synced as soon as the server responds") : nil)
        return (written, nil)
    }
}
