import AVFoundation
import CoreImage
import ImageIO
import Observation
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import Vision
import VisionKit

/// Lecture d'un QR code de double authentification : caméra, photo ou
/// capture d'écran, presse-papiers.
///
/// Sécurité (voir SECURITY.md, « Scanner un QR code ») :
/// - aucune image de la caméra n'est enregistrée : VisionKit (ou
///   AVFoundation) ne rend que le texte du QR code ;
/// - l'image choisie dans Photos (ou collée) n'existe qu'en mémoire, le
///   temps de la lire, puis est relâchée ;
/// - la graine part directement dans le brouillon chiffré de l'élément ;
///   elle n'est jamais journalisée ni copiée dans le presse-papiers.
@MainActor
@Observable
final class OTPScanFlow: Identifiable {
    /// D'où vient la demande.
    enum Purpose: Equatable {
        /// Écran de modification (`isNew` : création d'un identifiant).
        case editor(isNew: Bool)
        /// Fiche d'un identifiant sans code (« Ajouter un code (QR) »).
        case item(id: String, title: String)

        var isEditor: Bool {
            if case .editor = self { return true }
            return false
        }
    }

    enum Phase {
        case scanning
        case preview(OtpScanResult)
    }

    /// Ce que devient un compte lu.
    enum Destination: Hashable {
        case skip
        case newLogin
        case attach(String)
        /// Le formulaire de l'écran de modification ouvert.
        case form
    }

    /// État de la caméra.
    enum Camera: Equatable {
        case checking
        /// VisionKit (`DataScannerViewController`).
        case dataScanner
        /// Repli AVFoundation (`AVCaptureMetadataOutput`).
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
    /// Destination choisie pour chaque compte (par position).
    var destinations: [Int: Destination] = [:]
    /// Dernier texte refusé : la caméra le revoit à chaque image, on ne le
    /// relit pas.
    @ObservationIgnored private var lastRejected: String?

    init(purpose: Purpose) {
        self.purpose = purpose
    }

    var result: OtpScanResult? {
        if case .preview(let result) = phase { return result }
        return nil
    }

    // MARK: Caméra

    /// Vérifie qu'il y a une caméra, puis l'autorisation (demandée au
    /// premier usage), puis choisit VisionKit ou, à défaut, AVFoundation.
    func prepareCamera() async {
        // Sans caméra (simulateur), inutile de demander l'autorisation.
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

    // MARK: Lecture

    /// Texte d'un QR code (caméra) ou collé. `fromCamera` : un texte refusé
    /// n'est signalé qu'une fois.
    func handle(text: String, session: VaultSession, fromCamera: Bool = false) {
        guard case .scanning = phase, !busy else { return }
        if fromCamera, text == lastRejected { return }
        do {
            let result = try session.scanOtp(text: text, unixTime: UInt64(Date().timeIntervalSince1970))
            guard !result.accounts.isEmpty else {
                lastRejected = text
                error = result.skipped > 0
                    ? "Les codes HOTP (à compteur) ne sont pas pris en charge, seulement les codes TOTP."
                    : "Ce QR code ne contient aucun compte."
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

    /// Image (photo, capture d'écran, image collée) : ses QR codes sont lus
    /// hors du fil principal, puis l'image est relâchée.
    func handle(imageData: Data, session: VaultSession) async {
        guard case .scanning = phase, !busy else { return }
        busy = true
        let payloads = await Task.detached(priority: .userInitiated) {
            QRImageReader.payloads(in: imageData)
        }.value
        busy = false
        guard !payloads.isEmpty else {
            error = "Aucun QR code trouvé dans l'image. Recadrez la capture sur le QR code, puis réessayez."
            return
        }
        // Le premier QR code qui porte un code à usage unique.
        for payload in payloads {
            handle(text: payload, session: session)
            if case .preview = phase { return }
        }
    }

    /// Contenu du presse-papiers, collé par `PasteButton` (sans alerte de
    /// collage) : image ou texte.
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
        error = "Le presse-papiers ne contient ni lien otpauth:// ni image de QR code."
    }

    private static func load(_ provider: NSItemProvider, type: UTType) async -> Data? {
        await withCheckedContinuation { continuation in
            _ = provider.loadDataRepresentation(for: type) { data, _ in continuation.resume(returning: data) }
        }
    }

    /// Revient à la caméra (autre QR code).
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
            case .editor:
                chosen[index] = account.matches.first.map { .attach($0.id) } ?? .newLogin
            }
        }
        return chosen
    }

    static func describe(_ error: Error) -> String {
        if case .InvalidTotp(let message)? = error as? VerrouError {
            return message.prefix(1).uppercased() + message.dropFirst() + "."
        }
        return ErrorText.describe(error)
    }

    // MARK: Application

    /// Applique les destinations choisies ; rend `true` si la feuille peut se
    /// fermer.
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

    /// Plan d'après les destinations choisies (tous les comptes).
    var plan: [(ScannedOtp, Destination)] {
        guard let result else { return [] }
        return result.accounts.enumerated().map { ($0.element, destinations[$0.offset] ?? .skip) }
    }
}

/// Compte choisi pour remplir l'écran de modification ouvert.
struct OTPFormFill: Equatable {
    let id = UUID()
    let account: ScannedOtp

    static func == (lhs: Self, rhs: Self) -> Bool { lhs.id == rhs.id }
}

// MARK: Lecture des images

enum QRImageReader {
    /// Contenus des QR codes d'une image (PNG, JPEG, HEIC…). Vision d'abord,
    /// Core Image en secours.
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

// MARK: Écritures

extension PhoneModel {
    func startOTPScan(_ purpose: OTPScanFlow.Purpose) {
        guard canEdit else { return }
        otpScan = OTPScanFlow(purpose: purpose)
    }

    /// Enregistre les comptes scannés : ajout à un identifiant existant,
    /// nouvel identifiant, ou remplissage du formulaire ouvert. Rend l'erreur
    /// à afficher dans la feuille, s'il y en a une.
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
                    let title = summary(id: itemID)?.title ?? account.title
                    if session.needsConfirmation(id: itemID) {
                        guard await confirmAccess(itemID: itemID, title: title) else { return (written, nil) }
                    }
                    var draft = try await session.editDraft(id: itemID)
                    guard draft.login != nil else { return (written, "« \(title) » n'est pas un identifiant.") }
                    guard (draft.login?.totp ?? "").isEmpty else {
                        return (written, "« \(title) » a déjà un code à usage unique.")
                    }
                    draft.login?.totp = account.uri
                    try await session.updateItem(id: itemID, draft: draft)
                    written += 1
                    attachedTo.append(itemID)
                case .newLogin:
                    var urls: [String] = []
                    // Un service écrit comme un domaine (`github.com`) devient le site.
                    if let issuer = account.issuer, issuer.contains("."), !issuer.contains(" ") {
                        urls = ["https://\(issuer.lowercased())"]
                    }
                    let draft = ItemDraft(name: account.title, folderId: nil, favorite: false, notes: nil,
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
        // Depuis un nouvel identifiant laissé vide : l'écran de création se
        // ferme, la fiche ajoutée s'ouvre.
        if purpose == .editor(isNew: true), otpFormFill == nil {
            editor = nil
        }
        let opened = attachedTo.first ?? created.first
        // Depuis une fiche, elle est déjà affichée.
        if written == 1, purpose.isEditor, let opened, editor == nil {
            open(session.resolveItemId(id: opened))
        }
        let message = written == 1
            ? (attachedTo.isEmpty ? "Identifiant créé avec son code" : "Code ajouté à « \(summary(id: attachedTo[0])?.title ?? "l'élément") »")
            : "\(written) codes enregistrés"
        toast = Toast(message: message,
                      detail: syncState == .offline ? "Hors ligne : synchronisé dès que le serveur répondra" : nil)
        return (written, nil)
    }
}
